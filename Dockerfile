FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    protobuf-compiler \
    perl \
    make \
    cmake \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src

COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN groupadd -r pingsix && useradd -r -g pingsix pingsix

WORKDIR /app

COPY --from=builder /app/target/release/pingsix /usr/local/bin/pingsix

COPY config.yaml /app/config.yaml

RUN mkdir -p /var/log/pingsix /var/run/pingsix && \
    sed -i \
        -e 's|pid_file: /run/pingora.pid|pid_file: /var/run/pingsix/pingora.pid|' \
        -e 's|address: "127.0.0.1:7085"|address: "0.0.0.0:7085"|' \
        -e '/^  user: nobody$/d' \
        -e '/^  group: webusers$/d' \
        /app/config.yaml && \
    chown -R pingsix:pingsix /app /var/log/pingsix /var/run/pingsix

USER pingsix

# Proxy listener, status/readiness probes, and Prometheus.
EXPOSE 8080 7085 9091

CMD ["pingsix", "-c", "/app/config.yaml"]
