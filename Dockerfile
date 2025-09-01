FROM rust:1.88-slim as builder

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
    cargo build --release && \
    rm -rf src

COPY src ./src

RUN cargo build --release

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
    chown -R pingsix:pingsix /app /var/log/pingsix /var/run/pingsix

USER pingsix

EXPOSE 8080 9091 9181

CMD ["pingsix", "-c", "/app/config.yaml"]
