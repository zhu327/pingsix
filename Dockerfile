# 多阶段构建 Dockerfile for PingSIX
# 第一阶段：构建阶段
FROM docker.m.daocloud.io/rust:1.88-slim as builder

# 安装构建依赖
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

# 设置工作目录
WORKDIR /app

# 复制 Cargo 文件以利用 Docker 层缓存
COPY Cargo.toml Cargo.lock ./

# 创建一个虚拟的 main.rs 来构建依赖项（优化构建时间）
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# 复制源代码
COPY src ./src

# 构建应用程序
RUN cargo build --release

# 第二阶段：运行时镜像
FROM docker.m.daocloud.io/debian:bookworm-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 创建非特权用户
RUN groupadd -r pingsix && useradd -r -g pingsix pingsix

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/target/release/pingsix /usr/local/bin/pingsix

# 复制配置文件
COPY config.yaml /app/config.yaml

# 创建必要的目录并设置权限
RUN mkdir -p /var/log/pingsix /var/run/pingsix && \
    chown -R pingsix:pingsix /app /var/log/pingsix /var/run/pingsix

# 切换到非特权用户
USER pingsix

# 暴露端口
EXPOSE 8080 9091 9181

# 设置默认命令
CMD ["pingsix", "-c", "/app/config.yaml"]
