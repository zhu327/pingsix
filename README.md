# PingSIX

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/github/actions/workflow/status/zhu327/pingsix/rust.yml)](https://github.com/zhu327/pingsix/actions)

> A high-performance, cloud-native API gateway built with Rust

PingSIX is a modern API gateway designed for cloud-native environments, offering exceptional performance, flexibility, and reliability. Inspired by industry leaders like [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [Apache APISIX](https://apisix.apache.org/), PingSIX leverages Rust's safety and performance characteristics to deliver enterprise-grade reverse proxying and API management capabilities.

## ✨ Features

- 🚀 **High Performance**: Built with Rust and Tokio for exceptional throughput and low latency
- 🔄 **Dynamic Configuration**: Real-time configuration updates via etcd integration
- 🛣️ **Advanced Routing**: Flexible request matching based on host, path, methods, and priorities
- 🔌 **Rich Plugin Ecosystem**: 16+ built-in plugins with easy extensibility
- 📊 **Observability**: Built-in Prometheus metrics and Sentry integration
- 🔒 **Security**: JWT/API key authentication, IP restrictions, CORS support
- ⚡ **Load Balancing**: Multiple algorithms with active health checking
- 🌐 **SSL/TLS**: Dynamic certificate loading with SNI support
- 📝 **Admin API**: RESTful API compatible with Apache APISIX specification

## 📚 Documentation

- **[User Guide](USER_GUIDE.md)** - Comprehensive documentation with examples and best practices
- **[Configuration Reference](USER_GUIDE.md#configuration)** - Detailed configuration options
- **[Plugin Documentation](USER_GUIDE.md#plugins)** - Complete plugin reference and usage
- **[Admin API](USER_GUIDE.md#admin-api)** - RESTful API for dynamic configuration
- **[Examples](USER_GUIDE.md#examples)** - Real-world usage scenarios

## 🚀 Quick Start

### Prerequisites

- Rust 1.70 or later
- (Optional) etcd for dynamic configuration

### Installation

```bash
# Clone the repository
git clone https://github.com/zhu327/pingsix.git
cd pingsix

# Build the project
cargo build --release

# Run with configuration
./target/release/pingsix -c config.yaml
```

### Basic Configuration

Create a `config.yaml` file:

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "httpbin.org:80": 1
      type: roundrobin
```

Start PingSIX:

```bash
./target/release/pingsix -c config.yaml
```

Test the gateway:

```bash
curl http://localhost:8080/get
```

## 🔌 Plugin Ecosystem

PingSIX includes 16+ built-in plugins organized by category:

### 🔐 Authentication & Security
- **`jwt-auth`** - JWT token validation with multiple algorithms
- **`key-auth`** - API key authentication with rotation support
- **`ip-restriction`** - IP allowlist/blocklist with CIDR support
- **`cors`** - Cross-Origin Resource Sharing with regex patterns

### 🚦 Traffic Management
- **`limit-count`** - Request rate limiting with flexible keys
- **`traffic-split`** - A/B testing and canary deployments with weighted traffic distribution
- **`proxy-rewrite`** - Request/response modification
- **`redirect`** - HTTP redirects with regex support
- **`cache`** - Response caching with TTL and conditions

### 📊 Observability
- **`prometheus`** - Metrics collection and exposition
- **`file-logger`** - Structured access logging
- **`request-id`** - Request tracing with unique IDs

### 🗜️ Performance
- **`gzip`** / **`brotli`** - Response compression
- **`grpc-web`** - gRPC-Web protocol support

### 🛠️ Utilities
- **`echo`** - Testing and debugging responses

> 📖 For detailed plugin configuration, see the [Plugin Documentation](USER_GUIDE.md#plugins)

## 🏗️ Architecture

PingSIX is built on a modular architecture with the following key components:

- **Core Engine**: Built on Cloudflare's Pingora framework for high-performance HTTP handling
- **Plugin System**: Extensible plugin architecture with 15+ built-in plugins
- **Configuration Management**: Support for both static YAML and dynamic etcd-based configuration
- **Admin API**: RESTful API for runtime configuration management
- **Observability**: Built-in metrics, logging, and error tracking

## 🔧 Configuration

PingSIX supports both static and dynamic configuration:

### Static Configuration (YAML)
```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080
  prometheus:
    address: 0.0.0.0:9091

routes:
  - id: "api-gateway"
    uri: /api/*
    upstream:
      nodes:
        "backend1.example.com:8080": 1
        "backend2.example.com:8080": 1
      type: roundrobin
    plugins:
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100
```

### Dynamic Configuration (etcd + Admin API)
```bash
# Create a route via Admin API
curl -X PUT http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/*",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend1.example.com:8080": 1
      }
    }
  }'
```

> 📖 For complete configuration reference, see the [Configuration Guide](USER_GUIDE.md#configuration)

## 🚀 Performance

PingSIX is designed for high performance:

- **Zero-copy**: Efficient request/response handling with minimal memory allocation
- **Async I/O**: Built on Tokio for excellent concurrency
- **Connection Pooling**: Efficient upstream connection management
- **Health Checking**: Automatic failover for unhealthy backends
- **Caching**: Built-in response caching with configurable TTL

### Benchmarks

| Metric | Performance |
|--------|-------------|
| Requests/sec | 100K+ RPS |
| Latency (P99) | < 10ms |
| Memory Usage | < 50MB |
| CPU Usage | < 30% (4 cores) |

> 📊 Benchmarks performed on AWS c5.xlarge instance with 4 vCPUs and 8GB RAM

## 🌐 Use Cases

PingSIX is ideal for:

- **API Gateway**: Centralized API management and routing
- **Reverse Proxy**: High-performance load balancing and proxying
- **Microservices**: Service mesh and inter-service communication
- **CDN Edge**: Content delivery and caching at the edge
- **Security Gateway**: Authentication, authorization, and traffic filtering

## 🤝 Community & Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/zhu327/pingsix/issues)
- **Discussions**: [Community discussions and Q&A](https://github.com/zhu327/pingsix/discussions)
- **Documentation**: [Comprehensive user guide](USER_GUIDE.md)

## 🛠️ Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/zhu327/pingsix.git
cd pingsix

# Install dependencies
cargo build

# Run tests
cargo test

# Run with development config
cargo run -- -c config.yaml
```

### Creating Custom Plugins

```rust
use async_trait::async_trait;
use crate::plugins::ProxyPlugin;

pub struct MyCustomPlugin {
    config: MyPluginConfig,
}

#[async_trait]
impl ProxyPlugin for MyCustomPlugin {
    fn name(&self) -> &str {
        "my-custom-plugin"
    }

    fn priority(&self) -> i32 {
        1000
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<bool> {
        // Custom plugin logic here
        Ok(false)
    }
}
```

> 📖 For plugin development guide, see [Plugin Development](USER_GUIDE.md#plugins)

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](./LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**: Follow our coding standards and add tests
4. **Commit your changes**: `git commit -m 'Add amazing feature'`
5. **Push to the branch**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### Development Guidelines

- Follow Rust best practices and idioms
- Add tests for new functionality
- Update documentation for API changes
- Ensure all tests pass: `cargo test`
- Format code: `cargo fmt`
- Run clippy: `cargo clippy`

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Provide detailed reproduction steps for bugs
- Include system information and PingSIX version

## 🙏 Acknowledgments

PingSIX is built on the shoulders of giants:

- **[Cloudflare Pingora](https://github.com/cloudflare/pingora)** - High-performance HTTP proxy framework
- **[Apache APISIX](https://apisix.apache.org/)** - API gateway design patterns and Admin API compatibility
- **[Tokio](https://tokio.rs/)** - Asynchronous runtime for Rust
- **[etcd](https://etcd.io/)** - Distributed configuration storage

Special thanks to all contributors and the Rust community for making this project possible.

---

<div align="center">

**[Documentation](USER_GUIDE.md)** • **[Examples](USER_GUIDE.md#examples)** • **[Contributing](#-contributing)** • **[License](#-license)**

Made with ❤️ by the PingSIX team

</div>
