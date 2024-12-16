# PingSIX

PingSIX is a high-performance and scalable API gateway tailored for modern cloud-native environments. Inspired by Cloudflare's Pingora and APISIX, PingSIX combines flexibility, robustness, and the efficiency of Rust to provide a powerful reverse proxy and API management solution.

## Key Features

- **High Performance**: Built with Rust, leveraging multi-threading for exceptional performance.
- **Dynamic Configuration**: Supports dynamic configuration via etcd for seamless distributed deployment, enabling real-time updates across distributed systems.
- **Flexible Routing**: Offers advanced routing based on host, URI, and methods with support for priority-based rules.
- **Plugin Ecosystem**: Includes a range of plugins for compression, access control, gRPC support, and more.
- **Observability**: Exposes metrics via Prometheus and integrates with Sentry for debugging and monitoring.
- **Distributed Configuration Management**: Admin API for resource management through etcd, fully compatible with APISIX's Admin API.
- **Global Rules and Services**: Implements reusable global plugin behaviors and service configurations to simplify plugin and upstream reuse.
- **Upstream Health Checks**: Provides active health checks for upstream reliability.

## Plugin Highlights

PingSIX includes the following plugins, inspired by APISIX:

- **brotli**: Brotli compression for HTTP responses, optimizing bandwidth usage.
- **gzip**: Gzip compression for HTTP responses.
- **echo**: A utility plugin for testing, allowing custom headers and response bodies.
- **grpc_web**: Support for handling gRPC-Web requests.
- **ip_restriction**: IP-based access control.
- **limit_count**: Rate limiting with customizable policies.
- **prometheus**: Metrics exposure for monitoring API gateway performance and health.
- **proxy_rewrite**: Dynamic modification of request/response proxying rules.

## Configuration

PingSIX now supports YAML-based configuration inspired by the APISIX model. It includes support for global rules, services, and upstream configurations. Below is an example configuration:

```yaml
pingora:
  version: 1
  threads: 2
  pid_file: /run/pingora.pid
  upgrade_sock: /tmp/pingora_upgrade.sock
  user: nobody
  group: webusers

pingsix:
  listeners:
    - address: 0.0.0.0:8080

  # etcd:
  #   host:
  #     - "http://192.168.2.141:2379"
  #   prefix: /apisix

  # admin:
  #   address: "0.0.0.0:8082"
  #   api_key: pingsix

  prometheus:
    address: 0.0.0.0:8081

  sentry:
    dsn: https://1234567890@sentry.io/123456

routes:
  - id: 1
    uri: /
    host: www.baidu.com
    upstream:
      nodes:
        "www.baidu.com": 1
      type: roundrobin
      checks:
        active:
          type: https
          timeout: 1
          host: www.baidu.com
          http_path: /
          https_verify_certificate: true
          req_headers: ["User-Agent: curl/7.29.0"]
          healthy:
            interval: 5
            http_statuses: [200, 201]
            successes: 2
          unhealthy:
            http_failures: 5
            tcp_failures: 2

upstreams:
  - id: 1
    nodes:
      "www.taobao.com": 1
    type: roundrobin

services:
  - id: 1
    hosts: ["www.qq.com"]
    upstream_id: 2
    plugins:
      limit-count:
        key_type: head
        key: Host
        time_window: 1
        count: 1
        rejected_code: 429
        rejected_msg: "Please slow down!"

global_rules:
  - id: 1
    plugins:
      prometheus: {}
```

## Usage

Run PingSIX with the configuration file:

```bash
cargo run -- -c config.yaml
```

This will start the API gateway with the specified settings.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/zhu327/pingsix.git
   ```
2. Build the project:
   ```bash
   cd pingsix
   cargo build --release
   ```
3. Run the binary:
   ```bash
   ./target/release/pingsix -c config.yaml
   ```

## Observability

- **Prometheus Metrics**: Exposes metrics at `0.0.0.0:8081` (configurable).
- **Sentry Integration**: Tracks errors and performance metrics using Sentry.

## Extensibility

PingSIX is designed with extensibility in mind. Its plugin system allows developers to use built-in plugins or create custom ones to suit specific requirements.

## License

PingSIX is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for discussions or suggestions.

## Acknowledgments

This project is inspired by [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [APISIX](https://apisix.apache.org/).
