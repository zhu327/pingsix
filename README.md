# PingSIX

PingSIX is a high-performance and scalable API gateway designed for modern cloud-native environments. Inspired by Cloudflare Pingora and APISIX, PingSIX combines Rust's flexibility, robustness, and efficiency to provide powerful reverse proxy and API management capabilities.

## Key Features

- **High Performance**: Built with Rust, utilizing multi-threading for exceptional performance.
- **Dynamic Configuration**: Supports dynamic configuration via etcd for real-time updates across distributed systems.
- **Flexible Routing**: Advanced routing based on host, URI, and HTTP methods with priority-based rules.
- **Plugin Ecosystem**: Includes plugins for compression, access control, gRPC support, and more, with support for custom plugin extensions.
- **Observability**: Exposes Prometheus metrics and integrates with Sentry for error tracking and monitoring.
- **Distributed Configuration Management**: Admin API compatible with APISIX Admin API for resource management.
- **Global Rules and Services**: Implements reusable global plugin behaviors and service configurations to simplify plugin and upstream reuse.
- **Upstream Health Checks**: Provides active health checks to ensure upstream reliability.

## Plugin Overview

PingSIX includes multiple built-in plugins that enhance API gateway capabilities, including but not limited to:

- **brotli**: Brotli compression for HTTP responses, optimizing bandwidth usage.
- **gzip**: Gzip compression for HTTP responses.
- **echo**: A utility plugin for testing, allowing custom headers and response bodies.
- **grpc_web**: Support for handling gRPC-Web requests.
- **ip_restriction**: IP-based access control.
- **limit_count**: Rate limiting based on request count.
- **prometheus**: Exposes API monitoring metrics.
- **proxy_rewrite**: Supports dynamic modification of proxy request/response rules.
- **redirect**: Allows redirecting requests to a specified URL.

## Configuration Example

PingSIX uses a YAML configuration format, supporting global rules, services, and upstream configurations. Example:

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

## etcd Admin API

If etcd is enabled as a dynamic configuration store, PingSIX supports resource management using the Admin API, fully compatible with APISIX Admin API.

Example:

**Create a Route**
```bash
curl http://127.0.0.1:8082/apisix/admin/routes/1 \
     -H "X-API-KEY: pingsix" \
     -X PUT -d '{
       "uri": "/test",
       "upstream": {
         "type": "roundrobin",
         "nodes": { "httpbin.org": 1 }
       }
     }'
```

For more API details, refer to [APISIX Admin API documentation](https://apisix.apache.org/docs/apisix/admin-api/).

## Running PingSIX

Run PingSIX with the configuration file:

```bash
cargo run -- -c config.yaml
```

## Installation Guide

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

- **Prometheus Metrics**: Exposes API monitoring data at `0.0.0.0:8081` (configurable).
- **Sentry Tracking**: Integrates with Sentry for error analysis and performance monitoring.

## Extensibility

PingSIX is designed with a flexible plugin system, allowing developers to use built-in plugins or create custom ones to meet specific requirements.

## License

PingSIX is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a PR or open an issue for discussions or suggestions.

## Acknowledgments

This project is inspired by [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [APISIX](https://apisix.apache.org/), with gratitude for their excellent open-source contributions.
