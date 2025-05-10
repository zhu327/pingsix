# PingSIX

PingSIX is a high-performance, scalable, and flexible API gateway built with Rust, designed for modern cloud-native environments. Inspired by industry leaders like Cloudflare Pingora and Apache APISIX, PingSIX leverages Rust's safety, speed, and concurrency features to deliver robust reverse proxying and advanced API management.

## Key Features

-   **High Performance:** Built entirely in Rust, utilizing Tokio's asynchronous runtime and multi-threading for exceptional throughput and low latency.
-   **Dynamic Configuration:** Seamlessly integrates with etcd for real-time configuration updates across distributed deployments (optional). Static file configuration is also supported.
-   **Flexible Routing:** Advanced request routing based on host, path (with path parameters like `/users/:id`), HTTP methods, and priority-based rules.
-   **Extensible Plugin Ecosystem:** Supports a wide range of built-in plugins (compression, authentication, rate limiting, observability, CORS, etc.) and allows easy development of custom Rust plugins.
-   **Observability:** Built-in support for Prometheus metrics endpoint and Sentry integration for comprehensive monitoring and error tracking.
-   **Distributed Configuration Management:** When using etcd, provides an Admin API compatible with the Apache APISIX specification for managing routes, services, upstreams, SSL certificates, etc.
-   **Global Rules & Services:** Define reusable global plugins and service configurations to reduce duplication and simplify management.
-   **Upstream Health Checks:** Active health checking (HTTP/HTTPS/TCP) for upstream services ensures traffic is only routed to healthy instances.
-   **Dynamic SSL Certificate Loading:** Load SSL certificates dynamically based on the Server Name Indication (SNI) during the TLS handshake, using etcd or static configuration.
-   **File Logging:** Configurable access log output to a specified file.

## Plugin Overview

PingSIX comes with several built-in plugins to enhance its capabilities:

-   `brotli` / `gzip`: Response compression using Brotli or Gzip algorithms.
-   `cors`: Handles Cross-Origin Resource Sharing (CORS) preflight and actual requests.
-   `echo`: Responds directly with predefined headers and body, useful for testing.
-   `file-logger`: Flexible request/response logging to a file using custom formats.
-   `grpc_web`: Bridges gRPC-Web requests to backend gRPC services.
-   `ip_restriction`: Whitelists or blacklists client IP addresses or ranges.
-   `jwt_auth`: Authenticates requests using JSON Web Tokens (JWT).
-   `key_auth`: Authenticates requests using simple API keys.
-   `limit_count`: Implements request rate limiting based on various criteria (IP, header, etc.).
-   `prometheus`: Exposes detailed request metrics (latency, status codes, bandwidth) for Prometheus scraping.
-   `proxy_rewrite`: Modifies request URI, headers, method, or host before proxying to the upstream.
-   `redirect`: Redirects requests based on configured rules (e.g., HTTP to HTTPS, URI rewrite).
-   `request_id`: Injects a unique request ID header into requests and responses for tracing.

The plugin system is designed for easy extension. You can create your own plugins in Rust by implementing the `ProxyPlugin` trait.

## Configuration Example

PingSIX uses a YAML configuration format, supporting global rules, services, and upstream configurations. Example:

```yaml
# Basic Pingora server settings
pingora:
  version: 1
  threads: 4 # Adjust based on your server cores
  pid_file: /var/run/pingsix.pid
  upgrade_sock: /tmp/pingsix_upgrade.sock
  user: nobody
  group: nogroup
  daemon: false # Run in foreground by default

# PingSIX specific configuration
pingsix:
  # Listeners define where PingSIX accepts connections
  listeners:
    - address: 0.0.0.0:80 # HTTP listener
      offer_h2c: true # Offer HTTP/2 Cleartext (Upgrade)
    - address: 0.0.0.0:443 # HTTPS listener
      tls:
        # Default cert/key used if SNI doesn't match dynamic certs
        cert_path: /etc/pingsix/ssl/default.crt
        key_path: /etc/pingsix/ssl/default.key
      offer_h2: true # Offer HTTP/2 over TLS (ALPN)

  # Optional: Enable etcd for dynamic configuration
  # etcd:
  #   host:
  #     - "http://127.0.0.1:2379"
  #   prefix: /pingsix # Prefix for all keys in etcd

  # Optional: Enable Admin API (requires etcd)
  # admin:
  #   address: "0.0.0.0:9181" # Admin API listening address
  #   api_key: "pingsix_admin_key" # Secure your Admin API

  # Optional: Prometheus metrics endpoint
  prometheus:
    address: 0.0.0.0:9091

  # Optional: Sentry integration for error tracking
  # sentry:
  #  dsn: "YOUR_SENTRY_DSN_HERE"

  # Optional: File logging configuration
  log:
    path: /var/log/pingsix/access.log
    # Example format (see file-logger plugin for variables)
    # format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'

# --- Static Resource Definitions (used if etcd is not enabled) ---

# Routes define how incoming requests are matched and processed
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

# Upstreams define backend server pools
upstreams:
  - id: 1
    nodes:
      "www.taobao.com": 1
    type: roundrobin

# Services group upstream and plugins, reusable by routes
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

# Global rules apply plugins to all matching requests
global_rules:
  - id: 1
    plugins:
      prometheus: {}
      file-logger: {}

# SSL Certificates (used for dynamic loading via SNI if etcd enabled or defined statically)
ssls:
  - id: 1
    # Certificate and key content (PEM format)
    cert: |
      -----BEGIN CERTIFICATE-----
      ... cert content ...
      -----END CERTIFICATE-----
    key: |
      -----BEGIN PRIVATE KEY-----
      ... key content ...
      -----END PRIVATE KEY-----
    # Server names this certificate applies to
    snis: ["example.com", "www.example.com"]
```

## etcd Admin API

Note: The Admin API is only available when etcd is enabled for dynamic configuration (pingsix.etcd section in config.yaml).

PingSIX provides an Admin API compatible with the Apache APISIX Admin API specification for managing resources like routes, services, upstreams, and SSL certificates dynamically when using etcd.

Example: Create a Route via Admin API

**Create a Route**
```bash
curl http://127.0.0.1:9181/apisix/admin/routes/1 \
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

## Documentation

For detailed documentation, including setup guides, configuration options, plugin development, and API references, visit the [PingSIX Documentation](https://deepwiki.com/zhu327/pingsix) hosted on DeepWiki. This resource provides in-depth information to help you get started and customize PingSIX for your use case.

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

- **Prometheus Metrics**: Exposes API monitoring data at `0.0.0.0:9091` (configurable).
- **Sentry Tracking**: Integrates with Sentry for error analysis and performance monitoring.
- **File Logging**: If enabled (pingsix.log), access logs will be written to the specified file path in the configured format.

## Extensibility

PingSIX is designed with a flexible plugin system, allowing developers to use built-in plugins or create custom ones to meet specific requirements.

## License

PingSIX is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a PR or open an issue for discussions or suggestions.

## Acknowledgments

This project is inspired by [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [APISIX](https://apisix.apache.org/), with gratitude for their excellent open-source contributions.
