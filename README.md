# PingSIX  

PingSIX is a high-performance and scalable API gateway tailored for modern cloud-native environments. Inspired by Cloudflare's Pingora and APISIX, PingSIX combines flexibility, robustness, and the efficiency of Rust to provide a powerful reverse proxy and API management solution.  

## Key Features  

- **High Performance**: Built with Rust, leveraging multi-threading for exceptional performance.  
- **Flexible Configuration**: Offers a YAML-based configuration style for easy customization of routes, upstreams, health checks, and more.  
- **Advanced Routing**: Supports host-based and URI-based routing with fine-grained control.  
- **Upstream Health Checks**: Provides active health checks to ensure upstream reliability.  
- **Observability**: Prometheus metrics and Sentry integration for monitoring and debugging.  
- **Plugin System**: A rich plugin ecosystem for features such as compression, rate limiting, and gRPC support.  

## Plugin Highlights  

PingSIX now includes the following plugins to enhance its capabilities:  

- **brotli**: Supports Brotli compression for responses, optimizing bandwidth usage.  
- **gzip**: Provides Gzip compression for HTTP responses.  
- **echo**: A utility plugin for testing, allowing custom headers and response bodies.  
- **grpc_web**: Adds support for handling gRPC-Web requests.  
- **limit_count**: Implements rate limiting with customizable policies.  
- **prometheus**: Exposes metrics for monitoring the API gateway's performance and health.  

## Configuration Example  

Below is an example configuration file for PingSIX, including plugins:  

```yaml
pingora:
  version: 1
  threads: 2
  pid_file: /run/pingora.pid
  upgrade_sock: /tmp/pingora_upgrade.sock
  user: nobody
  group: webusers

prometheus:
  address: 0.0.0.0:8081

listeners:
  - address: 0.0.0.0:8080

routers:
  - id: 1
    uri: /
    host: www.example.com
    plugins:
      gzip:
        comp_level: 6
    upstream:
      nodes:
        "www.example.com": 1
      type: roundrobin
  - id: 2
    uri: /api
    host: api.example.com
    plugins:
      grpc_web: {}
      limit_count:
        key_type: head
        key: Host
        time_window: 1
        count: 10
        rejected_code: 429
        rejected_msg: "Too Many Requests"

services:
  - id: 1
    upstream:
      nodes:
        "api.example.com": 1
      type: roundrobin
```

## Usage  

To run PingSIX with a configuration file:  

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

## Extensibility  

With its plugin system, PingSIX is highly extensible. You can use built-in plugins or develop your own to meet specific requirements.  

## License  

PingSIX is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) for details.  

## Contributing  

Contributions are welcome! Please submit a pull request or open an issue for discussions or suggestions.  

## Acknowledgments  

This project is inspired by [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [APISIX](https://apisix.apache.org/).  
