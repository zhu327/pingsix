# pingsix

PingSIX is an API gateway project inspired by Cloudflare's Pingora and designed with a configuration style similar to APISIX. This project is developed in Rust, focusing on providing a high-performance, scalable API gateway solution.

## Features

- **Standalone Mode**: Supports basic reverse proxy functionality, including routing and upstream configurations.
- **Routing and Upstream Support**: Configure routes and upstreams with flexible options similar to APISIX.
- **Customizable Health Checks**: Supports active health checks for upstream nodes to ensure reliable routing.

## Configuration Example

Below is an example configuration file for PingSIX, adapted from Cloudflare Pingora and APISIX configuration styles:

```yaml
pingora:
  version: 1
  threads: 2
  pid_file: /run/pingora.pid
  upgrade_sock: /tmp/pingora_upgrade.sock
  user: nobody
  group: webusers

listeners:
  - address: 0.0.0.0:8080
  # - address: "[::1]:443"
  #   tls:
  #     cert_path: /etc/ssl/server.crt
  #     key_path: /etc/ssl/server.key
  #   offer_h2: true

routers:
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
      hash_on: vars
      key: uri
      pass_host: rewrite
      upstream_host: www.baidu.com
      scheme: https
  - id: 2
    uri: /
    host: www.taobao.com
    upstream:
      nodes:
        "www.taobao.com": 1
      type: roundrobin
      pass_host: rewrite
      upstream_host: www.taobao.com
      scheme: http
```

## Usage

To run PingSIX with your configuration file, use the following command:

```bash
cargo run -- -c config.yaml
```

This command will start the API gateway using the settings provided in `config.yaml`.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/zhu327/pingsix.git
   ```

2. Build the project with Cargo:

   ```bash
   cd pingsix
   cargo build --release
   ```

## License

PingSIX is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss any changes.

## Acknowledgments

- This project is inspired by [Cloudflare Pingora](https://github.com/cloudflare/pingora) and [APISIX](https://apisix.apache.org/).
