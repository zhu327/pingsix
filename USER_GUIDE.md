# PingSIX API Gateway - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Core Concepts](#core-concepts)
4. [Configuration](#configuration)
5. [Routing](#routing)
6. [Upstreams](#upstreams)
7. [Services](#services)
8. [Global Rules](#global-rules)
9. [Plugins](#plugins)
10. [Admin API](#admin-api)
11. [SSL/TLS Configuration](#ssltls-configuration)
12. [Monitoring and Observability](#monitoring-and-observability)
13. [Examples](#examples)
14. [Troubleshooting](#troubleshooting)

## Introduction

PingSIX is a high-performance API gateway built with Rust, designed for modern cloud-native environments. It provides advanced routing, load balancing, security, and observability features with excellent performance and reliability.

### Key Features

- **High Performance**: Built with Rust and Tokio for exceptional throughput and low latency
- **Dynamic Configuration**: Real-time configuration updates via etcd integration
- **Flexible Routing**: Advanced request matching based on host, path, methods, and priorities
- **Rich Plugin Ecosystem**: 15+ built-in plugins for authentication, rate limiting, compression, and more
- **Health Checking**: Active health checks for upstream services
- **Observability**: Built-in Prometheus metrics and Sentry integration
- **Admin API**: RESTful API for dynamic configuration management

## Getting Started

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/zhu327/pingsix.git
   cd pingsix
   ```

2. **Build the project**:
   ```bash
   cargo build --release
   ```

3. **Run PingSIX**:
   ```bash
   ./target/release/pingsix -c config.yaml
   ```

### Basic Configuration

Create a `config.yaml` file with the following minimal configuration:

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

This configuration creates a simple proxy that forwards all requests to httpbin.org.

## Core Concepts

### Routes

Routes define how incoming requests are matched and processed. Each route specifies:
- **Matching criteria**: URI patterns, hosts, HTTP methods
- **Destination**: Where to forward the request (upstream or service)
- **Plugins**: Additional processing to apply

### Upstreams

Upstreams define backend server pools with:
- **Nodes**: List of backend servers with weights
- **Load balancing**: Algorithm for distributing requests
- **Health checks**: Monitoring backend server health

### Services

Services group upstreams and plugins for reusability:
- **Upstream reference**: Link to an upstream configuration
- **Plugin configuration**: Shared plugins across multiple routes
- **Host matching**: Optional host-based routing

### Global Rules

Global rules apply plugins to all requests matching certain criteria:
- **Universal plugins**: Applied to all traffic
- **Monitoring**: Prometheus metrics, logging
- **Security**: Global authentication, rate limiting

## Configuration

### Configuration Structure

PingSIX uses YAML configuration with the following main sections:

```yaml
# Pingora framework settings
pingora:
  version: 1
  threads: 4
  pid_file: /var/run/pingsix.pid
  daemon: false

# PingSIX specific settings
pingsix:
  listeners: []      # Network listeners
  etcd: {}          # etcd configuration (optional)
  admin: {}         # Admin API (optional)
  prometheus: {}    # Metrics endpoint (optional)
  sentry: {}        # Error tracking (optional)
  log: {}           # File logging (optional)

# Resource definitions
routes: []          # Route configurations
upstreams: []       # Upstream server pools
services: []        # Service definitions
global_rules: []    # Global plugin rules
ssls: []           # SSL certificates
```

### Listeners

Listeners define where PingSIX accepts connections:

```yaml
pingsix:
  listeners:
    # HTTP listener
    - address: 0.0.0.0:80
      offer_h2c: true  # HTTP/2 Cleartext support
    
    # HTTPS listener
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true   # HTTP/2 over TLS
```

### etcd Integration

Enable dynamic configuration with etcd:

```yaml
pingsix:
  etcd:
    host:
      - "http://127.0.0.1:2379"
      - "http://127.0.0.1:2380"
    prefix: /pingsix
    timeout: 30
    connect_timeout: 10
    user: username      # Optional authentication
    password: password  # Optional authentication
```

## Routing

### Basic Route Configuration

```yaml
routes:
  - id: "api-v1"
    uri: /api/v1/{*path}        # Catch-all for /api/v1/* requests
    host: api.example.com
    methods: ["GET", "POST"]
    upstream:
      nodes:
        "backend1.example.com:8080": 1
        "backend2.example.com:8080": 1
      type: roundrobin
```

### Route Matching

Routes support multiple matching criteria based on the `matchit` routing library:

#### URI Matching

PingSIX uses `matchit` for route matching, which supports the following patterns:

```yaml
# Static/exact match
uri: /api/users

# Named parameters (capture path segments)
uri: /api/users/{id}          # Matches /api/users/123, captures id=123
uri: /api/users/{id}/posts    # Matches /api/users/123/posts

# Catch-all parameters (capture remaining path)
uri: /static/{*filepath}      # Matches /static/css/style.css, captures filepath=css/style.css
uri: /{*path}                 # Matches any path

# Parameter with suffix
uri: /images/img{id}.png      # Matches /images/img123.png, captures id=123

# Multiple URIs with different patterns
uris: ["/api/v1/users/{id}", "/api/v2/users/{user_id}"]
```

**Important Notes:**
- Use `{parameter_name}` for named parameters that capture a single path segment
- Use `{*parameter_name}` for catch-all parameters that capture the remaining path
- Catch-all parameters must be at the end of the path
- Only one parameter is allowed per path segment
- Static routes have higher priority than dynamic routes

**Route Parameter Examples:**
```yaml
# Named parameter examples
uri: /users/{id}                    # Matches: /users/123
uri: /users/{id}/posts/{post_id}    # Matches: /users/123/posts/456
uri: /files/{filename}.{ext}        # Matches: /files/document.pdf

# Catch-all parameter examples  
uri: /static/{*filepath}            # Matches: /static/css/main.css
uri: /api/v1/{*path}               # Matches: /api/v1/users/123/posts
uri: /{*path}                      # Matches: any path

# Mixed examples
uri: /api/{version}/users/{*path}   # Matches: /api/v1/users/123/posts
```

**Parameter Access:**
Route parameters are captured and can be accessed by plugins and upstream services. The parameter names become available in the request context for use by plugins like `proxy-rewrite` or for logging purposes.

#### Host Matching
```yaml
# Single host
host: api.example.com

# Multiple hosts
hosts: ["api.example.com", "www.api.example.com"]
```

#### Method Matching
```yaml
methods: ["GET", "POST", "PUT", "DELETE"]
```

#### Priority-Based Routing
```yaml
routes:
  - id: "specific-route"
    uri: /api/users/admin
    priority: 100  # Higher priority - static routes
    upstream: { ... }
  
  - id: "user-by-id"
    uri: /api/users/{id}
    priority: 50   # Medium priority - named parameter
    upstream: { ... }
  
  - id: "catch-all-route"
    uri: /api/{*path}
    priority: 10   # Lower priority - catch-all
    upstream: { ... }
```

**Route Matching Priority:**
1. **Static routes** (e.g., `/api/users/admin`) - highest priority
2. **Named parameter routes** (e.g., `/api/users/{id}`) - medium priority  
3. **Catch-all routes** (e.g., `/api/{*path}`) - lowest priority
4. **Custom priority** - use the `priority` field to override default ordering

### Route Timeouts

Configure request timeouts:

```yaml
routes:
  - id: "timeout-example"
    uri: /api/{*path}           # Catch-all for /api/* requests
    timeout:
      connect: 5    # Connection timeout (seconds)
      send: 10      # Send timeout (seconds)
      read: 30      # Read timeout (seconds)
    upstream: { ... }
```

## Upstreams

### Basic Upstream Configuration

```yaml
upstreams:
  - id: "backend-pool"
    nodes:
      "server1.example.com:8080": 1    # Weight 1
      "server2.example.com:8080": 2    # Weight 2
      "server3.example.com:8080": 1    # Weight 1
    type: roundrobin
```

### Load Balancing Algorithms

#### Round Robin (Default)
```yaml
type: roundrobin  # Distributes requests evenly
```

#### Random
```yaml
type: random      # Random selection
```

#### Consistent Hashing
```yaml
type: ketama      # Consistent hashing
hash_on: vars     # Hash based on variables
key: uri          # Hash key (uri, cookie, header)
```

#### FNV Hashing
```yaml
type: fnv         # FNV hash algorithm
hash_on: head     # Hash based on headers
key: user-id      # Header name to hash
```

### Health Checks

Configure active health checking:

```yaml
upstreams:
  - id: "monitored-backend"
    nodes:
      "api1.example.com:443": 1
      "api2.example.com:443": 1
    type: roundrobin
    scheme: https
    checks:
      active:
        type: https                    # http, https, or tcp
        timeout: 5                     # Health check timeout
        host: api.example.com          # Host header for health checks
        http_path: /health             # Health check endpoint
        https_verify_certificate: true # Verify SSL certificates
        req_headers: 
          - "User-Agent: PingSIX-HealthCheck/1.0"
        healthy:
          interval: 10                 # Check interval (seconds)
          http_statuses: [200, 201]    # Healthy status codes
          successes: 2                 # Consecutive successes needed
        unhealthy:
          http_failures: 3             # HTTP failures before marking unhealthy
          tcp_failures: 2              # TCP failures before marking unhealthy
```

### Host Header Handling

Control how the Host header is passed to upstream:

```yaml
upstreams:
  - id: "host-rewrite-example"
    nodes:
      "internal-api.local:8080": 1
    pass_host: rewrite              # Options: pass, rewrite
    upstream_host: internal-api.local  # Required when pass_host is rewrite
```

## Services

Services provide reusable configurations:

```yaml
services:
  - id: "user-service"
    hosts: ["users.api.example.com"]
    upstream_id: "user-backend"     # Reference to upstream
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100

routes:
  - id: "user-routes"
    uri: /users/{*path}             # Catch-all for /users/* requests
    service_id: "user-service"      # Reference to service
```

## Global Rules

Apply plugins globally to all requests:

```yaml
global_rules:
  - id: "monitoring"
    plugins:
      prometheus: {}                # Enable metrics collection
      file-logger:                  # Enable access logging
        path: /var/log/pingsix/access.log
        format: '$remote_addr - [$time_local] "$request" $status $body_bytes_sent'
  
  - id: "security"
    plugins:
      cors:                         # Enable CORS for all routes
        allow_origins: "*"
        allow_methods: "GET,POST,PUT,DELETE"
        allow_headers: "*"
```

## Plugins

PingSIX includes 15+ built-in plugins for various functionalities:

### Authentication Plugins

#### JWT Authentication
```yaml
plugins:
  jwt-auth:
    header: authorization           # Header containing JWT
    query: token                   # Query parameter name
    cookie: jwt                    # Cookie name
    secret: "your-secret-key"      # HMAC secret
    algorithm: HS256               # Supported: HS256, HS512, RS256, ES256
    hide_credentials: true         # Remove JWT from request
    store_in_ctx: true            # Store payload in context
```

#### API Key Authentication
```yaml
plugins:
  key-auth:
    header: apikey                 # Header name
    query: apikey                  # Query parameter name
    key: "your-api-key"           # Single key
    # OR multiple keys for rotation
    keys: 
      - "key1"
      - "key2"
      - "key3"
    hide_credentials: false        # Keep credentials in request
```

### Security Plugins

#### IP Restriction
```yaml
plugins:
  ip-restriction:
    whitelist:                     # Allow only these IPs/networks
      - "192.168.1.0/24"
      - "10.0.0.0/8"
    blacklist:                     # Block these IPs/networks
      - "192.168.1.100"
      - "172.16.0.0/12"
    message: "Access denied"       # Custom rejection message
    use_forwarded_headers: true    # Trust X-Forwarded-For headers
    trusted_proxies:               # Trusted proxy networks
      - "10.0.0.0/8"
```

#### CORS (Cross-Origin Resource Sharing)
```yaml
plugins:
  cors:
    allow_origins: "https://example.com,https://app.example.com"
    allow_methods: "GET,POST,PUT,DELETE,OPTIONS"
    allow_headers: "Content-Type,Authorization,X-Requested-With"
    expose_headers: "X-Request-ID"
    max_age: 86400                 # Preflight cache time
    allow_credential: true         # Allow credentials
    allow_origins_by_regex:        # Regex patterns for origins
      - "https://.*\\.example\\.com"
```

### Rate Limiting

#### Request Rate Limiting
```yaml
plugins:
  limit-count:
    key_type: vars                 # vars, head, cookie
    key: remote_addr              # Key to rate limit on
    time_window: 60               # Time window in seconds
    count: 100                    # Max requests per window
    rejected_code: 429            # HTTP status for rejected requests
    rejected_msg: "Rate limit exceeded"
    show_limit_quota_header: true # Include rate limit headers
    key_missing_policy: allow     # allow, deny, default
```

### Traffic Management

#### Request/Response Modification
```yaml
plugins:
  proxy-rewrite:
    uri: /new/path                # Rewrite request URI
    method: POST                  # Change HTTP method
    host: new-host.example.com    # Change Host header
    headers:                      # Add/modify headers
      X-Custom-Header: "custom-value"
      X-Forwarded-Proto: "https"
    regex_uri:                    # Regex-based URI rewriting
      - "^/old/(.*)"              # Pattern
      - "/new/$1"                 # Replacement
```

#### Redirect
```yaml
plugins:
  redirect:
    http_to_https: true           # Redirect HTTP to HTTPS
    ret_code: 301                 # Redirect status code
    uri: /new-location            # Static redirect
    append_query_string: true     # Preserve query parameters
    regex_uri:                    # Regex-based redirects
      - "^/old/(.*)"
      - "/new/$1"
```

### Compression

#### Gzip Compression
```yaml
plugins:
  gzip:
    min_length: 1024              # Minimum response size to compress
    comp_level: 6                 # Compression level (1-9)
    types:                        # MIME types to compress
      - "text/html"
      - "application/json"
      - "text/css"
```

#### Brotli Compression
```yaml
plugins:
  brotli:
    min_length: 1024
    comp_level: 6                 # Compression level (1-11)
    types:
      - "text/html"
      - "application/json"
```

### Caching

#### Response Caching
```yaml
plugins:
  cache:
    ttl: 3600                     # Cache TTL in seconds
    cache_http_methods: ["GET", "HEAD"]
    cache_http_statuses: [200, 301, 404]
    no_cache_str:                 # Regex patterns to skip caching
      - ".*private.*"
      - ".*no-cache.*"
    vary: ["Accept-Encoding"]     # Vary headers for cache keys
    hide_cache_headers: false     # Hide cache-related headers
    max_file_size_bytes: 1048576  # Max cacheable response size
```

### Observability

#### Prometheus Metrics
```yaml
plugins:
  prometheus:
    prefer_name: true             # Use route names in metrics
```

#### File Logging
```yaml
plugins:
  file-logger:
    path: /var/log/pingsix/access.log
    format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time'
```

#### Request ID
```yaml
plugins:
  request-id:
    header_name: X-Request-ID     # Header name for request ID
    include_in_response: true     # Include in response headers
    algorithm: uuid4              # uuid4 or snowflake
```

### Utility Plugins

#### Echo (Testing)
```yaml
plugins:
  echo:
    body: "Hello, World!"         # Response body
    headers:                      # Response headers
      Content-Type: "text/plain"
      X-Echo: "true"
```

#### gRPC Web
```yaml
plugins:
  grpc-web: {}                    # Enable gRPC-Web support
```

## Admin API

The Admin API allows dynamic configuration management when etcd is enabled.

### Configuration

```yaml
pingsix:
  etcd:
    host: ["http://127.0.0.1:2379"]
    prefix: /pingsix
  
  admin:
    address: "0.0.0.0:9181"
    api_key: "your-secure-api-key"
```

### API Endpoints

All Admin API requests require the `X-API-KEY` header:

```bash
curl -H "X-API-KEY: your-secure-api-key" \
     -H "Content-Type: application/json" \
     http://127.0.0.1:9181/apisix/admin/routes/1
```

#### Routes Management

**Create/Update Route**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/*",
    "host": "api.example.com",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend1.example.com:8080": 1,
        "backend2.example.com:8080": 1
      }
    },
    "plugins": {
      "limit-count": {
        "key_type": "vars",
        "key": "remote_addr",
        "time_window": 60,
        "count": 100
      }
    }
  }'
```

**Get Route**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key"
```

**Delete Route**:
```bash
curl -X DELETE http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-api-key"
```

#### Upstreams Management

**Create/Update Upstream**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/upstreams/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "roundrobin",
    "nodes": {
      "backend1.example.com:8080": 1,
      "backend2.example.com:8080": 2
    },
    "checks": {
      "active": {
        "type": "http",
        "http_path": "/health",
        "healthy": {
          "interval": 10,
          "successes": 2
        },
        "unhealthy": {
          "http_failures": 3
        }
      }
    }
  }'
```

#### Services Management

**Create/Update Service**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/services/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "upstream_id": "1",
    "plugins": {
      "jwt-auth": {
        "secret": "your-jwt-secret"
      }
    }
  }'
```

#### Global Rules Management

**Create/Update Global Rule**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/global_rules/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "plugins": {
      "prometheus": {},
      "cors": {
        "allow_origins": "*",
        "allow_methods": "GET,POST,PUT,DELETE"
      }
    }
  }'
```

#### SSL Certificates Management

**Create/Update SSL Certificate**:
```bash
curl -X PUT http://127.0.0.1:9181/apisix/admin/ssls/1 \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "snis": ["example.com", "www.example.com"]
  }'
```

## SSL/TLS Configuration

### Static SSL Configuration

Configure SSL certificates in the configuration file:

```yaml
pingsix:
  listeners:
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/certs/server.crt
        key_path: /etc/ssl/private/server.key
      offer_h2: true

ssls:
  - id: "example-com-cert"
    cert: |
      -----BEGIN CERTIFICATE-----
      MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
      ...
      -----END CERTIFICATE-----
    key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGtJmWmWWKvO
      ...
      -----END PRIVATE KEY-----
    snis: ["example.com", "www.example.com"]
```

### Dynamic SSL with SNI

When using etcd, SSL certificates can be loaded dynamically based on Server Name Indication (SNI):

```bash
# Add certificate via Admin API
curl -X PUT http://127.0.0.1:9181/apisix/admin/ssls/example-com \
  -H "X-API-KEY: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "snis": ["example.com", "*.example.com"]
  }'
```

## Monitoring and Observability

### Prometheus Metrics

Enable Prometheus metrics collection:

```yaml
pingsix:
  prometheus:
    address: 0.0.0.0:9091

global_rules:
  - id: "metrics"
    plugins:
      prometheus: {}
```

Available metrics include:
- Request count by route, status code, method
- Request duration histograms
- Upstream response times
- Active connections
- Bandwidth usage

### Sentry Integration

Configure Sentry for error tracking:

```yaml
pingsix:
  sentry:
    dsn: "https://your-dsn@sentry.io/project-id"
```

### File Logging

Configure access logging:

```yaml
pingsix:
  log:
    path: /var/log/pingsix/access.log

global_rules:
  - id: "logging"
    plugins:
      file-logger:
        path: /var/log/pingsix/access.log
        format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_response_time'
```

Available log variables:
- `$remote_addr` - Client IP address
- `$remote_user` - Remote user (if authenticated)
- `$time_local` - Local time
- `$request` - Full request line
- `$status` - Response status code
- `$body_bytes_sent` - Response body size
- `$http_referer` - Referer header
- `$http_user_agent` - User-Agent header
- `$request_time` - Total request processing time
- `$upstream_response_time` - Upstream response time

## Examples

### Example 1: Simple API Gateway

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080

routes:
  - id: "api-gateway"
    uri: /api/{*path}               # Catch-all for /api/* requests
    upstream:
      nodes:
        "api-server1.example.com:8080": 1
        "api-server2.example.com:8080": 1
      type: roundrobin
      checks:
        active:
          type: http
          http_path: /health
          healthy:
            interval: 10
            successes: 2
          unhealthy:
            http_failures: 3
```

### Example 2: Multi-Service Architecture

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:80
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

upstreams:
  - id: "user-service"
    nodes:
      "user-api1.internal:8080": 1
      "user-api2.internal:8080": 1
    type: roundrobin
    
  - id: "order-service"
    nodes:
      "order-api1.internal:8080": 1
      "order-api2.internal:8080": 1
    type: roundrobin

services:
  - id: "authenticated-service"
    upstream_id: "user-service"
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
        algorithm: HS256
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 1000

routes:
  - id: "user-api"
    uri: /api/users/{*path}         # Catch-all for /api/users/* requests
    host: api.example.com
    service_id: "authenticated-service"
    
  - id: "order-api"
    uri: /api/orders/{*path}        # Catch-all for /api/orders/* requests
    host: api.example.com
    upstream_id: "order-service"
    plugins:
      key-auth:
        key: "order-service-key"

global_rules:
  - id: "monitoring"
    plugins:
      prometheus: {}
      cors:
        allow_origins: "https://app.example.com"
        allow_methods: "GET,POST,PUT,DELETE"
        allow_credentials: true
```

### Example 3: High-Performance Caching Gateway

```yaml
pingora:
  version: 1
  threads: 8

pingsix:
  listeners:
    - address: 0.0.0.0:80
  
  prometheus:
    address: 0.0.0.0:9091

upstreams:
  - id: "cdn-origin"
    nodes:
      "origin1.example.com:80": 1
      "origin2.example.com:80": 1
    type: roundrobin
    checks:
      active:
        type: http
        http_path: /health
        healthy:
          interval: 30
          successes: 2
        unhealthy:
          http_failures: 3

routes:
  - id: "static-assets"
    uri: /static/{*filepath}        # Catch-all for /static/* requests
    upstream_id: "cdn-origin"
    plugins:
      cache:
        ttl: 86400  # 24 hours
        cache_http_methods: ["GET", "HEAD"]
        cache_http_statuses: [200, 301, 404]
        vary: ["Accept-Encoding"]
      gzip:
        min_length: 1024
        comp_level: 6
        types:
          - "text/css"
          - "application/javascript"
          - "text/html"
  
  - id: "api-content"
    uri: /api/{*path}               # Catch-all for /api/* requests
    upstream_id: "cdn-origin"
    plugins:
      cache:
        ttl: 300  # 5 minutes
        cache_http_methods: ["GET"]
        cache_http_statuses: [200]
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100

global_rules:
  - id: "observability"
    plugins:
      prometheus: {}
      request-id:
        header_name: X-Request-ID
        include_in_response: true
```

### Example 4: Microservices with Authentication

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:443
      tls:
        cert_path: /etc/ssl/api.crt
        key_path: /etc/ssl/api.key
      offer_h2: true
  
  etcd:
    host: ["http://etcd1:2379", "http://etcd2:2379"]
    prefix: /pingsix
  
  admin:
    address: "0.0.0.0:9181"
    api_key: "secure-admin-key"

upstreams:
  - id: "auth-service"
    nodes:
      "auth-svc.k8s.local:8080": 1
    type: roundrobin
    
  - id: "user-service"
    nodes:
      "user-svc.k8s.local:8080": 1
    type: roundrobin
    
  - id: "payment-service"
    nodes:
      "payment-svc.k8s.local:8080": 1
    type: roundrobin

routes:
  # Public authentication endpoint
  - id: "auth-login"
    uri: /auth/login
    host: api.example.com
    methods: ["POST"]
    upstream_id: "auth-service"
    plugins:
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 300
        count: 5  # 5 login attempts per 5 minutes
  
  # Protected user endpoints
  - id: "user-api"
    uri: /api/users/{*path}         # Catch-all for /api/users/* requests
    host: api.example.com
    upstream_id: "user-service"
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
        algorithm: HS256
        store_in_ctx: true
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100
  
  # High-security payment endpoints
  - id: "payment-api"
    uri: /api/payments/{*path}      # Catch-all for /api/payments/* requests
    host: api.example.com
    upstream_id: "payment-service"
    plugins:
      jwt-auth:
        secret: "your-jwt-secret"
        algorithm: HS256
      ip-restriction:
        whitelist: ["10.0.0.0/8", "192.168.0.0/16"]
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 10  # Strict rate limiting

global_rules:
  - id: "security-headers"
    plugins:
      proxy-rewrite:
        headers:
          X-Frame-Options: "DENY"
          X-Content-Type-Options: "nosniff"
          X-XSS-Protection: "1; mode=block"
          Strict-Transport-Security: "max-age=31536000; includeSubDomains"
  
  - id: "monitoring"
    plugins:
      prometheus: {}
      file-logger:
        path: /var/log/pingsix/access.log
        format: '$remote_addr - [$time_local] "$request" $status $body_bytes_sent $request_time'
```

## Troubleshooting

### Common Issues

#### 1. Route Not Matching

**Problem**: Requests are not matching expected routes.

**Solutions**:
- Check route priority - higher priority routes are matched first
- Verify URI patterns - use `/path/{*subpath}` for catch-all matching or `/path/{id}` for named parameters
- Check host matching - ensure host headers match exactly
- Review method restrictions
- Remember that static routes have higher priority than dynamic routes

```yaml
# Debug route matching
routes:
  - id: "debug-route"
    uri: /debug/{*path}             # Catch-all for /debug/* requests
    priority: 1000  # High priority for debugging
    plugins:
      echo:
        body: "Route matched successfully"
```

#### 2. Upstream Connection Failures

**Problem**: 502 Bad Gateway or connection timeouts.

**Solutions**:
- Verify upstream server addresses and ports
- Check network connectivity from PingSIX to upstream
- Review timeout configurations
- Enable health checks to monitor upstream status

```yaml
# Debug upstream connectivity
upstreams:
  - id: "debug-upstream"
    nodes:
      "upstream-server:8080": 1
    timeout:
      connect: 10
      send: 30
      read: 30
    checks:
      active:
        type: http
        http_path: /health
        timeout: 5
```

#### 3. Plugin Configuration Errors

**Problem**: Plugins not working as expected.

**Solutions**:
- Validate plugin configuration syntax
- Check plugin execution order (priority)
- Review plugin-specific requirements
- Enable debug logging

```yaml
# Plugin debugging
plugins:
  file-logger:
    path: /tmp/debug.log
    format: 'Plugin Debug: $request_id $status $upstream_response_time'
```

#### 4. SSL/TLS Issues

**Problem**: SSL handshake failures or certificate errors.

**Solutions**:
- Verify certificate and key file paths
- Check certificate validity and expiration
- Ensure SNI configuration matches certificate domains
- Validate certificate chain completeness

#### 5. Performance Issues

**Problem**: High latency or low throughput.

**Solutions**:
- Increase thread count in pingora configuration
- Optimize upstream connection pooling
- Enable compression for large responses
- Use caching for frequently accessed content
- Monitor resource usage (CPU, memory, network)

### Debug Configuration

Enable detailed logging for troubleshooting:

```yaml
pingsix:
  log:
    path: /var/log/pingsix/debug.log

global_rules:
  - id: "debug-logging"
    plugins:
      file-logger:
        path: /var/log/pingsix/debug.log
        format: 'DEBUG: $remote_addr $request_method $uri $status $request_time $upstream_addr $upstream_response_time'
```

### Health Check Monitoring

Monitor upstream health status:

```yaml
upstreams:
  - id: "monitored-upstream"
    nodes:
      "server1:8080": 1
      "server2:8080": 1
    checks:
      active:
        type: http
        http_path: /health
        timeout: 5
        req_headers: ["X-Health-Check: PingSIX"]
        healthy:
          interval: 10
          http_statuses: [200]
          successes: 2
        unhealthy:
          interval: 5
          http_failures: 3
          tcp_failures: 2
```

### Performance Tuning

Optimize PingSIX performance:

```yaml
pingora:
  version: 1
  threads: 8              # Match CPU cores
  work_stealing: true     # Enable work stealing
  
pingsix:
  listeners:
    - address: 0.0.0.0:80
      tcp_fast_open: true  # Enable TCP Fast Open
      tcp_keepalive: 600   # TCP keepalive timeout
```

For additional support and advanced configuration options, refer to the [PingSIX Documentation](https://deepwiki.com/zhu327/pingsix) or open an issue on the GitHub repository.
