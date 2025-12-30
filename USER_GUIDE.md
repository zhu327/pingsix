# PingSIX API Gateway - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Core Concepts](#core-concepts)
4. [Configuration](#configuration)
5. [Docker Deployment](#docker-deployment)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Routing](#routing)
8. [Upstreams](#upstreams)
9. [Services](#services)
10. [Global Rules](#global-rules)
11. [Plugins](#plugins)
12. [Admin API](#admin-api)
13. [SSL/TLS Configuration](#ssltls-configuration)
14. [Monitoring and Observability](#monitoring-and-observability)
15. [Examples](#examples)
16. [Troubleshooting](#troubleshooting)

## Introduction

PingSIX is a high-performance API gateway built with Rust, designed for modern cloud-native environments. It provides advanced routing, load balancing, security, and observability features with excellent performance and reliability.

### Key Features

- **High Performance**: Built with Rust and Tokio for exceptional throughput and low latency
- **Dynamic Configuration**: Real-time configuration updates via etcd integration
- **Flexible Routing**: Advanced request matching based on host, path, methods, and priorities
- **Rich Plugin Ecosystem**: 16+ built-in plugins for authentication, rate limiting, compression, and more
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

#### Hot Reload & Atomic Resource Swaps

When etcd pushes an update the watcher pipeline performs the following steps:

1. Deserialize the new resource set (routes, upstreams, services, rules, SSLs) in-memory.
2. Validate IDs and plugin payloads exactly the same way as the bootstrap path.
3. Swap the active data structure via `ArcSwap::store` (`reload_resources()` on each registry).
   Readers always operate on an `Arc` snapshot, so they never observe partial state.
4. Update the shared health-check registry by unregistering removed upstream IDs before registering
   new ones. The executor reacts to `RegistryUpdate` events so probes are restarted with the latest
   options.

If validation fails at any step the old snapshot stays in place and the error is logged—no reload
occurs until etcd provides a valid payload. This gives PingSIX an implicit rollback strategy where
operators simply fix the broken config and re-publish; traffic continues to flow using the previous
revision throughout the failure window.

## Docker Deployment

PingSIX provides a multi-stage Docker build for efficient containerized deployment. The Docker image is optimized for production use with minimal attack surface and resource consumption.

### Building the Docker Image

Build the PingSIX Docker image from the project root:

```bash
# Build the Docker image
docker build -t pingsix:latest .

# Build for multiple architectures (if using buildx)
docker buildx build --platform linux/amd64,linux/arm64 -t pingsix:latest .
```

### Docker Image Features

The PingSIX Docker image includes:

- **Multi-stage build**: Optimized build process with dependency caching
- **Minimal runtime**: Based on Debian Bookworm Slim for security and size
- **Non-root user**: Runs as `pingsix` user for enhanced security
- **Pre-configured directories**: Logging and runtime directories with proper permissions
- **Exposed ports**: 8080 (HTTP), 9091 (Prometheus), 9181 (Admin API)

### Running PingSIX with Docker

#### Basic Usage

```bash
# Run with default configuration
docker run -d --name pingsix \
  -p 8080:8080 \
  -p 9091:9091 \
  -p 9181:9181 \
  pingsix:latest

# Run with custom configuration
docker run -d --name pingsix \
  -p 8080:8080 \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  pingsix:latest

# Run with custom configuration and log persistence
docker run -d --name pingsix \
  -p 8080:8080 \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  -v /path/to/logs:/var/log/pingsix \
  pingsix:latest
```

#### Docker Compose Deployment

Create a `docker-compose.yml` file for easy deployment:

```yaml
version: '3.8'

services:
  pingsix:
    image: pingsix:latest
    container_name: pingsix
    restart: unless-stopped
    ports:
      - "80:8080"      # HTTP traffic
      - "443:8443"     # HTTPS traffic (if configured)
      - "9091:9091"    # Prometheus metrics
      - "9181:9181"    # Admin API
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./ssl:/etc/ssl:ro                    # SSL certificates
      - pingsix-logs:/var/log/pingsix        # Log persistence
    environment:
      - RUST_LOG=info
    networks:
      - pingsix-network

  # Optional: etcd for dynamic configuration
  etcd:
    image: quay.io/coreos/etcd:v3.5.9
    container_name: pingsix-etcd
    restart: unless-stopped
    ports:
      - "2379:2379"
      - "2380:2380"
    environment:
      - ETCD_NAME=etcd1
      - ETCD_DATA_DIR=/etcd-data
      - ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379
      - ETCD_ADVERTISE_CLIENT_URLS=http://etcd:2379
      - ETCD_LISTEN_PEER_URLS=http://0.0.0.0:2380
      - ETCD_INITIAL_ADVERTISE_PEER_URLS=http://etcd:2380
      - ETCD_INITIAL_CLUSTER=etcd1=http://etcd:2380
      - ETCD_INITIAL_CLUSTER_TOKEN=etcd-cluster-1
      - ETCD_INITIAL_CLUSTER_STATE=new
    volumes:
      - etcd-data:/etcd-data
    networks:
      - pingsix-network

volumes:
  pingsix-logs:
  etcd-data:

networks:
  pingsix-network:
    driver: bridge
```

Run the stack:

```bash
# Start the services
docker-compose up -d

# View logs
docker-compose logs -f pingsix

# Stop the services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Configuration Best Practices

#### Volume Mounts

```yaml
volumes:
  # Configuration (read-only)
  - ./config.yaml:/app/config.yaml:ro
  
  # SSL certificates (read-only)
  - ./ssl:/etc/ssl:ro
  
  # Logs (read-write)
  - ./logs:/var/log/pingsix
```

#### Environment Variables

```bash
# Logging level
RUST_LOG=info
```

## Kubernetes Deployment

PingSIX provides Helm charts for easy deployment in Kubernetes environments. The Helm chart supports three deployment modes to fit different use cases:

1. **Ingress Controller Mode**: Full Kubernetes Ingress controller with dynamic configuration
2. **etcd Mode**: Standalone gateway with etcd for dynamic configuration management
3. **Static Configuration Mode**: Standalone gateway with static YAML configuration

### Prerequisites

- Kubernetes cluster (v1.19+)
- Helm 3.x installed
- kubectl configured to access your cluster

### Installation

First, clone the PingSIX Helm chart repository:

```bash
git clone https://github.com/zhu327/pingsix-helm-chart.git
cd pingsix-helm-chart/charts
```

### Deployment Mode 1: Ingress Controller Mode

This mode enables PingSIX to work as a Kubernetes Ingress controller, automatically synchronizing Ingress, Gateway API, and custom resources (ApisixRoute, ApisixUpstream, etc.) to configure routes dynamically.

**Features:**
- Full Kubernetes Ingress controller functionality
- Support for Gateway API, Ingress, and APISIX custom resources
- Automatic configuration synchronization from Kubernetes resources
- No etcd required (uses in-memory configuration)

**Installation:**

```bash
helm install apisix \
  --namespace ingress-apisix \
  --create-namespace \
  --set etcd.enabled=false \
  --set ingress-controller.enabled=true \
  --set ingress-controller.gatewayProxy.createDefault=true \
  ./apisix
```

**Configuration:**

When using Ingress controller mode, you manage routes through Kubernetes resources instead of YAML configuration files.

#### Using Gateway API

First, configure the GatewayClass and Gateway resources:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  namespace: ingress-apisix
  name: apisix
spec:
  controllerName: apisix.apache.org/apisix-ingress-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  namespace: ingress-apisix
  name: apisix
spec:
  gatewayClassName: apisix
  listeners:
  - name: http
    protocol: HTTP
    port: 80
  infrastructure:
    parametersRef:
      group: apisix.apache.org
      kind: GatewayProxy
      name: apisix-config
```

Then create an HTTPRoute to configure routing:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  namespace: ingress-apisix
  name: httpbin-route
spec:
  parentRefs:
  - name: apisix
  rules:
  - matches:
    - path:
        type: Exact
        value: /ip
    backendRefs:
    - name: httpbin
      port: 80
```

#### Using Kubernetes Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  namespace: ingress-apisix
  name: httpbin-ingress
spec:
  ingressClassName: apisix
  rules:
    - http:
        paths:
          - backend:
              service:
                name: httpbin
                port:
                  number: 80
            path: /ip
            pathType: Exact
```

#### Using APISIX Custom Resources

```yaml
apiVersion: apisix.apache.org/v2
kind: ApisixRoute
metadata:
  namespace: ingress-apisix
  name: httpbin-route
spec:
  ingressClassName: apisix
  http:
    - name: getting-started-ip
      match:
        paths:
          - /ip
      backends:
        - serviceName: httpbin
          servicePort: 80
      plugins:
        - name: limit-count
          enable: true
          config:
            key_type: vars
            key: remote_addr
            time_window: 60
            count: 100
```

**More Examples:**

For detailed Ingress controller examples and configuration, refer to the official Apache APISIX Ingress Controller documentation:
- [Configure Routes](https://apisix.apache.org/zh/docs/ingress-controller/getting-started/configure-routes/)
- [Load Balancing](https://apisix.apache.org/docs/ingress-controller/tutorials/load-balancing)
- [Authentication](https://apisix.apache.org/docs/ingress-controller/tutorials/authentication)

### Deployment Mode 2: etcd Mode

This mode deploys PingSIX with etcd for dynamic configuration management via the Admin API.

**Features:**
- Dynamic configuration updates via Admin API
- etcd-based configuration persistence
- Suitable for traditional API gateway deployments

**Installation:**

```bash
helm install apisix \
  --namespace pingsix \
  --create-namespace \
  --set etcd.enabled=true \
  --set ingress-controller.enabled=false \
  --set pingsix.admin.enabled=true \
  --set pingsix.admin.apiKey="your-secure-api-key" \
  ./apisix
```

**Configuration via Admin API:**

After installation, you can manage routes dynamically using the Admin API:

```bash
# Port forward to access Admin API
kubectl port-forward -n pingsix svc/apisix-admin 9181:9181

# Create a route
curl -X PUT http://127.0.0.1:9181/apisix/admin/routes/1 \
  -H "X-API-KEY: your-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/*",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend-service.default.svc.cluster.local:8080": 1
      }
    }
  }'
```

**Custom Values:**

Create a `values-etcd.yaml` file:

```yaml
etcd:
  enabled: true
  auth:
    rbac:
      create: true
      rootPassword: "your-etcd-password"

pingsix:
  admin:
    enabled: true
    apiKey: "your-secure-api-key"
    address: "0.0.0.0:9181"
  
  prometheus:
    enabled: true
    address: "0.0.0.0:9091"

  listeners:
    - address: "0.0.0.0:8080"
      offerH2c: false
```

Install with custom values:

```bash
helm install apisix \
  --namespace pingsix \
  --create-namespace \
  -f values-etcd.yaml \
  ./apisix
```

### Deployment Mode 3: Static Configuration Mode

This mode deploys PingSIX with static YAML configuration, suitable for simple deployments or when etcd is managed externally.

**Features:**
- Simple deployment with static configuration
- No etcd dependency (use external etcd or static config)
- Configuration updates require pod restart

**Installation with Static Configuration:**

Create a `values-static.yaml` file:

```yaml
etcd:
  enabled: false

ingress-controller:
  enabled: false

pingsix:
  listeners:
    - address: "0.0.0.0:8080"
      offerH2c: false

routes:
  - id: "1"
    uri: /api/{*path}
    upstream:
      nodes:
        "backend-service.default.svc.cluster.local:8080": 1
      type: roundrobin
    plugins:
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100

globalRules:
  - id: "1"
    plugins:
      prometheus: {}
```

Install with static configuration:

```bash
helm install apisix \
  --namespace pingsix \
  --create-namespace \
  -f values-static.yaml \
  ./apisix
```

**Installation with External etcd:**

If you have an external etcd cluster:

```yaml
etcd:
  enabled: false

externalEtcd:
  host:
    - "http://etcd-cluster.etcd.svc.cluster.local:2379"
  user: "root"
  password: "your-password"

pingsix:
  admin:
    enabled: true
    apiKey: "your-secure-api-key"
```

### Common Helm Configuration Options

#### Scaling and Resources

```yaml
# Use DaemonSet for node-level deployment
useDaemonSet: true

# Or use Deployment with replicas
useDaemonSet: false
replicaCount: 3

# Enable autoscaling
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

# Resource requests and limits
resources:
  limits:
    cpu: 1000m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi
```

#### Service Configuration

```yaml
service:
  type: LoadBalancer  # Options: ClusterIP, NodePort, LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
  externalTrafficPolicy: Local  # Preserve client source IP
```

#### TLS/SSL Configuration

```yaml
pingsix:
  listeners:
    - address: "0.0.0.0:8080"
    - address: "0.0.0.0:8443"
      tls:
        # Use Kubernetes Secret for certificates
        secretName: pingsix-tls
        # Or use custom filenames in secret
        certFilename: tls.crt
        keyFilename: tls.key
      offerH2: true
```

Create the TLS secret:

```bash
kubectl create secret tls pingsix-tls \
  --cert=server.crt \
  --key=server.key \
  -n pingsix
```

#### Monitoring and Observability

```yaml
pingsix:
  prometheus:
    enabled: true
    address: "0.0.0.0:9091"

metrics:
  serviceMonitor:
    enabled: true
    interval: 15s
    labels:
      release: prometheus

pingsix:
  sentry:
    enabled: true
    dsn: "https://your-dsn@sentry.io/project-id"
```

### Accessing PingSIX

#### Port Forward

```bash
# Access gateway
kubectl port-forward -n pingsix svc/apisix-gateway 8080:80

# Access Admin API (if enabled)
kubectl port-forward -n pingsix svc/apisix-admin 9181:9181

# Access Prometheus metrics (if enabled)
kubectl port-forward -n pingsix svc/apisix-gateway 9091:9091
```

#### Using Ingress

```yaml
ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: nginx
  hosts:
    - host: pingsix.example.com
      paths:
        - /
  tls:
    - secretName: pingsix-ingress-tls
      hosts:
        - pingsix.example.com
```

### Upgrading

```bash
# Update chart repository
cd pingsix-helm-chart
git pull

# Upgrade with new configuration
helm upgrade apisix \
  --namespace pingsix \
  -f values.yaml \
  ./charts/apisix

# Check upgrade status
helm history apisix -n pingsix
```

### Uninstalling

```bash
# Uninstall PingSIX
helm uninstall apisix -n pingsix

# Delete namespace (optional)
kubectl delete namespace pingsix
```

### Troubleshooting Kubernetes Deployment

#### Check Pod Status

```bash
kubectl get pods -n pingsix
kubectl describe pod <pod-name> -n pingsix
kubectl logs <pod-name> -n pingsix
```

#### Check Configuration

```bash
# View ConfigMap
kubectl get configmap -n pingsix
kubectl describe configmap apisix -n pingsix

# View generated config
kubectl get configmap apisix -n pingsix -o yaml
```

#### Debug Connection Issues

```bash
# Test internal connectivity
kubectl run -n pingsix test-pod --image=curlimages/curl --rm -it -- sh

# Inside the pod
curl http://apisix-gateway:80/health
```

#### Check Service Endpoints

```bash
kubectl get endpoints -n pingsix
kubectl get svc -n pingsix
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
- A route must have at least one URI pattern defined, using either the `uri` field for a single pattern or the `uris` field for multiple patterns.
- Use `{parameter_name}` for named parameters that capture a single path segment.
- Use `{*parameter_name}` for catch-all parameters that capture the remaining path.
- Catch-all parameters must be at the end of the path.
- Only one parameter is allowed per path segment.
- Static routes have higher priority than dynamic routes.

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

### Request Retries

Configure automatic retries on connection failures:

```yaml
upstreams:
  - id: "backend-with-retry"
    nodes:
      "unstable-server.example.com:8080": 1
    retries: 3           # Number of retry attempts on connection failure
    retry_timeout: 5     # Total time in seconds allowed for all retry attempts
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

#### Shared Health Check Lifecycle

PingSIX runs all upstream health checks through a single global executor (`SHARED_HEALTH_CHECK_SERVICE`)
so workers do not duplicate TCP/TLS probes. The lifecycle looks like:

```
┌──────────┐   register_upstream()   ┌──────────────────────┐
│  Config  │ ─────────────────────▶  │ HealthCheckRegistry  │
│ (route & │                         │  (DashMap + events)  │
│ upstream)│ ◀────────────────────── └─────────┬────────────┘
└──────────┘    unregister_upstream()          │broadcast
                                               │RegistryUpdate
                                               ▼
                                     ┌──────────────────────┐
                                     │ HealthCheckExecutor │
                                     │  tokio task router  │
                                     └─────────┬────────────┘
                                               │spawn
                                               ▼
                                     ┌──────────────────────┐
                                     │ LoadBalancer task   │
                                     │ (one per upstream) │
                                     └──────────────────────┘
```

- Registering an upstream pushes a `RegistryUpdate::Added` event; the executor spawns a tokio task
  that runs the Pingora load balancer's active probe loop until the shutdown channel flips.
- Removing or replacing an upstream sends `RegistryUpdate::Removed`, and the executor aborts the
  previous task before the new configuration is applied.
- During graceful shutdown the executor listens on `ShutdownWatch` so every probe stops cleanly.

Because registrations are idempotent, updating an upstream simply unregisters the old task and
installs the new one with fresh thresholds and destinations.

### Host Header Handling

Control how the Host header is passed to upstream:

```yaml
upstreams:
  - id: "host-rewrite-example"
    nodes:
      "internal-api.local:8080": 1
    pass_host: rewrite              # Options: pass, rewrite, node
    upstream_host: internal-api.local  # Required when pass_host is rewrite
```

**Pass Host Options:**
- **`pass`** (default): Pass the client's original Host header to the upstream
- **`rewrite`**: Replace the Host header with the value specified in `upstream_host`
- **`node`**: Use the upstream node's hostname as the Host header

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
        log_format: '$remote_addr - [$time_local] "$request" $status $body_bytes_sent'
  
  - id: "security"
    plugins:
      cors:                         # Enable CORS for all routes
        allow_origins: "*"
        allow_methods: "GET,POST,PUT,DELETE"
        allow_headers: "*"
```

## Plugins

PingSIX includes 16+ built-in plugins for various functionalities:

### Authentication Plugins

#### JWT Authentication
```yaml
plugins:
  jwt-auth:
    header: authorization        # Header containing JWT
    query: token                # Query parameter name
    cookie: jwt                 # Cookie name
    # For HMAC algorithms (HS256, HS512)
    secret: "your-secret-key"
    base64_secret: false        # Set to true if the secret is base64 encoded
    # For RSA/ECDSA algorithms (RS256, ES256)
    public_key: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    algorithm: HS256            # Supported: HS256, HS512, RS256, ES256
    lifetime_grace_period: 60   # Optional: 60 seconds grace period for token expiration
    hide_credentials: true      # Remove JWT from request
    store_in_ctx: true         # Store payload in context
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

#### Basic Authentication
```yaml
plugins:
  basic-auth:
    username: "admin"              # Username for authentication
    password: "secret"             # Password for authentication
    hide_credentials: true         # Remove Authorization header from upstream request
```

**Basic Authentication Features:**
- **Simple Credentials**: Username and password-based authentication
- **HTTP 401 Response**: Returns 401 Unauthorized with `WWW-Authenticate: Basic realm="pingsix"` header on invalid credentials
- **Constant-Time Comparison**: Uses constant-time string comparison to prevent timing attacks
- **Credential Hiding**: Optionally removes Authorization header before forwarding to upstream services
- **Standard Compliance**: Follows RFC 7617 HTTP Basic Authentication specification

**Common Use Cases:**
- Protecting development or staging environments
- Internal service authentication
- Simple API access control

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

#### CSRF (Cross-Site Request Forgery Protection)
```yaml
plugins:
  csrf:
    key: "your-csrf-secret-key"    # Secret key for token generation and validation
    expires: 7200                  # Token expiration time in seconds (default: 7200)
    name: "pingsix-csrf-token"     # Cookie/header name for CSRF token (default: pingsix-csrf-token)
```

**CSRF Protection Features:**
- **Double Submit Cookie Pattern**: Validates that token in header matches token in cookie
- **Token Expiration**: Automatically expires tokens based on configured TTL
- **Signature Validation**: Uses SHA256 to sign tokens with configurable secret key
- **Safe Methods**: Skips validation for GET, HEAD, and OPTIONS requests
- **Automatic Token Generation**: Generates and distributes tokens in response cookies
- **SameSite Cookie**: Sets SameSite=Lax for enhanced security

**Token Validation Flow:**
1. Client receives token in response cookie and header
2. For state-changing requests (POST, PUT, DELETE, PATCH), client must include token in request header
3. Server validates:
   - Token is present in both cookie and header
   - Cookie and header tokens match
   - Token signature is valid
   - Token has not expired

**Common Use Cases:**
- Protecting form submissions from CSRF attacks
- Securing API endpoints that modify data
- Web application security in traditional request-response patterns

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

#### Traffic Split (A/B Testing & Canary Deployment)
```yaml
plugins:
  traffic-split:
    rules:
      - vars:                                  # Match conditions (optional)
          - ["arg_version", "==", "v2"]        # Query parameter match
          - ["http_x-user-type", "==", "beta"] # Header match
        weighted_upstreams:
          - upstream_id: "backend-v2"          # Reference to existing upstream
            weight: 50                         # 50% traffic
          - upstream:                          # Or inline upstream definition
              nodes:
                "canary-server:8080": 1
              type: roundrobin
            weight: 50                         # 50% traffic
      
      - vars: []                               # Default rule (matches all)
        weighted_upstreams:
          - upstream_id: "stable-backend"
            weight: 90                         # 90% to stable
          - upstream_id: "canary-backend"
            weight: 10                         # 10% to canary
```

**Traffic Split Features:**
- **Weighted Distribution**: Distribute traffic across multiple upstreams based on weights
- **Conditional Routing**: Match requests based on query parameters, headers, or cookies
- **Variable Matching**: Support for `==` (equals) and `!=` (not equals) operators
- **Inline or Referenced Upstreams**: Use `upstream_id` to reference existing upstreams or define inline
- **Default Fallback**: If weight doesn't specify an upstream, falls back to route's default upstream

**Common Use Cases:**
- A/B testing different backend versions
- Canary deployments with gradual traffic shifting
- Blue-green deployments
- Feature flag-based routing

#### Request Modification (Proxy Rewrite)
```yaml
plugins:
  proxy-rewrite:
    uri: /new/path                # Rewrite request URI
    method: POST                  # Change HTTP method
    host: new-host.example.com    # Change Host header
    headers:                      # Add/modify/remove headers
      set:
        - name: "X-Header-To-Set"
          value: "new-value"
      add:
        - name: "X-Header-To-Add"
          value: "another-value"
      remove:
        - "X-Header-To-Remove"
    regex_uri:                    # Regex-based URI rewriting
      - "^/old/(.*)"              # Pattern
      - "/new/$1"                 # Replacement
```

#### Response Modification (Response Rewrite)
```yaml
plugins:
  response-rewrite:
    status_code: 200              # Rewrite response status code
    headers:                      # Modify response headers (simple mode)
      X-Custom-Header: "value"
      X-Another-Header: "value2"
    # OR structured mode for add/set/remove
    headers:
      set:
        X-Response-Header: "new-value"
        X-Client-IP: "$remote_addr"  # Variables supported: $remote_addr, $upstream_addr, $request_id
      add:
        - "X-Added-Header: appended-value"
      remove:
        - "X-Remove-This-Header"
    vars:                         # Conditional rewrite based on request matching
      - ["arg_version", "==", "v2"]    # Query parameter match
      - ["http_x-user-type", "==", "premium"]  # Header match
```

**Response Rewrite Features:**
- **Status Code Modification**: Change response HTTP status codes conditionally
- **Header Manipulation**: Set, add, or remove response headers
- **Variable Substitution**: Support for variables like `$remote_addr`, `$upstream_addr`, `$request_id` in header values
- **Conditional Rewriting**: Apply rewrites only when request conditions match
- **Flexible Configuration**: Both simple (key-value) and structured (add/set/remove) header modes

**Variable Placeholders:**
- `$remote_addr` - Client IP address
- `$upstream_addr` - Upstream server address
- `$request_id` - Request tracking ID (if request-id plugin is enabled)

**Common Use Cases:**
- Adding security headers (X-Content-Type-Options, X-Frame-Options)
- Injecting custom headers for downstream processing
- Rewriting status codes based on request type
- Adding request tracing headers

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

#### Fault Injection (Testing & Chaos Engineering)
```yaml
plugins:
  fault-injection:
    delay:                        # Inject latency into requests
      duration: 2.5               # Delay in seconds (supports decimals)
      percentage: 50              # Apply to 50% of requests (optional, omit for all)
    
    abort:                        # Return error response
      http_status: 503            # HTTP status code to return
      body: "Service Unavailable" # Optional response body
      percentage: 10              # Apply to 10% of requests (optional, omit for all)
      headers:                    # Optional custom headers
        X-Fault-Injected: "true"
        Retry-After: "60"
```

**Fault Injection Features:**
- **Delay Injection**: Inject artificial latency to test timeout handling and performance under degraded conditions
- **Abort Injection**: Return error responses to simulate service failures
- **Percentage-Based**: Apply faults to a percentage of requests for realistic testing
- **Combined Faults**: Can use both delay and abort together
- **Custom Responses**: Define response status, body, and headers for abort responses

**Common Use Cases:**
- Chaos engineering and resilience testing
- Testing timeout handling and retry logic
- Load testing under failure scenarios
- Circuit breaker and fallback validation
- SLA compliance testing

**Configuration Examples:**
```yaml
# Delay only - add 1 second latency to 20% of requests
delay:
  duration: 1.0
  percentage: 20

# Abort only - return 500 error for 5% of requests
abort:
  http_status: 500
  percentage: 5

# Combined - both delay and abort
delay:
  duration: 3.0
  percentage: 10
abort:
  http_status: 503
  body: "Gateway Timeout"
  percentage: 5
```

### Compression

#### Gzip Compression
```yaml
plugins:
  gzip:
    comp_level: 6                 # Compression level (0-9)
    decompression: false          # Enable decompression if needed
```

#### Brotli Compression
```yaml
plugins:
  brotli:
    comp_level: 6                 # Compression level (0-11)
    decompression: false          # Enable decompression if needed
```

### Caching

#### Response Caching
```yaml
plugins:
  cache:
    ttl: 3600                     # Cache TTL in seconds
    cache_http_methods: ["GET", "HEAD"]  # Default: ["GET", "HEAD"]
    cache_http_statuses: [200, 301, 404] # Default: [200]
    no_cache_str:                 # Regex patterns to skip caching
      - ".*private.*"
      - ".*no-cache.*"
    vary: ["Accept-Encoding"]     # Vary headers for cache keys
    hide_cache_headers: false     # Hide cache-related headers (default: false)
    max_file_size_bytes: 1048576  # Max cacheable response size (bytes, 0 = no limit)
    stale_while_revalidate_secs: 60  # Serve stale content while revalidating (optional)
    respect_s_maxage: true        # Respect Cache-Control s-maxage directive (default: true)
```

**Cache Plugin Features:**
- **TTL Management**: Configure cache expiration with `ttl` parameter
- **Stale-While-Revalidate**: Serve stale cached content while fetching fresh content in the background, improving perceived performance
- **s-maxage Support**: When enabled (default), respects `Cache-Control: s-maxage` directive from origin, overriding configured TTL for shared cache scenarios
- **Selective Caching**: Control which HTTP methods and status codes are cacheable
- **Pattern-Based Exclusion**: Use regex patterns to exclude specific URIs from caching
- **Size Limits**: Prevent memory exhaustion by limiting cacheable response size
- **Vary Support**: Generate cache keys based on specified request headers

**Common Use Cases:**
- CDN-like caching for static assets
- API response caching with TTL
- Serving stale content during origin failures
- Respecting origin cache control policies

### Observability

#### Prometheus Metrics
```yaml
plugins:
  prometheus:
    max_label_length: 100         # Maximum path label length (default: 100)
    max_unique_paths: 1000        # Maximum unique paths tracked (default: 1000)
  # OR zero-configuration
  prometheus: {}                  # Use defaults: max_label_length=100, max_unique_paths=1000
```

**Prometheus Plugin Features:**
- **Cardinality Control**: Limits metric cardinality by normalizing URI paths and enforcing label length limits
- **Path Normalization**: Automatically replaces numeric IDs, UUIDs, and hashes with placeholders (e.g., `/users/123` becomes `/users/{id}`)
- **Label Length Limit**: Truncates long path labels to prevent memory issues
- **Path Tracking Limit**: Collapses paths to `/...` after exceeding unique path threshold

**Collected Metrics:**
- `http_requests_total` - Total number of requests
- `http_status` - Status codes per route/service/node with normalized paths
- `http_latency` - Request latency histogram
- `bandwidth` - Ingress/egress bandwidth per route/service
- `http_request_size_bytes` - Request size distribution
- `http_response_size_bytes` - Response size distribution

**Configuration Best Practices:**
- Keep `max_label_length` under 200 to avoid Prometheus issues
- Set `max_unique_paths` based on your API diversity (1000-10000 typical)
- Monitor metric cardinality in Prometheus to tune these values

#### File Logging
```yaml
plugins:
  file-logger:
    # NOTE: The log file path must be configured globally under `pingsix.log.path`.
    log_format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
```

#### Request ID
```yaml
plugins:
  request-id:
    header_name: X-Request-ID     # Header name for request ID
    include_in_response: true     # Include in response headers
    algorithm: uuid               # 'uuid' or 'range_id'
    # Optional: configuration for 'range_id' algorithm
    range_id:
      char_set: "ABCDEF0123456789"
      length: 32
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
  grpc-web: {}                    # Enable gRPC-Web support (zero-configuration)
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

**Available Operations:**
- **PUT** `/apisix/admin/{resource_type}/{id}` - Create or update a resource
- **GET** `/apisix/admin/{resource_type}/{id}` - Get a specific resource
- **DELETE** `/apisix/admin/{resource_type}/{id}` - Delete a resource
- **GET** `/apisix/admin/{resource_type}` - List all resources of a type

**Supported Resource Types:**
- `routes` - Route configurations
- `upstreams` - Upstream server pools
- `services` - Service definitions
- `global_rules` - Global plugin rules
- `ssls` - SSL certificates

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

**List All Routes**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/routes \
  -H "X-API-KEY: your-api-key"
```

Response format:
```json
{
  "total": 2,
  "list": [
    {
      "key": "routes/1",
      "value": { /* route configuration */ },
      "createdIndex": 10,
      "modifiedIndex": 15
    },
    {
      "key": "routes/2",
      "value": { /* route configuration */ },
      "createdIndex": 20,
      "modifiedIndex": 20
    }
  ]
}
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

**List All Upstreams**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/upstreams \
  -H "X-API-KEY: your-api-key"
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

**List All Services**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/services \
  -H "X-API-KEY: your-api-key"
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

**List All Global Rules**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/global_rules \
  -H "X-API-KEY: your-api-key"
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

**List All SSL Certificates**:
```bash
curl -X GET http://127.0.0.1:9181/apisix/admin/ssls \
  -H "X-API-KEY: your-api-key"
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
      prometheus:
        max_label_length: 100      # Optional: Max path label length (default: 100)
        max_unique_paths: 1000     # Optional: Max unique paths (default: 1000)
```

Available metrics include:
- `http_requests_total` - Total number of requests
- `http_status{code, route, path_template, matched_host, service, node}` - Request count by status and normalized path
- `http_latency{type, route, service, node}` - Request duration histograms in milliseconds
- `bandwidth{type, route, service, node}` - Ingress/egress bandwidth in bytes
- `http_request_size_bytes{route, service}` - Request size distribution
- `http_response_size_bytes{route, service}` - Response size distribution

**Metric Labels:**
- `path_template` - Normalized URI path to avoid high cardinality (e.g., `/users/{id}` instead of `/users/123`)
- `route` - Route ID
- `service` - Service ID
- `node` - Upstream node address
- `matched_host` - Matched host from route configuration

**Path Normalization:**
The Prometheus plugin automatically normalizes paths to prevent metric cardinality explosion:
- Numeric IDs: `/users/123` → `/users/{id}`
- UUIDs: `/items/550e8400-e29b-41d4-a716-446655440000` → `/items/{uuid}`
- Hashes: `/files/a1b2c3d4e5f6...` → `/files/{hash}`
- Deep paths: Limits to 8 segments, truncates to `/segment1/.../segment7/...`

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
        log_format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time'
```

Available log variables:
- `$remote_addr` - Client IP address
- `$remote_port` - Client port
- `$remote_user` - Remote user (if authenticated)
- `$time_local` - Local time
- `$request` - Full request line (`$request_method $uri $server_protocol`)
- `$request_method` - Request method (e.g., GET)
- `$request_id` - The unique request ID
- `$status` - Response status code
- `$body_bytes_sent` - Response body size in bytes
- `$http_host` - The host from the request URI
- `$http_referer` - Referer header
- `$http_user_agent` - User-Agent header
- `$request_time` - Total request processing time in milliseconds
- `$server_addr` - The server address PingSIX listened on
- `$server_protocol` - The request protocol (e.g., http/1.1)
- `$uri` - The request URI path
- `$query_string` - The request query string
- `$error` - The error message if an error occurred

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
        max_file_size_bytes: 10485760  # 10MB limit
        stale_while_revalidate_secs: 300  # Serve stale for 5 min while revalidating
        respect_s_maxage: true
      gzip:
        comp_level: 6
  
  - id: "api-content"
    uri: /api/{*path}               # Catch-all for /api/* requests
    upstream_id: "cdn-origin"
    plugins:
      cache:
        ttl: 300  # 5 minutes
        cache_http_methods: ["GET"]
        cache_http_statuses: [200]
        stale_while_revalidate_secs: 60
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 100

global_rules:
  - id: "observability"
    plugins:
      prometheus:
        max_label_length: 150
        max_unique_paths: 2000
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
          add:
            - name: "X-Frame-Options"
              value: "DENY"
            - name: "X-Content-Type-Options"
              value: "nosniff"
            - name: "X-XSS-Protection"
              value: "1; mode=block"
            - name: "Strict-Transport-Security"
              value: "max-age=31536000; includeSubDomains"
  
  - id: "monitoring"
    plugins:
      prometheus: {}
      file-logger:
        log_format: '$remote_addr - [$time_local] "$request" $status $body_bytes_sent $request_time'
```

### Example 5: Canary Deployment with Traffic Split

```yaml
pingora:
  version: 1
  threads: 4

pingsix:
  listeners:
    - address: 0.0.0.0:8080
  
  prometheus:
    address: 0.0.0.0:9091

upstreams:
  - id: "production-v1"
    nodes:
      "prod-v1-1.example.com:8080": 1
      "prod-v1-2.example.com:8080": 1
    type: roundrobin
    pass_host: pass
    checks:
      active:
        type: http
        http_path: /health
        healthy:
          interval: 10
          successes: 2
        unhealthy:
          http_failures: 3
  
  - id: "canary-v2"
    nodes:
      "canary-v2-1.example.com:8080": 1
    type: roundrobin
    pass_host: node                    # Use node hostname as Host header
    checks:
      active:
        type: http
        http_path: /health
        healthy:
          interval: 10
          successes: 2
        unhealthy:
          http_failures: 3

routes:
  # Beta users get 100% canary traffic
  - id: "api-beta"
    uri: /api/{*path}
    host: api.example.com
    priority: 100
    upstream_id: "production-v1"
    plugins:
      traffic-split:
        rules:
          - vars:
              - ["http_x-user-type", "==", "beta"]
            weighted_upstreams:
              - upstream_id: "canary-v2"
                weight: 100              # 100% to canary for beta users
      
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 1000
  
  # General users get 90/10 split
  - id: "api-general"
    uri: /api/{*path}
    host: api.example.com
    upstream_id: "production-v1"
    plugins:
      traffic-split:
        rules:
          - vars: []                     # Match all requests
            weighted_upstreams:
              - upstream_id: "production-v1"
                weight: 90               # 90% to stable
              - upstream_id: "canary-v2"
                weight: 10               # 10% to canary
      
      request-id:
        header_name: X-Request-ID
        include_in_response: true
      
      limit-count:
        key_type: vars
        key: remote_addr
        time_window: 60
        count: 1000

global_rules:
  - id: "monitoring"
    plugins:
      prometheus:
        max_label_length: 100
        max_unique_paths: 1000
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
- Validate plugin configuration syntax in `config.yaml`.
- Check plugin execution order (priority).
- Review plugin-specific requirements in this guide.
- Check PingSIX startup logs for plugin-related errors.

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
- Increase thread count in `pingora` configuration to match CPU cores.
- Optimize upstream connection pooling.
- Enable compression for large responses.
- Use caching for frequently accessed content.
- Monitor resource usage (CPU, memory, network).

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
        log_format: 'DEBUG: $remote_addr $request_method $uri $status $request_time $error'
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