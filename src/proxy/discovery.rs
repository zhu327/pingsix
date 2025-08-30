use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use hickory_resolver::TokioResolver;
use once_cell::sync::OnceCell;
use pingora::{protocols::ALPN, upstreams::peer::HttpPeer};
use pingora_error::{Error, ErrorType::InternalError, Result};
use pingora_load_balancing::{
    discovery::{ServiceDiscovery, Static},
    Backend,
};
use regex::Regex;
use std::time::{Duration, Instant};
use prometheus::{register_histogram_vec, HistogramVec};

use super::{ProxyError, ProxyResult};
use crate::config::{Upstream, UpstreamPassHost, UpstreamScheme};

static GLOBAL_RESOLVER: OnceCell<Arc<TokioResolver>> = OnceCell::new();

fn get_global_resolver() -> Arc<TokioResolver> {
    if let Some(r) = GLOBAL_RESOLVER.get() {
        return r.clone();
    }
    // Build resolver without unwrap, fallback to system config, and if all fail, log and use a noop panic-on-use resolver is not viable.
    match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(resolver) => {
            let arc = Arc::new(resolver);
            let _ = GLOBAL_RESOLVER.set(arc.clone());
            arc
        }
        Err(e) => {
            log::error!("Failed to build DNS resolver: {}", e);
            // Try default from_system_conf
            match TokioResolver::tokio_from_system_conf() {
                Ok(resolver) => {
                    let arc = Arc::new(resolver);
                    let _ = GLOBAL_RESOLVER.set(arc.clone());
                    arc
                }
                Err(e2) => {
                    log::error!("Failed to init resolver from system conf: {}", e2);
                    // As a last resort, panic to avoid undefined DNS behavior
                    panic!("Unable to initialize DNS resolver");
                }
            }
        }
    }
}

/// DNS-based service discovery.
///
/// Resolves DNS names to IP addresses and creates backends for each resolved IP.
pub struct DnsDiscovery {
    resolver: Arc<TokioResolver>,
    domain: String,
    port: u32,
    scheme: UpstreamScheme,
    weight: u32,
}

impl DnsDiscovery {
    /// Creates a new `DnsDiscovery` instance.
    pub fn new(
        domain: String,
        port: u32,
        scheme: UpstreamScheme,
        weight: u32,
        resolver: Arc<TokioResolver>,
    ) -> Self {
        Self {
            resolver,
            domain,
            port,
            scheme,
            weight,
        }
    }
}

#[async_trait]
impl ServiceDiscovery for DnsDiscovery {
    /// Discovers backends by resolving DNS names to IP addresses.
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let domain = self.domain.as_str();
        log::debug!("Resolving DNS for domain: {domain}");

        let ips = match self.resolver.lookup_ip(domain).await {
            Ok(ips) => ips,
            Err(e) => {
                log::warn!("DNS discovery failed for domain: {domain}: {e}");
                return Err(Error::because(
                    InternalError,
                    format!("DNS discovery failed for domain: {domain}: {e}"),
                    e,
                ));
            }
        };

        // Record resolution time per domain
        static DNS_RESOLVE_MS: Lazy<HistogramVec> = Lazy::new(|| {
            register_histogram_vec!(
                "pingsix_dns_resolve_duration_ms",
                "DNS resolve duration in ms",
                &["domain"]
            )
            .unwrap()
        });
        let start = Instant::now();

        let backends: BTreeSet<Backend> = ips
            .iter()
            .map(|ip| {
                let addr = SocketAddr::new(ip, self.port as _).to_string();

                // Creating backend
                let mut backend = Backend::new_with_weight(&addr, self.weight as _).unwrap();

                // Determine if TLS is needed
                let tls = matches!(self.scheme, UpstreamScheme::HTTPS | UpstreamScheme::GRPCS);

                // Create HttpPeer
                let mut peer = HttpPeer::new(&addr, tls, self.domain.clone());
                if matches!(self.scheme, UpstreamScheme::GRPC | UpstreamScheme::GRPCS) {
                    peer.options.alpn = ALPN::H2;
                }

                // Insert HttpPeer into the backend
                let _ = backend.ext.insert::<HttpPeer>(peer);

                backend
            })
            .collect();

        DNS_RESOLVE_MS
            .with_label_values(&[domain])
            .observe(start.elapsed().as_millis() as f64);

        // Return backends and an empty HashMap for now
        Ok((backends, HashMap::new()))
    }
}

/// Hybrid service discovery.
///
/// Combines static and DNS-based service discovery.
#[derive(Default)]
pub struct HybridDiscovery {
    discoveries: Vec<Box<dyn ServiceDiscovery + Send + Sync>>,
}

#[async_trait]
impl ServiceDiscovery for HybridDiscovery {
    /// Discovers backends by combining static and DNS-based service discovery.
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        // Combine backends from static and DNS discoveries
        let mut backends = BTreeSet::new();
        let mut health_checks = HashMap::new();

        let futures = self.discoveries.iter().map(|discovery| async move {
            discovery.discover().await.map_err(|e| {
                log::warn!("Hybrid discovery failed: {e}");
                e
            })
        });

        let results = join_all(futures).await;

        for (part_backends, part_health_checks) in results.into_iter().flatten() {
            backends.extend(part_backends);
            health_checks.extend(part_health_checks);
        }

        Ok((backends, health_checks))
    }
}

impl TryFrom<Upstream> for HybridDiscovery {
    type Error = ProxyError;

    fn try_from(upstream: Upstream) -> ProxyResult<Self> {
        let mut this = Self::default();
        let mut backends = BTreeSet::new();

        // Process each node in upstream
        for (addr, weight) in upstream.nodes.iter() {
            let (host, port) = parse_host_and_port(addr)?;
            let port = port.unwrap_or(match upstream.scheme {
                UpstreamScheme::HTTPS | UpstreamScheme::GRPCS => 443,
                _ => 80,
            });

            if host.parse::<IpAddr>().is_err() {
                // It's a domain name
                // Handle DNS discovery for domain names
                let resolver = get_global_resolver();
                let discovery = DnsDiscovery::new(host, port, upstream.scheme, *weight, resolver);
                this.discoveries.push(Box::new(discovery));
            } else {
                // It's an IP address
                // Handle backend creation for IP addresses
                let addr = &SocketAddr::new(host.parse::<IpAddr>().unwrap(), port as _).to_string();
                let mut backend = Backend::new_with_weight(addr, *weight as _).unwrap();

                let tls = matches!(
                    upstream.scheme,
                    UpstreamScheme::HTTPS | UpstreamScheme::GRPCS
                );
                let sni = if upstream.pass_host == UpstreamPassHost::REWRITE {
                    upstream
                        .upstream_host
                        .clone()
                        .unwrap_or_else(|| host.to_string())
                } else {
                    host.to_string()
                };

                let mut peer = HttpPeer::new(addr, tls, sni);
                if matches!(
                    upstream.scheme,
                    UpstreamScheme::GRPC | UpstreamScheme::GRPCS
                ) {
                    peer.options.alpn = ALPN::H2;
                }
                assert!(backend.ext.insert::<HttpPeer>(peer).is_none());

                backends.insert(backend);
            }
        }

        if !backends.is_empty() {
            this.discoveries.push(Static::new(backends));
        }

        Ok(this)
    }
}

/// Regular expression for parsing host and port from an address string.
static HOST_PORT_REGEX: once_cell::sync::Lazy<Regex> =
    once_cell::sync::Lazy::new(|| Regex::new(r"^(?:\[(.+?)\]|([^:]+))(?::(\d+))?$").unwrap());

/// Parses a host and port from a string.
///
/// Supports IPv4, IPv6, and domain names, with optional port.
/// Returns IPv6 addresses enclosed in square brackets for consistency.
fn parse_host_and_port(addr: &str) -> ProxyResult<(String, Option<u32>)> {
    let caps = HOST_PORT_REGEX
        .captures(addr)
        .ok_or_else(|| ProxyError::Configuration("Invalid address format".to_string()))?;

    let host = caps.get(1).or(caps.get(2)).unwrap().as_str();

    let port = if let Some(port_str) = caps.get(3).map(|p| p.as_str()) {
        Some(
            port_str
                .parse::<u32>()
                .map_err(|_| ProxyError::Configuration("Invalid port number".to_string()))?,
        )
    } else {
        None
    };

    // Ensure IPv6 addresses are enclosed in square brackets
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };

    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::parse_host_and_port;

    #[test]
    fn test_parse_upstream_node() {
        let test_cases = [
            ("127.0.0.1", ("127.0.0.1".to_string(), None)),
            ("[::1]", ("[::1]".to_string(), None)),
            ("example.com", ("example.com".to_string(), None)),
            ("example.com:80", ("example.com".to_string(), Some(80))),
            ("192.168.1.1:8080", ("192.168.1.1".to_string(), Some(8080))),
            (
                "[2001:db8:85a3::8a2e:370:7334]:8080",
                ("[2001:db8:85a3::8a2e:370:7334]".to_string(), Some(8080)),
            ),
        ];

        for (input, expected) in test_cases {
            let result = parse_host_and_port(input).unwrap();
            assert_eq!(result, expected);
        }

        // Test invalid cases
        assert!(parse_host_and_port("").is_err());
        assert!(parse_host_and_port("invalid:port").is_err());
        assert!(parse_host_and_port("127.0.0.1:invalid").is_err());
    }
}
