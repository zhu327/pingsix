use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::OnceCell;
use pingora::protocols::ALPN;
use pingora::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType::InternalError, OrErr, Result};
use pingora_load_balancing::{
    discovery::{ServiceDiscovery, Static},
    Backend,
};
use regex::Regex;

use crate::config::{Upstream, UpstreamPassHost, UpstreamScheme};

static GLOBAL_RESOLVER: OnceCell<Arc<TokioAsyncResolver>> = OnceCell::new();

fn get_global_resolver() -> Arc<TokioAsyncResolver> {
    GLOBAL_RESOLVER
        .get_or_init(|| Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap()))
        .clone()
}

/// DNS-based service discovery.
///
/// Resolves DNS names to IP addresses and creates backends for each resolved IP.
pub struct DnsDiscovery {
    resolver: Arc<TokioAsyncResolver>,
    name: String,
    port: u32,

    scheme: UpstreamScheme,
    weight: u32,
}

impl DnsDiscovery {
    /// Creates a new `DnsDiscovery` instance.
    pub fn new(
        name: String,
        port: u32,
        scheme: UpstreamScheme,
        weight: u32,
        resolver: Arc<TokioAsyncResolver>,
    ) -> Self {
        Self {
            resolver,
            name,
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
        let name = self.name.as_str();
        log::debug!("Resolving DNS for domain: {}", name);

        let backends = self
            .resolver
            .lookup_ip(name)
            .await
            .or_err_with(InternalError, || {
                format!("Dns discovery failed for domain {name}")
            })?
            .iter()
            .map(|ip| {
                let addr = &SocketAddr::new(ip, self.port as u16).to_string();

                let mut backend = Backend::new(addr).unwrap();
                backend.weight = self.weight as usize;

                let tls =
                    self.scheme == UpstreamScheme::HTTPS || self.scheme == UpstreamScheme::GRPCS;
                let mut uppy = HttpPeer::new(addr, tls, self.name.clone());
                if self.scheme == UpstreamScheme::GRPC || self.scheme == UpstreamScheme::GRPCS {
                    uppy.options.alpn = ALPN::H2;
                };

                assert!(backend.ext.insert::<HttpPeer>(uppy).is_none());

                backend
            })
            .collect();
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
                log::warn!("Hydrid discovery failed: {}", e);
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
    type Error = Box<Error>;

    fn try_from(upstream: Upstream) -> Result<Self> {
        let mut this = Self::default();

        let mut backends = BTreeSet::new();
        for (addr, weight) in upstream.nodes.iter() {
            let (host, port) = parse_host_and_port(addr)?;
            let port = port.unwrap_or(if upstream.scheme == UpstreamScheme::HTTPS {
                443
            } else {
                80
            });

            if host.parse::<IpAddr>().is_err() {
                // host is a domain name
                let resolver = get_global_resolver();
                this.discoveries.push(Box::new(DnsDiscovery::new(
                    host,
                    port,
                    upstream.scheme,
                    *weight,
                    resolver,
                )));
            } else {
                let addr =
                    &SocketAddr::new(host.parse::<IpAddr>().unwrap(), port as u16).to_string();

                let mut backend = Backend::new(addr).unwrap();
                backend.weight = *weight as usize;

                let tls = upstream.scheme == UpstreamScheme::HTTPS
                    || upstream.scheme == UpstreamScheme::GRPCS;
                let sni = if upstream.pass_host == UpstreamPassHost::REWRITE {
                    upstream.upstream_host.clone().unwrap()
                } else {
                    host
                };

                let mut uppy = HttpPeer::new(addr, tls, sni);
                if upstream.scheme == UpstreamScheme::GRPC
                    || upstream.scheme == UpstreamScheme::GRPCS
                {
                    uppy.options.alpn = ALPN::H2;
                };
                assert!(backend.ext.insert::<HttpPeer>(uppy).is_none());
                backends.insert(backend);
            }
        }

        if !backends.is_empty() {
            this.discoveries.push(Static::new(backends));
        }

        Ok(this)
    }
}

/// Parses a host and port from a string.
fn parse_host_and_port(addr: &str) -> Result<(String, Option<u32>)> {
    let re = Regex::new(r"^(?:\[(.+?)\]|([^:]+))(?::(\d+))?$").unwrap();

    let caps = match re.captures(addr) {
        Some(caps) => caps,
        None => return Err(Error::explain(InternalError, "Invalid address format")),
    };

    let host = caps.get(1).or(caps.get(2)).unwrap().as_str();
    let port_opt = caps.get(3).map(|p| p.as_str());
    let port = port_opt
        .map(|p| p.parse::<u32>())
        .transpose()
        .or_err_with(InternalError, || "Invalid port")?;

    // Ensure IPv6 addresses are enclosed in square brackets
    let host = if host.contains(':') {
        format!("[{}]", host)
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
