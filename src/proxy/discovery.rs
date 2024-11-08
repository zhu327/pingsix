use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::OnceCell;
use pingora::prelude::HttpPeer;
use pingora::ErrorType::InternalError;
use pingora_error::{OrErr, Result};
use pingora_load_balancing::{
    discovery::{ServiceDiscovery, Static},
    Backend,
};
use regex::Regex;

use crate::config::{Upstream, UpstreamScheme};

static GLOBAL_RESOLVER: OnceCell<Arc<TokioAsyncResolver>> = OnceCell::new();

fn get_global_resolver() -> Arc<TokioAsyncResolver> {
    GLOBAL_RESOLVER
        .get_or_init(|| Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap()))
        .clone()
}

pub struct DnsDiscovery {
    resolver: Arc<TokioAsyncResolver>,
    name: String,
    port: u32,

    scheme: UpstreamScheme,
    weight: u32,
}

impl DnsDiscovery {
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

                let tls = self.scheme == UpstreamScheme::HTTPS;
                let uppy = HttpPeer::new(addr, tls, self.name.clone());
                assert!(backend.ext.insert::<HttpPeer>(uppy).is_none());

                backend
            })
            .collect();
        Ok((backends, HashMap::new()))
    }
}

#[derive(Default)]
pub struct HybridDiscovery {
    static_discovery: Option<Box<Static>>,
    dns_discoveries: Vec<DnsDiscovery>,
}

impl From<Upstream> for HybridDiscovery {
    fn from(upstream: Upstream) -> Self {
        let mut this = Self::default();

        let mut backends = BTreeSet::new();
        for (addr, weight) in upstream.nodes.iter() {
            let (host, port, is_domain) = parse_upstream_node(addr).unwrap();
            let port = port.unwrap_or(if upstream.scheme == UpstreamScheme::HTTPS {
                443
            } else {
                80
            });

            if is_domain {
                let resolver = get_global_resolver();
                this.dns_discoveries.push(DnsDiscovery::new(
                    host,
                    port,
                    upstream.scheme,
                    *weight,
                    resolver,
                ));
            } else {
                let mut backend = Backend::new(addr).unwrap();
                let uppy = HttpPeer::new(addr, false, "".to_string());
                assert!(backend.ext.insert::<HttpPeer>(uppy).is_none());
                backends.insert(backend);
            }
        }

        if !backends.is_empty() {
            this.static_discovery = Some(Static::new(backends));
        }

        this
    }
}

#[async_trait]
impl ServiceDiscovery for HybridDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        // Combine backends from static and DNS discoveries

        let mut backends = BTreeSet::new();
        let mut health_checks = HashMap::new();

        // 1. Process static discovery first (if available)
        if let Some(static_discovery) = &self.static_discovery {
            let (static_backends, static_health_checks) = static_discovery.discover().await?;
            backends.extend(static_backends);
            health_checks.extend(static_health_checks);
        }

        // 2. Then process DNS discoveries
        for discovery in self.dns_discoveries.iter() {
            let (dns_backends, dns_health_checks) = discovery.discover().await?;
            backends.extend(dns_backends);
            health_checks.extend(dns_health_checks);
        }

        Ok((backends, health_checks))
    }
}

fn parse_upstream_node(
    addr: &str,
) -> Result<(String, Option<u32>, bool), Box<dyn std::error::Error>> {
    let re = Regex::new(r"^(?:\[(.+?)\]|([^:]+))(?::(\d+))?$").unwrap();

    let caps = match re.captures(addr) {
        Some(caps) => caps,
        None => return Err("Invalid address format".into()),
    };

    let raw_host = caps.get(1).or(caps.get(2)).unwrap().as_str();
    let port_str = caps.get(3).map(|p| p.as_str());
    let port = port_str.map(|p| p.parse::<u32>()).transpose()?;

    let is_domain = raw_host.parse::<IpAddr>().is_err();

    // Ensure IPv6 addresses are enclosed in square brackets
    let host = if !is_domain && raw_host.contains(':') {
        format!("[{}]", raw_host)
    } else {
        raw_host.to_string()
    };

    Ok((host, port, is_domain))
}

#[cfg(test)]
mod tests {
    use super::parse_upstream_node;

    #[test]
    fn test_parse_upstream_node() {
        let test_cases = [
            ("127.0.0.1", ("127.0.0.1".to_string(), None, false)),
            ("[::1]", ("[::1]".to_string(), None, false)),
            ("example.com", ("example.com".to_string(), None, true)),
            (
                "example.com:80",
                ("example.com".to_string(), Some(80), true),
            ),
            (
                "192.168.1.1:8080",
                ("192.168.1.1".to_string(), Some(8080), false),
            ),
            // ... 其他测试用例
        ];

        for (input, expected) in test_cases {
            let result = parse_upstream_node(input).unwrap();
            assert_eq!(result, expected);
        }

        // 测试异常情况
        assert!(parse_upstream_node("").is_err());
    }
}
