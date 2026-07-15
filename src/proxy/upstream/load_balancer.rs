use std::{sync::Arc, time::Duration};

use futures::FutureExt;
use http::Uri;
use pingora::services::background::background_service;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Error;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::{
    health_check::{HealthCheck as HealthCheckTrait, HttpHealthCheck, TcpHealthCheck},
    selection::{
        consistent::KetamaHashing, BackendIter, BackendSelection, FVNHash, Random, RoundRobin,
    },
    Backend, Backends, LoadBalancer,
};
use pingora_proxy::Session;

use crate::{
    config::{self, Identifiable},
    core::{ProxyError, ProxyResult, UpstreamSelector},
    utils::request::request_selector_key,
};

use super::discovery::HybridDiscovery;

/// Runs a closure over the inner LB for any SelectionLB variant, eliminating repetitive match arms.
macro_rules! with_lb {
    ($lb:expr, |$lb_var:ident| $body:expr) => {
        match $lb {
            SelectionLB::RoundRobin($lb_var) => $body,
            SelectionLB::Random($lb_var) => $body,
            SelectionLB::Fnv($lb_var) => $body,
            SelectionLB::Ketama($lb_var) => $body,
        }
    };
}

/// Proxy load balancer.
///
/// Manages the load balancing of requests to upstream servers.
pub struct ProxyUpstream {
    pub inner: config::Upstream,
    lb: SelectionLB,
}

impl Identifiable for ProxyUpstream {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyUpstream {
    /// Build an upstream without changing the global health-check registry.
    pub(crate) fn build(mut upstream: config::Upstream) -> ProxyResult<Self> {
        // Auto-generate upstream ID if empty (for inline upstreams in route, service, traffic-split)
        if upstream.id.is_empty() {
            upstream.id = format!("inline_{}", uuid::Uuid::new_v4());
            log::debug!("Generated ID for inline upstream: {}", upstream.id);
        }

        let lb = SelectionLB::try_from(upstream.clone()).map_err(|e| {
            ProxyError::Configuration(format!("Failed to create load balancer: {e}"))
        })?;

        Ok(ProxyUpstream {
            inner: upstream,
            lb,
        })
    }

    pub(crate) fn health_check_service(
        &self,
    ) -> Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync> {
        with_lb!(&self.lb, |lb| lb.upstreams.clone())
    }

    /// Test helper: select a backend without a full proxy session.
    #[cfg(test)]
    pub(crate) fn select_backend_for_test(&self) -> Option<Backend> {
        let mut backend = with_lb!(&self.lb, |lb| lb.upstreams.select(b"", 256));
        if let Some(backend) = backend.as_mut() {
            if let Some(peer) = backend.ext.get_mut::<HttpPeer>() {
                self.set_timeout(peer);
            }
        }
        backend
    }

    /// Sets the timeout for an `HttpPeer`.
    /// Note: Duplicated in ProxyRoute — consider extracting to shared utility if consolidating.
    fn set_timeout(&self, p: &mut HttpPeer) {
        if let Some(config::Timeout {
            connect,
            read,
            send,
        }) = config::resolve_upstream_timeout(
            self.inner.timeout.clone(),
            config::default_upstream_timeout(),
        ) {
            p.options.connection_timeout = Some(Duration::from_secs(connect));
            p.options.read_timeout = Some(Duration::from_secs(read));
            p.options.write_timeout = Some(Duration::from_secs(send));
        }
    }
}

// Implementation of UpstreamSelector trait for decoupling from core module
impl UpstreamSelector for ProxyUpstream {
    fn select_backend<'a>(&'a self, session: &'a mut Session) -> Option<Backend> {
        let mut backend = match &self.lb {
            SelectionLB::RoundRobin(lb) => lb.upstreams.select(b"", 256),
            SelectionLB::Random(lb) => lb.upstreams.select(b"", 256),
            SelectionLB::Fnv(lb) => {
                let key =
                    request_selector_key(session, &self.inner.hash_on, self.inner.key.as_str());
                log::debug!("proxy lb key: {key}");
                lb.upstreams.select(key.as_bytes(), 256)
            }
            SelectionLB::Ketama(lb) => {
                let key =
                    request_selector_key(session, &self.inner.hash_on, self.inner.key.as_str());
                log::debug!("proxy lb key: {key}");
                lb.upstreams.select(key.as_bytes(), 256)
            }
        };

        if let Some(backend) = backend.as_mut() {
            if let Some(peer) = backend.ext.get_mut::<HttpPeer>() {
                self.set_timeout(peer);
            }
        }

        backend
    }

    fn get_retries(&self) -> Option<usize> {
        self.inner.retries.map(|r| r as _)
    }

    fn get_retry_timeout(&self) -> Option<u64> {
        self.inner.retry_timeout
    }

    fn get_pass_host(&self) -> &config::UpstreamPassHost {
        &self.inner.pass_host
    }

    fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader) {
        if self.inner.pass_host == config::UpstreamPassHost::REWRITE {
            if let Some(host) = &self.inner.upstream_host {
                if let Err(e) = upstream_request.insert_header(http::header::HOST, host) {
                    log::error!("Failed to rewrite upstream host header: {e}");
                }
            }
        }
    }
}

enum SelectionLB {
    RoundRobin(LB<RoundRobin>),
    Random(LB<Random>),
    Fnv(LB<FVNHash>),
    Ketama(LB<KetamaHashing>),
}

impl TryFrom<config::Upstream> for SelectionLB {
    type Error = ProxyError;

    fn try_from(value: config::Upstream) -> ProxyResult<Self> {
        match value.r#type {
            config::SelectionType::RoundRobin => {
                Ok(SelectionLB::RoundRobin(LB::<RoundRobin>::try_from(value)?))
            }
            config::SelectionType::Random => {
                Ok(SelectionLB::Random(LB::<Random>::try_from(value)?))
            }
            config::SelectionType::Fnv => Ok(SelectionLB::Fnv(LB::<FVNHash>::try_from(value)?)),
            config::SelectionType::Ketama => {
                Ok(SelectionLB::Ketama(LB::<KetamaHashing>::try_from(value)?))
            }
        }
    }
}

struct LB<BS: BackendSelection> {
    upstreams: Arc<LoadBalancer<BS>>,
}

impl<BS> TryFrom<config::Upstream> for LB<BS>
where
    BS: BackendSelection + Send + Sync + 'static,
    BS::Iter: BackendIter,
{
    type Error = ProxyError;

    fn try_from(upstream: config::Upstream) -> ProxyResult<Self> {
        let discovery: HybridDiscovery = upstream.clone().try_into()?;
        let mut upstreams = LoadBalancer::<BS>::from_backends(Backends::new(Box::new(discovery)));

        if let Some(check) = upstream.checks {
            let health_check: Box<dyn HealthCheckTrait + Send + Sync + 'static> =
                check.clone().into();
            upstreams.set_health_check(health_check);

            let health_check_frequency = check
                .active
                .healthy
                .map(|healthy| Duration::from_secs(healthy.interval as _))
                .unwrap_or(Duration::from_secs(1));

            upstreams.health_check_frequency = Some(health_check_frequency);
        }

        // Extract the Arc<LoadBalancer> via background_service().task().
        // The wrapper is intentionally dropped — health checks are driven by
        // SHARED_HEALTH_CHECK_SERVICE, not by Pingora's background service mechanism.
        let background =
            background_service(&format!("health check for {}", upstream.id), upstreams);
        let upstreams = background.task();

        // Discover backends before the LB is published. Pingora's Backends start empty;
        // without this, a newly published runtime can select nothing until the HC task
        // runs its first update(). Static discovery completes via now_or_never; DNS
        // discovery runs on a helper thread so we never nest block_on inside Tokio.
        eager_discover_backends(&upstreams, &upstream.id)?;

        Ok(Self { upstreams })
    }
}

fn eager_discover_backends<BS>(lb: &Arc<LoadBalancer<BS>>, upstream_id: &str) -> ProxyResult<()>
where
    BS: BackendSelection + Send + Sync + 'static,
    BS::Iter: BackendIter,
{
    match lb.update().now_or_never() {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(ProxyError::Configuration(format!(
            "Upstream '{upstream_id}' discovery failed: {e}"
        ))),
        None => {
            let lb = lb.clone();
            let id = upstream_id.to_string();
            std::thread::Builder::new()
                .name(format!("upstream-discover-{id}"))
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            ProxyError::Configuration(format!(
                                "Failed to create discovery runtime for upstream '{id}': {e}"
                            ))
                        })?;
                    rt.block_on(lb.update()).map_err(|e| {
                        ProxyError::Configuration(format!("Upstream '{id}' discovery failed: {e}"))
                    })
                })
                .map_err(|e| {
                    ProxyError::Configuration(format!(
                        "Failed to spawn discovery for upstream '{upstream_id}': {e}"
                    ))
                })?
                .join()
                .map_err(|_| {
                    ProxyError::Configuration(format!(
                        "Discovery thread panicked for upstream '{upstream_id}'"
                    ))
                })?
        }
    }
}

impl From<config::HealthCheck> for Box<dyn HealthCheckTrait + Send + Sync + 'static> {
    fn from(value: config::HealthCheck) -> Self {
        match value.active.r#type {
            config::ActiveCheckType::TCP => Into::<Box<TcpHealthCheck>>::into(value),
            config::ActiveCheckType::HTTP | config::ActiveCheckType::HTTPS => {
                Into::<Box<HttpHealthCheck>>::into(value)
            }
        }
    }
}

impl From<config::HealthCheck> for Box<TcpHealthCheck> {
    fn from(value: config::HealthCheck) -> Self {
        let mut health_check = TcpHealthCheck::new();
        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.active.timeout as _));

        if let Some(healthy) = value.active.healthy {
            health_check.consecutive_success = healthy.successes as _;
        }

        if let Some(unhealthy) = value.active.unhealthy {
            health_check.consecutive_failure = unhealthy.tcp_failures as _;
        }

        health_check
    }
}

impl From<config::HealthCheck> for Box<HttpHealthCheck> {
    fn from(value: config::HealthCheck) -> Self {
        let host = value.active.host.unwrap_or_default();
        let tls = value.active.r#type == config::ActiveCheckType::HTTPS;
        let mut health_check = HttpHealthCheck::new(host.as_str(), tls);

        // Set total connection timeout if provided
        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.active.timeout as _));

        // Set certificate verification if TLS is enabled
        health_check.peer_template.options.verify_cert = value.active.https_verify_certificate;

        // Build URI for HTTP health check path, log failure if any
        if let Ok(uri) = Uri::builder()
            .path_and_query(&value.active.http_path)
            .build()
        {
            health_check.req.set_uri(uri);
        } else {
            log::warn!(
                "Invalid URI path provided for health check: {}",
                value.active.http_path
            );
        }

        // Insert headers, ensure they are properly formatted
        for header in value.active.req_headers.iter() {
            let mut parts = header.splitn(2, ":");
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                let key = key.trim().to_string();
                let value = value.trim().to_string();
                let _ = health_check.req.insert_header(key, &value);
            }
        }

        // Handle port override
        if let Some(port) = value.active.port {
            health_check.port_override = Some(port as _);
        }

        // Set the success conditions
        if let Some(healthy) = value.active.healthy {
            health_check.consecutive_success = healthy.successes as _;

            // Validator for HTTP status codes
            if !healthy.http_statuses.is_empty() {
                let http_statuses = healthy.http_statuses.clone(); // Clone to move into closure
                health_check.validator = Some(Box::new(move |header: &ResponseHeader| {
                    if http_statuses.contains(&(header.status.as_u16() as _)) {
                        Ok(())
                    } else {
                        Err(Error::new_str("Invalid response"))
                    }
                }));
            }
        }

        // Set the failure conditions
        if let Some(unhealthy) = value.active.unhealthy {
            health_check.consecutive_failure = unhealthy.http_failures as _;
        }

        // Return the Boxed health check
        Box::new(health_check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        init_default_upstream_timeout, SelectionType, Timeout, UpstreamHashOn, UpstreamPassHost,
        UpstreamScheme,
    };
    use std::collections::HashMap;

    fn sample_upstream(id: &str, timeout: Option<Timeout>) -> config::Upstream {
        let mut nodes = HashMap::new();
        nodes.insert("127.0.0.1:18080".to_string(), 1);
        config::Upstream {
            id: id.to_string(),
            retries: None,
            retry_timeout: None,
            timeout,
            nodes,
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
        }
    }

    #[test]
    fn explicit_upstream_timeout_applied_to_peer() {
        init_default_upstream_timeout(Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        }));
        let upstream = ProxyUpstream::build(sample_upstream(
            "payments",
            Some(Timeout {
                connect: 30,
                send: 30,
                read: 30,
            }),
        ))
        .unwrap();
        let backend = upstream.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(30))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn missing_upstream_timeout_uses_global_default() {
        init_default_upstream_timeout(Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        }));
        // First-wins OnceCell: if a prior test already set a different value,
        // resolve via whatever is currently configured.
        let global = crate::config::default_upstream_timeout();
        let upstream = ProxyUpstream::build(sample_upstream("plain", None)).unwrap();
        let backend = upstream.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        if let Some(g) = global {
            assert_eq!(
                peer.options.connection_timeout,
                Some(Duration::from_secs(g.connect))
            );
            assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(g.read)));
            assert_eq!(
                peer.options.write_timeout,
                Some(Duration::from_secs(g.send))
            );
        } else {
            assert!(peer.options.connection_timeout.is_none());
        }
    }
}
