use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use http::Uri;
use log::info;
use once_cell::sync::Lazy;
use pingora::services::background::background_service;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
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
    utils::request::request_selector_key,
};

use super::{discovery::HybridDiscovery, health_check::SHARED_HEALTH_CHECK_SERVICE, MapOperations};

/// Fetches an upstream by its ID.
pub fn upstream_fetch(id: &str) -> Option<Arc<ProxyUpstream>> {
    match UPSTREAM_MAP.get(id) {
        Some(upstream) => Some(upstream.value().clone()),
        None => {
            log::warn!("Upstream with id '{id}' not found");
            None
        }
    }
}

/// Proxy load balancer.
///
/// Manages the load balancing of requests to upstream servers.
pub struct ProxyUpstream {
    pub inner: config::Upstream,
    lb: SelectionLB,
    health_check_id: Option<String>, // 注册到共享服务的ID
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
    /// 创建一个使用共享健康检查服务的ProxyUpstream
    pub fn new_with_shared_health_check(upstream: config::Upstream) -> Result<Self> {
        let mut proxy_upstream = ProxyUpstream {
            inner: upstream.clone(),
            lb: SelectionLB::try_from(upstream.clone())?,
            health_check_id: None,
        };

        // 注册到共享健康检查服务
        if let Err(e) = proxy_upstream.register_health_check() {
            log::warn!(
                "Failed to register health check for upstream '{}': {}",
                upstream.id,
                e
            );
        }

        Ok(proxy_upstream)
    }

    /// 注册健康检查到共享服务
    fn register_health_check(&mut self) -> Result<()> {
        // 直接获取 LoadBalancer 的 Arc 引用
        let load_balancer: Arc<
            dyn pingora_core::services::background::BackgroundService + Send + Sync,
        > = match &self.lb {
            SelectionLB::RoundRobin(lb) => lb.upstreams.clone(),
            SelectionLB::Random(lb) => lb.upstreams.clone(),
            SelectionLB::Fnv(lb) => lb.upstreams.clone(),
            SelectionLB::Ketama(lb) => lb.upstreams.clone(),
        };

        let upstream_id = self.inner.id.clone();

        // 注册到共享服务
        SHARED_HEALTH_CHECK_SERVICE
            .register_upstream(upstream_id.clone(), load_balancer)
            .map_err(|e| {
                Error::explain(
                    pingora_error::ErrorType::InternalError,
                    format!("Failed to register health check: {e}"),
                )
            })?;

        self.health_check_id = Some(upstream_id);
        info!(
            "Registered upstream '{}' to shared health check service",
            self.inner.id
        );

        Ok(())
    }

    /// Selects a backend server for a given session.
    pub fn select_backend<'a>(&'a self, session: &'a mut Session) -> Option<Backend> {
        let key = request_selector_key(session, &self.inner.hash_on, self.inner.key.as_str());
        log::debug!("proxy lb key: {}", &key);

        let mut backend = match &self.lb {
            SelectionLB::RoundRobin(lb) => lb.upstreams.select(key.as_bytes(), 256),
            SelectionLB::Random(lb) => lb.upstreams.select(key.as_bytes(), 256),
            SelectionLB::Fnv(lb) => lb.upstreams.select(key.as_bytes(), 256),
            SelectionLB::Ketama(lb) => lb.upstreams.select(key.as_bytes(), 256),
        };

        if let Some(backend) = backend.as_mut() {
            if let Some(peer) = backend.ext.get_mut::<HttpPeer>() {
                self.set_timeout(peer);
            }
        }

        backend
    }

    /// Rewrites the upstream host in the request header if needed.
    pub fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader) {
        if self.inner.pass_host == config::UpstreamPassHost::REWRITE {
            if let Some(host) = &self.inner.upstream_host {
                upstream_request
                    .insert_header(http::header::HOST, host)
                    .unwrap();
            }
        }
    }

    /// 停止健康检查服务
    fn stop_health_check(&mut self) {
        if let Some(upstream_id) = self.health_check_id.take() {
            SHARED_HEALTH_CHECK_SERVICE.unregister_upstream(&upstream_id);
            info!("Unregistered upstream '{upstream_id}' from shared health check service");
        }
    }

    /// Gets the number of retries from the upstream configuration.
    pub fn get_retries(&self) -> Option<usize> {
        self.inner.retries.map(|r| r as _)
    }

    /// Gets the retry timeout from the upstream configuration.
    pub fn get_retry_timeout(&self) -> Option<u64> {
        self.inner.retry_timeout
    }

    /// Sets the timeout for an `HttpPeer`.
    fn set_timeout(&self, p: &mut HttpPeer) {
        if let Some(config::Timeout {
            connect,
            read,
            send,
        }) = self.inner.timeout
        {
            p.options.connection_timeout = Some(Duration::from_secs(connect));
            p.options.read_timeout = Some(Duration::from_secs(read));
            p.options.write_timeout = Some(Duration::from_secs(send));
        }
    }
}

impl Drop for ProxyUpstream {
    /// 停止健康检查服务
    fn drop(&mut self) {
        self.stop_health_check();
    }
}

enum SelectionLB {
    RoundRobin(LB<RoundRobin>),
    Random(LB<Random>),
    Fnv(LB<FVNHash>),
    Ketama(LB<KetamaHashing>),
}

impl TryFrom<config::Upstream> for SelectionLB {
    type Error = Box<Error>;

    fn try_from(value: config::Upstream) -> Result<Self> {
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
    type Error = Box<Error>;

    fn try_from(upstream: config::Upstream) -> Result<Self> {
        let discovery: HybridDiscovery = upstream.clone().try_into()?;
        let mut upstreams = LoadBalancer::<BS>::from_backends(Backends::new(Box::new(discovery)));

        if let Some(check) = upstream.checks {
            let health_check: Box<(dyn HealthCheckTrait + Send + Sync + 'static)> =
                check.clone().into();
            upstreams.set_health_check(health_check);

            let health_check_frequency = check
                .active
                .healthy
                .map(|healthy| Duration::from_secs(healthy.interval as _))
                .unwrap_or(Duration::from_secs(1));

            upstreams.health_check_frequency = Some(health_check_frequency);
        }

        let background =
            background_service(&format!("health check for {}", upstream.id), upstreams);
        let upstreams = background.task();

        let this = Self { upstreams };

        Ok(this)
    }
}

impl From<config::HealthCheck> for Box<(dyn HealthCheckTrait + Send + Sync + 'static)> {
    fn from(value: config::HealthCheck) -> Self {
        match value.active.r#type {
            config::ActiveCheckType::TCP => {
                let health_check: Box<TcpHealthCheck> = value.into();
                health_check
            }
            config::ActiveCheckType::HTTP | config::ActiveCheckType::HTTPS => {
                let health_check: Box<HttpHealthCheck> = value.into();
                health_check
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

// Define a global upstream map, initialized lazily
pub static UPSTREAM_MAP: Lazy<DashMap<String, Arc<ProxyUpstream>>> = Lazy::new(DashMap::new);

/// Loads upstreams from the given configuration.
pub fn load_static_upstreams(config: &config::Config) -> Result<()> {
    // Collect all ProxyUpstream instances into a vector.
    let proxy_upstreams: Vec<Arc<ProxyUpstream>> = config
        .upstreams
        .iter()
        .map(|upstream| {
            info!("Configuring Upstream: {}", upstream.id);
            match ProxyUpstream::new_with_shared_health_check(upstream.clone()) {
                Ok(proxy_upstream) => Ok(Arc::new(proxy_upstream)),
                Err(e) => {
                    log::error!("Failed to configure Upstream {}: {}", upstream.id, e);
                    Err(e)
                }
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let upstream_count = proxy_upstreams.len();

    // Insert all ProxyUpstream instances into the global map.
    UPSTREAM_MAP.reload_resources(proxy_upstreams);

    info!("Loaded {upstream_count} upstreams with shared health check service");
    Ok(())
}
