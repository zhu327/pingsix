//! New upstream implementation that implements UpstreamProvider trait
//!
//! This module provides the refactored upstream implementation that eliminates
//! circular dependencies by implementing the UpstreamProvider trait.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use pingora_load_balancing::{Backend, LoadBalancer};
use pingora_proxy::Session;

use crate::{
    config::{self, Identifiable},
    core::{
        error::{ProxyError, ProxyResult},
        traits::UpstreamProvider,
    },
    proxy::{
        discovery::HybridDiscovery,
        upstream::{SelectionLB, UPSTREAM_MAP}, // Temporarily use existing types
    },
    utils::request::request_selector_key,
};

/// New upstream implementation that follows the trait-based architecture
pub struct NewProxyUpstream {
    pub inner: config::Upstream,
    lb: SelectionLB,
}

impl Identifiable for NewProxyUpstream {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

#[async_trait]
impl UpstreamProvider for NewProxyUpstream {
    fn select_backend(&self, session: &Session) -> Option<Backend> {
        let key = request_selector_key(
            &mut session.clone(), // TODO: This clone should be avoided
            &self.inner.hash_on,
            self.inner.key.as_str(),
        );
        
        log::debug!("Upstream selection key: {}", &key);

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

    fn id(&self) -> &str {
        &self.inner.id
    }

    fn get_retries(&self) -> Option<usize> {
        self.inner.retries.map(|r| r as usize)
    }

    fn get_retry_timeout(&self) -> Option<u64> {
        self.inner.retry_timeout
    }
}

impl NewProxyUpstream {
    /// Create a new upstream from configuration
    pub fn new(upstream_config: config::Upstream) -> ProxyResult<Self> {
        let lb = SelectionLB::try_from(upstream_config.clone()).map_err(|e| {
            ProxyError::Configuration(format!("Failed to create load balancer: {e}"))
        })?;

        Ok(Self {
            inner: upstream_config,
            lb,
        })
    }

    /// Set timeout configuration for an HttpPeer
    fn set_timeout(&self, peer: &mut HttpPeer) {
        if let Some(config::Timeout { connect, read, send }) = self.inner.timeout {
            peer.options.connection_timeout = Some(Duration::from_secs(connect));
            peer.options.read_timeout = Some(Duration::from_secs(read));
            peer.options.write_timeout = Some(Duration::from_secs(send));
        }
    }

    /// Rewrite upstream host header if needed
    pub fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader) {
        if self.inner.pass_host == config::UpstreamPassHost::REWRITE {
            if let Some(host) = &self.inner.upstream_host {
                upstream_request
                    .insert_header(http::header::HOST, host)
                    .unwrap_or_else(|e| log::error!("Failed to set host header: {}", e));
            }
        }
    }

    /// Get the upstream scheme
    pub fn get_scheme(&self) -> &config::UpstreamScheme {
        &self.inner.scheme
    }

    /// Check if this upstream has health checks configured
    pub fn has_health_check(&self) -> bool {
        self.inner.checks.is_some()
    }
}

/// Factory function to create upstream providers from configuration
pub fn create_upstream_provider(config: config::Upstream) -> ProxyResult<Arc<dyn UpstreamProvider>> {
    let upstream = NewProxyUpstream::new(config)?;
    Ok(Arc::new(upstream))
}