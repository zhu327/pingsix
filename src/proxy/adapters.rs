//! Adapters for bridging old and new implementations
//!
//! This module provides adapters that allow existing implementations
//! to work with the new trait-based architecture during migration.

use std::sync::Arc;

use async_trait::async_trait;
use pingora_load_balancing::Backend;
use pingora_proxy::Session;

use crate::{
    core::traits::{RouteResolver, ServiceProvider, UpstreamProvider},
    proxy::{route::ProxyRoute, service::ProxyService, upstream::ProxyUpstream},
};

/// Adapter for existing ProxyUpstream to implement UpstreamProvider
pub struct UpstreamAdapter {
    inner: Arc<ProxyUpstream>,
}

impl UpstreamAdapter {
    pub fn new(upstream: Arc<ProxyUpstream>) -> Self {
        Self { inner: upstream }
    }
}

impl UpstreamProvider for UpstreamAdapter {
    fn select_backend(&self, session: &Session) -> Option<Backend> {
        // Create a mutable clone for the existing API
        // This is not ideal but necessary for compatibility
        let mut session_clone = session.clone();
        self.inner.select_backend(&mut session_clone)
    }

    fn id(&self) -> &str {
        self.inner.id()
    }

    fn get_retries(&self) -> Option<usize> {
        self.inner.get_retries()
    }

    fn get_retry_timeout(&self) -> Option<u64> {
        self.inner.get_retry_timeout()
    }
}

/// Adapter for existing ProxyService to implement ServiceProvider
pub struct ServiceAdapter {
    inner: Arc<ProxyService>,
}

impl ServiceAdapter {
    pub fn new(service: Arc<ProxyService>) -> Self {
        Self { inner: service }
    }
}

impl ServiceProvider for ServiceAdapter {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn get_upstream_provider(&self) -> Option<Arc<dyn UpstreamProvider>> {
        self.inner.resolve_upstream().map(|upstream| {
            Arc::new(UpstreamAdapter::new(upstream)) as Arc<dyn UpstreamProvider>
        })
    }

    fn get_hosts(&self) -> &[String] {
        &self.inner.inner.hosts
    }
}

/// Adapter for existing ProxyRoute to implement RouteResolver
pub struct RouteAdapter {
    inner: Arc<ProxyRoute>,
}

impl RouteAdapter {
    pub fn new(route: Arc<ProxyRoute>) -> Self {
        Self { inner: route }
    }
}

impl RouteResolver for RouteAdapter {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamProvider>> {
        self.inner.resolve_upstream().map(|upstream| {
            Arc::new(UpstreamAdapter::new(upstream)) as Arc<dyn UpstreamProvider>
        })
    }

    fn select_http_peer(&self, session: &mut Session) -> crate::core::error::ProxyResult<Box<pingora_core::upstreams::peer::HttpPeer>> {
        self.inner.select_http_peer(session).map_err(|e| e.into())
    }

    fn priority(&self) -> u32 {
        self.inner.inner.priority
    }

    fn get_hosts(&self) -> Vec<String> {
        self.inner.get_hosts()
    }

    fn get_uris(&self) -> Vec<String> {
        self.inner.inner.get_uris()
    }

    fn matches(&self, host: Option<&str>, _path: &str) -> bool {
        let route_hosts = self.get_hosts();
        
        // If no hosts specified, match any host
        if route_hosts.is_empty() {
            return true;
        }

        // Check if request host matches any route host
        if let Some(req_host) = host {
            route_hosts.iter().any(|route_host| route_host == req_host)
        } else {
            false
        }
    }
}

/// Migration helper to populate registry from existing global maps
pub fn populate_registry_from_global_maps(registry: &crate::core::ResourceRegistry) {
    info!("Populating registry from existing global maps...");

    // Migrate upstreams
    for entry in crate::proxy::upstream::UPSTREAM_MAP.iter() {
        let (id, upstream) = entry.pair();
        let adapter = Arc::new(UpstreamAdapter::new(upstream.clone()));
        registry.insert_upstream(id.clone(), adapter);
    }

    // Migrate services
    for entry in crate::proxy::service::SERVICE_MAP.iter() {
        let (id, service) = entry.pair();
        let adapter = Arc::new(ServiceAdapter::new(service.clone()));
        registry.insert_service(id.clone(), adapter);
    }

    // Migrate routes
    for entry in crate::proxy::route::ROUTE_MAP.iter() {
        let (id, route) = entry.pair();
        let adapter = Arc::new(RouteAdapter::new(route.clone()));
        registry.insert_route(id.clone(), adapter);
    }

    let stats = registry.get_stats();
    info!(
        "Registry populated: {} routes, {} upstreams, {} services",
        stats.route_count, stats.upstream_count, stats.service_count
    );
}