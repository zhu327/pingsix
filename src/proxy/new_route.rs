//! New route implementation that implements RouteResolver trait
//!
//! This module provides the refactored route implementation that eliminates
//! circular dependencies by implementing the RouteResolver trait.

use std::{collections::HashMap, sync::Arc, time::Duration};

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;

use crate::{
    config::{self, Identifiable},
    core::{
        error::{ProxyError, ProxyResult},
        registry::ResourceRegistry,
        traits::{RouteResolver, ServiceProvider, UpstreamProvider},
    },
    plugin::{build_plugin, ProxyPlugin},
};

/// New route implementation that follows the trait-based architecture
pub struct NewProxyRoute {
    pub inner: config::Route,
    pub upstream: Option<Arc<dyn UpstreamProvider>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
    /// Reference to registry for resolving dependencies
    registry: Arc<ResourceRegistry>,
}

impl Identifiable for NewProxyRoute {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl RouteResolver for NewProxyRoute {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamProvider>> {
        // Try direct upstream first
        if let Some(upstream) = &self.upstream {
            return Some(upstream.clone());
        }

        // Try upstream_id
        if let Some(upstream_id) = &self.inner.upstream_id {
            if let Some(upstream) = self.registry.get_upstream(upstream_id) {
                return Some(upstream);
            }
        }

        // Try service_id
        if let Some(service_id) = &self.inner.service_id {
            if let Some(service) = self.registry.get_service(service_id) {
                return service.get_upstream_provider();
            }
        }

        None
    }

    fn select_http_peer(&self, session: &mut Session) -> ProxyResult<Box<HttpPeer>> {
        let upstream = self.resolve_upstream().ok_or_else(|| {
            ProxyError::UpstreamSelection(
                "Failed to retrieve upstream configuration for route".to_string(),
            )
        })?;

        let mut backend = upstream.select_backend(session).ok_or_else(|| {
            ProxyError::UpstreamSelection("Unable to determine backend for the request".to_string())
        })?;

        let peer = backend.ext.get_mut::<HttpPeer>().ok_or_else(|| {
            ProxyError::UpstreamSelection(
                "Missing selected backend metadata for HttpPeer".to_string(),
            )
        })?;

        self.set_timeout(peer);
        Ok(Box::new(peer.clone()))
    }

    fn priority(&self) -> u32 {
        self.inner.priority
    }

    fn get_hosts(&self) -> Vec<String> {
        self.get_hosts_internal()
    }

    fn get_uris(&self) -> Vec<String> {
        self.inner.get_uris()
    }

    fn matches(&self, host: Option<&str>, _path: &str) -> bool {
        let route_hosts = self.get_hosts_internal();
        
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

impl NewProxyRoute {
    /// Create a new route from configuration
    pub fn new(
        route_config: config::Route,
        registry: Arc<ResourceRegistry>,
    ) -> ProxyResult<Self> {
        let mut route = Self {
            inner: route_config.clone(),
            upstream: None,
            plugins: Vec::new(),
            registry,
        };

        // Configure upstream if present
        if let Some(upstream_config) = route_config.upstream {
            let upstream = super::new_upstream::create_upstream_provider(upstream_config)?;
            route.upstream = Some(upstream);
        }

        // Load plugins
        for (name, config) in route_config.plugins {
            let plugin = build_plugin(&name, config).map_err(|e| {
                ProxyError::Plugin(format!("Failed to build plugin '{}': {}", name, e))
            })?;
            route.plugins.push(plugin);
        }

        Ok(route)
    }

    /// Get the list of hosts for the route (internal implementation)
    fn get_hosts_internal(&self) -> Vec<String> {
        let hosts = self.inner.get_hosts();
        if !hosts.is_empty() {
            hosts
        } else if let Some(service_id) = &self.inner.service_id {
            if let Some(service) = self.registry.get_service(service_id) {
                service.get_hosts().to_vec()
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }

    /// Set timeout configuration for an HttpPeer
    fn set_timeout(&self, peer: &mut HttpPeer) {
        if let Some(config::Timeout { connect, read, send }) = self.inner.timeout {
            peer.options.connection_timeout = Some(Duration::from_secs(connect));
            peer.options.read_timeout = Some(Duration::from_secs(read));
            peer.options.write_timeout = Some(Duration::from_secs(send));
        }
    }

    /// Get route plugins
    pub fn get_plugins(&self) -> &[Arc<dyn ProxyPlugin>] {
        &self.plugins
    }


}

/// Factory function to create route resolvers from configuration
pub fn create_route_resolver(
    config: config::Route,
    registry: Arc<ResourceRegistry>,
) -> ProxyResult<Arc<dyn RouteResolver>> {
    let route = NewProxyRoute::new(config, registry)?;
    Ok(Arc::new(route))
}