//! New service implementation that implements ServiceProvider trait
//!
//! This module provides the refactored service implementation that eliminates
//! circular dependencies by implementing the ServiceProvider trait.

use std::{collections::HashMap, sync::Arc};

use crate::{
    config::{self, Identifiable},
    core::{
        error::{ProxyError, ProxyResult},
        registry::ResourceRegistry,
        traits::{ServiceProvider, UpstreamProvider},
    },
    plugin::{build_plugin, ProxyPlugin},
};

/// New service implementation that follows the trait-based architecture
pub struct NewProxyService {
    pub inner: config::Service,
    pub upstream: Option<Arc<dyn UpstreamProvider>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl Identifiable for NewProxyService {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ServiceProvider for NewProxyService {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn get_upstream_provider(&self) -> Option<Arc<dyn UpstreamProvider>> {
        self.upstream.clone()
    }

    fn get_hosts(&self) -> &[String] {
        &self.inner.hosts
    }
}

impl NewProxyService {
    /// Create a new service from configuration
    pub fn new(
        service_config: config::Service,
        registry: &ResourceRegistry,
    ) -> ProxyResult<Self> {
        let mut service = Self {
            inner: service_config.clone(),
            upstream: None,
            plugins: Vec::new(),
        };

        // Resolve upstream
        if let Some(upstream_config) = service_config.upstream {
            // Create upstream directly from config
            let upstream = super::new_upstream::create_upstream_provider(upstream_config)?;
            service.upstream = Some(upstream);
        } else if let Some(upstream_id) = &service_config.upstream_id {
            // Get upstream from registry
            service.upstream = registry.get_upstream(upstream_id);
            if service.upstream.is_none() {
                return Err(ProxyError::Configuration(format!(
                    "Upstream '{}' not found for service '{}'",
                    upstream_id, service_config.id
                )));
            }
        }

        // Load plugins
        for (name, config) in service_config.plugins {
            let plugin = build_plugin(&name, config).map_err(|e| {
                ProxyError::Plugin(format!("Failed to build plugin '{}': {}", name, e))
            })?;
            service.plugins.push(plugin);
        }

        Ok(service)
    }

    /// Resolve upstream provider for this service
    pub fn resolve_upstream_provider(&self, registry: &ResourceRegistry) -> Option<Arc<dyn UpstreamProvider>> {
        // First try direct upstream
        if let Some(upstream) = &self.upstream {
            return Some(upstream.clone());
        }

        // Then try upstream_id
        if let Some(upstream_id) = &self.inner.upstream_id {
            return registry.get_upstream(upstream_id);
        }

        None
    }

    /// Get service plugins
    pub fn get_plugins(&self) -> &[Arc<dyn ProxyPlugin>] {
        &self.plugins
    }
}

/// Factory function to create service providers from configuration
pub fn create_service_provider(
    config: config::Service,
    registry: &ResourceRegistry,
) -> ProxyResult<Arc<dyn ServiceProvider>> {
    let service = NewProxyService::new(config, registry)?;
    Ok(Arc::new(service))
}