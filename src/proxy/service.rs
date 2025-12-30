use std::sync::Arc;

use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::{
    config::{self, Identifiable},
    core::{
        sort_plugins_by_priority_desc, ErrorContext, ProxyError, ProxyPlugin, ProxyResult,
        UpstreamSelector,
    },
    plugins::build_plugin,
};

use super::{
    upstream::{upstream_fetch, ProxyUpstream},
    MapOperations,
};

/// Fetches a service by its ID.
pub fn service_fetch(id: &str) -> Option<Arc<ProxyService>> {
    match SERVICE_MAP.get(id) {
        Some(service) => Some(service.value().clone()),
        None => {
            log::debug!("Service '{id}' not found in cache");
            None
        }
    }
}

/// Represents a proxy service that manages upstreams.
pub struct ProxyService {
    pub inner: config::Service,
    pub upstream: Option<Arc<ProxyUpstream>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl Identifiable for ProxyService {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyService {
    pub fn new_with_upstream_and_plugins(service: config::Service) -> ProxyResult<Self> {
        let mut proxy_service = ProxyService {
            inner: service.clone(),
            upstream: None,
            plugins: Vec::with_capacity(service.plugins.len()),
        };

        // Configure upstream if specified
        if let Some(ref upstream_config) = service.upstream {
            let proxy_upstream =
                ProxyUpstream::new_with_shared_health_check(upstream_config.clone()).with_context(
                    &format!("Failed to create upstream for service '{}'", service.id),
                )?;
            proxy_service.upstream = Some(Arc::new(proxy_upstream));
        }

        // Load configured plugins
        for (name, value) in service.plugins {
            let plugin = build_plugin(&name, value).map_err(|e| {
                ProxyError::Plugin(format!(
                    "Failed to build plugin '{}' for service '{}': {}",
                    name, service.id, e
                ))
            })?;
            proxy_service.plugins.push(plugin);
        }

        // Pre-sort plugins once at build-time to avoid per-request sorting in route+service merges.
        sort_plugins_by_priority_desc(proxy_service.plugins.as_mut_slice());

        Ok(proxy_service)
    }

    /// Gets the upstream for the service.
    pub fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>> {
        self.upstream
            .clone()
            .map(|u| u as Arc<dyn UpstreamSelector>)
            .or_else(|| {
                self.inner
                    .upstream_id
                    .as_deref()
                    .and_then(upstream_fetch)
                    .map(|u| u as Arc<dyn UpstreamSelector>)
            })
    }
}

/// Global map to store services, initialized lazily.
pub static SERVICE_MAP: Lazy<DashMap<String, Arc<ProxyService>>> = Lazy::new(DashMap::new);

/// Loads services from the given configuration.
pub fn load_static_services(config: &config::Config) -> ProxyResult<()> {
    let proxy_services: Vec<Arc<ProxyService>> = config
        .services
        .iter()
        .map(|service| {
            log::info!("Configuring Service: {}", service.id);
            match ProxyService::new_with_upstream_and_plugins(service.clone()) {
                Ok(proxy_service) => Ok(Arc::new(proxy_service)),
                Err(e) => {
                    log::error!("Failed to configure Service {}: {}", service.id, e);
                    Err(e)
                }
            }
        })
        .collect::<ProxyResult<Vec<_>>>()?;

    SERVICE_MAP.reload_resources(proxy_services);

    Ok(())
}
