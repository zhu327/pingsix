use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use once_cell::sync::Lazy;
use pingora_error::Result;

use crate::config;

use super::{
    plugin::{build_plugin, ProxyPlugin},
    upstream::{upstream_fetch, ProxyUpstream},
    Identifiable, MapOperations,
};

/// Fetches a service by its ID.
pub fn service_fetch(id: &str) -> Option<Arc<ProxyService>> {
    SERVICE_MAP.get(id)
}

/// Represents a proxy service that manages upstreams.
pub struct ProxyService {
    pub inner: config::Service,
    pub upstream: Option<Arc<ProxyUpstream>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl From<config::Service> for ProxyService {
    fn from(value: config::Service) -> Self {
        Self {
            inner: value,
            upstream: None,
            plugins: Vec::new(),
        }
    }
}

impl Identifiable for ProxyService {
    fn id(&self) -> String {
        self.inner.id.clone()
    }
}

impl ProxyService {
    pub fn new_with_upstream_and_plugins(
        service: config::Service,
        work_stealing: bool,
    ) -> Result<Self> {
        let mut proxy_service = Self::from(service.clone());

        // 配置 upstream
        if let Some(ref upstream_config) = service.upstream {
            let mut proxy_upstream = ProxyUpstream::try_from(upstream_config.clone())?;
            proxy_upstream.start_health_check(work_stealing);
            proxy_service.upstream = Some(Arc::new(proxy_upstream));
        }

        // 加载插件
        for (name, value) in service.plugins {
            let plugin = build_plugin(&name, value)?;
            proxy_service.plugins.push(plugin);
        }

        Ok(proxy_service)
    }

    /// Gets the upstream for the service.
    pub fn get_upstream(&self) -> Option<Arc<ProxyUpstream>> {
        if self.upstream.is_some() {
            return self.upstream.clone();
        };

        self.inner.upstream_id.as_deref().and_then(upstream_fetch)
    }
}

/// Global map to store services, initialized lazily.
pub static SERVICE_MAP: Lazy<RwLock<HashMap<String, Arc<ProxyService>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Loads services from the given configuration.
pub fn load_services(config: &config::Config) -> Result<()> {
    let proxy_services: Vec<Arc<ProxyService>> = config
        .services
        .iter()
        .map(|service| {
            log::info!("Configuring Service: {}", service.id);
            let proxy_service = ProxyService::new_with_upstream_and_plugins(
                service.clone(),
                config.pingora.work_stealing,
            )?;

            Ok(Arc::new(proxy_service))
        })
        .collect::<Result<Vec<_>>>()?;

    SERVICE_MAP.reload_resource(proxy_services);

    Ok(())
}
