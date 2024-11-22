use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use once_cell::sync::Lazy;
use pingora_error::Result;

use crate::config::{Config, Service};

use super::upstream::{upstream_fetch, ProxyUpstream};

/// Represents a proxy service that manages upstreams.
pub struct ProxyService {
    pub inner: Service,
    pub upstream: Option<Arc<ProxyUpstream>>,
}

impl From<Service> for ProxyService {
    fn from(value: Service) -> Self {
        Self {
            inner: value,
            upstream: None,
        }
    }
}

impl ProxyService {
    /// Gets the upstream for the service.
    pub fn get_upstream(&self) -> Option<Arc<ProxyUpstream>> {
        if self.upstream.is_some() {
            return self.upstream.clone();
        };

        self.inner.upstream_id.as_deref().and_then(upstream_fetch)
    }
}

/// Global map to store services, initialized lazily.
static SERVICE_MAP: Lazy<RwLock<HashMap<String, Arc<ProxyService>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Loads services from the given configuration.
pub fn load_services(config: &Config) -> Result<()> {
    let mut map = SERVICE_MAP
        .write()
        .expect("Failed to acquire write lock on the service map");

    for service in config.services.iter() {
        log::info!("Configuring Service: {}", service.id);
        let mut proxy_service = ProxyService::from(service.clone());

        if let Some(upstream) = service.upstream.clone() {
            let mut proxy_upstream = ProxyUpstream::try_from(upstream)?;
            proxy_upstream.start_health_check(config.pingora.work_stealing);

            proxy_service.upstream = Some(Arc::new(proxy_upstream));
        }

        map.insert(service.id.clone(), Arc::new(proxy_service));
    }

    Ok(())
}

/// Fetches a service by its ID.
pub fn service_fetch(id: &str) -> Option<Arc<ProxyService>> {
    let map = SERVICE_MAP.read().unwrap();
    map.get(id).cloned()
}
