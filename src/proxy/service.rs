use std::{collections::HashMap, sync::Arc};

use crate::{
    config::{self, Identifiable},
    core::{
        sort_plugins_by_priority_desc, ErrorContext, ProxyError, ProxyPlugin, ProxyResult,
        UpstreamSelector,
    },
    plugins::build_plugin_with_upstreams,
};

use super::upstream::{inline_key, PreparedUpstreams, ProxyUpstream};

/// Represents a proxy service that manages upstreams.
pub struct ProxyService {
    pub inner: config::Service,
    pub upstream: Option<Arc<dyn UpstreamSelector>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
    pub inline_upstream: Option<Arc<ProxyUpstream>>,
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
    pub(crate) fn build(
        service: config::Service,
        upstreams: &HashMap<String, Arc<ProxyUpstream>>,
        prepared: &PreparedUpstreams,
    ) -> ProxyResult<Self> {
        let inline_upstream = if let Some(ref upstream_config) = service.upstream {
            Some(Arc::new(
                ProxyUpstream::build(
                    upstream_config.clone(),
                    prepared
                        .get(&inline_key(&format!("service/{}", service.id)))
                        .cloned()
                        .ok_or_else(|| {
                            ProxyError::Configuration(format!(
                                "Service '{}' inline upstream was not prepared",
                                service.id
                            ))
                        })?,
                )
                .with_context(&format!(
                    "Failed to create upstream for service '{}'",
                    service.id
                ))?,
            ))
        } else {
            None
        };
        let upstream = if let Some(proxy_upstream) = &inline_upstream {
            Some(proxy_upstream.clone() as Arc<dyn UpstreamSelector>)
        } else if let Some(upstream_id) = service.upstream_id.as_deref() {
            Some(upstreams.get(upstream_id).cloned().ok_or_else(|| {
                ProxyError::Configuration(format!(
                    "Service '{}' references missing upstream '{}'",
                    service.id, upstream_id
                ))
            })? as Arc<dyn UpstreamSelector>)
        } else {
            None
        };

        let mut proxy_service = ProxyService {
            inner: service.clone(),
            upstream,
            plugins: Vec::with_capacity(service.plugins.len()),
            inline_upstream,
        };

        // Load configured plugins
        for (name, value) in service.plugins {
            let plugin = build_plugin_with_upstreams(
                &name,
                value,
                upstreams,
                prepared,
                &format!("service/{}", service.id),
            )
            .map_err(|e| {
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
        self.upstream.clone()
    }
}
