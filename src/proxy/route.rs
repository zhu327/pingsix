use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use matchit::{InsertError, Router as MatchRouter};
use once_cell::sync::Lazy;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Result;
use pingora_proxy::Session;

use crate::{
    config::{self, Identifiable},
    core::{
        ErrorContext, ProxyError, ProxyPlugin, ProxyPluginExecutor, ProxyResult, RouteContext,
        UpstreamSelector,
    },
    plugin::build_plugin,
    utils::request::get_request_host,
};

use super::{
    service::service_fetch,
    upstream::{upstream_fetch, ProxyUpstream},
    MapOperations,
};

/// Proxy route with upstream and plugin configuration.
///
/// Routes are compiled at startup and cached for high-performance request matching.
/// Plugin executors are dynamically built to ensure configuration changes take effect immediately.
pub struct ProxyRoute {
    pub inner: config::Route,
    pub upstream: Option<Arc<ProxyUpstream>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl Identifiable for ProxyRoute {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyRoute {
    pub fn new_with_upstream_and_plugins(route: config::Route) -> ProxyResult<Self> {
        let mut proxy_route = ProxyRoute {
            inner: route.clone(),
            upstream: None,
            plugins: Vec::with_capacity(route.plugins.len()),
        };

        // Configure upstream
        if let Some(upstream_config) = route.upstream {
            let proxy_upstream =
                ProxyUpstream::new_with_shared_health_check(upstream_config).with_context(
                    &format!("Failed to create upstream for route '{}'", route.id),
                )?;
            proxy_route.upstream = Some(Arc::new(proxy_upstream));
        }

        // Load plugins
        for (name, value) in route.plugins {
            let plugin = build_plugin(&name, value)
                .map_err(|e| ProxyError::Plugin(format!("Failed to build plugin '{name}': {e}")))?;
            proxy_route.plugins.push(plugin);
        }

        Ok(proxy_route)
    }

    /// Gets the list of hosts for the route.
    fn get_hosts(&self) -> Vec<String> {
        let hosts = self.inner.get_hosts();
        if !hosts.is_empty() {
            hosts
        } else if let Some(service) = self
            .inner
            .service_id
            .as_ref()
            .and_then(|id| service_fetch(id.as_str()))
        {
            service.inner.hosts.clone()
        } else {
            vec![]
        }
    }
}

impl RouteContext for ProxyRoute {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn service_id(&self) -> Option<&str> {
        self.inner.service_id.as_deref()
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

    fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor> {
        let mut plugin_map: HashMap<String, Arc<dyn ProxyPlugin>> = HashMap::new();

        // Merge route and service plugins
        // Service plugins are fetched dynamically to ensure configuration changes take effect
        let service_plugins = self
            .inner
            .service_id
            .as_deref()
            .and_then(service_fetch)
            .map_or_else(Vec::new, |service| service.plugins.clone());

        // Route plugins take precedence over service plugins (first inserted wins)
        for plugin in self.plugins.iter().chain(service_plugins.iter()) {
            plugin_map
                .entry(plugin.name().to_string())
                .or_insert_with(|| plugin.clone());
        }

        // Sort by priority in descending order
        let mut merged_plugins: Vec<_> = plugin_map.into_values().collect();
        merged_plugins.sort_by_key(|b| std::cmp::Reverse(b.priority()));

        Arc::new(ProxyPluginExecutor {
            plugins: merged_plugins,
        })
    }

    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>> {
        self.upstream
            .clone()
            .map(|u| u as Arc<dyn UpstreamSelector>)
            .or_else(|| {
                self.inner
                    .upstream_id
                    .as_ref()
                    .and_then(|id| upstream_fetch(id.as_str()))
                    .map(|u| u as Arc<dyn UpstreamSelector>)
            })
            .or_else(|| {
                self.inner
                    .service_id
                    .as_ref()
                    .and_then(|id| service_fetch(id).and_then(|s| s.resolve_upstream()))
            })
    }
}

impl ProxyRoute {
    /// Sets the timeout for an `HttpPeer` based on the route configuration.
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

#[derive(Default)]
pub struct MatchEntry {
    /// Router for non-host URI matching
    non_host_uri: MatchRouter<Vec<Arc<ProxyRoute>>>,
    /// Router for host URI matching
    host_uris: MatchRouter<MatchRouter<Vec<Arc<ProxyRoute>>>>,
    /// Cache for reversed host strings to avoid repeated computation
    reversed_host_cache: DashMap<String, String>,
}

impl MatchEntry {
    /// Helper method to get or compute reversed host string with caching
    /// Converts wildcard patterns to matchit format for reversed hosts
    fn get_reversed_host(&self, host: &str) -> String {
        self.reversed_host_cache
            .entry(host.to_string())
            .or_insert_with(|| {
                if let Some(domain_part) = host.strip_prefix("*") {
                    // Convert "*.example.com" to "moc.elpmaxe.{*subdomain}"
                    // This allows matchit to match any subdomain suffix when reversed
                    let reversed_domain: String = domain_part.chars().rev().collect();
                    format!("{reversed_domain}{{*subdomain}}")
                } else {
                    // For exact hosts, just reverse normally
                    host.chars().rev().collect()
                }
            })
            .clone()
    }

    fn insert_into_router(
        router: &mut MatchRouter<Vec<Arc<ProxyRoute>>>,
        uri: &str,
        proxy_route: Arc<ProxyRoute>,
    ) -> Result<(), InsertError> {
        match router.at_mut(uri) {
            Ok(routes) => {
                routes.value.push(proxy_route);
                // Sort routes by priority (higher priority values take precedence)
                routes
                    .value
                    .sort_by(|a, b| b.inner.priority.cmp(&a.inner.priority));
            }
            Err(_) => {
                router.insert(uri, vec![proxy_route])?;
            }
        }
        Ok(())
    }

    /// Inserts a route into the match entry.
    pub fn insert_route(&mut self, proxy_route: Arc<ProxyRoute>) -> Result<(), InsertError> {
        let hosts = proxy_route.get_hosts();
        let uris = proxy_route.inner.get_uris();

        if hosts.is_empty() {
            // Insert for non-host URIs
            for uri in &uris {
                Self::insert_into_router(&mut self.non_host_uri, uri, proxy_route.clone())?;
            }
        } else {
            // Insert for host URIs
            // Host strings are processed for wildcard matching:
            // - Exact hosts are reversed: "example.com" → "moc.elpmaxe"
            // - Wildcard hosts are converted: "*.example.com" → "moc.elpmaxe.{*subdomain}"
            // This enables efficient suffix matching using matchit's prefix-based router
            for host in hosts.iter() {
                let processed_host = self.get_reversed_host(host);
                let inner_router = self.host_uris.at_mut(processed_host.as_str());

                let inner_router = match inner_router {
                    Ok(router) => router.value,
                    Err(_) => {
                        let new_router = MatchRouter::new();
                        self.host_uris.insert(processed_host.clone(), new_router)?;
                        self.host_uris
                            .at_mut(processed_host.as_str())
                            .unwrap()
                            .value
                    }
                };

                for uri in &uris {
                    Self::insert_into_router(inner_router, uri, proxy_route.clone())?;
                }
            }
        }

        Ok(())
    }

    /// Matches a request to a route.
    pub fn match_request(
        &self,
        session: &mut Session,
    ) -> Option<(BTreeMap<String, String>, Arc<ProxyRoute>)> {
        let host = get_request_host(session.req_header());
        let uri = session.req_header().uri.path();
        let method = session.req_header().method.as_str();

        log::debug!("match request: host={host:?}, uri={uri:?}, method={method:?}");

        // Attempt to match using host_uris if a valid host is provided
        if let Some(host_str) = host.filter(|h| !h.is_empty()) {
            // Just reverse the host and let matchit handle the matching
            // matchit will automatically match "moc.elpmaxe.ipa" against "moc.elpmaxe.{*subdomain}"
            let reversed_host = host_str.chars().rev().collect::<String>();
            if let Ok(v) = self.host_uris.at(&reversed_host) {
                if let Some(result) = Self::match_uri_method(v.value, uri, method) {
                    return Some(result);
                }
            }
        }

        // Fall back to non-host URI matching
        Self::match_uri_method(&self.non_host_uri, uri, method)
    }

    /// Matches a URI to a route.
    fn match_uri_method(
        match_router: &MatchRouter<Vec<Arc<ProxyRoute>>>,
        uri: &str,
        method: &str,
    ) -> Option<(BTreeMap<String, String>, Arc<ProxyRoute>)> {
        if let Ok(v) = match_router.at(uri) {
            let params: BTreeMap<String, String> = v
                .params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for route in v.value.iter() {
                if route.inner.methods.is_empty() {
                    return Some((params, route.clone()));
                }

                // Match method
                if route.inner.methods.iter().any(|m| *m == method) {
                    return Some((params, route.clone()));
                }
            }
        }
        None
    }
}

/// Global map to store global rules, initialized lazily.
pub static ROUTE_MAP: Lazy<DashMap<String, Arc<ProxyRoute>>> = Lazy::new(DashMap::new);
static GLOBAL_ROUTE_MATCH: Lazy<ArcSwap<MatchEntry>> =
    Lazy::new(|| ArcSwap::new(Arc::new(MatchEntry::default())));

pub fn global_route_match_fetch() -> Arc<MatchEntry> {
    GLOBAL_ROUTE_MATCH.load().clone()
}

pub fn reload_global_route_match() {
    let mut matcher = MatchEntry::default();

    for route in ROUTE_MAP.iter() {
        log::debug!("Inserting route: {}", route.inner.id);
        if let Err(e) = matcher.insert_route(route.clone()) {
            log::error!("Failed to insert route {}: {}", route.inner.id, e);
            // Continue with other routes to avoid partial failures stopping the process
        }
    }

    GLOBAL_ROUTE_MATCH.store(Arc::new(matcher));
}

/// Loads routes from the given configuration.
pub fn load_static_routes(config: &config::Config) -> ProxyResult<()> {
    let proxy_routes: Vec<Arc<ProxyRoute>> = config
        .routes
        .iter()
        .map(|route| {
            log::info!("Configuring Route: {}", route.id);
            match ProxyRoute::new_with_upstream_and_plugins(route.clone()) {
                Ok(proxy_route) => Ok(Arc::new(proxy_route)),
                Err(e) => {
                    log::error!("Failed to configure Route {}: {}", route.id, e);
                    Err(e)
                }
            }
        })
        .collect::<ProxyResult<Vec<_>>>()?;

    ROUTE_MAP.reload_resources(proxy_routes);

    reload_global_route_match();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_host_processing() {
        let match_entry = MatchEntry::default();

        // Test wildcard host conversion
        assert_eq!(
            match_entry.get_reversed_host("*.example.com"),
            "moc.elpmaxe.{*subdomain}"
        );

        // Test exact host conversion
        assert_eq!(
            match_entry.get_reversed_host("api.example.com"),
            "moc.elpmaxe.ipa"
        );

        // Test subdomain extraction logic for matching
        let test_host = "api.example.com";
        if let Some(dot_pos) = test_host.find('.') {
            let domain_part = &test_host[dot_pos + 1..];
            let reversed_domain: String = domain_part.chars().rev().collect();
            let wildcard_pattern = format!("{}.{{*subdomain}}", reversed_domain);

            assert_eq!(domain_part, "example.com");
            assert_eq!(reversed_domain, "moc.elpmaxe");
            assert_eq!(wildcard_pattern, "moc.elpmaxe.{*subdomain}");
        }

        // Test complex subdomain cases
        assert_eq!(
            match_entry.get_reversed_host("*.api.example.com"),
            "moc.elpmaxe.ipa.{*subdomain}"
        );

        // Test single level domain
        assert_eq!(match_entry.get_reversed_host("*.com"), "moc.{*subdomain}");
    }

    #[test]
    fn test_host_matching_patterns() {
        // Test that the wildcard pattern matching logic works correctly
        let match_entry = MatchEntry::default();

        // Test that incoming hosts are simply reversed for matching
        let incoming_host = "api.example.com";
        let reversed_host: String = incoming_host.chars().rev().collect();
        assert_eq!(reversed_host, "moc.elpmaxe.ipa");

        // Wildcard pattern "*.example.com" becomes "moc.elpmaxe.{*subdomain}"
        let wildcard_pattern = match_entry.get_reversed_host("*.example.com");
        assert_eq!(wildcard_pattern, "moc.elpmaxe.{*subdomain}");

        // matchit should be able to match "moc.elpmaxe.ipa" against "moc.elpmaxe.{*subdomain}"
        // This test just verifies our pattern generation is correct
    }

    #[test]
    fn test_matchit_wildcard_matching() {
        // Test that matchit can actually match our patterns
        use matchit::Router as MatchRouter;

        let mut router = MatchRouter::new();

        // Insert a wildcard pattern (simulating *.example.com)
        router
            .insert("moc.elpmaxe.{*subdomain}", "wildcard_route")
            .unwrap();

        // Insert an exact pattern
        router.insert("moc.elpmaxe.ipa", "exact_route").unwrap();

        // Test exact match takes priority
        let result = router.at("moc.elpmaxe.ipa").unwrap();
        assert_eq!(result.value, &"exact_route");

        // Test wildcard matching
        let result = router.at("moc.elpmaxe.ipa.bus").unwrap(); // sub.api.example.com
        assert_eq!(result.value, &"wildcard_route");
        assert_eq!(result.params.get("subdomain"), Some("ipa.bus"));

        let result = router.at("moc.elpmaxe.v1").unwrap(); // v1.example.com
        assert_eq!(result.value, &"wildcard_route");
        assert_eq!(result.params.get("subdomain"), Some("v1"));
    }
}
