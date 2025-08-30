use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use log::debug;
use matchit::{InsertError, Router as MatchRouter};
use once_cell::sync::Lazy;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Result;
use pingora_proxy::Session;
use prometheus::{register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec};

use crate::{
    config::{self, Identifiable},
    plugin::{build_plugin, ProxyPlugin},
    utils::request::get_request_host,
};

use super::{
    service::service_fetch,
    upstream::{upstream_fetch, ProxyUpstream},
    ErrorContext, MapOperations, ProxyError, ProxyPluginExecutor, ProxyResult,
};

/// Proxy route.
///
/// Manages routing of requests to appropriate proxy load balancers.
pub struct ProxyRoute {
    pub inner: config::Route,
    pub upstream: Option<Arc<ProxyUpstream>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
    /// Cached plugin executor to avoid rebuilding on each request
    cached_plugin_executor: once_cell::sync::OnceCell<Arc<ProxyPluginExecutor>>,
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
            cached_plugin_executor: once_cell::sync::OnceCell::new(),
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

    /// Gets the upstream for the route.
    pub fn resolve_upstream(&self) -> Option<Arc<ProxyUpstream>> {
        self.upstream
            .clone()
            .or_else(|| {
                self.inner
                    .upstream_id
                    .as_ref()
                    .and_then(|id| upstream_fetch(id.as_str()))
            })
            .or_else(|| {
                self.inner
                    .service_id
                    .as_ref()
                    .and_then(|id| service_fetch(id).and_then(|s| s.resolve_upstream()))
            })
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

    pub fn select_http_peer<'a>(&'a self, session: &'a mut Session) -> ProxyResult<Box<HttpPeer>> {
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

    /// Sets the timeout for an `HttpPeer` based on the route configuration.
    fn set_timeout(&self, p: &mut HttpPeer) {
        if let Some(config::Timeout {
            connect,
            read,
            send,
            ..
        }) = self.inner.timeout
        {
            p.options.connection_timeout = Some(Duration::from_secs(connect));
            p.options.read_timeout = Some(Duration::from_secs(read));
            p.options.write_timeout = Some(Duration::from_secs(send));
            if let Some(total) = self.inner.timeout.as_ref().and_then(|t| t.total) {
                p.options.total_connection_timeout = Some(Duration::from_secs(total));
            }
        }
    }

    /// Builds a `ProxyPluginExecutor` by combining plugins from both a route and its associated service.
    /// Uses caching to avoid rebuilding the executor on each request.
    ///
    /// # Returns
    /// - `Arc<ProxyPluginExecutor>`: A cached reference-counted pointer to a `ProxyPluginExecutor`.
    ///
    /// # Performance Notes
    /// - The executor is built once and cached for subsequent requests
    /// - Plugins from the route take precedence over those from the service in case of naming conflicts
    pub fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor> {
        self.cached_plugin_executor
            .get_or_init(|| {
                let mut plugin_map: HashMap<String, Arc<dyn ProxyPlugin>> = HashMap::new();

                // Merge route and service plugins
                let service_plugins = self
                    .inner
                    .service_id
                    .as_deref()
                    .and_then(service_fetch)
                    .map_or_else(Vec::new, |service| service.plugins.clone());

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
            })
            .clone()
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
    fn get_reversed_host(&self, host: &str) -> String {
        self.reversed_host_cache
            .entry(host.to_string())
            .or_insert_with(|| host.chars().rev().collect())
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
            // Host strings are reversed to enable suffix/wildcard matching with matchit's prefix-based router
            // (e.g., "*.example.com" becomes "moc.elpmaxe.*" for efficient matching)
            for host in hosts.iter() {
                let reversed_host = self.get_reversed_host(host);
                let inner_router = self.host_uris.at_mut(reversed_host.as_str());

                let inner_router = match inner_router {
                    Ok(router) => router.value,
                    Err(_) => {
                        let new_router = MatchRouter::new();
                        self.host_uris.insert(reversed_host.clone(), new_router)?;
                        self.host_uris.at_mut(reversed_host.as_str()).unwrap().value
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
        // Host is reversed to match the format used during insertion (e.g., "moc.elpmaxe.*")
        if let Some(host_str) = host.filter(|h| !h.is_empty()) {
            let reversed_host = self.get_reversed_host(host_str);
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

// Metrics for route matcher rebuild
static ROUTE_REBUILD_DURATION_MS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "pingsix_matcher_rebuild_duration_ms",
        "Duration of matcher rebuild in milliseconds",
        &["type"]
    )
    .unwrap()
});

static ROUTE_REBUILD_RESULTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_matcher_rebuild_results_total",
        "Results of matcher rebuilds",
        &["type", "result"]
    )
    .unwrap()
});

pub fn global_route_match_fetch() -> Arc<MatchEntry> {
    GLOBAL_ROUTE_MATCH.load().clone()
}

pub fn reload_global_route_match() {
    let start = Instant::now();
    let mut matcher = MatchEntry::default();
    let mut failures: u64 = 0;

    for route in ROUTE_MAP.iter() {
        debug!("Inserting route: {}", route.inner.id);
        if let Err(e) = matcher.insert_route(route.clone()) {
            log::error!("Failed to insert route {}: {}", route.inner.id, e);
            failures += 1;
        }
    }

    GLOBAL_ROUTE_MATCH.store(Arc::new(matcher));

    let elapsed_ms = start.elapsed().as_millis() as f64;
    ROUTE_REBUILD_DURATION_MS
        .with_label_values(&["route"])
        .observe(elapsed_ms);
    if failures == 0 {
        ROUTE_REBUILD_RESULTS
            .with_label_values(&["route", "success"])
            .inc();
    } else {
        ROUTE_REBUILD_RESULTS
            .with_label_values(&["route", "partial_fail"])
            .inc_by(failures as _);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Route as CRoute, Upstream as CUpstream, SelectionType as CSelectionType, UpstreamScheme as CScheme, UpstreamPassHost as CPassHost};

    fn make_route(id: &str, uri: &str, priority: u32) -> ProxyRoute {
        let upstream = CUpstream {
            id: "up1".to_string(),
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes: {
                let mut m = std::collections::HashMap::new();
                m.insert("127.0.0.1:80".to_string(), 1u32);
                m
            },
            r#type: CSelectionType::RoundRobin,
            checks: None,
            hash_on: crate::config::UpstreamHashOn::VARS,
            key: "uri".to_string(),
            scheme: CScheme::HTTP,
            pass_host: CPassHost::PASS,
            upstream_host: None,
        };

        let route = CRoute {
            id: id.to_string(),
            uri: Some(uri.to_string()),
            uris: vec![],
            methods: vec![],
            host: None,
            hosts: vec![],
            priority,
            plugins: Default::default(),
            upstream: Some(upstream),
            upstream_id: None,
            service_id: None,
            timeout: None,
        };

        ProxyRoute::new_with_upstream_and_plugins(route).unwrap()
    }

    #[test]
    fn test_priority_order_for_same_uri() {
        let r1 = Arc::new(make_route("r-high", "/foo/:id", 10));
        let r2 = Arc::new(make_route("r-low", "/foo/:id", 5));

        let mut entry = MatchEntry::default();
        entry.insert_route(r2.clone()).unwrap();
        entry.insert_route(r1.clone()).unwrap();

        // direct access to non_host_uri router
        let res = MatchEntry::match_uri_method(&entry.non_host_uri, "/foo/123", "GET").unwrap();
        assert_eq!(res.1.inner.id, "r-high");
    }
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
