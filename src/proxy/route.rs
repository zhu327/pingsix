use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::BTreeMap, sync::RwLock};

use arc_swap::ArcSwap;
use log::debug;
use matchit::{InsertError, Router as MatchRouter};
use once_cell::sync::Lazy;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_proxy::Session;

use crate::config;

use super::{
    get_request_host,
    plugin::build_plugin,
    plugin::ProxyPlugin,
    service::service_fetch,
    upstream::{upstream_fetch, ProxyUpstream},
    Identifiable, MapOperations,
};

/// Proxy route.
///
/// Manages routing of requests to appropriate proxy load balancers.
pub struct ProxyRoute {
    pub inner: config::Route,
    pub upstream: Option<Arc<ProxyUpstream>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl From<config::Route> for ProxyRoute {
    /// Creates a new `ProxyRoute` instance from a `Route` configuration.
    fn from(value: config::Route) -> Self {
        Self {
            inner: value,
            upstream: None,
            plugins: Vec::new(),
        }
    }
}

impl Identifiable for ProxyRoute {
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyRoute {
    pub fn new_with_upstream_and_plugins(
        route: config::Route,
        work_stealing: bool,
    ) -> Result<Self> {
        let mut proxy_route = Self::from(route.clone());

        // 配置 upstream
        if let Some(upstream_config) = route.upstream {
            let mut proxy_upstream = ProxyUpstream::try_from(upstream_config)?;
            proxy_upstream.start_health_check(work_stealing);
            proxy_route.upstream = Some(Arc::new(proxy_upstream));
        }

        // 加载插件
        for (name, value) in route.plugins {
            let plugin = build_plugin(&name, value)?;
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

    /// Selects an HTTP peer for a given session.
    pub fn select_http_peer<'a>(&'a self, session: &'a mut Session) -> Result<Box<HttpPeer>> {
        let upstream = self
            .resolve_upstream()
            .ok_or_else(|| Error::new_str("Failed to retrieve upstream configuration for route"))?;

        let mut backend = upstream
            .select_backend(session)
            .ok_or_else(|| Error::new_str("Unable to determine backend for the request"))?;

        backend
            .ext
            .get_mut::<HttpPeer>()
            .map(|peer| {
                self.set_timeout(peer);
                Box::new(peer.clone())
            })
            .ok_or_else(|| Error::new_str("Missing selected backend metadata for HttpPeer"))
    }

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
}

impl MatchEntry {
    /// Inserts a route into the match entry.
    pub fn insert_route(&mut self, proxy_route: Arc<ProxyRoute>) -> Result<(), InsertError> {
        let hosts = proxy_route.get_hosts();
        let uris = proxy_route.inner.get_uris();

        if hosts.is_empty() {
            // Insert for non-host URIs
            Self::insert_route_for_uri(&mut self.non_host_uri, &uris, proxy_route)?;
        } else {
            // Insert for host URIs
            for host in hosts.iter() {
                let reversed_host = host.chars().rev().collect::<String>();

                if self.host_uris.at(reversed_host.as_str()).is_err() {
                    let mut inner = MatchRouter::new();
                    for uri in uris.iter() {
                        inner.insert(uri, vec![proxy_route.clone()])?;
                    }
                    self.host_uris.insert(reversed_host, inner)?;
                } else {
                    let inner = self.host_uris.at_mut(reversed_host.as_str()).unwrap().value;
                    Self::insert_route_for_uri(inner, &uris, proxy_route.clone())?;
                }
            }
        }

        Ok(())
    }

    /// Inserts a route for a given URI.
    fn insert_route_for_uri(
        match_router: &mut MatchRouter<Vec<Arc<ProxyRoute>>>,
        uris: &[String],
        proxy_route: Arc<ProxyRoute>,
    ) -> Result<(), InsertError> {
        for uri in uris.iter() {
            if match_router.at(uri).is_err() {
                match_router.insert(uri, vec![proxy_route.clone()])?;
            } else {
                let routes = match_router.at_mut(uri).unwrap();
                routes.value.push(proxy_route.clone());
                // Sort by priority
                routes
                    .value
                    .sort_by(|a, b| b.inner.priority.cmp(&a.inner.priority));
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

        log::debug!(
            "match request: host={:?}, uri={:?}, method={:?}",
            host,
            uri,
            method
        );

        // Attempt to match using host_uris if a valid host is provided
        if let Some(reversed_host) = host
            .filter(|h| !h.is_empty())
            .map(|h| h.chars().rev().collect::<String>())
        {
            if let Ok(v) = self.host_uris.at(&reversed_host) {
                if let Some(result) = Self::match_uri(v.value, uri, method) {
                    return Some(result);
                }
            }
        }

        // Fall back to non-host URI matching
        Self::match_uri(&self.non_host_uri, uri, method)
    }

    /// Matches a URI to a route.
    fn match_uri(
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
                if route
                    .inner
                    .methods
                    .iter()
                    .map(|method| method.to_string())
                    .collect::<Vec<String>>()
                    .contains(&method.to_string())
                {
                    return Some((params, route.clone()));
                }
            }
        }
        None
    }
}

/// Global map to store global rules, initialized lazily.
pub static ROUTE_MAP: Lazy<RwLock<HashMap<String, Arc<ProxyRoute>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static GLOBAL_MATCH: Lazy<ArcSwap<MatchEntry>> =
    Lazy::new(|| ArcSwap::new(Arc::new(MatchEntry::default())));

pub fn global_match_fetch() -> Arc<MatchEntry> {
    GLOBAL_MATCH.load().clone()
}

pub fn reload_global_match() {
    let mut matcher = MatchEntry::default();

    let routes = ROUTE_MAP.read().unwrap();
    for route in routes.values() {
        debug!("Inserting route: {}", route.inner.id);
        matcher.insert_route(route.clone()).unwrap();
    }

    GLOBAL_MATCH.store(Arc::new(matcher));
}

/// Loads routes from the given configuration.
pub fn load_static_routes(config: &config::Config) -> Result<()> {
    let proxy_routes: Vec<Arc<ProxyRoute>> = config
        .routes
        .iter()
        .map(|route| {
            log::info!("Configuring Route: {}", route.id);
            match ProxyRoute::new_with_upstream_and_plugins(
                route.clone(),
                config.pingora.work_stealing,
            ) {
                Ok(proxy_route) => Ok(Arc::new(proxy_route)),
                Err(e) => {
                    log::error!("Failed to configure Route {}: {}", route.id, e);
                    Err(e)
                }
            }
        })
        .collect::<Result<Vec<_>>>()?;

    ROUTE_MAP.reload_resource(proxy_routes);

    reload_global_match();

    Ok(())
}

/// Fetches an upstream by its ID.
pub fn route_fetch(id: &str) -> Option<Arc<ProxyRoute>> {
    match ROUTE_MAP.get(id) {
        Some(rule) => Some(rule),
        None => {
            log::warn!("Route with id '{}' not found", id);
            None
        }
    }
}
