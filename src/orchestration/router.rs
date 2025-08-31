//! Request routing orchestration
//!
//! This module handles route matching and resolution without
//! directly depending on specific proxy implementations.

use std::{collections::BTreeMap, sync::Arc};

use matchit::{Match, Router as MatchRouter};
use pingora_proxy::Session;

use crate::{
    core::{
        registry::ResourceRegistry,
        traits::RouteResolver,
        error::{ProxyResult, ProxyError},
    },
    utils::request::get_request_host,
};

/// Request router that matches incoming requests to routes
pub struct RequestRouter {
    /// Resource registry for looking up routes
    registry: Arc<ResourceRegistry>,
    
    /// Route matching engine
    matcher: RouteMatchEngine,
}

impl RequestRouter {
    /// Create a new request router
    pub fn new(registry: Arc<ResourceRegistry>) -> Self {
        Self {
            registry,
            matcher: RouteMatchEngine::new(),
        }
    }

    /// Match a request to a route and extract parameters
    pub fn match_request(
        &self,
        session: &Session,
    ) -> Option<(BTreeMap<String, String>, Arc<dyn RouteResolver>)> {
        let host = get_request_host(session.req_header())?;
        let path = session.req_header().uri.path();

        // Try to match the route
        if let Some((route_id, params)) = self.matcher.match_route(host, path) {
            if let Some(route) = self.registry.get_route(&route_id) {
                return Some((params, route));
            }
        }

        None
    }

    /// Reload the routing table
    pub fn reload_routes(&mut self) -> ProxyResult<()> {
        let routes = self.registry.list_route_ids();
        self.matcher.rebuild_from_registry(&self.registry, routes)?;
        Ok(())
    }
}

/// Internal route matching engine
struct RouteMatchEngine {
    // Host-based routers
    host_routers: std::collections::HashMap<String, MatchRouter<String>>,
    // Fallback router for routes without specific hosts
    default_router: MatchRouter<String>,
}

impl RouteMatchEngine {
    fn new() -> Self {
        Self {
            host_routers: std::collections::HashMap::new(),
            default_router: MatchRouter::new(),
        }
    }

    fn match_route(&self, host: &str, path: &str) -> Option<(String, BTreeMap<String, String>)> {
        // Try host-specific router first
        if let Some(router) = self.host_routers.get(host) {
            if let Ok(Match { value, params }) = router.at(path) {
                let params_map = params
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                return Some((value.clone(), params_map));
            }
        }

        // Fallback to default router
        if let Ok(Match { value, params }) = self.default_router.at(path) {
            let params_map = params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            return Some((value.clone(), params_map));
        }

        None
    }

    fn rebuild_from_registry(
        &mut self,
        registry: &ResourceRegistry,
        route_ids: Vec<String>,
    ) -> ProxyResult<()> {
        // Clear existing routers
        self.host_routers.clear();
        self.default_router = MatchRouter::new();

        // Group routes by host for efficient matching
        let mut host_routes: std::collections::HashMap<String, Vec<(String, String)>> = 
            std::collections::HashMap::new();
        let mut default_routes: Vec<(String, String)> = Vec::new();

        // Collect routes and group by host
        for route_id in route_ids {
            if let Some(route) = registry.get_route(&route_id) {
                let hosts = route.get_hosts();
                let uris = route.get_uris();
                
                for uri in uris {
                    if hosts.is_empty() {
                        // No specific host, add to default router
                        default_routes.push((route_id.clone(), uri));
                    } else {
                        // Add to host-specific routers
                        for host in &hosts {
                            host_routes
                                .entry(host.clone())
                                .or_insert_with(Vec::new)
                                .push((route_id.clone(), uri.clone()));
                        }
                    }
                }
                
                log::debug!("Added route: {} with hosts: {:?}", route.id(), hosts);
            }
        }

        // Build host-specific routers
        for (host, routes) in host_routes {
            let mut router = MatchRouter::new();
            for (route_id, uri) in routes {
                if let Err(e) = router.insert(uri, route_id) {
                    log::warn!("Failed to insert route for host {}: {}", host, e);
                }
            }
            self.host_routers.insert(host, router);
        }

        // Build default router
        for (route_id, uri) in default_routes {
            if let Err(e) = self.default_router.insert(uri, route_id) {
                log::warn!("Failed to insert default route: {}", e);
            }
        }

        Ok(())
    }
}