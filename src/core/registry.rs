//! Centralized resource registry
//!
//! This module provides a unified registry for managing routes, upstreams,
//! and services, eliminating the need for cross-module function calls.

use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;
use log::{debug, info, warn};

use super::traits::{ResourceManager, RouteResolver, ServiceProvider, UpstreamProvider};

/// Centralized registry for all proxy resources
pub struct ResourceRegistry {
    routes: DashMap<String, Arc<dyn RouteResolver>>,
    upstreams: DashMap<String, Arc<dyn UpstreamProvider>>,
    services: DashMap<String, Arc<dyn ServiceProvider>>,
}

impl Default for ResourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
            upstreams: DashMap::new(),
            services: DashMap::new(),
        }
    }

    /// Get a route by ID
    pub fn get_route(&self, id: &str) -> Option<Arc<dyn RouteResolver>> {
        self.routes.get(id).map(|entry| entry.value().clone())
    }

    /// Get an upstream by ID
    pub fn get_upstream(&self, id: &str) -> Option<Arc<dyn UpstreamProvider>> {
        self.upstreams.get(id).map(|entry| entry.value().clone())
    }

    /// Get a service by ID
    pub fn get_service(&self, id: &str) -> Option<Arc<dyn ServiceProvider>> {
        self.services.get(id).map(|entry| entry.value().clone())
    }

    /// Insert or update a route
    pub fn insert_route(&self, id: String, route: Arc<dyn RouteResolver>) {
        debug!("Inserting route with ID: {}", id);
        self.routes.insert(id, route);
    }

    /// Insert or update an upstream
    pub fn insert_upstream(&self, id: String, upstream: Arc<dyn UpstreamProvider>) {
        debug!("Inserting upstream with ID: {}", id);
        self.upstreams.insert(id, upstream);
    }

    /// Insert or update a service
    pub fn insert_service(&self, id: String, service: Arc<dyn ServiceProvider>) {
        debug!("Inserting service with ID: {}", id);
        self.services.insert(id, service);
    }

    /// Remove a route
    pub fn remove_route(&self, id: &str) -> Option<Arc<dyn RouteResolver>> {
        debug!("Removing route with ID: {}", id);
        self.routes.remove(id).map(|(_, route)| route)
    }

    /// Remove an upstream
    pub fn remove_upstream(&self, id: &str) -> Option<Arc<dyn UpstreamProvider>> {
        debug!("Removing upstream with ID: {}", id);
        self.upstreams.remove(id).map(|(_, upstream)| upstream)
    }

    /// Remove a service
    pub fn remove_service(&self, id: &str) -> Option<Arc<dyn ServiceProvider>> {
        debug!("Removing service with ID: {}", id);
        self.services.remove(id).map(|(_, service)| service)
    }

    /// Bulk reload routes
    pub fn reload_routes(&self, routes: Vec<Arc<dyn RouteResolver>>) {
        info!("Reloading {} routes", routes.len());
        
        // Collect IDs of new routes
        let new_ids: HashSet<String> = routes.iter().map(|r| r.id().to_string()).collect();
        
        // Remove routes not in the new set
        self.routes.retain(|id, _| new_ids.contains(id));
        
        // Insert or update all new routes
        for route in routes {
            self.routes.insert(route.id().to_string(), route);
        }
    }

    /// Bulk reload upstreams
    pub fn reload_upstreams(&self, upstreams: Vec<Arc<dyn UpstreamProvider>>) {
        info!("Reloading {} upstreams", upstreams.len());
        
        let new_ids: HashSet<String> = upstreams.iter().map(|u| u.id().to_string()).collect();
        
        self.upstreams.retain(|id, _| new_ids.contains(id));
        
        for upstream in upstreams {
            self.upstreams.insert(upstream.id().to_string(), upstream);
        }
    }

    /// Bulk reload services
    pub fn reload_services(&self, services: Vec<Arc<dyn ServiceProvider>>) {
        info!("Reloading {} services", services.len());
        
        let new_ids: HashSet<String> = services.iter().map(|s| s.id().to_string()).collect();
        
        self.services.retain(|id, _| new_ids.contains(id));
        
        for service in services {
            self.services.insert(service.id().to_string(), service);
        }
    }

    /// Get all route IDs
    pub fn list_route_ids(&self) -> Vec<String> {
        self.routes.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get all upstream IDs
    pub fn list_upstream_ids(&self) -> Vec<String> {
        self.upstreams.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get all service IDs
    pub fn list_service_ids(&self) -> Vec<String> {
        self.services.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get resource counts for monitoring
    pub fn get_stats(&self) -> ResourceStats {
        ResourceStats {
            route_count: self.routes.len(),
            upstream_count: self.upstreams.len(),
            service_count: self.services.len(),
        }
    }
}

/// Statistics about registry contents
#[derive(Debug, Clone)]
pub struct ResourceStats {
    pub route_count: usize,
    pub upstream_count: usize,
    pub service_count: usize,
}

// Implement ResourceManager trait for each resource type
impl ResourceManager<dyn RouteResolver> for ResourceRegistry {
    fn get(&self, id: &str) -> Option<Arc<dyn RouteResolver>> {
        self.get_route(id)
    }

    fn insert(&self, id: String, resource: Arc<dyn RouteResolver>) {
        self.insert_route(id, resource);
    }

    fn remove(&self, id: &str) -> Option<Arc<dyn RouteResolver>> {
        self.remove_route(id)
    }

    fn list(&self) -> Vec<Arc<dyn RouteResolver>> {
        self.routes.iter().map(|entry| entry.value().clone()).collect()
    }

    fn reload(&self, resources: Vec<Arc<dyn RouteResolver>>) {
        self.reload_routes(resources);
    }
}

impl ResourceManager<dyn UpstreamProvider> for ResourceRegistry {
    fn get(&self, id: &str) -> Option<Arc<dyn UpstreamProvider>> {
        self.get_upstream(id)
    }

    fn insert(&self, id: String, resource: Arc<dyn UpstreamProvider>) {
        self.insert_upstream(id, resource);
    }

    fn remove(&self, id: &str) -> Option<Arc<dyn UpstreamProvider>> {
        self.remove_upstream(id)
    }

    fn list(&self) -> Vec<Arc<dyn UpstreamProvider>> {
        self.upstreams.iter().map(|entry| entry.value().clone()).collect()
    }

    fn reload(&self, resources: Vec<Arc<dyn UpstreamProvider>>) {
        self.reload_upstreams(resources);
    }
}

impl ResourceManager<dyn ServiceProvider> for ResourceRegistry {
    fn get(&self, id: &str) -> Option<Arc<dyn ServiceProvider>> {
        self.get_service(id)
    }

    fn insert(&self, id: String, resource: Arc<dyn ServiceProvider>) {
        self.insert_service(id, resource);
    }

    fn remove(&self, id: &str) -> Option<Arc<dyn ServiceProvider>> {
        self.remove_service(id)
    }

    fn list(&self) -> Vec<Arc<dyn ServiceProvider>> {
        self.services.iter().map(|entry| entry.value().clone()).collect()
    }

    fn reload(&self, resources: Vec<Arc<dyn ServiceProvider>>) {
        self.reload_services(resources);
    }
}