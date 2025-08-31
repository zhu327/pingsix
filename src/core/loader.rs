//! Resource loading utilities
//!
//! This module provides utilities for loading resources from configuration
//! into the registry without circular dependencies.

use std::sync::Arc;

use log::{info, warn};

use crate::{
    config::{Config, GlobalRule, Route, Service, Upstream},
    core::{
        container::ServiceContainer,
        error::{ProxyError, ProxyResult},
        registry::ResourceRegistry,
        traits::{RouteResolver, ServiceProvider, UpstreamProvider},
    },
    plugin::manager::{PluginInterface, PluginManager},
    proxy::{
        new_route::create_route_resolver,
        new_service::create_service_provider,
        new_upstream::create_upstream_provider,
    },
};

/// Resource loader that handles loading configuration into the registry
pub struct ResourceLoader {
    registry: Arc<ResourceRegistry>,
    plugin_manager: Option<Arc<PluginManager>>,
}

impl ResourceLoader {
    /// Create a new resource loader
    pub fn new(registry: Arc<ResourceRegistry>) -> Self {
        Self { 
            registry,
            plugin_manager: None,
        }
    }

    /// Create a resource loader with plugin manager
    pub fn with_plugin_manager(registry: Arc<ResourceRegistry>, plugin_manager: Arc<PluginManager>) -> Self {
        Self {
            registry,
            plugin_manager: Some(plugin_manager),
        }
    }

    /// Load all static resources from configuration
    pub fn load_static_resources(&self, config: &Config) -> ProxyResult<()> {
        info!("Loading static resources from configuration...");

        // Load in dependency order: upstreams -> services -> routes
        self.load_static_upstreams(&config.upstreams)?;
        self.load_static_services(&config.services)?;
        self.load_static_routes(&config.routes)?;
        self.load_static_global_rules(&config.global_rules)?;

        info!("Successfully loaded all static resources");
        Ok(())
    }

    /// Load static upstreams (no dependencies)
    fn load_static_upstreams(&self, upstreams: &[Upstream]) -> ProxyResult<()> {
        info!("Loading {} static upstreams", upstreams.len());

        for upstream_config in upstreams {
            let upstream = create_upstream_provider(upstream_config.clone())?;
            self.registry.insert_upstream(upstream_config.id.clone(), upstream);
        }

        Ok(())
    }

    /// Load static services (depend on upstreams)
    fn load_static_services(&self, services: &[Service]) -> ProxyResult<()> {
        info!("Loading {} static services", services.len());

        for service_config in services {
            let service = create_service_provider(service_config.clone(), &self.registry)?;
            self.registry.insert_service(service_config.id.clone(), service);
        }

        Ok(())
    }

    /// Load static routes (depend on upstreams and services)
    fn load_static_routes(&self, routes: &[Route]) -> ProxyResult<()> {
        info!("Loading {} static routes", routes.len());

        for route_config in routes {
            let route = create_route_resolver(route_config.clone(), self.registry.clone())?;
            self.registry.insert_route(route_config.id.clone(), route);
        }

        Ok(())
    }

    /// Load static global rules
    fn load_static_global_rules(&self, global_rules: &[GlobalRule]) -> ProxyResult<()> {
        info!("Loading {} static global rules", global_rules.len());
        
        if let Some(plugin_manager) = &self.plugin_manager {
            let mut global_plugins = Vec::new();
            
            for rule in global_rules {
                for (plugin_name, plugin_config) in &rule.plugins {
                    let plugin = plugin_manager.create_plugin(plugin_name, plugin_config.clone())?;
                    global_plugins.push(plugin);
                }
            }
            
            // Sort by priority and set as global plugins
            global_plugins.sort_by_key(|p| p.priority());
            
            // Note: We need a way to update the plugin manager's global plugins
            // This requires making the plugin manager mutable or using interior mutability
            log::info!("Loaded {} global plugins", global_plugins.len());
        } else {
            log::warn!("No plugin manager available for loading global rules");
        }
        
        Ok(())
    }

    /// Reload a specific upstream
    pub fn reload_upstream(&self, upstream_config: Upstream) -> ProxyResult<()> {
        let upstream = create_upstream_provider(upstream_config.clone())?;
        self.registry.insert_upstream(upstream_config.id.clone(), upstream);
        info!("Reloaded upstream: {}", upstream_config.id);
        Ok(())
    }

    /// Reload a specific service
    pub fn reload_service(&self, service_config: Service) -> ProxyResult<()> {
        let service = create_service_provider(service_config.clone(), &self.registry)?;
        self.registry.insert_service(service_config.id.clone(), service);
        info!("Reloaded service: {}", service_config.id);
        Ok(())
    }

    /// Reload a specific route
    pub fn reload_route(&self, route_config: Route) -> ProxyResult<()> {
        let route = create_route_resolver(route_config.clone(), self.registry.clone())?;
        self.registry.insert_route(route_config.id.clone(), route);
        info!("Reloaded route: {}", route_config.id);
        Ok(())
    }

    /// Remove an upstream
    pub fn remove_upstream(&self, id: &str) -> bool {
        if self.registry.remove_upstream(id).is_some() {
            info!("Removed upstream: {}", id);
            true
        } else {
            warn!("Attempted to remove non-existent upstream: {}", id);
            false
        }
    }

    /// Remove a service
    pub fn remove_service(&self, id: &str) -> bool {
        if self.registry.remove_service(id).is_some() {
            info!("Removed service: {}", id);
            true
        } else {
            warn!("Attempted to remove non-existent service: {}", id);
            false
        }
    }

    /// Remove a route
    pub fn remove_route(&self, id: &str) -> bool {
        if self.registry.remove_route(id).is_some() {
            info!("Removed route: {}", id);
            true
        } else {
            warn!("Attempted to remove non-existent route: {}", id);
            false
        }
    }

    /// Get resource statistics
    pub fn get_stats(&self) -> ResourceStats {
        self.registry.get_stats()
    }
}

/// Resource loading statistics
#[derive(Debug, Clone)]
pub struct ResourceStats {
    pub route_count: usize,
    pub upstream_count: usize,
    pub service_count: usize,
}

impl From<crate::core::registry::ResourceStats> for ResourceStats {
    fn from(stats: crate::core::registry::ResourceStats) -> Self {
        Self {
            route_count: stats.route_count,
            upstream_count: stats.upstream_count,
            service_count: stats.service_count,
        }
    }
}