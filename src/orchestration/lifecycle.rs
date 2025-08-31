//! Component lifecycle management
//!
//! This module manages the lifecycle of various components
//! and ensures proper initialization and cleanup order.

use std::sync::Arc;

use log::{info, warn};

use crate::{
    config::Config,
    core::{
        container::ServiceContainer,
        registry::ResourceRegistry,
        ProxyResult,
    },
};

/// Manages the lifecycle of application components
pub struct ComponentLifecycle {
    container: Arc<ServiceContainer>,
}

impl ComponentLifecycle {
    /// Create a new lifecycle manager
    pub fn new(container: Arc<ServiceContainer>) -> Self {
        Self { container }
    }

    /// Initialize all components in the correct order
    pub async fn initialize(&self, config: &Config) -> ProxyResult<()> {
        info!("Starting component initialization...");

        // Phase 1: Initialize foundation components
        self.initialize_foundation(config).await?;

        // Phase 2: Initialize core logic components
        self.initialize_core_logic(config).await?;

        // Phase 3: Initialize plugin system
        self.initialize_plugin_system(config).await?;

        // Phase 4: Initialize orchestration layer
        self.initialize_orchestration(config).await?;

        info!("Component initialization completed successfully");
        Ok(())
    }

    /// Shutdown all components in reverse order
    pub async fn shutdown(&self) -> ProxyResult<()> {
        info!("Starting graceful shutdown...");

        // Shutdown in reverse order of initialization
        self.shutdown_orchestration().await?;
        self.shutdown_plugin_system().await?;
        self.shutdown_core_logic().await?;
        self.shutdown_foundation().await?;

        info!("Graceful shutdown completed");
        Ok(())
    }

    /// Initialize foundation components (config, utils, logging)
    async fn initialize_foundation(&self, _config: &Config) -> ProxyResult<()> {
        info!("Initializing foundation components...");
        // Foundation components are typically initialized in main.rs
        Ok(())
    }

    /// Initialize core logic components (routes, upstreams, services)
    async fn initialize_core_logic(&self, config: &Config) -> ProxyResult<()> {
        info!("Initializing core logic components...");

        let registry = self.container.registry();

        // Load static upstreams first (no dependencies)
        self.load_static_upstreams(registry, config).await?;

        // Load static services (depend on upstreams)
        self.load_static_services(registry, config).await?;

        // Load static routes (depend on upstreams and services)
        self.load_static_routes(registry, config).await?;

        Ok(())
    }

    /// Initialize plugin system
    async fn initialize_plugin_system(&self, _config: &Config) -> ProxyResult<()> {
        info!("Initializing plugin system...");
        // Plugin initialization logic
        Ok(())
    }

    /// Initialize orchestration layer
    async fn initialize_orchestration(&self, _config: &Config) -> ProxyResult<()> {
        info!("Initializing orchestration layer...");
        // Orchestration initialization logic
        Ok(())
    }

    /// Load static upstreams from configuration
    async fn load_static_upstreams(
        &self,
        _registry: &ResourceRegistry,
        _config: &Config,
    ) -> ProxyResult<()> {
        // Implementation would convert config::Upstream to Arc<dyn UpstreamProvider>
        // and register them in the registry
        Ok(())
    }

    /// Load static services from configuration
    async fn load_static_services(
        &self,
        _registry: &ResourceRegistry,
        _config: &Config,
    ) -> ProxyResult<()> {
        // Implementation would convert config::Service to Arc<dyn ServiceProvider>
        // and register them in the registry
        Ok(())
    }

    /// Load static routes from configuration
    async fn load_static_routes(
        &self,
        _registry: &ResourceRegistry,
        _config: &Config,
    ) -> ProxyResult<()> {
        // Implementation would convert config::Route to Arc<dyn RouteResolver>
        // and register them in the registry
        Ok(())
    }

    /// Shutdown orchestration layer
    async fn shutdown_orchestration(&self) -> ProxyResult<()> {
        info!("Shutting down orchestration layer...");
        Ok(())
    }

    /// Shutdown plugin system
    async fn shutdown_plugin_system(&self) -> ProxyResult<()> {
        info!("Shutting down plugin system...");
        Ok(())
    }

    /// Shutdown core logic components
    async fn shutdown_core_logic(&self) -> ProxyResult<()> {
        info!("Shutting down core logic components...");
        Ok(())
    }

    /// Shutdown foundation components
    async fn shutdown_foundation(&self) -> ProxyResult<()> {
        info!("Shutting down foundation components...");
        Ok(())
    }
}

/// Component initialization order and dependencies
#[derive(Debug, Clone)]
pub struct InitializationOrder {
    /// Components that must be initialized first
    pub foundation: Vec<String>,
    
    /// Core business logic components
    pub core_logic: Vec<String>,
    
    /// Plugin system components
    pub plugin_system: Vec<String>,
    
    /// Orchestration layer components
    pub orchestration: Vec<String>,
    
    /// Service layer components
    pub services: Vec<String>,
    
    /// Application layer components
    pub application: Vec<String>,
}

impl Default for InitializationOrder {
    fn default() -> Self {
        Self {
            foundation: vec![
                "config".to_string(),
                "logging".to_string(),
                "utils".to_string(),
            ],
            core_logic: vec![
                "upstreams".to_string(),
                "services".to_string(),
                "routes".to_string(),
                "health_check".to_string(),
            ],
            plugin_system: vec![
                "plugin_manager".to_string(),
                "global_rules".to_string(),
            ],
            orchestration: vec![
                "router".to_string(),
                "executor".to_string(),
            ],
            services: vec![
                "http_service".to_string(),
            ],
            application: vec![
                "admin_api".to_string(),
                "prometheus".to_string(),
            ],
        }
    }
}