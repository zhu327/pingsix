//! Dependency injection container
//!
//! This module provides a service container that manages all application
//! dependencies and eliminates the need for global singletons.

use std::sync::Arc;

use super::{
    registry::ResourceRegistry,
    traits::{HealthChecker, PluginExecutor},
    error::ProxyResult,
};
use crate::plugin::manager::PluginManager;

/// Main dependency injection container
pub struct ServiceContainer {
    /// Resource registry for routes, upstreams, and services
    registry: Arc<ResourceRegistry>,
    
    /// Plugin manager for handling all plugins
    plugin_manager: Arc<PluginManager>,
    
    /// Health checker service
    health_checker: Arc<dyn HealthChecker>,
    
    /// Configuration manager
    config_manager: Arc<dyn ConfigManager>,
}

impl ServiceContainer {
    /// Create a new service container
    pub fn new() -> Self {
        Self {
            registry: Arc::new(ResourceRegistry::new()),
            plugin_manager: Arc::new(PluginManager::new()),
            health_checker: Arc::new(NoOpHealthChecker),
            config_manager: Arc::new(StaticConfigManager),
        }
    }

    /// Create a container with custom components
    pub fn with_components(
        registry: Arc<ResourceRegistry>,
        plugin_manager: Arc<PluginManager>,
        health_checker: Arc<dyn HealthChecker>,
        config_manager: Arc<dyn ConfigManager>,
    ) -> Self {
        Self {
            registry,
            plugin_manager,
            health_checker,
            config_manager,
        }
    }

    /// Get the resource registry
    pub fn registry(&self) -> &ResourceRegistry {
        &self.registry
    }

    /// Get the plugin manager
    pub fn plugin_manager(&self) -> &PluginManager {
        &self.plugin_manager
    }

    /// Get the global plugin executor
    pub fn global_plugin_executor(&self) -> Arc<dyn PluginExecutor> {
        self.plugin_manager.global_executor()
    }

    /// Get the health checker
    pub fn health_checker(&self) -> Arc<dyn HealthChecker> {
        self.health_checker.clone()
    }

    /// Get the configuration manager
    pub fn config_manager(&self) -> Arc<dyn ConfigManager> {
        self.config_manager.clone()
    }

    /// Update the plugin manager
    pub fn set_plugin_manager(&mut self, manager: Arc<PluginManager>) {
        self.plugin_manager = manager;
    }

    /// Update the health checker
    pub fn set_health_checker(&mut self, checker: Arc<dyn HealthChecker>) {
        self.health_checker = checker;
    }
}

impl Default for ServiceContainer {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for configuration management
pub trait ConfigManager: Send + Sync {
    /// Reload configuration from source
    fn reload_config(&self) -> ProxyResult<()>;
    
    /// Get configuration value
    fn get_config<T>(&self, key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned;
}

/// Empty plugin executor implementation
struct EmptyPluginExecutor;

#[async_trait::async_trait]
impl PluginExecutor for EmptyPluginExecutor {
    async fn early_request_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _ctx: &mut super::ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    async fn request_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _ctx: &mut super::ProxyContext,
    ) -> ProxyResult<bool> {
        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut super::ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _upstream_response: &mut pingora_http::ResponseHeader,
        _ctx: &mut super::ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }
}

/// No-op health checker implementation
struct NoOpHealthChecker;

#[async_trait::async_trait]
impl HealthChecker for NoOpHealthChecker {
    async fn register_upstream(&self, _upstream: Arc<dyn super::traits::UpstreamProvider>) -> ProxyResult<()> {
        Ok(())
    }

    async fn unregister_upstream(&self, _upstream_id: &str) -> ProxyResult<()> {
        Ok(())
    }

    fn is_healthy(&self, _upstream_id: &str, _backend_addr: &str) -> bool {
        true
    }
}

/// Static configuration manager implementation
struct StaticConfigManager;

impl ConfigManager for StaticConfigManager {
    fn reload_config(&self) -> ProxyResult<()> {
        Ok(())
    }

    fn get_config<T>(&self, _key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        None
    }
}