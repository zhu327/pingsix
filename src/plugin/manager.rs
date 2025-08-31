//! Plugin management system
//!
//! This module provides centralized plugin management without
//! circular dependencies on the proxy module.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use serde_json::Value as JsonValue;

use crate::core::{
    context::ProxyContext,
    error::{ProxyError, ProxyResult},
    traits::PluginExecutor,
};

/// Plugin interface that doesn't depend on proxy module
#[async_trait]
pub trait PluginInterface: Send + Sync {
    /// Return the name of this plugin
    fn name(&self) -> &str;

    /// Return the priority of this plugin (lower number = higher priority)
    fn priority(&self) -> i32;

    /// Handle early request phase
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    /// Handle request filtering phase
    /// Returns true if request was handled and should not continue
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<bool> {
        Ok(false)
    }

    /// Modify upstream request before sending
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    /// Modify response before sending to client
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    /// Handle response body chunks
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    /// Handle logging phase
    async fn logging(
        &self,
        _session: &mut Session,
        _error: Option<&pingora_error::Error>,
        _ctx: &mut ProxyContext,
    ) {
        // Default: do nothing
    }
}

/// Plugin factory function type
pub type PluginFactory = fn(JsonValue) -> ProxyResult<Arc<dyn PluginInterface>>;

/// Plugin manager that handles plugin lifecycle and execution
pub struct PluginManager {
    /// Registered plugin factories
    factories: HashMap<String, PluginFactory>,
    
    /// Global plugin instances
    global_plugins: Vec<Arc<dyn PluginInterface>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        let mut manager = Self {
            factories: HashMap::new(),
            global_plugins: Vec::new(),
        };
        
        // Register built-in plugin factories
        manager.register_builtin_plugins();
        manager
    }

    /// Register a plugin factory
    pub fn register_factory(&mut self, name: String, factory: PluginFactory) {
        self.factories.insert(name, factory);
    }

    /// Create a plugin instance from configuration
    pub fn create_plugin(&self, name: &str, config: JsonValue) -> ProxyResult<Arc<dyn PluginInterface>> {
        let factory = self.factories.get(name).ok_or_else(|| {
            ProxyError::Plugin(format!("Unknown plugin type: {}", name))
        })?;
        
        factory(config)
    }

    /// Build a plugin executor from plugin configurations
    pub fn build_executor(&self, plugin_configs: HashMap<String, JsonValue>) -> ProxyResult<Arc<dyn PluginExecutor>> {
        let mut plugins = Vec::new();
        
        for (name, config) in plugin_configs {
            let plugin = self.create_plugin(&name, config)?;
            plugins.push(plugin);
        }
        
        // Sort by priority (lower number = higher priority)
        plugins.sort_by_key(|p| p.priority());
        
        Ok(Arc::new(PluginExecutorImpl::new(plugins)))
    }

    /// Set global plugins
    pub fn set_global_plugins(&mut self, plugins: Vec<Arc<dyn PluginInterface>>) {
        self.global_plugins = plugins;
        self.global_plugins.sort_by_key(|p| p.priority());
    }

    /// Get global plugin executor
    pub fn global_executor(&self) -> Arc<dyn PluginExecutor> {
        Arc::new(PluginExecutorImpl::new(self.global_plugins.clone()))
    }

    /// Register all built-in plugin factories
    fn register_builtin_plugins(&mut self) {
        // We'll implement this after we create the adapter layer
        // This will bridge the old plugin system to the new interface
    }
}

/// Implementation of PluginExecutor that runs a list of plugins
struct PluginExecutorImpl {
    plugins: Vec<Arc<dyn PluginInterface>>,
}

impl PluginExecutorImpl {
    fn new(plugins: Vec<Arc<dyn PluginInterface>>) -> Self {
        Self { plugins }
    }
}

#[async_trait]
impl PluginExecutor for PluginExecutorImpl {
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        for plugin in &self.plugins {
            plugin.early_request_filter(session, ctx).await?;
        }
        Ok(())
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<bool> {
        for plugin in &self.plugins {
            if plugin.request_filter(session, ctx).await? {
                return Ok(true); // Request was handled
            }
        }
        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        for plugin in &self.plugins {
            plugin.upstream_request_filter(session, upstream_request, ctx).await?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        for plugin in &self.plugins {
            plugin.response_filter(session, upstream_response, ctx).await?;
        }
        Ok(())
    }
}