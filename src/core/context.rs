//! Request context management
//!
//! This module provides the ProxyContext that holds per-request state
//! and facilitates communication between different components.

use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

use super::traits::{PluginExecutor, RouteResolver};
use super::error::ProxyResult;

/// Context that holds per-request state and metadata
pub struct ProxyContext {
    /// The matched route resolver, if any
    pub route: Option<Arc<dyn RouteResolver>>,
    
    /// Parameters extracted from the route pattern
    pub route_params: Option<BTreeMap<String, String>>,
    
    /// Number of retry attempts so far
    pub tries: usize,
    
    /// Executor for route-specific plugins
    pub plugin_executor: Arc<dyn PluginExecutor>,
    
    /// Executor for global plugins
    pub global_plugin_executor: Arc<dyn PluginExecutor>,
    
    /// Custom variables available to plugins (type-erased, thread-safe)
    vars: HashMap<String, Box<dyn Any + Send + Sync>>,
}

impl Default for ProxyContext {
    fn default() -> Self {
        // Initialize vars and insert request_start timestamp
        let mut vars: HashMap<String, Box<dyn Any + Send + Sync>> = HashMap::new();
        vars.insert("request_start".to_string(), Box::new(Instant::now()));

        Self {
            route: None,
            route_params: None,
            tries: 0,
            plugin_executor: Arc::new(EmptyPluginExecutor),
            global_plugin_executor: Arc::new(EmptyPluginExecutor),
            vars,
        }
    }
}

impl ProxyContext {
    /// Create a new context with the given route and plugin executors
    pub fn new(
        route: Option<Arc<dyn RouteResolver>>,
        plugin_executor: Arc<dyn PluginExecutor>,
        global_plugin_executor: Arc<dyn PluginExecutor>,
    ) -> Self {
        let mut ctx = Self::default();
        ctx.route = route;
        ctx.plugin_executor = plugin_executor;
        ctx.global_plugin_executor = global_plugin_executor;
        ctx
    }

    /// Store a typed value into the context
    pub fn set<T: Any + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        self.vars.insert(key.into(), Box::new(value));
    }

    /// Get a typed reference from the context
    pub fn get<T: Any>(&self, key: &str) -> Option<&T> {
        self.vars.get(key).and_then(|v| v.downcast_ref::<T>())
    }

    /// Get a string slice if the stored value is a `String`
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get::<String>(key).map(|s| s.as_str())
    }

    /// Check if a key exists in the context
    pub fn contains(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }

    /// Remove a value from the context
    pub fn remove(&mut self, key: &str) -> Option<Box<dyn Any + Send + Sync>> {
        self.vars.remove(key)
    }

    /// Clear all custom variables (keeps built-in ones like request_start)
    pub fn clear_custom_vars(&mut self) {
        self.vars.retain(|k, _| k == "request_start");
    }
}

/// Empty plugin executor for default contexts
struct EmptyPluginExecutor;

#[async_trait::async_trait]
impl PluginExecutor for EmptyPluginExecutor {
    async fn early_request_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    async fn request_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<bool> {
        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut pingora_proxy::Session,
        _upstream_response: &mut pingora_http::ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        Ok(())
    }
}