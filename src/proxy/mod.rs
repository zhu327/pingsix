//! Module for proxy context and resource management.
//!
//! This module defines the `ProxyContext` used per request and the generic
//! `MapOperations` trait for managing resources in a thread-safe map.

pub mod discovery;
pub mod event;
pub mod global_rule;
pub mod health_check;
pub mod route;
pub mod service;
pub mod ssl;
pub mod upstream;

// New trait-based implementations
pub mod new_route;
pub mod new_service;
pub mod new_upstream;

// Adapters for migration
pub mod adapters;

use std::{
    any::Any,
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::{config::Identifiable, plugin::ProxyPlugin};

use route::ProxyRoute;

/// Unified error types for the proxy module
#[derive(Debug)]
pub enum ProxyError {
    Configuration(String),
    Network(std::io::Error),
    DnsResolution(String),
    HealthCheck(String),
    RouteMatching(String),
    UpstreamSelection(String),
    Ssl(String),
    Plugin(String),
    Internal(String),
    Pingora(pingora_error::Error),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Configuration(msg) => write!(f, "Configuration error: {msg}"),
            ProxyError::Network(err) => write!(f, "Network error: {err}"),
            ProxyError::DnsResolution(msg) => write!(f, "DNS resolution failed: {msg}"),
            ProxyError::HealthCheck(msg) => write!(f, "Health check failed: {msg}"),
            ProxyError::RouteMatching(msg) => write!(f, "Route matching failed: {msg}"),
            ProxyError::UpstreamSelection(msg) => write!(f, "Upstream selection failed: {msg}"),
            ProxyError::Ssl(msg) => write!(f, "SSL/TLS error: {msg}"),
            ProxyError::Plugin(msg) => write!(f, "Plugin execution error: {msg}"),
            ProxyError::Internal(msg) => write!(f, "Internal error: {msg}"),
            ProxyError::Pingora(err) => write!(f, "Pingora error: {err}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProxyError::Network(err) => Some(err),
            ProxyError::Pingora(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        ProxyError::Network(err)
    }
}

impl From<pingora_error::Error> for ProxyError {
    fn from(err: pingora_error::Error) -> Self {
        ProxyError::Pingora(err)
    }
}

impl From<ProxyError> for Box<pingora_error::Error> {
    fn from(err: ProxyError) -> Self {
        match err {
            ProxyError::Pingora(pingora_err) => Box::new(pingora_err),
            ProxyError::Configuration(_) => pingora_error::Error::new_str("Configuration error"),
            ProxyError::Network(_) => pingora_error::Error::new_str("Network error"),
            ProxyError::DnsResolution(_) => pingora_error::Error::new_str("DNS resolution failed"),
            ProxyError::HealthCheck(_) => pingora_error::Error::new_str("Health check failed"),
            ProxyError::RouteMatching(_) => pingora_error::Error::new_str("Route matching failed"),
            ProxyError::UpstreamSelection(_) => {
                pingora_error::Error::new_str("Upstream selection failed")
            }
            ProxyError::Ssl(_) => pingora_error::Error::new_str("SSL/TLS error"),
            ProxyError::Plugin(_) => pingora_error::Error::new_str("Plugin execution error"),
            ProxyError::Internal(_) => pingora_error::Error::new_str("Internal error"),
        }
    }
}

/// Result type alias for proxy operations
pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

/// Helper trait for converting errors with context
pub trait ErrorContext<T> {
    fn with_context(self, context: &str) -> ProxyResult<T>;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: std::fmt::Display,
{
    fn with_context(self, context: &str) -> ProxyResult<T> {
        self.map_err(|e| ProxyError::Internal(format!("{context}: {e}")))
    }
}

/// Default empty plugin executor for new ProxyContext.
static DEFAULT_PLUGIN_EXECUTOR: Lazy<Arc<ProxyPluginExecutor>> =
    Lazy::new(|| Arc::new(ProxyPluginExecutor::default()));

/// Holds the context for each proxy request.
pub struct ProxyContext {
    /// The matched proxy route, if any.
    pub route: Option<Arc<ProxyRoute>>,
    /// Parameters extracted from the route pattern.
    pub route_params: Option<BTreeMap<String, String>>,
    /// Number of retry attempts so far.
    pub tries: usize,
    /// Executor for route-specific plugins.
    pub plugin: Arc<ProxyPluginExecutor>,
    /// Executor for global plugins.
    pub global_plugin: Arc<ProxyPluginExecutor>,
    /// Custom variables available to plugins (type-erased, thread-safe).
    pub vars: HashMap<String, Box<dyn Any + Send + Sync>>,
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
            plugin: DEFAULT_PLUGIN_EXECUTOR.clone(),
            global_plugin: DEFAULT_PLUGIN_EXECUTOR.clone(),
            vars,
        }
    }
}

impl ProxyContext {
    /// Store a typed value into the context.
    pub fn set<T: Any + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        self.vars.insert(key.into(), Box::new(value));
    }

    /// Get a typed reference from the context.
    pub fn get<T: Any>(&self, key: &str) -> Option<&T> {
        self.vars.get(key).and_then(|v| v.downcast_ref::<T>())
    }

    /// Get a string slice if the stored value is a `String`.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get::<String>(key).map(|s| s.as_str())
    }

    /// Check if a key exists in the context.
    pub fn contains(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }
}

/// Trait for performing common operations on a map of resources.
///
/// Provides methods to fetch, bulk reload, and insert individual resources.
pub trait MapOperations<T> {
    /// Get a resource by its identifier.
    ///
    /// Returns `Some(Arc<T>)` if found, otherwise logs a warning and returns `None`.
    fn get(&self, id: &str) -> Option<Arc<T>>;

    /// Reload the entire set of resources.
    ///
    /// Removes entries not present in `resources`, and inserts or updates all given resources.
    fn reload_resources(&self, resources: Vec<Arc<T>>);

    /// Insert or update a single resource.
    fn insert_resource(&self, resource: Arc<T>);
}

impl<T> MapOperations<T> for DashMap<String, Arc<T>>
where
    T: Identifiable,
{
    fn get(&self, id: &str) -> Option<Arc<T>> {
        if let Some(entry) = self.get(id) {
            Some(entry.clone())
        } else {
            log::warn!("Resource with id '{id}' not found");
            None
        }
    }

    fn reload_resources(&self, resources: Vec<Arc<T>>) {
        // Log incoming resources
        for resource in &resources {
            log::info!("Upstream resource: {}", resource.id());
        }

        // Build a set of IDs to keep
        let valid_ids: HashSet<String> = resources.iter().map(|r| r.id().to_string()).collect();

        // Remove entries not in the new set
        self.retain(|key, _| valid_ids.contains(key));

        // Insert or update all resources
        for resource in resources {
            let key = resource.id().to_string();
            log::info!("Inserting or updating resource '{key}'");
            self.insert(key, resource);
        }
    }

    fn insert_resource(&self, resource: Arc<T>) {
        let key = resource.id();
        log::info!("Inserting resource '{key}'");
        self.insert(key.to_string(), resource);
    }
}

/// A struct that manages the execution of proxy plugins.
///
/// # Fields
/// - `plugins`: A vector of reference-counted pointers to `ProxyPlugin` instances.
///   These plugins are executed in the order of their priorities, typically determined
///   during the construction of the `ProxyPluginExecutor`.
///
/// # Purpose
/// - This struct is responsible for holding and managing a collection of proxy plugins.
/// - It is typically used to facilitate the execution of plugins in a proxy routing context,
///   where plugins can perform various tasks such as authentication, logging, traffic shaping, etc.
///
/// # Usage
/// - The plugins are expected to be sorted by their priority (in descending order) during
///   the initialization of the `ProxyPluginExecutor`.
#[derive(Default)]
pub struct ProxyPluginExecutor {
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

#[async_trait]
impl ProxyPlugin for ProxyPluginExecutor {
    fn name(&self) -> &str {
        "plugin-executor"
    }

    fn priority(&self) -> i32 {
        0
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        for plugin in self.plugins.iter() {
            if plugin.request_filter(session, ctx).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin.early_request_filter(session, ctx).await?;
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin
                .upstream_request_filter(session, upstream_request, ctx)
                .await?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin
                .response_filter(session, upstream_response, ctx)
                .await?;
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin.response_body_filter(session, body, end_of_stream, ctx)?;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        for plugin in self.plugins.iter() {
            plugin.logging(session, e, ctx).await;
        }
    }
}
