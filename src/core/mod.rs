//! Core module containing fundamental types and utilities for the pingsix proxy.
//!
//! This module provides the essential building blocks for the proxy system:
//! - Error handling and result types
//! - Plugin system infrastructure
//! - Request context management
//! - Plugin execution framework

use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use regex::Regex;
use serde_json::Value as JsonValue;

// =============================================================================
// ROUTE ABSTRACTION
// =============================================================================

/// Trait for route behavior that can be used in proxy context
#[async_trait]
pub trait RouteContext: Send + Sync {
    /// Get the route identifier
    fn id(&self) -> &str;

    /// Get the service ID if available
    fn service_id(&self) -> Option<&str>;

    /// Select an HTTP peer for the route
    fn select_http_peer<'a>(&'a self, session: &'a mut Session) -> ProxyResult<Box<HttpPeer>>;

    /// Build plugin executor for this route
    fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor>;

    /// Resolve upstream for this route
    fn resolve_upstream(&self) -> Option<Arc<crate::proxy::upstream::ProxyUpstream>>;
}

// =============================================================================
// ERROR HANDLING
// =============================================================================

/// Unified error types for the pingsix proxy.
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

// =============================================================================
// PLUGIN SYSTEM
// =============================================================================

/// Type alias for plugin initialization functions
pub type PluginCreateFn = fn(JsonValue) -> Result<Arc<dyn ProxyPlugin>>;

/// The core plugin trait that defines the lifecycle hooks for proxy plugins.
#[async_trait]
pub trait ProxyPlugin: Send + Sync {
    /// Return the name of this plugin
    fn name(&self) -> &str;

    /// Return the priority of this plugin
    fn priority(&self) -> i32;

    /// Handle the incoming request.
    ///
    /// In this phase, users can parse, validate, rate limit, perform access control and/or
    /// return a response for this request.
    /// Like APISIX rewrite access phase.
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Handle the incoming request before any downstream module is executed.
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the request before it is sent to the upstream
    ///
    /// Like APISIX before_proxy phase.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the response header before it is sent to the downstream
    ///
    /// Like APISIX header_filter phase.
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Handle the response body chunks
    ///
    /// Like APISIX body_filter phase.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// This filter is called when the entire response is sent to the downstream successfully or
    /// there is a fatal error that terminate the request.
    ///
    /// An error log is already emitted if there is any error. This phase is used for collecting
    /// metrics and sending access logs.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut ProxyContext) {}
}

/// Utility function for constant-time string comparison
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    // Simple constant-time comparison implementation
    // For production use, consider adding the `subtle` crate dependency
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (a_byte, b_byte) in a.bytes().zip(b.bytes()) {
        result |= a_byte ^ b_byte;
    }
    result == 0
}

/// Applies regex-based URI rewriting based on provided precompiled patterns.
///
/// # Arguments
/// - `uri`: The input URI to be rewritten.
/// - `regex_patterns`: A slice of tuples containing precompiled `Regex` objects and their corresponding replacement templates.
///
/// # Returns
/// - `String`: The rewritten URI if a pattern matches, or the original URI if no match is found.
///
/// # Notes
/// - The regex patterns are precompiled during plugin creation (e.g., in `proxy_rewrite` or `redirect` plugins)
///   to avoid repeated compilation overhead.
/// - This function assumes that the regex patterns are valid, as they are validated during plugin configuration.
pub fn apply_regex_uri_template(uri: &str, regex_patterns: &[(Regex, String)]) -> String {
    for (re, redirect_template) in regex_patterns {
        if let Some(captures) = re.captures(uri) {
            // Generate new URI by replacing capture groups in the template
            let redirect_uri = captures
                .iter()
                .skip(1) // Skip the full match
                .enumerate()
                .fold(redirect_template.to_string(), |acc, (i, capture)| {
                    // Replace $1, $2, ... with capture groups
                    acc.replace(&format!("${}", i + 1), capture.unwrap().as_str())
                });
            return redirect_uri;
        }
    }

    // If no match, return original URI
    uri.to_string()
}

// =============================================================================
// PLUGIN EXECUTOR
// =============================================================================

/// Default empty plugin executor for new ProxyContext.
static DEFAULT_PLUGIN_EXECUTOR: Lazy<Arc<ProxyPluginExecutor>> =
    Lazy::new(|| Arc::new(ProxyPluginExecutor::default()));

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

impl ProxyPluginExecutor {
    /// Get the default empty plugin executor
    pub fn default_shared() -> Arc<Self> {
        DEFAULT_PLUGIN_EXECUTOR.clone()
    }
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

// =============================================================================
// PROXY CONTEXT
// =============================================================================

/// Holds the context for each proxy request.
pub struct ProxyContext {
    /// The matched proxy route, if any.
    pub route: Option<Arc<dyn RouteContext>>,
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
            plugin: ProxyPluginExecutor::default_shared(),
            global_plugin: ProxyPluginExecutor::default_shared(),
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

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_with_valid_match() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/iresty/a/b/c";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/a-b-c");
    }

    #[test]
    fn test_second_match_in_multi_patterns() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/theothers/x/y";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/theothers/x-y");
    }

    #[test]
    fn test_no_match_should_return_original_uri() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/api/test";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/api/test");
    }

    #[test]
    fn test_empty_uri() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "");
    }

    #[test]
    fn test_uri_with_multiple_parts() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/iresty/a/b/c/d/e/f";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/a/b/c/d-e-f");
    }

    #[test]
    fn test_uri_with_special_characters() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/iresty/a/!/@";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/a-!-@");
    }

    #[test]
    fn test_empty_template_should_return_empty_string() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "".to_string(),
            ),
        ];
        let uri = "/iresty/a/b/c";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "");
    }
}
