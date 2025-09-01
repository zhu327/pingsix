//! Core components for the Pingsix proxy.
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
use pingora_error::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::Backend;
use pingora_proxy::Session;
use regex::Regex;
use serde_json::Value as JsonValue;

// =============================================================================
// UPSTREAM ABSTRACTION
// =============================================================================

/// Abstract trait for upstream backend selection
///
/// Decouples route logic from specific upstream implementations, enabling
/// different load balancing strategies and upstream configurations.
pub trait UpstreamSelector: Send + Sync {
    /// Select a backend for the given session
    fn select_backend(&self, session: &mut Session) -> Option<Backend>;

    /// Get the number of retries configured for this upstream
    fn get_retries(&self) -> Option<usize>;

    /// Get the retry timeout configured for this upstream
    fn get_retry_timeout(&self) -> Option<u64>;

    /// Rewrite the upstream host in the request header if needed
    fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader);
}

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
    fn select_http_peer(&self, session: &mut Session) -> ProxyResult<Box<HttpPeer>>;

    /// Build plugin executor for this route
    fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor>;

    /// Resolve upstream for this route
    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>>;
}

// =============================================================================
// ERROR HANDLING
// =============================================================================

/// Unified error types for the pingsix proxy.
///
/// Provides context-aware error handling with chaining support for better debugging.
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
    /// A generic error variant that can hold any error with context
    WithCause {
        message: String,
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
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
            ProxyError::WithCause { message, cause } => write!(f, "{message}: {cause}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProxyError::Network(err) => Some(err),
            ProxyError::Pingora(err) => Some(err),
            ProxyError::WithCause { cause, .. } => Some(cause.as_ref()),
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
            ProxyError::Configuration(msg) => Error::explain(
                ErrorType::InternalError,
                format!("Configuration error: {msg}"),
            ),
            ProxyError::Network(io_err) => {
                Error::because(ErrorType::ConnectError, "Network error", io_err)
            }
            ProxyError::DnsResolution(msg) => Error::explain(
                ErrorType::ConnectNoRoute,
                format!("DNS resolution failed: {msg}"),
            ),
            ProxyError::HealthCheck(msg) => Error::explain(
                ErrorType::InternalError,
                format!("Health check failed: {msg}"),
            ),
            ProxyError::RouteMatching(msg) => Error::explain(
                ErrorType::InternalError,
                format!("Route matching failed: {msg}"),
            ),
            ProxyError::UpstreamSelection(msg) => Error::explain(
                ErrorType::InternalError,
                format!("Upstream selection failed: {msg}"),
            ),
            ProxyError::Ssl(msg) => Error::explain(
                ErrorType::TLSHandshakeFailure,
                format!("SSL/TLS error: {msg}"),
            ),
            ProxyError::Plugin(msg) => Error::explain(
                ErrorType::InternalError,
                format!("Plugin execution error: {msg}"),
            ),
            ProxyError::Internal(msg) => {
                Error::explain(ErrorType::InternalError, format!("Internal error: {msg}"))
            }
            ProxyError::WithCause { message, cause } => {
                Error::because(ErrorType::InternalError, message, cause)
            }
        }
    }
}

/// Result type alias for proxy operations
pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

impl ProxyError {
    /// Create a new ProxyError with an underlying cause
    pub fn with_cause<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::WithCause {
            message: message.into(),
            cause: Box::new(cause),
        }
    }

    /// Create a configuration error with cause
    pub fn config_error<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause(format!("Configuration error: {}", message.into()), cause)
    }

    /// Create a plugin error with cause
    pub fn plugin_error<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause(format!("Plugin execution error: {}", message.into()), cause)
    }
}

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
///
/// Plugin execution follows APISIX's phase model for consistency with existing ecosystems.
#[async_trait]
pub trait ProxyPlugin: Send + Sync {
    /// Return the name of this plugin
    fn name(&self) -> &str;

    /// Return the priority of this plugin
    fn priority(&self) -> i32;

    /// Handle the incoming request in the access phase.
    ///
    /// Use this phase for: request validation, authentication, rate limiting,
    /// access control, and early response generation.
    /// Corresponds to APISIX's rewrite/access phase.
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Handle the incoming request before any downstream processing.
    ///
    /// Use this for early request inspection and modification before
    /// core proxy logic executes.
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the request before it is sent to the upstream
    ///
    /// Use this for: adding authentication headers, request transformation,
    /// and upstream-specific modifications.
    /// Corresponds to APISIX's before_proxy phase.
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
    /// Use this for: adding security headers, CORS handling, and response transformation.
    /// Corresponds to APISIX's header_filter phase.
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
    /// Use this for: content compression, body transformation, and filtering.
    /// Corresponds to APISIX's body_filter phase.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after the complete response is sent or on fatal error.
    ///
    /// Use this for: metrics collection, access logging, cleanup operations.
    /// Error logging is already handled by the framework.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut ProxyContext) {}
}

/// Constant-time string comparison to prevent timing attacks.
///
/// Used primarily for secret/token comparison in authentication plugins.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    // Early return for different lengths is safe from timing attacks
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (a_byte, b_byte) in a.bytes().zip(b.bytes()) {
        result |= a_byte ^ b_byte;
    }
    result == 0
}

/// Applies regex-based URI rewriting using precompiled patterns.
///
/// Patterns are applied in order until first match. This enables implementing
/// complex routing rules, redirects, and URL transformations efficiently.
///
/// # Arguments
/// - `uri`: The input URI to be rewritten.
/// - `regex_patterns`: Precompiled regex patterns with replacement templates.
///
/// # Returns
/// The rewritten URI if a pattern matches, otherwise the original URI.
///
/// # Performance Notes
/// Regex patterns are precompiled during plugin initialization to avoid
/// per-request compilation overhead in high-traffic scenarios.
pub fn apply_regex_uri_template(uri: &str, regex_patterns: &[(Regex, String)]) -> String {
    for (re, redirect_template) in regex_patterns {
        if let Some(captures) = re.captures(uri) {
            // Build new URI by substituting capture groups into template
            let redirect_uri = captures
                .iter()
                .skip(1) // Skip the full match
                .enumerate()
                .fold(redirect_template.to_string(), |acc, (i, capture)| {
                    // Replace $1, $2, ... with actual capture group values
                    acc.replace(&format!("${}", i + 1), capture.unwrap().as_str())
                });
            return redirect_uri;
        }
    }

    // Return original URI if no patterns match
    uri.to_string()
}

// =============================================================================
// PLUGIN EXECUTOR
// =============================================================================

/// Shared empty plugin executor instance to avoid allocations for routes without plugins.
static DEFAULT_PLUGIN_EXECUTOR: Lazy<Arc<ProxyPluginExecutor>> =
    Lazy::new(|| Arc::new(ProxyPluginExecutor::default()));

/// Manages execution of multiple plugins in priority order.
///
/// Plugins are sorted by priority (higher numbers execute first) to ensure
/// critical plugins like auth and rate limiting run before others.
/// Uses Arc for efficient sharing across multiple concurrent requests.
#[derive(Default)]
pub struct ProxyPluginExecutor {
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl ProxyPluginExecutor {
    /// Returns shared empty executor instance to minimize memory allocation.
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

/// Request-scoped context shared across all plugin phases.
///
/// Contains routing information, retry state, and plugin-specific data.
/// The vars field enables plugins to share data across different execution phases.
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
        // Pre-populate with request timestamp for performance metrics
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
    /// Store a typed value into the context for inter-plugin communication.
    pub fn set<T: Any + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        self.vars.insert(key.into(), Box::new(value));
    }

    /// Get a typed reference from the context with type safety.
    pub fn get<T: Any>(&self, key: &str) -> Option<&T> {
        self.vars.get(key).and_then(|v| v.downcast_ref::<T>())
    }

    /// Convenience method for string values to avoid repeated type annotation.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get::<String>(key).map(|s| s.as_str())
    }

    /// Check if a key exists without retrieving the value.
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
