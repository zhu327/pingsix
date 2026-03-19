//! Plugin system for the Pingsix proxy.
//!
//! Provides the plugin trait, executor, context, and URI rewriting utilities.

use std::{any::Any, collections::HashMap, sync::Arc, time::Instant};

use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use regex::Regex;
use serde_json::Value as JsonValue;

use crate::config;
use crate::core::error::ProxyResult;
use pingora_load_balancing::Backend;

// =============================================================================
// UPSTREAM & ROUTE TRAITS (defined here to avoid circular deps with context)
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

    /// Get the pass host configuration for this upstream
    fn get_pass_host(&self) -> &config::UpstreamPassHost;

    /// Rewrite the upstream host in the request header if needed
    fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader);
}

/// Trait for route behavior that can be used in proxy context
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
// PROXY CONTEXT (in plugin to avoid context<->plugin circular dependency)
// =============================================================================

/// Request-scoped context shared across all plugin phases.
///
/// Contains routing information, retry state, and plugin-specific data.
/// Common fields like request_start and request_id are directly accessible for better performance.
/// The vars field enables plugins to share additional data across different execution phases.
pub struct ProxyContext {
    /// The matched proxy route, if any.
    pub route: Option<Arc<dyn RouteContext>>,
    /// Parameters extracted from the route pattern.
    /// Stored as Vec for better performance with small number of params (typical case).
    pub route_params: Option<Vec<(String, String)>>,
    /// The upstream override selected by the traffic-split plugin.
    pub upstream_override: Option<Arc<dyn UpstreamSelector>>,
    // Selected HTTP peer for the upstream request.
    pub peer: Option<Box<HttpPeer>>,
    /// Number of retry attempts so far.
    pub tries: usize,
    /// Executor for route-specific plugins.
    pub plugin: Arc<ProxyPluginExecutor>,
    /// Executor for global plugins.
    pub global_plugin: Arc<ProxyPluginExecutor>,
    /// Request start timestamp for performance metrics and timeouts.
    pub request_start: Instant,
    /// Unique request identifier, set by request-id plugin if enabled.
    pub request_id: Option<String>,
    /// Custom variables available to plugins (type-erased, thread-safe).
    pub vars: HashMap<String, Box<dyn Any + Send + Sync>>,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            route: None,
            route_params: None,
            upstream_override: None,
            peer: None,
            tries: 0,
            plugin: ProxyPluginExecutor::default_shared(),
            global_plugin: ProxyPluginExecutor::default_shared(),
            request_start: Instant::now(),
            request_id: None,
            vars: HashMap::new(),
        }
    }
}

#[allow(dead_code)]
impl ProxyContext {
    /// Get a route parameter by key.
    /// Returns None if no params exist or the key is not found.
    pub fn get_param(&self, key: &str) -> Option<&str> {
        self.route_params
            .as_ref()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Get all route parameters as an iterator of (key, value) pairs.
    pub fn params(&self) -> impl Iterator<Item = (&str, &str)> {
        self.route_params
            .iter()
            .flat_map(|params| params.iter())
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Check if a specific route parameter exists.
    pub fn has_param(&self, key: &str) -> bool {
        self.get_param(key).is_some()
    }

    /// Get the number of route parameters.
    pub fn params_len(&self) -> usize {
        self.route_params.as_ref().map_or(0, |p| p.len())
    }

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

    /// Get the elapsed time since request start in milliseconds.
    pub fn elapsed_ms(&self) -> u128 {
        self.request_start.elapsed().as_millis()
    }

    /// Get the elapsed time since request start as f64 milliseconds (for metrics).
    pub fn elapsed_ms_f64(&self) -> f64 {
        self.elapsed_ms() as f64
    }

    /// Get the request ID if set.
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Set the request ID.
    pub fn set_request_id(&mut self, id: String) {
        self.request_id = Some(id);
    }
}

// =============================================================================
// PLUGIN TRAIT & UTILITIES
// =============================================================================

/// Type alias for plugin initialization functions
pub type PluginCreateFn = fn(JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>>;

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

/// Sort proxy plugins deterministically by:
/// - higher priority first
/// - for ties, sort by plugin name
pub fn sort_plugins_by_priority_desc(plugins: &mut [Arc<dyn ProxyPlugin>]) {
    plugins.sort_by(|a, b| {
        b.priority()
            .cmp(&a.priority())
            .then_with(|| a.name().cmp(b.name()))
    });
}

/// Constant-time string comparison to prevent timing attacks.
///
/// Uses HMAC-based comparison to avoid leaking length or content information.
/// Both inputs are hashed first so the comparison always operates on fixed-size data.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};

    let hash_a = Sha256::digest(a.as_bytes());
    let hash_b = Sha256::digest(b.as_bytes());

    let mut result = 0u8;
    for (byte_a, byte_b) in hash_a.iter().zip(hash_b.iter()) {
        result |= byte_a ^ byte_b;
    }
    result == 0
}

/// Precompiled placeholder pattern for regex URI templates (e.g., "$1", "$10").
static TEMPLATE_PLACEHOLDER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$(\d+)").expect("Invalid template placeholder regex"));

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
            // Build new URI by substituting capture groups into template.
            // Use regex replacement to avoid "$10" being treated as "$1" + "0".
            let redirect_uri =
                TEMPLATE_PLACEHOLDER_RE.replace_all(redirect_template, |caps: &regex::Captures| {
                    let idx = caps
                        .get(1)
                        .and_then(|m| m.as_str().parse::<usize>().ok())
                        .unwrap_or(0);
                    if idx == 0 {
                        // Preserve "$0" or malformed placeholders verbatim
                        caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string()
                    } else {
                        captures
                            .get(idx)
                            .map(|m| m.as_str())
                            .unwrap_or("")
                            .to_string()
                    }
                });
            return redirect_uri.into_owned();
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

/// Invokes a plugin method on each plugin in sequence (async, propagates Result).
macro_rules! for_each_plugin_async {
    ($self:expr, $method:ident, $($arg:expr),*) => {
        for plugin in $self.plugins.iter() {
            plugin.$method($($arg),*).await?;
        }
    };
}

/// Invokes a plugin method on each plugin in sequence (sync, propagates Result).
macro_rules! for_each_plugin_sync {
    ($self:expr, $method:ident, $($arg:expr),*) => {
        for plugin in $self.plugins.iter() {
            plugin.$method($($arg),*)?;
        }
    };
}

/// Invokes a plugin method on each plugin in sequence (async, no return value).
macro_rules! for_each_plugin_async_unit {
    ($self:expr, $method:ident, $($arg:expr),*) => {
        for plugin in $self.plugins.iter() {
            plugin.$method($($arg),*).await;
        }
    };
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
        for_each_plugin_async!(self, early_request_filter, session, ctx);
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_async!(
            self,
            upstream_request_filter,
            session,
            upstream_request,
            ctx
        );
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_async!(self, response_filter, session, upstream_response, ctx);
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_sync!(
            self,
            response_body_filter,
            session,
            body,
            end_of_stream,
            ctx
        );
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        for_each_plugin_async_unit!(self, logging, session, e, ctx);
    }
}

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

    #[test]
    fn test_template_with_double_digit_group() {
        let regex_patterns = [(
            Regex::new(r"^/a/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)$")
                .unwrap(),
            "/$10-$1".to_string(),
        )];
        let uri = "/a/9/2/3/4/5/6/7/8/9/123";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/123-9");
    }
}
