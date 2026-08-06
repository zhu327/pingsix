//! Plugin system for the Pingsix proxy.
//!
//! Provides the plugin trait, executor, context, and URI rewriting utilities.

use std::{any::Any, borrow::Cow, collections::HashMap, sync::Arc, time::Instant};

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
/// Trait for upstream selection that can be used in proxy context
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

    /// Stable cache-namespace fragment that changes when upstream identity or
    /// origin-selection configuration changes, so process-local cache cannot
    /// reuse stale entries after a dynamic config switch.
    fn cache_isolation_key(&self) -> String;
}

/// One request's compiled upstream selection: the selected peer plus the
/// selector that owns retry, host-rewrite, and cache-isolation policy.
///
/// Downstream callbacks (host rewrite, retry accounting, cache key) delegate
/// to this single artifact instead of re-deriving policy from raw selectors,
/// and the route path and the traffic-split override path both produce one.
pub struct UpstreamSelection {
    pub peer: Box<HttpPeer>,
    pub upstream: Arc<dyn UpstreamSelector>,
}

/// Trait for route behavior that can be used in proxy context
pub trait RouteContext: Send + Sync {
    /// Get the route identifier
    fn id(&self) -> &str;

    /// Optional human-readable route name from configuration.
    fn name(&self) -> Option<&str> {
        None
    }

    /// Get the service ID if available
    fn service_id(&self) -> Option<&str>;

    /// Optional human-readable service name from the bound service configuration.
    fn service_name(&self) -> Option<&str> {
        None
    }

    /// Return the configured URI template used to match this route.
    fn uri_template(&self) -> Option<&str>;

    /// Select an upstream peer for the route, compiling the selection artifact
    /// (peer plus owning selector) used by all downstream callbacks.
    fn select_upstream(&self, session: &mut Session) -> ProxyResult<UpstreamSelection>;

    /// Return the effective host patterns used to match this route.
    ///
    /// Exposed so plugins can derive bounded labels from route configuration
    /// instead of attacker-controllable request input. Default is empty.
    fn effective_hosts(&self) -> &[String] {
        &[]
    }

    /// Fingerprint of the compiled route's cache namespace inputs (route/service
    /// identity and response-affecting plugin configuration). Combined with the
    /// live upstream isolation key at request time.
    fn cache_namespace_fingerprint(&self) -> u64 {
        0
    }

    /// Build plugin executor for this route
    fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor>;

    /// Resolve upstream for this route
    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>>;

    /// Route-level timeout, applied after an upstream override is selected.
    fn timeout(&self) -> Option<&crate::config::Timeout>;
}

// =============================================================================
// HEALTH CHECK SPECS (shared by plugins and runtime reconcile)
// =============================================================================

/// Stable fingerprint of health-check-relevant configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HealthCheckFingerprint(pub u64);

/// Spec used to reconcile background health checks without restarting unchanged ones.
pub struct HealthCheckSpec {
    pub key: String,
    pub fingerprint: HealthCheckFingerprint,
    pub service: Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync>,
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
    /// The upstream override selected by the traffic-split plugin. Consumed by
    /// cache namespacing and [`HttpService::upstream_peer`]; the compiled result
    /// of that selection lives in [`Self::selected`].
    pub upstream_override: Option<Arc<dyn UpstreamSelector>>,
    /// The compiled upstream selection for this request (peer + owning
    /// selector). Set by `upstream_peer`; all retry and host-rewrite decisions
    /// must use it.
    pub selected: Option<UpstreamSelection>,
    /// Number of retry attempts so far.
    pub tries: usize,
    /// Compiled global-rule + route/service plugin layers for this request.
    /// Owns phase traversal and short-circuit rules; set in `early_request_filter`.
    pub pipeline: CompiledPluginPipeline,
    /// Request start timestamp for performance metrics and timeouts.
    pub request_start: Instant,
    /// Unique request identifier, set by request-id plugin if enabled.
    pub request_id: Option<String>,
    /// Whether the original downstream request contained authentication/session credentials.
    /// Captured before plugins can remove or rewrite headers (Authorization, Proxy-Authorization, Cookie).
    pub original_request_had_credentials: bool,
    /// Set when any auth plugin observes credentials (including custom headers/query).
    pub request_has_credentials: bool,
    /// Custom variables available to plugins (type-erased, thread-safe).
    /// Lazily allocated because many requests never store plugin variables.
    pub vars: Option<HashMap<String, Box<dyn Any + Send + Sync>>>,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            route: None,
            route_params: None,
            upstream_override: None,
            selected: None,
            tries: 0,
            pipeline: CompiledPluginPipeline::default(),
            request_start: Instant::now(),
            request_id: None,
            original_request_had_credentials: false,
            request_has_credentials: false,
            vars: None,
        }
    }
}

impl ProxyContext {
    /// Mark that the request carried credentials (regardless of auth success).
    pub fn mark_request_has_credentials(&mut self) {
        self.request_has_credentials = true;
        self.original_request_had_credentials = true;
    }

    /// Store a typed value into the context for inter-plugin communication.
    pub fn set<T: Any + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        self.vars
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), Box::new(value));
    }

    /// Get a typed reference from the context with type safety.
    pub fn get<T: Any>(&self, key: &str) -> Option<&T> {
        self.vars
            .as_ref()
            .and_then(|vars| vars.get(key))
            .and_then(|v| v.downcast_ref::<T>())
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

    /// Typed health-check specs with stable fingerprints for incremental
    /// reconcile. Only plugins that own background maintenance register here;
    /// the default is no specs.
    fn health_check_specs(&self) -> Vec<HealthCheckSpec> {
        Vec::new()
    }

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

    /// Whether this plugin implements response body filtering.
    ///
    /// Executors use this capability to skip body-filter traversal when no
    /// configured plugin needs it.
    fn has_response_body_filter(&self) -> bool {
        false
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

/// Hashes a secret for comparison against precomputed configuration digests.
pub fn secret_digest(value: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(value.as_bytes()).into()
}

/// Compares fixed-length secret digests in constant time.
pub fn constant_time_digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;

    a.ct_eq(b).into()
}

/// Constant-time string comparison for legacy callers.
///
/// New authentication plugins should precompute their expected digest during
/// configuration loading and call `constant_time_digest_eq` instead.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    constant_time_digest_eq(&secret_digest(a), &secret_digest(b))
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
pub fn apply_regex_uri_template<'a>(
    uri: &'a str,
    regex_patterns: &[(Regex, String)],
) -> Cow<'a, str> {
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
            return Cow::Owned(redirect_uri.into_owned());
        }
    }

    // Return original URI if no patterns match
    Cow::Borrowed(uri)
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
///
/// Storage is private: construction is either [`Self::new`] (which sorts
/// deterministically) or [`Self::from_sorted`] (which asserts the caller's
/// ordering precondition), so an unordered executor can never be built by
/// accident.
#[derive(Default)]
pub struct ProxyPluginExecutor {
    /// Plugins in deterministic execution order (priority descending).
    plugins: Vec<Arc<dyn ProxyPlugin>>,
    /// Whether at least one configured plugin processes response body chunks.
    has_response_body_filter: bool,
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
    /// Sort plugins deterministically (priority desc, then name asc) and build.
    pub fn new(plugins: Vec<Arc<dyn ProxyPlugin>>) -> Self {
        let mut plugins = plugins;
        sort_plugins_by_priority_desc(&mut plugins);
        Self::from_sorted(plugins)
    }

    /// Build from an already-ordered plugin list.
    ///
    /// The precondition is a non-increasing priority sequence; tie order is
    /// whatever the caller produced (e.g. the route-over-service merge prefers
    /// the route side on equal priority). In debug builds this is asserted.
    pub fn from_sorted(plugins: Vec<Arc<dyn ProxyPlugin>>) -> Self {
        debug_assert!(
            plugins
                .windows(2)
                .all(|window| window[0].priority() >= window[1].priority()),
            "ProxyPluginExecutor::from_sorted requires priority-descending input"
        );
        let has_response_body_filter = plugins
            .iter()
            .any(|plugin| plugin.has_response_body_filter());
        Self {
            plugins,
            has_response_body_filter,
        }
    }

    pub fn has_plugin(&self, name: &str) -> bool {
        self.plugins.iter().any(|plugin| plugin.name() == name)
    }

    /// Read-only access to the ordered plugin list.
    pub fn plugins(&self) -> &[Arc<dyn ProxyPlugin>] {
        &self.plugins
    }

    /// Whether any plugin in this executor processes response body chunks.
    pub fn has_response_body_filter(&self) -> bool {
        self.has_response_body_filter
    }

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
        if self.has_response_body_filter {
            for_each_plugin_sync!(
                self,
                response_body_filter,
                session,
                body,
                end_of_stream,
                ctx
            );
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        for_each_plugin_async_unit!(self, logging, session, e, ctx);
    }
}

// =============================================================================
// COMPILED PLUGIN PIPELINE
// =============================================================================

/// Shared empty pipeline used when no route matched or no plugins are configured.
static DEFAULT_PLUGIN_PIPELINE: Lazy<Arc<CompiledPluginPipeline>> =
    Lazy::new(|| Arc::new(CompiledPluginPipeline::default()));

/// Compiled per-request plugin composition: global rules then route/service.
///
/// Owns the layer-precedence policy that previously lived in `HttpService`'s
/// `run_global_then_route_*` helpers: global plugins always run first, a global
/// `request_filter` short-circuit skips the route layer, and every phase
/// traverses global → route. Both layers arrive already ordered from their
/// builders, so no per-request sorting or merge happens here.
#[derive(Clone)]
pub struct CompiledPluginPipeline {
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
}

impl Default for CompiledPluginPipeline {
    fn default() -> Self {
        Self {
            global: ProxyPluginExecutor::default_shared(),
            route: ProxyPluginExecutor::default_shared(),
        }
    }
}

impl CompiledPluginPipeline {
    pub fn new(global: Arc<ProxyPluginExecutor>, route: Arc<ProxyPluginExecutor>) -> Self {
        Self { global, route }
    }

    /// Shared empty pipeline with no plugins in either layer.
    pub fn empty() -> Arc<Self> {
        DEFAULT_PLUGIN_PIPELINE.clone()
    }

    /// Whether either layer contains a plugin named `name` (e.g. CORS preflight).
    pub fn has_plugin(&self, name: &str) -> bool {
        self.global.has_plugin(name) || self.route.has_plugin(name)
    }

    /// Run global-rule plugins then route/service plugins for `early_request_filter`.
    pub async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global.early_request_filter(session, ctx).await?;
        self.route.early_request_filter(session, ctx).await
    }

    /// Run global-rule plugins then route/service plugins for `request_filter`.
    ///
    /// Returns `true` when a plugin short-circuits the request. Global plugins
    /// run first; a global short-circuit skips the route layer entirely.
    pub async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<bool> {
        if self.global.request_filter(session, ctx).await? {
            return Ok(true);
        }
        self.route.request_filter(session, ctx).await
    }

    /// Run global-rule plugins then route/service plugins for `upstream_request_filter`.
    pub async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;
        self.route
            .upstream_request_filter(session, upstream_request, ctx)
            .await
    }

    /// Run global-rule plugins then route/service plugins for `response_filter`.
    pub async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global
            .response_filter(session, upstream_response, ctx)
            .await?;
        self.route
            .response_filter(session, upstream_response, ctx)
            .await
    }

    /// Run global-rule plugins then route/service plugins for `response_body_filter`.
    pub fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global
            .response_body_filter(session, body, end_of_stream, ctx)?;
        self.route
            .response_body_filter(session, body, end_of_stream, ctx)
    }

    /// Run global-rule plugins then route/service plugins for `logging`.
    pub async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        self.global.logging(session, e, ctx).await;
        self.route.logging(session, e, ctx).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BodyFilterPlugin;

    #[async_trait]
    impl ProxyPlugin for BodyFilterPlugin {
        fn name(&self) -> &str {
            "body-filter"
        }

        fn priority(&self) -> i32 {
            0
        }

        fn has_response_body_filter(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_executor_detects_response_body_filter() {
        let executor = ProxyPluginExecutor::new(vec![Arc::new(BodyFilterPlugin)]);
        assert!(executor.has_response_body_filter());
    }

    #[test]
    fn new_sorts_plugins_by_priority_desc() {
        let low: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "low",
            priority: 10,
        });
        let high: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "high",
            priority: 100,
        });
        let executor = ProxyPluginExecutor::new(vec![low.clone(), high.clone()]);
        let names: Vec<&str> = executor.plugins().iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["high", "low"]);
    }

    #[test]
    fn new_breaks_ties_by_name() {
        let zebra: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "zebra",
            priority: 50,
        });
        let alpha: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "alpha",
            priority: 50,
        });
        let executor = ProxyPluginExecutor::new(vec![zebra, alpha]);
        let names: Vec<&str> = executor.plugins().iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["alpha", "zebra"]);
    }

    struct DummyPlugin {
        name: &'static str,
        priority: i32,
    }

    #[async_trait]
    impl ProxyPlugin for DummyPlugin {
        fn name(&self) -> &str {
            self.name
        }

        fn priority(&self) -> i32 {
            self.priority
        }
    }

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
