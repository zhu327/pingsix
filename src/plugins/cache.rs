use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::Method;
use once_cell::sync::OnceCell;
use pingora_error::Result;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

pub const PLUGIN_NAME: &str = "cache";
const PRIORITY: i32 = 1085;

/// Global default max object size, populated once at startup from
/// `pingsix.defaults.cache.default_max_object_bytes`. Falls back to 1MB when unset
/// (e.g. in unit tests that do not initialize the full config).
static DEFAULT_MAX_OBJECT_BYTES: OnceCell<usize> = OnceCell::new();

/// 1MB fallback used when no global default has been initialized.
const FALLBACK_MAX_OBJECT_BYTES: usize = 1024 * 1024;

/// Populates the global default max object size from configuration. Called once at
/// startup by `service::http::init_cache_defaults`. Subsequent calls are no-ops
/// (the first value wins), which keeps parallel test initialization safe.
pub fn init_default_max_object_bytes(bytes: usize) {
    let _ = DEFAULT_MAX_OBJECT_BYTES.set(bytes);
}

/// Returns the effective global default max object size, falling back to 1MB when unset.
pub fn default_max_object_bytes() -> usize {
    DEFAULT_MAX_OBJECT_BYTES
        .get()
        .copied()
        .unwrap_or(FALLBACK_MAX_OBJECT_BYTES)
}

/// Resolves the final `max_file_size_bytes` a cache plugin would embed for `cfg`.
///
/// Used by static-config integration tests to assert that YAML defaults are applied
/// before plugin construction.
pub fn resolved_max_file_size_bytes(cfg: JsonValue) -> ProxyResult<usize> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(resolve_max_file_size(
        config.max_file_size_bytes,
        default_max_object_bytes(),
    ))
}

/// Resolves the final `max_file_size_bytes` for `CacheSettings`.
/// `None` (unconfigured) -> use the global default; `Some(0)` -> 0 (unlimited);
/// `Some(n)` -> n.
fn resolve_max_file_size(configured: Option<usize>, global_default: usize) -> usize {
    configured.unwrap_or(global_default)
}

// Context key for sharing cache settings between plugin and HttpService
pub const CTX_KEY_CACHE_SETTINGS: &str = "pingsix_cache_settings";

/// Lightweight cache configuration passed to HttpService.
///
/// This serves as a communication contract between the cache plugin and the HTTP service,
/// containing only the essential information needed for caching decisions during request processing.
#[derive(Clone)]
pub struct CacheSettings {
    pub ttl: Duration,
    pub statuses: Arc<HashSet<u16>>,
    /// Lowercase, trimmed Vary header names from config, pre-normalized at plugin creation.
    pub vary: Arc<Vec<String>>,
    pub hide_cache_headers: bool,
    pub max_file_size_bytes: usize,
    /// Enable Stale-While-Revalidate: serve stale content while fetching fresh content in background
    pub stale_while_revalidate: Option<Duration>,
    /// Enable s-maxage support: respect Cache-Control s-maxage directive for shared caches
    pub respect_s_maxage: bool,
    /// Cache authenticated or cookie-bearing requests. Disabled by default because a shared
    /// cache must not reuse user-specific responses without an explicit cache key strategy.
    pub cache_authenticated_requests: bool,
    /// Cache responses that set cookies. Disabled independently because replaying Set-Cookie from
    /// a shared cache can leak or overwrite sessions even for otherwise anonymous requests.
    pub cache_set_cookie_responses: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PluginConfig {
    #[validate(range(min = 1))]
    pub ttl: u64,

    #[serde(default = "PluginConfig::default_cache_http_methods")]
    #[validate(custom(function = "validate_methods"))]
    pub cache_http_methods: Vec<String>,

    #[serde(default = "PluginConfig::default_cache_http_statuses")]
    #[validate(custom(function = "validate_statuses"))]
    pub cache_http_statuses: Vec<u16>,

    #[serde(default)]
    #[validate(custom(function = "validate_regexes"))]
    pub no_cache_str: Vec<String>,

    #[serde(default)]
    pub vary: Vec<String>,

    #[serde(default)]
    pub hide_cache_headers: bool,

    /// Maximum cacheable response size in bytes.
    /// `None` (default) inherits the global `default_max_object_bytes`
    /// (`pingsix.defaults.cache.default_max_object_bytes`, 1MB by default).
    /// `Some(0)` means no limit. `Some(n)` enforces an explicit byte limit.
    #[serde(default)]
    pub max_file_size_bytes: Option<usize>,

    /// Stale-While-Revalidate duration in seconds.
    /// When set, stale cached responses can be served while a background revalidation occurs.
    /// This improves performance by reducing wait times for fresh content.
    #[serde(default)]
    pub stale_while_revalidate_secs: Option<u64>,

    /// Respect Cache-Control s-maxage directive for shared caches.
    /// When enabled, s-maxage overrides the configured TTL for shared cache scenarios.
    /// Default: true (recommended for CDN/proxy scenarios)
    #[serde(default = "PluginConfig::default_respect_s_maxage")]
    pub respect_s_maxage: bool,

    /// Allow shared caching for requests that include Authorization or Cookie headers.
    /// Defaults to false to prevent accidental cross-user response reuse.
    #[serde(default)]
    pub cache_authenticated_requests: bool,

    /// Allow responses containing Set-Cookie to enter the shared cache.
    /// This is a separate, high-risk opt-in and defaults to false.
    #[serde(default)]
    pub cache_set_cookie_responses: bool,
}

impl PluginConfig {
    fn default_cache_http_methods() -> Vec<String> {
        vec!["GET".to_string(), "HEAD".to_string()]
    }
    fn default_cache_http_statuses() -> Vec<u16> {
        vec![200]
    }
    fn default_respect_s_maxage() -> bool {
        true
    }
}

fn validate_methods(methods: &[String]) -> Result<(), ValidationError> {
    for m in methods {
        if m.parse::<Method>().is_err() {
            return Err(ValidationError::new("invalid_http_method"));
        }
    }
    Ok(())
}

fn validate_statuses(statuses: &[u16]) -> Result<(), ValidationError> {
    for &status in statuses {
        if !(100..=599).contains(&status) {
            return Err(ValidationError::new("invalid_http_status"));
        }
    }
    Ok(())
}

fn validate_regexes(patterns: &[String]) -> Result<(), ValidationError> {
    for pattern in patterns {
        if Regex::new(pattern).is_err() {
            return Err(ValidationError::new("invalid_regex_pattern"));
        }
    }
    Ok(())
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse cache plugin config", e)
        })?;

        config.validate()?;

        Ok(config)
    }
}

pub struct PluginCache {
    methods: HashSet<Method>,
    no_cache_regex: Vec<Regex>,
    // Pre-compiled shared settings to avoid recreation on each request
    cache_settings: Arc<CacheSettings>,
}

pub fn create_cache_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;

    let methods = config
        .cache_http_methods
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let statuses = Arc::new(config.cache_http_statuses.iter().cloned().collect());
    let no_cache_regex = config
        .no_cache_str
        .iter()
        .map(|s| {
            Regex::new(s).map_err(|e| -> Box<pingora_error::Error> {
                ProxyError::validation_error(format!("Invalid regex in no_cache_str '{s}': {e}"))
                    .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let vary = Arc::new(
        config
            .vary
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect(),
    );

    // Resolve the final max object size: None inherits the global default,
    // Some(0) means unlimited, Some(n) is an explicit limit.
    let max_file_size_bytes =
        resolve_max_file_size(config.max_file_size_bytes, default_max_object_bytes());

    // Pre-build cache settings at plugin creation to avoid per-request overhead
    let cache_settings = Arc::new(CacheSettings {
        ttl: Duration::from_secs(config.ttl),
        statuses,
        vary,
        hide_cache_headers: config.hide_cache_headers,
        max_file_size_bytes,
        stale_while_revalidate: config.stale_while_revalidate_secs.map(Duration::from_secs),
        respect_s_maxage: config.respect_s_maxage,
        cache_authenticated_requests: config.cache_authenticated_requests,
        cache_set_cookie_responses: config.cache_set_cookie_responses,
    });

    Ok(Arc::new(PluginCache {
        methods,
        no_cache_regex,
        cache_settings,
    }))
}

pub(crate) fn should_bypass_authenticated_request(
    settings: &CacheSettings,
    ctx: &ProxyContext,
) -> bool {
    !settings.cache_authenticated_requests
        && (ctx.original_request_had_credentials || ctx.request_has_credentials)
}

#[cfg(test)]
fn should_bypass_set_cookie_response(settings: &CacheSettings, has_set_cookie: bool) -> bool {
    has_set_cookie && !settings.cache_set_cookie_responses
}

#[async_trait]
impl ProxyPlugin for PluginCache {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        let method = &session.req_header().method;
        let path = session.req_header().uri.path();

        // 1. Check if method is cacheable
        if !self.methods.contains(method) {
            log::trace!("Method {method} not cacheable, skipping cache");
            return Ok(false);
        }

        // 2. Shared caching of authenticated or cookie-bearing requests is opt-in.
        if should_bypass_authenticated_request(&self.cache_settings, ctx) {
            log::trace!("Request contains credentials, skipping shared cache");
            return Ok(false);
        }

        // 3. Check if URI matches a no-cache pattern
        for re in &self.no_cache_regex {
            if re.is_match(path) {
                log::trace!("Path {path} matches no-cache pattern, skipping cache");
                return Ok(false);
            }
        }

        // 4. All checks passed. Put the lightweight CacheSettings into context.
        ctx.set(CTX_KEY_CACHE_SETTINGS, self.cache_settings.clone());
        log::trace!("Cache enabled for {method} {path}");

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_from_json_with_default(
        value: serde_json::Value,
        global_default: usize,
    ) -> CacheSettings {
        let config = PluginConfig::try_from(value).unwrap();
        CacheSettings {
            ttl: Duration::from_secs(config.ttl),
            statuses: Arc::new(config.cache_http_statuses.iter().cloned().collect()),
            vary: Arc::new(vec![]),
            hide_cache_headers: config.hide_cache_headers,
            max_file_size_bytes: resolve_max_file_size(config.max_file_size_bytes, global_default),
            stale_while_revalidate: config.stale_while_revalidate_secs.map(Duration::from_secs),
            respect_s_maxage: config.respect_s_maxage,
            cache_authenticated_requests: config.cache_authenticated_requests,
            cache_set_cookie_responses: config.cache_set_cookie_responses,
        }
    }

    fn settings_from_json(value: serde_json::Value) -> CacheSettings {
        settings_from_json_with_default(value, default_max_object_bytes())
    }

    #[test]
    fn authenticated_requests_are_not_cacheable_by_default() {
        let config = PluginConfig::try_from(serde_json::json!({ "ttl": 60 })).unwrap();

        assert!(!config.cache_authenticated_requests);
    }

    #[test]
    fn authenticated_request_caching_requires_explicit_opt_in() {
        let config = PluginConfig::try_from(serde_json::json!({
            "ttl": 60,
            "cache_authenticated_requests": true
        }))
        .unwrap();

        assert!(config.cache_authenticated_requests);
        assert!(!config.cache_set_cookie_responses);
    }

    #[test]
    fn set_cookie_response_caching_requires_separate_opt_in() {
        let config = PluginConfig::try_from(serde_json::json!({
            "ttl": 60,
            "cache_authenticated_requests": true,
            "cache_set_cookie_responses": true
        }))
        .unwrap();

        assert!(config.cache_set_cookie_responses);
    }

    #[test]
    fn credential_flags_bypass_shared_cache_by_default() {
        let settings = settings_from_json(serde_json::json!({ "ttl": 60 }));

        let from_headers = ProxyContext {
            original_request_had_credentials: true,
            ..Default::default()
        };
        assert!(should_bypass_authenticated_request(
            &settings,
            &from_headers
        ));

        let mut from_plugin = ProxyContext::default();
        from_plugin.mark_request_has_credentials();
        assert!(should_bypass_authenticated_request(&settings, &from_plugin));

        let opt_in = settings_from_json(serde_json::json!({
            "ttl": 60,
            "cache_authenticated_requests": true
        }));
        assert!(!should_bypass_authenticated_request(&opt_in, &from_plugin));
    }

    #[test]
    fn late_auth_mark_still_bypasses_when_checked_at_enable_time() {
        // Simulates global cache setting CacheSettings before route key-auth marks credentials.
        let settings = settings_from_json(serde_json::json!({ "ttl": 60 }));
        let mut ctx = ProxyContext::default();
        assert!(!should_bypass_authenticated_request(&settings, &ctx));
        ctx.mark_request_has_credentials();
        assert!(should_bypass_authenticated_request(&settings, &ctx));
    }

    #[test]
    fn set_cookie_responses_bypass_unless_explicitly_enabled() {
        let defaults = settings_from_json(serde_json::json!({ "ttl": 60 }));
        assert!(should_bypass_set_cookie_response(&defaults, true));
        assert!(!should_bypass_set_cookie_response(&defaults, false));

        let opt_in = settings_from_json(serde_json::json!({
            "ttl": 60,
            "cache_set_cookie_responses": true
        }));
        assert!(!should_bypass_set_cookie_response(&opt_in, true));
    }

    #[test]
    fn max_file_size_none_uses_global_default() {
        // None (unconfigured) inherits the global default, whatever it is.
        let s = settings_from_json_with_default(serde_json::json!({ "ttl": 60 }), 999_999);
        assert_eq!(s.max_file_size_bytes, 999_999);
    }

    #[test]
    fn max_file_size_some_zero_means_unlimited() {
        let s = settings_from_json_with_default(
            serde_json::json!({ "ttl": 60, "max_file_size_bytes": 0 }),
            999_999,
        );
        assert_eq!(s.max_file_size_bytes, 0);
    }

    #[test]
    fn max_file_size_some_value() {
        let s = settings_from_json_with_default(
            serde_json::json!({ "ttl": 60, "max_file_size_bytes": 5_000_000 }),
            999_999,
        );
        assert_eq!(s.max_file_size_bytes, 5_000_000);
    }
}
