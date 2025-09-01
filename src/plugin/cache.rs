use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::Method;
use pingora_error::Result;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

pub const PLUGIN_NAME: &str = "cache";
const PRIORITY: i32 = 1085;

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
    pub vary: Arc<Vec<String>>,
    pub hide_cache_headers: bool,
    pub max_file_size_bytes: usize,
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

    /// Maximum cacheable response size in bytes. Zero means no limit.
    /// Used to prevent memory exhaustion from caching large responses.
    #[serde(default)]
    pub max_file_size_bytes: usize,
}

impl PluginConfig {
    fn default_cache_http_methods() -> Vec<String> {
        vec!["GET".to_string(), "HEAD".to_string()]
    }
    fn default_cache_http_statuses() -> Vec<u16> {
        vec![200]
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

        config.validate().map_err(|e| {
            ProxyError::validation_error(format!("Cache plugin config validation failed: {e}"))
        })?;

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
                ProxyError::validation_error(format!(
                    "Invalid regex in no_cache_str '{s}': {e}"
                ))
                .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Pre-build cache settings at plugin creation to avoid per-request overhead
    let cache_settings = Arc::new(CacheSettings {
        ttl: Duration::from_secs(config.ttl),
        statuses,
        vary: Arc::new(config.vary.clone()),
        hide_cache_headers: config.hide_cache_headers,
        max_file_size_bytes: config.max_file_size_bytes,
    });

    Ok(Arc::new(PluginCache {
        methods,
        no_cache_regex,
        cache_settings,
    }))
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

        // 2. Check if URI matches a no-cache pattern
        for re in &self.no_cache_regex {
            if re.is_match(path) {
                log::trace!("Path {path} matches no-cache pattern, skipping cache");
                return Ok(false);
            }
        }

        // 3. All checks passed. Put the lightweight CacheSettings into context.
        ctx.set(CTX_KEY_CACHE_SETTINGS, self.cache_settings.clone());
        log::trace!("Cache enabled for {method} {path}");

        Ok(false)
    }
}
