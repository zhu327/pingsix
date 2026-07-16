use std::{sync::Arc, time::Duration};

use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, IntCounterVec};

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_limits::rate::Rate;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    config::UpstreamHashOn,
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::{request::request_selector_key, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "limit-count";
const PRIORITY: i32 = 1002;

static RATE_LIMIT_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_rate_limit_requests_total",
        "Rate-limit decisions by local outcome",
        &["outcome", "scope"]
    )
    .expect("rate-limit metric registration must succeed")
});

/// Creates a Limit Count plugin instance with the given configuration.
/// This plugin enforces rate limiting on requests based on a key derived from the request
/// (e.g., client IP, header, or custom variable). Exceeding the limit results in a configurable
/// response (default: `503 Service Unavailable`).
pub fn create_limit_count_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;

    let rate = Rate::new(Duration::from_secs(config.time_window as u64));

    Ok(Arc::new(PluginRateLimit { config, rate }))
}

/// Configuration for the Limit Count plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Type of key to use for rate limiting (e.g., `IP`, `HEADER`, `VARS`).
    /// Defaults to `vars` for APISIX compatibility.
    #[serde(default)]
    key_type: UpstreamHashOn,

    /// Key name or value to use for rate limiting (e.g., header name for `HEADER`, variable name for `VARS`).
    /// Defaults to `remote_addr` for APISIX compatibility.
    /// Must be non-empty and valid for the specified `key_type`.
    #[validate(custom(function = "validate_key"))]
    #[serde(default = "PluginConfig::default_key")]
    key: String,

    /// Time window for rate limiting, in seconds.
    #[validate(range(min = 1, max = 86400))] // 1 second to 1 day
    time_window: u32,

    /// Maximum number of requests allowed in the time window.
    #[validate(range(min = 1))]
    count: u32,

    /// HTTP status code for rejected requests (default: 503).
    #[serde(default = "PluginConfig::default_rejected_code")]
    #[validate(range(min = 400, max = 599))]
    rejected_code: u16,

    /// Optional custom message for rejected requests. If not set, no response body is sent.
    #[serde(default)]
    rejected_msg: Option<String>,

    /// Whether to include `X-Rate-Limit-*` headers in the response (default: true).
    #[serde(default = "PluginConfig::default_show_limit_quota_header")]
    show_limit_quota_header: bool,

    /// Policy for handling requests when key extraction fails (default: allow).
    #[serde(default = "PluginConfig::default_key_missing_policy")]
    key_missing_policy: KeyMissingPolicy,

    /// Rate limiting is process-local in this release; cluster scope needs a shared backend.
    #[serde(default)]
    scope: Scope,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
enum KeyMissingPolicy {
    /// Allow requests when key cannot be extracted
    #[default]
    Allow,
    /// Deny requests when key cannot be extracted
    Deny,
    /// Use a default key for all requests with missing keys
    Default,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Scope {
    #[default]
    Local,
    Cluster,
}

impl PluginConfig {
    fn default_key() -> String {
        "remote_addr".to_string()
    }

    fn default_rejected_code() -> u16 {
        503
    }

    fn default_show_limit_quota_header() -> bool {
        true
    }

    fn default_key_missing_policy() -> KeyMissingPolicy {
        KeyMissingPolicy::Allow
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid limit count plugin config", e))?;

        config.validate()?;
        if config.scope == Scope::Cluster {
            return Err(ProxyError::validation_error(
                "limit-count scope 'cluster' requires a distributed backend",
            ));
        }

        Ok(config)
    }
}

/// Validates the `key` field based on `key_type`.
fn validate_key(key: &str) -> Result<(), ValidationError> {
    if key.is_empty() {
        return Err(ValidationError::new("key cannot be empty"));
    }
    // Additional validation based on key_type (e.g., header names should be alphanumeric + dashes)
    if key.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.') {
        return Err(ValidationError::new(
            "key contains invalid characters (only alphanumeric, -, _, . allowed)",
        ));
    }
    Ok(())
}

/// Rate Limit plugin implementation.
///
/// This is a per-instance in-memory rate limiter. In a multi-replica deployment,
/// the effective limit is approximately `config.count * replica_count`.
pub struct PluginRateLimit {
    config: PluginConfig,
    rate: Rate,
}

#[async_trait]
impl ProxyPlugin for PluginRateLimit {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        let key = request_selector_key(session, &self.config.key_type, self.config.key.as_str());

        // Handle empty key based on policy
        if key.is_empty() {
            return self.handle_missing_key(session, ctx).await;
        }

        // Check rate limit without forcing borrowed selector keys to allocate.
        let (is_limited, current_count, remaining) = self.check_rate_limit(key.as_ref());

        if is_limited {
            RATE_LIMIT_REQUESTS
                .with_label_values(&["rejected", "local"])
                .inc();
            return self
                .handle_rate_limit(session, current_count, remaining)
                .await;
        }
        RATE_LIMIT_REQUESTS
            .with_label_values(&["allowed", "local"])
            .inc();

        // Store rate limit info in context for potential use by other plugins
        if self.config.show_limit_quota_header {
            ctx.set("rate_limit_limit", self.config.count.to_string());
            ctx.set("rate_limit_remaining", remaining.to_string());
            ctx.set("rate_limit_reset", self.config.time_window.to_string());
        }

        Ok(false)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if self.config.show_limit_quota_header {
            for (context_key, header) in [
                ("rate_limit_limit", "X-Rate-Limit-Limit"),
                ("rate_limit_remaining", "X-Rate-Limit-Remaining"),
                ("rate_limit_reset", "X-Rate-Limit-Reset"),
            ] {
                if let Some(value) = ctx.get_str(context_key) {
                    upstream_response.insert_header(header, value)?;
                }
            }
            // Only expose the implementation scope when this plugin recorded
            // quota data for the request. A short-circuited request may still
            // reach this filter without ever being rate-limited.
            if ctx.get_str("rate_limit_limit").is_some() {
                upstream_response.insert_header("X-RateLimit-Scope", "local")?;
            }
        }
        Ok(())
    }
}

impl PluginRateLimit {
    /// Handle requests with missing keys based on configured policy
    async fn handle_missing_key(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<bool> {
        match self.config.key_missing_policy {
            KeyMissingPolicy::Allow => {
                RATE_LIMIT_REQUESTS
                    .with_label_values(&["allowed", "local"])
                    .inc();
                Ok(false)
            }
            KeyMissingPolicy::Deny => {
                RATE_LIMIT_REQUESTS
                    .with_label_values(&["rejected", "local"])
                    .inc();
                ResponseBuilder::send_proxy_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    Some("Missing required key for rate limiting"),
                    None,
                )
                .await?;
                Ok(true)
            }
            KeyMissingPolicy::Default => {
                // Use a default key for all requests with missing keys
                let (is_limited, current_count, remaining) =
                    self.check_rate_limit("_default_rate_limit_key");

                if is_limited {
                    RATE_LIMIT_REQUESTS
                        .with_label_values(&["rejected", "local"])
                        .inc();
                    self.handle_rate_limit(session, current_count, remaining)
                        .await
                } else {
                    RATE_LIMIT_REQUESTS
                        .with_label_values(&["allowed", "local"])
                        .inc();
                    if self.config.show_limit_quota_header {
                        ctx.set("rate_limit_limit", self.config.count.to_string());
                        ctx.set("rate_limit_remaining", remaining.to_string());
                        ctx.set("rate_limit_reset", self.config.time_window.to_string());
                    }
                    Ok(false)
                }
            }
        }
    }

    /// Check if the request exceeds the rate limit and return detailed information
    fn check_rate_limit(&self, key: &str) -> (bool, isize, isize) {
        // Rate::observe requires a sized hash key. Passing &&str keeps this allocation-free.
        let current_count = self.rate.observe(&key, 1);
        let remaining = (self.config.count as isize) - current_count;
        let is_limited = current_count > self.config.count as isize;

        (is_limited, current_count, remaining.max(0))
    }

    /// Handle rate-limited requests by sending a rejection response with detailed headers
    async fn handle_rate_limit(
        &self,
        session: &mut Session,
        current_count: isize,
        remaining: isize,
    ) -> Result<bool> {
        let headers = build_rate_limit_headers(
            self.config.count,
            remaining,
            self.config.time_window,
            current_count,
            self.config.show_limit_quota_header,
        );

        let headers_ref: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (&**k, &**v)).collect();

        session.set_keepalive(None);

        ResponseBuilder::send_proxy_error(
            session,
            StatusCode::from_u16(self.config.rejected_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            self.config.rejected_msg.as_deref(),
            if headers_ref.is_empty() {
                None
            } else {
                Some(&headers_ref)
            },
        )
        .await?;

        Ok(true)
    }
}

/// Build the rate-limit response headers for a rejected request.
///
/// `X-RateLimit-Scope: local` advertises that this limiter is per-instance/in-memory,
/// so operators know the effective limit scales with replica count.
fn build_rate_limit_headers(
    count: u32,
    remaining: isize,
    time_window: u32,
    current_count: isize,
    show: bool,
) -> Vec<(&'static str, String)> {
    if !show {
        return Vec::new();
    }

    vec![
        ("X-Rate-Limit-Limit", count.to_string()),
        ("X-Rate-Limit-Remaining", remaining.to_string()),
        ("X-Rate-Limit-Reset", time_window.to_string()),
        ("X-Rate-Limit-Used", current_count.to_string()),
        ("Retry-After", time_window.to_string()),
        ("X-RateLimit-Scope", "local".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_response_includes_local_scope() {
        let headers = build_rate_limit_headers(10, 3, 60, 7, true);
        let scope = headers
            .iter()
            .find(|(name, _)| *name == "X-RateLimit-Scope")
            .map(|(_, value)| value.as_str());
        assert_eq!(scope, Some("local"));
    }

    #[test]
    fn build_rate_limit_headers_respects_show_flag() {
        let headers = build_rate_limit_headers(10, 3, 60, 7, false);
        assert!(headers.is_empty());
    }
}
