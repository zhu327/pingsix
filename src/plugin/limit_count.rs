use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_limits::rate::Rate;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{config::UpstreamHashOn, proxy::ProxyContext, utils::request::request_selector_key};

use super::ProxyPlugin;
use crate::utils::response::ResponseBuilder;

pub const PLUGIN_NAME: &str = "limit-count";
const PRIORITY: i32 = 1002;

/// Creates a Limit Count plugin instance with the given configuration.
/// This plugin enforces rate limiting on requests based on a key derived from the request
/// (e.g., client IP, header, or custom variable). Exceeding the limit results in a configurable
/// response (default: `503 Service Unavailable`).
pub fn create_limit_count_plugin(cfg: JsonValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig = serde_json::from_value(cfg)
        .or_err_with(ReadError, || "Invalid limit count plugin config")?;

    config
        .validate()
        .or_err_with(ReadError, || "Invalid limit count plugin config")?;

    let rate = Rate::new(Duration::from_secs(config.time_window as u64));

    Ok(Arc::new(PluginRateLimit { config, rate }))
}

/// Configuration for the Limit Count plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Type of key to use for rate limiting (e.g., `IP`, `HEADER`, `VARS`).
    key_type: UpstreamHashOn,

    /// Key name or value to use for rate limiting (e.g., header name for `HEADER`, variable name for `VARS`).
    /// Must be non-empty and valid for the specified `key_type`.
    #[validate(custom(function = "validate_key"))]
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

impl PluginConfig {
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
/// Enforces request rate limiting using an in-memory counter.
/// Note: This is a single-instance rate limiter. For distributed environments, consider using
/// an external store like Redis or etcd for global rate limiting.
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

        // Check rate limit
        let (is_limited, current_count, remaining) = self.check_rate_limit(&key);

        if is_limited {
            return self
                .handle_rate_limit(session, current_count, remaining)
                .await;
        }

        // Store rate limit info in context for potential use by other plugins
        if self.config.show_limit_quota_header {
            ctx.set("rate_limit_limit", self.config.count.to_string());
            ctx.set("rate_limit_remaining", remaining.to_string());
            ctx.set("rate_limit_reset", self.config.time_window.to_string());
        }

        Ok(false)
    }
}

impl PluginRateLimit {
    /// Handle requests with missing keys based on configured policy
    async fn handle_missing_key(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        match self.config.key_missing_policy {
            KeyMissingPolicy::Allow => Ok(false),
            KeyMissingPolicy::Deny => {
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
                let default_key = "_default_rate_limit_key".to_string();
                let (is_limited, current_count, remaining) = self.check_rate_limit(&default_key);

                if is_limited {
                    self.handle_rate_limit(session, current_count, remaining)
                        .await
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Check if the request exceeds the rate limit and return detailed information
    fn check_rate_limit(&self, key: &str) -> (bool, isize, isize) {
        let current_count = self.rate.observe(&key.to_string(), 1);
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
        let mut headers = Vec::new();

        if self.config.show_limit_quota_header {
            headers.push(("X-Rate-Limit-Limit", self.config.count.to_string()));
            headers.push(("X-Rate-Limit-Remaining", remaining.to_string()));
            headers.push(("X-Rate-Limit-Reset", self.config.time_window.to_string()));
            // Add current usage for debugging
            headers.push(("X-Rate-Limit-Used", current_count.to_string()));
            // Add retry-after header
            headers.push(("Retry-After", self.config.time_window.to_string()));
        }

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
