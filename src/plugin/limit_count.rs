use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use http::header;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_limits::rate::Rate;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use validator::{Validate, ValidationError};

use crate::{config::UpstreamHashOn, proxy::ProxyContext, utils::request::request_selector_key};

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "limit-count";
const PRIORITY: i32 = 1002;

/// Creates a Limit Count plugin instance with the given configuration.
/// This plugin enforces rate limiting on requests based on a key derived from the request
/// (e.g., client IP, header, or custom variable). Exceeding the limit results in a configurable
/// response (default: `503 Service Unavailable`).
pub fn create_limit_count_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig = serde_yaml::from_value(cfg)
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
    time_window: u32,

    /// Maximum number of requests allowed in the time window.
    count: u32,

    /// HTTP status code for rejected requests (default: 503).
    #[serde(default = "PluginConfig::default_rejected_code")]
    rejected_code: u16,

    /// Optional custom message for rejected requests. If not set, no response body is sent.
    #[serde(default)]
    rejected_msg: Option<String>,

    /// Whether to include `X-Rate-Limit-*` headers in the response (default: true).
    #[serde(default = "PluginConfig::default_show_limit_quota_header")]
    show_limit_quota_header: bool,
}

impl PluginConfig {
    fn default_rejected_code() -> u16 {
        503
    }

    fn default_show_limit_quota_header() -> bool {
        true
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

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let key = request_selector_key(session, &self.config.key_type, self.config.key.as_str());

        // Handle empty key (e.g., missing header or variable)
        if key.is_empty() {
            return self.handle_rate_limit(session).await;
        }

        if self.is_rate_limited(key) {
            return self.handle_rate_limit(session).await;
        }

        Ok(false)
    }
}

impl PluginRateLimit {
    /// Check if the request exceeds the rate limit.
    fn is_rate_limited(&self, key: String) -> bool {
        let curr_window_requests = self.rate.observe(&key, 1);
        curr_window_requests > self.config.count as isize
    }

    /// Handle rate-limited requests by sending a rejection response.
    async fn handle_rate_limit(&self, session: &mut Session) -> Result<bool> {
        let mut header = ResponseHeader::build(self.config.rejected_code, None)?;

        if self.config.show_limit_quota_header {
            header.insert_header("X-Rate-Limit-Limit", self.config.count.to_string())?;
            header.insert_header("X-Rate-Limit-Remaining", "0")?;
            header.insert_header("X-Rate-Limit-Reset", "1")?;
        }

        session.set_keepalive(None);

        if let Some(ref msg) = self.config.rejected_msg {
            header.insert_header(header::CONTENT_LENGTH, msg.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(msg.clone().into()), true)
                .await?;
        } else {
            session
                .write_response_header(Box::new(header), true)
                .await?;
        }

        Ok(true)
    }
}
