use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{constant_time_eq, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::{request, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "key-auth";
const PRIORITY: i32 = 2500;

/// Default header name for API key
const DEFAULT_API_KEY_HEADER: &str = "apikey";
/// Default query parameter name for API key
const DEFAULT_API_KEY_QUERY: &str = "apikey";

/// Creates a Key Auth plugin instance with the given configuration.
/// This plugin authenticates requests by matching an API key in the HTTP header or query parameter
/// against configured keys. If the key is invalid or missing, it returns a `401 Unauthorized` response.
pub fn create_key_auth_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginKeyAuth { config }))
}

/// Configuration for the Key Auth plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// HTTP header field name containing the API key (default: `apikey`).
    #[serde(default = "PluginConfig::default_header")]
    header: String,

    /// Query parameter name containing the API key (default: `apikey`).
    #[serde(default = "PluginConfig::default_query")]
    query: String,

    /// The API key to match against. Must be non-empty.
    /// For backward compatibility, single key as string.
    #[validate(length(min = 1))]
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,

    /// Multiple API keys to match against. Supports key rotation.
    /// Takes precedence over single `key` if both are provided.
    #[validate(length(min = 1))]
    #[serde(default)]
    keys: Vec<String>,

    /// Whether to remove the API key from headers or query parameters after validation (default: false).
    #[serde(default = "PluginConfig::default_hide_credentials")]
    hide_credentials: bool,
}

impl PluginConfig {
    fn default_header() -> String {
        DEFAULT_API_KEY_HEADER.to_string()
    }

    fn default_query() -> String {
        DEFAULT_API_KEY_QUERY.to_string()
    }

    fn default_hide_credentials() -> bool {
        false
    }

    /// Get all valid keys (combines single key and multiple keys)
    fn get_valid_keys(&self) -> Vec<&String> {
        if !self.keys.is_empty() {
            self.keys.iter().collect()
        } else if let Some(ref key) = self.key {
            vec![key]
        } else {
            vec![]
        }
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse key auth plugin config", e)
        })?;

        config.validate()?;

        Ok(config)
    }
}

/// Source of the API key (header, query, or none).
#[derive(PartialEq)]
enum KeySource {
    Header,
    Query,
    None,
}

/// Key Auth plugin implementation.
/// Validates API keys from HTTP headers or query parameters using constant-time comparison.
/// Supports multiple keys for key rotation scenarios.
/// Note: For production environments, consider using more secure mechanisms like HMAC signatures
/// or integration with a consumer management system instead of fixed key matching.
pub struct PluginKeyAuth {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginKeyAuth {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        // Try to extract key from header or query
        let (value, source) =
            request::get_req_header_value(session.req_header(), &self.config.header)
                .map(|val| (val, KeySource::Header))
                .or_else(|| {
                    request::get_query_value(session.req_header(), &self.config.query)
                        .map(|val| (val, KeySource::Query))
                })
                .unwrap_or(("", KeySource::None));

        // Validate key using constant-time comparison
        if value.is_empty() || !self.is_valid_key(value) {
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("Invalid user authorization"),
                Some(&[("WWW-Authenticate", "ApiKey error=\"invalid_key\"")]),
            )
            .await?;
            return Ok(true);
        }

        // Hide credentials if configured
        if self.config.hide_credentials {
            match source {
                KeySource::Header => {
                    session.req_header_mut().remove_header(&self.config.header);
                }
                KeySource::Query => {
                    let _ = request::remove_query_from_header(
                        session.req_header_mut(),
                        &self.config.query,
                    );
                }
                KeySource::None => {}
            }
        }

        Ok(false)
    }
}

impl PluginKeyAuth {
    /// Validate the provided key against configured keys using constant-time comparison
    fn is_valid_key(&self, provided_key: &str) -> bool {
        let valid_keys = self.config.get_valid_keys();

        if valid_keys.is_empty() {
            return false;
        }

        // Use constant-time comparison to prevent timing attacks
        for valid_key in valid_keys {
            if constant_time_eq(provided_key, valid_key) {
                return true;
            }
        }

        false
    }
}
