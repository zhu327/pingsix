use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::{header, StatusCode};
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{constant_time_eq, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::{request, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "basic-auth";
const PRIORITY: i32 = 2520;

/// Creates a Basic Auth plugin instance.
pub fn create_basic_auth_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginBasicAuth { config }))
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[validate(length(min = 1))]
    username: String,
    #[validate(length(min = 1))]
    password: String,
    #[serde(default)]
    hide_credentials: bool,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse basic auth plugin config", e)
        })?;
        config.validate()?;
        Ok(config)
    }
}

pub struct PluginBasicAuth {
    config: PluginConfig,
}

impl PluginBasicAuth {
    /// Validates Basic Authentication credentials using constant-time comparison.
    ///
    /// This method:
    /// 1. Checks for "Basic " prefix (case-insensitive)
    /// 2. Decodes the Base64-encoded credentials
    /// 3. Splits username and password at the first colon
    /// 4. Uses constant-time comparison to prevent timing attacks
    fn validate_credentials(&self, auth_value: &str) -> bool {
        // 1. Check prefix
        if !auth_value.to_lowercase().starts_with("basic ") {
            return false;
        }

        // 2. Decode Base64
        let credential_part = &auth_value[6..];
        let Ok(decoded_bytes) = general_purpose::STANDARD.decode(credential_part) else {
            return false;
        };

        let Ok(decoded_str) = String::from_utf8(decoded_bytes) else {
            return false;
        };

        // 3. Separate username:password
        let Some((user, pass)) = decoded_str.split_once(':') else {
            return false;
        };

        // 4. Use constant-time comparison to prevent timing attacks
        constant_time_eq(user, &self.config.username)
            && constant_time_eq(pass, &self.config.password)
    }
}

#[async_trait]
impl ProxyPlugin for PluginBasicAuth {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let auth_header =
            request::get_req_header_value(session.req_header(), header::AUTHORIZATION.as_str());

        let is_valid = match auth_header {
            Some(val) => self.validate_credentials(val),
            None => false,
        };

        if !is_valid {
            // Return 401 and include the standard Basic challenge header
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("Invalid user authorization"),
                Some(&[("WWW-Authenticate", "Basic realm=\"pingsix\"")]),
            )
            .await?;
            return Ok(true);
        }

        // Hide credentials by removing the Authorization header before forwarding upstream
        if self.config.hide_credentials {
            session
                .req_header_mut()
                .remove_header(&header::AUTHORIZATION);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_plugin(username: &str, password: &str) -> PluginBasicAuth {
        PluginBasicAuth {
            config: PluginConfig {
                username: username.to_string(),
                password: password.to_string(),
                hide_credentials: false,
            },
        }
    }

    #[test]
    fn validate_credentials_accepts_valid_pairs() {
        let plugin = build_plugin("demo", "s3cret");
        let header = format!("Basic {}", general_purpose::STANDARD.encode("demo:s3cret"));
        assert!(plugin.validate_credentials(&header));
    }

    #[test]
    fn validate_credentials_rejects_invalid_pairs() {
        let plugin = build_plugin("demo", "s3cret");

        // Wrong prefix
        assert!(!plugin.validate_credentials("Bearer something"));

        // Wrong password
        let header = format!("Basic {}", general_purpose::STANDARD.encode("demo:badpass"));
        assert!(!plugin.validate_credentials(&header));
    }
}
