use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::{header, Method, StatusCode};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use validator::Validate;

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};
use crate::utils::{request, response::ResponseBuilder};

pub const PLUGIN_NAME: &str = "csrf";
const PRIORITY: i32 = 2980;

/// Safe HTTP methods that do not require CSRF validation
const SAFE_METHODS: &[Method] = &[Method::GET, Method::HEAD, Method::OPTIONS];

pub fn create_csrf_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginCsrf { config }))
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[validate(length(min = 1))]
    key: String,
    #[serde(default = "PluginConfig::default_expires")]
    expires: u64,
    #[serde(default = "PluginConfig::default_name")]
    name: String,
}

impl PluginConfig {
    fn default_expires() -> u64 {
        7200
    }
    fn default_name() -> String {
        "pingsix-csrf-token".to_string()
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;
    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid csrf plugin config", e))?;
        config.validate()?;
        Ok(config)
    }
}

#[derive(Serialize, Deserialize)]
struct CsrfToken {
    random: f64,
    expires: u64,
    sign: String,
}

pub struct PluginCsrf {
    config: PluginConfig,
}

impl PluginCsrf {
    // Generates deterministic signature: sha256("{expires:123,random:0.5,key:secret}")
    fn gen_sign(&self, random: f64, expires: u64) -> String {
        let sign_str = format!(
            "{{expires:{},random:{},key:{}}}",
            expires, random, self.config.key
        );
        let mut hasher = Sha256::new();
        hasher.update(sign_str);
        hex::encode(hasher.finalize())
    }

    fn gen_token_string(&self) -> String {
        let mut rng = rand::rng();
        let random: f64 = rng.random();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sign = self.gen_sign(random, now);

        let token = CsrfToken {
            random,
            expires: now,
            sign,
        };

        let json = serde_json::to_string(&token).unwrap();
        general_purpose::STANDARD.encode(json)
    }

    fn check_token(&self, token_b64: &str) -> bool {
        let Ok(decoded) = general_purpose::STANDARD.decode(token_b64) else {
            log::error!("csrf token base64 decode error");
            return false;
        };

        let Ok(token_table) = serde_json::from_slice::<CsrfToken>(&decoded) else {
            log::error!("csrf token json decode error");
            return false;
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check expiration window
        if self.config.expires > 0 && (now - token_table.expires) > self.config.expires {
            log::error!("csrf token expired");
            return false;
        }

        // Validate signature
        let expected_sign = self.gen_sign(token_table.random, token_table.expires);
        if token_table.sign != expected_sign {
            log::error!("csrf token invalid signature");
            return false;
        }

        true
    }
}

#[async_trait]
impl ProxyPlugin for PluginCsrf {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let method = &session.req_header().method;

        // 1. Allow safe methods to bypass CSRF validation
        if SAFE_METHODS.contains(method) {
            return Ok(false);
        }

        // 2. Read token from headers
        let header_token = request::get_req_header_value(session.req_header(), &self.config.name);
        if header_token.is_none() || header_token.unwrap().is_empty() {
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("no csrf token in headers"),
                None,
            )
            .await?;
            return Ok(true);
        }

        // 3. Read token from cookies
        let cookie_token = request::get_cookie_value(session.req_header(), &self.config.name);
        if cookie_token.is_none() {
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("no csrf cookie"),
                None,
            )
            .await?;
            return Ok(true);
        }

        let h_token = header_token.unwrap();
        let c_token = cookie_token.unwrap();

        // 4. Double-submit consistency check
        if h_token != c_token {
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("csrf token mismatch"),
                None,
            )
            .await?;
            return Ok(true);
        }

        // 5. Verify token signature and expiration
        if !self.check_token(c_token) {
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("Failed to verify the csrf token signature"),
                None,
            )
            .await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        let csrf_token = self.gen_token_string();

        // Set the CSRF cookie; production deployments may also want HttpOnly (if applicable),
        // Secure, and stricter SameSite policies.
        let cookie_val = format!(
            "{}={}; Path=/; SameSite=Lax; Max-Age={}",
            self.config.name, csrf_token, self.config.expires
        );

        upstream_response.insert_header(header::SET_COOKIE, cookie_val)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_plugin(expires: u64) -> PluginCsrf {
        PluginCsrf {
            config: PluginConfig {
                key: "unit-test-key".to_string(),
                expires,
                name: "csrf-token".to_string(),
            },
        }
    }

    #[test]
    fn token_roundtrip_passes_validation() {
        let plugin = build_plugin(7200);
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let random = 0.5_f64;
        let sign = plugin.gen_sign(random, expires);
        let token = CsrfToken {
            random,
            expires,
            sign,
        };
        let json = serde_json::to_string(&token).unwrap();
        let encoded = general_purpose::STANDARD.encode(json);
        assert!(plugin.check_token(&encoded));
    }

    #[test]
    fn tampered_token_is_rejected() {
        let plugin = build_plugin(7200);
        let token = plugin.gen_token_string();
        let mut decoded = general_purpose::STANDARD.decode(token.as_bytes()).unwrap();
        decoded[0] ^= 0x01;
        let tampered = general_purpose::STANDARD.encode(decoded);
        assert!(!plugin.check_token(&tampered));
    }
}
