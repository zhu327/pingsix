use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use http::{header, Method, StatusCode};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::Sha256;
use validator::Validate;

use crate::core::{constant_time_eq, ProxyContext, ProxyError, ProxyPlugin, ProxyResult};
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
    /// Random bytes (hex encoded) for uniqueness
    random: String,
    /// Token creation timestamp in seconds since UNIX_EPOCH
    expires: u64,
    /// HMAC signature of the token
    sign: String,
}

pub struct PluginCsrf {
    config: PluginConfig,
}

impl PluginCsrf {
    /// Generates HMAC-SHA256 signature for the token
    ///
    /// Uses standard HMAC-SHA256(key, random || expires).
    fn gen_sign(&self, random: &str, expires: u64) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(self.config.key.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(random.as_bytes());
        mac.update(expires.to_string().as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Generates a new CSRF token string (base64 encoded JSON)
    ///
    /// Returns None if system time is unavailable (should never happen in practice)
    fn gen_token_string(&self) -> Option<String> {
        let mut rng = rand::thread_rng();
        // Generate 16 random bytes for better entropy than f64
        let random_bytes: [u8; 16] = rng.gen();
        let random = hex::encode(random_bytes);

        // Get current timestamp, handle potential system time errors gracefully
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

        let sign = self.gen_sign(&random, now);

        let token = CsrfToken {
            random,
            expires: now,
            sign,
        };

        // Serialize to JSON, return None on error instead of panicking
        let json = serde_json::to_string(&token).ok()?;
        Some(general_purpose::STANDARD.encode(json))
    }

    /// Validates a CSRF token
    ///
    /// Returns false if the token is invalid, expired, or has an incorrect signature
    fn check_token(&self, token_b64: &str) -> bool {
        // Decode base64
        let Ok(decoded) = general_purpose::STANDARD.decode(token_b64) else {
            log::debug!("CSRF token base64 decode error");
            return false;
        };

        // Parse JSON
        let Ok(token_table) = serde_json::from_slice::<CsrfToken>(&decoded) else {
            log::debug!("CSRF token json decode error");
            return false;
        };

        // Get current timestamp, handle system time errors gracefully
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(e) => {
                log::error!("System time error during CSRF validation: {e}");
                return false;
            }
        };

        // Check expiration using safe arithmetic (avoid underflow)
        // Token is valid if: token_expires + ttl >= now
        // Or equivalently: now <= token_expires + ttl
        if self.config.expires > 0 {
            // Use saturating_add to prevent overflow
            let expiry_time = token_table.expires.saturating_add(self.config.expires);
            if now > expiry_time {
                log::debug!("CSRF token expired (now: {now}, expiry: {expiry_time})");
                return false;
            }
        }

        // Validate signature using constant-time comparison
        let expected_sign = self.gen_sign(&token_table.random, token_table.expires);
        if !constant_time_eq(&token_table.sign, &expected_sign) {
            log::debug!("CSRF token invalid signature");
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
        let Some(h_token) = header_token.filter(|t| !t.is_empty()) else {
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("no csrf token in headers"),
                None,
            )
            .await?;
            return Ok(true);
        };

        // 3. Read token from cookies
        let cookie_token = request::get_cookie_value(session.req_header(), &self.config.name);
        let Some(c_token) = cookie_token else {
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("no csrf cookie"),
                None,
            )
            .await?;
            return Ok(true);
        };

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
        // Generate token, handle potential errors gracefully
        let Some(csrf_token) = self.gen_token_string() else {
            log::error!("Failed to generate CSRF token");
            return Ok(());
        };

        // Set the CSRF cookie with security attributes
        // Note: HttpOnly is intentionally NOT set because JavaScript needs to read this
        // for the double-submit pattern (sending it in both cookie and header)
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
            .expect("System time should be available in tests")
            .as_secs();
        let random = "0123456789abcdef0123456789abcdef".to_string();
        let sign = plugin.gen_sign(&random, expires);
        let token = CsrfToken {
            random,
            expires,
            sign,
        };
        let json = serde_json::to_string(&token).expect("Serialization should succeed");
        let encoded = general_purpose::STANDARD.encode(json);
        assert!(plugin.check_token(&encoded));
    }

    #[test]
    fn tampered_token_is_rejected() {
        let plugin = build_plugin(7200);
        let token = plugin
            .gen_token_string()
            .expect("Token generation should succeed");
        let mut decoded = general_purpose::STANDARD
            .decode(token.as_bytes())
            .expect("Decode should succeed");
        decoded[0] ^= 0x01;
        let tampered = general_purpose::STANDARD.encode(decoded);
        assert!(!plugin.check_token(&tampered));
    }

    #[test]
    fn expired_token_is_rejected() {
        let plugin = build_plugin(1); // 1 second expiry
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time should be available")
            .as_secs()
            .saturating_sub(10); // Token created 10 seconds ago
        let random = "0123456789abcdef0123456789abcdef".to_string();
        let sign = plugin.gen_sign(&random, expires);
        let token = CsrfToken {
            random,
            expires,
            sign,
        };
        let json = serde_json::to_string(&token).expect("Serialization should succeed");
        let encoded = general_purpose::STANDARD.encode(json);
        assert!(!plugin.check_token(&encoded));
    }

    #[test]
    fn token_generation_never_panics() {
        let plugin = build_plugin(7200);
        // Should not panic even if called multiple times
        for _ in 0..100 {
            assert!(plugin.gen_token_string().is_some());
        }
    }
}
