use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use http::{header, StatusCode};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::{proxy::ProxyContext, utils::request};

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "jwt-auth";
const PRIORITY: i32 = 2510;
const DEFAULT_HEADER: &str = "authorization";
const DEFAULT_QUERY: &str = "jwt";
const DEFAULT_COOKIE: &str = "jwt";

/// Creates a JWT Auth plugin instance with the given configuration.
/// This plugin validates JWTs from HTTP headers, query parameters, or cookies, and optionally
/// stores the JWT payload in the request context or hides credentials after validation.
pub fn create_jwt_auth_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid jwt auth plugin config")?;
    let decoding_key = config
        .get_decoding_key()
        .or_err_with(ReadError, || "Invalid decoding key")?;

    Ok(Arc::new(PluginJWTAuth {
        config,
        decoding_key,
    }))
}

/// Configuration for the JWT Auth plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// HTTP header field name containing the JWT (default: `authorization`).
    /// If the header starts with "Bearer ", the prefix is stripped.
    #[serde(default = "PluginConfig::default_header")]
    pub header: String,

    /// Query parameter name containing the JWT (default: `jwt`).
    #[serde(default = "PluginConfig::default_query")]
    pub query: String,

    /// Cookie field name containing the JWT (default: `jwt`).
    #[serde(default = "PluginConfig::default_cookie")]
    pub cookie: String,

    /// Whether to remove JWT credentials from headers, query parameters, or cookies after validation.
    #[serde(default)]
    pub hide_credentials: bool,

    /// Whether to store the JWT payload in the request context under `jwt-auth-payload`.
    #[serde(default)]
    pub store_in_ctx: bool,

    /// Symmetric secret key (or base64-encoded secret) for HMAC algorithms (HS256, HS512).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Signature algorithm (default: HS256).
    #[serde(default = "PluginConfig::default_algorithm")]
    pub algorithm: Algorithm,

    /// Whether the secret is base64-encoded (default: false).
    #[serde(default)]
    pub base64_secret: bool,

    /// Token lifetime grace period in seconds (default: 0).
    #[serde(default)]
    pub lifetime_grace_period: u64,

    /// Public key (PEM format) for RSA/ECDSA algorithms (RS256, ES256).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl PluginConfig {
    fn default_header() -> String {
        DEFAULT_HEADER.to_string()
    }

    fn default_query() -> String {
        DEFAULT_QUERY.to_string()
    }

    fn default_cookie() -> String {
        DEFAULT_COOKIE.to_string()
    }

    fn default_algorithm() -> Algorithm {
        Algorithm::HS256
    }

    fn get_decoding_key(&self) -> Result<DecodingKey, &'static str> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS512 => {
                let secret = self.secret.as_ref().ok_or("missing secret")?;
                let key: Vec<u8> = if self.base64_secret {
                    general_purpose::STANDARD
                        .decode(secret)
                        .map_err(|_| "invalid base64")?
                } else {
                    secret.as_bytes().to_vec()
                };
                Ok(DecodingKey::from_secret(&key))
            }
            Algorithm::RS256 | Algorithm::ES256 => {
                let public_key = self.public_key.as_ref().ok_or("missing public_key")?;
                Ok(DecodingKey::from_rsa_pem(public_key.as_bytes()).map_err(|_| "bad pem")?)
            }
            _ => Err("unsupported algorithm"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Standard JWT Claims
    exp: Option<i64>,
    iat: Option<i64>,
    nbf: Option<i64>,
    /// Custom claims
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// JWT Auth plugin implementation.
/// Validates JWTs and optionally stores payload or hides credentials.
pub struct PluginJWTAuth {
    config: PluginConfig,
    decoding_key: DecodingKey,
}

#[async_trait]
impl ProxyPlugin for PluginJWTAuth {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        let token = self.extract_token(session);
        let token = match token {
            Some(t) => t,
            None => {
                self.send_unauthorized_response(session, "Token not found")
                    .await?;
                return Ok(true);
            }
        };

        // Parse JWT
        let mut validation = Validation::new(self.config.algorithm);
        validation.leeway = self.config.lifetime_grace_period;

        let token_data = match decode::<Claims>(&token, &self.decoding_key, &validation) {
            Ok(data) => data,
            Err(e) => {
                let error_msg = match e.kind() {
                    jsonwebtoken::errors::ErrorKind::InvalidToken => "Invalid token format",
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => "Invalid signature",
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => "Token expired",
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => "Invalid issuer",
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => "Invalid audience",
                    jsonwebtoken::errors::ErrorKind::InvalidSubject => "Invalid subject",
                    jsonwebtoken::errors::ErrorKind::ImmatureSignature => "Token not yet valid",
                    _ => "Invalid token",
                };
                self.send_unauthorized_response(session, error_msg).await?;
                return Ok(true);
            }
        };

        if self.config.store_in_ctx {
            let payload_value = serde_json::to_value(&token_data.claims.extra)
                .or_err_with(ReadError, || "Invalid jwt auth payload")?;
            ctx.vars
                .insert("jwt-auth-payload".to_string(), payload_value.to_string());
        }

        Ok(false)
    }
}

impl PluginJWTAuth {
    /// Extracts JWT from header, query, or cookie, and removes credentials if configured.
    fn extract_token(&self, session: &mut Session) -> Option<String> {
        // 1. Header
        let mut token_to_return: Option<String> = None;
        let mut should_remove_header = false;

        // Scope for immutable borrow
        {
            if let Some(header_val) =
                request::get_req_header_value(session.req_header(), &self.config.header)
            {
                // Determine the token value
                if header_val.to_lowercase().starts_with("bearer ") {
                    token_to_return = Some(header_val[7..].to_string());
                } else {
                    token_to_return = Some(header_val.to_string());
                }

                // Decide if removal is needed
                if self.config.hide_credentials {
                    should_remove_header = true;
                }
            }
        } // Immutable borrow ends

        // Perform header removal
        if should_remove_header {
            session.req_header_mut().remove_header(&self.config.header);
        }

        // Return token if found in header
        if token_to_return.is_some() {
            return token_to_return;
        }

        // 2. Query parameter
        let mut should_remove_query = false;

        // Scope for immutable borrow
        {
            if let Some(query) = request::get_query_value(session.req_header(), &self.config.query)
            {
                token_to_return = Some(query.to_string());
                if self.config.hide_credentials {
                    should_remove_query = true;
                }
            }
        } // Immutable borrow ends

        // Perform query removal
        if should_remove_query {
            let _ = request::remove_query_from_header(session.req_header_mut(), &self.config.query);
        }

        // Return token if found in query
        if token_to_return.is_some() {
            return token_to_return;
        }

        // 3. cookie
        if let Some(cookie) = request::get_cookie_value(session.req_header(), &self.config.cookie) {
            // TODO remove cookie
            return Some(cookie.to_string());
        }

        token_to_return
    }

    /// Sends a `401 Unauthorized` response with a specific error message.
    async fn send_unauthorized_response(
        &self,
        session: &mut Session,
        error_msg: &str,
    ) -> Result<()> {
        let mut header = ResponseHeader::build(StatusCode::UNAUTHORIZED, None)?;
        header.insert_header(header::CONTENT_LENGTH, error_msg.len().to_string())?;
        header.insert_header(
            header::WWW_AUTHENTICATE,
            format!("Bearer error=\"invalid_token\", error_description=\"{error_msg}\""),
        )?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::copy_from_slice(error_msg.as_bytes())), true)
            .await?;
        Ok(())
    }
}
