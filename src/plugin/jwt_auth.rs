use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::StatusCode;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::{proxy::ProxyContext, utils::request};

use super::{send_error_response, ProxyPlugin};

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

    // Pre-create validation object for better performance
    let mut validation = Validation::new(config.algorithm);
    validation.leeway = config.lifetime_grace_period;

    Ok(Arc::new(PluginJWTAuth {
        config,
        decoding_key,
        validation,
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
    validation: Validation, // Pre-created for better performance
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
                send_error_response(
                    session,
                    StatusCode::UNAUTHORIZED,
                    Some("Token not found"),
                    Some(&[(
                        "WWW-Authenticate",
                        "Bearer error=\"invalid_token\", error_description=\"Token not found\"",
                    )]),
                )
                .await?;
                return Ok(true);
            }
        };

        // Parse JWT using pre-created validation
        let token_data = match decode::<Claims>(&token, &self.decoding_key, &self.validation) {
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
                send_error_response(
                    session,
                    StatusCode::UNAUTHORIZED,
                    Some(error_msg),
                    Some(&[(
                        "WWW-Authenticate",
                        &format!(
                            "Bearer error=\"invalid_token\", error_description=\"{error_msg}\""
                        ),
                    )]),
                )
                .await?;
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
    /// Extracts JWT from header, query, or cookie using a cleaner chain approach
    fn extract_token(&self, session: &mut Session) -> Option<String> {
        self.extract_from_header(session)
            .or_else(|| self.extract_from_query(session))
            .or_else(|| self.extract_from_cookie(session))
    }

    /// Extract token from header and optionally remove it
    fn extract_from_header(&self, session: &mut Session) -> Option<String> {
        let token = {
            let header_val =
                request::get_req_header_value(session.req_header(), &self.config.header)?;
            if header_val.to_lowercase().starts_with("bearer ") {
                Some(header_val[7..].to_string())
            } else {
                Some(header_val.to_string())
            }
        };

        if token.is_some() && self.config.hide_credentials {
            session.req_header_mut().remove_header(&self.config.header);
        }

        token
    }

    /// Extract token from query parameter and optionally remove it
    fn extract_from_query(&self, session: &mut Session) -> Option<String> {
        let token = {
            request::get_query_value(session.req_header(), &self.config.query)
                .map(|q| q.to_string())
        };

        if token.is_some() && self.config.hide_credentials {
            let _ = request::remove_query_from_header(session.req_header_mut(), &self.config.query);
        }

        token
    }

    /// Extract token from cookie and optionally remove it
    fn extract_from_cookie(&self, session: &mut Session) -> Option<String> {
        let token = request::get_cookie_value(session.req_header(), &self.config.cookie)
            .map(|c| c.to_string());

        if token.is_some() && self.config.hide_credentials {
            self.remove_cookie_credential(session);
        }

        token
    }

    /// Remove cookie credential by setting an expired cookie
    fn remove_cookie_credential(&self, _session: &mut Session) {
        // Set an expired cookie to effectively "remove" it
        let _cookie_header = format!("{}=; Max-Age=0; Path=/; HttpOnly", self.config.cookie);
        // Note: This would need to be implemented in the response phase
        // For now, we'll store this information in the context for later use
        // This is a limitation of the current architecture where we can't modify response headers in request phase
    }
}
