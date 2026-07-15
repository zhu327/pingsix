use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::StatusCode;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::{request, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "jwt-auth";
const PRIORITY: i32 = 2510;

/// Key for storing JWT authentication payload in the proxy context
const JWT_AUTH_PAYLOAD_KEY: &str = "jwt-auth-payload";
/// Default authorization header name
const DEFAULT_AUTH_HEADER: &str = "authorization";
/// Default cookie name for JWT token
const DEFAULT_JWT_COOKIE: &str = "jwt";

/// Creates a JWT Auth plugin instance with the given configuration.
/// This plugin validates JWTs from HTTP headers, query parameters, or cookies, and optionally
/// stores the JWT payload in the request context or hides credentials after validation.
pub fn create_jwt_auth_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let decoding_key = config.get_decoding_key().map_err(|e| {
        ProxyError::Configuration(format!("Failed to create JWT decoding key: {e}"))
    })?;

    // Pre-create validation object for better performance
    let validation = build_validation(&config);

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

    /// Query parameter name containing the JWT (default: `""`, which disables query extraction).
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

    /// Expected issuer (`iss`) claim. When set, tokens must carry a matching `iss`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Expected audience (`aud`) claim. When set, tokens must carry a matching `aud`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Registered claims that must be present (e.g. `sub`, `iss`, `aud`, `exp`, `nbf`).
    /// Only the registered claim names listed by `jsonwebtoken` are enforced.
    #[serde(default)]
    pub required_claims: Vec<String>,
}

impl PluginConfig {
    fn default_header() -> String {
        DEFAULT_AUTH_HEADER.to_string()
    }

    fn default_query() -> String {
        String::new()
    }

    fn default_cookie() -> String {
        DEFAULT_JWT_COOKIE.to_string()
    }

    fn default_algorithm() -> Algorithm {
        Algorithm::HS256
    }

    fn get_decoding_key(&self) -> Result<DecodingKey, String> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS512 => {
                let secret = self
                    .secret
                    .as_ref()
                    .ok_or("Secret is required for HMAC algorithms (HS256, HS512)")?;
                let key: Vec<u8> = if self.base64_secret {
                    general_purpose::STANDARD
                        .decode(secret)
                        .map_err(|e| format!("Failed to decode base64 secret: {e}"))?
                } else {
                    secret.as_bytes().to_vec()
                };
                Ok(DecodingKey::from_secret(&key))
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                let public_key = self
                    .public_key
                    .as_ref()
                    .ok_or("Public key is required for RSA algorithms (RS256, RS384, RS512)")?;
                DecodingKey::from_rsa_pem(public_key.as_bytes())
                    .map_err(|e| format!("Failed to parse RSA public key: {e}"))
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                let public_key = self
                    .public_key
                    .as_ref()
                    .ok_or("Public key is required for ECDSA algorithms (ES256, ES384)")?;
                DecodingKey::from_ec_pem(public_key.as_bytes())
                    .map_err(|e| format!("Failed to parse ECDSA public key: {e}"))
            }
            _ => Err(format!("Unsupported algorithm: {:?}", self.algorithm)),
        }
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse JWT auth plugin config", e)
        })
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

/// Build the `jsonwebtoken` [`Validation`] from the plugin config.
///
/// Extracted as a free function so the issuer/audience/required-claim logic can be unit tested
/// without constructing a full proxy [`Session`].
fn build_validation(config: &PluginConfig) -> Validation {
    let mut validation = Validation::new(config.algorithm);
    validation.leeway = config.lifetime_grace_period;
    if let Some(iss) = &config.iss {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = &config.aud {
        validation.set_audience(&[aud]);
    }
    // `set_required_spec_claims` replaces the whole set, so insert user-required claims into
    // the default set (which already contains "exp") to preserve the default behavior.
    for claim in &config.required_claims {
        validation.required_spec_claims.insert(claim.clone());
    }
    validation
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
        let token = self.extract_token(session, ctx)?;
        if token.is_some() {
            ctx.mark_request_has_credentials();
        }
        let token = match token {
            Some(t) => t,
            None => {
                ResponseBuilder::send_proxy_error(
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
                ResponseBuilder::send_proxy_error(
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
            // Store structured payload directly for downstream plugins to use without re-parsing
            ctx.set(JWT_AUTH_PAYLOAD_KEY, token_data.claims.extra.clone());
        }

        Ok(false)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Handle cookie clearing if needed
        if let Some(cookie_name) = ctx.get_str("jwt_auth_clear_cookie") {
            let clear_cookie_header = format!("{cookie_name}=; Max-Age=0; Path=/; HttpOnly");
            upstream_response.append_header("Set-Cookie", clear_cookie_header)?;
        }
        Ok(())
    }
}

impl PluginJWTAuth {
    /// Extracts JWT from header, query, or cookie using a cleaner chain approach
    fn extract_token(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<Option<String>> {
        if let Some(token) = self.extract_from_header(session)? {
            return Ok(Some(token));
        }
        if let Some(token) = self.extract_from_query(session)? {
            return Ok(Some(token));
        }
        self.extract_from_cookie(session, ctx)
    }

    /// Extract token from header and optionally remove it
    fn extract_from_header(&self, session: &mut Session) -> Result<Option<String>> {
        let token = request::get_req_header_value(session.req_header(), &self.config.header).map(
            |header_val| {
                if header_val.len() >= 7 && header_val[..7].eq_ignore_ascii_case("bearer ") {
                    header_val[7..].to_string()
                } else {
                    header_val.to_string()
                }
            },
        );
        if token.is_some() && self.config.hide_credentials {
            session.req_header_mut().remove_header(&self.config.header);
        }
        Ok(token)
    }

    /// Extract token from query parameter and optionally remove it
    fn extract_from_query(&self, session: &mut Session) -> Result<Option<String>> {
        let token = self.extract_token_from_query(session.req_header());
        if token.is_some() && self.config.hide_credentials {
            request::remove_query_from_header(session.req_header_mut(), &self.config.query)
                .map_err(|e| {
                    ProxyError::validation_error(format!(
                        "Failed to hide JWT query credential: {e}"
                    ))
                })?;
        }
        Ok(token)
    }

    /// Pure query-extraction helper operating on a [`RequestHeader`] directly, so it can be
    /// unit tested without a [`Session`].
    ///
    /// Returns `None` when query extraction is disabled (empty `config.query`).
    fn extract_token_from_query(&self, req_header: &RequestHeader) -> Option<String> {
        // An empty `query` config disables query-based token extraction.
        if self.config.query.is_empty() {
            return None;
        }
        request::get_query_value(req_header, &self.config.query).map(|q| q.to_string())
    }

    /// Extract token from cookie and optionally remove it
    fn extract_from_cookie(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<Option<String>> {
        let token = request::get_cookie_value(session.req_header(), &self.config.cookie)
            .map(str::to_string);
        if token.is_some() && self.config.hide_credentials {
            request::remove_cookie_from_header(session.req_header_mut(), &self.config.cookie)
                .map_err(|e| {
                    ProxyError::validation_error(format!(
                        "Failed to hide JWT cookie credential: {e}"
                    ))
                })?;
            // Best-effort response-side deletion uses Path=/ because request Cookie
            // fields do not expose the original cookie attributes.
            ctx.set("jwt_auth_clear_cookie", self.config.cookie.clone());
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    const TEST_SECRET: &str = "test-secret";

    #[derive(Serialize)]
    struct TestClaims {
        exp: Option<u64>,
        iss: Option<String>,
        aud: Option<String>,
        sub: Option<String>,
    }

    fn base_config() -> PluginConfig {
        PluginConfig {
            header: PluginConfig::default_header(),
            query: PluginConfig::default_query(),
            cookie: PluginConfig::default_cookie(),
            hide_credentials: false,
            store_in_ctx: false,
            secret: Some(TEST_SECRET.to_string()),
            algorithm: Algorithm::HS256,
            base64_secret: false,
            lifetime_grace_period: 0,
            public_key: None,
            iss: None,
            aud: None,
            required_claims: vec![],
        }
    }

    fn decoding_key() -> DecodingKey {
        DecodingKey::from_secret(TEST_SECRET.as_bytes())
    }

    fn encoding_key() -> EncodingKey {
        EncodingKey::from_secret(TEST_SECRET.as_bytes())
    }

    fn make_token(claims: TestClaims) -> String {
        encode(&Header::new(Algorithm::HS256), &claims, &encoding_key()).unwrap()
    }

    fn far_future_exp() -> Option<u64> {
        Some(9_999_999_999)
    }

    #[test]
    fn default_query_is_empty_disabling_extraction() {
        // The default `query` config is now an empty string, which disables query extraction.
        let cfg = base_config();
        assert!(cfg.query.is_empty());
    }

    #[test]
    fn valid_token_with_matching_iss_aud_passes() {
        let mut cfg = base_config();
        cfg.iss = Some("issuer-a".to_string());
        cfg.aud = Some("audience-a".to_string());

        let validation = build_validation(&cfg);
        let token = make_token(TestClaims {
            exp: far_future_exp(),
            iss: Some("issuer-a".to_string()),
            aud: Some("audience-a".to_string()),
            sub: None,
        });

        let result = decode::<Claims>(&token, &decoding_key(), &validation);
        assert!(
            result.is_ok(),
            "token with matching iss/aud should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn token_with_wrong_iss_rejected() {
        let mut cfg = base_config();
        cfg.iss = Some("expected-issuer".to_string());

        let validation = build_validation(&cfg);
        let token = make_token(TestClaims {
            exp: far_future_exp(),
            iss: Some("wrong-issuer".to_string()),
            aud: None,
            sub: None,
        });

        let err = decode::<Claims>(&token, &decoding_key(), &validation).unwrap_err();
        assert!(
            matches!(err.kind(), jsonwebtoken::errors::ErrorKind::InvalidIssuer),
            "expected InvalidIssuer, got {:?}",
            err.kind()
        );
    }

    #[test]
    fn token_missing_required_claim_rejected() {
        let mut cfg = base_config();
        cfg.required_claims = vec!["sub".to_string()];

        let validation = build_validation(&cfg);
        // Token carries exp (so the default exp requirement is satisfied) but no `sub`.
        let token = make_token(TestClaims {
            exp: far_future_exp(),
            iss: None,
            aud: None,
            sub: None,
        });

        let err = decode::<Claims>(&token, &decoding_key(), &validation).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim) if claim == "sub"
            ),
            "expected MissingRequiredClaim(\"sub\"), got {:?}",
            err.kind()
        );
    }

    #[test]
    fn query_extraction_disabled_by_default() {
        // Default config has query="", so extraction must return None even when the request
        // carries a `jwt=` query parameter.
        let plugin = PluginJWTAuth {
            config: base_config(),
            decoding_key: decoding_key(),
            validation: Validation::new(Algorithm::HS256),
        };

        let req = RequestHeader::build("GET", b"/protected?jwt=sometoken", None).unwrap();
        assert!(plugin.extract_token_from_query(&req).is_none());
    }

    #[test]
    fn query_extraction_enabled_when_configured() {
        let mut cfg = base_config();
        cfg.query = "jwt".to_string();

        let plugin = PluginJWTAuth {
            config: cfg,
            decoding_key: decoding_key(),
            validation: Validation::new(Algorithm::HS256),
        };

        let req = RequestHeader::build("GET", b"/protected?jwt=sometoken", None).unwrap();
        assert_eq!(
            plugin.extract_token_from_query(&req).as_deref(),
            Some("sometoken")
        );
    }
}
