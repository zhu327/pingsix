use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::StatusCode;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use pingsix_macros::EncryptFields;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, Rejection},
    plugins::config::{parse_and_validate_plugin_config, validate_apisix_realm},
    utils::{request, response::content_type},
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
pub fn create_jwt_auth_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
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

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators (including the decoding-key derivation) WITHOUT constructing
/// the plugin.
pub fn validate_jwt_auth_config(cfg: &JsonValue) -> ProxyResult<()> {
    let config = PluginConfig::try_from(cfg.clone())?;
    config.get_decoding_key().map_err(|e| {
        ProxyError::Configuration(format!("Failed to create JWT decoding key: {e}"))
    })?;
    Ok(())
}

/// Configuration for the JWT Auth plugin.
#[derive(Debug, Clone, Serialize, Deserialize, EncryptFields, Validate)]
#[encrypt_fields(export)]
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

    /// Realm advertised in the `WWW-Authenticate` challenge. APISIX's default
    /// would be `jwt`, but pingsix keeps its legacy structured
    /// `Bearer error=...` challenge unless a realm is configured explicitly.
    #[serde(default)]
    pub realm: Option<String>,

    /// APISIX `claims_to_verify`: when `Some` and non-empty, the listed claims
    /// (`exp` or `nbf`, unique) are verified in addition to the `jsonwebtoken`
    /// defaults. `exp` is validated by default anyway; listing `nbf` makes the
    /// not-before value itself checked (a token whose `nbf` is in the future
    /// is rejected). When `None` or empty, only the `jsonwebtoken` defaults
    /// apply (`exp` required and validated; `nbf` neither required nor
    /// validated).
    #[serde(default)]
    #[validate(custom(function = "PluginConfig::validate_claims_to_verify"))]
    pub claims_to_verify: Option<Vec<String>>,

    /// Symmetric secret key (or base64-encoded secret) for HMAC algorithms
    /// (HS256, HS384, HS512).
    #[encrypt]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Signature algorithm (default: HS256).
    /// APISIX also lists ES512, but jsonwebtoken 9.3.1 has no ES512 variant (its
    /// ECDSA support covers P-256/P-384 only). Configuring `ES512` therefore fails
    /// deserialization instead of silently falling back to a different algorithm.
    #[serde(default = "PluginConfig::default_algorithm")]
    pub algorithm: Algorithm,

    /// Whether the secret is base64-encoded (default: false).
    #[serde(default)]
    pub base64_secret: bool,

    /// Token lifetime grace period in seconds (default: 0).
    #[serde(default)]
    pub lifetime_grace_period: u64,

    /// Public key (PEM format) for RSA (`RS*`/`PS*`), ECDSA (`ES256`/`ES384`),
    /// and EdDSA algorithms.
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
    // APISIX's consumer-side `exp` field (token lifetime in seconds, default 86400)
    // is intentionally not ported: pingsix has no consumer object to attach it to.
    // Token lifetime is configured at signing time and enforced via `exp` validation
    // plus `lifetime_grace_period`.
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

    fn validate_claims_to_verify(claims: &&Vec<String>) -> Result<(), ValidationError> {
        for (index, claim) in claims.iter().enumerate() {
            if claim != "exp" && claim != "nbf" {
                return Err(ValidationError::new(
                    "claims_to_verify entries must be \"exp\" or \"nbf\"",
                ));
            }
            if claims[..index].contains(claim) {
                return Err(ValidationError::new(
                    "claims_to_verify entries must be unique",
                ));
            }
        }
        Ok(())
    }

    fn get_decoding_key(&self) -> Result<DecodingKey, String> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let secret = self
                    .secret
                    .as_ref()
                    .ok_or("Secret is required for HMAC algorithms (HS256, HS384, HS512)")?;
                let key: Vec<u8> = if self.base64_secret {
                    general_purpose::STANDARD
                        .decode(secret)
                        .map_err(|e| format!("Failed to decode base64 secret: {e}"))?
                } else {
                    secret.as_bytes().to_vec()
                };
                if key.is_empty() {
                    return Err("Secret must not be empty for HMAC algorithms".to_string());
                }
                Ok(DecodingKey::from_secret(&key))
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                let public_key = self.public_key.as_ref().ok_or(
                    "Public key is required for RSA algorithms (RS256, RS384, RS512, PS256, PS384, PS512)",
                )?;
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
            Algorithm::EdDSA => {
                let public_key = self
                    .public_key
                    .as_ref()
                    .ok_or("Public key is required for EdDSA")?;
                DecodingKey::from_ed_pem(public_key.as_bytes())
                    .map_err(|e| format!("Failed to parse EdDSA public key: {e}"))
            }
        }
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Failed to parse JWT auth plugin config")?;
        if let Some(realm) = config.realm.as_deref() {
            validate_apisix_realm(realm).map_err(ProxyError::from)?;
        }
        Ok(config)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Standard JWT Claims. `iat` is parsed here (and therefore excluded from
    /// the custom `extra` map) so the stored payload shape stays stable.
    exp: Option<i64>,
    iat: Option<i64>,
    nbf: Option<i64>,
    /// Custom claims
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// Build the `Bearer realm="<realm>"` challenge header value.
fn build_realm_challenge(realm: &str) -> String {
    format!("Bearer realm=\"{realm}\"")
}

/// Build the legacy pingsix structured Bearer challenge.
fn build_legacy_challenge(error_msg: &str) -> String {
    format!("Bearer error=\"invalid_token\", error_description=\"{error_msg}\"")
}

impl PluginConfig {
    fn challenge_for(&self, error_msg: &str) -> String {
        match self.realm.as_deref() {
            Some(realm) => build_realm_challenge(realm),
            None => build_legacy_challenge(error_msg),
        }
    }
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
    // APISIX `claims_to_verify`: `Some` non-empty makes those claims required as
    // well; listing `nbf` also turns on value verification (jsonwebtoken only
    // checks the not-before time when `validate_nbf` is set — a required-but-
    // unchecked `nbf` would accept future-dated tokens). `None` or empty keeps
    // the jsonwebtoken defaults untouched.
    if let Some(claims) = &config.claims_to_verify {
        for claim in claims {
            validation.required_spec_claims.insert(claim.clone());
            if claim == "nbf" {
                validation.validate_nbf = true;
            }
        }
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
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        let token = self.extract_token(session, ctx)?;
        if token.is_some() {
            ctx.mark_request_has_credentials();
        }
        let token = match token {
            Some(t) => t,
            None => {
                return Ok(FilterVerdict::Reject(
                    Rejection::new(StatusCode::UNAUTHORIZED)
                        .with_body("Token not found")
                        .with_content_type(content_type::TEXT_PLAIN)
                        .with_header(
                            "WWW-Authenticate",
                            self.config.challenge_for("Token not found"),
                        ),
                ));
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
                return Ok(FilterVerdict::Reject(
                    Rejection::new(StatusCode::UNAUTHORIZED)
                        .with_body(error_msg)
                        .with_content_type(content_type::TEXT_PLAIN)
                        .with_header("WWW-Authenticate", self.config.challenge_for(error_msg)),
                ));
            }
        };

        if self.config.store_in_ctx {
            // Store structured payload directly for downstream plugins to use without re-parsing
            ctx.set(JWT_AUTH_PAYLOAD_KEY, token_data.claims.extra.clone());
        }

        // Record the verified credential for shared-cache consumer
        // isolation before it can be stripped from the upstream request
        // (extraction may already have removed the header/query carrier).
        ctx.note_request_credential(&token);

        Ok(FilterVerdict::Continue)
    }
}

impl PluginJWTAuth {
    /// Extracts JWT from header, query, or cookie using a cleaner chain approach
    fn extract_token(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<Option<String>> {
        if let Some(token) = self.extract_from_header(session)? {
            return Ok(Some(token));
        }
        if let Some(token) = self.extract_from_query(session)? {
            return Ok(Some(token));
        }
        self.extract_from_cookie(session)
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

    /// Extract token from cookie and optionally remove it from the forwarded
    /// request `Cookie` header without clearing the client's browser cookie.
    fn extract_from_cookie(&self, session: &mut Session) -> Result<Option<String>> {
        let token = request::get_cookie_value(session.req_header(), &self.config.cookie)
            .map(str::to_string);
        if token.is_some() && self.config.hide_credentials {
            request::remove_cookie_from_header(session.req_header_mut(), &self.config.cookie)
                .map_err(|e| {
                    ProxyError::validation_error(format!(
                        "Failed to hide JWT cookie credential: {e}"
                    ))
                })?;
        }
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encryption::KeyringService;
    use crate::utils::encryption::{EncryptFields, SecretOp, CIPHERTEXT_PREFIX};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    const TEST_SECRET: &str = "test-secret";

    const RSA_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n\
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n\
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n\
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n\
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n\
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n\
MwIDAQAB\n-----END PUBLIC KEY-----";

    const ED25519_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEA2+Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8=\n-----END PUBLIC KEY-----";

    /// Test-only RSA-2048 key pair for full sign/decode roundtrips.
    const RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDJENiTcOIbMzyn\n\
CNV8++r0zS2TPQASJNflZgwH9tYrCvVAZHczccxaEhzN6zzNvg8HJw1E43ayEMo+\n\
Ynbqkl/lOic52GKEsCp9sIAJ1IqfEkXT8LUpiOcJOgeyYhp7Wn8MUvg7EpoefuRB\n\
p0dfY4yygsrFfafBiG1fLNriuxFlKpkk+2wHGuH+DACmrG16j97k8dDzI34wX2az\n\
XksfN6C1Dp4CeqsTv15cvMKRHWWtM20ydmufkWoWomJynFFCGMzSTPzpekSPLHcR\n\
W5OTAWSYuSeWUH2aAYAw2P+hqzF6usYD7Ia9q70SeaoJ5nVPIQq4lbQwMB7njeao\n\
+YAr9moHAgMBAAECggEAFXHTBOgMGDuUPfp5Y/MDFxNPx5LretlBdOmNN0eShb+4\n\
SE25evFUYCJAvo5W4K4N20Tv1jJD0Bpt/6Ov1t/qvhTq5xwBkfEExH1lLTyP1lx0\n\
DyFD/oc9S6TL+ltv7fUedM7f7n5S6sASPJWzTToIYRJbFHTiRggfe4BaDhxGmYP2\n\
PhN/Fm7Z4ST5nVsxSoUl9qMgjlT7+2AhH2wIyp0btK4zs7VqE00wtwvTTgszbpYp\n\
aSOsCJRl0loeYMumV9D4gbsZ8IFyO5qWyxvkGCiU4dQet5fNgS1EaZmcxEGwuEWL\n\
PB7ib7ybNL7nZW7xI0BE5WISb5LF4mebtkNUduQskQKBgQDzK9iZsote/2TbJ5z8\n\
JVjDHQxLH0oezwekrPLGkWym0JvseriaAotCey3s78uydGu9sJ576MnvW3/E33ra\n\
Ai6ANdZjgk/84Qg7oSWB46wUAX6Z97Kup3w3mCi+VOrUkeDVZr1sHcD071v0Dhhx\n\
C4tbF54bFm7q4fx8+5mKpAd9NwKBgQDTrFgAKyowwRq+Gue3yOV3fAstkd5OLxup\n\
v0bqdmr3F5wh5231xJGqeGtc5uGcf3ZMtqWmin2IJQ/ZZFkNAk0WpL4aQbbtmaNl\n\
iYSm52xsZ4G7Qh7HRnXeEP5NCWTrEDaQNkOyeNZK2xoXkEySB+Vmdyxt+dQlUpoh\n\
nF4FmeFhsQKBgGtFyWysLf1/bw+a3w8ArrKMKvMs33bN39JOlV7xolvIpTBiRvNx\n\
8dsnGfBvLI4R+8GXm6KP5B1aYPgJmll4IuleVrBZOU4WO5qKkVBGjo/YxO/JLKMN\n\
saeY0Uh9j4asv+GETEXYrlmfChKU8UVVUWmi9pV+hPnLLaY5G9fkWoVrAoGAEi/p\n\
s8IBswS0hocLR9hEFxsaXsT8w9z6VIBx2G1qTWbC7IrVANvt5CbKmsXftrGg+YBs\n\
BT47APqmPPiJSjvbYcmv59OjoxCjYHMLacfSohHWrL9Go7qjH/x3zSi0ehn/hi6T\n\
bH9DclUXDdVBLv7sr/wnXh+sIbTSN3cXAQYyvlECgYBaZdLIRlHzxPgQt/uUfp8A\n\
8/tuTRzz6uTusan4Rnz9p3I/XvqYExjb8DfOas/1fs7qdYmNIkg9V6c5edHX7Aac\n\
MUEgMpNUGz2to7To0ABtBEcTOHKqin+F45enFU2I5KRopPKuPdYXo90+zWdhEzMk\n\
4tSz24EgGo+OPhXGhLU4UQ==\n-----END PRIVATE KEY-----";

    const RSA_TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRDYk3DiGzM8pwjVfPvq\n\
9M0tkz0AEiTX5WYMB/bWKwr1QGR3M3HMWhIczes8zb4PBycNRON2shDKPmJ26pJf\n\
5TonOdhihLAqfbCACdSKnxJF0/C1KYjnCToHsmIae1p/DFL4OxKaHn7kQadHX2OM\n\
soLKxX2nwYhtXyza4rsRZSqZJPtsBxrh/gwApqxteo/e5PHQ8yN+MF9ms15LHzeg\n\
tQ6eAnqrE79eXLzCkR1lrTNtMnZrn5FqFqJicpxRQhjM0kz86XpEjyx3EVuTkwFk\n\
mLknllB9mgGAMNj/oasxerrGA+yGvau9EnmqCeZ1TyEKuJW0MDAe543mqPmAK/Zq\n\
BwIDAQAB\n-----END PUBLIC KEY-----";

    /// Test-only Ed25519 key pair for full sign/decode roundtrips.
    const ED25519_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIOyqxHrY28gWbRq/rETjG6h2B+VfXFucmGuGkUo3iSYf\n\
-----END PRIVATE KEY-----";

    const ED25519_TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAV5mabaUY4PG3Q9hEDDzWBvPdl0bMu+Q16CzssxT1VBA=\n-----END PUBLIC KEY-----";

    #[derive(Serialize, Clone)]
    struct TestClaims {
        exp: Option<u64>,
        iss: Option<String>,
        aud: Option<String>,
        sub: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nbf: Option<u64>,
    }

    fn base_config() -> PluginConfig {
        PluginConfig {
            header: PluginConfig::default_header(),
            query: PluginConfig::default_query(),
            cookie: PluginConfig::default_cookie(),
            hide_credentials: false,
            store_in_ctx: false,
            realm: None,
            claims_to_verify: None,
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

    fn make_token_with(algorithm: Algorithm, claims: &TestClaims, key: &EncodingKey) -> String {
        encode(&Header::new(algorithm), claims, key).unwrap()
    }

    fn rsa_encoding_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes()).unwrap()
    }

    fn ed25519_encoding_key() -> EncodingKey {
        EncodingKey::from_ed_pem(ED25519_PRIVATE_KEY_PEM.as_bytes()).unwrap()
    }

    fn plain_claims() -> TestClaims {
        TestClaims {
            exp: far_future_exp(),
            iss: None,
            aud: None,
            sub: None,
            nbf: None,
        }
    }

    fn far_future_exp() -> Option<u64> {
        Some(9_999_999_999)
    }

    #[test]
    fn transform_secrets_touches_secret_not_public_key() {
        let mut cfg = serde_json::json!({
            "secret": "hmac-secret",
            "public_key": "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----",
            "header": "authorization",
        });
        // Encryption disabled → plaintext pass-through.
        PluginConfig::transform_secrets(&mut cfg, SecretOp::Decrypt, &KeyringService::disabled())
            .unwrap();
        assert_eq!(cfg["secret"], "hmac-secret");
        assert_eq!(
            cfg["public_key"],
            "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----"
        );
        assert_eq!(cfg["header"], "authorization");
    }

    #[test]
    fn transform_secrets_visits_secret_field() {
        let mut cfg = serde_json::json!({
            "secret": format!("{CIPHERTEXT_PREFIX}deadbeef"),
            "public_key": "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----",
        });
        let err = PluginConfig::transform_secrets(
            &mut cfg,
            SecretOp::Decrypt,
            &KeyringService::disabled(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("data_encryption is disabled")
                || err.to_string().contains("Encrypted value"),
            "{err}"
        );
        // public_key must remain untouched even when secret decrypt fails.
        assert_eq!(
            cfg["public_key"],
            "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----"
        );
    }

    #[test]
    fn secrets_transform_const_matches_trait_method() {
        let mut via_const = serde_json::json!({ "secret": "s" });
        let mut via_trait = via_const.clone();
        (SECRETS_TRANSFORM)(
            &mut via_const,
            SecretOp::Decrypt,
            &KeyringService::disabled(),
        )
        .unwrap();
        PluginConfig::transform_secrets(
            &mut via_trait,
            SecretOp::Decrypt,
            &KeyringService::disabled(),
        )
        .unwrap();
        assert_eq!(via_const, via_trait);
    }

    #[test]
    fn default_query_is_empty_disabling_extraction() {
        // The default `query` config is now an empty string, which disables query extraction.
        let cfg = base_config();
        assert!(cfg.query.is_empty());
    }

    #[test]
    fn realm_is_optional_and_defaults_to_legacy_challenge() {
        let config = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(config.realm, None);
        assert_eq!(
            config.challenge_for("Token not found"),
            "Bearer error=\"invalid_token\", error_description=\"Token not found\""
        );
    }

    #[test]
    fn custom_realm_is_used_in_challenge() {
        let config = PluginConfig::try_from(serde_json::json!({ "realm": "tenant-a" })).unwrap();
        assert_eq!(config.realm.as_deref(), Some("tenant-a"));
        assert_eq!(
            config.challenge_for("Token not found"),
            "Bearer realm=\"tenant-a\""
        );
    }

    #[test]
    fn invalid_realms_are_rejected() {
        for invalid in ["", "a\"b", "a\\b", "caf\u{e9}"] {
            let err = PluginConfig::try_from(serde_json::json!({ "realm": invalid }))
                .expect_err("invalid realm must be rejected");
            assert!(err.to_string().contains("realm"), "{err}");
        }

        let long_realm = "a".repeat(129);
        let err = PluginConfig::try_from(serde_json::json!({ "realm": long_realm }))
            .expect_err("overlong realm must be rejected");
        assert!(err.to_string().contains("realm"), "{err}");
    }

    #[test]
    fn key_claim_name_is_ignored() {
        // pingsix validates against a single static key; the APISIX consumer
        // claim name is a tolerated unknown field.
        let config =
            PluginConfig::try_from(serde_json::json!({ "key_claim_name": "kid" })).unwrap();
        assert_eq!(config.secret.as_deref(), None);
    }

    #[test]
    fn claims_to_verify_defaults_to_none() {
        let config = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(config.claims_to_verify, None);
    }

    #[test]
    fn claims_to_verify_accepts_exp_and_nbf() {
        let config = PluginConfig::try_from(serde_json::json!({
            "claims_to_verify": ["exp", "nbf"],
        }))
        .unwrap();
        assert_eq!(
            config.claims_to_verify,
            Some(vec!["exp".to_string(), "nbf".to_string()])
        );
    }

    #[test]
    fn claims_to_verify_rejects_unknown_or_duplicate_claims() {
        for invalid in [
            serde_json::json!(["sub"]),
            serde_json::json!(["exp", "exp"]),
            serde_json::json!(["nbf", "exp", "nbf"]),
        ] {
            let err = PluginConfig::try_from(serde_json::json!({
                "claims_to_verify": invalid,
            }))
            .expect_err("invalid claims_to_verify must be rejected");
            assert!(err.to_string().contains("claims_to_verify"), "{err}");
        }
    }

    #[test]
    fn claims_to_verify_makes_nbf_required() {
        let mut cfg = base_config();
        cfg.claims_to_verify = Some(vec!["nbf".to_string()]);
        let validation = build_validation(&cfg);

        let missing = make_token(TestClaims {
            exp: far_future_exp(),
            iss: None,
            aud: None,
            sub: None,
            nbf: None,
        });
        let err = decode::<Claims>(&missing, &decoding_key(), &validation).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim) if claim == "nbf"
            ),
            "expected MissingRequiredClaim(\"nbf\"), got {:?}",
            err.kind()
        );

        let present = make_token(TestClaims {
            exp: far_future_exp(),
            iss: None,
            aud: None,
            sub: None,
            nbf: Some(1_000_000_000),
        });
        assert!(
            decode::<Claims>(&present, &decoding_key(), &validation).is_ok(),
            "token with nbf must pass when nbf is required"
        );
    }

    #[test]
    fn claims_to_verify_nbf_also_checks_the_value() {
        // APISIX `claims_to_verify` verifies the claim, not just its presence:
        // a future-dated `nbf` must be rejected when (and only when) listed.
        let future_nbf = plain_claims_with_nbf(now_secs() + 3600);

        let mut cfg = base_config();
        cfg.claims_to_verify = Some(vec!["nbf".to_string()]);
        let validation = build_validation(&cfg);
        assert!(validation.validate_nbf);
        let token = make_token(future_nbf.clone());
        let err = decode::<Claims>(&token, &decoding_key(), &validation).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                jsonwebtoken::errors::ErrorKind::ImmatureSignature
            ),
            "future-dated nbf must be rejected when listed, got {:?}",
            err.kind()
        );

        // Not listed: jsonwebtoken defaults leave nbf unvalidated.
        let default_validation = build_validation(&base_config());
        assert!(!default_validation.validate_nbf);
        assert!(
            decode::<Claims>(&token, &decoding_key(), &default_validation).is_ok(),
            "nbf is ignored unless listed in claims_to_verify"
        );
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn plain_claims_with_nbf(nbf: u64) -> TestClaims {
        TestClaims {
            nbf: Some(nbf),
            ..plain_claims()
        }
    }

    #[test]
    fn rs256_ps256_and_eddsa_tokens_decode_with_matching_keys() {
        // Full roundtrips: sign with the matching family key, decode through
        // the plugin's own validation (algorithm pinned from config).
        for (algorithm, encoding, public_pem) in [
            (
                Algorithm::RS256,
                rsa_encoding_key(),
                RSA_TEST_PUBLIC_KEY_PEM,
            ),
            (
                Algorithm::PS256,
                rsa_encoding_key(),
                RSA_TEST_PUBLIC_KEY_PEM,
            ),
            (
                Algorithm::EdDSA,
                ed25519_encoding_key(),
                ED25519_TEST_PUBLIC_KEY_PEM,
            ),
        ] {
            let mut cfg = base_config();
            cfg.algorithm = algorithm;
            cfg.public_key = Some(public_pem.to_string());
            let token = make_token_with(algorithm, &plain_claims(), &encoding);
            let decoded = decode::<Claims>(
                &token,
                &cfg.get_decoding_key().unwrap(),
                &build_validation(&cfg),
            )
            .unwrap_or_else(|e| panic!("{algorithm:?} roundtrip failed: {e}"));
            assert!(decoded.claims.exp.is_some());
        }
    }

    #[test]
    fn cross_algorithm_tokens_are_rejected() {
        // Algorithm confusion guards: the pinned config algorithm must reject
        // tokens signed with any other algorithm, even with a usable key.
        let hs256_token = make_token(plain_claims());

        // HS256 token against an RS256 config.
        let mut rs_cfg = base_config();
        rs_cfg.algorithm = Algorithm::RS256;
        rs_cfg.public_key = Some(RSA_TEST_PUBLIC_KEY_PEM.to_string());
        let err = decode::<Claims>(
            &hs256_token,
            &rs_cfg.get_decoding_key().unwrap(),
            &build_validation(&rs_cfg),
        )
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
        ));

        // HS256 token against an HS384 config (same secret material).
        let mut hs384_cfg = base_config();
        hs384_cfg.algorithm = Algorithm::HS384;
        let err = decode::<Claims>(
            &hs256_token,
            &hs384_cfg.get_decoding_key().unwrap(),
            &build_validation(&hs384_cfg),
        )
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
        ));

        // RS256 token against an EdDSA config.
        let rs256_token = make_token_with(Algorithm::RS256, &plain_claims(), &rsa_encoding_key());
        let mut ed_cfg = base_config();
        ed_cfg.algorithm = Algorithm::EdDSA;
        ed_cfg.public_key = Some(ED25519_TEST_PUBLIC_KEY_PEM.to_string());
        let err = decode::<Claims>(
            &rs256_token,
            &ed_cfg.get_decoding_key().unwrap(),
            &build_validation(&ed_cfg),
        )
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
        ));
    }

    #[test]
    fn empty_claims_to_verify_keeps_default_validation() {
        let mut cfg = base_config();
        cfg.claims_to_verify = Some(vec![]);
        let validation = build_validation(&cfg);
        assert!(validation.required_spec_claims.contains("exp"));
        assert!(!validation.required_spec_claims.contains("nbf"));
    }

    #[test]
    fn decoding_key_supports_hs384_and_hs512() {
        for algorithm in [Algorithm::HS384, Algorithm::HS512] {
            let mut cfg = base_config();
            cfg.algorithm = algorithm;
            assert!(cfg.get_decoding_key().is_ok(), "{algorithm:?}");
        }
    }

    #[test]
    fn decoding_key_supports_ps_algorithms() {
        for algorithm in [Algorithm::PS256, Algorithm::PS384, Algorithm::PS512] {
            let mut cfg = base_config();
            cfg.algorithm = algorithm;
            cfg.public_key = Some(RSA_PUBLIC_KEY_PEM.to_string());
            assert!(cfg.get_decoding_key().is_ok(), "{algorithm:?}");
        }
    }

    #[test]
    fn decoding_key_supports_eddsa() {
        let mut cfg = base_config();
        cfg.algorithm = Algorithm::EdDSA;
        cfg.public_key = Some(ED25519_PUBLIC_KEY_PEM.to_string());
        assert!(cfg.get_decoding_key().is_ok());
    }

    #[test]
    fn ps256_invalid_pem_reaches_key_parsing_not_unsupported() {
        let mut cfg = base_config();
        cfg.algorithm = Algorithm::PS256;
        cfg.public_key =
            Some("-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----".to_string());
        let err = match cfg.get_decoding_key() {
            Ok(_) => panic!("invalid PEM must fail to parse"),
            Err(err) => err,
        };
        assert!(err.contains("Failed to parse RSA public key"), "{err}");
    }

    #[test]
    fn apisix_consumer_fields_are_ignored() {
        // APISIX uses consumer objects for credentials; PingSIX keeps them in
        // the plugin config. Unknown fields such as `anonymous_consumer` are
        // tolerated and ignored — authentication stays enforced with the
        // configured secret.
        let config = PluginConfig::try_from(serde_json::json!({
            "secret": "test-secret",
            "anonymous_consumer": "anonymous"
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(config.secret.as_deref(), Some("test-secret"));
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
            nbf: None,
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
            nbf: None,
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
            nbf: None,
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

    #[test]
    fn empty_hmac_secret_is_rejected() {
        for cfg in [
            serde_json::json!({ "secret": "" }),
            serde_json::json!({ "secret": "", "base64_secret": true }),
        ] {
            let err = validate_jwt_auth_config(&cfg).unwrap_err();
            assert!(err.to_string().contains("must not be empty"), "{err}");
        }
    }

    #[tokio::test]
    async fn hide_credentials_cookie_strips_upstream_cookie_without_clearing_client_cookie() {
        #[derive(Serialize)]
        struct TestClaims {
            sub: &'static str,
            exp: usize,
        }
        let token = encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                sub: "alice",
                exp: 4_000_000_000,
            },
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap();

        let mut cfg = base_config();
        cfg.hide_credentials = true;
        let plugin = PluginJWTAuth {
            validation: build_validation(&cfg),
            decoding_key: cfg.get_decoding_key().unwrap(),
            config: cfg,
        };

        let wire = format!(
            "GET /protected HTTP/1.1\r\nHost: example.com\r\nCookie: jwt={token}; theme=dark\r\n\r\n"
        );
        let mut session = crate::utils::testing::session_from_request(&wire).await;
        let mut ctx = ProxyContext::default();

        let verdict = plugin
            .request_filter(&mut session, &mut ctx)
            .await
            .expect("valid cookie token must authenticate");
        assert!(matches!(verdict, FilterVerdict::Continue));
        assert!(
            request::get_cookie_value(session.req_header(), "jwt").is_none(),
            "jwt cookie must be hidden from upstream request"
        );
        assert_eq!(
            request::get_cookie_value(session.req_header(), "theme"),
            Some("dark"),
            "unrelated cookies must be preserved"
        );
        assert!(
            ctx.get_str("jwt_auth_clear_cookie").is_none(),
            "hide_credentials must not schedule client cookie deletion"
        );
    }
}
