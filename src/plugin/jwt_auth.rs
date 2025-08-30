use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::StatusCode;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{proxy::ProxyContext, utils::request};

use super::ProxyPlugin;
use crate::utils::response::ResponseBuilder;

// ------------------ JWKS Support ------------------
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    crv: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks { keys: Vec<Jwk> }

#[derive(Clone)]
struct JwksCacheEntry {
    fetched_at_ms: u128,
    keys: Vec<Jwk>,
}

#[derive(Clone)]
struct JwksManager {
    url: String,
    cache_secs: u64,
    timeout_ms: u64,
    inner: Arc<std::sync::Mutex<Option<JwksCacheEntry>>>,
}

static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .expect("reqwest client build")
});

impl JwksManager {
    fn new(url: String, cache_secs: u64, timeout_ms: u64) -> std::result::Result<Self, String> {
        if url.is_empty() { return Err("jwks_url cannot be empty".to_string()); }
        Ok(Self { url, cache_secs, timeout_ms, inner: Arc::new(std::sync::Mutex::new(None)) })
    }

    async fn resolve_for_token(&self, token: &str, alg: Algorithm) -> std::result::Result<DecodingKey, String> {
        let header = decode_header(token).map_err(|e| format!("Failed to decode token header: {}", e))?;
        let kid = header.kid.ok_or("Token header missing kid")?;
        let keys = self.get_keys().await?;
        let jwk = keys.iter().find(|k| k.kid.as_deref() == Some(&kid))
            .ok_or_else(|| format!("JWKS key not found for kid: {}", kid))?;

        match alg {
            Algorithm::RS256 => self.jwk_to_rsa_key(jwk),
            Algorithm::ES256 => self.jwk_to_ec_key(jwk),
            _ => Err(format!("Unsupported JWKS algorithm: {:?}", alg)),
        }
    }

    fn jwk_to_rsa_key(&self, jwk: &Jwk) -> std::result::Result<DecodingKey, String> {
        let n_b64 = jwk.n.as_ref().ok_or("Missing modulus n in JWK")?;
        let e_b64 = jwk.e.as_ref().ok_or("Missing exponent e in JWK")?;
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(n_b64)
            .map_err(|e| format!("Invalid base64url n: {}", e))?;
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(e_b64)
            .map_err(|e| format!("Invalid base64url e: {}", e))?;
        DecodingKey::from_rsa_components(&n, &e).map_err(|e| format!("Failed to build RSA key: {}", e))
    }

    fn jwk_to_ec_key(&self, jwk: &Jwk) -> std::result::Result<DecodingKey, String> {
        let x_b64 = jwk.x.as_ref().ok_or("Missing x in JWK")?;
        let y_b64 = jwk.y.as_ref().ok_or("Missing y in JWK")?;
        let crv = jwk.crv.as_deref().ok_or("Missing crv in JWK")?;
        if crv != "P-256" { return Err(format!("Unsupported EC curve: {}", crv)); }
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|e| format!("Invalid base64url x: {}", e))?;
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(y_b64)
            .map_err(|e| format!("Invalid base64url y: {}", e))?;
        DecodingKey::from_ec_components(&x, &y).map_err(|e| format!("Failed to build EC key: {}", e))
    }

    async fn get_keys(&self) -> std::result::Result<Vec<Jwk>, String> {
        // check cache TTL
        if let Some(entry) = self.inner.lock().unwrap().clone() {
            let age_ms = now_millis().saturating_sub(entry.fetched_at_ms);
            if age_ms < (self.cache_secs as u128) * 1000 {
                return Ok(entry.keys);
            }
        }
        // fetch with timeout and cache
        let resp = HTTP_CLIENT
            .get(&self.url)
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {}", e))?;
        let jwks: Jwks = resp.json().await.map_err(|e| format!("Invalid JWKS JSON: {}", e))?;
        let keys = jwks.keys.clone();
        *self.inner.lock().unwrap() = Some(JwksCacheEntry { fetched_at_ms: now_millis(), keys: keys.clone() });
        Ok(keys)
    }
}

fn now_millis() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

enum KeySource {
    Static(DecodingKey),
    Jwks(JwksManager),
}

pub const PLUGIN_NAME: &str = "jwt-auth";
const PRIORITY: i32 = 2510;
const DEFAULT_HEADER: &str = "authorization";
const DEFAULT_QUERY: &str = "jwt";
const DEFAULT_COOKIE: &str = "jwt";

/// Creates a JWT Auth plugin instance with the given configuration.
/// This plugin validates JWTs from HTTP headers, query parameters, or cookies, and optionally
/// stores the JWT payload in the request context or hides credentials after validation.
pub fn create_jwt_auth_plugin(cfg: JsonValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig = serde_json::from_value(cfg)
        .or_err_with(ReadError, || "Failed to parse JWT auth plugin config")?;

    // Prepare decoding key or JWKS manager depending on configuration
    let (decoding_key, jwks) = match config.get_decoding_key_or_jwks() {
        Ok(KeySource::Static(key)) => (Some(key), None),
        Ok(KeySource::Jwks(manager)) => (None, Some(Arc::new(manager))),
        Err(e) => return Err(pingora_error::Error::e_explain(ReadError, e)),
    };

    // Pre-create validation object for better performance
    let mut validation = Validation::new(config.algorithm);
    validation.leeway = config.lifetime_grace_period;

    Ok(Arc::new(PluginJWTAuth {
        config,
        decoding_key,
        jwks,
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

    /// JWKS endpoint URL. If provided (and public_key is None), keys will be resolved by kid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,

    /// JWKS cache TTL seconds (default: 300)
    #[serde(default = "PluginConfig::default_jwks_cache_secs")]
    pub jwks_cache_secs: u64,

    /// JWKS HTTP timeout milliseconds (default: 2000)
    #[serde(default = "PluginConfig::default_jwks_timeout_ms")]
    pub jwks_timeout_ms: u64,
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

    fn default_jwks_cache_secs() -> u64 { 300 }
    fn default_jwks_timeout_ms() -> u64 { 2000 }

    fn get_decoding_key_or_jwks(&self) -> std::result::Result<KeySource, String> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS512 => {
                let secret = self
                    .secret
                    .as_ref()
                    .ok_or("Secret is required for HMAC algorithms (HS256, HS512)")?;
                let key: Vec<u8> = if self.base64_secret {
                    general_purpose::STANDARD
                        .decode(secret)
                        .map_err(|e| format!("Failed to decode base64 secret: {}", e))?
                } else {
                    secret.as_bytes().to_vec()
                };
                Ok(KeySource::Static(DecodingKey::from_secret(&key)))
            }
            Algorithm::RS256 => {
                if let Some(public_key) = self.public_key.as_ref() {
                    return DecodingKey::from_rsa_pem(public_key.as_bytes())
                        .map(KeySource::Static)
                        .map_err(|e| format!("Failed to parse RSA public key: {}", e));
                }
                if let Some(url) = &self.jwks_url {
                    return Ok(KeySource::Jwks(JwksManager::new(
                        url.clone(),
                        self.jwks_cache_secs,
                        self.jwks_timeout_ms,
                    )?));
                }
                Err("Either public_key or jwks_url must be provided for RS algorithms".to_string())
            }
            Algorithm::ES256 => {
                if let Some(public_key) = self.public_key.as_ref() {
                    return DecodingKey::from_ec_pem(public_key.as_bytes())
                        .map(KeySource::Static)
                        .map_err(|e| format!("Failed to parse EC public key: {}", e));
                }
                if let Some(url) = &self.jwks_url {
                    return Ok(KeySource::Jwks(JwksManager::new(
                        url.clone(),
                        self.jwks_cache_secs,
                        self.jwks_timeout_ms,
                    )?));
                }
                Err("Either public_key or jwks_url must be provided for ES algorithms".to_string())
            }
            _ => Err(format!("Unsupported algorithm: {:?}", self.algorithm)),
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
    decoding_key: Option<DecodingKey>,
    jwks: Option<Arc<JwksManager>>,
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
        let token = self.extract_token(session, ctx);
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

        // Resolve decoding key (static or JWKS)
        let key = match (&self.decoding_key, &self.jwks) {
            (Some(k), _) => k.clone(),
            (None, Some(manager)) => {
                match manager.resolve_for_token(&token, self.config.algorithm).await {
                    Ok(k) => k,
                    Err(e) => {
                        ResponseBuilder::send_proxy_error(
                            session,
                            StatusCode::UNAUTHORIZED,
                            Some(&format!("{}", e)),
                            Some(&[("WWW-Authenticate", "Bearer error=\"invalid_token\"")]),
                        ).await?;
                        return Ok(true);
                    }
                }
            }
            _ => unreachable!(),
        };

        // Parse JWT using pre-created validation
        let token_data = match decode::<Claims>(&token, &key, &self.validation) {
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
            ctx.set("jwt-auth-payload", token_data.claims.extra.clone());
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
            let clear_cookie_header = format!("{}=; Max-Age=0; Path=/; HttpOnly", cookie_name);
            upstream_response.insert_header("Set-Cookie", clear_cookie_header)?;
        }
        Ok(())
    }
}

impl PluginJWTAuth {
    /// Extracts JWT from header, query, or cookie using a cleaner chain approach
    fn extract_token(&self, session: &mut Session, ctx: &mut ProxyContext) -> Option<String> {
        self.extract_from_header(session)
            .or_else(|| self.extract_from_query(session))
            .or_else(|| self.extract_from_cookie(session, ctx))
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
    fn extract_from_cookie(&self, session: &mut Session, ctx: &mut ProxyContext) -> Option<String> {
        let token = request::get_cookie_value(session.req_header(), &self.config.cookie)
            .map(|c| c.to_string());

        if token.is_some() && self.config.hide_credentials {
            // Store the cookie name in context for later clearing in response phase
            ctx.set("jwt_auth_clear_cookie", self.config.cookie.clone());
        }

        token
    }
}
