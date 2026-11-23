use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use http::{header, Method, StatusCode};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, Rejection},
    plugins::config::parse_and_validate_plugin_config,
    utils::request,
};

pub const PLUGIN_NAME: &str = "cors";
const PRIORITY: i32 = 4000;

/// Creates an CORS plugin instance with the given configuration.
pub fn create_cors_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;

    // Pre-compile regex patterns and create optimized config
    let compiled_config = config.compile_and_optimize()?;

    Ok(Arc::new(PluginCors {
        config: compiled_config,
    }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators (including regex compilation) WITHOUT constructing the plugin.
pub fn validate_cors_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?.compile_and_optimize()?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Default, Validate)]
#[validate(schema(function = "PluginConfig::validate"))]
pub struct PluginConfig {
    #[serde(default = "PluginConfig::default_star")]
    #[validate(custom(function = "PluginConfig::validate_origins"))]
    pub allow_origins: String,

    #[serde(default = "PluginConfig::default_star")]
    #[validate(custom(function = "PluginConfig::validate_methods"))]
    pub allow_methods: String,

    #[serde(default = "PluginConfig::default_star")]
    #[validate(custom(function = "PluginConfig::validate_headers"))]
    pub allow_headers: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expose_headers: Option<String>,

    #[serde(default = "PluginConfig::default_max_age")]
    pub max_age: i32,

    #[serde(default)]
    pub allow_credential: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_origins_by_regex: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing_allow_origins: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing_allow_origins_by_regex: Option<Vec<String>>,

    /// Accepted for APISIX schema compatibility. PingSIX has no plugin
    /// metadata store, so a non-empty list is rejected during validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_origins_by_metadata: Option<Vec<String>>,
}

impl PluginConfig {
    fn default_star() -> String {
        "*".to_string()
    }

    fn default_max_age() -> i32 {
        5
    }

    fn validate(&self) -> Result<(), ValidationError> {
        // Both "*" and "**" mean any origin; credentials cannot be combined with
        // either unless `allow_origins_by_regex` is configured (in which case
        // regex matching governs and the matched origin is reflected).
        if self.allow_credential
            && self.allow_origins_by_regex.is_none()
            && (self.allow_origins == "*" || self.allow_origins == "**")
        {
            return Err(ValidationError::new(
                "allow_credential cannot be used with allow_origins='*' or '**'",
            ));
        }
        if self.allow_credential && self.allow_headers == "*" {
            return Err(ValidationError::new(
                "allow_credential cannot be used with allow_headers='*'; use '**' to reflect request headers",
            ));
        }
        if self.allow_credential && self.allow_methods == "*" {
            return Err(ValidationError::new(
                "allow_credential cannot be used with allow_methods='*'",
            ));
        }
        if self.allow_credential && self.expose_headers.as_deref() == Some("*") {
            return Err(ValidationError::new(
                "allow_credential cannot be used with expose_headers='*'",
            ));
        }
        if self.allow_credential && self.timing_allow_origins.as_deref() == Some("*") {
            return Err(ValidationError::new(
                "allow_credential cannot be used with timing_allow_origins='*'",
            ));
        }
        if let Some(regexes) = &self.allow_origins_by_regex {
            Self::validate_regex_list(regexes, "allow_origins_by_regex")?;
        }
        if let Some(timing_origins) = &self.timing_allow_origins {
            Self::validate_origin_list(timing_origins, "timing_allow_origins")?;
        }
        if let Some(regexes) = &self.timing_allow_origins_by_regex {
            Self::validate_regex_list(regexes, "timing_allow_origins_by_regex")?;
        }
        if let Some(metadata) = &self.allow_origins_by_metadata {
            if !metadata.is_empty() {
                return Err(ValidationError::new("plugin metadata is not supported"));
            }
        }
        Ok(())
    }

    fn validate_regex_list(regexes: &[String], field: &str) -> Result<(), ValidationError> {
        if regexes.is_empty() {
            return Err(ValidationError::new("regex list must not be empty")
                .with_message(format!("{field} must not be empty").into()));
        }
        let mut seen = HashSet::new();
        for regex in regexes {
            if regex.is_empty() {
                return Err(ValidationError::new("regex entry must not be empty")
                    .with_message(format!("{field} entries must not be empty").into()));
            }
            if regex.chars().count() > 4096 {
                return Err(ValidationError::new("regex entry too long").with_message(
                    format!("{field} entries must be at most 4096 characters").into(),
                ));
            }
            if !seen.insert(regex.as_str()) {
                return Err(ValidationError::new("regex entry must be unique")
                    .with_message(format!("{field} entries must be unique").into()));
            }
        }
        Ok(())
    }

    fn validate_origins(origins: &str) -> Result<(), ValidationError> {
        Self::validate_origin_list(origins, "allow_origins")
    }

    fn validate_origin_list(value: &str, field: &str) -> Result<(), ValidationError> {
        if value.is_empty() {
            let message = match field {
                "timing_allow_origins" => "timing_allow_origins cannot be empty",
                _ => "allow_origins cannot be empty",
            };
            return Err(ValidationError::new(message));
        }
        if value != "*" && value != "**" {
            for origin in value.split(',').map(str::trim) {
                if origin.is_empty() {
                    let message = match field {
                        "timing_allow_origins" => "timing_allow_origins contains empty origin",
                        _ => "allow_origins contains empty origin",
                    };
                    return Err(ValidationError::new(message));
                }
            }
        }
        Ok(())
    }

    fn validate_methods(methods: &str) -> Result<(), ValidationError> {
        if methods != "*" && methods != "**" {
            for method in methods.split(',').map(str::trim) {
                if !["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
                    .contains(&method.to_uppercase().as_str())
                {
                    return Err(ValidationError::new("invalid HTTP method"));
                }
            }
        }
        Ok(())
    }

    fn validate_headers(headers: &str) -> Result<(), ValidationError> {
        if headers != "*" && headers != "**" {
            for header in headers.split(',').map(str::trim) {
                if !header.chars().all(|c| c.is_alphanumeric() || c == '-') {
                    return Err(ValidationError::new("invalid header name"));
                }
            }
        }
        Ok(())
    }

    fn compile_and_optimize(self) -> ProxyResult<OptimizedPluginConfig> {
        if self
            .allow_origins_by_metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.is_empty())
        {
            return Err(ProxyError::validation_error(
                "plugin metadata is not supported",
            ));
        }

        // Pre-compile regex patterns
        let compiled_regexes = if let Some(regex_list) = &self.allow_origins_by_regex {
            let compiled: Vec<Arc<Regex>> = regex_list
                .iter()
                .map(|re| {
                    Regex::new(re)
                        .map(Arc::new)
                        .map_err(|e| -> Box<pingora_error::Error> {
                            ProxyError::validation_error(format!(
                                "Invalid regex pattern '{re}': {e}"
                            ))
                            .into()
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            Some(compiled)
        } else {
            None
        };

        let compiled_timing_regexes = if let Some(regex_list) = &self.timing_allow_origins_by_regex
        {
            let compiled: Vec<Arc<Regex>> = regex_list
                .iter()
                .map(|re| {
                    Regex::new(re)
                        .map(Arc::new)
                        .map_err(|e| -> Box<pingora_error::Error> {
                            ProxyError::validation_error(format!(
                                "Invalid timing regex pattern '{re}': {e}"
                            ))
                            .into()
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            Some(compiled)
        } else {
            None
        };

        // Pre-compile allowed origins set for faster lookup
        let allow_origins_set = compile_origins_set(&self.allow_origins);
        let timing_allow_origins_set = self
            .timing_allow_origins
            .as_deref()
            .and_then(compile_origins_set);

        Ok(OptimizedPluginConfig {
            allow_origins: self.allow_origins,
            allow_methods: self.allow_methods,
            allow_headers: self.allow_headers,
            expose_headers: self.expose_headers,
            max_age: self.max_age,
            allow_credential: self.allow_credential,
            allow_origins_by_regex: compiled_regexes,
            allow_origins_set,
            timing_allow_origins: self.timing_allow_origins,
            timing_allow_origins_by_regex: compiled_timing_regexes,
            timing_allow_origins_set,
        })
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Failed to parse CORS plugin config")?;

        Ok(config)
    }
}

/// Compile a comma-separated origin list into a lookup set. Wildcards and
/// empty values produce `None`/are skipped; callers pre-validate the list.
fn compile_origins_set(origins: &str) -> Option<HashSet<String>> {
    if origins.is_empty() || origins == "*" || origins == "**" {
        return None;
    }
    Some(
        origins
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
    )
}

#[derive(Debug)]
pub struct OptimizedPluginConfig {
    pub allow_origins: String,
    pub allow_methods: String,
    pub allow_headers: String,
    pub expose_headers: Option<String>,
    pub max_age: i32,
    pub allow_credential: bool,
    pub allow_origins_by_regex: Option<Vec<Arc<Regex>>>,
    pub allow_origins_set: Option<HashSet<String>>, // Pre-compiled for faster lookup
    pub timing_allow_origins: Option<String>,
    pub timing_allow_origins_by_regex: Option<Vec<Arc<Regex>>>,
    pub timing_allow_origins_set: Option<HashSet<String>>,
}

impl OptimizedPluginConfig {
    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_origins.is_empty() {
            return false;
        }

        // When `allow_origins_by_regex` is configured, it takes precedence over
        // the default `"*"`/`"**"` wildcard so configuring regex rules alone
        // never inadvertently allows all origins. Explicit non-wildcard
        // `allow_origins` lists continue to union with regex patterns.
        if let Some(regex_list) = &self.allow_origins_by_regex {
            if let Some(ref origins_set) = self.allow_origins_set {
                if origins_set.contains(origin) {
                    return true;
                }
            }
            return regex_list.iter().any(|re| re.is_match(origin));
        }

        // Handle wildcard cases
        if self.allow_origins == "*" || self.allow_origins == "**" {
            return true;
        }

        // Use pre-compiled HashSet for fast lookup
        if let Some(ref origins_set) = self.allow_origins_set {
            if origins_set.contains(origin) {
                return true;
            }
        }

        false
    }

    /// Value for `Timing-Allow-Origin` when the timing configuration matches
    /// the request origin; `None` means the header stays unset. APISIX: `*` is
    /// a literal wildcard (emitted even without an Origin header), `**`
    /// reflects the request origin, and the regex list takes precedence over
    /// the plain list.
    fn timing_allow_origin_value<'a>(&self, origin: Option<&'a str>) -> Option<&'a str> {
        if let Some(regex_list) = &self.timing_allow_origins_by_regex {
            return origin.filter(|origin| regex_list.iter().any(|re| re.is_match(origin)));
        }
        let configured = self.timing_allow_origins.as_deref()?;
        if configured == "*" {
            return Some("*");
        }
        let origin = origin?;
        if configured == "**" {
            return Some(origin);
        }
        self.timing_allow_origins_set
            .as_ref()
            .filter(|set| set.contains(origin))
            .map(|_| origin)
    }
}

pub struct PluginCors {
    config: OptimizedPluginConfig,
}

impl PluginCors {
    fn apply_cors_headers(&self, session: &mut Session, resp: &mut ResponseHeader) -> Result<()> {
        let origin = request::get_req_header_value(session.req_header(), header::ORIGIN.as_str())
            .map(|s| s.to_string());

        if let Some(origin) = &origin {
            if self.config.is_origin_allowed(origin) {
                self.apply_cors_headers_with_origin(session, resp, origin)?;
            }
        }
        // `Timing-Allow-Origin` is computed from the raw Origin independently
        // of the CORS allow outcome — APISIX emits it in header_filter for
        // every response, and a browser needs it even when the origin is not
        // allowed to read CORS-protected resources.
        self.apply_timing_allow_origin(resp, origin.as_deref())
    }

    fn apply_timing_allow_origin(
        &self,
        resp: &mut ResponseHeader,
        origin: Option<&str>,
    ) -> Result<()> {
        if let Some(timing_origin) = self.config.timing_allow_origin_value(origin) {
            resp.insert_header("Timing-Allow-Origin", timing_origin)?;
        }
        Ok(())
    }

    fn apply_cors_headers_with_origin(
        &self,
        session: &mut Session,
        resp: &mut ResponseHeader,
        origin: &str,
    ) -> Result<()> {
        // Without credentials and without regex matching, "*" may be returned
        // literally; otherwise reflect Origin (with Vary: Origin).
        let reflecting_origin = if !self.config.allow_credential
            && self.config.allow_origins_by_regex.is_none()
            && (self.config.allow_origins == "*" || self.config.allow_origins == "**")
        {
            resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")?;
            false
        } else {
            resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin)?;
            true
        };

        if self.config.allow_credential {
            resp.insert_header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")?;
        }

        let methods = if self.config.allow_methods == "**" {
            "GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD".to_string()
        } else {
            self.config.allow_methods.clone()
        };
        resp.insert_header(header::ACCESS_CONTROL_ALLOW_METHODS, methods)?;

        let headers = if self.config.allow_headers == "**" {
            request::get_req_header_value(
                session.req_header(),
                header::ACCESS_CONTROL_REQUEST_HEADERS.as_str(),
            )
            .unwrap_or_default()
            .to_string()
        } else {
            self.config.allow_headers.clone()
        };
        let dynamic_allow_headers = self.config.allow_headers == "**";
        resp.insert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, headers)?;

        resp.insert_header(
            header::ACCESS_CONTROL_MAX_AGE,
            self.config.max_age.to_string(),
        )?;

        if let Some(expose) = &self.config.expose_headers {
            resp.insert_header(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose)?;
        }

        if reflecting_origin {
            merge_vary(resp, "Origin")?;
        }
        if dynamic_allow_headers {
            merge_vary(resp, "Access-Control-Request-Headers")?;
        }

        Ok(())
    }

    fn handle_options_request(&self, session: &mut Session) -> Result<Option<ResponseHeader>> {
        let req = session.req_header();
        let Some(requested_method) =
            request::get_req_header_value(req, header::ACCESS_CONTROL_REQUEST_METHOD.as_str())
        else {
            // An OPTIONS request without this header is ordinary application traffic.
            return Ok(None);
        };
        let origin =
            request::get_req_header_value(req, header::ORIGIN.as_str()).map(str::to_string);
        let allowed = origin
            .as_deref()
            .is_some_and(|origin| self.config.is_origin_allowed(origin))
            && method_is_allowed(&self.config.allow_methods, requested_method)
            && request::get_req_header_value(req, header::ACCESS_CONTROL_REQUEST_HEADERS.as_str())
                .is_none_or(|headers| headers_are_allowed(&self.config.allow_headers, headers));
        if !allowed {
            return Ok(Some(ResponseHeader::build(StatusCode::FORBIDDEN, None)?));
        }
        // `allowed` is true only when origin is Some and allowed.
        let origin = origin.expect("allowed implies origin is Some");
        let mut resp = ResponseHeader::build(StatusCode::NO_CONTENT, None)?;
        self.apply_cors_headers_with_origin(session, &mut resp, &origin)?;
        // APISIX's header_filter runs for preflight responses too.
        self.apply_timing_allow_origin(&mut resp, Some(&origin))?;
        Ok(Some(resp))
    }
}

#[async_trait]
impl ProxyPlugin for PluginCors {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        if session.req_header().method == Method::OPTIONS {
            if let Some(resp) = self.handle_options_request(session)? {
                // The preflight answer is bodyless; `headers` carry the full
                // CORS header set built by the shared helpers.
                let rejection = Rejection::new(resp.status).with_headers(resp.headers.iter().map(
                    |(name, value)| {
                        (
                            name.as_str().to_string(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    },
                ));
                return Ok(FilterVerdict::Reject(rejection));
            }
        }
        Ok(FilterVerdict::Continue)
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.apply_cors_headers(session, upstream_response)?;
        Ok(())
    }
}

fn method_is_allowed(allowed: &str, requested: &str) -> bool {
    const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

    METHODS
        .iter()
        .any(|method| method.eq_ignore_ascii_case(requested))
        && (allowed == "*"
            || allowed == "**"
            || allowed
                .split(',')
                .any(|method| method.trim().eq_ignore_ascii_case(requested)))
}

fn headers_are_allowed(allowed: &str, requested: &str) -> bool {
    allowed == "*"
        || allowed == "**"
        || requested.split(',').map(str::trim).all(|requested| {
            !requested.is_empty()
                && allowed
                    .split(',')
                    .any(|header| header.trim().eq_ignore_ascii_case(requested))
        })
}

/// Merge a vary token into an existing Vary header without duplicates.
fn merge_vary(resp: &mut ResponseHeader, name: &str) -> Result<()> {
    let mut values: Vec<String> = resp
        .headers
        .get_all(header::VARY)
        .iter()
        .flat_map(|v| v.to_str().unwrap_or("").split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let has_name = values.iter().any(|v| v.eq_ignore_ascii_case(name));
    if !has_name {
        values.push(name.to_string());
    }

    let mut seen = HashSet::new();
    values.retain(|v| seen.insert(v.to_ascii_lowercase()));

    resp.insert_header(header::VARY, values.join(", "))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_http::ResponseHeader;

    #[test]
    fn credentials_rejected_with_double_star() {
        let cfg = PluginConfig {
            allow_origins: "**".into(),
            allow_credential: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn credentials_rejected_with_single_star() {
        let cfg = PluginConfig {
            allow_origins: "*".into(),
            allow_credential: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn credentials_rejected_with_wildcard_headers() {
        let cfg = PluginConfig {
            allow_origins: "https://example.com".into(),
            allow_headers: "*".into(),
            allow_credential: true,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn credentials_reject_all_remaining_wildcards() {
        let base = || PluginConfig {
            allow_origins: "https://example.com".into(),
            allow_headers: "Content-Type".into(),
            allow_methods: "GET".into(),
            allow_credential: true,
            ..Default::default()
        };

        let mut wildcard_methods = base();
        wildcard_methods.allow_methods = "*".into();
        assert!(wildcard_methods.validate().is_err());

        let mut wildcard_expose = base();
        wildcard_expose.expose_headers = Some("*".into());
        assert!(wildcard_expose.validate().is_err());

        let mut wildcard_timing = base();
        wildcard_timing.timing_allow_origins = Some("*".into());
        assert!(wildcard_timing.validate().is_err());
    }

    #[test]
    fn wildcard_methods_only_allow_advertised_methods() {
        assert!(method_is_allowed("**", "GET"));
        assert!(!method_is_allowed("**", "CONNECT"));
        assert!(!method_is_allowed("**", "TRACE"));
        assert!(!method_is_allowed("**", "FOO"));
    }

    #[test]
    fn merge_vary_origin_preserves_existing_and_dedups() {
        let mut resp = ResponseHeader::build(http::StatusCode::OK, None).unwrap();
        resp.insert_header(header::VARY, "Accept-Encoding").unwrap();
        merge_vary(&mut resp, "Origin").unwrap();
        let vary = resp.headers.get(header::VARY).unwrap().to_str().unwrap();
        assert!(vary.to_ascii_lowercase().contains("accept-encoding"));
        assert!(vary.to_ascii_lowercase().contains("origin"));

        merge_vary(&mut resp, "Origin").unwrap();
        let vary2 = resp.headers.get(header::VARY).unwrap().to_str().unwrap();
        assert_eq!(
            vary2.to_ascii_lowercase().matches("origin").count(),
            1,
            "Origin must not be duplicated: {vary2}"
        );
    }

    #[test]
    fn merge_vary_adds_access_control_request_headers() {
        let mut resp = ResponseHeader::build(http::StatusCode::OK, None).unwrap();
        merge_vary(&mut resp, "Access-Control-Request-Headers").unwrap();
        let vary = resp.headers.get(header::VARY).unwrap().to_str().unwrap();
        assert!(vary
            .to_ascii_lowercase()
            .contains("access-control-request-headers"));
    }

    fn optimized(cfg: PluginConfig) -> OptimizedPluginConfig {
        cfg.compile_and_optimize().expect("config compiles")
    }

    #[test]
    fn timing_allow_origins_parses_and_validates() {
        let cfg: PluginConfig =
            PluginConfig::try_from(serde_json::json!({ "timing_allow_origins": "*" })).unwrap();
        assert_eq!(cfg.timing_allow_origins.as_deref(), Some("*"));

        assert!(PluginConfig::try_from(serde_json::json!({ "timing_allow_origins": "" })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins": "a.example, ,b.example"
        }))
        .is_err());
    }

    #[test]
    fn timing_regexes_must_be_nonempty_unique() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins_by_regex": []
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins_by_regex": ["^https://a$", "^https://a$"]
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins_by_regex": [""]
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins_by_regex": ["^https://a$", "^https://b$"]
        }))
        .is_ok());
    }

    #[test]
    fn timing_regex_invalid_pattern_is_rejected_at_compile() {
        let cfg = PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins_by_regex": ["("]
        }))
        .unwrap();
        assert!(cfg.compile_and_optimize().is_err());
    }

    #[test]
    fn timing_allow_origin_matches_configuration() {
        let wildcard = optimized(PluginConfig {
            allow_origins: "*".into(),
            timing_allow_origins: Some("*".into()),
            ..Default::default()
        });
        assert_eq!(
            wildcard.timing_allow_origin_value(Some("https://x.example")),
            Some("*")
        );
        // APISIX emits the literal wildcard even without an Origin header.
        assert_eq!(wildcard.timing_allow_origin_value(None), Some("*"));

        let reflected = optimized(PluginConfig {
            allow_origins: "*".into(),
            timing_allow_origins: Some("**".into()),
            ..Default::default()
        });
        assert_eq!(
            reflected.timing_allow_origin_value(Some("https://x.example")),
            Some("https://x.example")
        );
        assert_eq!(reflected.timing_allow_origin_value(None), None);

        let listed = optimized(PluginConfig {
            allow_origins: "*".into(),
            timing_allow_origins: Some("https://a.example,https://b.example".into()),
            ..Default::default()
        });
        assert_eq!(
            listed.timing_allow_origin_value(Some("https://a.example")),
            Some("https://a.example")
        );
        assert_eq!(
            listed.timing_allow_origin_value(Some("https://c.example")),
            None
        );

        let regex = optimized(PluginConfig {
            allow_origins: "*".into(),
            timing_allow_origins_by_regex: Some(vec!["^https://[a-z]+\\.example$".into()]),
            ..Default::default()
        });
        assert_eq!(
            regex.timing_allow_origin_value(Some("https://api.example")),
            Some("https://api.example")
        );
        assert_eq!(
            regex.timing_allow_origin_value(Some("https://other.test")),
            None
        );

        // APISIX gives the regex list precedence: the plain list is ignored
        // when both are configured.
        let regex_precedence = optimized(PluginConfig {
            allow_origins: "*".into(),
            timing_allow_origins: Some("https://plain.example".into()),
            timing_allow_origins_by_regex: Some(vec!["^https://api\\.example$".into()]),
            ..Default::default()
        });
        assert_eq!(
            regex_precedence.timing_allow_origin_value(Some("https://api.example")),
            Some("https://api.example")
        );
        assert_eq!(
            regex_precedence.timing_allow_origin_value(Some("https://plain.example")),
            None,
            "plain-list match must be ignored when the regex list is configured"
        );

        let unconfigured = optimized(PluginConfig::default());
        assert_eq!(
            unconfigured.timing_allow_origin_value(Some("https://x.example")),
            None
        );
    }

    #[test]
    fn timing_regex_entries_are_capped_at_4096_characters() {
        let long = "a".repeat(4097);
        assert!(PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins_by_regex": [long]
        }))
        .is_err());
        let ok = "a".repeat(4096);
        assert!(PluginConfig::try_from(serde_json::json!({
            "timing_allow_origins_by_regex": [ok]
        }))
        .is_ok());
    }

    async fn cors_session(method: &str, headers: &[&str]) -> Session {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(1024);
        let mut request = format!("{method} / HTTP/1.1\r\nHost: t\r\n");
        for header in headers {
            request.push_str(&format!("{header}\r\n"));
        }
        request.push_str("\r\n");
        server.write_all(request.as_bytes()).await.unwrap();
        drop(server);
        let mut session = Session::new_h1(Box::new(client));
        session.downstream_session.read_request().await.unwrap();
        session
    }

    #[tokio::test]
    async fn timing_allow_origin_is_emitted_independently_of_cors_allow() {
        // The timing match is computed from the raw Origin even when the
        // origin is NOT allowed for CORS (and even with no Origin at all
        // when the wildcard is configured).
        let cfg = optimized(PluginConfig {
            allow_origins: "https://app.example".into(),
            timing_allow_origins: Some("*".into()),
            ..Default::default()
        });
        let plugin = PluginCors { config: cfg };

        let mut session = cors_session("GET", &["Origin: https://other.example"]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        plugin.apply_cors_headers(&mut session, &mut resp).unwrap();
        assert!(
            resp.headers.get("Access-Control-Allow-Origin").is_none(),
            "not-allowed origin must not get ACAO"
        );
        assert_eq!(
            resp.headers.get("Timing-Allow-Origin").unwrap(),
            "*",
            "TAO must be emitted independently of the CORS allow outcome"
        );

        // No Origin header at all: the literal wildcard is still emitted.
        let mut session = cors_session("GET", &[]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        plugin.apply_cors_headers(&mut session, &mut resp).unwrap();
        assert_eq!(resp.headers.get("Timing-Allow-Origin").unwrap(), "*");
    }

    #[tokio::test]
    async fn preflight_response_carries_timing_allow_origin() {
        let cfg = optimized(PluginConfig {
            allow_origins: "*".into(),
            allow_methods: "GET".into(),
            timing_allow_origins: Some("**".into()),
            ..Default::default()
        });
        let plugin = PluginCors { config: cfg };
        let mut session = cors_session(
            "OPTIONS",
            &[
                "Origin: https://app.example",
                "Access-Control-Request-Method: GET",
            ],
        )
        .await;
        let resp = plugin
            .handle_options_request(&mut session)
            .unwrap()
            .unwrap();
        assert_eq!(
            resp.headers.get("Timing-Allow-Origin").unwrap(),
            "https://app.example"
        );
    }

    #[tokio::test]
    async fn allow_origins_by_regex_is_not_bypassed_by_default_wildcard() {
        let cfg = PluginConfig::try_from(serde_json::json!({
            "allow_origins_by_regex": ["^https://trusted\\.example$"]
        }))
        .unwrap()
        .compile_and_optimize()
        .unwrap();
        assert!(cfg.is_origin_allowed("https://trusted.example"));
        assert!(
            !cfg.is_origin_allowed("https://evil.example"),
            "default allow_origins='*' must not bypass allow_origins_by_regex"
        );

        let plugin = PluginCors { config: cfg };
        let mut session = cors_session("GET", &["Origin: https://trusted.example"]).await;
        let mut resp = ResponseHeader::build(200, None).unwrap();
        plugin.apply_cors_headers(&mut session, &mut resp).unwrap();
        assert_eq!(
            resp.headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://trusted.example",
            "regex-matched origin must be reflected rather than emitting '*'"
        );
        assert!(resp
            .headers
            .get(header::VARY)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("origin"));

        // Credentials + regex-only config is valid because matched origins are reflected.
        let cred_cfg = PluginConfig::try_from(serde_json::json!({
            "allow_origins_by_regex": ["^https://trusted\\.example$"],
            "allow_methods": "GET",
            "allow_headers": "Content-Type",
            "allow_credential": true
        }))
        .expect("allow_credential with allow_origins_by_regex must be accepted");
        assert!(cred_cfg.compile_and_optimize().is_ok());

        // Explicit non-wildcard allow_origins continues to union with regex patterns.
        let union_cfg = PluginConfig::try_from(serde_json::json!({
            "allow_origins": "https://exact.example",
            "allow_origins_by_regex": ["^https://sub\\.example$"]
        }))
        .unwrap()
        .compile_and_optimize()
        .unwrap();
        assert!(union_cfg.is_origin_allowed("https://exact.example"));
        assert!(union_cfg.is_origin_allowed("https://sub.example"));
        assert!(!union_cfg.is_origin_allowed("https://other.example"));

        // Empty or duplicate regex lists are rejected just like timing_allow_origins_by_regex.
        assert!(PluginConfig::try_from(serde_json::json!({
            "allow_origins_by_regex": []
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "allow_origins_by_regex": ["^https://a$", "^https://a$"]
        }))
        .is_err());
    }

    #[test]
    fn allow_origins_by_metadata_is_rejected_when_nonempty() {
        let err =
            PluginConfig::try_from(serde_json::json!({ "allow_origins_by_metadata": ["foo"] }))
                .unwrap_err();
        assert!(err.to_string().contains("plugin metadata is not supported"));

        // An empty metadata list is accepted for schema compatibility.
        assert!(
            PluginConfig::try_from(serde_json::json!({ "allow_origins_by_metadata": [] })).is_ok()
        );
    }
}
