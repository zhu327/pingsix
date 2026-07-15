use std::sync::Arc;

use async_trait::async_trait;
use http::{header, uri::Scheme, StatusCode, Uri};
use ipnetwork::IpNetwork;
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::core::{apply_regex_uri_template, ProxyContext, ProxyError, ProxyPlugin, ProxyResult};
use crate::utils::request::get_direct_client_ip;

pub const PLUGIN_NAME: &str = "redirect";
const PRIORITY: i32 = 900;

pub fn create_redirect_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;

    // Precompile regex patterns for regex_uri to improve performance
    let mut regex_patterns = Vec::new();
    for i in (0..config.regex_uri.len()).step_by(2) {
        let pattern = &config.regex_uri[i];
        let template = &config.regex_uri[i + 1];
        // Validation ensures regex is valid, so expect is safe
        let re = Regex::new(pattern).expect("Regex validation should ensure this pattern is valid");
        regex_patterns.push((re, template.clone()));
    }

    let trusted_proxies = config
        .trusted_proxies
        .iter()
        .map(|s| {
            s.parse::<IpNetwork>().map_err(|e| {
                ProxyError::validation_error(format!("Invalid trusted_proxies network '{s}': {e}"))
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(Arc::new(PluginRedirect {
        config,
        regex_patterns,
        trusted_proxies,
    }))
}

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// If true, redirects HTTP requests to HTTPS. Takes precedence over `uri` and `regex_uri`.
    ///
    /// The redirect triggers when the request is not already over HTTPS:
    /// - Absolute-form URI with `http` scheme → redirect.
    /// - Absolute-form URI with `https` scheme → no redirect.
    /// - Downstream TLS session (`ssl_digest` present) → no redirect.
    /// - Origin-form URI (no scheme): redirect unless a trusted proxy sent
    ///   `X-Forwarded-Proto: https`. Client-supplied XFP is ignored unless the
    ///   immediate peer is listed in `trusted_proxies`.
    ///
    /// When `http_to_https` is true, `redirect_host` is required so Location
    /// cannot be influenced by a forged Host header.
    #[serde(default)]
    http_to_https: bool,
    /// The URI to redirect to. Takes precedence over `regex_uri` if both are set.
    uri: Option<String>,
    /// List of regex pattern and replacement template pairs for URI rewriting.
    #[validate(custom(function = "PluginConfig::validate_regex_uri"))]
    regex_uri: Vec<String>,
    /// HTTP status code for the redirect (e.g., 301, 302, 307, 308). Defaults to 302 (temporary redirect).
    #[serde(default = "PluginConfig::default_ret_code")]
    ret_code: u16,
    /// If true, appends the original query string to the redirect URI, even if the target URI has a query string.
    #[serde(default)]
    append_query_string: bool,
    /// Fixed host for the HTTPS redirect Location. Required when `http_to_https`
    /// is true. Prevents host-header injection into the Location header.
    redirect_host: Option<String>,
    /// CIDR/IP networks whose immediate peer address may be trusted for
    /// `X-Forwarded-Proto`. Empty (default) means XFP is never trusted.
    #[serde(default)]
    trusted_proxies: Vec<String>,
}

impl PluginConfig {
    fn default_ret_code() -> u16 {
        302 // Default to temporary redirect (FOUND)
    }

    fn validate_regex_uri(regex_uri: &[String]) -> Result<(), ValidationError> {
        if !regex_uri.len().is_multiple_of(2) {
            return Err(ValidationError::new("regex_uri_length"));
        }

        regex_uri
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .map(|(_, pattern)| {
                Regex::new(pattern).map_err(|_| ValidationError::new("invalid_regex"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid redirect plugin config", e))?;

        config.validate()?;

        if config.http_to_https {
            let host = config.redirect_host.as_deref().map(str::trim).unwrap_or("");
            if host.is_empty() {
                return Err(ProxyError::Configuration(
                    "redirect plugin: http_to_https requires redirect_host \
                     (do not fall back to the request Host header)"
                        .into(),
                ));
            }
        }

        Ok(config)
    }
}

pub struct PluginRedirect {
    config: PluginConfig,
    regex_patterns: Vec<(Regex, String)>, // Precompiled regex and template pairs
    trusted_proxies: Vec<IpNetwork>,
}

#[async_trait]
impl ProxyPlugin for PluginRedirect {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        if self.config.http_to_https && self.needs_https_redirect(session) {
            return self.redirect_https(session).await;
        }

        if let Some(new_uri) = self.construct_uri(session).await {
            return self.send_redirect_response(session, new_uri).await;
        }

        Ok(false)
    }
}

impl PluginRedirect {
    fn merge_query_string(
        target_query: &str,
        original_query: &str,
        append_query_string: bool,
    ) -> String {
        if append_query_string {
            if target_query.is_empty() {
                original_query.to_string()
            } else if original_query.is_empty() || target_query == original_query {
                target_query.to_string()
            } else {
                format!("{target_query}&{original_query}")
            }
        } else {
            target_query.to_string()
        }
    }

    fn needs_https_redirect(&self, session: &Session) -> bool {
        // Real downstream TLS: never redirect based on client headers.
        if session_has_tls(session) {
            return false;
        }

        let trust_xff = self.is_trusted_proxy_peer(session);
        req_header_needs_https_redirect(session.req_header(), trust_xff)
    }

    fn is_trusted_proxy_peer(&self, session: &Session) -> bool {
        if self.trusted_proxies.is_empty() {
            return false;
        }
        let Some(ip) = get_direct_client_ip(session) else {
            return false;
        };
        self.trusted_proxies.iter().any(|net| net.contains(ip))
    }

    async fn redirect_https(&self, session: &mut Session) -> Result<bool> {
        let current_uri = session.req_header().uri.clone();

        // redirect_host is required for http_to_https (validated at config load).
        let authority = self
            .config
            .redirect_host
            .as_ref()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .ok_or_else(|| {
                ProxyError::Internal(
                    "redirect_host missing for http_to_https (should have been rejected at load)"
                        .into(),
                )
            })?;

        let path_and_query = current_uri
            .path_and_query()
            .ok_or_else(|| ProxyError::Internal("Missing path and query in URI".to_string()))?
            .to_owned();

        let new_uri = Uri::builder()
            .scheme(Scheme::HTTPS)
            .authority(authority)
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| ProxyError::Internal(format!("Failed to build HTTPS URI: {e}")))?;

        self.send_redirect_response(session, new_uri).await
    }

    async fn construct_uri(&self, session: &mut Session) -> Option<Uri> {
        // Extract original query string directly from the URI to avoid borrowing parts
        let original_query = session
            .req_header()
            .uri
            .path_and_query()
            .and_then(|pq| pq.query())
            .unwrap_or("");
        let parts = session.req_header().uri.clone().into_parts();

        if let Some(ref path) = self.config.uri {
            return self.build_uri_from_path(path, parts, original_query);
        }

        if !self.regex_patterns.is_empty() {
            return self.build_uri_from_regex(parts, original_query);
        }

        None
    }

    fn build_uri_from_path(
        &self,
        path: &str,
        mut parts: http::uri::Parts,
        original_query: &str,
    ) -> Option<Uri> {
        let target_query = path
            .parse::<Uri>()
            .ok()
            .and_then(|uri| uri.query().map(|q| q.to_string()))
            .unwrap_or_default();
        let new_path = path.split('?').next().unwrap_or(path);
        let new_query = Self::merge_query_string(
            &target_query,
            original_query,
            self.config.append_query_string,
        );

        let new_path_and_query = if new_query.is_empty() {
            new_path.to_string()
        } else {
            format!("{new_path}?{new_query}")
        };

        parts.path_and_query = Some(new_path_and_query.parse().ok()?);
        Uri::from_parts(parts).ok()
    }

    fn build_uri_from_regex(
        &self,
        mut parts: http::uri::Parts,
        original_query: &str,
    ) -> Option<Uri> {
        if let Some(pq) = parts.path_and_query.take() {
            let path = pq.path();
            let rewritten = apply_regex_uri_template(path, &self.regex_patterns);
            let (new_path, target_query) = rewritten
                .split_once('?')
                .map_or_else(|| (rewritten.as_ref(), ""), |(p, q)| (p, q));
            let new_query = Self::merge_query_string(
                target_query,
                original_query,
                self.config.append_query_string,
            );

            let new_uri = if new_query.is_empty() {
                new_path.to_string()
            } else {
                format!("{new_path}?{new_query}")
            };
            parts.path_and_query = Some(new_uri.parse().ok()?);
            Uri::from_parts(parts).ok()
        } else {
            None
        }
    }

    async fn send_redirect_response(&self, session: &mut Session, new_uri: Uri) -> Result<bool> {
        let status_code = StatusCode::from_u16(self.config.ret_code).unwrap_or(StatusCode::FOUND); // Fallback to 302 if invalid
        let mut res_headers = ResponseHeader::build(status_code, Some(1))?;
        res_headers.append_header(header::LOCATION, new_uri.to_string())?;
        res_headers.append_header(header::CONTENT_TYPE, "text/plain")?;
        res_headers.append_header(header::CONTENT_LENGTH, 0)?;

        session
            .write_response_header(Box::new(res_headers), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from_static(b"")), true)
            .await?;
        Ok(true)
    }
}

fn session_has_tls(session: &Session) -> bool {
    session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some()
}

/// Determine whether an HTTP request header should trigger an HTTPS redirect.
///
/// - Absolute-form URI with `https` scheme → no redirect.
/// - Absolute-form URI with `http` scheme → redirect.
/// - Origin-form URI (no scheme): redirect unless `trust_xff` is true and
///   `X-Forwarded-Proto: https` is present.
fn req_header_needs_https_redirect(req: &RequestHeader, trust_xff: bool) -> bool {
    match req.uri.scheme() {
        Some(s) if s.as_str() == "https" => false,
        Some(s) if s.as_str() == "http" => true,
        _ => {
            if !trust_xff {
                return true;
            }
            !req.headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("https"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    use pingora_http::RequestHeader;

    fn ip_is_trusted(ip: IpAddr, trusted: &[IpNetwork]) -> bool {
        trusted.iter().any(|net| net.contains(ip))
    }

    fn make_req_header(
        method: &'static str,
        target: &'static [u8],
        headers: Vec<(&'static str, &'static str)>,
    ) -> RequestHeader {
        let mut rh = RequestHeader::build(method, target, Some(headers.len())).unwrap();
        for (name, value) in headers {
            rh.insert_header(name, value).unwrap();
        }
        rh
    }

    /// Build a RequestHeader with an absolute-form URI (preserving scheme).
    /// `RequestHeader::build` may strip the scheme for HTTP/1.1 origin-form,
    /// so we set the URI directly for absolute URI tests.
    fn make_req_header_absolute_uri(
        method: &'static str,
        absolute_uri: &'static str,
        headers: Vec<(&'static str, &'static str)>,
    ) -> RequestHeader {
        let mut rh = RequestHeader::build(method, b"/", Some(headers.len())).unwrap();
        rh.uri = absolute_uri.parse().unwrap();
        for (name, value) in headers {
            rh.insert_header(name, value).unwrap();
        }
        rh
    }

    #[test]
    fn merge_query_string_does_not_duplicate_same_query() {
        let merged = PluginRedirect::merge_query_string("a=1", "a=1", true);
        assert_eq!(merged, "a=1");
    }

    #[test]
    fn merge_query_string_appends_when_different() {
        let merged = PluginRedirect::merge_query_string("b=2", "a=1", true);
        assert_eq!(merged, "b=2&a=1");
    }

    // --- req_header_needs_https_redirect tests ---

    #[test]
    fn absolute_http_scheme_triggers_redirect() {
        let rh = make_req_header_absolute_uri("GET", "http://example.com/path", vec![]);
        assert!(req_header_needs_https_redirect(&rh, false));
        assert!(req_header_needs_https_redirect(&rh, true));
    }

    #[test]
    fn absolute_https_scheme_skips_redirect() {
        let rh = make_req_header_absolute_uri("GET", "https://example.com/path", vec![]);
        assert!(!req_header_needs_https_redirect(&rh, false));
    }

    #[test]
    fn origin_form_no_header_triggers_redirect() {
        let rh = make_req_header("GET", b"/path", vec![("host", "example.com")]);
        assert!(req_header_needs_https_redirect(&rh, false));
    }

    #[test]
    fn origin_form_untrusted_x_forwarded_proto_https_still_redirects() {
        // Client-controlled XFP must not bypass redirect when peer is untrusted.
        let rh = make_req_header(
            "GET",
            b"/path",
            vec![("host", "example.com"), ("x-forwarded-proto", "https")],
        );
        assert!(req_header_needs_https_redirect(&rh, false));
    }

    #[test]
    fn origin_form_trusted_x_forwarded_proto_https_skips_redirect() {
        let rh = make_req_header(
            "GET",
            b"/path",
            vec![("host", "example.com"), ("x-forwarded-proto", "https")],
        );
        assert!(!req_header_needs_https_redirect(&rh, true));
    }

    #[test]
    fn origin_form_trusted_x_forwarded_proto_http_triggers_redirect() {
        let rh = make_req_header(
            "GET",
            b"/path",
            vec![("host", "example.com"), ("x-forwarded-proto", "http")],
        );
        assert!(req_header_needs_https_redirect(&rh, true));
    }

    #[test]
    fn trusted_proxy_cidr_matches() {
        let nets: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(ip_is_trusted("10.1.2.3".parse().unwrap(), &nets));
        assert!(!ip_is_trusted("192.168.1.1".parse().unwrap(), &nets));
    }

    // --- redirect_host config tests ---

    #[test]
    fn http_to_https_requires_redirect_host() {
        let err = PluginConfig::try_from(serde_json::json!({
            "http_to_https": true,
            "regex_uri": []
        }))
        .unwrap_err();
        assert!(
            err.to_string().contains("redirect_host"),
            "expected redirect_host requirement, got: {err}"
        );
    }

    #[test]
    fn http_to_https_rejects_blank_redirect_host() {
        let err = PluginConfig::try_from(serde_json::json!({
            "http_to_https": true,
            "redirect_host": "   ",
            "regex_uri": []
        }))
        .unwrap_err();
        assert!(err.to_string().contains("redirect_host"));
    }

    #[test]
    fn redirect_host_parsed_from_config() {
        let cfg = PluginConfig::try_from(serde_json::json!({
            "http_to_https": true,
            "redirect_host": "secure.example.com",
            "regex_uri": []
        }))
        .unwrap();
        assert_eq!(cfg.redirect_host.as_deref(), Some("secure.example.com"));
    }

    #[test]
    fn non_https_redirect_does_not_require_redirect_host() {
        let cfg = PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "regex_uri": []
        }))
        .unwrap();
        assert!(cfg.redirect_host.is_none());
    }
}
