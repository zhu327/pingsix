use std::{fmt::Write as _, sync::Arc};

use async_trait::async_trait;
use http::{header, uri::Scheme, StatusCode, Uri};
use ipnetwork::IpNetwork;
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::utils::request::{
    get_direct_client_ip, render_template, resolve_var, session_is_tls, TemplateOptions,
};
use crate::{
    core::{
        apply_regex_uri_template, FilterVerdict, ProxyContext, ProxyError, ProxyPlugin,
        ProxyResult, Rejection,
    },
    plugins::config::parse_and_validate_plugin_config,
};

pub const PLUGIN_NAME: &str = "redirect";
const PRIORITY: i32 = 900;

pub fn create_redirect_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;

    // Precompile regex patterns for regex_uri to improve performance
    let mut regex_patterns = Vec::new();
    for i in (0..config.regex_uri.len()).step_by(2) {
        let pattern = &config.regex_uri[i];
        let template = &config.regex_uri[i + 1];
        // Validation ensures regex is valid; propagate error if it somehow isn't
        let re = Regex::new(pattern).map_err(|e| {
            ProxyError::Plugin(format!("Invalid redirect regex pattern '{pattern}': {e}"))
        })?;
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

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators (the `regex_uri` compile and `trusted_proxies` network parse)
/// WITHOUT constructing the plugin.
pub fn validate_redirect_config(cfg: &JsonValue) -> ProxyResult<()> {
    let config = PluginConfig::try_from(cfg.clone())?;
    for i in (0..config.regex_uri.len()).step_by(2) {
        let pattern = &config.regex_uri[i];
        Regex::new(pattern).map_err(|e| {
            ProxyError::Plugin(format!("Invalid redirect regex pattern '{pattern}': {e}"))
        })?;
    }
    for network in &config.trusted_proxies {
        network.parse::<IpNetwork>().map_err(|e| {
            ProxyError::validation_error(format!(
                "Invalid trusted_proxies network '{network}': {e}"
            ))
        })?;
    }
    Ok(())
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
    #[serde(default)]
    #[validate(custom(function = "PluginConfig::validate_regex_uri"))]
    regex_uri: Vec<String>,
    /// HTTP status code for the redirect (e.g., 301, 302, 307, 308). Defaults to 302 (temporary redirect).
    #[serde(default = "PluginConfig::default_ret_code")]
    #[validate(range(min = 200, max = 599))]
    ret_code: u16,
    /// If true, appends the original query string to the redirect URI, even if the target URI has a query string.
    #[serde(default)]
    append_query_string: bool,
    /// If true, percent-encode the rewritten path part of the redirect URI.
    /// Existing percent-encoded sequences and `/` are preserved.
    #[serde(default)]
    encode_uri: bool,
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
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid redirect plugin config")?;

        let has_action =
            config.http_to_https || config.uri.is_some() || !config.regex_uri.is_empty();
        if !has_action {
            return Err(ProxyError::validation_error(
                "redirect plugin requires one of 'http_to_https', 'uri', or 'regex_uri'",
            ));
        }

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

        if let Some(host) = config.redirect_host.as_deref().map(str::trim) {
            if !host.is_empty() && host.parse::<http::uri::Authority>().is_err() {
                return Err(ProxyError::validation_error(format!(
                    "redirect_host '{host}' is not a valid HTTP authority"
                )));
            }
        }

        if let Some(uri) = &config.uri {
            if uri.len() < 2 {
                return Err(ProxyError::validation_error(
                    "redirect uri must be at least 2 characters",
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
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        if self.config.http_to_https && self.needs_https_redirect(session) {
            return self.redirect_https(session).await;
        }

        if let Some(new_uri) = self.construct_uri(session).await {
            return self.redirect_response(new_uri);
        }

        Ok(FilterVerdict::Continue)
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

    async fn redirect_https(&self, session: &mut Session) -> Result<FilterVerdict> {
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

        self.redirect_response(new_uri)
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
            let expanded = expand_uri_template(path, session);
            return self.build_uri_from_path(&expanded, parts, original_query);
        }

        if !self.regex_patterns.is_empty() {
            return self.build_uri_from_regex(parts, original_query);
        }

        None
    }

    fn build_uri_from_path(
        &self,
        path: &str,
        parts: http::uri::Parts,
        original_query: &str,
    ) -> Option<Uri> {
        self.build_redirect_target(path, parts, original_query)
    }

    fn build_uri_from_regex(
        &self,
        mut parts: http::uri::Parts,
        original_query: &str,
    ) -> Option<Uri> {
        let pq = parts.path_and_query.take()?;
        let rewritten = apply_regex_uri_template(pq.path(), &self.regex_patterns);
        self.build_redirect_target(&rewritten, parts, original_query)
    }

    /// Build a redirect target URI from either an absolute URL
    /// (`scheme://authority[/path][?query]`) or an origin-form path
    /// (`/path[?query]`).
    fn build_redirect_target(
        &self,
        target: &str,
        mut parts: http::uri::Parts,
        original_query: &str,
    ) -> Option<Uri> {
        let (before_query, target_query) = target.split_once('?').unwrap_or((target, ""));
        let new_query = Self::merge_query_string(
            target_query,
            original_query,
            self.config.append_query_string,
        );

        if let Some((scheme_str, rest)) = before_query.split_once("://") {
            let (authority_str, raw_path) = match rest.find('/') {
                Some(idx) => (&rest[..idx], &rest[idx..]),
                None => (rest, "/"),
            };
            let new_path = if self.config.encode_uri {
                encode_uri_safe_path(raw_path)
            } else {
                raw_path.to_string()
            };
            let new_path_and_query = if new_query.is_empty() {
                new_path
            } else {
                format!("{new_path}?{new_query}")
            };
            let scheme = http::uri::Scheme::try_from(scheme_str).ok()?;
            let authority = http::uri::Authority::try_from(authority_str).ok()?;
            let path_and_query = new_path_and_query.parse::<http::uri::PathAndQuery>().ok()?;
            return Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(path_and_query)
                .build()
                .ok();
        }

        let new_path = if self.config.encode_uri {
            encode_uri_safe_path(before_query)
        } else {
            before_query.to_string()
        };
        let new_path_and_query = if new_query.is_empty() {
            new_path
        } else {
            format!("{new_path}?{new_query}")
        };

        parts.path_and_query = Some(new_path_and_query.parse().ok()?);
        Uri::from_parts(parts).ok()
    }

    /// The redirect as a rejection value (the pipeline writes it through
    /// the shared exit helper: `Location`, `text/plain`, empty body).
    fn redirect_response(&self, new_uri: Uri) -> Result<FilterVerdict> {
        let status_code = StatusCode::from_u16(self.config.ret_code).unwrap_or(StatusCode::FOUND); // Fallback to 302 if invalid
                                                                                                   // Content-Type travels as a plain header (not `content_type`) so it
                                                                                                   // is emitted even though the redirect body is empty, matching the
                                                                                                   // historical response shape (`text/plain`, `Content-Length: 0`).
        Ok(FilterVerdict::Reject(
            Rejection::new(status_code)
                .with_header(header::LOCATION.as_str(), new_uri.to_string())
                .with_header(header::CONTENT_TYPE.as_str(), "text/plain"),
        ))
    }
}

fn session_has_tls(session: &Session) -> bool {
    session_is_tls(session)
}

/// Percent-encode a URI path without touching unreserved characters, `/`, or
/// already-encoded `%XX` sequences.
fn encode_uri_safe_path(path: &str) -> String {
    fn is_hex_digit(byte: u8) -> bool {
        byte.is_ascii_hexdigit()
    }

    let bytes = path.as_bytes();
    let mut encoded = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            encoded.push(byte as char);
            index += 1;
        } else if byte == b'%'
            && bytes.len() >= index + 3
            && is_hex_digit(bytes[index + 1])
            && is_hex_digit(bytes[index + 2])
        {
            encoded.push('%');
            encoded.push(bytes[index + 1] as char);
            encoded.push(bytes[index + 2] as char);
            index += 3;
        } else {
            write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
            index += 1;
        }
    }
    encoded
}

/// Expand APISIX nginx-style `$name` / `${name}` variables in a redirect URI
/// template with the shared request-phase variable registry. Escaped `\$`
/// stays a literal `$`; unknown variables expand to an empty string.
///
/// `scheme` needs the connection's TLS state when the URI is origin-form;
/// [`resolve_var`] derives it from the session itself.
fn expand_uri_template(template: &str, session: &Session) -> String {
    render_template(
        template,
        TemplateOptions {
            escape_dollar: true,
        },
        |name| resolve_var(session, name).into_owned(),
    )
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

    use crate::utils::{request::apisix_key, testing::session_from_request};
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
        rh.set_uri(absolute_uri.parse().unwrap());
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

    #[test]
    fn empty_config_is_rejected_by_oneof() {
        let err = PluginConfig::try_from(serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("http_to_https"));

        let err = PluginConfig::try_from(serde_json::json!({
            "http_to_https": false,
            "regex_uri": []
        }))
        .unwrap_err();
        assert!(err.to_string().contains("http_to_https"));
    }

    #[test]
    fn each_oneof_branch_alone_is_valid() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "http_to_https": true,
            "redirect_host": "secure.example.com"
        }))
        .is_ok());
        assert!(PluginConfig::try_from(serde_json::json!({ "uri": "/new" })).is_ok());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "regex_uri": ["^/old$", "/new"] })).is_ok()
        );
    }

    #[test]
    fn encode_uri_safe_path_keeps_unreserved_and_percent_sequences() {
        assert_eq!(encode_uri_safe_path("/a b"), "/a%20b");
        assert_eq!(encode_uri_safe_path("/a%20b"), "/a%20b");
        assert_eq!(encode_uri_safe_path("/café"), "/caf%C3%A9");
        assert_eq!(encode_uri_safe_path("/a-b_c.d~e"), "/a-b_c.d~e");
        assert_eq!(encode_uri_safe_path("/%zz"), "/%25zz");
    }

    #[tokio::test]
    async fn expand_uri_template_resolves_request_vars_and_keeps_escaped_dollar() {
        // `$name` / `${name}` equivalence, `\$` -> literal `$`, unknown -> "".
        let session =
            session_from_request("POST /p?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        assert_eq!(
            expand_uri_template(
                "$host$request_uri-$uri-${scheme}-${request_method}-$unknown-\\$host",
                &session,
            ),
            "example.com/p?q=1-/p-http-POST--$host"
        );
    }

    /// Wire a session over a real loopback TCP pair so the session digest
    /// carries a real peer address (`$remote_addr` / `$remote_port`).
    #[cfg(unix)]
    async fn tcp_session(raw: &str) -> (Session, std::net::SocketAddr) {
        use pingora_core::protocols::l4::stream::Stream;
        use pingora_core::protocols::{GetSocketDigest, SocketDigest, IO};
        use std::os::unix::io::AsRawFd;
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let client_addr = client.local_addr().unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client.write_all(raw.as_bytes()).await.unwrap();

        let raw_fd = server.as_raw_fd();
        let mut stream = Stream::from(server);
        stream.set_socket_digest(SocketDigest::from_raw_fd(raw_fd));
        let mut session = Session::new_h1(Box::new(stream) as Box<dyn IO>);
        session
            .downstream_session
            .read_request()
            .await
            .expect("loopback request parses");
        (session, client_addr)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expand_uri_template_resolves_connection_and_selector_vars() {
        // Intended T5 gains: `$remote_addr`, `$remote_port`, `arg_*` and
        // `http_*` previously expanded to "" in redirect templates.
        let wire = "GET /p?a=q1 HTTP/1.1\r\nHost: example.com\r\nX-K: v1\r\n\r\n";
        let (session, client_addr) = tcp_session(wire).await;
        assert_eq!(
            expand_uri_template("$remote_addr:$remote_port:$arg_a:$http_x_k", &session),
            format!("{}:{}:q1:v1", client_addr.ip(), client_addr.port(),)
        );
        assert_eq!(client_addr.ip().to_string(), "127.0.0.1");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn expand_uri_template_scheme_falls_back_to_connection_tls_state() {
        // Origin-form URI + plaintext loopback connection -> "http".
        let (session, _) = tcp_session("GET /p HTTP/1.1\r\nHost: t\r\n\r\n").await;
        assert_eq!(expand_uri_template("$scheme", &session), "http");
    }

    #[tokio::test]
    async fn redirect_host_var_matches_apisix_key_precedence() {
        // Host precedence parity: URI authority wins over the Host header in
        // both the redirect template and the APISIX limiter-key path.
        let wire = "GET /p?a=1 HTTP/1.1\r\nHost: header.example:9090\r\n\r\n";
        let mut for_redirect = session_from_request(wire).await;
        for_redirect
            .req_header_mut()
            .set_uri("http://uri.example:8080/p?a=1".parse().unwrap());
        let mut for_key = session_from_request(wire).await;
        for_key
            .req_header_mut()
            .set_uri("http://uri.example:8080/p?a=1".parse().unwrap());

        let redirect_host = expand_uri_template("$host", &for_redirect);
        let key_host = apisix_key(&mut for_key, "host", false);
        assert_eq!(redirect_host, key_host.as_ref());
        assert_eq!(redirect_host, "uri.example");
    }

    #[tokio::test]
    async fn absolute_url_uri_and_regex_redirects_succeed() {
        let plugin = PluginRedirect {
            config: PluginConfig::try_from(serde_json::json!({
                "uri": "https://new.example.com/login?next=1",
                "append_query_string": true
            }))
            .unwrap(),
            regex_patterns: vec![],
            trusted_proxies: vec![],
        };
        let mut session =
            session_from_request("GET /old?from=home HTTP/1.1\r\nHost: old.example.com\r\n\r\n")
                .await;
        let target = plugin
            .construct_uri(&mut session)
            .await
            .expect("absolute URL redirect must build a valid Uri");
        assert_eq!(
            target.to_string(),
            "https://new.example.com/login?next=1&from=home"
        );

        let regex_cfg = PluginConfig::try_from(serde_json::json!({
            "regex_uri": ["^/assets/(.*)$", "https://cdn.example.com/$1"]
        }))
        .unwrap();
        let regex_plugin = PluginRedirect {
            regex_patterns: vec![(
                Regex::new("^/assets/(.*)$").unwrap(),
                "https://cdn.example.com/$1".to_string(),
            )],
            config: regex_cfg,
            trusted_proxies: vec![],
        };
        let mut session =
            session_from_request("GET /assets/app.js HTTP/1.1\r\nHost: old.example.com\r\n\r\n")
                .await;
        let target = regex_plugin
            .construct_uri(&mut session)
            .await
            .expect("absolute regex_uri redirect must build a valid Uri");
        assert_eq!(target.to_string(), "https://cdn.example.com/app.js");
    }

    #[test]
    fn invalid_ret_code_and_redirect_host_are_rejected() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "ret_code": 9999
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "http_to_https": true,
            "redirect_host": "https://bad.example.com/path"
        }))
        .is_err());
    }
}
