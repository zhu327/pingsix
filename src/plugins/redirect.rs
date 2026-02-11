use std::sync::Arc;

use async_trait::async_trait;
use http::{header, uri::Scheme, StatusCode, Uri};
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::core::{apply_regex_uri_template, ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

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

    Ok(Arc::new(PluginRedirect {
        config,
        regex_patterns,
    }))
}

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// If true, redirects HTTP requests to HTTPS. Takes precedence over `uri` and `regex_uri`.
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

        Ok(config)
    }
}

pub struct PluginRedirect {
    config: PluginConfig,
    regex_patterns: Vec<(Regex, String)>, // Precompiled regex and template pairs
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
        if self.config.http_to_https && session.req_header().uri.scheme() == Some(&Scheme::HTTP) {
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

    async fn redirect_https(&self, session: &mut Session) -> Result<bool> {
        let current_uri = session.req_header().uri.clone();
        let authority = get_request_authority(session.req_header())
            .ok_or_else(|| ProxyError::Internal("Missing host authority".to_string()))?;

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
                .map_or_else(|| (rewritten.as_str(), ""), |(p, q)| (p, q));
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

fn get_request_authority(header: &RequestHeader) -> Option<String> {
    if let Some(authority) = header.uri.authority() {
        let authority = authority.as_str().trim();
        if !authority.is_empty() {
            return Some(authority.to_string());
        }
    }

    if let Some(host_header_value) = header.headers.get(header::HOST) {
        if let Ok(host_str) = host_header_value.to_str() {
            let host_str = host_str.trim();
            if !host_str.is_empty() {
                return Some(host_str.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::PluginRedirect;

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
}
