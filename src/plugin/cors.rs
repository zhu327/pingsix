use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use http::{header, Method, StatusCode};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use validator::{Validate, ValidationError};

use crate::{proxy::ProxyContext, utils::request};

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "cors";
const PRIORITY: i32 = 4000;

/// Creates an CORS plugin instance with the given configuration.
pub fn create_cors_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid cors plugin config")?;

    config
        .validate()
        .or_err_with(ReadError, || "Invalid cors plugin config")?;

    // Pre-compile regex patterns
    let compiled_config = config.compile_regexes()?;

    Ok(Arc::new(PluginCors {
        config: compiled_config,
    }))
}

#[derive(Debug, Serialize, Deserialize, Default, Validate)]
#[validate(schema(function = "PluginConfig::validate"))]
pub struct PluginConfig {
    /// Specifies allowed origins. Use '*' to allow all origins when no credentials are used,
    /// or '**' to forcefully allow all origins (WARNING: This poses security risks, use with caution).
    /// Multiple origins can be specified, separated by commas. Default: *
    #[serde(default = "PluginConfig::default_star")]
    #[validate(custom(function = "PluginConfig::validate_origins"))]
    pub allow_origins: String,

    /// Specifies allowed HTTP methods. Use '*' to allow all methods when no credentials are used,
    /// or '**' to forcefully allow all methods (WARNING: This poses security risks, use with caution).
    /// Multiple methods can be specified, separated by commas. Default: *
    #[serde(default = "PluginConfig::default_star")]
    #[validate(custom(function = "PluginConfig::validate_methods"))]
    pub allow_methods: String,

    /// Specifies allowed headers. Use '*' to allow all headers when no credentials are used,
    /// or '**' to forcefully allow all headers (WARNING: This poses security risks, use with caution).
    /// Multiple headers can be specified, separated by commas. Default: *
    #[serde(default = "PluginConfig::default_star")]
    #[validate(custom(function = "PluginConfig::validate_headers"))]
    pub allow_headers: String,

    /// Specifies headers to expose to the client. Multiple headers can be specified, separated by commas.
    /// If not specified, no custom headers are exposed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expose_headers: Option<String>,

    /// Maximum number of seconds the results can be cached.
    /// -1 means no caching. The maximum value depends on the browser.
    /// See MDN for more details. Default: 5
    #[serde(default = "PluginConfig::default_max_age")]
    pub max_age: i32,

    /// Allows clients to include credentials. Per CORS specification,
    /// if set to true, '*' cannot be used for other options.
    #[serde(default)]
    pub allow_credential: bool,

    /// Regular expressions to allow specific origins when no credentials are used.
    /// Example: [.*\\.test.com$] allows a.test.com and b.test.com
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_origins_by_regex: Option<Vec<String>>,
}

impl PluginConfig {
    fn default_star() -> String {
        "*".to_string()
    }

    fn default_max_age() -> i32 {
        5
    }

    fn validate(&self) -> Result<(), ValidationError> {
        if self.allow_credential && self.allow_origins == "*" {
            return Err(ValidationError::new(
                "allow_credential cannot be used with allow_origins='*'",
            ));
        }
        Ok(())
    }

    fn validate_origins(origins: &str) -> Result<(), ValidationError> {
        if origins.is_empty() {
            return Err(ValidationError::new("allow_origins cannot be empty"));
        }
        if origins != "*" && origins != "**" {
            for origin in origins.split(',').map(str::trim) {
                if origin.is_empty() {
                    return Err(ValidationError::new("allow_origins contains empty origin"));
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

    fn compile_regexes(self) -> Result<CompiledPluginConfig> {
        let compiled_regexes = if let Some(regex_list) = &self.allow_origins_by_regex {
            let compiled: Vec<Arc<Regex>> = regex_list
                .iter()
                .map(|re| {
                    Regex::new(re)
                        .map(Arc::new)
                        .or_err_with(ReadError, || format!("Invalid regex: {}", re))
                })
                .collect::<Result<Vec<_>>>()?;
            Some(compiled)
        } else {
            None
        };

        Ok(CompiledPluginConfig {
            allow_origins: self.allow_origins,
            allow_methods: self.allow_methods,
            allow_headers: self.allow_headers,
            expose_headers: self.expose_headers,
            max_age: self.max_age,
            allow_credential: self.allow_credential,
            allow_origins_by_regex: compiled_regexes,
        })
    }
}

#[derive(Debug)]
pub struct CompiledPluginConfig {
    pub allow_origins: String,
    pub allow_methods: String,
    pub allow_headers: String,
    pub expose_headers: Option<String>,
    pub max_age: i32,
    pub allow_credential: bool,
    pub allow_origins_by_regex: Option<Vec<Arc<Regex>>>,
}

impl CompiledPluginConfig {
    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_origins.is_empty() {
            return false;
        }
        if self.allow_origins == "*" || self.allow_origins == "**" {
            return true;
        }
        let allowed_set: HashSet<_> = self
            .allow_origins
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if allowed_set.contains(origin) {
            return true;
        }

        if let Some(regex_list) = &self.allow_origins_by_regex {
            for re in regex_list {
                if re.is_match(origin) {
                    return true;
                }
            }
        }

        false
    }
}

pub struct PluginCors {
    config: CompiledPluginConfig,
}

impl PluginCors {
    fn apply_cors_headers(&self, session: &mut Session, resp: &mut ResponseHeader) -> Result<()> {
        if let Some(origin) =
            request::get_req_header_value(session.req_header(), header::ORIGIN.as_str())
        {
            if !self.config.is_origin_allowed(origin) {
                return Ok(());
            }

            resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin)?;
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
            resp.insert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, headers)?;

            resp.insert_header(
                header::ACCESS_CONTROL_MAX_AGE,
                self.config.max_age.to_string(),
            )?;

            if let Some(expose) = &self.config.expose_headers {
                resp.insert_header(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose)?;
            }

            if self.config.allow_origins != "*" {
                resp.insert_header(header::VARY, "Origin")?;
            }
        }
        Ok(())
    }

    fn handle_options_request(&self, session: &mut Session) -> Result<Option<ResponseHeader>> {
        if let Some(origin) =
            request::get_req_header_value(session.req_header(), header::ORIGIN.as_str())
        {
            if !self.config.is_origin_allowed(origin) {
                return Ok(None);
            }

            let mut resp = ResponseHeader::build(StatusCode::NO_CONTENT, None)?;
            self.apply_cors_headers(session, &mut resp)?;
            Ok(Some(resp))
        } else {
            Ok(None)
        }
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

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        if session.req_header().method == Method::OPTIONS {
            if let Some(resp) = self.handle_options_request(session)? {
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }
        Ok(false)
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
