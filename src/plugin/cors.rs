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

    // Pre-compile regex patterns and create optimized config
    let compiled_config = config.compile_and_optimize()?;

    Ok(Arc::new(PluginCors {
        config: compiled_config,
    }))
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

    fn compile_and_optimize(self) -> Result<OptimizedPluginConfig> {
        // Pre-compile regex patterns
        let compiled_regexes = if let Some(regex_list) = &self.allow_origins_by_regex {
            let compiled: Vec<Arc<Regex>> = regex_list
                .iter()
                .map(|re| {
                    Regex::new(re)
                        .map(Arc::new)
                        .or_err_with(ReadError, || format!("Invalid regex: {re}"))
                })
                .collect::<Result<Vec<_>>>()?;
            Some(compiled)
        } else {
            None
        };

        // Pre-compile allowed origins set for faster lookup
        let allow_origins_set = if self.allow_origins != "*" && self.allow_origins != "**" {
            Some(
                self.allow_origins
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<HashSet<String>>(),
            )
        } else {
            None
        };

        Ok(OptimizedPluginConfig {
            allow_origins: self.allow_origins,
            allow_methods: self.allow_methods,
            allow_headers: self.allow_headers,
            expose_headers: self.expose_headers,
            max_age: self.max_age,
            allow_credential: self.allow_credential,
            allow_origins_by_regex: compiled_regexes,
            allow_origins_set,
        })
    }
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
}

impl OptimizedPluginConfig {
    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_origins.is_empty() {
            return false;
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

        // Check regex patterns if available
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
    config: OptimizedPluginConfig,
}

impl PluginCors {
    fn apply_cors_headers(&self, session: &mut Session, resp: &mut ResponseHeader) -> Result<()> {
        let origin = request::get_req_header_value(session.req_header(), header::ORIGIN.as_str())
            .map(|s| s.to_string());

        if let Some(origin) = origin {
            if self.config.is_origin_allowed(&origin) {
                self.apply_cors_headers_with_origin(session, resp, &origin)?;
            }
        }
        Ok(())
    }

    fn apply_cors_headers_with_origin(
        &self,
        session: &mut Session,
        resp: &mut ResponseHeader,
        origin: &str,
    ) -> Result<()> {
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

        Ok(())
    }

    fn handle_options_request(&self, session: &mut Session) -> Result<Option<ResponseHeader>> {
        let origin = request::get_req_header_value(session.req_header(), header::ORIGIN.as_str())
            .map(|s| s.to_string());

        match origin {
            Some(origin) if self.config.is_origin_allowed(&origin) => {
                let mut resp = ResponseHeader::build(StatusCode::NO_CONTENT, None)?;
                self.apply_cors_headers_with_origin(session, &mut resp, &origin)?;
                Ok(Some(resp))
            }
            _ => Ok(None),
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
