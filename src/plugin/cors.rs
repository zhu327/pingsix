use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use http::{Method, StatusCode};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::{proxy::ProxyContext, utils::request};

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "cors";

/// Creates an CORS plugin instance with the given configuration.
pub fn create_cors_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid echo plugin config")?;

    Ok(Arc::new(PluginCors { config }))
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    /// you can use '*' to allow all origins when no credentials,
    /// '**' to allow forcefully (it will bring some security risks, be carefully),
    /// multiple origin use ',' to split. default: *
    #[serde(default = "PluginConfig::default_star")]
    pub allow_origins: String,

    /// you can use '*' to allow all methods when no credentials,
    /// '**' to allow forcefully (it will bring some security risks, be carefully),
    /// multiple method use ',' to split. default: *
    #[serde(default = "PluginConfig::default_star")]
    pub allow_methods: String,

    /// you can use '*' to allow all headers when no credentials,
    /// '**' to allow forcefully (it will bring some security risks, be carefully),
    /// multiple header use ',' to split. default: *
    #[serde(default = "PluginConfig::default_star")]
    pub allow_headers: String,

    /// multiple header use ',' to split.
    /// If not specified, no custom headers are exposed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expose_headers: Option<String>,

    /// maximum number of seconds the results can be cached.
    /// -1 means no cached, the max value is depend on browser,
    /// more details plz check MDN. default: 5
    #[serde(default = "PluginConfig::default_max_age")]
    pub max_age: i32,

    /// allow client append credential. according to CORS specification,
    /// if you set this option to 'true', you can not use '*' for other options.
    #[serde(default)]
    pub allow_credential: bool,

    /// you can use regex to allow specific origins when no credentials,
    /// e.g., [.*\\.test.com$] to allow a.test.com and b.test.com
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

    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_origins == "*" {
            return true;
        }

        let allowed_set: HashSet<_> = self.allow_origins.split(',').map(str::trim).collect();

        if allowed_set.contains(origin) {
            return true;
        }

        if let Some(regex_list) = &self.allow_origins_by_regex {
            for re in regex_list {
                if let Ok(re) = Regex::new(re) {
                    if re.is_match(origin) {
                        return true;
                    }
                }
            }
        }

        false
    }
}

pub struct PluginCors {
    config: PluginConfig,
}

impl PluginCors {
    fn apply_cors_headers(&self, session: &mut Session, resp: &mut ResponseHeader) -> Result<()> {
        let origin = request::get_req_header_value(session.req_header(), "Origin");
        if origin.is_none() {
            return Ok(());
        }

        let origin = origin.unwrap();
        if !self.config.is_origin_allowed(origin) {
            return Ok(());
        }

        resp.insert_header("access-control-allow-origin", origin)?;
        if self.config.allow_credential {
            resp.insert_header("access-control-allow-credentials", "true")?;
        }

        let methods = if self.config.allow_methods == "**" {
            "GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD".to_string()
        } else {
            self.config.allow_methods.clone()
        };
        resp.insert_header("access-control-allow-methods", methods)?;

        let headers = if self.config.allow_headers == "**" {
            request::get_req_header_value(session.req_header(), "access-control-request-headers")
                .unwrap_or_default()
                .to_string()
        } else {
            self.config.allow_headers.clone()
        };
        resp.insert_header("access-control-allow-headers", headers)?;

        resp.insert_header("access-control-max-age", self.config.max_age.to_string())?;

        if let Some(expose) = &self.config.expose_headers {
            resp.insert_header("access-control-expose-headers", expose)?;
        }

        if self.config.allow_origins != "*" {
            resp.insert_header("vary", "Origin")?;
        }

        Ok(())
    }
}

#[async_trait]
impl ProxyPlugin for PluginCors {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        4000
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        // 如果是options请求，直接返回，并设置好请求头
        if session.req_header().method == Method::OPTIONS {
            let mut resp = ResponseHeader::build(StatusCode::NO_CONTENT, None)?;
            self.apply_cors_headers(session, &mut resp)?;
            session.write_response_header(Box::new(resp), true).await?;
            return Ok(true);
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
