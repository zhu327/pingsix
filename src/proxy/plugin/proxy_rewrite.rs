use std::sync::Arc;

use async_trait::async_trait;
use http::Uri;
use pingora_error::{
    ErrorType::{InternalError, ReadError},
    OrErr, Result,
};
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::proxy::ProxyContext;

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "proxy-rewrite";

pub fn create_proxy_rewrite_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid echo plugin config")?;

    Ok(Arc::new(PluginProxyRewrite { config }))
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct Head {
    name: String,
    value: String,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct Headers {
    #[serde(default)]
    add: Vec<Head>,
    #[serde(default)]
    set: Vec<Head>,
    #[serde(default)]
    remove: Vec<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    headers: Option<Headers>,
}

pub struct PluginProxyRewrite {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginProxyRewrite {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        1008
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        if let Some(ref path) = self.config.uri {
            let mut parts = session.req_header().uri.clone().into_parts();

            let path_and_query = match parts.path_and_query {
                Some(pq) => {
                    let query = pq.query().unwrap_or("");
                    format!("{}?{}", path, query).parse().ok()
                }
                None => Some(path.to_string().parse().unwrap()),
            };

            parts.path_and_query = path_and_query;

            let uri = Uri::from_parts(parts).or_err_with(InternalError, || "Invalid uri")?;
            upstream_request.set_uri(uri);
        }

        if let Some(ref method) = self.config.method {
            upstream_request.set_method(
                method
                    .as_bytes()
                    .try_into()
                    .or_err_with(InternalError, || "Invalid method")?,
            );
        }

        if let Some(ref host) = self.config.host {
            upstream_request
                .insert_header(http::header::HOST, host)
                .or_err_with(InternalError, || "Invalid host")?;
        }

        if let Some(headers) = self.config.headers.clone() {
            for head in headers.set {
                upstream_request
                    .insert_header(head.name, head.value.as_str())
                    .or_err_with(InternalError, || "Invalid header")?;
            }

            for name in headers.remove.iter() {
                upstream_request.remove_header(name);
            }

            for head in headers.add {
                upstream_request
                    .append_header(head.name, head.value.as_str())
                    .or_err_with(InternalError, || "Invalid header")?;
            }
        }

        Ok(())
    }
}
