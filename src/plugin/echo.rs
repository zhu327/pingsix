use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use http::{header, StatusCode};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

pub const PLUGIN_NAME: &str = "echo";
const PRIORITY: i32 = 412;

/// Creates an Echo plugin instance with the given configuration.
pub fn create_echo_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginEcho { config }))
}

/// Configuration for the Echo plugin.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    /// The response body to be sent back in the HTTP response.
    body: String,

    /// Additional HTTP headers to include in the response.
    /// Keys are header names, and values are header values.
    #[serde(default)]
    headers: HashMap<String, String>,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid echo plugin config", e))
    }
}

/// Echo plugin implementation.
pub struct PluginEcho {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginEcho {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let mut resp = ResponseHeader::build(StatusCode::OK, None)?;

        // Insert headers from the config
        for (k, v) in &self.config.headers {
            resp.insert_header(k.clone(), v.clone())?;
        }

        // Insert Content-Length header
        resp.insert_header(header::CONTENT_LENGTH, self.config.body.len().to_string())?;

        // Write response header to the session
        session.write_response_header(Box::new(resp), false).await?;

        // Write response body to the session
        session
            .write_response_body(Some(self.config.body.clone().into()), true)
            .await?;

        Ok(true)
    }
}
