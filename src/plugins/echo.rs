use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use http::{header, StatusCode};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use validator::Validate;

use crate::proxy::{plugin::ProxyPlugin, ProxyContext};

pub fn create_echo_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginEchoConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid echo plugin config")?;
    Ok(Arc::new(PluginEcho { config }))
}

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginEchoConfig {
    body: String,
    headers: Option<HashMap<String, String>>,
}

pub struct PluginEcho {
    config: PluginEchoConfig,
}

#[async_trait]
impl ProxyPlugin for PluginEcho {
    fn name(&self) -> &str {
        "echo"
    }

    fn priority(&self) -> i32 {
        412
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let mut resp = ResponseHeader::build(StatusCode::OK, Some(4)).unwrap();
        if let Some(headers) = self.config.headers.clone() {
            for (k, v) in headers {
                let _ = resp.insert_header(k.to_string(), v);
            }
        }
        resp.insert_header(header::CONTENT_LENGTH, self.config.body.len().to_string())
            .unwrap();

        session
            .write_response_header(Box::new(resp), false)
            .await
            .unwrap();

        session
            .write_response_body(Some(self.config.body.clone().into()), true)
            .await
            .unwrap();

        Ok(true)
    }
}
