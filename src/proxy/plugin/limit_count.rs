use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use http::header;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_limits::rate::Rate;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::config::UpstreamHashOn;
use crate::proxy::request_selector_key;
use crate::proxy::ProxyContext;

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "limit-count";

pub fn create_limit_count_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig = serde_yaml::from_value(cfg)
        .or_err_with(ReadError, || "Invalid limit count plugin config")?;

    let rate = Rate::new(Duration::from_secs(config.time_window as u64));

    Ok(Arc::new(PluginRateLimit { config, rate }))
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    key_type: UpstreamHashOn,
    key: String,
    time_window: u32,
    count: u32,

    #[serde(default = "PluginConfig::default_rejected_code")]
    rejected_code: u16,
    #[serde(default)]
    rejected_msg: Option<String>,
    #[serde(default = "PluginConfig::default_show_limit_quota_header")]
    show_limit_quota_header: bool,
}

impl PluginConfig {
    fn default_rejected_code() -> u16 {
        503
    }

    fn default_show_limit_quota_header() -> bool {
        true
    }
}

pub struct PluginRateLimit {
    config: PluginConfig,
    rate: Rate,
}

#[async_trait]
impl ProxyPlugin for PluginRateLimit {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        1002
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let key = request_selector_key(session, &self.config.key_type, self.config.key.as_str());

        // Retrieve the current window requests
        let curr_window_requests = self.rate.observe(&key, 1);
        if curr_window_requests > self.config.count as isize {
            let mut header = ResponseHeader::build(self.config.rejected_code, None)?;

            // If the rate limit headers are to be shown, insert them
            if self.config.show_limit_quota_header {
                header.insert_header("X-Rate-Limit-Limit", self.config.count.to_string())?;
                header.insert_header("X-Rate-Limit-Remaining", "0")?;
                header.insert_header("X-Rate-Limit-Reset", "1")?;
            }

            // Disable keep-alive connection
            session.set_keepalive(None);

            if let Some(ref msg) = self.config.rejected_msg {
                header.insert_header(header::CONTENT_LENGTH, msg.len().to_string())?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(msg.clone().into()), true)
                    .await?;
            } else {
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
            }

            return Ok(true);
        }

        Ok(false)
    }
}
