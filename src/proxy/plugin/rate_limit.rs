use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_limits::rate::Rate;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use validator::Validate;

use crate::config::UpstreamHashOn;
use crate::proxy::request_selector_key;
use crate::proxy::ProxyContext;

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "rate_limit";

pub fn create_rate_limit_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginRaLimitConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid echo plugin config")?;

    let rate = Rate::new(Duration::from_secs(config.window_sec as u64));

    Ok(Arc::new(PluginRateLimit { config, rate }))
}

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginRaLimitConfig {
    hash_on: UpstreamHashOn,
    key: String,
    window_sec: u32,
    max_req_per_sec: u32,
}

pub struct PluginRateLimit {
    config: PluginRaLimitConfig,
    rate: Rate,
}

#[async_trait]
impl ProxyPlugin for PluginRateLimit {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        1001
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let key = request_selector_key(session, &self.config.hash_on, self.config.key.as_str());

        // retrieve the current window requests
        let curr_window_requests = self.rate.observe(&key, 1);
        if curr_window_requests > self.config.max_req_per_sec as isize {
            // rate limited, return 429
            let mut header = ResponseHeader::build(429, None).unwrap();
            header
                .insert_header(
                    "X-Rate-Limit-Limit",
                    self.config.max_req_per_sec.to_string(),
                )
                .unwrap();
            header.insert_header("X-Rate-Limit-Remaining", "0").unwrap();
            header.insert_header("X-Rate-Limit-Reset", "1").unwrap();
            session.set_keepalive(None);
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }
}
