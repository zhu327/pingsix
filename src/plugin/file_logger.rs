use std::sync::Arc;

use async_trait::async_trait;
use log::info;
use pingora_core::{Error, Result};
use pingora_proxy::Session;
use serde_yaml::Value as YamlValue;

use crate::proxy::ProxyContext;

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "file-logger";

pub fn create_file_logger_plugin(_cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    Ok(Arc::new(PluginFileLogger {}))
}

// TODO support custom log_format like nginx access log
pub struct PluginFileLogger;

#[async_trait]
impl ProxyPlugin for PluginFileLogger {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        399
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, _ctx: &mut ProxyContext) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "{} response code: {response_code}",
            session.as_ref().request_summary()
        );
    }
}
