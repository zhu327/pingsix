use std::sync::Arc;

use async_trait::async_trait;
use pingora::{
    modules::http::compression::ResponseCompression, protocols::http::compression::Algorithm,
};
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

pub const PLUGIN_NAME: &str = "brotli";
const PRIORITY: i32 = 996;

/// Creates a Brotli plugin instance with the given configuration.
pub fn create_brotli_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginBrotli { config }))
}

/// Configuration for the Brotli plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Compression level (0-11) for Brotli.
    #[serde(default = "PluginConfig::default_comp_level")]
    #[validate(range(min = 0, max = 11))]
    comp_level: u32,

    /// Whether to enable decompression for Brotli.
    #[serde(default)]
    decompression: bool,
}

impl PluginConfig {
    fn default_comp_level() -> u32 {
        1
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid brotli plugin config", e))?;

        config.validate().map_err(|e| {
            ProxyError::validation_error(format!("Brotli plugin config validation failed: {e}"))
        })?;

        Ok(config)
    }
}

/// Brotli plugin implementation.
pub struct PluginBrotli {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginBrotli {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        let resp_compression = session
            .downstream_modules_ctx
            .get_mut::<ResponseCompression>()
            .expect("ResponseCompression module added");

        resp_compression.adjust_algorithm_level(Algorithm::Brotli, self.config.comp_level);

        resp_compression.adjust_decompression(self.config.decompression);

        Ok(())
    }
}
