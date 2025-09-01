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

pub const PLUGIN_NAME: &str = "gzip";
const PRIORITY: i32 = 995;

/// Creates a Gzip plugin instance with the given configuration.
pub fn create_gzip_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginGzip { config }))
}

/// Configuration for the Gzip plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Compression level for Gzip (0-9).
    #[serde(default = "PluginConfig::default_comp_level")]
    #[validate(range(min = 0, max = 9))]
    comp_level: u32,

    /// Enable or disable decompression (default: false).
    #[serde(default)]
    decompression: bool,
}

impl PluginConfig {
    /// Default compression level.
    fn default_comp_level() -> u32 {
        1
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid gzip plugin config", e))?;

        config.validate().map_err(|e| {
            ProxyError::validation_error(format!("Gzip plugin config validation failed: {e}"))
        })?;

        Ok(config)
    }
}

/// Gzip Plugin implementation.
pub struct PluginGzip {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginGzip {
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

        resp_compression.adjust_algorithm_level(Algorithm::Gzip, self.config.comp_level);

        resp_compression.adjust_decompression(self.config.decompression);

        Ok(())
    }
}
