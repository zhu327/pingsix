use std::sync::Arc;

use async_trait::async_trait;
use pingora::{
    modules::http::compression::ResponseCompression, protocols::http::compression::Algorithm,
};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::proxy::ProxyContext;

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "brotli";

pub fn create_brotli_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid brotli plugin config")?;
    Ok(Arc::new(PluginBrotli { config }))
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    #[serde(default = "PluginConfig::default_comp_level")]
    comp_level: u32,
    #[serde(default)]
    decompression: bool,
}

impl PluginConfig {
    fn default_comp_level() -> u32 {
        1
    }
}

pub struct PluginBrotli {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginBrotli {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        996
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        let c = session
            .downstream_modules_ctx
            .get_mut::<ResponseCompression>()
            .expect("ResponseCompression module added");

        c.adjust_algorithm_level(Algorithm::Brotli, self.config.comp_level);

        c.adjust_decompression(self.config.decompression);

        Ok(())
    }
}
