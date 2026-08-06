use std::sync::Arc;

use pingora::protocols::http::compression::Algorithm;
use serde_json::Value as JsonValue;

use crate::core::{ProxyPlugin, ProxyResult};

use super::compression::CompressionPlugin;

pub const PLUGIN_NAME: &str = "brotli";
const PRIORITY: i32 = 996;

/// Creates a Brotli plugin instance with the given configuration.
///
/// Schema and plugin name stay here; the shared implementation lives in
/// [`CompressionPlugin`].
pub fn create_brotli_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    CompressionPlugin::build(
        PLUGIN_NAME,
        PRIORITY,
        Algorithm::Brotli,
        cfg,
        "brotli",
        0,
        11,
    )
}
