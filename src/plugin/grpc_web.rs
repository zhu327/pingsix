use std::sync::Arc;

use async_trait::async_trait;
use pingora::modules::http::grpc_web::GrpcWebBridge;
use pingora_error::Result;
use pingora_proxy::Session;
use serde_yaml::Value as YamlValue;

use crate::proxy::ProxyContext;

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "grpc-web";
const PRIORITY: i32 = 505;

/// Creates a gRPC-Web plugin instance.
/// This plugin enables support for the gRPC-Web protocol by initializing the `GrpcWebBridge` module
/// for each request. The configuration is currently unused, but the `cfg` parameter is provided for
/// future extensibility.
pub fn create_grpc_web_plugin(_cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    Ok(Arc::new(PluginGrpcWeb {}))
}

/// gRPC-Web plugin implementation.
/// This plugin integrates the `GrpcWebBridge` module to enable gRPC-Web protocol support
/// in the proxy, allowing clients to communicate with gRPC services over HTTP/1.1 or HTTP/2.
#[derive(Default)]
pub struct PluginGrpcWeb;

#[async_trait]
impl ProxyPlugin for PluginGrpcWeb {
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
        let grpc = session
            .downstream_modules_ctx
            .get_mut::<GrpcWebBridge>()
            .expect("GrpcWebBridge module added");

        // Initialize gRPC module for this request
        grpc.init();
        Ok(())
    }
}
