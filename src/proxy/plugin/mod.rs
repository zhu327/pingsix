pub mod brotli;
pub mod echo;
pub mod grpc_web;
pub mod gzip;
pub mod limit_count;
pub mod prometheus;
pub mod proxy_rewrite;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora::OkOrErr;
use pingora_error::{Error, ErrorType::ReadError, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use serde_yaml::Value as YamlValue;

use super::{router::ProxyRouter, service::service_fetch, ProxyContext};

/// Type alias for plugin initialization functions
pub type PluginCreateFn = Arc<dyn Fn(YamlValue) -> Result<Arc<dyn ProxyPlugin>> + Send + Sync>;

/// Registry of plugin builders
static PLUGIN_BUILDER_REGISTRY: Lazy<HashMap<&'static str, PluginCreateFn>> = Lazy::new(|| {
    let arr: Vec<(&str, PluginCreateFn)> = vec![
        (echo::PLUGIN_NAME, Arc::new(echo::create_echo_plugin)), // 412
        (
            prometheus::PLUGIN_NAME, // 500
            Arc::new(prometheus::create_prometheus_plugin),
        ),
        (
            limit_count::PLUGIN_NAME, // 503
            Arc::new(limit_count::create_limit_count_plugin),
        ),
        (
            grpc_web::PLUGIN_NAME, // 505
            Arc::new(grpc_web::create_grpc_web_plugin),
        ),
        (gzip::PLUGIN_NAME, Arc::new(gzip::create_gzip_plugin)), // 995
        (brotli::PLUGIN_NAME, Arc::new(brotli::create_brotli_plugin)), // 996
        (
            proxy_rewrite::PLUGIN_NAME, // 1008
            Arc::new(proxy_rewrite::create_proxy_rewrite_plugin),
        ),
    ];
    arr.into_iter().collect()
});

/// Builds a plugin instance based on its name and configuration.
///
/// # Arguments
/// - `name`: The name of the plugin to be created.
/// - `cfg`: The configuration for the plugin, provided as a `YamlValue`.
///
/// # Returns
/// - `Result<Arc<dyn ProxyPlugin>>`: On success, returns a reference-counted pointer to the created plugin instance.
///   On failure, returns an error.
///
/// # Errors
/// - `ReadError`: Returned if the plugin name is not found in the `PLUGIN_BUILDER_REGISTRY`.
///
/// # Notes
/// - This function retrieves the appropriate plugin builder from a global registry and invokes it with the provided configuration.
pub fn build_plugin(name: &str, cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let builder = PLUGIN_BUILDER_REGISTRY
        .get(name)
        .or_err(ReadError, "Unknow plugin type")?;
    builder(cfg)
}

/// Builds a `ProxyPluginExecutor` by combining plugins from both a router and its associated service.
///
/// # Arguments
/// - `router`: A reference-counted pointer to a `ProxyRouter` instance containing router-specific plugins.
///
/// # Returns
/// - `Arc<ProxyPluginExecutor>`: A reference-counted pointer to a `ProxyPluginExecutor` that manages the merged plugin list.
///
/// # Process
/// - Retrieves router-specific plugins from the `router`.
/// - If the router is associated with a service (via `service_id`), retrieves service-specific plugins.
/// - Combines the router and service plugins, ensuring unique entries by their name.
/// - Sorts the merged plugin list by priority in descending order.
/// - Constructs and returns the `ProxyPluginExecutor` instance.
///
/// # Notes
/// - This function ensures that plugins from the router take precedence over those from the service in case of naming conflicts.
pub fn build_plugin_executor(router: Arc<ProxyRouter>) -> Arc<ProxyPluginExecutor> {
    let mut plugin_map: HashMap<String, Arc<dyn ProxyPlugin>> = HashMap::new();

    // 合并 router 和 service 的插件
    let service_plugins = router
        .inner
        .service_id
        .as_deref() // 将 Option<String> 转换为 Option<&str>
        .and_then(service_fetch)
        .map_or_else(Vec::new, |service| service.plugins.clone());

    for plugin in router.plugins.iter().chain(service_plugins.iter()) {
        plugin_map
            .entry(plugin.name().to_string())
            .or_insert_with(|| plugin.clone());
    }

    // 按优先级逆序排序
    let mut merged_plugins: Vec<_> = plugin_map.into_values().collect();
    merged_plugins.sort_by_key(|b| std::cmp::Reverse(b.priority()));

    Arc::new(ProxyPluginExecutor {
        plugins: merged_plugins,
    })
}

#[async_trait]
pub trait ProxyPlugin: Send + Sync {
    /// Return the name of this plugin
    ///
    /// # Returns
    /// * `&str` - The name of this plugin
    fn name(&self) -> &str;

    /// Return the priority of this plugin
    ///
    /// # Returns
    /// * `i32` - The priority of this plugin
    fn priority(&self) -> i32;

    /// Handle the incoming request.
    ///
    /// In this phase, users can parse, validate, rate limit, perform access control and/or
    /// return a response for this request.
    /// Like APISIX rewrite access phase.
    ///
    /// # Arguments
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_ctx` - Mutable reference to the plugin context
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if a response was sent and the proxy should exit
    /// * `Ok(false)` if the proxy should continue to the next phase
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Handle the incoming request before any downstream module is executed.
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the request before it is sent to the upstream
    ///
    /// # Arguments
    /// Like APISIX before_proxy phase.
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_upstream_request` - Mutable reference to the upstream request header
    /// * `_ctx` - Mutable reference to the plugin context
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the response header before it is sent to the downstream
    ///
    /// # Arguments
    /// Like APISIX header_filter phase.
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_upstream_response` - Mutable reference to the upstream response header
    /// * `_ctx` - Mutable reference to the plugin context
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Handle the response body chunks
    ///
    /// # Arguments
    /// Like APISIX body_filter phase.
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_body` - Mutable reference to an optional Bytes containing the body chunk
    /// * `_end_of_stream` - Boolean indicating if this is the last chunk
    /// * `_ctx` - Mutable reference to the plugin context
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// This filter is called when the entire response is sent to the downstream successfully or
    /// there is a fatal error that terminate the request.
    ///
    /// An error log is already emitted if there is any error. This phase is used for collecting
    /// metrics and sending access logs.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut ProxyContext) {}
}

/// A struct that manages the execution of proxy plugins.
///
/// # Fields
/// - `plugins`: A vector of reference-counted pointers to `ProxyPlugin` instances.
///   These plugins are executed in the order of their priorities, typically determined
///   during the construction of the `ProxyPluginExecutor`.
///
/// # Purpose
/// - This struct is responsible for holding and managing a collection of proxy plugins.
/// - It is typically used to facilitate the execution of plugins in a proxy routing context,
///   where plugins can perform various tasks such as authentication, logging, traffic shaping, etc.
///
/// # Usage
/// - The plugins are expected to be sorted by their priority (in descending order) during
///   the initialization of the `ProxyPluginExecutor`.
#[derive(Default)]
pub struct ProxyPluginExecutor {
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

#[async_trait]
impl ProxyPlugin for ProxyPluginExecutor {
    fn name(&self) -> &str {
        "plugin-executor"
    }

    fn priority(&self) -> i32 {
        0
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        for plugin in self.plugins.iter() {
            if plugin.request_filter(session, ctx).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin.early_request_filter(session, ctx).await?;
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin
                .upstream_request_filter(session, upstream_request, ctx)
                .await?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin
                .response_filter(session, upstream_response, ctx)
                .await?;
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin.response_body_filter(session, body, end_of_stream, ctx)?;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        for plugin in self.plugins.iter() {
            plugin.logging(session, e, ctx).await;
        }
    }
}
