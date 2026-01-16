pub mod basic_auth;
pub mod brotli;
pub mod cache;
pub mod cors;
pub mod csrf;
pub mod echo;
pub mod fault_injection;
pub mod file_logger;
pub mod grpc_web;
pub mod gzip;
pub mod ip_restriction;
pub mod jwt_auth;
pub mod key_auth;
pub mod limit_count;
pub mod prometheus;
pub mod proxy_rewrite;
pub mod redirect;
pub mod request_id;
pub mod response_rewrite;
pub mod traffic_split;

use std::{collections::HashMap, sync::Arc};

use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;

use crate::core::{PluginCreateFn, ProxyError, ProxyPlugin, ProxyResult};

/// Global registry mapping plugin names to their factory functions.
///
/// Plugins are registered with their priority values as comments for reference.
/// Higher priority values execute earlier in the plugin chain.
static PLUGIN_BUILDER_REGISTRY: Lazy<HashMap<&'static str, PluginCreateFn>> = Lazy::new(|| {
    let arr: Vec<(&str, PluginCreateFn)> = vec![
        (
            file_logger::PLUGIN_NAME,
            file_logger::create_file_logger_plugin,
        ), // 399
        (echo::PLUGIN_NAME, echo::create_echo_plugin), // 412
        (
            prometheus::PLUGIN_NAME,
            prometheus::create_prometheus_plugin,
        ), // 500
        (
            limit_count::PLUGIN_NAME,
            limit_count::create_limit_count_plugin,
        ), // 503
        (grpc_web::PLUGIN_NAME, grpc_web::create_grpc_web_plugin), // 505
        (
            response_rewrite::PLUGIN_NAME,
            response_rewrite::create_response_rewrite_plugin,
        ), // 899
        (redirect::PLUGIN_NAME, redirect::create_redirect_plugin), // 900
        (
            traffic_split::PLUGIN_NAME,
            traffic_split::create_traffic_split_plugin,
        ), // 966
        (gzip::PLUGIN_NAME, gzip::create_gzip_plugin), // 995
        (brotli::PLUGIN_NAME, brotli::create_brotli_plugin), // 996
        (
            proxy_rewrite::PLUGIN_NAME,
            proxy_rewrite::create_proxy_rewrite_plugin,
        ), // 1008
        (cache::PLUGIN_NAME, cache::create_cache_plugin), // 1085
        (
            fault_injection::PLUGIN_NAME,
            fault_injection::create_fault_injection_plugin,
        ), // 11000
        (
            request_id::PLUGIN_NAME,
            request_id::create_request_id_plugin,
        ), // 12015
        (key_auth::PLUGIN_NAME, key_auth::create_key_auth_plugin), // 2500
        (
            basic_auth::PLUGIN_NAME,
            basic_auth::create_basic_auth_plugin,
        ), // 2520
        (jwt_auth::PLUGIN_NAME, jwt_auth::create_jwt_auth_plugin), // 2510
        (csrf::PLUGIN_NAME, csrf::create_csrf_plugin), // 2980
        (
            ip_restriction::PLUGIN_NAME,
            ip_restriction::create_ip_restriction_plugin,
        ), // 3000
        (cors::PLUGIN_NAME, cors::create_cors_plugin), // 4000
    ];
    arr.into_iter().collect()
});

/// Creates plugin instances from configuration using a factory pattern.
///
/// Looks up the plugin builder function in the global registry and invokes it
/// with the provided configuration. Fails fast for unknown plugin types.
///
/// # Arguments
/// - `name`: Plugin identifier (must match registry keys)
/// - `cfg`: Plugin configuration as JSON
///
/// # Returns
/// Arc-wrapped plugin instance for thread-safe sharing across requests
///
/// # Errors
/// Returns `ReadError` for unknown plugin names or configuration parsing failures
pub fn build_plugin(name: &str, cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let builder = PLUGIN_BUILDER_REGISTRY
        .get(name)
        .ok_or_else(|| ProxyError::Plugin(format!("Unknown plugin type: {name}")))?;
    builder(cfg)
}
