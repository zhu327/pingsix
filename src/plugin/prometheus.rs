use std::sync::Arc;

use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora_core::{Error, Result};
use pingora_proxy::Session;
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, HistogramOpts,
    HistogramVec, IntCounter, IntCounterVec,
};
use serde_yaml::Value as YamlValue;

use crate::{proxy::ProxyContext, utils::request::get_request_host};

use super::ProxyPlugin;

const DEFAULT_BUCKETS: &[f64] = &[
    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 30000.0,
    60000.0,
];

// Total number of requests
static REQUESTS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "http_requests_total",
        "The total number of client requests since pingsix started"
    )
    .unwrap()
});

// Counter for HTTP status codes
static STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_status",
        "HTTP status codes per service in pingsix",
        &[
            "code",         // HTTP status code
            "route",        // Route ID
            "matched_uri",  // Matched URI
            "matched_host", // Matched Host
            "service",      // Service ID
            "node",         // Node ID
        ]
    )
    .unwrap()
});

// Histogram for request latency
static LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "http_latency",
        "HTTP request latency in milliseconds per service in pingsix",
    )
    .buckets(DEFAULT_BUCKETS.to_vec());
    register_histogram_vec!(opts, &["type", "route", "service", "node"]).unwrap()
});

// Bandwidth counter
static BANDWIDTH: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "bandwidth",
        "Total bandwidth in bytes consumed per service in pingsix",
        &[
            "type",    // HTTP status code
            "route",   // Route ID
            "service", // Service ID
            "node",    // Node ID
        ]
    )
    .unwrap()
});

pub const PLUGIN_NAME: &str = "prometheus";
const PRIORITY: i32 = 500;

pub fn create_prometheus_plugin(_cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    Ok(Arc::new(PluginPrometheus {}))
}

pub struct PluginPrometheus;

#[async_trait]
impl ProxyPlugin for PluginPrometheus {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut ProxyContext) {
        REQUESTS.inc();

        // Clone route only once
        let route = ctx.route.clone();

        // Extract response code
        let code = session
            .response_written()
            .map_or("", |resp| resp.status.as_str());

        // Extract route information, falling back to empty string if not present
        let route_id = route.as_ref().map_or_else(|| "", |r| r.inner.id.as_str());

        // Extract URI template (or fallback to empty string) to avoid high cardinality from raw URIs
        let uri = route
            .as_ref()
            .map_or("", |_| session.req_header().uri.path());

        // Extract host, falling back to empty string
        let host = route.as_ref().map_or("", |_| {
            get_request_host(session.req_header()).unwrap_or_default()
        });

        // Extract service, falling back to "unknown" if service_id is None
        let service = route.as_ref().map_or_else(
            || "unknown",
            |r| r.inner.service_id.as_deref().unwrap_or("unknown"),
        );

        // Extract node from context variables (assumes HttpService::upstream_peer sets ctx.vars["upstream"])
        let node = ctx.vars.get("upstream").map_or("", |s| s.as_str());

        // Update Prometheus metrics
        // ! The matched_uri tag still uses the original path, which can cause high cardinality issues.
        STATUS
            .with_label_values(&[code, route_id, uri, host, service, node])
            .inc();

        LATENCY
            .with_label_values(&["request", route_id, service, node])
            .observe(ctx.request_start.elapsed().as_millis() as f64);

        BANDWIDTH
            .with_label_values(&["ingress", route_id, service, node])
            .inc_by(session.body_bytes_read() as _);

        BANDWIDTH
            .with_label_values(&["egress", route_id, service, node])
            .inc_by(session.body_bytes_sent() as _);
    }
}
