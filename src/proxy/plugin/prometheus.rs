use std::sync::Arc;

use async_trait::async_trait;
use once_cell::sync::Lazy;
use pingora_core::{Error, Result};
use pingora_proxy::Session;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge, HistogramOpts,
    HistogramVec, IntCounterVec, IntGauge,
};
use serde_yaml::Value as YamlValue;

use crate::proxy::{get_request_host, ProxyContext};

use super::ProxyPlugin;

const DEFAULT_BUCKETS: &[f64] = &[
    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 30000.0,
    60000.0,
];

// Total number of requests
static REQUESTS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
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
    register_histogram_vec!(opts, &["type", "route", "service"]).unwrap()
});

pub const PLUGIN_NAME: &str = "prometheus";

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
        500
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut ProxyContext) {
        REQUESTS.inc();

        let code = session
            .response_written()
            .map_or("", |resp| resp.status.as_str());

        let route = ctx
            .router
            .clone()
            .map_or(String::new(), |r| r.inner.id.clone());
        let uri = ctx
            .router
            .clone()
            .clone()
            .map_or("", |_| session.req_header().uri.path());
        let host = ctx.router.clone().clone().map_or("", |_| {
            get_request_host(session.req_header()).unwrap_or_default()
        });
        let service = ctx.router.clone().map_or(String::new(), |r| {
            r.inner.service_id.clone().unwrap_or(host.to_string())
        });

        STATUS
            .with_label_values(&[code, &route, uri, host, &service])
            .inc();

        LATENCY
            .with_label_values(&["request", &route, &service])
            .observe(ctx.request_start.elapsed().as_millis() as f64);
    }
}
