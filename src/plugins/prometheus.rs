use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_core::Error;
use pingora_proxy::Session;
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, HistogramOpts,
    HistogramVec, IntCounter, IntCounterVec,
};
use regex::Regex;
use serde_json::Value as JsonValue;

use crate::{
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::request::get_request_host,
};

const DEFAULT_BUCKETS: &[f64] = &[
    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 30000.0,
    60000.0,
];

// Compiled regex patterns for path normalization
static NUMERIC_ID_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"/\d+").expect("Invalid regex pattern for numeric ID replacement"));

static UUID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        .expect("Invalid regex pattern for UUID replacement")
});

static HASH_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"/[0-9a-fA-F]{32,}").expect("Invalid regex pattern for hash replacement")
});

// Total number of requests
static REQUESTS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "http_requests_total",
        "The total number of client requests since pingsix started"
    )
    .expect("Failed to register prometheus metric: http_requests_total")
});

// Counter for HTTP status codes with normalized URI paths
static STATUS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "http_status",
        "HTTP status codes per service in pingsix",
        &[
            "code",          // HTTP status code
            "route",         // Route ID
            "path_template", // Normalized path template to avoid high cardinality
            "matched_host",  // Matched Host
            "service",       // Service ID
            "node",          // Node ID
        ]
    )
    .expect("Failed to register prometheus metric: http_status")
});

// Histogram for request latency
static LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new(
        "http_latency",
        "HTTP request latency in milliseconds per service in pingsix",
    )
    .buckets(DEFAULT_BUCKETS.to_vec());
    register_histogram_vec!(opts, &["type", "route", "service", "node"])
        .expect("Failed to register prometheus metric: http_latency")
});

// Bandwidth counter
static BANDWIDTH: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "bandwidth",
        "Total bandwidth in bytes consumed per service in pingsix",
        &[
            "type",    // ingress/egress
            "route",   // Route ID
            "service", // Service ID
            "node",    // Node ID
        ]
    )
    .expect("Failed to register prometheus metric: bandwidth")
});

// Request size histogram
static REQUEST_SIZE: Lazy<HistogramVec> = Lazy::new(|| {
    let opts =
        HistogramOpts::new("http_request_size_bytes", "HTTP request size in bytes").buckets(vec![
            100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
        ]);
    register_histogram_vec!(opts, &["route", "service"])
        .expect("Failed to register prometheus metric: http_request_size_bytes")
});

// Response size histogram
static RESPONSE_SIZE: Lazy<HistogramVec> = Lazy::new(|| {
    let opts = HistogramOpts::new("http_response_size_bytes", "HTTP response size in bytes")
        .buckets(vec![
            100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
        ]);
    register_histogram_vec!(opts, &["route", "service"])
        .expect("Failed to register prometheus metric: http_response_size_bytes")
});

pub const PLUGIN_NAME: &str = "prometheus";
const PRIORITY: i32 = 500;

/// Configuration for the Prometheus plugin
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PrometheusConfig {
    /// Maximum length for path template labels to prevent cardinality explosion
    /// Default: 100 characters
    #[serde(default = "PrometheusConfig::default_max_label_length")]
    pub max_label_length: usize,

    /// Maximum number of unique path segments to track
    /// If exceeded, paths will be collapsed to "/..." pattern
    /// Default: 1000
    #[serde(default = "PrometheusConfig::default_max_unique_paths")]
    pub max_unique_paths: usize,
}

impl PrometheusConfig {
    fn default_max_label_length() -> usize {
        100
    }

    fn default_max_unique_paths() -> usize {
        1000
    }
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            max_label_length: Self::default_max_label_length(),
            max_unique_paths: Self::default_max_unique_paths(),
        }
    }
}

pub fn create_prometheus_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = if cfg.is_null() {
        PrometheusConfig::default()
    } else {
        serde_json::from_value(cfg).map_err(|e| {
            ProxyError::serialization_error("Failed to parse prometheus plugin config", e)
        })?
    };

    Ok(Arc::new(PluginPrometheus {
        config,
        seen_paths: Arc::new(DashMap::new()),
    }))
}

pub struct PluginPrometheus {
    config: PrometheusConfig,
    /// Set of unique normalized paths seen so far
    /// Used to implement max_unique_paths limit correctly
    seen_paths: Arc<DashMap<String, ()>>,
}

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
        let route_id = route.as_ref().map_or_else(|| "", |r| r.id());

        // Use path template to avoid high cardinality issues
        let path_template = self.normalize_path_template(session);

        // Extract host, falling back to empty string
        let host = route.as_ref().map_or("", |_| {
            get_request_host(session.req_header()).unwrap_or_default()
        });

        // Extract service, falling back to "unknown" if service_id is None
        let service = route
            .as_ref()
            .map_or_else(|| "unknown", |r| r.service_id().unwrap_or("unknown"));

        // Extract node from context variables (assumes HttpService::upstream_peer sets ctx["upstream"]) as String
        let node = ctx
            .peer
            .as_ref()
            .map_or_else(|| "".to_string(), |p| p._address.to_string());

        // Update Prometheus metrics with normalized path template
        STATUS
            .with_label_values(&[code, route_id, &path_template, host, service, &node])
            .inc();

        // Record request latency
        let elapsed_ms = ctx.elapsed_ms_f64();
        LATENCY
            .with_label_values(&["request", route_id, service, &node])
            .observe(elapsed_ms);

        // Record bandwidth metrics
        BANDWIDTH
            .with_label_values(&["ingress", route_id, service, &node])
            .inc_by(session.body_bytes_read() as _);

        BANDWIDTH
            .with_label_values(&["egress", route_id, service, &node])
            .inc_by(session.body_bytes_sent() as _);

        // Record request and response sizes
        REQUEST_SIZE
            .with_label_values(&[route_id, service])
            .observe(session.body_bytes_read() as f64);

        RESPONSE_SIZE
            .with_label_values(&[route_id, service])
            .observe(session.body_bytes_sent() as f64);
    }
}

impl PluginPrometheus {
    /// Normalize URI path to avoid high cardinality issues
    /// Uses route path template if available, otherwise applies basic normalization
    fn normalize_path_template(&self, session: &Session) -> String {
        // For now, just use the actual path since we don't expose URI templates in the trait
        // In a real implementation, you might want to add path template methods to RouteContext
        let actual_path = session.req_header().uri.path();

        // Apply basic normalization patterns
        self.normalize_path(actual_path)
    }

    /// Apply basic path normalization to reduce metric cardinality
    /// Implements max_label_length limit and path convergence strategy
    /// Correctly tracks unique paths (not total request count)
    fn normalize_path(&self, path: &str) -> String {
        // Replace numeric IDs with placeholders using pre-compiled regex
        let path = NUMERIC_ID_REGEX.replace_all(path, "/{id}");

        // Replace UUIDs with placeholders using pre-compiled regex
        let path = UUID_REGEX.replace_all(&path, "/{uuid}");

        // Replace other common patterns using pre-compiled regex
        let path = HASH_REGEX.replace_all(&path, "/{hash}");

        // Limit path segment count to prevent deep hierarchies
        let segments: Vec<&str> = path.split('/').collect();
        let path = if segments.len() > 8 {
            // Keep first 7 segments and append "..."
            format!("{}/...", segments[..7].join("/"))
        } else {
            path.to_string()
        };

        // Enforce maximum label length to prevent memory issues
        let normalized = if path.len() > self.config.max_label_length {
            let truncate_at = self.config.max_label_length.saturating_sub(3);
            format!("{}...", &path[..truncate_at])
        } else {
            path
        };

        // Check if this normalized path has been seen before
        if self.seen_paths.contains_key(&normalized) {
            return normalized;
        }

        // New path: check if we've reached the limit
        if self.seen_paths.len() >= self.config.max_unique_paths {
            // Return generic pattern for new paths after limit is reached
            return "/...".to_string();
        }

        // Record this new path
        self.seen_paths.insert(normalized.clone(), ());
        normalized
    }
}
