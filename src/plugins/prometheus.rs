use std::{borrow::Cow, sync::Arc};

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
        let path_template = self.normalize_path_template(session, ctx);

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
            .map_or(Cow::Borrowed(""), |p| Cow::Owned(p._address.to_string()));

        // Update Prometheus metrics with normalized path template
        STATUS
            .with_label_values(&[code, route_id, &path_template, host, service, node.as_ref()])
            .inc();

        // Record request latency
        let elapsed_ms = ctx.elapsed_ms_f64();
        LATENCY
            .with_label_values(&["request", route_id, service, node.as_ref()])
            .observe(elapsed_ms);

        // Record bandwidth metrics
        BANDWIDTH
            .with_label_values(&["ingress", route_id, service, node.as_ref()])
            .inc_by(session.body_bytes_read() as _);

        BANDWIDTH
            .with_label_values(&["egress", route_id, service, node.as_ref()])
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
    /// Normalize URI path to avoid high cardinality issues.
    /// Prefer the matched route template, which avoids request-time regex work and
    /// naturally groups dynamic path parameters into one metric series.
    fn normalize_path_template(&self, session: &Session, ctx: &ProxyContext) -> String {
        if let Some(template) = ctx.route.as_ref().and_then(|route| route.uri_template()) {
            return self.limit_path_label(template.to_string());
        }

        self.normalize_path(session.req_header().uri.path())
    }

    /// Apply basic path normalization to reduce metric cardinality.
    fn normalize_path(&self, path: &str) -> String {
        // Replace numeric IDs with placeholders using pre-compiled regex
        let path = NUMERIC_ID_REGEX.replace_all(path, "/{id}");

        // Replace UUIDs with placeholders using pre-compiled regex
        let path = UUID_REGEX.replace_all(&path, "/{uuid}");

        // Replace other common patterns using pre-compiled regex
        let path = HASH_REGEX.replace_all(&path, "/{hash}");

        // Limit path segment count without collecting all path segments.
        // Matches the original `split('/').collect()` semantics: once the path
        // exceeds 8 segments, keep only the first 7 and append "/...".
        let mut segment_count = 0;
        let mut truncate_at = None;
        for (index, byte) in path.bytes().enumerate() {
            if byte == b'/' {
                segment_count += 1;
                if segment_count == 7 {
                    truncate_at = Some(index);
                } else if segment_count == 8 {
                    break;
                }
            }
        }
        let path = if segment_count >= 8 {
            format!(
                "{}/...",
                &path[..truncate_at.expect("recorded at 7th slash")]
            )
        } else {
            path.into_owned()
        };

        self.limit_path_label(path)
    }

    /// Enforce label length and unique-path limits for both request paths and
    /// route templates.
    fn limit_path_label(&self, path: String) -> String {
        let normalized = if path.len() > self.config.max_label_length {
            let truncate_at = path
                .char_indices()
                .map(|(index, _)| index)
                .take_while(|&index| index <= self.config.max_label_length.saturating_sub(3))
                .last()
                .unwrap_or(0);
            format!("{}...", &path[..truncate_at])
        } else {
            path
        };

        if self.seen_paths.contains_key(&normalized) {
            return normalized;
        }

        if self.seen_paths.len() >= self.config.max_unique_paths {
            return "/...".to_string();
        }

        self.seen_paths.insert(normalized.clone(), ());
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(max_label_length: usize, max_unique_paths: usize) -> PluginPrometheus {
        PluginPrometheus {
            config: PrometheusConfig {
                max_label_length,
                max_unique_paths,
            },
            seen_paths: Arc::new(DashMap::new()),
        }
    }

    #[test]
    fn route_templates_obey_label_length_limit() {
        let plugin = plugin(8, 10);
        assert_eq!(
            plugin.limit_path_label("/abcdefghij".to_string()),
            "/abcd..."
        );
    }

    #[test]
    fn route_templates_obey_unique_path_limit() {
        let plugin = plugin(100, 1);
        assert_eq!(plugin.limit_path_label("/first".to_string()), "/first");
        assert_eq!(plugin.limit_path_label("/second".to_string()), "/...");
    }

    #[test]
    fn normalize_path_collapses_beyond_eight_segments() {
        let plugin = plugin(100, 100);
        // 9 segments: keep the first 7 and append "/...".
        assert_eq!(
            plugin.normalize_path("/a/b/c/d/e/f/g/h"),
            "/a/b/c/d/e/f/..."
        );
        // 8 segments: under the limit, unchanged.
        assert_eq!(plugin.normalize_path("/a/b/c/d/e/f/g"), "/a/b/c/d/e/f/g");
    }
}
