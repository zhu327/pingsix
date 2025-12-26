use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, StatusCode};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

pub const PLUGIN_NAME: &str = "fault-injection";
const PRIORITY: i32 = 11000;

/// Creates a Fault Injection plugin instance with the given configuration.
/// This plugin allows you to inject faults (delays and aborts) into requests for testing purposes.
pub fn create_fault_injection_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginFaultInjection { config }))
}

/// Configuration for injecting delays into requests
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
struct DelayConfig {
    /// Duration to delay the request in seconds (supports decimals)
    #[validate(range(min = 0.0))]
    duration: f64,

    /// Percentage of requests to apply delay to (0-100). If not set, applies to all requests.
    #[serde(default)]
    #[validate(range(min = 0, max = 100))]
    percentage: Option<u32>,
}

/// Configuration for aborting requests with a specific status code
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
struct AbortConfig {
    /// HTTP status code to return (must be >= 200)
    #[validate(range(min = 200))]
    http_status: u16,

    /// Optional response body to send
    #[serde(default)]
    body: Option<String>,

    /// Optional headers to include in the response
    #[serde(default)]
    headers: Option<HashMap<String, serde_json::Value>>,

    /// Percentage of requests to abort (0-100). If not set, aborts all requests.
    #[serde(default)]
    #[validate(range(min = 0, max = 100))]
    percentage: Option<u32>,
}

/// Main plugin configuration
#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Optional delay configuration
    #[serde(default)]
    #[validate(nested)]
    delay: Option<DelayConfig>,

    /// Optional abort configuration
    #[serde(default)]
    #[validate(nested)]
    abort: Option<AbortConfig>,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Invalid fault injection plugin config", e)
        })?;

        config.validate()?;

        // Validate that at least one of delay or abort is configured
        if config.delay.is_none() && config.abort.is_none() {
            return Err(ProxyError::Plugin(
                "At least one of 'delay' or 'abort' must be configured".to_string(),
            ));
        }

        Ok(config)
    }
}

/// Fault Injection plugin implementation
pub struct PluginFaultInjection {
    config: PluginConfig,
}

impl PluginFaultInjection {
    /// Check if a fault should be applied based on the configured percentage
    fn sample_hit(percentage: Option<u32>) -> bool {
        match percentage {
            None => true, // If no percentage is set, always apply
            Some(pct) => {
                let mut rng = rand::rng();
                rng.random_range(1..=100) <= pct
            }
        }
    }

    /// Apply delay if configured and sampled
    async fn apply_delay(&self) {
        if let Some(ref delay_config) = self.config.delay {
            if Self::sample_hit(delay_config.percentage) {
                let duration = Duration::from_secs_f64(delay_config.duration);
                tokio::time::sleep(duration).await;
            }
        }
    }

    /// Check if request should be aborted and send abort response if needed
    async fn check_and_abort(&self, session: &mut Session) -> Result<bool> {
        if let Some(ref abort_config) = self.config.abort {
            if Self::sample_hit(abort_config.percentage) {
                return self.send_abort_response(session, abort_config).await;
            }
        }
        Ok(false)
    }

    /// Send an abort response with configured status, body, and headers
    async fn send_abort_response(
        &self,
        session: &mut Session,
        abort_config: &AbortConfig,
    ) -> Result<bool> {
        let status = StatusCode::from_u16(abort_config.http_status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let body = abort_config.body.as_deref().unwrap_or("");
        let body_len = body.len();

        // Build response header
        let mut resp = ResponseHeader::build(status, None)?;
        resp.insert_header(header::CONTENT_LENGTH, body_len.to_string())?;
        resp.insert_header(header::CONTENT_TYPE, "text/plain")?;

        // Add custom headers if configured
        if let Some(ref headers) = abort_config.headers {
            for (name, value) in headers {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue, // Skip complex types
                };
                resp.insert_header(name.clone(), value_str)?;
            }
        }

        // Send response
        session
            .write_response_header(Box::new(resp), body_len == 0)
            .await?;

        if body_len > 0 {
            session
                .write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true)
                .await?;
        }

        Ok(true)
    }
}

#[async_trait]
impl ProxyPlugin for PluginFaultInjection {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        // Apply delay first (if configured)
        self.apply_delay().await;

        // Then check if request should be aborted (if configured)
        self.check_and_abort(session).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_config_with_delay_only() {
        let cfg = json!({
            "delay": {
                "duration": 1.5,
                "percentage": 50
            }
        });

        let config = PluginConfig::try_from(cfg);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(config.delay.is_some());
        assert!(config.abort.is_none());
    }

    #[test]
    fn test_config_with_abort_only() {
        let cfg = json!({
            "abort": {
                "http_status": 503,
                "body": "Service Unavailable",
                "percentage": 100
            }
        });

        let config = PluginConfig::try_from(cfg);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(config.delay.is_none());
        assert!(config.abort.is_some());
    }

    #[test]
    fn test_config_with_both() {
        let cfg = json!({
            "delay": {
                "duration": 2.0
            },
            "abort": {
                "http_status": 500,
                "body": "Internal Server Error",
                "headers": {
                    "X-Custom-Header": "test-value"
                }
            }
        });

        let config = PluginConfig::try_from(cfg);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(config.delay.is_some());
        assert!(config.abort.is_some());
    }

    #[test]
    fn test_config_empty_fails() {
        let cfg = json!({});
        let config = PluginConfig::try_from(cfg);
        assert!(config.is_err());
    }

    #[test]
    fn test_config_invalid_percentage() {
        let cfg = json!({
            "delay": {
                "duration": 1.0,
                "percentage": 150
            }
        });

        let config = PluginConfig::try_from(cfg);
        assert!(config.is_err());
    }

    #[test]
    fn test_config_negative_duration() {
        let cfg = json!({
            "delay": {
                "duration": -1.0
            }
        });

        let config = PluginConfig::try_from(cfg);
        assert!(config.is_err());
    }

    #[test]
    fn test_config_invalid_status_code() {
        let cfg = json!({
            "abort": {
                "http_status": 100
            }
        });

        let config = PluginConfig::try_from(cfg);
        assert!(config.is_err());
    }

    #[test]
    fn test_sample_hit_always_true_when_none() {
        assert!(PluginFaultInjection::sample_hit(None));
    }

    #[test]
    fn test_sample_hit_never_at_zero() {
        assert!(!PluginFaultInjection::sample_hit(Some(0)));
    }

    #[test]
    fn test_sample_hit_always_at_hundred() {
        for _ in 0..100 {
            assert!(PluginFaultInjection::sample_hit(Some(100)));
        }
    }
}
