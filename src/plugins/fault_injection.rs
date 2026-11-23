use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_proxy::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, Rejection},
    plugins::config::parse_and_validate_plugin_config,
};

pub const PLUGIN_NAME: &str = "fault-injection";
const PRIORITY: i32 = 11000;

/// Creates a Fault Injection plugin instance with the given configuration.
/// This plugin allows you to inject faults (delays and aborts) into requests for testing purposes.
pub fn create_fault_injection_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginFaultInjection { config }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators WITHOUT constructing the plugin.
pub fn validate_fault_injection_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?;
    Ok(())
}

/// Maximum allowed delay in seconds (24 hours), bounding `Duration::from_secs_f64`
/// against floating-point overflow panics.
const MAX_DELAY_SECS: f64 = 86_400.0;

/// Configuration for injecting delays into requests
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
struct DelayConfig {
    /// Duration to delay the request in seconds (supports decimals)
    #[validate(range(min = 0.0, max = 86_400.0))]
    duration: f64,

    /// Percentage of requests to apply delay to (0-100). If not set, applies to all requests.
    #[serde(default)]
    #[validate(range(min = 0, max = 100))]
    percentage: Option<u32>,

    /// APISIX variable-expression matchers. Parsed only to fail with a clear
    /// validation error: var-expression evaluation is not supported. Entries
    /// are JSON values (APISIX vars commonly contain numbers, e.g.
    /// `["arg_limit", ">", 100]`) so all shapes reach the friendly error
    /// instead of a raw serde type error.
    #[serde(default)]
    vars: Option<Vec<Vec<serde_json::Value>>>,
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

    /// APISIX variable-expression matchers. Parsed only to fail with a clear
    /// validation error: var-expression evaluation is not supported. Entries
    /// are JSON values (APISIX vars commonly contain numbers).
    #[serde(default)]
    vars: Option<Vec<Vec<serde_json::Value>>>,
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
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid fault injection plugin config")?;

        // Validate that at least one of delay or abort is configured
        if config.delay.is_none() && config.abort.is_none() {
            return Err(ProxyError::Plugin(
                "At least one of 'delay' or 'abort' must be configured".to_string(),
            ));
        }

        // APISIX `abort.headers` only supports JSON strings and numbers.
        if let Some(headers) = config
            .abort
            .as_ref()
            .and_then(|abort| abort.headers.as_ref())
        {
            if headers.is_empty() {
                return Err(ProxyError::validation_error(
                    "fault injection abort.headers must not be empty",
                ));
            }
            for (name, value) in headers {
                if !value.is_string() && !value.is_number() {
                    return Err(ProxyError::validation_error(format!(
                        "fault injection abort header '{name}' must be a JSON string or number"
                    )));
                }
                // Dry-run name/value conversion at config time so a malformed
                // entry fails the config write instead of erroring every
                // aborted response.
                http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    ProxyError::validation_error(format!(
                        "fault injection abort header name '{name}' is invalid"
                    ))
                })?;
                let rendered = match value {
                    serde_json::Value::String(value) => value.clone(),
                    other => other.to_string(),
                };
                http::HeaderValue::from_str(&rendered).map_err(|_| {
                    ProxyError::validation_error(format!(
                        "fault injection abort header value for '{name}' is invalid"
                    ))
                })?;
            }
        }

        if config
            .delay
            .as_ref()
            .and_then(|delay| delay.vars.as_ref())
            .is_some_and(|vars| !vars.is_empty())
        {
            return Err(ProxyError::validation_error(
                "fault-injection delay.vars uses var expressions, which are not supported",
            ));
        }
        if config
            .abort
            .as_ref()
            .and_then(|abort| abort.vars.as_ref())
            .is_some_and(|vars| !vars.is_empty())
        {
            return Err(ProxyError::validation_error(
                "fault-injection abort.vars uses var expressions, which are not supported",
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
                let mut rng = rand::thread_rng();
                rng.gen_range(1..=100) <= pct
            }
        }
    }

    /// Apply delay if configured and sampled
    async fn apply_delay(&self) {
        if let Some(ref delay_config) = self.config.delay {
            if Self::sample_hit(delay_config.percentage) {
                let clamped = delay_config.duration.clamp(0.0, MAX_DELAY_SECS);
                let duration = Duration::try_from_secs_f64(clamped)
                    .unwrap_or_else(|_| Duration::from_secs(MAX_DELAY_SECS as u64));
                tokio::time::sleep(duration).await;
            }
        }
    }

    /// Check if request should be aborted and build the abort response if so
    fn check_and_abort(&self) -> Option<FilterVerdict> {
        if let Some(ref abort_config) = self.config.abort {
            if Self::sample_hit(abort_config.percentage) {
                return Some(FilterVerdict::Reject(Self::abort_rejection(abort_config)));
            }
        }
        None
    }

    /// Build the abort rejection value with configured status, body, and
    /// headers (the pipeline writes it through the shared exit helper).
    fn abort_rejection(abort_config: &AbortConfig) -> Rejection {
        let status = StatusCode::from_u16(abort_config.http_status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let mut rejection = Rejection::new(status)
            .with_body(abort_config.body.clone().unwrap_or_default())
            .with_content_type(crate::utils::response::content_type::TEXT_PLAIN);

        // Add custom headers if configured
        if let Some(ref headers) = abort_config.headers {
            for (name, value) in headers {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue, // Skip complex types
                };
                rejection = rejection.with_header(name.clone(), value_str);
            }
        }

        rejection
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
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        // Apply delay first (if configured)
        self.apply_delay().await;

        // Then check if request should be aborted (if configured)
        Ok(self.check_and_abort().unwrap_or(FilterVerdict::Continue))
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

        let huge = json!({
            "delay": {
                "duration": 1e300
            }
        });
        assert!(
            PluginConfig::try_from(huge).is_err(),
            "overflowing duration must be rejected before Duration::from_secs_f64"
        );
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

    #[test]
    fn bodyless_abort_preserves_plain_text_content_type() {
        let config = PluginConfig::try_from(json!({
            "abort": { "http_status": 503 }
        }))
        .expect("valid abort");
        let abort = config.abort.as_ref().expect("abort config");
        let rejection = PluginFaultInjection::abort_rejection(abort);
        assert_eq!(rejection.body.as_deref(), Some(""));
        assert_eq!(
            rejection.content_type.as_deref(),
            Some(crate::utils::response::content_type::TEXT_PLAIN)
        );
    }

    #[test]
    fn nonempty_apisix_vars_are_rejected() {
        let delay = json!({
            "delay": {
                "duration": 0.5,
                "vars": [["arg_name", "==", "test"]]
            }
        });
        let err = PluginConfig::try_from(delay).expect_err("delay.vars must be rejected");
        assert!(err.to_string().contains("var expressions"), "{err}");

        // APISIX vars commonly carry numbers; they must reach the friendly
        // error rather than a raw serde type error.
        let numeric = json!({
            "delay": {
                "duration": 0.5,
                "vars": [["arg_limit", ">", 100]]
            }
        });
        let err = PluginConfig::try_from(numeric).expect_err("numeric vars must be rejected");
        assert!(err.to_string().contains("var expressions"), "{err}");

        let abort = json!({
            "abort": {
                "http_status": 503,
                "vars": [["http_x-custom", "!", "skip"]]
            }
        });
        let err = PluginConfig::try_from(abort).expect_err("abort.vars must be rejected");
        assert!(err.to_string().contains("var expressions"), "{err}");

        // Empty vars arrays are structural no-ops and remain accepted.
        PluginConfig::try_from(json!({
            "delay": {"duration": 0.5, "vars": []}
        }))
        .expect("empty vars is a no-op");
    }

    #[test]
    fn test_config_abort_headers_must_not_be_empty() {
        let cfg = json!({
            "abort": {
                "http_status": 503,
                "headers": {}
            }
        });
        assert!(PluginConfig::try_from(cfg).is_err());
    }

    #[test]
    fn test_config_abort_headers_accept_strings_and_numbers() {
        let cfg = json!({
            "abort": {
                "http_status": 503,
                "headers": {
                    "X-String": "value",
                    "X-Number": 42
                }
            }
        });
        assert!(PluginConfig::try_from(cfg).is_ok());
    }

    #[test]
    fn test_config_abort_headers_reject_bool_null_object_array() {
        for bad in [json!(true), json!(null), json!({}), json!([])] {
            let cfg = json!({
                "abort": {
                    "http_status": 503,
                    "headers": { "X-Bad": bad }
                }
            });
            let err = PluginConfig::try_from(cfg).unwrap_err();
            assert!(matches!(err, ProxyError::Validation(_)));
        }
    }

    #[test]
    fn test_config_abort_headers_reject_malformed_names_and_values_at_build() {
        let bad_name = json!({
            "abort": { "http_status": 503, "headers": { "X Bad": "v" } }
        });
        let err = PluginConfig::try_from(bad_name).unwrap_err();
        assert!(err.to_string().contains("X Bad"), "{err}");

        let bad_value = json!({
            "abort": { "http_status": 503, "headers": { "X-Ok": "bad\r\nvalue" } }
        });
        let err = PluginConfig::try_from(bad_value).unwrap_err();
        assert!(err.to_string().contains("X-Ok"), "{err}");

        // Valid names and numeric values still pass.
        assert!(PluginConfig::try_from(json!({
            "abort": { "http_status": 503, "headers": { "X-Ok": "v", "X-Num": 42 } }
        }))
        .is_ok());
    }
}
