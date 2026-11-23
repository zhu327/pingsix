//! Leaky-bucket rate limiting plugin, APISIX `limit-req` compatible.
//!
//! Limits request velocity per key using the leaky bucket algorithm: up to
//! `rate` requests per second pass immediately; requests up to `rate + burst`
//! are delayed (queued) rather than dropped; requests beyond `rate + burst`
//! are rejected with `rejected_code`. With `nodelay: true` no delay is
//! applied, so the burst capacity is consumed at full speed and subsequent
//! requests are rejected until the bucket drains.
//!
//! The algorithm mirrors `lua-resty-limit-traffic`'s `limit/req.lua`
//! `incoming()` so behavior matches APISIX with `policy: local`. Schema,
//! pure transition, and hook wiring live here; shard admission/overflow,
//! policy enums, and the rejection writer live in `plugins::limiting`.

use std::{
    collections::hash_map::Entry,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::{
        config::parse_and_validate_plugin_config,
        limiting::{
            default_rejected_code, validate_key, validate_rejected_msg, BoundedShardMap, KeyType,
            Policy, RejectPolicy, SweepMiss, LIMIT_REQ_OVERFLOW,
        },
    },
    utils::request::apisix_key,
};

pub const PLUGIN_NAME: &str = "limit-req";

/// APISIX `limit-req` runs at priority 1001 (before limit-count 1002).
const PRIORITY: i32 = 1001;

/// Creates a `limit-req` plugin instance from JSON configuration.
pub fn create_limit_req_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginLimitReq {
        reject: RejectPolicy::new(config.rejected_code, config.rejected_msg.clone()),
        config,
        buckets: BoundedShardMap::new(),
    }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators WITHOUT constructing the plugin (no buckets allocated).
pub fn validate_limit_req_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?;
    Ok(())
}

/// Mutable leaky-bucket state for one key. `last` is the drain anchor: the
/// instant from which the next request measures elapsed draining time.
struct Bucket {
    excess: f64,
    last: Instant,
}

/// Pure leaky-bucket transition (unit-testable).
///
/// Returns `Ok((delay_secs, new_excess))` when the request may proceed
/// (`delay` is 0 when `nodelay` is set), or `Err(())` when the request
/// exceeds `rate + burst`.
fn leaky_bucket_step(
    old_excess: f64,
    elapsed_secs: f64,
    rate: f64,
    burst: f64,
    nodelay: bool,
) -> Result<(f64, f64), ()> {
    let excess = (old_excess - elapsed_secs * rate + 1.0).max(0.0);
    if excess > burst {
        return Err(());
    }
    let _ = nodelay; // nodelay skips sleeping; it never changes state.
    Ok((excess / rate, excess))
}

/// Apply one request to an already-tracked bucket at time `now`.
///
/// Mirrors `lua-resty-limit-traffic`'s `limit/req.lua` commit discipline: the
/// drain anchor (`last`) and `excess` are written only when the request is
/// accepted. A rejected request leaves both untouched — otherwise every
/// rejection would re-anchor the drain clock and a client retrying just
/// above the rate would stay locked out forever.
fn bucket_incoming(
    bucket: &mut Bucket,
    now: Instant,
    rate: f64,
    burst: f64,
    nodelay: bool,
) -> Result<f64, ()> {
    let elapsed = now.duration_since(bucket.last).as_secs_f64();
    match leaky_bucket_step(bucket.excess, elapsed, rate, burst, nodelay) {
        Ok((delay, new_excess)) => {
            bucket.last = now;
            bucket.excess = new_excess;
            Ok(delay)
        }
        Err(()) => Err(()),
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Maximum number of requests allowed per second (bucket drain rate).
    #[validate(custom(function = "validate_rate"))]
    rate: f64,

    /// Number of requests allowed to be delayed (bucket capacity above rate).
    /// APISIX allows fractional burst values; pingsix keeps its default of 0.
    #[serde(default)]
    #[validate(custom(function = "validate_burst"))]
    burst: f64,

    #[serde(default)]
    key_type: KeyType,

    /// Variable (or whitespace-separated variable combination) to key on.
    #[validate(custom(function = "validate_key"))]
    key: String,

    #[serde(default = "default_rejected_code")]
    #[validate(range(min = 200, max = 599))]
    rejected_code: u16,

    #[serde(default)]
    #[validate(custom(function = "validate_rejected_msg"))]
    rejected_msg: Option<String>,

    /// If true, requests within the burst range are not delayed; the burst is
    /// consumed at full speed and further requests are rejected.
    #[serde(default)]
    nodelay: bool,

    /// Counter backend. Only `local` is supported in this release.
    #[serde(default)]
    policy: Policy,
}

const MAX_DELAY_SECS: f64 = 86_400.0;

fn validate_rate(value: f64) -> Result<(), ValidationError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(ValidationError::new("rate must be > 0"));
    }
    Ok(())
}

fn validate_burst(value: f64) -> Result<(), ValidationError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ValidationError::new("burst must be >= 0"));
    }
    Ok(())
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid limit-req plugin config")?;
        config.policy.ensure_local("limit-req")?;
        let max_delay = config.burst / config.rate;
        if !max_delay.is_finite()
            || max_delay > MAX_DELAY_SECS
            || Duration::try_from_secs_f64(max_delay).is_err()
        {
            return Err(ProxyError::validation_error(format!(
                "limit-req maximum burst delay (burst / rate) must be finite and <= {MAX_DELAY_SECS}s"
            )));
        }
        Ok(config)
    }
}

/// Leaky-bucket rate limiting plugin implementation.
pub struct PluginLimitReq {
    config: PluginConfig,
    /// Sharded leaky buckets. Admission, the stable overflow bucket, and the
    /// budgeted drain sweep are the shared `plugins::limiting` machinery;
    /// only the drain predicate and the transition are plugin-local.
    buckets: BoundedShardMap<Bucket>,
    reject: RejectPolicy,
}

#[async_trait]
impl ProxyPlugin for PluginLimitReq {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        let key = apisix_key(
            session,
            &self.config.key,
            self.config.key_type == KeyType::VarCombination,
        );

        let now = Instant::now();
        let rate = self.config.rate;

        // The lock is held only for the pure state transition; sleeping and
        // response writes happen after the bucket state is updated.
        let (delay, rejected) = {
            let mut buckets = self.buckets.lock(key.as_ref());
            match buckets.admit(&key, LIMIT_REQ_OVERFLOW, |shard| {
                // A drained bucket leaves no residue worth keeping. Fixed
                // work budget; no request can scan the full map.
                shard.sweep(
                    |bucket| now.duration_since(bucket.last).as_secs_f64() * rate >= bucket.excess,
                    SweepMiss::Restore,
                )
            }) {
                Entry::Vacant(slot) => {
                    // First request for this bucket initializes it and passes.
                    slot.insert(Bucket {
                        excess: 0.0,
                        last: now,
                    });
                    (Some(0.0), false)
                }
                Entry::Occupied(slot) => match bucket_incoming(
                    slot.into_mut(),
                    now,
                    rate,
                    self.config.burst,
                    self.config.nodelay,
                ) {
                    Ok(delay) => (Some(delay), false),
                    Err(()) => (None, true),
                },
            }
        };

        if rejected {
            return Ok(FilterVerdict::Reject(self.reject.rejection()));
        }

        let delay = delay.expect("not rejected implies a delay");
        if delay > 0.0 && !self.config.nodelay {
            let sleep_duration = Duration::try_from_secs_f64(delay.clamp(0.0, MAX_DELAY_SECS))
                .unwrap_or_else(|_| Duration::from_secs(MAX_DELAY_SECS as u64));
            tokio::time::sleep(sleep_duration).await;
        }
        Ok(FilterVerdict::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_empty_state_adds_one_request() {
        assert_eq!(
            leaky_bucket_step(0.0, 0.0, 1.0, 1.0, false).unwrap(),
            (1.0, 1.0)
        );
    }

    #[test]
    fn existing_state_uses_post_increment_excess_for_delay() {
        // resty.limit.req calculates max(old - elapsed * rate + 1, 0), then
        // returns delay = excess / rate.
        assert_eq!(
            leaky_bucket_step(1.0, 0.5, 2.0, 2.0, false).unwrap(),
            (0.5, 1.0)
        );
    }

    #[test]
    fn idle_bucket_drains_and_next_request_has_no_delay() {
        assert_eq!(
            leaky_bucket_step(5.0, 5.0, 1.0, 1.0, false).unwrap(),
            (1.0, 1.0)
        );
    }

    #[test]
    fn above_rate_plus_burst_is_rejected() {
        // rate=1, burst=1: after two immediate arrivals excess is 2 > burst 1.
        assert_eq!(leaky_bucket_step(2.0, 0.0, 1.0, 1.0, false), Err(()));
    }

    #[test]
    fn nodelay_only_suppresses_sleep_not_state() {
        assert_eq!(
            leaky_bucket_step(0.0, 0.0, 1.0, 1.0, true).unwrap(),
            (1.0, 1.0)
        );
        assert_eq!(
            leaky_bucket_step(0.0, 0.0, 1.0, 1.0, false).unwrap(),
            (1.0, 1.0)
        );
        assert_eq!(leaky_bucket_step(1.0, 0.0, 1.0, 1.0, true), Err(()));
    }

    #[test]
    fn bucket_drains_over_time() {
        // excess 2, rate 1: after 1.5s the new excess is 1.5, which
        // exceeds burst 1 and is rejected.
        assert_eq!(leaky_bucket_step(2.0, 1.5, 1.0, 1.0, false), Err(()));
    }

    #[test]
    fn fractional_burst_is_accepted() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0.5,
            "key": "remote_addr"
        }))
        .unwrap();
        assert_eq!(config.burst, 0.5);
        assert_eq!(
            leaky_bucket_step(0.25, 0.0, 1.0, 1.25, false),
            Ok((1.25, 1.25))
        );
    }

    #[test]
    fn rejected_request_does_not_reanchor_drain_clock() {
        // rate=1, burst=0: accepted at t0, rejected at t0+0.5s, accepted
        // again at t0+1.1s. Before the fix the rejection committed
        // `last = t0+0.5`, so the retry only saw 0.6s of drain and was
        // rejected too — a client retrying just above the rate stayed
        // locked out forever.
        let t0 = Instant::now();
        // The bucket `request_filter` leaves behind after the accepted
        // request at t0 (first request initializes and passes with excess 0).
        let mut bucket = Bucket {
            excess: 0.0,
            last: t0,
        };
        // t0+0.5s: excess = max(0 - 0.5*1 + 1, 0) = 0.5 > burst 0 -> rejected.
        assert_eq!(
            bucket_incoming(
                &mut bucket,
                t0 + Duration::from_millis(500),
                1.0,
                0.0,
                false
            ),
            Err(())
        );
        // The rejection must have left BOTH `last` and `excess` untouched.
        assert_eq!(bucket.last, t0);
        assert_eq!(bucket.excess, 0.0);
        // t0+1.1s: the bucket fully drained since t0, so the retry passes.
        assert_eq!(
            bucket_incoming(
                &mut bucket,
                t0 + Duration::from_millis(1100),
                1.0,
                0.0,
                false
            ),
            Ok(0.0)
        );
    }

    #[test]
    fn accepted_request_commits_drain_anchor_and_excess() {
        let t0 = Instant::now();
        let mut bucket = Bucket {
            excess: 0.0,
            last: t0,
        };
        // Accepted at t0+0.5s: excess = max(0 - 0.5 + 1, 0) = 0.5, delay 0.5.
        assert_eq!(
            bucket_incoming(
                &mut bucket,
                t0 + Duration::from_millis(500),
                1.0,
                1.0,
                false
            ),
            Ok(0.5)
        );
        assert_eq!(bucket.excess, 0.5);
        assert_eq!(bucket.last, t0 + Duration::from_millis(500));
    }

    #[test]
    fn config_rejects_invalid_values() {
        assert!(PluginConfig::try_from(
            serde_json::json!({ "rate": 0, "burst": 0, "key": "remote_addr" })
        )
        .is_err());
        assert!(PluginConfig::try_from(
            serde_json::json!({ "rate": 1, "burst": -0.5, "key": "remote_addr" })
        )
        .is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "rate": 1, "burst": 0, "key": "" }))
                .is_err()
        );
        assert!(PluginConfig::try_from(
            serde_json::json!({ "rate": 1, "burst": 0, "key": "remote_addr", "policy": "redis" })
        )
        .is_err());
    }

    #[test]
    fn config_rejects_redis_cluster_policy_with_clear_validation_error() {
        let err = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr",
            "policy": "redis-cluster"
        }))
        .unwrap_err();
        assert!(err.to_string().contains("requires a distributed backend"));
    }

    #[test]
    fn config_accepts_var_combination_key_type() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "$remote_addr $http_x_user",
            "key_type": "var_combination"
        }))
        .unwrap();
        assert_eq!(config.key_type, KeyType::VarCombination);
    }

    #[test]
    fn config_defaults_match_apisix() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr"
        }))
        .unwrap();
        assert_eq!(config.rejected_code, 503);
        assert!(!config.nodelay);
        assert_eq!(config.key_type, KeyType::Var);
        assert_eq!(config.policy, Policy::Local);
    }

    #[test]
    fn config_ignores_unknown_fields_and_rejects_status_outside_http_range() {
        // Fields outside the limit-req schema (e.g. limit-count's `rules`)
        // are tolerated and ignored.
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1, "burst": 0, "key": "remote_addr", "rules": []
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(config.rate, 1.0);
        assert!(PluginConfig::try_from(serde_json::json!({
            "rate": 1, "burst": 0, "key": "remote_addr", "rejected_code": 199
        }))
        .is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({
                "rate": 1e-300, "burst": 1e300, "key": "remote_addr"
            }))
            .is_err(),
            "overflowing burst / rate delay must be rejected"
        );
    }

    #[test]
    fn config_accepts_rejected_code_200_and_rejects_empty_msg() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr",
            "rejected_code": 200
        }))
        .unwrap();
        assert_eq!(config.rejected_code, 200);
        assert!(PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr",
            "rejected_msg": ""
        }))
        .is_err());
    }
}
