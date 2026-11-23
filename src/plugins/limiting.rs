//! Shared machinery for the local limiter plugin family (`limit-req`,
//! `limit-conn`, `limit-count`) and `api-breaker`.
//!
//! These plugins re-derived identical scaffolding around genuinely different
//! cores (leaky bucket, connection counting, rate estimator / sliding window,
//! breaker state machine). This module owns the scaffolding once, following
//! the `compression.rs` model: each plugin keeps its schema (`TryFrom`), its
//! pure transition function, and its hook wiring; everything below is shared:
//!
//! - [`Policy`] / [`CountPolicy`] / [`KeyType`] / [`CountKeyType`] with their
//!   serde shapes and the "only local supported" rejection.
//! - [`BoundedShardMap`] / [`Shard`]: shard-aware admission, one stable
//!   overflow bucket per shard, and budgeted recency sweeps. `api-breaker`
//!   uses [`Shard`] directly for its simpler fixed-capacity LRU.
//! - [`resolve_rule_key`] / [`select_rules`]: APISIX `rules`-branch key
//!   resolution shared by `limit-conn` and `limit-count`.
//! - [`RejectPolicy`] / [`rejection`]: the ONE constructor for every limiter
//!   rejection. Post-T10 it constructs the returned [`Rejection`] value and
//!   the plugin returns it via `FilterVerdict::Reject`; the pipeline writes
//!   it through `send_exit_response` (so an `exit-transformer` rule sees
//!   limiter rejections exactly like every other gateway exit).
//! - [`instance_ctx_key`]: per-instance context keys so a global and a route
//!   instance of the same limiter never share state slots.

use std::{
    borrow::Cow,
    collections::{hash_map::Entry, HashMap},
    sync::{Mutex, MutexGuard},
};

use http::StatusCode;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use validator::ValidationError;

use crate::{
    core::{ProxyError, ProxyResult, Rejection},
    plugins::limiter_shards::{
        shard_idx, TouchOrder, CLEANUP_BUDGET, LIMIT_SHARDS, PER_SHARD_REGULAR_MAX,
    },
    utils::{request::render_apisix_request_template, response::content_type},
};

/// Stable overflow bucket for the `limit-req` plugin's shards.
pub(crate) const LIMIT_REQ_OVERFLOW: &str = "__pingsix_limit_req_overflow__";
/// Stable overflow bucket for the `limit-conn` plugin's shards.
pub(crate) const LIMIT_CONN_OVERFLOW: &str = "__pingsix_limit_conn_overflow__";
/// Stable overflow bucket for the `limit-count` plugin's shards.
pub(crate) const LIMIT_COUNT_OVERFLOW: &str = "__pingsix_limit_count_overflow__";

/// Counter backend shared by `limit-req` and `limit-conn`. Only `local` is
/// supported in this release; the other APISIX values parse so their
/// rejection carries a clear message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Policy {
    #[default]
    Local,
    Redis,
    #[serde(rename = "redis-cluster")]
    RedisCluster,
}

impl Policy {
    /// Reject every non-local backend with the established APISIX wording.
    pub(crate) fn ensure_local(self, plugin: &'static str) -> ProxyResult<()> {
        if self == Policy::Local {
            return Ok(());
        }
        Err(ProxyError::validation_error(format!(
            "{plugin} policy 'redis'/'redis-cluster' requires a distributed backend; only 'local' is supported"
        )))
    }
}

/// `limit-count`'s wider backend list (adds `redis-sentinel`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CountPolicy {
    #[default]
    Local,
    Redis,
    #[serde(rename = "redis-cluster")]
    RedisCluster,
    #[serde(rename = "redis-sentinel")]
    RedisSentinel,
}

impl CountPolicy {
    /// Reject every non-local backend with the established APISIX wording.
    pub(crate) fn ensure_local(self, plugin: &'static str) -> ProxyResult<()> {
        if self == CountPolicy::Local {
            return Ok(());
        }
        Err(ProxyError::validation_error(format!(
            "{plugin} policy 'redis'/'redis-cluster'/'redis-sentinel' requires a distributed backend; only 'local' is supported"
        )))
    }
}

/// Key selection mode shared by `limit-req` and `limit-conn`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum KeyType {
    #[default]
    Var,
    #[serde(rename = "var_combination")]
    VarCombination,
}

/// `limit-count`'s wider key selection (APISIX `constant` plus pingsix's
/// legacy `head`/`cookie` selectors).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CountKeyType {
    #[default]
    Var,
    #[serde(rename = "var_combination")]
    VarCombination,
    Constant,
    /// Pingsix legacy selector: `key` names an HTTP request header.
    Head,
    /// Pingsix legacy selector: `key` names a cookie.
    Cookie,
}

/// APISIX `rejected_code` default shared by every limiter.
pub(crate) fn default_rejected_code() -> u16 {
    503
}

/// Validates a limiter `key`. APISIX keys may be nginx variables or variable
/// combinations, so no character restrictions are applied beyond non-emptiness.
pub(crate) fn validate_key(key: &str) -> Result<(), ValidationError> {
    if key.trim().is_empty() {
        return Err(ValidationError::new("key cannot be empty"));
    }
    Ok(())
}

pub(crate) fn validate_rejected_msg(value: &&String) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new(
            "rejected_msg must have at least 1 character",
        ));
    }
    Ok(())
}

/// The configured `rejected_code`/`rejected_msg` pair, snapshot from the
/// plugin config at construction so the request path stays read-only.
#[derive(Debug, Clone)]
pub(crate) struct RejectPolicy {
    code: u16,
    msg: Option<String>,
}

impl RejectPolicy {
    pub(crate) fn new(code: u16, msg: Option<String>) -> Self {
        Self { code, msg }
    }

    /// Historical fallback shared by every limiter writer.
    pub(crate) fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.code).unwrap_or(StatusCode::SERVICE_UNAVAILABLE)
    }

    /// Reject the request with the configured code and message (T10: a
    /// returned value; the pipeline writes it).
    pub(crate) fn rejection(&self) -> Rejection {
        rejection(self.status(), self.msg.as_deref(), &[])
    }
}

/// The single constructor every limiter-family rejection goes through (T10).
///
/// The value travels out of the plugin via `FilterVerdict::Reject` and the
/// pipeline writes it through `send_exit_response`, so an `exit-transformer`
/// rule sees limiter rejections exactly like every other gateway exit. The
/// content type for bodies matches the historical
/// `ResponseBuilder::send_proxy_error` framing (`text/plain`).
pub(crate) fn rejection(
    status: StatusCode,
    body: Option<&str>,
    extra_headers: &[(String, String)],
) -> Rejection {
    let mut value = Rejection::new(status).with_headers(extra_headers.iter().cloned());
    if let Some(body) = body {
        value = value
            .with_body(body)
            .with_content_type(content_type::TEXT_PLAIN);
    }
    value
}

/// Evaluate an APISIX `rules` entry's key template. APISIX skips a rule only
/// when the template contains no placeholders; a placeholder whose variable
/// is absent renders empty and is still enforced as the empty-key bucket.
pub(crate) fn resolve_rule_key(session: &mut Session, rule_key: &str) -> Option<Cow<'static, str>> {
    if !rule_key.contains('$') {
        return None;
    }
    Some(Cow::Owned(render_apisix_request_template(
        session, rule_key,
    )))
}

/// Resolve every matching rule's key (APISIX enforces all of them) and map
/// each to its plugin-specific selection. Returns `None` when no rule
/// applies; the caller turns that into 500 or `allow_degradation` pass,
/// mirroring APISIX.
pub(crate) fn select_rules<'a, R, S>(
    session: &mut Session,
    rules: &'a [R],
    rule_key: impl Fn(&'a R) -> &'a str,
    mut selection: impl FnMut(usize, &'a R, Cow<'static, str>) -> S,
) -> Option<Vec<S>> {
    let mut selected = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        if let Some(key) = resolve_rule_key(session, rule_key(rule)) {
            selected.push(selection(index, rule, key));
        }
    }
    if selected.is_empty() {
        None
    } else {
        Some(selected)
    }
}

/// Per-instance context keys moved to the crate-wide [`super::ctx_keys`]
/// module (T12); re-exported so existing limiter call sites stay put.
pub(crate) use super::ctx_keys::next_instance_ctx_key;

/// What [`Shard::sweep`] does with an entry that fails the eviction
/// predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SweepMiss {
    /// Restore the entry's original recency position (drain/age predicates,
    /// where eviction pressure is proportional to idle time).
    Restore,
    /// Move the entry to the back of the recency order so one hot oldest
    /// entry cannot consume every bounded-cleanup slot (active-connection
    /// predicates).
    PushBack,
}

/// One shard of a bounded limiter map: the entries plus their recency order.
///
/// Capacity policy (admission, overflow bucket, budgeted sweep) lives here
/// once; each limiter supplies its own eviction predicate.
pub(crate) struct Shard<V> {
    entries: HashMap<String, V>,
    touch_order: TouchOrder,
}

// Hand-implemented: the derive would demand `V: Default`, but the entry type
// never is (only the map is).
impl<V> Default for Shard<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            touch_order: TouchOrder::default(),
        }
    }
}

impl<V> Shard<V> {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Mark an entry as most recently used.
    pub(crate) fn touch(&mut self, key: &str) {
        self.touch_order.touch(key);
    }

    /// HashMap entry API for callers that insert explicitly.
    pub(crate) fn entry(&mut self, key: String) -> Entry<'_, String, V> {
        self.entries.entry(key)
    }

    /// Unconditionally evict the least recently used entry, if any. Used by
    /// the fixed-capacity variant (api-breaker); the limiters prefer the
    /// predicate-driven [`Shard::sweep`] so live state is never evicted.
    pub(crate) fn evict_oldest(&mut self) {
        if let Some((_touch, key)) = self.touch_order.pop_oldest() {
            self.entries.remove(&key);
        }
    }

    /// Budgeted recency sweep: examine at most [`CLEANUP_BUDGET`] oldest
    /// entries, removing those whose state satisfies `evict` (an entry with
    /// no state is always removed). No request can scan the full map.
    pub(crate) fn sweep(&mut self, evict: impl Fn(&V) -> bool, on_miss: SweepMiss) {
        let mut restored = Vec::new();
        for _ in 0..CLEANUP_BUDGET {
            let Some((touch, key)) = self.touch_order.pop_oldest() else {
                break;
            };
            if self.entries.get(&key).is_none_or(&evict) {
                self.entries.remove(&key);
            } else {
                match on_miss {
                    // Defer re-insertion until after the loop so a single
                    // non-evictable oldest entry does not consume all
                    // CLEANUP_BUDGET iterations.
                    SweepMiss::Restore => restored.push((touch, key)),
                    SweepMiss::PushBack => self.touch(&key),
                }
            }
        }
        for (touch, key) in restored {
            self.touch_order.restore(touch, key);
        }
    }

    /// Admit `key` under the shared bounded-shard admission policy and
    /// return the entry for its storage slot.
    ///
    /// Extant entries never trigger a sweep and always keep their slot. A new
    /// key gets one budgeted sweep when the shard is full, then either a
    /// regular slot or the stable overflow bucket (`overflow_key`) it shares
    /// with other overflowed keys. The caller decides what the entry holds on
    /// first use (limiters never evict live state into another key).
    pub(crate) fn admit(
        &mut self,
        key: &str,
        overflow_key: &str,
        sweep: impl FnOnce(&mut Self),
    ) -> Entry<'_, String, V> {
        let new_key = !self.entries.contains_key(key);
        if new_key && self.entries.len() >= PER_SHARD_REGULAR_MAX {
            sweep(self);
        }
        let storage_key = if !new_key || self.entries.len() < PER_SHARD_REGULAR_MAX {
            key.to_string()
        } else {
            overflow_key.to_string()
        };
        self.touch(&storage_key);
        self.entries.entry(storage_key)
    }
}

/// Sharded, capacity-bounded map from limiter keys to per-key state.
///
/// Sharding keeps requests with different keys off the same mutex and bounds
/// any cleanup sweep to one shard (1/`LIMIT_SHARDS` of keys). Entries are
/// swept when a shard grows past its per-shard capacity, bounding memory
/// under ephemeral keys; each shard reserves one slot for its stable
/// overflow bucket.
pub(crate) struct BoundedShardMap<V> {
    shards: [Mutex<Shard<V>>; LIMIT_SHARDS],
}

impl<V> Default for BoundedShardMap<V> {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(Shard::default())),
        }
    }
}

impl<V> BoundedShardMap<V> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Lock the shard owning `key`. Overflowed keys stay in the shard of the
    /// key that overflowed even though the sentinel hashes elsewhere, so all
    /// callers must reach the map through the original key.
    pub(crate) fn lock(&self, key: &str) -> MutexGuard<'_, Shard<V>> {
        self.shards[shard_idx(key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing;

    const TEST_OVERFLOW: &str = "__pingsix_test_overflow__";

    fn fill_shard(shard: &mut Shard<u32>, n: usize) {
        for i in 0..n {
            let key = i.to_string();
            shard
                .admit(&key, TEST_OVERFLOW, |_| {
                    panic!("below capacity no sweep runs")
                })
                .or_insert(i as u32);
        }
    }

    #[test]
    fn admission_uses_one_stable_overflow_bucket_once_regular_slots_fill() {
        let mut shard: Shard<u32> = Shard::default();
        fill_shard(&mut shard, PER_SHARD_REGULAR_MAX);

        // The sweep evicts nothing, so a new key lands in the overflow bucket.
        let no_evictions = |_: &u32| false;
        shard
            .admit("stray-a", TEST_OVERFLOW, |shard| {
                shard.sweep(no_evictions, SweepMiss::Restore)
            })
            .or_insert(1);
        assert_eq!(shard.len(), PER_SHARD_REGULAR_MAX + 1);
        assert!(shard.contains_key(TEST_OVERFLOW));

        // Further overflowed keys share that one stable entry.
        match shard.admit("stray-b", TEST_OVERFLOW, |shard| {
            shard.sweep(no_evictions, SweepMiss::Restore)
        }) {
            Entry::Occupied(slot) => assert_eq!(*slot.get(), 1),
            Entry::Vacant(_) => panic!("overflowed keys must share the stable bucket"),
        }
        assert_eq!(shard.len(), PER_SHARD_REGULAR_MAX + 1);
    }

    #[test]
    fn swept_slots_are_reused_by_new_keys() {
        let mut shard: Shard<u32> = Shard::default();
        fill_shard(&mut shard, PER_SHARD_REGULAR_MAX);
        // Every entry is evictable, so the budgeted sweep frees slots and the
        // new key gets a regular slot rather than the overflow bucket.
        match shard.admit("fresh", TEST_OVERFLOW, |shard| {
            shard.sweep(|_| true, SweepMiss::Restore)
        }) {
            Entry::Vacant(slot) => slot.insert(99),
            Entry::Occupied(_) => panic!("freed regular slot must be vacant"),
        };
        assert!(shard.contains_key("fresh"));
        assert!(!shard.contains_key(TEST_OVERFLOW));
    }

    #[test]
    fn admit_of_existing_key_never_sweeps_even_at_capacity() {
        let mut shard: Shard<u32> = Shard::default();
        fill_shard(&mut shard, PER_SHARD_REGULAR_MAX);
        match shard.admit("0", TEST_OVERFLOW, |_| panic!("existing keys never sweep")) {
            Entry::Occupied(slot) => assert_eq!(*slot.get(), 0),
            Entry::Vacant(_) => panic!("existing key stays in its slot"),
        }
        assert_eq!(shard.len(), PER_SHARD_REGULAR_MAX);
    }

    #[test]
    fn sweep_removes_at_most_budget_matching_entries() {
        let mut shard: Shard<u32> = Shard::default();
        for i in 0..CLEANUP_BUDGET + 2 {
            let key = i.to_string();
            shard.entry(key.clone()).or_insert(i as u32);
            shard.touch(&key);
        }
        shard.sweep(|_| true, SweepMiss::Restore);
        assert_eq!(shard.len(), 2, "an 8-item budget leaves two entries");
    }

    #[test]
    fn sweep_restore_evicts_eligible_entries_behind_non_evictable_oldest() {
        let mut shard: Shard<u32> = Shard::default();
        // Oldest entry is live (`1`, not evictable); subsequent entries are expired (`0`).
        shard.entry("live-oldest".into()).or_insert(1);
        shard.touch("live-oldest");
        for i in 0..CLEANUP_BUDGET {
            let key = format!("expired-{i}");
            shard.entry(key.clone()).or_insert(0);
            shard.touch(&key);
        }

        shard.sweep(|v| *v == 0, SweepMiss::Restore);

        // Budget of 8 visits `live-oldest` (restored) plus 7 expired entries (evicted).
        assert!(shard.contains_key("live-oldest"));
        assert_eq!(
            shard.len(),
            2,
            "SweepMiss::Restore must inspect past a non-evictable oldest entry"
        );
        // `live-oldest` kept its original oldest recency position.
        shard.evict_oldest();
        assert!(!shard.contains_key("live-oldest"));
    }

    #[test]
    fn sweep_pushback_keeps_nonmatching_entries_and_stays_within_budget() {
        // Mirrors limit-conn: active entries (`1`) are never evicted and are
        // pushed to the back so they cannot consume every cleanup slot.
        let mut shard: Shard<u32> = Shard::default();
        shard.entry("active".into()).or_insert(1);
        shard.touch("active");
        for i in 0..CLEANUP_BUDGET + 2 {
            let key = i.to_string();
            shard.entry(key.clone()).or_insert(0);
            shard.touch(&key);
        }
        shard.sweep(|v| *v == 0, SweepMiss::PushBack);
        assert!(shard.contains_key("active"));
        assert_eq!(shard.len(), 4, "the active entry plus two inactive remain");
    }

    #[test]
    fn evict_oldest_drops_least_recently_touched_entry() {
        let mut shard: Shard<u32> = Shard::default();
        for (i, key) in ["a", "b", "c"].iter().enumerate() {
            shard.entry(key.to_string()).or_insert(i as u32);
            shard.touch(key);
        }
        shard.evict_oldest();
        assert!(!shard.contains_key("a"));
        shard.evict_oldest();
        assert!(!shard.contains_key("b"));
        assert!(shard.contains_key("c"));
        assert_eq!(shard.len(), 1);
    }

    #[test]
    fn bounded_shard_map_routes_keys_deterministically() {
        let map: BoundedShardMap<u32> = BoundedShardMap::new();
        map.lock("alpha").entry("alpha".into()).or_insert(1);
        match map.lock("alpha").entry("alpha".into()) {
            Entry::Occupied(slot) => assert_eq!(*slot.get(), 1),
            Entry::Vacant(_) => panic!("the inserted entry is routed to the same shard"),
        };
    }

    #[test]
    fn non_local_policies_are_rejected_with_the_established_wording() {
        assert!(Policy::Local.ensure_local("limit-req").is_ok());
        assert!(CountPolicy::Local.ensure_local("limit-count").is_ok());

        let err = Policy::Redis.ensure_local("limit-req").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Validation error: limit-req policy 'redis'/'redis-cluster' requires a distributed backend; only 'local' is supported"
        );
        let err = Policy::RedisCluster.ensure_local("limit-conn").unwrap_err();
        assert!(err
            .to_string()
            .starts_with("Validation error: limit-conn policy 'redis'/'redis-cluster' requires"));
        let err = CountPolicy::RedisSentinel
            .ensure_local("limit-count")
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Validation error: limit-count policy 'redis'/'redis-cluster'/'redis-sentinel' requires a distributed backend; only 'local' is supported"
        );
    }

    #[test]
    fn shared_validators_pin_the_established_wording() {
        assert!(validate_key("remote_addr").is_ok());
        assert!(validate_key("   ").is_err());
        assert!(validate_rejected_msg(&&"busy".to_string()).is_ok());
        let err = validate_rejected_msg(&&String::new()).unwrap_err();
        assert_eq!(err.code, "rejected_msg must have at least 1 character");
        assert_eq!(default_rejected_code(), 503);
    }

    #[tokio::test]
    async fn bare_rule_keys_are_skipped_and_templates_render() {
        let mut session = testing::session_from_request(&testing::http_get_wire("/", &[])).await;
        assert!(resolve_rule_key(&mut session, "remote_addr").is_none());
        // Absent variables render empty and still count as a match (the
        // empty-key bucket, per APISIX).
        assert_eq!(
            resolve_rule_key(&mut session, "$http_x_missing"),
            Some(Cow::Owned(String::new()))
        );
    }

    #[tokio::test]
    async fn select_rules_enforces_every_matching_template_rule_or_none() {
        struct Rule {
            key: &'static str,
            n: u32,
        }
        let rules = [
            Rule {
                key: "$http_a",
                n: 1,
            },
            Rule { key: "bare", n: 2 },
            Rule {
                key: "$http_b",
                n: 3,
            },
        ];
        let mut session = testing::session_from_request(&testing::http_get_wire("/", &[])).await;
        let selected = select_rules(
            &mut session,
            &rules,
            |rule| rule.key,
            |index, rule, key| (index, rule.n, key.into_owned()),
        )
        .expect("template rules apply under the empty-key bucket");
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].1, 1);
        assert_eq!(selected[1].1, 3);
        assert!(selected.iter().all(|(_, _, key)| key.is_empty()));

        let bare_only = [Rule { key: "bare", n: 1 }];
        assert!(select_rules(
            &mut session,
            &bare_only,
            |rule| rule.key,
            |index, rule: &Rule, key| (index, rule.n, key)
        )
        .is_none());
    }

    #[tokio::test]
    async fn rejection_value_carries_status_body_content_type_and_headers() {
        let rejected = rejection(
            StatusCode::TOO_MANY_REQUESTS,
            Some("slow down"),
            &[("X-RateLimit-Scope".to_string(), "local".to_string())],
        );
        assert_eq!(rejected.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rejected.body.as_deref(), Some("slow down"));
        assert_eq!(
            rejected.content_type.as_deref(),
            Some(content_type::TEXT_PLAIN)
        );
        assert_eq!(
            rejected.headers,
            vec![("X-RateLimit-Scope".to_string(), "local".to_string())]
        );
        assert!(!rejected.close_connection);

        // The pipeline's single write renders the value on the wire.
        let (mut session, written) =
            testing::session_for(testing::http_get_wire("/", &[]).as_bytes()).await;
        let ctx = crate::core::ProxyContext::default();
        crate::utils::response::send_rejection(&mut session, &rejected, &ctx)
            .await
            .unwrap();
        drop(session);

        let out = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert!(out.starts_with("HTTP/1.1 429"), "got: {out}");
        assert!(out.contains("slow down"), "got: {out}");
        assert!(
            out.to_ascii_lowercase()
                .contains("content-type: text/plain"),
            "got: {out}"
        );
        assert!(out.contains("X-RateLimit-Scope: local"), "got: {out}");
    }

    #[test]
    fn reject_policy_builds_the_configured_code_and_message() {
        let policy = RejectPolicy::new(503, Some("busy".to_string()));
        let rejected = policy.rejection();
        assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejected.body.as_deref(), Some("busy"));
    }
}
