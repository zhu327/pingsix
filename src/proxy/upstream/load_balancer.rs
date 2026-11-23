use std::{
    borrow::Cow,
    collections::{BTreeSet, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use dashmap::DashMap;
use futures::FutureExt;
use hickory_resolver::TokioResolver;
use http::Uri;
use pingora::services::background::background_service;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Error;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::{
    health_check::{HealthCheck as HealthCheckTrait, HttpHealthCheck, TcpHealthCheck},
    selection::{
        consistent::KetamaHashing, BackendIter, BackendSelection, FVNHash, Random, RoundRobin,
    },
    Backend, Backends, LoadBalancer,
};
use pingora_proxy::Session;

use crate::{
    config::{self, EffectiveDefaults, Identifiable},
    core::{PassiveOutcome, ProxyError, ProxyResult, UpstreamSelector},
    proxy::upstream::selection,
    utils::request::request_selector_key,
};

#[cfg(test)]
use super::discovery::prepare_static_upstream;
use super::discovery::{HybridDiscovery, PreparedUpstream, SeededDiscovery};

/// Upper bound on backends probed per selection attempt, as required by
/// [`LoadBalancer::select_with`].
const MAX_LB_ITERATIONS: usize = 256;

/// Runs a closure over the inner LB for any SelectionLB variant, eliminating repetitive match arms.
macro_rules! with_lb {
    ($lb:expr, |$lb_var:ident| $body:expr) => {
        match $lb {
            SelectionLB::RoundRobin($lb_var) => $body,
            SelectionLB::Random($lb_var) => $body,
            SelectionLB::Fnv($lb_var) => $body,
            SelectionLB::Ketama($lb_var) => $body,
        }
    };
}

/// Proxy load balancer.
///
/// Manages the load balancing of requests to upstream servers.
pub struct ProxyUpstream {
    pub inner: config::Upstream,
    lb: SelectionLB,
    /// Stable fingerprint of origin-identity fields used for cache namespacing.
    cache_origin_fingerprint: u64,
    /// Passive health-check counters keyed by collision-free backend identity
    /// (APISIX `checks.passive`).
    passive: Option<Arc<PassiveHealthState>>,
    /// Effective `pingsix.defaults.upstream_timeout` captured at build time, so
    /// peer timeouts honor the owning gateway instance's defaults.
    default_timeout: Option<config::Timeout>,
}

/// Per-upstream passive health-check state: real-traffic failure counters per
/// backend with independent thresholds for HTTP failures, TCP failures, and
/// timeouts (APISIX `resty.healthcheck` semantics).
struct PassiveHealthState {
    config: config::PassiveCheck,
    /// Keyed by stable backend id (`selection::backend_id`) instead of the
    /// backend address string, so observe/select paths never allocate a
    /// `String` per lookup. A sharded map keeps per-key state off a single
    /// global mutex: every ready-backend check during selection only locks
    /// the shard of that one backend.
    counters: DashMap<selection::BackendId, PassiveCounters>,
}

/// A half-open probe reservation expires if no observation arrives within this
/// window. Without it, a request selected as a probe but cancelled before
/// `observe()` (plugin error, disconnect, unclassified upstream error) would
/// pin the node permanently and block recovery.
const PROBE_LEASE: Duration = Duration::from_secs(30);

/// Cooldown before admitting a half-open probe to a passively tripped node
/// while healthy siblings are still available. Prevents a tripped node in a
/// multi-node upstream from remaining permanently deadlocked when siblings stay
/// healthy, without flooding a failing backend on every rotation.
const PROBE_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Default)]
struct PassiveCounters {
    http_failures: u32,
    tcp_failures: u32,
    timeouts: u32,
    successes: u32,
    /// Consecutive active health-check successes observed while passively
    /// tripped; once this reaches the active checker's healthy threshold, the
    /// passive trip is cleared.
    active_successes: usize,
    /// Node currently disabled by passive checking. It remains enabled in
    /// Pingora so this layer can send controlled half-open probes.
    tripped: bool,
    /// Earliest instant a half-open probe may be admitted while healthy
    /// siblings are still serving traffic.
    next_probe_at: Option<Instant>,
    /// Deadline of the in-flight half-open probe; `None` when no probe is
    /// reserved. Expired leases are treated as free.
    probe_lease: Option<Instant>,
}

impl PassiveHealthState {
    fn observe(&self, backend: &Backend, outcome: PassiveOutcome) {
        self.observe_at(backend, outcome, Instant::now());
    }

    fn observe_at(&self, backend: &Backend, outcome: PassiveOutcome, now: Instant) {
        let mut node = self
            .counters
            .entry(selection::backend_id(backend))
            .or_default();

        let unhealthy = &self.config.unhealthy;
        let healthy_statuses = &self.config.healthy.http_statuses;

        match outcome {
            PassiveOutcome::TcpFailure => {
                node.tcp_failures += 1;
                node.http_failures = 0;
                node.timeouts = 0;
                node.successes = 0;
                node.active_successes = 0;
                if unhealthy.tcp_failures > 0 && node.tcp_failures >= unhealthy.tcp_failures {
                    node.tripped = true;
                }
                if node.tripped {
                    node.next_probe_at = Some(now + PROBE_COOLDOWN);
                }
            }
            PassiveOutcome::Timeout => {
                node.timeouts += 1;
                node.http_failures = 0;
                node.tcp_failures = 0;
                node.successes = 0;
                node.active_successes = 0;
                if unhealthy.timeouts > 0 && node.timeouts >= unhealthy.timeouts {
                    node.tripped = true;
                }
                if node.tripped {
                    node.next_probe_at = Some(now + PROBE_COOLDOWN);
                }
            }
            PassiveOutcome::Http(status) => {
                if unhealthy.http_statuses.contains(&(status as u32)) {
                    node.http_failures += 1;
                    node.tcp_failures = 0;
                    node.timeouts = 0;
                    node.successes = 0;
                    node.active_successes = 0;
                    if unhealthy.http_failures > 0 && node.http_failures >= unhealthy.http_failures
                    {
                        node.tripped = true;
                    }
                    if node.tripped {
                        node.next_probe_at = Some(now + PROBE_COOLDOWN);
                    }
                } else if healthy_statuses.contains(&(status as u32)) {
                    node.http_failures = 0;
                    node.tcp_failures = 0;
                    node.timeouts = 0;
                    if node.tripped {
                        node.successes += 1;
                        if self.config.healthy.successes > 0
                            && node.successes >= self.config.healthy.successes
                        {
                            node.tripped = false;
                            node.successes = 0;
                            node.active_successes = 0;
                            node.next_probe_at = None;
                        } else {
                            // A recovery probe succeeded; allow the next probe
                            // immediately so multi-success recovery finishes
                            // without waiting another full cooldown.
                            node.next_probe_at = Some(now);
                        }
                    }
                }
                // Status codes in neither set are ignored (APISIX behavior).
            }
        }
        // Every outcome completes a half-open probe. Unknown HTTP statuses do
        // not affect counters but must free the probe lease.
        node.probe_lease = None;
    }

    fn observe_active_success(&self, backend: &Backend, threshold: usize) {
        let Some(mut node) = self.counters.get_mut(&selection::backend_id(backend)) else {
            return;
        };
        if !node.tripped {
            return;
        }
        node.active_successes = node.active_successes.saturating_add(1);
        if node.active_successes >= threshold.max(1) {
            node.tripped = false;
            node.http_failures = 0;
            node.tcp_failures = 0;
            node.timeouts = 0;
            node.successes = 0;
            node.active_successes = 0;
            node.next_probe_at = None;
            node.probe_lease = None;
        }
    }

    fn reset_active_successes(&self, backend: &Backend) {
        if let Some(mut node) = self.counters.get_mut(&selection::backend_id(backend)) {
            node.active_successes = 0;
        }
    }

    fn clear_tripped(&self, backend: &Backend) {
        if let Some(mut node) = self.counters.get_mut(&selection::backend_id(backend)) {
            node.tripped = false;
            node.http_failures = 0;
            node.tcp_failures = 0;
            node.timeouts = 0;
            node.successes = 0;
            node.active_successes = 0;
            node.next_probe_at = None;
            node.probe_lease = None;
        }
    }

    fn prune_stale(&self, live: &BTreeSet<Backend>) {
        if self.counters.len() <= live.len() {
            return;
        }
        let live_ids: HashSet<selection::BackendId> =
            live.iter().map(selection::backend_id).collect();
        self.counters.retain(|id, _| live_ids.contains(id));
    }

    fn has_tripped(&self) -> bool {
        self.counters.iter().any(|entry| entry.value().tripped)
    }

    /// Regular-pass eligibility: returns `true` for any non-tripped backend, or
    /// admits a single-flight half-open probe for a tripped backend once its
    /// cooldown has elapsed.
    fn is_selectable_or_cooldown_probe(&self, backend: &Backend, now: Instant) -> bool {
        let id = selection::backend_id(backend);
        // Fast read path for healthy/unseen backends: avoids acquiring a write
        // lock on the shard when the node is not tripped or still in cooldown.
        {
            let Some(node) = self.counters.get(&id) else {
                return true;
            };
            if !node.tripped {
                return true;
            }
            let cooldown_elapsed = node.next_probe_at.is_none_or(|t| t <= now);
            let lease_free = node.probe_lease.is_none_or(|d| d <= now);
            if !cooldown_elapsed || !lease_free {
                return false;
            }
        }
        // Slow path: re-check under mutable shard lock and reserve single-flight
        // half-open probe atomically.
        let Some(mut node) = self.counters.get_mut(&id) else {
            return true;
        };
        if !node.tripped {
            return true;
        }
        let cooldown_elapsed = node.next_probe_at.is_none_or(|t| t <= now);
        let lease_free = node.probe_lease.is_none_or(|d| d <= now);
        if cooldown_elapsed && lease_free {
            node.probe_lease = Some(now + PROBE_LEASE);
            node.next_probe_at = Some(now + PROBE_COOLDOWN);
            true
        } else {
            false
        }
    }

    /// Admit at most one half-open request to a tripped node until its probe
    /// lease expires. Used as the fallback when no regular ready node was
    /// selectable (e.g. all nodes are tripped and still within cooldown).
    fn take_probe(&self, backend: &Backend, now: Instant) -> bool {
        let Some(mut node) = self.counters.get_mut(&selection::backend_id(backend)) else {
            return false;
        };
        let lease_free = node.probe_lease.map(|d| d <= now).unwrap_or(true);
        if node.tripped && lease_free {
            node.probe_lease = Some(now + PROBE_LEASE);
            true
        } else {
            false
        }
    }
}

/// Wraps an active [`HealthCheckTrait`] so active recovery also resets passive
/// trip state on the same backend.
struct PassiveResetHealthCheck {
    inner: Box<dyn HealthCheckTrait + Send + Sync + 'static>,
    passive: Arc<PassiveHealthState>,
}

#[async_trait]
impl HealthCheckTrait for PassiveResetHealthCheck {
    async fn check(&self, target: &Backend) -> pingora_error::Result<()> {
        match self.inner.check(target).await {
            Ok(()) => {
                self.passive
                    .observe_active_success(target, self.inner.health_threshold(true));
                Ok(())
            }
            Err(err) => {
                self.passive.reset_active_successes(target);
                Err(err)
            }
        }
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        self.inner.health_status_change(target, healthy).await;
        if healthy {
            self.passive.clear_tripped(target);
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        self.inner.backend_summary(target)
    }

    fn health_threshold(&self, success: bool) -> usize {
        self.inner.health_threshold(success)
    }
}

impl Identifiable for ProxyUpstream {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyUpstream {
    /// Test-only static-IP constructor. Production candidates must supply
    /// explicitly prepared material to [`Self::build`].
    #[cfg(test)]
    pub(crate) fn build_static(upstream: config::Upstream) -> ProxyResult<Self> {
        let resolver = super::discovery::build_resolver_for_state()?;
        let prepared = prepare_static_upstream(&upstream, &resolver)?;
        Self::build(upstream, prepared, &EffectiveDefaults::default(), &resolver)
    }

    /// Build an upstream from material prepared before candidate compilation.
    /// This constructor never performs discovery I/O. `defaults` supplies the
    /// effective `pingsix.defaults` fallbacks for this gateway instance.
    pub(crate) fn build(
        mut upstream: config::Upstream,
        prepared: PreparedUpstream,
        defaults: &EffectiveDefaults,
        resolver: &Arc<TokioResolver>,
    ) -> ProxyResult<Self> {
        // Auto-generate upstream ID if empty (for inline upstreams in route, service, traffic-split)
        if upstream.id.is_empty() {
            upstream.id = format!("inline_{}", uuid::Uuid::new_v4());
            log::debug!("Generated ID for inline upstream: {}", upstream.id);
        }

        let cache_origin_fingerprint =
            upstream.fingerprint(config::UpstreamFingerprintProfile::CacheOrigin);

        // Passive state intentionally does not call `Backends::set_enable`:
        // Pingora has no half-open transition for manually disabled backends.
        // Keeping its health intact lets selection issue our controlled probes.
        let passive = upstream
            .checks
            .as_ref()
            .and_then(|c| c.passive.clone())
            .map(|config| {
                Arc::new(PassiveHealthState {
                    config,
                    counters: DashMap::new(),
                })
            });

        let lb = SelectionLB::from_prepared(
            upstream.clone(),
            prepared,
            defaults,
            resolver,
            passive.clone(),
        )
        .map_err(|e| ProxyError::Configuration(format!("Failed to create load balancer: {e}")))?;

        Ok(ProxyUpstream {
            inner: upstream,
            lb,
            cache_origin_fingerprint,
            passive,
            default_timeout: defaults.upstream_timeout.clone(),
        })
    }

    pub(crate) fn health_check_service(
        &self,
    ) -> Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync> {
        with_lb!(&self.lb, |lb| lb.upstreams.clone())
    }

    fn select_with_passive(&self, key: &[u8]) -> Option<Backend> {
        self.select_with_passive_at(key, Instant::now())
    }

    fn select_with_passive_at(&self, key: &[u8], now: Instant) -> Option<Backend> {
        // 1. Regular pass: pick any non-tripped ready backend, or admit a
        //    single-flight half-open probe for a tripped backend whose
        //    cooldown has elapsed so tripped nodes can recover even while
        //    healthy siblings stay online.
        let regular_or_probe = |backend: &Backend| {
            self.passive
                .as_ref()
                .is_none_or(|passive| passive.is_selectable_or_cooldown_probe(backend, now))
        };
        if let Some(backend) = with_lb!(&self.lb, |lb| {
            lb.upstreams
                .select_with(key, MAX_LB_ITERATIONS, |backend, ready| {
                    ready && regular_or_probe(backend)
                })
        }) {
            return Some(backend);
        }

        // 2. No regular candidate remains (e.g. all nodes are tripped and still
        //    within cooldown). Admit one half-open probe among
        //    tripped-but-actively-ready nodes.
        if self
            .passive
            .as_ref()
            .is_some_and(|passive| passive.has_tripped())
        {
            if let Some(backend) = with_lb!(&self.lb, |lb| {
                lb.upstreams
                    .select_with(key, MAX_LB_ITERATIONS, |backend, ready| {
                        ready
                            && self
                                .passive
                                .as_ref()
                                .is_some_and(|passive| passive.take_probe(backend, now))
                    })
            }) {
                return Some(backend);
            }
        }

        // 3. All-unready fallback: preserve APISIX/Pingora behavior of serving
        //    from the highest-priority backend when nothing is healthy. This
        //    also covers the case where passive is configured but no node is
        //    tripped, so active health semantics are not broken.
        with_lb!(&self.lb, |lb| lb.select(key))
    }

    /// Test helper: select a backend without a full proxy session.
    #[cfg(test)]
    pub(crate) fn select_backend_for_test(&self) -> Option<Backend> {
        let mut backend = self.select_with_passive(b"");
        if let Some(backend) = backend.as_mut() {
            if let Some(peer) = backend.ext.get_mut::<HttpPeer>() {
                self.set_timeout(peer);
            }
        }
        backend
    }

    /// Sets the finite upstream/global/built-in timeout for an `HttpPeer`,
    /// plus the per-upstream keepalive idle timeout when configured.
    ///
    /// These values are the upstream-defaults layer (step 1) of the
    /// peer-timeout precedence chain, NOT the final word: after selection the
    /// peer passes through route `apply_route_timeout` (2), WebSocket
    /// relaxation (3), and finally the plugin `upstream_peer_filter` phase
    /// (4), any of which may override what is set here. The full ordering is
    /// documented at `HttpService::upstream_peer` in `service/http.rs`, which
    /// owns the chain.
    fn set_timeout(&self, p: &mut HttpPeer) {
        let config::Timeout {
            connect,
            read,
            send,
        } = config::resolve_upstream_timeout(
            self.inner.timeout.clone(),
            self.default_timeout.clone(),
        );
        p.options.connection_timeout = Some(Duration::from_secs(connect));
        p.options.read_timeout = Some(Duration::from_secs(read));
        p.options.write_timeout = Some(Duration::from_secs(send));
        if let Some(keepalive) = &self.inner.keepalive_pool {
            p.options.idle_timeout = Some(Duration::from_millis(keepalive.idle_timeout_ms));
        }
    }

    /// Hash key for the session-aware selection algorithms.
    fn hash_key<'a>(&self, session: &'a mut Session) -> Cow<'a, str> {
        let key = request_selector_key(session, &self.inner.hash_on, self.inner.key.as_str());
        log::debug!("proxy lb key: {key}");
        key
    }
}

// Implementation of UpstreamSelector trait for decoupling from core module
impl UpstreamSelector for ProxyUpstream {
    fn select_backend(&self, session: &mut Session) -> Option<Backend> {
        let key = match &self.lb {
            SelectionLB::RoundRobin(_) | SelectionLB::Random(_) => Cow::Borrowed(""),
            SelectionLB::Fnv(_) | SelectionLB::Ketama(_) => self.hash_key(session),
        };
        let mut backend = self.select_with_passive(key.as_bytes());

        if let Some(backend) = backend.as_mut() {
            if let Some(peer) = backend.ext.get_mut::<HttpPeer>() {
                self.set_timeout(peer);
            }
        }

        backend
    }

    fn get_retries(&self) -> Option<usize> {
        self.inner.retries.map(|r| r as _)
    }

    fn get_retry_timeout(&self) -> Option<u64> {
        self.inner.retry_timeout
    }

    fn get_pass_host(&self) -> &config::UpstreamPassHost {
        &self.inner.pass_host
    }

    fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader) {
        if self.inner.pass_host == config::UpstreamPassHost::REWRITE {
            if let Some(host) = &self.inner.upstream_host {
                if let Err(e) = upstream_request.insert_header(http::header::HOST, host) {
                    log::error!("Failed to rewrite upstream host header: {e}");
                }
            }
        }
    }

    fn cache_isolation_key(&self) -> u64 {
        self.cache_origin_fingerprint
    }

    fn observe_passive(&self, backend: &Backend, outcome: PassiveOutcome) {
        if let Some(passive) = &self.passive {
            passive.observe(backend, outcome);
            let live = with_lb!(&self.lb, |lb| lb.upstreams.backends().get_backend());
            passive.prune_stale(&live);
        }
    }
}

enum SelectionLB {
    RoundRobin(LB<RoundRobin>),
    Random(LB<Random>),
    Fnv(LB<FVNHash>),
    Ketama(LB<KetamaHashing>),
}

impl SelectionLB {
    fn from_prepared(
        value: config::Upstream,
        prepared: PreparedUpstream,
        defaults: &EffectiveDefaults,
        resolver: &Arc<TokioResolver>,
        passive: Option<Arc<PassiveHealthState>>,
    ) -> ProxyResult<Self> {
        match value.r#type {
            config::SelectionType::RoundRobin => Ok(SelectionLB::RoundRobin(
                LB::<RoundRobin>::from_prepared(value, prepared, defaults, resolver, passive)?,
            )),
            config::SelectionType::Random => Ok(SelectionLB::Random(LB::<Random>::from_prepared(
                value, prepared, defaults, resolver, passive,
            )?)),
            config::SelectionType::Fnv => Ok(SelectionLB::Fnv(LB::<FVNHash>::from_prepared(
                value, prepared, defaults, resolver, passive,
            )?)),
            config::SelectionType::Ketama => Ok(SelectionLB::Ketama(
                LB::<KetamaHashing>::from_prepared(value, prepared, defaults, resolver, passive)?,
            )),
        }
    }
}

/// `BS` is the configured algorithm; it is applied per priority group by
/// [`selection::PriorityGrouped`].
struct LB<BS: BackendSelection>
where
    BS::Iter: BackendIter,
{
    upstreams: Arc<LoadBalancer<selection::PriorityGrouped<BS>>>,
}

impl<BS> LB<BS>
where
    BS: BackendSelection + Send + Sync + 'static,
    BS::Iter: BackendIter,
{
    /// Select a backend honouring node priority, then health.
    fn select(&self, key: &[u8]) -> Option<Backend> {
        selection::select_backend(&self.upstreams, key, MAX_LB_ITERATIONS)
    }

    fn from_prepared(
        upstream: config::Upstream,
        prepared: PreparedUpstream,
        defaults: &EffectiveDefaults,
        resolver: &Arc<TokioResolver>,
        passive: Option<Arc<PassiveHealthState>>,
    ) -> ProxyResult<Self> {
        let refresh: HybridDiscovery = HybridDiscovery::build(upstream.clone(), resolver.clone())?;
        let discovery = SeededDiscovery::new(
            prepared,
            refresh,
            Duration::from_secs(defaults.dns_resolution_timeout),
        );
        let mut upstreams = LoadBalancer::<selection::PriorityGrouped<BS>>::from_backends(
            Backends::new(Box::new(discovery)),
        );

        if let Some(check) = upstream.checks {
            // Active probing is optional: a passive-only `checks` block must
            // not register an active health checker or pollute its frequency.
            if let Some(active) = check.active.clone() {
                let health_check_frequency = active
                    .healthy
                    .as_ref()
                    .map(|healthy| Duration::from_secs(healthy.interval as _))
                    .unwrap_or(Duration::from_secs(1));
                let health_check: Box<dyn HealthCheckTrait + Send + Sync + 'static> =
                    active.try_into().map_err(|e| {
                        ProxyError::Configuration(format!(
                            "Upstream '{}' has an invalid health check configuration: {e}",
                            upstream.id
                        ))
                    })?;
                let health_check: Box<dyn HealthCheckTrait + Send + Sync + 'static> =
                    if let Some(passive) = passive {
                        Box::new(PassiveResetHealthCheck {
                            inner: health_check,
                            passive,
                        })
                    } else {
                        health_check
                    };
                upstreams.set_health_check(health_check);

                upstreams.health_check_frequency = Some(health_check_frequency);
            }
        }

        if let Some(interval) = defaults.dns_refresh_interval {
            // Pingora exposes one refresh frequency per upstream, rather than
            // a scheduler hook. Derive a stable, bounded phase from the
            // upstream id so otherwise-identical instances do not refresh in
            // lockstep while reloads retain their cadence.
            upstreams.update_frequency = Some(dns_refresh_frequency(&upstream.id, interval));
        }

        // Extract the Arc<LoadBalancer> via background_service().task().
        // The wrapper is intentionally dropped — health checks are driven by
        // the instance-owned SharedHealthCheckService, not by Pingora's
        // background service mechanism.
        let background =
            background_service(&format!("health check for {}", upstream.id), upstreams);
        let upstreams = background.task();

        // The seeded discovery result is immediately ready and never performs
        // I/O, so populate selection before this LB can be published.
        let update_result = upstreams.update().now_or_never().ok_or_else(|| {
            ProxyError::Configuration(format!(
                "Upstream '{}' seeded discovery was not immediately ready",
                upstream.id
            ))
        })?;
        update_result.map_err(|e| {
            ProxyError::Configuration(format!(
                "Upstream '{}' failed to install prepared backends: {e}",
                upstream.id
            ))
        })?;

        Ok(Self { upstreams })
    }
}

/// Stable upstream-level DNS refresh jitter for Pingora's frequency-only API.
/// The base interval remains the lower bound; jitter is at most 10% (capped at
/// 60 seconds) and is represented at millisecond precision for small values.
fn dns_refresh_frequency(upstream_id: &str, interval_secs: u64) -> Duration {
    let base = Duration::from_secs(interval_secs);
    let jitter = base / 10;
    let jitter = jitter.min(Duration::from_secs(60));
    if jitter.is_zero() {
        return base;
    }

    // FNV-1a is used only to distribute a deterministic schedule; this is not
    // an identity or security boundary.
    let hash = upstream_id
        .bytes()
        .fold(0xcbf29ce484222325u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        });
    let jitter_nanos = jitter.as_nanos();
    let offset = Duration::from_nanos((u128::from(hash) % (jitter_nanos + 1)) as u64);
    base + offset
}

impl TryFrom<config::ActiveCheck> for Box<dyn HealthCheckTrait + Send + Sync + 'static> {
    type Error = ProxyError;

    fn try_from(value: config::ActiveCheck) -> Result<Self, Self::Error> {
        match value.r#type {
            config::ActiveCheckType::TCP => Ok(Into::<Box<TcpHealthCheck>>::into(value)),
            config::ActiveCheckType::HTTP | config::ActiveCheckType::HTTPS => {
                Ok(Box::new(HttpHealthCheck::try_from(value)?))
            }
        }
    }
}

impl From<config::ActiveCheck> for Box<TcpHealthCheck> {
    fn from(value: config::ActiveCheck) -> Self {
        let mut health_check = TcpHealthCheck::new();
        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.timeout as _));

        if let Some(healthy) = value.healthy {
            health_check.consecutive_success = healthy.successes as _;
        }

        if let Some(unhealthy) = value.unhealthy {
            health_check.consecutive_failure = unhealthy.tcp_failures as _;
        }

        health_check
    }
}

impl TryFrom<config::ActiveCheck> for HttpHealthCheck {
    type Error = ProxyError;

    fn try_from(value: config::ActiveCheck) -> Result<Self, Self::Error> {
        let host = value.host.unwrap_or_default();
        let tls = value.r#type == config::ActiveCheckType::HTTPS;
        let mut health_check = HttpHealthCheck::new(host.as_str(), tls);

        // Set total connection timeout if provided
        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.timeout as _));

        // Set certificate verification if TLS is enabled
        health_check.peer_template.options.verify_cert = value.https_verify_certificate;

        // Build URI for HTTP health check path. A malformed path must fail
        // candidate publication rather than silently disabling the probe.
        let uri = Uri::builder()
            .path_and_query(&value.http_path)
            .build()
            .map_err(|e| {
                ProxyError::Configuration(format!(
                    "Invalid health check path '{}': {e}",
                    value.http_path
                ))
            })?;
        health_check.req.set_uri(uri);

        // Insert headers; malformed entries must fail closed instead of being
        // silently dropped, otherwise probes run with a different request than
        // the operator configured.
        for header in value.req_headers.iter() {
            let mut parts = header.splitn(2, ':');
            let (key, val) = match (parts.next(), parts.next()) {
                (Some(key), Some(val)) => (key.trim().to_string(), val.trim().to_string()),
                _ => {
                    return Err(ProxyError::Configuration(format!(
                        "Invalid health check header {header:?}: expected 'Name: value'"
                    )))
                }
            };
            if key.is_empty() {
                return Err(ProxyError::Configuration(format!(
                    "Invalid health check header {header:?}: empty header name"
                )));
            }
            health_check.req.insert_header(key, &val).map_err(|e| {
                ProxyError::Configuration(format!("Invalid health check header {header:?}: {e}"))
            })?;
        }

        // Handle port override
        if let Some(port) = value.port {
            health_check.port_override = Some(port as _);
        }

        // Set the success conditions
        if let Some(healthy) = value.healthy {
            health_check.consecutive_success = healthy.successes as _;

            // Validator for HTTP status codes
            if !healthy.http_statuses.is_empty() {
                let http_statuses = healthy.http_statuses.clone(); // Clone to move into closure
                health_check.validator = Some(Box::new(move |header: &ResponseHeader| {
                    if http_statuses.contains(&(header.status.as_u16() as _)) {
                        Ok(())
                    } else {
                        Err(Error::new_str("Invalid response"))
                    }
                }));
            }
        }

        // Set the failure conditions
        if let Some(unhealthy) = value.unhealthy {
            health_check.consecutive_failure = unhealthy.http_failures as _;
        }

        // Return the Boxed health check
        Ok(health_check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Nodes, SelectionType, Timeout, UpstreamHashOn, UpstreamPassHost, UpstreamScheme,
    };
    use std::collections::HashMap;

    fn node(host: &str, port: u16, priority: i8) -> config::Node {
        config::Node {
            host: host.into(),
            // Test convenience: 0 means "port omitted" (scheme default).
            port: (port != 0).then_some(port),
            weight: 1,
            priority,
        }
    }

    /// Cache-origin (cache namespace) fingerprint via the config-declared
    /// profile; kept under the old test helper name for readability.
    fn cache_origin_fingerprint(upstream: &config::Upstream) -> u64 {
        upstream.fingerprint(config::UpstreamFingerprintProfile::CacheOrigin)
    }

    fn sample_upstream(id: &str, timeout: Option<Timeout>) -> config::Upstream {
        let mut nodes = HashMap::new();
        nodes.insert("127.0.0.1:18080".to_string(), 1);
        config::Upstream {
            id: id.to_string(),
            retries: None,
            retry_timeout: None,
            timeout,
            nodes: Nodes::from_map(nodes),
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
            keepalive_pool: None,
        }
    }

    #[test]
    fn explicit_upstream_timeout_applied_to_peer() {
        let upstream = ProxyUpstream::build_static(sample_upstream(
            "payments",
            Some(Timeout {
                connect: 30,
                send: 30,
                read: 30,
            }),
        ))
        .unwrap();
        let backend = upstream.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(30))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn keepalive_idle_timeout_applied_to_peer() {
        let mut upstream = sample_upstream("pooled", None);
        upstream.keepalive_pool = Some(crate::config::KeepalivePool {
            idle_timeout_ms: 15_000,
        });
        let built = ProxyUpstream::build_static(upstream).unwrap();
        let backend = built.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        assert_eq!(
            peer.options.idle_timeout,
            Some(Duration::from_millis(15_000))
        );
    }

    #[test]
    fn keepalive_absent_leaves_peer_idle_timeout_unset() {
        let upstream = ProxyUpstream::build_static(sample_upstream("plain", None)).unwrap();
        let backend = upstream.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        assert_eq!(peer.options.idle_timeout, None);
    }

    #[test]
    fn injected_defaults_produce_distinct_peer_timeouts() {
        // Two gateway instances with different `pingsix.defaults.upstream_timeout`
        // must yield different peer timeouts for the same upstream config.
        let make = |defaults: &EffectiveDefaults| {
            let upstream = sample_upstream("plain", None);
            let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
            let prepared =
                crate::proxy::upstream::discovery::prepare_static_upstream(&upstream, &resolver)
                    .unwrap();
            let built = ProxyUpstream::build(upstream, prepared, defaults, &resolver).unwrap();
            let backend = built.select_backend_for_test().unwrap();
            backend.ext.get::<HttpPeer>().unwrap().clone()
        };
        let a = make(&EffectiveDefaults {
            upstream_timeout: Some(Timeout {
                connect: 1,
                send: 2,
                read: 3,
            }),
            ..EffectiveDefaults::default()
        });
        let b = make(&EffectiveDefaults {
            upstream_timeout: Some(Timeout {
                connect: 9,
                send: 8,
                read: 7,
            }),
            ..EffectiveDefaults::default()
        });
        assert_eq!(a.options.connection_timeout, Some(Duration::from_secs(1)));
        assert_eq!(a.options.read_timeout, Some(Duration::from_secs(3)));
        assert_eq!(b.options.connection_timeout, Some(Duration::from_secs(9)));
        assert_eq!(b.options.read_timeout, Some(Duration::from_secs(7)));
    }

    #[test]
    fn missing_upstream_timeout_uses_instance_default() {
        let defaults = EffectiveDefaults {
            upstream_timeout: Some(Timeout {
                connect: 5,
                send: 5,
                read: 5,
            }),
            ..EffectiveDefaults::default()
        };
        let upstream = sample_upstream("plain", None);
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let prepared =
            crate::proxy::upstream::discovery::prepare_static_upstream(&upstream, &resolver)
                .unwrap();
        let built = ProxyUpstream::build(upstream, prepared, &defaults, &resolver).unwrap();
        let backend = built.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(5)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn dns_refresh_jitter_is_stable_and_bounded() {
        let a = dns_refresh_frequency("orders", 60);
        assert_eq!(a, dns_refresh_frequency("orders", 60));
        assert!(a >= Duration::from_secs(60));
        assert!(a <= Duration::from_secs(66));
        // A spread of IDs should exercise distinct phases without any timing
        // dependency or external resolver.
        let phases: std::collections::HashSet<_> = (0..64)
            .map(|n| dns_refresh_frequency(&format!("upstream-{n}"), 60))
            .collect();
        assert!(phases.len() > 1, "stable jitter must spread refreshes");
    }

    #[test]
    fn cache_origin_fingerprint_changes_with_host_rewrite() {
        let base = sample_upstream("u1", None);
        let fp1 = cache_origin_fingerprint(&base);
        let mut rewritten = base.clone();
        rewritten.pass_host = UpstreamPassHost::REWRITE;
        rewritten.upstream_host = Some("tenant-b.internal".into());
        let fp2 = cache_origin_fingerprint(&rewritten);
        assert_ne!(
            fp1, fp2,
            "pass_host/upstream_host must change cache origin fingerprint"
        );
        let mut nodes_changed = base;
        nodes_changed
            .nodes
            .push("10.0.0.2:80".parse().expect("valid node address"));
        assert_ne!(
            fp1,
            cache_origin_fingerprint(&nodes_changed),
            "node set must change cache origin fingerprint"
        );
    }

    #[test]
    fn cache_origin_fingerprint_is_stable_across_node_order() {
        let mut a_nodes = HashMap::new();
        a_nodes.insert("10.0.0.2:80".into(), 1);
        a_nodes.insert("10.0.0.1:80".into(), 2);
        let mut b_nodes = HashMap::new();
        b_nodes.insert("10.0.0.1:80".into(), 2);
        b_nodes.insert("10.0.0.2:80".into(), 1);

        let a = config::Upstream {
            nodes: Nodes::from_map(a_nodes),
            ..sample_upstream("u1", None)
        };
        let b = config::Upstream {
            nodes: Nodes::from_map(b_nodes),
            ..sample_upstream("u1", None)
        };
        assert_eq!(cache_origin_fingerprint(&a), cache_origin_fingerprint(&b));
    }

    #[test]
    fn negative_priority_is_lower_than_zero() {
        let upstream = ProxyUpstream::build_static(config::Upstream {
            nodes: Nodes(vec![
                node("127.0.0.1", 18301, 0),
                node("127.0.0.1", 18302, -1),
            ]),
            ..sample_upstream("neg", None)
        })
        .unwrap();

        let backend = upstream.select_backend_for_test().unwrap();
        assert_eq!(backend.addr.to_string(), "127.0.0.1:18301");
        assert_eq!(selection::backend_priority(&backend), 0);
    }

    #[test]
    fn duplicate_addr_keeps_higher_priority() {
        // Pingora Backend identity ignores ext; same addr+weight collapses.
        // We keep the higher priority so negative cannot "stick" over 0/10.
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let prepared = prepare_static_upstream(
            &config::Upstream {
                nodes: Nodes(vec![node("127.0.0.1", 443, -1), node("127.0.0.1", 443, 10)]),
                ..sample_upstream("dup", None)
            },
            &resolver,
        )
        .unwrap();

        assert_eq!(prepared.backends.len(), 1);
        let only = prepared.backends.iter().next().unwrap();
        assert_eq!(selection::backend_priority(only), 10);
    }

    #[test]
    fn cache_origin_fingerprint_canonicalizes_scheme_default_port() {
        // An omitted port and an explicit scheme-default port dial the same
        // origin, so they must share a cache namespace.
        let no_port = config::Upstream {
            nodes: Nodes(vec![node("example.com", 0, 0)]),
            ..sample_upstream("u1", None)
        };
        let explicit = config::Upstream {
            nodes: Nodes(vec![node("example.com", 80, 0)]),
            ..sample_upstream("u1", None)
        };
        assert_eq!(
            cache_origin_fingerprint(&no_port),
            cache_origin_fingerprint(&explicit),
            "omitted port and explicit scheme default are the same origin"
        );

        // But a genuinely different effective port must differ.
        let other = config::Upstream {
            nodes: Nodes(vec![node("example.com", 8080, 0)]),
            ..sample_upstream("u1", None)
        };
        assert_ne!(
            cache_origin_fingerprint(&no_port),
            cache_origin_fingerprint(&other),
            "different effective ports must not share a cache namespace"
        );
    }

    /// A malformed health-check path or header must fail candidate build
    /// instead of silently disabling/altering the probe.
    #[test]
    fn invalid_health_check_config_fails_candidate_build() {
        use crate::config::{ActiveCheck, ActiveCheckType, HealthCheck as HealthCheckConfig};

        fn upstream_with_http_path(path: &str) -> config::Upstream {
            let mut upstream = sample_upstream("hc", None);
            upstream.checks = Some(HealthCheckConfig {
                active: Some(ActiveCheck {
                    r#type: ActiveCheckType::HTTP,
                    timeout: 1,
                    http_path: path.to_string(),
                    host: None,
                    port: None,
                    https_verify_certificate: true,
                    req_headers: vec![],
                    healthy: None,
                    unhealthy: None,
                }),
                passive: None,
            });
            upstream
        }

        let invalid_path = upstream_with_http_path("not a uri path");
        let err = ProxyUpstream::build_static(invalid_path)
            .err()
            .expect("malformed health check path must fail build")
            .to_string();
        assert!(
            err.contains("health check") || err.contains("Invalid health check path"),
            "malformed health check path must fail build, got: {err}"
        );

        let mut malformed_header = upstream_with_http_path("/");
        if let Some(check) = malformed_header.checks.as_mut() {
            check.active.as_mut().unwrap().req_headers = vec!["HeaderWithoutColon".into()];
        }
        let err = ProxyUpstream::build_static(malformed_header)
            .err()
            .expect("malformed health check header must fail build")
            .to_string();
        assert!(
            err.contains("Invalid health check header"),
            "malformed health check header must fail build, got: {err}"
        );

        // A well-formed configuration still builds.
        let mut ok = upstream_with_http_path("/healthz");
        if let Some(check) = ok.checks.as_mut() {
            check.active.as_mut().unwrap().req_headers = vec!["X-Probe: healthz".into()];
        }
        ProxyUpstream::build_static(ok).expect("valid health check must build");
    }

    // ---------------------------------------------------------------------
    // Real active health-check failure/recovery
    // ---------------------------------------------------------------------

    fn upstream_with_active_check(addr: &str) -> config::Upstream {
        use crate::config::{ActiveCheck, ActiveCheckType, Health, HealthCheck as HC, Unhealthy};
        let mut upstream = sample_upstream("hc-live", None);
        // Probe the test backend, not the sample upstream's hard-coded node.
        upstream.nodes = Nodes::from_map(HashMap::from([(addr.to_string(), 1)]));
        upstream.checks = Some(HC {
            active: Some(ActiveCheck {
                r#type: ActiveCheckType::HTTP,
                timeout: 1,
                http_path: "/".into(),
                host: None,
                port: None,
                https_verify_certificate: true,
                req_headers: vec![],
                // Fast transitions: one probe decides each way.
                healthy: Some(Health {
                    interval: 1,
                    http_statuses: vec![200],
                    successes: 1,
                }),
                unhealthy: Some(Unhealthy {
                    http_failures: 1,
                    tcp_failures: 1,
                }),
            }),
            passive: None,
        });
        upstream
    }

    /// Serve minimal HTTP/1.1 200 responses for every accepted connection.
    async fn serve_http(listener: tokio::net::TcpListener) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
            });
        }
    }

    /// Bind a listener that can immediately reuse the same port after a close.
    fn bind_reusable(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        socket.listen(1024)
    }

    fn any_backend_ready(upstream: &ProxyUpstream) -> bool {
        with_lb!(&upstream.lb, |lb| {
            lb.upstreams
                .backends()
                .get_backend()
                .iter()
                .any(|b| lb.upstreams.backends().ready(b))
        })
    }

    async fn wait_for_ready(upstream: &ProxyUpstream, expect_ready: bool, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if any_backend_ready(upstream) == expect_ready {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "backend readiness did not become {expect_ready} within {timeout:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Real Pingora health probes against a live local backend: readiness must
    /// follow healthy → unhealthy (backend stopped) → healthy (backend back).
    /// Selection itself still returns a backend when nothing is ready, via the
    /// APISIX-compatible all-unready fallback.
    #[tokio::test]
    async fn active_health_check_failure_and_recovery() {
        let _ = env_logger::builder().is_test(true).try_init();
        let listener = bind_reusable("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut backend = tokio::spawn(serve_http(listener));

        let upstream = ProxyUpstream::build_static(upstream_with_active_check(&addr.to_string()))
            .expect("upstream with active check must build");
        let service = upstream.health_check_service();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let health_task = tokio::spawn(async move {
            service.start(shutdown_rx).await;
        });

        // Backend up → probe succeeds → ready and selectable.
        wait_for_ready(&upstream, true, Duration::from_secs(10)).await;
        assert!(upstream.select_backend_for_test().is_some());

        // Backend down → consecutive probe failure → not ready, but the
        // all-unready fallback still yields an enabled backend.
        backend.abort();
        wait_for_ready(&upstream, false, Duration::from_secs(15)).await;
        assert!(
            upstream.select_backend_for_test().is_some(),
            "all-unready fallback must still select an enabled backend"
        );

        // Backend restored on the same port → probe recovers → ready again.
        let listener2 = bind_reusable(addr).expect("same port must be reusable");
        backend = tokio::spawn(serve_http(listener2));
        wait_for_ready(&upstream, true, Duration::from_secs(15)).await;
        assert!(upstream.select_backend_for_test().is_some());

        health_task.abort();
        backend.abort();
    }
}

#[cfg(test)]
mod passive_tests {
    use super::*;
    use crate::config::{PassiveCheck, PassiveHealthy, PassiveUnhealthy};

    /// Passive-health assertions observe the state the selector acts on
    /// (`has_tripped`, probe admission) rather than tickling internal
    /// transition callbacks: the observable behavior is what changes
    /// selection outcomes.
    fn test_state(
        http_failures: u32,
        tcp_failures: u32,
        timeouts: u32,
        successes: u32,
    ) -> PassiveHealthState {
        PassiveHealthState {
            config: PassiveCheck {
                healthy: PassiveHealthy {
                    http_statuses: vec![200],
                    successes,
                },
                unhealthy: PassiveUnhealthy {
                    http_statuses: vec![500],
                    tcp_failures,
                    timeouts,
                    http_failures,
                },
            },
            counters: DashMap::new(),
        }
    }

    fn backend() -> Backend {
        Backend::new("127.0.0.1:18080").unwrap()
    }

    #[test]
    fn trips_after_http_failure_threshold() {
        let state = test_state(3, 2, 7, 5);
        let b = backend();
        for _ in 0..2 {
            state.observe(&b, PassiveOutcome::Http(500));
        }
        assert!(!state.has_tripped());
        state.observe(&b, PassiveOutcome::Http(500));
        assert!(state.has_tripped());
    }

    #[test]
    fn trips_after_tcp_failure_threshold() {
        let state = test_state(5, 2, 7, 5);
        let b = backend();
        state.observe(&b, PassiveOutcome::TcpFailure);
        assert!(!state.has_tripped());
        state.observe(&b, PassiveOutcome::TcpFailure);
        assert!(state.has_tripped());
    }

    #[test]
    fn trips_after_timeout_threshold() {
        let state = test_state(5, 2, 3, 5);
        let b = backend();
        for _ in 0..2 {
            state.observe(&b, PassiveOutcome::Timeout);
        }
        assert!(!state.has_tripped());
        state.observe(&b, PassiveOutcome::Timeout);
        assert!(state.has_tripped());
    }

    #[test]
    fn mixed_failures_do_not_accumulate_across_categories() {
        let state = test_state(3, 2, 7, 5);
        let b = backend();
        state.observe(&b, PassiveOutcome::Http(500));
        state.observe(&b, PassiveOutcome::Http(500));
        // A TCP failure resets the http failure counter.
        state.observe(&b, PassiveOutcome::TcpFailure);
        state.observe(&b, PassiveOutcome::Http(500));
        assert!(!state.has_tripped());
        state.observe(&b, PassiveOutcome::Http(500));
        state.observe(&b, PassiveOutcome::Http(500));
        assert!(state.has_tripped());
    }

    #[test]
    fn restores_after_healthy_successes() {
        let state = test_state(3, 2, 7, 2);
        let b = backend();
        for _ in 0..3 {
            state.observe(&b, PassiveOutcome::Http(500));
        }
        assert!(state.has_tripped());
        state.observe(&b, PassiveOutcome::Http(200));
        assert!(state.has_tripped());
        state.observe(&b, PassiveOutcome::Http(200));
        assert!(!state.has_tripped());
    }

    #[test]
    fn zero_threshold_disables_its_failure_category() {
        let state = test_state(0, 0, 0, 1);
        let b = backend();
        for _ in 0..10 {
            state.observe(&b, PassiveOutcome::TcpFailure);
            state.observe(&b, PassiveOutcome::Timeout);
            state.observe(&b, PassiveOutcome::Http(500));
        }
        assert!(!state.has_tripped());
    }

    #[test]
    fn half_open_probe_is_single_flight_and_recovers() {
        let state = test_state(1, 2, 7, 1);
        let b = backend();
        let now = Instant::now();
        state.observe(&b, PassiveOutcome::Http(500));
        assert!(state.has_tripped());
        assert!(state.take_probe(&b, now));
        // A second probe within the lease window is refused.
        assert!(!state.take_probe(&b, now));
        state.observe(&b, PassiveOutcome::Http(200));
        assert!(!state.has_tripped());
    }

    #[test]
    fn half_open_probe_allows_exactly_one_concurrent_winner() {
        use std::sync::{Arc, Barrier};

        let state = Arc::new(test_state(1, 2, 7, 1));
        let b = backend();
        state.observe(&b, PassiveOutcome::Http(500));
        assert!(state.has_tripped());

        let workers = 32;
        let barrier = Arc::new(Barrier::new(workers));
        let winners: Vec<_> = (0..workers)
            .map(|_| {
                let state = state.clone();
                let barrier = barrier.clone();
                let backend = b.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    state.take_probe(&backend, Instant::now()) as usize
                })
            })
            .collect();
        assert_eq!(
            winners
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum::<usize>(),
            1,
            "the half-open lease must elect exactly one concurrent probe"
        );
    }

    #[test]
    fn half_open_probe_lease_expires_without_observation() {
        // A request selected as a probe but cancelled before observe() must
        // not pin the node forever: the lease expires and another probe is
        // admitted after PROBE_LEASE.
        let state = test_state(1, 2, 7, 1);
        let b = backend();
        let now = Instant::now();
        state.observe(&b, PassiveOutcome::Http(500));
        assert!(state.has_tripped());
        assert!(state.take_probe(&b, now));
        // Still tripped, lease held.
        assert!(!state.take_probe(&b, now));
        // Past the lease window a new probe is admitted even without observe().
        assert!(state.take_probe(&b, now + PROBE_LEASE));
    }

    #[test]
    fn successful_outcomes_do_not_trip_when_not_tripped() {
        let state = test_state(3, 2, 7, 5);
        let b = backend();
        state.observe(&b, PassiveOutcome::Http(200));
        state.observe(&b, PassiveOutcome::Http(200));
        assert!(!state.has_tripped());
    }

    #[test]
    fn out_of_set_statuses_are_ignored() {
        let state = test_state(3, 2, 7, 5);
        let b = backend();
        for _ in 0..10 {
            state.observe(&b, PassiveOutcome::Http(404));
        }
        assert!(!state.has_tripped());
    }

    #[test]
    fn tripped_node_in_multi_node_upstream_recovers_after_cooldown_while_sibling_healthy() {
        let mut nodes = std::collections::HashMap::new();
        nodes.insert("127.0.0.1:18081".to_string(), 1);
        nodes.insert("127.0.0.1:18082".to_string(), 1);
        let upstream = ProxyUpstream::build_static(config::Upstream {
            id: "multi-passive".into(),
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes: config::Nodes::from_map(nodes),
            r#type: config::SelectionType::RoundRobin,
            checks: Some(config::HealthCheck {
                active: None,
                passive: Some(PassiveCheck {
                    healthy: PassiveHealthy {
                        http_statuses: vec![200],
                        successes: 1,
                    },
                    unhealthy: PassiveUnhealthy {
                        http_statuses: vec![500],
                        http_failures: 1,
                        tcp_failures: 1,
                        timeouts: 1,
                    },
                }),
            }),
            hash_on: config::UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: config::UpstreamScheme::HTTP,
            pass_host: config::UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
            keepalive_pool: None,
        })
        .expect("multi-node passive upstream must build");

        let passive = upstream.passive.as_ref().unwrap();
        let all_backends: Vec<Backend> = with_lb!(&upstream.lb, |lb| {
            lb.upstreams
                .backends()
                .get_backend()
                .iter()
                .cloned()
                .collect()
        });
        assert_eq!(all_backends.len(), 2);
        let tripped = &all_backends[0];
        let healthy = &all_backends[1];

        let t0 = Instant::now();
        passive.observe_at(tripped, PassiveOutcome::Http(500), t0);
        assert!(passive.has_tripped());

        // During cooldown, only the healthy sibling is selected.
        for _ in 0..8 {
            let picked = upstream.select_with_passive_at(b"", t0 + Duration::from_secs(1));
            assert_eq!(picked.as_ref().map(|b| &b.addr), Some(&healthy.addr));
        }

        // After cooldown elapses, the tripped node is admitted for a single-flight
        // half-open probe even though its sibling remains healthy.
        let probe_time = t0 + PROBE_COOLDOWN;
        let mut probed_tripped = 0;
        for _ in 0..6 {
            let picked = upstream.select_with_passive_at(b"", probe_time).unwrap();
            if picked.addr == tripped.addr {
                probed_tripped += 1;
            }
        }
        assert_eq!(
            probed_tripped, 1,
            "tripped node must receive exactly one half-open probe after cooldown"
        );

        // Probe succeeds -> node recovers and returns to regular rotation.
        passive.observe_at(tripped, PassiveOutcome::Http(200), probe_time);
        assert!(!passive.has_tripped());
    }

    #[test]
    fn active_health_check_success_resets_passive_trip_and_prune_removes_stale() {
        let state = test_state(1, 2, 7, 1);
        let b1 = Backend::new("127.0.0.1:18081").unwrap();
        let b2 = Backend::new("127.0.0.1:18082").unwrap();
        state.observe(&b1, PassiveOutcome::Http(500));
        state.observe(&b2, PassiveOutcome::Http(500));
        assert!(state.has_tripped());

        // Active check requires threshold=2 consecutive successes to clear trip.
        state.observe_active_success(&b1, 2);
        assert!(
            state
                .counters
                .get(&selection::backend_id(&b1))
                .unwrap()
                .tripped
        );
        state.observe_active_success(&b1, 2);
        assert!(
            !state
                .counters
                .get(&selection::backend_id(&b1))
                .unwrap()
                .tripped
        );

        // Pruning drops backends no longer in the live set (DNS rotation).
        let mut live = BTreeSet::new();
        live.insert(b1.clone());
        state.prune_stale(&live);
        assert_eq!(state.counters.len(), 1);
        assert!(state.counters.contains_key(&selection::backend_id(&b1)));
        assert!(!state.counters.contains_key(&selection::backend_id(&b2)));
    }
}
