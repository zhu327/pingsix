//! Immutable runtime snapshots for the data plane.
//!
//! Writers compile a `CandidateSnapshot` into a `RuntimeSnapshot` and publish it
//! atomically. Health checks are reconciled incrementally by `RuntimeStore`.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use once_cell::sync::Lazy;

use crate::{
    config,
    core::{ProxyPluginExecutor, ProxyResult},
};

use super::{
    control_plane::CandidateSnapshot,
    global_rule::{build_global_plugin_executor, ProxyGlobalRule},
    route::{MatchEntry as RouteMatcher, ProxyRoute},
    service::ProxyService,
    ssl::{MatchEntry as SslMatcher, ProxySSL},
    upstream::{
        health_check::{
            HealthCheckFingerprint, HealthCheckRegistration, HealthCheckSpec,
            SHARED_HEALTH_CHECK_SERVICE,
        },
        ProxyUpstream,
    },
};

/// Immutable data-plane view. Requests must only read from this snapshot.
pub struct RuntimeSnapshot {
    pub revision: i64,
    pub routes: Arc<HashMap<String, Arc<ProxyRoute>>>,
    pub upstreams: Arc<HashMap<String, Arc<ProxyUpstream>>>,
    pub services: Arc<HashMap<String, Arc<ProxyService>>>,
    pub global_rules: Arc<HashMap<String, Arc<ProxyGlobalRule>>>,
    pub ssls: Arc<HashMap<String, Arc<ProxySSL>>>,
    pub route_matcher: Arc<RouteMatcher>,
    pub global_plugins: Arc<ProxyPluginExecutor>,
    pub ssl_matcher: Arc<SslMatcher>,
}

impl RuntimeSnapshot {
    fn empty() -> Self {
        Self {
            revision: 0,
            routes: Arc::new(HashMap::new()),
            upstreams: Arc::new(HashMap::new()),
            services: Arc::new(HashMap::new()),
            global_rules: Arc::new(HashMap::new()),
            ssls: Arc::new(HashMap::new()),
            route_matcher: Arc::new(RouteMatcher::default()),
            global_plugins: ProxyPluginExecutor::default_shared(),
            ssl_matcher: Arc::new(SslMatcher::default()),
        }
    }

    /// Sole construction path for published runtime state.
    pub fn compile(candidate: CandidateSnapshot, revision: i64) -> ProxyResult<Self> {
        let routes = Arc::new(candidate.routes);
        let upstreams = Arc::new(candidate.upstreams);
        let services = Arc::new(candidate.services);
        let global_rules = Arc::new(candidate.global_rules);
        let ssls = Arc::new(candidate.ssls);
        let route_matcher = Arc::new(RouteMatcher::build(&routes)?);
        let global_plugins = build_global_plugin_executor(&global_rules);
        let ssl_matcher = Arc::new(SslMatcher::build(&ssls)?);

        Ok(Self {
            revision,
            routes,
            upstreams,
            services,
            global_rules,
            ssls,
            route_matcher,
            global_plugins,
            ssl_matcher,
        })
    }
}

fn health_check_fingerprint(upstream: &config::Upstream) -> HealthCheckFingerprint {
    fingerprint_upstream_for_health_check(upstream)
}

/// Stable fingerprint of upstream fields that affect health-check behavior.
///
/// Includes scheme, node addresses (not weights), and `checks`. Excludes retries,
/// pass_host, and similar LB-only fields so unrelated edits do not restart HC tasks.
pub fn fingerprint_upstream_for_health_check(
    upstream: &config::Upstream,
) -> HealthCheckFingerprint {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    if let Ok(scheme) = serde_json::to_vec(&upstream.scheme) {
        scheme.hash(&mut hasher);
    }
    let mut addrs: Vec<_> = upstream.nodes.keys().collect();
    addrs.sort();
    for addr in addrs {
        addr.hash(&mut hasher);
    }
    if let Ok(bytes) = serde_json::to_vec(&upstream.checks) {
        bytes.hash(&mut hasher);
    }
    HealthCheckFingerprint(hasher.finish())
}

fn collect_health_checks(snapshot: &RuntimeSnapshot) -> Vec<HealthCheckSpec> {
    let mut targets = Vec::new();

    for (id, upstream) in snapshot.upstreams.iter() {
        targets.push(HealthCheckSpec {
            key: format!("upstream/{id}"),
            fingerprint: health_check_fingerprint(&upstream.inner),
            service: upstream.health_check_service(),
        });
    }
    for (id, service) in snapshot.services.iter() {
        if let Some(upstream) = &service.inline_upstream {
            targets.push(HealthCheckSpec {
                key: format!("service/{id}/inline"),
                fingerprint: health_check_fingerprint(&upstream.inner),
                service: upstream.health_check_service(),
            });
        }
        for plugin in &service.plugins {
            targets.extend(plugin_health_checks(
                &format!("service/{id}/plugin"),
                plugin,
            ));
        }
    }
    for (id, route) in snapshot.routes.iter() {
        if let Some(upstream) = &route.inline_upstream {
            targets.push(HealthCheckSpec {
                key: format!("route/{id}/inline"),
                fingerprint: health_check_fingerprint(&upstream.inner),
                service: upstream.health_check_service(),
            });
        }
        for plugin in &route.plugins {
            targets.extend(plugin_health_checks(&format!("route/{id}/plugin"), plugin));
        }
    }
    for (id, rule) in snapshot.global_rules.iter() {
        for plugin in &rule.plugins {
            targets.extend(plugin_health_checks(
                &format!("global-rule/{id}/plugin"),
                plugin,
            ));
        }
    }

    targets
}

fn plugin_health_checks(
    prefix: &str,
    plugin: &Arc<dyn crate::core::ProxyPlugin>,
) -> Vec<HealthCheckSpec> {
    // Prefer typed traffic-split targets with upstream config when available.
    if let Some(specs) = plugin.health_check_specs() {
        return specs
            .into_iter()
            .map(|mut spec| {
                spec.key = format!("{prefix}/{}", spec.key);
                spec
            })
            .collect();
    }

    plugin
        .health_check_targets()
        .into_iter()
        .map(|(key, service)| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut hasher);
            HealthCheckSpec {
                key: format!("{prefix}/{key}"),
                fingerprint: HealthCheckFingerprint(hasher.finish()),
                service,
            }
        })
        .collect()
}

struct ActiveHealthCheckEntry {
    fingerprint: HealthCheckFingerprint,
    registration: HealthCheckRegistration,
    /// Retained so publish can detect "same fingerprint, different LB Arc".
    service: Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync>,
}

/// Currently activated health checks owned by the runtime store.
///
/// Ownership lives here (not on snapshot Drop) so unchanged checks survive republish.
struct ActiveHealthCheckSet {
    entries: HashMap<String, ActiveHealthCheckEntry>,
}

impl ActiveHealthCheckSet {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

pub struct RuntimeStore {
    current: ArcSwap<RuntimeSnapshot>,
    health_checks: Mutex<ActiveHealthCheckSet>,
    publish_lock: Mutex<()>,
}

impl RuntimeStore {
    fn new() -> Self {
        Self {
            current: ArcSwap::from_pointee(RuntimeSnapshot::empty()),
            health_checks: Mutex::new(ActiveHealthCheckSet::new()),
            publish_lock: Mutex::new(()),
        }
    }

    pub fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    /// Publish a compiled snapshot and incrementally reconcile health checks.
    ///
    /// Order:
    /// 1. Start new / replacement checks without stopping displaced ones
    /// 2. Store the runtime snapshot
    /// 3. Discard displaced checks and stop removed keys
    ///
    /// Registration is infallible (Candidate build owns fallible work). Displaced
    /// checks keep running until after snapshot commit.
    pub fn publish(&self, snapshot: RuntimeSnapshot) -> ProxyResult<Arc<RuntimeSnapshot>> {
        let _guard = self.publish_lock.lock().unwrap_or_else(|e| e.into_inner());
        let desired = collect_health_checks(&snapshot);
        let mut active = self.health_checks.lock().unwrap_or_else(|e| e.into_inner());

        let mut next_entries = HashMap::with_capacity(desired.len());
        let mut displaced = Vec::new();

        for spec in desired {
            if let Some(existing) = active.entries.get(&spec.key) {
                // Fingerprint alone is insufficient: a rebuilt ProxyUpstream can share the
                // HC fingerprint (e.g. weight-only edits) while owning a different LB Arc.
                // Only keep the registration when the LB service Arc is identical.
                if existing.fingerprint == spec.fingerprint
                    && Arc::ptr_eq(&existing.service, &spec.service)
                {
                    next_entries.insert(
                        spec.key,
                        ActiveHealthCheckEntry {
                            fingerprint: existing.fingerprint,
                            registration: existing.registration,
                            service: existing.service.clone(),
                        },
                    );
                    continue;
                }
            }

            let (registration, maybe_displaced) = SHARED_HEALTH_CHECK_SERVICE
                .register_upstream(spec.key.clone(), spec.service.clone());
            if let Some(d) = maybe_displaced {
                displaced.push(d);
            }
            next_entries.insert(
                spec.key,
                ActiveHealthCheckEntry {
                    fingerprint: spec.fingerprint,
                    registration,
                    service: spec.service,
                },
            );
        }

        let mut removed = Vec::new();
        for (key, entry) in active.entries.iter() {
            match next_entries.get(key) {
                Some(next) if next.registration == entry.registration => {}
                Some(_) => {
                    // Replacement: old generation is stopped via displaced.discard() below.
                }
                None => {
                    removed.push((key.clone(), entry.registration));
                }
            }
        }

        let snapshot = Arc::new(snapshot);
        self.current.store(snapshot.clone());
        crate::core::status::set_published_revision(snapshot.revision);

        for d in displaced {
            d.discard();
        }
        for (key, registration) in removed {
            SHARED_HEALTH_CHECK_SERVICE.unregister_upstream(&key, registration);
        }

        active.entries = next_entries;
        Ok(snapshot)
    }

    /// Test helper: currently active health-check generations by key.
    #[cfg(test)]
    pub fn health_check_generation(&self, key: &str) -> Option<u64> {
        self.health_checks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .get(key)
            .map(|e| e.registration.generation())
    }
}

pub static RUNTIME: Lazy<RuntimeStore> = Lazy::new(RuntimeStore::new);

/// Serializes tests that publish to the process-global [`RUNTIME`].
#[cfg(test)]
pub(crate) static RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        SelectionType, Upstream, UpstreamHashOn, UpstreamPassHost, UpstreamScheme,
    };

    fn sample_upstream(id: &str, nodes: &[(&str, u32)]) -> Upstream {
        let mut map = HashMap::new();
        for (addr, weight) in nodes {
            map.insert((*addr).to_string(), *weight);
        }
        Upstream {
            id: id.to_string(),
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes: map,
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
        }
    }

    #[test]
    fn runtime_store_keeps_loaded_snapshot_after_publish() {
        let store = RuntimeStore::new();
        let old = store.load();
        let empty = RuntimeSnapshot::empty();
        let published = store.publish(empty).unwrap();

        assert!(!Arc::ptr_eq(&old, &published));
        assert!(old.routes.is_empty());
        assert!(published.routes.is_empty());
        assert!(Arc::ptr_eq(&store.load(), &published));
    }

    #[test]
    fn health_check_fingerprint_is_stable_across_hashmap_insertion_order() {
        let a = sample_upstream("u", &[("10.0.0.2:80", 1), ("10.0.0.1:80", 2)]);
        let b = sample_upstream("u", &[("10.0.0.1:80", 2), ("10.0.0.2:80", 1)]);
        assert_eq!(
            fingerprint_upstream_for_health_check(&a),
            fingerprint_upstream_for_health_check(&b)
        );
    }

    #[test]
    fn health_check_fingerprint_ignores_node_weight_changes() {
        let a = sample_upstream("u", &[("10.0.0.1:80", 1)]);
        let b = sample_upstream("u", &[("10.0.0.1:80", 99)]);
        assert_eq!(
            fingerprint_upstream_for_health_check(&a),
            fingerprint_upstream_for_health_check(&b)
        );
    }

    #[test]
    fn unchanged_upstream_keeps_health_check_generation_across_publish() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::proxy::control_plane::{CandidateSnapshot, ResourceConfigSet};

        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", &[("10.0.0.1:80", 1)]));
        let snap1 =
            RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), 1).unwrap();
        RUNTIME.publish(snap1).unwrap();
        let gen1 = RUNTIME
            .health_check_generation("upstream/u1")
            .expect("hc registered");

        // Route-only addition; upstream config unchanged.
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
            },
        );
        let snap2 = RuntimeSnapshot::compile(CandidateSnapshot::build(set).unwrap(), 2).unwrap();
        RUNTIME.publish(snap2).unwrap();
        let gen2 = RUNTIME
            .health_check_generation("upstream/u1")
            .expect("hc still registered");
        assert_eq!(gen1, gen2);
    }

    #[test]
    fn route_only_update_reuses_upstream_arc_and_keeps_backends_selectable() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::proxy::control_plane::{CandidateSnapshot, ResourceConfigSet};

        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", &[("10.0.0.1:80", 1)]));
        RUNTIME
            .publish(
                RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), 1)
                    .unwrap(),
            )
            .unwrap();
        let before = RUNTIME.load().upstreams.get("u1").cloned().unwrap();
        assert!(
            before.select_backend_for_test().is_some(),
            "eager discovery must populate backends before publish"
        );

        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
            },
        );
        RUNTIME
            .publish(RuntimeSnapshot::compile(CandidateSnapshot::build(set).unwrap(), 2).unwrap())
            .unwrap();
        let after = RUNTIME.load().upstreams.get("u1").cloned().unwrap();
        assert!(
            Arc::ptr_eq(&before, &after),
            "route-only publish must reuse ProxyUpstream Arc so HC stays bound to the live LB"
        );
        assert!(
            after.select_backend_for_test().is_some(),
            "published runtime LB must still select a backend after route-only update"
        );
    }

    #[test]
    fn weight_only_upstream_change_replaces_health_check_generation() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::proxy::control_plane::{CandidateSnapshot, ResourceConfigSet};

        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", &[("10.0.0.1:80", 1)]));
        RUNTIME
            .publish(
                RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), 1)
                    .unwrap(),
            )
            .unwrap();
        let gen1 = RUNTIME.health_check_generation("upstream/u1").unwrap();
        let before = RUNTIME.load().upstreams.get("u1").cloned().unwrap();

        // Weight is ignored by HC fingerprint but still rebuilds the LB.
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", &[("10.0.0.1:80", 99)]));
        RUNTIME
            .publish(RuntimeSnapshot::compile(CandidateSnapshot::build(set).unwrap(), 2).unwrap())
            .unwrap();
        let after = RUNTIME.load().upstreams.get("u1").cloned().unwrap();
        let gen2 = RUNTIME.health_check_generation("upstream/u1").unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(
            fingerprint_upstream_for_health_check(&before.inner),
            fingerprint_upstream_for_health_check(&after.inner)
        );
        assert_ne!(
            gen1, gen2,
            "new LB Arc must get its own HC registration even when fingerprint matches"
        );
        assert!(after.select_backend_for_test().is_some());
    }

    #[test]
    fn upstream_node_change_replaces_health_check_generation() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::proxy::control_plane::{CandidateSnapshot, ResourceConfigSet};

        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", &[("10.0.0.1:80", 1)]));
        RUNTIME
            .publish(
                RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), 1)
                    .unwrap(),
            )
            .unwrap();
        let gen1 = RUNTIME.health_check_generation("upstream/u1").unwrap();

        set.upstreams
            .insert("u1".into(), sample_upstream("u1", &[("10.0.0.2:80", 1)]));
        RUNTIME
            .publish(RuntimeSnapshot::compile(CandidateSnapshot::build(set).unwrap(), 2).unwrap())
            .unwrap();
        let gen2 = RUNTIME.health_check_generation("upstream/u1").unwrap();
        assert_ne!(gen1, gen2);
    }
}
