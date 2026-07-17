//! Control-plane coordinator for atomic dynamic configuration.
//!
//! List, watch, and static YAML loading all build a candidate `ResourceConfigSet`,
//! compile it into a `RuntimeSnapshot`, and publish only on full success.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures::{stream, StreamExt, TryStreamExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use etcd_client::{Event, GetResponse};
use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};
use validator::Validate;

use crate::{
    config::{
        self,
        etcd::{canonicalize_prefix, json_to_resource},
        GlobalRule, Identifiable, Route, Service, Upstream, SSL,
    },
    core::{status, ProxyError, ProxyResult},
};

static PREPARATION_ATTEMPTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_control_plane_preparation_total",
        "Control-plane candidate preparation attempts",
        &["outcome"]
    )
    .expect("control-plane preparation metric registration must succeed")
});
static PENDING_REVISION: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "pingsix_control_plane_pending_revision",
        "Latest etcd revision awaiting successful publication, or zero"
    )
    .expect("control-plane pending revision metric registration must succeed")
});

use super::{
    global_rule::ProxyGlobalRule,
    route::ProxyRoute,
    runtime::{RuntimeSnapshot, RUNTIME},
    service::ProxyService,
    ssl::ProxySSL,
    upstream::{
        discovery::prepare_upstream, inline_key, named_key, prepare_static_upstream,
        traffic_split_key, PreparedUpstreams, ProxyUpstream,
    },
};

/// Deserialized raw configuration graph used by the control plane.
#[derive(Clone, Debug, Default)]
pub struct ResourceConfigSet {
    pub upstreams: HashMap<String, Upstream>,
    pub services: HashMap<String, Service>,
    pub global_rules: HashMap<String, GlobalRule>,
    pub routes: HashMap<String, Route>,
    pub ssls: HashMap<String, SSL>,
}

impl ResourceConfigSet {
    pub fn from_yaml_config(config: &config::Config) -> Self {
        let mut set = Self::default();
        for upstream in &config.upstreams {
            set.upstreams.insert(upstream.id.clone(), upstream.clone());
        }
        for service in &config.services {
            set.services.insert(service.id.clone(), service.clone());
        }
        for rule in &config.global_rules {
            set.global_rules.insert(rule.id.clone(), rule.clone());
        }
        for route in &config.routes {
            set.routes.insert(route.id.clone(), route.clone());
        }
        for ssl in &config.ssls {
            set.ssls.insert(ssl.id.clone(), ssl.clone());
        }
        set
    }

    /// True when the set contains no routable/business configuration.
    pub fn is_business_empty(&self) -> bool {
        self.upstreams.is_empty()
            && self.services.is_empty()
            && self.global_rules.is_empty()
            && self.routes.is_empty()
            && self.ssls.is_empty()
    }

    pub fn from_etcd_list(response: &GetResponse, prefix: &str) -> ProxyResult<Self> {
        let canonical = canonicalize_prefix(prefix);
        let mut set = Self::default();
        for kv in response.kvs() {
            if is_metadata_key(kv.key()) {
                continue;
            }
            let key = String::from_utf8_lossy(kv.key());
            if !key.starts_with(&canonical) {
                log::warn!("Ignoring etcd key outside configured namespace: {key}");
                continue;
            }
            insert_kv(&mut set, kv.key(), kv.value(), &canonical)?;
        }
        Ok(set)
    }
}

/// Insert a single `(key, value)` pair into a `ResourceConfigSet`.
///
/// Shared by `from_etcd_list` and the admin CAS path (which builds a candidate
/// set from a full-graph read before validating references).
fn insert_kv(
    set: &mut ResourceConfigSet,
    key: &[u8],
    value: &[u8],
    canonical_prefix: &str,
) -> ProxyResult<()> {
    let (id, key_type) = parse_key(key, Some(canonical_prefix))
        .map_err(|e| ProxyError::Configuration(format!("Invalid etcd key: {e}")))?;
    match key_type.as_str() {
        "upstreams" => {
            let mut resource = json_to_resource::<Upstream>(value)?;
            resource.set_id(id.clone());
            set.upstreams.insert(id, resource);
        }
        "services" => {
            let mut resource = json_to_resource::<Service>(value)?;
            resource.set_id(id.clone());
            set.services.insert(id, resource);
        }
        "global_rules" => {
            let mut resource = json_to_resource::<GlobalRule>(value)?;
            resource.set_id(id.clone());
            set.global_rules.insert(id, resource);
        }
        "routes" => {
            let mut resource = json_to_resource::<Route>(value)?;
            resource.set_id(id.clone());
            set.routes.insert(id, resource);
        }
        "ssls" => {
            let mut resource = json_to_resource::<SSL>(value)?;
            resource.set_id(id.clone());
            set.ssls.insert(id, resource);
        }
        other => {
            return Err(ProxyError::Configuration(format!(
                "Unknown etcd resource type: {other}"
            )));
        }
    }
    Ok(())
}

/// Build a `ResourceConfigSet` from an arbitrary list of `(physical_key, value)`
/// pairs. Used by the Admin write path to reconstruct the full resource graph
/// from a `read_full_graph` snapshot so `CandidateSnapshot::build` can validate
/// cross-resource references before a CAS commit.
pub fn build_config_set_from_kvs(
    kvs: &[(String, Vec<u8>)],
    prefix: &str,
) -> ProxyResult<ResourceConfigSet> {
    let canonical = canonicalize_prefix(prefix);
    let mut set = ResourceConfigSet::default();
    for (key, value) in kvs {
        if is_metadata_key(key.as_bytes()) {
            continue;
        }
        if !key.starts_with(&canonical) {
            log::warn!("Ignoring etcd key outside configured namespace: {key}");
            continue;
        }
        insert_kv(&mut set, key.as_bytes(), value, &canonical)?;
    }
    Ok(set)
}

/// Lightweight validation of a candidate resource graph without constructing
/// runtime objects (`ProxyUpstream`/`ProxyRoute`/...).
///
/// Performs per-resource `Validate::validate()` plus cross-resource reference
/// checks that mirror `CandidateSnapshot::build`:
/// - `route.service_id` must resolve to an existing service.
/// - `route.upstream_id` (when no inline upstream) must resolve to an existing upstream.
/// - `service.upstream_id` (when no inline upstream) must resolve to an existing upstream.
/// - `traffic-split` `weighted_upstreams[].upstream_id` on routes, services, and
///   global rules must resolve to an existing upstream.
///
/// Used by the Admin write path so PUT/DELETE do not pay the cost of building
/// the full runtime graph (and its `Configuring ...` log noise) just to check
/// references.
pub fn validate_config_set(set: &ResourceConfigSet) -> ProxyResult<()> {
    for upstream in set.upstreams.values() {
        upstream.validate().map_err(|e| {
            ProxyError::Configuration(format!("Upstream '{}' validation failed: {e}", upstream.id))
        })?;
    }
    for service in set.services.values() {
        service.validate().map_err(|e| {
            ProxyError::Configuration(format!("Service '{}' validation failed: {e}", service.id))
        })?;
    }
    for rule in set.global_rules.values() {
        rule.validate().map_err(|e| {
            ProxyError::Configuration(format!("GlobalRule '{}' validation failed: {e}", rule.id))
        })?;
    }
    for route in set.routes.values() {
        route.validate().map_err(|e| {
            ProxyError::Configuration(format!("Route '{}' validation failed: {e}", route.id))
        })?;
    }
    for ssl in set.ssls.values() {
        ssl.validate().map_err(|e| {
            ProxyError::Configuration(format!("SSL '{}' validation failed: {e}", ssl.id))
        })?;
    }

    // Cross-resource reference checks.
    for route in set.routes.values() {
        if let Some(id) = &route.service_id {
            if !set.services.contains_key(id) {
                return Err(ProxyError::Configuration(format!(
                    "Route '{}' references missing service '{}'",
                    route.id, id
                )));
            }
        }
        if route.upstream.is_none() {
            if let Some(id) = &route.upstream_id {
                if !set.upstreams.contains_key(id) {
                    return Err(ProxyError::Configuration(format!(
                        "Route '{}' references missing upstream '{}'",
                        route.id, id
                    )));
                }
            }
        }
        validate_plugin_upstream_refs(
            &format!("Route '{}'", route.id),
            &route.plugins,
            &set.upstreams,
        )?;
    }
    for service in set.services.values() {
        if service.upstream.is_none() {
            if let Some(id) = &service.upstream_id {
                if !set.upstreams.contains_key(id) {
                    return Err(ProxyError::Configuration(format!(
                        "Service '{}' references missing upstream '{}'",
                        service.id, id
                    )));
                }
            }
        }
        validate_plugin_upstream_refs(
            &format!("Service '{}'", service.id),
            &service.plugins,
            &set.upstreams,
        )?;
    }
    for rule in set.global_rules.values() {
        validate_plugin_upstream_refs(
            &format!("GlobalRule '{}'", rule.id),
            &rule.plugins,
            &set.upstreams,
        )?;
    }
    Ok(())
}

/// Validate plugin-embedded named upstream references (currently traffic-split).
fn validate_plugin_upstream_refs(
    owner: &str,
    plugins: &HashMap<String, serde_json::Value>,
    upstreams: &HashMap<String, Upstream>,
) -> ProxyResult<()> {
    if let Some(value) = plugins.get("traffic-split") {
        crate::plugins::traffic_split::validate_traffic_split_config(value)?;
        for id in crate::plugins::traffic_split::named_upstream_ids(value)? {
            if !upstreams.contains_key(&id) {
                return Err(ProxyError::Configuration(format!(
                    "{owner} traffic-split references missing upstream '{id}'"
                )));
            }
        }
    }
    Ok(())
}

/// Control-plane-only candidate built from a single version of the resource graph.
pub struct CandidateSnapshot {
    pub upstreams: HashMap<String, Arc<ProxyUpstream>>,
    pub services: HashMap<String, Arc<ProxyService>>,
    pub global_rules: HashMap<String, Arc<ProxyGlobalRule>>,
    pub routes: HashMap<String, Arc<ProxyRoute>>,
    pub ssls: HashMap<String, Arc<ProxySSL>>,
}

impl CandidateSnapshot {
    /// Build every runtime object from the same raw resource graph.
    ///
    /// Dependency order: upstreams → services → global rules → routes → ssls.
    /// Constructors must not read mutable global state other than the previously
    /// published [`RUNTIME`] snapshot used for Arc reuse.
    pub fn build(config: ResourceConfigSet) -> ProxyResult<Self> {
        let prepared = prepare_static_candidate(&config)?;
        Self::build_prepared(config, &prepared)
    }

    /// Compile a candidate exclusively from material prepared outside the
    /// control-plane writer. This method must never initiate DNS I/O.
    pub(crate) fn build_prepared(
        config: ResourceConfigSet,
        prepared: &PreparedUpstreams,
    ) -> ProxyResult<Self> {
        for upstream in config.upstreams.values() {
            upstream.validate().map_err(|e| {
                ProxyError::Configuration(format!(
                    "Upstream '{}' validation failed: {e}",
                    upstream.id
                ))
            })?;
        }
        for service in config.services.values() {
            service.validate().map_err(|e| {
                ProxyError::Configuration(format!(
                    "Service '{}' validation failed: {e}",
                    service.id
                ))
            })?;
        }
        for rule in config.global_rules.values() {
            rule.validate().map_err(|e| {
                ProxyError::Configuration(format!(
                    "GlobalRule '{}' validation failed: {e}",
                    rule.id
                ))
            })?;
        }
        for route in config.routes.values() {
            route.validate().map_err(|e| {
                ProxyError::Configuration(format!("Route '{}' validation failed: {e}", route.id))
            })?;
        }
        for ssl in config.ssls.values() {
            ssl.validate().map_err(|e| {
                ProxyError::Configuration(format!("SSL '{}' validation failed: {e}", ssl.id))
            })?;
        }

        let previous = RUNTIME.load();

        let mut upstreams = HashMap::with_capacity(config.upstreams.len());
        let mut all_named_upstreams_reused = true;
        for (id, upstream) in config.upstreams {
            log::info!("Configuring upstream: {id}");
            let arc = match previous.upstreams.get(&id) {
                Some(existing) if existing.inner == upstream => existing.clone(),
                _ => {
                    all_named_upstreams_reused = false;
                    Arc::new(ProxyUpstream::build(
                        upstream,
                        prepared.get(&named_key(&id)).cloned().ok_or_else(|| {
                            ProxyError::Configuration(format!("Upstream '{id}' was not prepared"))
                        })?,
                    )?)
                }
            };
            upstreams.insert(id, arc);
        }
        // Deleted named upstreams also invalidate dependent reuse.
        if previous
            .upstreams
            .keys()
            .any(|id| !upstreams.contains_key(id))
        {
            all_named_upstreams_reused = false;
        }

        let mut services = HashMap::with_capacity(config.services.len());
        for (id, service) in config.services {
            log::info!("Configuring service: {id}");
            let arc = if all_named_upstreams_reused {
                match previous.services.get(&id) {
                    Some(existing) if existing.inner == service => existing.clone(),
                    _ => Arc::new(ProxyService::build(service, &upstreams, prepared)?),
                }
            } else {
                Arc::new(ProxyService::build(service, &upstreams, prepared)?)
            };
            services.insert(id, arc);
        }

        let mut global_rules = HashMap::with_capacity(config.global_rules.len());
        for (id, rule) in config.global_rules {
            log::info!("Configuring global rule: {id}");
            let arc = if all_named_upstreams_reused {
                match previous.global_rules.get(&id) {
                    Some(existing) if existing.inner == rule => existing.clone(),
                    _ => Arc::new(ProxyGlobalRule::build(rule, &upstreams, prepared)?),
                }
            } else {
                Arc::new(ProxyGlobalRule::build(rule, &upstreams, prepared)?)
            };
            global_rules.insert(id, arc);
        }

        let services_stable = all_named_upstreams_reused
            && previous.services.keys().all(|id| {
                services
                    .get(id)
                    .zip(previous.services.get(id))
                    .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
            })
            && previous.services.len() == services.len();

        let mut routes = HashMap::with_capacity(config.routes.len());
        for (id, route) in config.routes {
            log::info!("Configuring route: {id}");
            let arc = if services_stable {
                match previous.routes.get(&id) {
                    Some(existing) if existing.inner == route => existing.clone(),
                    _ => Arc::new(ProxyRoute::build(route, &upstreams, &services, prepared)?),
                }
            } else {
                Arc::new(ProxyRoute::build(route, &upstreams, &services, prepared)?)
            };
            routes.insert(id, arc);
        }

        let mut ssls = HashMap::with_capacity(config.ssls.len());
        for (id, ssl) in config.ssls {
            log::info!("Configuring ssl: {id}");
            let arc = match previous.ssls.get(&id) {
                Some(existing) if existing.inner == ssl => existing.clone(),
                _ => Arc::new(ProxySSL::try_from(ssl)?),
            };
            ssls.insert(id, arc);
        }

        Ok(Self {
            upstreams,
            services,
            global_rules,
            routes,
            ssls,
        })
    }
}

/// Prepare every upstream occurrence synchronously. This is used only for
/// static startup; DNS occurrences return an error directing callers to the
/// asynchronous preparation path.
async fn prepare_candidate(config: &ResourceConfigSet) -> ProxyResult<PreparedUpstreams> {
    let previous = RUNTIME.load();
    let mut jobs: Vec<(String, Upstream)> = config
        .upstreams
        .iter()
        .filter(|(id, upstream)| {
            previous
                .upstreams
                .get(*id)
                .is_none_or(|existing| existing.inner != **upstream)
        })
        .map(|(id, upstream)| (named_key(id), upstream.clone()))
        .collect();
    for (id, route) in &config.routes {
        if let Some(upstream) = &route.upstream {
            jobs.push((inline_key(&format!("route/{id}")), upstream.clone()));
        }
        collect_plugin_upstreams(&mut jobs, &format!("route/{id}"), &route.plugins)?;
    }
    for (id, service) in &config.services {
        if let Some(upstream) = &service.upstream {
            jobs.push((inline_key(&format!("service/{id}")), upstream.clone()));
        }
        collect_plugin_upstreams(&mut jobs, &format!("service/{id}"), &service.plugins)?;
    }
    for (id, rule) in &config.global_rules {
        collect_plugin_upstreams(&mut jobs, &format!("global-rule/{id}"), &rule.plugins)?;
    }
    let prepared = stream::iter(jobs)
        .map(|(key, upstream)| async move {
            Ok::<_, ProxyError>((key, prepare_upstream(&upstream).await?))
        })
        .buffer_unordered(8)
        .try_collect::<Vec<_>>()
        .await?;
    Ok(prepared.into_iter().collect())
}

/// Parse inline upstreams declared inside a `traffic-split` plugin into
/// `(prepared-key, upstream)` pairs. Shared by the async and static paths.
fn traffic_split_upstream_jobs(
    owner: &str,
    plugins: &HashMap<String, serde_json::Value>,
) -> ProxyResult<Vec<(String, Upstream)>> {
    let Some(traffic_split) = plugins.get("traffic-split") else {
        return Ok(Vec::new());
    };
    let rules = traffic_split
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ProxyError::Configuration("Invalid traffic-split rules".into()))?;
    let mut jobs = Vec::new();
    for (rule_index, rule) in rules.iter().enumerate() {
        let upstreams = rule
            .get("weighted_upstreams")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                ProxyError::Configuration("Invalid traffic-split weighted_upstreams".into())
            })?;
        for (upstream_index, weighted) in upstreams.iter().enumerate() {
            if let Some(value) = weighted.get("upstream") {
                let upstream: Upstream = serde_json::from_value(value.clone()).map_err(|e| {
                    ProxyError::Configuration(format!("Invalid traffic-split upstream: {e}"))
                })?;
                jobs.push((
                    traffic_split_key(owner, rule_index, upstream_index),
                    upstream,
                ));
            }
        }
    }
    Ok(jobs)
}

fn collect_plugin_upstreams(
    jobs: &mut Vec<(String, Upstream)>,
    owner: &str,
    plugins: &HashMap<String, serde_json::Value>,
) -> ProxyResult<()> {
    jobs.extend(traffic_split_upstream_jobs(owner, plugins)?);
    Ok(())
}

fn prepare_static_candidate(config: &ResourceConfigSet) -> ProxyResult<PreparedUpstreams> {
    let mut prepared = PreparedUpstreams::new();
    for (id, upstream) in &config.upstreams {
        prepared.insert(named_key(id), prepare_static_upstream(upstream)?);
    }
    for (id, route) in &config.routes {
        if let Some(upstream) = &route.upstream {
            prepared.insert(
                inline_key(&format!("route/{id}")),
                prepare_static_upstream(upstream)?,
            );
        }
        prepare_static_plugin_upstreams(&mut prepared, &format!("route/{id}"), &route.plugins)?;
    }
    for (id, service) in &config.services {
        if let Some(upstream) = &service.upstream {
            prepared.insert(
                inline_key(&format!("service/{id}")),
                prepare_static_upstream(upstream)?,
            );
        }
        prepare_static_plugin_upstreams(&mut prepared, &format!("service/{id}"), &service.plugins)?;
    }
    for (id, rule) in &config.global_rules {
        prepare_static_plugin_upstreams(
            &mut prepared,
            &format!("global-rule/{id}"),
            &rule.plugins,
        )?;
    }
    Ok(prepared)
}

fn prepare_static_plugin_upstreams(
    prepared: &mut PreparedUpstreams,
    owner: &str,
    plugins: &HashMap<String, serde_json::Value>,
) -> ProxyResult<()> {
    for (key, upstream) in traffic_split_upstream_jobs(owner, plugins)? {
        prepared.insert(key, prepare_static_upstream(&upstream)?);
    }
    Ok(())
}

enum CoalescedChange {
    Put {
        resource_type: String,
        id: String,
        value: Vec<u8>,
    },
    Delete {
        resource_type: String,
        id: String,
    },
}

/// Unified control-plane entry for list/watch/static publish.
#[derive(Clone)]
struct CandidatePreparation {
    generation: u64,
    revision: i64,
    raw: ResourceConfigSet,
    cancellation: CancellationToken,
}

pub struct ControlPlane {
    raw: Mutex<ResourceConfigSet>,
    /// Latest submitted graph, including candidates still awaiting DNS.
    target: Mutex<Option<CandidatePreparation>>,
    /// Serializes only short raw-candidate creation and fenced publish commits.
    write_lock: Mutex<()>,
    latest_generation: Mutex<u64>,
    /// One bounded owner serializes preparation; submissions replace its pending
    /// target and never block etcd list/watch processing on DNS.
    preparation: AsyncMutex<()>,
    worker_tx: Mutex<Option<mpsc::Sender<()>>>,
    worker_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    active_cancellation: Mutex<Option<CancellationToken>>,
    /// Canonical etcd namespace (`/prefix/`) used to reject foreign keys.
    etcd_prefix: Mutex<Option<String>>,
}

impl ControlPlane {
    fn new() -> Self {
        Self {
            raw: Mutex::new(ResourceConfigSet::default()),
            target: Mutex::new(None),
            write_lock: Mutex::new(()),
            latest_generation: Mutex::new(0),
            preparation: AsyncMutex::new(()),
            worker_tx: Mutex::new(None),
            worker_task: Mutex::new(None),
            active_cancellation: Mutex::new(None),
            etcd_prefix: Mutex::new(None),
        }
    }

    /// Record the active etcd namespace for watch/list key validation.
    pub fn set_etcd_prefix(&self, prefix: String) {
        *self.etcd_prefix.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(canonicalize_prefix(&prefix));
    }

    /// Start the single bounded preparation worker from a Tokio runtime.
    pub fn start_preparation_worker(&'static self) {
        if self
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return;
        }
        let (tx, mut rx) = mpsc::channel(1);
        *self.worker_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let task = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                let mut retry_delay = std::time::Duration::from_secs(1);
                loop {
                    match self.prepare_latest().await {
                        Ok(()) => break,
                        Err(error) => {
                            PREPARATION_ATTEMPTS.with_label_values(&["failed"]).inc();
                            crate::core::status::record_preparation_error(error.to_string());
                            log::warn!(
                                "Control-plane candidate preparation failed; retrying in {}s: {error}",
                                retry_delay.as_secs()
                            );
                            let cancellation = self
                                .active_cancellation
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone();
                            let Some(cancellation) = cancellation else {
                                break;
                            };
                            tokio::select! {
                                _ = tokio::time::sleep(retry_delay) => {}
                                _ = cancellation.cancelled() => break,
                            }
                            retry_delay = (retry_delay * 2).min(std::time::Duration::from_secs(30));
                        }
                    }
                }
            }
        });
        self.worker_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(task);
    }

    /// Submit a full graph without waiting for DNS. A capacity-one signal queue
    /// coalesces churn; the worker always reads the latest generation.
    pub fn submit_replace_all(
        &self,
        resources: ResourceConfigSet,
        revision: i64,
    ) -> ProxyResult<()> {
        let _writer = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.submit(resources, revision)
    }

    pub fn submit_events(&self, events: &[Event], revision: i64) -> ProxyResult<()> {
        if events.is_empty()
            || events
                .iter()
                .all(|event| event.kv().is_some_and(|kv| is_metadata_key(kv.key())))
        {
            return Ok(());
        }
        let _writer = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        if revision < RUNTIME.load().revision {
            return Err(ProxyError::Configuration(format!(
                "Rejecting stale watch revision {revision} < committed runtime revision {}",
                RUNTIME.load().revision
            )));
        }
        let mut candidate = self
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|target| target.raw.clone())
            .unwrap_or_else(|| self.raw.lock().unwrap_or_else(|e| e.into_inner()).clone());
        apply_coalesced_events(&mut candidate, events)?;
        self.submit(candidate, revision)
    }

    fn submit(&self, resources: ResourceConfigSet, revision: i64) -> ProxyResult<()> {
        let generation = {
            let mut generation = self
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *generation += 1;
            *generation
        };
        let cancellation = CancellationToken::new();
        if let Some(previous) = self
            .active_cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(cancellation.clone())
        {
            previous.cancel();
        }
        *self.target.lock().unwrap_or_else(|e| e.into_inner()) = Some(CandidatePreparation {
            generation,
            revision,
            raw: resources,
            cancellation,
        });
        PENDING_REVISION.set(revision);
        let sender = self
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| {
                ProxyError::Configuration("Control-plane preparation worker is not running".into())
            })?;
        match sender.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(ProxyError::Configuration(
                "Control-plane preparation worker stopped".into(),
            )),
        }
    }

    async fn prepare_latest(&self) -> ProxyResult<()> {
        let _owner = self.preparation.lock().await;
        let Some(target) = self
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return Ok(());
        };
        let CandidatePreparation {
            generation,
            raw,
            revision,
            cancellation,
        } = target;
        let prepared = tokio::select! {
            result = prepare_candidate(&raw) => result?,
            _ = cancellation.cancelled() => return Ok(()),
        };
        let _writer = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        if cancellation.is_cancelled()
            || *self
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                != generation
        {
            return Ok(());
        }
        if revision < RUNTIME.load().revision {
            return Ok(());
        }
        let candidate = CandidateSnapshot::build_prepared(raw.clone(), &prepared)?;
        let published = RUNTIME.publish(RuntimeSnapshot::compile(candidate, revision)?)?;
        *self.raw.lock().unwrap_or_else(|e| e.into_inner()) = raw;
        PENDING_REVISION.set(0);
        PREPARATION_ATTEMPTS.with_label_values(&["published"]).inc();
        log::debug!(
            "Published prepared control-plane generation {generation} at revision {}",
            published.revision
        );
        Ok(())
    }

    /// Stop accepting work, cancel the in-flight preparation, and wait a
    /// bounded interval for the sole worker to observe cancellation.
    pub async fn stop_preparation_worker(&self) {
        if let Some(active) = self
            .active_cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            active.cancel();
        }
        self.worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        PENDING_REVISION.set(0);
        let task = self
            .worker_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(mut task) = task {
            if tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .is_err()
            {
                log::warn!("Control-plane preparation worker missed shutdown deadline; aborting");
                task.abort();
                let _ = task.await;
            }
        }
    }

    pub fn replace_all(
        &self,
        resources: ResourceConfigSet,
        revision: i64,
    ) -> ProxyResult<Arc<RuntimeSnapshot>> {
        let _writer = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        // Full list / static reload is authoritative and may move the revision cursor freely.
        self.build_and_publish_locked(resources, revision)
    }

    /// Publish a candidate whose upstreams were prepared outside the sync writer
    /// (static boot DNS path).
    pub(crate) fn replace_all_prepared(
        &self,
        resources: ResourceConfigSet,
        prepared: &PreparedUpstreams,
        revision: i64,
    ) -> ProxyResult<Arc<RuntimeSnapshot>> {
        let _writer = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let candidate = CandidateSnapshot::build_prepared(resources.clone(), prepared)?;
        let snapshot = RuntimeSnapshot::compile(candidate, revision)?;
        let published = RUNTIME.publish(snapshot)?;
        *self.raw.lock().unwrap_or_else(|e| e.into_inner()) = resources.clone();
        *self.target.lock().unwrap_or_else(|e| e.into_inner()) = Some(CandidatePreparation {
            generation: *self
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            revision,
            raw: resources,
            cancellation: CancellationToken::new(),
        });
        Ok(published)
    }

    pub fn apply_events(
        &self,
        events: &[Event],
        revision: i64,
    ) -> ProxyResult<Arc<RuntimeSnapshot>> {
        if events.is_empty() {
            return Ok(RUNTIME.load());
        }

        let _writer = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = RUNTIME.load().revision;
        if revision < current {
            return Err(ProxyError::Configuration(format!(
                "Rejecting stale watch revision {revision} < committed runtime revision {current}"
            )));
        }

        let mut guard = self.raw.lock().unwrap_or_else(|e| e.into_inner());
        let mut candidate_raw = guard.clone();
        apply_coalesced_events(&mut candidate_raw, events)?;

        let candidate = CandidateSnapshot::build(candidate_raw.clone())?;
        let snapshot = RuntimeSnapshot::compile(candidate, revision)?;
        let published = RUNTIME.publish(snapshot)?;
        *guard = candidate_raw;
        Ok(published)
    }

    fn build_and_publish_locked(
        &self,
        candidate_raw: ResourceConfigSet,
        revision: i64,
    ) -> ProxyResult<Arc<RuntimeSnapshot>> {
        let candidate = CandidateSnapshot::build(candidate_raw.clone())?;
        let snapshot = RuntimeSnapshot::compile(candidate, revision)?;
        let published = RUNTIME.publish(snapshot)?;
        *self.raw.lock().unwrap_or_else(|e| e.into_inner()) = candidate_raw.clone();
        *self.target.lock().unwrap_or_else(|e| e.into_inner()) = Some(CandidatePreparation {
            generation: *self
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            revision,
            raw: candidate_raw,
            cancellation: CancellationToken::new(),
        });
        Ok(published)
    }

    /// Snapshot of currently committed raw configuration (for tests / diagnostics).
    #[cfg(test)]
    pub fn raw_snapshot(&self) -> ResourceConfigSet {
        self.raw.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub static CONTROL_PLANE: Lazy<ControlPlane> = Lazy::new(ControlPlane::new);

/// Load static YAML configuration with bounded asynchronous DNS preparation.
///
/// Unlike the etcd worker path, static boot must finish preparation before
/// listeners start. Unresolvable DNS-only upstreams fail the process.
pub fn load_static_configurations(config: &config::Config) -> ProxyResult<Arc<RuntimeSnapshot>> {
    let resources = ResourceConfigSet::from_yaml_config(config);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            ProxyError::Configuration(format!("Failed to create DNS preparation runtime: {e}"))
        })?;
    let prepared = rt.block_on(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
                ProxyError::Configuration(format!("Failed to install SIGTERM handler: {e}"))
            })?;
            tokio::select! {
                result = prepare_candidate(&resources) => result,
                _ = sigterm.recv() => Err(ProxyError::Configuration(
                    "Static configuration DNS preparation cancelled by SIGTERM".into(),
                )),
            }
        }
        #[cfg(not(unix))]
        {
            prepare_candidate(&resources).await
        }
    })?;
    let snapshot = CONTROL_PLANE.replace_all_prepared(resources, &prepared, 0)?;
    status::mark_ready(status::ConfigSource::Yaml);
    Ok(snapshot)
}

fn apply_coalesced_events(raw: &mut ResourceConfigSet, events: &[Event]) -> ProxyResult<()> {
    // Preserve etcd causal order per key: later events overwrite earlier ones.
    let mut final_by_key: HashMap<String, CoalescedChange> = HashMap::new();
    let prefix = CONTROL_PLANE
        .etcd_prefix
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    for event in events {
        let kv = event
            .kv()
            .ok_or_else(|| ProxyError::Configuration("Etcd event missing key-value pair".into()))?;
        let key_bytes = kv.key();
        let key = String::from_utf8_lossy(key_bytes).into_owned();
        if is_metadata_key(key_bytes) {
            continue;
        }
        if let Some(ref canonical) = prefix {
            if !key.starts_with(canonical) {
                log::warn!("Ignoring etcd event outside configured namespace: {key}");
                continue;
            }
        }
        let (id, resource_type) = parse_key(key_bytes, prefix.as_deref()).map_err(|e| {
            ProxyError::Configuration(format!("Failed to parse etcd key '{key}': {e}"))
        })?;

        let change = match event.event_type() {
            etcd_client::EventType::Put => CoalescedChange::Put {
                resource_type,
                id,
                value: kv.value().to_vec(),
            },
            etcd_client::EventType::Delete => CoalescedChange::Delete { resource_type, id },
        };
        final_by_key.insert(key, change);
    }

    for change in final_by_key.into_values() {
        apply_raw_change(raw, change)?;
    }
    Ok(())
}

/// Apply already-coalesced per-key changes (test helper / shared with event coalescing).
#[cfg(test)]
fn apply_coalesced_changes(
    raw: &mut ResourceConfigSet,
    changes: impl IntoIterator<Item = (String, CoalescedChange)>,
) -> ProxyResult<()> {
    let mut final_by_key: HashMap<String, CoalescedChange> = HashMap::new();
    for (key, change) in changes {
        final_by_key.insert(key, change);
    }
    for change in final_by_key.into_values() {
        apply_raw_change(raw, change)?;
    }
    Ok(())
}

fn apply_raw_change(raw: &mut ResourceConfigSet, change: CoalescedChange) -> ProxyResult<()> {
    match change {
        CoalescedChange::Put {
            resource_type,
            id,
            value,
        } => match resource_type.as_str() {
            "upstreams" => {
                let mut resource = json_to_resource::<Upstream>(&value)?;
                resource.set_id(id.clone());
                raw.upstreams.insert(id, resource);
            }
            "services" => {
                let mut resource = json_to_resource::<Service>(&value)?;
                resource.set_id(id.clone());
                raw.services.insert(id, resource);
            }
            "global_rules" => {
                let mut resource = json_to_resource::<GlobalRule>(&value)?;
                resource.set_id(id.clone());
                raw.global_rules.insert(id, resource);
            }
            "routes" => {
                let mut resource = json_to_resource::<Route>(&value)?;
                resource.set_id(id.clone());
                raw.routes.insert(id, resource);
            }
            "ssls" => {
                let mut resource = json_to_resource::<SSL>(&value)?;
                resource.set_id(id.clone());
                raw.ssls.insert(id, resource);
            }
            other => {
                return Err(ProxyError::Configuration(format!(
                    "Unhandled PUT resource type: {other}"
                )));
            }
        },
        CoalescedChange::Delete { resource_type, id } => match resource_type.as_str() {
            "upstreams" => {
                raw.upstreams.remove(&id);
            }
            "services" => {
                raw.services.remove(&id);
            }
            "global_rules" => {
                raw.global_rules.remove(&id);
            }
            "routes" => {
                raw.routes.remove(&id);
            }
            "ssls" => {
                raw.ssls.remove(&id);
            }
            other => {
                return Err(ProxyError::Configuration(format!(
                    "Unhandled DELETE resource type: {other}"
                )));
            }
        },
    }
    Ok(())
}

/// Whether this is internal control-plane metadata rather than a resource.
///
/// Any etcd key whose final path segment starts with `.` is treated as
/// metadata (e.g. `.pingsix_graph_revision`, ingress-controller-internal
/// sync-barrier keys). These must not be parsed as business resources.
pub(crate) fn is_metadata_key(key: &[u8]) -> bool {
    std::str::from_utf8(key)
        .ok()
        .and_then(|key| key.rsplit('/').next())
        .is_some_and(|leaf| leaf.starts_with('.'))
}

/// Parses etcd key in the format `{canonical_prefix}resource_type/id`.
///
/// When `canonical_prefix` is provided, the key must strip exactly to
/// `resource_type/id` (two non-empty segments, no further slashes).
pub(crate) fn parse_key(
    key: &[u8],
    canonical_prefix: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let key = std::str::from_utf8(key)?;
    let rest = if let Some(prefix) = canonical_prefix {
        key.strip_prefix(prefix)
            .ok_or_else(|| format!("Key '{key}' is outside etcd namespace '{prefix}'"))?
    } else {
        // Legacy path for callers without a namespace: take the last two segments
        // but still require at least one parent segment.
        let mut parts = key.rsplit('/');
        let id = parts
            .next()
            .ok_or_else(|| format!("Invalid key format: {key}"))?;
        let key_type = parts
            .next()
            .ok_or_else(|| format!("Invalid key format: {key}"))?;
        if id.is_empty() || key_type.is_empty() || parts.next().is_none() {
            return Err(format!("Invalid key format: {key}").into());
        }
        return Ok((id.to_string(), key_type.to_string()));
    };

    let (key_type, id) = rest
        .split_once('/')
        .ok_or_else(|| format!("Invalid key format under namespace: {key}"))?;
    if key_type.is_empty() || id.is_empty() || id.contains('/') {
        return Err(format!("Invalid key format under namespace: {key}").into());
    }

    Ok((id.to_string(), key_type.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        SelectionType, Upstream, UpstreamHashOn, UpstreamPassHost, UpstreamScheme,
    };
    use crate::proxy::runtime::RUNTIME_TEST_LOCK;
    use std::collections::HashMap as StdHashMap;

    fn sample_upstream(id: &str, node: &str) -> Upstream {
        let mut nodes = StdHashMap::new();
        nodes.insert(node.to_string(), 1);
        Upstream {
            id: id.to_string(),
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes,
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
    fn validate_config_set_rejects_dangling_route_upstream_id() {
        let mut set = ResourceConfigSet::default();
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
                upstream_id: Some("missing".into()),
                service_id: None,
                timeout: None,
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_rejects_dangling_route_service_id() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
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
                service_id: Some("missing".into()),
                timeout: None,
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_rejects_dangling_service_upstream_id() {
        let mut set = ResourceConfigSet::default();
        set.services.insert(
            "s1".into(),
            crate::config::Service {
                id: "s1".into(),
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("missing".into()),
                hosts: vec![],
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_rejects_traffic_split_missing_upstream_on_route() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "does-not-exist", "weight": 100 }
                    ]
                }]
            }),
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
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
            },
        );
        let err = validate_config_set(&set).unwrap_err().to_string();
        assert!(
            err.contains("does-not-exist"),
            "expected missing upstream error, got: {err}"
        );
    }

    #[test]
    fn validate_config_set_rejects_traffic_split_missing_upstream_on_service() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "missing-svc-up", "weight": 100 }
                    ]
                }]
            }),
        );
        set.services.insert(
            "s1".into(),
            crate::config::Service {
                id: "s1".into(),
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                hosts: vec![],
            },
        );
        let err = validate_config_set(&set).unwrap_err().to_string();
        assert!(err.contains("missing-svc-up"), "got: {err}");
    }

    #[test]
    fn validate_config_set_rejects_traffic_split_missing_upstream_on_global_rule() {
        let mut set = ResourceConfigSet::default();
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "missing-gr-up", "weight": 100 }
                    ]
                }]
            }),
        );
        set.global_rules.insert(
            "g1".into(),
            crate::config::GlobalRule {
                id: "g1".into(),
                plugins,
            },
        );
        let err = validate_config_set(&set).unwrap_err().to_string();
        assert!(err.contains("missing-gr-up"), "got: {err}");
    }

    #[test]
    fn validate_config_set_accepts_traffic_split_with_existing_upstream() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        set.upstreams.insert(
            "payments".into(),
            sample_upstream("payments", "10.0.0.2:80"),
        );
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "payments", "weight": 100 }
                    ]
                }]
            }),
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
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
            },
        );
        assert!(validate_config_set(&set).is_ok());
    }

    #[test]
    fn validate_config_set_delete_upstream_referenced_by_traffic_split_fails() {
        // Simulate DELETE of upstream "payments" while a route traffic-split still
        // references it: the candidate set without "payments" must be rejected.
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        // payments intentionally absent (deleted).
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "payments", "weight": 100 }
                    ]
                }]
            }),
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
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_accepts_valid_graph() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        set.services.insert(
            "s1".into(),
            crate::config::Service {
                id: "s1".into(),
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("u1".into()),
                hosts: vec![],
            },
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
                service_id: Some("s1".into()),
                timeout: None,
            },
        );
        assert!(validate_config_set(&set).is_ok());
    }

    #[test]
    fn coalesce_delete_then_put_keeps_resource() {
        let mut raw = ResourceConfigSet::default();
        raw.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));

        apply_coalesced_changes(
            &mut raw,
            [
                (
                    "/p/upstreams/u1".to_string(),
                    CoalescedChange::Delete {
                        resource_type: "upstreams".into(),
                        id: "u1".into(),
                    },
                ),
                (
                    "/p/upstreams/u1".to_string(),
                    CoalescedChange::Put {
                        resource_type: "upstreams".into(),
                        id: "u1".into(),
                        value: serde_json::to_vec(&sample_upstream("u1", "10.0.0.2:80")).unwrap(),
                    },
                ),
            ],
        )
        .unwrap();

        assert!(raw.upstreams.contains_key("u1"));
        assert!(raw.upstreams["u1"].nodes.contains_key("10.0.0.2:80"));
    }

    #[test]
    fn parse_key_rejects_sibling_prefix_pollution() {
        let canonical = canonicalize_prefix("/apisix");
        assert!(parse_key(b"/apisix/routes/1", Some(&canonical)).is_ok());
        assert!(parse_key(b"/apisix-other/routes/2", Some(&canonical)).is_err());
        assert!(parse_key(b"/apisix/routes/1/extra", Some(&canonical)).is_err());
        assert!(parse_key(b"/apisix/routes", Some(&canonical)).is_err());
    }

    #[test]
    fn metadata_key_is_excluded_from_full_graph_build() {
        let set = build_config_set_from_kvs(
            &[
                ("/pingsix/.pingsix_graph_revision".into(), b"1".to_vec()),
                ("/pingsix/.ingress_sync_barrier".into(), b"{}".to_vec()),
            ],
            "/pingsix",
        )
        .unwrap();
        assert!(set.routes.is_empty());
        assert!(is_metadata_key(b"/pingsix/.pingsix_graph_revision"));
        assert!(is_metadata_key(b"/pingsix/.ingress_sync_barrier"));
        assert!(!is_metadata_key(b"/pingsix/routes/1"));
    }

    #[test]
    fn coalesce_put_then_delete_removes_resource() {
        let mut raw = ResourceConfigSet::default();
        apply_coalesced_changes(
            &mut raw,
            [
                (
                    "/p/upstreams/u1".to_string(),
                    CoalescedChange::Put {
                        resource_type: "upstreams".into(),
                        id: "u1".into(),
                        value: serde_json::to_vec(&sample_upstream("u1", "10.0.0.1:80")).unwrap(),
                    },
                ),
                (
                    "/p/upstreams/u1".to_string(),
                    CoalescedChange::Delete {
                        resource_type: "upstreams".into(),
                        id: "u1".into(),
                    },
                ),
            ],
        )
        .unwrap();
        assert!(!raw.upstreams.contains_key("u1"));
    }

    #[test]
    fn coalesce_put_v1_then_put_v2_keeps_v2() {
        let mut raw = ResourceConfigSet::default();
        apply_coalesced_changes(
            &mut raw,
            [
                (
                    "/p/upstreams/u1".to_string(),
                    CoalescedChange::Put {
                        resource_type: "upstreams".into(),
                        id: "u1".into(),
                        value: serde_json::to_vec(&sample_upstream("u1", "10.0.0.1:80")).unwrap(),
                    },
                ),
                (
                    "/p/upstreams/u1".to_string(),
                    CoalescedChange::Put {
                        resource_type: "upstreams".into(),
                        id: "u1".into(),
                        value: serde_json::to_vec(&sample_upstream("u1", "10.0.0.9:80")).unwrap(),
                    },
                ),
            ],
        )
        .unwrap();
        assert!(raw.upstreams["u1"].nodes.contains_key("10.0.0.9:80"));
        assert!(!raw.upstreams["u1"].nodes.contains_key("10.0.0.1:80"));
    }

    #[test]
    fn failed_apply_leaves_revision_and_raw_unchanged() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let plane = ControlPlane::new();
        let mut good = ResourceConfigSet::default();
        good.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        plane.replace_all(good, 3).unwrap();

        // Missing upstream dependency must fail without advancing committed state.
        let mut bad = ResourceConfigSet::default();
        bad.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                uri: Some("/x".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("missing".into()),
                service_id: None,
                timeout: None,
            },
        );
        assert!(plane.replace_all(bad, 4).is_err());
        assert_eq!(RUNTIME.load().revision, 3);
        assert!(plane.raw_snapshot().upstreams.contains_key("u1"));
        assert!(plane.raw_snapshot().routes.is_empty());
    }

    #[test]
    fn failed_candidate_build_leaves_committed_raw_unchanged() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let plane = ControlPlane::new();
        let mut good = ResourceConfigSet::default();
        good.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        plane.replace_all(good, 1).unwrap();
        assert!(plane.raw_snapshot().upstreams.contains_key("u1"));

        let mut bad = ResourceConfigSet::default();
        // Route references a missing upstream — compile must fail.
        use crate::config::Route;
        bad.routes.insert(
            "r1".into(),
            Route {
                id: "r1".into(),
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("missing".into()),
                service_id: None,
                timeout: None,
            },
        );
        assert!(plane.replace_all(bad, 2).is_err());
        assert!(plane.raw_snapshot().upstreams.contains_key("u1"));
        assert!(!plane.raw_snapshot().routes.contains_key("r1"));
        assert_eq!(RUNTIME.load().revision, 1);
    }

    #[test]
    fn empty_apply_events_does_not_change_revision() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let plane = ControlPlane::new();
        let mut good = ResourceConfigSet::default();
        good.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        plane.replace_all(good, 7).unwrap();
        let before = RUNTIME.load().revision;
        plane.apply_events(&[], 99).unwrap();
        assert_eq!(RUNTIME.load().revision, before);
    }

    #[test]
    fn service_rebinding_follows_updated_upstream_on_full_replace() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let plane = ControlPlane::new();
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        set.services.insert(
            "s1".into(),
            crate::config::Service {
                id: "s1".into(),
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("u1".into()),
                hosts: vec![],
            },
        );
        plane.replace_all(set.clone(), 1).unwrap();
        let old_ptr = Arc::as_ptr(RUNTIME.load().upstreams.get("u1").unwrap());

        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.2:80"));
        // Service config unchanged; full rebuild must still bind the new upstream object.
        plane.replace_all(set, 2).unwrap();
        let snap = RUNTIME.load();
        let new_ptr = Arc::as_ptr(snap.upstreams.get("u1").unwrap());
        assert_ne!(old_ptr, new_ptr);
        assert!(snap.upstreams["u1"].inner.nodes.contains_key("10.0.0.2:80"));
        assert_eq!(snap.revision, 2);
    }
}
