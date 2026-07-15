//! Control-plane coordinator for atomic dynamic configuration.
//!
//! List, watch, and static YAML loading all build a candidate `ResourceConfigSet`,
//! compile it into a `RuntimeSnapshot`, and publish only on full success.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use etcd_client::{Event, GetResponse};
use once_cell::sync::Lazy;
use validator::Validate;

use crate::{
    config::{
        self, etcd::json_to_resource, GlobalRule, Identifiable, Route, Service, Upstream, SSL,
    },
    core::{status, ProxyError, ProxyResult},
};

use super::{
    global_rule::ProxyGlobalRule,
    route::ProxyRoute,
    runtime::{RuntimeSnapshot, RUNTIME},
    service::ProxyService,
    ssl::ProxySSL,
    upstream::ProxyUpstream,
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

    pub fn from_etcd_list(response: &GetResponse) -> ProxyResult<Self> {
        let mut set = Self::default();
        for kv in response.kvs() {
            insert_kv(&mut set, kv.key(), kv.value())?;
        }
        Ok(set)
    }
}

/// Insert a single `(key, value)` pair into a `ResourceConfigSet`.
///
/// Shared by `from_etcd_list` and the admin CAS path (which builds a candidate
/// set from a full-graph read before validating references).
fn insert_kv(set: &mut ResourceConfigSet, key: &[u8], value: &[u8]) -> ProxyResult<()> {
    let (id, key_type) =
        parse_key(key).map_err(|e| ProxyError::Configuration(format!("Invalid etcd key: {e}")))?;
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
pub fn build_config_set_from_kvs(kvs: &[(String, Vec<u8>)]) -> ProxyResult<ResourceConfigSet> {
    let mut set = ResourceConfigSet::default();
    for (key, value) in kvs {
        insert_kv(&mut set, key.as_bytes(), value)?;
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
                    Arc::new(ProxyUpstream::build(upstream)?)
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
                    _ => Arc::new(ProxyService::build(service, &upstreams)?),
                }
            } else {
                Arc::new(ProxyService::build(service, &upstreams)?)
            };
            services.insert(id, arc);
        }

        let mut global_rules = HashMap::with_capacity(config.global_rules.len());
        for (id, rule) in config.global_rules {
            log::info!("Configuring global rule: {id}");
            let arc = if all_named_upstreams_reused {
                match previous.global_rules.get(&id) {
                    Some(existing) if existing.inner == rule => existing.clone(),
                    _ => Arc::new(ProxyGlobalRule::build(rule, &upstreams)?),
                }
            } else {
                Arc::new(ProxyGlobalRule::build(rule, &upstreams)?)
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
                    _ => Arc::new(ProxyRoute::build(route, &upstreams, &services)?),
                }
            } else {
                Arc::new(ProxyRoute::build(route, &upstreams, &services)?)
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
pub struct ControlPlane {
    raw: Mutex<ResourceConfigSet>,
    /// Serializes all writers (`replace_all` / `apply_events`) across build → publish → commit.
    write_lock: Mutex<()>,
}

impl ControlPlane {
    fn new() -> Self {
        Self {
            raw: Mutex::new(ResourceConfigSet::default()),
            write_lock: Mutex::new(()),
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
        *self.raw.lock().unwrap_or_else(|e| e.into_inner()) = candidate_raw;
        Ok(published)
    }

    /// Snapshot of currently committed raw configuration (for tests / diagnostics).
    #[cfg(test)]
    pub fn raw_snapshot(&self) -> ResourceConfigSet {
        self.raw.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub static CONTROL_PLANE: Lazy<ControlPlane> = Lazy::new(ControlPlane::new);

/// Load static YAML configuration through the same publish path as etcd list.
pub fn load_static_configurations(config: &config::Config) -> ProxyResult<Arc<RuntimeSnapshot>> {
    let resources = ResourceConfigSet::from_yaml_config(config);
    let snapshot = CONTROL_PLANE.replace_all(resources, 0)?;
    status::mark_ready(status::ConfigSource::Yaml);
    Ok(snapshot)
}

fn apply_coalesced_events(raw: &mut ResourceConfigSet, events: &[Event]) -> ProxyResult<()> {
    // Preserve etcd causal order per key: later events overwrite earlier ones.
    let mut final_by_key: HashMap<String, CoalescedChange> = HashMap::new();

    for event in events {
        let kv = event
            .kv()
            .ok_or_else(|| ProxyError::Configuration("Etcd event missing key-value pair".into()))?;
        let key_bytes = kv.key();
        let key = String::from_utf8_lossy(key_bytes).into_owned();
        let (id, resource_type) = parse_key(key_bytes).map_err(|e| {
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

/// Parses etcd key in the format `/prefix/resource_type/id`.
pub(crate) fn parse_key(key: &[u8]) -> Result<(String, String), Box<dyn std::error::Error>> {
    let key = std::str::from_utf8(key)?;
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
