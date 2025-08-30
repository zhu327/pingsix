use std::sync::Arc;

use etcd_client::{Event, GetResponse};
use prometheus::{register_int_counter_vec, IntCounterVec};

use crate::config::{
    etcd::{json_to_resource, EtcdEventHandler},
    GlobalRule, Identifiable, Route, Service, Upstream, SSL,
};

use super::{
    global_rule::{reload_global_plugin, ProxyGlobalRule, GLOBAL_RULE_MAP},
    route::{reload_global_route_match, ProxyRoute, ROUTE_MAP},
    service::{ProxyService, SERVICE_MAP},
    ssl::{reload_global_ssl_match, ProxySSL, SSL_MAP},
    upstream::{ProxyUpstream, UPSTREAM_MAP},
    MapOperations,
};

// Adapter functions to convert ProxyResult to pingora Result
fn create_proxy_route(route: Route) -> pingora_error::Result<ProxyRoute> {
    ProxyRoute::new_with_upstream_and_plugins(route).map_err(|e| e.into())
}

fn create_proxy_upstream(upstream: Upstream) -> pingora_error::Result<ProxyUpstream> {
    ProxyUpstream::new_with_shared_health_check(upstream).map_err(|e| e.into())
}

fn create_proxy_service(service: Service) -> pingora_error::Result<ProxyService> {
    ProxyService::new_with_upstream_and_plugins(service).map_err(|e| e.into())
}

fn create_proxy_global_rule(rule: GlobalRule) -> pingora_error::Result<ProxyGlobalRule> {
    ProxyGlobalRule::new_with_plugins(rule).map_err(|e| e.into())
}

// Note: The following types must implement `Identifiable` in `crate::config`:
// - Route
// - Upstream
// - Service
// - GlobalRule
// - SSL
// Example implementation (add to `src/config/mod.rs` or relevant module):
/*
impl Identifiable for Route {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn set_id(&mut self, id: String) {
        self.id = id;
    }
}
// Repeat for Upstream, Service, GlobalRule, SSL
*/

// Trait to compare proxy types with their inner configuration types
trait InnerComparable<T> {
    fn inner_equals(&self, other: &T) -> bool;
}

impl InnerComparable<Route> for ProxyRoute {
    fn inner_equals(&self, other: &Route) -> bool {
        self.inner == *other
    }
}

impl InnerComparable<Upstream> for ProxyUpstream {
    fn inner_equals(&self, other: &Upstream) -> bool {
        self.inner == *other
    }
}

impl InnerComparable<Service> for ProxyService {
    fn inner_equals(&self, other: &Service) -> bool {
        self.inner == *other
    }
}

impl InnerComparable<GlobalRule> for ProxyGlobalRule {
    fn inner_equals(&self, other: &GlobalRule) -> bool {
        self.inner == *other
    }
}

impl InnerComparable<SSL> for ProxySSL {
    fn inner_equals(&self, other: &SSL) -> bool {
        self.inner == *other
    }
}

pub struct ProxyEventHandler;

impl Default for ProxyEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyEventHandler {
    pub fn new() -> Self {
        ProxyEventHandler
    }

    /// Generic function to handle list responses for different resource types.
    fn handle_list_resource<T, P>(
        &self,
        response: &GetResponse,
        key_type: &str,
        map: &impl MapOperations<P>,
        create_proxy: fn(T) -> pingora_error::Result<P>,
        reload_fn: Option<fn()>,
    ) where
        T: serde::de::DeserializeOwned + Clone + Identifiable,
        P: Identifiable + InnerComparable<T>,
    {
        static LIST_RESULTS: once_cell::sync::Lazy<IntCounterVec> = once_cell::sync::Lazy::new(|| {
            register_int_counter_vec!(
                "pingsix_resource_list_results_total",
                "Results of resource list operations",
                &["type", "result"]
            )
            .unwrap()
        });

        let resources: Vec<T> = response
            .kvs()
            .iter()
            .filter_map(|kv| match parse_key(kv.key()) {
                Ok((id, parsed_key_type)) if parsed_key_type == key_type => {
                    match json_to_resource::<T>(kv.value()) {
                        Ok(mut resource) => {
                            resource.set_id(id);
                            Some(resource)
                        }
                        Err(e) => {
                            log::error!("Failed to load etcd {key_type}: {id} {e}");
                            LIST_RESULTS.with_label_values(&[key_type, "invalid"]).inc();
                            None
                        }
                    }
                }
                _ => None,
            })
            .collect();

        let proxy_resources: Vec<Arc<P>> = resources
            .iter()
            .filter_map(|resource| {
                if let Some(proxy_res) = map.get(resource.id()) {
                    if proxy_res.inner_equals(resource) {
                        LIST_RESULTS.with_label_values(&[key_type, "reuse"]).inc();
                        return Some(proxy_res.clone());
                    }
                }

                log::info!("Configuring {}: {}", key_type, resource.id());
                match create_proxy(resource.clone()) {
                    Ok(proxy) => { LIST_RESULTS.with_label_values(&[key_type, "created"]).inc(); Some(Arc::new(proxy)) },
                    Err(e) => {
                        log::error!(
                            "Failed to create proxy for {} {}: {}",
                            key_type,
                            resource.id(),
                            e
                        );
                        LIST_RESULTS.with_label_values(&[key_type, "failed"]).inc();
                        None
                    }
                }
            })
            .collect();

        map.reload_resources(proxy_resources);
        if let Some(reload) = reload_fn {
            reload();
        }
    }

    fn handle_routes(&self, response: &GetResponse) {
        self.handle_list_resource(
            response,
            "routes",
            &*ROUTE_MAP,
            create_proxy_route,
            Some(reload_global_route_match),
        );
    }

    fn handle_upstreams(&self, response: &GetResponse) {
        self.handle_list_resource(
            response,
            "upstreams",
            &*UPSTREAM_MAP,
            create_proxy_upstream,
            None,
        );
    }

    fn handle_services(&self, response: &GetResponse) {
        self.handle_list_resource(
            response,
            "services",
            &*SERVICE_MAP,
            create_proxy_service,
            None,
        );
    }

    fn handle_global_rules(&self, response: &GetResponse) {
        self.handle_list_resource(
            response,
            "global_rules",
            &*GLOBAL_RULE_MAP,
            create_proxy_global_rule,
            Some(reload_global_plugin),
        );
    }

    fn handle_ssls(&self, response: &GetResponse) {
        self.handle_list_resource(
            response,
            "ssls",
            &*SSL_MAP,
            |ssl| Ok(ProxySSL::from(ssl)),
            Some(reload_global_ssl_match),
        );
    }

    fn handle_resource<T, P, F>(
        &self,
        event: &Event,
        key_type: &str,
        map: &impl MapOperations<P>,
        create_proxy: F,
    ) where
        T: serde::de::DeserializeOwned + Clone + Identifiable,
        P: Identifiable + InnerComparable<T>,
        F: Fn(T) -> pingora_error::Result<P>,
    {
        static EVENT_RESULTS: once_cell::sync::Lazy<IntCounterVec> = once_cell::sync::Lazy::new(|| {
            register_int_counter_vec!(
                "pingsix_resource_event_results_total",
                "Results of resource event handling",
                &["type", "result"]
            )
            .unwrap()
        });

        let key = event.kv().unwrap().key();
        match parse_key(key) {
            Ok((id, parsed_key_type)) if parsed_key_type == key_type => {
                match json_to_resource::<T>(event.kv().unwrap().value()) {
                    Ok(resource) => {
                        log::info!("Handling {key_type}: {id}");
                        // retry-once strategy for transient failures
                        match create_proxy(resource.clone()) {
                            Ok(proxy) => {
                                map.insert_resource(Arc::new(proxy));
                                EVENT_RESULTS.with_label_values(&[key_type, "created"]).inc();
                            }
                            Err(e1) => {
                                log::warn!("Create proxy failed, retrying: {}", e1);
                                match create_proxy(resource) {
                                    Ok(proxy) => {
                                        map.insert_resource(Arc::new(proxy));
                                        EVENT_RESULTS.with_label_values(&[key_type, "created_retry"]).inc();
                                    }
                                    Err(e2) => {
                                        log::error!("Failed to create proxy for {key_type} {id}: {}", e2);
                                        EVENT_RESULTS.with_label_values(&[key_type, "failed"]).inc();
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to deserialize resource of type {key_type}: {e}");
                        EVENT_RESULTS.with_label_values(&[key_type, "invalid"]).inc();
                    }
                }
            }
            _ => {
                log::warn!(
                    "Failed to parse key or incorrect key type for {} event: {}",
                    key_type,
                    String::from_utf8_lossy(key)
                );
                EVENT_RESULTS.with_label_values(&[key_type, "ignored"]).inc();
            }
        }
    }

    fn handle_route_event(&self, event: &Event) {
        self.handle_resource(event, "routes", &*ROUTE_MAP, create_proxy_route);
        reload_global_route_match();
    }

    fn handle_upstream_event(&self, event: &Event) {
        self.handle_resource(event, "upstreams", &*UPSTREAM_MAP, create_proxy_upstream);
    }

    fn handle_service_event(&self, event: &Event) {
        self.handle_resource(event, "services", &*SERVICE_MAP, create_proxy_service);
    }

    fn handle_global_rule_event(&self, event: &Event) {
        self.handle_resource(
            event,
            "global_rules",
            &*GLOBAL_RULE_MAP,
            create_proxy_global_rule,
        );
        reload_global_plugin();
    }

    fn handle_ssl_event(&self, event: &Event) {
        self.handle_resource(event, "ssls", &*SSL_MAP, |ssl| Ok(ProxySSL::from(ssl)));
        reload_global_ssl_match();
    }
}

// ! When resource creation fails, it still just logs the error and skips.
// ! This may cause the gateway state to be inconsistent with etcd.
// ! For the creation failure of critical resources, more complex handling strategies may be required (for example, retry, mark as invalid, or stop the service if the failure has a large impact, etc.).
impl EtcdEventHandler for ProxyEventHandler {
    fn handle_event(&self, event: &Event) {
        if event.kv().is_none() {
            log::warn!("Event does not contain a key-value pair");
            return;
        }

        let key = String::from_utf8_lossy(event.kv().unwrap().key());
        match event.event_type() {
            etcd_client::EventType::Put => match parse_key(event.kv().unwrap().key()) {
                Ok((_, key_type)) => {
                    log::info!("Processing PUT event for key: {key}");
                    match key_type.as_str() {
                        "routes" => self.handle_route_event(event),
                        "upstreams" => self.handle_upstream_event(event),
                        "services" => self.handle_service_event(event),
                        "global_rules" => self.handle_global_rule_event(event),
                        "ssls" => self.handle_ssl_event(event),
                        _ => log::warn!("Unhandled PUT event for key type: {key_type}"),
                    }
                }
                Err(e) => log::error!("Failed to parse key during PUT event: {key}: {e}"),
            },
            etcd_client::EventType::Delete => match parse_key(event.kv().unwrap().key()) {
                Ok((id, key_type)) => {
                    log::info!("Processing DELETE event for {key_type}: {id}");
                    match key_type.as_str() {
                        "routes" => {
                            ROUTE_MAP.remove(&id);
                            reload_global_route_match();
                        }
                        "upstreams" => {
                            UPSTREAM_MAP.remove(&id);
                        }
                        "services" => {
                            SERVICE_MAP.remove(&id);
                        }
                        "global_rules" => {
                            GLOBAL_RULE_MAP.remove(&id);
                            reload_global_plugin();
                        }
                        "ssls" => {
                            SSL_MAP.remove(&id);
                            reload_global_ssl_match();
                        }
                        _ => log::warn!("Unhandled DELETE event for key type: {key_type}"),
                    }
                }
                Err(e) => log::error!("Failed to parse key during DELETE event: {key}: {e}"),
            },
        }
    }

    fn handle_list_response(&self, response: &GetResponse) {
        self.handle_ssls(response);
        self.handle_upstreams(response);
        self.handle_services(response);
        self.handle_global_rules(response);
        self.handle_routes(response);
    }
}

/// Parses etcd key in the format `/prefix/resource_type/id`.
fn parse_key(key: &[u8]) -> Result<(String, String), Box<dyn std::error::Error>> {
    let key = String::from_utf8(key.to_vec())?;
    let parts: Vec<&str> = key.split('/').collect();

    if parts.len() < 3 {
        return Err(format!("Invalid key format: {key}").into());
    }

    Ok((
        parts[parts.len() - 1].to_string(),
        parts[parts.len() - 2].to_string(),
    ))
}
