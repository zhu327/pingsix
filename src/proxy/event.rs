use std::sync::Arc;

use etcd_client::{Event, GetResponse};

use crate::config::{etcd::EtcdEventHandler, GlobalRule, Router, Service, Upstream};

use super::{
    global_rule::{global_rule_fetch, reload_global_plugin, ProxyGlobalRule, GLOBAL_RULE_MAP},
    router::{reload_global_match, router_fetch, ProxyRouter, ROUTER_MAP},
    service::{service_fetch, ProxyService, SERVICE_MAP},
    upstream::{upstream_fetch, ProxyUpstream, UPSTREAM_MAP},
    Identifiable, MapOperations,
};

pub struct ProxyEventHandler {
    work_stealing: bool,
}

impl ProxyEventHandler {
    pub fn new(work_stealing: bool) -> Self {
        ProxyEventHandler { work_stealing }
    }

    fn handle_routers(&self, response: &GetResponse) {
        let routers: Vec<Router> = response
            .kvs()
            .iter()
            .filter_map(|kv| match parse_key(kv.key()) {
                Ok((id, key_type)) if key_type == "routers" => {
                    match value_to_resource::<Router>(kv.value()) {
                        Ok(mut router) => {
                            router.id = id;
                            Some(router)
                        }
                        Err(_) => None,
                    }
                }
                _ => None,
            })
            .collect();

        let proxy_routers: Vec<Arc<ProxyRouter>> = routers
            .iter()
            .filter_map(|router| {
                // 尝试从缓存或其他地方获取现有的 ProxyRouter
                if let Some(proxy_router) = router_fetch(&router.id) {
                    if proxy_router.inner == *router {
                        return Some(proxy_router); // 如果已经有匹配的ProxyRouter则直接返回
                    }
                }

                log::info!("Configuring Router: {}", router.id);

                // 创建新的 ProxyRouter
                ProxyRouter::new_with_upstream_and_plugins(router.clone(), self.work_stealing)
                    .ok()
                    .map(Arc::new)
            })
            .collect();

        ROUTER_MAP.reload_resource(proxy_routers);
        reload_global_match();
    }

    fn handle_upstreams(&self, response: &GetResponse) {
        let upstream: Vec<Upstream> = response
            .kvs()
            .iter()
            .filter_map(|kv| match parse_key(kv.key()) {
                Ok((id, key_type)) if key_type == "upstreams" => {
                    match value_to_resource::<Upstream>(kv.value()) {
                        Ok(mut upstream) => {
                            upstream.id = id;
                            Some(upstream)
                        }
                        Err(_) => None,
                    }
                }
                _ => None,
            })
            .collect();

        let proxy_upstreams: Vec<Arc<ProxyUpstream>> = upstream
            .iter()
            .filter_map(|upstream| {
                // 尝试从缓存或其他地方获取现有的 ProxyRouter
                if let Some(proxy_upstream) = upstream_fetch(&upstream.id) {
                    if proxy_upstream.inner == *upstream {
                        return Some(proxy_upstream); // 如果已经有匹配的ProxyRouter则直接返回
                    }
                }

                log::info!("Configuring Upstream: {}", upstream.id);
                ProxyUpstream::new_with_health_check(upstream.clone(), self.work_stealing)
                    .ok()
                    .map(Arc::new)
            })
            .collect();

        UPSTREAM_MAP.reload_resource(proxy_upstreams);
    }

    fn handle_services(&self, response: &GetResponse) {
        let service: Vec<Service> = response
            .kvs()
            .iter()
            .filter_map(|kv| match parse_key(kv.key()) {
                Ok((id, key_type)) if key_type == "services" => {
                    match value_to_resource::<Service>(kv.value()) {
                        Ok(mut service) => {
                            service.id = id;
                            Some(service)
                        }
                        Err(_) => None,
                    }
                }
                _ => None,
            })
            .collect();

        let proxy_services: Vec<Arc<ProxyService>> = service
            .iter()
            .filter_map(|service| {
                // 尝试从缓存或其他地方获取现有的 ProxyRouter
                if let Some(proxy_service) = service_fetch(&service.id) {
                    if proxy_service.inner == *service {
                        return Some(proxy_service); // 如果已经有匹配的ProxyRouter则直接返回
                    }
                }

                log::info!("Configuring Service: {}", service.id);
                ProxyService::new_with_upstream_and_plugins(service.clone(), self.work_stealing)
                    .ok()
                    .map(Arc::new)
            })
            .collect();

        SERVICE_MAP.reload_resource(proxy_services);
    }

    fn handle_global_rules(&self, response: &GetResponse) {
        let global_rules: Vec<GlobalRule> = response
            .kvs()
            .iter()
            .filter_map(|kv| match parse_key(kv.key()) {
                Ok((id, key_type)) if key_type == "global_rules" => {
                    match value_to_resource::<GlobalRule>(kv.value()) {
                        Ok(mut rule) => {
                            rule.id = id;
                            Some(rule)
                        }
                        Err(_) => None,
                    }
                }
                _ => None,
            })
            .collect();

        let proxy_global_rules: Vec<Arc<ProxyGlobalRule>> = global_rules
            .iter()
            .filter_map(|rule| {
                // 尝试从缓存或其他地方获取现有的 ProxyRouter
                if let Some(proxy_global_rule) = global_rule_fetch(&rule.id) {
                    if proxy_global_rule.inner == *rule {
                        return Some(proxy_global_rule); // 如果已经有匹配的ProxyRouter则直接返回
                    }
                }

                log::info!("Configuring Global Rule: {}", rule.id);
                ProxyGlobalRule::new_with_plugins(rule.clone())
                    .ok()
                    .map(Arc::new)
            })
            .collect();

        GLOBAL_RULE_MAP.reload_resource(proxy_global_rules);
        reload_global_plugin();
    }

    // 通用的资源处理函数
    fn handle_resource<T, F>(&self, event: &Event, key_type: &str, handler: F)
    where
        T: serde::de::DeserializeOwned + Clone,
        F: Fn(&Self, String, &T),
    {
        let key = event.kv().unwrap().key();
        match parse_key(key) {
            Ok((id, parsed_key_type)) if parsed_key_type == key_type => {
                match value_to_resource::<T>(event.kv().unwrap().value()) {
                    Ok(resource) => {
                        log::info!("Handling {}: {}", key_type, id);
                        handler(self, id, &resource);
                    }
                    Err(e) => {
                        log::error!("Failed to deserialize resource of type {}: {}", key_type, e);
                    }
                }
            }
            _ => {
                log::warn!(
                    "Failed to parse key or incorrect key type for {} event",
                    key_type
                );
            }
        }
    }

    fn handle_router_event(&self, event: &Event) {
        self.handle_resource::<Router, _>(event, "routers", |handler, id, router| {
            if let Ok(mut proxy_router) =
                ProxyRouter::new_with_upstream_and_plugins(router.clone(), handler.work_stealing)
            {
                proxy_router.set_id(id);
                ROUTER_MAP.insert(Arc::new(proxy_router));
                reload_global_match();
            }
        });
    }

    fn handle_upstream_event(&self, event: &Event) {
        self.handle_resource::<Upstream, _>(event, "upstreams", |handler, id, upstream| {
            if let Ok(mut proxy_upstream) =
                ProxyUpstream::new_with_health_check(upstream.clone(), handler.work_stealing)
            {
                proxy_upstream.set_id(id);
                UPSTREAM_MAP.insert(Arc::new(proxy_upstream));
            }
        });
    }

    fn handle_service_event(&self, event: &Event) {
        self.handle_resource::<Service, _>(event, "services", |handler, id, service| {
            if let Ok(mut proxy_service) =
                ProxyService::new_with_upstream_and_plugins(service.clone(), handler.work_stealing)
            {
                proxy_service.set_id(id);
                SERVICE_MAP.insert(Arc::new(proxy_service));
            }
        });
    }

    fn handle_global_rule_event(&self, event: &Event) {
        self.handle_resource::<GlobalRule, _>(event, "global_rules", |_handler, id, rule| {
            if let Ok(mut proxy_global_rule) = ProxyGlobalRule::new_with_plugins(rule.clone()) {
                proxy_global_rule.set_id(id);
                GLOBAL_RULE_MAP.insert(Arc::new(proxy_global_rule));
                reload_global_plugin();
            }
        });
    }
}

impl EtcdEventHandler for ProxyEventHandler {
    fn handle_event(&self, event: &Event) {
        if event.kv().is_none() {
            log::warn!("Event does not contain a key-value pair");
            return;
        }

        match event.event_type() {
            // A PUT event indicates that a key-value pair was added or updated
            etcd_client::EventType::Put => match parse_key(event.kv().unwrap().key()) {
                Ok((_, key_type)) => match key_type.as_str() {
                    "routers" => {
                        self.handle_router_event(event);
                    }
                    "upstreams" => {
                        self.handle_upstream_event(event);
                    }
                    "services" => {
                        self.handle_service_event(event);
                    }
                    "global_rules" => {
                        self.handle_global_rule_event(event);
                    }
                    _ => {
                        log::warn!("Unhandled PUT event for key type: {}", key_type);
                    }
                },
                Err(e) => {
                    log::error!("Failed to parse key during PUT event: {}", e);
                }
            },
            // A DELETE event indicates that a key-value pair was removed
            etcd_client::EventType::Delete => {
                // Parse the key to determine its type
                match parse_key(event.kv().unwrap().key()) {
                    Ok((id, key_type)) => {
                        match key_type.as_str() {
                            "routers" => {
                                log::info!("DELETE Router: {}", id);
                                // Handle the removal of a router
                                ROUTER_MAP.remove(&id);
                                reload_global_match();
                            }
                            "upstreams" => {
                                log::info!("DELETE Upstream: {}", id);
                                // Handle the removal of an upstream
                                UPSTREAM_MAP.remove(&id);
                            }
                            "services" => {
                                log::info!("DELETE Service: {}", id);
                                // Handle the removal of a service
                                SERVICE_MAP.remove(&id);
                            }
                            "global_rules" => {
                                log::info!("DELETE Global Rule: {}", id);
                                // Handle the removal of a global rule
                                GLOBAL_RULE_MAP.remove(&id);
                                reload_global_plugin();
                            }
                            _ => {
                                log::warn!("Unhandled DELETE event for key type: {}", key_type);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to parse key during DELETE event: {}", e);
                    }
                }
            }
        }
    }

    fn handle_list_response(&self, response: &GetResponse) {
        self.handle_upstreams(response);
        self.handle_services(response);
        self.handle_routers(response);
        self.handle_global_rules(response);
    }
}

fn value_to_resource<T>(value: &[u8]) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned,
{
    // Deserialize the input value from JSON
    let json_value: serde_json::Value = serde_json::from_slice(value)?;

    // Serialize the JSON value to YAML directly into a Vec<u8>
    let mut yaml_output = Vec::new();
    let mut serializer = serde_yaml::Serializer::new(&mut yaml_output);
    serde_transcode::transcode(json_value, &mut serializer)?;

    // Deserialize directly from the YAML bytes
    let resource: T = serde_yaml::from_slice(&yaml_output)?;

    Ok(resource)
}

fn parse_key(key: &[u8]) -> Result<(String, String), Box<dyn std::error::Error>> {
    let key = String::from_utf8(key.to_vec())?;
    let parts: Vec<&str> = key.split('/').collect();

    if parts.len() < 2 {
        return Err("invalid key".into());
    }

    Ok((
        parts[parts.len() - 1].to_string(),
        parts[parts.len() - 2].to_string(),
    ))
}
