use std::sync::Arc;

use etcd_client::{Event, GetResponse};

use crate::config::{etcd::EtcdSyncHandler, GlobalRule, Router, Service, Upstream};

use super::{
    global_rule::{global_rule_fetch, reload_global_plugin, ProxyGlobalRule, GLOBAL_RULE_MAP},
    plugin::build_plugin,
    router::{reload_global_match, router_fetch, ProxyRouter, ROUTER_MAP},
    service::{service_fetch, ProxyService, SERVICE_MAP},
    upstream::{upstream_fetch, ProxyUpstream, UPSTREAM_MAP},
    MapOperations,
};

pub struct ProxySyncHandler {
    work_stealing: bool,
}

impl ProxySyncHandler {
    pub fn new(work_stealing: bool) -> Self {
        ProxySyncHandler { work_stealing }
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
                let mut proxy_router = ProxyRouter::from(router.clone());

                // 配置上游 (upstream)
                if let Some(upstream) = router.upstream.clone() {
                    let mut proxy_upstream = match ProxyUpstream::try_from(upstream) {
                        Ok(proxy_upstream) => proxy_upstream,
                        Err(_) => return None,
                    };
                    proxy_upstream.start_health_check(self.work_stealing);

                    proxy_router.upstream = Some(Arc::new(proxy_upstream));
                }

                // 配置路由插件
                for (name, value) in router.plugins.iter() {
                    if let Ok(plugin) = build_plugin(name, value.clone()) {
                        proxy_router.plugins.push(plugin);
                    }
                }

                Some(Arc::new(proxy_router))
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

                let mut proxy_upstream = match ProxyUpstream::try_from(upstream.clone()) {
                    Ok(proxy_upstream) => proxy_upstream,
                    Err(_) => return None,
                };
                proxy_upstream.start_health_check(self.work_stealing);

                Some(Arc::new(proxy_upstream))
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

                let mut proxy_service = ProxyService::from(service.clone());

                // 配置上游 (upstream)
                if let Some(upstream) = service.upstream.clone() {
                    let mut proxy_upstream = match ProxyUpstream::try_from(upstream) {
                        Ok(proxy_upstream) => proxy_upstream,
                        Err(_) => return None,
                    };
                    proxy_upstream.start_health_check(self.work_stealing);

                    proxy_service.upstream = Some(Arc::new(proxy_upstream));
                }

                // 配置路由插件
                for (name, value) in service.plugins.iter() {
                    if let Ok(plugin) = build_plugin(name, value.clone()) {
                        proxy_service.plugins.push(plugin);
                    }
                }

                Some(Arc::new(proxy_service))
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
            .map(|rule| {
                // 尝试从缓存或其他地方获取现有的 ProxyRouter
                if let Some(proxy_global_rule) = global_rule_fetch(&rule.id) {
                    if proxy_global_rule.inner == *rule {
                        return proxy_global_rule; // 如果已经有匹配的ProxyRouter则直接返回
                    }
                }

                log::info!("Configuring Global Rule: {}", rule.id);

                let mut proxy_global_rule = ProxyGlobalRule::from(rule.clone());

                // load service plugins
                for (name, value) in rule.plugins.iter() {
                    if let Ok(plugin) = build_plugin(name, value.clone()) {
                        proxy_global_rule.plugins.push(plugin);
                    }
                }

                Arc::new(proxy_global_rule)
            })
            .collect();

        GLOBAL_RULE_MAP.reload_resource(proxy_global_rules);
        reload_global_plugin();
    }

    // 通用的资源处理函数
    fn handle_resource<T, F>(&self, event: &Event, key_type: &str, handler: F)
    where
        T: serde::de::DeserializeOwned + Clone,
        F: Fn(&Self, &T),
    {
        let key = event.kv().unwrap().key();
        match parse_key(key) {
            Ok((id, parsed_key_type)) if parsed_key_type == key_type => {
                if let Ok(resource) = value_to_resource::<T>(event.kv().unwrap().value()) {
                    log::info!("Handling {}: {}", key_type, id);
                    handler(self, &resource);
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
        self.handle_resource::<Router, _>(event, "routers", |handler, router| {
            // 处理路由器的逻辑
            let mut proxy_router = ProxyRouter::from(router.clone());

            if let Some(upstream) = router.upstream.clone() {
                let proxy_upstream = ProxyUpstream::try_from(upstream).ok();
                if let Some(mut proxy_upstream) = proxy_upstream {
                    proxy_upstream.start_health_check(handler.work_stealing);
                    proxy_router.upstream = Some(Arc::new(proxy_upstream));
                }
            }

            for (name, value) in router.plugins.iter() {
                if let Ok(plugin) = build_plugin(name, value.clone()) {
                    proxy_router.plugins.push(plugin);
                }
            }

            // 更新路由器的映射
            let proxy_router = Arc::new(proxy_router);
            ROUTER_MAP.insert(proxy_router);
            reload_global_match();
        });
    }

    fn handle_upstream_event(&self, event: &Event) {
        self.handle_resource::<Upstream, _>(event, "upstreams", |handler, upstream| {
            // 处理上游的逻辑
            let proxy_upstream = ProxyUpstream::try_from(upstream.clone()).ok();
            if let Some(mut proxy_upstream) = proxy_upstream {
                proxy_upstream.start_health_check(handler.work_stealing);

                let proxy_upstream = Arc::new(proxy_upstream);
                UPSTREAM_MAP.insert(proxy_upstream);
            }
        });
    }

    fn handle_service_event(&self, event: &Event) {
        self.handle_resource::<Service, _>(event, "services", |handler, service| {
            // 处理服务的逻辑
            let mut proxy_service = ProxyService::from(service.clone());

            if let Some(upstream) = service.upstream.clone() {
                let proxy_upstream = ProxyUpstream::try_from(upstream).ok();
                if let Some(mut proxy_upstream) = proxy_upstream {
                    proxy_upstream.start_health_check(handler.work_stealing);

                    proxy_service.upstream = Some(Arc::new(proxy_upstream));
                }
            }

            for (name, value) in service.plugins.iter() {
                if let Ok(plugin) = build_plugin(name, value.clone()) {
                    proxy_service.plugins.push(plugin);
                }
            }

            // 更新服务的映射
            let proxy_service = Arc::new(proxy_service);
            SERVICE_MAP.insert(proxy_service);
        });
    }

    fn handle_global_rule_event(&self, event: &Event) {
        self.handle_resource::<GlobalRule, _>(event, "global_rules", |_handler, rule| {
            // 处理全局规则的逻辑
            let mut proxy_global_rule = ProxyGlobalRule::from(rule.clone());

            for (name, value) in rule.plugins.iter() {
                if let Ok(plugin) = build_plugin(name, value.clone()) {
                    proxy_global_rule.plugins.push(plugin);
                }
            }

            // 更新全局规则的映射
            let proxy_global_rule = Arc::new(proxy_global_rule);
            GLOBAL_RULE_MAP.insert(proxy_global_rule);
            reload_global_plugin();
        });
    }
}

impl EtcdSyncHandler for ProxySyncHandler {
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
