pub mod discovery;
pub mod global_rule;
pub mod plugin;
pub mod router;
pub mod service;
pub mod sync;
pub mod upstream;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Instant,
};

use pingora_http::RequestHeader;
use pingora_proxy::Session;

use plugin::ProxyPluginExecutor;
use router::ProxyRouter;

use crate::config;

/// Proxy context.
///
/// Holds the context for each request.
pub struct ProxyContext {
    pub router: Option<Arc<ProxyRouter>>,
    pub router_params: Option<BTreeMap<String, String>>,

    pub tries: usize,
    pub request_start: Instant,

    pub plugin: Arc<ProxyPluginExecutor>,

    // Share custom vars between plugins
    #[allow(dead_code)]
    pub vars: HashMap<String, String>,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            router: None,
            router_params: None,
            tries: 0,
            request_start: Instant::now(),
            plugin: Arc::new(ProxyPluginExecutor::default()),
            vars: HashMap::new(),
        }
    }
}

/// Build request selector key.
pub fn request_selector_key(
    session: &mut Session,
    hash_on: &config::UpstreamHashOn,
    key: &str,
) -> String {
    match hash_on {
        config::UpstreamHashOn::VARS => handle_vars(session, key),
        config::UpstreamHashOn::HEAD => get_req_header_value(session.req_header(), key)
            .unwrap_or_default()
            .to_string(),
        config::UpstreamHashOn::COOKIE => get_cookie_value(session.req_header(), key)
            .unwrap_or_default()
            .to_string(),
    }
}

/// Handles variable-based request selection.
fn handle_vars(session: &mut Session, key: &str) -> String {
    if key.starts_with("arg_") {
        if let Some(name) = key.strip_prefix("arg_") {
            return get_query_value(session.req_header(), name)
                .unwrap_or_default()
                .to_string();
        }
    }

    match key {
        "uri" => session.req_header().uri.path().to_string(),
        "request_uri" => session
            .req_header()
            .uri
            .path_and_query()
            .map_or_else(|| "".to_string(), |pq| pq.to_string()),
        "query_string" => session
            .req_header()
            .uri
            .query()
            .unwrap_or_default()
            .to_string(),
        "remote_addr" => session
            .client_addr()
            .map_or_else(|| "".to_string(), |addr| addr.to_string()),
        "remote_port" => session
            .client_addr()
            .and_then(|s| s.as_inet())
            .map_or_else(|| "".to_string(), |i| i.port().to_string()),
        "server_addr" => session
            .server_addr()
            .map_or_else(|| "".to_string(), |addr| addr.to_string()),
        _ => "".to_string(),
    }
}

fn get_query_value<'a>(req_header: &'a RequestHeader, name: &str) -> Option<&'a str> {
    if let Some(query) = req_header.uri.query() {
        for item in query.split('&') {
            if let Some((k, v)) = item.split_once('=') {
                if k == name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

fn get_req_header_value<'a>(req_header: &'a RequestHeader, key: &str) -> Option<&'a str> {
    if let Some(value) = req_header.headers.get(key) {
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

fn get_cookie_value<'a>(req_header: &'a RequestHeader, cookie_name: &str) -> Option<&'a str> {
    if let Some(cookie_value) = get_req_header_value(req_header, "Cookie") {
        for item in cookie_value.split(';') {
            if let Some((k, v)) = item.split_once('=') {
                if k == cookie_name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

/// Retrieves the request host from the request header.
pub fn get_request_host(header: &RequestHeader) -> Option<&str> {
    if let Some(host) = header.uri.host() {
        return Some(host);
    }
    if let Some(host) = header.headers.get(http::header::HOST) {
        if let Ok(value) = host.to_str().map(|host| host.split(':').next()) {
            return value;
        }
    }
    None
}

pub trait Identifiable {
    fn id(&self) -> String;
    fn set_id(&mut self, id: String);
}

pub trait MapOperations<T> {
    fn reload_resource(&self, resources: Vec<Arc<T>>);

    fn remove(&self, id: &str);
    fn insert(&self, resource: Arc<T>);
    fn get(&self, id: &str) -> Option<Arc<T>>;
}

impl<T> MapOperations<T> for RwLock<HashMap<String, Arc<T>>>
where
    T: Identifiable,
{
    // reload_resource：根据新的资源更新 map，删除不在 resources 中的条目
    fn reload_resource(&self, resources: Vec<Arc<T>>) {
        let mut map = self.write().unwrap();

        // 先从 resources 中提取所有 id
        let resource_ids: HashSet<String> = resources.iter().map(|r| r.id()).collect();

        // 删除那些不在资源中的条目
        map.retain(|key, _| resource_ids.contains(key));

        // 用新的资源更新 map
        for resource in resources {
            let key = resource.id();
            map.insert(key, resource);
        }
    }

    // remove：根据 id 从 map 中删除条目
    fn remove(&self, id: &str) {
        let mut map = self.write().unwrap();
        map.remove(id);
    }

    // insert：插入新的资源
    fn insert(&self, resource: Arc<T>) {
        let mut map = self.write().unwrap();
        let key = resource.id();
        map.insert(key, resource);
    }

    // get：根据 id 从 map 中获取资源
    fn get(&self, id: &str) -> Option<Arc<T>> {
        let map = self.read().unwrap();
        map.get(id).cloned()
    }
}
