use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use matchit::{InsertError, Router as MatchRouter};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Result;
use pingora_proxy::Session;

use crate::{
    config::{self, Identifiable},
    core::{
        sort_plugins_by_priority_desc, ErrorContext, ProxyError, ProxyPlugin, ProxyPluginExecutor,
        ProxyResult, RouteContext, UpstreamSelector,
    },
    plugins::build_plugin_with_upstreams,
    utils::request::get_request_host,
};

use super::{service::ProxyService, upstream::ProxyUpstream};

fn build_plugin_name_index(plugins: &[Arc<dyn ProxyPlugin>]) -> Vec<String> {
    let mut names: Vec<String> = plugins.iter().map(|p| p.name().to_string()).collect();
    names.sort();
    names.dedup();
    names
}

fn route_overrides_plugin(route_plugin_names: &[String], plugin_name: &str) -> bool {
    // route_plugin_names is sorted
    route_plugin_names
        .binary_search_by(|n| n.as_str().cmp(plugin_name))
        .is_ok()
}

/// Merge two already-sorted plugin lists (priority desc) into a single list.
///
/// - Maintains global priority ordering (descending).
/// - When a plugin name exists in route, service plugin with same name is skipped.
/// - On equal priority, prefers route plugins for deterministic results.
fn merge_route_and_service_plugins(
    route_plugins: &[Arc<dyn ProxyPlugin>],
    service_plugins: &[Arc<dyn ProxyPlugin>],
    route_plugin_names: &[String],
) -> Vec<Arc<dyn ProxyPlugin>> {
    let mut merged = Vec::with_capacity(route_plugins.len() + service_plugins.len());

    let mut i = 0usize;
    let mut j = 0usize;

    while i < route_plugins.len() || j < service_plugins.len() {
        let take_route = match (route_plugins.get(i), service_plugins.get(j)) {
            (Some(rp), Some(sp)) => {
                let rp_prio = rp.priority();
                let sp_prio = sp.priority();
                if rp_prio > sp_prio {
                    true
                } else if rp_prio < sp_prio {
                    false
                } else {
                    // Same priority: prefer route side
                    true
                }
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };

        if take_route {
            merged.push(route_plugins[i].clone());
            i += 1;
            continue;
        }

        // Take service plugin (unless overridden by route)
        let sp = service_plugins[j].clone();
        j += 1;
        if route_overrides_plugin(route_plugin_names, sp.name()) {
            continue;
        }
        merged.push(sp);
    }

    merged
}

/// Type alias for route match result: (params, route)
type RouteMatchResult = Option<(Vec<(String, String)>, Arc<ProxyRoute>)>;

/// Proxy route with all service and upstream dependencies bound at build time.
pub struct ProxyRoute {
    pub inner: config::Route,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
    resolved_upstream: Option<Arc<dyn UpstreamSelector>>,
    effective_hosts: Vec<String>,
    plugin_executor: Arc<ProxyPluginExecutor>,
    pub inline_upstream: Option<Arc<ProxyUpstream>>,
}

impl Identifiable for ProxyRoute {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyRoute {
    pub(crate) fn build(
        route: config::Route,
        upstreams: &HashMap<String, Arc<ProxyUpstream>>,
        services: &HashMap<String, Arc<ProxyService>>,
    ) -> ProxyResult<Self> {
        let service = route
            .service_id
            .as_deref()
            .map(|id| {
                services.get(id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Route '{}' references missing service '{}'",
                        route.id, id
                    ))
                })
            })
            .transpose()?;

        let inline_upstream = if let Some(upstream_config) = route.upstream.clone() {
            Some(Arc::new(
                ProxyUpstream::build(upstream_config).with_context(&format!(
                    "Failed to create upstream for route '{}'",
                    route.id
                ))?,
            ))
        } else {
            None
        };
        let resolved_upstream = if let Some(proxy_upstream) = &inline_upstream {
            Some(proxy_upstream.clone() as Arc<dyn UpstreamSelector>)
        } else if let Some(id) = route.upstream_id.as_deref() {
            Some(upstreams.get(id).cloned().ok_or_else(|| {
                ProxyError::Configuration(format!(
                    "Route '{}' references missing upstream '{}'",
                    route.id, id
                ))
            })? as Arc<dyn UpstreamSelector>)
        } else {
            service.as_ref().and_then(|s| s.resolve_upstream())
        };

        let effective_hosts = if !route.get_hosts().is_empty() {
            route.get_hosts().into_iter().map(str::to_string).collect()
        } else {
            service
                .as_ref()
                .map(|s| s.inner.hosts.clone())
                .unwrap_or_default()
        };

        let mut plugins = Vec::with_capacity(route.plugins.len());
        for (name, value) in route.plugins.clone() {
            let plugin = build_plugin_with_upstreams(&name, value, upstreams)
                .map_err(|e| ProxyError::Plugin(format!("Failed to build plugin '{name}': {e}")))?;
            plugins.push(plugin);
        }
        sort_plugins_by_priority_desc(plugins.as_mut_slice());

        let plugin_names = build_plugin_name_index(&plugins);
        let merged_plugins = if let Some(service) = &service {
            merge_route_and_service_plugins(&plugins, &service.plugins, &plugin_names)
        } else {
            plugins.clone()
        };
        let plugin_executor = if merged_plugins.is_empty() {
            ProxyPluginExecutor::default_shared()
        } else {
            Arc::new(ProxyPluginExecutor::new(merged_plugins))
        };

        Ok(Self {
            inner: route,
            plugins,
            resolved_upstream,
            effective_hosts,
            plugin_executor,
            inline_upstream,
        })
    }

    fn get_hosts(&self) -> Vec<&str> {
        self.effective_hosts.iter().map(String::as_str).collect()
    }
}

impl RouteContext for ProxyRoute {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn service_id(&self) -> Option<&str> {
        self.inner.service_id.as_deref()
    }

    fn uri_template(&self) -> Option<&str> {
        // A route with multiple URIs does not retain which alternative matched;
        // use runtime normalization for those to avoid assigning the wrong label.
        self.inner.uri.as_deref()
    }

    fn select_http_peer(&self, session: &mut Session) -> ProxyResult<Box<HttpPeer>> {
        let upstream = self.resolve_upstream().ok_or_else(|| {
            ProxyError::UpstreamSelection(
                "Failed to retrieve upstream configuration for route".to_string(),
            )
        })?;

        let mut backend = upstream.select_backend(session).ok_or_else(|| {
            ProxyError::UpstreamSelection(format!(
                "No healthy backend available for route '{}'",
                self.inner.id
            ))
        })?;

        let peer = backend.ext.get_mut::<HttpPeer>().ok_or_else(|| {
            ProxyError::UpstreamSelection(
                "Missing selected backend metadata for HttpPeer".to_string(),
            )
        })?;

        self.set_timeout(peer);
        Ok(Box::new(peer.clone()))
    }

    fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor> {
        self.plugin_executor.clone()
    }

    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>> {
        self.resolved_upstream.clone()
    }
}

impl ProxyRoute {
    /// Sets the timeout for an `HttpPeer` based on the route configuration.
    fn set_timeout(&self, p: &mut HttpPeer) {
        if let Some(config::Timeout {
            connect,
            read,
            send,
        }) = self.inner.timeout
        {
            p.options.connection_timeout = Some(Duration::from_secs(connect));
            p.options.read_timeout = Some(Duration::from_secs(read));
            p.options.write_timeout = Some(Duration::from_secs(send));
        }
    }
}

#[derive(Default)]
pub struct MatchEntry {
    /// Router for non-host URI matching
    non_host_uri: MatchRouter<Vec<Arc<ProxyRoute>>>,
    /// Router for host URI matching
    host_uris: MatchRouter<MatchRouter<Vec<Arc<ProxyRoute>>>>,
}

impl MatchEntry {
    pub(crate) fn build(
        routes: &std::collections::HashMap<String, Arc<ProxyRoute>>,
    ) -> ProxyResult<Self> {
        let mut matcher = Self::default();
        for route in routes.values() {
            matcher.insert_route(route.clone()).map_err(|e| {
                ProxyError::Configuration(format!(
                    "Failed to build route matcher for '{}': {e}",
                    route.inner.id
                ))
            })?;
        }
        Ok(matcher)
    }

    /// Converts host to reversed matchit-compatible pattern.
    /// Wildcard "*.example.com" becomes "moc.elpmaxe.{*subdomain}".
    /// Exact "api.example.com" becomes "moc.elpmaxe.ipa".
    fn reverse_ascii_lowercase(input: &str) -> String {
        let mut reversed = String::with_capacity(input.len());
        for ch in input.chars().rev() {
            reversed.push(ch.to_ascii_lowercase());
        }
        reversed
    }

    fn reverse_host(host: &str) -> String {
        if let Some(domain_part) = host.strip_prefix("*") {
            let reversed_domain = Self::reverse_ascii_lowercase(domain_part);
            format!("{reversed_domain}{{*subdomain}}")
        } else {
            Self::reverse_ascii_lowercase(host)
        }
    }

    fn insert_into_router(
        router: &mut MatchRouter<Vec<Arc<ProxyRoute>>>,
        uri: &str,
        proxy_route: Arc<ProxyRoute>,
    ) -> Result<(), InsertError> {
        match router.at_mut(uri) {
            Ok(routes) => {
                routes.value.push(proxy_route);
                // Sort routes by priority (higher priority values take precedence)
                routes
                    .value
                    .sort_by_key(|b| std::cmp::Reverse(b.inner.priority));
            }
            Err(_) => {
                router.insert(uri, vec![proxy_route])?;
            }
        }
        Ok(())
    }

    /// Inserts a route into the match entry.
    pub fn insert_route(&mut self, proxy_route: Arc<ProxyRoute>) -> Result<(), InsertError> {
        let route_hosts = proxy_route.get_hosts();
        let uris = proxy_route.inner.get_uris();

        let has_hosts = if !route_hosts.is_empty() {
            self.insert_host_uris(route_hosts.iter().copied(), &uris, &proxy_route)?;
            true
        } else {
            false
        };

        if !has_hosts {
            for uri in &uris {
                Self::insert_into_router(&mut self.non_host_uri, uri, proxy_route.clone())?;
            }
        }

        Ok(())
    }

    fn insert_host_uris<'a>(
        &mut self,
        hosts: impl Iterator<Item = &'a str>,
        uris: &[&str],
        proxy_route: &Arc<ProxyRoute>,
    ) -> Result<(), InsertError> {
        for host in hosts {
            let processed_host = Self::reverse_host(host);
            let inner_router = self.host_uris.at_mut(processed_host.as_str());

            let inner_router = match inner_router {
                Ok(router) => router.value,
                Err(_) => {
                    let new_router = MatchRouter::new();
                    self.host_uris.insert(processed_host.clone(), new_router)?;
                    self.host_uris
                        .at_mut(processed_host.as_str())
                        .unwrap()
                        .value
                }
            };

            for uri in uris {
                Self::insert_into_router(inner_router, uri, proxy_route.clone())?;
            }
        }
        Ok(())
    }

    /// Matches a request to a route.
    pub(crate) fn match_request(&self, session: &mut Session) -> RouteMatchResult {
        let host = get_request_host(session.req_header());
        let uri = session.req_header().uri.path();
        let method = session.req_header().method.as_str();

        log::debug!("match request: host={host:?}, uri={uri:?}, method={method:?}");

        // Attempt to match using host_uris if a valid host is provided
        if let Some(host_str) = host.filter(|h| !h.is_empty()) {
            // Just reverse the host and let matchit handle the matching
            // matchit will automatically match "moc.elpmaxe.ipa" against "moc.elpmaxe.{*subdomain}"
            let reversed_host = Self::reverse_ascii_lowercase(host_str);
            if let Ok(v) = self.host_uris.at(&reversed_host) {
                if let Some(result) = Self::match_uri_method(v.value, uri, method) {
                    return Some(result);
                }
            }
        }

        // Fall back to non-host URI matching
        Self::match_uri_method(&self.non_host_uri, uri, method)
    }

    /// Matches a URI to a route.
    fn match_uri_method(
        match_router: &MatchRouter<Vec<Arc<ProxyRoute>>>,
        uri: &str,
        method: &str,
    ) -> RouteMatchResult {
        if let Ok(v) = match_router.at(uri) {
            let route = v.value.iter().find(|route| {
                route.inner.methods.is_empty()
                    || route
                        .inner
                        .methods
                        .iter()
                        .any(|configured| *configured == method)
            })?;

            let params = (!v.params.is_empty()).then(|| {
                v.params
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect()
            });
            return Some((params.unwrap_or_default(), route.clone()));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::Value as JsonValue;
    use std::collections::HashMap;

    #[test]
    fn test_wildcard_host_processing() {
        // Test wildcard host conversion
        assert_eq!(
            MatchEntry::reverse_host("*.example.com"),
            "moc.elpmaxe.{*subdomain}"
        );

        // Test exact host conversion
        assert_eq!(
            MatchEntry::reverse_host("api.example.com"),
            "moc.elpmaxe.ipa"
        );

        // Test subdomain extraction logic for matching
        let test_host = "api.example.com";
        if let Some(dot_pos) = test_host.find('.') {
            let domain_part = &test_host[dot_pos + 1..];
            let reversed_domain: String = domain_part.chars().rev().collect();
            let wildcard_pattern = format!("{reversed_domain}.{{*subdomain}}");

            assert_eq!(domain_part, "example.com");
            assert_eq!(reversed_domain, "moc.elpmaxe");
            assert_eq!(wildcard_pattern, "moc.elpmaxe.{*subdomain}");
        }

        // Test complex subdomain cases
        assert_eq!(
            MatchEntry::reverse_host("*.api.example.com"),
            "moc.elpmaxe.ipa.{*subdomain}"
        );

        // Test single level domain
        assert_eq!(MatchEntry::reverse_host("*.com"), "moc.{*subdomain}");
    }

    #[test]
    fn test_host_matching_patterns() {
        // Test that incoming hosts are simply reversed for matching
        let incoming_host = "api.example.com";
        let reversed_host: String = incoming_host.to_ascii_lowercase().chars().rev().collect();
        assert_eq!(reversed_host, "moc.elpmaxe.ipa");

        // Wildcard pattern "*.example.com" becomes "moc.elpmaxe.{*subdomain}"
        let wildcard_pattern = MatchEntry::reverse_host("*.example.com");
        assert_eq!(wildcard_pattern, "moc.elpmaxe.{*subdomain}");

        // matchit should be able to match "moc.elpmaxe.ipa" against "moc.elpmaxe.{*subdomain}"
        // This test just verifies our pattern generation is correct
    }

    #[test]
    fn test_host_reversal_preserves_utf8_characters() {
        let host = "例子.测试";
        let reversed = host.to_ascii_lowercase().chars().rev().collect::<String>();
        assert_eq!(reversed, MatchEntry::reverse_host(host));
    }

    #[test]
    fn test_matchit_wildcard_matching() {
        // Test that matchit can actually match our patterns
        use matchit::Router as MatchRouter;

        let mut router = MatchRouter::new();

        // Insert a wildcard pattern (simulating *.example.com)
        router
            .insert("moc.elpmaxe.{*subdomain}", "wildcard_route")
            .unwrap();

        // Insert an exact pattern
        router.insert("moc.elpmaxe.ipa", "exact_route").unwrap();

        // Test exact match takes priority
        let result = router.at("moc.elpmaxe.ipa").unwrap();
        assert_eq!(result.value, &"exact_route");

        // Test wildcard matching
        let result = router.at("moc.elpmaxe.ipa.bus").unwrap(); // sub.api.example.com
        assert_eq!(result.value, &"wildcard_route");
        assert_eq!(result.params.get("subdomain"), Some("ipa.bus"));

        let result = router.at("moc.elpmaxe.v1").unwrap(); // v1.example.com
        assert_eq!(result.value, &"wildcard_route");
        assert_eq!(result.params.get("subdomain"), Some("v1"));
    }

    #[derive(Debug)]
    struct DummyPlugin {
        name: &'static str,
        priority: i32,
    }

    #[async_trait]
    impl ProxyPlugin for DummyPlugin {
        fn name(&self) -> &str {
            self.name
        }

        fn priority(&self) -> i32 {
            self.priority
        }
    }

    #[test]
    fn test_merge_route_service_plugins_preserves_priority_order() {
        let route_plugins: Vec<Arc<dyn ProxyPlugin>> = vec![
            Arc::new(DummyPlugin {
                name: "route_mid",
                priority: 50,
            }),
            Arc::new(DummyPlugin {
                name: "route_low",
                priority: 10,
            }),
        ];
        let service_plugins: Vec<Arc<dyn ProxyPlugin>> = vec![
            Arc::new(DummyPlugin {
                name: "service_high",
                priority: 100,
            }),
            Arc::new(DummyPlugin {
                name: "service_lowmid",
                priority: 20,
            }),
        ];

        let route_names = build_plugin_name_index(&route_plugins);
        let merged =
            merge_route_and_service_plugins(&route_plugins, &service_plugins, &route_names);

        let merged_names: Vec<&str> = merged.iter().map(|p| p.name()).collect();
        assert_eq!(
            merged_names,
            vec!["service_high", "route_mid", "service_lowmid", "route_low"]
        );
    }

    #[test]
    fn test_merge_route_overrides_service_same_name() {
        let route_dup: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "dup",
            priority: 10,
        });
        let service_dup: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "dup",
            priority: 10,
        });
        let service_other: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "other",
            priority: 5,
        });

        let route_plugins = vec![route_dup.clone()];
        let service_plugins = vec![service_dup, service_other.clone()];

        let route_names = build_plugin_name_index(&route_plugins);
        let merged =
            merge_route_and_service_plugins(&route_plugins, &service_plugins, &route_names);

        assert_eq!(merged.len(), 2);
        assert!(Arc::ptr_eq(&merged[0], &route_dup)); // route wins
        assert!(Arc::ptr_eq(&merged[1], &service_other));
    }

    #[test]
    fn test_route_without_service_and_without_plugins_reuses_shared_executor() {
        let route_cfg = config::Route {
            id: "r1".to_string(),
            uri: Some("/".to_string()),
            uris: vec![],
            methods: vec![],
            host: None,
            hosts: vec![],
            priority: 0,
            plugins: HashMap::<String, JsonValue>::new(),
            upstream: None,
            upstream_id: None,
            service_id: None,
            timeout: None,
        };

        let upstreams = HashMap::new();
        let services = HashMap::new();
        let proxy_route = ProxyRoute::build(route_cfg, &upstreams, &services).unwrap();
        let exec = proxy_route.build_plugin_executor();
        assert!(Arc::ptr_eq(&exec, &ProxyPluginExecutor::default_shared()));
    }
}
