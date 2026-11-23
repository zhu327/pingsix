use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use matchit::Router as MatchRouter;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;

use crate::{
    config::{self, Identifiable},
    core::{
        sort_plugins_by_priority_desc, ErrorContext, PluginEntry, ProxyError, ProxyPluginExecutor,
        ProxyResult, RouteContext, RouteLabels, UpstreamSelection, UpstreamSelector,
    },
    plugins::{build_plugin_with_upstreams, cors},
    utils::request::get_request_host,
};

use super::{
    service::ProxyService,
    upstream::{PreparedUpstreams, ProxyUpstream, TrafficSplitOwner, UpstreamOccurrence},
};

fn build_plugin_name_index(plugins: &[PluginEntry]) -> Vec<String> {
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
    route_plugins: &[PluginEntry],
    service_plugins: &[PluginEntry],
    route_plugin_names: &[String],
) -> Vec<PluginEntry> {
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
pub type RouteMatchResult = Option<(Vec<(String, String)>, Arc<ProxyRoute>)>;

/// Proxy route with all service and upstream dependencies bound at build time.
pub struct ProxyRoute {
    pub inner: config::Route,
    pub plugins: Vec<PluginEntry>,
    resolved_upstream: Option<Arc<dyn UpstreamSelector>>,
    effective_hosts: Vec<String>,
    /// Human-readable name of the bound service, when configured.
    service_name: Option<String>,
    plugin_executor: Arc<ProxyPluginExecutor>,
    pub inline_upstream: Option<Arc<ProxyUpstream>>,
    /// Fingerprint of route/service identity and response-affecting plugins.
    cache_namespace_fingerprint: u64,
    /// Whether the route's effective (route+service) configuration enables
    /// CORS, making the route a candidate for CORS preflight fallback
    /// matching. Compiled at build time so the matcher never inspects
    /// plugin names at request time.
    serves_preflight: bool,
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
        prepared: &PreparedUpstreams,
        defaults: &config::EffectiveDefaults,
        resolver: &Arc<hickory_resolver::TokioResolver>,
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
                ProxyUpstream::build(
                    upstream_config,
                    prepared
                        .get(&UpstreamOccurrence::RouteInline(route.id.clone()))
                        .cloned()
                        .ok_or_else(|| {
                            ProxyError::Configuration(format!(
                                "Route '{}' inline upstream was not prepared",
                                route.id
                            ))
                        })?,
                    defaults,
                    resolver,
                )
                .with_context(&format!(
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
        let owner = TrafficSplitOwner::Route(route.id.clone());
        for (name, value) in route.plugins.clone() {
            let entry = build_plugin_with_upstreams(
                &name, value, upstreams, prepared, &owner, defaults, resolver,
            )
            .map_err(|e| ProxyError::Plugin(format!("Failed to build plugin '{name}': {e}")))?;
            plugins.push(entry);
        }
        sort_plugins_by_priority_desc(plugins.as_mut_slice());

        let plugin_names = build_plugin_name_index(&plugins);
        let merged_plugins = if let Some(service) = &service {
            merge_route_and_service_plugins(&plugins, &service.plugins, &plugin_names)
        } else {
            plugins.clone()
        };
        // `merge_route_and_service_plugins` already guarantees a non-increasing
        // priority sequence with route-side tie preference; `from_sorted` keeps
        // that order instead of re-sorting (which would break the tie rule).
        let plugin_executor = if merged_plugins.is_empty() {
            ProxyPluginExecutor::default_shared()
        } else {
            Arc::new(ProxyPluginExecutor::from_sorted(merged_plugins))
        };
        let serves_preflight = plugin_executor.has_plugin(cors::PLUGIN_NAME);

        let cache_namespace_fingerprint =
            route.cache_namespace_fingerprint(service.as_ref().map(|service| &service.inner));

        let service_name = service.as_ref().and_then(|s| s.inner.name.clone());

        Ok(Self {
            inner: route,
            plugins,
            resolved_upstream,
            effective_hosts,
            service_name,
            plugin_executor,
            inline_upstream,
            cache_namespace_fingerprint,
            serves_preflight,
        })
    }

    fn get_hosts(&self) -> Vec<&str> {
        self.effective_hosts.iter().map(String::as_str).collect()
    }

    /// Return the effective host patterns used to match this route (route
    /// hosts, falling back to service hosts). Exposed so plugins can derive
    /// bounded labels from route configuration instead of raw request input.
    pub fn effective_hosts(&self) -> &[String] {
        &self.effective_hosts
    }
}

impl RouteContext for ProxyRoute {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn enable_websocket(&self) -> bool {
        self.inner.enable_websocket
    }

    fn select_upstream(&self, session: &mut Session) -> ProxyResult<UpstreamSelection> {
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
        let selected_backend = backend.clone();

        let peer = backend.ext.get_mut::<HttpPeer>().ok_or_else(|| {
            ProxyError::UpstreamSelection(
                "Missing selected backend metadata for HttpPeer".to_string(),
            )
        })?;

        Ok(UpstreamSelection {
            peer: Box::new(peer.clone()),
            upstream,
            backend: selected_backend,
        })
    }

    fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor> {
        self.plugin_executor.clone()
    }

    fn cache_namespace_fingerprint(&self) -> u64 {
        self.cache_namespace_fingerprint
    }

    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>> {
        self.resolved_upstream.clone()
    }

    fn timeout(&self) -> Option<&config::Timeout> {
        self.inner.timeout.as_ref()
    }

    fn labels(&self) -> Option<&dyn RouteLabels> {
        Some(self)
    }
}

impl RouteLabels for ProxyRoute {
    fn name(&self) -> Option<&str> {
        self.inner.name.as_deref()
    }

    fn service_id(&self) -> Option<&str> {
        self.inner.service_id.as_deref()
    }

    fn service_name(&self) -> Option<&str> {
        self.service_name.as_deref()
    }

    fn uri_template(&self) -> Option<&str> {
        // A route with multiple URIs does not retain which alternative matched;
        // use runtime normalization for those to avoid assigning the wrong label.
        self.inner.uri.as_deref()
    }

    fn effective_hosts(&self) -> &[String] {
        &self.effective_hosts
    }
}

/// Apply an explicit route timeout onto a peer. No-op when `route_timeout` is `None`.
///
/// Priority: `route.timeout` > upstream-written timeout (explicit or global).
/// When the route has no timeout, leave the peer alone so named/inline upstream
/// settings (or `pingsix.defaults.upstream_timeout` applied by the upstream)
/// are preserved. Applied by [`HttpService::upstream_peer`]
/// (crate::service::http::HttpService) so both selection paths (route and
/// traffic-split override) get exactly one application site.
pub(crate) fn apply_route_timeout(route_timeout: Option<&config::Timeout>, p: &mut HttpPeer) {
    if let Some(config::Timeout {
        connect,
        read,
        send,
    }) = route_timeout
    {
        p.options.connection_timeout = Some(Duration::from_secs(*connect));
        p.options.read_timeout = Some(Duration::from_secs(*read));
        p.options.write_timeout = Some(Duration::from_secs(*send));
    }
}

#[derive(Default)]
pub struct MatchEntry {
    /// Router for non-host URI matching
    non_host_uri: MatchRouter<Vec<Arc<ProxyRoute>>>,
    /// Exact (lowercased) host -> URI router
    exact_hosts: std::collections::HashMap<String, MatchRouter<Vec<Arc<ProxyRoute>>>>,
    /// Wildcard suffix (e.g. `".example.com"` for `"*.example.com"`) -> URI router,
    /// sorted longest-suffix-first so the most specific wildcard wins.
    wildcard_hosts: Vec<(String, MatchRouter<Vec<Arc<ProxyRoute>>>)>,
    /// Whether global rules enable CORS, making every method-compatible route
    /// a preflight fallback candidate. Compiled at build time.
    global_cors: bool,
}

impl MatchEntry {
    pub(crate) fn build(
        routes: &std::collections::HashMap<String, Arc<ProxyRoute>>,
        global_plugins: &ProxyPluginExecutor,
    ) -> ProxyResult<Self> {
        // Make the matcher deterministic across process restarts: `HashMap`
        // iteration order is randomized, and equal-priority routes sharing the
        // same URI keep insertion order. Without an explicit tie-break, which
        // route wins a tie could change on every boot.
        let mut sorted_routes: Vec<_> = routes.values().cloned().collect();
        sorted_routes.sort_by(|a, b| {
            b.inner
                .priority
                .cmp(&a.inner.priority)
                .then_with(|| a.inner.id.cmp(&b.inner.id))
        });

        let mut non_host_groups: std::collections::HashMap<String, Vec<Arc<ProxyRoute>>> =
            std::collections::HashMap::new();
        let mut exact_host_groups: std::collections::HashMap<
            String,
            std::collections::HashMap<String, Vec<Arc<ProxyRoute>>>,
        > = std::collections::HashMap::new();
        let mut wildcard_host_groups: std::collections::HashMap<
            String,
            std::collections::HashMap<String, Vec<Arc<ProxyRoute>>>,
        > = std::collections::HashMap::new();

        // Group by exact host/URI pattern string before inserting into matchit.
        // Calling `matchit::Router::at_mut` during insertion performs pattern
        // matching rather than exact-key lookup, which would merge lower-priority
        // specific routes into an already-inserted wildcard route.
        for route in sorted_routes {
            let route_hosts = route.get_hosts();
            let uris = route.inner.get_uris();

            if route_hosts.is_empty() {
                for uri in uris {
                    non_host_groups
                        .entry(uri.to_string())
                        .or_default()
                        .push(route.clone());
                }
            } else {
                for host in route_hosts {
                    let normalized = host.to_ascii_lowercase();
                    let target = if let Some(suffix) = normalized.strip_prefix('*') {
                        wildcard_host_groups.entry(suffix.to_string()).or_default()
                    } else {
                        exact_host_groups.entry(normalized).or_default()
                    };
                    for uri in &uris {
                        target
                            .entry((*uri).to_string())
                            .or_default()
                            .push(route.clone());
                    }
                }
            }
        }

        let non_host_uri = Self::compile_uri_router(non_host_groups)?;

        let mut exact_hosts = std::collections::HashMap::with_capacity(exact_host_groups.len());
        for (host, groups) in exact_host_groups {
            exact_hosts.insert(host, Self::compile_uri_router(groups)?);
        }

        let mut wildcard_hosts = Vec::with_capacity(wildcard_host_groups.len());
        for (suffix, groups) in wildcard_host_groups {
            wildcard_hosts.push((suffix, Self::compile_uri_router(groups)?));
        }
        wildcard_hosts.sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));

        Ok(Self {
            non_host_uri,
            exact_hosts,
            wildcard_hosts,
            global_cors: global_plugins.has_plugin(cors::PLUGIN_NAME),
        })
    }

    fn compile_uri_router(
        groups: std::collections::HashMap<String, Vec<Arc<ProxyRoute>>>,
    ) -> ProxyResult<MatchRouter<Vec<Arc<ProxyRoute>>>> {
        // Insert in deterministic pattern order so conflict errors are reproducible.
        let mut entries: Vec<_> = groups.into_iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut router = MatchRouter::new();
        for (uri, routes) in entries {
            let first_id = routes
                .first()
                .map(|r| r.inner.id.clone())
                .unwrap_or_else(|| "<unknown>".to_string());
            router.insert(uri, routes).map_err(|e| {
                ProxyError::Configuration(format!(
                    "Failed to build route matcher for '{first_id}': {e}"
                ))
            })?;
        }
        Ok(router)
    }

    /// Multi-label wildcard host match: `suffix` is the portion after `*`
    /// (e.g. `".example.com"` for `"*.example.com"`). Requires at least one
    /// leading character before the suffix so `"example.com"` does not match
    /// `"*.example.com"`.
    fn host_matches_wildcard(host_lower: &str, suffix: &str) -> bool {
        host_lower.len() > suffix.len() && host_lower.ends_with(suffix)
    }

    /// Converts host to reversed matchit-compatible pattern.
    /// Wildcard "*.example.com" becomes "moc.elpmaxe.{*subdomain}".
    /// Exact "api.example.com" becomes "moc.elpmaxe.ipa".
    #[cfg(test)]
    fn reverse_ascii_lowercase(input: &str) -> String {
        let mut reversed = String::with_capacity(input.len());
        for ch in input.chars().rev() {
            reversed.push(ch.to_ascii_lowercase());
        }
        reversed
    }

    #[cfg(test)]
    fn reverse_host(host: &str) -> String {
        if let Some(domain_part) = host.strip_prefix("*") {
            let reversed_domain = Self::reverse_ascii_lowercase(domain_part);
            format!("{reversed_domain}{{*subdomain}}")
        } else {
            Self::reverse_ascii_lowercase(host)
        }
    }

    /// Matches a request to a route.
    pub(crate) fn match_request(&self, session: &mut Session) -> RouteMatchResult {
        let host = get_request_host(session.req_header());
        let uri = session.req_header().uri.path();
        let method = session.req_header().method.as_str();

        log::debug!("match request: host={host:?}, uri={uri:?}, method={method:?}");
        self.match_host_uri_method(host, uri, method)
    }

    /// Match host/URI/method without a Pingora session.
    ///
    /// Used by request matching and by Criterion microbenchmarks.
    pub fn match_host_uri_method(
        &self,
        host: Option<&str>,
        uri: &str,
        method: &str,
    ) -> RouteMatchResult {
        if let Some(host_str) = host.filter(|h| !h.is_empty()) {
            let host_lower = host_str.to_ascii_lowercase();
            if let Some(router) = self.exact_hosts.get(&host_lower) {
                if let Some(result) = Self::match_uri_method(router, uri, method) {
                    return Some(result);
                }
            }
            for (suffix, router) in &self.wildcard_hosts {
                if Self::host_matches_wildcard(&host_lower, suffix) {
                    if let Some(result) = Self::match_uri_method(router, uri, method) {
                        return Some(result);
                    }
                }
            }
        }

        Self::match_uri_method(&self.non_host_uri, uri, method)
    }

    /// Match a syntactically valid CORS preflight using its requested method.
    /// Normal OPTIONS routes remain preferred because callers invoke this only
    /// after normal matching fails. Preflight eligibility (route/service/global
    /// CORS) is compiled into the matcher at build time.
    pub(crate) fn match_preflight(&self, session: &mut Session) -> RouteMatchResult {
        let request = session.req_header();
        if request.method != http::Method::OPTIONS
            || !request.headers.contains_key(http::header::ORIGIN)
        {
            return None;
        }
        let method = request
            .headers
            .get(http::header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|value| value.to_str().ok())?;
        if method.parse::<http::Method>().is_err() {
            return None;
        }
        let uri = request.uri.path();
        if let Some(host) = get_request_host(request).filter(|host| !host.is_empty()) {
            let host_lower = host.to_ascii_lowercase();
            if let Some(router) = self.exact_hosts.get(&host_lower) {
                if let Some(result) =
                    Self::match_preflight_uri(router, uri, method, self.global_cors)
                {
                    return Some(result);
                }
            }
            for (suffix, router) in &self.wildcard_hosts {
                if Self::host_matches_wildcard(&host_lower, suffix) {
                    if let Some(result) =
                        Self::match_preflight_uri(router, uri, method, self.global_cors)
                    {
                        return Some(result);
                    }
                }
            }
        }
        Self::match_preflight_uri(&self.non_host_uri, uri, method, self.global_cors)
    }

    fn match_preflight_uri(
        match_router: &MatchRouter<Vec<Arc<ProxyRoute>>>,
        uri: &str,
        method: &str,
        global_cors: bool,
    ) -> RouteMatchResult {
        let matched = match_router.at(uri).ok()?;
        let route = matched.value.iter().find(|route| {
            (global_cors || route.serves_preflight)
                && (route.inner.methods.is_empty()
                    || route
                        .inner
                        .methods
                        .iter()
                        .any(|configured| *configured == method))
        })?;
        let params = matched
            .params
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        Some((params, route.clone()))
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

    use crate::core::{PluginPhases, ProxyPlugin};

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

    fn entry(plugin: DummyPlugin) -> PluginEntry {
        PluginEntry::new(Arc::new(plugin), PluginPhases::empty())
    }

    #[test]
    fn test_merge_route_service_plugins_preserves_priority_order() {
        let route_plugins: Vec<PluginEntry> = vec![
            entry(DummyPlugin {
                name: "route_mid",
                priority: 50,
            }),
            entry(DummyPlugin {
                name: "route_low",
                priority: 10,
            }),
        ];
        let service_plugins: Vec<PluginEntry> = vec![
            entry(DummyPlugin {
                name: "service_high",
                priority: 100,
            }),
            entry(DummyPlugin {
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
        let route_dup = entry(DummyPlugin {
            name: "dup",
            priority: 10,
        });
        let service_dup = entry(DummyPlugin {
            name: "dup",
            priority: 10,
        });
        let service_other = entry(DummyPlugin {
            name: "other",
            priority: 5,
        });

        let route_plugins = vec![route_dup.clone()];
        let service_plugins = vec![service_dup, service_other.clone()];

        let route_names = build_plugin_name_index(&route_plugins);
        let merged =
            merge_route_and_service_plugins(&route_plugins, &service_plugins, &route_names);

        assert_eq!(merged.len(), 2);
        assert!(Arc::ptr_eq(&merged[0].plugin, &route_dup.plugin)); // route wins
        assert!(Arc::ptr_eq(&merged[1].plugin, &service_other.plugin));
    }

    #[test]
    fn test_route_without_service_and_without_plugins_reuses_shared_executor() {
        let route_cfg = config::Route {
            id: "r1".to_string(),
            name: None,
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
            enable_websocket: false,
        };

        let upstreams = HashMap::new();
        let services = HashMap::new();
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let proxy_route = ProxyRoute::build(
            route_cfg,
            &upstreams,
            &services,
            &HashMap::new(),
            &config::EffectiveDefaults::default(),
            &resolver,
        )
        .unwrap();
        let exec = proxy_route.build_plugin_executor();
        assert!(Arc::ptr_eq(&exec, &ProxyPluginExecutor::default_shared()));
    }

    #[test]
    fn same_priority_same_uri_routes_follow_id_tie_break_across_builds() {
        // Regression for determinism: equal-priority routes sharing one URI
        // used to inherit HashMap iteration order, which is randomized per
        // map instance / process. The matcher must always prefer the same
        // route (smallest id) regardless of insertion order.
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let mk = |id: &str| {
            Arc::new(
                ProxyRoute::build(
                    config::Route {
                        id: id.to_string(),
                        name: None,
                        uri: Some("/tie".to_string()),
                        uris: vec![],
                        methods: vec![],
                        host: None,
                        hosts: vec![],
                        priority: 7,
                        plugins: HashMap::new(),
                        upstream: None,
                        upstream_id: None,
                        service_id: None,
                        timeout: None,
                        enable_websocket: false,
                    },
                    &HashMap::new(),
                    &HashMap::new(),
                    &HashMap::new(),
                    &config::EffectiveDefaults::default(),
                    &resolver,
                )
                .unwrap(),
            )
        };
        let zebra = mk("zebra");
        let alpha = mk("alpha");

        for _ in 0..100 {
            let mut routes = HashMap::new();
            // Deliberately insert in the "wrong" order each time.
            routes.insert("zebra".to_string(), zebra.clone());
            routes.insert("alpha".to_string(), alpha.clone());
            let matcher =
                MatchEntry::build(&routes, &ProxyPluginExecutor::default_shared()).unwrap();
            let (_, route) = matcher
                .match_host_uri_method(None, "/tie", "GET")
                .expect("route matches");
            assert_eq!(route.inner.id, "alpha");
        }
    }

    #[test]
    fn high_priority_wildcard_does_not_swallow_lower_priority_exact_uri() {
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let mk = |id: &str, uri: &str, methods: Vec<http::Method>, priority: u32| {
            Arc::new(
                ProxyRoute::build(
                    config::Route {
                        id: id.to_string(),
                        name: None,
                        uri: Some(uri.to_string()),
                        uris: vec![],
                        methods,
                        host: None,
                        hosts: vec![],
                        priority,
                        plugins: HashMap::new(),
                        upstream: None,
                        upstream_id: None,
                        service_id: None,
                        timeout: None,
                        enable_websocket: false,
                    },
                    &HashMap::new(),
                    &HashMap::new(),
                    &HashMap::new(),
                    &config::EffectiveDefaults::default(),
                    &resolver,
                )
                .unwrap(),
            )
        };

        let mut routes = HashMap::new();
        routes.insert(
            "catch-all".to_string(),
            mk("catch-all", "/{*path}", vec![http::Method::GET], 100),
        );
        routes.insert(
            "admin-secret".to_string(),
            mk("admin-secret", "/admin/secret", vec![http::Method::POST], 1),
        );

        let matcher = MatchEntry::build(&routes, &ProxyPluginExecutor::default_shared()).unwrap();

        // A POST to an arbitrary path must NOT hit the lower-priority /admin/secret route.
        assert!(
            matcher
                .match_host_uri_method(None, "/public/anything", "POST")
                .is_none(),
            "POST /public/anything must not be routed to /admin/secret"
        );
        let (_, matched_admin) = matcher
            .match_host_uri_method(None, "/admin/secret", "POST")
            .expect("exact POST /admin/secret must match");
        assert_eq!(matched_admin.inner.id, "admin-secret");
        let (_, matched_public) = matcher
            .match_host_uri_method(None, "/public/anything", "GET")
            .expect("GET catch-all must still match");
        assert_eq!(matched_public.inner.id, "catch-all");
    }

    #[test]
    fn high_priority_wildcard_host_does_not_swallow_exact_host_and_falls_back() {
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let mk = |id: &str, host: &str, uri: &str, priority: u32| {
            Arc::new(
                ProxyRoute::build(
                    config::Route {
                        id: id.to_string(),
                        name: None,
                        uri: Some(uri.to_string()),
                        uris: vec![],
                        methods: vec![],
                        host: Some(host.to_string()),
                        hosts: vec![],
                        priority,
                        plugins: HashMap::new(),
                        upstream: None,
                        upstream_id: None,
                        service_id: None,
                        timeout: None,
                        enable_websocket: false,
                    },
                    &HashMap::new(),
                    &HashMap::new(),
                    &HashMap::new(),
                    &config::EffectiveDefaults::default(),
                    &resolver,
                )
                .unwrap(),
            )
        };

        let mut routes = HashMap::new();
        routes.insert(
            "wildcard".to_string(),
            mk("wildcard", "*.example.com", "/shared", 100),
        );
        routes.insert(
            "admin".to_string(),
            mk("admin", "admin.example.com", "/secret", 1),
        );

        let matcher = MatchEntry::build(&routes, &ProxyPluginExecutor::default_shared()).unwrap();

        // Other subdomains must NOT see admin.example.com's routes.
        assert!(
            matcher
                .match_host_uri_method(Some("other.example.com"), "/secret", "GET")
                .is_none(),
            "other.example.com must not match admin.example.com routes"
        );
        // Exact host matches its own route.
        let (_, matched_admin) = matcher
            .match_host_uri_method(Some("admin.example.com"), "/secret", "GET")
            .expect("admin.example.com/secret must match");
        assert_eq!(matched_admin.inner.id, "admin");
        // Exact host missing a URI falls back to matching wildcard host.
        let (_, matched_wildcard) = matcher
            .match_host_uri_method(Some("admin.example.com"), "/shared", "GET")
            .expect("admin.example.com/shared must fall back to *.example.com");
        assert_eq!(matched_wildcard.inner.id, "wildcard");
    }

    #[test]
    fn apply_route_timeout_none_preserves_peer_timeouts() {
        use pingora_core::upstreams::peer::HttpPeer;

        let mut peer = HttpPeer::new("127.0.0.1:80", false, String::new());
        peer.options.connection_timeout = Some(Duration::from_secs(30));
        peer.options.read_timeout = Some(Duration::from_secs(30));
        peer.options.write_timeout = Some(Duration::from_secs(30));

        apply_route_timeout(None, &mut peer);

        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(30))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn apply_route_timeout_some_overrides_peer_timeouts() {
        use pingora_core::upstreams::peer::HttpPeer;

        let mut peer = HttpPeer::new("127.0.0.1:80", false, String::new());
        peer.options.connection_timeout = Some(Duration::from_secs(30));
        peer.options.read_timeout = Some(Duration::from_secs(30));
        peer.options.write_timeout = Some(Duration::from_secs(30));

        let route_timeout = config::Timeout {
            connect: 5,
            read: 5,
            send: 5,
        };
        apply_route_timeout(Some(&route_timeout), &mut peer);

        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(5)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(5)));
    }
}
