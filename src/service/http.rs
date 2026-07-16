use std::{collections::HashSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::{
    header::{SET_COOKIE, VARY},
    StatusCode,
};
use once_cell::sync::{Lazy, OnceCell};
use pingora::modules::http::{
    HttpModules,
    {compression::ResponseCompressionBuilder, grpc_web::GrpcWeb},
};
use pingora_cache::{
    cache_control::{CacheControl, DirectiveMap, DirectiveValue},
    eviction::simple_lru::Manager,
    filters::resp_cacheable,
    key::{CacheKey, HashBinary},
    lock::{CacheKeyLockImpl, CacheLock},
    CacheMeta, CacheMetaDefaults, CachePhase, MemCache, NoCacheReason, RespCacheable,
    VarianceBuilder,
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use prometheus::{register_int_counter_vec, IntCounterVec};

use crate::{
    config::{self, CacheDefaults},
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyPluginExecutor, RouteContext},
    plugins::cache::{self, CacheSettings, CTX_KEY_CACHE_SETTINGS},
    proxy::runtime::RUNTIME,
};

/// Headers that imply credentials for shared-cache safety (checked before plugins mutate them).
pub(crate) fn headers_indicate_shared_cache_credentials(headers: &http::HeaderMap) -> bool {
    headers.contains_key("authorization")
        || headers.contains_key("proxy-authorization")
        || headers.contains_key("cookie")
}

static CACHE_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_cache_requests_total",
        "Local response-cache outcomes",
        &["outcome", "scope"]
    )
    .expect("cache metric registration must succeed")
});

/// Whether any `Vary` field contains the wildcard token. RFC semantics make
/// such a response unsuitable for reuse by a shared cache.
fn response_has_vary_star(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("*"))
}

// --- START: Global Cache Infrastructure ---
// 1. Cache backend: In-memory cache for high performance
static CACHE_BACKEND: Lazy<MemCache> = Lazy::new(MemCache::new);

// 2. Default cache metadata: No caching by default unless explicitly configured
const CACHE_DEFAULT: CacheMetaDefaults = CacheMetaDefaults::new(|_| None, 0, 0);

/// Configured eviction memory budget, populated once at startup from
/// `pingsix.defaults.cache.max_memory_bytes`. Falls back to 512MB when unset.
static CACHE_MAX_MEMORY_BYTES: OnceCell<usize> = OnceCell::new();

/// 512MB fallback used when no memory budget has been initialized.
const FALLBACK_MAX_MEMORY_BYTES: usize = 512 * 1024 * 1024;

/// Populates global cache capacity defaults from configuration. Must be called once
/// at startup before the proxy serves traffic. Subsequent calls are no-ops (first
/// value wins), keeping parallel test initialization safe.
pub fn init_cache_defaults(cache: &CacheDefaults) {
    let _ = CACHE_MAX_MEMORY_BYTES.set(cache.max_memory_bytes);
    cache::init_default_max_object_bytes(cache.default_max_object_bytes);
}

/// Returns the effective cache memory budget, falling back to 512MB when unset.
pub fn configured_max_memory_bytes() -> usize {
    CACHE_MAX_MEMORY_BYTES
        .get()
        .copied()
        .unwrap_or(FALLBACK_MAX_MEMORY_BYTES)
}

// 3. Eviction manager: sized from `pingsix.defaults.cache.max_memory_bytes`
static EVICTION_MANAGER: Lazy<Manager> = Lazy::new(|| Manager::new(configured_max_memory_bytes()));

// 4. Cache lock: Timeout should be slightly larger than upstream P99 response time
static CACHE_LOCK: Lazy<Box<CacheKeyLockImpl>> =
    Lazy::new(|| CacheLock::new_boxed(Duration::from_secs(5)));
// --- END: Global Cache Infrastructure ---

/// Proxy service.
///
/// Manages the proxying of requests to upstream servers.
#[derive(Default)]
pub struct HttpService;

/// Run global-rule plugins then route/service plugins for `early_request_filter`.
pub async fn run_global_then_route_early_request_filter(
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
    session: &mut Session,
    ctx: &mut ProxyContext,
) -> Result<()> {
    global.early_request_filter(session, ctx).await?;
    route.early_request_filter(session, ctx).await
}

/// Run global-rule plugins then route/service plugins for `request_filter`.
///
/// Returns `true` when a plugin short-circuits the request. Global plugins run
/// first; a global short-circuit skips the route layer entirely.
pub async fn run_global_then_route_request_filter(
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
    session: &mut Session,
    ctx: &mut ProxyContext,
) -> Result<bool> {
    if global.request_filter(session, ctx).await? {
        return Ok(true);
    }
    route.request_filter(session, ctx).await
}

/// Run global-rule plugins then route/service plugins for `upstream_request_filter`.
pub async fn run_global_then_route_upstream_request_filter(
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
    session: &mut Session,
    upstream_request: &mut RequestHeader,
    ctx: &mut ProxyContext,
) -> Result<()> {
    global
        .upstream_request_filter(session, upstream_request, ctx)
        .await?;
    route
        .upstream_request_filter(session, upstream_request, ctx)
        .await
}

/// Run global-rule plugins then route/service plugins for `response_filter`.
pub async fn run_global_then_route_response_filter(
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
    session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut ProxyContext,
) -> Result<()> {
    global
        .response_filter(session, upstream_response, ctx)
        .await?;
    route.response_filter(session, upstream_response, ctx).await
}

/// Run global-rule plugins then route/service plugins for `response_body_filter`.
pub fn run_global_then_route_response_body_filter(
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut ProxyContext,
) -> Result<()> {
    global.response_body_filter(session, body, end_of_stream, ctx)?;
    route.response_body_filter(session, body, end_of_stream, ctx)
}

/// Run global-rule plugins then route/service plugins for `logging`.
pub async fn run_global_then_route_logging(
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
    session: &mut Session,
    e: Option<&Error>,
    ctx: &mut ProxyContext,
) {
    global.logging(session, e, ctx).await;
    route.logging(session, e, ctx).await;
}

#[async_trait]
impl ProxyHttp for HttpService {
    type CTX = ProxyContext;

    /// Creates a new context for each request
    fn new_ctx(&self) -> Self::CTX {
        Self::CTX::default()
    }

    /// Set up downstream modules.
    ///
    /// set up [ResponseCompressionBuilder] for gzip and brotli compression.
    /// set up [GrpcWeb] for grpc-web protocol.
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        // Add disabled downstream compression module by default
        modules.add_module(ResponseCompressionBuilder::enable(0));
        // Add the gRPC web module
        modules.add_module(Box::new(GrpcWeb));
    }

    /// Handle the incoming request before any downstream module is executed.
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let original_headers = &session.req_header().headers;
        ctx.original_request_had_credentials =
            headers_indicate_shared_cache_credentials(original_headers);
        if ctx.original_request_had_credentials {
            ctx.request_has_credentials = true;
        }

        // Load one immutable runtime snapshot for all data-plane configuration used here.
        let runtime = RUNTIME.load();
        ctx.global_plugin = runtime.global_plugins.clone();
        let (route_match, is_fallback_preflight) =
            match runtime.route_matcher.match_request(session) {
                Some(route_match) => (Some(route_match), false),
                None => (
                    runtime
                        .route_matcher
                        .match_preflight(session, runtime.global_plugins.has_plugin("cors")),
                    true,
                ),
            };
        if let Some((route_params, route)) = route_match {
            // The preflight matcher itself filters fallback candidates to routes
            // whose effective route/service/global configuration contains CORS.
            let executor = route.build_plugin_executor();
            debug_assert!(
                !is_fallback_preflight
                    || executor.has_plugin("cors")
                    || runtime.global_plugins.has_plugin("cors")
            );
            ctx.route_params = Some(route_params);
            ctx.plugin = executor;
            ctx.route = Some(route);
        }

        // Execute global rule plugins, then route/service plugins.
        run_global_then_route_early_request_filter(
            ctx.global_plugin.clone(),
            ctx.plugin.clone(),
            session,
            ctx,
        )
        .await
    }

    /// Filters incoming requests
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if ctx.route.is_none() {
            session
                .respond_error(StatusCode::NOT_FOUND.as_u16())
                .await?;
            return Ok(true);
        }

        run_global_then_route_request_filter(
            ctx.global_plugin.clone(),
            ctx.plugin.clone(),
            session,
            ctx,
        )
        .await
    }

    /// Selects an upstream peer for the request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let (peer, selected_upstream) = if let Some(upstream) = ctx.upstream_override.clone() {
            let mut backend = upstream.select_backend(session).ok_or_else(|| {
                ProxyError::UpstreamSelection("Traffic-split selected no backend".to_string())
            })?;
            let mut peer = backend
                .ext
                .get_mut::<HttpPeer>()
                .ok_or_else(|| ProxyError::Internal("Peer missing".into()))
                .map(|p| Box::new(p.clone()))?;
            if let Some(route) = ctx.route.as_ref() {
                crate::proxy::route::apply_route_timeout(route.timeout(), &mut peer);
            }
            (peer, Some(upstream))
        } else {
            let route = ctx
                .route
                .as_ref()
                .ok_or_else(|| ProxyError::Internal("Route not found".into()))?;
            (route.select_http_peer(session)?, route.resolve_upstream())
        };

        ctx.selected_upstream = selected_upstream;
        ctx.peer = Some(peer.clone());
        Ok(peer)
    }

    /// Modify the request before it is sent to the upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        run_global_then_route_upstream_request_filter(
            ctx.global_plugin.clone(),
            ctx.plugin.clone(),
            session,
            upstream_request,
            ctx,
        )
        .await?;

        // Rewrite host header
        // Priority: upstream_override > route upstream
        if let Some(upstream) = ctx.selected_upstream.as_ref() {
            match upstream.get_pass_host() {
                config::UpstreamPassHost::PASS => {
                    // Do nothing, preserve original host
                }
                config::UpstreamPassHost::REWRITE => {
                    upstream.upstream_host_rewrite(upstream_request);
                }
                config::UpstreamPassHost::NODE => {
                    if let Some(peer) = ctx.peer.as_ref() {
                        if let Err(e) =
                            upstream_request.insert_header(http::header::HOST, peer.sni.as_str())
                        {
                            log::error!("Failed to rewrite upstream host header: {e}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Add X-Cache-Status header logic
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
            let cache_phase = session.cache.phase();
            let status_str = match cache_phase {
                CachePhase::Hit => "HIT",
                CachePhase::Miss => "MISS",
                CachePhase::Stale => "STALE",
                CachePhase::Expired => "EXPIRED",
                CachePhase::Revalidated => "REVALIDATED",
                _ => "BYPASS",
            };
            CACHE_REQUESTS
                .with_label_values(&[&status_str.to_ascii_lowercase(), "local"])
                .inc();
            if !settings.hide_cache_headers {
                upstream_response.insert_header("X-Cache-Status", status_str)?;
                upstream_response.insert_header("X-Cache-Scope", "local")?;
            }
        }

        run_global_then_route_response_filter(
            ctx.global_plugin.clone(),
            ctx.plugin.clone(),
            session,
            upstream_response,
            ctx,
        )
        .await
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        run_global_then_route_response_body_filter(
            ctx.global_plugin.clone(),
            ctx.plugin.clone(),
            session,
            body,
            end_of_stream,
            ctx,
        )?;
        Ok(None)
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Check for cache bypass headers (optimized to avoid repeated map lookups)
        let headers = &session.req_header().headers;

        if headers.contains_key("x-bypass-cache") {
            log::debug!("Cache bypass requested via x-bypass-cache header");
            return Ok(());
        }

        if let Some(cache_control) = headers.get("cache-control") {
            if let Ok(cc_str) = cache_control.to_str() {
                if cc_str.contains("no-cache") {
                    log::debug!("Cache bypass requested via cache-control: no-cache");
                    return Ok(());
                }
            }
        }

        // Check for cache settings from plugin configuration.
        // Re-check credentials here: global cache may run before route auth plugins mark them.
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
            if crate::plugins::cache::should_bypass_authenticated_request(settings, ctx) {
                log::debug!("Skipping shared cache: request has credentials");
                return Ok(());
            }

            log::debug!("Cache settings found, enabling Pingora cache.");

            // Enable caching with configured backend and eviction manager
            session.cache.enable(
                &*CACHE_BACKEND,
                Some(
                    &*EVICTION_MANAGER
                        as &'static (dyn pingora_cache::eviction::EvictionManager + Sync),
                ),
                None,
                Some(CACHE_LOCK.as_ref()),
                None,
            );

            // Set maximum file size if configured
            if settings.max_file_size_bytes > 0 {
                session
                    .cache
                    .set_max_file_size_bytes(settings.max_file_size_bytes);
                log::debug!(
                    "Set max cache file size to {} bytes",
                    settings.max_file_size_bytes
                );
            }
        }
        Ok(())
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let req = session.req_header();
        let host = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let primary = format!("{} {} {}", req.method, host, req.uri);

        let route_fp = ctx
            .route
            .as_ref()
            .map(|r| r.cache_namespace_fingerprint())
            .unwrap_or(0);
        let policy_fp = ctx
            .get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
            .map(|s| s.policy_fingerprint)
            .unwrap_or(0);
        let upstream_key = if let Some(override_up) = ctx.upstream_override.as_ref() {
            override_up.cache_isolation_key()
        } else {
            ctx.route
                .as_ref()
                .and_then(|r| r.resolve_upstream())
                .map(|u| u.cache_isolation_key())
                .unwrap_or_default()
        };
        let scheme = if session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some()
        {
            "https"
        } else {
            "http"
        };
        // Route fingerprint covers identity + response-affecting plugins;
        // upstream isolation covers origin selection (nodes, Host rewrite, TLS).
        let namespace = format!("rf={route_fp:x}|c={policy_fp:x}|u={upstream_key}|sch={scheme}");
        Ok(CacheKey::new(namespace, primary, ""))
    }

    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        ctx: &mut Self::CTX,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        // Only process Vary headers when cache settings are present
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
            let mut key = VarianceBuilder::new();
            let mut vary_headers: HashSet<String> = HashSet::new();

            // `Vary: *` responses must never enter a shared cache. The response
            // filter enforces that rule; this is a defensive guard against ever
            // constructing a stable variance for the literal `*` header name.
            if response_has_vary_star(meta.headers()) {
                return None;
            }

            // 1. Add headers from origin's `Vary` response header
            meta.headers()
                .get_all(VARY)
                .iter()
                .flat_map(|v| v.to_str().unwrap_or("").split(','))
                .for_each(|h| {
                    let trimmed = h.trim().to_lowercase();
                    if !trimmed.is_empty() {
                        vary_headers.insert(trimmed);
                    }
                });

            // 2. Add headers from plugin's pre-normalized `vary` configuration
            for h in settings.vary.iter() {
                vary_headers.insert(h.clone());
            }

            // 3. Build the variance key
            if vary_headers.is_empty() {
                return None; // No vary headers, no variance key
            }

            for header_name in &vary_headers {
                key.add_value(
                    header_name,
                    req.headers
                        .get(header_name)
                        .map(|v| v.as_bytes())
                        .unwrap_or(&[]),
                );
            }

            return key.finalize();
        }

        None
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
        };

        // These reasons may run after `session.cache.enable()`; NeverEnabled panics there.
        if crate::plugins::cache::should_bypass_authenticated_request(settings, ctx) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        if !settings.statuses.contains(&resp.status.as_u16()) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        if !settings.cache_set_cookie_responses && resp.headers.contains_key(SET_COOKIE) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        if response_has_vary_star(&resp.headers) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        let cc = CacheControl::from_resp_headers(resp);
        let final_cc = ensure_max_age(cc, settings);

        // Only treat the request as authorized when credentials were actually
        // present; the previous hard-coded `true` made every response require
        // `public`/`s-maxage` and prevented the default TTL path from caching.
        let authorization_present =
            ctx.original_request_had_credentials || ctx.request_has_credentials;

        Ok(resp_cacheable(
            final_cc.as_ref(),
            resp.clone(),
            authorization_present,
            &CACHE_DEFAULT,
        ))
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        run_global_then_route_logging(
            ctx.global_plugin.clone(),
            ctx.plugin.clone(),
            session,
            e,
            ctx,
        )
        .await;
    }

    /// This filter is called when there is an error in the process of establishing a connection to the upstream.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(upstream) = ctx.selected_upstream.as_ref() {
            if let Some(retries) = upstream.get_retries() {
                if retries > 0 && ctx.tries < retries {
                    let within_timeout = match upstream.get_retry_timeout() {
                        Some(timeout) => ctx.elapsed_ms() <= (timeout * 1000) as u128,
                        None => true,
                    };
                    if within_timeout {
                        ctx.tries += 1;
                        e.set_retry(true);
                    }
                }
            }
        }
        e
    }
}

/// Ensures CacheControl has max-age set, adding default TTL if missing.
/// Also handles s-maxage and stale-while-revalidate directives based on settings.
fn ensure_max_age(cc: Option<CacheControl>, settings: &CacheSettings) -> Option<CacheControl> {
    match cc {
        Some(existing_cc) => {
            let has_max_age_existing = existing_cc.directives.contains_key("max-age");
            let needs_smaxage_rewrite =
                settings.respect_s_maxage && existing_cc.directives.contains_key("s-maxage");
            let needs_stale_while_revalidate = settings.stale_while_revalidate.is_some_and(|_| {
                !existing_cc
                    .directives
                    .contains_key("stale-while-revalidate")
            });

            if has_max_age_existing && !needs_smaxage_rewrite && !needs_stale_while_revalidate {
                return Some(existing_cc);
            }

            let mut directives = DirectiveMap::with_capacity(existing_cc.directives.len() + 3);
            let mut has_max_age = false;

            // Copy existing directives and check for max-age
            for (key, value) in &existing_cc.directives {
                // If respect_s_maxage is enabled and s-maxage is present, use it as max-age for shared cache
                if settings.respect_s_maxage && key == "s-maxage" {
                    if let Some(s_maxage_value) = value {
                        // Use s-maxage value as max-age for shared cache scenario
                        let max_age_from_s_maxage = DirectiveValue(s_maxage_value.0.clone());
                        directives.insert("max-age".to_string(), Some(max_age_from_s_maxage));
                        has_max_age = true;
                    }
                    // Also keep the original s-maxage
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                } else if key == "max-age" {
                    has_max_age = true;
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                } else {
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                }
            }

            // Add max-age if not present (and not set from s-maxage)
            if !has_max_age {
                let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
                directives.insert("max-age".to_string(), Some(max_age_value));
            }

            // Add stale-while-revalidate if configured and not already present
            if let Some(swr_duration) = settings.stale_while_revalidate {
                if !directives.contains_key("stale-while-revalidate") {
                    let swr_value = DirectiveValue(swr_duration.as_secs().to_string().into_bytes());
                    directives.insert("stale-while-revalidate".to_string(), Some(swr_value));
                }
            }

            Some(CacheControl { directives })
        }
        None => {
            // No Cache-Control header, create new instance
            let capacity = 1 + settings.stale_while_revalidate.is_some() as usize;
            let mut directives = DirectiveMap::with_capacity(capacity);

            // Add max-age directive
            let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
            directives.insert("max-age".to_string(), Some(max_age_value));

            // Add stale-while-revalidate if configured
            if let Some(swr_duration) = settings.stale_while_revalidate {
                let swr_value = DirectiveValue(swr_duration.as_secs().to_string().into_bytes());
                directives.insert("stale-while-revalidate".to_string(), Some(swr_value));
            }

            Some(CacheControl { directives })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vary_star_is_detected_across_all_header_lines() {
        let mut headers = http::HeaderMap::new();
        headers.append(VARY, "Accept-Encoding".parse().unwrap());
        headers.append(VARY, "Origin, *".parse().unwrap());
        assert!(response_has_vary_star(&headers));
        headers.clear();
        headers.insert(VARY, "Origin, Accept-Encoding".parse().unwrap());
        assert!(!response_has_vary_star(&headers));
    }

    #[test]
    fn shared_cache_credential_headers_include_proxy_authorization() {
        let mut headers = http::HeaderMap::new();
        assert!(!headers_indicate_shared_cache_credentials(&headers));

        headers.insert("authorization", "Basic x".parse().unwrap());
        assert!(headers_indicate_shared_cache_credentials(&headers));

        headers.clear();
        headers.insert("proxy-authorization", "Basic x".parse().unwrap());
        assert!(headers_indicate_shared_cache_credentials(&headers));

        headers.clear();
        headers.insert("cookie", "a=b".parse().unwrap());
        assert!(headers_indicate_shared_cache_credentials(&headers));
    }

    #[test]
    fn eviction_manager_uses_configured_memory() {
        // init_cache_defaults is idempotent (first call wins); in a fresh test binary this
        // is the only setter, so the configured value is observable via the getter.
        let cache = CacheDefaults {
            max_memory_bytes: 777_777,
            default_max_object_bytes: 888,
        };
        init_cache_defaults(&cache);
        assert_eq!(configured_max_memory_bytes(), 777_777);
        assert_eq!(cache::default_max_object_bytes(), 888);
    }
}
