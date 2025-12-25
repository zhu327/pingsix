use std::{collections::HashSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header::VARY, StatusCode};
use once_cell::sync::Lazy;
use pingora::modules::http::{
    HttpModules,
    {compression::ResponseCompressionBuilder, grpc_web::GrpcWeb},
};
use pingora_cache::{
    cache_control::{CacheControl, DirectiveMap, DirectiveValue},
    eviction::simple_lru::Manager,
    filters::resp_cacheable,
    key::HashBinary,
    lock::{CacheKeyLockImpl, CacheLock},
    CacheMeta, CacheMetaDefaults, CachePhase, MemCache, NoCacheReason, RespCacheable,
    VarianceBuilder,
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

use crate::{
    config,
    core::{ProxyContext, ProxyError, ProxyPlugin, RouteContext},
    plugin::{
        cache::{CacheSettings, CTX_KEY_CACHE_SETTINGS},
        traffic_split::CTX_KEY_UPSTREAM_OVERRIDE,
    },
    proxy::{global_rule::global_plugin_fetch, route::global_route_match_fetch},
};

// --- START: Global Cache Infrastructure ---
// 1. Cache backend: In-memory cache for high performance
static CACHE_BACKEND: Lazy<MemCache> = Lazy::new(MemCache::new);

// 2. Default cache metadata: No caching by default unless explicitly configured
const CACHE_DEFAULT: CacheMetaDefaults = CacheMetaDefaults::new(|_| None, 0, 0);

// 3. Eviction manager: Adjust based on server memory, using 512MB as example
static EVICTION_MANAGER: Lazy<Manager> = Lazy::new(|| Manager::new(512 * 1024 * 1024));

// 4. Cache lock: Timeout should be slightly larger than upstream P99 response time
static CACHE_LOCK: Lazy<Box<CacheKeyLockImpl>> =
    Lazy::new(|| CacheLock::new_boxed(Duration::from_secs(5)));
// --- END: Global Cache Infrastructure ---

/// Proxy service.
///
/// Manages the proxying of requests to upstream servers.
#[derive(Default)]
pub struct HttpService;

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
        // Match request to pipeline
        if let Some((route_params, route)) = global_route_match_fetch().match_request(session) {
            ctx.route_params = Some(route_params);
            ctx.plugin = route.build_plugin_executor();
            ctx.route = Some(route);

            ctx.global_plugin = global_plugin_fetch();
        }

        // Execute global rule plugins
        ctx.global_plugin
            .clone()
            .early_request_filter(session, ctx)
            .await?;

        // Execute plugins
        ctx.plugin.clone().early_request_filter(session, ctx).await
    }

    /// Filters incoming requests
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if ctx.route.is_none() {
            session
                .respond_error(StatusCode::NOT_FOUND.as_u16())
                .await?;
            return Ok(true);
        }

        // Execute global rule plugins
        if ctx
            .global_plugin
            .clone()
            .request_filter(session, ctx)
            .await?
        {
            return Ok(true);
        };

        // Execute plugins
        ctx.plugin.clone().request_filter(session, ctx).await
    }

    /// Selects an upstream peer for the request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = if let Some(ups_override) =
            ctx.get::<Arc<dyn crate::core::UpstreamSelector>>(CTX_KEY_UPSTREAM_OVERRIDE)
        {
            let mut backend = ups_override.select_backend(session).ok_or_else(|| {
                ProxyError::UpstreamSelection("Traffic-split selected no backend".to_string())
            })?;

            backend
                .ext
                .get_mut::<HttpPeer>()
                .ok_or_else(|| ProxyError::Internal("Peer missing".into()))
                .map(|p| Box::new(p.clone()))?
        } else {
            ctx.route
                .as_ref()
                .ok_or_else(|| ProxyError::Internal("Route not found".into()))
                .and_then(|r| r.select_http_peer(session))?
        };

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
        // Execute global rule plugins
        ctx.global_plugin
            .clone()
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        // Execute plugins
        ctx.plugin
            .clone()
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        // Rewrite host header
        if let Some(upstream) = ctx.route.as_ref().and_then(|r| r.resolve_upstream()) {
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
            if !settings.hide_cache_headers {
                let cache_phase = session.cache.phase();
                let status_str = match cache_phase {
                    CachePhase::Hit => "HIT",
                    CachePhase::Miss => "MISS",
                    CachePhase::Stale => "STALE",
                    CachePhase::Expired => "EXPIRED",
                    CachePhase::Revalidated => "REVALIDATED",
                    _ => "BYPASS",
                };
                upstream_response.insert_header("X-Cache-Status", status_str)?;
            }
        }

        // Execute global rule plugins
        ctx.global_plugin
            .clone()
            .response_filter(session, upstream_response, ctx)
            .await?;

        // Execute plugins
        ctx.plugin
            .clone()
            .response_filter(session, upstream_response, ctx)
            .await
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        // Execute global rule plugins
        ctx.global_plugin
            .clone()
            .response_body_filter(session, body, end_of_stream, ctx)?;

        // Execute plugins
        ctx.plugin
            .clone()
            .response_body_filter(session, body, end_of_stream, ctx)?;
        Ok(None)
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Check for cache bypass headers
        if session.req_header().headers.contains_key("x-bypass-cache")
            || session.req_header().headers.contains_key("cache-control")
                && session
                    .req_header()
                    .headers
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.contains("no-cache"))
                    .unwrap_or(false)
        {
            log::debug!("Cache bypass requested, skipping cache");
            return Ok(());
        }

        // Check for cache settings from plugin configuration
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
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

            // 2. Add headers from plugin's `vary` configuration
            for h in settings.vary.iter() {
                vary_headers.insert(h.trim().to_lowercase());
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

        if !settings.statuses.contains(&resp.status.as_u16()) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
        }

        let cc = CacheControl::from_resp_headers(resp);
        let final_cc = ensure_max_age(cc, settings);

        Ok(resp_cacheable(
            final_cc.as_ref(),
            resp.clone(),
            true,
            &CACHE_DEFAULT,
        ))
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        // Execute global rule plugins
        ctx.global_plugin.clone().logging(session, e, ctx).await;

        // Execute plugins
        ctx.plugin.clone().logging(session, e, ctx).await;
    }

    /// This filter is called when there is an error in the process of establishing a connection to the upstream.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(route) = ctx.route.as_ref() {
            if let Some(upstream) = route.resolve_upstream() {
                if let Some(retries) = upstream.get_retries() {
                    if retries > 0 && ctx.tries < retries {
                        if let Some(timeout) = upstream.get_retry_timeout() {
                            let elapsed_ms = ctx.elapsed_ms();
                            if elapsed_ms <= (timeout * 1000) as u128 {
                                ctx.tries += 1;
                                e.set_retry(true);
                            }
                        }
                    }
                }
            }
        }
        e
    }
}

/// Ensures CacheControl has max-age set, adding default TTL if missing
fn ensure_max_age(cc: Option<CacheControl>, settings: &CacheSettings) -> Option<CacheControl> {
    match cc {
        Some(existing_cc) => {
            // Check if max-age is already present
            if existing_cc.max_age().unwrap_or(None).is_some() {
                return Some(existing_cc);
            }

            // Need to add max-age, copy existing directives
            let mut directives = DirectiveMap::with_capacity(existing_cc.directives.len() + 1);

            // Copy existing directives (excluding max-age)
            for (key, value) in &existing_cc.directives {
                if key != "max-age" {
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                }
            }

            // Add max-age directive
            let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
            directives.insert("max-age".to_string(), Some(max_age_value));

            Some(CacheControl { directives })
        }
        None => {
            // No Cache-Control header, create new instance with max-age only
            let mut directives = DirectiveMap::with_capacity(1);
            let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
            directives.insert("max-age".to_string(), Some(max_age_value));

            Some(CacheControl { directives })
        }
    }
}
