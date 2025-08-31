//! New HTTP service implementation using dependency injection
//!
//! This module provides a refactored HTTP service that uses the new
//! architecture with dependency injection and eliminates circular dependencies.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

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
    core::{
        container::ServiceContainer,
        context::ProxyContext,
    },
    orchestration::{RequestExecutor, RequestRouter},
    plugin::cache::{CacheSettings, CTX_KEY_CACHE_SETTINGS},
};

// --- START: Global Cache Infrastructure ---
static CACHE_BACKEND: Lazy<MemCache> = Lazy::new(MemCache::new);
const CACHE_DEFAULT: CacheMetaDefaults = CacheMetaDefaults::new(|_| None, 0, 0);
static EVICTION_MANAGER: Lazy<Manager> = Lazy::new(|| Manager::new(512 * 1024 * 1024));
static CACHE_LOCK: Lazy<Box<CacheKeyLockImpl>> =
    Lazy::new(|| CacheLock::new_boxed(Duration::from_secs(5)));
// --- END: Global Cache Infrastructure ---

/// New HTTP service implementation using dependency injection
pub struct NewHttpService {
    /// Service container with all dependencies
    container: Arc<ServiceContainer>,
    
    /// Request router for matching requests to routes
    router: Arc<RequestRouter>,
    
    /// Request executor for handling the request pipeline
    executor: Arc<RequestExecutor>,
}

impl NewHttpService {
    /// Create a new HTTP service with dependency injection
    pub fn new(container: Arc<ServiceContainer>) -> Self {
        let router = Arc::new(RequestRouter::new(container.registry().clone()));
        let executor = Arc::new(RequestExecutor::new(container.clone()));

        Self {
            container,
            router,
            executor,
        }
    }

    /// Initialize the router with current routes
    pub fn initialize_router(&mut self) -> Result<()> {
        // The router will automatically use the registry to build its routing table
        log::info!("HTTP service router initialized");
        Ok(())
    }
}

#[async_trait]
impl ProxyHttp for NewHttpService {
    type CTX = ProxyContext;

    /// Creates a new context for each request
    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    /// Set up downstream modules
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        // Add disabled downstream compression module by default
        modules.add_module(ResponseCompressionBuilder::enable(0));
        // Add the gRPC web module
        modules.add_module(Box::new(GrpcWeb));
    }

    /// Handle the incoming request before any downstream module is executed
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Match request to route using the new router
        if let Some((route_params, route)) = self.router.match_request(session) {
            ctx.route_params = Some(route_params);
            ctx.route = Some(route.clone());

            // Build plugin executors for this route
            ctx.global_plugin_executor = self.container.global_plugin_executor();
            
            // For now, use the same global executor for route-specific plugins
            // TODO: Build route-specific plugin executor from route configuration
            ctx.plugin_executor = self.container.global_plugin_executor();
        }

        // Execute the early request filter pipeline
        self.executor.execute_early_request_filter(session, ctx).await
            .map_err(|e| -> Box<Error> { e.into() })
    }

    /// Filters incoming requests
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if ctx.route.is_none() {
            session.respond_error(StatusCode::NOT_FOUND.as_u16()).await?;
            return Ok(true);
        }

        // Execute the request filter pipeline
        self.executor.execute_request_filter(session, ctx).await
            .map_err(|e| -> Box<Error> { e.into() })
    }

    /// Selects an upstream peer for the request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = self.executor.select_upstream_peer(session, ctx).await
            .map_err(|e| -> Box<Error> { e.into() })?;
        
        ctx.set("upstream", peer._address.to_string());
        Ok(peer)
    }

    /// Modify the request before it is sent to the upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Execute upstream request filters
        self.executor.execute_upstream_request_filter(session, upstream_request, ctx).await
            .map_err(|e| -> Box<Error> { e.into() })?;

        // Handle host rewriting
        if let Some(route) = &ctx.route {
            if let Some(upstream) = route.resolve_upstream() {
                // TODO: Add upstream_host_rewrite method to UpstreamProvider trait
                // upstream.upstream_host_rewrite(upstream_request);
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

        // Execute response filters
        self.executor.execute_response_filter(session, upstream_response, ctx).await
            .map_err(|e| -> Box<Error> { e.into() })
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        // Execute response body filters through executor
        // For now, use the existing plugin system
        ctx.global_plugin_executor
            .response_body_filter(session, body, end_of_stream, ctx)
            .map_err(|e| -> Box<Error> { e.into() })?;

        ctx.plugin_executor
            .response_body_filter(session, body, end_of_stream, ctx)
            .map_err(|e| -> Box<Error> { e.into() })?;

        Ok(None)
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Check cache bypass headers
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

        // Check for cache settings
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
            log::debug!("Cache settings found, enabling Pingora cache.");

            session.cache.enable(
                &*CACHE_BACKEND,
                Some(&*EVICTION_MANAGER as &'static (dyn pingora_cache::eviction::EvictionManager + Sync)),
                None,
                Some(CACHE_LOCK.as_ref()),
                None,
            );

            if settings.max_file_size_bytes > 0 {
                session.cache.set_max_file_size_bytes(settings.max_file_size_bytes);
                log::debug!("Set max cache file size to {} bytes", settings.max_file_size_bytes);
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
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
            let mut key = VarianceBuilder::new();
            let mut vary_headers: HashSet<String> = HashSet::new();

            // Add headers from origin's Vary response header
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

            // Add headers from plugin's vary configuration
            for h in settings.vary.iter() {
                vary_headers.insert(h.trim().to_lowercase());
            }

            if vary_headers.is_empty() {
                return None;
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
            false,
            &CACHE_DEFAULT,
        ))
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        // Execute logging through the new plugin system
        for plugin in ctx.global_plugin_executor.as_ref() {
            // TODO: Implement logging method in PluginExecutor trait
        }
    }

    /// Handle connection failures with retry logic
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
                            let elapsed_ms = ctx
                                .get::<Instant>("request_start")
                                .map(|t| t.elapsed().as_millis())
                                .unwrap_or(u128::MAX);
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

/// Ensure CacheControl has max-age, add default TTL if missing
fn ensure_max_age(cc: Option<CacheControl>, settings: &CacheSettings) -> Option<CacheControl> {
    match cc {
        Some(existing_cc) => {
            if existing_cc.max_age().unwrap_or(None).is_some() {
                return Some(existing_cc);
            }

            let mut directives = DirectiveMap::with_capacity(existing_cc.directives.len() + 1);

            for (key, value) in &existing_cc.directives {
                if key != "max-age" {
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                }
            }

            let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
            directives.insert("max-age".to_string(), Some(max_age_value));

            Some(CacheControl { directives })
        }
        None => {
            let mut directives = DirectiveMap::with_capacity(1);
            let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
            directives.insert("max-age".to_string(), Some(max_age_value));

            Some(CacheControl { directives })
        }
    }
}