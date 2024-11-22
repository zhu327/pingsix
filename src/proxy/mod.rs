use std::sync::Arc;
use std::time::Instant;
use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use plugin::{PluginExecutor, ProxyPlugin};
use router::{MatchEntry, ProxyRouter};
use upstream::ProxyUpstream;

use crate::config::Config;

pub mod discovery;
pub mod plugin;
pub mod router;
pub mod service;
pub mod upstream;

/// Proxy context.
///
/// Holds the context for each request.
pub struct ProxyContext {
    pub router: Option<Arc<ProxyRouter>>,
    pub router_params: BTreeMap<String, String>,

    pub plugin: Arc<PluginExecutor>,

    pub tries: usize,
    pub request_start: Instant,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            router: None,
            router_params: BTreeMap::new(),
            plugin: Arc::new(PluginExecutor::default()),
            tries: 0,
            request_start: Instant::now(),
        }
    }
}

/// Proxy service.
///
/// Manages the proxying of requests to upstream servers.
#[derive(Default)]
pub struct ProxyService {
    pub matcher: MatchEntry,
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = ProxyContext;

    /// Creates a new context for each request
    fn new_ctx(&self) -> Self::CTX {
        Self::CTX::default()
    }

    /// Filters incoming requests
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        // Match request to pipeline
        if let Some((router_params, router)) = self.matcher.match_request(session) {
            ctx.router_params = router_params;
            ctx.router = Some(router);
            // TODO: match router plugins
        } else {
            let _ = session.respond_error(StatusCode::NOT_FOUND.as_u16()).await;
            return Ok(true);
        }

        // execute plugins
        ctx.plugin.clone().request_filter(session, ctx).await
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // execute plugins
        ctx.plugin
            .clone()
            .request_body_filter(session, body, end_of_stream, ctx)
            .await
    }

    /// This filter is called when there is an error in the process of establishing a connection to the upstream.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(router) = ctx.router.as_ref() {
            let upstream = router.get_upstream().unwrap();

            if let Some(retries) = upstream.get_retries() {
                if retries == 0 || ctx.tries >= retries {
                    return e;
                }

                if let Some(timeout) = upstream.get_retry_timeout() {
                    if ctx.request_start.elapsed().as_millis() > (timeout * 1000) as u128 {
                        return e;
                    }
                }

                ctx.tries += 1;
                e.set_retry(true);
                return e;
            }
        }

        e
    }

    /// Selects an upstream peer for the request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        ctx.router.as_ref().unwrap().select_http_peer(session)
    }

    // Modify the request before it is sent to the upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // execute plugins
        ctx.plugin
            .clone()
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        // rewrite host header
        let upstream = ctx.router.as_ref().unwrap().get_upstream().unwrap();
        upstream.upstream_host_rewrite(upstream_request);
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // execute plugins
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
        // execute plugins
        ctx.plugin
            .clone()
            .response_body_filter(session, body, end_of_stream, ctx)?;
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        // execute plugins
        ctx.plugin.clone().logging(session, e, ctx).await;
    }
}

/// Initializes a proxy service from the given configuration.
pub fn init_proxy_service(config: &Config) -> Result<ProxyService> {
    let mut proxy_service = ProxyService::default();
    for router in config.routers.iter() {
        log::info!("Configuring Router: {}", router.id);
        let mut proxy_router = ProxyRouter::from(router.clone());

        if let Some(upstream) = router.upstream.clone() {
            let mut proxy_upstream = ProxyUpstream::try_from(upstream)?;
            proxy_upstream.start_health_check(config.pingora.work_stealing);

            proxy_router.upstream = Some(Arc::new(proxy_upstream));
        }

        proxy_service.matcher.insert_router(proxy_router).unwrap();
    }

    Ok(proxy_service)
}
