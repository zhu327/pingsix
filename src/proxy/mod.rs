use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use http::StatusCode;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_proxy::{ProxyHttp, Session};

use router::{MatchEntry, ProxyRouter};
use upstream::ProxyUpstream;

use crate::config::Config;

pub mod discovery;
pub mod router;
pub mod service;
pub mod upstream;

/// Proxy context.
///
/// Holds the context for each request.
pub struct ProxyContext {
    pub router: Option<Arc<ProxyRouter>>,
    pub router_params: BTreeMap<String, String>,

    pub tries: usize,
    pub request_start: Instant,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            router: None,
            router_params: BTreeMap::new(),
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
        } else {
            let _ = session.respond_error(StatusCode::NOT_FOUND.as_u16()).await;
            return Ok(true);
        }

        Ok(false)
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
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // TODO: plugin may rewrite the host header, so we should check the order of the headers
        let upstream = ctx.router.as_ref().unwrap().get_upstream().unwrap();
        upstream.upstream_host_rewrite(upstream_request);
        Ok(())
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
