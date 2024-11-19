use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use http::StatusCode;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_proxy::{ProxyHttp, Session};

use router::{MatchEntry, ProxyRouter};

pub mod discovery;
pub mod lb;
pub mod router;

/// Proxy context.
///
/// Holds the context for each request.
pub struct ProxyContext {
    pub router: Option<Arc<ProxyRouter>>,
    pub router_params: HashMap<String, String>,

    pub tries: usize,
    pub request_start: Instant,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            router: None,
            router_params: HashMap::new(),
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
            if let Some(retries) = router.lb.get_retries() {
                if retries == 0 || ctx.tries >= retries {
                    return e;
                }

                if let Some(timeout) = router.lb.get_retry_timeout() {
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
        ctx.router
            .as_ref()
            .unwrap()
            .lb
            .upstream_host_rewrite(upstream_request);
        Ok(())
    }
}
