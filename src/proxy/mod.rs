use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Response, StatusCode};
use once_cell::sync::Lazy;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use router::{MatchEntry, ProxyRouter};

pub mod discovery;
pub mod lb;
pub mod router;

static NOT_FOUND: Lazy<Bytes> = Lazy::new(|| Bytes::from("not found"));

#[derive(Default)]
pub struct ProxyContext {
    pub router: Option<Arc<ProxyRouter>>,
    pub router_params: HashMap<String, String>,

    pub tries: usize,
    pub created_at: u64,
}

#[derive(Default)]
pub struct ProxyService {
    pub matcher: MatchEntry,
}

impl ProxyService {
    pub fn new() -> ProxyService {
        ProxyService {
            matcher: MatchEntry::default(),
        }
    }
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
            ctx.router = Some(Arc::clone(&router));
        } else {
            send_response(
                session,
                StatusCode::NOT_FOUND,
                None,
                Some(NOT_FOUND.clone()),
                None,
            )
            .await?;
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
        let reties = ctx.router.as_ref().unwrap().lb.get_retries();
        if reties.is_none() || matches!(reties, Some(0)) {
            return e;
        }

        let retry_timeout = ctx.router.as_ref().unwrap().lb.get_retry_timeout();
        if let Some(timeout) = retry_timeout {
            if (now().as_millis() as u64) - ctx.created_at > (timeout * 1000) {
                return e;
            }
        }

        if ctx.tries > reties.unwrap() {
            return e;
        }

        // retry
        ctx.tries += 1;
        e.set_retry(true);
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

pub async fn send_response(
    session: &mut Session,
    status: StatusCode,
    content_type: Option<&'static str>,
    body: Option<Bytes>,
    headers: Option<HashMap<String, String>>,
) -> Result<()> {
    let cl = body.as_ref().map(|b| b.len()).unwrap_or(0);
    let mut bd = Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, cl);
    if let Some(headers) = headers {
        for (key, value) in headers {
            bd = bd.header(key, value);
        }
    }
    if let Some(content_type) = content_type {
        bd = bd.header(header::CONTENT_TYPE, content_type);
    } else {
        bd = bd.header(header::CONTENT_TYPE, "text/plain");
    }

    if let Some(body) = body {
        let resp = bd.body(body).unwrap();
        let (parts, body) = resp.into_parts();
        let resp_header: ResponseHeader = parts.into();
        session
            .write_response_header(Box::new(resp_header), false)
            .await?;
        session.write_response_body(Some(body), true).await
    } else {
        let resp = bd.body(()).unwrap();
        let (parts, _) = resp.into_parts();
        let resp_header: ResponseHeader = parts.into();
        session
            .write_response_header(Box::new(resp_header), false)
            .await?;
        session.write_response_body(None, true).await
    }
}

pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}
