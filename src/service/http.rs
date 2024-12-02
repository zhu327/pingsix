use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora::modules::http::{
    HttpModules,
    {compression::ResponseCompressionBuilder, grpc_web::GrpcWeb},
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

use crate::proxy::{
    global_rule::global_plugin_fetch,
    plugin::{build_plugin_executor, ProxyPlugin},
    router::global_match_fetch,
    ProxyContext,
};

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

    /// Selects an upstream peer for the request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = ctx.router.as_ref().unwrap().select_http_peer(session);
        if let Ok(ref p) = peer {
            ctx.vars
                .insert("upstream".to_string(), p._address.to_string());
        }
        peer
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

    /// Filters incoming requests
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if ctx.router.is_none() {
            session
                .respond_error(StatusCode::NOT_FOUND.as_u16())
                .await?;
            return Ok(true);
        }

        // execute global rule plugins
        if global_plugin_fetch().request_filter(session, ctx).await? {
            return Ok(true);
        };

        // execute plugins
        ctx.plugin.clone().request_filter(session, ctx).await
    }

    /// Handle the incoming request before any downstream module is executed.
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Match request to pipeline
        if let Some((router_params, router)) = global_match_fetch().match_request(session) {
            ctx.router_params = Some(router_params);
            ctx.router = Some(router.clone());
            ctx.plugin = build_plugin_executor(router);
        }

        // execute global rule plugins
        global_plugin_fetch()
            .early_request_filter(session, ctx)
            .await?;

        // execute plugins
        ctx.plugin.clone().early_request_filter(session, ctx).await
    }

    // Modify the request before it is sent to the upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // execute global rule plugins
        global_plugin_fetch()
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

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
        // execute global rule plugins
        global_plugin_fetch()
            .response_filter(session, upstream_response, ctx)
            .await?;

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
        // execute global rule plugins
        global_plugin_fetch().response_body_filter(session, body, end_of_stream, ctx)?;

        // execute plugins
        ctx.plugin
            .clone()
            .response_body_filter(session, body, end_of_stream, ctx)?;
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        // execute global rule plugins
        global_plugin_fetch().logging(session, e, ctx).await;

        // execute plugins
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
}
