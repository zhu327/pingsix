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
    route::global_route_match_fetch,
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
            ctx.route = Some(route.clone());
            ctx.plugin = build_plugin_executor(route);

            ctx.global_plugin = global_plugin_fetch();
        }

        // execute global rule plugins
        ctx.global_plugin
            .clone()
            .early_request_filter(session, ctx)
            .await?;

        // execute plugins
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

        // execute global rule plugins
        if ctx
            .global_plugin
            .clone()
            .request_filter(session, ctx)
            .await?
        {
            return Ok(true);
        };

        // execute plugins
        ctx.plugin.clone().request_filter(session, ctx).await
    }

    /// Selects an upstream peer for the request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let peer = ctx.route.as_ref().unwrap().select_http_peer(session);
        if let Ok(ref peer) = peer {
            ctx.vars
                .insert("upstream".to_string(), peer._address.to_string());
        }
        peer
    }

    // Modify the request before it is sent to the upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // execute global rule plugins
        ctx.global_plugin
            .clone()
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        // execute plugins
        ctx.plugin
            .clone()
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        // rewrite host header
        if let Some(upstream) = ctx.route.as_ref().and_then(|r| r.resolve_upstream()) {
            upstream.upstream_host_rewrite(upstream_request);
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // execute global rule plugins
        ctx.global_plugin
            .clone()
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
        ctx.global_plugin
            .clone()
            .response_body_filter(session, body, end_of_stream, ctx)?;

        // execute plugins
        ctx.plugin
            .clone()
            .response_body_filter(session, body, end_of_stream, ctx)?;
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        // execute global rule plugins
        ctx.global_plugin.clone().logging(session, e, ctx).await;

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
        if let Some(route) = ctx.route.as_ref() {
            if let Some(upstream) = route.resolve_upstream() {
                if let Some(retries) = upstream.get_retries() {
                    if retries > 0 && ctx.tries < retries {
                        if let Some(timeout) = upstream.get_retry_timeout() {
                            if ctx.request_start.elapsed().as_millis() <= (timeout * 1000) as _ {
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
