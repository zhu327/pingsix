use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora::modules::http::HttpModules;
use pingora::modules::http::{compression::ResponseCompressionBuilder, grpc_web::GrpcWeb};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

use crate::config::Config;
use crate::proxy::plugin::{build_plugin, build_plugin_executor, ProxyPlugin};
use crate::proxy::router::{MatchEntry, ProxyRouter};
use crate::proxy::upstream::ProxyUpstream;
use crate::proxy::ProxyContext;

/// Proxy service.
///
/// Manages the proxying of requests to upstream servers.
#[derive(Default)]
pub struct HttpService {
    pub matcher: MatchEntry,
}

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

        // execute plugins
        ctx.plugin.clone().request_filter(session, ctx).await
    }

    /// Handle the incoming request before any downstream module is executed.
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Match request to pipeline
        if let Some((router_params, router)) = self.matcher.match_request(session) {
            ctx.router_params = router_params;
            ctx.router = Some(router.clone());
            ctx.plugin = build_plugin_executor(router);
        }

        // execute plugins
        ctx.plugin.clone().early_request_filter(session, ctx).await
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

    // Modify the request before it is sent to the upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
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

/// Initializes a proxy service from the given configuration.
pub fn build_http_service(config: &Config) -> Result<HttpService> {
    let mut http_service = HttpService::default();
    for router in config.routers.iter() {
        log::info!("Configuring Router: {}", router.id);
        let mut proxy_router = ProxyRouter::from(router.clone());

        if let Some(upstream) = router.upstream.clone() {
            let mut proxy_upstream = ProxyUpstream::try_from(upstream)?;
            proxy_upstream.start_health_check(config.pingora.work_stealing);

            proxy_router.upstream = Some(Arc::new(proxy_upstream));
        }

        // load router plugins
        for (name, value) in router.plugins.iter() {
            let plugin = build_plugin(name, value.clone())?;
            proxy_router.plugins.push(plugin);
        }

        http_service.matcher.insert_router(proxy_router).unwrap();
    }

    Ok(http_service)
}
