use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use super::ProxyContext;

/*
5. 考虑下插件的加载
    1. 插件可能是从service_id来的，也可能是直接从router来的
    2. router上要有插件的绑定，service也可能有
    3. 可能需要有一个插件的runner来包装在ctx上，执行的时候clone出来
    4. 在router匹配之后，然后组合排序去重把插件加载到ctx
*/

#[async_trait]
pub trait ProxyPlugin: Send + Sync {
    /// Return the name of this plugin
    ///
    /// # Returns
    /// * `&str` - The name of this plugin
    fn name(&self) -> &str;

    /// Return the priority of this plugin
    ///
    /// # Returns
    /// * `i32` - The priority of this plugin
    fn priority(&self) -> i32;

    /// Handle the incoming request.
    ///
    /// In this phase, users can parse, validate, rate limit, perform access control and/or
    /// return a response for this request.
    /// Like APISIX rewrite access phase.
    ///
    /// # Arguments
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_ctx` - Mutable reference to the plugin context
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if a response was sent and the proxy should exit
    /// * `Ok(false)` if the proxy should continue to the next phase
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Handle the incoming request body.
    ///
    /// This function will be called every time a piece of request body is received.
    ///
    /// # Arguments
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_body` - Mutable reference to an optional Bytes containing the body chunk
    /// * `_end_of_stream` - Boolean indicating if this is the last chunk
    /// * `_ctx` - Mutable reference to the plugin context
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the request before it is sent to the upstream
    ///
    /// # Arguments
    /// Like APISIX before_proxy phase.
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_upstream_request` - Mutable reference to the upstream request header
    /// * `_ctx` - Mutable reference to the plugin context
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the response header before it is sent to the downstream
    ///
    /// # Arguments
    /// Like APISIX header_filter phase.
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_upstream_response` - Mutable reference to the upstream response header
    /// * `_ctx` - Mutable reference to the plugin context
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Handle the response body chunks
    ///
    /// # Arguments
    /// Like APISIX body_filter phase.
    ///
    /// * `_session` - Mutable reference to the current session
    /// * `_body` - Mutable reference to an optional Bytes containing the body chunk
    /// * `_end_of_stream` - Boolean indicating if this is the last chunk
    /// * `_ctx` - Mutable reference to the plugin context
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// This filter is called when the entire response is sent to the downstream successfully or
    /// there is a fatal error that terminate the request.
    ///
    /// An error log is already emitted if there is any error. This phase is used for collecting
    /// metrics and sending access logs.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut ProxyContext) {}
}

#[derive(Default)]
pub struct PluginExecutor {
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

#[async_trait]
impl ProxyPlugin for PluginExecutor {
    fn name(&self) -> &str {
        "plugin-executor"
    }

    fn priority(&self) -> i32 {
        0
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        for plugin in self.plugins.iter() {
            if plugin.request_filter(session, ctx).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin
                .request_body_filter(session, body, end_of_stream, ctx)
                .await?;
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin
                .upstream_request_filter(session, upstream_request, ctx)
                .await?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin
                .response_filter(session, upstream_response, ctx)
                .await?;
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for plugin in self.plugins.iter() {
            plugin.response_body_filter(session, body, end_of_stream, ctx)?;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        for plugin in self.plugins.iter() {
            plugin.logging(session, e, ctx).await;
        }
    }
}
