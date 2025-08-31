//! Request execution orchestration
//!
//! This module coordinates the execution of requests through
//! the plugin pipeline and upstream selection.

use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::{
    core::{
        container::ServiceContainer,
        context::ProxyContext,
        traits::{PluginExecutor, RouteResolver},
        ProxyResult,
    },
};

/// Orchestrates request execution through the plugin pipeline
pub struct RequestExecutor {
    /// Service container with all dependencies
    container: Arc<ServiceContainer>,
}

impl RequestExecutor {
    /// Create a new request executor
    pub fn new(container: Arc<ServiceContainer>) -> Self {
        Self { container }
    }

    /// Execute the complete request pipeline
    pub async fn execute_request(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<bool> {
        // Early request filter phase
        self.execute_early_request_filter(session, ctx).await?;

        // Request filter phase
        if self.execute_request_filter(session, ctx).await? {
            return Ok(true); // Request was handled by a plugin
        }

        // Upstream selection
        let _peer = self.select_upstream_peer(session, ctx).await?;

        Ok(false)
    }

    /// Execute early request filters
    async fn execute_early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        // Execute global plugins first
        ctx.global_plugin_executor
            .early_request_filter(session, ctx)
            .await?;

        // Execute route-specific plugins
        ctx.plugin_executor
            .early_request_filter(session, ctx)
            .await?;

        Ok(())
    }

    /// Execute request filters
    async fn execute_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<bool> {
        // Execute global plugins first
        if ctx
            .global_plugin_executor
            .request_filter(session, ctx)
            .await?
        {
            return Ok(true);
        }

        // Execute route-specific plugins
        ctx.plugin_executor.request_filter(session, ctx).await
    }

    /// Select upstream peer for the request
    async fn select_upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<Box<HttpPeer>> {
        let route = ctx.route.as_ref().ok_or_else(|| {
            crate::core::error::ProxyError::RouteMatching("No route matched".to_string())
        })?;

        let peer = route.select_http_peer(session)?;
        
        // Store upstream info in context
        ctx.set("upstream", peer._address.to_string());
        
        Ok(peer)
    }

    /// Execute upstream request filters
    pub async fn execute_upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        // Execute global plugins
        ctx.global_plugin_executor
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        // Execute route-specific plugins
        ctx.plugin_executor
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        Ok(())
    }

    /// Execute response filters
    pub async fn execute_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        // Execute global plugins
        ctx.global_plugin_executor
            .response_filter(session, upstream_response, ctx)
            .await?;

        // Execute route-specific plugins
        ctx.plugin_executor
            .response_filter(session, upstream_response, ctx)
            .await?;

        Ok(())
    }
}