//! Plugin adapter layer
//!
//! This module provides adapters to bridge the existing plugin system
//! with the new PluginInterface, enabling gradual migration.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::core::{
    context::ProxyContext,
    error::ProxyResult,
};

use super::{
    manager::PluginInterface,
    ProxyPlugin, // The existing plugin trait
};

/// Adapter that wraps existing ProxyPlugin to implement new PluginInterface
pub struct PluginAdapter {
    inner: Arc<dyn ProxyPlugin>,
}

impl PluginAdapter {
    /// Create a new adapter for an existing plugin
    pub fn new(plugin: Arc<dyn ProxyPlugin>) -> Self {
        Self { inner: plugin }
    }

    /// Convert ProxyResult to pingora Result for compatibility
    fn convert_result<T>(result: ProxyResult<T>) -> pingora_error::Result<T> {
        result.map_err(|e| -> Box<pingora_error::Error> { e.into() })
    }
}

#[async_trait]
impl PluginInterface for PluginAdapter {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn priority(&self) -> i32 {
        self.inner.priority()
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        // Convert new ProxyContext to old format for compatibility
        let mut old_ctx = self.convert_context_to_old(ctx);
        
        let result = self.inner.early_request_filter(session, &mut old_ctx).await;
        
        // Convert back any changes
        self.convert_context_from_old(ctx, &old_ctx);
        
        Self::convert_result(result.map_err(Into::into))
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<bool> {
        let mut old_ctx = self.convert_context_to_old(ctx);
        
        let result = self.inner.request_filter(session, &mut old_ctx).await;
        
        self.convert_context_from_old(ctx, &old_ctx);
        
        Self::convert_result(result.map_err(Into::into))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        let mut old_ctx = self.convert_context_to_old(ctx);
        
        let result = self.inner.upstream_request_filter(session, upstream_request, &mut old_ctx).await;
        
        self.convert_context_from_old(ctx, &old_ctx);
        
        Self::convert_result(result.map_err(Into::into))
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        let mut old_ctx = self.convert_context_to_old(ctx);
        
        let result = self.inner.response_filter(session, upstream_response, &mut old_ctx).await;
        
        self.convert_context_from_old(ctx, &old_ctx);
        
        Self::convert_result(result.map_err(Into::into))
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()> {
        let mut old_ctx = self.convert_context_to_old(ctx);
        
        let result = self.inner.response_body_filter(session, body, end_of_stream, &mut old_ctx);
        
        self.convert_context_from_old(ctx, &old_ctx);
        
        Self::convert_result(result.map_err(Into::into))
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora_error::Error>,
        ctx: &mut ProxyContext,
    ) {
        let mut old_ctx = self.convert_context_to_old(ctx);
        
        self.inner.logging(session, error, &mut old_ctx).await;
        
        self.convert_context_from_old(ctx, &old_ctx);
    }

    // Helper methods for context conversion
    fn convert_context_to_old(&self, _new_ctx: &ProxyContext) -> crate::proxy::ProxyContext {
        // For now, create a default old context
        // In a real implementation, you'd convert the data
        crate::proxy::ProxyContext::default()
    }

    fn convert_context_from_old(&self, _new_ctx: &mut ProxyContext, _old_ctx: &crate::proxy::ProxyContext) {
        // Convert any changes back to the new context
        // This is where you'd sync any state changes
    }
}