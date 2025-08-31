//! Core traits for PingSIX components
//!
//! This module defines the fundamental interfaces that decouple
//! different layers of the application architecture.

use std::sync::Arc;
use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;
use pingora_load_balancing::Backend;

use super::{context::ProxyContext, error::ProxyResult};

/// Trait for upstream selection and load balancing
#[async_trait]
pub trait UpstreamProvider: Send + Sync {
    /// Select a backend for the given session
    fn select_backend(&self, session: &Session) -> Option<Backend>;
    
    /// Get the upstream ID
    fn id(&self) -> &str;
    
    /// Get retry configuration
    fn get_retries(&self) -> Option<usize>;
    fn get_retry_timeout(&self) -> Option<u64>;
}

/// Trait for service configuration and management
pub trait ServiceProvider: Send + Sync {
    /// Get the service ID
    fn id(&self) -> &str;
    
    /// Get the associated upstream provider
    fn get_upstream_provider(&self) -> Option<Arc<dyn UpstreamProvider>>;
    
    /// Get service-level configuration
    fn get_hosts(&self) -> &[String];
}

/// Trait for route matching and resolution
pub trait RouteResolver: Send + Sync {
    /// Get the route ID
    fn id(&self) -> &str;
    
    /// Resolve the upstream for this route
    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamProvider>>;
    
    /// Select an HTTP peer for the request
    fn select_http_peer(&self, session: &mut Session) -> ProxyResult<Box<HttpPeer>>;
    
    /// Get route priority
    fn priority(&self) -> u32;
}

/// Trait for plugin execution
#[async_trait]
pub trait PluginExecutor: Send + Sync {
    /// Execute early request filters
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()>;
    
    /// Execute request filters
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<bool>;
    
    /// Execute upstream request filters
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()>;
    
    /// Execute response filters
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<()>;
}

/// Trait for resource management operations
pub trait ResourceManager<T>: Send + Sync {
    /// Get a resource by ID
    fn get(&self, id: &str) -> Option<Arc<T>>;
    
    /// Insert or update a resource
    fn insert(&self, id: String, resource: Arc<T>);
    
    /// Remove a resource
    fn remove(&self, id: &str) -> Option<Arc<T>>;
    
    /// List all resources
    fn list(&self) -> Vec<Arc<T>>;
    
    /// Bulk reload resources
    fn reload(&self, resources: Vec<Arc<T>>);
}

/// Trait for health checking
#[async_trait]
pub trait HealthChecker: Send + Sync {
    /// Register an upstream for health checking
    async fn register_upstream(&self, upstream: Arc<dyn UpstreamProvider>) -> ProxyResult<()>;
    
    /// Unregister an upstream
    async fn unregister_upstream(&self, upstream_id: &str) -> ProxyResult<()>;
    
    /// Get health status
    fn is_healthy(&self, upstream_id: &str, backend_addr: &str) -> bool;
}