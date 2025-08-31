//! Upstream management module.
//!
//! This module contains all the upstream-related functionality including:
//! - Service discovery (DNS and static)
//! - Load balancing and backend selection
//! - Health checking and monitoring

pub mod discovery;
pub mod health_check;
pub mod load_balancer;

// Re-export commonly used items
pub use health_check::SHARED_HEALTH_CHECK_SERVICE;
pub use load_balancer::{load_static_upstreams, upstream_fetch, ProxyUpstream, UPSTREAM_MAP};
