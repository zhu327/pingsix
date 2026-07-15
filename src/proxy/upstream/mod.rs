//! Upstream management module.
//!
//! This module contains all the upstream-related functionality including:
//! - Service discovery (DNS and static)
//! - Load balancing and backend selection
//! - Health checking and monitoring

pub mod discovery;
pub mod health_check;
pub mod load_balancer;

use std::collections::HashMap;

pub(crate) use discovery::prepare_static_upstream;

pub(crate) type PreparedUpstreams = HashMap<String, discovery::PreparedUpstream>;

pub(crate) fn named_key(id: &str) -> String {
    format!("named/{id}")
}

pub(crate) fn inline_key(owner: &str) -> String {
    format!("inline/{owner}")
}

pub(crate) fn traffic_split_key(owner: &str, rule: usize, upstream: usize) -> String {
    format!("traffic-split/{owner}/{rule}/{upstream}")
}

// Re-export commonly used items
pub use health_check::SHARED_HEALTH_CHECK_SERVICE;
pub use load_balancer::ProxyUpstream;
