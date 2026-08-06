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

/// One upstream occurrence in the configuration graph.
///
/// Replaces the former `named/…`, `inline/…`, `traffic-split/…` string keys so
/// occurrence identity is typed and shared by preparation, compilation, and
/// health-check reconciliation without string-format coupling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum UpstreamOccurrence {
    /// A top-level named upstream.
    Named(String),
    /// An inline upstream declared directly on a route.
    RouteInline(String),
    /// An inline upstream declared directly on a service.
    ServiceInline(String),
    /// An inline upstream embedded in a `traffic-split` plugin.
    TrafficSplit(TrafficSplitOwner, usize, usize),
}

/// The configuration scope that owns a traffic-split inline upstream.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TrafficSplitOwner {
    Route(String),
    Service(String),
    GlobalRule(String),
}

pub(crate) type PreparedUpstreams = HashMap<UpstreamOccurrence, discovery::PreparedUpstream>;

// Re-export commonly used items
pub use health_check::SHARED_HEALTH_CHECK_SERVICE;
pub use load_balancer::ProxyUpstream;
