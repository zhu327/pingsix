//! Upstream backend selection (priority + health).
//!
//! Same node `priority` values form a group. Selection prefers the highest
//! priority group that still has at least one ready (healthy + enabled)
//! backend. When no group has a ready backend, selection falls back to the
//! full set using the configured load-balancing algorithm (ignoring health).

use pingora_load_balancing::{
    selection::{BackendIter, BackendSelection},
    Backend, LoadBalancer,
};
use std::collections::BTreeSet;

/// Opaque backend metadata: node priority (`i8`, default 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodePriority(pub i8);

pub(crate) fn set_backend_priority(backend: &mut Backend, priority: i8) {
    backend.ext.insert(NodePriority(priority));
}

pub(crate) fn backend_priority(backend: &Backend) -> i8 {
    backend.ext.get::<NodePriority>().map(|p| p.0).unwrap_or(0)
}

/// Insert `backend` into `set`, keeping the higher priority when Pingora identity
/// collides (same addr + weight; `ext` is ignored by `Backend` equality).
///
/// Config validation already rejects duplicate `host:port` among enabled nodes,
/// so a collision here means two distinct hostnames resolved to the same
/// address. Dropping the lower priority is the only representable outcome.
pub(crate) fn insert_backend(set: &mut BTreeSet<Backend>, backend: Backend) {
    let Some(existing) = set.get(&backend).cloned() else {
        set.insert(backend);
        return;
    };

    let (new_priority, existing_priority) =
        (backend_priority(&backend), backend_priority(&existing));
    if new_priority == existing_priority {
        return;
    }

    log::warn!(
        "backend {} resolved twice with different priorities ({existing_priority}, {new_priority}); keeping {}",
        backend.addr,
        new_priority.max(existing_priority)
    );

    if new_priority > existing_priority {
        set.remove(&existing);
        set.insert(backend);
    }
}

/// Distinct node priority levels (highest → lowest), precomputed once at upstream
/// construction so request-time selection never scans the backend set or allocates.
///
/// Built from the prepared backend set (not raw config) so collapsed duplicate
/// addresses cannot leave ghost levels behind.
#[derive(Debug, Clone)]
pub(crate) struct PriorityLevels {
    levels: Box<[i8]>,
}

impl PriorityLevels {
    pub(crate) fn from_backends(backends: &BTreeSet<Backend>) -> Self {
        backends.iter().map(backend_priority).collect()
    }

    /// Whether grouping can be skipped: no backends, or all of them share one
    /// priority.
    fn is_single_group(&self) -> bool {
        self.levels.len() <= 1
    }

    fn iter(&self) -> std::slice::Iter<'_, i8> {
        self.levels.iter()
    }
}

impl FromIterator<i8> for PriorityLevels {
    fn from_iter<I: IntoIterator<Item = i8>>(iter: I) -> Self {
        let mut levels: Vec<i8> = iter.into_iter().collect();
        levels.sort_unstable_by(|a, b| b.cmp(a));
        levels.dedup();
        Self {
            levels: levels.into_boxed_slice(),
        }
    }
}

/// Select a backend: highest ready priority group, else all-unready fallback.
pub(crate) fn select_backend<BS>(
    lb: &LoadBalancer<BS>,
    levels: &PriorityLevels,
    key: &[u8],
    max_iterations: usize,
) -> Option<Backend>
where
    BS: BackendSelection + 'static,
    BS::Iter: BackendIter,
{
    // Common case: every backend shares one priority, so grouping cannot change
    // the outcome. Skip the per-candidate priority lookup entirely.
    if levels.is_single_group() {
        let backend = lb
            .select(key, max_iterations)
            .or_else(|| lb.select_with(key, max_iterations, |_, _| true));
        if let Some(ref backend) = backend {
            log::debug!(
                "proxy lb select: {} priority={} (single group)",
                backend.addr,
                backend_priority(backend)
            );
        }
        return backend;
    }

    // Multiple levels: probe distinct priorities from highest to lowest and pick
    // the first level that still has a ready backend.
    for &prio in levels.iter() {
        if let Some(backend) = lb.select_with(key, max_iterations, |candidate, ready| {
            ready && backend_priority(candidate) == prio
        }) {
            log::debug!("proxy lb select: {} priority={}", backend.addr, prio);
            return Some(backend);
        }
        log::debug!("proxy lb select: no ready backend at priority={prio}");
    }

    // No ready backend in any priority group, ignoring health.
    let backend = lb.select_with(key, max_iterations, |_, _| true);
    if let Some(ref backend) = backend {
        log::debug!(
            "proxy lb select: {} priority={} (all-unready fallback)",
            backend.addr,
            backend_priority(backend)
        );
    }
    backend
}

#[cfg(test)]
mod tests {

    use super::*;
    use futures::FutureExt;
    use pingora_load_balancing::{
        discovery::Static, selection::RoundRobin, Backend, Backends, LoadBalancer,
    };
    use std::collections::BTreeSet;

    fn lb_from(nodes: &[(&str, i8)]) -> (LoadBalancer<RoundRobin>, PriorityLevels) {
        let mut backends = BTreeSet::new();
        for &(addr, priority) in nodes {
            let mut backend = Backend::new_with_weight(addr, 1).unwrap();
            set_backend_priority(&mut backend, priority);
            backends.insert(backend);
        }
        let levels = PriorityLevels::from_backends(&backends);
        let lb = LoadBalancer::<RoundRobin>::from_backends(Backends::new(Static::new(backends)));
        lb.update()
            .now_or_never()
            .expect("static discovery is ready")
            .expect("static discovery succeeds");
        (lb, levels)
    }

    fn set_ready(lb: &LoadBalancer<RoundRobin>, addr: &str, enabled: bool) {
        for backend in lb.backends().get_backend().iter() {
            if backend.addr.to_string() == addr {
                lb.backends().set_enable(backend, enabled);
            }
        }
    }

    fn pick_addr(lb: &LoadBalancer<RoundRobin>, levels: &PriorityLevels) -> String {
        select_backend(lb, levels, b"", 256)
            .expect("expected a backend")
            .addr
            .to_string()
    }

    #[test]
    fn selects_highest_ready_group_then_recovers() {
        let high = "127.0.0.1:18081";
        let low = "127.0.0.1:18082";
        let (lb, levels) = lb_from(&[(high, 10), (low, 0)]);

        assert_eq!(pick_addr(&lb, &levels), high);

        set_ready(&lb, high, false);
        assert_eq!(
            pick_addr(&lb, &levels),
            low,
            "must fall over to lower priority when highest group is not ready"
        );

        set_ready(&lb, high, true);
        assert_eq!(
            pick_addr(&lb, &levels),
            high,
            "must recover to highest priority on the next select"
        );
    }

    #[test]
    fn all_unready_falls_back_ignoring_health() {
        let a = "127.0.0.1:18091";
        let b = "127.0.0.1:18092";
        let (lb, levels) = lb_from(&[(a, 5), (b, 1)]);
        set_ready(&lb, a, false);
        set_ready(&lb, b, false);

        let addr = pick_addr(&lb, &levels);
        assert!(
            addr == a || addr == b,
            "all-unready fallback must still pick via the LB algorithm: {addr}"
        );
    }

    #[test]
    fn prefers_zero_over_negative_and_negative_over_lower() {
        let high = "127.0.0.1:18201";
        let mid = "127.0.0.1:18202";
        let low = "127.0.0.1:18203";
        let (lb, levels) = lb_from(&[(high, 0), (mid, -1), (low, -2)]);
        assert_eq!(&*levels.levels, &[0, -1, -2]);
        assert_eq!(pick_addr(&lb, &levels), high);

        set_ready(&lb, high, false);
        assert_eq!(pick_addr(&lb, &levels), mid);

        set_ready(&lb, mid, false);
        assert_eq!(pick_addr(&lb, &levels), low);
    }

    #[test]
    fn single_group_skips_priority_filter_and_still_honors_health() {
        let a = "127.0.0.1:18211";
        let b = "127.0.0.1:18212";
        let (lb, levels) = lb_from(&[(a, 7), (b, 7)]);
        assert!(
            levels.is_single_group(),
            "one distinct priority must take the fast path"
        );

        set_ready(&lb, a, false);
        assert_eq!(pick_addr(&lb, &levels), b);
    }

    #[test]
    fn insert_backend_keeps_higher_priority_on_addr_collision() {
        let mut set = BTreeSet::new();
        let mut low = Backend::new_with_weight("127.0.0.1:443", 1).unwrap();
        set_backend_priority(&mut low, -1);
        insert_backend(&mut set, low);

        let mut high = Backend::new_with_weight("127.0.0.1:443", 1).unwrap();
        set_backend_priority(&mut high, 10);
        insert_backend(&mut set, high);

        assert_eq!(set.len(), 1);
        assert_eq!(backend_priority(set.iter().next().unwrap()), 10);
    }
}
