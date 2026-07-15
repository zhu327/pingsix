//! Service readiness and etcd sync status for probes and diagnostics.

use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use serde::Serialize;

/// Configuration source type for better error reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigSource {
    Yaml,
    Etcd,
}

impl ConfigSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfigSource::Yaml => "yaml",
            ConfigSource::Etcd => "etcd",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatusView {
    pub initialized: bool,
    pub ready: bool,
    pub config_source: Option<&'static str>,
    /// Last successfully observed/processed etcd revision (watch cursor / list header).
    pub observed_revision: Option<i64>,
    /// Revision embedded in the currently published runtime snapshot.
    pub published_revision: Option<i64>,
    /// Alias of `observed_revision` for backward-compatible clients.
    pub revision: Option<i64>,
    pub connected: bool,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
    pub last_success_age_secs: Option<u64>,
    pub last_error: Option<String>,
}

struct RuntimeStatusInner {
    initialized: bool,
    config_source: Option<ConfigSource>,
    revision: Option<i64>,
    published_revision: Option<i64>,
    last_success: Option<Instant>,
    last_error: Option<String>,
    connected: bool,
    config_stale_after: Duration,
    fail_readiness_when_stale: bool,
}

impl Default for RuntimeStatusInner {
    fn default() -> Self {
        Self {
            initialized: false,
            config_source: None,
            revision: None,
            published_revision: None,
            last_success: None,
            last_error: None,
            connected: false,
            config_stale_after: Duration::from_secs(300),
            fail_readiness_when_stale: false,
        }
    }
}

static STATUS: Lazy<Mutex<RuntimeStatusInner>> =
    Lazy::new(|| Mutex::new(RuntimeStatusInner::default()));

// Fast path for readiness used on the hot path.
static READY_FAST: AtomicBool = AtomicBool::new(false);
static REVISION_FAST: AtomicI64 = AtomicI64::new(-1);

/// Configure stale-sync readiness behavior (typically from YAML status section).
pub fn configure_status_policy(config_stale_after_secs: u64, fail_readiness_when_stale: bool) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.config_stale_after = Duration::from_secs(config_stale_after_secs);
    status.fail_readiness_when_stale = fail_readiness_when_stale;
}

/// Mark the service as ready after successful configuration loading.
pub fn mark_ready(source: ConfigSource) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.initialized = true;
    status.config_source = Some(source);
    status.last_success = Some(Instant::now());
    status.last_error = None;
    if source == ConfigSource::Yaml {
        status.connected = true;
    }
    READY_FAST.store(true, Ordering::SeqCst);
    log::info!(
        "Configuration loaded from {}, service is ready",
        source.as_str()
    );
}

pub fn mark_etcd_connected(connected: bool) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.connected = connected;
}

pub fn set_revision(revision: Option<i64>) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.revision = revision;
    REVISION_FAST.store(revision.unwrap_or(-1), Ordering::SeqCst);
}

pub fn set_published_revision(revision: i64) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.published_revision = Some(revision);
}

pub fn record_sync_success(revision: i64) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.revision = Some(revision);
    status.last_success = Some(Instant::now());
    status.last_error = None;
    status.connected = true;
    status.initialized = true;
    if status.config_source.is_none() {
        status.config_source = Some(ConfigSource::Etcd);
    }
    READY_FAST.store(true, Ordering::SeqCst);
    REVISION_FAST.store(revision, Ordering::SeqCst);
}

pub fn record_sync_error(error: String) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.last_error = Some(error);
    status.connected = false;
}

/// Check if the service is ready to handle traffic.
pub fn is_ready() -> bool {
    let status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    compute_ready(&status)
}

pub fn is_live() -> bool {
    true
}

pub fn status_view() -> RuntimeStatusView {
    let status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    let stale = is_stale(&status);
    let ready = compute_ready(&status);
    let degraded = status.initialized && (!status.connected || stale);
    let degraded_reason = if !status.initialized {
        None
    } else if !status.connected {
        Some("etcd disconnected".into())
    } else if stale {
        Some("configuration sync is stale".into())
    } else {
        None
    };

    RuntimeStatusView {
        initialized: status.initialized,
        ready,
        config_source: status.config_source.map(|s| s.as_str()),
        observed_revision: status.revision,
        published_revision: status.published_revision,
        revision: status.revision,
        connected: status.connected,
        degraded,
        degraded_reason,
        last_success_age_secs: status.last_success.map(|t| t.elapsed().as_secs()),
        last_error: status.last_error.clone(),
    }
}

fn compute_ready(status: &RuntimeStatusInner) -> bool {
    if !status.initialized {
        return false;
    }
    if status.fail_readiness_when_stale && is_stale(status) {
        return false;
    }
    true
}

fn is_stale(status: &RuntimeStatusInner) -> bool {
    // Static YAML has no continuous sync; only etcd sync can become stale.
    if status.config_source != Some(ConfigSource::Etcd) {
        return false;
    }
    // A healthy idle watch (connected, possibly no config events) is not stale.
    // Staleness tracks prolonged disconnection / failed sync, not absence of puts.
    if status.connected {
        return false;
    }
    status
        .last_success
        .is_none_or(|t| t.elapsed() > status.config_stale_after)
}

/// Reset readiness status (useful for testing)
#[allow(dead_code)]
pub fn reset() {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    *status = RuntimeStatusInner::default();
    READY_FAST.store(false, Ordering::SeqCst);
    REVISION_FAST.store(-1, Ordering::SeqCst);
    log::debug!("Readiness status reset");
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_initial_state_not_ready() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        assert!(!is_ready());
    }

    #[test]
    fn test_mark_ready_yaml() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        assert!(!is_ready());
        mark_ready(ConfigSource::Yaml);
        assert!(is_ready());
    }

    #[test]
    fn test_mark_ready_etcd() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        assert!(!is_ready());
        mark_ready(ConfigSource::Etcd);
        assert!(is_ready());
    }

    #[test]
    fn test_multiple_marks_stay_ready() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        mark_ready(ConfigSource::Yaml);
        assert!(is_ready());
        mark_ready(ConfigSource::Etcd);
        assert!(is_ready());
    }

    #[test]
    fn stale_fails_readiness_when_configured() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        configure_status_policy(0, true);
        mark_ready(ConfigSource::Etcd);
        // Disconnected etcd with zero threshold: any elapsed time is stale.
        std::thread::sleep(Duration::from_millis(5));
        assert!(!is_ready());
        configure_status_policy(300, false);
    }

    #[test]
    fn idle_but_connected_etcd_watch_is_not_stale() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        configure_status_policy(0, true);
        mark_ready(ConfigSource::Etcd);
        mark_etcd_connected(true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(is_ready());
        assert!(!status_view().degraded);
        configure_status_policy(300, false);
    }

    #[test]
    fn disconnected_etcd_becomes_stale_after_threshold() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        configure_status_policy(0, true);
        mark_ready(ConfigSource::Etcd);
        mark_etcd_connected(true);
        assert!(is_ready());
        mark_etcd_connected(false);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!is_ready());
        configure_status_policy(300, false);
    }

    #[test]
    fn yaml_source_never_becomes_stale() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        configure_status_policy(0, true);
        mark_ready(ConfigSource::Yaml);
        std::thread::sleep(Duration::from_millis(5));
        assert!(is_ready());
        configure_status_policy(300, false);
    }
}
