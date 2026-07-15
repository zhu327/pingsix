//! Service readiness and etcd sync status for probes and diagnostics.

use std::sync::Mutex;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigErrorKind {
    EtcdUnavailable,
    CandidateInvalid,
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
    pub error_kind: Option<ConfigErrorKind>,
    pub last_error: Option<String>,
}

struct RuntimeStatusInner {
    initialized: bool,
    config_source: Option<ConfigSource>,
    revision: Option<i64>,
    published_revision: Option<i64>,
    last_success: Option<Instant>,
    error_kind: Option<ConfigErrorKind>,
    last_error: Option<String>,
    connected: bool,
    disconnected_since: Option<Instant>,
    awaiting_publish_after_reconnect: bool,
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
            error_kind: None,
            last_error: None,
            connected: false,
            disconnected_since: None,
            awaiting_publish_after_reconnect: false,
            config_stale_after: Duration::from_secs(300),
            fail_readiness_when_stale: true,
        }
    }
}

static STATUS: Lazy<Mutex<RuntimeStatusInner>> =
    Lazy::new(|| Mutex::new(RuntimeStatusInner::default()));

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
    status.error_kind = None;
    status.last_error = None;
    if source == ConfigSource::Yaml {
        status.connected = true;
    }
    log::info!(
        "Configuration loaded from {}, service is ready",
        source.as_str()
    );
}

pub fn mark_etcd_connected(connected: bool) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    if connected {
        status.disconnected_since = None;
    } else if status.connected || status.disconnected_since.is_none() {
        status.disconnected_since = Some(Instant::now());
    }
    status.connected = connected;
}

/// Identify etcd as the active configuration source without claiming a valid
/// snapshot has been published yet.
pub fn begin_etcd_sync() {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.config_source = Some(ConfigSource::Etcd);
}

pub fn set_revision(revision: Option<i64>) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.revision = revision;
}

pub fn set_published_revision(revision: i64) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.published_revision = Some(revision);
    if status.config_source == Some(ConfigSource::Etcd) {
        status.initialized = true;
        status.last_success = Some(Instant::now());
        status.error_kind = None;
        status.last_error = None;
        status.awaiting_publish_after_reconnect = false;
    }
}

/// Record etcd list/watch progress. This deliberately does not restore readiness:
/// only a successfully published configuration snapshot can do that.
pub fn record_sync_success(revision: i64) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.revision = Some(revision);
    status.last_success = Some(Instant::now());
    // A successful list/watch proves transport recovery; clear a transport
    // error without touching a candidate-validation error (cleared on publish).
    if status.error_kind == Some(ConfigErrorKind::EtcdUnavailable) {
        status.error_kind = None;
        status.last_error = None;
    }
    if status.config_source.is_none() {
        status.config_source = Some(ConfigSource::Etcd);
    }
    if !status.connected && status.initialized {
        // A reconnect/list only proves transport health. Keep readiness closed
        // until that listed graph has actually compiled and published.
        status.awaiting_publish_after_reconnect = true;
    }
    status.connected = true;
    status.disconnected_since = None;
}

pub fn record_sync_error(error: String) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.error_kind = Some(ConfigErrorKind::EtcdUnavailable);
    status.last_error = Some(error);
    if status.connected || status.disconnected_since.is_none() {
        status.disconnected_since = Some(Instant::now());
    }
    status.connected = false;
}

/// Record a rejected async candidate without conflating it with etcd transport health.
pub fn record_preparation_error(error: String) {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    status.error_kind = Some(ConfigErrorKind::CandidateInvalid);
    status.last_error = Some(error);
}

/// Check if the service is ready to handle traffic.
pub fn is_ready() -> bool {
    let status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    compute_ready(&status)
}

pub fn is_live() -> bool {
    true
}

/// Readiness and its stable public reason from one consistent state snapshot.
pub fn readiness() -> (bool, Option<&'static str>) {
    let status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    let ready = compute_ready(&status);
    let reason = if ready {
        None
    } else if !status.initialized {
        Some("not_initialized")
    } else if is_stale(&status) {
        Some("config_stale")
    } else {
        Some("config_invalid")
    };
    (ready, reason)
}

pub fn status_view() -> RuntimeStatusView {
    let status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    let stale = is_stale(&status);
    let ready = compute_ready(&status);
    let degraded =
        status.initialized && (!status.connected || stale || status.error_kind.is_some());
    let degraded_reason = if !status.initialized {
        None
    } else if !status.connected {
        Some("etcd disconnected".into())
    } else if stale {
        Some("configuration sync is stale".into())
    } else if status.error_kind == Some(ConfigErrorKind::CandidateInvalid) {
        Some("latest configuration candidate is invalid".into())
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
        error_kind: status.error_kind,
        last_error: status.last_error.clone(),
    }
}

fn compute_ready(status: &RuntimeStatusInner) -> bool {
    if !status.initialized || status.awaiting_publish_after_reconnect {
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
        .disconnected_since
        .is_some_and(|t| t.elapsed() > status.config_stale_after)
}

/// Reset readiness status (useful for testing)
#[cfg(test)]
pub fn reset() {
    let mut status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    *status = RuntimeStatusInner::default();
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
    fn stale_fails_readiness_by_default() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        configure_status_policy(0, true);
        mark_ready(ConfigSource::Etcd);
        mark_etcd_connected(false);
        // Disconnected etcd with zero threshold: any elapsed time is stale.
        std::thread::sleep(Duration::from_millis(5));
        assert!(!is_ready());
        configure_status_policy(300, true);
    }

    #[test]
    fn watch_progress_does_not_restore_readiness_without_publish() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        configure_status_policy(0, true);
        begin_etcd_sync();
        record_sync_success(10);
        mark_etcd_connected(false);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!is_ready());
        record_sync_success(11);
        assert!(!is_ready());
        set_published_revision(11);
        assert!(is_ready());
        configure_status_policy(300, true);
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
    fn short_disconnection_keeps_last_known_good_ready() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        configure_status_policy(60, true);
        mark_ready(ConfigSource::Etcd);
        mark_etcd_connected(true);
        mark_etcd_connected(false);
        assert!(is_ready());
        configure_status_policy(300, true);
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
    fn preparation_error_has_stable_diagnostic_category() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        begin_etcd_sync();
        mark_ready(ConfigSource::Etcd);
        mark_etcd_connected(true);
        record_preparation_error("resolver leaked internal.example".into());
        let view = status_view();
        assert_eq!(view.error_kind, Some(ConfigErrorKind::CandidateInvalid));
        assert_eq!(
            view.degraded_reason.as_deref(),
            Some("latest configuration candidate is invalid")
        );
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
