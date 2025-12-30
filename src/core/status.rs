use std::sync::atomic::{AtomicBool, Ordering};

/// Global readiness flag indicating whether the service has successfully loaded its configuration.
///
/// This is used by the readiness probe endpoint to determine if the service can accept traffic.
/// It's a simple atomic boolean that's set to true once configuration loading completes.
static CONFIG_LOADED: AtomicBool = AtomicBool::new(false);

/// Configuration source type for better error reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Mark the service as ready after successful configuration loading.
///
/// Should be called once after:
/// - Static YAML configuration is loaded successfully, OR
/// - Initial etcd configuration sync completes successfully
pub fn mark_ready(source: ConfigSource) {
    CONFIG_LOADED.store(true, Ordering::SeqCst);
    log::info!(
        "Configuration loaded from {}, service is ready",
        source.as_str()
    );
}

/// Check if the service is ready to handle traffic.
///
/// Returns true if configuration has been successfully loaded, false otherwise.
pub fn is_ready() -> bool {
    CONFIG_LOADED.load(Ordering::SeqCst)
}

/// Reset readiness status (useful for testing)
#[allow(dead_code)]
pub fn reset() {
    CONFIG_LOADED.store(false, Ordering::SeqCst);
    log::debug!("Readiness status reset");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These tests touch global process-wide state (CONFIG_LOADED).
    // Rust runs tests in parallel by default, so we must serialize this module's tests
    // to avoid racy failures where another test flips the readiness flag mid-assertion.
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
}
