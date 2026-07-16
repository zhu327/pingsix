use std::time::Duration;

use url::Url;

use async_trait::async_trait;
use etcd_client::{
    Client, Compare, CompareOp, ConnectOptions, Event, GetOptions, GetResponse, Txn, TxnOp,
    WatchOptions,
};
use pingora::server::ListenFds;
use pingora_core::{server::ShutdownWatch, services::Service};
use tokio::{
    sync::{Mutex, OnceCell},
    time::sleep,
};

use super::{Etcd, EtcdTls};
use crate::{
    core::{status, ProxyError, ProxyResult},
    proxy::control_plane::CONTROL_PLANE,
};

// Retry delay constants
const LIST_RETRY_DELAY: Duration = Duration::from_secs(3);
const WATCH_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Normalize an etcd namespace so range queries cannot leak across sibling prefixes.
///
/// `/apisix` and `/apisix/` both become `/apisix/`, which excludes `/apisix-other/...`.
pub fn canonicalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("{trimmed}/")
    }
}

/// Service responsible for syncing and watching etcd configuration changes.
pub struct EtcdConfigSync {
    config: Etcd,
    /// Trailing-slash form used for list/watch range queries.
    canonical_prefix: String,
    client: Option<Client>,
    revision: i64,
    handler: Box<dyn EtcdEventHandler + Send + Sync>,
}

impl EtcdConfigSync {
    pub fn new(config: Etcd, handler: Box<dyn EtcdEventHandler + Send + Sync>) -> Self {
        let canonical_prefix = canonicalize_prefix(&config.prefix);
        CONTROL_PLANE.set_etcd_prefix(canonical_prefix.clone());
        Self {
            config,
            canonical_prefix,
            client: None,
            revision: 0,
            handler,
        }
    }

    /// Get or initialize the etcd client.
    async fn get_client(&mut self) -> ProxyResult<&mut Client> {
        if self.client.is_none() {
            log::debug!("Creating etcd client for prefix '{}'", self.config.prefix);
            self.client = Some(create_client(&self.config).await?);
        }

        self.client
            .as_mut()
            .ok_or_else(|| ProxyError::etcd_error("Etcd client is not initialized"))
    }

    /// Synchronize etcd data on initialization.
    async fn list(&mut self) -> ProxyResult<()> {
        let prefix = self.canonical_prefix.clone();
        let client = self.get_client().await?;

        let options = GetOptions::new().with_prefix();
        let response = client
            .get(prefix.as_str(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(format!("Failed to list key '{prefix}'"), e)
            })?;

        if let Some(header) = response.header() {
            self.revision = header.revision();
        } else {
            return Err(ProxyError::etcd_error(
                "Failed to get header from list response",
            ));
        }

        self.handler.handle_list_response(&response).await?;
        status::record_sync_success(self.revision);
        Ok(())
    }

    /// Watch for etcd data changes.
    async fn watch(&mut self) -> ProxyResult<()> {
        let prefix = self.canonical_prefix.clone();
        let start_revision = self.revision + 1;
        let options = WatchOptions::new()
            .with_start_revision(start_revision)
            .with_prefix()
            // Idle watches must still refresh liveness; without progress notify a healthy
            // connection with no config changes looks stale to readiness probes.
            .with_progress_notify();

        let client = self.get_client().await?;

        let mut stream = client
            .watch(prefix.as_str(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(format!("Failed to watch key '{prefix}'"), e)
            })?;

        status::mark_etcd_connected(true);

        // Periodically request progress so last_success advances even when the server
        // is quiet and its own progress interval is longer than config_stale_after.
        let mut progress_interval = tokio::time::interval(Duration::from_secs(30));
        progress_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick; list() already recorded success.
        progress_interval.tick().await;

        loop {
            tokio::select! {
                result = stream.message() => {
                    let response = result.map_err(|e| {
                        ProxyError::etcd_error_with_cause("Failed to receive watch message", e)
                    })?;
                    let Some(response) = response else {
                        break;
                    };

                    if response.canceled() {
                        log::debug!("Watch stream for prefix '{prefix}' was canceled");
                        break;
                    }

                    // Propagate handler failures so the sync loop relists instead of
                    // silently advancing past a rejected revision.
                    // Progress responses have no events; handle_events is a no-op for them.
                    self.handler.handle_events(response.events()).await?;

                    if let Some(header) = response.header() {
                        self.revision = header.revision();
                        status::record_sync_success(self.revision);
                    }
                }
                _ = progress_interval.tick() => {
                    if let Err(e) = stream.request_progress().await {
                        return Err(ProxyError::etcd_error_with_cause(
                            "Failed to request etcd watch progress",
                            e,
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Reset the client on failure.
    fn reset_client(&mut self) {
        log::debug!("Resetting etcd client for prefix '{}'", self.config.prefix);
        self.client = None;
        status::mark_etcd_connected(false);
    }

    /// Main task loop for synchronization.
    async fn run_sync_loop(&mut self, mut shutdown: ShutdownWatch) {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::debug!("Shutdown signal received, stopping etcd config sync for prefix '{}'", self.config.prefix);
                        CONTROL_PLANE.stop_preparation_worker().await;
                        return;
                    }
                },

                result = self.list() => {
                    if let Err(err) = result {
                        log::error!("List operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        status::record_sync_error(err.to_string());
                        self.reset_client();
                        if sleep_or_shutdown(LIST_RETRY_DELAY, &shutdown).await {
                            CONTROL_PLANE.stop_preparation_worker().await;
                            return;
                        }
                        continue;
                    }
                }
            }

            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::debug!("Shutdown signal received, stopping etcd config sync for prefix '{}'", self.config.prefix);
                        CONTROL_PLANE.stop_preparation_worker().await;
                        return;
                    }
                },

                result = self.watch() => {
                    if let Err(err) = result {
                        log::error!("Watch operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        status::record_sync_error(err.to_string());
                        self.reset_client();
                        if sleep_or_shutdown(WATCH_RETRY_DELAY, &shutdown).await {
                            CONTROL_PLANE.stop_preparation_worker().await;
                            return;
                        }
                        // Loop continues to list() — full resync after watch failure.
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Service for EtcdConfigSync {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        status::begin_etcd_sync();
        self.run_sync_loop(shutdown).await
    }

    fn name(&self) -> &'static str {
        "Etcd config SYNC"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

#[async_trait]
pub trait EtcdEventHandler {
    /// Submit all events from one etcd watch response. Acceptance is fast; DNS
    /// preparation and publishing are owned by the control-plane worker.
    async fn handle_events(&self, events: &[Event]) -> ProxyResult<()>;

    async fn handle_list_response(&self, response: &GetResponse) -> ProxyResult<()>;
}

/// Sleep for `delay`, but return `true` immediately if shutdown is requested.
async fn sleep_or_shutdown(delay: Duration, shutdown: &ShutdownWatch) -> bool {
    let mut shutdown = shutdown.clone();
    tokio::select! {
        _ = sleep(delay) => false,
        result = shutdown.changed() => {
            match result {
                Ok(()) => *shutdown.borrow(),
                Err(_) => true,
            }
        }
    }
}

async fn create_client(cfg: &Etcd) -> ProxyResult<Client> {
    let options = build_connect_options(cfg)?;
    let endpoints = validate_etcd_endpoints(&cfg.host, cfg.tls.is_some())?;
    Client::connect(endpoints, Some(options))
        .await
        .map_err(|e| {
            ProxyError::etcd_error_with_cause(
                format!("Failed to connect to host '{:?}'", cfg.host),
                e,
            )
        })
}

/// Parse etcd endpoints and require an explicit scheme to agree with TLS.
/// Bare authorities infer the scheme from the TLS configuration; explicit URLs
/// are never rewritten, preventing an accidental HTTPS-to-HTTP downgrade.
pub(crate) fn validate_etcd_endpoints(hosts: &[String], use_tls: bool) -> ProxyResult<Vec<String>> {
    hosts
        .iter()
        .map(|host| {
            let endpoint = if host.contains("://") {
                host.clone()
            } else {
                format!("{}://{host}", if use_tls { "https" } else { "http" })
            };
            let parsed = Url::parse(&endpoint)
                .map_err(|_| ProxyError::validation_error("Invalid etcd endpoint"))?;
            let scheme_matches_tls = match parsed.scheme() {
                "http" => !use_tls,
                "https" => use_tls,
                _ => false,
            };
            if !scheme_matches_tls
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(ProxyError::validation_error("Invalid etcd endpoint"));
            }
            Ok(endpoint)
        })
        .collect()
}

/// Build etcd `ConnectOptions` from config (timeout, auth, TLS).
///
/// Separated from `create_client` so the TLS/options logic is unit-testable
/// without a live etcd endpoint. TLS is only attached when `etcd.tls` is set.
fn build_connect_options(cfg: &Etcd) -> ProxyResult<ConnectOptions> {
    let mut options = ConnectOptions::default();
    // Production-safe defaults when omitted from YAML.
    let timeout = cfg.timeout.unwrap_or(5);
    let connect_timeout = cfg.connect_timeout.unwrap_or(3);
    options = options.with_timeout(Duration::from_secs(timeout as _));
    options = options.with_connect_timeout(Duration::from_secs(connect_timeout as _));
    if let (Some(user), Some(password)) = (&cfg.user, &cfg.password) {
        options = options.with_user(user.clone(), password.clone());
    }
    if let Some(tls_cfg) = &cfg.tls {
        options = options.with_tls(build_tls_options(tls_cfg)?);
    }
    Ok(options)
}

/// Build tonic `ClientTlsConfig` from `EtcdTls` by reading the configured PEM
/// files. Used for both server certificate verification (CA) and mutual TLS
/// (client cert/key) when the latter are present.
fn build_tls_options(tls_cfg: &EtcdTls) -> ProxyResult<etcd_client::TlsOptions> {
    let ca_pem = read_pem(&tls_cfg.ca_cert, "CA cert")?;
    let mut tls =
        etcd_client::TlsOptions::new().ca_certificate(etcd_client::Certificate::from_pem(ca_pem));
    if let (Some(cert_path), Some(key_path)) = (&tls_cfg.client_cert, &tls_cfg.client_key) {
        let cert_pem = read_pem(cert_path, "client cert")?;
        let key_pem = read_pem(key_path, "client key")?;
        tls = tls.identity(etcd_client::Identity::from_pem(cert_pem, key_pem));
    }
    if let Some(domain) = &tls_cfg.domain {
        tls = tls.domain_name(domain);
    }
    Ok(tls)
}

/// Read a PEM file, mapping the IO error to an etcd error with a descriptive cause.
fn read_pem(path: &str, label: &str) -> ProxyResult<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        ProxyError::etcd_error_with_cause(format!("Failed to read etcd {label} '{path}'"), e)
    })
}

pub fn json_to_resource<T>(value: &[u8]) -> ProxyResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let resource: T = serde_json::from_slice(value)
        .map_err(|e| ProxyError::serialization_error("Failed to deserialize JSON", e))?;
    Ok(resource)
}

/// Reserved metadata key serializing supported Admin mutations of a resource graph.
pub const GRAPH_REVISION_KEY: &str = ".pingsix_graph_revision";
/// Guard value identifies the transaction protocol. Changing this requires an
/// explicit mixed-version migration; old single-key writers are unsupported.
pub const GRAPH_PROTOCOL_VERSION: &[u8] = b"pingsix-graph-v1";

/// A complete resource graph plus the revision of its generation guard.
pub struct FullGraph {
    pub kvs: std::collections::HashMap<String, Vec<u8>>,
    pub mod_revisions: std::collections::HashMap<String, i64>,
    pub guard_mod_revision: Option<i64>,
}

/// Wrapper for etcd client used by Admin API, ensuring local mutability.
pub struct EtcdClientWrapper {
    config: Etcd,
    canonical_prefix: String,
    client: OnceCell<Mutex<Client>>,
}

impl EtcdClientWrapper {
    pub fn new(cfg: Etcd) -> Self {
        let canonical_prefix = canonicalize_prefix(&cfg.prefix);
        CONTROL_PLANE.set_etcd_prefix(canonical_prefix.clone());
        Self {
            config: cfg,
            canonical_prefix,
            client: OnceCell::new(),
        }
    }

    /// Configured etcd namespace (canonical trailing-slash form).
    pub fn prefix(&self) -> &str {
        &self.canonical_prefix
    }

    async fn ensure_connected(&self) -> ProxyResult<&Mutex<Client>> {
        self.client
            .get_or_try_init(|| async {
                log::debug!("Creating etcd client for prefix '{}'", self.config.prefix);
                let client = create_client(&self.config).await?;
                Ok::<Mutex<Client>, ProxyError>(Mutex::new(client))
            })
            .await
            .map_err(|e| ProxyError::etcd_error_with_cause("Failed to create etcd client", e))
    }

    pub async fn get(&self, key: &str) -> ProxyResult<Option<Vec<u8>>> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let prefixed_key = self.with_prefix(key);
        client
            .get(prefixed_key.as_bytes(), None)
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(format!("Failed to get key '{prefixed_key}'"), e)
            })
            .map(|resp| resp.kvs().first().map(|kv| kv.value().to_vec()))
    }

    pub async fn put(&self, key: &str, value: Vec<u8>) -> ProxyResult<()> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let prefixed_key = self.with_prefix(key);
        client
            .put(prefixed_key.as_bytes(), value, None)
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(
                    format!("Put operation for key '{prefixed_key}' failed"),
                    e,
                )
            })?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> ProxyResult<()> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let prefixed_key = self.with_prefix(key);
        client
            .delete(prefixed_key.as_bytes(), None)
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(
                    format!("Delete operation for key '{prefixed_key}' failed"),
                    e,
                )
            })?;
        Ok(())
    }

    pub async fn list(&self, key: &str) -> ProxyResult<etcd_client::GetResponse> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let prefixed_key = self.with_prefix(key);
        let options = GetOptions::new().with_prefix();
        client
            .get(prefixed_key.as_bytes(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(
                    format!("List operation for key '{prefixed_key}' failed"),
                    e,
                )
            })
    }

    /// Read every key-value pair under the configured prefix.
    ///
    /// Read resource keys and the graph-generation guard under the configured prefix.
    pub async fn read_full_graph(&self) -> ProxyResult<FullGraph> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let prefixed_key = self.canonical_prefix.clone();
        let options = GetOptions::new().with_prefix();
        let response = client
            .get(prefixed_key.as_bytes(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(
                    format!("read_full_graph for prefix '{prefixed_key}' failed"),
                    e,
                )
            })?;

        if response.header().is_none() {
            return Err(ProxyError::etcd_error(
                "read_full_graph: missing response header",
            ));
        }
        let guard_key = self.prefixed_key(GRAPH_REVISION_KEY);
        let mut kvs = std::collections::HashMap::new();
        let mut mod_revisions = std::collections::HashMap::new();
        let mut guard_mod_revision = None;
        for kv in response.kvs() {
            let key = String::from_utf8_lossy(kv.key()).into_owned();
            if !key.starts_with(&self.canonical_prefix) {
                log::warn!("Ignoring etcd key outside configured namespace: {key}");
                continue;
            }
            if key == guard_key {
                // `1` was written by the initial graph-guard implementation and
                // is accepted only as a transition; the next mutation upgrades it.
                if kv.value() != GRAPH_PROTOCOL_VERSION && kv.value() != b"1" {
                    return Err(ProxyError::Configuration(
                        "Unsupported configuration graph guard protocol".into(),
                    ));
                }
                guard_mod_revision = Some(kv.mod_revision());
            } else {
                kvs.insert(key.clone(), kv.value().to_vec());
                mod_revisions.insert(key, kv.mod_revision());
            }
        }
        Ok(FullGraph {
            kvs,
            mod_revisions,
            guard_mod_revision,
        })
    }

    /// Atomically mutate a resource and advance the graph generation guard.
    async fn graph_txn(
        &self,
        key: &str,
        value: Option<Vec<u8>>,
        expected_mod_revision: Option<i64>,
        guard_mod_revision: Option<i64>,
    ) -> ProxyResult<i64> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;
        let target = match expected_mod_revision {
            None => Compare::create_revision(key.as_bytes(), CompareOp::Equal, 0),
            Some(revision) => Compare::mod_revision(key.as_bytes(), CompareOp::Equal, revision),
        };
        let guard_key = self.prefixed_key(GRAPH_REVISION_KEY);
        let guard = match guard_mod_revision {
            None => Compare::create_revision(guard_key.as_bytes(), CompareOp::Equal, 0),
            Some(revision) => {
                Compare::mod_revision(guard_key.as_bytes(), CompareOp::Equal, revision)
            }
        };
        let mutation = match value {
            Some(value) => TxnOp::put(key.as_bytes(), value, None),
            None => TxnOp::delete(key.as_bytes(), None),
        };
        let txn = Txn::new().when(vec![target, guard]).and_then(vec![
            mutation,
            TxnOp::put(guard_key.as_bytes(), GRAPH_PROTOCOL_VERSION.to_vec(), None),
        ]);
        let response = client
            .txn(txn)
            .await
            .map_err(|e| ProxyError::etcd_error_with_cause("graph transaction failed", e))?;
        if !response.succeeded() {
            return Err(ProxyError::CasConflict(
                "configuration graph changed concurrently".into(),
            ));
        }
        response
            .header()
            .map(|header| header.revision())
            .ok_or_else(|| ProxyError::etcd_error("graph transaction: missing response header"))
    }

    pub async fn graph_txn_put(
        &self,
        key: &str,
        value: Vec<u8>,
        expected: Option<i64>,
        guard: Option<i64>,
    ) -> ProxyResult<i64> {
        self.graph_txn(key, Some(value), expected, guard).await
    }

    pub async fn graph_txn_delete(
        &self,
        key: &str,
        expected: i64,
        guard: Option<i64>,
    ) -> ProxyResult<i64> {
        self.graph_txn(key, None, Some(expected), guard).await
    }

    /// Returns the full physical etcd key (prefix + logical key). Exposed so the
    /// Admin write path can correlate `read_full_graph` keys (which are physical)
    /// with CAS operations.
    pub fn prefixed_key(&self, key: &str) -> String {
        self.with_prefix(key)
    }

    fn with_prefix(&self, key: &str) -> String {
        format!("{}{}", self.canonical_prefix, key.trim_start_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Etcd, EtcdTls};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Monotonic counter so each test gets a unique temp-file name.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Write `contents` to a unique temp file and return its path.
    /// Files are cleaned up via `TempFile`'s Drop.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(contents: &[u8], _ext: &str) -> Self {
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir()
                .join(format!("pingsix_etcd_tls_{}_{id}.pem", std::process::id(),));
            std::fs::write(&path, contents).expect("write temp file");
            TempFile(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().expect("utf8 temp path")
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    const CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
fake-ca
-----END CERTIFICATE-----\n";
    const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
fake-cert
-----END CERTIFICATE-----\n";
    const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
fake-key
-----END PRIVATE KEY-----\n";

    fn etcd_with_tls(tls: EtcdTls) -> Etcd {
        Etcd {
            host: vec!["127.0.0.1:2379".to_string()],
            prefix: "/pingsix".to_string(),
            timeout: None,
            connect_timeout: None,
            user: None,
            password: None,
            tls: Some(tls),
        }
    }

    #[test]
    fn canonicalize_prefix_adds_trailing_slash_and_isolates_siblings() {
        assert_eq!(canonicalize_prefix("/apisix"), "/apisix/");
        assert_eq!(canonicalize_prefix("/apisix/"), "/apisix/");
        assert_eq!(canonicalize_prefix("/apisix///"), "/apisix/");
        let canonical = canonicalize_prefix("/apisix");
        assert!(!"/apisix-other/routes/1".starts_with(&canonical));
        assert!("/apisix/routes/1".starts_with(&canonical));
    }

    #[test]
    fn endpoints_infer_scheme_only_for_bare_authorities() {
        assert_eq!(
            validate_etcd_endpoints(&["127.0.0.1:2379".into()], false).unwrap(),
            vec!["http://127.0.0.1:2379"]
        );
        assert_eq!(
            validate_etcd_endpoints(&["127.0.0.1:2379".into()], true).unwrap(),
            vec!["https://127.0.0.1:2379"]
        );
    }

    #[test]
    fn endpoints_reject_scheme_tls_mismatch_and_url_components() {
        assert!(validate_etcd_endpoints(&["https://etcd:2379".into()], false).is_err());
        assert!(validate_etcd_endpoints(&["http://etcd:2379".into()], true).is_err());
        for endpoint in [
            "ftp://etcd:2379",
            "http://user:secret@etcd:2379",
            "http://etcd:2379/path",
            "http://etcd:2379/?query",
            "http://etcd:2379/#fragment",
        ] {
            assert!(
                validate_etcd_endpoints(&[endpoint.into()], false).is_err(),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn build_tls_options_with_ca_only() {
        let ca = TempFile::new(CA_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: None,
            client_key: None,
            domain: None,
        };
        // TlsOptions internals are opaque; success means CA was parsed and config built.
        assert!(build_tls_options(&tls).is_ok());
    }

    #[test]
    fn build_tls_options_with_mtls() {
        let ca = TempFile::new(CA_PEM, "pem");
        let cert = TempFile::new(CERT_PEM, "pem");
        let key = TempFile::new(KEY_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: Some(cert.path().to_string()),
            client_key: Some(key.path().to_string()),
            domain: Some("etcd.example".to_string()),
        };
        assert!(build_tls_options(&tls).is_ok());
    }

    #[test]
    fn build_tls_options_missing_ca_file() {
        let tls = EtcdTls {
            ca_cert: "/nonexistent/path/ca.pem".to_string(),
            client_cert: None,
            client_key: None,
            domain: None,
        };
        assert!(build_tls_options(&tls).is_err());
    }

    #[test]
    fn build_tls_options_missing_client_cert_file() {
        let ca = TempFile::new(CA_PEM, "pem");
        // cert path missing while key is present — must error rather than silently skip mTLS.
        let key = TempFile::new(KEY_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: Some("/nonexistent/path/cert.pem".to_string()),
            client_key: Some(key.path().to_string()),
            domain: None,
        };
        assert!(build_tls_options(&tls).is_err());
    }

    #[test]
    fn create_client_no_tls_keeps_options_plain() {
        let cfg = Etcd {
            host: vec!["http://127.0.0.1:2379".to_string()],
            prefix: "/pingsix".to_string(),
            timeout: Some(5),
            connect_timeout: Some(2),
            user: Some("root".to_string()),
            password: Some("pw".to_string()),
            tls: None,
        };
        // No TLS configured: options must build without invoking any file reads.
        assert!(build_connect_options(&cfg).is_ok());
    }

    #[test]
    fn build_connect_options_with_tls_succeeds() {
        let ca = TempFile::new(CA_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: None,
            client_key: None,
            domain: Some("etcd.example".to_string()),
        };
        let cfg = etcd_with_tls(tls);
        assert!(build_connect_options(&cfg).is_ok());
    }
}
