use std::time::Duration;

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
use crate::core::{status, ProxyError, ProxyResult};

// Retry delay constants
const LIST_RETRY_DELAY: Duration = Duration::from_secs(3);
const WATCH_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Service responsible for syncing and watching etcd configuration changes.
pub struct EtcdConfigSync {
    config: Etcd,
    client: Option<Client>,
    revision: i64,
    handler: Box<dyn EtcdEventHandler + Send + Sync>,
}

impl EtcdConfigSync {
    pub fn new(config: Etcd, handler: Box<dyn EtcdEventHandler + Send + Sync>) -> Self {
        Self {
            config,
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
        let prefix = self.config.prefix.clone();
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

        self.handler.handle_list_response(&response)?;
        status::record_sync_success(self.revision);
        Ok(())
    }

    /// Watch for etcd data changes.
    async fn watch(&mut self) -> ProxyResult<()> {
        let prefix = self.config.prefix.clone();
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
                    self.handler.handle_events(response.events())?;

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
                        return;
                    }
                },

                result = self.list() => {
                    if let Err(err) = result {
                        log::error!("List operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        status::record_sync_error(err.to_string());
                        self.reset_client();
                        if sleep_or_shutdown(LIST_RETRY_DELAY, &shutdown).await {
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
                        return;
                    }
                },

                result = self.watch() => {
                    if let Err(err) = result {
                        log::error!("Watch operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        status::record_sync_error(err.to_string());
                        self.reset_client();
                        if sleep_or_shutdown(WATCH_RETRY_DELAY, &shutdown).await {
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
        self.run_sync_loop(shutdown).await
    }

    fn name(&self) -> &'static str {
        "Etcd config SYNC"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

pub trait EtcdEventHandler {
    /// Apply all events from one etcd watch response.
    ///
    /// On `Err`, the sync loop must reset and relist so failed updates are not lost.
    fn handle_events(&self, events: &[Event]) -> ProxyResult<()>;

    fn handle_list_response(&self, response: &GetResponse) -> ProxyResult<()>;
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
    // TLS is opt-in via `etcd.tls`. etcd-client auto-enables TLS for any
    // `https://` URL (even with empty TlsOptions), so normalize the scheme
    // from the TLS config rather than trusting the configured host prefix.
    let endpoints = normalize_etcd_endpoints(&cfg.host, cfg.tls.is_some());
    Client::connect(endpoints, Some(options))
        .await
        .map_err(|e| {
            ProxyError::etcd_error_with_cause(
                format!("Failed to connect to host '{:?}'", cfg.host),
                e,
            )
        })
}

/// Rewrite etcd host URLs so the scheme matches whether TLS is enabled.
///
/// Plaintext is the default: without `etcd.tls`, endpoints become `http://...`
/// even if the config wrote `https://`. With TLS, endpoints become `https://...`.
fn normalize_etcd_endpoints(hosts: &[String], use_tls: bool) -> Vec<String> {
    let scheme = if use_tls { "https://" } else { "http://" };
    hosts
        .iter()
        .map(|host| {
            let stripped = host
                .strip_prefix("https://")
                .or_else(|| host.strip_prefix("http://"))
                .unwrap_or(host.as_str());
            format!("{scheme}{stripped}")
        })
        .collect()
}

/// Build etcd `ConnectOptions` from config (timeout, auth, TLS).
///
/// Separated from `create_client` so the TLS/options logic is unit-testable
/// without a live etcd endpoint. TLS is only attached when `etcd.tls` is set.
fn build_connect_options(cfg: &Etcd) -> ProxyResult<ConnectOptions> {
    let mut options = ConnectOptions::default();
    if let Some(timeout) = cfg.timeout {
        options = options.with_timeout(Duration::from_secs(timeout as _));
    }
    if let Some(connect_timeout) = cfg.connect_timeout {
        options = options.with_connect_timeout(Duration::from_secs(connect_timeout as _));
    }
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

/// Wrapper for etcd client used by Admin API, ensuring local mutability.
pub struct EtcdClientWrapper {
    config: Etcd,
    client: OnceCell<Mutex<Client>>,
}

impl EtcdClientWrapper {
    pub fn new(cfg: Etcd) -> Self {
        Self {
            config: cfg,
            client: OnceCell::new(),
        }
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
    /// Returns `(key -> value, header revision, key -> mod_revision)` where keys
    /// are the full physical etcd keys (including the prefix). Used by the Admin
    /// write path to reconstruct the full resource graph for reference-integrity
    /// validation before a CAS commit.
    pub async fn read_full_graph(
        &self,
    ) -> ProxyResult<(
        std::collections::HashMap<String, Vec<u8>>,
        i64,
        std::collections::HashMap<String, i64>,
    )> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let prefixed_key = self.config.prefix.clone();
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

        let revision = response
            .header()
            .map(|h| h.revision())
            .ok_or_else(|| ProxyError::etcd_error("read_full_graph: missing response header"))?;

        let mut kv_map = std::collections::HashMap::new();
        let mut mod_map = std::collections::HashMap::new();
        for kv in response.kvs() {
            let key = String::from_utf8_lossy(kv.key()).into_owned();
            kv_map.insert(key.clone(), kv.value().to_vec());
            mod_map.insert(key, kv.mod_revision());
        }
        Ok((kv_map, revision, mod_map))
    }

    /// Compare-and-swap put. `expected_mod_revision = None` means the key must
    /// not exist yet (create_revision == 0); `Some(r)` means the key's current
    /// mod_revision must equal `r`. On success returns the committed header
    /// revision. The `key` is the full physical etcd key (including prefix) and
    /// is used verbatim — no further prefixing is applied.
    pub async fn cas_put(
        &self,
        key: &str,
        value: Vec<u8>,
        expected_mod_revision: Option<i64>,
    ) -> ProxyResult<i64> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let compare = match expected_mod_revision {
            None => Compare::create_revision(key.as_bytes(), CompareOp::Equal, 0),
            Some(r) => Compare::mod_revision(key.as_bytes(), CompareOp::Equal, r),
        };
        let txn =
            Txn::new()
                .when(vec![compare])
                .and_then(vec![TxnOp::put(key.as_bytes(), value, None)]);

        let response = client.txn(txn).await.map_err(|e| {
            ProxyError::etcd_error_with_cause(format!("cas_put for key '{key}' failed"), e)
        })?;

        if !response.succeeded() {
            return Err(ProxyError::CasConflict(format!(
                "cas_put conflict for key '{key}': expected mod_revision mismatch"
            )));
        }

        response
            .header()
            .map(|h| h.revision())
            .ok_or_else(|| ProxyError::etcd_error("cas_put: missing response header"))
    }

    /// Compare-and-swap delete. The key's current mod_revision must equal
    /// `expected_mod_revision`, otherwise the transaction fails. The `key` is
    /// the full physical etcd key (including prefix) and is used verbatim.
    pub async fn cas_delete(&self, key: &str, expected_mod_revision: i64) -> ProxyResult<()> {
        let client_mutex = self.ensure_connected().await?;
        let mut client = client_mutex.lock().await;

        let compare =
            Compare::mod_revision(key.as_bytes(), CompareOp::Equal, expected_mod_revision);
        let txn = Txn::new()
            .when(vec![compare])
            .and_then(vec![TxnOp::delete(key.as_bytes(), None)]);

        let response = client.txn(txn).await.map_err(|e| {
            ProxyError::etcd_error_with_cause(format!("cas_delete for key '{key}' failed"), e)
        })?;

        if !response.succeeded() {
            return Err(ProxyError::CasConflict(format!(
                "cas_delete conflict for key '{key}': expected mod_revision mismatch"
            )));
        }
        Ok(())
    }

    /// Returns the full physical etcd key (prefix + logical key). Exposed so the
    /// Admin write path can correlate `read_full_graph` keys (which are physical)
    /// with CAS operations.
    pub fn prefixed_key(&self, key: &str) -> String {
        self.with_prefix(key)
    }

    fn with_prefix(&self, key: &str) -> String {
        format!("{}/{}", self.config.prefix, key)
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
    fn normalize_endpoints_default_plaintext() {
        let hosts = vec![
            "127.0.0.1:2379".to_string(),
            "http://etcd:2379".to_string(),
            "https://etcd:2379".to_string(),
        ];
        assert_eq!(
            normalize_etcd_endpoints(&hosts, false),
            vec![
                "http://127.0.0.1:2379",
                "http://etcd:2379",
                "http://etcd:2379",
            ]
        );
    }

    #[test]
    fn normalize_endpoints_tls_uses_https() {
        let hosts = vec![
            "127.0.0.1:2379".to_string(),
            "http://etcd:2379".to_string(),
            "https://etcd:2379".to_string(),
        ];
        assert_eq!(
            normalize_etcd_endpoints(&hosts, true),
            vec![
                "https://127.0.0.1:2379",
                "https://etcd:2379",
                "https://etcd:2379",
            ]
        );
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
