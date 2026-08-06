use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use url::Url;

use async_trait::async_trait;
use etcd_client::{
    Client, Compare, CompareOp, ConnectOptions, Event, GetOptions, Txn, TxnOp, WatchOptions,
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
    proxy::graph_mutation::{
        CommitRevision, ConfigurationGraph, GraphCommit, GraphError, GraphStore, ResourceKey,
        ResourceKind, StoreError, StoredChange, StoredGraph, StoredMutation, StoredResource,
        WatchBatch,
    },
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
///
/// The list/watch adapter for the configuration graph authority: maps etcd
/// native responses into storage-neutral [`StoredGraph`]/[`WatchBatch`] inputs
/// and feeds them to the shared [`ConfigurationGraph`].
pub struct EtcdConfigSync {
    config: Etcd,
    /// Trailing-slash form used for list/watch range queries.
    canonical_prefix: String,
    client: Option<Client>,
    revision: i64,
    graph: Arc<ConfigurationGraph>,
}

impl EtcdConfigSync {
    pub fn new(config: Etcd, graph: Arc<ConfigurationGraph>) -> Self {
        let canonical_prefix = canonicalize_prefix(&config.prefix);
        Self {
            config,
            canonical_prefix,
            client: None,
            revision: 0,
            graph,
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
    async fn list(&mut self) -> Result<(), SyncError> {
        let prefix = self.canonical_prefix.clone();
        let client = self.get_client().await?;

        let options = GetOptions::new().with_prefix();
        let response = client
            .get(prefix.as_str(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(format!("Failed to list key '{prefix}'"), e)
            })?;

        let revision = response
            .header()
            .ok_or_else(|| ProxyError::etcd_error("Failed to get header from list response"))?
            .revision();

        // Mark transport recovery before submitting: a fast publish must be the
        // operation that clears the reconnect publication fence.
        status::record_sync_success(revision);
        let kvs: Vec<ListKv<'_>> = response
            .kvs()
            .iter()
            .map(|kv| ListKv {
                key: kv.key(),
                value: kv.value(),
                create_revision: kv.create_revision(),
                mod_revision: kv.mod_revision(),
            })
            .collect();
        let snapshot =
            graph_snapshot_from_list(&kvs, revision, &self.canonical_prefix).map_err(|e| {
                SyncError::Transport(ProxyError::Configuration(format!(
                    "Failed to map etcd list response: {e:?}"
                )))
            })?;
        self.graph
            .replace_all(snapshot)
            .map_err(classify_rejection)?;
        self.revision = revision;
        status::set_revision(Some(revision));
        Ok(())
    }

    /// Watch for etcd data changes.
    async fn watch(&mut self) -> Result<(), SyncError> {
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

                    // Propagate authority failures so the sync loop relists instead of
                    // silently advancing past a rejected revision. Progress responses
                    // have no events; the mapped batch is empty and apply_watch no-ops.
                    let changes =
                        graph_changes_from_events(response.events(), &self.canonical_prefix)?;
                    let revision = response
                        .events()
                        .iter()
                        .filter_map(|event| event.kv().map(|kv| kv.mod_revision()))
                        .max()
                        .unwrap_or(0);
                    self.graph
                        .apply_watch(WatchBatch { revision, changes })
                        .map_err(classify_rejection)?;

                    if let Some(header) = response.header() {
                        self.revision = header.revision();
                        status::record_sync_success(self.revision);
                    }
                }
                _ = progress_interval.tick() => {
                    if let Err(e) = stream.request_progress().await {
                        return Err(SyncError::Transport(
                            ProxyError::etcd_error_with_cause(
                                "Failed to request etcd watch progress",
                                e,
                            ),
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
                        self.graph.shutdown().await;
                        return;
                    }
                },

                result = self.list() => {
                    if let Err(err) = result {
                        log::error!("List operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        match &err {
                            SyncError::Transport(_) => {
                                status::record_sync_error(err.to_string());
                                self.reset_client();
                            }
                            SyncError::Data(_) => {
                                // Broken configuration data: keep the etcd
                                // connection and readiness on the LKG while
                                // relisting for an operator repair.
                                status::record_preparation_error(err.to_string());
                            }
                        }
                        if sleep_or_shutdown(LIST_RETRY_DELAY, &shutdown).await {
                            self.graph.shutdown().await;
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
                        self.graph.shutdown().await;
                        return;
                    }
                },

                result = self.watch() => {
                    if let Err(err) = result {
                        log::error!("Watch operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        match &err {
                            SyncError::Transport(_) => {
                                status::record_sync_error(err.to_string());
                                self.reset_client();
                            }
                            SyncError::Data(_) => {
                                status::record_preparation_error(err.to_string());
                            }
                        }
                        if sleep_or_shutdown(WATCH_RETRY_DELAY, &shutdown).await {
                            self.graph.shutdown().await;
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

/// One key-value pair from a list response, decoupled from etcd types so the
/// mapping logic stays pure and testable without constructing etcd responses.
struct ListKv<'a> {
    key: &'a [u8],
    value: &'a [u8],
    create_revision: i64,
    mod_revision: i64,
}

/// Map a full etcd list response into a storage-neutral [`StoredGraph`].
///
/// Shared by the sync adapter and [`EtcdGraphStore`] so both interpret the
/// same physical namespace identically. The graph generation guard
/// (`.pingsix_graph_revision`) is validated and its mod revision recorded;
/// metadata keys and foreign-prefix keys are excluded here, at the adapter
/// boundary, so the graph authority never sees physical etcd concerns.
fn graph_snapshot_from_list(
    kvs: &[ListKv<'_>],
    header_revision: i64,
    canonical_prefix: &str,
) -> Result<StoredGraph, StoreError> {
    let guard_key = format!("{canonical_prefix}{GRAPH_REVISION_KEY}");
    let mut resources = HashMap::new();
    let mut guard_mod_revision = None;
    for kv in kvs {
        let key = String::from_utf8_lossy(kv.key).into_owned();
        if !key.starts_with(canonical_prefix) {
            log::warn!("Ignoring etcd key outside configured namespace: {key}");
            continue;
        }
        if key == guard_key {
            validate_guard_value(kv.value)?;
            guard_mod_revision = Some(kv.mod_revision);
            continue;
        }
        if is_metadata_key(kv.key) {
            continue;
        }
        let resource_key = physical_key_to_resource_key(kv.key, canonical_prefix)
            .map_err(|message| StoreError::InvalidResponse { message })?;
        resources.insert(
            resource_key,
            StoredResource {
                value: kv.value.to_vec(),
                create_revision: kv.create_revision,
                mod_revision: kv.mod_revision,
            },
        );
    }
    Ok(StoredGraph {
        resources,
        guard_mod_revision,
        revision: header_revision,
    })
}

/// Map one watch response into a storage-neutral, per-key coalesced batch.
///
/// Later events for the same key win (causal order per key). Metadata and
/// foreign-prefix keys are excluded; malformed keys reject the whole batch so
/// the sync loop relists rather than advancing past a rejected revision.
fn graph_changes_from_events(
    events: &[Event],
    canonical_prefix: &str,
) -> ProxyResult<Vec<StoredChange>> {
    let mut final_by_key: HashMap<ResourceKey, StoredChange> = HashMap::new();
    for event in events {
        let kv = event
            .kv()
            .ok_or_else(|| ProxyError::Configuration("Etcd event missing key-value pair".into()))?;
        let key = String::from_utf8_lossy(kv.key()).into_owned();
        if is_metadata_key(kv.key()) {
            continue;
        }
        if !key.starts_with(canonical_prefix) {
            log::warn!("Ignoring etcd event outside configured namespace: {key}");
            continue;
        }
        let resource_key = physical_key_to_resource_key(kv.key(), canonical_prefix)
            .map_err(ProxyError::Configuration)?;
        let change = match event.event_type() {
            etcd_client::EventType::Put => StoredChange::Put {
                key: resource_key.clone(),
                resource: StoredResource {
                    value: kv.value().to_vec(),
                    create_revision: kv.create_revision(),
                    mod_revision: kv.mod_revision(),
                },
            },
            etcd_client::EventType::Delete => StoredChange::Delete {
                key: resource_key.clone(),
            },
        };
        final_by_key.insert(resource_key, change);
    }
    Ok(final_by_key.into_values().collect())
}

/// Failure classification of one list/watch iteration, distinguishing
/// configuration data rejected by the graph authority (relist while keeping
/// the etcd connection and readiness on the last-known-good graph) from
/// transport/protocol failures (reset the client and mark etcd disconnected).
#[derive(Debug)]
enum SyncError {
    Transport(ProxyError),
    Data(ProxyError),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::Transport(err) | SyncError::Data(err) => write!(f, "{err}"),
        }
    }
}

impl From<ProxyError> for SyncError {
    fn from(err: ProxyError) -> Self {
        SyncError::Transport(err)
    }
}

/// Classify a rejection from the configuration graph authority's ingestion
/// surface. Invalid candidate data is a data problem, not a transport one: the
/// sync loop relists without marking etcd disconnected, readiness stays green
/// on the last-known-good graph, and the error surfaces as a candidate
/// preparation error. Anything else is treated as a sync failure.
fn classify_rejection(err: GraphError) -> SyncError {
    let is_data = matches!(
        err,
        GraphError::InvalidCandidate { .. }
            | GraphError::InvalidResource { .. }
            | GraphError::Secret { .. }
    );
    let message = format!("Configuration graph rejected input: {err}");
    if is_data {
        SyncError::Data(ProxyError::Configuration(message))
    } else {
        SyncError::Transport(ProxyError::Configuration(message))
    }
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

/// Reserved metadata key serializing supported Admin mutations of a resource graph.
pub const GRAPH_REVISION_KEY: &str = ".pingsix_graph_revision";
/// Guard value identifies the transaction protocol. Changing this requires an
/// explicit mixed-version migration; old single-key writers are unsupported.
pub const GRAPH_PROTOCOL_VERSION: &[u8] = b"pingsix-graph-v1";

/// Production [`GraphStore`] adapter: whole-graph snapshots and guarded CAS.
pub struct EtcdGraphStore {
    config: Etcd,
    canonical_prefix: String,
    client: OnceCell<Mutex<Client>>,
}

impl EtcdGraphStore {
    pub fn new(cfg: Etcd) -> Self {
        let canonical_prefix = canonicalize_prefix(&cfg.prefix);
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

    fn prefixed_key(&self, key: &str) -> String {
        self.with_prefix(key)
    }

    fn with_prefix(&self, key: &str) -> String {
        format!("{}{}", self.canonical_prefix, key.trim_start_matches('/'))
    }
}

#[async_trait]
impl GraphStore for EtcdGraphStore {
    async fn snapshot(&self) -> Result<StoredGraph, StoreError> {
        let client_mutex = self
            .ensure_connected()
            .await
            .map_err(|e| StoreError::Unavailable { source: e })?;
        let mut client = client_mutex.lock().await;

        let options = GetOptions::new().with_prefix();
        let response = client
            .get(self.canonical_prefix.as_bytes(), Some(options))
            .await
            .map_err(|e| StoreError::Unavailable {
                source: ProxyError::etcd_error_with_cause(
                    format!(
                        "Failed to read full graph for prefix '{}'",
                        self.canonical_prefix
                    ),
                    e,
                ),
            })?;
        let header = response
            .header()
            .ok_or_else(|| StoreError::InvalidResponse {
                message: "snapshot: missing response header".into(),
            })?;
        let kvs: Vec<ListKv<'_>> = response
            .kvs()
            .iter()
            .map(|kv| ListKv {
                key: kv.key(),
                value: kv.value(),
                create_revision: kv.create_revision(),
                mod_revision: kv.mod_revision(),
            })
            .collect();
        graph_snapshot_from_list(&kvs, header.revision(), &self.canonical_prefix)
    }

    async fn compare_and_swap(&self, commit: GraphCommit) -> Result<CommitRevision, StoreError> {
        let (key, value, expected_target) = match commit.mutation {
            StoredMutation::Put { key, value } => (
                self.with_prefix(&key.logical_path()),
                Some(value),
                commit.expected_target_mod_revision,
            ),
            StoredMutation::Delete { key } => (
                self.with_prefix(&key.logical_path()),
                None,
                commit.expected_target_mod_revision,
            ),
        };
        self.graph_txn(
            &key,
            value,
            expected_target,
            commit.expected_guard_mod_revision,
        )
        .await
        .map(CommitRevision)
        .map_err(|e| match e {
            ProxyError::CasConflict(_) => StoreError::Conflict,
            other => StoreError::Unavailable { source: other },
        })
    }
}

/// Accept the current graph guard value plus the legacy transition value `1`.
fn validate_guard_value(value: &[u8]) -> Result<(), StoreError> {
    if value != GRAPH_PROTOCOL_VERSION && value != b"1" {
        return Err(StoreError::UnsupportedProtocol);
    }
    Ok(())
}

/// Whether an etcd key is internal control-plane metadata (dotted leaf segment).
fn is_metadata_key(key: &[u8]) -> bool {
    std::str::from_utf8(key)
        .ok()
        .and_then(|key| key.rsplit('/').next())
        .is_some_and(|leaf| leaf.starts_with('.'))
}

/// Map a physical etcd key to a logical [`ResourceKey`] under the canonical prefix.
fn physical_key_to_resource_key(key: &[u8], canonical_prefix: &str) -> Result<ResourceKey, String> {
    let key = std::str::from_utf8(key).map_err(|e| format!("Key is not valid UTF-8: {e}"))?;
    let rest = key
        .strip_prefix(canonical_prefix)
        .ok_or_else(|| format!("Key '{key}' is outside etcd namespace '{canonical_prefix}'"))?;
    let (kind, id) = rest
        .split_once('/')
        .ok_or_else(|| format!("Invalid key format under namespace: {key}"))?;
    if kind.is_empty() || id.is_empty() || id.contains('/') {
        return Err(format!("Invalid key format under namespace: {key}"));
    }
    let kind = ResourceKind::parse(kind).map_err(|e| e.to_string())?;
    ResourceKey::new(kind, id).map_err(|e| e.to_string())
}

/// Minimal faithful stand-in for the external configuration store.
///
/// Models only the behavior the authority relies on: whole-graph snapshots and
/// guarded atomic CAS. No watch, lease, or TLS semantics.
pub struct InMemoryGraphStore {
    state: tokio::sync::Mutex<InMemoryState>,
}

struct InMemoryState {
    graph: StoredGraph,
    next_revision: i64,
}

impl InMemoryGraphStore {
    pub fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::new(InMemoryState {
                graph: StoredGraph::default(),
                next_revision: 1,
            }),
        }
    }
}

impl Default for InMemoryGraphStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GraphStore for InMemoryGraphStore {
    async fn snapshot(&self) -> Result<StoredGraph, StoreError> {
        Ok(self.state.lock().await.graph.clone())
    }

    async fn compare_and_swap(&self, commit: GraphCommit) -> Result<CommitRevision, StoreError> {
        let mut state = self.state.lock().await;
        let target_key = match &commit.mutation {
            StoredMutation::Put { key, .. } | StoredMutation::Delete { key } => key,
        };
        let target_ok = match commit.expected_target_mod_revision {
            None => !state.graph.resources.contains_key(target_key),
            Some(expected) => {
                state
                    .graph
                    .resources
                    .get(target_key)
                    .map(|r| r.mod_revision)
                    == Some(expected)
            }
        };
        let guard_ok = match commit.expected_guard_mod_revision {
            None => state.graph.guard_mod_revision.is_none(),
            Some(expected) => state.graph.guard_mod_revision == Some(expected),
        };
        if !target_ok || !guard_ok {
            return Err(StoreError::Conflict);
        }

        let revision = state.next_revision;
        state.next_revision += 1;
        match commit.mutation {
            StoredMutation::Put { key, value } => {
                let create_revision = state
                    .graph
                    .resources
                    .get(&key)
                    .map(|r| r.create_revision)
                    .unwrap_or(revision);
                state.graph.resources.insert(
                    key,
                    StoredResource {
                        value,
                        create_revision,
                        mod_revision: revision,
                    },
                );
            }
            StoredMutation::Delete { key } => {
                state.graph.resources.remove(&key);
            }
        }
        state.graph.guard_mod_revision = Some(revision);
        state.graph.revision = revision;
        Ok(CommitRevision(revision))
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

    #[test]
    fn metadata_key_detection_matches_dotted_leaves() {
        assert!(is_metadata_key(b"/apisix/.pingsix_graph_revision"));
        assert!(is_metadata_key(b"/apisix/.ingress_sync_barrier"));
        assert!(!is_metadata_key(b"/apisix/routes/1"));
        assert!(is_metadata_key(b"/apisix/routes/.hidden"));
    }

    #[test]
    fn physical_key_maps_to_resource_key_under_namespace() {
        let prefix = "/pingsix/";
        let upstream = physical_key_to_resource_key(b"/pingsix/upstreams/u1", prefix).unwrap();
        assert_eq!(upstream.kind, ResourceKind::Upstream);
        assert_eq!(upstream.id, "u1");
        let ssl = physical_key_to_resource_key(b"/pingsix/ssls/t1", prefix).unwrap();
        assert_eq!(ssl.kind, ResourceKind::Ssl);
        assert_eq!(ssl.id, "t1");
        assert_eq!(
            physical_key_to_resource_key(b"/pingsix/routes/1", prefix)
                .unwrap()
                .logical_path(),
            "routes/1"
        );
    }

    #[test]
    fn physical_key_rejects_foreign_nested_and_unknown() {
        let prefix = "/pingsix/";
        assert!(physical_key_to_resource_key(b"/pingsix-other/routes/1", prefix).is_err());
        assert!(physical_key_to_resource_key(b"/pingsix/routes", prefix).is_err());
        assert!(physical_key_to_resource_key(b"/pingsix/routes/a/b", prefix).is_err());
        assert!(physical_key_to_resource_key(b"/pingsix/certificates/1", prefix).is_err());
    }

    #[test]
    fn rejection_classification_distinguishes_data_from_transport() {
        let data = classify_rejection(GraphError::InvalidCandidate {
            source: ProxyError::Configuration("broken graph".into()),
        });
        assert!(matches!(data, SyncError::Data(_)), "{data:?}");

        let data = classify_rejection(GraphError::InvalidResource {
            key: ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
            source: ProxyError::Configuration("bad document".into()),
        });
        assert!(matches!(data, SyncError::Data(_)), "{data:?}");

        let transport = classify_rejection(GraphError::StaleRevision {
            incoming: 1,
            published: 2,
        });
        assert!(
            matches!(transport, SyncError::Transport(_)),
            "{transport:?}"
        );

        let transport = classify_rejection(GraphError::WorkerStopped);
        assert!(
            matches!(transport, SyncError::Transport(_)),
            "{transport:?}"
        );
    }

    #[test]
    fn guard_value_accepts_current_and_legacy() {
        assert!(validate_guard_value(GRAPH_PROTOCOL_VERSION).is_ok());
        assert!(validate_guard_value(b"1").is_ok());
        assert!(matches!(
            validate_guard_value(b"pingsix-graph-v2"),
            Err(StoreError::UnsupportedProtocol)
        ));
    }

    fn list_kv(
        key: &'static str,
        value: &'static [u8],
        create_revision: i64,
        mod_revision: i64,
    ) -> ListKv<'static> {
        ListKv {
            key: key.as_bytes(),
            value,
            create_revision,
            mod_revision,
        }
    }

    #[test]
    fn list_mapping_reads_and_validates_guard() {
        let prefix = "/pingsix/";
        let kvs = vec![
            list_kv("/pingsix/upstreams/u1", b"{}", 1, 3),
            list_kv("/pingsix/routes/r1", b"{}", 1, 5),
            list_kv(
                "/pingsix/.pingsix_graph_revision",
                GRAPH_PROTOCOL_VERSION,
                2,
                4,
            ),
        ];
        let graph = graph_snapshot_from_list(&kvs, 42, prefix).unwrap();
        assert_eq!(graph.revision, 42);
        assert_eq!(graph.guard_mod_revision, Some(4));
        assert_eq!(graph.resources.len(), 2);
        assert!(graph
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Upstream, "u1").unwrap()));
        assert!(graph
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Route, "r1").unwrap()));
    }

    #[test]
    fn list_mapping_accepts_legacy_guard_value() {
        let prefix = "/pingsix/";
        let kvs = vec![list_kv("/pingsix/.pingsix_graph_revision", b"1", 2, 4)];
        let graph = graph_snapshot_from_list(&kvs, 7, prefix).unwrap();
        assert_eq!(graph.guard_mod_revision, Some(4));
        assert!(graph.resources.is_empty());
    }

    #[test]
    fn list_mapping_rejects_unsupported_guard() {
        let prefix = "/pingsix/";
        let kvs = vec![list_kv(
            "/pingsix/.pingsix_graph_revision",
            b"pingsix-graph-v2",
            2,
            4,
        )];
        assert!(matches!(
            graph_snapshot_from_list(&kvs, 7, prefix),
            Err(StoreError::UnsupportedProtocol)
        ));
    }

    #[test]
    fn list_mapping_excludes_metadata_and_foreign_keys() {
        let prefix = "/pingsix/";
        let kvs = vec![
            list_kv("/pingsix/.ingress_sync_barrier", b"{}", 1, 1),
            list_kv("/pingsix-other/routes/1", b"{}", 1, 1),
            list_kv("/pingsix/ssls/t1", b"{}", 1, 2),
        ];
        let graph = graph_snapshot_from_list(&kvs, 9, prefix).unwrap();
        assert_eq!(graph.resources.len(), 1);
        assert!(graph
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Ssl, "t1").unwrap()));
        assert_eq!(graph.guard_mod_revision, None);
    }

    #[tokio::test]
    async fn in_memory_store_cas_contract() {
        use crate::proxy::graph_mutation::{ResourceKey, ResourceKind, StoredMutation};
        let store = InMemoryGraphStore::new();
        let key = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let body = b"{\"id\":\"r1\"}".to_vec();

        // Create: absent target + absent guard.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: body.clone(),
            },
            expected_target_mod_revision: None,
            expected_guard_mod_revision: None,
        };
        let rev1 = store.compare_and_swap(commit).await.unwrap();
        assert_eq!(rev1, CommitRevision(1));
        let snapshot = store.snapshot().await.unwrap();
        assert_eq!(snapshot.resources[&key].mod_revision, 1);
        assert_eq!(snapshot.guard_mod_revision, Some(1));

        // Replace with exact mod revision.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: body.clone(),
            },
            expected_target_mod_revision: Some(1),
            expected_guard_mod_revision: Some(1),
        };
        assert_eq!(
            store.compare_and_swap(commit).await.unwrap(),
            CommitRevision(2)
        );

        // Stale target mod revision conflicts.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: body,
            },
            expected_target_mod_revision: Some(1),
            expected_guard_mod_revision: Some(2),
        };
        assert!(matches!(
            store.compare_and_swap(commit).await,
            Err(StoreError::Conflict)
        ));

        // Stale guard conflicts even with correct target.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: b"x".to_vec(),
            },
            expected_target_mod_revision: Some(2),
            expected_guard_mod_revision: Some(1),
        };
        assert!(matches!(
            store.compare_and_swap(commit).await,
            Err(StoreError::Conflict)
        ));

        // Conflict leaves state unchanged.
        let after = store.snapshot().await.unwrap();
        assert_eq!(after.resources[&key].mod_revision, 2);
        assert_eq!(after.guard_mod_revision, Some(2));

        // Delete of a missing target conflicts.
        let ghost = ResourceKey::new(ResourceKind::Route, "ghost").unwrap();
        let commit = GraphCommit {
            mutation: StoredMutation::Delete { key: ghost },
            expected_target_mod_revision: Some(2),
            expected_guard_mod_revision: Some(2),
        };
        assert!(matches!(
            store.compare_and_swap(commit).await,
            Err(StoreError::Conflict)
        ));

        // Delete of existing target succeeds and removes only the target.
        let commit = GraphCommit {
            mutation: StoredMutation::Delete { key: key.clone() },
            expected_target_mod_revision: Some(2),
            expected_guard_mod_revision: Some(2),
        };
        assert_eq!(
            store.compare_and_swap(commit).await.unwrap(),
            CommitRevision(3)
        );
        let after = store.snapshot().await.unwrap();
        assert!(!after.resources.contains_key(&key));
        assert_eq!(after.guard_mod_revision, Some(3));
        assert!(after.resources.is_empty());

        // Recreate after delete: create_revision tracks the new creation.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: b"new".to_vec(),
            },
            expected_target_mod_revision: None,
            expected_guard_mod_revision: Some(3),
        };
        store.compare_and_swap(commit).await.unwrap();
        let after = store.snapshot().await.unwrap();
        assert_eq!(after.resources[&key].create_revision, 4);
        assert_eq!(after.resources[&key].mod_revision, 4);
    }
}
