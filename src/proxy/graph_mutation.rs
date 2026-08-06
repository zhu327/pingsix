//! Configuration graph authority: the single owner of stored graph state,
//! whole-graph validation, secret handling, guarded mutations, and (via the
//! preparation worker) last-known-good runtime publication.
//!
//! HTTP parsing and response mapping stay in the admin adapter; concrete etcd
//! I/O stays behind the [`GraphStore`] seam in [`crate::config::etcd`].

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;
use validator::Validate;

use crate::{
    config::{self, Config, GlobalRule, Identifiable, Route, Service, Upstream, SSL},
    core::{status, ProxyError, ProxyResult},
    plugins::{build_plugin, traffic_split},
    proxy::{
        control_plane::{
            prepare_candidate, validate_config_set, CandidateSnapshot, ResourceConfigSet,
        },
        runtime::{RuntimeSnapshot, RUNTIME},
        ssl::ProxySSL,
    },
    utils::encryption::SecretOp,
};

static PREPARATION_ATTEMPTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_control_plane_preparation_total",
        "Control-plane candidate preparation attempts",
        &["outcome"]
    )
    .expect("control-plane preparation metric registration must succeed")
});
static PENDING_REVISION: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "pingsix_control_plane_pending_revision",
        "Latest etcd revision awaiting successful publication, or zero"
    )
    .expect("control-plane pending revision metric registration must succeed")
});

// =============================================================================
// STORAGE-NEUTRAL GRAPH VOCABULARY
// =============================================================================

/// The configuration resource kinds managed by the graph authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Upstream,
    Service,
    GlobalRule,
    Route,
    Ssl,
}

impl ResourceKind {
    /// Storage segment used by etcd keys and Admin API paths.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstreams",
            Self::Service => "services",
            Self::GlobalRule => "global_rules",
            Self::Route => "routes",
            Self::Ssl => "ssls",
        }
    }

    pub fn parse(value: &str) -> Result<Self, GraphError> {
        match value {
            "upstreams" => Ok(Self::Upstream),
            "services" => Ok(Self::Service),
            "global_rules" => Ok(Self::GlobalRule),
            "routes" => Ok(Self::Route),
            "ssls" => Ok(Self::Ssl),
            other => Err(GraphError::InvalidKey {
                key: other.to_string(),
                reason: "unknown resource kind".into(),
            }),
        }
    }
}

/// Logical identity of one stored configuration resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResourceKey {
    pub kind: ResourceKind,
    pub id: String,
}

impl ResourceKey {
    pub fn new(kind: ResourceKind, id: impl Into<String>) -> Result<Self, GraphError> {
        let id = id.into();
        if id.is_empty() || id.contains('/') {
            return Err(GraphError::InvalidKey {
                key: format!("{}/{}", kind.as_str(), id),
                reason: "resource id must be non-empty and must not contain '/'".into(),
            });
        }
        Ok(Self { kind, id })
    }

    pub fn logical_path(&self) -> String {
        format!("{}/{}", self.kind.as_str(), self.id)
    }
}

/// One stored resource: stored bytes plus revision metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredResource {
    pub value: Vec<u8>,
    pub create_revision: i64,
    pub mod_revision: i64,
}

/// A complete stored configuration graph plus its generation guard revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredGraph {
    pub resources: HashMap<ResourceKey, StoredResource>,
    /// Mod revision of the graph generation guard; `None` before its first write.
    pub guard_mod_revision: Option<i64>,
    /// Cluster revision of the read that produced this snapshot.
    pub revision: i64,
}

/// One causally ordered watch response mapped to logical changes.
#[derive(Clone, Debug, Default)]
pub struct WatchBatch {
    pub revision: i64,
    pub changes: Vec<StoredChange>,
}

#[derive(Clone, Debug)]
pub enum StoredChange {
    Put {
        key: ResourceKey,
        resource: StoredResource,
    },
    Delete {
        key: ResourceKey,
    },
}

/// A validated mutation plus CAS expectations derived from one snapshot.
#[derive(Clone, Debug)]
pub struct GraphCommit {
    pub mutation: StoredMutation,
    /// `None` means the target must not exist yet (create).
    pub expected_target_mod_revision: Option<i64>,
    /// `None` means the guard must not exist yet.
    pub expected_guard_mod_revision: Option<i64>,
}

#[derive(Clone, Debug)]
pub enum StoredMutation {
    Put { key: ResourceKey, value: Vec<u8> },
    Delete { key: ResourceKey },
}

/// Cluster revision at which a committed mutation landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitRevision(pub i64);

/// Admin-facing view of one stored resource: decrypted and redacted.
#[derive(Clone, Debug)]
pub struct ResourceView {
    pub key: ResourceKey,
    pub value: serde_json::Value,
    pub create_revision: i64,
    pub mod_revision: i64,
}

/// Whether stored secret fields are decrypted while decoding a graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretMode {
    /// Decrypt marked fields and fail closed on ciphertext (runtime ingestion).
    DecryptForRuntime,
    /// Leave stored bytes untouched (Admin candidate validation).
    PreserveStored,
}

/// Which secret operation failed, for error reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretOperation {
    Encrypt,
    Decrypt,
    Redact,
    Restore,
}

/// Errors from the external configuration store.
#[derive(Debug)]
pub enum StoreError {
    Unavailable { source: ProxyError },
    InvalidResponse { message: String },
    UnsupportedProtocol,
    Conflict,
}

/// The external configuration store seam: whole-graph snapshot + guarded CAS.
///
/// Only whole-graph operations are exposed so callers cannot bypass the
/// graph authority's consistency model with point reads or writes.
#[async_trait]
pub trait GraphStore: Send + Sync {
    /// Read the complete stored graph with its generation guard revision.
    async fn snapshot(&self) -> Result<StoredGraph, StoreError>;

    /// Atomically apply a validated mutation if target and guard still match.
    async fn compare_and_swap(&self, commit: GraphCommit) -> Result<CommitRevision, StoreError>;
}

/// Domain errors of the configuration graph authority.
#[derive(Debug)]
pub enum GraphError {
    InvalidKey {
        key: String,
        reason: String,
    },
    InvalidResource {
        key: ResourceKey,
        source: ProxyError,
    },
    InvalidCandidate {
        source: ProxyError,
    },
    ReferentialConflict {
        source: ProxyError,
    },
    NotFound {
        key: ResourceKey,
    },
    CasConflict,
    StaleRevision {
        incoming: i64,
        published: i64,
    },
    Secret {
        key: ResourceKey,
        operation: SecretOperation,
        source: ProxyError,
    },
    Preparation {
        revision: i64,
        source: ProxyError,
    },
    WorkerStopped,
    Store(StoreError),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey { key, reason } => write!(f, "invalid key '{key}': {reason}"),
            Self::InvalidResource { key, source } => {
                write!(f, "invalid resource '{}': {source}", key.logical_path())
            }
            Self::InvalidCandidate { source } => write!(f, "invalid candidate graph: {source}"),
            Self::ReferentialConflict { source } => {
                write!(f, "candidate graph has conflicting references: {source}")
            }
            Self::NotFound { key } => write!(f, "resource '{}' not found", key.logical_path()),
            Self::CasConflict => write!(f, "configuration graph changed concurrently"),
            Self::StaleRevision {
                incoming,
                published,
            } => write!(
                f,
                "rejecting stale watch revision {incoming} < published revision {published}"
            ),
            Self::Secret {
                key,
                operation,
                source,
            } => write!(
                f,
                "secret {:?} failed for '{}': {source}",
                operation,
                key.logical_path()
            ),
            Self::Preparation { revision, source } => {
                write!(
                    f,
                    "candidate preparation failed at revision {revision}: {source}"
                )
            }
            Self::WorkerStopped => write!(f, "control-plane preparation worker stopped"),
            Self::Store(err) => write!(f, "configuration store error: {err:?}"),
        }
    }
}

impl std::error::Error for GraphError {}

// =============================================================================
// PURE GRAPH OPERATIONS
// =============================================================================

/// Decode a stored graph into typed resources. `DecryptForRuntime` fails
/// closed on undecryptable secret values; `PreserveStored` leaves them.
pub(crate) fn decode_graph(
    graph: &StoredGraph,
    mode: SecretMode,
) -> ProxyResult<ResourceConfigSet> {
    let decrypt = mode == SecretMode::DecryptForRuntime;
    let mut set = ResourceConfigSet::default();
    for (key, resource) in &graph.resources {
        insert_resource(&mut set, key, &resource.value, decrypt)?;
    }
    Ok(set)
}

fn insert_resource(
    set: &mut ResourceConfigSet,
    key: &ResourceKey,
    value: &[u8],
    decrypt: bool,
) -> ProxyResult<()> {
    match key.kind {
        ResourceKind::Upstream => {
            let mut resource = resource_from_stored::<Upstream>(value, "upstreams", decrypt)?;
            resource.set_id(key.id.clone());
            set.upstreams.insert(key.id.clone(), resource);
        }
        ResourceKind::Service => {
            let mut resource = resource_from_stored::<Service>(value, "services", decrypt)?;
            resource.set_id(key.id.clone());
            set.services.insert(key.id.clone(), resource);
        }
        ResourceKind::GlobalRule => {
            let mut resource = resource_from_stored::<GlobalRule>(value, "global_rules", decrypt)?;
            resource.set_id(key.id.clone());
            set.global_rules.insert(key.id.clone(), resource);
        }
        ResourceKind::Route => {
            let mut resource = resource_from_stored::<Route>(value, "routes", decrypt)?;
            resource.set_id(key.id.clone());
            set.routes.insert(key.id.clone(), resource);
        }
        ResourceKind::Ssl => {
            let mut resource = resource_from_stored::<SSL>(value, "ssls", decrypt)?;
            resource.set_id(key.id.clone());
            set.ssls.insert(key.id.clone(), resource);
        }
    }
    Ok(())
}

fn resource_from_stored<T: serde::de::DeserializeOwned>(
    value: &[u8],
    resource_type: &str,
    decrypt: bool,
) -> ProxyResult<T> {
    let mut json = serde_json::from_slice::<serde_json::Value>(value)
        .map_err(|e| ProxyError::serialization_error("Failed to parse resource JSON", e))?;
    if decrypt {
        config::transform_resource_secrets(resource_type, &mut json, SecretOp::Decrypt)?;
    }
    serde_json::from_value(json)
        .map_err(|e| ProxyError::serialization_error("Failed to deserialize resource", e))
}

/// Apply a watch batch to a base graph. Later changes for the same key win.
pub(crate) fn apply_watch_batch(
    base: &StoredGraph,
    batch: &WatchBatch,
) -> Result<StoredGraph, GraphError> {
    if batch.changes.is_empty() {
        return Ok(base.clone());
    }
    let mut next = base.clone();
    next.revision = batch.revision;
    for change in &batch.changes {
        match change {
            StoredChange::Put { key, resource } => {
                next.resources.insert(key.clone(), resource.clone());
            }
            StoredChange::Delete { key } => {
                next.resources.remove(key);
            }
        }
    }
    Ok(next)
}

/// Build the candidate graph for a PUT and derive the CAS commit expectations.
pub(crate) fn plan_put_mutation(
    snapshot: &StoredGraph,
    key: &ResourceKey,
    stored_value: Vec<u8>,
) -> Result<GraphCommit, GraphError> {
    let mut candidate = snapshot.clone();
    candidate.resources.insert(
        key.clone(),
        StoredResource {
            value: stored_value.clone(),
            create_revision: 0,
            mod_revision: 0,
        },
    );
    let set = decode_graph(&candidate, SecretMode::PreserveStored)
        .map_err(|e| GraphError::InvalidCandidate { source: e })?;
    validate_config_set(&set).map_err(|e| GraphError::InvalidCandidate { source: e })?;
    let expected_target_mod_revision = snapshot.resources.get(key).map(|r| r.mod_revision);
    Ok(GraphCommit {
        mutation: StoredMutation::Put {
            key: key.clone(),
            value: stored_value,
        },
        expected_target_mod_revision,
        expected_guard_mod_revision: snapshot.guard_mod_revision,
    })
}

/// Build the candidate graph for a DELETE and derive the CAS commit expectations.
pub(crate) fn plan_delete_mutation(
    snapshot: &StoredGraph,
    key: &ResourceKey,
) -> Result<GraphCommit, GraphError> {
    let existing = snapshot
        .resources
        .get(key)
        .ok_or_else(|| GraphError::NotFound { key: key.clone() })?;
    let mut candidate = snapshot.clone();
    candidate.resources.remove(key);
    let set = decode_graph(&candidate, SecretMode::PreserveStored)
        .map_err(|e| GraphError::ReferentialConflict { source: e })?;
    validate_config_set(&set).map_err(|e| GraphError::ReferentialConflict { source: e })?;
    Ok(GraphCommit {
        mutation: StoredMutation::Delete { key: key.clone() },
        expected_target_mod_revision: Some(existing.mod_revision),
        expected_guard_mod_revision: snapshot.guard_mod_revision,
    })
}

// =============================================================================
// GRAPH AUTHORITY
// =============================================================================

/// Sentinel [`redact`] writes over secrets; on write it means "keep the stored
/// value" rather than "set the secret to this literal string".
const REDACTED_SENTINEL: &str = "***";

/// The single authority over stored and pending configuration graph state.
///
/// All graph reads, mutations, list/watch ingestion, and runtime publication
/// cross this interface. The store is injected behind the [`GraphStore`] seam;
/// HTTP and etcd transport stay in their adapters.
#[derive(Clone)]
pub struct ConfigurationGraph {
    inner: Arc<Inner>,
}

/// Last generation whose runtime snapshot published successfully.
struct CommittedGraph {
    stored: StoredGraph,
}

/// Latest submitted generation, including invalid or DNS-pending candidates.
#[derive(Clone)]
struct PendingGraph {
    generation: u64,
    revision: i64,
    stored: StoredGraph,
    logical: ResourceConfigSet,
    cancellation: CancellationToken,
}

struct Inner {
    store: Arc<dyn GraphStore>,
    committed: Mutex<Option<CommittedGraph>>,
    target: Mutex<Option<PendingGraph>>,
    /// Serializes only short raw-candidate creation and fenced publish commits.
    write_lock: Mutex<()>,
    latest_generation: Mutex<u64>,
    /// One bounded owner serializes preparation; submissions replace its
    /// pending target and never block list/watch processing on DNS.
    preparation: AsyncMutex<()>,
    worker_tx: Mutex<Option<mpsc::Sender<()>>>,
    worker_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    active_cancellation: Mutex<Option<CancellationToken>>,
}

impl ConfigurationGraph {
    pub fn new(store: Arc<dyn GraphStore>) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                committed: Mutex::new(None),
                target: Mutex::new(None),
                write_lock: Mutex::new(()),
                latest_generation: Mutex::new(0),
                preparation: AsyncMutex::new(()),
                worker_tx: Mutex::new(None),
                worker_task: Mutex::new(None),
                active_cancellation: Mutex::new(None),
            }),
        }
    }

    /// Accept an authoritative full list snapshot without waiting for DNS.
    ///
    /// The snapshot is decoded (fail-closed on secrets) and whole-graph
    /// validated synchronously before submission, so the etcd adapter can
    /// relist instead of silently accepting a broken graph; the worker only
    /// prepares DNS and compiles.
    pub fn replace_all(&self, snapshot: StoredGraph) -> Result<(), GraphError> {
        let logical = decode_graph(&snapshot, SecretMode::DecryptForRuntime)
            .map_err(|e| GraphError::InvalidCandidate { source: e })?;
        validate_config_set(&logical).map_err(|e| GraphError::InvalidCandidate { source: e })?;
        self.submit(snapshot, logical)
    }

    /// Accept one causally ordered watch batch without waiting for DNS.
    ///
    /// Changes layer on the latest pending target (otherwise the committed
    /// graph), so updates arriving while a previous generation is still
    /// preparing DNS are not lost. Empty batches are no-ops. The resulting
    /// graph is decoded and whole-graph validated synchronously, so invalid
    /// batches are rejected and the sync loop relists instead of retrying a
    /// broken candidate in the worker.
    pub fn apply_watch(&self, batch: WatchBatch) -> Result<(), GraphError> {
        if batch.changes.is_empty() {
            return Ok(());
        }
        let _writer = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let published = RUNTIME.load().revision;
        if batch.revision < published {
            return Err(GraphError::StaleRevision {
                incoming: batch.revision,
                published,
            });
        }
        let base = self
            .inner
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|t| t.stored.clone())
            .unwrap_or_else(|| {
                self.inner
                    .committed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|c| c.stored.clone())
                    .unwrap_or_default()
            });
        let stored = apply_watch_batch(&base, &batch)?;
        let logical = decode_graph(&stored, SecretMode::DecryptForRuntime)
            .map_err(|e| GraphError::InvalidCandidate { source: e })?;
        validate_config_set(&logical).map_err(|e| GraphError::InvalidCandidate { source: e })?;
        self.submit(stored, logical)
    }

    /// Stop accepting work, cancel in-flight preparation, and wait a bounded
    /// interval for the sole worker to observe cancellation.
    pub async fn shutdown(&self) {
        if let Some(active) = self
            .inner
            .active_cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            active.cancel();
        }
        self.inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        PENDING_REVISION.set(0);
        let task = self
            .inner
            .worker_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(mut task) = task {
            if tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .is_err()
            {
                log::warn!("Control-plane preparation worker missed shutdown deadline; aborting");
                task.abort();
                let _ = task.await;
            }
        }
    }

    /// Static startup path: prepare DNS fully before returning and publishing.
    ///
    /// Unlike the dynamic path, preparation must finish before listeners start;
    /// unresolvable DNS-only upstreams fail the process.
    pub fn load_static(config: &Config) -> ProxyResult<Arc<RuntimeSnapshot>> {
        let resources = ResourceConfigSet::from_yaml_config(config);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                ProxyError::Configuration(format!("Failed to create DNS preparation runtime: {e}"))
            })?;
        let prepared = rt.block_on(async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
                    ProxyError::Configuration(format!("Failed to install SIGTERM handler: {e}"))
                })?;
                tokio::select! {
                    result = prepare_candidate(&resources) => result,
                    _ = sigterm.recv() => Err(ProxyError::Configuration(
                        "Static configuration DNS preparation cancelled by SIGTERM".into(),
                    )),
                }
            }
            #[cfg(not(unix))]
            {
                prepare_candidate(&resources).await
            }
        })?;
        let candidate = CandidateSnapshot::build_prepared(resources, &prepared)?;
        let snapshot = RuntimeSnapshot::compile(candidate, 0)?;
        let published = RUNTIME.publish(snapshot)?;
        status::mark_ready(status::ConfigSource::Yaml);
        Ok(published)
    }

    /// Start the single bounded preparation worker if it is not already running.
    fn ensure_worker_started(&self) -> Result<(), GraphError> {
        if self
            .inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(());
        }
        let (tx, mut rx) = mpsc::channel(1);
        *self
            .inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let graph = self.clone();
        let task = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                let mut retry_delay = std::time::Duration::from_secs(1);
                loop {
                    // Snapshot the target this attempt will serve, so a failure
                    // can tell whether a newer submission superseded it before
                    // sleeping out the failed generation's backoff.
                    let attempted = graph.current_target();
                    match graph.prepare_latest().await {
                        Ok(()) => break,
                        Err(error) => {
                            PREPARATION_ATTEMPTS.with_label_values(&["failed"]).inc();
                            status::record_preparation_error(error.to_string());
                            log::warn!(
                                "Control-plane candidate preparation failed; retrying in {}s: {error}",
                                retry_delay.as_secs()
                            );
                            let Some((failed_generation, cancellation)) = attempted else {
                                break;
                            };
                            if !graph.is_current_generation(failed_generation) {
                                // A newer submission superseded the failed
                                // generation: restart preparation for the
                                // latest target immediately instead of waiting
                                // out the old generation's backoff.
                                continue;
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(retry_delay) => {}
                                _ = cancellation.cancelled() => break,
                            }
                            retry_delay = (retry_delay * 2).min(std::time::Duration::from_secs(30));
                        }
                    }
                }
            }
        });
        self.inner
            .worker_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(task);
        Ok(())
    }

    /// Store a new pending generation and signal the worker. Submissions never
    /// wait for DNS; the worker always reads the latest generation.
    fn submit(&self, stored: StoredGraph, logical: ResourceConfigSet) -> Result<(), GraphError> {
        self.ensure_worker_started()?;
        let generation = {
            let mut generation = self
                .inner
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *generation += 1;
            *generation
        };
        let revision = stored.revision;
        let cancellation = CancellationToken::new();
        if let Some(previous) = self
            .inner
            .active_cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(cancellation.clone())
        {
            previous.cancel();
        }
        *self.inner.target.lock().unwrap_or_else(|e| e.into_inner()) = Some(PendingGraph {
            generation,
            revision,
            stored,
            logical,
            cancellation,
        });
        PENDING_REVISION.set(revision);
        let sender = self
            .inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(GraphError::WorkerStopped)?;
        match sender.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(GraphError::WorkerStopped),
        }
    }

    /// Snapshot of the current pending target's generation and cancellation
    /// token, taken before a preparation attempt so a failure can detect that
    /// a newer submission superseded it.
    fn current_target(&self) -> Option<(u64, CancellationToken)> {
        self.inner
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|target| (target.generation, target.cancellation.clone()))
    }

    /// Whether `generation` is still the latest submitted generation.
    fn is_current_generation(&self, generation: u64) -> bool {
        *self
            .inner
            .latest_generation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            == generation
    }

    /// Prepare, compile, and publish the latest pending generation.
    async fn prepare_latest(&self) -> ProxyResult<()> {
        let _owner = self.inner.preparation.lock().await;
        let Some(target) = self
            .inner
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return Ok(());
        };
        let PendingGraph {
            generation,
            revision,
            stored,
            logical,
            cancellation,
        } = target;
        let prepared = tokio::select! {
            result = prepare_candidate(&logical) => result?,
            _ = cancellation.cancelled() => return Ok(()),
        };
        let _writer = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if cancellation.is_cancelled()
            || *self
                .inner
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                != generation
        {
            return Ok(());
        }
        if revision < RUNTIME.load().revision {
            return Ok(());
        }
        let candidate = CandidateSnapshot::build_prepared(logical.clone(), &prepared)?;
        let published = RUNTIME.publish(RuntimeSnapshot::compile(candidate, revision)?)?;
        *self
            .inner
            .committed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(CommittedGraph { stored });
        PENDING_REVISION.set(0);
        PREPARATION_ATTEMPTS.with_label_values(&["published"]).inc();
        log::debug!(
            "Published prepared control-plane generation {generation} at revision {}",
            published.revision
        );
        Ok(())
    }

    /// Read one stored resource, decrypted and redacted, for the Admin API.
    pub async fn get(&self, key: &ResourceKey) -> Result<Option<ResourceView>, GraphError> {
        let snapshot = self
            .inner
            .store
            .snapshot()
            .await
            .map_err(GraphError::Store)?;
        let Some(resource) = snapshot.resources.get(key) else {
            return Ok(None);
        };
        let mut json = parse_stored_resource(key, &resource.value)?;
        decrypt_for_read(key.kind, &mut json).map_err(|source| GraphError::Secret {
            key: key.clone(),
            operation: SecretOperation::Decrypt,
            source,
        })?;
        redact(key.kind, &mut json);
        Ok(Some(ResourceView {
            key: key.clone(),
            value: json,
            create_revision: resource.create_revision,
            mod_revision: resource.mod_revision,
        }))
    }

    /// List all stored resources of one kind, decrypted and redacted.
    pub async fn list(&self, kind: ResourceKind) -> Result<Vec<ResourceView>, GraphError> {
        let snapshot = self
            .inner
            .store
            .snapshot()
            .await
            .map_err(GraphError::Store)?;
        let mut views = Vec::new();
        for (key, resource) in &snapshot.resources {
            if key.kind != kind {
                continue;
            }
            let mut json = parse_stored_resource(key, &resource.value)?;
            decrypt_for_read(kind, &mut json).map_err(|source| GraphError::Secret {
                key: key.clone(),
                operation: SecretOperation::Decrypt,
                source,
            })?;
            redact(kind, &mut json);
            views.push(ResourceView {
                key: key.clone(),
                value: json,
                create_revision: resource.create_revision,
                mod_revision: resource.mod_revision,
            });
        }
        views.sort_by(|a, b| a.key.id.cmp(&b.key.id));
        Ok(views)
    }

    /// Validate and commit an Admin PUT. `value` is the logical plaintext JSON,
    /// possibly containing the redaction sentinel at genuine secret paths.
    ///
    /// Secret restoration and CAS planning derive from the same snapshot, so a
    /// concurrent update cannot mix an older secret with a newer observation.
    pub async fn put(
        &self,
        key: ResourceKey,
        mut value: serde_json::Value,
    ) -> Result<CommitRevision, GraphError> {
        let snapshot = self
            .inner
            .store
            .snapshot()
            .await
            .map_err(GraphError::Store)?;

        if contains_redaction_sentinel(&value) {
            if let Some(stored) = snapshot.resources.get(&key) {
                let mut existing = parse_stored_resource(&key, &stored.value)?;
                decrypt_for_read(key.kind, &mut existing).map_err(|source| GraphError::Secret {
                    key: key.clone(),
                    operation: SecretOperation::Restore,
                    source,
                })?;
                restore_redacted_secrets(key.kind, &mut value, &existing);
            }
        }

        validate_resource_json(key.kind, &value).map_err(|source| GraphError::InvalidResource {
            key: key.clone(),
            source,
        })?;

        let stored =
            encrypt_for_storage(key.kind, &mut value).map_err(|source| GraphError::Secret {
                key: key.clone(),
                operation: SecretOperation::Encrypt,
                source,
            })?;

        let commit = plan_put_mutation(&snapshot, &key, stored)?;
        self.inner
            .store
            .compare_and_swap(commit)
            .await
            .map_err(map_store_error)
    }

    /// Validate and commit an Admin DELETE against the whole graph.
    pub async fn delete(&self, key: ResourceKey) -> Result<CommitRevision, GraphError> {
        let snapshot = self
            .inner
            .store
            .snapshot()
            .await
            .map_err(GraphError::Store)?;
        let commit = plan_delete_mutation(&snapshot, &key)?;
        self.inner
            .store
            .compare_and_swap(commit)
            .await
            .map_err(map_store_error)
    }
}

fn map_store_error(err: StoreError) -> GraphError {
    match err {
        StoreError::Conflict => GraphError::CasConflict,
        other => GraphError::Store(other),
    }
}

fn parse_stored_resource(key: &ResourceKey, value: &[u8]) -> Result<serde_json::Value, GraphError> {
    serde_json::from_slice(value).map_err(|e| GraphError::InvalidResource {
        key: key.clone(),
        source: ProxyError::serialization_error("Failed to parse stored resource", e),
    })
}

/// Validate a logical resource JSON document against its typed schema, plugin
/// configurations, and (for SSL) certificate/key material.
fn validate_resource_json(kind: ResourceKind, value: &serde_json::Value) -> ProxyResult<()> {
    match kind {
        ResourceKind::Upstream => {
            let resource: Upstream =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
        }
        ResourceKind::Service => {
            let resource: Service =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            validate_plugins(&resource.plugins)?;
        }
        ResourceKind::GlobalRule => {
            let resource: GlobalRule =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            validate_plugins(&resource.plugins)?;
        }
        ResourceKind::Route => {
            let resource: Route =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            validate_plugins(&resource.plugins)?;
        }
        ResourceKind::Ssl => {
            let resource: SSL =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            ProxySSL::try_from(resource)?;
        }
    }
    Ok(())
}

fn serialization_error(e: serde_json::Error) -> ProxyError {
    ProxyError::serialization_error("Failed to deserialize resource JSON", e)
}

/// Build every configured plugin to surface invalid plugin configuration.
/// Traffic-split is validated structurally without resolving named upstreams;
/// candidate publication owns reference resolution against the same graph.
fn validate_plugins(plugins: &HashMap<String, serde_json::Value>) -> ProxyResult<()> {
    for (name, value) in plugins {
        if name == traffic_split::PLUGIN_NAME {
            traffic_split::validate_traffic_split_config(value).map_err(|e| {
                ProxyError::Plugin(format!("Failed to validate plugin '{name}': {e}"))
            })?;
            continue;
        }
        build_plugin(name, value.clone())
            .map_err(|e| ProxyError::Plugin(format!("Failed to validate plugin '{name}': {e}")))?;
    }
    Ok(())
}

/// Mask secret fields (SSL/TLS private keys, plugin credentials) with `***`.
///
/// Reuses the exact same `#[encrypt]` field walk as encrypt/decrypt, so the
/// masked set is the single source of truth. Performs no crypto and cannot fail.
pub fn redact(kind: ResourceKind, value: &mut serde_json::Value) {
    config::transform_resource_secrets(kind.as_str(), value, SecretOp::Redact)
        .expect("redaction performs no fallible crypto");
}

/// Does any string leaf equal the redaction sentinel? Used to skip the extra
/// store read on the common PUT path where the client sends real values.
fn contains_redaction_sentinel(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s == REDACTED_SENTINEL,
        serde_json::Value::Array(items) => items.iter().any(contains_redaction_sentinel),
        serde_json::Value::Object(map) => map.values().any(contains_redaction_sentinel),
        _ => false,
    }
}

/// Restore secrets the client left redacted (`"***"`) from the stored resource,
/// so a GET/LIST → edit → PUT round-trip preserves untouched secrets.
///
/// Restoration is scoped to true secret leaves: redacting a copy of the stored
/// (decrypted) resource yields exactly the secret paths, and only there is an
/// incoming sentinel swapped for the stored plaintext. A client rotating a
/// secret sends its new value (not the sentinel), which is left untouched.
pub fn restore_redacted_secrets(
    kind: ResourceKind,
    incoming: &mut serde_json::Value,
    existing_plaintext: &serde_json::Value,
) {
    let mut secret_map = existing_plaintext.clone();
    redact(kind, &mut secret_map);
    restore_walk(incoming, existing_plaintext, &secret_map);
}

/// Walk driven by `secret_map` (the redacted stored resource): its sentinel
/// leaves mark secret paths. Where `incoming` still holds the sentinel at such
/// a path, replace it with the stored plaintext at the same path.
fn restore_walk(
    incoming: &mut serde_json::Value,
    plaintext: &serde_json::Value,
    secret_map: &serde_json::Value,
) {
    match secret_map {
        serde_json::Value::String(s)
            if s == REDACTED_SENTINEL && incoming.as_str() == Some(REDACTED_SENTINEL) =>
        {
            *incoming = plaintext.clone();
        }
        serde_json::Value::Object(map) => {
            let (Some(inc), Some(pt)) = (incoming.as_object_mut(), plaintext.as_object()) else {
                return;
            };
            for (key, sub) in map {
                if let (Some(iv), Some(pv)) = (inc.get_mut(key), pt.get(key)) {
                    restore_walk(iv, pv, sub);
                }
            }
        }
        serde_json::Value::Array(items) => {
            let (Some(inc), Some(pt)) = (incoming.as_array_mut(), plaintext.as_array()) else {
                return;
            };
            for (i, sub) in items.iter().enumerate() {
                if let (Some(iv), Some(pv)) = (inc.get_mut(i), pt.get(i)) {
                    restore_walk(iv, pv, sub);
                }
            }
        }
        _ => {}
    }
}

/// Compact a validated resource to storage bytes, encrypting sensitive fields
/// first when data encryption is enabled. No-op when encryption is disabled.
fn encrypt_for_storage(kind: ResourceKind, value: &mut serde_json::Value) -> ProxyResult<Vec<u8>> {
    if crate::utils::encryption::is_enabled() {
        config::transform_resource_secrets(kind.as_str(), value, SecretOp::Encrypt)?;
    }
    serde_json::to_vec(value)
        .map_err(|e| ProxyError::serialization_error("Failed to serialize resource for storage", e))
}

/// Decrypt a resource's secret fields for the read API (GET/LIST). Fail-closed:
/// an undecryptable value surfaces an error rather than leaking ciphertext.
fn decrypt_for_read(kind: ResourceKind, value: &mut serde_json::Value) -> ProxyResult<()> {
    if crate::utils::encryption::is_enabled() {
        config::transform_resource_secrets(kind.as_str(), value, SecretOp::Decrypt)?;
    }
    Ok(())
}

#[cfg(test)]
mod pure_graph_tests {
    use super::*;

    fn stored_upstream_json(id: &str, node: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "nodes": { node: 1 },
            "type": "roundrobin",
            "hash_on": "vars",
            "key": "uri",
            "scheme": "http",
            "pass_host": "pass",
        }))
        .unwrap()
    }

    fn stored_route_json(id: &str, upstream_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "uri": "/",
            "upstream_id": upstream_id,
        }))
        .unwrap()
    }

    fn stored_service_json(id: &str, upstream_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "upstream_id": upstream_id,
        }))
        .unwrap()
    }

    fn stored_global_rule_json(id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "plugins": {},
        }))
        .unwrap()
    }

    fn stored_ssl_json(id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "cert": "C",
            "key": "K",
            "snis": ["example.com"],
        }))
        .unwrap()
    }

    fn stored(_key: ResourceKey, value: Vec<u8>) -> StoredResource {
        StoredResource {
            value,
            create_revision: 1,
            mod_revision: 1,
        }
    }

    fn sample_graph() -> StoredGraph {
        let mut graph = StoredGraph {
            guard_mod_revision: Some(1),
            revision: 10,
            ..Default::default()
        };
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Upstream, "u1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Upstream, "u1").unwrap(),
                stored_upstream_json("body-id-ignored", "127.0.0.1:80"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
                stored_route_json("r1", "u1"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Service, "s1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Service, "s1").unwrap(),
                stored_service_json("s1", "u1"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::GlobalRule, "g1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::GlobalRule, "g1").unwrap(),
                stored_global_rule_json("g1"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                stored_ssl_json("t1"),
            ),
        );
        graph
    }

    #[test]
    fn resource_kind_parse_round_trips() {
        for kind in [
            ResourceKind::Upstream,
            ResourceKind::Service,
            ResourceKind::GlobalRule,
            ResourceKind::Route,
            ResourceKind::Ssl,
        ] {
            assert_eq!(ResourceKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(matches!(
            ResourceKind::parse("certificates"),
            Err(GraphError::InvalidKey { .. })
        ));
    }

    #[test]
    fn resource_key_rejects_empty_and_slashed_ids() {
        assert!(ResourceKey::new(ResourceKind::Route, "").is_err());
        assert!(ResourceKey::new(ResourceKind::Route, "a/b").is_err());
        assert_eq!(
            ResourceKey::new(ResourceKind::Route, "r1")
                .unwrap()
                .logical_path(),
            "routes/r1"
        );
    }

    #[test]
    fn decode_graph_round_trips_all_kinds_and_uses_key_id() {
        let graph = sample_graph();
        let set = decode_graph(&graph, SecretMode::PreserveStored).unwrap();

        // IDs come from the storage key, never the JSON body.
        assert_eq!(set.upstreams.get("u1").unwrap().id, "u1");
        assert_eq!(set.upstreams["u1"].nodes.get("127.0.0.1:80"), Some(&1));
        assert!(set.routes.contains_key("r1"));
        assert!(set.services.contains_key("s1"));
        assert!(set.global_rules.contains_key("g1"));
        assert!(set.ssls.contains_key("t1"));
        assert_eq!(set.upstreams.len(), 1);
    }

    #[test]
    fn decode_preserve_stored_tolerates_ciphertext() {
        let mut graph = StoredGraph::default();
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                serde_json::to_vec(&serde_json::json!({
                    "id": "t1",
                    "cert": "C",
                    "key": "$pingsix-enc:v1$ciphertext",
                    "snis": ["example.com"],
                }))
                .unwrap(),
            ),
        );
        let set = decode_graph(&graph, SecretMode::PreserveStored).unwrap();
        assert_eq!(
            set.ssls["t1"].key, "$pingsix-enc:v1$ciphertext",
            "validation path must not touch secret values"
        );
    }

    #[test]
    fn decode_runtime_fails_closed_on_ciphertext() {
        let mut graph = StoredGraph::default();
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                serde_json::to_vec(&serde_json::json!({
                    "id": "t1",
                    "cert": "C",
                    "key": "$pingsix-enc:v1$ciphertext",
                    "snis": ["example.com"],
                }))
                .unwrap(),
            ),
        );
        let err = decode_graph(&graph, SecretMode::DecryptForRuntime).unwrap_err();
        assert!(
            err.to_string().contains("Encrypted value found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn apply_watch_put_then_delete_removes_key() {
        let base = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), stored_route_json("r1", "u1")),
                },
                StoredChange::Delete { key: key.clone() },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        assert!(!next.resources.contains_key(&key));
        assert_eq!(next.revision, 11);
        assert_eq!(base.revision, 10, "base graph must not be mutated");
    }

    #[test]
    fn apply_watch_delete_then_put_keeps_final_resource() {
        let base = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Delete { key: key.clone() },
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), stored_route_json("r1", "u1")),
                },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        assert!(next.resources.contains_key(&key));
    }

    #[test]
    fn apply_watch_same_key_later_wins() {
        let base = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r2").unwrap();
        let v1 = serde_json::to_vec(&serde_json::json!({"id":"r2","uri":"/v1","upstream_id":"u1"}))
            .unwrap();
        let v2 = serde_json::to_vec(&serde_json::json!({"id":"r2","uri":"/v2","upstream_id":"u1"}))
            .unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), v1),
                },
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), v2),
                },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        let decoded = decode_graph(&next, SecretMode::PreserveStored).unwrap();
        assert_eq!(decoded.routes["r2"].uri.as_deref(), Some("/v2"));
    }

    #[test]
    fn apply_watch_empty_batch_is_noop() {
        let base = sample_graph();
        let next = apply_watch_batch(&base, &WatchBatch::default()).unwrap();
        assert_eq!(next, base);
    }

    #[test]
    fn apply_watch_different_keys_both_retained() {
        let base = sample_graph();
        let r2 = ResourceKey::new(ResourceKind::Route, "r2").unwrap();
        let s2 = ResourceKey::new(ResourceKind::Service, "s2").unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Put {
                    key: r2.clone(),
                    resource: stored(r2.clone(), stored_route_json("r2", "u1")),
                },
                StoredChange::Put {
                    key: s2.clone(),
                    resource: stored(s2.clone(), stored_service_json("s2", "u1")),
                },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        assert!(next.resources.contains_key(&r2));
        assert!(next.resources.contains_key(&s2));
        assert!(next
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Upstream, "u1").unwrap()));
    }

    #[test]
    fn plan_put_create_uses_absent_target_expectation() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r2").unwrap();
        let commit = plan_put_mutation(&snapshot, &key, stored_route_json("r2", "u1")).unwrap();
        assert_eq!(commit.expected_target_mod_revision, None);
        assert_eq!(
            commit.expected_guard_mod_revision,
            snapshot.guard_mod_revision
        );
        match commit.mutation {
            StoredMutation::Put { key: k, value } => {
                assert_eq!(k, key);
                assert!(!value.is_empty());
            }
            _ => panic!("expected Put"),
        }
    }

    #[test]
    fn plan_put_replace_uses_exact_mod_revision() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        let commit =
            plan_put_mutation(&snapshot, &key, stored_upstream_json("u1", "127.0.0.1:81")).unwrap();
        assert_eq!(
            commit.expected_target_mod_revision,
            Some(snapshot.resources[&key].mod_revision)
        );
    }

    #[test]
    fn plan_put_rejects_dangling_upstream_id() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "bad").unwrap();
        let err =
            plan_put_mutation(&snapshot, &key, stored_route_json("bad", "missing")).unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn plan_delete_missing_target_is_not_found() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "ghost").unwrap();
        let err = plan_delete_mutation(&snapshot, &key).unwrap_err();
        assert!(matches!(err, GraphError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn plan_delete_referenced_upstream_conflicts() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        let err = plan_delete_mutation(&snapshot, &key).unwrap_err();
        assert!(
            matches!(err, GraphError::ReferentialConflict { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn plan_delete_unreferenced_upstream_succeeds() {
        let snapshot = sample_graph();
        let u2 = ResourceKey::new(ResourceKind::Upstream, "u2").unwrap();
        let mut snapshot = snapshot;
        snapshot.resources.insert(
            u2.clone(),
            stored(u2.clone(), stored_upstream_json("u2", "127.0.0.1:82")),
        );
        let commit = plan_delete_mutation(&snapshot, &u2).unwrap();
        assert_eq!(
            commit.expected_target_mod_revision,
            Some(snapshot.resources[&u2].mod_revision)
        );
        assert!(matches!(commit.mutation, StoredMutation::Delete { .. }));
    }

    #[test]
    fn decode_graph_rejects_invalid_document_json() {
        // A malformed stored document must fail decode before it can enter a typed graph.
        let mut graph = StoredGraph::default();
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
                b"not-json".to_vec(),
            ),
        );
        assert!(decode_graph(&graph, SecretMode::PreserveStored).is_err());
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::config::etcd::InMemoryGraphStore;

    fn upstream_json(id: &str, node: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "nodes": { node: 1 },
            "type": "roundrobin",
            "hash_on": "vars",
            "key": "uri",
            "scheme": "http",
            "pass_host": "pass",
        })
    }

    fn route_json(id: &str, upstream_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "uri": "/",
            "upstream_id": upstream_id,
        })
    }

    fn ssl_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "cert": include_str!("testdata/example.crt"),
            "key": include_str!("testdata/example.key"),
            "snis": ["example.com"],
        })
    }

    async fn seed(store: &InMemoryGraphStore, key: ResourceKey, value: Vec<u8>) {
        store
            .compare_and_swap(GraphCommit {
                mutation: StoredMutation::Put { key, value },
                expected_target_mod_revision: None,
                expected_guard_mod_revision: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn put_commits_and_get_round_trips() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        let rev = graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        assert_eq!(rev.0, 1);

        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(route.clone(), route_json("r1", "u1"))
            .await
            .unwrap();

        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["uri"], "/");
        assert_eq!(view.mod_revision, 2);
        assert_eq!(graph.get(&up).await.unwrap().unwrap().create_revision, 1);

        assert!(graph
            .get(&ResourceKey::new(ResourceKind::Route, "ghost").unwrap())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn put_redacted_resave_restores_stored_secret() {
        let store = Arc::new(InMemoryGraphStore::new());
        let graph = ConfigurationGraph::new(store.clone());

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();

        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let stored = serde_json::json!({
            "id": "r1",
            "uri": "/",
            "upstream_id": "u1",
            "plugins": { "key-auth": { "keys": ["real-key"] } },
        });
        graph.put(route.clone(), stored.clone()).await.unwrap();

        // Client resaves the redacted GET body: the sentinel is restored from
        // the same snapshot used for the CAS commit.
        let resave = serde_json::json!({
            "id": "r1",
            "uri": "/v2",
            "upstream_id": "u1",
            "plugins": { "key-auth": { "keys": ["***"] } },
        });
        graph.put(route.clone(), resave.clone()).await.unwrap();

        // GET returns the redacted view by design; the stored value must hold
        // the restored secret.
        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["uri"], "/v2");
        assert_eq!(view.value["plugins"]["key-auth"]["keys"][0], "***");
        let snapshot = store.snapshot().await.unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&snapshot.resources[&route].value).unwrap();
        assert_eq!(stored["plugins"]["key-auth"]["keys"][0], "real-key");
    }

    #[tokio::test]
    async fn put_rotation_keeps_new_secret() {
        let store = Arc::new(InMemoryGraphStore::new());
        let graph = ConfigurationGraph::new(store.clone());

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(
                route.clone(),
                serde_json::json!({
                    "id": "r1", "uri": "/", "upstream_id": "u1",
                    "plugins": { "key-auth": { "keys": ["old-key"] } },
                }),
            )
            .await
            .unwrap();

        // Rotation sends a real value (not the sentinel); it must be kept.
        graph
            .put(
                route.clone(),
                serde_json::json!({
                    "id": "r1", "uri": "/", "upstream_id": "u1",
                    "plugins": { "key-auth": { "keys": ["new-key"] } },
                }),
            )
            .await
            .unwrap();

        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["plugins"]["key-auth"]["keys"][0], "***");
        let snapshot = store.snapshot().await.unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&snapshot.resources[&route].value).unwrap();
        assert_eq!(stored["plugins"]["key-auth"]["keys"][0], "new-key");
    }

    #[tokio::test]
    async fn put_invalid_candidate_rejects_without_store_mutation() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let before = graph.list(ResourceKind::Route).await.unwrap();

        let route = ResourceKey::new(ResourceKind::Route, "bad").unwrap();
        let err = graph
            .put(route.clone(), route_json("bad", "missing"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );

        let after = graph.list(ResourceKind::Route).await.unwrap();
        assert_eq!(before.len(), after.len());
        assert!(graph.get(&route).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_referenced_conflicts_and_missing_is_not_found() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(route.clone(), route_json("r1", "u1"))
            .await
            .unwrap();

        let err = graph.delete(up.clone()).await.unwrap_err();
        assert!(
            matches!(err, GraphError::ReferentialConflict { .. }),
            "{err:?}"
        );

        let err = graph
            .delete(ResourceKey::new(ResourceKind::Route, "ghost").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, GraphError::NotFound { .. }), "{err:?}");

        graph.delete(route.clone()).await.unwrap();
        graph.delete(up.clone()).await.unwrap();
        assert!(graph.list(ResourceKind::Route).await.unwrap().is_empty());
        assert!(graph.list(ResourceKind::Upstream).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_returns_only_requested_kind() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));
        graph
            .put(
                ResourceKey::new(ResourceKind::Upstream, "u1").unwrap(),
                upstream_json("u1", "127.0.0.1:80"),
            )
            .await
            .unwrap();
        graph
            .put(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                ssl_json("t1"),
            )
            .await
            .unwrap();
        graph
            .put(
                ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
                route_json("r1", "u1"),
            )
            .await
            .unwrap();

        let routes = graph.list(ResourceKind::Route).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key.id, "r1");
        let ssls = graph.list(ResourceKind::Ssl).await.unwrap();
        assert_eq!(ssls.len(), 1);
        assert_eq!(ssls[0].value["key"], "***", "GET/LIST views are redacted");
        assert_eq!(ssls[0].value["snis"], serde_json::json!(["example.com"]));
    }

    #[tokio::test]
    async fn undecryptable_sibling_does_not_block_unrelated_put() {
        let store = Arc::new(InMemoryGraphStore::new());
        let graph = ConfigurationGraph::new(store.clone());

        // Stored SSL whose key is ciphertext that cannot be decrypted (no
        // keyring installed in unit tests). Validation must not attempt to
        // decrypt it, so a repair PUT of an unrelated resource still works.
        let ssl = ResourceKey::new(ResourceKind::Ssl, "t1").unwrap();
        let mut ciphertext_ssl = ssl_json("t1");
        ciphertext_ssl["key"] = serde_json::json!("$pingsix-enc:v1$cipher");
        seed(
            store.as_ref(),
            ssl.clone(),
            serde_json::to_vec(&ciphertext_ssl).unwrap(),
        )
        .await;

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(route.clone(), route_json("r1", "u1"))
            .await
            .unwrap();
        assert!(graph.get(&route).await.unwrap().is_some());
    }

    // ---- Moved from admin: secret helper semantics ----

    #[test]
    fn redact_ssl_key() {
        let mut input = serde_json::json!({
            "cert": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            "key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        });
        redact(ResourceKind::Ssl, &mut input);
        assert_eq!(
            input["cert"],
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
        );
        assert_eq!(input["key"], "***");
    }

    #[test]
    fn redact_jwt_secret() {
        let mut input = serde_json::json!({ "plugins": { "jwt-auth": { "secret": "abc" } } });
        redact(ResourceKind::Route, &mut input);
        assert_eq!(input["plugins"]["jwt-auth"]["secret"], "***");
    }

    #[test]
    fn redact_basic_auth_password() {
        let mut input = serde_json::json!({
            "plugins": { "basic-auth": { "username": "u", "password": "p" } },
        });
        redact(ResourceKind::Route, &mut input);
        assert_eq!(input["plugins"]["basic-auth"]["username"], "u");
        assert_eq!(input["plugins"]["basic-auth"]["password"], "***");
    }

    #[test]
    fn redact_key_auth_keys() {
        let mut input = serde_json::json!({
            "plugins": { "key-auth": { "key": "k0", "keys": ["k1", "k2"] } },
        });
        redact(ResourceKind::Route, &mut input);
        assert_eq!(input["plugins"]["key-auth"]["key"], "***");
        assert_eq!(
            input["plugins"]["key-auth"]["keys"],
            serde_json::json!(["***", "***"])
        );
    }

    #[test]
    fn redact_csrf_key() {
        let mut input = serde_json::json!({ "plugins": { "csrf": { "key": "secret-csrf" } } });
        redact(ResourceKind::GlobalRule, &mut input);
        assert_eq!(input["plugins"]["csrf"]["key"], "***");
    }

    #[test]
    fn redact_nested_upstream_tls() {
        let mut input = serde_json::json!({
            "upstream": {
                "tls": {
                    "client_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
                    "client_cert": "cert-data",
                }
            }
        });
        redact(ResourceKind::Route, &mut input);
        assert_eq!(input["upstream"]["tls"]["client_key"], "***");
        assert_eq!(input["upstream"]["tls"]["client_cert"], "cert-data");
        let mut service = serde_json::json!({
            "upstream": { "tls": { "client_key": "k", "client_cert": "c" } }
        });
        redact(ResourceKind::Service, &mut service);
        assert_eq!(service["upstream"]["tls"]["client_key"], "***");
    }

    #[test]
    fn redact_preserves_upstream_hash_on_key() {
        let mut input = serde_json::json!({ "key": "uri", "type": "roundrobin" });
        redact(ResourceKind::Upstream, &mut input);
        assert_eq!(input["key"], "uri");
        assert_eq!(input["type"], "roundrobin");
    }

    #[test]
    fn redact_redacts_upstream_tls_client_key() {
        let mut input = serde_json::json!({
            "key": "uri",
            "type": "roundrobin",
            "tls": {
                "client_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
                "client_cert": "cert-data",
            },
        });
        redact(ResourceKind::Upstream, &mut input);
        assert_eq!(input["key"], "uri");
        assert_eq!(input["tls"]["client_key"], "***");
        assert_eq!(input["tls"]["client_cert"], "cert-data");
    }

    #[test]
    fn redact_non_sensitive_unchanged() {
        let mut input = serde_json::json!({
            "id": "r1",
            "uri": "/x",
            "methods": ["GET"],
            "upstream_id": "u1",
        });
        let original = input.clone();
        redact(ResourceKind::Route, &mut input);
        assert_eq!(input, original);
    }

    #[test]
    fn restore_keeps_masked_secret_and_accepts_rotation() {
        let existing = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "-----BEGIN PRIVATE KEY-----\nreal\n-----END PRIVATE KEY-----",
        });
        let mut resave = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "***",
        });
        restore_redacted_secrets(ResourceKind::Ssl, &mut resave, &existing);
        assert_eq!(resave["key"], existing["key"]);

        let mut rotate = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----",
        });
        restore_redacted_secrets(ResourceKind::Ssl, &mut rotate, &existing);
        assert_eq!(
            rotate["key"],
            "-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----"
        );
    }

    #[test]
    fn restore_walks_plugins_nested_upstream_and_arrays() {
        let existing = serde_json::json!({
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "demo", "password": "s3cret" },
                "key-auth": { "key": "k0", "keys": ["k1", "k2"] },
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": {
                    "client_cert": "cert-pem",
                    "client_key": "-----BEGIN PRIVATE KEY-----\nreal\n-----END PRIVATE KEY-----",
                },
            },
        });
        let mut resave = serde_json::json!({
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "changed", "password": "***" },
                "key-auth": { "key": "***", "keys": ["***", "***"] },
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": { "client_cert": "cert-pem", "client_key": "***" },
            },
        });
        restore_redacted_secrets(ResourceKind::Route, &mut resave, &existing);
        assert_eq!(resave["plugins"]["basic-auth"]["username"], "changed");
        assert_eq!(resave["plugins"]["basic-auth"]["password"], "s3cret");
        assert_eq!(resave["plugins"]["key-auth"]["key"], "k0");
        assert_eq!(
            resave["plugins"]["key-auth"]["keys"],
            serde_json::json!(["k1", "k2"])
        );
        assert_eq!(
            resave["upstream"]["tls"]["client_key"],
            existing["upstream"]["tls"]["client_key"]
        );
        assert!(!contains_redaction_sentinel(&resave));
    }

    #[test]
    fn restore_ignores_non_secret_sentinel() {
        let existing = serde_json::json!({ "uri": "/old", "id": "r1" });
        let mut resave = serde_json::json!({ "uri": "***", "id": "r1" });
        restore_redacted_secrets(ResourceKind::Route, &mut resave, &existing);
        assert_eq!(resave["uri"], "***");
    }

    #[test]
    fn encrypt_for_storage_noop_when_disabled() {
        let mut input = serde_json::json!({
            "id": "1",
            "cert": "c",
            "key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            "snis": ["example.com"],
        });
        let out = encrypt_for_storage(ResourceKind::Ssl, &mut input).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["key"], input["key"]);
        // Output is compacted even when encryption is disabled.
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains('\n'));
    }

    #[test]
    fn encrypt_for_storage_leaves_plugin_and_inline_upstream_secrets_when_disabled() {
        let mut input = serde_json::json!({
            "id": "1",
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "demo", "password": "s3cret" }
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": { "client_cert": "cert", "client_key": "key-material" }
            }
        });
        let out = encrypt_for_storage(ResourceKind::Route, &mut input).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["plugins"]["basic-auth"]["password"], "s3cret");
        assert_eq!(parsed["upstream"]["tls"]["client_key"], "key-material");
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    use crate::config::etcd::InMemoryGraphStore;
    use crate::proxy::runtime::RUNTIME_TEST_LOCK;
    use std::time::Duration;

    fn upstream_json(id: &str, node: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "nodes": { node: 1 },
            "type": "roundrobin",
            "hash_on": "vars",
            "key": "uri",
            "scheme": "http",
            "pass_host": "pass",
        })
    }

    fn route_json(id: &str, upstream_id: &str, uri: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "uri": uri,
            "upstream_id": upstream_id,
        })
    }

    fn stored_graph(
        revision: i64,
        pairs: Vec<(ResourceKind, &str, serde_json::Value)>,
    ) -> StoredGraph {
        let mut graph = StoredGraph {
            revision,
            ..Default::default()
        };
        for (kind, id, value) in pairs {
            let key = ResourceKey::new(kind, id).unwrap();
            graph.resources.insert(
                key.clone(),
                StoredResource {
                    value: serde_json::to_vec(&value).unwrap(),
                    create_revision: 1,
                    mod_revision: revision,
                },
            );
        }
        graph
    }

    fn upstream_change(revision: i64, id: &str, node: &str) -> WatchBatch {
        let key = ResourceKey::new(ResourceKind::Upstream, id).unwrap();
        WatchBatch {
            revision,
            changes: vec![StoredChange::Put {
                key: key.clone(),
                resource: StoredResource {
                    value: serde_json::to_vec(&upstream_json(id, node)).unwrap(),
                    create_revision: 1,
                    mod_revision: revision,
                },
            }],
        }
    }

    fn route_change(revision: i64, id: &str, upstream_id: &str, uri: &str) -> WatchBatch {
        let key = ResourceKey::new(ResourceKind::Route, id).unwrap();
        WatchBatch {
            revision,
            changes: vec![StoredChange::Put {
                key: key.clone(),
                resource: StoredResource {
                    value: serde_json::to_vec(&route_json(id, upstream_id, uri)).unwrap(),
                    create_revision: 1,
                    mod_revision: revision,
                },
            }],
        }
    }

    async fn wait_for_revision(min: i64, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if RUNTIME.load().revision >= min {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Tests share the process-global RUNTIME; each derives its revisions from
    /// the current committed revision so order and residue never matter.
    fn current_revision() -> i64 {
        RUNTIME.load().revision
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn replace_all_publishes_snapshot() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));
        let revision = base + 100;
        let snapshot = stored_graph(
            revision,
            vec![
                (
                    ResourceKind::Upstream,
                    "u1",
                    upstream_json("u1", "127.0.0.1:80"),
                ),
                (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
            ],
        );
        graph.replace_all(snapshot).unwrap();
        assert!(
            wait_for_revision(revision, Duration::from_secs(5)).await,
            "snapshot must publish"
        );
        let snap = RUNTIME.load();
        assert_eq!(snap.revision, revision);
        assert!(snap.upstreams.contains_key("u1"));
        assert!(snap.routes.contains_key("r1"));
        graph.shutdown().await;
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn invalid_candidate_rejected_synchronously_keeps_lkg_and_later_valid_publishes() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));

        let good = base + 100;
        graph
            .replace_all(stored_graph(
                good,
                vec![(
                    ResourceKind::Upstream,
                    "u1",
                    upstream_json("u1", "127.0.0.1:80"),
                )],
            ))
            .unwrap();
        assert!(wait_for_revision(good, Duration::from_secs(5)).await);

        // Dangling route reference: whole-graph validation rejects the full
        // list synchronously, so nothing is submitted and the worker never
        // retries a permanently invalid candidate.
        let bad = good + 1;
        let err = graph
            .replace_all(stored_graph(
                bad,
                vec![(
                    ResourceKind::Route,
                    "bad",
                    route_json("bad", "missing", "/"),
                )],
            ))
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            RUNTIME.load().revision,
            good,
            "invalid candidate must not publish"
        );

        // A later valid generation publishes on top of the LKG.
        let later = good + 2;
        graph
            .replace_all(stored_graph(
                later,
                vec![
                    (
                        ResourceKind::Upstream,
                        "u1",
                        upstream_json("u1", "127.0.0.1:80"),
                    ),
                    (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
                ],
            ))
            .unwrap();
        assert!(
            wait_for_revision(later, Duration::from_secs(5)).await,
            "later valid generation must publish"
        );
        graph.shutdown().await;
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn apply_watch_stale_and_empty_batches() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));
        let published = base + 100;
        graph
            .replace_all(stored_graph(
                published,
                vec![(
                    ResourceKind::Upstream,
                    "u1",
                    upstream_json("u1", "127.0.0.1:80"),
                )],
            ))
            .unwrap();
        assert!(wait_for_revision(published, Duration::from_secs(5)).await);

        // Empty batch is a no-op and does not advance the published revision.
        graph.apply_watch(WatchBatch::default()).unwrap();
        assert_eq!(RUNTIME.load().revision, published);

        // A watch older than the published revision is rejected synchronously.
        let err = graph
            .apply_watch(upstream_change(published - 1, "u1", "127.0.0.1:81"))
            .unwrap_err();
        assert!(matches!(
            err,
            GraphError::StaleRevision {
                incoming,
                published: p
            } if incoming == published - 1 && p == published
        ));
        graph.shutdown().await;
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn watch_changes_layer_on_pending_target() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));
        let first = base + 100;
        graph
            .replace_all(stored_graph(
                first,
                vec![
                    (
                        ResourceKind::Upstream,
                        "u1",
                        upstream_json("u1", "127.0.0.1:80"),
                    ),
                    (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
                ],
            ))
            .unwrap();
        assert!(wait_for_revision(first, Duration::from_secs(5)).await);

        // Two batches back-to-back: the second must layer on the first, not on
        // the committed graph, so no update is lost regardless of worker timing.
        graph
            .apply_watch(upstream_change(first + 1, "u1", "127.0.0.1:81"))
            .unwrap();
        graph
            .apply_watch(route_change(first + 2, "r1", "u1", "/v2"))
            .unwrap();
        assert!(
            wait_for_revision(first + 2, Duration::from_secs(5)).await,
            "layered watch batches must publish"
        );
        let snap = RUNTIME.load();
        assert_eq!(snap.revision, first + 2);
        assert!(snap.upstreams["u1"]
            .inner
            .nodes
            .contains_key("127.0.0.1:81"));
        assert_eq!(snap.routes["r1"].inner.uri.as_deref(), Some("/v2"));
        graph.shutdown().await;
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn route_only_change_reuses_upstream_arc() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));
        let first = base + 100;
        graph
            .replace_all(stored_graph(
                first,
                vec![
                    (
                        ResourceKind::Upstream,
                        "u1",
                        upstream_json("u1", "127.0.0.1:80"),
                    ),
                    (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
                ],
            ))
            .unwrap();
        assert!(wait_for_revision(first, Duration::from_secs(5)).await);
        let old_upstream = Arc::as_ptr(RUNTIME.load().upstreams.get("u1").unwrap());

        graph
            .apply_watch(route_change(first + 1, "r1", "u1", "/v2"))
            .unwrap();
        assert!(wait_for_revision(first + 1, Duration::from_secs(5)).await);
        let snap = RUNTIME.load();
        assert_eq!(
            Arc::as_ptr(snap.upstreams.get("u1").unwrap()),
            old_upstream,
            "unchanged upstream must be reused"
        );
        assert_eq!(snap.routes["r1"].inner.uri.as_deref(), Some("/v2"));
        graph.shutdown().await;
    }

    /// A stored SSL whose TLS material is structurally fine but unparseable:
    /// passes decode and whole-graph validation, fails candidate build. This is
    /// the deterministic worker-level failure used by the retry-loop tests.
    fn stored_bad_ssl_graph(revision: i64) -> StoredGraph {
        stored_graph(
            revision,
            vec![(
                ResourceKind::Ssl,
                "t1",
                serde_json::json!({
                    "id": "t1",
                    "cert": "not-a-pem",
                    "key": "not-a-pem",
                    "snis": ["example.com"],
                }),
            )],
        )
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn apply_watch_rejects_invalid_batches_without_publish() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));
        let published = base + 100;
        graph
            .replace_all(stored_graph(
                published,
                vec![
                    (
                        ResourceKind::Upstream,
                        "u1",
                        upstream_json("u1", "127.0.0.1:80"),
                    ),
                    (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
                ],
            ))
            .unwrap();
        assert!(wait_for_revision(published, Duration::from_secs(5)).await);

        // Dangling route reference: rejected synchronously, no submission.
        let err = graph
            .apply_watch(WatchBatch {
                revision: published + 1,
                changes: vec![StoredChange::Put {
                    key: ResourceKey::new(ResourceKind::Route, "dangling").unwrap(),
                    resource: StoredResource {
                        value: serde_json::to_vec(&route_json("dangling", "missing", "/")).unwrap(),
                        create_revision: 1,
                        mod_revision: published + 1,
                    },
                }],
            })
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );

        // Traffic-split referencing a missing upstream: whole-graph validation
        // catches it before submission, not after DNS preparation.
        let err = graph
            .apply_watch(WatchBatch {
                revision: published + 2,
                changes: vec![StoredChange::Put {
                    key: ResourceKey::new(ResourceKind::Route, "split").unwrap(),
                    resource: StoredResource {
                        value: serde_json::to_vec(&serde_json::json!({
                            "id": "split",
                            "uri": "/split",
                            "upstream_id": "u1",
                            "plugins": {
                                "traffic-split": {
                                    "rules": [{
                                        "weighted_upstreams": [
                                            { "upstream_id": "does-not-exist", "weight": 100 }
                                        ]
                                    }]
                                }
                            },
                        }))
                        .unwrap(),
                        create_revision: 1,
                        mod_revision: published + 2,
                    },
                }],
            })
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            RUNTIME.load().revision,
            published,
            "rejected batches must not publish"
        );
        graph.shutdown().await;
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn superseded_failed_generation_does_not_delay_valid_submission() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));

        // The failing generation passes validation but fails candidate build,
        // so the worker enters its retry/backoff loop.
        let failing = base + 100;
        graph.replace_all(stored_bad_ssl_graph(failing)).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A valid submission while the failed generation is backing off must
        // publish promptly — it must not wait out the failed backoff.
        let valid = failing + 1;
        graph
            .replace_all(stored_graph(
                valid,
                vec![
                    (
                        ResourceKind::Upstream,
                        "u1",
                        upstream_json("u1", "127.0.0.1:80"),
                    ),
                    (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
                ],
            ))
            .unwrap();
        assert!(
            wait_for_revision(valid, Duration::from_secs(2)).await,
            "valid generation must publish without waiting out the failed backoff"
        );
        let snap = RUNTIME.load();
        assert_eq!(snap.revision, valid);
        assert!(snap.upstreams.contains_key("u1"));
        graph.shutdown().await;
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn shutdown_cancels_retry_loop() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));
        // Garbage TLS material passes validation but fails candidate build, so
        // the worker enters its retry/backoff loop.
        graph.replace_all(stored_bad_ssl_graph(base + 100)).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Shutdown must cancel the retry sleep and return within the bound.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        graph.shutdown().await;
        assert!(tokio::time::Instant::now() < deadline);
        assert_eq!(
            RUNTIME.load().revision,
            base,
            "failing candidate must never publish"
        );
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn replace_all_rejects_undecryptable_graph_without_publish() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = current_revision();
        let graph = ConfigurationGraph::new(Arc::new(InMemoryGraphStore::new()));
        let err = graph
            .replace_all(stored_graph(
                base + 100,
                vec![(
                    ResourceKind::Ssl,
                    "t1",
                    serde_json::json!({
                        "id": "t1",
                        "cert": "C",
                        "key": "$pingsix-enc:v1$cipher",
                        "snis": ["example.com"],
                    }),
                )],
            ))
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(RUNTIME.load().revision, base);
        graph.shutdown().await;
    }

    #[test]
    fn load_static_publishes_empty_config() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = ConfigurationGraph::load_static(&config::Config::default()).unwrap();
        assert!(snapshot.routes.is_empty());
        crate::core::status::reset();
    }
}
