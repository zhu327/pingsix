use std::time::Duration;

use async_trait::async_trait;
use etcd_client::{Client, ConnectOptions, Event, GetOptions, GetResponse, WatchOptions};
use pingora::server::ListenFds;
use pingora_core::{server::ShutdownWatch, services::Service};
use tokio::{
    sync::{Mutex, OnceCell},
    time::sleep,
};

use super::Etcd;
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

    Client::connect(cfg.host.clone(), Some(options))
        .await
        .map_err(|e| {
            ProxyError::etcd_error_with_cause(
                format!("Failed to connect to host '{:?}'", cfg.host),
                e,
            )
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

    fn with_prefix(&self, key: &str) -> String {
        format!("{}/{}", self.config.prefix, key)
    }
}
