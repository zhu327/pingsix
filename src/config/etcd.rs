use std::{error::Error, fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use etcd_client::{Client, ConnectOptions, Event, GetOptions, GetResponse, WatchOptions};
use pingora::server::ListenFds;
use pingora_core::{server::ShutdownWatch, services::Service};
use tokio::{sync::Mutex, time::sleep};

use super::Etcd;

// Retry delay constants
const LIST_RETRY_DELAY: Duration = Duration::from_secs(3);
const WATCH_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum EtcdError {
    ClientNotInitialized,
    ConnectionFailed(String),
    ListOperationFailed(String),
    WatchOperationFailed(String),
    Other(String),
}

impl fmt::Display for EtcdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtcdError::ClientNotInitialized => write!(f, "Etcd client is not initialized"),
            EtcdError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            EtcdError::ListOperationFailed(msg) => write!(f, "List operation failed: {}", msg),
            EtcdError::WatchOperationFailed(msg) => write!(f, "Watch operation failed: {}", msg),
            EtcdError::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl std::error::Error for EtcdError {}

/// Service responsible for syncing and watching etcd configuration changes.
pub struct EtcdConfigSync {
    config: Etcd,
    client: Option<Client>,
    revision: i64,
    handler: Box<dyn EtcdEventHandler + Send + Sync>,
}

impl EtcdConfigSync {
    pub fn new(config: Etcd, handler: Box<dyn EtcdEventHandler + Send + Sync>) -> Self {
        assert!(
            !config.prefix.is_empty(),
            "EtcdConfigSync requires a non-empty prefix"
        );

        Self {
            config,
            client: None,
            revision: 0,
            handler,
        }
    }

    /// Get or initialize the etcd client.
    async fn get_client(&mut self) -> Result<&mut Client, EtcdError> {
        if self.client.is_none() {
            log::info!(
                "Creating new etcd client for prefix '{}'",
                self.config.prefix
            );
            self.client = Some(create_client(&self.config).await?);
        }

        self.client.as_mut().ok_or(EtcdError::ClientNotInitialized)
    }

    /// Synchronize etcd data on initialization.
    async fn list(&mut self) -> Result<(), EtcdError> {
        let prefix = self.config.prefix.clone();
        let client = self.get_client().await?;

        let options = GetOptions::new().with_prefix();
        let response = client
            .get(prefix.as_str(), Some(options))
            .await
            .map_err(|e| {
                EtcdError::ListOperationFailed(format!("Failed to list key '{}': {}", prefix, e))
            })?;

        if let Some(header) = response.header() {
            self.revision = header.revision();
        } else {
            return Err(EtcdError::Other(
                "Failed to get header from list response".to_string(),
            ));
        }

        self.handler.handle_list_response(&response);
        Ok(())
    }

    /// Watch for etcd data changes.
    async fn watch(&mut self) -> Result<(), EtcdError> {
        let prefix = self.config.prefix.clone();
        let start_revision = self.revision + 1;
        let options = WatchOptions::new()
            .with_start_revision(start_revision)
            .with_prefix();

        let client = self.get_client().await?;

        let (mut watcher, mut stream) = client
            .watch(prefix.as_str(), Some(options))
            .await
            .map_err(|e| {
                EtcdError::WatchOperationFailed(format!("Failed to watch key '{}': {}", prefix, e))
            })?;

        watcher.request_progress().await.map_err(|e| {
            EtcdError::WatchOperationFailed(format!("Failed to request progress: {}", e))
        })?;

        while let Some(response) = stream.message().await.map_err(|e| {
            EtcdError::WatchOperationFailed(format!("Failed to receive watch message: {}", e))
        })? {
            if response.canceled() {
                log::warn!("Watch stream for prefix '{}' was canceled", prefix);
                break;
            }

            for event in response.events() {
                self.handler.handle_event(event);
            }
        }
        Ok(())
    }

    /// Reset the client on failure.
    fn reset_client(&mut self) {
        log::warn!("Resetting etcd client for prefix '{}'", self.config.prefix);
        self.client = None;
    }

    /// Main task loop for synchronization.
    async fn run_sync_loop(&mut self, mut shutdown: ShutdownWatch) {
        loop {
            tokio::select! {
                biased; // Prioritize shutdown signal
                // Shutdown signal handling
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::info!("Shutdown signal received, stopping etcd config sync for prefix '{}'", self.config.prefix);
                        return;
                    }
                },

                // Perform list operation
                result = self.list() => {
                    if let Err(err) = result {
                        log::error!("List operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        self.reset_client();
                        sleep(LIST_RETRY_DELAY).await;
                        continue;
                    }
                }
            }

            tokio::select! {
                biased; // Prioritize shutdown signal
                // Shutdown signal handling during watch
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::info!("Shutdown signal received, stopping etcd config sync for prefix '{}'", self.config.prefix);
                        return;
                    }
                },

                // Perform watch operation
                result = self.watch() => {
                    if let Err(err) = result {
                        log::error!("Watch operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        self.reset_client();
                        sleep(WATCH_RETRY_DELAY).await;
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
    fn handle_event(&self, event: &Event);
    fn handle_list_response(&self, response: &GetResponse);
}

async fn create_client(cfg: &Etcd) -> Result<Client, EtcdError> {
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
            EtcdError::ConnectionFailed(format!(
                "Failed to connect to host '{:?}': {}",
                cfg.host, e
            ))
        })
}

pub fn json_to_resource<T>(value: &[u8]) -> Result<T, Box<dyn Error>>
where
    T: serde::de::DeserializeOwned,
{
    // Deserialize the input value from JSON
    let json_value: serde_json::Value = serde_json::from_slice(value)?;

    // Serialize the JSON value to YAML directly into a Vec<u8>
    let mut yaml_output = Vec::new();
    let mut serializer = serde_yaml::Serializer::new(&mut yaml_output);
    serde_transcode::transcode(json_value, &mut serializer)?;

    // Deserialize directly from the YAML bytes
    let resource: T = serde_yaml::from_slice(&yaml_output)?;

    Ok(resource)
}

/// Wrapper for etcd client used by Admin API, ensuring local mutability.
pub struct EtcdClientWrapper {
    config: Etcd,
    client: Arc<Mutex<Option<Client>>>,
}

impl EtcdClientWrapper {
    pub fn new(cfg: Etcd) -> Self {
        Self {
            config: cfg,
            client: Arc::new(Mutex::new(None)),
        }
    }

    async fn ensure_connected(&self) -> Result<Arc<Mutex<Option<Client>>>, EtcdError> {
        let mut client_guard = self.client.lock().await;

        if client_guard.is_none() {
            log::info!(
                "Creating new etcd client for prefix '{}'",
                self.config.prefix
            );
            *client_guard = Some(
                create_client(&self.config)
                    .await
                    .map_err(|e| EtcdError::ConnectionFailed(e.to_string()))?,
            );
        }

        Ok(self.client.clone())
    }

    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, EtcdError> {
        let client_arc = self.ensure_connected().await?;
        let mut client_guard = client_arc.lock().await;

        let client = client_guard
            .as_mut()
            .ok_or(EtcdError::ClientNotInitialized)?;

        let prefixed_key = self.with_prefix(key);
        client
            .get(prefixed_key.as_bytes(), None)
            .await
            .map_err(|e| {
                EtcdError::ListOperationFailed(format!(
                    "Failed to get key '{}': {}",
                    prefixed_key, e
                ))
            })
            .map(|resp| resp.kvs().first().map(|kv| kv.value().to_vec()))
    }

    pub async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), EtcdError> {
        let client_arc = self.ensure_connected().await?;
        let mut client_guard = client_arc.lock().await;

        let client = client_guard
            .as_mut()
            .ok_or(EtcdError::ClientNotInitialized)?;

        let prefixed_key = self.with_prefix(key);
        client
            .put(prefixed_key.as_bytes(), value, None)
            .await
            .map_err(|e| {
                EtcdError::Other(format!(
                    "Put operation for key '{}' failed: {}",
                    prefixed_key, e
                ))
            })?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<(), EtcdError> {
        let client_arc = self.ensure_connected().await?;
        let mut client_guard = client_arc.lock().await;

        let client = client_guard
            .as_mut()
            .ok_or(EtcdError::ClientNotInitialized)?;

        let prefixed_key = self.with_prefix(key);
        client
            .delete(prefixed_key.as_bytes(), None)
            .await
            .map_err(|e| {
                EtcdError::Other(format!(
                    "Delete operation for key '{}' failed: {}",
                    prefixed_key, e
                ))
            })?;
        Ok(())
    }

    fn with_prefix(&self, key: &str) -> String {
        format!("{}/{}", self.config.prefix, key)
    }
}
