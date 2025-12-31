use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, Service},
};
use tokio::sync::{broadcast, watch};

/// Registry update event types
#[derive(Debug, Clone)]
pub enum RegistryUpdate {
    Added(String),
    Removed(String),
}

/// Registered upstream information
struct RegisteredUpstream {
    load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Health check registry using DashMap for better concurrent performance
pub struct HealthCheckRegistry {
    upstreams: DashMap<String, RegisteredUpstream>,
    update_notifier: broadcast::Sender<RegistryUpdate>,
}

impl Default for HealthCheckRegistry {
    fn default() -> Self {
        // Use larger buffer to reduce lag probability
        let (tx, _rx) = broadcast::channel(1000);
        Self {
            upstreams: DashMap::new(),
            update_notifier: tx,
        }
    }
}

impl HealthCheckRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register upstream health check - no mutable reference needed, DashMap supports concurrent inserts
    ///
    /// If an upstream with the same ID already exists, it will be replaced and the old health check
    /// task will be gracefully shut down to prevent task leaks.
    pub fn register_upstream(
        &self,
        upstream_id: String,
        load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let registered = RegisteredUpstream {
            load_balancer,
            shutdown_tx,
            shutdown_rx,
        };

        // Check if there's an existing upstream and shut it down first
        if let Some(old_registered) = self.upstreams.insert(upstream_id.clone(), registered) {
            log::info!(
                "Replacing existing upstream '{upstream_id}', shutting down old health check"
            );
            // Send shutdown signal to the old health check task
            if let Err(e) = old_registered.shutdown_tx.send(true) {
                log::warn!("Failed to send shutdown signal to old upstream '{upstream_id}': {e}");
            }
        }

        // Notify executor of new upstream registration
        if let Err(e) = self
            .update_notifier
            .send(RegistryUpdate::Added(upstream_id.clone()))
        {
            log::warn!("Failed to notify registry update: {e}");
        }

        log::info!("Registered upstream '{upstream_id}' for health check");
        Ok(())
    }

    /// Unregister upstream health check - no mutable reference needed, DashMap supports concurrent removes
    pub fn unregister_upstream(&self, upstream_id: &str) -> bool {
        if let Some((_, registered)) = self.upstreams.remove(upstream_id) {
            // Send shutdown signal
            if let Err(e) = registered.shutdown_tx.send(true) {
                log::warn!("Failed to send shutdown signal to upstream '{upstream_id}': {e}");
            }

            // Notify executor
            if let Err(e) = self
                .update_notifier
                .send(RegistryUpdate::Removed(upstream_id.to_string()))
            {
                log::warn!("Failed to notify registry update: {e}");
            }

            log::info!("Unregistered upstream '{upstream_id}' from health check");
            true
        } else {
            log::warn!("Attempted to unregister non-existent upstream '{upstream_id}'");
            false
        }
    }

    /// Subscribes to registry update notifications.
    ///
    /// Returns a broadcast receiver that will receive `RegistryUpdate` events
    /// when upstreams are added or removed from the registry.
    pub fn subscribe_updates(&self) -> broadcast::Receiver<RegistryUpdate> {
        self.update_notifier.subscribe()
    }

    /// Retrieves the specified upstream for starting health checks.
    ///
    /// Returns a tuple containing the upstream ID, load balancer reference, and shutdown receiver
    /// that can be used to spawn a health check task for the upstream.
    pub fn get_upstream_for_start(
        &self,
        upstream_id: &str,
    ) -> Option<(
        String,
        Arc<dyn BackgroundService + Send + Sync>,
        watch::Receiver<bool>,
    )> {
        self.upstreams.get(upstream_id).map(|registered| {
            (
                upstream_id.to_string(),
                registered.load_balancer.clone(),
                registered.shutdown_rx.clone(),
            )
        })
    }

    /// Get all upstream ID list using DashMap iterator
    pub fn get_all_upstream_ids(&self) -> Vec<String> {
        self.upstreams
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }
}

/// Health check executor that manages running health check tasks.
///
/// The executor runs as a background service, listening for registry updates
/// and spawning/stopping health check tasks as upstreams are registered/unregistered.
#[derive(Clone)]
pub struct HealthCheckExecutor;

impl Default for HealthCheckExecutor {
    fn default() -> Self {
        Self
    }
}

impl HealthCheckExecutor {
    pub fn new() -> Self {
        Self
    }

    /// Runs the health check executor main loop.
    ///
    /// This method:
    /// 1. Subscribes to registry updates
    /// 2. Spawns health check tasks for all registered upstreams
    /// 3. Listens for add/remove events and manages tasks accordingly (with Lagged handling)
    /// 4. Performs periodic cleanup of finished tasks
    /// 5. Gracefully shuts down all tasks on shutdown signal
    pub async fn run(&self, registry: Arc<HealthCheckRegistry>, mut shutdown: ShutdownWatch) {
        log::info!("Starting health check executor");

        // Get update receiver directly from registry
        let mut update_receiver = registry.subscribe_updates();

        // Store started health check tasks
        let mut running_tasks: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
            std::collections::HashMap::new();

        // Start health checks for existing upstreams
        for upstream_id in registry.get_all_upstream_ids() {
            if let Some((task_upstream_id, load_balancer, shutdown_rx)) =
                registry.get_upstream_for_start(&upstream_id)
            {
                let task_id = upstream_id.clone();

                let handle = tokio::spawn(async move {
                    log::info!("Starting health check service for upstream '{task_upstream_id}'");

                    // Call LoadBalancer's start method directly
                    load_balancer.start(shutdown_rx).await;

                    log::info!("Health check service stopped for upstream '{task_upstream_id}'");
                });

                running_tasks.insert(task_id, handle);
            }
        }

        loop {
            tokio::select! {
                biased; // Prioritize shutdown signal

                // Shutdown signal handling - properly wait for signal changes
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::info!("Health check executor received shutdown signal");
                        // Cancel all running tasks
                        for (upstream_id, handle) in running_tasks {
                            log::debug!("Cancelling health check task for upstream '{upstream_id}'");
                            handle.abort();
                        }
                        break;
                    }
                }

                // Handle registry update events with Lagged error handling
                result = update_receiver.recv() => {
                    let update = match result {
                        Ok(upd) => upd,
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            log::warn!(
                                "Health check executor lagged, skipped {skipped} events. Performing full resync."
                            );
                            // Perform full resync: rebuild running_tasks from current registry state
                            self.resync_tasks(&registry, &mut running_tasks).await;
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            log::info!("Registry update channel closed, stopping executor");
                            break;
                        }
                    };
                    match update {
                        RegistryUpdate::Added(id) => {
                            log::debug!("Health check executor: upstream '{id}' added");

                            // If there's already a running task for this upstream, abort it first
                            // This handles the case where register_upstream is called multiple times
                            // for the same upstream_id (e.g., during configuration updates)
                            if let Some(old_handle) = running_tasks.remove(&id) {
                                log::info!("Aborting existing health check task for upstream '{id}' before starting new one");
                                old_handle.abort();
                            }

                            // Start new health check task - direct registry access, no lock needed
                            if let Some((upstream_id, load_balancer, shutdown_rx)) =
                                registry.get_upstream_for_start(&id)
                            {
                                let task_id = upstream_id.clone();

                                let handle = tokio::spawn(async move {
                                    log::info!(
                                        "Starting health check service for upstream '{upstream_id}'"
                                    );

                                    // LoadBalancer::start runs in a loop until shutdown signal received
                                    // LoadBalancer handles all concurrency control and timing internally
                                    load_balancer.start(shutdown_rx).await;

                                    log::info!(
                                        "Health check service stopped for upstream '{upstream_id}'"
                                    );
                                });

                                running_tasks.insert(task_id, handle);
                            }
                        }
                        RegistryUpdate::Removed(id) => {
                            log::debug!("Health check executor: upstream '{id}' removed");
                            // Stop corresponding health check task
                            if let Some(handle) = running_tasks.remove(&id) {
                                log::debug!("Stopping health check task for upstream '{id}'");
                                handle.abort();
                            }
                        }
                    }

                    // Clean up completed tasks after processing update
                    running_tasks.retain(|upstream_id, handle| {
                        if handle.is_finished() {
                            log::debug!("Health check task for upstream '{upstream_id}' has finished");
                            false
                        } else {
                            true
                        }
                    });
                }

                // Periodic cleanup of completed tasks when no events occur
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    running_tasks.retain(|upstream_id, handle| {
                        if handle.is_finished() {
                            log::debug!("Health check task for upstream '{upstream_id}' has finished");
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }

        log::info!("Health check executor stopped");
    }

    /// Resync running tasks with current registry state after lagged events
    async fn resync_tasks(
        &self,
        registry: &Arc<HealthCheckRegistry>,
        running_tasks: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    ) {
        let current_upstream_ids: std::collections::HashSet<String> =
            registry.get_all_upstream_ids().into_iter().collect();

        // Remove tasks for upstreams no longer in registry
        running_tasks.retain(|upstream_id, handle| {
            if !current_upstream_ids.contains(upstream_id) {
                log::debug!("Resync: stopping task for removed upstream '{upstream_id}'");
                handle.abort();
                false
            } else {
                true
            }
        });

        // Start tasks for upstreams not yet running
        for upstream_id in current_upstream_ids {
            if let std::collections::hash_map::Entry::Vacant(e) = running_tasks.entry(upstream_id) {
                if let Some((task_upstream_id, load_balancer, shutdown_rx)) =
                    registry.get_upstream_for_start(e.key())
                {
                    log::debug!("Resync: starting task for new upstream '{task_upstream_id}'");
                    let handle = tokio::spawn(async move {
                        load_balancer.start(shutdown_rx).await;
                    });
                    e.insert(handle);
                }
            }
        }
    }
}

/// Shared health check service using DashMap for better concurrent performance
#[derive(Clone)]
pub struct SharedHealthCheckService {
    registry: Arc<HealthCheckRegistry>,
    executor: HealthCheckExecutor,
}

impl Default for SharedHealthCheckService {
    fn default() -> Self {
        Self {
            registry: Arc::new(HealthCheckRegistry::new()),
            executor: HealthCheckExecutor::new(),
        }
    }
}

impl SharedHealthCheckService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register upstream health check - no lock needed, call registry method directly
    pub fn register_upstream(
        &self,
        upstream_id: String,
        load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.registry.register_upstream(upstream_id, load_balancer)
    }

    /// Unregister upstream health check - no lock needed, call registry method directly
    pub fn unregister_upstream(&self, upstream_id: &str) -> bool {
        self.registry.unregister_upstream(upstream_id)
    }
}

#[async_trait]
impl Service for SharedHealthCheckService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora_core::server::ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        self.executor.run(self.registry.clone(), shutdown).await;
    }

    fn name(&self) -> &str {
        "SharedHealthCheckService"
    }

    fn threads(&self) -> Option<usize> {
        Some(1) // Run on a single thread
    }
}

/// Global shared health check service instance
pub static SHARED_HEALTH_CHECK_SERVICE: Lazy<SharedHealthCheckService> =
    Lazy::new(SharedHealthCheckService::new);
