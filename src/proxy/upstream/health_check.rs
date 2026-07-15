use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, Service},
};
use tokio::sync::{broadcast, watch};

/// Registry update event types. Generations prevent delayed events from affecting replacements.
#[derive(Debug, Clone)]
pub enum RegistryUpdate {
    Added {
        id: String,
        registration: HealthCheckRegistration,
    },
    Removed {
        id: String,
        registration: HealthCheckRegistration,
    },
}

pub use crate::core::{HealthCheckFingerprint, HealthCheckSpec};

/// Identifies one registration of an upstream health check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HealthCheckRegistration {
    generation: u64,
}

impl HealthCheckRegistration {
    pub fn generation(self) -> u64 {
        self.generation
    }
}

struct RegisteredUpstream {
    generation: u64,
    load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Previous entry displaced by a replacement. Call [`discard`](Self::discard) only after
/// the new runtime snapshot is published so failed publishes never stop the old check.
pub struct DisplacedHealthCheck {
    id: String,
    registration: HealthCheckRegistration,
    registered: RegisteredUpstream,
    notifier: broadcast::Sender<RegistryUpdate>,
}

impl DisplacedHealthCheck {
    pub fn registration(&self) -> HealthCheckRegistration {
        self.registration
    }

    /// Stop the displaced task after the replacement has been committed.
    pub fn discard(self) {
        if let Err(e) = self.registered.shutdown_tx.send(true) {
            log::warn!(
                "Failed to shut down displaced health check '{}': {e}",
                self.id
            );
        }
        let _ = self.notifier.send(RegistryUpdate::Removed {
            id: self.id,
            registration: self.registration,
        });
    }

    /// Restore the previous registry entry (publish aborted before commit).
    pub fn restore(self, registry: &HealthCheckRegistry) {
        registry.upstreams.insert(self.id.clone(), self.registered);
        // New registration must already have been removed by the caller.
        let _ = self.notifier.send(RegistryUpdate::Added {
            id: self.id,
            registration: self.registration,
        });
    }
}

pub struct HealthCheckRegistry {
    upstreams: DashMap<String, RegisteredUpstream>,
    update_notifier: broadcast::Sender<RegistryUpdate>,
    next_generation: AtomicU64,
}

impl Default for HealthCheckRegistry {
    fn default() -> Self {
        let (tx, _rx) = broadcast::channel(1000);
        Self {
            upstreams: DashMap::new(),
            update_notifier: tx,
            next_generation: AtomicU64::new(1),
        }
    }
}

impl HealthCheckRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a health check. Infallible: all fallible work belongs in Candidate build.
    ///
    /// On replace, the previous task is **not** stopped here. The caller receives a
    /// [`DisplacedHealthCheck`] and must [`discard`](DisplacedHealthCheck::discard) it after
    /// a successful runtime publish (or [`restore`](DisplacedHealthCheck::restore) on abort).
    pub fn register_upstream(
        &self,
        upstream_id: String,
        load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    ) -> (HealthCheckRegistration, Option<DisplacedHealthCheck>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registration = HealthCheckRegistration {
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
        };

        let registered = RegisteredUpstream {
            generation: registration.generation,
            load_balancer,
            shutdown_tx,
            shutdown_rx,
        };

        let displaced =
            self.upstreams
                .insert(upstream_id.clone(), registered)
                .map(|old_registered| {
                    log::info!(
                        "Displacing health check '{upstream_id}' gen {} → {}",
                        old_registered.generation,
                        registration.generation
                    );
                    DisplacedHealthCheck {
                        id: upstream_id.clone(),
                        registration: HealthCheckRegistration {
                            generation: old_registered.generation,
                        },
                        registered: old_registered,
                        notifier: self.update_notifier.clone(),
                    }
                });

        if let Err(e) = self.update_notifier.send(RegistryUpdate::Added {
            id: upstream_id.clone(),
            registration,
        }) {
            log::warn!("Failed to notify registry update: {e}");
        }

        log::info!("Registered upstream '{upstream_id}' for health check");
        (registration, displaced)
    }

    pub fn unregister_upstream(
        &self,
        upstream_id: &str,
        registration: HealthCheckRegistration,
    ) -> bool {
        if let Some((_, registered)) = self.upstreams.remove_if(upstream_id, |_, current| {
            current.generation == registration.generation
        }) {
            if let Err(e) = registered.shutdown_tx.send(true) {
                log::warn!("Failed to send shutdown signal to upstream '{upstream_id}': {e}");
            }
            if let Err(e) = self.update_notifier.send(RegistryUpdate::Removed {
                id: upstream_id.to_string(),
                registration,
            }) {
                log::warn!("Failed to notify registry update: {e}");
            }
            log::info!("Unregistered upstream '{upstream_id}' from health check");
            true
        } else {
            log::debug!("Ignoring stale health-check unregister for upstream '{upstream_id}'");
            false
        }
    }

    pub fn subscribe_updates(&self) -> broadcast::Receiver<RegistryUpdate> {
        self.update_notifier.subscribe()
    }

    pub fn get_upstream_for_start(
        &self,
        upstream_id: &str,
        registration: HealthCheckRegistration,
    ) -> Option<(
        String,
        Arc<dyn BackgroundService + Send + Sync>,
        watch::Receiver<bool>,
    )> {
        self.upstreams.get(upstream_id).and_then(|registered| {
            (registered.generation == registration.generation).then(|| {
                (
                    upstream_id.to_string(),
                    registered.load_balancer.clone(),
                    registered.shutdown_rx.clone(),
                )
            })
        })
    }

    pub fn get_all_upstreams(&self) -> Vec<(String, HealthCheckRegistration)> {
        self.upstreams
            .iter()
            .map(|entry| {
                (
                    entry.key().clone(),
                    HealthCheckRegistration {
                        generation: entry.generation,
                    },
                )
            })
            .collect()
    }
}

struct RunningHealthCheck {
    handle: tokio::task::JoinHandle<()>,
}

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

    pub async fn run(&self, registry: Arc<HealthCheckRegistry>, mut shutdown: ShutdownWatch) {
        log::info!("Starting health check executor");

        let mut update_receiver = registry.subscribe_updates();
        // Key by (id, generation) so a replacement can run alongside the displaced task
        // until the publisher discards the old generation after snapshot commit.
        let mut running_tasks: std::collections::HashMap<(String, u64), RunningHealthCheck> =
            std::collections::HashMap::new();

        for (upstream_id, registration) in registry.get_all_upstreams() {
            self.start_task(&registry, &mut running_tasks, upstream_id, registration);
        }

        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(1));
        cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::info!("Health check executor received shutdown signal");
                        for ((id, gen), running) in running_tasks {
                            log::debug!("Cancelling health check task for upstream '{id}' gen {gen}");
                            running.handle.abort();
                        }
                        break;
                    }
                }

                result = update_receiver.recv() => {
                    let update = match result {
                        Ok(upd) => upd,
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            log::warn!(
                                "Health check executor lagged, skipped {skipped} events. Performing full resync."
                            );
                            self.resync_tasks(&registry, &mut running_tasks).await;
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            log::info!("Registry update channel closed, stopping executor");
                            break;
                        }
                    };
                    match update {
                        RegistryUpdate::Added { id, registration } => {
                            log::debug!(
                                "Health check executor: upstream '{id}' gen {} added",
                                registration.generation()
                            );
                            self.start_task(&registry, &mut running_tasks, id, registration);
                        }
                        RegistryUpdate::Removed { id, registration } => {
                            let key = (id.clone(), registration.generation());
                            if let Some(running) = running_tasks.remove(&key) {
                                log::debug!(
                                    "Stopping health check task for upstream '{id}' gen {}",
                                    registration.generation()
                                );
                                running.handle.abort();
                            }
                        }
                    }

                    running_tasks.retain(|(id, gen), running| {
                        if running.handle.is_finished() {
                            log::debug!("Health check task for upstream '{id}' gen {gen} has finished");
                            false
                        } else {
                            true
                        }
                    });
                }

                _ = cleanup_interval.tick() => {
                    running_tasks.retain(|(id, gen), running| {
                        if running.handle.is_finished() {
                            log::debug!("Health check task for upstream '{id}' gen {gen} has finished");
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

    fn start_task(
        &self,
        registry: &Arc<HealthCheckRegistry>,
        running_tasks: &mut std::collections::HashMap<(String, u64), RunningHealthCheck>,
        id: String,
        registration: HealthCheckRegistration,
    ) {
        let key = (id.clone(), registration.generation());
        // Initial enumeration and a queued Added can both observe the same generation.
        // Identical (id, generation) must be an idempotent no-op — never drop a live handle.
        let std::collections::hash_map::Entry::Vacant(slot) = running_tasks.entry(key) else {
            return;
        };

        let Some((upstream_id, load_balancer, shutdown_rx)) =
            registry.get_upstream_for_start(&id, registration)
        else {
            return;
        };

        slot.insert(RunningHealthCheck {
            handle: tokio::spawn(async move {
                log::info!("Starting health check service for upstream '{upstream_id}'");
                load_balancer.start(shutdown_rx).await;
                log::info!("Health check service stopped for upstream '{upstream_id}'");
            }),
        });
    }

    async fn resync_tasks(
        &self,
        registry: &Arc<HealthCheckRegistry>,
        running_tasks: &mut std::collections::HashMap<(String, u64), RunningHealthCheck>,
    ) {
        let current: std::collections::HashSet<(String, u64)> = registry
            .get_all_upstreams()
            .into_iter()
            .map(|(id, reg)| (id, reg.generation()))
            .collect();

        running_tasks.retain(|key, running| {
            let keep = current.contains(key);
            if !keep {
                log::debug!(
                    "Resync: stopping stale task for upstream '{}' gen {}",
                    key.0,
                    key.1
                );
                running.handle.abort();
            }
            keep
        });

        for (upstream_id, registration) in registry.get_all_upstreams() {
            let key = (upstream_id.clone(), registration.generation());
            if !running_tasks.contains_key(&key) {
                self.start_task(registry, running_tasks, upstream_id, registration);
            }
        }
    }
}

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

    pub fn register_upstream(
        &self,
        upstream_id: String,
        load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    ) -> (HealthCheckRegistration, Option<DisplacedHealthCheck>) {
        self.registry.register_upstream(upstream_id, load_balancer)
    }

    pub fn unregister_upstream(
        &self,
        upstream_id: &str,
        registration: HealthCheckRegistration,
    ) -> bool {
        self.registry.unregister_upstream(upstream_id, registration)
    }

    pub fn registry(&self) -> &HealthCheckRegistry {
        &self.registry
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
        Some(1)
    }
}

pub static SHARED_HEALTH_CHECK_SERVICE: Lazy<SharedHealthCheckService> =
    Lazy::new(SharedHealthCheckService::new);

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopBackgroundService;

    #[async_trait]
    impl BackgroundService for NoopBackgroundService {}

    #[test]
    fn stale_registration_cannot_unregister_replacement() {
        let registry = HealthCheckRegistry::new();
        let (first, displaced) =
            registry.register_upstream("upstream-1".into(), Arc::new(NoopBackgroundService));
        assert!(displaced.is_none());

        let (replacement, displaced) =
            registry.register_upstream("upstream-1".into(), Arc::new(NoopBackgroundService));
        let displaced = displaced.expect("replacement should displace previous");
        assert_eq!(displaced.registration(), first);

        // Old generation is not in the map until restore; unregister of first fails.
        assert!(!registry.unregister_upstream("upstream-1", first));
        assert!(registry
            .get_upstream_for_start("upstream-1", replacement)
            .is_some());

        displaced.discard();
        assert!(registry.unregister_upstream("upstream-1", replacement));
        assert!(registry
            .get_upstream_for_start("upstream-1", replacement)
            .is_none());
    }

    #[test]
    fn displaced_can_be_restored_before_discard() {
        let registry = HealthCheckRegistry::new();
        let (first, _) = registry.register_upstream("u".into(), Arc::new(NoopBackgroundService));
        let (second, displaced) =
            registry.register_upstream("u".into(), Arc::new(NoopBackgroundService));
        let displaced = displaced.unwrap();

        registry.unregister_upstream("u", second);
        displaced.restore(&registry);
        assert!(registry.get_upstream_for_start("u", first).is_some());
    }

    struct HangUntilShutdown;

    #[async_trait]
    impl BackgroundService for HangUntilShutdown {
        async fn start(&self, mut shutdown: watch::Receiver<bool>) {
            let _ = shutdown.wait_for(|v| *v).await;
        }
    }

    #[tokio::test]
    async fn start_task_is_idempotent_for_same_generation() {
        let registry = Arc::new(HealthCheckRegistry::new());
        let (registration, _) =
            registry.register_upstream("upstream-1".into(), Arc::new(HangUntilShutdown));

        let executor = HealthCheckExecutor::new();
        let mut running_tasks = std::collections::HashMap::new();
        executor.start_task(
            &registry,
            &mut running_tasks,
            "upstream-1".into(),
            registration,
        );
        executor.start_task(
            &registry,
            &mut running_tasks,
            "upstream-1".into(),
            registration,
        );

        assert_eq!(running_tasks.len(), 1);
        for ((_, _), running) in running_tasks {
            running.handle.abort();
        }
    }
}
