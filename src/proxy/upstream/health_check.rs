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

    /// Signal every currently registered task to stop (process-shutdown path).
    ///
    /// Tasks observe their own `watch::Receiver` and exit cleanly; the executor
    /// then awaits them with a bounded grace period before aborting.
    pub fn request_shutdown_all(&self) {
        for entry in self.upstreams.iter() {
            let _ = entry.shutdown_tx.send(true);
        }
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
                        // Graceful path: signal every task, then wait a bounded
                        // interval for it to drain instead of aborting mid-cleanup.
                        registry.request_shutdown_all();
                        self.stop_all_tasks(&mut running_tasks).await;
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
                            self.restart_finished_tasks(&registry, &mut running_tasks);
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            log::info!("Registry update channel closed, stopping executor");
                            self.stop_all_tasks(&mut running_tasks).await;
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
                                self.stop_task(running.handle).await;
                            }
                        }
                    }

                    self.restart_finished_tasks(&registry, &mut running_tasks);
                }

                _ = cleanup_interval.tick() => {
                    self.restart_finished_tasks(&registry, &mut running_tasks);
                }
            }
        }

        log::info!("Health check executor stopped");
    }

    /// Await every running task with a shared bounded grace period, aborting
    /// only tasks that refuse to stop. Idempotent; drains the map.
    async fn stop_all_tasks(
        &self,
        running_tasks: &mut std::collections::HashMap<(String, u64), RunningHealthCheck>,
    ) {
        let handles: Vec<(String, u64, tokio::task::JoinHandle<()>)> = running_tasks
            .drain()
            .map(|((id, gen), running)| (id, gen, running.handle))
            .collect();
        let grace = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(grace);
        for (id, gen, mut handle) in handles {
            tokio::select! {
                _ = &mut handle => {
                    log::debug!("Health check task for upstream '{id}' gen {gen} stopped cleanly");
                }
                _ = &mut grace => {
                    log::warn!(
                        "Health check task for upstream '{id}' gen {gen} missed shutdown grace; aborting"
                    );
                    handle.abort();
                    let _ = handle.await;
                }
            }
        }
    }

    /// Await one task's clean exit with a short grace period before aborting.
    async fn stop_task(&self, mut handle: tokio::task::JoinHandle<()>) {
        let grace = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(grace);
        tokio::select! {
            _ = &mut handle => {}
            _ = &mut grace => {
                handle.abort();
                let _ = handle.await;
            }
        }
    }

    /// Re-own tasks that exited unexpectedly while still registered.
    ///
    /// A maintenance task (DNS refresh / active probes) that returns without a
    /// shutdown request would otherwise be lost forever on a quiet system, so
    /// it is restarted on the next cleanup tick. Tasks whose registration is no
    /// longer current (replaced or unregistered) are dropped instead.
    fn restart_finished_tasks(
        &self,
        registry: &Arc<HealthCheckRegistry>,
        running_tasks: &mut std::collections::HashMap<(String, u64), RunningHealthCheck>,
    ) {
        let finished: Vec<(String, u64)> = running_tasks
            .iter()
            .filter(|(_, running)| running.handle.is_finished())
            .map(|((id, gen), _)| (id.clone(), *gen))
            .collect();
        for (id, gen) in finished {
            let registration = HealthCheckRegistration { generation: gen };
            running_tasks.remove(&(id.clone(), gen));
            if registry.get_upstream_for_start(&id, registration).is_some() {
                log::warn!(
                    "Health check task for upstream '{id}' gen {gen} exited unexpectedly; restarting"
                );
                self.start_task(registry, running_tasks, id, registration);
            } else {
                log::debug!(
                    "Health check task for upstream '{id}' gen {gen} exited; no longer registered"
                );
            }
        }
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

        // Collect stale keys first (`retain`'s closure is synchronous and
        // cannot await), then stop each displaced task with the same bounded
        // grace as every other removal path.
        let stale_keys: Vec<(String, u64)> = running_tasks
            .iter()
            .filter(|(key, _)| !current.contains(*key))
            .map(|((id, gen), _)| (id.clone(), *gen))
            .collect();
        for (id, gen) in stale_keys {
            log::debug!("Resync: stopping stale task for upstream '{id}' gen {gen}");
            if let Some(running) = running_tasks.remove(&(id.clone(), gen)) {
                self.stop_task(running.handle).await;
            }
        }

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

    struct ExitImmediately;

    #[async_trait]
    impl BackgroundService for ExitImmediately {
        async fn start(&self, _shutdown: watch::Receiver<bool>) {}
    }

    #[tokio::test]
    async fn crashed_task_is_restarted_while_still_registered() {
        let registry = Arc::new(HealthCheckRegistry::new());
        let (registration, _) = registry.register_upstream("u".into(), Arc::new(ExitImmediately));
        let executor = HealthCheckExecutor::new();
        let mut running_tasks = std::collections::HashMap::new();
        executor.start_task(&registry, &mut running_tasks, "u".into(), registration);

        let key = ("u".to_string(), registration.generation());
        assert!(running_tasks.contains_key(&key));
        // Wait for the task to exit on its own, leaving its finished handle in
        // the map for the supervisor to detect.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !running_tasks
            .get(&key)
            .is_some_and(|running| running.handle.is_finished())
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "task should finish promptly"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        executor.restart_finished_tasks(&registry, &mut running_tasks);
        assert!(
            running_tasks.contains_key(&key),
            "a maintenance task that exited while still registered must be restarted"
        );
        let restarted = running_tasks.remove(&key).unwrap();
        restarted.handle.abort();
    }

    #[tokio::test]
    async fn finished_task_is_not_restarted_after_unregister() {
        let registry = Arc::new(HealthCheckRegistry::new());
        let (registration, _) = registry.register_upstream("u".into(), Arc::new(ExitImmediately));
        let executor = HealthCheckExecutor::new();
        let mut running_tasks = std::collections::HashMap::new();
        executor.start_task(&registry, &mut running_tasks, "u".into(), registration);

        let key = ("u".to_string(), registration.generation());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !running_tasks
            .get(&key)
            .is_some_and(|running| running.handle.is_finished())
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "task should finish promptly"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Unregister removes the registration; the finished task must not resurrect.
        assert!(registry.unregister_upstream("u", registration));
        executor.restart_finished_tasks(&registry, &mut running_tasks);
        assert!(
            running_tasks.is_empty(),
            "a task that exited after unregister must not resurrect"
        );
    }

    #[test]
    fn request_shutdown_all_signals_every_registered_task() {
        let registry = Arc::new(HealthCheckRegistry::new());
        let (registration, _) =
            registry.register_upstream("u1".into(), Arc::new(HangUntilShutdown));
        let (_registration2, _) =
            registry.register_upstream("u2".into(), Arc::new(HangUntilShutdown));

        registry.request_shutdown_all();

        // The tasks observe the shutdown through their receivers: drain the
        // current registration and confirm its watch flipped to true.
        let (_, _, shutdown_rx) = registry
            .get_upstream_for_start("u1", registration)
            .expect("u1 still registered");
        assert!(
            *shutdown_rx.borrow(),
            "request_shutdown_all must signal registered task watches"
        );
    }

    /// A broadcast-lag resync must remove stale tasks using the same bounded
    /// grace as every other removal path (never a bare abort).
    #[tokio::test]
    async fn resync_removes_stale_tasks_with_bounded_stop() {
        let registry = Arc::new(HealthCheckRegistry::new());
        let executor = HealthCheckExecutor::new();
        let mut running_tasks = std::collections::HashMap::new();

        // A task whose registration no longer exists in the registry.
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let service = Arc::new(HangUntilShutdown);
        let handle = tokio::spawn(async move {
            service.start(shutdown_rx).await;
        });
        running_tasks.insert(("gone".to_string(), 7), RunningHealthCheck { handle });

        executor.resync_tasks(&registry, &mut running_tasks).await;

        assert!(
            running_tasks.is_empty(),
            "resync must remove tasks whose registration is gone"
        );
    }
}
