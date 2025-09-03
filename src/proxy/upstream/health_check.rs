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
        let (tx, _rx) = broadcast::channel(100);
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

        self.upstreams.insert(upstream_id.clone(), registered);

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

    /// 获取指定upstream用于启动健康检查
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

    /// 获取更新通知接收器
    pub fn subscribe_updates(&self) -> broadcast::Receiver<RegistryUpdate> {
        self.update_notifier.subscribe()
    }
}

/// 健康检查执行器
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

    /// 运行健康检查执行器 - 优化并发性能，移除RwLock
    pub async fn run(&self, registry: Arc<HealthCheckRegistry>, shutdown: ShutdownWatch) {
        log::info!("Starting health check executor");

        // Get update receiver directly from registry, no lock needed
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
            // Check if shutdown is requested
            if *shutdown.borrow() {
                log::info!("Health check executor received shutdown signal");
                // Cancel all running tasks
                for (upstream_id, handle) in running_tasks {
                    log::debug!("Cancelling health check task for upstream '{upstream_id}'");
                    handle.abort();
                }
                break;
            }

            // Handle registry update events
            while let Ok(update) = update_receiver.try_recv() {
                match update {
                    RegistryUpdate::Added(id) => {
                        log::debug!("Health check executor: upstream '{id}' added");
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
            }

            // Clean up completed tasks
            running_tasks.retain(|upstream_id, handle| {
                if handle.is_finished() {
                    log::debug!("Health check task for upstream '{upstream_id}' has finished");
                    false
                } else {
                    true
                }
            });

            // 短暂等待，避免忙等待
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        log::info!("Health check executor stopped");
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
        Some(1) // 使用单线程运行
    }
}

/// 全局共享健康检查服务实例
pub static SHARED_HEALTH_CHECK_SERVICE: Lazy<SharedHealthCheckService> =
    Lazy::new(SharedHealthCheckService::new);
