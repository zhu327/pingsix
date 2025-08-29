use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use log::{debug, info, warn};
use once_cell::sync::Lazy;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, Service},
};
// LoadBalancer相关的导入在这里不需要，因为我们直接使用Service
use tokio::sync::{broadcast, watch};

/// 注册表更新事件
#[derive(Debug, Clone)]
pub enum RegistryUpdate {
    Added(String),
    Removed(String),
}

/// 已注册的upstream信息
struct RegisteredUpstream {
    load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// 健康检查注册表
pub struct HealthCheckRegistry {
    upstreams: HashMap<String, RegisteredUpstream>,
    update_notifier: broadcast::Sender<RegistryUpdate>,
}

impl Default for HealthCheckRegistry {
    fn default() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        Self {
            upstreams: HashMap::new(),
            update_notifier: tx,
        }
    }
}

impl HealthCheckRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个upstream的健康检查
    pub fn register_upstream(
        &mut self,
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

        // 通知executor有新的upstream注册
        if let Err(e) = self
            .update_notifier
            .send(RegistryUpdate::Added(upstream_id.clone()))
        {
            warn!("Failed to notify registry update: {e}");
        }

        info!("Registered upstream '{upstream_id}' for health check");
        Ok(())
    }

    /// 注销一个upstream的健康检查
    pub fn unregister_upstream(&mut self, upstream_id: &str) -> bool {
        if let Some(registered) = self.upstreams.remove(upstream_id) {
            // 发送关闭信号
            if let Err(e) = registered.shutdown_tx.send(true) {
                warn!("Failed to send shutdown signal to upstream '{upstream_id}': {e}");
            }

            // 通知executor
            if let Err(e) = self
                .update_notifier
                .send(RegistryUpdate::Removed(upstream_id.to_string()))
            {
                warn!("Failed to notify registry update: {e}");
            }

            info!("Unregistered upstream '{upstream_id}' from health check");
            true
        } else {
            warn!("Attempted to unregister non-existent upstream '{upstream_id}'");
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

    /// 获取所有upstream的ID列表
    pub fn get_all_upstream_ids(&self) -> Vec<String> {
        self.upstreams.keys().cloned().collect()
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

    /// 运行健康检查执行器
    pub async fn run(&self, registry: Arc<RwLock<HealthCheckRegistry>>, shutdown: ShutdownWatch) {
        info!("Starting health check executor");

        // 移除 Semaphore，因为 LoadBalancer::start() 内部已经处理并发控制
        let mut update_receiver = {
            let registry_guard = registry.read().unwrap();
            registry_guard.subscribe_updates()
        };

        // 存储已启动的健康检查任务
        let mut running_tasks: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
            std::collections::HashMap::new();

        // 启动已存在的upstream的健康检查
        {
            let registry_guard = registry.read().unwrap();
            for upstream_id in registry_guard.get_all_upstream_ids() {
                if let Some((task_upstream_id, load_balancer, shutdown_rx)) =
                    registry_guard.get_upstream_for_start(&upstream_id)
                {
                    let task_id = upstream_id.clone();

                    let handle = tokio::spawn(async move {
                        info!("Starting health check service for upstream '{task_upstream_id}'");

                        // 直接调用 LoadBalancer 的 start 方法
                        load_balancer.start(shutdown_rx).await;

                        info!("Health check service stopped for upstream '{task_upstream_id}'");
                    });

                    running_tasks.insert(task_id, handle);
                }
            }
        }

        loop {
            // 检查是否需要关闭
            if *shutdown.borrow() {
                info!("Health check executor received shutdown signal");
                // 取消所有运行中的任务
                for (upstream_id, handle) in running_tasks {
                    debug!("Cancelling health check task for upstream '{upstream_id}'");
                    handle.abort();
                }
                break;
            }

            // 处理注册表更新事件
            while let Ok(update) = update_receiver.try_recv() {
                match update {
                    RegistryUpdate::Added(id) => {
                        debug!("Health check executor: upstream '{id}' added");
                        // 启动新的健康检查任务
                        if let Some((upstream_id, load_balancer, shutdown_rx)) = {
                            let registry_guard = registry.read().unwrap();
                            registry_guard.get_upstream_for_start(&id)
                        } {
                            let task_id = upstream_id.clone();

                            let handle = tokio::spawn(async move {
                                info!("Starting health check service for upstream '{upstream_id}'");

                                // LoadBalancer::start 是一个循环，会一直运行直到收到shutdown信号
                                // LoadBalancer 内部会处理所有的并发控制和时间调度
                                load_balancer.start(shutdown_rx).await;

                                info!("Health check service stopped for upstream '{upstream_id}'");
                            });

                            running_tasks.insert(task_id, handle);
                        }
                    }
                    RegistryUpdate::Removed(id) => {
                        debug!("Health check executor: upstream '{id}' removed");
                        // 停止对应的健康检查任务
                        if let Some(handle) = running_tasks.remove(&id) {
                            debug!("Stopping health check task for upstream '{id}'");
                            handle.abort();
                        }
                    }
                }
            }

            // 清理已完成的任务
            running_tasks.retain(|upstream_id, handle| {
                if handle.is_finished() {
                    debug!("Health check task for upstream '{upstream_id}' has finished");
                    false
                } else {
                    true
                }
            });

            // 短暂等待，避免忙等待
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("Health check executor stopped");
    }
}

/// 共享健康检查服务
#[derive(Clone)]
pub struct SharedHealthCheckService {
    registry: Arc<RwLock<HealthCheckRegistry>>,
    executor: HealthCheckExecutor,
}

impl Default for SharedHealthCheckService {
    fn default() -> Self {
        Self {
            registry: Arc::new(RwLock::new(HealthCheckRegistry::new())),
            executor: HealthCheckExecutor::new(),
        }
    }
}

impl SharedHealthCheckService {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个upstream的健康检查
    pub fn register_upstream(
        &self,
        upstream_id: String,
        load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut registry = self.registry.write().unwrap();
        registry.register_upstream(upstream_id, load_balancer)
    }

    /// 注销一个upstream的健康检查
    pub fn unregister_upstream(&self, upstream_id: &str) -> bool {
        let mut registry = self.registry.write().unwrap();
        registry.unregister_upstream(upstream_id)
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
