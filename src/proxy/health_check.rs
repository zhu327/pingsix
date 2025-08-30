use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
use log::{debug, info, warn};
use once_cell::sync::Lazy;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, Service},
};
use tokio::sync::{broadcast, watch};
use prometheus::{register_histogram, register_int_counter, Histogram, IntCounter};
use std::time::Instant;

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

/// 健康检查注册表 - 使用DashMap提供更好的并发性能
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

    /// 注册一个upstream的健康检查 - 无需可变引用，DashMap支持并发插入
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

    /// 注销一个upstream的健康检查 - 无需可变引用，DashMap支持并发删除
    pub fn unregister_upstream(&self, upstream_id: &str) -> bool {
        if let Some((_, registered)) = self.upstreams.remove(upstream_id) {
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

    /// 获取所有upstream的ID列表 - 使用DashMap的迭代器
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
        info!("Starting health check executor");

        // metrics
        static HC_TASKS_STARTED: Lazy<IntCounter> = Lazy::new(|| {
            register_int_counter!(
                "pingsix_health_check_tasks_started_total",
                "Number of health check tasks started"
            )
            .unwrap()
        });
        static HC_TASKS_ABORTED: Lazy<IntCounter> = Lazy::new(|| {
            register_int_counter!(
                "pingsix_health_check_tasks_aborted_total",
                "Number of health check tasks aborted"
            )
            .unwrap()
        });
        static HC_LOOP_LATENCY: Lazy<Histogram> = Lazy::new(|| {
            register_histogram!(
                "pingsix_health_check_loop_interval_ms",
                "Loop interval latency in ms"
            )
            .unwrap()
        });

        // 直接从registry获取更新接收器，无需锁
        let mut update_receiver = registry.subscribe_updates();

        // 存储已启动的健康检查任务
        let mut running_tasks: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
            std::collections::HashMap::new();

        // 启动已存在的upstream的健康检查
        for upstream_id in registry.get_all_upstream_ids() {
            if let Some((task_upstream_id, load_balancer, shutdown_rx)) =
                registry.get_upstream_for_start(&upstream_id)
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

        loop {
            let loop_start = Instant::now();
            // 检查是否需要关闭
            if *shutdown.borrow() {
                info!("Health check executor received shutdown signal");
                // 取消所有运行中的任务
                for (upstream_id, handle) in running_tasks {
                    debug!("Cancelling health check task for upstream '{upstream_id}'");
                    handle.abort();
                    HC_TASKS_ABORTED.inc();
                }
                break;
            }

            // 处理注册表更新事件
            while let Ok(update) = update_receiver.try_recv() {
                match update {
                    RegistryUpdate::Added(id) => {
                        debug!("Health check executor: upstream '{id}' added");
                        // 启动新的健康检查任务 - 直接访问registry，无需锁
                        if let Some((upstream_id, load_balancer, shutdown_rx)) =
                            registry.get_upstream_for_start(&id)
                        {
                            let task_id = upstream_id.clone();

                            let handle = tokio::spawn(async move {
                                info!("Starting health check service for upstream '{upstream_id}'");

                                // LoadBalancer::start 是一个循环，会一直运行直到收到shutdown信号
                                // LoadBalancer 内部会处理所有的并发控制和时间调度
                                load_balancer.start(shutdown_rx).await;

                                info!("Health check service stopped for upstream '{upstream_id}'");
                            });

                            running_tasks.insert(task_id, handle);
                            HC_TASKS_STARTED.inc();
                        }
                    }
                    RegistryUpdate::Removed(id) => {
                        debug!("Health check executor: upstream '{id}' removed");
                        // 停止对应的健康检查任务
                        if let Some(handle) = running_tasks.remove(&id) {
                            debug!("Stopping health check task for upstream '{id}'");
                            handle.abort();
                            HC_TASKS_ABORTED.inc();
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
            let elapsed_ms = loop_start.elapsed().as_millis() as f64;
            HC_LOOP_LATENCY.observe(elapsed_ms);
        }

        info!("Health check executor stopped");
    }
}

/// 共享健康检查服务 - 移除RwLock，使用DashMap提供更好的并发性能
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

    /// 注册一个upstream的健康检查 - 无需锁，直接调用registry方法
    pub fn register_upstream(
        &self,
        upstream_id: String,
        load_balancer: Arc<dyn BackgroundService + Send + Sync>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.registry.register_upstream(upstream_id, load_balancer)
    }

    /// 注销一个upstream的健康检查 - 无需锁，直接调用registry方法
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
