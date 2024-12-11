use std::{error::Error, sync::Arc, time::Duration};

use async_trait::async_trait;
use etcd_client::{Client, ConnectOptions, Event, GetOptions, GetResponse, WatchOptions};
use pingora_core::services::background::BackgroundService;
use tokio::{sync::Mutex, time::sleep};

use super::Etcd;

pub struct EtcdConfigSync {
    config: Etcd,
    client: Arc<Mutex<Option<Client>>>,
    revision: Arc<Mutex<i64>>,
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
            client: Arc::new(Mutex::new(None)),
            revision: Arc::new(Mutex::new(0)),
            handler,
        }
    }

    /// 创建一个新的 etcd 客户端
    async fn create_client(&self) -> Result<Client, Box<dyn Error + Send + Sync>> {
        let mut options = ConnectOptions::default();
        if let Some(timeout) = self.config.timeout {
            options = options.with_timeout(Duration::from_secs(timeout as u64));
        }
        if let Some(connect_timeout) = self.config.connect_timeout {
            options = options.with_connect_timeout(Duration::from_secs(connect_timeout as u64));
        }
        if let (Some(user), Some(password)) = (&self.config.user, &self.config.password) {
            options = options.with_user(user.clone(), password.clone());
        }

        let client = Client::connect(self.config.host.clone(), Some(options)).await?;
        Ok(client)
    }

    /// 获取初始化的 etcd 客户端
    async fn get_client(&self) -> Result<Arc<Mutex<Option<Client>>>, Box<dyn Error + Send + Sync>> {
        let mut client_guard = self.client.lock().await;

        if client_guard.is_none() {
            log::info!("Creating new etcd client...");
            *client_guard = Some(self.create_client().await?);
        }

        Ok(self.client.clone())
    }

    /// 初始化时同步 etcd 数据
    async fn list(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let client_arc = self.get_client().await?; // 获取完整的 `Arc<Mutex>` 对象
        let mut client_guard = client_arc.lock().await; // 重新锁定获取内部值

        let client = client_guard
            .as_mut()
            .ok_or("Etcd client is not initialized")?;

        let options = GetOptions::new().with_prefix();
        let response = client
            .get(self.config.prefix.as_bytes(), Some(options))
            .await?;

        if let Some(header) = response.header() {
            *self.revision.lock().await = header.revision();
        } else {
            return Err("Missing response header from etcd".into());
        }

        self.handler.handle_list_response(&response);
        Ok(())
    }

    /// 监听 etcd 数据变更
    async fn watch(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let start_revision = *self.revision.lock().await + 1;
        let options = WatchOptions::new()
            .with_start_revision(start_revision)
            .with_prefix();

        let client_arc = self.get_client().await?; // 获取完整的 `Arc<Mutex>` 对象
        let mut client_guard = client_arc.lock().await; // 重新锁定获取内部值

        let client = client_guard
            .as_mut()
            .ok_or("Etcd client is not initialized")?;

        let (mut watcher, mut stream) = client
            .watch(self.config.prefix.as_bytes(), Some(options))
            .await?;

        watcher.request_progress().await?;

        while let Some(response) = stream.message().await? {
            if response.canceled() {
                log::warn!("Watch stream was canceled");
                break;
            }

            for event in response.events() {
                self.handler.handle_event(event);
            }
        }
        Ok(())
    }

    /// 重置客户端
    async fn reset_client(&self) {
        log::warn!("Resetting etcd client...");
        *self.client.lock().await = None;
    }

    /// 主任务循环
    async fn run_sync_loop(&self, shutdown: &pingora_core::server::ShutdownWatch) {
        loop {
            if *shutdown.borrow() {
                log::info!("Shutdown signal received, stopping etcd config sync");
                return;
            }

            if let Err(err) = self.list().await {
                log::error!("List operation failed: {:?}", err);
                self.reset_client().await;
                sleep(Duration::from_secs(3)).await;
                continue;
            }

            if let Err(err) = self.watch().await {
                log::error!("Watch operation failed: {:?}", err);
                self.reset_client().await;
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[async_trait]
impl BackgroundService for EtcdConfigSync {
    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) {
        self.run_sync_loop(&shutdown).await;
    }
}

pub trait EtcdEventHandler {
    fn handle_event(&self, event: &Event);
    fn handle_list_response(&self, response: &GetResponse);
}
