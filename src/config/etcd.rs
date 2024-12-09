use std::{sync::Arc, time::Duration};

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
        Self {
            config,
            client: Arc::new(Mutex::new(None)),
            revision: Arc::new(Mutex::new(0)),
            handler,
        }
    }

    /// 创建一个新的 etcd 客户端
    async fn create_client(&self) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
        let mut options = ConnectOptions::default();
        if let Some(timeout) = self.config.timeout {
            options = options.with_timeout(Duration::from_secs(timeout as u64));
        };
        if let Some(connect_timeout) = self.config.connect_timeout {
            options = options.with_connect_timeout(Duration::from_secs(connect_timeout as u64));
        };
        if let (Some(user), Some(password)) = (&self.config.user, &self.config.password) {
            options = options.with_user(user.clone(), password.clone());
        };

        let client = Client::connect(self.config.host.clone(), Some(options)).await?;
        Ok(client)
    }

    /// 初始化时同步 etcd 数据
    async fn list(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let options = GetOptions::new().with_prefix();

        let mut client_guard = self.client.lock().await;
        let client = client_guard
            .as_mut()
            .ok_or("Etcd client is not initialized")?;

        let response = client
            .get(self.config.prefix.as_bytes(), Some(options))
            .await?;
        let revision = response.header().unwrap().revision();
        *self.revision.lock().await = revision;

        // handle response
        self.handler.handle_list_response(&response);

        Ok(())
    }

    /// 监听 etcd 数据变更
    async fn watch(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_revision = *self.revision.lock().await + 1;
        let options = WatchOptions::new()
            .with_start_revision(start_revision)
            .with_prefix();

        // 获取 Client 的可变引用
        let mut client_guard = self.client.lock().await;
        let client = client_guard
            .as_mut()
            .ok_or("Etcd client is not initialized")?;

        let (mut watcher, mut stream) = client
            .watch(self.config.prefix.as_bytes(), Some(options))
            .await?;

        watcher.request_progress().await?;

        while let Some(response) = stream.message().await? {
            if response.canceled() {
                break;
            }

            for event in response.events() {
                // handle event
                self.handler.handle_event(event);
            }
        }
        Ok(())
    }

    /// 确保 etcd 客户端可用，否则重新创建
    async fn ensure_client(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client_guard = self.client.lock().await;

        if client_guard.is_none() {
            log::info!("Creating new etcd client...");
            *client_guard = Some(self.create_client().await?);
        }
        Ok(())
    }
}

#[async_trait]
impl BackgroundService for EtcdConfigSync {
    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) -> () {
        loop {
            if *shutdown.borrow() {
                return;
            }

            // 确保客户端存在
            log::info!("Ensuring etcd client...");
            if let Err(err) = self.ensure_client().await {
                log::error!("Failed to create etcd client: {:?}", err);
                sleep(Duration::from_secs(3)).await;
                continue;
            }

            // 执行 list 操作
            log::info!("Executing etcd list operation...");
            if let Err(err) = self.list().await {
                log::error!("List operation failed: {:?}", err);
                *self.client.lock().await = None; // 重置客户端以便重试
                sleep(Duration::from_secs(3)).await;
                continue;
            }

            // 执行 watch 操作
            log::info!("Executing etcd watch operation...");
            if let Err(err) = self.watch().await {
                log::error!("Watch operation failed: {:?}", err);
                *self.client.lock().await = None; // 重置客户端以便重试
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

pub trait EtcdEventHandler {
    fn handle_event(&self, event: &Event);
    fn handle_list_response(&self, response: &GetResponse);
}
