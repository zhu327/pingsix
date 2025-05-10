use std::io::{self, Write};

use async_trait::async_trait;
use env_logger::Builder;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::{
    fs::{create_dir_all, metadata, OpenOptions},
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc::{channel, Receiver, Sender},
    time::{interval, Duration},
};

use crate::config;

pub struct AsyncWriter {
    sender: Sender<Vec<u8>>,
}

impl Write for AsyncWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let data = buf.to_vec();
        match self.sender.try_send(data) {
            Ok(_) => Ok(buf.len()),
            Err(e) => {
                eprintln!("Log buffer full, discarding message: {}", e);
                // Return Ok to avoid breaking env_logger, which expects success
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct Logger {
    sender: Sender<Vec<u8>>,
    receiver: Receiver<Vec<u8>>,
    config: config::Log,
}

impl Logger {
    pub fn new(config: config::Log) -> Self {
        // Bounded channel with configurable buffer size (default: 1024)
        let (sender, receiver) = channel::<Vec<u8>>(1024);
        Self {
            sender,
            receiver,
            config,
        }
    }

    fn create_async_writer(&self) -> AsyncWriter {
        AsyncWriter {
            sender: self.sender.clone(),
        }
    }

    pub fn init_env_logger(&self) {
        let writer = self.create_async_writer();
        Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .target(env_logger::Target::Pipe(Box::new(writer)))
            .init();
    }
}

#[async_trait]
impl Service for Logger {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let log_file_path = &self.config.path;

        if let Some(parent) = std::path::Path::new(log_file_path).parent() {
            if metadata(parent).await.is_err() {
                create_dir_all(parent)
                    .await
                    .expect("Failed to create log path");
            }
        }

        let file = OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .mode(0o644)
            .open(log_file_path)
            .await
            .expect("Failed to open or create log file");

        let mut file = BufWriter::with_capacity(4096, file);

        // Use configurable flush interval (default: 5 seconds)
        let mut flush_interval = interval(Duration::from_secs(5));

        // TODO: For log rotation, consider integrating `tracing_appender::rolling` or similar.
        // Example:
        // let mut roller = tracing_appender::rolling::hourly(parent, "app.log");
        // On rotation, update `file` to the new file handle.

        loop {
            tokio::select! {
                biased;
                // Shutdown signal handling
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::info!("Shutdown signal received, stopping write log");
                        break;
                    }
                },
                _ = flush_interval.tick() => {
                    if let Err(e) = file.flush().await {
                        log::error!("Failed to flush to log file '{}': {}", log_file_path, e);
                    }
                },
                data = self.receiver.recv() => {
                    match data {
                        Some(data) => {
                            if let Err(e) = file.write_all(&data).await {
                                log::error!("Failed to write to log file '{}': {}", log_file_path, e);
                            }
                        }
                        None => {
                            log::info!("Log channel closed, stopping write log");
                            break;
                        }
                    }
                }
            }
        }

        if let Err(e) = file.flush().await {
            log::error!("Failed to flush log file '{}': {}", log_file_path, e);
        }
    }

    fn name(&self) -> &'static str {
        "Log SYNC"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}
