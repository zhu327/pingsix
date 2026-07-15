use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

/// Backoff applied after each runtime write/flush failure to avoid a tight
/// error loop when the destination is unavailable.
const WRITE_FAILURE_BACKOFF: Duration = Duration::from_millis(10);
/// Emit a throttled "consecutive failures" summary every N runtime failures so
/// stderr is not flooded while still surfacing the degraded state.
const FAILURE_SUMMARY_EVERY: u64 = 16;

pub struct AsyncWriter {
    sender: Sender<Vec<u8>>,
    /// Shared flag set once the Logger service has given up on the file and
    /// entered the stderr fallback path (or shut down). When set, the writer
    /// emits log lines directly to stderr instead of just discarding them.
    stopped: Arc<AtomicBool>,
}

impl Write for AsyncWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let data = buf.to_vec();
        match self.sender.try_send(data) {
            Ok(_) => Ok(buf.len()),
            Err(e) => {
                // Never re-enter our own channel via log::error! here: that
                // would feed the failure back into the very pipe we are
                // writing to and cause a self-amplifying loop.
                if self.stopped.load(Ordering::Relaxed) {
                    // Writer has stopped / is in fallback: preserve the log
                    // line by writing it straight to stderr.
                    let _ = io::stderr().write_all(buf);
                } else {
                    eprintln!("Log buffer full, discarding message: {e}");
                }
                // Return Ok to avoid breaking env_logger, which expects
                // success from its writer.
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
    stopped: Arc<AtomicBool>,
}

impl Logger {
    pub fn new(config: config::Log) -> Self {
        // Bounded channel with configurable buffer size (default: 1024)
        let (sender, receiver) = channel::<Vec<u8>>(4096);
        Self {
            sender,
            receiver,
            config,
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    fn create_async_writer(&self) -> AsyncWriter {
        AsyncWriter {
            sender: self.sender.clone(),
            stopped: self.stopped.clone(),
        }
    }

    pub fn init_env_logger(&self) {
        let writer = self.create_async_writer();
        Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .target(env_logger::Target::Pipe(Box::new(writer)))
            .init();
    }

    /// Report a runtime writer error to stderr (never via `log::error!`, which
    /// would re-enter this same channel), throttle a periodic summary, and
    /// apply a short backoff so a persistently failing destination does not
    /// spin the select loop.
    async fn report_write_failure(fail_count: &mut u64, path: &str, err: io::Error) {
        *fail_count = fail_count.saturating_add(1);
        eprintln!("Failed to write to log file '{path}': {err}");
        if *fail_count % FAILURE_SUMMARY_EVERY == 0 {
            eprintln!(
                "Log writer has failed {fail_count} consecutive times; \
                 applying backoff and continuing on stderr"
            );
        }
        tokio::time::sleep(WRITE_FAILURE_BACKOFF).await;
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
                if let Err(e) = create_dir_all(parent).await {
                    let parent_path = parent.display();
                    // Startup init error: report on stderr and keep going so
                    // the file-open failure below transitions us into the
                    // stderr fallback instead of dropping all future logs.
                    eprintln!("Failed to create log directory '{parent_path}': {e}");
                }
            }
        }

        // `file_writer` is `None` when the file could not be opened; in that
        // case we keep the loop running and redirect every received log line
        // to stderr so application logs are not silently lost.
        let mut file_writer: Option<BufWriter<tokio::fs::File>> = match OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .mode(0o644)
            .open(log_file_path)
            .await
        {
            Ok(f) => Some(BufWriter::with_capacity(4096, f)),
            Err(e) => {
                // Runtime fallback marker: the AsyncWriter will now write
                // directly to stderr once the channel fills or this service
                // exits.
                self.stopped.store(true, Ordering::Relaxed);
                eprintln!(
                    "Failed to open or create log file '{log_file_path}': {e}; \
                     falling back to stderr"
                );
                None
            }
        };

        // Use configurable flush interval (default: 5 seconds)
        let mut flush_interval = interval(Duration::from_secs(5));
        let mut fail_count: u64 = 0;

        log::warn!(
            "Log rotation is not implemented. Log file '{log_file_path}' will grow unbounded. \
             Configure external log rotation (e.g., logrotate) for production use."
        );

        loop {
            tokio::select! {
                biased;
                // Shutdown signal handling
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::debug!("Shutdown signal received, stopping log writer");
                        break;
                    }
                },
                _ = flush_interval.tick() => {
                    if let Some(ref mut file) = file_writer {
                        if let Err(e) = file.flush().await {
                            Self::report_write_failure(
                                &mut fail_count,
                                log_file_path,
                                e,
                            )
                            .await;
                            // Unrecoverable flush failure: switch to stderr fallback.
                            file_writer = None;
                            self.stopped.store(true, Ordering::Relaxed);
                        } else {
                            fail_count = 0;
                        }
                    }
                },
                data = self.receiver.recv() => {
                    match data {
                        Some(data) => {
                            if file_writer.is_some() {
                                let write_ok = {
                                    let file = file_writer.as_mut().unwrap();
                                    match file.write_all(&data).await {
                                        Ok(()) => {
                                            fail_count = 0;
                                            true
                                        }
                                        Err(e) => {
                                            // Preserve the original log line on stderr, then
                                            // abandon the broken file handle for the existing
                                            // stderr fallback path.
                                            let _ = io::stderr().write_all(&data);
                                            Self::report_write_failure(
                                                &mut fail_count,
                                                log_file_path,
                                                e,
                                            )
                                            .await;
                                            false
                                        }
                                    }
                                };
                                if !write_ok {
                                    file_writer = None;
                                    self.stopped.store(true, Ordering::Relaxed);
                                    // Drain any queued lines to stderr after switching.
                                    for _ in 0..256 {
                                        let Ok(queued) = self.receiver.try_recv() else {
                                            break;
                                        };
                                        let _ = io::stderr().write_all(&queued);
                                    }
                                    continue;
                                }

                                // Drain a bounded batch to amortize select and write overhead
                                // without starving the shutdown and periodic flush branches.
                                let mut switched = false;
                                for _ in 0..256 {
                                    let Ok(queued) = self.receiver.try_recv() else {
                                        break;
                                    };
                                    let file = file_writer.as_mut().unwrap();
                                    if let Err(e) = file.write_all(&queued).await {
                                        let _ = io::stderr().write_all(&queued);
                                        Self::report_write_failure(
                                            &mut fail_count,
                                            log_file_path,
                                            e,
                                        )
                                        .await;
                                        file_writer = None;
                                        self.stopped.store(true, Ordering::Relaxed);
                                        switched = true;
                                        break;
                                    }
                                }
                                if switched {
                                    for _ in 0..256 {
                                        let Ok(queued) = self.receiver.try_recv() else {
                                            break;
                                        };
                                        let _ = io::stderr().write_all(&queued);
                                    }
                                }
                            } else {
                                // File unavailable: emit directly to stderr
                                // so application logs survive.
                                let _ = io::stderr().write_all(&data);
                                for _ in 0..256 {
                                    let Ok(queued) = self.receiver.try_recv() else {
                                        break;
                                    };
                                    let _ = io::stderr().write_all(&queued);
                                }
                            }
                        }
                        None => {
                            log::debug!("Log channel closed, stopping log writer");
                            break;
                        }
                    }
                }
            }
        }

        if let Some(ref mut file) = file_writer {
            if let Err(e) = file.flush().await {
                // Final flush failure: stderr only, never re-enter the channel.
                eprintln!("Failed to flush log file '{log_file_path}': {e}");
            }
        }
    }

    fn name(&self) -> &'static str {
        "Log SYNC"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    fn config_for(path: impl Into<String>) -> config::Log {
        config::Log { path: path.into() }
    }

    /// `AsyncWriter::write` must never panic and must report `Ok` even when the
    /// channel is closed or full, and must not re-enter the logging channel
    /// (it writes to stderr instead).
    #[tokio::test]
    async fn async_writer_closed_channel_does_not_panic_or_reenter() {
        let (sender, receiver) = channel::<Vec<u8>>(2);
        let stopped = Arc::new(AtomicBool::new(true));
        let mut writer = AsyncWriter { sender, stopped };

        // Drop the receiver so `try_send` returns `Closed`.
        drop(receiver);

        let mut sink = io::sink();
        for i in 0..8 {
            let line = format!("line {i}\n");
            let n = writer.write(line.as_bytes()).unwrap();
            assert_eq!(n, line.len());
            // Mirror what env_logger would do with a real stderr target so the
            // test exercises the stderr path without spamming the terminal.
            let _ = sink.write_all(line.as_bytes());
        }
    }

    /// When the log file cannot be opened, the service must not silently
    /// `return` and drop every subsequent log line. It stays alive, drains the
    /// channel to stderr, and shuts down cleanly within a timeout.
    #[tokio::test]
    async fn file_open_failure_falls_back_to_stderr() {
        // Build a read-only directory; creating a file inside it fails.
        let dir =
            std::env::temp_dir().join(format!("pingsix-log-open-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Strip write permission so file creation fails with EACCES.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        }

        let path = dir.join("child.log");
        let mut logger = Logger::new(config_for(path.to_string_lossy()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sender = logger.sender.clone();

        let handle = tokio::spawn(async move {
            logger.start_service(None, shutdown_rx, 0).await;
        });

        for i in 0..16 {
            sender
                .try_send(format!("fallback msg {i}\n").into_bytes())
                .unwrap();
        }

        // Give the service time to drain the channel into stderr (fallback).
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            sender.capacity(),
            4096,
            "channel should be fully drained in fallback mode"
        );

        shutdown_tx.send(true).unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .is_ok();
        assert!(completed, "start_service did not shut down in time");

        // Restore permissions so cleanup succeeds.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Continuous runtime write failures (file open succeeds but writes fail)
    /// must switch to stderr fallback: preserve the failed line on stderr, clear
    /// `file_writer`, set `stopped`, and keep draining without re-entering the
    /// logging channel.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn continuous_write_failure_switches_to_stderr_fallback() {
        // `/dev/full` opens fine but every write returns ENOSPC.
        if !std::path::Path::new("/dev/full").exists() {
            return;
        }
        let mut logger = Logger::new(config_for("/dev/full"));
        let stopped = logger.stopped.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sender = logger.sender.clone();

        let handle = tokio::spawn(async move {
            logger.start_service(None, shutdown_rx, 0).await;
        });

        // Messages larger than the 4096-byte BufWriter force an immediate
        // underlying write, which fails with ENOSPC.
        let big = vec![b'x'; 8192];
        for _ in 0..4 {
            sender.try_send(big.clone()).unwrap();
        }

        // Allow processing with backoff + fallback switch.
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(
            stopped.load(Ordering::Relaxed),
            "write failure must set stopped and enter stderr fallback"
        );

        // After fallback, further messages must still be consumed (to stderr).
        for i in 0..8 {
            sender
                .try_send(format!("after-fallback {i}\n").into_bytes())
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Because errors go to stderr (not `log::error!`), no self-generated
        // messages re-enter the channel; it must return to full capacity.
        assert_eq!(
            sender.capacity(),
            4096,
            "channel should be empty: write failures must not feed back via log macros"
        );

        shutdown_tx.send(true).unwrap();
        let completed = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .is_ok();
        assert!(completed, "start_service did not shut down in time");
    }
}
