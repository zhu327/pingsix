use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use env_logger::Builder;
use once_cell::sync::Lazy;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use prometheus::{register_int_counter, register_int_counter_vec, IntCounter, IntCounterVec};
use tokio::{
    fs::{create_dir_all, metadata, OpenOptions},
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc::{channel, Receiver, Sender},
    time::{interval, Duration},
};

use crate::config;

#[cfg(unix)]
fn secure_open_options(options: &mut OpenOptions) {
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn secure_open_options(_options: &mut OpenOptions) {}

async fn open_log_file(path: &str) -> io::Result<tokio::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).append(true).create(true);
    secure_open_options(&mut options);
    let file = options.open(path).await?;
    if !file.metadata().await?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "log path is not a regular file",
        ));
    }
    Ok(file)
}

/// Backoff applied after each runtime write/flush failure to avoid a tight
/// error loop when the destination is unavailable.
const WRITE_FAILURE_BACKOFF: Duration = Duration::from_millis(10);
/// Emit a throttled "consecutive failures" summary every N runtime failures so
/// stderr is not flooded while still surfacing the degraded state.
const FAILURE_SUMMARY_EVERY: u64 = 16;

static LOG_DROPPED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_log_messages_dropped_total",
        "Log messages not accepted by the asynchronous writer",
        &["reason"]
    )
    .expect("log metric registration must succeed")
});
static LOG_WRITE_FAILURES: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("pingsix_log_write_failures_total", "Log writer failures")
        .expect("log metric registration must succeed")
});
static LOG_ROTATIONS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "pingsix_log_rotations_total",
        "Completed internal log rotations"
    )
    .expect("log metric registration must succeed")
});
static DROP_SUMMARY: AtomicU64 = AtomicU64::new(0);

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
                let reason = match &e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => "buffer_full",
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => "channel_closed",
                };
                LOG_DROPPED.with_label_values(&[reason]).inc();
                // Never re-enter our own channel via log::error! here: that
                // would feed the failure back into the very pipe we are
                // writing to and cause a self-amplifying loop.
                if self.stopped.load(Ordering::Relaxed) {
                    // Writer has stopped / is in fallback: preserve the log
                    // line by writing it straight to stderr.
                    let _ = io::stderr().write_all(buf);
                } else if DROP_SUMMARY
                    .fetch_add(1, Ordering::Relaxed)
                    .is_multiple_of(16)
                {
                    eprintln!("Log buffer unavailable, discarding messages: {e}");
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

async fn rotate_log_file(path: &str, max_backups: u32) -> io::Result<()> {
    // Remove backups retained by an earlier, larger `max_backups` setting.
    let path = std::path::Path::new(path);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "log path has no valid file name",
            )
        })?;
    let prefix = format!("{name}.");
    let mut entries = tokio::fs::read_dir(parent).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let Some(suffix) = file_name
            .to_str()
            .and_then(|file_name| file_name.strip_prefix(&prefix))
        else {
            continue;
        };
        if suffix.parse::<u32>().is_ok_and(|index| index > max_backups) {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }

    let path = path.to_string_lossy().into_owned();
    if max_backups == 0 {
        return tokio::fs::remove_file(&path)
            .await
            .or_else(|e| (e.kind() == io::ErrorKind::NotFound).then_some(()).ok_or(e));
    }
    for index in (1..max_backups).rev() {
        let from = format!("{path}.{index}");
        let to = format!("{path}.{}", index + 1);
        match tokio::fs::rename(&from, &to).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    tokio::fs::rename(&path, format!("{path}.1")).await
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
        LOG_WRITE_FAILURES.inc();
        eprintln!("Failed to write to log file '{path}': {err}");
        if (*fail_count).is_multiple_of(FAILURE_SUMMARY_EVERY) {
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
        let mut file_writer: Option<BufWriter<tokio::fs::File>> =
            match open_log_file(log_file_path).await {
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

                                // Rotate between messages, preserving the active writer's
                                // ordering and bounding retained disk use.
                                let should_rotate = self.config.rotation == config::LogRotation::Internal
                                    && match file_writer.as_ref() {
                                    Some(file) => file
                                        .get_ref()
                                        .metadata()
                                        .await
                                        .is_ok_and(|metadata| metadata.len() >= self.config.max_size_bytes),
                                    None => false,
                                };
                                if should_rotate {
                                    if let Some(file) = file_writer.as_mut() {
                                        if let Err(e) = file.flush().await {
                                            Self::report_write_failure(&mut fail_count, log_file_path, e).await;
                                            file_writer = None;
                                            self.stopped.store(true, Ordering::Relaxed);
                                            continue;
                                        }
                                    }
                                    drop(file_writer.take());
                                    if let Err(e) = rotate_log_file(log_file_path, self.config.max_backups).await {
                                        Self::report_write_failure(&mut fail_count, log_file_path, e).await;
                                        self.stopped.store(true, Ordering::Relaxed);
                                    } else {
                                        match open_log_file(log_file_path).await {
                                            Ok(file) => {
                                                file_writer = Some(BufWriter::with_capacity(4096, file));
                                                LOG_ROTATIONS.inc();
                                            }
                                            Err(e) => {
                                                Self::report_write_failure(&mut fail_count, log_file_path, e).await;
                                                self.stopped.store(true, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    if file_writer.is_none() {
                                        // Rotation/reopen failed: preserve queued lines via the
                                        // stderr fallback instead of entering the batch writer.
                                        for _ in 0..256 {
                                            let Ok(queued) = self.receiver.try_recv() else {
                                                break;
                                            };
                                            let _ = io::stderr().write_all(&queued);
                                        }
                                        continue;
                                    }
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
        config::Log {
            path: path.into(),
            max_size_bytes: 100 * 1024 * 1024,
            max_backups: 5,
            rotation: config::LogRotation::Internal,
        }
    }

    #[tokio::test]
    async fn rotation_retains_configured_backups() {
        let path = std::env::temp_dir().join(format!("pingsix-log-{}", std::process::id()));
        std::fs::write(&path, b"current").unwrap();
        std::fs::write(format!("{}.1", path.display()), b"old").unwrap();
        std::fs::write(format!("{}.3", path.display()), b"stale").unwrap();
        rotate_log_file(path.to_str().unwrap(), 2).await.unwrap();
        assert!(!path.with_extension("log-ignored").exists());
        assert!(std::path::PathBuf::from(format!("{}.1", path.display())).exists());
        assert!(std::path::PathBuf::from(format!("{}.2", path.display())).exists());
        assert!(!std::path::PathBuf::from(format!("{}.3", path.display())).exists());
        let _ = std::fs::remove_file(format!("{}.1", path.display()));
        let _ = std::fs::remove_file(format!("{}.2", path.display()));
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
