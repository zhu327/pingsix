use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Component, Path},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::{Bytes, BytesMut};
use log::{error, info};
use once_cell::sync::Lazy;
use pingora_core::Error;
use pingora_error::Result;
use pingora_proxy::Session;
use prometheus::{register_int_counter, IntCounter};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::ctx_keys::next_instance_ctx_key,
    utils::request,
};

pub const PLUGIN_NAME: &str = "file-logger";
const PRIORITY: i32 = 399;

/// Bounds memory use when the log disk cannot keep up with request traffic.
const LOG_QUEUE_CAPACITY: usize = 1_024;

/// Lines the writer thread still flushes after observing the closing flag
/// set by `FileLogWriter`'s `Drop`. The shutdown drain must stay bounded
/// because the last plugin handle is often released on a Tokio worker thread
/// during hot reload or shutdown: a slow or wedged log disk may stall the
/// runtime for at most this many writes, never for the whole
/// [`LOG_QUEUE_CAPACITY`] queue. Lines beyond the budget are abandoned and
/// logged at error level — the same fail-open policy as the live
/// drop-on-full queue.
const SHUTDOWN_DRAIN_BUDGET: usize = 256;

static FILE_LOG_ENTRIES_DROPPED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "pingsix_file_logger_entries_dropped_total",
        "File logger entries dropped because the bounded writer queue was full"
    )
    .expect("file-logger metric registration must succeed")
});

/// APISIX master default for the maximum body size kept for logging.
const DEFAULT_MAX_BODY_BYTES: u64 = 524_288;

fn push_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{{{:04x}}}", character as u32);
            }
            character => output.push(character),
        }
    }
}

fn redact_query(query: &str, names: &[String]) -> String {
    query
        .split('&')
        .map(|part| match part.split_once('=') {
            Some((name, _)) if names.iter().any(|candidate| candidate == name) => {
                format!("{name}=***")
            }
            _ => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Creates a file logger plugin instance with the given configuration.
pub fn create_file_logger_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginFileLogger::build(config)?))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators WITHOUT constructing the plugin. Deliberately NOT
/// [`PluginFileLogger::build`]: validation must not open (or create) the
/// configured log file, so an unwritable path passes validation and only
/// fails when the route is actually built. Pinned by
/// `plugins::builtin_phases_tests::plain_validation_does_not_touch_the_file_logger_file`.
pub fn validate_file_logger_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?;
    Ok(())
}

/// Configuration for the file logger plugin.
#[derive(Debug, Serialize, Deserialize)]
struct PluginConfig {
    /// The log format string, containing static text and variables (e.g., `$remote_addr "$request_method $uri" $status`).
    /// Supported variables include: `request_method`, `uri`, `query_string`, `http_host`, `request_time`,
    /// `http_user_agent`, `http_referer`, `remote_addr`, `remote_port`, `server_addr`, `status`,
    /// `server_protocol`, `request_id`, `body_bytes_sent`, `error`, and custom variables via `var_<name>`.
    /// Both the `$name` and `${name}` spelling are accepted.
    ///
    /// APISIX master accepts an object here, but pingsix keeps the existing
    /// custom string format extension.
    #[serde(default = "PluginConfig::default_log_format")]
    log_format: String,

    /// Query parameter names to redact from `$query_string` output.
    #[serde(default)]
    redact_query_params: Vec<String>,

    /// Log file path. When present, one JSON line per request is appended to
    /// the file instead of emitting the custom format through `log::info!`.
    path: Option<String>,

    /// APISIX master `log_format_extra` object. Parsed only to fail with a
    /// clear validation error: it cannot be merged into the pingsix custom
    /// string format.
    log_format_extra: Option<JsonValue>,

    /// Whether to log the (truncated) request body as base64.
    #[serde(default)]
    include_req_body: bool,

    /// APISIX var expression controlling request body logging. Parsed only to
    /// fail with a clear validation error (no expression engine).
    include_req_body_expr: Option<Vec<Vec<String>>>,

    /// Whether to log the (truncated) response body as base64.
    #[serde(default)]
    include_resp_body: bool,

    /// APISIX var expression controlling response body logging. Parsed only
    /// to fail with a clear validation error (no expression engine).
    include_resp_body_expr: Option<Vec<Vec<String>>>,

    /// Maximum request body bytes collected for logging.
    #[serde(default = "PluginConfig::default_max_req_body_bytes")]
    max_req_body_bytes: u64,

    /// Maximum response body bytes collected for logging.
    #[serde(default = "PluginConfig::default_max_resp_body_bytes")]
    max_resp_body_bytes: u64,

    /// APISIX var expression deciding whether the request is logged. Parsed
    /// only to fail with a clear validation error (no expression engine).
    #[serde(rename = "match", default)]
    match_rules: Option<Vec<Vec<String>>>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            log_format: Self::default_log_format(),
            redact_query_params: Vec::new(),
            path: None,
            log_format_extra: None,
            include_req_body: false,
            include_req_body_expr: None,
            include_resp_body: false,
            include_resp_body_expr: None,
            max_req_body_bytes: Self::default_max_req_body_bytes(),
            max_resp_body_bytes: Self::default_max_resp_body_bytes(),
            match_rules: None,
        }
    }
}

impl PluginConfig {
    fn default_log_format() -> String {
        "$remote_addr \"$request_method $uri\" $status".to_string()
    }

    fn default_max_req_body_bytes() -> u64 {
        DEFAULT_MAX_BODY_BYTES
    }

    fn default_max_resp_body_bytes() -> u64 {
        DEFAULT_MAX_BODY_BYTES
    }

    fn validate(&self) -> ProxyResult<()> {
        if let Some(path) = &self.path {
            validate_log_path(path)?;
        }
        if self.max_req_body_bytes < 1 {
            return Err(ProxyError::validation_error(
                "file-logger max_req_body_bytes must be at least 1",
            ));
        }
        if self.max_resp_body_bytes < 1 {
            return Err(ProxyError::validation_error(
                "file-logger max_resp_body_bytes must be at least 1",
            ));
        }
        // Behavior-bearing APISIX fields are rejected rather than silently
        // ignored: pingsix has no expression evaluator for these fields.
        if self.log_format_extra.is_some() {
            return Err(ProxyError::validation_error(
                "file-logger log_format_extra is not supported; use the pingsix log_format string",
            ));
        }
        if self.include_req_body_expr.is_some() {
            return Err(ProxyError::validation_error(
                "file-logger include_req_body_expr is not supported; use include_req_body",
            ));
        }
        if self.include_resp_body_expr.is_some() {
            return Err(ProxyError::validation_error(
                "file-logger include_resp_body_expr is not supported; use include_resp_body",
            ));
        }
        if self.match_rules.is_some() {
            return Err(ProxyError::validation_error(
                "file-logger match expressions are not supported",
            ));
        }
        Ok(())
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: Self = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid file logger plugin config", e))?;
        config.validate()?;
        Ok(config)
    }
}

/// File logger plugin implementation.
pub struct PluginFileLogger {
    log_format: LogFormat,
    redact_query_params: Vec<String>,
    writer: Option<FileLogWriter>,
    include_req_body: bool,
    include_resp_body: bool,
    max_req_body_bytes: u64,
    max_resp_body_bytes: u64,
    request_body_key: String,
    response_body_key: String,
}

impl PluginFileLogger {
    fn build(config: PluginConfig) -> ProxyResult<Self> {
        let log_format = LogFormat::new(config.log_format);

        let writer = config
            .path
            .as_deref()
            .map(open_append_log)
            .transpose()?
            .map(FileLogWriter::start)
            .transpose()?;
        let (request_body_key, response_body_key) = (
            next_instance_ctx_key("pingsix_file_logger_request_body_"),
            next_instance_ctx_key("pingsix_file_logger_response_body_"),
        );

        Ok(PluginFileLogger {
            log_format,
            redact_query_params: config.redact_query_params,
            writer,
            include_req_body: config.include_req_body,
            include_resp_body: config.include_resp_body,
            max_req_body_bytes: config.max_req_body_bytes,
            max_resp_body_bytes: config.max_resp_body_bytes,
            request_body_key,
            response_body_key,
        })
    }
}

/// Validate the configured log path without touching the filesystem.
///
/// Rejects empty paths, embedded NUL bytes, relative paths (which could write
/// into the process working directory such as `/app/config.yaml`), and `..`
/// parent-directory traversal components.
fn validate_log_path(path: &str) -> ProxyResult<()> {
    if path.is_empty() {
        return Err(ProxyError::validation_error(
            "file-logger path must not be empty",
        ));
    }
    if path.contains('\0') {
        return Err(ProxyError::validation_error(
            "file-logger path must not contain NUL bytes",
        ));
    }
    let parsed = Path::new(path);
    if !parsed.is_absolute() {
        return Err(ProxyError::validation_error(
            "file-logger path must be an absolute path",
        ));
    }
    if parsed
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ProxyError::validation_error(
            "file-logger path must not contain '..' traversal segments",
        ));
    }
    Ok(())
}

/// Opens the log file in append mode, creating it when missing.
///
/// On Unix, passes `O_NOFOLLOW` so a symlink at the target path cannot
/// redirect log writes to an unintended file.
fn open_append_log(path: &str) -> ProxyResult<File> {
    validate_log_path(path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|error| {
        ProxyError::validation_error_with_cause(
            format!("file-logger cannot open log file '{path}'"),
            error,
        )
    })
}

/// Bounded, non-blocking producer paired with one dedicated file writer.
///
/// A standard thread is intentional: plugin construction also occurs in
/// contexts where no Tokio runtime is installed. Dropping the final plugin
/// flags the worker as closing, closes the channel, and joins the worker,
/// which flushes at most [`SHUTDOWN_DRAIN_BUDGET`] further lines before
/// abandoning the rest of the queue.
struct FileLogWriter {
    sender: Option<SyncSender<Vec<u8>>>,
    worker: Option<JoinHandle<()>>,
    closing: Arc<AtomicBool>,
}

impl FileLogWriter {
    fn start(file: File) -> ProxyResult<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(LOG_QUEUE_CAPACITY);
        let closing = Arc::new(AtomicBool::new(false));
        let worker_closing = Arc::clone(&closing);
        let worker = thread::Builder::new()
            .name("pingsix-file-logger".to_string())
            .spawn(move || {
                run_writer(file, receiver, &worker_closing);
            })
            .map_err(|error| {
                ProxyError::validation_error_with_cause(
                    "file-logger cannot start log writer thread",
                    error,
                )
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            closing,
        })
    }

    fn write_line(&self, mut line: String) {
        line.push('\n');
        let Some(sender) = &self.sender else {
            return;
        };
        match sender.try_send(line.into_bytes()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                FILE_LOG_ENTRIES_DROPPED.inc();
                error!(
                    "file-logger: writer queue is full; dropping log entry (dropped total: {})",
                    FILE_LOG_ENTRIES_DROPPED.get()
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                error!("file-logger: writer thread stopped; dropping log entry");
            }
        }
    }
}

/// Body of the writer thread: drains the queue into `file` until the channel
/// disconnects, or — once `closing` is observed — until
/// [`SHUTDOWN_DRAIN_BUDGET`] further lines have been written, after which the
/// rest of the queue is abandoned. Returns the number of abandoned lines (0
/// when everything accepted was flushed).
fn run_writer<W: Write>(mut file: W, receiver: Receiver<Vec<u8>>, closing: &AtomicBool) -> usize {
    let mut closing_seen = false;
    let mut drained_after_close = 0usize;
    let mut abandoned = 0usize;
    while let Ok(line) = receiver.recv() {
        if let Err(write_error) = file.write_all(&line) {
            error!("file-logger: failed to write log entry: {write_error}");
        }
        if !closing_seen {
            closing_seen = closing.load(Ordering::Acquire);
        }
        if closing_seen {
            drained_after_close += 1;
            if drained_after_close >= SHUTDOWN_DRAIN_BUDGET {
                abandoned = std::iter::from_fn(|| receiver.try_recv().ok()).count();
                error!(
                    "file-logger: shutdown drain budget of {SHUTDOWN_DRAIN_BUDGET} lines \
                     reached; abandoning {abandoned} queued log lines"
                );
                break;
            }
        }
    }
    if let Err(flush_error) = file.flush() {
        error!("file-logger: failed to flush log file: {flush_error}");
    }
    abandoned
}

impl Drop for FileLogWriter {
    /// Bounded shutdown drain. The closing flag is set before joining so the
    /// worker flushes at most [`SHUTDOWN_DRAIN_BUDGET`] further lines and
    /// abandons the rest: a slow or wedged log disk can stall the dropping
    /// thread — often a Tokio worker during hot reload or shutdown — for at
    /// most that many writes instead of the whole [`LOG_QUEUE_CAPACITY`]
    /// queue.
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Release);
        self.sender.take();
        if self
            .worker
            .take()
            .is_some_and(|worker| worker.join().is_err())
        {
            error!("file-logger: log writer thread panicked");
        }
    }
}

#[async_trait]
impl ProxyPlugin for PluginFileLogger {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Without a writer the buffered bytes can never be emitted — the
        // legacy log_format string has no body variables — so skip buffering.
        if !self.include_req_body || self.writer.is_none() {
            return Ok(());
        }
        if let Some(chunk) = body.as_ref() {
            body_buffer(ctx, &self.request_body_key).append(chunk, self.max_req_body_bytes);
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Without a writer the buffered bytes can never be emitted — the
        // legacy log_format string has no body variables — so skip buffering.
        if !self.include_resp_body || self.writer.is_none() {
            return Ok(());
        }
        if let Some(chunk) = body.as_ref() {
            body_buffer(ctx, &self.response_body_key).append(chunk, self.max_resp_body_bytes);
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        // Build only the output form this instance can emit: path mode
        // appends one JSON line, legacy mode (no path) renders only the
        // log_format string. Body buffers exist only in path mode — the
        // body filters skip buffering without a writer.
        match &self.writer {
            None => {
                // Legacy behavior when no path is configured: emit the custom
                // pingsix log_format string through the standard logger.
                let rendered = self
                    .log_format
                    .render(session, e, ctx, &self.redact_query_params);
                info!("{rendered}");
            }
            Some(writer) => {
                let request_body = take_body_buffer(ctx, &self.request_body_key);
                let response_body = take_body_buffer(ctx, &self.response_body_key);
                let entry = render_json_entry(
                    session,
                    ctx,
                    request_body.as_ref(),
                    response_body.as_ref(),
                    self.include_req_body,
                    self.include_resp_body,
                );
                writer.write_line(entry);
            }
        }
    }
}

/// Buffered body bytes plus the truncation marker used by the body filters.
#[derive(Debug, Default)]
struct BodyBuffer {
    bytes: BytesMut,
    exceeded: bool,
}

impl BodyBuffer {
    /// Appends up to `max` total bytes, marking the buffer exceeded once a
    /// chunk would push it past the limit. The original chunk is never
    /// modified by the caller, so body flow is unaffected.
    fn append(&mut self, chunk: &[u8], max: u64) {
        if self.exceeded {
            return;
        }
        let capacity = usize::try_from(max).unwrap_or(usize::MAX);
        let remaining = capacity.saturating_sub(self.bytes.len());
        let accepted = remaining.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..accepted]);
        self.exceeded = accepted < chunk.len();
    }
}

/// Returns the mutable body buffer stored under `key`, creating it on first use.
fn body_buffer<'a>(ctx: &'a mut ProxyContext, key: &str) -> &'a mut BodyBuffer {
    if ctx.get::<BodyBuffer>(key).is_none() {
        ctx.set(key, BodyBuffer::default());
    }
    ctx.get_mut::<BodyBuffer>(key)
        .expect("body buffer was just inserted")
}

/// Takes the body buffer out of the context and removes the context entry.
fn take_body_buffer(ctx: &mut ProxyContext, key: &str) -> Option<BodyBuffer> {
    let buffer = {
        let stored = ctx.get_mut::<BodyBuffer>(key)?;
        std::mem::take(stored)
    };
    ctx.vars.as_mut()?.remove(key);
    Some(buffer)
}

/// Renders the JSON line appended to the configured log file.
///
/// This is a deliberately small pingsix JSON subset (not APISIX's full
/// log-util entry): `request_method`, `uri` (path without query string),
/// `status`, `request_id`, `latency` (integer milliseconds), and
/// `request_time` (seconds as a JSON number, three-decimal precision). When
/// enabled, `request_body` and `response_body` are included as standard
/// base64 encodings of the collected bytes, each accompanied by a
/// `<field>_truncated: true` marker when the buffer hit its configured cap,
/// so a truncated body stays distinguishable from a complete max-length
/// one. The custom pingsix `log_format` string is intentionally not embedded
/// in the JSON line; it remains the payload of the legacy `log::info!` path.
fn render_json_entry(
    session: &mut Session,
    ctx: &mut ProxyContext,
    req_body: Option<&BodyBuffer>,
    resp_body: Option<&BodyBuffer>,
    include_req_body: bool,
    include_resp_body: bool,
) -> String {
    use serde_json::{Map, Number};

    let status = session
        .response_written()
        .map(|response| response.status.as_u16())
        .unwrap_or(0);
    let latency = u64::try_from(ctx.elapsed_ms()).unwrap_or(u64::MAX);

    let mut entry: Map<String, JsonValue> = Map::new();
    entry.insert(
        "request_method".to_string(),
        JsonValue::String(session.req_header().method.as_str().to_string()),
    );
    entry.insert(
        "uri".to_string(),
        JsonValue::String(session.req_header().uri.path().to_string()),
    );
    entry.insert(
        "status".to_string(),
        JsonValue::Number(Number::from(status)),
    );
    entry.insert(
        "request_id".to_string(),
        JsonValue::String(ctx.request_id().unwrap_or("").to_string()),
    );
    entry.insert(
        "latency".to_string(),
        JsonValue::Number(Number::from(latency)),
    );
    let request_time_secs = (ctx.elapsed_ms_f64() / 1_000.0 * 1_000.0).round() / 1_000.0;
    entry.insert(
        "request_time".to_string(),
        JsonValue::Number(
            // Elapsed time is finite in practice; fail open to 0 rather than
            // dropping the whole log line.
            Number::from_f64(request_time_secs).unwrap_or_else(|| Number::from(0)),
        ),
    );
    if include_req_body {
        let encoded = req_body
            .map(|body| BASE64.encode(&body.bytes))
            .unwrap_or_default();
        entry.insert("request_body".to_string(), JsonValue::String(encoded));
        if req_body.is_some_and(|body| body.exceeded) {
            entry.insert("request_body_truncated".to_string(), JsonValue::Bool(true));
        }
    }
    if include_resp_body {
        let encoded = resp_body
            .map(|body| BASE64.encode(&body.bytes))
            .unwrap_or_default();
        entry.insert("response_body".to_string(), JsonValue::String(encoded));
        if resp_body.is_some_and(|body| body.exceeded) {
            entry.insert("response_body_truncated".to_string(), JsonValue::Bool(true));
        }
    }

    JsonValue::Object(entry).to_string()
}

/// A log format template. Parsing is deferred to render time and shared
/// with every other `$var` template in the gateway
/// ([`request::render_template`]); both `$name` and `${name}` spell a
/// variable, a bare `$` not followed by a name stays literal, and unknown
/// variables render empty. There is no escape syntax: a `\` is an ordinary
/// character, same as before.
#[derive(Debug)]
struct LogFormat {
    format: String,
}

impl LogFormat {
    fn new(format: String) -> Self {
        LogFormat { format }
    }

    /// Renders the log format into a string, replacing variables with their values.
    /// Supports built-in variables (e.g., `request_method`, `status`) and custom variables
    /// via `var_<name>` (e.g., `var_my_custom_data` from `ctx.vars`).
    /// The `error` variable is populated from the `e` parameter, which is guaranteed by
    /// `Pingora::ProxyHttp::logging` to be passed correctly.
    fn render(
        &self,
        session: &mut Session,
        e: Option<&Error>,
        ctx: &mut ProxyContext,
        redact_query_params: &[String],
    ) -> String {
        request::render_template(&self.format, request::TemplateOptions::default(), |name| {
            resolve_log_var(name, session, e, ctx, redact_query_params)
        })
    }
}

/// Log-phase resolver for [`LogFormat`]: request-derived variables plus the
/// log-phase-only ones (`status`, `body_bytes_sent`, `request_time`,
/// `server_protocol`, `error`) and `var_<name>` context values.
fn resolve_log_var(
    var: &str,
    session: &mut Session,
    e: Option<&Error>,
    ctx: &mut ProxyContext,
    redact_query_params: &[String],
) -> String {
    use std::fmt::Write;

    let mut output = String::new();

    if let Some(custom_var_name) = var.strip_prefix("var_") {
        push_escaped(&mut output, ctx.get_str(custom_var_name).unwrap_or(""));
        return output;
    }

    match var {
        "request_method" => push_escaped(&mut output, session.req_header().method.as_str()),
        "uri" => push_escaped(&mut output, session.req_header().uri.path()),
        "query_string" => {
            let query = session.req_header().uri.query().unwrap_or_default();
            if redact_query_params.is_empty() {
                push_escaped(&mut output, query);
            } else {
                push_escaped(&mut output, &redact_query(query, redact_query_params));
            }
        }
        "http_host" => push_escaped(
            &mut output,
            session.req_header().uri.host().unwrap_or_default(),
        ),
        "request_time" => {
            let _ = write!(output, "{}", ctx.elapsed_ms());
        }
        "http_user_agent" => push_escaped(
            &mut output,
            request::get_req_header_value(session.req_header(), "user-agent").unwrap_or_default(),
        ),
        "http_referer" => push_escaped(
            &mut output,
            request::get_req_header_value(session.req_header(), "referer").unwrap_or_default(),
        ),
        "remote_addr" => {
            if let Some(addr) = session.client_addr() {
                let _ = write!(output, "{addr}");
            }
        }
        "remote_port" => {
            if let Some(port) = session
                .client_addr()
                .and_then(|addr| addr.as_inet())
                .map(|addr| addr.port())
            {
                let _ = write!(output, "{port}");
            }
        }
        "server_addr" => {
            if let Some(addr) = session.server_addr() {
                let _ = write!(output, "{addr}");
            }
        }
        "status" => {
            if let Some(response) = session.response_written() {
                let _ = write!(output, "{}", response.status.as_u16());
            }
        }
        "server_protocol" => output.push_str(if session.is_http2() {
            "http/2"
        } else {
            "http/1.1"
        }),
        "request_id" => push_escaped(&mut output, ctx.request_id().unwrap_or("")),
        "body_bytes_sent" => {
            let _ = write!(output, "{}", session.body_bytes_sent());
        }
        "error" => {
            if let Some(error) = e {
                push_escaped(&mut output, &format!("{error}"));
            }
        }
        _ => {}
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::session_from_request as session_for;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::time::{SystemTime, UNIX_EPOCH};

    async fn write_ok_response(session: &mut Session) {
        session
            .write_response_header(
                Box::new(pingora_http::ResponseHeader::build(200, None).unwrap()),
                false,
            )
            .await
            .unwrap();
    }

    struct TempLogPath {
        path: PathBuf,
    }

    impl TempLogPath {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("pingsix_file_logger_test_{label}_{nanos}.log"));
            Self { path }
        }
    }

    impl Drop for TempLogPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn config_parses_apisix_fields_with_defaults() {
        let config = PluginConfig::try_from(json!({})).unwrap();
        assert_eq!(
            config.log_format,
            "$remote_addr \"$request_method $uri\" $status"
        );
        assert!(config.redact_query_params.is_empty());
        assert!(config.path.is_none());
        assert!(config.log_format_extra.is_none());
        assert!(!config.include_req_body);
        assert!(!config.include_resp_body);
        assert_eq!(config.max_req_body_bytes, 524_288);
        assert_eq!(config.max_resp_body_bytes, 524_288);
        assert!(config.include_req_body_expr.is_none());
        assert!(config.include_resp_body_expr.is_none());
        assert!(config.match_rules.is_none());

        let config = PluginConfig::try_from(json!({
            "path": "/tmp/access.log",
            "log_format": "$status",
            "include_req_body": true,
            "include_resp_body": true,
            "max_req_body_bytes": 16,
            "max_resp_body_bytes": 32,
            "redact_query_params": ["token"]
        }))
        .unwrap();
        assert_eq!(config.path.as_deref(), Some("/tmp/access.log"));
        assert_eq!(config.log_format, "$status");
        assert!(config.include_req_body);
        assert!(config.include_resp_body);
        assert_eq!(config.max_req_body_bytes, 16);
        assert_eq!(config.max_resp_body_bytes, 32);
        assert_eq!(config.redact_query_params, vec!["token".to_string()]);
    }

    #[test]
    fn behavior_bearing_apisix_expression_fields_are_rejected() {
        for invalid in [
            json!({"log_format_extra": {"source": "nginx"}}),
            json!({"include_req_body_expr": [["http_x", "==", "1"]]}),
            json!({"include_resp_body_expr": [["http_x", "==", "1"]]}),
            json!({"match": [["uri", "==", "/x"]]}),
        ] {
            let err = PluginConfig::try_from(invalid)
                .expect_err("unsupported expression fields must be rejected");
            assert!(err.to_string().contains("not supported"), "{err}");
        }
    }

    #[test]
    fn config_validation_rejects_invalid_limits_and_empty_expression_lists() {
        for invalid in [
            json!({"path": ""}),
            json!({"path": "relative.log"}),
            json!({"path": "./config.yaml"}),
            json!({"path": "/tmp/../etc/passwd"}),
            json!({"path": "/tmp/bad\0name.log"}),
            json!({"max_req_body_bytes": 0}),
            json!({"max_resp_body_bytes": 0}),
            json!({"include_req_body_expr": []}),
            json!({"include_resp_body_expr": []}),
            json!({"match": []}),
        ] {
            assert!(
                PluginConfig::try_from(invalid).is_err(),
                "invalid config must be rejected"
            );
        }

        // Unsupported APISIX expression fields must fail loudly, not parse.
        let err = PluginConfig::try_from(json!({
            "log_format_extra": {"upstream": "x"},
            "include_req_body_expr": [["arg_x", "==", "1"]],
            "include_resp_body_expr": [["arg_x", "==", "1"]],
            "match": [["uri", "==", "/x"]]
        }))
        .expect_err("unsupported fields must be rejected");
        assert!(err.to_string().contains("not supported"), "{err}");
    }

    #[tokio::test]
    async fn render_json_entry_has_apisix_style_fields_without_bodies() {
        let mut session =
            session_for("GET /api/items?token=secret HTTP/1.1\r\nHost: t\r\n\r\n").await;
        write_ok_response(&mut session).await;
        let mut ctx = ProxyContext::default();
        ctx.set_request_id("req-123".to_string());

        let rendered = render_json_entry(&mut session, &mut ctx, None, None, false, false);
        let entry: JsonValue = serde_json::from_str(&rendered).unwrap();

        assert_eq!(entry["request_method"], "GET");
        assert_eq!(entry["uri"], "/api/items");
        assert_eq!(entry["status"], 200);
        assert_eq!(entry["request_id"], "req-123");
        assert!(entry["latency"].as_u64().is_some());
        let request_time = entry["request_time"]
            .as_f64()
            .expect("request_time is a JSON number");
        assert!(request_time >= 0.0);
        assert!(entry.get("request_body").is_none());
        assert!(entry.get("response_body").is_none());
    }

    #[tokio::test]
    async fn render_json_entry_includes_base64_bodies_when_enabled() {
        let mut session = session_for("POST /upload HTTP/1.1\r\nHost: t\r\n\r\n").await;
        write_ok_response(&mut session).await;
        let mut ctx = ProxyContext::default();
        ctx.set_request_id("req-bodies".to_string());

        let rendered = render_json_entry(
            &mut session,
            &mut ctx,
            Some(&BodyBuffer {
                bytes: BytesMut::from(&b"request-body"[..]),
                exceeded: false,
            }),
            Some(&BodyBuffer {
                bytes: BytesMut::from(&b"response-body"[..]),
                exceeded: false,
            }),
            true,
            true,
        );
        let entry: JsonValue = serde_json::from_str(&rendered).unwrap();

        assert_eq!(entry["request_body"], BASE64.encode(b"request-body"));
        assert_eq!(entry["response_body"], BASE64.encode(b"response-body"));
        assert!(entry.get("request_body_truncated").is_none());
        assert!(entry.get("response_body_truncated").is_none());
    }

    #[tokio::test]
    async fn render_json_entry_marks_truncated_bodies() {
        let mut session = session_for("POST /big HTTP/1.1\r\nHost: t\r\n\r\n").await;
        write_ok_response(&mut session).await;
        let mut ctx = ProxyContext::default();

        let rendered = render_json_entry(
            &mut session,
            &mut ctx,
            Some(&BodyBuffer {
                bytes: BytesMut::from(&b"0123456789"[..]),
                exceeded: true,
            }),
            Some(&BodyBuffer {
                bytes: BytesMut::from(&b"abcdefghij"[..]),
                exceeded: true,
            }),
            true,
            true,
        );
        let entry: JsonValue = serde_json::from_str(&rendered).unwrap();

        assert_eq!(entry["request_body_truncated"], json!(true));
        assert_eq!(entry["response_body_truncated"], json!(true));
    }

    #[test]
    fn body_buffer_stops_collecting_at_capacity() {
        let mut buffer = BodyBuffer::default();
        buffer.append(b"0123456789", 4);
        assert_eq!(&buffer.bytes[..], b"0123");
        assert!(buffer.exceeded);

        // Once exceeded, later chunks are ignored entirely.
        buffer.append(b"zz", 4);
        assert_eq!(&buffer.bytes[..], b"0123");
    }

    #[test]
    fn take_body_buffer_removes_the_context_entry() {
        let mut ctx = ProxyContext::default();
        let key = "file-logger-test-request-body";
        ctx.set(
            key,
            BodyBuffer {
                bytes: BytesMut::from(&b"data"[..]),
                exceeded: false,
            },
        );

        let taken = take_body_buffer(&mut ctx, key).unwrap();
        assert_eq!(&taken.bytes[..], b"data");
        assert!(ctx.get::<BodyBuffer>(key).is_none());
    }

    #[tokio::test]
    async fn configured_path_writes_one_json_line_and_body_filters_pass_chunks_through() {
        let temp = TempLogPath::new("json_line");
        let plugin = PluginFileLogger::build(PluginConfig {
            path: Some(temp.path.to_string_lossy().into_owned()),
            include_req_body: true,
            include_resp_body: true,
            // The request body (12 bytes) exceeds its cap, so the JSON line
            // must surface truncation; the response body stays within its
            // cap, so it must not.
            max_req_body_bytes: 8,
            max_resp_body_bytes: 32,
            ..PluginConfig::default()
        })
        .unwrap();

        let mut session = session_for("GET /logged HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let mut ctx = ProxyContext::default();
        ctx.set_request_id("req-file".to_string());

        let mut request_chunk = Some(Bytes::from_static(b"request-data"));
        plugin
            .request_body_filter(&mut session, &mut request_chunk, false, &mut ctx)
            .await
            .unwrap();
        assert_eq!(request_chunk.as_deref(), Some(&b"request-data"[..]));

        let mut response_chunk = Some(Bytes::from_static(b"response-data"));
        plugin
            .response_body_filter(&mut session, &mut response_chunk, false, &mut ctx)
            .unwrap();
        assert_eq!(response_chunk.as_deref(), Some(&b"response-data"[..]));

        write_ok_response(&mut session).await;
        plugin.logging(&mut session, None, &mut ctx).await;
        assert!(ctx.get::<BodyBuffer>(&plugin.request_body_key).is_none());
        assert!(ctx.get::<BodyBuffer>(&plugin.response_body_key).is_none());

        // Dropping closes the channel and waits for accepted entries to flush.
        drop(plugin);
        let content = std::fs::read_to_string(&temp.path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 1, "one JSON line per request");
        let entry: JsonValue = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry["request_method"], "GET");
        assert_eq!(entry["uri"], "/logged");
        assert_eq!(entry["request_id"], "req-file");
        assert_eq!(entry["request_body"], BASE64.encode(b"request-"));
        assert_eq!(entry["request_body_truncated"], json!(true));
        assert_eq!(entry["response_body"], BASE64.encode(b"response-data"));
        assert!(entry.get("response_body_truncated").is_none());
    }

    #[tokio::test]
    async fn log_format_braced_and_plain_variables_are_equivalent() {
        let mut session = session_for("GET /legacy?token=secret HTTP/1.1\r\nHost: t\r\n\r\n").await;
        write_ok_response(&mut session).await;
        let mut ctx = ProxyContext::default();
        ctx.set_request_id("req-eq".to_string());

        let plain = LogFormat::new("$request_method $uri $status $request_id".to_string());
        let braced = LogFormat::new("${request_method} ${uri} ${status} ${request_id}".to_string());
        let plain_rendered = plain.render(&mut session, None, &mut ctx, &[]);
        let braced_rendered = braced.render(&mut session, None, &mut ctx, &[]);
        assert_eq!(plain_rendered, braced_rendered);
        assert_eq!(plain_rendered, "GET /legacy 200 req-eq");
    }

    #[tokio::test]
    async fn log_format_keeps_unmatched_dollars_literal_and_blanks_unknown_vars() {
        // Guards the pre-T5 rendering contract of the regex parser: a `$`
        // not followed by a name stays literal and unknown names vanish.
        let mut session = session_for("GET /x HTTP/1.1\r\nHost: t\r\n\r\n").await;
        write_ok_response(&mut session).await;
        let mut ctx = ProxyContext::default();

        let format = LogFormat::new("cost: $ x |$ |$$uri|$bogus|".to_string());
        assert_eq!(
            format.render(&mut session, None, &mut ctx, &[]),
            "cost: $ x |$ |$/x||"
        );
    }

    #[test]
    fn writer_starts_without_tokio_and_serializes_then_flushes_on_drop() {
        let temp = TempLogPath::new("sync_writer");
        let file = open_append_log(temp.path.to_str().unwrap()).unwrap();
        let writer = FileLogWriter::start(file).unwrap();
        writer.write_line("first".to_string());
        writer.write_line("second".to_string());
        drop(writer);

        assert_eq!(
            std::fs::read_to_string(&temp.path).unwrap(),
            "first\nsecond\n"
        );
    }

    #[test]
    fn full_writer_queue_drops_entry_and_increments_metric() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let writer = FileLogWriter {
            sender: Some(sender),
            worker: None,
            closing: Arc::new(AtomicBool::new(false)),
        };
        writer.write_line("queued".to_string());
        let before = FILE_LOG_ENTRIES_DROPPED.get();
        writer.write_line("dropped".to_string());
        assert_eq!(FILE_LOG_ENTRIES_DROPPED.get(), before + 1);
    }

    #[tokio::test]
    async fn path_less_configuration_keeps_legacy_logging_and_skips_body_buffering() {
        let plugin = PluginFileLogger::build(PluginConfig {
            include_req_body: true,
            include_resp_body: true,
            ..PluginConfig::default()
        })
        .unwrap();
        assert!(plugin.writer.is_none());

        let mut session = session_for("GET /legacy?token=secret HTTP/1.1\r\nHost: t\r\n\r\n").await;
        write_ok_response(&mut session).await;
        let mut ctx = ProxyContext::default();

        // Body filters must not buffer anything without a writer: the legacy
        // log_format line never includes body bytes.
        let mut request_chunk = Some(Bytes::from_static(b"request-data"));
        plugin
            .request_body_filter(&mut session, &mut request_chunk, false, &mut ctx)
            .await
            .unwrap();
        assert!(ctx.get::<BodyBuffer>(&plugin.request_body_key).is_none());

        let mut response_chunk = Some(Bytes::from_static(b"response-data"));
        plugin
            .response_body_filter(&mut session, &mut response_chunk, false, &mut ctx)
            .unwrap();
        assert!(ctx.get::<BodyBuffer>(&plugin.response_body_key).is_none());

        let rendered =
            plugin
                .log_format
                .render(&mut session, None, &mut ctx, &plugin.redact_query_params);
        assert!(rendered.contains("GET /legacy"));
        assert!(rendered.contains(" 200"));

        // Must not panic or touch a file when no path is configured.
        plugin.logging(&mut session, None, &mut ctx).await;
    }

    /// A writer whose `write` calls block until the test grants a permit, so
    /// the writer thread's progress is controlled deterministically.
    struct GatedWriter {
        permits: mpsc::Receiver<()>,
        writes: Arc<AtomicUsize>,
    }

    impl Write for GatedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.permits
                .recv()
                .expect("permit channel stays open until the worker exits");
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn run_writer_drains_a_small_queue_fully_even_after_closing() {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(LOG_QUEUE_CAPACITY);
        for index in 0..3 {
            sender.send(format!("line-{index}").into_bytes()).unwrap();
        }
        drop(sender);
        let closing = AtomicBool::new(true);

        let mut sink = Vec::new();
        let abandoned = run_writer(&mut sink, receiver, &closing);

        assert_eq!(abandoned, 0);
        assert_eq!(sink, b"line-0line-1line-2");
    }

    #[test]
    fn run_writer_abandons_the_queue_beyond_the_shutdown_drain_budget() {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(LOG_QUEUE_CAPACITY);
        for index in 0..LOG_QUEUE_CAPACITY {
            sender.send(format!("line-{index}").into_bytes()).unwrap();
        }
        let closing = Arc::new(AtomicBool::new(false));
        let (permit_sender, permits) = mpsc::channel::<()>();
        let writes = Arc::new(AtomicUsize::new(0));
        let worker_closing = Arc::clone(&closing);
        let worker_writes = Arc::clone(&writes);
        let worker = thread::spawn(move || {
            run_writer(
                GatedWriter {
                    permits,
                    writes: worker_writes,
                },
                receiver,
                &worker_closing,
            )
        });

        // Close (as Drop would), then grant exactly the budget's worth of
        // permits: the worker must flush only those lines and abandon
        // everything still queued instead of draining the full queue.
        closing.store(true, Ordering::Release);
        for _ in 0..SHUTDOWN_DRAIN_BUDGET {
            permit_sender.send(()).unwrap();
        }

        let abandoned = worker.join().expect("writer thread must not panic");
        assert_eq!(writes.load(Ordering::Relaxed), SHUTDOWN_DRAIN_BUDGET);
        assert_eq!(abandoned, LOG_QUEUE_CAPACITY - SHUTDOWN_DRAIN_BUDGET);
    }

    #[cfg(unix)]
    #[test]
    fn open_append_log_rejects_symlink_targets() {
        use std::os::unix::fs::symlink;

        let target = TempLogPath::new("symlink_target");
        std::fs::write(&target.path, b"original\n").unwrap();
        let link = TempLogPath::new("symlink_link");
        symlink(&target.path, &link.path).unwrap();

        let err = open_append_log(link.path.to_str().unwrap())
            .expect_err("symlink log path must be rejected by O_NOFOLLOW");
        assert!(err.to_string().contains("cannot open log file"), "{err}");
    }
}
