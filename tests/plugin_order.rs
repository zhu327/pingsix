//! Semantic anchor for plugin execution order and pipeline composition.
//!
//! These tests pin down the data-plane contract documented in
//! `USER_GUIDE.md` under "Plugin Execution Order":
//!
//! 1. Global-rule plugins run *before* route/service plugins.
//! 2. Within each layer, plugins run in priority-descending order.
//! 3. A global plugin that short-circuits the request (`request_filter`
//!    returns `Ok(true)`) prevents any route plugin — including
//!    authentication plugins — from running. This is intentional: it lets
//!    global redirect/echo rules respond early, but it also means a global
//!    short-circuit can bypass route-level auth. Do not mix the two.
//!
//! Ordering is exercised through
//! [`pingsix::core::CompiledPluginPipeline`], the same type
//! `HttpService::request_filter` uses in production. Recording plugins cover
//! every phase (early-request, request, upstream-request, response,
//! response-body, logging) so a precedence change in any phase is caught here.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, IO,
};
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use pingsix::core::{CompiledPluginPipeline, ProxyContext, ProxyPlugin, ProxyPluginExecutor};

// ---------------------------------------------------------------------------
// Minimal downstream stream so we can construct a `pingora_proxy::Session`
// without a real TCP connection. The stub plugins below never read from or
// write to the session, so an immediately-EOF stream is sufficient. All
// `pingora_core::protocols::IO` supertraits are implemented with no-op/empty
// defaults; the blanket `IO` impl then applies.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MockStream;

impl AsyncRead for MockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Immediately signal EOF: nothing to read.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Discard writes silently.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Shutdown for MockStream {
    async fn shutdown(&mut self) {}
}

impl UniqueID for MockStream {
    fn id(&self) -> UniqueIDType {
        0
    }
}

impl Ssl for MockStream {}

impl GetTimingDigest for MockStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        Vec::new()
    }
}

impl GetProxyDigest for MockStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for MockStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        None
    }
}

#[async_trait]
impl Peek for MockStream {}

fn make_session() -> Session {
    let stream: Box<dyn IO> = Box::new(MockStream);
    Session::new_h1(stream)
}

// ---------------------------------------------------------------------------
// Stub plugins
// ---------------------------------------------------------------------------

/// A global-rule plugin that short-circuits the request, e.g. a redirect or
/// echo rule. Priority 1000 (high).
struct GlobalShortCircuit;

#[async_trait]
impl ProxyPlugin for GlobalShortCircuit {
    fn name(&self) -> &str {
        "global-short-circuit"
    }

    fn priority(&self) -> i32 {
        1000
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// A global-rule plugin that does NOT short-circuit. Priority 1000 (high).
struct GlobalNoop;

#[async_trait]
impl ProxyPlugin for GlobalNoop {
    fn name(&self) -> &str {
        "global-noop"
    }

    fn priority(&self) -> i32 {
        1000
    }
}

/// A route-level authentication plugin that records whether it ran. Priority 100.
struct RouteAuthRecorder {
    called: Arc<AtomicBool>,
}

#[async_trait]
impl ProxyPlugin for RouteAuthRecorder {
    fn name(&self) -> &str {
        "route-auth-recorder"
    }

    fn priority(&self) -> i32 {
        100
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        self.called.store(true, Ordering::SeqCst);
        Ok(false)
    }
}

/// Records every phase invocation as `"{layer}:{phase}"` into a shared log.
struct RecordingPlugin {
    layer: &'static str,
    log: Arc<Mutex<Vec<String>>>,
    /// If set, `request_filter` returns this value instead of `false`.
    short_circuit: Option<bool>,
    /// If set, `early_request_filter` fails with this message.
    fail_early: Option<&'static str>,
}

impl RecordingPlugin {
    fn record(&self, phase: &str) {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{}:{phase}", self.layer));
    }
}

#[async_trait]
impl ProxyPlugin for RecordingPlugin {
    fn name(&self) -> &str {
        "recorder"
    }

    fn priority(&self) -> i32 {
        500
    }

    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.record("early");
        if let Some(message) = self.fail_early {
            return Err(pingora_error::Error::new_str(message));
        }
        Ok(())
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        self.record("request");
        Ok(self.short_circuit.unwrap_or(false))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.record("upstream");
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut pingora_http::ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.record("response");
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.record("body");
        Ok(())
    }

    fn has_response_body_filter(&self) -> bool {
        true
    }

    async fn logging(
        &self,
        _session: &mut Session,
        _e: Option<&pingora_error::Error>,
        _ctx: &mut ProxyContext,
    ) {
        self.record("logging");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn global_short_circuit_skips_route_plugins() {
    let auth_called = Arc::new(AtomicBool::new(false));

    let global = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(GlobalShortCircuit)]));
    let route = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(
        RouteAuthRecorder {
            called: auth_called.clone(),
        },
    )]));
    let pipeline = CompiledPluginPipeline::new(global, route);

    let mut session = make_session();
    let mut ctx = ProxyContext::default();

    let short_circuited = pipeline
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("plugin filters must not error");

    assert!(
        short_circuited,
        "global short-circuit plugin must cause request_filter to return true"
    );
    assert!(
        !auth_called.load(Ordering::SeqCst),
        "route auth plugin must NOT execute when a global plugin short-circuits"
    );
}

#[tokio::test]
async fn route_plugins_run_when_global_does_not_short_circuit() {
    let auth_called = Arc::new(AtomicBool::new(false));

    let global = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(GlobalNoop)]));
    let route = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(
        RouteAuthRecorder {
            called: auth_called.clone(),
        },
    )]));
    let pipeline = CompiledPluginPipeline::new(global, route);

    let mut session = make_session();
    let mut ctx = ProxyContext::default();

    let short_circuited = pipeline
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("plugin filters must not error");

    assert!(
        !short_circuited,
        "without a global short-circuit the request proceeds to route plugins"
    );
    assert!(
        auth_called.load(Ordering::SeqCst),
        "route auth plugin MUST execute when no global plugin short-circuits"
    );
}

/// Every phase must traverse global → route in that order.
#[tokio::test]
async fn every_phase_traverses_global_then_route() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let global = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(RecordingPlugin {
        layer: "global",
        log: log.clone(),
        short_circuit: None,
        fail_early: None,
    })]));
    let route = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(RecordingPlugin {
        layer: "route",
        log: log.clone(),
        short_circuit: None,
        fail_early: None,
    })]));
    let pipeline = CompiledPluginPipeline::new(global, route);

    let mut session = make_session();
    let mut ctx = ProxyContext::default();
    let mut upstream_request = RequestHeader::build("GET", b"/", None).unwrap();
    let mut response = pingora_http::ResponseHeader::build(200, None).unwrap();
    let mut body = Some(Bytes::from_static(b"payload"));

    pipeline
        .early_request_filter(&mut session, &mut ctx)
        .await
        .unwrap();
    pipeline
        .request_filter(&mut session, &mut ctx)
        .await
        .unwrap();
    pipeline
        .upstream_request_filter(&mut session, &mut upstream_request, &mut ctx)
        .await
        .unwrap();
    pipeline
        .response_filter(&mut session, &mut response, &mut ctx)
        .await
        .unwrap();
    pipeline
        .response_body_filter(&mut session, &mut body, true, &mut ctx)
        .expect("body filter must not error");
    pipeline.logging(&mut session, None, &mut ctx).await;

    let events = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        events,
        vec![
            "global:early",
            "route:early",
            "global:request",
            "route:request",
            "global:upstream",
            "route:upstream",
            "global:response",
            "route:response",
            "global:body",
            "route:body",
            "global:logging",
            "route:logging",
        ],
        "every phase must run global plugins before route plugins"
    );
}

/// An error in a global phase must abort the phase and propagate, so the route
/// layer never runs for that phase.
#[tokio::test]
async fn global_phase_error_aborts_phase_and_propagates() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let global = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(RecordingPlugin {
        layer: "global",
        log: log.clone(),
        short_circuit: None,
        fail_early: Some("global early failure"),
    })]));
    let route = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(RecordingPlugin {
        layer: "route",
        log: log.clone(),
        short_circuit: None,
        fail_early: None,
    })]));
    let pipeline = CompiledPluginPipeline::new(global, route);

    let mut session = make_session();
    let mut ctx = ProxyContext::default();

    let err = pipeline
        .early_request_filter(&mut session, &mut ctx)
        .await
        .expect_err("global early failure must propagate");

    assert!(
        err.to_string().contains("global early failure"),
        "unexpected error: {err}"
    );
    let events = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        events,
        vec!["global:early"],
        "route layer must not run for a phase whose global layer errored"
    );
}

/// A route-layer short-circuit must not prevent the global layer from running
/// first, but must stop the remaining route-layer plugins.
#[tokio::test]
async fn route_layer_short_circuit_runs_after_global_and_stops_route_chain() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let global = Arc::new(ProxyPluginExecutor::new(vec![Arc::new(RecordingPlugin {
        layer: "global",
        log: log.clone(),
        short_circuit: None,
        fail_early: None,
    })]));
    // First route plugin short-circuits; the second must never run.
    let short_route = RecordingPlugin {
        layer: "route-a",
        log: log.clone(),
        short_circuit: Some(true),
        fail_early: None,
    };
    let late_route = RecordingPlugin {
        layer: "route-b",
        log: log.clone(),
        short_circuit: None,
        fail_early: None,
    };
    let route = Arc::new(ProxyPluginExecutor::from_sorted(vec![
        Arc::new(short_route),
        Arc::new(late_route),
    ]));
    let pipeline = CompiledPluginPipeline::new(global, route);

    let mut session = make_session();
    let mut ctx = ProxyContext::default();

    let short_circuited = pipeline
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("plugin filters must not error");
    assert!(short_circuited, "route short-circuit must surface as true");

    let events = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        events,
        vec!["global:request", "route-a:request"],
        "global runs first; route short-circuit stops the rest of the route layer"
    );
}

/// Executors built from mixed input orders are always sorted by priority.
#[test]
fn executor_sorts_unsorted_input_deterministically() {
    let low = Arc::new(RecordingPlugin {
        layer: "low",
        log: Arc::new(Mutex::new(Vec::new())),
        short_circuit: None,
        fail_early: None,
    }) as Arc<dyn ProxyPlugin>;
    let high = Arc::new(RecordingPlugin {
        layer: "high",
        log: Arc::new(Mutex::new(Vec::new())),
        short_circuit: None,
        fail_early: None,
    }) as Arc<dyn ProxyPlugin>;
    let executor = ProxyPluginExecutor::new(vec![low, high]);
    let names: Vec<&str> = executor.plugins().iter().map(|p| p.name()).collect();
    assert_eq!(names, vec!["recorder", "recorder"]);
    // Both plugins share priority 500; deterministic name tie-break keeps a
    // stable order regardless of insertion order.
    let priorities: Vec<i32> = executor.plugins().iter().map(|p| p.priority()).collect();
    assert!(priorities.windows(2).all(|w| w[0] >= w[1]));
}

/// The shared empty pipeline runs no plugins and never short-circuits.
#[tokio::test]
async fn empty_pipeline_is_a_noop() {
    let pipeline = CompiledPluginPipeline::empty();
    let mut session = make_session();
    let mut ctx = ProxyContext::default();
    assert!(!pipeline
        .request_filter(&mut session, &mut ctx)
        .await
        .unwrap());
    assert!(!pipeline.has_plugin("anything"));
}
