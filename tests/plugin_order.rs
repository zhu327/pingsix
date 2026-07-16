//! Semantic anchor for plugin execution order.
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
//! [`pingsix::service::http::run_global_then_route_request_filter`], the same
//! helper `HttpService::request_filter` uses in production.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, IO,
};
use pingora_error::Result;
use pingora_proxy::Session;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use pingsix::core::{ProxyContext, ProxyPlugin, ProxyPluginExecutor};
use pingsix::service::http::run_global_then_route_request_filter;

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

    // Global plugins must be ordered before route plugins by priority. With a
    // 1000 vs 100 split, the global short-circuit wins decisively.
    assert!(global.plugins[0].priority() > route.plugins[0].priority());

    let mut session = make_session();
    let mut ctx = ProxyContext::default();

    let short_circuited =
        run_global_then_route_request_filter(global, route, &mut session, &mut ctx)
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

    let mut session = make_session();
    let mut ctx = ProxyContext::default();

    let short_circuited =
        run_global_then_route_request_filter(global, route, &mut session, &mut ctx)
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
