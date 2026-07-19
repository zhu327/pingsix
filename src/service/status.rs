use async_trait::async_trait;
use http::{Response, StatusCode};
use pingora::{
    apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service,
};
use serde::Serialize;

use crate::{
    config::Status,
    core::{constant_time_eq, status},
};

#[derive(Serialize)]
struct LiveResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// HTTP application for serving public probes and protected diagnostics.
pub struct StatusHttpApp {
    config: Status,
}

impl StatusHttpApp {
    pub fn new(cfg: &Status) -> Self {
        Self {
            config: cfg.clone(),
        }
    }

    pub fn status_http_service(cfg: &Status) -> Service<Self> {
        let app = Self::new(cfg);
        let addr = &app.config.address.to_string();
        let mut service = Service::new("Status HTTP".to_string(), app);
        service.add_tcp(addr);
        service
    }

    fn diagnostics_authorized(&self, session: &ServerSession) -> bool {
        if !self.config.diagnostics_enabled() {
            return false;
        }
        // Loopback diagnostics are intentionally local-only. A remote plaintext
        // listener requires both explicit opt-in and an API key.
        if self.config.address.ip().is_loopback() {
            return true;
        }
        let Some(expected) = self.config.diagnostics_api_key.as_deref() else {
            return false;
        };
        let supplied = session
            .get_header("x-api-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        constant_time_eq(supplied, expected)
    }
}

#[async_trait]
impl ServeHttp for StatusHttpApp {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        http_session.set_keepalive(None);
        match http_session.req_header().uri.path() {
            "/status/live" => handle_live_endpoint(),
            "/status/ready" => handle_ready_endpoint(),
            "/status/config" if self.config.diagnostics_enabled() => {
                if self.diagnostics_authorized(http_session) {
                    handle_config_endpoint()
                } else {
                    forbidden_response()
                }
            }
            _ => not_found_response(),
        }
    }
}

fn handle_live_endpoint() -> Response<Vec<u8>> {
    json_response(StatusCode::OK, &LiveResponse { status: "ok" })
}

fn handle_ready_endpoint() -> Response<Vec<u8>> {
    let (ready, reason) = status::readiness();
    let response = ReadyResponse {
        status: if ready { "ok" } else { "error" },
        reason,
    };
    json_response(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        &response,
    )
}

fn handle_config_endpoint() -> Response<Vec<u8>> {
    json_response(StatusCode::OK, &status::status_view())
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Vec<u8>> {
    let json_body = serde_json::to_vec(body).unwrap_or_else(|e| {
        log::error!("Failed to serialize status response: {e}");
        b"{}".to_vec()
    });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(json_body)
        .unwrap_or_else(|e| {
            log::error!("Failed to build status HTTP response: {e}");
            let mut resp = Response::new(b"Internal Server Error".to_vec());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

fn forbidden_response() -> Response<Vec<u8>> {
    let mut resp = Response::new(b"Forbidden".to_vec());
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp
}

fn not_found_response() -> Response<Vec<u8>> {
    let mut resp = Response::new(b"Not Found".to_vec());
    *resp.status_mut() = StatusCode::NOT_FOUND;
    resp
}
