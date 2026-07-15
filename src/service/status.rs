use async_trait::async_trait;
use http::{Response, StatusCode};
use pingora::{
    apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service,
};
use serde::Serialize;

use crate::{config::Status, core::status};

#[derive(Serialize)]
struct SimpleStatusResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// HTTP application for serving status/health check endpoints.
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
}

#[async_trait]
impl ServeHttp for StatusHttpApp {
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        http_session.set_keepalive(None);

        let path = http_session.req_header().uri.path();

        match path {
            "/status/live" => handle_live_endpoint(),
            "/status/ready" => handle_ready_endpoint(),
            "/status/config" => handle_config_endpoint(),
            _ => not_found_response(),
        }
    }
}

fn handle_live_endpoint() -> Response<Vec<u8>> {
    let response = SimpleStatusResponse {
        status: "ok".to_string(),
        error: None,
    };
    json_response(StatusCode::OK, &response)
}

fn handle_ready_endpoint() -> Response<Vec<u8>> {
    if status::is_ready() {
        let response = SimpleStatusResponse {
            status: "ok".to_string(),
            error: None,
        };
        json_response(StatusCode::OK, &response)
    } else {
        let view = status::status_view();
        let response = SimpleStatusResponse {
            status: "error".to_string(),
            error: Some(
                view.degraded_reason
                    .unwrap_or_else(|| "Configuration not loaded yet".to_string()),
            ),
        };
        json_response(StatusCode::SERVICE_UNAVAILABLE, &response)
    }
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
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(b"Internal Server Error".to_vec())
                .unwrap()
        })
}

fn not_found_response() -> Response<Vec<u8>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(b"Not Found".to_vec())
        .unwrap_or_else(|e| {
            log::error!("Failed to build 404 response: {e}");
            Response::new(b"Not Found".to_vec())
        })
}
