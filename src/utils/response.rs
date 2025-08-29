//! Unified response handling utilities for both Admin API and Plugin responses.
//!
//! This module provides a consistent interface for building success and error responses
//! across different parts of the application, following the DRY principle.

use bytes::Bytes;
use http::{header, HeaderValue, Response, StatusCode};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::Serialize;

/// Standard content types
pub mod content_type {
    pub const TEXT_PLAIN: &str = "text/plain";
    pub const APPLICATION_JSON: &str = "application/json";
}

/// Unified response builder for different response types
pub struct ResponseBuilder;

impl ResponseBuilder {
    /// Build a success HTTP Response for Admin API
    pub fn success_http(body: Vec<u8>, content_type: Option<&str>) -> Response<Vec<u8>> {
        let mut builder = Response::builder().status(StatusCode::OK);

        if let Some(ct) = content_type {
            match HeaderValue::from_str(ct) {
                Ok(header_value) => {
                    builder = builder.header(header::CONTENT_TYPE, header_value);
                }
                Err(e) => {
                    log::error!("Invalid content type '{}': {}", ct, e);
                }
            }
        }

        builder.body(body).unwrap_or_else(|e| {
            log::error!("Failed to build success response: {}", e);
            Self::error_http(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        })
    }

    /// Build an error HTTP Response for Admin API
    pub fn error_http(status: StatusCode, message: &str) -> Response<Vec<u8>> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, content_type::TEXT_PLAIN)
            .body(message.as_bytes().to_vec())
            .unwrap_or_else(|e| {
                log::error!("Failed to build error response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(b"Internal Server Error".to_vec())
                    .unwrap()
            })
    }

    /// Build a JSON success HTTP Response for Admin API
    pub fn success_json<T: Serialize>(data: &T) -> Response<Vec<u8>> {
        match serde_json::to_vec(data) {
            Ok(json_body) => Self::success_http(json_body, Some(content_type::APPLICATION_JSON)),
            Err(e) => {
                log::error!("Failed to serialize JSON response: {}", e);
                Self::error_http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "JSON serialization failed",
                )
            }
        }
    }

    /// Build a proxy ResponseHeader for plugins
    pub fn build_proxy_response(
        status: StatusCode,
        message: Option<&str>,
        headers: Option<&[(&str, &str)]>,
    ) -> Result<ResponseHeader> {
        let mut resp = ResponseHeader::build(status, None)?;

        if let Some(msg) = message {
            resp.insert_header(header::CONTENT_LENGTH, msg.len().to_string())?;
            resp.insert_header(header::CONTENT_TYPE, content_type::TEXT_PLAIN)?;
        }

        if let Some(hdrs) = headers {
            for (name, value) in hdrs {
                resp.insert_header(name.to_string(), value.to_string())?;
            }
        }

        Ok(resp)
    }

    /// Send a proxy error response for plugins
    pub async fn send_proxy_error(
        session: &mut Session,
        status: StatusCode,
        message: Option<&str>,
        headers: Option<&[(&str, &str)]>,
    ) -> Result<()> {
        let resp = Self::build_proxy_response(status, message, headers)?;
        session
            .write_response_header(Box::new(resp), message.is_none())
            .await?;

        if let Some(msg) = message {
            session
                .write_response_body(Some(Bytes::copy_from_slice(msg.as_bytes())), true)
                .await?;
        }

        Ok(())
    }
}

/// Common error response helpers
pub struct CommonErrors;

impl CommonErrors {
    pub fn bad_request(message: &str) -> Response<Vec<u8>> {
        ResponseBuilder::error_http(StatusCode::BAD_REQUEST, message)
    }

    pub fn forbidden(message: &str) -> Response<Vec<u8>> {
        ResponseBuilder::error_http(StatusCode::FORBIDDEN, message)
    }

    pub fn internal_server_error(message: &str) -> Response<Vec<u8>> {
        ResponseBuilder::error_http(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_response() {
        let response =
            ResponseBuilder::success_http(b"OK".to_vec(), Some(content_type::TEXT_PLAIN));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"OK");
    }

    #[test]
    fn test_error_response() {
        let response = ResponseBuilder::error_http(StatusCode::BAD_REQUEST, "Invalid input");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.body(), b"Invalid input");
    }

    #[test]
    fn test_json_response() {
        use serde_json::json;
        let data = json!({"message": "success", "code": 200});
        let response = ResponseBuilder::success_json(&data);
        assert_eq!(response.status(), StatusCode::OK);
        let expected = r#"{"code":200,"message":"success"}"#;
        assert_eq!(response.body(), expected.as_bytes());
    }

    #[test]
    fn test_common_errors() {
        let response = CommonErrors::bad_request("Missing parameter");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.body(), b"Missing parameter");
    }
}
