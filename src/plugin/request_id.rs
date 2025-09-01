use std::sync::Arc;

use async_trait::async_trait;

use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::{
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::request,
};

pub const PLUGIN_NAME: &str = "request-id";
const PRIORITY: i32 = 12015;

// Note: Request ID is now stored directly in ProxyContext.request_id field
/// Default header name for request ID
const DEFAULT_REQUEST_ID_HEADER: &str = "X-Request-Id";
/// UUID algorithm identifier for request ID generation
const ALGORITHM_UUID: &str = "uuid";
/// Range ID algorithm identifier for request ID generation
const ALGORITHM_RANGE_ID: &str = "range_id";
/// Default character set used for generating range-based request IDs
const DEFAULT_CHAR_SET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789";

/// Creates a Request ID plugin instance with the given configuration.
pub fn create_request_id_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginRequestID { config }))
}

/// Configuration for the Request ID plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[serde(default = "PluginConfig::default_header_name")]
    header_name: String,
    #[serde(default = "PluginConfig::default_include_in_response")]
    include_in_response: bool,
    #[serde(default = "PluginConfig::default_algorithm")]
    #[validate(custom(function = "PluginConfig::validate_algorithm"))]
    algorithm: String,
    #[serde(default)]
    range_id: RangeID,
}

impl PluginConfig {
    fn default_header_name() -> String {
        DEFAULT_REQUEST_ID_HEADER.to_string()
    }

    fn default_include_in_response() -> bool {
        true
    }

    fn default_algorithm() -> String {
        ALGORITHM_UUID.to_string()
    }

    fn validate_algorithm(algorithm: &String) -> Result<(), ValidationError> {
        if algorithm == ALGORITHM_UUID || algorithm == ALGORITHM_RANGE_ID {
            Ok(())
        } else {
            Err(ValidationError::new(
                "algorithm must be either 'uuid' or 'range_id'",
            ))
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct RangeID {
    #[serde(default = "RangeID::default_char_set")]
    char_set: String,
    #[serde(default = "RangeID::default_length")]
    length: u32,
}

impl RangeID {
    pub fn default_char_set() -> String {
        DEFAULT_CHAR_SET.to_string()
    }

    pub fn default_length() -> u32 {
        16
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid request id plugin config", e))?;

        config.validate().map_err(|e| {
            ProxyError::validation_error(format!(
                "Request ID plugin config validation failed: {e}"
            ))
        })?;

        Ok(config)
    }
}

pub struct PluginRequestID {
    config: PluginConfig,
}

impl PluginRequestID {
    fn get_request_id(&self) -> String {
        match self.config.algorithm.as_str() {
            ALGORITHM_UUID => Uuid::new_v4().to_string(),
            ALGORITHM_RANGE_ID => self.get_range_id(),
            _ => Uuid::new_v4().to_string(), // Fallback for invalid algorithm
        }
    }

    fn get_range_id(&self) -> String {
        let char_set = if self.config.range_id.char_set.is_empty() {
            DEFAULT_CHAR_SET
        } else {
            &self.config.range_id.char_set
        };
        let chars: Vec<char> = char_set.chars().collect();
        let mut rng = rand::rng();
        (0..self.config.range_id.length)
            .map(|_| *chars.choose(&mut rng).unwrap())
            .collect()
    }
}

#[async_trait]
impl ProxyPlugin for PluginRequestID {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        // Retrieve request ID from header, or generate a new one
        let value =
            match request::get_req_header_value(session.req_header(), &self.config.header_name) {
                Some(s) => s.to_string(),
                None => {
                    let request_id = self.get_request_id();
                    session
                        .req_header_mut()
                        .insert_header(self.config.header_name.clone(), &request_id)
                        .map_err(|e| {
                            ProxyError::Internal(format!("Session insert header fail: {e}"))
                        })?;
                    request_id
                }
            };

        ctx.set_request_id(value);

        Ok(false)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if self.config.include_in_response {
            if let Some(request_id) = ctx.request_id() {
                upstream_response
                    .insert_header(self.config.header_name.clone(), request_id)
                    .map_err(|e| {
                        ProxyError::Internal(format!("Upstream response insert header fail: {e}"))
                    })?;
            }
        }

        Ok(())
    }
}
