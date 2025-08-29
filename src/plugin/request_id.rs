use std::sync::Arc;

use async_trait::async_trait;
use pingora::ErrorType::InternalError;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::{proxy::ProxyContext, utils::request};

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "request-id";
const PRIORITY: i32 = 12015;

// Constants for configuration and context keys
const DEFAULT_HEADER_NAME: &str = "X-Request-Id";
const ALGORITHM_UUID: &str = "uuid";
const ALGORITHM_RANGE_ID: &str = "range_id";
const REQUEST_ID_KEY: &str = "request-id";
const DEFAULT_CHAR_SET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789";

/// Creates a Request ID plugin instance with the given configuration.
pub fn create_request_id_plugin(cfg: JsonValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_json::from_value(cfg).or_err(ReadError, "Invalid request id plugin config")?;

    config
        .validate()
        .or_err(ReadError, "Invalid request id plugin config")?;

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
        DEFAULT_HEADER_NAME.to_string()
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
                        .or_err(InternalError, "Session insert header fail")?;
                    request_id
                }
            };

        ctx.set(REQUEST_ID_KEY, value);

        Ok(false)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if self.config.include_in_response {
            let value = ctx.get_str(REQUEST_ID_KEY).unwrap(); // Safe: inserted in request_filter

            upstream_response
                .insert_header(self.config.header_name.clone(), value)
                .or_err(InternalError, "Upstream response insert header fail")?;
        }

        Ok(())
    }
}
