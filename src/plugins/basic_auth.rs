use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::{header, StatusCode};
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{constant_time_eq, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::{request, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "basic-auth";
const PRIORITY: i32 = 2520;

/// Creates a Basic Auth plugin instance.
pub fn create_basic_auth_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginBasicAuth { config }))
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[validate(length(min = 1))]
    username: String,
    #[validate(length(min = 1))]
    password: String,
    #[serde(default)]
    hide_credentials: bool,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse basic auth plugin config", e)
        })?;
        config.validate()?;
        Ok(config)
    }
}

pub struct PluginBasicAuth {
    config: PluginConfig,
}

impl PluginBasicAuth {
    /// 校验 Basic Auth 凭证
    fn validate_credentials(&self, auth_value: &str) -> bool {
        // 1. 检查前缀
        if !auth_value.to_lowercase().starts_with("basic ") {
            return false;
        }

        // 2. 解码 Base64
        let credential_part = &auth_value[6..];
        let Ok(decoded_bytes) = general_purpose::STANDARD.decode(credential_part) else {
            return false;
        };

        let Ok(decoded_str) = String::from_utf8(decoded_bytes) else {
            return false;
        };

        // 3. 分离 username:password
        let Some((user, pass)) = decoded_str.split_once(':') else {
            return false;
        };

        // 4. 使用恒定时间比较防止计时攻击
        constant_time_eq(user, &self.config.username)
            && constant_time_eq(pass, &self.config.password)
    }
}

#[async_trait]
impl ProxyPlugin for PluginBasicAuth {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let auth_header =
            request::get_req_header_value(session.req_header(), header::AUTHORIZATION.as_str());

        let is_valid = match auth_header {
            Some(val) => self.validate_credentials(val),
            None => false,
        };

        if !is_valid {
            // 返回 401 并携带标准挑战头
            ResponseBuilder::send_proxy_error(
                session,
                StatusCode::UNAUTHORIZED,
                Some("Invalid user authorization"),
                Some(&[("WWW-Authenticate", "Basic realm=\"pingsix\"")]),
            )
            .await?;
            return Ok(true);
        }

        // 隐藏凭证：从上游请求中移除 Authorization 头
        if self.config.hide_credentials {
            session
                .req_header_mut()
                .remove_header(&header::AUTHORIZATION);
        }

        Ok(false)
    }
}
