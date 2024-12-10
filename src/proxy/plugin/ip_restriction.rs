use std::{net::IpAddr, str::FromStr, sync::Arc};

use async_trait::async_trait;
use http::{header, HeaderName, StatusCode};
use ipnetwork::IpNetwork;
use once_cell::sync::Lazy;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::proxy::ProxyContext;

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "ip-restriction";

pub fn create_ip_restriction_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig = serde_yaml::from_value(cfg)
        .or_err_with(ReadError, || "Invalid ip restriction plugin config")?;

    Ok(Arc::new(PluginIPRestriction { config }))
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    #[serde(default)]
    whitelist: Vec<IpNetwork>,
    #[serde(default)]
    blacklist: Vec<IpNetwork>,
    #[serde(default)]
    message: Option<String>,
}

pub struct PluginIPRestriction {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginIPRestriction {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        3000
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let ip = get_client_ip(session)
            .parse::<IpAddr>()
            .or_err_with(ReadError, || "Invalid client ip")?;

        // Check if the client IP is in whitelist
        if !self.config.whitelist.is_empty()
            && self
                .config
                .whitelist
                .iter()
                .any(|network| network.contains(ip))
        {
            return Ok(false);
        }

        // Check if the client IP is in blacklist
        if self.config.blacklist.is_empty()
            || !self
                .config
                .blacklist
                .iter()
                .any(|network| network.contains(ip))
        {
            return Ok(false);
        }

        let mut header = ResponseHeader::build(StatusCode::FORBIDDEN, None)?;

        if let Some(ref msg) = self.config.message {
            header.insert_header(header::CONTENT_LENGTH, msg.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(msg.clone().into()), true)
                .await?;
        } else {
            session
                .write_response_header(Box::new(header), true)
                .await?;
        }

        Ok(true)
    }
}

static HTTP_HEADER_X_FORWARDED_FOR: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Forwarded-For").unwrap());

static HTTP_HEADER_X_REAL_IP: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Real-Ip").unwrap());

/// Get remote addr from session
fn get_remote_addr(session: &Session) -> Option<(String, u16)> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| (addr.ip().to_string(), addr.port()))
}

/// Gets client ip from X-Forwarded-For,
/// If none, get from X-Real-Ip,
/// If none, get remote addr.
fn get_client_ip(session: &Session) -> String {
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR.clone()) {
        let arr: Vec<&str> = value.to_str().unwrap_or_default().split(',').collect();
        if !arr.is_empty() {
            return arr[0].trim().to_string();
        }
    }
    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP.clone()) {
        return value.to_str().unwrap_or_default().to_string();
    }
    if let Some((addr, _)) = get_remote_addr(session) {
        return addr;
    }
    "".to_string()
}
