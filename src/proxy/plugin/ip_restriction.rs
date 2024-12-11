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

/// Creates an IP Restriction plugin instance.
pub fn create_ip_restriction_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig = serde_yaml::from_value(cfg)
        .or_err_with(ReadError, || "Invalid IP restriction plugin config")?;
    Ok(Arc::new(PluginIPRestriction { config }))
}

/// Configuration for the IP Restriction plugin.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    /// List of allowed IP networks (whitelist).
    #[serde(default)]
    whitelist: Vec<IpNetwork>,

    /// List of denied IP networks (blacklist).
    #[serde(default)]
    blacklist: Vec<IpNetwork>,

    /// Custom rejection message.
    #[serde(default)]
    message: Option<String>,
}

/// IP Restriction Plugin implementation.
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
        let client_ip = get_client_ip(session)
            .parse::<IpAddr>()
            .or_err_with(ReadError, || "Failed to parse client IP")?;

        // Check whitelist
        if !self.config.whitelist.is_empty()
            && !self
                .config
                .whitelist
                .iter()
                .any(|network| network.contains(client_ip))
        {
            return self.reject_request(session).await;
        }

        // Check blacklist
        if self
            .config
            .blacklist
            .iter()
            .any(|network| network.contains(client_ip))
        {
            return self.reject_request(session).await;
        }

        Ok(false)
    }
}

impl PluginIPRestriction {
    /// Rejects the request with a `403 Forbidden` response.
    async fn reject_request(&self, session: &mut Session) -> Result<bool> {
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

/// Get remote address from session.
fn get_remote_addr(session: &Session) -> Option<(String, u16)> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| (addr.ip().to_string(), addr.port()))
}

/// Gets client IP from `X-Forwarded-For`, `X-Real-IP`, or remote address.
fn get_client_ip(session: &Session) -> String {
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR.clone()) {
        if let Ok(forwarded) = value.to_str() {
            if let Some(ip) = forwarded.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP.clone()) {
        if let Ok(real_ip) = value.to_str() {
            return real_ip.trim().to_string();
        }
    }

    if let Some((addr, _)) = get_remote_addr(session) {
        return addr;
    }

    "".to_string()
}
