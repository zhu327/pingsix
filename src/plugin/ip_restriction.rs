use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use http::StatusCode;
use ipnetwork::IpNetwork;
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::core::{ProxyContext, ProxyPlugin};
use crate::utils::{
    request::{get_client_ip, get_req_header_value},
    response::ResponseBuilder,
};

pub const PLUGIN_NAME: &str = "ip-restriction";
const PRIORITY: i32 = 3000;

/// Creates an IP restriction plugin for access control based on client IP addresses.
///
/// Supports CIDR notation for network ranges (e.g., `192.168.1.0/24`, `2001:db8::/32`).
/// Handles proxy chains by examining X-Forwarded-For and X-Real-IP headers when configured.
/// Whitelist takes precedence over blacklist for overlapping ranges.
pub fn create_ip_restriction_plugin(cfg: JsonValue) -> Result<Arc<dyn ProxyPlugin>> {
    #[derive(Deserialize)]
    struct RawConfig {
        #[serde(default)]
        whitelist: Vec<String>,
        #[serde(default)]
        blacklist: Vec<String>,
        message: Option<String>,
        #[serde(default)]
        trusted_proxies: Vec<String>,
        #[serde(default = "RawConfig::default_use_forwarded_headers")]
        use_forwarded_headers: bool,
    }

    impl RawConfig {
        fn default_use_forwarded_headers() -> bool {
            false
        }
    }

    let raw_config: RawConfig = serde_json::from_value(cfg)
        .or_err_with(ReadError, || "Failed to parse IP restriction plugin config")?;

    let whitelist = raw_config
        .whitelist
        .into_iter()
        .map(|s| {
            s.parse::<IpNetwork>()
                .or_err_with(ReadError, || format!("Invalid whitelist IP network: {}", s))
        })
        .collect::<Result<Vec<_>>>()?;

    let blacklist = raw_config
        .blacklist
        .into_iter()
        .map(|s| {
            s.parse::<IpNetwork>()
                .or_err_with(ReadError, || format!("Invalid blacklist IP network: {}", s))
        })
        .collect::<Result<Vec<_>>>()?;

    let trusted_proxies = raw_config
        .trusted_proxies
        .into_iter()
        .map(|s| {
            s.parse::<IpNetwork>().or_err_with(ReadError, || {
                format!("Invalid trusted proxy IP network: {}", s)
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let config = PluginConfig {
        whitelist,
        blacklist,
        message: raw_config.message,
        trusted_proxies,
        use_forwarded_headers: raw_config.use_forwarded_headers,
    };

    Ok(Arc::new(PluginIPRestriction { config }))
}

/// Configuration for IP-based access control.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    /// Allowed IP networks in CIDR notation. Empty list allows all IPs.
    #[serde(default)]
    whitelist: Vec<IpNetwork>,

    /// Denied IP networks in CIDR notation. Checked after whitelist.
    #[serde(default)]
    blacklist: Vec<IpNetwork>,

    /// Custom rejection message for blocked requests.
    message: Option<String>,

    /// Trusted proxy networks allowed to set forwarded headers.
    /// Used for proxy chain validation when use_forwarded_headers is true.
    #[serde(default)]
    trusted_proxies: Vec<IpNetwork>,

    /// Enable parsing of X-Forwarded-For and X-Real-IP headers from trusted proxies.
    /// Prevents IP spoofing by validating proxy chain.
    #[serde(default)]
    use_forwarded_headers: bool,
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
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let client_ip = self.get_real_client_ip(session)?;

        // Check whitelist first
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
    /// Get the real client IP address, considering proxy chains if configured
    fn get_real_client_ip(&self, session: &Session) -> Result<IpAddr> {
        if self.config.use_forwarded_headers {
            // Get the immediate client IP (could be a proxy)
            let immediate_client = get_client_ip(session)
                .parse::<IpAddr>()
                .or_err_with(ReadError, || "Failed to parse immediate client IP")?;

            // Check if the immediate client is a trusted proxy
            if self.is_trusted_proxy(immediate_client) {
                // Try to get the real client IP from headers
                if let Some(real_ip) = self.extract_forwarded_ip(session) {
                    return Ok(real_ip);
                }
            }

            // If not from trusted proxy or no forwarded IP found, use immediate client
            Ok(immediate_client)
        } else {
            // Use direct client IP without considering proxy headers
            get_client_ip(session)
                .parse::<IpAddr>()
                .or_err_with(ReadError, || "Failed to parse client IP")
        }
    }

    /// Check if an IP address is from a trusted proxy
    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.config
            .trusted_proxies
            .iter()
            .any(|network| network.contains(ip))
    }

    /// Extract the real client IP from forwarded headers
    fn extract_forwarded_ip(&self, session: &Session) -> Option<IpAddr> {
        // Try X-Real-IP first (usually contains single IP)
        if let Some(real_ip_header) = get_req_header_value(session.req_header(), "x-real-ip") {
            if let Ok(ip) = real_ip_header.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }

        // Try X-Forwarded-For (may contain multiple IPs)
        if let Some(forwarded_header) =
            get_req_header_value(session.req_header(), "x-forwarded-for")
        {
            // X-Forwarded-For format: client, proxy1, proxy2, ...
            // We want the first (leftmost) IP which should be the original client
            for ip_str in forwarded_header.split(',') {
                let ip_str = ip_str.trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    // Skip private/internal IPs in the chain (optional enhancement)
                    if !self.is_private_ip(ip) {
                        return Some(ip);
                    }
                }
            }
        }

        None
    }

    /// Check if an IP address is private/internal (optional filtering)
    fn is_private_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_multicast() ||
                // Check for IPv6 private ranges
                (ipv6.segments()[0] & 0xfe00) == 0xfc00 || // fc00::/7 (Unique Local)
                (ipv6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 (Link Local)
            }
        }
    }

    /// Rejects the request with a `403 Forbidden` response.
    async fn reject_request(&self, session: &mut Session) -> Result<bool> {
        ResponseBuilder::send_proxy_error(
            session,
            StatusCode::FORBIDDEN,
            self.config.message.as_deref(),
            None,
        )
        .await?;

        Ok(true)
    }
}
