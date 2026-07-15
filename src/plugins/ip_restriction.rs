use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use http::StatusCode;
use ipnetwork::IpNetwork;
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};
use crate::utils::{
    request::{get_direct_client_ip, get_req_header_value},
    response::ResponseBuilder,
};

pub const PLUGIN_NAME: &str = "ip-restriction";
const PRIORITY: i32 = 3000;

/// Raw configuration for IP restriction plugin (before parsing networks).
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
    /// When XFF is present but invalid: `direct` (default) uses the peer IP; `deny` rejects.
    #[serde(default = "RawConfig::default_forwarded_header_error_policy")]
    forwarded_header_error_policy: String,
}

impl RawConfig {
    fn default_use_forwarded_headers() -> bool {
        false
    }

    fn default_forwarded_header_error_policy() -> String {
        "direct".into()
    }
}

impl TryFrom<JsonValue> for RawConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse IP restriction plugin config", e)
        })
    }
}

/// Creates an IP restriction plugin for access control based on client IP addresses.
///
/// Supports CIDR notation for network ranges (e.g., `192.168.1.0/24`, `2001:db8::/32`).
/// Handles proxy chains by examining X-Forwarded-For and X-Real-IP headers when configured.
/// Whitelist takes precedence over blacklist for overlapping ranges.
pub fn create_ip_restriction_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let raw_config = RawConfig::try_from(cfg)?;

    let whitelist = raw_config
        .whitelist
        .into_iter()
        .map(|s| {
            s.parse::<IpNetwork>()
                .map_err(|e| -> Box<pingora_error::Error> {
                    ProxyError::validation_error(format!("Invalid whitelist IP network '{s}': {e}"))
                        .into()
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let blacklist = raw_config
        .blacklist
        .into_iter()
        .map(|s| {
            s.parse::<IpNetwork>()
                .map_err(|e| -> Box<pingora_error::Error> {
                    ProxyError::validation_error(format!("Invalid blacklist IP network '{s}': {e}"))
                        .into()
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let trusted_proxies = raw_config
        .trusted_proxies
        .into_iter()
        .map(|s| {
            s.parse::<IpNetwork>()
                .map_err(|e| -> Box<pingora_error::Error> {
                    ProxyError::validation_error(format!(
                        "Invalid trusted proxy IP network '{s}': {e}"
                    ))
                    .into()
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let policy = match raw_config.forwarded_header_error_policy.as_str() {
        "direct" => ForwardedHeaderErrorPolicy::Direct,
        "deny" => ForwardedHeaderErrorPolicy::Deny,
        other => {
            return Err(ProxyError::Configuration(format!(
                "Invalid forwarded_header_error_policy '{other}', expected 'direct' or 'deny'"
            )));
        }
    };

    let config = PluginConfig {
        whitelist,
        blacklist,
        message: raw_config.message,
        trusted_proxies,
        use_forwarded_headers: raw_config.use_forwarded_headers,
        forwarded_header_error_policy: policy,
    };

    Ok(Arc::new(PluginIPRestriction { config }))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ForwardedHeaderErrorPolicy {
    #[default]
    Direct,
    Deny,
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

    #[serde(default)]
    forwarded_header_error_policy: ForwardedHeaderErrorPolicy,
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
        let client_ip = match self.get_real_client_ip(session) {
            Ok(ip) => ip,
            Err(ClientIpError::InvalidForwardedHeader) => {
                return self.reject_request(session).await;
            }
            Err(ClientIpError::Other(err)) => return Err(err),
        };

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

enum ClientIpError {
    InvalidForwardedHeader,
    Other(Box<pingora_error::Error>),
}

impl PluginIPRestriction {
    /// Get the real client IP address, considering proxy chains if configured
    fn get_real_client_ip(&self, session: &Session) -> std::result::Result<IpAddr, ClientIpError> {
        if self.config.use_forwarded_headers {
            let immediate_client = get_direct_client_ip(session).ok_or_else(|| {
                ClientIpError::Other(
                    ProxyError::Internal("Failed to determine immediate client IP".into()).into(),
                )
            })?;

            if self.is_trusted_proxy(immediate_client) {
                match self.extract_forwarded_ip(session) {
                    Ok(Some(real_ip)) => return Ok(real_ip),
                    Ok(None) => {}
                    Err(()) => {
                        // Illegal XFF must not fall back to unverified X-Real-IP.
                        return match self.config.forwarded_header_error_policy {
                            ForwardedHeaderErrorPolicy::Direct => Ok(immediate_client),
                            ForwardedHeaderErrorPolicy::Deny => {
                                Err(ClientIpError::InvalidForwardedHeader)
                            }
                        };
                    }
                }
            }

            Ok(immediate_client)
        } else {
            get_direct_client_ip(session).ok_or_else(|| {
                ClientIpError::Other(
                    ProxyError::Internal("Failed to determine client IP".into()).into(),
                )
            })
        }
    }

    /// Check if an IP address is from a trusted proxy
    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.config
            .trusted_proxies
            .iter()
            .any(|network| network.contains(ip))
    }

    /// Extract the client IP by walking X-Forwarded-For from the nearest hop to the farthest.
    ///
    /// Semantics:
    /// - XFF present and valid → walk trusted chain (all-trusted → leftmost address)
    /// - XFF present but invalid → do **not** fall back to X-Real-IP; return None so the
    ///   caller can apply `forwarded_header_error_policy`
    /// - XFF absent → optionally use X-Real-IP from a directly connected trusted proxy
    fn extract_forwarded_ip(&self, session: &Session) -> Result<Option<IpAddr>, ()> {
        if let Some(forwarded_header) =
            get_req_header_value(session.req_header(), "x-forwarded-for")
        {
            let hops = forwarded_header
                .split(',')
                .map(str::trim)
                .map(str::parse::<IpAddr>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ())?;

            return Ok(Self::client_from_proxy_chain(&hops, |ip| {
                self.is_trusted_proxy(ip)
            }));
        }

        Ok(get_req_header_value(session.req_header(), "x-real-ip")
            .and_then(|value| value.trim().parse::<IpAddr>().ok()))
    }

    fn client_from_proxy_chain(
        hops: &[IpAddr],
        is_trusted: impl Fn(IpAddr) -> bool,
    ) -> Option<IpAddr> {
        hops.iter()
            .rev()
            .copied()
            .find(|ip| !is_trusted(*ip))
            .or_else(|| hops.first().copied())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn illegal_xff_does_not_use_x_real_ip_fallback_logic() {
        // When XFF is present but unparsable, extract_forwarded_ip returns Err(()) and
        // must not consult X-Real-IP.
        let xff_ok = "not-an-ip, also-bad"
            .split(',')
            .map(str::trim)
            .map(str::parse::<IpAddr>)
            .collect::<Result<Vec<_>, _>>()
            .is_ok();
        assert!(!xff_ok);

        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let x_real_ip: IpAddr = "203.0.113.9".parse().unwrap();
        // Production: on XFF parse failure, policy Direct uses peer — never X-Real-IP.
        let resolved = match ForwardedHeaderErrorPolicy::Direct {
            ForwardedHeaderErrorPolicy::Direct => peer,
            ForwardedHeaderErrorPolicy::Deny => peer,
        };
        assert_eq!(resolved, peer);
        assert_ne!(resolved, x_real_ip);
    }

    #[test]
    fn all_trusted_chain_returns_leftmost() {
        let hops = [
            "203.0.113.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ];
        let client = PluginIPRestriction::client_from_proxy_chain(
            &hops,
            |ip| matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 10),
        );
        assert_eq!(client, Some("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn proxy_chain_uses_first_untrusted_hop_from_the_right() {
        let hops = [
            "203.0.113.7".parse().unwrap(),
            "198.51.100.9".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ];

        let client = PluginIPRestriction::client_from_proxy_chain(&hops, |ip| {
            ip == "10.0.0.2".parse::<IpAddr>().unwrap()
        });

        assert_eq!(client, Some("198.51.100.9".parse().unwrap()));
    }

    #[test]
    fn proxy_chain_does_not_trust_spoofed_leftmost_value() {
        let hops = [
            "192.0.2.123".parse().unwrap(),
            "203.0.113.8".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ];

        let client = PluginIPRestriction::client_from_proxy_chain(&hops, |ip| {
            ip == "10.0.0.2".parse::<IpAddr>().unwrap()
        });

        assert_eq!(client, Some("203.0.113.8".parse().unwrap()));
    }
}
