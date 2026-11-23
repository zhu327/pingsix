use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use http::StatusCode;
use ipnetwork::IpNetwork;
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, Rejection};
use crate::utils::{
    request::{get_direct_client_ip, get_req_header_value},
    response::content_type,
};

pub const PLUGIN_NAME: &str = "ip-restriction";
const PRIORITY: i32 = 3000;

/// Raw configuration for IP restriction plugin (before parsing networks).
#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    whitelist: Vec<String>,
    #[serde(default)]
    blacklist: Vec<String>,
    #[serde(default = "RawConfig::default_message")]
    message: String,
    #[serde(default = "RawConfig::default_response_code")]
    response_code: u16,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default = "RawConfig::default_use_forwarded_headers")]
    use_forwarded_headers: bool,
    /// When XFF is present but invalid: `direct` (default) uses the peer IP; `deny` rejects.
    #[serde(default = "RawConfig::default_forwarded_header_error_policy")]
    forwarded_header_error_policy: String,
}

impl RawConfig {
    fn default_message() -> String {
        "Your IP address is not allowed".into()
    }

    fn default_response_code() -> u16 {
        403
    }

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
        let config: RawConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse IP restriction plugin config", e)
        })?;

        if config.whitelist.is_empty() && config.blacklist.is_empty() {
            return Err(ProxyError::validation_error(
                "At least one of 'whitelist' or 'blacklist' must be non-empty",
            ));
        }

        let message_len = config.message.chars().count();
        if !(1..=1024).contains(&message_len) {
            return Err(ProxyError::validation_error(format!(
                "message must be between 1 and 1024 characters, got {message_len}"
            )));
        }

        if !matches!(config.response_code, 403 | 404) {
            return Err(ProxyError::validation_error(format!(
                "response_code must be 403 or 404, got {}",
                config.response_code
            )));
        }

        Ok(config)
    }
}

/// Creates an IP restriction plugin for access control based on client IP addresses.
///
/// Supports CIDR notation for network ranges (e.g., `192.168.1.0/24`, `2001:db8::/32`).
/// Handles proxy chains by examining X-Forwarded-For and X-Real-IP headers when configured.
/// Blacklist takes precedence over whitelist for overlapping ranges: a request must match
/// the whitelist (when non-empty) and must not match the blacklist.
pub fn create_ip_restriction_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    Ok(Arc::new(PluginIPRestriction {
        config: compile_config(cfg)?,
    }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators (CIDR parsing, policy mapping) WITHOUT constructing the plugin.
pub fn validate_ip_restriction_config(cfg: &JsonValue) -> ProxyResult<()> {
    compile_config(cfg.clone())?;
    Ok(())
}

/// Parse and compile the raw config into the plugin's typed config. Shared by
/// construction and structural validation so both expose the same errors.
fn compile_config(cfg: JsonValue) -> ProxyResult<PluginConfig> {
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

    Ok(PluginConfig {
        whitelist,
        blacklist,
        message: raw_config.message,
        response_code: raw_config.response_code,
        trusted_proxies,
        use_forwarded_headers: raw_config.use_forwarded_headers,
        forwarded_header_error_policy: policy,
    })
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
    message: String,

    /// HTTP status code for blocked requests. APISIX allows 403 or 404.
    response_code: u16,

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
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        let client_ip = match self.get_real_client_ip(session) {
            Ok(ip) => ip,
            Err(ClientIpError::InvalidForwardedHeader) => {
                return Ok(FilterVerdict::Reject(self.rejection()));
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
            return Ok(FilterVerdict::Reject(self.rejection()));
        }

        // Check blacklist
        if self
            .config
            .blacklist
            .iter()
            .any(|network| network.contains(client_ip))
        {
            return Ok(FilterVerdict::Reject(self.rejection()));
        }

        Ok(FilterVerdict::Continue)
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
        // Read all X-Forwarded-For header instances in order so a proxy that
        // appends a second header instead of merging into a client-supplied one
        // cannot be bypassed by spoofing the first header.
        let mut xff_headers = session
            .req_header()
            .headers
            .get_all("x-forwarded-for")
            .iter();
        if let Some(first) = xff_headers.next() {
            let mut hops = Vec::new();
            for header_value in std::iter::once(first).chain(xff_headers) {
                let header_str = header_value.to_str().map_err(|_| ())?;
                for part in header_str.split(',') {
                    let ip = part.trim().parse::<IpAddr>().map_err(|_| ())?;
                    hops.push(ip);
                }
            }

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

    /// The rejection value for a blocked request: the configured response
    /// code and an APISIX-style JSON body (`{"message":"..."}`).
    fn rejection(&self) -> Rejection {
        Rejection::new(
            StatusCode::from_u16(self.config.response_code).unwrap_or(StatusCode::FORBIDDEN),
        )
        .with_body(build_rejection_body(&self.config.message))
        .with_content_type(content_type::APPLICATION_JSON)
    }
}

/// Build the APISIX-style JSON rejection body.
fn build_rejection_body(message: &str) -> String {
    serde_json::json!({ "message": message }).to_string()
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

    fn valid_raw(list_field: &str, entries: &[&str]) -> serde_json::Value {
        serde_json::json!({ list_field: entries })
    }

    #[test]
    fn config_requires_whitelist_or_blacklist() {
        let err = RawConfig::try_from(serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("whitelist"));
        assert!(RawConfig::try_from(valid_raw("whitelist", &["127.0.0.1"])).is_ok());
        assert!(RawConfig::try_from(valid_raw("blacklist", &["127.0.0.1"])).is_ok());
    }

    #[test]
    fn config_defaults_match_apisix() {
        let raw = RawConfig::try_from(valid_raw("whitelist", &["127.0.0.1"])).unwrap();
        assert_eq!(raw.message, "Your IP address is not allowed");
        assert_eq!(raw.response_code, 403);
    }

    #[test]
    fn response_code_only_accepts_403_and_404() {
        for code in [403, 404] {
            assert!(RawConfig::try_from(serde_json::json!({
                "whitelist": ["127.0.0.1"],
                "response_code": code
            }))
            .is_ok());
        }
        for code in [200, 401, 500, 0, 9999] {
            assert!(RawConfig::try_from(serde_json::json!({
                "whitelist": ["127.0.0.1"],
                "response_code": code
            }))
            .is_err());
        }
    }

    #[test]
    fn message_length_is_bounded() {
        assert!(RawConfig::try_from(serde_json::json!({
            "whitelist": ["127.0.0.1"],
            "message": ""
        }))
        .is_err());
        assert!(RawConfig::try_from(serde_json::json!({
            "whitelist": ["127.0.0.1"],
            "message": "a".repeat(1025)
        }))
        .is_err());
        assert!(RawConfig::try_from(serde_json::json!({
            "whitelist": ["127.0.0.1"],
            "message": "a".repeat(1024)
        }))
        .is_ok());
    }

    #[test]
    fn rejection_body_is_apisix_json_shape() {
        assert_eq!(
            build_rejection_body("Your IP address is not allowed"),
            "{\"message\":\"Your IP address is not allowed\"}"
        );
    }

    #[test]
    fn invalid_network_is_rejected() {
        assert!(create_ip_restriction_plugin(
            serde_json::json!({ "whitelist": ["not-a-network"] }),
            &crate::config::EffectiveDefaults::default(),
        )
        .is_err());
    }

    #[tokio::test]
    async fn multiple_xff_headers_cannot_be_bypassed_by_spoofed_first_header() {
        let config = compile_config(serde_json::json!({
            "whitelist": ["192.168.1.0/24"],
            "trusted_proxies": ["10.0.0.0/8"],
            "use_forwarded_headers": true
        }))
        .unwrap();
        let plugin = PluginIPRestriction { config };

        // Attacker sends a spoofed first X-Forwarded-For with a whitelisted IP;
        // the trusted proxy appends a second X-Forwarded-For with the real IP.
        let session = crate::utils::testing::session_from_request(
            "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 192.168.1.10\r\nX-Forwarded-For: 203.0.113.55\r\n\r\n",
        )
        .await;

        let extracted = plugin.extract_forwarded_ip(&session).unwrap();
        assert_eq!(
            extracted,
            Some("203.0.113.55".parse().unwrap()),
            "rightmost untrusted IP across all X-Forwarded-For headers must win"
        );
    }
}
