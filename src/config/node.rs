//! Upstream node configuration: address parsing, validation and wire forms.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

/// `host` / `host:port` / `[ipv6]:port`.
static HOST_PORT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:\[(.+?)\]|([^:]+))(?::(\d+))?$").expect("Invalid HOST_PORT_REGEX pattern")
});

/// Hostname / FQDN only (no port, no IP literals).
static HOST_FQDN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")
        .expect("Invalid regex pattern for node host FQDN validation")
});

fn validate_node_host(host: &str) -> Result<(), ValidationError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(ValidationError::new("invalid_host"));
    }
    let bare = if host.starts_with('[') {
        if !(host.ends_with(']') && host.len() > 2) {
            return Err(ValidationError::new("invalid_host"));
        }
        &host[1..host.len() - 1]
    } else {
        host
    };

    if bare.parse::<Ipv4Addr>().is_ok() || bare.parse::<Ipv6Addr>().is_ok() {
        return Ok(());
    }

    // Dotted-quad lookalikes (e.g. 999.999.999.999) would otherwise match the
    // FQDN regex because digit labels are valid hostnames.
    if is_ipv4_shaped(bare) {
        return Err(ValidationError::new("invalid_host"));
    }

    if HOST_FQDN_REGEX.is_match(host) {
        return Ok(());
    }

    Err(ValidationError::new("invalid_host"))
}

fn is_ipv4_shaped(s: &str) -> bool {
    let mut parts = 0;
    for part in s.split('.') {
        parts += 1;
        if parts > 4 || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    parts == 4
}

fn strip_ipv6_brackets(host: &str) -> &str {
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

/// Split `host` / `host:port` / `[ipv6]:port`. A missing port yields `0`, meaning
/// "use the upstream scheme default".
fn split_host_port(addr: &str) -> Result<(&str, u16), ValidationError> {
    let caps = HOST_PORT_REGEX
        .captures(addr)
        .ok_or_else(|| ValidationError::new("invalid_address_format"))?;
    let host = caps
        .get(1)
        .or_else(|| caps.get(2))
        .ok_or_else(|| ValidationError::new("invalid_host"))?
        .as_str();

    validate_node_host(host)?;

    let port = match caps.get(3) {
        Some(p) => p
            .as_str()
            .parse::<u16>()
            .map_err(|_| ValidationError::new("invalid_port"))?,
        None => 0,
    };

    Ok((host, port))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Node {
    #[validate(custom(function = "validate_node_host"))]
    pub host: String,
    /// `0` means "use the upstream scheme default" (80 / 443).
    #[serde(default)]
    pub port: u16,
    /// Relative load-balancing weight. `0` keeps the node in the configuration
    /// but excludes it from backend selection.
    #[serde(default = "Node::default_weight")]
    pub weight: u32,
    /// Selection priority among nodes (`i8`: -128..=127). Higher wins.
    #[serde(default)]
    pub priority: i8,
}

impl Node {
    fn default_weight() -> u32 {
        1
    }

    /// Whether this node participates in load balancing.
    pub fn is_enabled(&self) -> bool {
        self.weight > 0
    }

    /// Host without surrounding IPv6 brackets, for comparisons and sorting.
    pub fn bare_host(&self) -> &str {
        strip_ipv6_brackets(&self.host)
    }

    /// Sort / fingerprint key: `(bare_host, port)`.
    pub fn sort_key(&self) -> (&str, u16) {
        (self.bare_host(), self.port)
    }

    /// Canonical `host:port` / `[ipv6]:port` key used for lookups and display.
    ///
    /// Callers that only need to write the address somewhere should use the
    /// [`fmt::Display`] impl instead and skip the allocation.
    pub fn addr_key(&self) -> String {
        self.to_string()
    }

    /// Match a wire address (`host`, `host:port`, `[ipv6]:port`) without building
    /// an owned `addr_key` for this node.
    pub fn matches_addr(&self, addr: &str) -> bool {
        match split_host_port(addr) {
            Ok((host, port)) => self.bare_host() == host && self.port == port,
            Err(_) => false,
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.bare_host();
        if host.contains(':') {
            write!(f, "[{host}]:{}", self.port)
        } else {
            write!(f, "{host}:{}", self.port)
        }
    }
}

/// Parses the legacy address form (`host`, `host:port`, `[ipv6]:port`) into a
/// node with default weight and priority.
impl FromStr for Node {
    type Err = ValidationError;

    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        let (host, port) = split_host_port(addr)?;
        Ok(Node {
            host: host.to_string(),
            port,
            weight: Node::default_weight(),
            priority: 0,
        })
    }
}

/// Upstream node set.
///
/// Wire format accepts both the legacy map (`{"host:port": weight}`) and the
/// list (`[{host, port, weight, priority}, ...]`) forms. After
/// deserialization the canonical in-memory representation is always a list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Nodes(pub Vec<Node>);

impl Nodes {
    pub fn as_slice(&self) -> &[Node] {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Node> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Linear scan for a wire address; the node set is small by construction.
    pub fn contains_addr(&self, addr: &str) -> bool {
        self.0.iter().any(|n| n.matches_addr(addr))
    }

    pub fn push(&mut self, node: Node) {
        self.0.push(node);
    }

    #[cfg(test)]
    pub fn from_map(map: HashMap<String, u32>) -> Self {
        Self::try_from(map).unwrap_or_else(|e| panic!("invalid upstream nodes map: {e}"))
    }
}

impl TryFrom<HashMap<String, u32>> for Nodes {
    type Error = ValidationErrors;

    fn try_from(map: HashMap<String, u32>) -> Result<Self, Self::Error> {
        let mut errors = ValidationErrors::new();
        let mut nodes = Vec::with_capacity(map.len());
        for (addr, weight) in map {
            match addr.parse::<Node>() {
                Ok(node) => nodes.push(Node { weight, ..node }),
                Err(mut err) => {
                    err.add_param("key".into(), &addr);
                    errors.add("nodes", err);
                }
            }
        }

        if errors.is_empty() {
            Ok(Nodes(nodes))
        } else {
            Err(errors)
        }
    }
}

impl Validate for Nodes {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();
        if self.is_empty() {
            errors.add("nodes", ValidationError::new("nodes_empty"));
            return Err(errors);
        }

        if !self.iter().any(Node::is_enabled) {
            errors.add("nodes", ValidationError::new("nodes_all_disabled"));
        }

        // Pingora backend identity is `addr` + `weight`, so two enabled nodes on
        // the same address cannot be represented separately at runtime.
        let mut seen = HashSet::new();
        for node in self.iter().filter(|n| n.is_enabled()) {
            if !seen.insert(node.addr_key()) {
                errors.add("nodes", ValidationError::new("nodes_duplicate_address"));
                break;
            }
        }

        for node in self.as_slice() {
            errors.merge_self("nodes", node.validate());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl<'de> Deserialize<'de> for Nodes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawNodes {
            Map(HashMap<String, u32>),
            List(Vec<Node>),
        }

        match RawNodes::deserialize(deserializer)? {
            RawNodes::List(list) => Ok(Nodes(list)),
            RawNodes::Map(map) => Nodes::try_from(map).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(host: &str, port: u16, weight: u32, priority: i8) -> Node {
        Node {
            host: host.into(),
            port,
            weight,
            priority,
        }
    }

    #[test]
    fn split_host_port_parses_supported_forms() {
        let test_cases = [
            ("127.0.0.1", ("127.0.0.1", 0)),
            // IPv6 without brackets; brackets are re-added for SocketAddr / addr keys.
            ("[::1]", ("::1", 0)),
            ("example.com", ("example.com", 0)),
            ("example.com:80", ("example.com", 80)),
            ("192.168.1.1:8080", ("192.168.1.1", 8080)),
            (
                "[2001:db8:85a3::8a2e:370:7334]:8080",
                ("2001:db8:85a3::8a2e:370:7334", 8080),
            ),
        ];

        for (input, expected) in test_cases {
            let result = split_host_port(input).unwrap();
            assert_eq!(result, expected, "Failed for input: {input}");
        }

        assert!(split_host_port("").is_err());
        assert!(split_host_port("invalid:port").is_err());
        assert!(split_host_port("127.0.0.1:invalid").is_err());
    }

    #[test]
    fn node_display_formats_ipv4_and_ipv6() {
        assert_eq!(node("10.0.0.1", 80, 1, 0).addr_key(), "10.0.0.1:80");
        assert_eq!(node("::1", 8080, 1, 0).to_string(), "[::1]:8080");
        // Already-bracketed hosts must not be double-wrapped.
        assert_eq!(node("[::1]", 8080, 1, 0).to_string(), "[::1]:8080");
    }

    #[test]
    fn node_parses_from_addr_and_round_trips_through_display() {
        for addr in ["127.0.0.1:18080", "[2001:db8::1]:443", "example.com:80"] {
            let node: Node = addr.parse().unwrap();
            assert_eq!(node.to_string(), addr);
            assert_eq!(node.weight, 1);
            assert_eq!(node.priority, 0);
        }

        assert!("not a host".parse::<Node>().is_err());
    }

    #[test]
    fn nodes_deserializes_map_into_list() {
        let nodes: Nodes = serde_json::from_value(serde_json::json!({
            "127.0.0.1:18080": 1,
            "10.0.0.2:80": 2
        }))
        .unwrap();

        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains_addr("127.0.0.1:18080"));
        assert!(nodes.contains_addr("10.0.0.2:80"));
        let weights: HashMap<_, _> = nodes.iter().map(|n| (n.addr_key(), n.weight)).collect();
        assert_eq!(weights["127.0.0.1:18080"], 1);
        assert_eq!(weights["10.0.0.2:80"], 2);
    }

    #[test]
    fn nodes_deserializes_list_form() {
        let nodes: Nodes = serde_json::from_value(serde_json::json!([
            {"host": "127.0.0.1", "port": 18080, "weight": 1, "priority": 0},
            {"host": "10.0.0.2", "port": 80, "weight": 2}
        ]))
        .unwrap();

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes.as_slice()[0].host, "127.0.0.1");
        assert_eq!(nodes.as_slice()[0].port, 18080);
        assert_eq!(nodes.as_slice()[1].weight, 2);
        assert_eq!(nodes.as_slice()[1].priority, 0); // serde default
    }

    #[test]
    fn nodes_list_defaults_weight_and_omitted_port() {
        let nodes: Nodes =
            serde_json::from_value(serde_json::json!([{"host": "example.com"}])).unwrap();
        let node = &nodes.as_slice()[0];
        assert_eq!(node.port, 0);
        assert_eq!(node.weight, 1);
        assert_eq!(node.priority, 0);
    }

    #[test]
    fn nodes_serializes_as_list() {
        let nodes = Nodes::from_map(HashMap::from([("127.0.0.1:80".to_string(), 1)]));
        let value = serde_json::to_value(&nodes).unwrap();
        assert!(
            value.is_array(),
            "canonical wire output must be a list: {value}"
        );
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["host"], "127.0.0.1");
        assert_eq!(value[0]["port"], 80);
        assert_eq!(value[0]["weight"], 1);
    }

    #[test]
    fn nodes_rejects_empty_and_invalid_map_entries() {
        assert!(Nodes::default().validate().is_err());

        let bad_key = HashMap::from([("not a host".to_string(), 1)]);
        assert!(Nodes::try_from(bad_key).is_err());
    }

    #[test]
    fn nodes_push_and_contains_addr() {
        let mut nodes = Nodes::default();
        nodes.push("127.0.0.1:18080".parse().unwrap());
        nodes.push("[2001:db8::1]:443".parse().unwrap());

        assert!(nodes.contains_addr("127.0.0.1:18080"));
        assert!(nodes.contains_addr("[2001:db8::1]:443"));
        assert!(!nodes.contains_addr("10.0.0.9:80"));
        assert_eq!(nodes.len(), 2);
        assert!(nodes.validate().is_ok());
    }

    #[test]
    fn nodes_weight_zero_is_disabled_but_valid_with_enabled_peer() {
        let nodes = Nodes::from_map(HashMap::from([
            ("127.0.0.1:80".to_string(), 0),
            ("10.0.0.2:80".to_string(), 1),
        ]));
        assert!(nodes.validate().is_ok());
        assert_eq!(nodes.iter().filter(|n| n.is_enabled()).count(), 1);
        assert_eq!(nodes.iter().filter(|n| !n.is_enabled()).count(), 1);
    }

    #[test]
    fn validate_node_host_accepts_ipv4_ipv6_and_fqdn() {
        for host in [
            "127.0.0.1",
            "192.168.1.1",
            "::1",
            "[::1]",
            "2001:db8::1",
            "[2001:db8::1]",
            "localhost",
            "example.com",
            "api.example.com",
            "my-service.default.svc.cluster.local",
        ] {
            assert!(
                validate_node_host(host).is_ok(),
                "expected valid host: {host}"
            );
        }

        for host in [
            "",
            "   ",
            "not a host",
            "127.0.0.1:80",
            "999.999.999.999",
            "[::1",
            "example.com.",
            "-bad.example",
            "example..com",
        ] {
            assert!(
                validate_node_host(host).is_err(),
                "expected invalid host: {host}"
            );
        }
    }

    #[test]
    fn node_validate_rejects_invalid_host() {
        assert!(node("not a host", 80, 1, 0).validate().is_err());
        assert!(node("example.com", 80, 1, 0).validate().is_ok());
    }

    #[test]
    fn nodes_validate_rejects_all_disabled() {
        let all_disabled = Nodes(vec![node("127.0.0.1", 80, 0, 0)]);
        assert!(all_disabled.validate().is_err());
    }

    #[test]
    fn node_priority_is_i8() {
        let ok: Node = serde_json::from_value(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": -1
        }))
        .unwrap();
        assert_eq!(ok.priority, -1);

        let edges: Node = serde_json::from_value(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": 127
        }))
        .unwrap();
        assert_eq!(edges.priority, 127);

        assert!(serde_json::from_value::<Node>(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": 128
        }))
        .is_err());
        assert!(serde_json::from_value::<Node>(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "priority": -129
        }))
        .is_err());
    }

    #[test]
    fn nodes_reject_duplicate_enabled_addresses() {
        let dup = Nodes(vec![
            node("127.0.0.1", 443, 1, -1),
            node("127.0.0.1", 443, 1, 10),
        ]);
        let err = dup.validate().expect_err("duplicate host:port must fail");
        assert!(err.to_string().contains("nodes_duplicate_address"));
    }

    #[test]
    fn nodes_rejects_mixed_map_and_list_wire_forms() {
        // JSON: a bare Node object is neither a weight map (values must be u32)
        // nor a list (must be an array).
        assert!(serde_json::from_value::<Nodes>(serde_json::json!({
            "host": "127.0.0.1",
            "port": 80,
            "weight": 1
        }))
        .is_err());

        // JSON: array of weight-map entries is not a valid list of Node objects.
        assert!(serde_json::from_value::<Nodes>(serde_json::json!(["127.0.0.1:80", 1])).is_err());
    }
}
