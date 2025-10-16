pub mod etcd;

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
};

use http::Method;
use once_cell::sync::Lazy;
use pingora::server::configuration::{Opt, ServerConf};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{serde_as, DisplayFromStr};
use validator::{Validate, ValidationError};

// Pre-compiled regex for upstream node validation to avoid per-request compilation overhead
static NODE_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)(?::\d+)?$"
    ).expect("Invalid regex pattern for node key validation")
});

/// Enables uniform ID handling across configuration entities for validation.
pub trait Identifiable {
    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
}

macro_rules! impl_identifiable {
    ($type:ty) => {
        impl Identifiable for $type {
            fn id(&self) -> &str {
                &self.id
            }

            fn set_id(&mut self, id: String) {
                self.id = id;
            }
        }
    };
}

impl_identifiable!(Route);
impl_identifiable!(Upstream);
impl_identifiable!(Service);
impl_identifiable!(GlobalRule);
impl_identifiable!(SSL);

/// Root configuration structure combining Pingora framework config with Pingsix-specific settings.
#[serde_as]
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Config::validate_resource_id"))]
pub struct Config {
    /// Pingora framework configuration (workers, logging, etc.)
    #[serde(default)]
    pub pingora: ServerConf,

    /// Pingsix-specific configuration (listeners, etcd, plugins, etc.)
    #[validate(nested)]
    pub pingsix: Pingsix,

    // Static resource definitions - used when etcd is not configured
    #[validate(nested)]
    #[serde(default)]
    pub routes: Vec<Route>,
    #[validate(nested)]
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[validate(nested)]
    #[serde(default)]
    pub services: Vec<Service>,
    #[validate(nested)]
    #[serde(default)]
    pub global_rules: Vec<GlobalRule>,
    #[validate(nested)]
    #[serde(default)]
    pub ssls: Vec<SSL>,
}

// Configuration loading and validation methods
impl Config {
    /// Loads configuration from YAML file with comprehensive validation.
    ///
    /// Synchronous loading is intentional - configuration should be validated
    /// at startup before any async operations begin.
    pub fn load_from_yaml<P>(path: P) -> Result<Self>
    where
        P: AsRef<std::path::Path> + std::fmt::Display,
    {
        let conf_str = fs::read_to_string(&path).or_err_with(ReadError, || {
            format!("Unable to read conf file from {path}")
        })?;
        log::debug!("Conf file read from {path}");
        Self::from_yaml(&conf_str)
    }

    /// Main configuration loading entry point that combines file config with CLI overrides.
    pub fn load_yaml_with_opt_override(opt: &Opt) -> Result<Self> {
        if let Some(path) = &opt.conf {
            let mut conf = Self::load_from_yaml(path)?;
            conf.merge_with_opt(opt);
            Ok(conf)
        } else {
            Error::e_explain(ReadError, "No path specified")
        }
    }

    /// Parses YAML configuration string with comprehensive validation.
    pub fn from_yaml(conf_str: &str) -> Result<Self> {
        log::trace!("Read conf file: {conf_str}");
        let conf: Config = serde_yaml::from_str(conf_str).or_err_with(ReadError, || {
            format!("Unable to parse yaml conf {conf_str}")
        })?;

        log::trace!("Loaded conf: {conf:?}");

        // Validate configuration structure and constraints
        conf.validate()
            .or_err_with(FileReadError, || "Conf file validation failed")?;

        // Ensure all resource IDs are unique within their respective types
        Self::validate_unique_ids(&conf.routes, "route")
            .or_err_with(FileReadError, || "Route ID validation failed")?;
        Self::validate_unique_ids(&conf.upstreams, "upstream")
            .or_err_with(FileReadError, || "Upstream ID validation failed")?;
        Self::validate_unique_ids(&conf.services, "service")
            .or_err_with(FileReadError, || "Service ID validation failed")?;
        Self::validate_unique_ids(&conf.global_rules, "global_rule")
            .or_err_with(FileReadError, || "Global rule ID validation failed")?;
        Self::validate_unique_ids(&conf.ssls, "ssl")
            .or_err_with(FileReadError, || "SSL ID validation failed")?;

        Ok(conf)
    }

    /// Serializes configuration back to YAML format for debugging or export.
    #[allow(dead_code)]
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).unwrap_or_else(|e| {
            log::error!("Failed to serialize config to YAML: {e}");
            String::new()
        })
    }

    /// Applies CLI option overrides to loaded configuration.
    pub fn merge_with_opt(&mut self, opt: &Opt) {
        if opt.daemon {
            self.pingora.daemon = true;
        }
    }

    fn validate_resource_id(&self) -> Result<(), ValidationError> {
        if self.upstreams.iter().any(|upstream| upstream.id.is_empty()) {
            return Err(ValidationError::new("upstream_id_required"));
        }

        if self.routes.iter().any(|route| route.id.is_empty()) {
            return Err(ValidationError::new("route_id_required"));
        }

        if self.services.iter().any(|service| service.id.is_empty()) {
            return Err(ValidationError::new("service_id_required"));
        }

        if self.global_rules.iter().any(|rule| rule.id.is_empty()) {
            return Err(ValidationError::new("global_rule_id_required"));
        }

        if self.ssls.iter().any(|ssl| ssl.id.is_empty()) {
            return Err(ValidationError::new("ssl_id_required"));
        }

        Ok(())
    }

    fn validate_unique_ids<T: Identifiable>(items: &[T], resource_name: &str) -> Result<()> {
        let mut ids = HashSet::new();
        for item in items {
            if !ids.insert(item.id().to_string()) {
                return Error::e_explain(
                    FileReadError,
                    format!("Duplicate {} ID found: {}", resource_name, item.id()),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Validate)]
pub struct Pingsix {
    #[validate(length(min = 1))]
    #[validate(nested)]
    pub listeners: Vec<Listener>,

    #[validate(nested)]
    pub etcd: Option<Etcd>,

    #[validate(nested)]
    pub admin: Option<Admin>,

    #[validate(nested)]
    pub status: Option<Status>,

    #[validate(nested)]
    pub prometheus: Option<Prometheus>,

    #[validate(nested)]
    pub sentry: Option<Sentry>,

    #[validate(nested)]
    pub log: Option<Log>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Listener::validate_tls_for_offer_h2"))]
pub struct Listener {
    pub address: SocketAddr,
    pub tls: Option<Tls>,
    #[serde(default)]
    pub offer_h2: bool,
    #[serde(default)]
    pub offer_h2c: bool,
}

impl Listener {
    fn validate_tls_for_offer_h2(&self) -> Result<(), ValidationError> {
        if self.offer_h2 && self.tls.is_none() {
            Err(ValidationError::new("tls_required_for_h2"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct Etcd {
    #[validate(length(min = 1))]
    pub host: Vec<String>,
    pub prefix: String,
    pub timeout: Option<u32>,
    pub connect_timeout: Option<u32>,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct Admin {
    pub address: SocketAddr,
    pub api_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct Status {
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct Prometheus {
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct Sentry {
    pub dsn: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct Log {
    #[validate(length(min = 1), custom(function = "Log::validate_path"))]
    pub path: String,
}

impl Log {
    fn validate_path(path: &str) -> Result<(), ValidationError> {
        if path.contains('\0') || path.trim().is_empty() {
            return Err(ValidationError::new("Invalid log file path"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tls {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Timeout {
    pub connect: u64,
    pub send: u64,
    pub read: u64,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Route::validate"))]
pub struct Route {
    #[serde(default)]
    pub id: String,

    pub uri: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub methods: Vec<Method>,
    pub host: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default = "Route::default_priority")]
    pub priority: u32,

    #[serde(default)]
    pub plugins: HashMap<String, JsonValue>,
    #[validate(nested)]
    pub upstream: Option<Upstream>,
    pub upstream_id: Option<String>,
    pub service_id: Option<String>,
    #[validate(nested)]
    pub timeout: Option<Timeout>,
}

impl Route {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.uri.is_none() && self.uris.is_empty() {
            return Err(ValidationError::new("uri_or_uris_required"));
        }

        if self.upstream_id.is_none() && self.service_id.is_none() && self.upstream.is_none() {
            return Err(ValidationError::new("upstream_or_service_required"));
        }

        Ok(())
    }

    pub fn get_hosts(&self) -> Vec<String> {
        self.host
            .clone()
            .map_or_else(|| self.hosts.clone(), |host| vec![host.to_string()])
    }

    pub fn get_uris(&self) -> Vec<String> {
        self.uri
            .clone()
            .map_or_else(|| self.uris.clone(), |uri| vec![uri.to_string()])
    }

    fn default_priority() -> u32 {
        0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Upstream::validate_upstream_host"))]
pub struct Upstream {
    #[serde(default)]
    pub id: String,
    pub retries: Option<u32>,
    pub retry_timeout: Option<u64>,
    #[validate(nested)]
    pub timeout: Option<Timeout>,
    #[validate(length(min = 1), custom(function = "Upstream::validate_nodes_keys"))]
    pub nodes: HashMap<String, u32>,
    #[serde(default)]
    pub r#type: SelectionType,
    #[validate(nested)]
    pub checks: Option<HealthCheck>,
    #[serde(default)]
    pub hash_on: UpstreamHashOn,
    #[serde(default = "Upstream::default_key")]
    pub key: String,
    #[serde(default)]
    pub scheme: UpstreamScheme,
    #[serde(default)]
    pub pass_host: UpstreamPassHost,
    pub upstream_host: Option<String>,
}

impl Upstream {
    fn default_key() -> String {
        "uri".to_string()
    }

    fn validate_upstream_host(&self) -> Result<(), ValidationError> {
        if self.pass_host == UpstreamPassHost::REWRITE {
            self.upstream_host.as_ref().map_or_else(
                || Err(ValidationError::new("upstream_host_required_for_rewrite")),
                |_| Ok(()),
            )
        } else {
            Ok(())
        }
    }

    // Custom validation function for `nodes` keys
    fn validate_nodes_keys(nodes: &HashMap<String, u32>) -> Result<(), ValidationError> {
        for key in nodes.keys() {
            if !NODE_KEY_REGEX.is_match(key) {
                let mut err = ValidationError::new("invalid_node_key");
                err.add_param("key".into(), key);
                return Err(err);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectionType {
    #[default]
    RoundRobin,
    Random,
    Fnv,
    Ketama,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct HealthCheck {
    // only support passive check for now
    #[validate(nested)]
    pub active: ActiveCheck,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct ActiveCheck {
    #[serde(default)]
    pub r#type: ActiveCheckType,
    #[serde(default = "ActiveCheck::default_timeout")]
    pub timeout: u32,
    #[serde(default = "ActiveCheck::default_http_path")]
    pub http_path: String,
    pub host: Option<String>,
    pub port: Option<u32>,
    #[serde(default = "ActiveCheck::default_https_verify_certificate")]
    pub https_verify_certificate: bool,
    #[serde(default)]
    pub req_headers: Vec<String>,
    pub healthy: Option<Health>,
    #[validate(nested)]
    pub unhealthy: Option<Unhealthy>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActiveCheckType {
    TCP,
    #[default]
    HTTP,
    HTTPS,
}

impl ActiveCheck {
    fn default_timeout() -> u32 {
        1
    }

    fn default_http_path() -> String {
        "/".to_string()
    }

    fn default_https_verify_certificate() -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    #[serde(default = "Health::default_interval")]
    pub interval: u32,
    #[serde(default = "Health::default_http_statuses")]
    pub http_statuses: Vec<u32>,
    #[serde(default = "Health::default_successes")]
    pub successes: u32,
}

impl Health {
    fn default_interval() -> u32 {
        1
    }

    fn default_http_statuses() -> Vec<u32> {
        vec![200, 302]
    }

    fn default_successes() -> u32 {
        2
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Unhealthy {
    #[serde(default = "Unhealthy::default_http_failures")]
    pub http_failures: u32,
    #[serde(default = "Unhealthy::default_tcp_failures")]
    pub tcp_failures: u32,
}

impl Unhealthy {
    fn default_http_failures() -> u32 {
        5
    }

    fn default_tcp_failures() -> u32 {
        2
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamHashOn {
    #[default]
    VARS,
    HEAD,
    COOKIE,
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamScheme {
    #[default]
    HTTP,
    HTTPS,
    GRPC,
    GRPCS,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamPassHost {
    #[default]
    PASS,
    REWRITE,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Service::validate_upstream"))]
pub struct Service {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub plugins: HashMap<String, JsonValue>,
    pub upstream: Option<Upstream>,
    pub upstream_id: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl Service {
    fn validate_upstream(&self) -> Result<(), ValidationError> {
        if self.upstream_id.is_none() && self.upstream.is_none() {
            Err(ValidationError::new("upstream_required"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct GlobalRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub plugins: HashMap<String, JsonValue>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct SSL {
    #[serde(default)]
    pub id: String,
    pub cert: String,
    pub key: String,
    #[validate(length(min = 1))]
    pub snis: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn init_log() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_print_default_yaml() {
        init_log();
        let conf = Config::default();
        println!("{}", conf.to_yaml());
    }

    #[test]
    fn test_load_file() {
        init_log();
        let conf_str = r#"
---
pingora:
  version: 1
  client_bind_to_ipv4:
      - 1.2.3.4
      - 5.6.7.8
  client_bind_to_ipv6: []

pingsix:
  listeners:
    - address: 0.0.0.0:8080
    - address: "[::1]:8080"
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

routes:
  - id: "1"
    uri: /
    methods: [GET, POST]
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    id: "1"
    checks:
      active:
        type: http

services:
  - id: "1"
    upstream_id: "1"
    hosts: ["example.com"]
        "#;
        let conf = Config::from_yaml(conf_str).unwrap();
        assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
        assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
        assert_eq!(1, conf.pingora.version);
        assert_eq!(2, conf.pingsix.listeners.len());
        assert_eq!(1, conf.routes.len());
        assert_eq!(1, conf.upstreams.len());
        assert_eq!(1, conf.services.len());
        assert_eq!(vec![Method::GET, Method::POST], conf.routes[0].methods);
        print!("{}", conf.to_yaml());
    }

    #[test]
    fn test_load_file_upstream_id() {
        init_log();
        let conf_str = r#"
---
pingora:
  version: 1
  client_bind_to_ipv4:
      - 1.2.3.4
      - 5.6.7.8
  client_bind_to_ipv6: []

pingsix:
  listeners:
    - address: 0.0.0.0:8080
      offer_h2c: true
    - address: "[::1]:8080"
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

routes:
  - id: "1"
    uri: /
    methods: [GET]
    upstream_id: "1"

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    id: "1"
    checks:
      active:
        type: http
  - nodes:
      "127.0.0.1:1981": 1
    id: "2"
    checks:
      active:
        type: http

services:
  - id: "1"
    upstream_id: "1"
    hosts: ["example.com"]
        "#;
        let conf = Config::from_yaml(conf_str).unwrap();
        assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
        assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
        assert_eq!(1, conf.pingora.version);
        assert_eq!(2, conf.pingsix.listeners.len());
        assert_eq!(1, conf.routes.len());
        assert_eq!(2, conf.upstreams.len());
        assert_eq!(1, conf.services.len());
        assert_eq!(vec![Method::GET], conf.routes[0].methods);
        print!("{}", conf.to_yaml());
    }

    #[test]
    fn test_valid_listeners_length() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners: []

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_valid_listeners_tls_for_offer_h2() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
      offer_h2: true

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_valid_routes_uri_and_uris() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_valid_routes_upstream_host() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      pass_host: rewrite
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_valid_config_upstream_id() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    checks:
      active:
        type: http
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_valid_route_upstream() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_valid_service_upstream() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

services:
  - id: "1"
    hosts: ["example.com"]
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_duplicate_ids() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
  - id: "1"
    uri: /other
    upstream:
      nodes:
        "127.0.0.1:1981": 1

upstreams:
  - id: "1"
    nodes:
      "127.0.0.1:1980": 1
  - id: "1"
    nodes:
      "127.0.0.1:1981": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }

    #[test]
    fn test_invalid_node_key() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "-invalid.com:8080": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {:?}", e);
                assert!(true);
            }
        }
    }
}
