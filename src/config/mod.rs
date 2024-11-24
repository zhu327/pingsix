use std::fs;
use std::net::SocketAddr;
use std::{collections::HashMap, fmt};

use log::{debug, trace};
use pingora::server::configuration::{Opt, ServerConf};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use validator::{Validate, ValidationError};

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Config::validate_upstreams_id"))]
pub struct Config {
    #[serde(default)]
    pub pingora: ServerConf,

    #[validate(length(min = 1))]
    #[validate(nested)]
    pub listeners: Vec<Listener>,

    #[validate(length(min = 1))]
    #[validate(nested)]
    pub routers: Vec<Router>,
    #[validate(nested)]
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[validate(nested)]
    #[serde(default)]
    pub services: Vec<Service>,
}

// Config file load and validation
impl Config {
    // Does not have to be async until we want runtime reload
    pub fn load_from_yaml<P>(path: P) -> Result<Self>
    where
        P: AsRef<std::path::Path> + std::fmt::Display,
    {
        let conf_str = fs::read_to_string(&path).or_err_with(ReadError, || {
            format!("Unable to read conf file from {path}")
        })?;
        debug!("Conf file read from {path}");
        Self::from_yaml(&conf_str)
    }

    // config file load entry point
    pub fn load_yaml_with_opt_override(opt: &Opt) -> Result<Self> {
        if let Some(path) = &opt.conf {
            let mut conf = Self::load_from_yaml(path)?;
            conf.merge_with_opt(opt);
            Ok(conf)
        } else {
            Error::e_explain(ReadError, "No path specified")
        }
    }

    pub fn from_yaml(conf_str: &str) -> Result<Self> {
        trace!("Read conf file: {conf_str}");
        let conf: Config = serde_yaml::from_str(conf_str).or_err_with(ReadError, || {
            format!("Unable to parse yaml conf {conf_str}")
        })?;

        trace!("Loaded conf: {conf:?}");

        // use validator to validate conf file
        conf.validate()
            .or_err_with(FileReadError, || "Conf file valid failed")?;

        Ok(conf)
    }

    #[allow(dead_code)]
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).unwrap()
    }

    pub fn merge_with_opt(&mut self, opt: &Opt) {
        if opt.daemon {
            self.pingora.daemon = true;
        }
    }

    fn validate_upstreams_id(&self) -> Result<(), ValidationError> {
        for upstream in &self.upstreams {
            if upstream.id.is_none() {
                return Err(ValidationError::new("upstream_id_required"));
            }
        }

        Ok(())
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tls {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct Timeout {
    pub connect: u64,
    pub send: u64,
    pub read: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Router::validate"))]
pub struct Router {
    pub id: String,

    pub uri: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    pub methods: Vec<HttpMethod>,
    pub host: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default = "Router::default_priority")]
    pub priority: u32,

    #[serde(default)]
    pub plugins: HashMap<String, YamlValue>,
    #[validate(nested)]
    pub upstream: Option<Upstream>,
    pub upstream_id: Option<String>,
    pub service_id: Option<String>,
    #[validate(nested)]
    pub timeout: Option<Timeout>,
}

impl Router {
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
        if let Some(host) = &self.host {
            vec![host.to_string()]
        } else {
            self.hosts.clone()
        }
    }

    pub fn get_uris(&self) -> Vec<String> {
        if let Some(uri) = &self.uri {
            vec![uri.to_string()]
        } else {
            self.uris.clone()
        }
    }

    fn default_priority() -> u32 {
        0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE,
    PURGE,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let method = match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::CONNECT => "CONNECT",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::PURGE => "PURGE",
        };
        write!(f, "{}", method)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Upstream::validate_upstream_host"))]
pub struct Upstream {
    pub id: Option<String>,
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
        if self.pass_host == UpstreamPassHost::REWRITE && self.upstream_host.is_none() {
            Err(ValidationError::new("upstream_host_required_for_rewrite"))
        } else {
            Ok(())
        }
    }

    // Custom validation function for `nodes` keys
    fn validate_nodes_keys(nodes: &HashMap<String, u32>) -> Result<(), ValidationError> {
        // Define the regular expression for valid keys
        let re =
            Regex::new(r"(?i)^(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::\d+)?$")
                .unwrap();

        for key in nodes.keys() {
            if !re.is_match(key) {
                let mut err = ValidationError::new("invalid_node_key");
                err.add_param("key".into(), &key.to_string());
                return Err(err);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectionType {
    #[default]
    RoundRobin,
    Random,
    Fnv,
    Ketama,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct HealthCheck {
    // only support passive check for now
    #[validate(nested)]
    pub active: ActiveCheck,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
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

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
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

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamHashOn {
    #[default]
    VARS,
    HEAD,
    COOKIE,
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamScheme {
    #[default]
    HTTP,
    HTTPS,
    GRPC,
    GRPCS,
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamPassHost {
    #[default]
    PASS,
    REWRITE,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Service::validate_upstream"))]
pub struct Service {
    pub id: String,
    #[serde(default)]
    pub plugins: HashMap<String, YamlValue>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn init_log() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn not_a_test_i_cannot_write_yaml_by_hand() {
        init_log();
        let conf = Config::default();
        // cargo test -- --nocapture not_a_test_i_cannot_write_yaml_by_hand
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

listeners:
  - address: 0.0.0.0:8080
  - address: "[::1]:8080"
    tls:
      cert_path: /etc/ssl/server.crt
      key_path: /etc/ssl/server.key
    offer_h2: true

routers:
  - id: 1
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
    id: 1
    checks:
      active:
        type: http

services:
  - id: 1
    upstream_id: 1
    hosts: ["example.com"]
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str).unwrap();
        assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
        assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
        assert_eq!(1, conf.pingora.version);
        assert_eq!(2, conf.listeners.len());
        assert_eq!(1, conf.routers.len());
        assert_eq!(1, conf.upstreams.len());
        assert_eq!(1, conf.services.len());
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

listeners:
  - address: 0.0.0.0:8080
    offer_h2c: true
  - address: "[::1]:8080"
    tls:
      cert_path: /etc/ssl/server.crt
      key_path: /etc/ssl/server.key
    offer_h2: true

routers:
  - id: 1
    uri: /
    upstream_id: 1

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    id: 1
    checks:
      active:
        type: http
  - nodes:
      "127.0.0.1:1981": 1
    id: 2
    checks:
      active:
        type: http

services:
  - id: 1
    upstream_id: 1
    hosts: ["example.com"]
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str).unwrap();
        assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
        assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
        assert_eq!(1, conf.pingora.version);
        assert_eq!(2, conf.listeners.len());
        assert_eq!(1, conf.routers.len());
        assert_eq!(2, conf.upstreams.len());
        assert_eq!(1, conf.services.len());
        print!("{}", conf.to_yaml());
    }

    #[test]
    fn test_valid_listeners_length() {
        init_log();
        let conf_str = r#"
---
listeners: []

routers:
  - id: 1
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }

    #[test]
    fn test_valid_listeners_tls_for_offer_h2() {
        init_log();
        let conf_str = r#"
---
listeners:
  - address: "[::1]:8080"
    offer_h2: true

routers:
  - id: 1
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }

    #[test]
    fn test_valid_routers_length() {
        init_log();
        let conf_str = r#"
---
listeners:
  - address: "[::1]:8080"

routers: []
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }

    #[test]
    fn test_valid_routers_uri_and_uris() {
        init_log();
        let conf_str = r#"
---
listeners:
  - address: "[::1]:8080"

routers:
  - id: 1
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }

    #[test]
    fn test_valid_routers_upstream_host() {
        init_log();
        let conf_str = r#"
---
listeners:
  - address: "[::1]:8080"

routers:
  - id: 1
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      pass_host: rewrite
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }

    #[test]
    fn test_valid_config_upstream_id() {
        init_log();
        let conf_str = r#"
---
listeners:
  - address: "[::1]:8080"

routers:
  - id: 1
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
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }

    #[test]
    fn test_valid_router_upstream() {
        init_log();
        let conf_str = r#"
---
listeners:
  - address: "[::1]:8080"

routers:
  - id: 1
    uri: /
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }

    #[test]
    fn test_valid_service_upstream() {
        init_log();
        let conf_str = r#"
---
listeners:
  - address: "[::1]:8080"

routers:
  - id: 1
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

services:
  - id: 1
    hosts: ["example.com"]
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str);
        // Check for error and print the result
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                // Print the error here
                eprintln!("Error: {:?}", e);
                assert!(true); // You can assert true because you expect an error
            }
        }
    }
}
