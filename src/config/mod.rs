use std::fs;
use std::net::SocketAddr;
use std::{collections::HashMap, fmt};

use log::{debug, trace};
use pingora::server::configuration::{Opt, ServerConf};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
pub struct Config {
    #[serde(default)]
    pub pingora: ServerConf,

    #[validate(length(min = 1))]
    #[validate(nested)]
    pub listeners: Vec<Listener>,

    #[validate(length(min = 1))]
    #[validate(nested)]
    pub routers: Vec<Router>,
    // TODO: implement upstreams
    // #[validate(nested)]
    // pub upstreams: Option<Vec<Upstream>>,
}

// Config file load and validation
impl Config {
    // Does not has to be async until we want runtime reload
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
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Listener::validate_tls_for_offer_h2"))]
pub struct Listener {
    pub address: SocketAddr,
    pub tls: Option<Tls>,
    #[serde(default)]
    pub offer_h2: bool,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timeout {
    pub connect: u64,
    pub send: u64,
    pub read: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Router::validate_uri_and_uris"))]
pub struct Router {
    pub id: String,

    pub uri: Option<String>,
    pub uris: Option<Vec<String>>,
    pub methods: Option<Vec<HttpMethod>>,
    pub host: Option<String>,
    pub hosts: Option<Vec<String>>,

    #[validate(nested)]
    pub upstream: Upstream,
    pub timeout: Option<Timeout>,
}

impl Router {
    fn validate_uri_and_uris(router: &Router) -> Result<(), ValidationError> {
        if router.uri.is_none() && router.uris.as_ref().map_or(true, |v| v.is_empty()) {
            Err(ValidationError::new("uri_and_uris"))
        } else {
            Ok(())
        }
    }

    pub fn get_hosts(&self) -> Option<Vec<String>> {
        if let Some(host) = &self.host {
            Some(vec![host.clone()])
        } else {
            self.hosts.clone()
        }
    }

    pub fn get_uris(&self) -> Option<Vec<String>> {
        if let Some(uri) = &self.uri {
            Some(vec![uri.clone()])
        } else {
            self.uris.clone()
        }
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
    pub timeout: Option<Timeout>,
    #[validate(length(min = 1))]
    pub nodes: HashMap<String, u32>,
    #[serde(default)]
    pub r#type: SelectionType,
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

    fn validate_upstream_host(upstream: &Upstream) -> Result<(), ValidationError> {
        if upstream.pass_host == UpstreamPassHost::REWRITE && upstream.upstream_host.is_none() {
            Err(ValidationError::new("upstream_host_required_for_rewrite"))
        } else {
            Ok(())
        }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthCheck {
    // only support passive check for now
    pub active: ActiveCheck,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[serde(default = "Vec::new")]
    pub req_headers: Vec<String>,
    pub healthy: Option<Health>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamPassHost {
    #[default]
    PASS,
    REWRITE,
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
        "#
        .to_string();
        let conf = Config::from_yaml(&conf_str).unwrap();
        assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
        assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
        assert_eq!(1, conf.pingora.version);
        assert_eq!(2, conf.listeners.len());
        assert_eq!(1, conf.routers.len());
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
}
