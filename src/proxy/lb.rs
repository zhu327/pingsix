use std::time::Duration;

use http::Uri;
use pingora_error::Error;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::{
    health_check::{HealthCheck, HttpHealthCheck, TcpHealthCheck},
    selection::BackendSelection,
    LoadBalancer,
};
use pingora_proxy::Session;

use crate::config::{ActiveCheckType, Upstream, UpstreamHashOn, UpstreamPassHost};

pub struct LB<BS: BackendSelection> {
    // LB
    pub load_balancer: LoadBalancer<BS>,
    // health_check
}

impl Upstream {
    pub fn request_selector<'a>(&'a self, session: &'a mut Session) -> String {
        match self.hash_on {
            UpstreamHashOn::VARS => {
                if self.key.as_str().starts_with("arg_") {
                    if let Some(name) = self.key.as_str().strip_prefix("arg_") {
                        return get_query_value(session.req_header(), name)
                            .map_or("".to_string(), |q| q.to_string());
                    }
                }

                match self.key.as_str() {
                    "uri" => session.req_header().uri.path().to_string(),
                    "request_uri" => session
                        .req_header()
                        .uri
                        .path_and_query()
                        .map_or("".to_string(), |p| p.to_string()),
                    "query_string" => session
                        .req_header()
                        .uri
                        .query()
                        .map_or("".to_string(), |q| q.to_string()),
                    "remote_addr" => session
                        .client_addr()
                        .map_or("".to_string(), |s| s.to_string()),
                    "remote_port" => session
                        .client_addr()
                        .and_then(|s| s.as_inet())
                        .map_or("".to_string(), |i| i.port().to_string()),
                    "server_addr" => session
                        .server_addr()
                        .map_or("".to_string(), |s| s.to_string()),
                    _ => "".to_string(),
                }
            }
            UpstreamHashOn::HEAD => get_req_header_value(session.req_header(), self.key.as_str())
                .map_or("".to_string(), |s| s.to_string()),
            UpstreamHashOn::COOKIE => get_cookie_value(session.req_header(), self.key.as_str())
                .map_or("".to_string(), |s| s.to_string()),
        }
    }

    pub fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader) {
        if self.pass_host == UpstreamPassHost::REWRITE {
            if let Some(host) = self.upstream_host.clone() {
                upstream_request.insert_header("Host", host).unwrap();
            }
        }
    }

    pub fn to_health_check(&self) -> Option<Box<dyn HealthCheck>> {
        if let Some(check) = self.checks.clone() {
            match check.active.r#type {
                ActiveCheckType::TCP => {
                    let mut health_check = TcpHealthCheck::new();
                    health_check.peer_template.options.total_connection_timeout =
                        Some(Duration::from_secs(check.active.timeout as u64));

                    if let Some(healthy) = check.active.healthy {
                        health_check.consecutive_success = healthy.successes as usize
                    }

                    if let Some(unhealthy) = check.active.unhealthy {
                        health_check.consecutive_failure = unhealthy.tcp_failures as usize
                    }

                    return Some(health_check);
                }
                ActiveCheckType::HTTP | ActiveCheckType::HTTPS => {
                    let host = check.active.host.clone().unwrap_or_default();
                    let tls = check.active.r#type == ActiveCheckType::HTTPS;
                    let mut health_check = HttpHealthCheck::new(host.as_str(), tls);
                    health_check.peer_template.options.total_connection_timeout =
                        Some(Duration::from_secs(check.active.timeout as u64));
                    if tls {
                        health_check.peer_template.options.verify_cert =
                            check.active.https_verify_certificate;
                    };

                    if let Ok(uri) = Uri::builder()
                        .path_and_query(check.active.http_path)
                        .build()
                    {
                        health_check.req.set_uri(uri);
                    };

                    for header in check.active.req_headers.iter() {
                        let mut parts = header.splitn(2, ":");
                        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                            let key = key.trim().to_string();
                            let value = value.trim().to_string();
                            let _ = health_check.req.insert_header(key, value);
                        }
                    }

                    if let Some(port) = check.active.port {
                        health_check.port_override = Some(port as u16)
                    }

                    if let Some(healthy) = check.active.healthy {
                        health_check.consecutive_success = healthy.successes as usize;
                        if !healthy.http_statuses.is_empty() {
                            let http_statuses = healthy.http_statuses.clone();

                            health_check.validator =
                                Some(Box::new(move |header: &ResponseHeader| {
                                    if http_statuses.contains(&(header.status.as_u16() as u32)) {
                                        Ok(())
                                    } else {
                                        Err(Error::new_str("Invalid response"))
                                    }
                                }))
                        }
                    }

                    if let Some(unhealthy) = check.active.unhealthy {
                        health_check.consecutive_failure = unhealthy.http_failures as usize
                    }

                    return Some(Box::new(health_check));
                }
            }
        }
        None
    }
}

fn get_query_value<'a>(req_header: &'a RequestHeader, name: &str) -> Option<&'a str> {
    if let Some(query) = req_header.uri.query() {
        for item in query.split('&') {
            if let Some((k, v)) = item.split_once('=') {
                if k == name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

fn get_req_header_value<'a>(req_header: &'a RequestHeader, key: &str) -> Option<&'a str> {
    if let Some(value) = req_header.headers.get(key) {
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

fn get_cookie_value<'a>(req_header: &'a RequestHeader, cookie_name: &str) -> Option<&'a str> {
    if let Some(cookie_value) = get_req_header_value(req_header, "Cookie") {
        for item in cookie_value.split(';') {
            if let Some((k, v)) = item.split_once('=') {
                if k == cookie_name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}
