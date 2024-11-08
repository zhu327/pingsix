use pingora_http::RequestHeader;
use pingora_load_balancing::{selection::BackendSelection, LoadBalancer};
use pingora_proxy::Session;

use crate::config::{Upstream, UpstreamHashOn, UpstreamPassHost};

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
