use std::{
    sync::Arc,
    time::{self, Duration},
};

use http::Uri;
use pingora::services::background::background_service;
use pingora_core::services::Service;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Error;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::{
    health_check::{HealthCheck as HealthCheckTrait, HttpHealthCheck, TcpHealthCheck},
    selection::{
        consistent::KetamaHashing, BackendIter, BackendSelection, FVNHash, Random, RoundRobin,
    },
    Backend, Backends, LoadBalancer,
};
use pingora_proxy::Session;

use crate::config::{
    ActiveCheckType, HealthCheck, SelectionType, Timeout, Upstream, UpstreamHashOn,
    UpstreamPassHost,
};

use super::discovery::HybridDiscovery;

pub struct ProxyLB {
    upstream: Upstream,
    lb: SelectionLB,
    // TODO: add support retry
}

impl From<Upstream> for ProxyLB {
    fn from(value: Upstream) -> Self {
        ProxyLB {
            upstream: value.clone(),
            lb: SelectionLB::from(value),
        }
    }
}

impl ProxyLB {
    pub fn select_backend<'a>(&'a self, session: &'a mut Session) -> Option<Backend> {
        let key = self.request_selector_key(session);
        log::debug!("proxy lb key: {}", &key);

        let mut backend = match &self.lb {
            SelectionLB::RoundRobin(lb) => lb.upstreams.select(key.as_bytes(), 256),
            SelectionLB::Random(lb) => lb.upstreams.select(key.as_bytes(), 256),
            SelectionLB::Fnv(lb) => lb.upstreams.select(key.as_bytes(), 256),
            SelectionLB::Ketama(lb) => lb.upstreams.select(key.as_bytes(), 256),
        };

        if let Some(ref mut b) = backend {
            if let Some(p) = b.ext.get_mut::<HttpPeer>() {
                // set timeout from upstream
                self.set_timeout(p);
            };
        }

        backend
    }

    pub fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader) {
        if self.upstream.pass_host == UpstreamPassHost::REWRITE {
            if let Some(host) = self.upstream.upstream_host.clone() {
                upstream_request.insert_header("Host", host).unwrap();
            }
        }
    }

    pub fn take_background_service(&mut self) -> Option<Box<dyn Service + 'static>> {
        match self.lb {
            SelectionLB::RoundRobin(ref mut lb) => lb.service.take(),
            SelectionLB::Random(ref mut lb) => lb.service.take(),
            SelectionLB::Fnv(ref mut lb) => lb.service.take(),
            SelectionLB::Ketama(ref mut lb) => lb.service.take(),
        }
    }

    fn set_timeout(&self, p: &mut HttpPeer) {
        if let Some(Timeout {
            connect,
            read,
            send,
        }) = self.upstream.timeout.clone()
        {
            p.options.connection_timeout = connect.map(time::Duration::from_secs);
            p.options.read_timeout = read.map(time::Duration::from_secs);
            p.options.write_timeout = send.map(time::Duration::from_secs);
        }
    }

    fn request_selector_key<'a>(&'a self, session: &'a mut Session) -> String {
        match self.upstream.hash_on {
            UpstreamHashOn::VARS => self.handle_vars(session),
            UpstreamHashOn::HEAD => {
                get_req_header_value(session.req_header(), self.upstream.key.as_str())
                    .unwrap_or_default()
                    .to_string()
            }
            UpstreamHashOn::COOKIE => {
                get_cookie_value(session.req_header(), self.upstream.key.as_str())
                    .unwrap_or_default()
                    .to_string()
            }
        }
    }

    fn handle_vars<'a>(&'a self, session: &'a mut Session) -> String {
        if self.upstream.key.as_str().starts_with("arg_") {
            if let Some(name) = self.upstream.key.as_str().strip_prefix("arg_") {
                return get_query_value(session.req_header(), name)
                    .unwrap_or_default()
                    .to_string();
            }
        }

        match self.upstream.key.as_str() {
            "uri" => session.req_header().uri.path().to_string(),
            "request_uri" => session
                .req_header()
                .uri
                .path_and_query()
                .map_or_else(|| "".to_string(), |pq| pq.to_string()),
            "query_string" => session
                .req_header()
                .uri
                .query()
                .unwrap_or_default()
                .to_string(),
            "remote_addr" => session
                .client_addr()
                .map_or_else(|| "".to_string(), |addr| addr.to_string()),
            "remote_port" => session
                .client_addr()
                .and_then(|s| s.as_inet())
                .map_or_else(|| "".to_string(), |i| i.port().to_string()),
            "server_addr" => session
                .server_addr()
                .map_or_else(|| "".to_string(), |addr| addr.to_string()),
            _ => "".to_string(),
        }
    }
}

enum SelectionLB {
    RoundRobin(LB<RoundRobin>),
    Random(LB<Random>),
    Fnv(LB<FVNHash>),
    Ketama(LB<KetamaHashing>),
}

impl From<Upstream> for SelectionLB {
    fn from(value: Upstream) -> Self {
        match value.r#type {
            SelectionType::RoundRobin => SelectionLB::RoundRobin(LB::from(value)),
            SelectionType::Random => SelectionLB::Random(LB::from(value)),
            SelectionType::Fnv => SelectionLB::Fnv(LB::from(value)),
            SelectionType::Ketama => SelectionLB::Ketama(LB::from(value)),
        }
    }
}

struct LB<BS: BackendSelection> {
    upstreams: Arc<LoadBalancer<BS>>,
    service: Option<Box<dyn Service + 'static>>,
}

impl<BS> From<Upstream> for LB<BS>
where
    BS: BackendSelection + Send + Sync + 'static,
    BS::Iter: BackendIter,
{
    fn from(upstream: Upstream) -> Self {
        let discovery: HybridDiscovery = upstream.clone().into();
        let mut upstreams = LoadBalancer::<BS>::from_backends(Backends::new(Box::new(discovery)));

        if let Some(check) = upstream.checks.clone() {
            let health_check: Box<(dyn HealthCheckTrait + Send + Sync + 'static)> =
                check.clone().into();
            upstreams.set_health_check(health_check);

            let mut health_check_frequency = Duration::from_secs(1);
            if let Some(healthy) = check.active.healthy {
                health_check_frequency = Duration::from_secs(healthy.interval as u64);
            }
            upstreams.health_check_frequency = Some(health_check_frequency);
        }

        let background = background_service("health check", upstreams);
        let upstreams = background.task();

        LB {
            upstreams,
            service: Some(Box::new(background)),
        }
    }
}

impl From<HealthCheck> for Box<(dyn HealthCheckTrait + Send + Sync + 'static)> {
    fn from(value: HealthCheck) -> Self {
        match value.active.r#type {
            ActiveCheckType::TCP => {
                let health_check: Box<TcpHealthCheck> = value.into();
                health_check
            }
            ActiveCheckType::HTTP | ActiveCheckType::HTTPS => {
                let health_check: Box<HttpHealthCheck> = value.into();
                health_check
            }
        }
    }
}

impl From<HealthCheck> for Box<TcpHealthCheck> {
    fn from(value: HealthCheck) -> Self {
        let mut health_check = TcpHealthCheck::new();
        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.active.timeout as u64));

        if let Some(healthy) = value.active.healthy {
            health_check.consecutive_success = healthy.successes as usize;
        }

        if let Some(unhealthy) = value.active.unhealthy {
            health_check.consecutive_failure = unhealthy.tcp_failures as usize;
        }

        health_check
    }
}

impl From<HealthCheck> for Box<HttpHealthCheck> {
    fn from(value: HealthCheck) -> Self {
        let host = value.active.host.clone().unwrap_or_default();
        let tls = value.active.r#type == ActiveCheckType::HTTPS;
        let mut health_check = HttpHealthCheck::new(host.as_str(), tls);

        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.active.timeout as u64));
        if tls {
            health_check.peer_template.options.verify_cert = value.active.https_verify_certificate;
        }

        if let Ok(uri) = Uri::builder()
            .path_and_query(value.active.http_path)
            .build()
        {
            health_check.req.set_uri(uri);
        }

        for header in value.active.req_headers.iter() {
            let mut parts = header.splitn(2, ":");
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                let key = key.trim().to_string();
                let value = value.trim().to_string();
                let _ = health_check.req.insert_header(key, value);
            }
        }

        if let Some(port) = value.active.port {
            health_check.port_override = Some(port as u16);
        }

        if let Some(healthy) = value.active.healthy {
            health_check.consecutive_success = healthy.successes as usize;

            if !healthy.http_statuses.is_empty() {
                let http_statuses = healthy.http_statuses.clone();

                health_check.validator = Some(Box::new(move |header: &ResponseHeader| {
                    if http_statuses.contains(&(header.status.as_u16() as u32)) {
                        Ok(())
                    } else {
                        Err(Error::new_str("Invalid response"))
                    }
                }));
            }
        }

        if let Some(unhealthy) = value.active.unhealthy {
            health_check.consecutive_failure = unhealthy.http_failures as usize;
        }

        Box::new(health_check)
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
