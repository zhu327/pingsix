use std::collections::BTreeMap;
use std::sync::Arc;
use std::time;

use matchit::{InsertError, Router as MatchRouter};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::config;

use super::{
    plugin::ProxyPlugin,
    service::service_fetch,
    upstream::{upstream_fetch, ProxyUpstream},
};

/// Proxy router.
///
/// Manages routing of requests to appropriate proxy load balancers.
pub struct ProxyRouter {
    pub inner: config::Router,
    pub upstream: Option<Arc<ProxyUpstream>>,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl From<config::Router> for ProxyRouter {
    /// Creates a new `ProxyRouter` instance from a `Router` configuration.
    fn from(value: config::Router) -> Self {
        Self {
            inner: value,
            upstream: None,
            plugins: Vec::new(),
        }
    }
}

impl ProxyRouter {
    /// Gets the upstream for the router.
    pub fn get_upstream(&self) -> Option<Arc<ProxyUpstream>> {
        if self.upstream.is_some() {
            return self.upstream.clone();
        }

        if self.inner.upstream_id.is_some() {
            let upstream = upstream_fetch(&self.inner.upstream_id.clone().unwrap());
            if upstream.is_some() {
                return upstream;
            }
        }

        if self.inner.service_id.is_some() {
            let service = service_fetch(&self.inner.service_id.clone().unwrap());
            if let Some(service) = service {
                return service.get_upstream();
            }
        }

        None
    }

    /// Gets the list of hosts for the router.
    fn get_hosts(&self) -> Option<Vec<String>> {
        let hosts = self.inner.get_hosts();
        if hosts.is_some() {
            return hosts;
        }

        if self.inner.service_id.is_some() {
            let service = service_fetch(&self.inner.service_id.clone().unwrap());
            if let Some(service) = service {
                return Some(service.inner.hosts.clone());
            }
        }

        None
    }
}

impl ProxyRouter {
    /// Selects an HTTP peer for a given session.
    pub fn select_http_peer<'a>(&'a self, session: &'a mut Session) -> Result<Box<HttpPeer>> {
        let upstream = self
            .get_upstream()
            .ok_or_else(|| Error::new_str("No upstream configured"))?;

        let backend = upstream.select_backend(session);
        let mut backend = backend.ok_or_else(|| Error::new_str("Unable to determine backend"))?;

        backend
            .ext
            .get_mut::<HttpPeer>()
            .map(|p| {
                // set timeout from router
                self.set_timeout(p);

                Box::new(p.clone())
            })
            .ok_or_else(|| Error::new_str("Fatal: Missing selected backend metadata"))
    }

    /// Sets the timeout for an `HttpPeer` based on the router configuration.
    fn set_timeout(&self, p: &mut HttpPeer) {
        if let Some(config::Timeout {
            connect,
            read,
            send,
        }) = self.inner.timeout
        {
            p.options.connection_timeout = Some(time::Duration::from_secs(connect));
            p.options.read_timeout = Some(time::Duration::from_secs(read));
            p.options.write_timeout = Some(time::Duration::from_secs(send));
        }
    }
}

#[derive(Default)]
pub struct MatchEntry {
    /// Router for non-host URI matching
    non_host_uri: MatchRouter<Vec<Arc<ProxyRouter>>>,
    /// Router for host URI matching
    host_uris: MatchRouter<MatchRouter<Vec<Arc<ProxyRouter>>>>,
}

impl MatchEntry {
    /// Inserts a router into the match entry.
    pub fn insert_router(&mut self, proxy_router: ProxyRouter) -> Result<(), InsertError> {
        let hosts = proxy_router.get_hosts().unwrap_or_default();
        let uris = proxy_router.inner.get_uris().unwrap_or_default();
        let proxy_router = Arc::new(proxy_router);

        if hosts.is_empty() {
            // Insert for non-host URIs
            Self::insert_router_for_uri(&mut self.non_host_uri, &uris, proxy_router)?;
        } else {
            // Insert for host URIs
            for host in hosts.iter() {
                let reversed_host = host.chars().rev().collect::<String>();

                if self.host_uris.at(reversed_host.as_str()).is_err() {
                    let mut inner = MatchRouter::new();
                    for uri in uris.iter() {
                        inner.insert(uri, vec![proxy_router.clone()])?;
                    }
                    self.host_uris.insert(reversed_host, inner)?;
                } else {
                    let inner = self.host_uris.at_mut(reversed_host.as_str()).unwrap().value;
                    Self::insert_router_for_uri(inner, &uris, proxy_router.clone())?;
                }
            }
        }

        Ok(())
    }

    /// Inserts a router for a given URI.
    fn insert_router_for_uri(
        match_router: &mut MatchRouter<Vec<Arc<ProxyRouter>>>,
        uris: &[String],
        proxy_router: Arc<ProxyRouter>,
    ) -> Result<(), InsertError> {
        for uri in uris.iter() {
            if match_router.at(uri).is_err() {
                match_router.insert(uri, vec![proxy_router.clone()])?;
            } else {
                let routers = match_router.at_mut(uri).unwrap();
                routers.value.push(proxy_router.clone());
                // Sort by priority
                routers
                    .value
                    .sort_by(|a, b| b.inner.priority.cmp(&a.inner.priority));
            }
        }
        Ok(())
    }

    /// Matches a request to a router.
    pub fn match_request(
        &self,
        session: &mut Session,
    ) -> Option<(BTreeMap<String, String>, Arc<ProxyRouter>)> {
        let host = get_request_host(session.req_header());
        let uri = session.req_header().uri.path();
        let method = session.req_header().method.as_str();

        log::debug!(
            "match request: host={:?}, uri={:?}, method={:?}",
            host,
            uri,
            method
        );

        if host.map_or(true, |v| v.is_empty()) {
            // Match non-host uri
            return Self::match_uri(&self.non_host_uri, uri, method);
        } else {
            // Match host uri
            let reversed_host = host.unwrap().chars().rev().collect::<String>();
            if let Ok(v) = self.host_uris.at(reversed_host.as_str()) {
                return Self::match_uri(v.value, uri, method);
            }
        }

        None
    }

    /// Matches a URI to a router.
    fn match_uri(
        match_router: &MatchRouter<Vec<Arc<ProxyRouter>>>,
        uri: &str,
        method: &str,
    ) -> Option<(BTreeMap<String, String>, Arc<ProxyRouter>)> {
        if let Ok(v) = match_router.at(uri) {
            let params: BTreeMap<String, String> = v
                .params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for router in v.value.iter() {
                if router.inner.methods.is_none() {
                    return Some((params, router.clone()));
                }

                // Match method
                if router
                    .inner
                    .methods
                    .clone()
                    .unwrap()
                    .iter()
                    .map(|method| method.to_string())
                    .collect::<Vec<String>>()
                    .contains(&method.to_string())
                {
                    return Some((params, router.clone()));
                }
            }
        }
        None
    }
}

/// Retrieves the request host from the request header.
fn get_request_host(header: &RequestHeader) -> Option<&str> {
    if let Some(host) = header.uri.host() {
        return Some(host);
    }
    if let Some(host) = header.headers.get(http::header::HOST) {
        if let Ok(value) = host.to_str().map(|host| host.split(':').next()) {
            return value;
        }
    }
    None
}
