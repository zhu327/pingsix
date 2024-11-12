use std::collections::HashMap;
use std::sync::Arc;
use std::time;

use matchit::{InsertError, Router as MatchRouter};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::config::{Router, Timeout};

use super::lb::ProxyLB;

pub struct ProxyRouter {
    pub router: Router,
    pub lb: ProxyLB,
}

impl From<Router> for ProxyRouter {
    fn from(value: Router) -> Self {
        Self {
            router: value.clone(),
            // TODO: support get upstream from router.upstream_id.
            lb: ProxyLB::from(value.upstream),
        }
    }
}

impl ProxyRouter {
    pub fn select_http_peer<'a>(&'a self, session: &'a mut Session) -> Result<Box<HttpPeer>> {
        let backend = self.lb.select_backend(session);
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

    fn set_timeout(&self, p: &mut HttpPeer) {
        if let Some(Timeout {
            connect,
            read,
            send,
        }) = self.router.timeout.clone()
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
    pub fn insert_router(&mut self, proxy_router: ProxyRouter) -> Result<(), InsertError> {
        let hosts = proxy_router.router.get_hosts();
        let uris = proxy_router.router.get_uris();
        let proxy_router = Arc::new(proxy_router);

        if hosts.as_ref().map_or(true, |v| v.is_empty()) {
            // Insert for non-host URIs
            Self::insert_router_for_uri(&mut self.non_host_uri, uris.unwrap(), proxy_router)?;
        } else {
            // Insert for host URIs
            for host in hosts.unwrap().iter() {
                let reversed_host = host.chars().rev().collect::<String>();

                if self.host_uris.at(reversed_host.as_str()).is_err() {
                    let mut inner = MatchRouter::new();
                    for uri in uris.clone().unwrap().iter() {
                        inner.insert(uri, vec![proxy_router.clone()])?;
                    }
                    self.host_uris.insert(reversed_host, inner)?;
                } else {
                    let inner = self.host_uris.at_mut(reversed_host.as_str()).unwrap().value;
                    Self::insert_router_for_uri(
                        inner,
                        uris.clone().unwrap(),
                        proxy_router.clone(),
                    )?;
                }
            }
        }

        Ok(())
    }

    fn insert_router_for_uri(
        match_router: &mut MatchRouter<Vec<Arc<ProxyRouter>>>,
        uris: Vec<String>,
        proxy_router: Arc<ProxyRouter>,
    ) -> Result<(), InsertError> {
        for uri in uris.iter() {
            if match_router.at(uri).is_err() {
                match_router.insert(uri, vec![proxy_router.clone()])?;
            } else {
                match_router
                    .at_mut(uri)
                    .unwrap()
                    .value
                    .push(proxy_router.clone());
            }
        }
        Ok(())
    }

    pub fn match_request(
        &self,
        session: &mut Session,
    ) -> Option<(HashMap<String, String>, Arc<ProxyRouter>)> {
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

    fn match_uri(
        match_router: &MatchRouter<Vec<Arc<ProxyRouter>>>,
        uri: &str,
        method: &str,
    ) -> Option<(HashMap<String, String>, Arc<ProxyRouter>)> {
        if let Ok(v) = match_router.at(uri) {
            let params: HashMap<String, String> = v
                .params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for router in v.value.iter() {
                if router.router.methods.is_none() {
                    return Some((params, router.clone()));
                }

                // Match method
                if router
                    .router
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

fn get_request_host(header: &RequestHeader) -> Option<&str> {
    if let Some(host) = header.uri.host() {
        return Some(host);
    }
    if let Some(host) = header.headers.get("Host") {
        if let Ok(value) = host.to_str().map(|host| host.split(':').next()) {
            return value;
        }
    }
    None
}
