use std::collections::HashMap;
use std::sync::Arc;
use std::time;

use matchit::{InsertError, Router as MatchRouter};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::config::Router;

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
        let mut backend =
            backend.ok_or_else(|| pingora::Error::new_str("Unable to determine backend"))?;

        backend
            .ext
            .get_mut::<HttpPeer>()
            .map(|p| {
                // set timeout from router
                if let Some(timeout) = self.router.timeout.clone() {
                    if let Some(connect) = timeout.connect {
                        p.options.connection_timeout = Some(time::Duration::from_secs(connect));
                    }

                    if let Some(read) = timeout.read {
                        p.options.read_timeout = Some(time::Duration::from_secs(read));
                    }

                    if let Some(send) = timeout.send {
                        p.options.write_timeout = Some(time::Duration::from_secs(send));
                    }
                }

                Box::new(p.clone())
            })
            .ok_or_else(|| pingora::Error::new_str("Fatal: Missing selected backend metadata"))
    }
}

pub struct MatchEntry {
    /// Router for non-host URI matching
    non_host_uri: MatchRouter<Vec<Arc<ProxyRouter>>>,
    /// Router for host URI matching
    host_uris: MatchRouter<MatchRouter<Vec<Arc<ProxyRouter>>>>,
}

impl MatchEntry {
    pub fn new() -> Self {
        Self {
            non_host_uri: MatchRouter::new(),
            host_uris: MatchRouter::new(),
        }
    }

    pub fn insert_router(&mut self, router: Router) -> Result<(), InsertError> {
        let hosts = router.get_hosts();
        let uris = router.get_uris();
        let proxy_router = Arc::new(ProxyRouter::from(router));

        if hosts.as_ref().map_or(true, |v| v.is_empty()) {
            for uri in uris.unwrap().iter() {
                if self.non_host_uri.at(uri).is_err() {
                    self.non_host_uri.insert(uri, vec![proxy_router.clone()])?;
                } else {
                    self.non_host_uri
                        .at_mut(uri)
                        .unwrap()
                        .value
                        .push(proxy_router.clone());
                }
            }
        } else {
            for host in hosts.unwrap().iter() {
                // reverse host
                let reversed_host = host.chars().rev().collect::<String>();

                if self.host_uris.at(reversed_host.as_str()).is_err() {
                    let mut inner = MatchRouter::new();
                    for uri in uris.clone().unwrap().iter() {
                        inner.insert(uri, vec![proxy_router.clone()])?;
                    }
                    self.host_uris.insert(reversed_host, inner)?;
                } else {
                    let inner = self.host_uris.at_mut(reversed_host.as_str()).unwrap().value;
                    for uri in uris.clone().unwrap().iter() {
                        if inner.at(uri).is_err() {
                            inner.insert(uri, vec![proxy_router.clone()])?;
                        } else {
                            inner.at_mut(uri).unwrap().value.push(proxy_router.clone());
                        }
                    }
                }
            }
        };

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
            // match uri
            if let Ok(v) = self.non_host_uri.at(uri) {
                let params: HashMap<String, String> = v
                    .params
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();

                for router in v.value.iter() {
                    if router.router.methods.is_none() {
                        return Some((params, router.clone()));
                    }

                    // match method
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
        } else {
            let reversed_host = host.unwrap().chars().rev().collect::<String>();

            // match host
            if let Ok(v) = self.host_uris.at(reversed_host.as_str()) {
                // match uri
                if let Ok(v) = v.value.at(uri) {
                    let params: HashMap<String, String> = v
                        .params
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();

                    for router in v.value.iter() {
                        if router.router.methods.is_none() {
                            return Some((params, router.clone()));
                        }

                        // match method
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
            }
        }

        None
    }
}

impl Default for MatchEntry {
    fn default() -> Self {
        Self::new()
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
