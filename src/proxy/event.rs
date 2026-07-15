//! Etcd event handler that delegates to the unified ControlPlane.

use etcd_client::{Event, GetResponse};

use crate::{
    config::etcd::EtcdEventHandler,
    core::{status, ProxyResult},
};

use super::control_plane::{ResourceConfigSet, CONTROL_PLANE};

pub struct ProxyEventHandler;

impl Default for ProxyEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyEventHandler {
    pub fn new() -> Self {
        ProxyEventHandler
    }
}

impl EtcdEventHandler for ProxyEventHandler {
    fn handle_events(&self, events: &[Event]) -> ProxyResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        // Use the highest revision observed in the batch when available.
        let revision = events
            .iter()
            .filter_map(|event| event.kv().map(|kv| kv.mod_revision()))
            .max()
            .unwrap_or(0);

        CONTROL_PLANE.apply_events(events, revision)?;
        Ok(())
    }

    fn handle_list_response(&self, response: &GetResponse) -> ProxyResult<()> {
        let revision = response.header().map(|h| h.revision()).ok_or_else(|| {
            crate::core::ProxyError::etcd_error("Failed to get header from list response")
        })?;

        let resources = ResourceConfigSet::from_etcd_list(response)?;
        CONTROL_PLANE.replace_all(resources, revision)?;
        status::mark_ready(status::ConfigSource::Etcd);
        status::mark_etcd_connected(true);
        status::set_revision(Some(revision));
        Ok(())
    }
}
