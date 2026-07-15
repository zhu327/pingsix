//! Etcd event handler that delegates to the unified ControlPlane.

use async_trait::async_trait;
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

#[async_trait]
impl EtcdEventHandler for ProxyEventHandler {
    async fn handle_events(&self, events: &[Event]) -> ProxyResult<()> {
        CONTROL_PLANE.start_preparation_worker();
        if events.is_empty() {
            return Ok(());
        }

        // Use the highest revision observed in the batch when available.
        let revision = events
            .iter()
            .filter_map(|event| event.kv().map(|kv| kv.mod_revision()))
            .max()
            .unwrap_or(0);

        CONTROL_PLANE.submit_events(events, revision)?;
        Ok(())
    }

    async fn handle_list_response(&self, response: &GetResponse) -> ProxyResult<()> {
        CONTROL_PLANE.start_preparation_worker();
        let revision = response.header().map(|h| h.revision()).ok_or_else(|| {
            crate::core::ProxyError::etcd_error("Failed to get header from list response")
        })?;

        let resources = ResourceConfigSet::from_etcd_list(response)?;
        // Mark transport recovery before submitting: a fast publish must be the
        // operation that clears the reconnect publication fence.
        status::record_sync_success(revision);
        CONTROL_PLANE.submit_replace_all(resources, revision)?;
        status::set_revision(Some(revision));
        Ok(())
    }
}
