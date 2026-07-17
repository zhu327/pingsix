//! Etcd event handler that delegates to the unified ControlPlane.

use async_trait::async_trait;
use etcd_client::{Event, GetResponse};

use crate::{
    config::etcd::EtcdEventHandler,
    core::{status, ProxyError, ProxyResult},
};

use super::control_plane::{ResourceConfigSet, CONTROL_PLANE};

pub struct ProxyEventHandler {
    prefix: String,
}

impl ProxyEventHandler {
    pub fn new(prefix: impl Into<String>) -> Self {
        ProxyEventHandler {
            prefix: prefix.into(),
        }
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
        let revision = response
            .header()
            .map(|h| h.revision())
            .ok_or_else(|| ProxyError::etcd_error("Failed to get header from list response"))?;

        let resources = ResourceConfigSet::from_etcd_list(response, &self.prefix)?;

        // Empty full-lists are accepted. When PingSIX uses the ingress etcd
        // adapter, kube Service selection on ingress.pingsix.io/etcd-serving
        // ensures we only connect after the controller has synced. Direct etcd
        // mode has no such race, so empty means intentionally empty.

        // Mark transport recovery before submitting: a fast publish must be the
        // operation that clears the reconnect publication fence.
        status::record_sync_success(revision);
        CONTROL_PLANE.submit_replace_all(resources, revision)?;
        status::set_revision(Some(revision));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::control_plane::{is_metadata_key, ResourceConfigSet};

    #[test]
    fn dotted_leaf_keys_are_metadata() {
        assert!(is_metadata_key(b"/apisix/.pingsix_graph_revision"));
        assert!(is_metadata_key(b"/apisix/.ingress_sync_barrier"));
        assert!(!is_metadata_key(b"/apisix/routes/1"));
    }

    #[test]
    fn business_empty_detects_blank_set() {
        assert!(ResourceConfigSet::default().is_business_empty());
    }
}
