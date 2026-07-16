//! Whole-graph candidate construction, reference validation, and guarded etcd commit.
//!
//! Admin PUT/DELETE call this module; HTTP parsing and response mapping stay in the
//! admin adapter. Concrete etcd I/O stays in [`crate::config::etcd`].

use std::collections::HashMap;
use std::fmt;

use crate::{
    config::etcd::{EtcdClientWrapper, FullGraph},
    core::ProxyError,
    proxy::control_plane::{build_config_set_from_kvs, validate_config_set},
};

/// Outcomes of a guarded graph mutation that Admin maps to HTTP status codes.
#[derive(Debug)]
pub enum GraphMutationError {
    /// Target resource is absent (DELETE → 404).
    NotFound(String),
    /// Candidate graph fails reference checks on DELETE (→ 409).
    ReferentialConflict(String),
    /// Candidate graph is invalid on PUT (→ 400).
    InvalidCandidate(String),
    /// Guard or per-key CAS failed (→ 409).
    CasConflict(String),
    /// etcd or other storage failure.
    Storage(ProxyError),
}

impl fmt::Display for GraphMutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "{msg}"),
            Self::ReferentialConflict(msg) => write!(f, "{msg}"),
            Self::InvalidCandidate(msg) => write!(f, "{msg}"),
            Self::CasConflict(msg) => write!(f, "{msg}"),
            Self::Storage(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for GraphMutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ProxyError> for GraphMutationError {
    fn from(err: ProxyError) -> Self {
        match err {
            ProxyError::CasConflict(msg) => Self::CasConflict(msg),
            other => Self::Storage(other),
        }
    }
}

/// Collect `(physical_key, value)` pairs from a full-graph read, excluding `exclude`.
pub fn graph_without(kv_map: &HashMap<String, Vec<u8>>, exclude: &str) -> Vec<(String, Vec<u8>)> {
    kv_map
        .iter()
        .filter(|(k, _)| *k != exclude)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Build and validate a candidate graph for a put (`replacement = Some(body)`) or
/// delete (`replacement = None`).
///
/// Shared by the async commit path and unit tests so reference-check regressions
/// fail at this seam without etcd or HTTP.
pub fn validate_candidate(
    graph: &FullGraph,
    full_key: &str,
    replacement: Option<&[u8]>,
    prefix: &str,
) -> Result<(), GraphMutationError> {
    let mut candidate_kvs = graph_without(&graph.kvs, full_key);
    if let Some(body) = replacement {
        candidate_kvs.push((full_key.to_string(), body.to_vec()));
    }

    let candidate_set = build_config_set_from_kvs(&candidate_kvs, prefix).map_err(|e| {
        GraphMutationError::InvalidCandidate(format!("Failed to build candidate config set: {e}"))
    })?;

    validate_config_set(&candidate_set).map_err(|e| {
        if replacement.is_some() {
            GraphMutationError::InvalidCandidate(format!("Proposed configuration is invalid: {e}"))
        } else {
            GraphMutationError::ReferentialConflict(format!(
                "Resource is referenced by other resources: {e}"
            ))
        }
    })
}

/// Put a resource after whole-graph validation and a guarded etcd transaction.
///
/// `logical_key` is the unprefixed path (e.g. `upstreams/u1`). Returns the
/// committed etcd cluster revision.
pub async fn put_resource(
    etcd: &EtcdClientWrapper,
    logical_key: &str,
    body: Vec<u8>,
) -> Result<i64, GraphMutationError> {
    let graph = etcd.read_full_graph().await?;
    let full_key = etcd.prefixed_key(logical_key);

    validate_candidate(&graph, &full_key, Some(&body), etcd.prefix())?;

    let committed = etcd
        .graph_txn_put(
            &full_key,
            body,
            graph.mod_revisions.get(&full_key).copied(),
            graph.guard_mod_revision,
        )
        .await
        .map_err(map_txn_error)?;

    Ok(committed)
}

/// Delete a resource after existence check, whole-graph validation, and a
/// guarded etcd transaction.
pub async fn delete_resource(
    etcd: &EtcdClientWrapper,
    logical_key: &str,
) -> Result<(), GraphMutationError> {
    let graph = etcd.read_full_graph().await?;
    let full_key = etcd.prefixed_key(logical_key);

    let expected_mod_revision = *graph.mod_revisions.get(&full_key).ok_or_else(|| {
        GraphMutationError::NotFound("Resource not found".into())
    })?;

    validate_candidate(&graph, &full_key, None, etcd.prefix())?;

    etcd.graph_txn_delete(&full_key, expected_mod_revision, graph.guard_mod_revision)
        .await
        .map_err(map_txn_error)?;

    Ok(())
}

fn map_txn_error(e: ProxyError) -> GraphMutationError {
    match e {
        ProxyError::CasConflict(_) => {
            GraphMutationError::CasConflict("Resource was modified concurrently".into())
        }
        other => GraphMutationError::Storage(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        SelectionType, Upstream, UpstreamHashOn, UpstreamPassHost, UpstreamScheme,
    };

    fn sample_upstream_json(id: &str, node: &str) -> Vec<u8> {
        let mut nodes = HashMap::new();
        nodes.insert(node.to_string(), 1u32);
        let upstream = Upstream {
            id: id.to_string(),
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes,
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
        };
        serde_json::to_vec(&upstream).unwrap()
    }

    fn sample_route_json(id: &str, upstream_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "uri": "/",
            "upstream_id": upstream_id,
        }))
        .unwrap()
    }

    fn graph_with(kvs: Vec<(String, Vec<u8>)>) -> FullGraph {
        let mut map = HashMap::new();
        let mut mod_revisions = HashMap::new();
        for (i, (k, v)) in kvs.into_iter().enumerate() {
            mod_revisions.insert(k.clone(), (i + 1) as i64);
            map.insert(k, v);
        }
        FullGraph {
            kvs: map,
            mod_revisions,
            guard_mod_revision: Some(1),
        }
    }

    #[test]
    fn graph_without_excludes_target_key() {
        let mut kvs = HashMap::new();
        kvs.insert("/pingsix/upstreams/u1".into(), b"a".to_vec());
        kvs.insert("/pingsix/upstreams/u2".into(), b"b".to_vec());
        let out = graph_without(&kvs, "/pingsix/upstreams/u1");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "/pingsix/upstreams/u2");
    }

    #[test]
    fn put_candidate_rejects_dangling_upstream_id() {
        let prefix = "/pingsix/";
        let graph = graph_with(vec![(
            format!("{prefix}upstreams/u1"),
            sample_upstream_json("u1", "10.0.0.1:80"),
        )]);
        let full_key = format!("{prefix}routes/r1");
        let body = sample_route_json("r1", "missing");

        let err = validate_candidate(&graph, &full_key, Some(&body), prefix).unwrap_err();
        match err {
            GraphMutationError::InvalidCandidate(msg) => {
                assert!(msg.contains("Proposed configuration is invalid"));
            }
            other => panic!("expected InvalidCandidate, got {other}"),
        }
    }

    #[test]
    fn put_candidate_accepts_valid_graph() {
        let prefix = "/pingsix/";
        let graph = graph_with(vec![(
            format!("{prefix}upstreams/u1"),
            sample_upstream_json("u1", "10.0.0.1:80"),
        )]);
        let full_key = format!("{prefix}routes/r1");
        let body = sample_route_json("r1", "u1");

        assert!(validate_candidate(&graph, &full_key, Some(&body), prefix).is_ok());
    }

    #[test]
    fn delete_candidate_rejects_referenced_upstream() {
        let prefix = "/pingsix/";
        let upstream_key = format!("{prefix}upstreams/u1");
        let graph = graph_with(vec![
            (upstream_key.clone(), sample_upstream_json("u1", "10.0.0.1:80")),
            (
                format!("{prefix}routes/r1"),
                sample_route_json("r1", "u1"),
            ),
        ]);

        let err = validate_candidate(&graph, &upstream_key, None, prefix).unwrap_err();
        match err {
            GraphMutationError::ReferentialConflict(msg) => {
                assert!(msg.contains("Resource is referenced by other resources"));
            }
            other => panic!("expected ReferentialConflict, got {other}"),
        }
    }

    #[test]
    fn delete_candidate_allows_unreferenced_upstream() {
        let prefix = "/pingsix/";
        let upstream_key = format!("{prefix}upstreams/u1");
        let graph = graph_with(vec![(
            upstream_key.clone(),
            sample_upstream_json("u1", "10.0.0.1:80"),
        )]);

        assert!(validate_candidate(&graph, &upstream_key, None, prefix).is_ok());
    }

    #[test]
    fn map_txn_error_preserves_cas_message() {
        let err = map_txn_error(ProxyError::CasConflict("ignored".into()));
        match err {
            GraphMutationError::CasConflict(msg) => {
                assert_eq!(msg, "Resource was modified concurrently");
            }
            other => panic!("expected CasConflict, got {other}"),
        }
    }
}
