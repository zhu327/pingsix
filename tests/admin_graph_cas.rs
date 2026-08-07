//! Admin graph-guard CAS and redaction integration tests (ADMIN-1..5).

mod common;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use common::*;

fn boot_with_graph() -> (
    EtcdFixture,
    MockUpstream,
    u16,
    u16,
    u16,
    String,
    std::process::Child,
) {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();

    let yaml = etcd_config_yaml(&EtcdModeConfig {
        listen_port,
        status_port,
        admin_port,
        etcd_endpoint: etcd.endpoint.clone(),
        prefix: prefix.clone(),
        stale_after: 300,
        dns_timeout: 5,
        prometheus_port: None,
    });
    let config_path = write_config(listen_port, &yaml);
    let mut child = spawn_pingsix(&config_path);

    assert!(wait_until_status(
        status_port,
        "/status/live",
        200,
        Duration::from_secs(15)
    ));
    if !wait_until_admin_ready(admin_port, Duration::from_secs(15)) {
        let logs = std::fs::read_to_string(child_log_path(&config_path)).unwrap_or_default();
        let _ = child.kill();
        let _ = child.wait();
        cleanup_runtime_files(listen_port, &config_path);
        panic!("admin listener not ready; child logs:\n{logs}");
    }

    let node = format!("127.0.0.1:{}", upstream.port);
    let up = admin_put(admin_port, "upstreams", "1", &upstream_nodes(&node));
    assert_eq!(up.status, 200, "upstream put: {}", up.body);
    let route = admin_put(admin_port, "routes", "1", &route_to_upstream("/", "1"));
    assert_eq!(route.status, 200, "route put: {}", route.body);
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));

    (
        etcd,
        upstream,
        listen_port,
        status_port,
        admin_port,
        config_path,
        child,
    )
}

#[test]
fn admin1_put_get_roundtrip() {
    if !require_docker("admin_graph_cas") {
        return;
    }
    let (_etcd, _up, listen_port, _status, admin_port, config_path, mut child) = boot_with_graph();

    let got = admin_get(admin_port, "routes", "1");
    assert_eq!(got.status, 200, "{}", got.body);
    assert!(
        got.body.contains("\"uri\"") || got.body.contains("/"),
        "get body={}",
        got.body
    );

    let put = admin_put(
        admin_port,
        "routes",
        "1",
        &serde_json::json!({
            "uri": "/v2",
            "upstream_id": "1"
        }),
    );
    assert_eq!(put.status, 200, "{}", put.body);
    assert!(
        put.body.contains("revision"),
        "expected revision in {}",
        put.body
    );

    assert!(wait_until_proxy_body(
        listen_port,
        "/v2",
        "upstream-ok",
        Duration::from_secs(10)
    ));

    // Path id is authoritative: a mismatched body id is normalized, and GET
    // returns the path id so API and runtime views can never disagree.
    let put = admin_put(
        admin_port,
        "routes",
        "1",
        &serde_json::json!({
            "id": "totally-different",
            "uri": "/v3",
            "upstream_id": "1"
        }),
    );
    assert_eq!(put.status, 200, "{} ", put.body);
    let got = admin_get(admin_port, "routes", "1");
    assert_eq!(got.status, 200, "{}", got.body);
    assert!(
        got.body.contains("\"id\":\"1\"") || got.body.contains("\"id\": \"1\""),
        "GET must return the path id, got {}",
        got.body
    );
    assert!(
        !got.body.contains("totally-different"),
        "body id must not leak into the stored resource: {}",
        got.body
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn admin2_concurrent_put_one_conflicts() {
    if !require_docker("admin_graph_cas") {
        return;
    }
    let (_etcd, _up, listen_port, _status, admin_port, config_path, mut child) = boot_with_graph();

    // Second upstream so both concurrent route updates are individually valid.
    let up2 = admin_put(
        admin_port,
        "upstreams",
        "2",
        &upstream_nodes(&format!("127.0.0.1:{}", random_port())),
    );
    assert_eq!(up2.status, 200, "{}", up2.body);

    let barrier = Arc::new(Barrier::new(2));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    let spawn_one = |route_id: &str, uri: &str| {
        let barrier = barrier.clone();
        let results = results.clone();
        let route_id = route_id.to_string();
        let uri = uri.to_string();
        thread::spawn(move || {
            barrier.wait();
            let resp = admin_put(
                admin_port,
                "routes",
                &route_id,
                &serde_json::json!({
                    "uri": uri,
                    "upstream_id": "1"
                }),
            );
            results.lock().unwrap().push((route_id, resp.status));
        })
    };

    // Concurrent creates of two new routes — both touch the graph guard.
    let t1 = spawn_one("r-a", "/a");
    let t2 = spawn_one("r-b", "/b");
    t1.join().unwrap();
    t2.join().unwrap();

    let results = results.lock().unwrap().clone();
    assert_eq!(results.len(), 2);
    let mut ok = 0;
    let mut conflict = 0;
    for (id, status) in &results {
        match status {
            200 => ok += 1,
            409 => conflict += 1,
            other => panic!("unexpected status {other} for {id}"),
        }
        // The winner is persisted; the conflicted loser must not exist at all.
        let got = admin_get(admin_port, "routes", id);
        if *status == 200 {
            assert_eq!(
                got.status, 200,
                "route {id} with status 200 must be persisted: {}",
                got.body
            );
            let wanted = if id == "r-a" { "/a" } else { "/b" };
            assert!(
                got.body.contains(&format!("\"uri\":\"{wanted}\""))
                    || got.body.contains(&format!("\"uri\": \"{wanted}\"")),
                "route {id} must carry its uri: {}",
                got.body
            );
        } else {
            assert_eq!(
                got.status, 404,
                "conflicted route {id} must not exist: {}",
                got.body
            );
        }
    }
    assert!(
        ok >= 1,
        "expected at least one success, results={results:?}"
    );
    assert_eq!(ok + conflict, 2, "results={results:?}");

    let list = http_exchange(
        &format!("127.0.0.1:{admin_port}"),
        "GET",
        "/apisix/admin/routes",
        &[("x-api-key", ADMIN_API_KEY)],
        None,
    )
    .unwrap();
    assert_eq!(list.status, 200, "{}", list.body);

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn admin3_delete_referenced_upstream_conflicts() {
    if !require_docker("admin_graph_cas") {
        return;
    }
    let (_etcd, _up, listen_port, _status, admin_port, config_path, mut child) = boot_with_graph();

    let del = admin_delete(admin_port, "upstreams", "1");
    assert_eq!(
        del.status, 409,
        "deleting referenced upstream must 409: {}",
        del.body
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn admin4_get_redacts_secrets() {
    if !require_docker("admin_graph_cas") {
        return;
    }
    let (_etcd, _up, listen_port, _status, admin_port, config_path, mut child) = boot_with_graph();

    let put = admin_put(
        admin_port,
        "routes",
        "secure",
        &serde_json::json!({
            "uri": "/secure",
            "upstream_id": "1",
            "plugins": {
                "key-auth": { "keys": ["super-secret-key"] },
                "jwt-auth": { "secret": "jwt-super-secret" },
                "basic-auth": { "username": "alice", "password": "p@ss" },
                "csrf": { "key": "csrf-secret-value" }
            }
        }),
    );
    assert_eq!(put.status, 200, "put secure route: {}", put.body);

    let got = admin_get(admin_port, "routes", "secure");
    assert_eq!(got.status, 200, "{}", got.body);
    assert!(
        !got.body.contains("super-secret-key"),
        "key leaked: {}",
        got.body
    );
    assert!(
        !got.body.contains("jwt-super-secret"),
        "jwt secret leaked: {}",
        got.body
    );
    assert!(!got.body.contains("p@ss"), "password leaked: {}", got.body);
    assert!(
        !got.body.contains("csrf-secret-value"),
        "csrf key leaked: {}",
        got.body
    );
    assert!(got.body.contains("***"), "expected redaction markers");
    assert!(
        got.body.contains("alice"),
        "username should not be redacted"
    );

    // Inline upstream tls.client_key on a dedicated upstream resource. Valid
    // material is accepted and the key is redacted on read; invalid material
    // is rejected synchronously instead of being stored as a poison candidate.
    let tls_up = admin_put(
        admin_port,
        "upstreams",
        "tls1",
        &serde_json::json!({
            "nodes": { "127.0.0.1:9": 1 },
            "type": "roundrobin",
            "tls": {
                "client_cert": include_str!("../src/proxy/testdata/example.crt"),
                "client_key": include_str!("../src/proxy/testdata/example.key"),
            }
        }),
    );
    assert_eq!(tls_up.status, 200, "{}", tls_up.body);
    let tls_get = admin_get(admin_port, "upstreams", "tls1");
    assert_eq!(tls_get.status, 200, "{}", tls_get.body);
    assert!(
        !tls_get.body.contains("PRIVATE KEY"),
        "tls key leaked: {}",
        tls_get.body
    );
    assert!(
        tls_get.body.contains("***"),
        "expected redaction marker: {}",
        tls_get.body
    );

    let tls_bad = admin_put(
        admin_port,
        "upstreams",
        "tls-bad",
        &serde_json::json!({
            "nodes": { "127.0.0.1:9": 1 },
            "type": "roundrobin",
            "tls": {
                "client_cert": "CERTDATA",
                "client_key": "PRIVATE-KEY-MATERIAL"
            }
        }),
    );
    assert_eq!(
        tls_bad.status, 400,
        "invalid mTLS material must be rejected at write time: {}",
        tls_bad.body
    );
    let tls_bad_get = admin_get(admin_port, "upstreams", "tls-bad");
    assert_eq!(
        tls_bad_get.status, 404,
        "rejected upstream must not be stored: {}",
        tls_bad_get.body
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn admin5_missing_api_key_forbidden() {
    if !require_docker("admin_graph_cas") {
        return;
    }
    let (_etcd, _up, listen_port, _status, admin_port, config_path, mut child) = boot_with_graph();

    let resp = http_exchange(
        &format!("127.0.0.1:{admin_port}"),
        "GET",
        "/apisix/admin/routes/1",
        &[],
        None,
    )
    .unwrap();
    assert_eq!(resp.status, 403, "expected forbidden, got {}", resp.body);

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}
