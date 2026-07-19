//! Etcd control-plane + readiness integration tests (ETCD-1..6).

mod common;

use std::time::Duration;

use common::*;

fn seed_working_graph(etcd: &EtcdFixture, prefix: &str, upstream_addr: &str) {
    etcd.put_json(prefix, "upstreams", "1", &upstream_nodes(upstream_addr));
    etcd.put_json(prefix, "routes", "1", &route_to_upstream("/", "1"));
}

#[test]
fn etcd1_cold_start_empty_publishes_empty_graph() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
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

    let status_addr = format!("127.0.0.1:{status_port}");
    assert!(
        wait_until_status(status_port, "/status/live", 200, Duration::from_secs(15)),
        "live should be up"
    );
    // An empty prefix list is still a valid snapshot: ready after publish, no routes.
    assert!(
        wait_until_ready(status_port, Duration::from_secs(20)),
        "empty etcd list should publish and become ready"
    );
    let view = status_config(status_port);
    assert_eq!(view["ready"], true);
    assert!(
        view["published_revision"].as_i64().unwrap_or(0) > 0,
        "empty list still advances published_revision: {view}"
    );

    let proxy = http_get(&format!("127.0.0.1:{listen_port}"), "/");
    assert!(
        proxy
            .as_ref()
            .is_some_and(|r| r.status == 404 || r.status == 502),
        "empty graph should not route traffic; got {proxy:?}"
    );

    // Live stays up regardless of graph contents.
    assert_eq!(http_status(&status_addr, "/status/live"), Some(200));

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn etcd2_put_publishes_and_proxies() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "etcd2-ok".into(),
        ..Default::default()
    });
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

    assert!(
        wait_until_status(status_port, "/status/live", 200, Duration::from_secs(15)),
        "live"
    );

    let node = format!("127.0.0.1:{}", upstream.port);
    seed_working_graph(&etcd, &prefix, &node);

    assert!(
        wait_until_ready(status_port, Duration::from_secs(20)),
        "should become ready after valid graph"
    );
    assert!(
        wait_until_proxy_body(listen_port, "/", "etcd2-ok", Duration::from_secs(10)),
        "proxy should hit mock upstream"
    );

    let view = status_config(status_port);
    let published = view["published_revision"]
        .as_i64()
        .expect("published_revision");
    assert!(published > 0, "published_revision={published}");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn etcd3_invalid_candidate_keeps_lkg() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "lkg-ok".into(),
        ..Default::default()
    });
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

    let node = format!("127.0.0.1:{}", upstream.port);
    seed_working_graph(&etcd, &prefix, &node);
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));
    assert!(wait_until_proxy_body(
        listen_port,
        "/",
        "lkg-ok",
        Duration::from_secs(10)
    ));

    // Dangling upstream_id must not wipe LKG.
    etcd.put_json(
        &prefix,
        "routes",
        "bad",
        &serde_json::json!({
            "uri": "/bad",
            "upstream_id": "missing-upstream"
        }),
    );

    // Give watch + prep time to reject.
    std::thread::sleep(Duration::from_secs(2));

    assert!(
        wait_until_ready(status_port, Duration::from_secs(5)),
        "ready should stay green on LKG"
    );
    assert!(
        wait_until_proxy_body(listen_port, "/", "lkg-ok", Duration::from_secs(5)),
        "LKG proxy still works"
    );

    let view = status_config(status_port);
    // Either still clean (if validation rejected before status error) or candidate_invalid.
    if view["degraded"].as_bool() == Some(true) {
        let kind = view["error_kind"].as_str();
        assert_eq!(
            kind,
            Some("candidate_invalid"),
            "unexpected error_kind in {view}"
        );
    }

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn etcd4_disconnect_becomes_config_stale() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "stale-lkg".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();

    let yaml = etcd_config_yaml(&EtcdModeConfig {
        listen_port,
        status_port,
        admin_port,
        etcd_endpoint: etcd.endpoint.clone(),
        prefix: prefix.clone(),
        stale_after: 3,
        dns_timeout: // config_stale_after
        5,
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

    let node = format!("127.0.0.1:{}", upstream.port);
    seed_working_graph(&etcd, &prefix, &node);
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));

    etcd.stop();

    let ready = wait_until_ready_reason(status_port, "config_stale", Duration::from_secs(15));
    assert!(
        ready.is_some(),
        "expected config_stale after disconnect; got {:?}",
        http_get(&format!("127.0.0.1:{status_port}"), "/status/ready")
    );

    assert!(
        wait_until_proxy_body(listen_port, "/", "stale-lkg", Duration::from_secs(5)),
        "LKG traffic continues while stale"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn etcd5_reconnect_ready_only_after_publish() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "reconnect-ok".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();

    let yaml = etcd_config_yaml(&EtcdModeConfig {
        listen_port,
        status_port,
        admin_port,
        etcd_endpoint: etcd.endpoint.clone(),
        prefix: prefix.clone(),
        stale_after: 3,
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

    let node = format!("127.0.0.1:{}", upstream.port);
    seed_working_graph(&etcd, &prefix, &node);
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));

    etcd.stop();
    assert!(
        wait_until_ready_reason(status_port, "config_stale", Duration::from_secs(15)).is_some(),
        "should go stale"
    );

    etcd.start_again();

    assert!(
        wait_until_ready(status_port, Duration::from_secs(30)),
        "ready only after relist+publish"
    );
    let view = status_config(status_port);
    assert_eq!(view["ready"], true);
    assert!(view["published_revision"].as_i64().unwrap_or(0) > 0);
    assert!(wait_until_proxy_body(
        listen_port,
        "/",
        "reconnect-ok",
        Duration::from_secs(10)
    ));

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn etcd6_idle_connected_watch_stays_ready() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "idle-ok".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();

    // Short stale threshold; connected idle watch must NOT become stale.
    let yaml = etcd_config_yaml(&EtcdModeConfig {
        listen_port,
        status_port,
        admin_port,
        etcd_endpoint: etcd.endpoint.clone(),
        prefix: prefix.clone(),
        stale_after: 2,
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

    let node = format!("127.0.0.1:{}", upstream.port);
    seed_working_graph(&etcd, &prefix, &node);
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));

    std::thread::sleep(Duration::from_secs(5));

    let resp = http_get(&format!("127.0.0.1:{status_port}"), "/status/ready").expect("ready probe");
    assert_eq!(
        resp.status, 200,
        "idle connected watch must stay ready; body={}",
        resp.body
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}
