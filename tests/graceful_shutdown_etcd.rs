//! Graceful shutdown under etcd mode and during DNS preparation.

mod common;

use std::time::Duration;

use common::*;

#[test]
fn graceful_shutdown_etcd_after_publish() {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "sd-etcd".into(),
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
    etcd.put_json(&prefix, "upstreams", "1", &upstream_nodes(&node));
    etcd.put_json(&prefix, "routes", "1", &route_to_upstream("/", "1"));
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));
    assert!(wait_until_proxy_body(
        listen_port,
        "/",
        "sd-etcd",
        Duration::from_secs(10)
    ));

    sigterm(&child);
    let status = wait_exit(&mut child, Duration::from_secs(20));
    assert!(
        status.success() || status.code().is_none(),
        "clean exit, got {status:?}"
    );
    assert!(
        http_status(&format!("127.0.0.1:{status_port}"), "/status/ready").is_none(),
        "status port gone after shutdown"
    );
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn graceful_shutdown_during_dns_failure_prep() {
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

    let node = format!("127.0.0.1:{}", upstream.port);
    etcd.put_json(&prefix, "upstreams", "1", &upstream_nodes(&node));
    etcd.put_json(&prefix, "routes", "1", &route_to_upstream("/", "1"));
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));

    let _ = admin_put(
        admin_port,
        "upstreams",
        "1",
        &upstream_nodes("no-such-host.invalid:9"),
    );

    sigterm(&child);
    let status = wait_exit(&mut child, Duration::from_secs(20));
    assert!(
        status.success() || status.code().is_none(),
        "SIGTERM during DNS prep must exit, got {status:?}"
    );
    cleanup_runtime_files(listen_port, &config_path);
}
