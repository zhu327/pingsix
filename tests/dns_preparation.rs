//! DNS asynchronous preparation integration tests (DNS-1..6).

mod common;

use std::time::Duration;

use common::*;

struct BootPorts {
    listen: u16,
    status: u16,
    admin: u16,
    dns_timeout: u64,
    prom: Option<u16>,
}

fn boot_ready_with_ip_upstream(
    etcd: &EtcdFixture,
    prefix: &str,
    upstream_port: u16,
    ports: BootPorts,
) -> (String, std::process::Child) {
    let yaml = etcd_config_yaml(&EtcdModeConfig {
        listen_port: ports.listen,
        status_port: ports.status,
        admin_port: ports.admin,
        etcd_endpoint: etcd.endpoint.clone(),
        prefix: prefix.to_string(),
        stale_after: 300,
        dns_timeout: ports.dns_timeout,
        prometheus_port: ports.prom,
    });
    let config_path = write_config(ports.listen, &yaml);
    let child = spawn_pingsix(&config_path);
    assert!(wait_until_status(
        ports.status,
        "/status/live",
        200,
        Duration::from_secs(15)
    ));

    let node = format!("127.0.0.1:{upstream_port}");
    etcd.put_json(prefix, "upstreams", "1", &upstream_nodes(&node));
    etcd.put_json(prefix, "routes", "1", &route_to_upstream("/", "1"));
    assert!(wait_until_ready(ports.status, Duration::from_secs(20)));
    (config_path, child)
}

#[test]
fn dns1_localhost_hostname_publishes() {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "dns1-ok".into(),
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

    let host_node = format!("localhost:{}", upstream.port);
    let put = admin_put(admin_port, "upstreams", "dns", &upstream_nodes(&host_node));
    assert_eq!(put.status, 200, "{}", put.body);
    let route = admin_put(
        admin_port,
        "routes",
        "dns",
        &route_to_upstream("/dns", "dns"),
    );
    assert_eq!(route.status, 200, "{}", route.body);

    assert!(
        wait_until_proxy_body(listen_port, "/dns", "dns1-ok", Duration::from_secs(20)),
        "DNS-resolved localhost upstream should serve traffic"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn dns2_invalid_host_keeps_lkg() {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "dns2-lkg".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();

    let (config_path, mut child) = boot_ready_with_ip_upstream(
        &etcd,
        &prefix,
        upstream.port,
        BootPorts {
            listen: listen_port,
            status: status_port,
            admin: admin_port,
            dns_timeout: 1, // short DNS timeout
            prom: None,
        },
    );
    assert!(wait_until_proxy_body(
        listen_port,
        "/",
        "dns2-lkg",
        Duration::from_secs(10)
    ));

    let bad = admin_put(
        admin_port,
        "upstreams",
        "1",
        &upstream_nodes("no-such-host.invalid:9"),
    );
    // Admin validates graph refs, not DNS; put may succeed then prep fails.
    assert!(
        bad.status == 200 || bad.status == 400,
        "unexpected status {}: {}",
        bad.status,
        bad.body
    );

    std::thread::sleep(Duration::from_secs(3));

    assert!(
        wait_until_ready(status_port, Duration::from_secs(5)),
        "ready must not flip to not_initialized"
    );
    assert!(
        wait_until_proxy_body(listen_port, "/", "dns2-lkg", Duration::from_secs(5)),
        "LKG must keep serving"
    );

    let view = status_config(status_port);
    if view["error_kind"].as_str().is_some() {
        assert_eq!(view["error_kind"], "candidate_invalid");
    }

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn dns3_hybrid_static_survives_dns_failure() {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "hybrid-ok".into(),
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
        dns_timeout: 1,
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

    let hybrid = serde_json::json!({
        "nodes": {
            format!("127.0.0.1:{}", upstream.port): 1,
            "no-such-host.invalid:9": 1
        },
        "type": "roundrobin"
    });
    let put = admin_put(admin_port, "upstreams", "h", &hybrid);
    assert_eq!(put.status, 200, "{}", put.body);
    let route = admin_put(admin_port, "routes", "h", &route_to_upstream("/h", "h"));
    assert_eq!(route.status, 200, "{}", route.body);

    assert!(
        wait_until_proxy_body(listen_port, "/h", "hybrid-ok", Duration::from_secs(20)),
        "hybrid must route via static IP"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn dns4_burst_updates_publish_latest_only() {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let up_old = MockUpstream::start(MockUpstreamConfig {
        body: "old-backend".into(),
        ..Default::default()
    });
    let up_new = MockUpstream::start(MockUpstreamConfig {
        body: "new-backend".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();

    let (config_path, mut child) = boot_ready_with_ip_upstream(
        &etcd,
        &prefix,
        up_old.port,
        BootPorts {
            listen: listen_port,
            status: status_port,
            admin: admin_port,
            dns_timeout: 5,
            prom: None,
        },
    );

    // Rapid succession: first DNS-ish localhost to old, then to new.
    let _ = admin_put(
        admin_port,
        "upstreams",
        "1",
        &upstream_nodes(&format!("localhost:{}", up_old.port)),
    );
    let latest = admin_put(
        admin_port,
        "upstreams",
        "1",
        &upstream_nodes(&format!("localhost:{}", up_new.port)),
    );
    assert_eq!(latest.status, 200, "{}", latest.body);

    assert!(
        wait_until_proxy_body(listen_port, "/", "new-backend", Duration::from_secs(20)),
        "latest generation must win"
    );

    // Old backend should not keep receiving traffic after publish.
    up_old.reset_hits();
    up_new.reset_hits();
    for _ in 0..5 {
        let _ = http_get(&format!("127.0.0.1:{listen_port}"), "/");
    }
    assert_eq!(up_old.hits(), 0, "old backend should receive no traffic");
    assert!(up_new.hits() >= 1, "new backend should receive traffic");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn dns5_sigterm_during_dns_prep_exits() {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();

    let (config_path, mut child) = boot_ready_with_ip_upstream(
        &etcd,
        &prefix,
        upstream.port,
        BootPorts {
            listen: listen_port,
            status: status_port,
            admin: admin_port,
            dns_timeout: 5,
            prom: None,
        },
    );

    // Kick a slow/failing DNS prep then SIGTERM immediately.
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
        "clean SIGTERM exit, got {status:?}"
    );
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn dns6_control_plane_metrics_present() {
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "metrics-ok".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();
    let prom_port = random_port();

    let (config_path, mut child) = boot_ready_with_ip_upstream(
        &etcd,
        &prefix,
        upstream.port,
        BootPorts {
            listen: listen_port,
            status: status_port,
            admin: admin_port,
            dns_timeout: 5,
            prom: Some(prom_port),
        },
    );

    // Trigger a failed prep so preparation_total increments.
    let _ = admin_put(
        admin_port,
        "upstreams",
        "1",
        &upstream_nodes("no-such-host.invalid:9"),
    );
    std::thread::sleep(Duration::from_secs(2));

    let metrics =
        http_get(&format!("127.0.0.1:{prom_port}"), "/metrics").expect("prometheus scrape");
    assert_eq!(metrics.status, 200, "{}", metrics.body);
    assert!(
        metrics
            .body
            .contains("pingsix_control_plane_preparation_total")
            || metrics
                .body
                .contains("pingsix_control_plane_pending_revision"),
        "missing control-plane metrics in {}",
        metrics.body
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}
