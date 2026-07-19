//! Cache namespace isolation after dynamic upstream / plugin changes.

mod common;

use std::time::Duration;

use common::*;

fn boot_cached_route(
    etcd: &EtcdFixture,
    prefix: &str,
    upstream_port: u16,
) -> (u16, u16, u16, PingsixGuard) {
    let listen_port = random_port();
    let status_port = random_port();
    let admin_port = random_port();
    let yaml = etcd_config_yaml(&EtcdModeConfig {
        listen_port,
        status_port,
        admin_port,
        etcd_endpoint: etcd.endpoint.clone(),
        prefix: prefix.to_string(),
        stale_after: 300,
        dns_timeout: 5,
        prometheus_port: None,
    });
    let config_path = write_config(listen_port, &yaml);
    let child = spawn_pingsix(&config_path);
    let guard = PingsixGuard::new(listen_port, config_path, child);

    assert!(wait_until_status(
        status_port,
        "/status/live",
        200,
        Duration::from_secs(15)
    ));

    let node = format!("127.0.0.1:{upstream_port}");
    let up = admin_put(admin_port, "upstreams", "1", &upstream_nodes(&node));
    assert_eq!(up.status, 200, "{}", up.body);

    let route = admin_put(
        admin_port,
        "routes",
        "1",
        &serde_json::json!({
            "uri": "/cache",
            "upstream_id": "1",
            "plugins": {
                "cache": { "ttl": 120 }
            }
        }),
    );
    assert_eq!(route.status, 200, "{}", route.body);
    assert!(wait_until_ready(status_port, Duration::from_secs(20)));
    assert!(wait_until_admin_ready(admin_port, Duration::from_secs(10)));

    (listen_port, status_port, admin_port, guard)
}

fn warm_and_assert_cached(listen_port: u16, upstream: &MockUpstream, needle: &str) {
    let addr = format!("127.0.0.1:{listen_port}");
    let first = http_get(&addr, "/cache").expect("first request");
    assert_eq!(first.status, 200, "{}", first.body);
    assert!(
        first.body.contains(needle),
        "warm miss body={}, want {needle}",
        first.body
    );
    let hits_after_miss = upstream.hits();
    let second = http_get(&addr, "/cache").expect("second request");
    assert_eq!(second.status, 200, "{}", second.body);
    assert!(
        second.body.contains(needle),
        "warm hit body={}, want {needle}",
        second.body
    );
    assert_eq!(
        upstream.hits(),
        hits_after_miss,
        "second request must be served from cache"
    );
}

#[test]
fn cache_nodes_switch_invalidates_namespace() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream_a = MockUpstream::start(MockUpstreamConfig {
        body: "from-a".into(),
        ..Default::default()
    });
    let upstream_b = MockUpstream::start(MockUpstreamConfig {
        body: "from-b".into(),
        ..Default::default()
    });

    let (listen_port, _status, admin_port, _guard) =
        boot_cached_route(&etcd, &prefix, upstream_a.port);
    warm_and_assert_cached(listen_port, &upstream_a, "from-a");

    let put = admin_put(
        admin_port,
        "upstreams",
        "1",
        &upstream_nodes(&format!("127.0.0.1:{}", upstream_b.port)),
    );
    assert_eq!(put.status, 200, "{}", put.body);
    assert!(
        wait_until_proxy_body(listen_port, "/cache", "from-b", Duration::from_secs(20)),
        "after nodes switch, cache must not return upstream A"
    );
}

#[test]
fn cache_upstream_host_switch_invalidates_namespace() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        echo_host: true,
        body: "unused".into(),
        ..Default::default()
    });

    let (listen_port, _status, admin_port, _guard) =
        boot_cached_route(&etcd, &prefix, upstream.port);

    // Default pass_host leaves client Host (localhost) on the upstream request.
    warm_and_assert_cached(listen_port, &upstream, "localhost");

    let put = admin_put(
        admin_port,
        "upstreams",
        "1",
        &serde_json::json!({
            "nodes": { format!("127.0.0.1:{}", upstream.port): 1 },
            "type": "roundrobin",
            "pass_host": "rewrite",
            "upstream_host": "tenant-b.internal"
        }),
    );
    assert_eq!(put.status, 200, "{}", put.body);
    assert!(
        wait_until_proxy_body(
            listen_port,
            "/cache",
            "tenant-b.internal",
            Duration::from_secs(20)
        ),
        "after upstream_host rewrite, cache must not return old Host identity"
    );
}

#[test]
fn cache_response_plugin_switch_invalidates_namespace() {
    if !docker_available() {
        return;
    }
    let etcd = EtcdFixture::start();
    let prefix = etcd.unique_prefix();
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "origin-body".into(),
        ..Default::default()
    });

    let (listen_port, _status, admin_port, _guard) =
        boot_cached_route(&etcd, &prefix, upstream.port);
    warm_and_assert_cached(listen_port, &upstream, "origin-body");

    let put = admin_put(
        admin_port,
        "routes",
        "1",
        &serde_json::json!({
            "uri": "/cache",
            "upstream_id": "1",
            "plugins": {
                "cache": { "ttl": 120 },
                "response-rewrite": {
                    "headers": { "X-Rewritten": "v2" }
                }
            }
        }),
    );
    assert_eq!(put.status, 200, "{}", put.body);

    let addr = format!("127.0.0.1:{listen_port}");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let resp = http_get(&addr, "/cache").expect("probe");
        let has = resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-rewritten") && v == "v2");
        if has {
            assert!(
                resp.body.contains("origin-body"),
                "rewritten response should still carry origin body"
            );
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "expected X-Rewritten after plugin update; headers={:?} body={}",
                resp.headers, resp.body
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
