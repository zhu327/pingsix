//! Protocol security defaults: auth, CORS, cache (static YAML, no etcd).

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::*;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn make_jwt(secret: &str) -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600;
    encode(
        &Header::new(Algorithm::HS256),
        &Claims {
            sub: "user".into(),
            exp,
        },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn static_config(listen_port: u16, status_port: u16, routes_yaml: &str) -> String {
    format!(
        r#"{}
pingsix:
  listeners:
    - address: "127.0.0.1:{listen_port}"
  status:
    address: "127.0.0.1:{status_port}"

{routes_yaml}
"#,
        pingora_header(listen_port)
    )
}

fn spawn_static(
    listen_port: u16,
    status_port: u16,
    routes_yaml: &str,
) -> (String, std::process::Child) {
    let yaml = static_config(listen_port, status_port, routes_yaml);
    let config_path = write_config(listen_port, &yaml);
    let child = spawn_pingsix(&config_path);
    assert!(
        wait_until_ready(status_port, Duration::from_secs(15)),
        "static config should become ready"
    );
    (config_path, child)
}

#[test]
fn auth1_jwt_query_disabled_by_default() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let secret = "jwt-test-secret";
    let token = make_jwt(secret);

    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      jwt-auth:
        secret: "{secret}"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let via_query = http_get(&addr, &format!("/?jwt={token}")).unwrap();
    assert_eq!(
        via_query.status, 401,
        "query jwt must be ignored by default: {}",
        via_query.body
    );

    let via_header = http_exchange(
        &addr,
        "GET",
        "/",
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    )
    .unwrap();
    assert_eq!(via_header.status, 200, "{}", via_header.body);

    // Explicit query enable.
    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);

    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      jwt-auth:
        secret: "{secret}"
        query: jwt
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");
    let via_query = http_get(&addr, &format!("/?jwt={token}")).unwrap();
    assert_eq!(
        via_query.status, 200,
        "enabled query jwt: {}",
        via_query.body
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn auth2_key_auth_query_disabled_by_default() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      key-auth:
        keys: ["my-api-key"]
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let via_query = http_get(&addr, "/?apikey=my-api-key").unwrap();
    assert_eq!(via_query.status, 401, "query key-auth disabled by default");

    let via_header = http_exchange(&addr, "GET", "/", &[("apikey", "my-api-key")], None).unwrap();
    assert_eq!(via_header.status, 200, "{}", via_header.body);

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cors1_bare_options_is_not_preflight() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "options-app".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    methods: ["GET", "OPTIONS"]
    plugins:
      cors:
        allow_origins: "*"
        allow_methods: "**"
        allow_headers: "*"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let resp = http_exchange(
        &addr,
        "OPTIONS",
        "/",
        &[("Origin", "https://example.com")],
        None,
    )
    .unwrap();
    // Not a CORS preflight short-circuit (204); should reach upstream or normal handling.
    assert_ne!(
        resp.status, 204,
        "bare OPTIONS must not be treated as preflight"
    );
    assert!(
        !resp
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))
            || resp.body.contains("options-app"),
        "unexpected preflight-style response: status={} headers={:?}",
        resp.status,
        resp.headers
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cors2_real_preflight_returns_acao() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    methods: ["GET"]
    plugins:
      cors:
        allow_origins: "**"
        allow_methods: "**"
        allow_headers: "**"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    upstream.reset_hits();
    let resp = http_exchange(
        &addr,
        "OPTIONS",
        "/",
        &[
            ("Origin", "https://example.com"),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "X-Custom"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(resp.status, 204, "preflight status: {}", resp.body);
    let acao = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"));
    assert!(acao.is_some(), "missing ACAO in {:?}", resp.headers);
    let vary = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("vary"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(
        vary.to_ascii_lowercase().contains("origin")
            || vary
                .to_ascii_lowercase()
                .contains("access-control-request-headers"),
        "expected Vary merge, got {vary:?}"
    );
    assert_eq!(upstream.hits(), 0, "preflight must not hit upstream");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cache1_vary_star_not_cached() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "vary-star".into(),
        headers: vec![("Vary".into(), "*".into())],
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      cache:
        ttl: 60
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    let after_first = upstream.hits();
    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    assert!(
        upstream.hits() > after_first,
        "Vary: * response must not be served from shared cache"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cache2_authorization_bypasses_cache() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "auth-body".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      cache:
        ttl: 60
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let _ = http_exchange(&addr, "GET", "/", &[("Authorization", "Bearer x")], None).unwrap();
    let after_first = upstream.hits();
    let _ = http_exchange(&addr, "GET", "/", &[("Authorization", "Bearer x")], None).unwrap();
    assert!(
        upstream.hits() > after_first,
        "authenticated requests must bypass cache by default"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cache3_set_cookie_not_cached() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "cookie-body".into(),
        headers: vec![("Set-Cookie".into(), "sid=1".into())],
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      cache:
        ttl: 60
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    let after_first = upstream.hits();
    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    assert!(
        upstream.hits() > after_first,
        "Set-Cookie responses must not be cached by default"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn status1_config_diagnostics_on_loopback() {
    let listen_port = random_port();
    let status_port = random_port();
    let routes = r#"
routes: []
"#;
    let (config_path, mut child) = spawn_static(listen_port, status_port, routes);

    let live = http_get(&format!("127.0.0.1:{status_port}"), "/status/live").unwrap();
    assert_eq!(live.status, 200);
    let cfg = http_get(&format!("127.0.0.1:{status_port}"), "/status/config").unwrap();
    assert_eq!(cfg.status, 200, "{}", cfg.body);
    let view: serde_json::Value = serde_json::from_str(&cfg.body).unwrap();
    assert_eq!(view["ready"], true);
    assert_eq!(view["config_source"], "yaml");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}
