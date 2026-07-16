//! TLS certificate loading and handshake smoke tests.
//!
//! Verifies:
//! - testdata PEMs are readable
//! - `DynamicCert::new` accepts the pair (used by TLS listeners)
//! - a real TLS client (`openssl s_client`) completes a handshake against a
//!   spawned pingsix TLS listener with SNI `example.com`

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn testdata_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("proxy")
        .join("testdata")
        .join(name)
}

fn random_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_for_tcp(addr: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn testdata_certs_exist_and_are_readable() {
    let cert_path = testdata_path("example.crt");
    let key_path = testdata_path("example.key");
    assert!(cert_path.exists(), "example.crt not found at {cert_path:?}");
    assert!(key_path.exists(), "example.key not found at {key_path:?}");

    let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
    let key_pem = std::fs::read_to_string(&key_path).unwrap();
    assert!(cert_pem.contains("BEGIN CERTIFICATE"), "invalid cert PEM");
    assert!(key_pem.contains("BEGIN"), "invalid key PEM");
}

#[test]
fn dynamic_cert_loads_testdata_certs() {
    use pingsix::config::Tls;
    use pingsix::proxy::ssl::DynamicCert;

    let cert_path = testdata_path("example.crt");
    let key_path = testdata_path("example.key");

    let tls_config = Tls {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
    };

    let result = DynamicCert::new(&tls_config);
    assert!(
        result.is_ok(),
        "DynamicCert should load testdata certs: {:?}",
        result.err()
    );
}

#[test]
fn tls_listener_completes_handshake_with_sni() {
    let listen_port = random_port();
    let status_port = random_port();
    let cert_path = testdata_path("example.crt");
    let key_path = testdata_path("example.key");

    let config_yaml = format!(
        r#"
pingora:
  version: 1
  threads: 1
  pid_file: /tmp/pingsix-tls-test-{listen_port}.pid
  upgrade_sock: /tmp/pingsix-tls-test-{listen_port}.sock
  grace_period_seconds: 1
  graceful_shutdown_timeout_seconds: 1

pingsix:
  listeners:
    - address: "127.0.0.1:{listen_port}"
      tls:
        cert_path: "{cert}"
        key_path: "{key}"
  status:
    address: "127.0.0.1:{status_port}"

routes: []
"#,
        cert = cert_path.display(),
        key = key_path.display(),
    );

    let config_path = format!("/tmp/pingsix-tls-test-config-{listen_port}.yaml");
    std::fs::write(&config_path, config_yaml).unwrap();

    let bin_path = env!("CARGO_BIN_EXE_pingsix");
    let mut child = Command::new(bin_path)
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn pingsix");

    let addr = format!("127.0.0.1:{listen_port}");
    assert!(
        wait_for_tcp(&addr, Duration::from_secs(15)),
        "TLS listener did not accept TCP on {addr}"
    );

    // Real TLS handshake + SNI. Trust the testdata cert as CA (self-signed).
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &addr,
            "-servername",
            "example.com",
            "-CAfile",
            &cert_path.to_string_lossy(),
            "-brief",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("openssl s_client failed to run");

    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(format!("/tmp/pingsix-tls-test-{listen_port}.pid"));
    let _ = std::fs::remove_file(format!("/tmp/pingsix-tls-test-{listen_port}.sock"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        output.status.success()
            || combined.contains("Verification: OK")
            || combined.contains("Verify return code: 0"),
        "TLS handshake with SNI example.com failed.\nstatus={:?}\n{combined}",
        output.status
    );
}
