//! SIGTERM graceful shutdown integration test.
//!
//! Spawns the pingsix binary with a minimal static config, waits until the
//! status endpoint reports ready, sends SIGTERM, and verifies:
//! - readiness becomes unavailable / process exits
//! - process exits cleanly within a timeout

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Create a minimal static config YAML that doesn't require any external
/// dependencies (no etcd, no real upstream). The proxy will start but won't
/// have any routes configured.
fn minimal_config(listen_port: u16, status_port: u16) -> String {
    format!(
        r#"
pingora:
  version: 1
  threads: 1
  pid_file: /tmp/pingsix-test-{listen_port}.pid
  upgrade_sock: /tmp/pingsix-test-{listen_port}.sock
  # Pingora defaults to a 300s grace period; keep the test fast and deterministic.
  grace_period_seconds: 1
  graceful_shutdown_timeout_seconds: 1

pingsix:
  listeners:
    - address: "127.0.0.1:{listen_port}"
  status:
    address: "127.0.0.1:{status_port}"

routes: []
"#
    )
}

/// Pick a random unused port by binding to port 0.
fn random_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn http_status(addr: &str, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(status)
}

fn wait_until_ready(status_port: u16, timeout: Duration) -> bool {
    let addr = format!("127.0.0.1:{status_port}");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if http_status(&addr, "/status/ready") == Some(200) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn sigterm_triggers_graceful_shutdown() {
    let listen_port = random_port();
    let status_port = random_port();
    let config_yaml = minimal_config(listen_port, status_port);

    let config_path = format!("/tmp/pingsix-test-config-{listen_port}.yaml");
    {
        let mut f = std::fs::File::create(&config_path).unwrap();
        f.write_all(config_yaml.as_bytes()).unwrap();
    }

    let bin_path = env!("CARGO_BIN_EXE_pingsix");
    let mut child = Command::new(bin_path)
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        // Do not pipe stdout/stderr: an unread pipe can fill and block the
        // child during shutdown logging, which looks like a hang after SIGTERM.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn pingsix binary");

    assert!(
        wait_until_ready(status_port, Duration::from_secs(15)),
        "pingsix did not become ready on status port {status_port}"
    );

    // Confirm proxy listener is accepting connections before shutdown.
    assert!(
        TcpStream::connect_timeout(
            &format!("127.0.0.1:{listen_port}").parse().unwrap(),
            Duration::from_secs(1),
        )
        .is_ok(),
        "proxy listener should accept connections while running"
    );

    // Send SIGTERM
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Wait for exit with timeout
    let start = Instant::now();
    let timeout = Duration::from_secs(20);
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("pingsix did not exit within {timeout:?} after SIGTERM");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("error waiting for child: {e}"),
        }
    };

    // Clean up pid/socket/config artifacts
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(format!("/tmp/pingsix-test-{listen_port}.pid"));
    let _ = std::fs::remove_file(format!("/tmp/pingsix-test-{listen_port}.sock"));

    assert!(
        exit_status.success() || exit_status.code().is_none(),
        "pingsix should exit cleanly on SIGTERM, got: {exit_status:?}"
    );

    // After exit, readiness endpoint must be gone.
    assert!(
        http_status(&format!("127.0.0.1:{status_port}"), "/status/ready").is_none(),
        "status endpoint should be unavailable after shutdown"
    );
}
