//! Static YAML DNS-only upstream must fail fast (no empty publish).

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

#[test]
fn static_dns_only_upstream_exits_at_boot() {
    let listen_port = random_port();
    let status_port = random_port();
    let yaml = format!(
        r#"{}
pingsix:
  listeners:
    - address: "127.0.0.1:{listen_port}"
  status:
    address: "127.0.0.1:{status_port}"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "no-such-host.invalid:18080": 1
      type: roundrobin
"#,
        pingora_header(listen_port)
    );
    let config_path = write_config(listen_port, &yaml);

    let bin_path = env!("CARGO_BIN_EXE_pingsix");
    let mut child = Command::new(bin_path)
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(10) {
                    // If it somehow stayed up, it must not be ready with a published DNS graph.
                    let ready = http_status(&format!("127.0.0.1:{status_port}"), "/status/ready");
                    let _ = child.kill();
                    let _ = child.wait();
                    cleanup_runtime_files(listen_port, &config_path);
                    panic!("expected process exit for static DNS-only upstream; ready={ready:?}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("{e}"),
        }
    };

    cleanup_runtime_files(listen_port, &config_path);
    assert!(
        !status.success(),
        "static DNS-only upstream must fail boot, got {status:?}"
    );
}
