//! Regression coverage for the shared QUIC ingress boundary.
//!
//! An oversized UDP datagram must be dropped locally. It must never surface as
//! a fatal `AsyncUdpSocket` receive error that tears down the Quinn endpoint for
//! every H3 client on the listener.

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::RootCertStore;

const TEST_SNI: &str = "alive.h3.test";

#[test]
fn oversized_udp_does_not_kill_h3_endpoint() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = tempdir();
    let quic_port = free_udp_port();
    let ready_port = free_tcp_port();

    // Keep a UDP port open but intentionally do not speak QUIC. After the
    // inbound handshake the gateway will spend its connect timeout trying this
    // upstream, leaving the successfully-established inbound connection alive
    // long enough for this test to inspect its negotiated ALPN.
    let upstream = UdpSocket::bind("127.0.0.1:0").expect("bind dummy H3 upstream");
    let upstream_port = upstream.local_addr().unwrap().port();

    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "H3 resilience E2E CA"
leaf_validity_days = 90

[psl]
source = "embedded"

# Put QUIC first so it is spawned before the TCP readiness listener below.
[[listener]]
addr = "127.0.0.1:{quic_port}"
transport = "quic"
  [[listener.route]]
  name = "h3-alive"
  type = "h3"
  match_sni = ["{TEST_SNI}"]
  upstream = "127.0.0.1:{upstream_port}"
  override_sni = "{TEST_SNI}"
  connect_timeout = "5s"

# A TCP listener gives us an observable startup barrier. No route is required:
# the readiness connection is simply closed by the global unmatched policy.
[[listener]]
addr = "127.0.0.1:{ready_port}"
transport = "tcp"
"#
    );
    let _gateway = spawn_sni_gate(&config, dir.path());
    wait_tcp_port(ready_port);

    // Quinn's endpoint config determines the receive-buffer contract used by
    // SharedQuicSocket. Send a packet exactly one byte above that contract. The
    // IPv4 UDP payload ceiling is 65,507 bytes, so fail loudly if a future Quinn
    // default grows beyond what an on-wire regression test can exercise.
    let quinn_cap = quinn::EndpointConfig::default().get_max_udp_payload_size() as usize;
    assert!(
        quinn_cap < 65_507,
        "Quinn max UDP payload {quinn_cap} leaves no valid oversized IPv4 datagram"
    );
    let oversized = vec![0u8; quinn_cap + 1];
    let attacker = UdpSocket::bind("127.0.0.1:0").expect("bind attacker UDP socket");
    for _ in 0..5 {
        attacker
            .send_to(&oversized, ("127.0.0.1", quic_port))
            .expect("send oversized UDP datagram");
        std::thread::sleep(Duration::from_millis(20));
    }

    let ca_path = dir.path().join("ca").join("ca.crt");
    wait_file(&ca_path);
    let ca_pem = std::fs::read(&ca_path).expect("read generated CA certificate");

    let runtime = tokio::runtime::Runtime::new().expect("create Tokio runtime");
    runtime.block_on(async move {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            roots
                .add(cert.expect("parse generated CA certificate"))
                .unwrap();
        }

        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicClientConfig::try_from(tls).expect("build Quinn client crypto");
        let client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("bind Quinn test client");

        let connecting = endpoint
            .connect_with(
                client_config,
                std::net::SocketAddr::from(([127, 0, 0, 1], quic_port)),
                TEST_SNI,
            )
            .expect("start QUIC connection after oversized ingress");
        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("QUIC handshake timed out after oversized ingress")
            .expect("QUIC endpoint was not usable after oversized ingress");

        let protocol = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol.clone());
        assert_eq!(protocol.as_deref(), Some(&b"h3"[..]));
        connection.close(0u32.into(), b"resilience test complete");
        endpoint.wait_idle().await;
    });

    drop(upstream);
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_tcp_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("TCP readiness port {port} never came up");
}

fn wait_file(path: &std::path::Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("file {} was never created", path.display());
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_sni_gate(config: &str, workdir: &std::path::Path) -> ChildGuard {
    std::fs::write(workdir.join("sni-gate.toml"), config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_sni-gate"))
        .arg("-c")
        .arg(workdir.join("sni-gate.toml"))
        .current_dir(workdir)
        .env("SNI_GATE_LOG", "warn")
        .spawn()
        .expect("spawn sni-gate");
    ChildGuard(child)
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut path = std::env::temp_dir();
    path.push(format!(
        "sni-gate-quic-resilience-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
