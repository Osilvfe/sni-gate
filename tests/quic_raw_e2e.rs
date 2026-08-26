//! Hermetic end-to-end coverage for the raw QUIC passthrough path.
//!
//! A real Quinn client connects to the gateway with SNI, the gateway inspects
//! only the QUIC Initial to select a `raw` route, and the untouched datagrams
//! complete a real QUIC handshake with a local Quinn echo server. This catches
//! regressions that packet-parser unit tests cannot: UDP ingress ownership,
//! Initial buffering, NAT socket setup, bidirectional forwarding, and post-
//! handshake short-header traffic must all work together.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::PrivatePkcs8KeyDer;

const SNI: &str = "raw.quic.test";
const PAYLOAD: &[u8] = b"raw-quic-e2e-payload";

#[test]
fn raw_quic_route_preserves_a_real_quinn_connection() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    runtime.block_on(async {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SNI.to_string()]).expect("test certificate");
        let cert_der = cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key.into())
                .expect("QUIC server config");
        let upstream = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("bind QUIC echo server");
        let upstream_port = upstream.local_addr().unwrap().port();

        let echo_task = tokio::spawn(async move {
            let incoming = upstream.accept().await.expect("raw upstream connection");
            let connection = incoming.await.expect("raw upstream handshake");
            let (mut send, mut recv) = connection.accept_bi().await.expect("bidirectional stream");
            let payload = recv
                .read_to_end(64 * 1024)
                .await
                .expect("read test payload");
            send.write_all(&payload).await.expect("echo test payload");
            send.finish().expect("finish echo stream");

            // Keep the endpoint/connection alive until the client closes it.
            // Dropping the last handles immediately after `finish()` sends a
            // connection-level close that can race the peer observing the stream
            // FIN, which tests server lifetime rather than raw passthrough.
            let _ = connection.closed().await;
        });

        let dir = tempdir();
        let gateway_port = free_udp_port();
        let config = format!(
            r#"
[global]
resolver = "system"
unmatched = "close"

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "QUIC Raw E2E CA"
leaf_validity_days = 90

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:{gateway_port}"
transport = "quic"

  [[listener.route]]
  name = "raw-quic"
  type = "raw"
  match_sni = ["{SNI}"]
  upstream = "127.0.0.1:{upstream_port}"
"#
        );
        let _gateway = spawn_sni_gate(&config, dir.path());
        wait_for_gateway_start(dir.path()).await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust test QUIC server");
        let mut client = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .expect("bind QUIC client");
        client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots))
                .expect("QUIC client config"),
        );

        let connecting = client
            .connect(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), gateway_port),
                SNI,
            )
            .expect("start QUIC connection");
        let connection = tokio::time::timeout(Duration::from_secs(10), connecting)
            .await
            .expect("gateway QUIC handshake timed out")
            .expect("gateway raw QUIC handshake");

        let (mut send, mut recv) = connection.open_bi().await.expect("open test stream");
        send.write_all(PAYLOAD).await.expect("send test payload");
        send.finish().expect("finish test request");
        let echoed = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
            .await
            .expect("echo timed out")
            .expect("read echoed payload");
        assert_eq!(echoed, PAYLOAD);

        connection.close(0u32.into(), b"test complete");
        echo_task.await.expect("QUIC echo task");
    });
}

fn free_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind temporary UDP socket")
        .local_addr()
        .unwrap()
        .port()
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_sni_gate(config: &str, workdir: &Path) -> ChildGuard {
    std::fs::write(workdir.join("sni-gate.toml"), config).expect("write gateway config");
    let child = Command::new(env!("CARGO_BIN_EXE_sni-gate"))
        .arg("-c")
        .arg(workdir.join("sni-gate.toml"))
        .current_dir(workdir)
        .env("SNI_GATE_LOG", "warn")
        .spawn()
        .expect("spawn sni-gate");
    ChildGuard(child)
}

async fn wait_for_gateway_start(workdir: &Path) {
    // The CA is initialized before listeners are spawned. Once it appears, only
    // the cheap in-memory route/listener construction remains; a short grace
    // period avoids racing the UDP bind without relying on a TCP readiness port.
    let ca = workdir.join("ca").join("ca.crt");
    for _ in 0..100 {
        if ca.exists() {
            tokio::time::sleep(Duration::from_millis(150)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("sni-gate did not initialize its CA");
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut path = std::env::temp_dir();
    path.push(format!(
        "sni-gate-quic-raw-e2e-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create temporary test directory");
    TempDir(path)
}

struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
