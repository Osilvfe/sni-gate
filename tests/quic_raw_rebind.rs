//! Hermetic end-to-end coverage for raw QUIC source-port rebinding.
//!
//! A real Quinn client establishes one raw QUIC connection through sni-gate,
//! exchanges application data, switches the endpoint to a fresh UDP socket, and
//! exchanges more data on the same QUIC connection. This exercises FlowTable CID
//! ownership, peer migration, and response delivery to the latest client address
//! together instead of testing those pieces in isolation.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::PrivatePkcs8KeyDer;

const SNI: &str = "rebind.raw-quic.test";
const BEFORE_REBIND: &[u8] = b"before-rebind";
const AFTER_REBIND: &[u8] = b"after-rebind";

#[test]
fn raw_quic_connection_survives_client_udp_rebind() {
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

        let accept_endpoint = upstream.clone();
        let echo_task = tokio::spawn(async move {
            let incoming = accept_endpoint
                .accept()
                .await
                .expect("raw upstream connection");
            let connection = incoming.await.expect("raw upstream handshake");
            for _ in 0..2 {
                let (mut send, mut recv) =
                    connection.accept_bi().await.expect("bidirectional stream");
                let payload = recv
                    .read_to_end(64 * 1024)
                    .await
                    .expect("read test payload");
                send.write_all(&payload).await.expect("echo test payload");
                send.finish().expect("finish echo stream");
            }
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
common_name = "QUIC Raw Rebind E2E CA"
leaf_validity_days = 90

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:{gateway_port}"
transport = "quic"
connect_timeout = "2s"
idle_timeout = "5s"

  [[listener.route]]
  name = "raw-rebind"
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

        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .connect(
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), gateway_port),
                    SNI,
                )
                .expect("start raw QUIC connection"),
        )
        .await
        .expect("gateway raw QUIC handshake timed out")
        .expect("gateway raw QUIC handshake");

        exchange(&connection, BEFORE_REBIND).await;

        let old_addr = client.local_addr().expect("old QUIC client address");
        let new_socket =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind rebound UDP socket");
        new_socket
            .set_nonblocking(true)
            .expect("make rebound UDP socket nonblocking");
        let new_addr = new_socket.local_addr().expect("new QUIC client address");
        assert_ne!(old_addr, new_addr);
        client
            .rebind(new_socket)
            .expect("rebind QUIC client endpoint");
        assert_eq!(client.local_addr().unwrap(), new_addr);

        tokio::time::timeout(Duration::from_secs(5), exchange(&connection, AFTER_REBIND))
            .await
            .expect("raw QUIC traffic did not recover after client UDP rebind");

        connection.close(0u32.into(), b"test complete");
        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
        upstream.close(0u32.into(), b"test complete");
        echo_task.await.expect("QUIC echo task");
    });
}

async fn exchange(connection: &quinn::Connection, payload: &[u8]) {
    let (mut send, mut recv) = connection.open_bi().await.expect("open test stream");
    send.write_all(payload).await.expect("send test payload");
    send.finish().expect("finish test request");
    let echoed = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
        .await
        .expect("echo timed out")
        .expect("read echoed payload");
    assert_eq!(echoed, payload);
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
        "sni-gate-quic-raw-rebind-{}-{}",
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
