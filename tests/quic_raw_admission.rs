//! End-to-end coverage for process-wide raw QUIC admission.
//!
//! Two independent QUIC listeners share one `SNI_GATE_QUIC_MAX_RAW_FLOWS`
//! semaphore. With the limit set to one, a live raw flow on listener A must
//! prevent listener B from creating another flow. Once A becomes idle and is
//! torn down, listener B must be able to establish normally, proving the permit
//! is returned with the flow lifetime rather than leaked.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::PrivatePkcs8KeyDer;

const SNI_ONE: &str = "one.raw-admission.test";
const SNI_TWO: &str = "two.raw-admission.test";

#[test]
fn raw_flow_limit_is_process_wide_and_releases() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    runtime.block_on(async {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
            SNI_ONE.to_string(),
            SNI_TWO.to_string(),
        ])
        .expect("test certificate");
        let cert_der = cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key.into())
                .expect("QUIC server config");
        let upstream = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        )
        .expect("bind QUIC upstream");
        let upstream_port = upstream.local_addr().unwrap().port();

        let accept_endpoint = upstream.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                tokio::spawn(async move {
                    if let Ok(connection) = incoming.await {
                        let _ = connection.closed().await;
                    }
                });
            }
        });

        let dir = tempdir();
        let first_port = free_udp_port();
        let second_port = loop {
            let candidate = free_udp_port();
            if candidate != first_port {
                break candidate;
            }
        };
        let config = format!(
            r#"
[global]
resolver = "system"
unmatched = "close"

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "QUIC Raw Admission E2E CA"
leaf_validity_days = 90

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:{first_port}"
transport = "quic"
idle_timeout = "300ms"

  [[listener.route]]
  name = "raw-one"
  type = "raw"
  match_sni = ["{SNI_ONE}"]
  upstream = "127.0.0.1:{upstream_port}"

[[listener]]
addr = "127.0.0.1:{second_port}"
transport = "quic"
idle_timeout = "300ms"

  [[listener.route]]
  name = "raw-two"
  type = "raw"
  match_sni = ["{SNI_TWO}"]
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

        let first = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .connect(
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), first_port),
                    SNI_ONE,
                )
                .expect("start first raw connection"),
        )
        .await
        .expect("first raw QUIC handshake timed out")
        .expect("first raw QUIC handshake");

        // The historical 4096-flow ceiling was per listener. The environment
        // limit below is one process-wide slot, so listener B must be unable to
        // establish while listener A owns it.
        let second_attempt = client
            .connect(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), second_port),
                SNI_TWO,
            )
            .expect("start capacity-rejected raw connection");
        match tokio::time::timeout(Duration::from_millis(800), second_attempt).await {
            Ok(Ok(connection)) => {
                connection.close(0u32.into(), b"unexpected admission success");
                panic!("second raw flow established while process-wide limit was occupied");
            }
            Ok(Err(_)) | Err(_) => {}
        }

        first.close(0u32.into(), b"release admission slot");

        // Raw passthrough is intentionally protocol-blind after routing. The
        // forwarding task releases its active-flow permit on the configured
        // application idle timeout, not by interpreting QUIC CONNECTION_CLOSE.
        tokio::time::sleep(Duration::from_secs(1)).await;

        let third = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .connect(
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), second_port),
                    SNI_TWO,
                )
                .expect("start raw connection after release"),
        )
        .await
        .expect("raw QUIC handshake after release timed out")
        .expect("raw QUIC handshake after release");
        third.close(0u32.into(), b"test complete");

        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
        upstream.close(0u32.into(), b"test complete");
        accept_task.abort();
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
        .env("SNI_GATE_QUIC_MAX_RAW_FLOWS", "1")
        .env("SNI_GATE_QUIC_MAX_PENDING_RAW_CONNECTS", "8")
        .spawn()
        .expect("spawn sni-gate");
    ChildGuard(child)
}

async fn wait_for_gateway_start(workdir: &Path) {
    let ca = workdir.join("ca").join("ca.crt");
    for _ in 0..100 {
        if ca.exists() {
            tokio::time::sleep(Duration::from_millis(200)).await;
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
        "sni-gate-quic-raw-admission-{}-{}",
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
