//! End-to-end coverage for process-wide raw QUIC upstream-setup admission.
//!
//! The pending-connect semaphore is intentionally shorter-lived than the active
//! raw-flow semaphore: it protects DNS/socket/Happy-Eyeballs setup only. These
//! checks prove that a successful raw flow returns the setup permit while the
//! flow remains alive, and that a timed-out setup returns the permit on failure.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const SNI_ONE: &str = "one.raw-connect.test";
const SNI_TWO: &str = "two.raw-connect.test";
const SNI_BLACKHOLE: &str = "blackhole.raw-connect.test";

#[test]
fn raw_connect_slot_releases_after_success_while_flow_stays_active() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    runtime.block_on(async {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SNI_ONE.to_string(), SNI_TWO.to_string()])
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
        let accept_task = spawn_accept_loop(&upstream);

        let dir = tempdir("success");
        let first_port = free_udp_port();
        let second_port = distinct_udp_port(first_port);
        let config = format!(
            r#"
[global]
resolver = "system"
unmatched = "close"

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "QUIC Raw Connect Lifecycle CA"
leaf_validity_days = 90

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:{first_port}"
transport = "quic"
connect_timeout = "2s"
idle_timeout = "5s"

  [[listener.route]]
  name = "raw-one"
  type = "raw"
  match_sni = ["{SNI_ONE}"]
  upstream = "127.0.0.1:{upstream_port}"

[[listener]]
addr = "127.0.0.1:{second_port}"
transport = "quic"
connect_timeout = "2s"
idle_timeout = "5s"

  [[listener.route]]
  name = "raw-two"
  type = "raw"
  match_sni = ["{SNI_TWO}"]
  upstream = "127.0.0.1:{upstream_port}"
"#
        );
        let _gateway = spawn_sni_gate(&config, dir.path(), 4, 1);
        wait_for_gateway_start(dir.path()).await;

        let client = quinn_client(&cert_der);
        let first = connect(
            &client,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), first_port),
            SNI_ONE,
        )
        .await;

        // max_pending_raw_connects=1. If the setup permit were accidentally
        // retained for the whole raw-flow lifetime, this second handshake would
        // be unable to start while `first` is deliberately kept alive.
        let second = connect(
            &client,
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), second_port),
            SNI_TWO,
        )
        .await;

        first.close(0u32.into(), b"test complete");
        second.close(0u32.into(), b"test complete");
        client.close(0u32.into(), b"test complete");
        client.wait_idle().await;
        upstream.close(0u32.into(), b"test complete");
        accept_task.abort();
    });
}

#[test]
fn raw_connect_slot_releases_after_upstream_timeout() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    runtime.block_on(async {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SNI_TWO.to_string()])
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
        let accept_task = spawn_accept_loop(&upstream);

        // Bind a real UDP socket so the raw Happy-Eyeballs attempt does not get
        // an immediate ICMP port-unreachable error. It consumes the first flight
        // but never replies, deterministically holding the one setup permit until
        // the route connect timeout fires.
        let blackhole = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP blackhole");
        let blackhole_port = blackhole.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let blackhole_task = tokio::spawn(async move {
            let mut seen_tx = Some(seen_tx);
            let mut buf = [0u8; 65_535];
            while blackhole.recv_from(&mut buf).await.is_ok() {
                if let Some(tx) = seen_tx.take() {
                    let _ = tx.send(());
                }
            }
        });

        let dir = tempdir("timeout");
        let blackhole_listener = free_udp_port();
        let working_listener = distinct_udp_port(blackhole_listener);
        let config = format!(
            r#"
[global]
resolver = "system"
unmatched = "close"

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "QUIC Raw Connect Timeout CA"
leaf_validity_days = 90

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:{blackhole_listener}"
transport = "quic"
connect_timeout = "1500ms"
idle_timeout = "5s"

  [[listener.route]]
  name = "raw-blackhole"
  type = "raw"
  match_sni = ["{SNI_BLACKHOLE}"]
  upstream = "127.0.0.1:{blackhole_port}"

[[listener]]
addr = "127.0.0.1:{working_listener}"
transport = "quic"
connect_timeout = "2s"
idle_timeout = "5s"

  [[listener.route]]
  name = "raw-working"
  type = "raw"
  match_sni = ["{SNI_TWO}"]
  upstream = "127.0.0.1:{upstream_port}"
"#
        );
        let _gateway = spawn_sni_gate(&config, dir.path(), 4, 1);
        wait_for_gateway_start(dir.path()).await;

        let blocked_client = quinn_client(&cert_der);
        let blocked_connecting = blocked_client
            .connect(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), blackhole_listener),
                SNI_BLACKHOLE,
            )
            .expect("start blackholed raw connection");
        let blocked_task = tokio::spawn(async move {
            let _ = blocked_connecting.await;
        });

        tokio::time::timeout(Duration::from_secs(2), seen_rx)
            .await
            .expect("raw blackhole did not receive the initial flight")
            .expect("blackhole observation channel closed");
        // Stop client retransmissions from starting another blackholed flow once
        // the current setup times out. The gateway still owns the in-flight setup
        // and therefore keeps the process-wide permit until its 1500ms timeout.
        blocked_client.close(0u32.into(), b"stop retransmissions");

        let working_client = quinn_client(&cert_der);
        let mut working = Box::pin(
            working_client
                .connect(
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), working_listener),
                    SNI_TWO,
                )
                .expect("start working raw connection while setup slot is occupied"),
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(400), working.as_mut())
                .await
                .is_err(),
            "working raw connection established before the blackholed setup released its permit"
        );

        // The same Quinn connection keeps retransmitting Initial packets. Once
        // the blackholed setup reaches its route timeout, a later retransmission
        // can be admitted and the healthy upstream handshake must complete.
        let connection = tokio::time::timeout(Duration::from_secs(5), working)
            .await
            .expect("working raw connection did not recover after setup timeout")
            .expect("working raw connection after setup timeout");

        connection.close(0u32.into(), b"test complete");
        working_client.close(0u32.into(), b"test complete");
        working_client.wait_idle().await;
        blocked_task.abort();
        blackhole_task.abort();
        upstream.close(0u32.into(), b"test complete");
        accept_task.abort();
    });
}

fn quinn_client(cert_der: &CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust test QUIC server");
    let mut client = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("bind QUIC client");
    client.set_default_client_config(
        quinn::ClientConfig::with_root_certificates(Arc::new(roots)).expect("QUIC client config"),
    );
    client
}

async fn connect(client: &quinn::Endpoint, addr: SocketAddr, sni: &str) -> quinn::Connection {
    tokio::time::timeout(
        Duration::from_secs(10),
        client
            .connect(addr, sni)
            .expect("start raw QUIC connection"),
    )
    .await
    .expect("raw QUIC handshake timed out")
    .expect("raw QUIC handshake")
}

fn spawn_accept_loop(endpoint: &quinn::Endpoint) -> tokio::task::JoinHandle<()> {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    let _ = connection.closed().await;
                }
            });
        }
    })
}

fn free_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind temporary UDP socket")
        .local_addr()
        .unwrap()
        .port()
}

fn distinct_udp_port(other: u16) -> u16 {
    loop {
        let candidate = free_udp_port();
        if candidate != other {
            return candidate;
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_sni_gate(
    config: &str,
    workdir: &Path,
    max_raw_flows: usize,
    max_pending_raw_connects: usize,
) -> ChildGuard {
    std::fs::write(workdir.join("sni-gate.toml"), config).expect("write gateway config");
    let child = Command::new(env!("CARGO_BIN_EXE_sni-gate"))
        .arg("-c")
        .arg(workdir.join("sni-gate.toml"))
        .current_dir(workdir)
        .env("SNI_GATE_LOG", "warn")
        .env("SNI_GATE_QUIC_MAX_RAW_FLOWS", max_raw_flows.to_string())
        .env(
            "SNI_GATE_QUIC_MAX_PENDING_RAW_CONNECTS",
            max_pending_raw_connects.to_string(),
        )
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

fn tempdir(label: &str) -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut path = std::env::temp_dir();
    path.push(format!(
        "sni-gate-quic-raw-connect-{label}-{}-{}",
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
