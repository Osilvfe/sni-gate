//! Release-mode stress baselines for transparent raw QUIC forwarding.
//!
//! The regular smoke test keeps CI coverage cheap. The 1k/4k cases are ignored
//! by default and are intended for explicit release-mode runs on a host with a
//! sufficiently high file-descriptor limit.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::task::JoinSet;

const SNI: &str = "stress.raw-quic.test";
const PAYLOAD: &[u8] = b"raw-quic-stress-echo";

#[test]
fn raw_quic_stress_harness_smoke() {
    run_stress(32, 16);
}

#[test]
#[ignore = "manual release-mode 1024-flow raw QUIC stress baseline"]
fn raw_quic_stress_1024_flows() {
    run_stress(1024, 64);
}

#[test]
#[ignore = "manual release-mode 4096-flow raw QUIC stress baseline"]
fn raw_quic_stress_4096_flows() {
    run_stress(4096, 64);
}

fn run_stress(flow_count: usize, connect_concurrency: usize) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    runtime.block_on(async move {
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
        .expect("bind QUIC upstream");
        let upstream_port = upstream.local_addr().unwrap().port();
        let accept_task = spawn_echo_accept_loop(&upstream);

        let dir = tempdir(flow_count);
        let gateway_port = free_udp_port();
        let config = format!(
            r#"
[global]
resolver = "system"
unmatched = "close"

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "QUIC Raw Stress CA"
leaf_validity_days = 90

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:{gateway_port}"
transport = "quic"
connect_timeout = "10s"
idle_timeout = "120s"

  [[listener.route]]
  name = "raw-stress"
  type = "raw"
  match_sni = ["{SNI}"]
  upstream = "127.0.0.1:{upstream_port}"
"#
        );
        let _gateway = spawn_sni_gate(&config, dir.path(), flow_count, connect_concurrency);
        wait_for_gateway_start(dir.path()).await;

        let client = quinn_client(&cert_der);
        let gateway_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), gateway_port);

        let connect_started = Instant::now();
        let connections =
            establish_connections(&client, gateway_addr, flow_count, connect_concurrency).await;
        let connect_elapsed = connect_started.elapsed();

        let echo_started = Instant::now();
        echo_all(&connections, connect_concurrency.max(64)).await;
        let echo_elapsed = echo_started.elapsed();

        eprintln!(
            "raw-quic stress: flows={flow_count} connect_concurrency={connect_concurrency} \
             connect={connect_elapsed:?} ({:.1} flows/s) echo={echo_elapsed:?} ({:.1} ops/s)",
            rate(flow_count, connect_elapsed),
            rate(flow_count, echo_elapsed),
        );

        for connection in connections {
            connection.close(0u32.into(), b"stress complete");
        }
        client.close(0u32.into(), b"stress complete");
        client.wait_idle().await;
        upstream.close(0u32.into(), b"stress complete");
        accept_task.abort();
    });
}

async fn establish_connections(
    client: &quinn::Endpoint,
    gateway_addr: SocketAddr,
    flow_count: usize,
    concurrency: usize,
) -> Vec<quinn::Connection> {
    assert!(concurrency > 0);
    let mut next = 0usize;
    let mut completed = Vec::with_capacity(flow_count);
    let mut pending = JoinSet::new();

    while completed.len() < flow_count {
        while next < flow_count && pending.len() < concurrency {
            let client = client.clone();
            pending.spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(20),
                    client
                        .connect(gateway_addr, SNI)
                        .expect("start raw QUIC stress connection"),
                )
                .await
                .expect("raw QUIC stress handshake timed out")
                .expect("raw QUIC stress handshake")
            });
            next += 1;
        }

        let connection = pending
            .join_next()
            .await
            .expect("pending stress connection")
            .expect("stress connection task");
        completed.push(connection);
    }

    completed
}

async fn echo_all(connections: &[quinn::Connection], concurrency: usize) {
    let mut next = 0usize;
    let mut completed = 0usize;
    let mut pending = JoinSet::new();

    while completed < connections.len() {
        while next < connections.len() && pending.len() < concurrency {
            let connection = connections[next].clone();
            pending.spawn(async move {
                let (mut send, mut recv) = connection.open_bi().await.expect("open stress stream");
                send.write_all(PAYLOAD).await.expect("send stress payload");
                send.finish().expect("finish stress request");
                let echoed = tokio::time::timeout(
                    Duration::from_secs(10),
                    recv.read_to_end(64 * 1024),
                )
                .await
                .expect("stress echo timed out")
                .expect("read stress echo");
                assert_eq!(echoed, PAYLOAD);
            });
            next += 1;
        }

        pending
            .join_next()
            .await
            .expect("pending stress echo")
            .expect("stress echo task");
        completed += 1;
    }
}

fn spawn_echo_accept_loop(endpoint: &quinn::Endpoint) -> tokio::task::JoinHandle<()> {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                loop {
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        break;
                    };
                    tokio::spawn(async move {
                        let payload = recv
                            .read_to_end(64 * 1024)
                            .await
                            .expect("read stress payload");
                        send.write_all(&payload).await.expect("echo stress payload");
                        send.finish().expect("finish stress echo");
                    });
                }
            });
        }
    })
}

fn quinn_client(cert_der: &CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("trust stress QUIC server");
    let mut client = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("bind QUIC stress client");
    client.set_default_client_config(
        quinn::ClientConfig::with_root_certificates(Arc::new(roots))
            .expect("QUIC stress client config"),
    );
    client
}

fn rate(operations: usize, elapsed: Duration) -> f64 {
    operations as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE)
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

fn tempdir(flow_count: usize) -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut path = std::env::temp_dir();
    path.push(format!(
        "sni-gate-quic-raw-stress-{flow_count}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create temporary stress directory");
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
