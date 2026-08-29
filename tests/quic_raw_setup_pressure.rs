//! Manual pressure baseline for raw QUIC upstream-setup admission.
//!
//! One Quinn client endpoint starts many raw QUIC handshakes toward a UDP
//! blackhole while the gateway exposes a much smaller process-wide pending
//! setup budget. After the flood stops, a healthy raw connection measures how
//! quickly admission capacity becomes usable again.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::task::JoinSet;

const FLOOD_SNI: &str = "flood.raw-pressure.test";
const HEALTHY_SNI: &str = "healthy.raw-pressure.test";
const FLOOD_ATTEMPTS: usize = 1024;
const MAX_PENDING_RAW_CONNECTS: usize = 64;
const FLOOD_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const FLOOD_WINDOW: Duration = Duration::from_millis(500);
const MIN_EXPECTED_RECOVERY: Duration = Duration::from_secs(1);

#[test]
#[ignore = "manual release-mode raw QUIC setup pressure baseline"]
fn raw_quic_setup_pressure_recovers_after_1024_attempts() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    runtime.block_on(async {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
            FLOOD_SNI.to_string(),
            HEALTHY_SNI.to_string(),
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
        .expect("bind healthy QUIC upstream");
        let upstream_port = upstream.local_addr().unwrap().port();
        let accept_task = spawn_accept_loop(&upstream);

        let blackhole = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP blackhole");
        let blackhole_port = blackhole.local_addr().unwrap().port();
        let observed = Arc::new(AtomicUsize::new(0));
        let blackhole_task = {
            let observed = observed.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65_535];
                while blackhole.recv_from(&mut buf).await.is_ok() {
                    observed.fetch_add(1, Ordering::Relaxed);
                }
            })
        };

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
common_name = "QUIC Raw Setup Pressure CA"
leaf_validity_days = 90

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:{gateway_port}"
transport = "quic"
connect_timeout = "750ms"
idle_timeout = "10s"

  [[listener.route]]
  name = "raw-flood"
  type = "raw"
  match_sni = ["{FLOOD_SNI}"]
  upstream = "127.0.0.1:{blackhole_port}"
  connect_timeout = "3s"

  [[listener.route]]
  name = "raw-healthy"
  type = "raw"
  match_sni = ["{HEALTHY_SNI}"]
  upstream = "127.0.0.1:{upstream_port}"
"#
        );
        let _gateway = spawn_sni_gate(&config, dir.path());
        wait_for_gateway_start(dir.path()).await;

        let gateway_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), gateway_port);
        let flood_client = quinn_client(&cert_der);
        let mut flood_tasks = JoinSet::new();
        for _ in 0..FLOOD_ATTEMPTS {
            let client = flood_client.clone();
            flood_tasks.spawn(async move {
                let connecting = client
                    .connect(gateway_addr, FLOOD_SNI)
                    .expect("start blackholed raw QUIC connection");
                let _ = connecting.await;
            });
        }

        tokio::time::sleep(FLOOD_WINDOW).await;
        let observed_datagrams = observed.load(Ordering::Relaxed);
        assert!(
            observed_datagrams > 0,
            "setup pressure never reached the UDP blackhole"
        );

        flood_client.close(0u32.into(), b"stop setup pressure");
        flood_tasks.abort_all();
        drop(flood_tasks);

        let healthy_client = quinn_client(&cert_der);
        let recovery_started = Instant::now();
        let healthy = tokio::time::timeout(
            Duration::from_secs(6),
            healthy_client
                .connect(gateway_addr, HEALTHY_SNI)
                .expect("start healthy raw QUIC connection"),
        )
        .await
        .expect("healthy raw QUIC connection did not recover after setup pressure")
        .expect("healthy raw QUIC handshake after setup pressure");
        let recovery_elapsed = recovery_started.elapsed();
        assert!(
            recovery_elapsed >= MIN_EXPECTED_RECOVERY,
            "setup pressure did not keep raw connect admission saturated long enough: recovered in {recovery_elapsed:?}"
        );

        eprintln!(
            "raw-quic setup pressure: attempts={FLOOD_ATTEMPTS} max_pending={} \
             flood_connect_timeout={FLOOD_CONNECT_TIMEOUT:?} flood_window={FLOOD_WINDOW:?} \
             upstream_datagrams={observed_datagrams} recovery={recovery_elapsed:?}",
            MAX_PENDING_RAW_CONNECTS,
        );

        healthy.close(0u32.into(), b"pressure baseline complete");
        healthy_client.close(0u32.into(), b"pressure baseline complete");
        healthy_client.wait_idle().await;
        blackhole_task.abort();
        upstream.close(0u32.into(), b"pressure baseline complete");
        accept_task.abort();
    });
}

fn quinn_client(cert_der: &CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("trust pressure-test QUIC server");
    let mut client = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
        .expect("bind QUIC pressure client");
    client.set_default_client_config(
        quinn::ClientConfig::with_root_certificates(Arc::new(roots))
            .expect("QUIC pressure client config"),
    );
    client
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
        .env("SNI_GATE_QUIC_MAX_RAW_FLOWS", "2048")
        .env(
            "SNI_GATE_QUIC_MAX_PENDING_RAW_CONNECTS",
            MAX_PENDING_RAW_CONNECTS.to_string(),
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

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut path = std::env::temp_dir();
    path.push(format!(
        "sni-gate-quic-raw-setup-pressure-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create temporary pressure directory");
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
