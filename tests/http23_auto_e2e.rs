//! End-to-end proof that one configured listener can serve HTTP/2 over TCP and
//! an automatically-generated HTTP/3 companion over UDP on the same port.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

const H2_SNI: &str = "a.h2.auto.test";
const H3_SNI: &str = "a.h3.auto.test";
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 0x04, 0, 0, 0, 0, 0];

#[test]
fn global_http2_and_http3_share_one_listener_port_end_to_end() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = tempdir();
    let listen = free_dual_port();
    let (h2_backend, _h2_thread) = spawn_h2c_backend();

    // Keep a UDP upstream open without answering QUIC. The inbound H3 handshake
    // completes before the gateway's upstream connect timeout, which is enough to
    // prove the automatically-created UDP listener is live on the same port as h2.
    let h3_upstream = UdpSocket::bind("127.0.0.1:0").expect("bind dummy H3 upstream");
    let h3_upstream_port = h3_upstream.local_addr().unwrap().port();

    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"

[global.http2]
enabled = true
probe = "require"

[global.http3]
enabled = true

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "HTTP2+3 coexistence E2E CA"
leaf_validity_days = 90

[psl]
source = "embedded"

# This is the only configured listener. HTTP/2 remains on TCP; [global.http3]
# synthesizes UDP/QUIC on the same numeric port.
[[listener]]
addr = "127.0.0.1:{listen}"

  # Cleartext HTTP route exercises the existing h2 -> h2c path. It is
  # intentionally skipped by automatic HTTP/3 because no H3->h2c translation
  # exists.
  [[listener.route]]
  name = "h2"
  type = "http"
  match_sni = [".h2.auto.test"]
  upstream = "127.0.0.1:{h2_backend}"

  # This TCP TLS route keeps type=tls in the synthetic UDP companion; the
  # QUIC transport normalizes it to the H3 runtime path.
  [[listener.route]]
  name = "h3"
  type = "tls"
  match_sni = [".h3.auto.test"]
  upstream = "127.0.0.1:{h3_upstream_port}"
  override_sni = "{H3_SNI}"
  connect_timeout = "5s"
"#
    );

    let _gateway = spawn_sni_gate(&config, dir.path());
    wait_tcp_port(listen);
    let ca_path = dir.path().join("ca").join("ca.crt");
    wait_file(&ca_path);
    let ca_pem = std::fs::read(&ca_path).expect("read generated CA certificate");

    // First prove the configured TCP listener really negotiates h2 and carries
    // an H2 connection preface to the cleartext h2c backend.
    drive_h2(listen, &ca_pem);

    // Then, without changing the configured listener or numeric port, prove the
    // automatically-created UDP companion negotiates QUIC TLS with ALPN h3.
    drive_h3(listen, &ca_pem);

    drop(h3_upstream);
}

fn drive_h2(port: u16, ca_pem: &[u8]) {
    let roots = roots_from_pem(ca_pem);
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));

    let runtime = tokio::runtime::Runtime::new().expect("create H2 Tokio runtime");
    runtime.block_on(async move {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect H2 TCP listener");
        let name = ServerName::try_from(H2_SNI).expect("valid H2 SNI");
        let mut tls = connector
            .connect(name, tcp)
            .await
            .expect("complete inbound H2 TLS handshake");

        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(&b"h2"[..]),
            "TCP side should negotiate h2"
        );

        tls.write_all(H2_PREFACE).await.expect("send H2 preface");
        tls.write_all(&H2_EMPTY_SETTINGS)
            .await
            .expect("send client H2 SETTINGS");
        tls.flush().await.expect("flush H2 frames");

        let mut reply = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut reply))
            .await
            .expect("H2 backend SETTINGS timed out")
            .expect("read H2 backend SETTINGS");
        assert_eq!(reply[3], 0x04, "expected backend H2 SETTINGS: {reply:?}");
    });
}

fn drive_h3(port: u16, ca_pem: &[u8]) {
    let roots = roots_from_pem(ca_pem);
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicClientConfig::try_from(tls_config).expect("build Quinn rustls config");
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));

    let runtime = tokio::runtime::Runtime::new().expect("create H3 Tokio runtime");
    runtime.block_on(async move {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("bind H3 client endpoint");
        let connecting = endpoint
            .connect_with(
                client_config,
                std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                H3_SNI,
            )
            .expect("start H3 connection to automatic companion");
        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("automatic H3 companion handshake timed out")
            .expect("automatic H3 companion handshake failed");

        let protocol = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol.clone());
        assert_eq!(protocol.as_deref(), Some(&b"h3"[..]));

        connection.close(0u32.into(), b"HTTP2+3 coexistence test complete");
        endpoint.wait_idle().await;
    });
}

fn roots_from_pem(pem: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let mut reader = pem;
    for cert in rustls_pemfile::certs(&mut reader) {
        roots
            .add(cert.expect("parse generated CA certificate"))
            .expect("trust generated CA certificate");
    }
    roots
}

fn spawn_h2c_backend() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2c backend");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                if !buf[..n].starts_with(H2_PREFACE) {
                    return;
                }
                let _ = stream.write_all(&H2_EMPTY_SETTINGS);
                let _ = stream.flush();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, handle)
}

fn free_dual_port() -> u16 {
    for _ in 0..100 {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("reserve candidate TCP port");
        let port = tcp.local_addr().unwrap().port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) {
            drop(udp);
            drop(tcp);
            return port;
        }
    }
    panic!("could not find a port free for both TCP and UDP");
}

fn wait_tcp_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("TCP listener {port} never came up");
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
        "sni-gate-http23-auto-e2e-{}-{}",
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
