//! End-to-end tests that launch the built `sni-gate` binary against a mock
//! TCP backend and drive real connections through it. No external tools or
//! network are required, so these run unmodified in CI.
//!
//! Covered:
//!   * `http` route: TLS is terminated (a cert is issued by the local CA) and
//!     the plaintext request reaches the backend with its Host header intact.
//!   * `raw` route: the untouched byte stream is spliced to the backend.
//!   * `raw` route with a port-only `upstream`: the matched source Host is
//!     reflected as the dial target, with the configured port.
//!   * named template: a route that carries only `match_sni` + `use` inherits
//!     its `type`/`upstream` from a `[templates.*]` bundle and still works.
//!   * ladder issuance: `[issuance] mode = "ladder"` anchors one leaf at the
//!     registrable domain (compact ancestor-wildcard SANs); a sibling reuses it
//!     with no second signature, persisted as a single `certs/<registrable>.crt`.
//!   * WebSocket-style half-close: a request that half-closes still receives a
//!     full response back (the regression fixed in the proxy splice).
//!   * HTTP/2 on an `http` route: the client negotiates h2 and the decrypted
//!     stream reaches the backend as prior-knowledge h2c; with `[http2]` absent
//!     the same client is still answered with http/1.1 (h2 is opt-in).
//!   * the h2c startup probe: `require` aborts startup against an HTTP/1.1-only
//!     backend, while the default `warn` logs and keeps serving with h2 enabled.
//!   * `override_sni`: all three cases asserted against the actual upstream
//!     ClientHello — omitted reflects the inbound name, a fixed value is sent
//!     verbatim, and `""` sends no `server_name` extension at all.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::Duration;

/// The HTTP/2 client connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// An empty SETTINGS frame: length=0, type=0x4, flags=0, stream id=0.
const H2_EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 0x04, 0, 0, 0, 0, 0];

/// A trivial mock backend: for each connection, read the request bytes until a
/// short pause, then reply with a fixed body echoing nothing fancy. It also
/// supports a "half-close" probe: if the request contains "WSPROBE", it waits
/// for the client's half-close (read to EOF) then sends a large response.
///
/// `h2c` makes it answer the HTTP/2 connection preface with a SETTINGS frame,
/// which is all that is needed both to satisfy the gateway's startup h2c probe
/// and to prove an end-to-end h2 splice. It is deliberately *not* a real HTTP/2
/// implementation — no library, no HPACK, just enough framing to be recognized.
fn spawn_mock_backend_with(h2c: bool) -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = &buf[..n];

                if h2c && head.starts_with(H2_PREFACE) {
                    // Prior-knowledge h2c: reply with our own SETTINGS frame,
                    // then echo whatever else arrives so a test can prove the
                    // splice carries bytes in both directions.
                    let _ = s.write_all(&H2_EMPTY_SETTINGS);
                    let _ = s.flush();
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    return;
                }

                let req = String::from_utf8_lossy(head).to_string();
                if req.contains("WSPROBE") {
                    // Half-close probe: drain to EOF, then send a big response.
                    let mut rest = Vec::new();
                    let _ = s.read_to_end(&mut rest);
                    let body = vec![b'Z'; 200 * 1024];
                    let _ = s.write_all(&body);
                } else {
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
                    );
                }
            });
        }
    });
    (port, handle)
}

/// The HTTP/1.1-only mock backend used by most tests.
fn spawn_mock_backend() -> (u16, std::thread::JoinHandle<()>) {
    spawn_mock_backend_with(false)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Child2(Child);
impl Drop for Child2 {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Launch the sni-gate binary with the given config text in a temp dir.
fn spawn_sni_gate(config: &str, workdir: &std::path::Path) -> Child2 {
    std::fs::write(workdir.join("sni-gate.toml"), config).unwrap();
    let bin = env!("CARGO_BIN_EXE_sni-gate");
    let child = Command::new(bin)
        .arg("-c")
        .arg(workdir.join("sni-gate.toml"))
        .current_dir(workdir)
        .env("SNI_GATE_LOG", "warn")
        .spawn()
        .expect("spawn sni-gate");
    Child2(child)
}

/// Poll until a TCP port accepts connections, or panic after a timeout.
fn wait_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("port {port} never came up");
}

#[test]
fn raw_route_passes_bytes_through() {
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend();
    let listen = free_port();
    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[cache.psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "raw"
  type = "raw"
  match_sni = [".raw.test"]
  upstream = "127.0.0.1:{backend}"
"#
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    // Raw route: send a plain HTTP request; SNI-based routing uses the Host
    // header for a cleartext connection. The bytes reach the backend verbatim.
    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x.raw.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.contains("200 OK"), "raw route response: {resp:?}");
}

#[test]
fn raw_route_reflects_source_host_with_port_only_upstream() {
    // `upstream = "<port>"` reflects the matched source SNI/Host to that fixed
    // port. To stay hermetic (no DNS), the routing key is a literal IP —
    // `resolve_upstream` dials a literal host without any lookup — so we match
    // on "127.0.0.1" and connect with `Host: 127.0.0.1`. The dial host becomes
    // 127.0.0.1 (reflected) and the port becomes the mock backend's port.
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend();
    let listen = free_port();
    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[cache.psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "reflect"
  type = "raw"
  match_sni = ["127.0.0.1"]
  upstream = "{backend}"
"#
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(
        resp.contains("200 OK"),
        "reflected port-only upstream response: {resp:?}"
    );
}

#[test]
fn http_route_terminates_tls_and_issues_cert() {
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend();
    let listen = free_port();
    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[cache.psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "web"
  type = "http"
  match_sni = [".web.test"]
  upstream = "127.0.0.1:{backend}"
"#
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);
    drive_tls_http(listen, &dir.path().join("ca").join("ca.crt"), "a.web.test");
}

#[test]
fn ladder_issuance_mode_end_to_end() {
    // `[issuance] mode = "ladder"` anchors ONE certificate at the registrable
    // domain, covering the ancestor chain with compact parent wildcards (no
    // useless `*.leaf`). Prove end-to-end: a deep-SNI handshake succeeds and the
    // leaf carries the compact ladder; a sibling reuses it with no second
    // signature; a deeper new branch is MERGED into the same certificate; and it
    // is persisted as a single `certs/<registrable>.crt` (no per-host file, no
    // mode subdirectory).
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend();
    let listen = free_port();
    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[issuance]
mode = "ladder"
[store]
enabled = true
dir = "certs"
renew_margin_days = 30
[cache.psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "web"
  type = "http"
  match_sni = [".deep.example"]
  upstream = "127.0.0.1:{backend}"
"#
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let ca_path = dir.path().join("ca").join("ca.crt");
    let sans = drive_tls_collect_sans(listen, &ca_path, "b.a.deep.example");
    // Compact ladder anchored at the registrable domain (deep.example): a
    // wildcard per ancestor level plus the bare apex — and crucially NO
    // `*.b.a.deep.example` leaf wildcard.
    let mut got = sans.clone();
    got.sort();
    let mut want = vec!["*.a.deep.example", "*.deep.example", "deep.example"];
    want.sort();
    assert_eq!(got, want, "unexpected ladder SANs");
    assert!(
        !sans.iter().any(|s| s == "*.b.a.deep.example"),
        "must not emit the useless leaf wildcard"
    );

    // A sibling under the same registrable domain reuses the SAME certificate
    // (covered by *.a.deep.example): its handshake succeeds, no re-sign.
    drive_tls_http(listen, &ca_path, "c.a.deep.example");

    // A deeper, previously-uncovered branch is merged into the SAME cert file:
    // after it, the leaf carries both `*.a.deep.example` and `*.x.deep.example`.
    let merged = drive_tls_collect_sans(listen, &ca_path, "q.x.deep.example");
    for expected in ["*.a.deep.example", "*.x.deep.example", "*.deep.example"] {
        assert!(
            merged.iter().any(|s| s == expected),
            "expected accumulated SAN {expected:?}, got {merged:?}"
        );
    }

    // Exactly one certificate, keyed by the registrable domain, inside this
    // route's certificate-scope directory (`certs/<scope>/deep.example.crt`) —
    // one file for the whole domain, no per-host leaf. The scope level is what
    // keeps two routes that forward differently from overwriting each other.
    let crt_files = collect_certs(&dir.path().join("certs"));
    assert_eq!(
        crt_files,
        vec!["deep.example.crt".to_string()],
        "expected a single registrable-anchored cert, got {crt_files:?}"
    );
    let scopes = collect_scope_dirs(&dir.path().join("certs"));
    assert_eq!(
        scopes.len(),
        1,
        "one route forwarding one way is one scope, got {scopes:?}"
    );
}

/// Every `.crt` file name under `certs/`, at any scope depth, sorted.
fn collect_certs(certs_dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![certs_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|x| x == "crt") {
                out.push(path.file_name().unwrap().to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}

/// The certificate-scope subdirectory names under `certs/`, sorted.
fn collect_scope_dirs(certs_dir: &std::path::Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(certs_dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

#[test]
fn cross_route_coalescing_is_structurally_impossible() {
    // The reported bug, as an end-to-end assertion on real signed certificates.
    //
    // Two names under one registrable domain, deliberately routed to DIFFERENT
    // upstreams, with `mode = "ladder"` asking for the widest possible coverage:
    //
    //   apex.coalesce.test      -> backend A
    //   static.coalesce.test    -> backend B  (via default_route)
    //
    // Before the fix, the apex's handshake issued {*.coalesce.test, coalesce.test}
    // — valid for `static.coalesce.test` too. A browser holding that connection
    // may then coalesce a request for the static name onto it (RFC 9113 §9.1.1):
    // no new TCP, no new TLS, no new SNI, so sni-gate never routes it and backend
    // A answers for a name that belongs to backend B.
    //
    // What must hold now: neither certificate is valid for a name the other
    // route owns. That removes the browser's *permission* to coalesce, which is
    // the only one of the three preconditions this program controls.
    let dir = tempdir();
    let (backend_a, _ha) = spawn_mock_backend();
    let (backend_b, _hb) = spawn_mock_backend();
    let listen = free_port();
    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[issuance]
mode = "ladder"
[store]
enabled = true
dir = "certs"
renew_margin_days = 30
[cache.psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "apex"
  type = "http"
  match_sni = ["apex.coalesce.test"]
  upstream = "127.0.0.1:{backend_a}"
  [listener.default_route]
  name = "catchall"
  type = "http"
  upstream = "127.0.0.1:{backend_b}"
"#
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);
    let ca_path = dir.path().join("ca").join("ca.crt");

    // The apex, on its own route. `ladder` proposes `*.coalesce.test`, but every
    // other host under that wildcard falls to `default_route` — a different
    // upstream — so the wildcard must be withheld.
    let apex_sans = drive_tls_collect_sans(listen, &ca_path, "apex.coalesce.test");
    assert!(
        !apex_sans.iter().any(|s| s == "*.coalesce.test"),
        "apex cert must not claim *.coalesce.test (would authorize coalescing \
         onto the default route's names), got {apex_sans:?}"
    );
    assert!(
        !host_covered(&apex_sans, "static.coalesce.test"),
        "apex cert must not be valid for a default_route name, got {apex_sans:?}"
    );
    assert!(
        host_covered(&apex_sans, "apex.coalesce.test"),
        "apex cert must still cover its own host, got {apex_sans:?}"
    );

    // The sibling, on the default route. It must not claim the apex's name.
    let static_sans = drive_tls_collect_sans(listen, &ca_path, "static.coalesce.test");
    assert!(
        !host_covered(&static_sans, "apex.coalesce.test"),
        "default-route cert must not be valid for the apex route's name, got \
         {static_sans:?}"
    );
    assert!(
        host_covered(&static_sans, "static.coalesce.test"),
        "default-route cert must cover its own host, got {static_sans:?}"
    );

    // Both routes still serve their own traffic correctly.
    drive_tls_http(listen, &ca_path, "apex.coalesce.test");
    drive_tls_http(listen, &ca_path, "static.coalesce.test");

    // Two forwarding targets -> two certificate scopes -> two directories, so
    // neither can overwrite the other's file on disk. Without this partition the
    // two would share `certs/coalesce.test.crt` and a reload would serve one
    // certificate for both routes, re-widening coverage after the fact.
    let scopes = collect_scope_dirs(&dir.path().join("certs"));
    assert_eq!(
        scopes.len(),
        2,
        "two forwarding targets must be two scopes, got {scopes:?}"
    );
}

/// Whether a SAN list is valid for `host` — exact match or a single-level
/// wildcard. Mirrors the coverage rule a TLS client applies (RFC 6125 §6.4.3),
/// so these assertions test what a *browser* would conclude about the real cert.
fn host_covered(sans: &[String], host: &str) -> bool {
    sans.iter().any(|san| {
        if san == host {
            return true;
        }
        match san.strip_prefix("*.") {
            Some(suffix) => match host.split_once('.') {
                Some((label, rest)) => !label.is_empty() && rest == suffix,
                None => false,
            },
            None => false,
        }
    })
}

#[test]
fn template_supplies_type_and_upstream_end_to_end() {
    // A `[templates.web]` provides `type` and `upstream`; the route carries only
    // `match_sni` + `use`. Proves templates flow through the real binary and its
    // load-time validation, and that TLS is still terminated with an issued cert.
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend();
    let listen = free_port();
    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[cache.psl]
source = "embedded"
[templates.web]
type = "http"
upstream = "127.0.0.1:{backend}"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "templated"
  use = "web"
  match_sni = [".web.test"]
"#
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);
    drive_tls_http(listen, &dir.path().join("ca").join("ca.crt"), "a.web.test");
}

/// Connect to `listen` over TLS presenting `sni`, trusting the CA that sni-gate
/// generates at `ca_path`, send an HTTP request, and assert a `200 OK` comes
/// back — i.e. the cert was issued+trusted and the request reached the backend.
fn drive_tls_http(listen: u16, ca_path: &std::path::Path, sni: &'static str) {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    // Wait for the CA to be generated on disk, then trust it.
    for _ in 0..100 {
        if ca_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let ca_pem = std::fs::read(ca_path).expect("CA cert generated");

    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", listen))
            .await
            .unwrap();
        let name = ServerName::try_from(sni).unwrap();
        let mut tls = connector
            .connect(name, tcp)
            .await
            .expect("TLS handshake (cert issued + trusted)");

        let req = format!("GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.contains("200 OK"), "TLS route response: {resp:?}");
    });
}

/// Connect over TLS presenting `sni` (trusting the CA at `ca_path`), complete
/// the handshake, and return the DNS SANs of the leaf the gateway issued. Proves
/// the issuance mode's coverage against the real, signed certificate.
fn drive_tls_collect_sans(
    listen: u16,
    ca_path: &std::path::Path,
    sni: &'static str,
) -> Vec<String> {
    use std::sync::Arc;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    for _ in 0..100 {
        if ca_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let ca_pem = std::fs::read(ca_path).expect("CA cert generated");
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", listen))
            .await
            .unwrap();
        let name = ServerName::try_from(sni).unwrap();
        let tls = connector
            .connect(name, tcp)
            .await
            .expect("TLS handshake (cert issued + trusted)");

        let leaf = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .expect("server presented a leaf certificate")
            .clone();

        let (_, cert) = X509Certificate::from_der(leaf.as_ref()).expect("parse leaf DER");
        let mut out = Vec::new();
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in &san.value.general_names {
                if let GeneralName::DNSName(d) = gn {
                    out.push((*d).to_string());
                }
            }
        }
        out
    })
}

// ---------------------------------------------------------------------------
// HTTP/2
// ---------------------------------------------------------------------------

/// Connect over TLS offering `alpn`, and return the protocol the gateway
/// selected plus the TLS stream, so a caller can keep talking on it.
///
/// `exchange` runs against the established connection; it receives the stream
/// and returns whatever the test wants to assert on.
fn drive_tls_alpn<F>(
    listen: u16,
    ca_path: &std::path::Path,
    sni: &'static str,
    alpn: Vec<Vec<u8>>,
    exchange: F,
) -> (Option<Vec<u8>>, Vec<u8>)
where
    F: for<'a> FnOnce(
            &'a mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + 'a>>
        + Send
        + 'static,
{
    use std::sync::Arc;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    for _ in 0..100 {
        if ca_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let ca_pem = std::fs::read(ca_path).expect("CA cert generated");
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn;
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", listen))
            .await
            .unwrap();
        let name = ServerName::try_from(sni).unwrap();
        let mut tls = connector
            .connect(name, tcp)
            .await
            .expect("TLS handshake (cert issued + trusted)");

        let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let out = exchange(&mut tls).await;
        (negotiated, out)
    })
}

/// Config for a single `http` route with an explicit `[http2]` block.
fn http2_config(listen: u16, backend: u16, http2_block: &str) -> String {
    format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[cache.psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "web"
  type = "http"
  match_sni = [".h2.test"]
  upstream = "127.0.0.1:{backend}"
{http2_block}
"#
    )
}

#[test]
fn http2_http_route_negotiates_h2_and_splices_to_h2c_backend() {
    // The headline feature: with http2 enabled, a client offering h2 gets h2,
    // and the decrypted h2 bytes reach the cleartext backend as prior-knowledge
    // h2c — proven by the backend answering the preface with SETTINGS.
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend_with(true);
    let listen = free_port();
    let config = http2_config(
        listen,
        backend,
        "    [listener.route.http2]\n    enabled = true\n    probe = \"require\"\n",
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let (alpn, reply) = drive_tls_alpn(
        listen,
        &dir.path().join("ca").join("ca.crt"),
        "a.h2.test",
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        |tls| {
            Box::pin(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut hello = Vec::from(H2_PREFACE);
                hello.extend_from_slice(&H2_EMPTY_SETTINGS);
                tls.write_all(&hello).await.unwrap();
                tls.flush().await.unwrap();
                let mut frame = [0u8; 9];
                tls.read_exact(&mut frame).await.unwrap();
                frame.to_vec()
            })
        },
    );

    assert_eq!(
        alpn.as_deref(),
        Some(&b"h2"[..]),
        "gateway should negotiate h2 when the route enables http2"
    );
    assert_eq!(
        reply[3], 0x04,
        "backend should answer the spliced preface with a SETTINGS frame, got {reply:?}"
    );
}

#[test]
fn http2_disabled_still_negotiates_http1() {
    // Regression guard for the default path: without an [http2] block, a client
    // offering h2 must still be answered with http/1.1, exactly as before.
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend();
    let listen = free_port();
    let config = http2_config(listen, backend, "");
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let (alpn, resp) = drive_tls_alpn(
        listen,
        &dir.path().join("ca").join("ca.crt"),
        "a.h2.test",
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        |tls| {
            Box::pin(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                tls.write_all(b"GET / HTTP/1.1\r\nHost: a.h2.test\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                let mut out = Vec::new();
                tls.read_to_end(&mut out).await.unwrap();
                out
            })
        },
    );

    assert_eq!(
        alpn.as_deref(),
        Some(&b"http/1.1"[..]),
        "http2 is opt-in; the default must stay http/1.1"
    );
    assert!(
        String::from_utf8_lossy(&resp).contains("200 OK"),
        "response: {:?}",
        String::from_utf8_lossy(&resp)
    );
}

#[test]
fn http2_probe_require_aborts_startup_on_an_h1_only_backend() {
    // probe = "require" turns a backend that cannot do h2c into a startup
    // failure rather than a runtime mystery.
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend(); // HTTP/1.1 only
    let listen = free_port();
    let config = http2_config(
        listen,
        backend,
        "    [listener.route.http2]\n    enabled = true\n    probe = \"require\"\n",
    );
    std::fs::write(dir.path().join("sni-gate.toml"), &config).unwrap();
    let bin = env!("CARGO_BIN_EXE_sni-gate");
    let out = Command::new(bin)
        .arg("-c")
        .arg(dir.path().join("sni-gate.toml"))
        .current_dir(dir.path())
        .env("SNI_GATE_LOG", "info")
        .output()
        .expect("run sni-gate");

    assert!(
        !out.status.success(),
        "startup should fail when probe = require and the backend is HTTP/1.1 only"
    );
    // The tracing fmt layer writes to stdout; check both streams so the test
    // does not depend on which one carries the diagnostic.
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        logs.contains("h2c probe") || logs.contains("HTTP/1.x"),
        "expected an h2c probe diagnostic, got: {logs}"
    );
}

#[test]
fn http2_probe_warn_keeps_serving_an_h1_backend() {
    // The default policy: a failed probe warns but never downgrades or aborts.
    // The gateway must come up and still negotiate h2 as configured.
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend(); // HTTP/1.1 only
    let listen = free_port();
    let config = http2_config(
        listen,
        backend,
        "    [listener.route.http2]\n    enabled = true\n",
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let (alpn, _) = drive_tls_alpn(
        listen,
        &dir.path().join("ca").join("ca.crt"),
        "a.h2.test",
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        |_tls| Box::pin(async move { Vec::new() }),
    );
    assert_eq!(
        alpn.as_deref(),
        Some(&b"h2"[..]),
        "a failed warn-probe must not silently disable http2"
    );
}

// ---------------------------------------------------------------------------
// override_sni = "" (suppress the SNI extension)
// ---------------------------------------------------------------------------

/// A backend that captures the first bytes of the connection it receives and
/// reports the SNI found in them, then drops the connection.
///
/// The upstream ClientHello's `server_name` extension is plaintext, so the
/// handshake never has to complete (and no upstream cert is needed) to observe
/// what the gateway put on the wire. Returns a channel yielding the SNI the
/// gateway sent: `None` means no `server_name` extension was present at all.
fn spawn_client_hello_recorder() -> (u16, std::sync::mpsc::Receiver<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                // A ClientHello arrives in one segment in practice; read once.
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).unwrap_or(0);
                let _ = tx.send(sni_from_client_hello(&buf[..n]));
            });
        }
    });
    (port, rx)
}

/// Extract the SNI host_name from a TLS ClientHello record, or `None` when the
/// `server_name` extension is absent. A deliberately small, test-local parser
/// (walks record → handshake → extensions); returns `None` on anything
/// unexpected rather than panicking.
fn sni_from_client_hello(b: &[u8]) -> Option<String> {
    if b.len() < 5 || b[0] != 0x16 {
        return None;
    }
    let mut p = 5usize; // skip record header
    if b.get(p)? != &0x01 {
        return None; // not a ClientHello
    }
    p += 4; // handshake header
    p += 2 + 32; // client_version + random
    let sid_len = *b.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2 + cs_len;
    let comp_len = *b.get(p)? as usize;
    p += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(b.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([b[p], b[p + 1]]);
        let ext_len = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        p += 4;
        if ext_type == 0x0000 {
            // server_name: list_len(2) name_type(1) name_len(2) name
            let body = b.get(p..p + ext_len)?;
            let name_len = u16::from_be_bytes([*body.get(3)?, *body.get(4)?]) as usize;
            let name = body.get(5..5 + name_len)?;
            return String::from_utf8(name.to_vec()).ok();
        }
        p += ext_len;
    }
    None
}

/// Config for one `tls` route, with `override_sni` rendered verbatim so a test
/// can pass an empty string, a name, or omit the line entirely.
fn tls_route_config(listen: u16, backend: u16, override_line: &str) -> String {
    format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[cache.psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "up"
  type = "tls"
  match_sni = [".sni.test"]
  upstream = "127.0.0.1:{backend}"
{override_line}
"#
    )
}

/// Drive one TLS connection through the gateway, ignoring the outcome. The
/// upstream handshake is expected to fail (the recorder never replies); all we
/// care about is what the gateway *sent* upstream.
fn poke_tls(listen: u16, ca_path: &std::path::Path, sni: &'static str) {
    for _ in 0..100 {
        if ca_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = drive_tls_alpn(listen, ca_path, sni, Vec::new(), |_tls| {
        Box::pin(async move { Vec::new() })
    });
}

#[test]
fn empty_override_sni_sends_no_sni_extension_upstream() {
    // `override_sni = ""` must suppress the extension entirely...
    let dir = tempdir();
    let (backend, rx) = spawn_client_hello_recorder();
    let listen = free_port();
    let config = tls_route_config(listen, backend, "  override_sni = \"\"");
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    poke_tls(listen, &dir.path().join("ca").join("ca.crt"), "a.sni.test");
    let observed = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("upstream never saw a ClientHello");
    assert_eq!(
        observed, None,
        "expected no server_name extension upstream, got {observed:?}"
    );
}

#[test]
fn omitted_override_sni_reflects_the_inbound_name_upstream() {
    // ...while omitting the field keeps the existing reflect behavior. Together
    // these pin down that "" is distinct from unset.
    let dir = tempdir();
    let (backend, rx) = spawn_client_hello_recorder();
    let listen = free_port();
    let config = tls_route_config(listen, backend, "");
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    poke_tls(listen, &dir.path().join("ca").join("ca.crt"), "a.sni.test");
    let observed = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("upstream never saw a ClientHello");
    assert_eq!(observed.as_deref(), Some("a.sni.test"));
}

#[test]
fn fixed_override_sni_is_sent_upstream() {
    let dir = tempdir();
    let (backend, rx) = spawn_client_hello_recorder();
    let listen = free_port();
    let config = tls_route_config(listen, backend, "  override_sni = \"backend.internal\"");
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    poke_tls(listen, &dir.path().join("ca").join("ca.crt"), "a.sni.test");
    let observed = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("upstream never saw a ClientHello");
    assert_eq!(observed.as_deref(), Some("backend.internal"));
}

/// Minimal temp-dir helper (avoids a dev-dependency).
fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    // pid + a process-wide monotonic counter. The counter matters: tests run in
    // parallel threads, and a per-call stack address (the previous scheme) can
    // repeat across threads with identical stack layouts — two tests then shared
    // one directory and each read the other's CA, failing with BadSignature.
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut base = std::env::temp_dir();
    base.push(format!("sni-gate-e2e-{pid}-{n}"));
    // A leftover directory from a previous run would carry a stale CA.
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    TempDir(base)
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
