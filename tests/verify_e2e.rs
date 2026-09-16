//! Upstream certificate verification, end to end through the built binary.
//!
//! # The shape being reproduced
//!
//! A route that suppresses SNI (`override_sni = ""`), or that reaches a virtual
//! host by address, is answered with the upstream's **default** certificate —
//! issued for whatever name its operator chose, not for the name the client
//! asked for. The default policy correctly refuses it:
//!
//! ```text
//! upstream TLS handshake: invalid peer certificate: certificate not valid for
//! name "asked.test"; certificate is only valid for DnsName("default.upstream.test")
//! ```
//!
//! # What is left for this file
//!
//! Every *layer* is already unit-tested: what each policy accepts, in
//! `src/verify.rs`; the inheritance ladder and every refusal, in
//! `src/config.rs`. Both are orders of magnitude cheaper than spawning a
//! process, so nothing they settle is re-run here.
//!
//! What no unit test can reach is the **wiring**: that the policy an operator
//! writes in TOML is the one a real handshake is actually held to, through
//! config resolution, the verifier factory, the per-ALPN client configs and the
//! dial — and that the partition it selects is the directory certificates really
//! land in. That is two tests: the reported failure with its fix, and the scope
//! split. The upstream they dial ignores SNI and always presents its default
//! certificate, which is exactly what a virtual host does when no SNI selected
//! anything else.
//!
//! Nothing here touches the network or the machine: the route dials a literal
//! `127.0.0.1`, which `dns::resolve_upstream` answers without a lookup, the PSL
//! is the embedded copy, and the CA is generated inside a temp directory and
//! never installed.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use common::{free_port, spawn_sni_gate, tempdir, wait_port, TempDir};

/// The mock upstream's entire reply.
///
/// Shared with the client side, which reads until exactly this has arrived.
/// "The whole answer is here" is then one fact rather than two guesses, and no
/// case depends on when a connection happens to be torn down.
const UPSTREAM_REPLY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";

/// The name the upstream's certificate is really for.
const UPSTREAM_CERT_NAME: &str = "default.upstream.test";
/// The name the client asks for, and which the certificate does *not* cover.
const ASKED: &str = "asked.test";

/// A TLS upstream that answers every handshake with one fixed certificate, plus
/// the PEM of the CA that issued it (for a route that wants to trust it).
struct Upstream {
    port: u16,
    ca_pem: String,
}

/// Start a TLS server presenting a certificate for `names`, from a throwaway CA.
///
/// Deliberately indifferent to SNI: it has one certificate and serves it to
/// everyone, the way a virtual host answers a handshake that selected nothing.
fn spawn_tls_upstream(names: &[&str]) -> Upstream {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        SanType,
    };

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "verify-e2e upstream CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = CertificateDer::from(ca.der().to_vec());

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
    leaf_params.subject_alt_names = names
        .iter()
        .map(|n| SanType::DnsName((*n).try_into().unwrap()))
        .collect();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, names[0]);
    let issuer = Issuer::from_ca_cert_der(&ca_der, ca_key).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let chain = vec![CertificateDer::from(leaf.der().to_vec()), ca_der];
    let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key.into())
            .expect("the upstream's own certificate and key match"),
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(tcp) = stream else { continue };
            let server_config = server_config.clone();
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(server_config) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                // One read is enough: the gateway splices a whole HTTP/1.1
                // request head in a single write.
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf);
                let _ = tls.write_all(UPSTREAM_REPLY);
                let _ = tls.flush();
            });
        }
    });

    Upstream {
        port,
        ca_pem: ca.pem(),
    }
}

/// A gateway configuration with one `tls` route to `upstream`, carrying
/// `verify` verbatim as the route's `[verify]` block (empty for none at all).
fn config_for(listen: u16, upstream: u16, verify: &str) -> String {
    format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "Verify E2E CA"
leaf_validity_days = 90
[psl]
source = "embedded"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "web"
  type = "tls"
  match_sni = ["{ASKED}"]
  upstream = "127.0.0.1:{upstream}"
  fail = "close"
{verify}
"#
    )
}

/// Run one policy against the mock upstream and return the response text.
fn upstream_is_reachable(verify: &str) -> String {
    let dir = tempdir();
    let upstream = spawn_tls_upstream(&[UPSTREAM_CERT_NAME]);
    let listen = free_port();
    let config = config_for(listen, upstream.port, verify);
    std::fs::write(dir.path().join("upstream-ca.pem"), &upstream.ca_pem).unwrap();
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);
    fetch(listen, &dir, ASKED)
}

/// The reported failure and the fix for it, over one real handshake each.
///
/// Both halves are here rather than in two tests because neither means anything
/// without the other: that the default policy refuses is only interesting if the
/// same upstream, same route and same client succeed once the policy states what
/// the upstream actually proves.
#[test]
fn a_certificate_for_another_name_is_refused_until_the_policy_says_otherwise() {
    let refused = upstream_is_reachable("");
    assert!(
        !refused.contains("200 OK"),
        "an upstream certificate for another name must not be accepted: {refused:?}"
    );

    // `name` moves the subject of the claim and nothing else, so the upstream's
    // own CA still has to be trusted for the chain to build.
    let accepted = upstream_is_reachable(&format!(
        "    [listener.route.verify]\n    \
         name = \"{UPSTREAM_CERT_NAME}\"\n    \
         ca_file = \"upstream-ca.pem\"\n"
    ));
    assert!(
        accepted.contains("200 OK"),
        "a matching `verify.name` must complete the connection: {accepted:?}"
    );
}

/// Two routes to the same destination that demand *different* proof are
/// different certificate partitions, so neither can ever serve coverage the
/// other learned. The policy is part of the scope precisely so that this holds
/// without a runtime rule about who may mirror.
///
/// Also the one place `mode` is carried from TOML all the way into a live
/// handshake: both routes here reach the upstream under a mode the default
/// policy would have refused. What each mode *means* is settled far more cheaply
/// by the unit tests in `src/verify.rs`, which is why it is not re-run here.
#[test]
fn a_different_policy_is_a_different_certificate_scope() {
    let dir = tempdir();
    let upstream = spawn_tls_upstream(&[UPSTREAM_CERT_NAME]);
    let listen = free_port();
    std::fs::write(dir.path().join("upstream-ca.pem"), &upstream.ca_pem).unwrap();

    // Identical in every respect a scope is built from — type, dial host, port,
    // SNI policy, resolver, family — except what the upstream must prove.
    let config = format!(
        r#"
[global]
resolver = "system"
unmatched = "close"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "Verify E2E CA"
leaf_validity_days = 90
[psl]
source = "embedded"
[store]
enabled = true
dir = "certs"
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "strict"
  type = "tls"
  match_sni = ["strict.test"]
  upstream = "127.0.0.1:{port}"
  fail = "close"
    [listener.route.verify]
    mode = "chain"
    ca_file = "upstream-ca.pem"

  [[listener.route]]
  name = "loose"
  type = "tls"
  match_sni = ["loose.test"]
  upstream = "127.0.0.1:{port}"
  fail = "close"
    [listener.route.verify]
    mode = "none"
"#,
        port = upstream.port
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    for host in ["strict.test", "loose.test"] {
        let resp = fetch(listen, &dir, host);
        assert!(
            resp.contains("200 OK"),
            "{host} must reach the upstream under its own policy: {resp:?}"
        );
    }

    let scopes = scope_dirs(&dir.path().join("certs"));
    assert_eq!(
        scopes.len(),
        2,
        "two policies to one destination must not share a partition: {scopes:?}"
    );
}

/// Terminate TLS against the gateway as a browser would — trusting the CA it
/// generated — send a request for `host`, and return the response text (empty
/// when the gateway closed the connection without answering).
///
/// The inbound handshake succeeding proves nothing about the upstream: on this
/// path the gateway answers the client first and dials afterwards, so a refused
/// upstream certificate shows up as an empty response rather than a TLS error.
fn fetch(listen: u16, dir: &TempDir, host: &str) -> String {
    use rustls::pki_types::ServerName;

    let ca_path = dir.path().join("ca").join("ca.crt");
    for _ in 0..100 {
        if ca_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let ca_pem = std::fs::read(&ca_path).expect("the gateway generated its CA");

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let tcp = std::net::TcpStream::connect(("127.0.0.1", listen)).unwrap();
    // Bounded on purpose. Half of these cases *expect* the gateway to give up on
    // the upstream, and a test must not depend on how it does that: a close, a
    // reset and a silent hold all have to come back as "no response" quickly
    // rather than wedging the suite until some idle timeout expires.
    let budget = Some(std::time::Duration::from_secs(5));
    tcp.set_read_timeout(budget).unwrap();
    tcp.set_write_timeout(budget).unwrap();
    let name = ServerName::try_from(host.to_string()).unwrap();
    let conn = rustls::ClientConnection::new(config, name).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if tls.write_all(req.as_bytes()).is_err() {
        return String::new();
    }
    // Read until the reply is complete, not until end of stream. The gateway
    // honours half-close in both directions, so it correctly keeps this side
    // open after the upstream is done — waiting for EOF would be waiting on
    // that bookkeeping rather than on the answer being asserted, and
    // half-closing from here instead would race the reply.
    let mut resp = Vec::new();
    let mut buf = [0u8; 256];
    while !resp.ends_with(UPSTREAM_REPLY) {
        match tls.read(&mut buf) {
            // End of stream, close_notify, or the budget above. Whatever
            // arrived is the answer — for a refused upstream, nothing.
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&resp).to_string()
}

/// The scope directories the gateway created under `certs/`.
fn scope_dirs(certs: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(certs) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    out.sort();
    out
}
