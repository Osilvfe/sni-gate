//! QUIC/TCP configuration boundary tests.
//!
//! `sni-gate` is a binary crate, so this integration test reuses the production
//! config/error modules directly. `Config::load` exercises the same parse +
//! validation path as `main` without needing to start listeners or load CA key
//! material.

#[path = "../src/error.rs"]
mod error;
#[path = "../src/config.rs"]
mod config;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use config::{Config, ListenerTransport, RouteType};

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

fn load(body: &str) -> Result<Config, error::ConfigError> {
    let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let path: PathBuf = std::env::temp_dir().join(format!(
        "sni-gate-quic-config-{}-{id}.toml",
        std::process::id()
    ));
    let text = format!(
        "[ca]\ncert_path = \"ca.crt\"\nkey_path = \"ca.key\"\n{body}"
    );
    fs::write(&path, text).expect("write temporary config");
    let result = Config::load(&path);
    let _ = fs::remove_file(path);
    result
}

#[test]
fn tcp_and_quic_may_share_the_same_numeric_address() {
    let cfg = load(
        r#"
[[listener]]
addr = "0.0.0.0:443"
transport = "tcp"
  [[listener.route]]
  type = "raw"
  match_sni = [".tcp.example"]

[[listener]]
addr = "0.0.0.0:443"
transport = "quic"
  [[listener.route]]
  type = "raw"
  match_sni = [".quic.example"]
"#,
    )
    .expect("TCP and UDP/QUIC should be able to share a numeric bind address");

    assert_eq!(cfg.listeners[0].transport, ListenerTransport::Tcp);
    assert_eq!(cfg.listeners[1].transport, ListenerTransport::Quic);
}

#[test]
fn duplicate_quic_listener_address_is_rejected() {
    let error = load(
        r#"
[[listener]]
addr = "0.0.0.0:443"
transport = "quic"
  [[listener.route]]
  type = "raw"
  match_sni = [".one.example"]

[[listener]]
addr = "0.0.0.0:443"
transport = "quic"
  [[listener.route]]
  type = "raw"
  match_sni = [".two.example"]
"#,
    )
    .expect_err("duplicate QUIC listeners must be rejected");

    assert!(error.to_string().contains("duplicate Quic listener address"));
}

#[test]
fn quic_listener_accepts_h3_route() {
    let cfg = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  name = "web-h3"
  type = "h3"
  match_sni = ["h3.example"]
"#,
    )
    .expect("h3 is a valid QUIC route");

    assert_eq!(cfg.listeners[0].routes[0].route_type, Some(RouteType::H3));
}

#[test]
fn tcp_listener_rejects_h3_route() {
    let error = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "tcp"
  [[listener.route]]
  type = "h3"
  match_sni = ["h3.example"]
"#,
    )
    .expect_err("H3 cannot run on a TCP listener");

    assert!(error.to_string().contains("incompatible with a Tcp listener"));
}

#[test]
fn quic_listener_rejects_tls_route() {
    let error = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  type = "tls"
  match_sni = ["tls.example"]
"#,
    )
    .expect_err("TCP TLS routes cannot run on a QUIC listener");

    assert!(error.to_string().contains("incompatible with a Quic listener"));
}
