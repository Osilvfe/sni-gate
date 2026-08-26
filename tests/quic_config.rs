//! QUIC/TCP configuration boundary tests.
//!
//! `sni-gate` is a binary crate, so this integration test reuses the production
//! config/error modules directly. `Config::load` exercises the same parse +
//! validation path as `main` without needing to start listeners or load CA key
//! material.

// Reusing the production modules in a focused integration-test crate naturally
// leaves many configuration fields unused in this target. They are exercised by
// the binary and the config module's own unit tests, not by every test crate.
#![allow(dead_code)]

#[path = "../src/config.rs"]
mod config;
#[path = "../src/error.rs"]
mod error;

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
    let text = format!("[ca]\ncert_path = \"ca.crt\"\nkey_path = \"ca.key\"\n{body}");
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

    assert!(error
        .to_string()
        .contains("duplicate Quic listener address"));
}

#[test]
fn quic_listener_accepts_tls_route_as_h3_runtime() {
    let cfg = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  name = "web-h3"
  type = "tls"
  match_sni = ["h3.example"]
"#,
    )
    .expect("tls is a valid terminating QUIC route");

    let route_type = cfg.listeners[0].routes[0].route_type.unwrap();
    assert_eq!(route_type, RouteType::Tls);
    assert_eq!(
        Config::runtime_route_type(ListenerTransport::Quic, route_type),
        Some(RouteType::H3)
    );
}

#[test]
fn quic_listener_accepts_ech_route_as_h3_ech_runtime() {
    let cfg = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  name = "web-h3-ech"
  type = "ech"
  match_sni = ["h3-ech.example"]
"#,
    )
    .expect("ech is a valid terminating QUIC route");

    let route_type = cfg.listeners[0].routes[0].route_type.unwrap();
    assert_eq!(route_type, RouteType::Ech);
    assert_eq!(
        Config::runtime_route_type(ListenerTransport::Quic, route_type),
        Some(RouteType::H3Ech)
    );
}

#[test]
fn h3_names_are_not_public_route_types() {
    for route_type in ["h3", "h3-ech", "h3ech"] {
        let error = load(&format!(
            r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  type = "{route_type}"
  match_sni = ["h3.example"]
"#
        ))
        .expect_err("H3 naming is runtime-only, not a public route type");
        assert!(error.to_string().contains(route_type));
    }
}

#[test]
fn quic_listener_rejects_cleartext_http_route() {
    let error = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  type = "http"
  match_sni = ["http.example"]
"#,
    )
    .expect_err("cleartext HTTP upstream translation is not implemented for QUIC");

    assert!(error
        .to_string()
        .contains("incompatible with a Quic listener"));
}

#[test]
fn global_http2_and_http3_can_coexist_on_one_tcp_listener() {
    let cfg = load(
        r#"
[global.http2]
enabled = true
[global.http3]
enabled = true
[[listener]]
addr = "127.0.0.1:443"
  [[listener.route]]
  type = "tls"
  match_sni = [".web.example"]
"#,
    )
    .unwrap();
    let tcp = &cfg.listeners[0];
    let route = &tcp.routes[0];
    let rt_tpl = cfg.template_for(&route.use_template).unwrap();
    let ln_tpl = cfg.template_for(&tcp.use_template).unwrap();
    assert!(cfg.effective_http2(tcp, route, rt_tpl, ln_tpl).enabled);
    assert!(cfg.effective_http3(tcp, route, rt_tpl, ln_tpl).enabled);
    let expanded = cfg.expanded_listeners().unwrap();
    assert_eq!(expanded.len(), 2);
    assert_eq!(expanded[0].transport, ListenerTransport::Tcp);
    assert_eq!(expanded[0].routes[0].route_type, Some(RouteType::Tls));
    assert_eq!(expanded[1].transport, ListenerTransport::Quic);
    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::Tls));
    assert_eq!(
        Config::runtime_route_type(
            expanded[1].transport,
            expanded[1].routes[0].route_type.unwrap()
        ),
        Some(RouteType::H3)
    );
}

#[test]
fn route_http3_false_disables_global_default() {
    let cfg = load(
        r#"
[global.http3]
enabled = true
[[listener]]
addr = "127.0.0.1:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["disabled.example"]
    [listener.route.http3]
    enabled = false
"#,
    )
    .unwrap();
    assert_eq!(cfg.expanded_listeners().unwrap().len(), 1);
}

#[test]
fn listener_http3_false_disables_global_default() {
    let cfg = load(
        r#"
[global.http3]
enabled = true
[[listener]]
addr = "127.0.0.1:443"
  [listener.http3]
  enabled = false
  [[listener.route]]
  type = "tls"
  match_sni = ["disabled.example"]
"#,
    )
    .unwrap();
    assert_eq!(cfg.expanded_listeners().unwrap().len(), 1);
}

#[test]
fn template_can_enable_http3_companion() {
    let cfg = load(
        r#"
[templates.web]
type = "tls"
  [templates.web.http3]
  enabled = true
[[listener]]
addr = "127.0.0.1:443"
  [[listener.route]]
  use = "web"
  match_sni = ["template.example"]
"#,
    )
    .unwrap();
    let expanded = cfg.expanded_listeners().unwrap();
    assert_eq!(expanded.len(), 2);
    let route = &expanded[1].routes[0];
    assert_eq!(route.route_type, None);
    let template_name = route.use_template.as_deref().unwrap();
    let template = cfg.templates.get(template_name).unwrap();
    let configured_type = Config::effective_route_type(route, Some(template)).unwrap();
    assert_eq!(configured_type, RouteType::Tls);
    assert_eq!(
        Config::runtime_route_type(expanded[1].transport, configured_type),
        Some(RouteType::H3)
    );
}

#[test]
fn global_http3_maps_ech_and_raw() {
    let cfg = load(
        r#"
[global.http3]
enabled = true
[[listener]]
addr = "127.0.0.1:443"
  [[listener.route]]
  type = "ech"
  match_sni = ["private.example"]
  [[listener.route]]
  type = "raw"
  match_sni = ["raw.example"]
"#,
    )
    .unwrap();
    let expanded = cfg.expanded_listeners().unwrap();
    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::Ech));
    assert_eq!(expanded[1].routes[1].route_type, Some(RouteType::Raw));
    assert_eq!(
        Config::runtime_route_type(
            expanded[1].transport,
            expanded[1].routes[0].route_type.unwrap()
        ),
        Some(RouteType::H3Ech)
    );
}

#[test]
fn global_http3_skips_cleartext_http_without_translation() {
    let cfg = load(
        r#"
[global.http3]
enabled = true
[[listener]]
addr = "127.0.0.1:443"
  [[listener.route]]
  type = "http"
  match_sni = ["plain.example"]
"#,
    )
    .unwrap();
    assert_eq!(cfg.expanded_listeners().unwrap().len(), 1);
}

#[test]
fn explicit_route_http3_on_cleartext_http_is_rejected() {
    let error = load(
        r#"
[[listener]]
addr = "127.0.0.1:443"
  [[listener.route]]
  type = "http"
  match_sni = ["plain.example"]
    [listener.route.http3]
    enabled = true
"#,
    )
    .expect_err("explicit HTTP/3 on cleartext HTTP must be rejected");
    assert!(error
        .to_string()
        .contains("http3 cannot be enabled explicitly"));
}

#[test]
fn explicit_quic_listener_suppresses_automatic_companion() {
    let cfg = load(
        r#"
[global.http3]
enabled = true
[[listener]]
addr = "127.0.0.1:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["auto.example"]
[[listener]]
addr = "127.0.0.1:443"
transport = "quic"
  [[listener.route]]
  type = "raw"
  match_sni = ["manual.example"]
"#,
    )
    .unwrap();
    let expanded = cfg.expanded_listeners().unwrap();
    assert_eq!(expanded.len(), 2);
    let quic: Vec<_> = expanded
        .iter()
        .filter(|l| l.transport == ListenerTransport::Quic)
        .collect();
    assert_eq!(quic.len(), 1);
    assert_eq!(quic[0].routes[0].route_type, Some(RouteType::Raw));
}
