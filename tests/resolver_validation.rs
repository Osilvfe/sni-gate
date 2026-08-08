//! Load-time validation of `[resolvers]`: cycle detection, unknown names,
//! namespace collisions, ECH config completeness.

mod common;

use common::{preamble, run_sni_gate_to_completion, tempdir};

#[test]
fn cycle_a_to_b_to_a_is_rejected() {
    let dir = tempdir();
    let config = format!(
        r#"
[global]
{preamble}
[[listener]]
addr = "127.0.0.1:9999"
  [[listener.route]]
  name = "x"
  type = "raw"
  match_sni = ["x.test"]
  upstream = "127.0.0.1:1"

[resolvers.a]
endpoint = "https://a.test/dns-query"
bootstrap = "b"

[resolvers.b]
endpoint = "https://b.test/dns-query"
bootstrap = "a"
"#,
        preamble = preamble()
    );
    let (ok, out) = run_sni_gate_to_completion(&config, dir.path());
    assert!(
        !ok,
        "cycle should have been rejected at load; output:\n{out}"
    );
    assert!(
        out.contains("cycle") && out.contains("a -> b -> a"),
        "error should name the cycle; got:\n{out}"
    );
}

#[test]
fn unknown_resolver_reference_is_rejected() {
    let dir = tempdir();
    let config = format!(
        r#"
[global]
resolver = "typo"
{preamble}
[[listener]]
addr = "127.0.0.1:9999"
  [[listener.route]]
  name = "x"
  type = "raw"
  match_sni = ["x.test"]
  upstream = "127.0.0.1:1"
"#,
        preamble = preamble()
    );
    let (ok, out) = run_sni_gate_to_completion(&config, dir.path());
    assert!(!ok, "unknown resolver should be rejected; output:\n{out}");
    assert!(
        out.contains("unknown resolver") && out.contains("typo"),
        "error should name the unknown resolver; got:\n{out}"
    );
}

#[test]
fn static_ech_without_config_is_rejected() {
    let dir = tempdir();
    let config = format!(
        r#"
[global]
{preamble}
[[listener]]
addr = "127.0.0.1:9999"
  [[listener.route]]
  name = "x"
  type = "raw"
  match_sni = ["x.test"]
  upstream = "127.0.0.1:1"

[resolvers.r]
endpoint = "https://doh.test/dns-query"
  [resolvers.r.ech]
  mode = "static"
"#,
        preamble = preamble()
    );
    let (ok, out) = run_sni_gate_to_completion(&config, dir.path());
    assert!(
        !ok,
        "static ECH without config should be rejected; output:\n{out}"
    );
    assert!(
        out.contains("mode = \"static\"") && out.contains("config"),
        "error should explain the missing config; got:\n{out}"
    );
}

#[test]
fn resolver_name_that_looks_like_a_spec_is_rejected() {
    let dir = tempdir();
    let config = format!(
        r#"
[global]
{preamble}
[[listener]]
addr = "127.0.0.1:9999"
  [[listener.route]]
  name = "x"
  type = "raw"
  match_sni = ["x.test"]
  upstream = "127.0.0.1:1"

[resolvers."https://ambiguous.test/dns-query"]
endpoint = "https://real.test/dns-query"
"#,
        preamble = preamble()
    );
    let (ok, out) = run_sni_gate_to_completion(&config, dir.path());
    assert!(!ok, "ambiguous name should be rejected; output:\n{out}");
    assert!(
        out.contains("would also parse as an inline") && out.contains("ambiguous"),
        "error should explain the ambiguity; got:\n{out}"
    );
}

#[test]
fn self_bootstrap_is_rejected() {
    let dir = tempdir();
    let config = format!(
        r#"
[global]
{preamble}
[[listener]]
addr = "127.0.0.1:9999"
  [[listener.route]]
  name = "x"
  type = "raw"
  match_sni = ["x.test"]
  upstream = "127.0.0.1:1"

[resolvers.r]
endpoint = "https://doh.test/dns-query"
bootstrap = "r"
"#,
        preamble = preamble()
    );
    let (ok, out) = run_sni_gate_to_completion(&config, dir.path());
    assert!(
        !ok,
        "resolver bootstrapping from itself should be rejected; output:\n{out}"
    );
    assert!(
        out.contains("bootstrap") && out.contains("itself"),
        "error should explain the self-reference; got:\n{out}"
    );
}
