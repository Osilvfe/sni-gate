//! End-to-end tests for named resolvers: proving `[resolvers.<name>]` actually
//! works through hermetic mock DNS servers that log every query received.

mod common;

use common::{
    free_port, preamble, spawn_mock_backend, spawn_sni_gate, tempdir, wait_port, MockDns,
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};

/// A named resolver answers a route's upstream lookup, and the mock DNS log
/// proves it was asked.
#[test]
fn named_resolver_answers_upstream_lookup() {
    let dir = tempdir();
    let mock = MockDns::builder()
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();
    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"
[global]
resolver = "@test-dns"
address_family = "ipv4"
{preamble}

[resolvers.test-dns]
endpoint = "127.0.0.1:{dns_port}"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        dns_port = mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(resp.contains("200 OK"), "backend not reached: {resp}");
    assert!(mock.asked("upstream.test"), "resolver was not asked");
    assert_eq!(mock.count(), 1, "should be exactly one query");
}

/// Bootstrap chain: resolver A's endpoint host is resolved by resolver B (the
/// bootstrap), and the query log proves B was asked for A's host.
#[test]
fn bootstrap_resolver_answers_endpoint_lookup() {
    let dir = tempdir();

    let bootstrap_mock = MockDns::builder()
        .a("resolver-a.example", Ipv4Addr::new(127, 0, 0, 1))
        .start();

    let resolver_a_mock = MockDns::builder()
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();

    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"
[global]
resolver = "@resolver-a"
address_family = "ipv4"
{preamble}

[resolvers.bootstrap]
endpoint = "127.0.0.1:{bootstrap_port}"

[resolvers.resolver-a]
endpoint = "udp://resolver-a.example:{resolver_a_port}"
bootstrap = "@bootstrap"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        bootstrap_port = bootstrap_mock.port(),
        resolver_a_port = resolver_a_mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(resp.contains("200 OK"), "backend not reached");
    assert!(
        bootstrap_mock.asked("resolver-a.example"),
        "bootstrap resolver was not asked for the endpoint host"
    );
    assert!(
        resolver_a_mock.asked("upstream.test"),
        "resolver-a was not asked for upstream"
    );
}

/// `upstream` override dials a different target while the endpoint name stays
/// unchanged (for TLS transports, SNI and authority remain the original).
#[test]
fn upstream_override_changes_dial_target() {
    let dir = tempdir();
    let mock = MockDns::builder()
        .a("edge.cdn.test", Ipv4Addr::new(127, 0, 0, 1))
        .a("upstream.test", Ipv4Addr::new(127, 0, 0, 1))
        .start();
    let (backend_port, _bh) = spawn_mock_backend();
    let listen = free_port();

    // Use a plain DNS endpoint with hostname, where upstream override
    // changes the dial target.
    let config = format!(
        r#"
[global]
resolver = "@test-dns"
address_family = "ipv4"
{preamble}

[resolvers.test-dns]
endpoint = "udp://dns.original.test:{dns_port}"
upstream = "edge.cdn.test"
bootstrap = "@boot"

[resolvers.boot]
endpoint = "127.0.0.1:{dns_port}"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  type = "raw"
  name = "x"
  match_sni = ["x.test"]
  upstream = "upstream.test:{backend_port}"
"#,
        preamble = preamble(),
        dns_port = mock.port(),
        listen = listen,
        backend_port = backend_port
    );

    let _gw = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.0\r\nHost: x.test\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(resp.contains("200 OK"), "backend not reached");
    assert!(
        mock.asked("edge.cdn.test"),
        "bootstrap was not asked for the upstream override target"
    );
    assert!(
        mock.asked("upstream.test"),
        "test-dns was not asked for upstream"
    );
}
