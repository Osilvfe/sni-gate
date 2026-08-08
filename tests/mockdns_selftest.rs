//! Validates the mock DNS server in `tests/common` against the real hickory
//! resolver embedded in the gateway binary.
//!
//! This is a test *of the test harness*. If the wire format were wrong, every
//! resolver e2e test built on it would fail for reasons that have nothing to do
//! with the code under test, so the harness gets its own proof: drive the binary
//! with `resolver = "udp://127.0.0.1:<mock>"` and assert the gateway both
//! queried the mock and dialed the address the mock handed back.

mod common;

use common::{
    free_port, preamble, spawn_mock_backend, spawn_sni_gate, tempdir, wait_port, MockDns,
};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};

/// DNS qtype for A.
const A: u16 = 1;

#[test]
fn mock_dns_answers_the_gateways_a_lookup() {
    let dir = tempdir();
    let (backend, _bh) = spawn_mock_backend();
    // The upstream name resolves to loopback, where the mock backend listens, so
    // "the gateway dialed what the mock said" is observable as a real response.
    let dns = MockDns::builder()
        .a("upstream.test", Ipv4Addr::LOCALHOST)
        .start();

    let listen = free_port();
    let config = format!(
        r#"
[global]
resolver = "udp://127.0.0.1:{dns_port}"
address_family = "ipv4"
unmatched = "close"
{preamble}
[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "raw"
  type = "raw"
  match_sni = [".raw.test"]
  upstream = "upstream.test:{backend}"
"#,
        dns_port = dns.port(),
        preamble = preamble(),
    );
    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let mut s = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x.raw.test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();

    assert!(
        resp.contains("200 OK"),
        "the gateway should have reached the backend at the address the mock \
         returned; response was {resp:?}"
    );
    assert!(
        dns.asked_type("upstream.test", A),
        "the gateway should have sent an A query for upstream.test to the \
         configured resolver; queries seen: {:?}",
        dns.queries()
    );
}
