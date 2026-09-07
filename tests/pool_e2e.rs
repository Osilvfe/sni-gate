//! End-to-end tests for upstream pools, against the built binary.
//!
//! # What these cover that unit tests cannot
//!
//! The unit tests in `src/pool.rs` verify the ranking algebra — smoothing,
//! hysteresis, backoff — on synthetic state. What they cannot verify is that the
//! pieces are *wired together*: that a `@pool` reference survives config parsing,
//! that the probe task actually runs and publishes, that the data path reads the
//! ranking it publishes, and that a candidate nothing answers on never receives
//! traffic. Each of those is a seam between two components, and a seam is exactly
//! what a unit test mocks away.
//!
//! # Staying hermetic
//!
//! No network and no external tools. Live candidates are `127.0.0.1`; dead ones
//! are `192.0.2.1` (RFC 5737 TEST-NET-1, reserved for documentation and
//! guaranteed not to be routed), so "never answers" is a property of the address
//! rather than of the machine running the test.
//!
//! Routes here are `type = "http"` with cleartext inbound: the routing key comes
//! from the `Host` header, which keeps these tests about pool selection instead of
//! about TLS termination (covered in `e2e.rs`).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::{
    free_port, preamble, run_sni_gate_to_completion, spawn_mock_backend, spawn_sni_gate, tempdir,
    wait_port, MockDns,
};

/// An address that accepts nothing. RFC 5737 reserves 192.0.2.0/24 for
/// documentation, so nothing routes it and a connect attempt cannot accidentally
/// reach a real host on a developer's network.
const DEAD_IP: &str = "192.0.2.1";

/// Send one cleartext HTTP request through the gateway with `host`, retrying
/// until the pool has completed a probe cycle and published a ranking.
///
/// The retry is the point, not a workaround: a pool deliberately serves nothing
/// until it has *measured* something, so a request that arrives before the first
/// cycle is correctly refused. This asserts the steady state is reached, and that
/// it is reached without intervention.
fn get_via_gateway(listen: u16, host: &str) -> String {
    let mut last = String::new();
    for _ in 0..120 {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", listen)) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            if s.write_all(req.as_bytes()).is_ok() {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                last = String::from_utf8_lossy(&buf).into_owned();
                if last.contains("200 OK") {
                    return last;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    last
}

/// The end-to-end path: a pool probes a candidate, ranks it, and the data path
/// dials the address the pool chose.
#[test]
fn a_pool_routes_traffic_to_its_probed_candidate() {
    let dir = tempdir();
    let (backend, _b) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"{}
[pools.edge]
targets = ["127.0.0.1"]

[pools.edge.probe]
mode = "tcp"
port = {backend}
timeout = "1s"
interval = "5s"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "pooled"
  type = "http"
  match_sni = [".pool.test"]
  upstream = "@edge:{backend}"
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let resp = get_via_gateway(listen, "a.pool.test");
    assert!(
        resp.contains("200 OK"),
        "traffic never reached the pooled backend: {resp:?}"
    );
}

/// A candidate nothing answers on is never ranked, so it never receives traffic —
/// even when it is listed first.
///
/// This is the failover property stated as an observable: the dead address is
/// index 0, and a pool that ignored health would send every request into a
/// timeout.
#[test]
fn a_pool_never_dials_a_candidate_that_never_answered() {
    let dir = tempdir();
    let (backend, _b) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"{}
[pools.edge]
targets = ["{DEAD_IP}", "127.0.0.1"]

[pools.edge.probe]
mode = "tcp"
port = {backend}
timeout = "600ms"
interval = "5s"
degraded_interval = "1s"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "pooled"
  type = "http"
  match_sni = [".pool.test"]
  upstream = "@edge:{backend}"
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let resp = get_via_gateway(listen, "a.pool.test");
    assert!(
        resp.contains("200 OK"),
        "the pool did not fail over to its healthy candidate: {resp:?}"
    );
}

/// Send one request with a hard deadline, returning the response or `None`.
///
/// Unlike [`get_via_gateway`] this does **not** wait for a probe cycle: it exists
/// to assert that something is served *before* one completes.
fn get_within(listen: u16, host: &str, deadline: Duration) -> Option<String> {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", listen)) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
            let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            if s.write_all(req.as_bytes()).is_ok() {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                let resp = String::from_utf8_lossy(&buf).into_owned();
                if resp.contains("200 OK") {
                    return Some(resp);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// The fallback must be usable from the first connection, not only after the
/// first probe cycle finishes.
///
/// A regression test for the defect that motivated this: the ranking was
/// published *after* probing, so `pick` returned an error for the whole first
/// cycle. That window is not small — a few hundred sampled candidates at the
/// concurrency cap runs for tens of seconds — and on a `tls`/`ech` route with
/// HTTP/2 enabled the upstream is dialed before the inbound handshake completes,
/// so it surfaced to clients as a broken TLS handshake with no useful diagnostic.
///
/// The pool here is built so its first cycle *cannot* finish quickly: 30
/// unroutable candidates at a 10s timeout, which is ~20s at a concurrency of 16.
/// The assertion allows 5s. Before the fix that is a guaranteed failure; after it,
/// traffic flows as soon as the fallback target resolves.
#[test]
fn the_fallback_serves_traffic_before_the_first_probe_cycle_completes() {
    let dir = tempdir();
    let (backend, _b) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"{}
[pools.edge]
# [0] the live fallback, a literal so it needs no DNS.
# [1] 30 unroutable addresses, so the first cycle takes ~20s.
targets = ["127.0.0.1", "192.0.2.0/24[30]"]
fallback = 0

[pools.edge.probe]
mode = "tcp"
port = {backend}
timeout = "10s"
interval = "5m"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "pooled"
  type = "http"
  match_sni = [".pool.test"]
  upstream = "@edge:{backend}"
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let resp = get_within(listen, "a.pool.test", Duration::from_secs(5));
    assert!(
        resp.is_some(),
        "the pool served nothing within 5s: its fallback is not published until \
         the first probe cycle completes"
    );
}

/// A domain target contributes **every** address it publishes, not just the
/// first.
///
/// This is a regression test for a real defect: resolving a pool target through
/// the single-address `lookup_addr` yielded one candidate per family, silently
/// discarding the alternatives a pool exists to rank. The mock serves two A
/// records with the dead one **first**, so a pool that takes only the first record
/// has nothing healthy and fails, while one that expands all records degrades the
/// dead address and routes through the live one.
#[test]
fn a_domain_target_expands_to_every_published_address() {
    let dir = tempdir();
    let (backend, _b) = spawn_mock_backend();
    let listen = free_port();

    // Order matters: the unroutable address is answered first.
    let dns = MockDns::builder()
        .a("edge.pool.test", DEAD_IP.parse().unwrap())
        .a("edge.pool.test", "127.0.0.1".parse().unwrap())
        .start();

    let config = format!(
        r#"{}
[pools.edge]
targets = ["edge.pool.test"]
resolver = "udp://127.0.0.1:{}"

[pools.edge.probe]
mode = "tcp"
port = {backend}
timeout = "600ms"
interval = "5s"
degraded_interval = "1s"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "pooled"
  type = "http"
  match_sni = [".pool.test"]
  upstream = "@edge:{backend}"
"#,
        preamble(),
        dns.port()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let resp = get_via_gateway(listen, "a.pool.test");
    assert!(
        resp.contains("200 OK"),
        "the pool did not expand its domain target to every A record: {resp:?}"
    );
    assert!(
        dns.asked("edge.pool.test"),
        "the pool never resolved its domain target through the configured resolver"
    );
}

/// `select` restricts a route to a subset of a pool's candidates, addressed by
/// target index — and traffic still flows through the selected one.
#[test]
fn select_by_index_restricts_a_route_to_one_target() {
    let dir = tempdir();
    let (backend, _b) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"{}
[pools.edge]
targets = ["{DEAD_IP}", "127.0.0.1"]

[pools.edge.probe]
mode = "tcp"
port = {backend}
timeout = "600ms"
interval = "5s"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "pooled"
  type = "http"
  match_sni = [".pool.test"]
  upstream = "@edge:{backend}"
  select = [1]
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    let resp = get_via_gateway(listen, "a.pool.test");
    assert!(
        resp.contains("200 OK"),
        "select = [1] did not route to target 1: {resp:?}"
    );
}

/// Two targets may legitimately resolve to the same address. The endpoint is
/// probed once, but both target-index and custom-tag identities must survive.
#[test]
fn same_address_keeps_each_targets_selection_identity() {
    let dir = tempdir();
    let (backend, _b) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"{}
[pools.edge]
targets = [
  {{ addr = "127.0.0.1", tags = ["first"] }},
  {{ addr = "127.0.0.1", tags = ["second"] }},
]

[pools.edge.probe]
mode = "tcp"
port = {backend}
timeout = "1s"
interval = "5s"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "by-index"
  type = "http"
  match_sni = [".index.test"]
  upstream = "@edge:{backend}"
  select = [1]

  [[listener.route]]
  name = "by-tag"
  type = "http"
  match_sni = [".tag.test"]
  upstream = "@edge:{backend}"
  select = ["second"]
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);
    for host in ["a.index.test", "a.tag.test"] {
        let resp = get_via_gateway(listen, host);
        assert!(
            resp.contains("200 OK"),
            "{host} lost the shared address's target/tag provenance: {resp:?}"
        );
    }
}

/// Two routes reading different views of one pool both work, which is what
/// `register_view` deduplication and per-view publishing exist to support.
#[test]
fn two_routes_can_read_different_views_of_one_pool() {
    let dir = tempdir();
    let (backend, _b) = spawn_mock_backend();
    let listen = free_port();

    let config = format!(
        r#"{}
[pools.edge]
targets = ["127.0.0.1"]

[pools.edge.probe]
mode = "tcp"
port = {backend}
timeout = "1s"
interval = "5s"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "by-tag"
  type = "http"
  match_sni = [".tag.test"]
  upstream = "@edge:{backend}"
  select = ["ipv4"]

  [[listener.route]]
  name = "unfiltered"
  type = "http"
  match_sni = [".all.test"]
  upstream = "@edge:{backend}"
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    for host in ["a.tag.test", "a.all.test"] {
        let resp = get_via_gateway(listen, host);
        assert!(resp.contains("200 OK"), "{host} failed: {resp:?}");
    }
}

/// A pool whose only candidate is dead serves nothing, and the route's fail
/// policy takes over rather than the pool inventing a destination.
///
/// The gateway must stay up and keep answering on its port: an unreachable
/// upstream is a route-level failure, not a startup failure.
#[test]
fn a_pool_with_no_healthy_candidate_closes_the_connection() {
    let dir = tempdir();
    let listen = free_port();
    let unused = free_port();

    let config = format!(
        r#"{}
[pools.edge]
targets = ["{DEAD_IP}"]

[pools.edge.probe]
mode = "tcp"
port = {unused}
timeout = "400ms"
interval = "2s"

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "pooled"
  type = "http"
  match_sni = [".pool.test"]
  upstream = "@edge:{unused}"
  fail = "close"
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    // The port keeps accepting; the request simply gets no response body.
    let mut s = TcpStream::connect(("127.0.0.1", listen)).expect("gateway still accepting");
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let req = "GET / HTTP/1.1\r\nHost: a.pool.test\r\nConnection: close\r\n\r\n";
    let _ = s.write_all(req.as_bytes());
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let resp = String::from_utf8_lossy(&buf);
    assert!(
        !resp.contains("200 OK"),
        "a pool with no healthy candidate must not serve traffic, got: {resp:?}"
    );
}

// ---------------------------------------------------------------------------
// Load-time rejections, asserted against the real binary
// ---------------------------------------------------------------------------

/// Run a config to completion and assert it was refused with a message
/// containing `needle`.
fn assert_rejected(config_body: &str, needle: &str) {
    let dir = tempdir();
    let config = format!("{}{config_body}", preamble());
    let (ok, out) = run_sni_gate_to_completion(&config, dir.path());
    assert!(!ok, "config should have been refused:\n{out}");
    assert!(
        out.contains(needle),
        "expected a message containing {needle:?}, got:\n{out}"
    );
}

#[test]
fn an_unknown_pool_reference_is_refused_at_startup() {
    assert_rejected(
        r#"
[[listener]]
addr = "127.0.0.1:1"
  [[listener.route]]
  type = "http"
  match_sni = [".a.test"]
  upstream = "@nope"
"#,
        "unknown pool",
    );
}

/// The guard that keeps a `/12` from expanding into a million probes. A
/// documentation note cannot enforce this, so the binary must refuse it.
#[test]
fn an_unbounded_cidr_target_is_refused_at_startup() {
    assert_rejected(
        r#"
[pools.edge]
targets = ["104.16.0.0/12"]
[pools.edge.probe]
mode = "tcp"

[[listener]]
addr = "127.0.0.1:1"
  [[listener.route]]
  type = "http"
  match_sni = [".a.test"]
  upstream = "@edge"
"#,
        "sample count",
    );
}

/// A `select` index must be within `targets` — the addressing unit that exists
/// before any DNS answer does.
#[test]
fn an_out_of_bounds_select_index_is_refused_at_startup() {
    assert_rejected(
        r#"
[pools.edge]
targets = ["127.0.0.1"]
[pools.edge.probe]
mode = "tcp"

[[listener]]
addr = "127.0.0.1:1"
  [[listener.route]]
  type = "http"
  match_sni = [".a.test"]
  upstream = "@edge"
  select = [3]
"#,
        "out of bounds",
    );
}

/// A pool owns its own resolution, so a route-scope resolution knob beside a pool
/// upstream is refused rather than silently ignored.
#[test]
fn a_resolution_knob_beside_a_pool_upstream_is_refused_at_startup() {
    assert_rejected(
        r#"
[pools.edge]
targets = ["127.0.0.1"]
[pools.edge.probe]
mode = "tcp"

[[listener]]
addr = "127.0.0.1:1"
  [[listener.route]]
  type = "http"
  match_sni = [".a.test"]
  upstream = "@edge"
  address_family = "ipv4"
"#,
        "no effect when upstream is a pool",
    );
}

/// `select` on a non-pool upstream is inert, and an inert filter is a mistake
/// worth naming.
#[test]
fn select_without_a_pool_upstream_is_refused_at_startup() {
    assert_rejected(
        r#"
[[listener]]
addr = "127.0.0.1:1"
  [[listener.route]]
  type = "http"
  match_sni = [".a.test"]
  upstream = "127.0.0.1:9"
  select = ["ipv4"]
"#,
        "not a pool reference",
    );
}

/// An `http` probe without its required fields cannot measure anything.
#[test]
fn an_incomplete_http_probe_is_refused_at_startup() {
    assert_rejected(
        r#"
[pools.edge]
targets = ["127.0.0.1"]
[pools.edge.probe]
mode = "http"
sni = "x.test"
path = "/health"

[[listener]]
addr = "127.0.0.1:1"
  [[listener.route]]
  type = "http"
  match_sni = [".a.test"]
  upstream = "@edge"
"#,
        "requires `status`",
    );
}

/// A resolver cannot dial through a pool: a pool resolves its targets *with* a
/// resolver, so the reverse edge has no base case.
#[test]
fn a_resolver_dialing_through_a_pool_is_refused_at_startup() {
    assert_rejected(
        r#"
[pools.edge]
targets = ["127.0.0.1"]
[pools.edge.probe]
mode = "tcp"

[resolvers.bad]
endpoint = "https://dns.example/dns-query"
upstream = "@edge"

[[listener]]
addr = "127.0.0.1:1"
  [[listener.route]]
  type = "http"
  match_sni = [".a.test"]
  upstream = "@edge"
  resolver = "@bad"
"#,
        "cannot dial through a pool",
    );
}
