//! Shared end-to-end test scaffolding: a temp working directory, a launcher for
//! the built binary, a mock TCP backend, and a **mock DNS server**.
//!
//! This lives in `tests/common/` (a subdirectory, so cargo does not compile it as
//! its own test binary) and is pulled into each integration test with
//! `mod common;`.
//!
//! # Why a mock DNS server
//!
//! Named resolvers are a DNS feature, and a DNS feature that is only unit-tested
//! is only tested against its own idea of how DNS behaves. The mock closes that
//! gap while staying hermetic — no network, no external tools, so it runs
//! unmodified in CI on every platform.
//!
//! The mock's important property is not that it answers, but that it **records
//! what it was asked**. "Which resolver performed this lookup?" is otherwise
//! invisible from outside the process, and it is exactly the question every
//! interesting resolver behaviour turns on: whether a reference resolved to the
//! resolver the operator named, whether a bootstrap edge was actually walked,
//! whether `addr_resolver` and `ech_resolver` really can be different servers.
//! Two mocks plus their query logs make those assertions directly, at the wire.

#![allow(dead_code)] // Each test binary uses a different subset of these helpers.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Temp working directory
// ---------------------------------------------------------------------------

/// A working directory that is removed when the test ends.
pub struct TempDir(std::path::PathBuf);

impl TempDir {
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Create a unique temp directory for one test.
///
/// Named by pid **and** a process-wide counter. The counter is load-bearing:
/// tests run in parallel threads, and any scheme derived from a stack address can
/// repeat across threads with identical stack layouts — two tests then share one
/// directory, each reads the other's CA, and both fail with a signature error.
pub fn tempdir() -> TempDir {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut base = std::env::temp_dir();
    base.push(format!("sni-gate-it-{pid}-{n}"));
    // A leftover directory from a previous run would carry a stale CA.
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    TempDir(base)
}

/// An ephemeral port, obtained by binding and releasing.
///
/// Inherently racy in principle; in practice the OS does not hand the same port
/// out twice in quick succession, and every caller binds it immediately.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---------------------------------------------------------------------------
// The binary under test
// ---------------------------------------------------------------------------

/// A spawned child killed on drop, so a failed assertion cannot leak a process
/// still holding a listening port.
pub struct Killed(pub std::process::Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Launch the built binary with `config` written into `workdir`.
pub fn spawn_sni_gate(config: &str, workdir: &std::path::Path) -> Killed {
    spawn_sni_gate_with_log(config, workdir, "warn")
}

/// As [`spawn_sni_gate`], with an explicit `SNI_GATE_LOG` directive for tests
/// that assert on log output.
pub fn spawn_sni_gate_with_log(config: &str, workdir: &std::path::Path, log: &str) -> Killed {
    std::fs::write(workdir.join("sni-gate.toml"), config).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_sni-gate"))
        .arg("-c")
        .arg(workdir.join("sni-gate.toml"))
        .current_dir(workdir)
        .env("SNI_GATE_LOG", log)
        .spawn()
        .expect("spawn sni-gate");
    Killed(child)
}

/// Run the binary to completion and return `(success, combined output)`.
///
/// For load-time rejections: the process is expected to exit non-zero having
/// printed a diagnostic. Both streams are captured because a configuration error
/// is printed to stderr while the tracing layer writes to stdout, and a test
/// should not depend on which one carries the message.
pub fn run_sni_gate_to_completion(config: &str, workdir: &std::path::Path) -> (bool, String) {
    std::fs::write(workdir.join("sni-gate.toml"), config).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sni-gate"))
        .arg("-c")
        .arg(workdir.join("sni-gate.toml"))
        .current_dir(workdir)
        .env("SNI_GATE_LOG", "info")
        .output()
        .expect("run sni-gate");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), combined)
}

/// Poll until a TCP port accepts connections. Panics after ~10s.
pub fn wait_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("port {port} never came up");
}

/// Wait until `f` holds, polling every 50ms up to ~5s. Returns whether it did.
///
/// Used for assertions about work the gateway performs at startup (a bootstrap
/// lookup, say) which completes slightly after the listening port opens.
pub fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// ---------------------------------------------------------------------------
// Mock TCP backend
// ---------------------------------------------------------------------------

/// A trivial upstream: read the request, reply `200 OK`. Enough to prove bytes
/// traversed the gateway and reached the address it dialed.
pub fn spawn_mock_backend() -> (u16, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { break };
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
                );
                let _ = s.flush();
            });
        }
    });
    (port, handle)
}

// ---------------------------------------------------------------------------
// Mock DNS server
// ---------------------------------------------------------------------------

/// One record the mock is willing to answer with.
#[derive(Clone)]
enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// An HTTPS (RFC 9460, RR type 65) record carrying only an `ech=` SvcParam.
    HttpsEch(Vec<u8>),
}

impl Rdata {
    fn rtype(&self) -> u16 {
        match self {
            Rdata::A(_) => 1,
            Rdata::Aaaa(_) => 28,
            Rdata::HttpsEch(_) => 65,
        }
    }

    /// Encode just the RDATA field.
    fn encode(&self) -> Vec<u8> {
        match self {
            Rdata::A(ip) => ip.octets().to_vec(),
            Rdata::Aaaa(ip) => ip.octets().to_vec(),
            Rdata::HttpsEch(list) => {
                let mut v = Vec::with_capacity(list.len() + 8);
                v.extend_from_slice(&1u16.to_be_bytes()); // SvcPriority = 1
                v.push(0); // TargetName "." — the owner name itself
                v.extend_from_slice(&5u16.to_be_bytes()); // SvcParamKey 5 = ech
                v.extend_from_slice(&(list.len() as u16).to_be_bytes());
                v.extend_from_slice(list);
                v
            }
        }
    }
}

/// A UDP DNS server that answers from a fixed table and logs every question.
///
/// Only the wire subset the gateway exercises is implemented: a single-question
/// query over UDP, answered with A / AAAA / HTTPS records. Anything not in the
/// table gets an authoritative empty answer (NODATA), which is what makes a
/// negative case — "this name has no HTTPS record" — testable too.
pub struct MockDns {
    port: u16,
    log: Arc<Mutex<Vec<(String, u16)>>>,
    /// Dropping this stops the server thread at its next poll.
    _stop: Arc<StopFlag>,
}

struct StopFlag(std::sync::atomic::AtomicBool);

impl Drop for StopFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Builder for [`MockDns`].
#[derive(Default)]
pub struct MockDnsBuilder {
    zones: HashMap<(String, u16), Vec<Rdata>>,
}

impl MockDnsBuilder {
    /// Answer `name` with an A record.
    pub fn a(mut self, name: &str, ip: Ipv4Addr) -> Self {
        self.zones
            .entry((normalize(name), 1))
            .or_default()
            .push(Rdata::A(ip));
        self
    }

    /// Answer `name` with an AAAA record.
    pub fn aaaa(mut self, name: &str, ip: Ipv6Addr) -> Self {
        self.zones
            .entry((normalize(name), 28))
            .or_default()
            .push(Rdata::Aaaa(ip));
        self
    }

    /// Answer `name` with an HTTPS record whose `ech=` param carries
    /// `ech_config_list` verbatim.
    ///
    /// The bytes need not be a *usable* ECHConfigList: several behaviours worth
    /// testing (that the record was fetched at all, that a rebuild refetches it,
    /// that a rotation is noticed) are about acquisition, not about HPKE. Tests
    /// that need a well-formed list say so explicitly.
    pub fn https_ech(mut self, name: &str, ech_config_list: Vec<u8>) -> Self {
        self.zones
            .entry((normalize(name), 65))
            .or_default()
            .push(Rdata::HttpsEch(ech_config_list));
        self
    }

    /// Bind and start serving.
    pub fn start(self) -> MockDns {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        // A read timeout is what lets the thread notice the stop flag; without it
        // recv_from would block forever and the thread would outlive the test.
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();

        let log: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(StopFlag(std::sync::atomic::AtomicBool::new(false)));

        let zones = self.zones;
        let thread_log = log.clone();
        let thread_stop = stop.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            loop {
                if thread_stop.0.load(Ordering::Relaxed) {
                    return;
                }
                let (n, from) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue, // timeout: re-check the stop flag
                };
                let Some(q) = parse_question(&buf[..n]) else {
                    continue;
                };
                thread_log.lock().unwrap().push((q.name.clone(), q.qtype));
                let answers = zones
                    .get(&(q.name.clone(), q.qtype))
                    .cloned()
                    .unwrap_or_default();
                let reply = build_reply(&buf[..n], &q, &answers);
                let _ = sock.send_to(&reply, from);
            }
        });

        MockDns {
            port,
            log,
            _stop: stop,
        }
    }
}

impl MockDns {
    pub fn builder() -> MockDnsBuilder {
        MockDnsBuilder::default()
    }

    /// The port to point a `udp://127.0.0.1:<port>` resolver spec at.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Every question received so far, as `(name, qtype)` with the name
    /// lowercased and stripped of its trailing dot.
    pub fn queries(&self) -> Vec<(String, u16)> {
        self.log.lock().unwrap().clone()
    }

    /// Whether any question was asked for `name` (of any type).
    pub fn asked(&self, name: &str) -> bool {
        let want = normalize(name);
        self.queries().iter().any(|(n, _)| *n == want)
    }

    /// Whether a question was asked for `name` with `qtype`.
    pub fn asked_type(&self, name: &str, qtype: u16) -> bool {
        let want = normalize(name);
        self.queries()
            .iter()
            .any(|(n, t)| *n == want && *t == qtype)
    }

    /// How many questions arrived in total. Lets a test assert that a *second*
    /// resolver was never consulted (count stays zero) or that a refresh
    /// actually re-queried (count grows).
    pub fn count(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

/// A parsed question: the name, its type, and where the question section ends.
struct Question {
    name: String,
    qtype: u16,
    end: usize,
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Parse the single question of a DNS query.
///
/// Deliberately strict and allocation-light: labels only, no compression
/// pointers (a query's own question never uses them), and a hard bound on the
/// name so a malformed datagram cannot spin.
fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut i = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *msg.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        // 0xC0 marks a compression pointer, which a question never contains.
        if len >= 0xC0 || labels.len() > 127 {
            return None;
        }
        let label = msg.get(i..i + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        i += len;
    }
    let qtype = u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]);
    Some(Question {
        name: labels.join("."),
        qtype,
        end: i + 4, // QTYPE + QCLASS
    })
}

/// Build an authoritative reply echoing the question and appending `answers`.
///
/// An empty `answers` yields NODATA (RCODE 0, ANCOUNT 0) rather than NXDOMAIN:
/// the name exists, this type does not, which is the honest answer for "no
/// HTTPS record published" and is what a resolver library expects there.
fn build_reply(query: &[u8], q: &Question, answers: &[Rdata]) -> Vec<u8> {
    // QR=1 (response), Opcode=0, AA=1 (authoritative), RD/RA mirrored on.
    const FLAGS: u16 = 0x8580;

    let mut out = Vec::with_capacity(64 + answers.len() * 32);
    out.extend_from_slice(&query[0..2]); // echo the transaction ID
    out.extend_from_slice(&FLAGS.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query[12..q.end]); // question, verbatim

    for a in answers {
        // Point the owner name at the question's name at offset 12 rather than
        // re-encoding it.
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&a.rtype().to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        out.extend_from_slice(&5u32.to_be_bytes()); // TTL: short, so refresh paths are testable
        let rdata = a.encode();
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

// ---------------------------------------------------------------------------
// Config fragments
// ---------------------------------------------------------------------------

/// The `[ca]` / `[cache.psl]` preamble every e2e config needs.
///
/// `source = "embedded"` keeps the public-suffix list off the network, which is
/// what makes these tests hermetic.
pub fn preamble() -> String {
    r#"
[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "E2E CA"
leaf_validity_days = 90
[psl]
source = "embedded"
"#
    .to_string()
}
