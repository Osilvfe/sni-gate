//! End-to-end coverage for live pool failover.
//!
//! The regular pool E2E suite proves that active probes exclude endpoints that
//! were already dead. This test covers the harder race: an endpoint was healthy
//! when ranked, then stops accepting connections before the next client arrives.
//! The same client request must try the next published endpoint instead of
//! waiting for a later probe cycle to repair the ranking.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use common::{free_port, preamble, spawn_sni_gate, tempdir, wait_port};

struct StoppableBackend {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl StoppableBackend {
    fn spawn(listener: TcpListener, marker: &'static str) -> Self {
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread::spawn(move || {
                            // TCP probes connect and immediately close, so this
                            // blocking read returns EOF for probes. An actual
                            // client connection stays open until the gateway
                            // forwards its request. Do not put a scheduler-based
                            // deadline here: on busy Windows runners that races
                            // the very failover path this fixture is testing.
                            let mut buf = [0u8; 4096];
                            let n = stream.read(&mut buf).unwrap_or(0);
                            if n != 0 {
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    marker.len(),
                                    marker
                                );
                                let _ = stream.write_all(response.as_bytes());
                                let _ = stream.flush();
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }

    /// Wait until the OS itself reports this listener as unreachable.
    ///
    /// Windows may complete a TCP connect that was already queued when the
    /// listening socket is closed. Such a connection is *not* a P1 failover
    /// condition: the gateway correctly sees TCP connect success and only later
    /// observes that no application bytes arrive. Establish the test's actual
    /// precondition — a TCP connect error — before asking the gateway to retry.
    fn stop_and_wait_unreachable(&mut self) {
        self.stop();
        for _ in 0..100 {
            match TcpStream::connect_timeout(&self.addr, Duration::from_millis(50)) {
                Ok(stream) => drop(stream),
                Err(_) => return,
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "backend listener {} still accepted TCP after shutdown",
            self.addr
        );
    }
}

impl Drop for StoppableBackend {
    fn drop(&mut self) {
        self.stop();
    }
}

fn request_once(listen: u16, host: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", listen))?;
    // This is only a test watchdog, not part of the behavior under test. Leave
    // enough room for a loaded cross-platform runner to schedule both the
    // gateway and the mock backend after the first TCP attempt fails.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn wait_for_ranked_backend(listen: u16, host: &str) -> String {
    let mut last = String::new();
    for _ in 0..120 {
        if let Ok(response) = request_once(listen, host) {
            last = response;
            if last.contains("200 OK") {
                return last;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("pool never published a live backend; last response: {last:?}");
}

#[test]
fn a_ranked_endpoint_that_dies_fails_over_within_the_same_request() {
    let dir = tempdir();

    // One route port, two independent standard loopback addresses. IPv4 + IPv6
    // is portable across Linux, macOS and Windows, unlike assuming an additional
    // 127/8 alias is configured on every runner. Pre-bind both listeners so
    // there is no free-port race while they share the route's upstream port.
    let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = listener_a.local_addr().unwrap().port();
    let listener_b = TcpListener::bind(("::1", backend_port)).unwrap();
    let mut backend_a = StoppableBackend::spawn(listener_a, "backend-v4");
    let mut backend_b = StoppableBackend::spawn(listener_b, "backend-v6");

    let listen = free_port();
    let config = format!(
        r#"{}
[pools.edge]
targets = ["127.0.0.1", "::1"]

[pools.edge.probe]
mode = "tcp"
port = {backend_port}
timeout = "500ms"
interval = "30s"
degraded_interval = "1s"
fail_threshold = 3

[[listener]]
addr = "127.0.0.1:{listen}"
  [[listener.route]]
  name = "pooled-live-failover"
  type = "http"
  match_sni = [".pool.test"]
  upstream = "@edge:{backend_port}"
"#,
        preamble()
    );

    let _sg = spawn_sni_gate(&config, dir.path());
    wait_port(listen);

    // The first successful request tells us which ranked endpoint currently
    // leads, without depending on tiny and nondeterministic loopback RTTs.
    let first = wait_for_ranked_backend(listen, "live.pool.test");
    let expected_second = if first.contains("backend-v4") {
        backend_a.stop_and_wait_unreachable();
        "backend-v6"
    } else if first.contains("backend-v6") {
        backend_b.stop_and_wait_unreachable();
        "backend-v4"
    } else {
        panic!("unexpected backend response: {first:?}");
    };

    // Exactly one request after the leader disappears. The 30s active-probe
    // interval deliberately leaves the published ranking stale. Passive
    // feedback may ask the pool task to verify the failed address sooner, but it
    // never changes health itself; success here therefore requires the data path
    // to try the next address from this request's immutable DialPlan.
    let second = request_once(listen, "live.pool.test").unwrap_or_default();
    assert!(
        second.contains("200 OK") && second.contains(expected_second),
        "the stale ranked leader was not failed over within the same request: {second:?}"
    );
}
