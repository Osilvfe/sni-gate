//! Startup validation that an `http` route's backend really speaks h2c.
//!
//! A `type = "http"` route with HTTP/2 enabled splices the negotiated h2 byte
//! stream to a *cleartext* backend as a prior-knowledge h2c connection. Unlike
//! `tls`/`ech` routes — which mirror whatever ALPN the upstream selects, and so
//! self-correct per connection — nothing in the `http` data path can discover
//! that the backend only understands HTTP/1.1. The mistake would surface as
//! mystifying protocol errors under load instead of at boot.
//!
//! So we check at startup. Crucially the probe **validates, it never decides**:
//! no outcome silently downgrades a route to HTTP/1.1. A probe result is a
//! snapshot that goes stale the moment the backend is reconfigured (an `nginx
//! reload` that drops `http2 on` would leave a cached "no h2" verdict quietly
//! wrong, or a cached "h2 ok" verdict quietly right for the wrong reason), and a
//! silent downgrade would mask exactly the configuration error this is meant to
//! reveal. See [`crate::config::H2Probe`] for the three policies.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// The HTTP/2 client connection preface (RFC 9113 §3.4). A server that speaks
/// h2c responds to this with its own SETTINGS frame.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// An empty SETTINGS frame: length=0, type=0x4 (SETTINGS), flags=0, stream id=0.
/// The preface must be followed by one, so send it in the same write.
const EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 0x04, 0, 0, 0, 0, 0];

/// Length of an HTTP/2 frame header: length(3) type(1) flags(1) stream_id(4).
const FRAME_HEADER_LEN: usize = 9;

/// The SETTINGS frame type code.
const FRAME_TYPE_SETTINGS: u8 = 0x04;

/// Check that the backend at `addr` speaks prior-knowledge h2c.
///
/// Opens a TCP connection, writes the client preface plus an empty SETTINGS
/// frame, and requires the peer's first reply to be a SETTINGS frame. The whole
/// exchange is bounded by `budget`.
///
/// Errors describe the *specific* failure, because the remedy differs sharply:
/// an HTTP/1.1 response means the backend needs `http2` turned on, whereas a
/// refused connection usually just means it has not started yet.
pub async fn probe_h2c(addr: SocketAddr, budget: Duration) -> Result<()> {
    timeout(budget, exchange(addr))
        .await
        .map_err(|_| anyhow!("timed out after {budget:?}"))?
}

async fn exchange(addr: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    stream.set_nodelay(true).ok();

    let mut hello = Vec::with_capacity(PREFACE.len() + EMPTY_SETTINGS.len());
    hello.extend_from_slice(PREFACE);
    hello.extend_from_slice(&EMPTY_SETTINGS);
    stream
        .write_all(&hello)
        .await
        .context("sending the HTTP/2 connection preface")?;

    // Read up to a full frame header. A conforming h2c server sends its SETTINGS
    // immediately, without waiting for anything further from us.
    let mut buf = [0u8; FRAME_HEADER_LEN];
    let mut have = 0usize;
    while have < FRAME_HEADER_LEN {
        let n = stream
            .read(&mut buf[have..])
            .await
            .context("reading the backend's reply")?;
        if n == 0 {
            break;
        }
        have += n;
    }

    classify_reply(&buf[..have])
}

/// Interpret the first bytes a backend sent in response to the preface.
///
/// Split out from the I/O so the interesting cases are unit-testable.
fn classify_reply(reply: &[u8]) -> Result<()> {
    if reply.is_empty() {
        bail!("backend closed the connection without replying (it rejected the HTTP/2 preface)");
    }
    // The common misconfiguration: an HTTP/1.1-only server answers the preface
    // with a normal (usually 400/505) HTTP response.
    if reply.starts_with(b"HTTP/1.") {
        bail!("backend replied with HTTP/1.x, so it does not speak h2c (enable HTTP/2 on it, or disable http2 for this route)");
    }
    if reply.len() < FRAME_HEADER_LEN {
        bail!(
            "backend sent a short {}-byte reply, not an HTTP/2 frame header",
            reply.len()
        );
    }
    let frame_type = reply[3];
    if frame_type != FRAME_TYPE_SETTINGS {
        bail!("backend's first frame was type 0x{frame_type:02x}, expected SETTINGS (0x04)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed empty SETTINGS frame is the success case.
    #[test]
    fn settings_reply_is_accepted() {
        assert!(classify_reply(&EMPTY_SETTINGS).is_ok());
        // A non-empty SETTINGS frame (length 6, one setting) is equally fine —
        // only the header is inspected.
        let with_payload = [0, 0, 6, 0x04, 0, 0, 0, 0, 0];
        assert!(classify_reply(&with_payload).is_ok());
    }

    /// The misconfiguration this probe exists to catch.
    #[test]
    fn http1_reply_is_reported_as_such() {
        let err = classify_reply(b"HTTP/1.1 400 Bad Request\r\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("HTTP/1.x"), "unhelpful message: {err}");
    }

    #[test]
    fn empty_reply_means_the_preface_was_rejected() {
        let err = classify_reply(&[]).unwrap_err().to_string();
        assert!(err.contains("without replying"), "unhelpful message: {err}");
    }

    #[test]
    fn short_reply_is_rejected() {
        let err = classify_reply(&[0, 0, 0, 0x04]).unwrap_err().to_string();
        assert!(err.contains("short"), "unhelpful message: {err}");
    }

    /// A valid frame that simply is not SETTINGS (here: HEADERS, 0x01).
    #[test]
    fn wrong_frame_type_is_rejected() {
        let headers = [0, 0, 0, 0x01, 0, 0, 0, 0, 1];
        let err = classify_reply(&headers).unwrap_err().to_string();
        assert!(err.contains("0x01"), "unhelpful message: {err}");
    }

    /// The probe must not hang when the peer accepts but never speaks.
    #[tokio::test]
    async fn probe_times_out_on_a_silent_backend() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Hold the connection open without replying.
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let err = probe_h2c(addr, Duration::from_millis(150))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"), "unexpected error: {err}");
    }

    /// An unreachable backend must fail, never falsely pass. Whether the OS
    /// reports it as a refusal or lets the connect hang until the budget expires
    /// is platform-dependent (Windows commonly does the latter), so both are
    /// accepted — the contract is only that it is an error.
    #[tokio::test]
    async fn probe_fails_when_the_backend_is_down() {
        // Bind then drop, so the port is almost certainly closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = probe_h2c(addr, Duration::from_millis(500))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("connecting to") || err.contains("timed out"),
            "unexpected error: {err}"
        );
    }
}
