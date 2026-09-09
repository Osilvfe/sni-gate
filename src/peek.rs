//! Non-consuming connection classification.
//!
//! We must learn the routing key (TLS SNI, or HTTP Host) *without* consuming any
//! bytes, so that unmatched connections can be spliced through verbatim. This is
//! done with `TcpStream::peek` (a `recv(MSG_PEEK)`), which copies from the socket
//! buffer without advancing it.
//!
//! Two plaintext parsers operate on the peeked bytes:
//!   * `parse_tls_sni` — reads the SNI from a TLS ClientHello (SNI is not
//!     encrypted; no decryption is involved).
//!   * `parse_http_host` — reads the `Host` header from a plaintext HTTP request.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

/// Largest peek window. A ClientHello (or HTTP request head) that does not reveal
/// its SNI/Host within this many bytes is treated as "no key" and routed to the
/// default/unmatched path. 8 KiB comfortably covers real ClientHellos.
const MAX_PEEK: usize = 8 * 1024;

/// How long to wait for enough bytes to classify before giving up.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// The classification result for an inbound connection.
#[derive(Debug, Clone)]
pub enum Inbound {
    /// A TLS ClientHello was seen. `sni` is the extracted server name, if any.
    Tls { sni: Option<String> },
    /// A plaintext HTTP request was seen. `host` is the Host header, if any.
    Http { host: Option<String> },
    /// Neither TLS nor HTTP could be recognized.
    Unknown,
}

impl Inbound {
    /// The routing key (SNI for TLS, Host for HTTP), if present.
    pub fn key(&self) -> Option<&str> {
        match self {
            Inbound::Tls { sni } => sni.as_deref(),
            Inbound::Http { host } => host.as_deref(),
            Inbound::Unknown => None,
        }
    }

    /// Whether the inbound stream is TLS (and therefore terminable for ECH).
    pub fn is_tls(&self) -> bool {
        matches!(self, Inbound::Tls { .. })
    }
}

/// Peek at the connection and classify it. Never consumes bytes.
///
/// Repeatedly peeks a growing window until the SNI/Host can be determined, the
/// stream type is known to be undecodable, the window cap is hit, or the timeout
/// fires. Returns `Inbound::Unknown` on any I/O error or timeout.
pub async fn classify(stream: &TcpStream) -> Inbound {
    let mut buf = vec![0u8; MAX_PEEK];

    // First, get at least one byte to classify TLS vs HTTP.
    let mut have = match peek_at_least(stream, &mut buf, 1).await {
        Some(n) => n,
        None => return Inbound::Unknown,
    };

    let is_tls = buf[0] == 0x16; // TLS handshake record content type

    loop {
        if is_tls {
            match parse_tls_sni(&buf[..have]) {
                TlsParse::Sni(name) => return Inbound::Tls { sni: Some(name) },
                TlsParse::NoSni => return Inbound::Tls { sni: None },
                TlsParse::NeedMore if have < MAX_PEEK => { /* peek more below */ }
                TlsParse::NeedMore => return Inbound::Tls { sni: None },
                TlsParse::NotClientHello => return Inbound::Tls { sni: None },
            }
        } else {
            match parse_http_host(&buf[..have]) {
                HttpParse::Host(h) => return Inbound::Http { host: Some(h) },
                HttpParse::NoHost => return Inbound::Http { host: None },
                HttpParse::NeedMore if have < MAX_PEEK => { /* peek more below */ }
                HttpParse::NeedMore => return Inbound::Http { host: None },
                HttpParse::NotHttp => return Inbound::Unknown,
            }
        }

        // Need more data: peek a larger prefix. If the peer sent nothing new,
        // stop with what we have.
        let want = (have + 1).min(MAX_PEEK);
        match peek_at_least(stream, &mut buf, want).await {
            Some(n) if n > have => have = n,
            _ => {
                // No progress; decide with what we have.
                return if is_tls {
                    Inbound::Tls { sni: None }
                } else {
                    Inbound::Http { host: None }
                };
            }
        }
    }
}

/// Peek until at least `want` bytes are buffered (or the connection stalls).
/// Returns the number of bytes now available, or `None` on error/timeout/EOF.
///
/// `peek()` returns whatever is currently in the socket buffer, which may be
/// short of `want`. Since `peek` does not let us block until *more than N* bytes
/// are buffered, we re-peek with a small backoff until the count grows past the
/// previous observation or the overall timeout elapses. In practice a
/// ClientHello / HTTP head arrives in one or two segments, so this loops at most
/// a couple of times.
async fn peek_at_least(stream: &TcpStream, buf: &mut [u8], want: usize) -> Option<usize> {
    let want = want.min(buf.len());
    let overall = timeout(PEEK_TIMEOUT, async {
        let mut last = 0usize;
        let mut backoff = Duration::from_millis(1);
        loop {
            match stream.peek(buf).await {
                Ok(0) => return None, // EOF
                Ok(n) if n >= want => return Some(n),
                Ok(n) => {
                    // If no new bytes appeared since the last observation, wait a
                    // little for more to arrive; otherwise keep the fresh count
                    // and retry immediately.
                    if n <= last {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_millis(50));
                    }
                    last = n;
                }
                Err(_) => return None,
            }
        }
    })
    .await;

    match overall {
        Ok(res) => res,
        // Timed out waiting for `want`; return whatever is buffered now.
        Err(_) => match stream.peek(buf).await {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(n),
        },
    }
}

// ---------------------------------------------------------------------------
// TLS ClientHello SNI parser
// ---------------------------------------------------------------------------

enum TlsParse {
    Sni(String),
    NoSni,
    NeedMore,
    NotClientHello,
}

/// Parse the SNI (host_name) out of a TLS ClientHello. All indexing is bounds-
/// checked; malformed or truncated input yields `NeedMore`/`NotClientHello`
/// rather than panicking.
fn parse_tls_sni(b: &[u8]) -> TlsParse {
    // TLS record header: type(1) version(2) length(2)
    if b.len() < 5 {
        return TlsParse::NeedMore;
    }
    if b[0] != 0x16 {
        return TlsParse::NotClientHello;
    }
    // record length
    let rec_len = u16::from_be_bytes([b[3], b[4]]) as usize;
    let mut p = 5usize;
    // We can parse within the record even if not fully buffered, but need enough.
    let end = (p + rec_len).min(b.len());

    // Handshake header: msg_type(1) length(3)
    if end < p + 4 {
        return TlsParse::NeedMore;
    }
    if b[p] != 0x01 {
        return TlsParse::NotClientHello; // not a ClientHello
    }
    let hs_len = ((b[p + 1] as usize) << 16) | ((b[p + 2] as usize) << 8) | (b[p + 3] as usize);
    p += 4;
    let hs_end = (p + hs_len).min(b.len());

    // client_version(2) + random(32)
    p = match p.checked_add(34) {
        Some(v) => v,
        None => return TlsParse::NotClientHello,
    };
    if p > hs_end {
        return TlsParse::NeedMore;
    }

    // session_id
    let sid_len = match b.get(p) {
        Some(&v) => v as usize,
        None => return TlsParse::NeedMore,
    };
    p += 1 + sid_len;
    if p + 2 > hs_end {
        return TlsParse::NeedMore;
    }

    // cipher_suites
    let cs_len = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2 + cs_len;
    if p + 1 > hs_end {
        return TlsParse::NeedMore;
    }

    // compression_methods
    let comp_len = b[p] as usize;
    p += 1 + comp_len;
    if p + 2 > hs_end {
        // No extensions at all -> no SNI.
        return if p <= hs_end {
            TlsParse::NoSni
        } else {
            TlsParse::NeedMore
        };
    }

    // extensions
    let ext_total = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(hs_end);

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([b[p], b[p + 1]]);
        let ext_len = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        p += 4;
        if p + ext_len > b.len() {
            return TlsParse::NeedMore;
        }
        if ext_type == 0x0000 {
            // server_name extension
            return parse_sni_extension(&b[p..p + ext_len]);
        }
        p += ext_len;
    }

    if ext_end < p {
        TlsParse::NeedMore
    } else {
        TlsParse::NoSni
    }
}

/// Parse a server_name extension body: ServerNameList.
fn parse_sni_extension(b: &[u8]) -> TlsParse {
    // list_length(2), then entries: name_type(1) name_len(2) name(name_len)
    if b.len() < 2 {
        return TlsParse::NeedMore;
    }
    let list_len = u16::from_be_bytes([b[0], b[1]]) as usize;
    let mut p = 2;
    let end = (2 + list_len).min(b.len());
    while p + 3 <= end {
        let name_type = b[p];
        let name_len = u16::from_be_bytes([b[p + 1], b[p + 2]]) as usize;
        p += 3;
        if p + name_len > b.len() {
            return TlsParse::NeedMore;
        }
        if name_type == 0x00 {
            // host_name
            return match std::str::from_utf8(&b[p..p + name_len]) {
                Ok(s) if !s.is_empty() => TlsParse::Sni(s.to_string()),
                _ => TlsParse::NoSni,
            };
        }
        p += name_len;
    }
    TlsParse::NoSni
}

// ---------------------------------------------------------------------------
// HTTP Host parser
// ---------------------------------------------------------------------------

enum HttpParse {
    Host(String),
    NoHost,
    NeedMore,
    NotHttp,
}

/// The index one past the blank line ending the header block, or `None` when the
/// terminator is not in `b` yet.
///
/// Both framings are accepted: `\r\n\r\n` as every real client sends, and bare
/// `\n\n`, which the line scanner below tolerates anyway.
fn header_block_end(b: &[u8]) -> Option<usize> {
    for (i, _) in b.iter().enumerate().filter(|(_, &c)| c == b'\n') {
        match b[i + 1..] {
            [b'\n', ..] => return Some(i + 2),
            [b'\r', b'\n', ..] => return Some(i + 3),
            _ => {}
        }
    }
    None
}

/// Extract the `Host` header from a plaintext HTTP request head. Tolerant of a
/// partial buffer: returns `NeedMore` until the header block terminator or a
/// Host line is seen.
///
/// # Why this never decodes the whole buffer
///
/// The peek window holds whatever the socket had, which for a request with a body
/// means header bytes *followed by body bytes*. Only the head is text: a body is
/// arbitrary octets. Decoding the buffer as UTF-8 and rejecting the connection on
/// failure therefore made any small binary upload — a PNG, protobuf, gRPC-Web —
/// unroutable, because one `0xFF` past the terminator turned a well-formed
/// request into `NotHttp`, and from there into `Inbound::Unknown` and the
/// unmatched fail policy.
///
/// So the body is never looked at: parsing is bounded to the header block, and
/// that block is scanned as raw byte lines. Only the `Host` value itself has to
/// decode, which keeps one unrelated header carrying stray bytes from
/// invalidating the routing key too.
fn parse_http_host(b: &[u8]) -> HttpParse {
    // Quick sanity: the request line should start with a known method token.
    if !looks_like_http(b) {
        return HttpParse::NotHttp;
    }

    // Bound parsing to the head. With no terminator yet, everything buffered is
    // still head — and a Host line already in it is enough to answer early.
    let head_end = header_block_end(b);
    let head = match head_end {
        Some(end) => &b[..end],
        None => b,
    };

    for line in head.split(|&c| c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break; // the blank line ending the header block
        }
        // Header lines are "Name: value"; match Host case-insensitively.
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        if !line[..colon].trim_ascii().eq_ignore_ascii_case(b"host") {
            continue;
        }
        let value = line[colon + 1..].trim_ascii();
        return match std::str::from_utf8(value) {
            Ok(host) if !host.is_empty() => HttpParse::Host(host.to_string()),
            // Present but empty, or not text: no usable routing key.
            _ => HttpParse::NoHost,
        };
    }

    if head_end.is_some() {
        HttpParse::NoHost
    } else {
        HttpParse::NeedMore
    }
}

/// True if the buffer plausibly starts an HTTP request line.
fn looks_like_http(b: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELE", b"OPTI", b"PATC", b"TRAC", b"CONN",
    ];
    METHODS
        .iter()
        .any(|m| b.len() >= m.len() && &b[..m.len()] == *m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_host_basic() {
        let req = b"GET / HTTP/1.1\r\nHost: p.example.com\r\nConnection: close\r\n\r\n";
        match parse_http_host(req) {
            HttpParse::Host(h) => assert_eq!(h, "p.example.com"),
            _ => panic!("expected host"),
        }
    }

    #[test]
    fn http_host_partial_needs_more() {
        let req = b"GET / HTTP/1.1\r\n"; // no Host yet, no terminator
        assert!(matches!(parse_http_host(req), HttpParse::NeedMore));
    }

    /// A request body is arbitrary octets, and the peek window routinely contains
    /// some of it. Decoding the whole buffer as UTF-8 made one `0xFF` past the
    /// header terminator turn a well-formed request into `NotHttp` — and from
    /// there into `Inbound::Unknown` and the unmatched fail policy. Any small
    /// binary upload (PNG, protobuf, gRPC-Web) was therefore unroutable.
    #[test]
    fn a_binary_request_body_does_not_hide_the_host() {
        let mut req: Vec<u8> =
            b"POST /upload HTTP/1.1\r\nHost: p.example.com\r\nContent-Length: 4\r\n\r\n".to_vec();
        // 0xFF never appears in valid UTF-8.
        req.extend_from_slice(&[0x89, 0x50, 0x4e, 0xff]);
        match parse_http_host(&req) {
            HttpParse::Host(h) => assert_eq!(h, "p.example.com"),
            other => panic!("expected the Host, got {:?}", DebugHttp(&other)),
        }
    }

    /// The same guarantee when the Host line arrives before any terminator: the
    /// early answer must not depend on the rest of the window decoding.
    #[test]
    fn a_host_line_is_answered_before_the_terminator() {
        let mut req: Vec<u8> = b"POST /u HTTP/1.1\r\nHost: early.example\r\nX-Trace: ".to_vec();
        req.extend_from_slice(&[0xfe, 0xff]);
        match parse_http_host(&req) {
            HttpParse::Host(h) => assert_eq!(h, "early.example"),
            other => panic!("expected the Host, got {:?}", DebugHttp(&other)),
        }
    }

    /// Non-text bytes in an unrelated header must not invalidate the routing key.
    #[test]
    fn a_non_text_neighbouring_header_does_not_hide_the_host() {
        let mut req: Vec<u8> = b"GET / HTTP/1.1\r\nX-Odd: ".to_vec();
        req.extend_from_slice(&[0xff, 0xfe]);
        req.extend_from_slice(b"\r\nHost: still.example\r\n\r\n");
        match parse_http_host(&req) {
            HttpParse::Host(h) => assert_eq!(h, "still.example"),
            other => panic!("expected the Host, got {:?}", DebugHttp(&other)),
        }
    }

    /// A `Host` whose own value is not text yields no routing key, rather than a
    /// lossy or panicking conversion.
    #[test]
    fn a_non_text_host_value_is_no_host() {
        let mut req: Vec<u8> = b"GET / HTTP/1.1\r\nHost: ".to_vec();
        req.extend_from_slice(&[0xff, 0xfe]);
        req.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(parse_http_host(&req), HttpParse::NoHost));
    }

    /// A body that happens to contain a `Host:` line must never be read as the
    /// routing key: parsing stops at the header terminator.
    #[test]
    fn a_host_line_in_the_body_is_never_read() {
        let req = b"POST /u HTTP/1.1\r\nContent-Length: 22\r\n\r\nHost: attacker.example";
        assert!(
            matches!(parse_http_host(req), HttpParse::NoHost),
            "the body must not supply the routing key"
        );
    }

    #[test]
    fn bare_lf_framing_is_still_accepted() {
        // No \r anywhere: the terminator is a bare blank line.
        match parse_http_host(b"GET / HTTP/1.1\nHost: lf.example\n\nbody") {
            HttpParse::Host(h) => assert_eq!(h, "lf.example"),
            other => panic!("expected the Host, got {:?}", DebugHttp(&other)),
        }
        // Complete head, no Host at all.
        assert!(matches!(
            parse_http_host(b"GET / HTTP/1.1\nAccept: */*\n\n"),
            HttpParse::NoHost
        ));
    }

    #[test]
    fn header_block_end_finds_both_framings() {
        assert_eq!(header_block_end(b"a\r\n\r\nbody"), Some(5));
        assert_eq!(header_block_end(b"a\n\nbody"), Some(3));
        // Absent terminators, including the truncated `\r\n\r` prefix.
        assert_eq!(header_block_end(b"a\r\n"), None);
        assert_eq!(header_block_end(b"a\r\n\r"), None);
        assert_eq!(header_block_end(b""), None);
    }

    // Small debug shim so panic messages are readable.
    struct DebugHttp<'a>(&'a HttpParse);
    impl std::fmt::Debug for DebugHttp<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                HttpParse::Host(h) => write!(f, "Host({h})"),
                HttpParse::NoHost => write!(f, "NoHost"),
                HttpParse::NeedMore => write!(f, "NeedMore"),
                HttpParse::NotHttp => write!(f, "NotHttp"),
            }
        }
    }

    #[test]
    fn not_http() {
        assert!(matches!(
            parse_http_host(b"\x16\x03\x01"),
            HttpParse::NotHttp
        ));
    }

    #[test]
    fn tls_truncated_needs_more() {
        assert!(matches!(
            parse_tls_sni(b"\x16\x03\x01\x00"),
            TlsParse::NeedMore
        ));
    }

    #[test]
    fn tls_real_client_hello_sni() {
        // A minimal but well-formed ClientHello advertising SNI "example.ulfheim.net".
        // Bytes from the annotated handshake at https://tls.ulfheim.net/ (record + hs).
        let hello = build_client_hello_with_sni("router.test");
        match parse_tls_sni(&hello) {
            TlsParse::Sni(s) => assert_eq!(s, "router.test"),
            other => panic!("expected SNI, got {:?}", DebugParse(&other)),
        }
    }

    // Helper: construct a valid ClientHello carrying a single SNI host_name.
    fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        // server_name extension body
        let mut sni = Vec::new();
        let entry_len = 1 + 2 + host.len();
        sni.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list length
        sni.push(0x00); // name_type host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type SNI
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0x00); // session_id len 0
        hs_body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hs_body.extend_from_slice(&[0x13, 0x01]); // one suite
        hs_body.push(0x01); // compression methods len
        hs_body.push(0x00); // null compression
        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions len
        hs_body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // handshake type ClientHello
        let l = hs_body.len();
        hs.push((l >> 16) as u8);
        hs.push((l >> 8) as u8);
        hs.push(l as u8);
        hs.extend_from_slice(&hs_body);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake record
        rec.extend_from_slice(&[0x03, 0x01]); // legacy record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    // Small debug shim so panic messages are readable.
    struct DebugParse<'a>(&'a TlsParse);
    impl std::fmt::Debug for DebugParse<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                TlsParse::Sni(s) => write!(f, "Sni({s})"),
                TlsParse::NoSni => write!(f, "NoSni"),
                TlsParse::NeedMore => write!(f, "NeedMore"),
                TlsParse::NotClientHello => write!(f, "NotClientHello"),
            }
        }
    }
}
