//! The per-listener forwarding data path.
//!
//! For each accepted connection:
//!
//! 1. Peek (non-consuming) to learn the routing key — TLS SNI or HTTP Host.
//! 2. Resolve it to a route (exact > wildcard > suffix > regex > default_route).
//! 3. `raw` splices the untouched TCP stream to the upstream. Every other type
//!    terminates inbound TLS (issuing a cert for the SNI via the dynamic CA
//!    resolver) and re-originates: `ech` over TLS 1.3 + Encrypted Client Hello
//!    (with retry), `tls` over plain TLS (optional override SNI), `http` as
//!    cleartext.
//! 4. No route and no default_route → apply the fail policy.
//!
//! # HTTP/2
//!
//! Because step 3 *splices bytes* rather than parsing HTTP, the inbound and
//! upstream framing must be the same protocol — there is no h2↔h1 translation.
//! HTTP/2 is therefore a single coupled switch per route, and is negotiated two
//! different ways depending on whether the upstream speaks ALPN:
//!
//! * `tls` / `ech` — **ALPN mirroring**. The upstream is dialed *first*, offering
//!   the intersection of what the client offered and what the route allows;
//!   whatever it selects is then advertised verbatim on the inbound handshake.
//!   A protocol mismatch is structurally impossible, and falling back to
//!   HTTP/1.1 happens per connection against the live upstream rather than
//!   against a cached guess. See [`serve_mirrored`].
//! * `http` — the upstream is cleartext and has no ALPN, so the client's own
//!   preference decides. An h2 connection is spliced to the backend as
//!   prior-knowledge h2c (RFC 9113 §3.4), which is byte-identical to h2 over
//!   TLS. A startup probe (`src/probe.rs`) validates that the backend really
//!   speaks h2c, but never silently downgrades the route.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rustls::client::EchStatus;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::config::{AddressFamily, FailPolicy, RouteType, SniPolicy};
use crate::ech::EchProvider;
use crate::nat64::Nat64Prefix;
use crate::peek::{classify, Inbound};
use crate::resolver::{observed_dns_sans, DynamicResolver};
use crate::router::Router;

const COPY_BUF_SIZE: usize = 64 * 1024;

/// Everything a single route needs at runtime.
pub struct RouteRuntime {
    pub name: String,
    pub route_type: RouteType,
    /// Fixed upstream host, or `None` to reflect the matched source SNI/Host
    /// (the port-stripped routing key) per connection.
    pub upstream_host: Option<String>,
    pub upstream_port: u16,
    /// What SNI to present upstream: reflect the inbound name, force a fixed
    /// one, or send no `server_name` extension at all.
    pub sni_policy: SniPolicy,
    /// Allow HTTP/2 on this route. Always false for `raw`.
    pub http2: bool,
    pub require_ech: bool,
    pub max_retries: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub address_family: AddressFamily,
    pub nat64: Option<Nat64Prefix>,
    pub fail: FailPolicy,
    /// DNS resolver for upstream A/AAAA.
    pub addr_resolver: Arc<crate::dns_resolvers::DnsResolver>,
    /// ECH provider (only for `ech` routes).
    pub ech: Option<EchProvider>,
    /// Verified web-PKI roots for upstream TLS (`ech`/`tls`).
    pub root_store: Arc<rustls::RootCertStore>,
}

/// The inbound `ServerConfig`s, which differ *only* in the ALPN protocols they
/// advertise. All share one cert resolver (issuing per-SNI certs from the CA),
/// one ticketer and one session cache.
///
/// Sharing resumption state across them is safe: rustls warns that configs
/// sharing a ticketer/session store should have equivalent `verifier` and
/// `cert_resolver` (a session originated under one must not be resumed under a
/// weaker one) — and here those are literally the same objects. Only
/// `alpn_protocols` differs, which does not affect session security.
///
/// Pre-building the handful of variants at startup keeps the per-connection cost
/// to an `Arc` clone; the alternative (cloning and mutating a `ServerConfig` per
/// connection) would copy the whole config on every handshake.
pub struct ServerConfigs {
    /// No ALPN extension at all — used when the client offered none.
    pub none: Arc<ServerConfig>,
    /// `["http/1.1"]`. The default for every route without HTTP/2 enabled.
    pub h1: Arc<ServerConfig>,
    /// `["h2"]` — the upstream selected HTTP/2, so we mirror exactly that.
    pub h2: Arc<ServerConfig>,
    /// `["h2", "http/1.1"]`, h2 preferred. Used by `http` routes, where there is
    /// no upstream ALPN to mirror and the client's preference decides.
    pub h2h1: Arc<ServerConfig>,
}

/// Immutable per-listener state shared with every connection task.
pub struct ListenerState {
    pub addr: SocketAddr,
    /// Shared with this listener's certificate resolver, which routes each
    /// ClientHello's SNI to decide what the certificate may cover.
    pub router: Arc<Router>,
    pub routes: Vec<Arc<RouteRuntime>>,
    /// Inbound server configs, selected per connection by negotiated ALPN.
    pub server_configs: Arc<ServerConfigs>,
    /// Fail policy for connections matching no route and no default_route.
    pub unmatched: FailPolicy,
    /// This listener's certificate resolver. The data path reports each
    /// upstream's real certificate SANs back to it, which is what lets issued
    /// certificates mirror the coverage the upstream actually grants instead of
    /// guessing at it (see [`crate::resolver`]).
    pub cert_resolver: Arc<DynamicResolver>,
}

/// Bind and serve one listener until it errors unrecoverably.
pub async fn serve(state: Arc<ListenerState>) -> Result<()> {
    let listener = TcpListener::bind(state.addr)
        .await
        .with_context(|| format!("binding listener {}", state.addr))?;
    info!(addr = %state.addr, routes = state.routes.len(), "listening");

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!(addr = %state.addr, error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatch(client, peer, &state).await {
                debug!(%peer, error = %format!("{e:#}"), "connection closed with error");
            }
        });
    }
}

async fn dispatch(client: TcpStream, peer: SocketAddr, state: &ListenerState) -> Result<()> {
    client.set_nodelay(true).ok();

    let inbound = classify(&client).await;
    let key = inbound.key();

    let route_id = match key {
        Some(k) => state.router.match_host(k),
        None => state.router.match_host(""),
    };

    let Some(id) = route_id else {
        return apply_fail(client, peer, &inbound, &state.unmatched, "unmatched").await;
    };
    let rt = &state.routes[id];

    // Effective inner/override name. This is the name the upstream certificate
    // is verified against, so `Omit` still resolves one (the inbound key) — the
    // policy only decides whether it is *transmitted* as an SNI extension.
    let sni = match &rt.sni_policy {
        SniPolicy::Fixed(fixed) => Some(fixed.clone()),
        SniPolicy::Reflect | SniPolicy::Omit => key.map(strip_port),
    };

    // Effective dial host: the fixed upstream host, else the matched source
    // SNI/Host (port-stripped). `None` here means the route reflects but the
    // connection carried no SNI/Host — handled at dial time per route type.
    let dial_host = match rt.upstream_host.as_deref() {
        Some(fixed) => Some(fixed.to_string()),
        None => key.map(strip_port),
    };

    debug!(%peer, route = %rt.name, key = key.unwrap_or("<none>"), tls = inbound.is_tls(), "routed");

    // raw: never terminate, never issue a cert — splice the untouched stream.
    if rt.route_type == RouteType::Raw {
        return raw_passthrough(client, peer, rt, &inbound, dial_host).await;
    }

    // Everything else terminates inbound TLS (plaintext HTTP is spliced as-is).
    let result = if inbound.is_tls() {
        // With HTTP/2 allowed on a TLS-upstream route we must know what the
        // upstream negotiates before answering the client, which inverts the
        // usual order (upstream first, then inbound handshake). Every other case
        // keeps the original ordering and the plain http/1.1 config.
        let mirror = rt.http2 && matches!(rt.route_type, RouteType::Tls | RouteType::Ech);
        if mirror {
            serve_mirrored(client, peer, rt, state, sni, dial_host).await
        } else {
            serve_terminated(client, peer, rt, state, sni, dial_host).await
        }
    } else {
        // Cleartext inbound: no TLS to terminate; forward per route type.
        serve_plaintext(client, peer, rt, state, sni, dial_host).await
    };

    // On failure, honor the route's fail policy where it makes sense.
    if let Err(e) = result {
        debug!(%peer, route = %rt.name, error = %format!("{e:#}"), "route failed");
        return Err(e);
    }
    Ok(())
}

/// The ALPN protocols this gateway can carry, most preferred first. Anything
/// else the client offers is ignored: we can only splice a protocol whose
/// framing we pass through unchanged, and these are the two that matter.
const SUPPORTED_ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Narrow a client's ALPN offer to what this gateway can splice, ordered by our
/// own preference (h2 first) so the upstream always sees a stable offer.
///
/// An empty result means "send no ALPN extension upstream" — either the client
/// offered none, or it offered only protocols we cannot carry.
fn negotiable_alpn(client_offer: Option<Vec<&[u8]>>) -> Vec<Vec<u8>> {
    let Some(offered) = client_offer else {
        return Vec::new();
    };
    SUPPORTED_ALPN
        .iter()
        .filter(|ours| offered.iter().any(|theirs| theirs == *ours))
        .map(|p| p.to_vec())
        .collect()
}

/// Which inbound ALPN to advertise, given what the upstream selected and what
/// the client originally offered. This is the mirroring rule.
fn mirror_choice<'a>(
    configs: &'a ServerConfigs,
    upstream_selected: Option<&[u8]>,
    client_offered_any: bool,
) -> &'a Arc<ServerConfig> {
    match upstream_selected {
        Some(b"h2") => &configs.h2,
        Some(b"http/1.1") => &configs.h1,
        // The upstream named nothing. With no client offer either, answer
        // without an ALPN extension. If the client did offer, it must have been
        // something the upstream declined to name, so settle on HTTP/1.1 — the
        // implicit default both ends already understand.
        _ if !client_offered_any => &configs.none,
        _ => &configs.h1,
    }
}

/// Report the upstream's real certificate SANs to this listener's resolver, so
/// the certificate *this* gateway serves for `sni` mirrors the coverage the
/// upstream actually grants.
///
/// # Why this is on the data path
///
/// The upstream's certificate is the only authority on which names it will answer
/// for over one connection. A gateway that invents a wildcard the upstream does
/// not back lets a browser coalesce a second origin onto the connection
/// (RFC 9113 §9.1.1); the upstream then sees an `:authority` outside what its own
/// handshake authorized and rejects it — the 403 this mechanism exists to remove.
/// The certificate resolver runs inside the *inbound* handshake and cannot dial
/// anywhere, so the observation has to arrive from here, where the upstream
/// handshake actually completes.
///
/// # Why it does not block
///
/// The connection in hand is already served: its certificate was issued before
/// the client's ClientHello was answered. What mirroring affects is the client's
/// **next** connection — the one it could coalesce onto — so there is nothing to
/// wait for. The common case is an upstream whose certificate has not changed, so
/// that case is settled inline with a cache lookup and a slice comparison
/// ([`DynamicResolver::mirror_is_current`]); only a genuine change reaches the
/// blocking pool, where a signature and two file writes are allowed to take their
/// time.
fn record_upstream_coverage(
    state: &ListenerState,
    rt: &RouteRuntime,
    sni: Option<&String>,
    session: &rustls::ClientConnection,
) {
    // A route with a fixed `override_sni` asks every upstream for the same name,
    // so the certificate it returns says nothing about the *inbound* name this
    // certificate is for. Mirroring it would attach one upstream's coverage to
    // every name routed here.
    if rt.sni_policy != SniPolicy::Reflect {
        return;
    }
    let Some(sni) = sni else { return };
    let Some(chain) = session.peer_certificates() else {
        return;
    };

    let observed = observed_dns_sans(chain);
    if state.cert_resolver.mirror_is_current(sni, &observed) {
        return;
    }

    let resolver = state.cert_resolver.clone();
    let host = sni.clone();
    let route = rt.name.clone();
    // Detached: the certificate it produces is for a future connection, and the
    // current one must not wait on a signature.
    tokio::task::spawn_blocking(move || {
        debug!(route = %route, host = %host, sans = ?observed, "observed upstream certificate");
        resolver.record_upstream_sans(&host, &observed);
    });
}

/// Terminate inbound TLS with the dynamic-cert server config, then re-originate.
///
/// The original ordering: the inbound handshake completes first, then the
/// upstream is dialed. Used whenever HTTP/2 is not in play, so the default path
/// is unchanged — `http/1.1` is advertised and no extra work is done.
async fn serve_terminated(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()> {
    // `http` routes with HTTP/2 enabled offer both protocols and let the client
    // choose: the cleartext upstream has no ALPN of its own to mirror, and an h2
    // stream is spliced onward as prior-knowledge h2c.
    let config = if rt.http2 && rt.route_type == RouteType::Http {
        state.server_configs.h2h1.clone()
    } else {
        state.server_configs.h1.clone()
    };
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client);
    let start = acceptor.await?;
    let tls = start.into_stream(config).await?;
    if let Some(p) = tls.get_ref().1.alpn_protocol() {
        debug!(%peer, route = %rt.name, alpn = %String::from_utf8_lossy(p), "inbound ALPN");
    }
    forward(tls, peer, rt, state, sni, dial_host).await
}

/// Terminate inbound TLS **after** dialing the upstream, advertising exactly the
/// protocol the upstream selected. Used for `tls`/`ech` routes with HTTP/2
/// enabled.
///
/// Ordering matters here. We read the client's ALPN offer from the ClientHello
/// without committing to a `ServerConfig`, dial the upstream with the subset of
/// that offer we support, observe what it actually chose, and only then finish
/// the inbound handshake announcing that same protocol. The two sides therefore
/// cannot disagree, and an upstream that only speaks HTTP/1.1 transparently
/// downgrades this connection without any configuration or cached probe result.
///
/// Two consequences of the inversion, both deliberate:
///
/// * The upstream is dialed slightly earlier in the connection's life than on
///   the default path (before the inbound handshake rather than after).
/// * If the upstream dial fails we hold a `StartHandshake`, whose ClientHello
///   bytes have already been consumed by the acceptor — so the stream can no
///   longer be spliced elsewhere and a `passthrough` fail policy is not
///   applicable. This is not a regression: terminating routes never applied a
///   fail policy (it is reached only for unmatched connections and `raw`
///   upstream failures), and the observable result — the connection is dropped
///   and the error logged — is exactly what the default path already does when
///   its upstream is unreachable.
async fn serve_mirrored(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client);
    let start = acceptor.await?;

    // What the client is willing to speak, narrowed to what we can splice.
    let client_offer = negotiable_alpn(start.client_hello().alpn().map(Iterator::collect));

    let host = dial_host.ok_or_else(|| {
        anyhow!(
            "route {} reflects the source SNI/Host upstream, but the connection \
             presented none",
            rt.name
        )
    })?;
    let upstream_addr = rt
        .addr_resolver
        .lookup_addr(
            &host,
            rt.upstream_port,
            rt.address_family,
            rt.nat64.as_ref(),
        )
        .await
        .with_context(|| format!("resolving upstream {host}"))?;

    // Dial first, so the upstream's choice can drive the inbound handshake.
    let up = match rt.route_type {
        RouteType::Tls => {
            let name = sni.clone().unwrap_or_else(|| host.clone());
            dial_tls(upstream_addr, &name, rt, &client_offer).await?
        }
        RouteType::Ech => {
            // An inner name is required even when it will not be *sent*: it is
            // what the upstream certificate is verified against.
            let inner = sni.clone().ok_or_else(|| {
                anyhow!(
                    "ech route {}: the connection carried no SNI/Host to use as \
                     the inner name, and no override_sni supplies one",
                    rt.name
                )
            })?;
            dial_ech(upstream_addr, &inner, peer, rt, &client_offer).await?
        }
        RouteType::Http | RouteType::Raw => {
            unreachable!("mirroring only applies to tls/ech routes")
        }
    };

    let selected = up.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

    // The upstream handshake is complete: learn what its certificate really
    // covers before this connection is spliced away. On this path it matters
    // most — HTTP/2 is on, so coalescing is exactly what the client may do next.
    record_upstream_coverage(state, rt, sni.as_ref(), up.get_ref().1);

    let config = mirror_choice(
        &state.server_configs,
        selected.as_deref(),
        !client_offer.is_empty(),
    )
    .clone();
    debug!(
        %peer,
        route = %rt.name,
        upstream_alpn = %selected.as_deref().map_or("<none>".into(), |p| String::from_utf8_lossy(p).into_owned()),
        "mirroring upstream ALPN to the client"
    );

    let tls = start.into_stream(config).await?;
    splice(tls, up, rt.idle_timeout).await
}

/// Forward a cleartext inbound connection (no inbound TLS).
async fn serve_plaintext(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()> {
    forward(client, peer, rt, state, sni, dial_host).await
}

/// Dial the upstream per route type and splice bytes.
async fn forward<S>(
    inbound: S,
    peer: SocketAddr,
    rt: &RouteRuntime,
    state: &ListenerState,
    sni: Option<String>,
    dial_host: Option<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Concrete host to dial: the fixed upstream host, or the reflected source
    // SNI/Host. Absent only when the route reflects and the connection carried
    // no SNI/Host to reflect.
    let host = dial_host.ok_or_else(|| {
        anyhow!(
            "route {} reflects the source SNI/Host upstream, but the connection \
             presented none",
            rt.name
        )
    })?;

    let upstream_addr = rt
        .addr_resolver
        .lookup_addr(
            &host,
            rt.upstream_port,
            rt.address_family,
            rt.nat64.as_ref(),
        )
        .await
        .with_context(|| format!("resolving upstream {host}"))?;

    match rt.route_type {
        RouteType::Http => {
            let up = dial(upstream_addr, rt.connect_timeout).await?;
            splice(inbound, up, rt.idle_timeout).await
        }
        // These arms are only reached on the non-mirrored path (HTTP/2 disabled),
        // where inbound was negotiated as http/1.1 — so offer nothing upstream
        // and let it default to HTTP/1.1 too, exactly as before.
        RouteType::Tls => {
            let name = sni.clone().unwrap_or_else(|| host.clone());
            let up = dial_tls(upstream_addr, &name, rt, &[]).await?;
            // HTTP/2 is off for this connection, so it cannot coalesce — but a
            // later connection for the same name can, and this is a free look at
            // what the upstream's certificate covers.
            record_upstream_coverage(state, rt, sni.as_ref(), up.get_ref().1);
            splice(inbound, up, rt.idle_timeout).await
        }
        RouteType::Ech => {
            // An inner name is required even when it will not be *sent*: it is
            // what the upstream certificate is verified against.
            let inner = sni.clone().ok_or_else(|| {
                anyhow!(
                    "ech route {}: the connection carried no SNI/Host to use as \
                     the inner name, and no override_sni supplies one",
                    rt.name
                )
            })?;
            let up = dial_ech(upstream_addr, &inner, peer, rt, &[]).await?;
            record_upstream_coverage(state, rt, sni.as_ref(), up.get_ref().1);
            splice(inbound, up, rt.idle_timeout).await
        }
        RouteType::Raw => unreachable!("raw handled before termination"),
    }
}

/// Plain TCP dial with a timeout.
async fn dial(addr: SocketAddr, connect_timeout: Duration) -> Result<TcpStream> {
    let up = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("upstream connect timed out"))?
        .with_context(|| format!("connecting to {addr}"))?;
    up.set_nodelay(true).ok();
    Ok(up)
}

/// Dial a plain-TLS upstream, verifying the presented `server_name` and offering
/// `alpn` (empty = no ALPN extension).
///
/// `server_name` is always used to **verify** the upstream certificate. Whether
/// it is also **sent** as an SNI extension depends on the route's
/// [`SniPolicy`]: `Omit` clears `enable_sni`, so the handshake carries no
/// `server_name` while the certificate is still checked against that name.
async fn dial_tls(
    addr: SocketAddr,
    server_name: &str,
    rt: &RouteRuntime,
    alpn: &[Vec<u8>],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut config = plain_tls_config(rt.root_store.clone());
    config.alpn_protocols = alpn.to_vec();
    if rt.sni_policy == SniPolicy::Omit {
        config.enable_sni = false;
    }
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow!("invalid upstream SNI {server_name:?}"))?;
    let tcp = dial(addr, rt.connect_timeout).await?;
    let tls = timeout(rt.connect_timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| anyhow!("upstream TLS handshake timed out"))?
        .context("upstream TLS handshake")?;
    Ok(tls)
}

/// Dial an ECH upstream for `inner` offering `alpn`, with retry on ECH rejection.
async fn dial_ech(
    addr: SocketAddr,
    inner: &str,
    peer: SocketAddr,
    rt: &RouteRuntime,
    alpn: &[Vec<u8>],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let ech = rt
        .ech
        .as_ref()
        .ok_or_else(|| anyhow!("ech route {} missing ECH provider", rt.name))?;

    let name = ServerName::try_from(inner.to_string())
        .map_err(|_| anyhow!("invalid inner SNI {inner:?}"))?;

    let mut attempt = 0u32;
    loop {
        let client = ech
            .client(inner, alpn)
            .await
            .context("assembling ECH client config")?;
        let connector = TlsConnector::from(client.client_config.clone());
        let tcp = dial(addr, rt.connect_timeout).await?;

        match timeout(rt.connect_timeout, connector.connect(name.clone(), tcp)).await {
            Ok(Ok(tls)) => {
                let status = tls.get_ref().1.ech_status();
                match (rt.require_ech, status) {
                    (true, EchStatus::Accepted) => {
                        debug!(%peer, route = %rt.name, "ECH accepted");
                        return Ok(tls);
                    }
                    (false, s) => {
                        debug!(%peer, route = %rt.name, status = ?s, "forwarding (ECH not required)");
                        return Ok(tls);
                    }
                    (true, s) => {
                        // ECH required but not accepted on a completed handshake.
                        return Err(anyhow!("ECH required but status was {s:?}"));
                    }
                }
            }
            Ok(Err(e)) if is_ech_reject(&e) && attempt < rt.max_retries => {
                attempt += 1;
                warn!(%peer, route = %rt.name, attempt, "ECH rejected; refreshing config and retrying");
                // Force a fresh ECHConfig fetch (server rotated keys; DNS/source
                // now carries the new one) before the next attempt.
                ech.invalidate(inner).await;
                continue;
            }
            Ok(Err(e)) => return Err(e).context("upstream ECH handshake"),
            Err(_) => return Err(anyhow!("upstream ECH handshake timed out")),
        }
    }
}

/// Whether an I/O error is rustls's "server rejected ECH" signal.
///
/// Delegates to [`crate::ech::is_ech_reject_io`]. A resolver's own handshake
/// needs the identical verdict, so the predicate lives in `ech` and both paths
/// call it rather than each carrying a copy that could drift.
fn is_ech_reject(e: &std::io::Error) -> bool {
    crate::ech::is_ech_reject_io(e)
}

/// Splice bytes bidirectionally, enforcing a true **idle** timeout: the clock
/// resets on every chunk in either direction, so long-lived but active
/// connections (WebSocket, streaming) are never cut — only genuinely idle ones.
/// `idle` of zero disables the timeout.
///
/// Both directions are driven to completion independently (a half-close in one
/// direction does not tear down the other), so request/response and duplex
/// protocols both work. The splice ends when both directions have closed, or
/// when the idle timeout fires, whichever comes first.
async fn splice<A, B>(a: A, b: B, idle: Duration) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let activity = Arc::new(tokio::sync::Notify::new());

    // Run both directions to completion; only the idle guard races them.
    let both = async {
        let a2b = pump_direction(&mut ar, &mut bw, &activity);
        let b2a = pump_direction(&mut br, &mut aw, &activity);
        let (r1, r2) = tokio::join!(a2b, b2a);
        r1.context("proxying data (c->u)")?;
        r2.context("proxying data (u->c)")?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = both => r,
        _ = idle_guard(&activity, idle) => Err(anyhow!("idle timeout")),
    }
}

/// Copy one direction, signaling `activity` on every chunk. On EOF it
/// half-closes the writer (so the peer sees the close) and returns, leaving the
/// other direction free to continue.
async fn pump_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    activity: &tokio::sync::Notify,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        activity.notify_one();
    }
}

/// Resolve only when no activity has been signaled for `idle`. Never resolves
/// when `idle` is zero (timeout disabled). `Notify` holds a single permit, so a
/// notification arriving between `.notified()` awaits is not lost — it is
/// consumed by the next await, correctly resetting the clock.
async fn idle_guard(activity: &tokio::sync::Notify, idle: Duration) {
    if idle.is_zero() {
        std::future::pending::<()>().await;
        return;
    }
    loop {
        match timeout(idle, activity.notified()).await {
            Ok(()) => continue, // activity: reset the idle clock
            Err(_) => return,   // no activity within `idle`: time out
        }
    }
}

/// Raw byte-pump passthrough (no termination, no cert). Because nothing is
/// consumed, the route's fail policy can still be applied if the upstream is
/// unreachable.
async fn raw_passthrough(
    client: TcpStream,
    peer: SocketAddr,
    rt: &RouteRuntime,
    inbound: &Inbound,
    dial_host: Option<String>,
) -> Result<()> {
    let dialed = async {
        let host = dial_host.ok_or_else(|| {
            anyhow!(
                "route {} reflects the source SNI/Host upstream, but the \
                 connection presented none",
                rt.name
            )
        })?;
        let upstream_addr = rt
            .addr_resolver
            .lookup_addr(
                &host,
                rt.upstream_port,
                rt.address_family,
                rt.nat64.as_ref(),
            )
            .await?;
        dial(upstream_addr, rt.connect_timeout).await
    }
    .await;

    match dialed {
        Ok(up) => splice_tcp(client, up, rt.idle_timeout).await,
        Err(e) => {
            debug!(%peer, route = %rt.name, error = %format!("{e:#}"), "raw upstream failed; applying fail policy");
            apply_fail(client, peer, inbound, &rt.fail, "raw-fail").await
        }
    }
}

/// Raw TCP splice with the same true-idle-timeout semantics as [`splice`].
async fn splice_tcp(a: TcpStream, b: TcpStream, idle: Duration) -> Result<()> {
    splice(a, b, idle).await
}

/// Apply a fail/unmatched policy to a never-decrypted stream.
async fn apply_fail(
    client: TcpStream,
    peer: SocketAddr,
    inbound: &Inbound,
    policy: &FailPolicy,
    ctx: &str,
) -> Result<()> {
    match policy {
        FailPolicy::Close => {
            debug!(%peer, %ctx, "closing");
            Ok(())
        }
        FailPolicy::Passthrough { addr } => {
            let up = dial(*addr, Duration::from_secs(10)).await?;
            splice_tcp(client, up, Duration::from_secs(120)).await
        }
        FailPolicy::SystemOutbound => {
            let host = inbound
                .key()
                .ok_or_else(|| anyhow!("{ctx}: no SNI/Host for system-outbound"))?;
            let port = if inbound.is_tls() { 443 } else { 80 };
            let host = strip_port(host);
            let up = TcpStream::connect((host.as_str(), port)).await?;
            up.set_nodelay(true).ok();
            splice_tcp(client, up, Duration::from_secs(120)).await
        }
    }
}

/// Build a plain-TLS client config (TLS 1.2/1.3) trusting `roots`.
fn plain_tls_config(roots: Arc<rustls::RootCertStore>) -> ClientConfig {
    ClientConfig::builder()
        .with_root_certificates(roots.as_ref().clone())
        .with_no_client_auth()
}

/// Strip a trailing `:port` from a routing key, returning the bare host.
/// Handles `[v6]:port` (unwraps the brackets and drops the port), a bare DNS
/// name / IPv4 with a port, and a bare host with no port.
fn strip_port(host: &str) -> String {
    if let Some(rest) = host.strip_prefix('[') {
        // [v6] or [v6]:port — return the inner literal without brackets/port.
        if let Some((inner, _tail)) = rest.split_once(']') {
            return inner.to_string();
        }
        return rest.to_string();
    }
    // A bare IPv6 literal (multiple colons, no brackets) has no port to strip.
    if host.matches(':').count() > 1 {
        return host.to_string();
    }
    host.split(':').next().unwrap_or(host).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_forms() {
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("1.2.3.4:443"), "1.2.3.4");
        // Bracketed IPv6 with and without a port.
        assert_eq!(strip_port("[::1]:443"), "::1");
        assert_eq!(strip_port("[2a01:4f8::1]:443"), "2a01:4f8::1");
        assert_eq!(strip_port("[::1]"), "::1");
        // Bare IPv6 literal: nothing to strip.
        assert_eq!(strip_port("2a01:4f8::1"), "2a01:4f8::1");
    }

    // The half-close regression: after one direction reaches EOF, the other
    // must still deliver its full payload. Models a request/response where the
    // client half-closes its write side and then reads the response.
    #[tokio::test]
    async fn splice_survives_half_close_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Two in-memory duplex pipes act as the "client" and "upstream" ends.
        let (mut client, client_gate) = tokio::io::duplex(64 * 1024);
        let (mut upstream, upstream_gate) = tokio::io::duplex(64 * 1024);

        // splice() bridges the two gate ends.
        let spliced = tokio::spawn(async move {
            splice(client_gate, upstream_gate, Duration::from_secs(5)).await
        });

        let big = vec![0xABu8; 256 * 1024];
        let big_for_upstream = big.clone();

        // Upstream side: read the full request, then stream a large response.
        // Runs concurrently so the >buffer response doesn't deadlock.
        let upstream_task = tokio::spawn(async move {
            let mut got = Vec::new();
            upstream.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"REQUEST");
            upstream.write_all(&big_for_upstream).await.unwrap();
            upstream.shutdown().await.unwrap();
        });

        // Client sends a request, half-closes its write side, then reads the
        // response — which must arrive in full despite the half-close.
        client.write_all(b"REQUEST").await.unwrap();
        client.shutdown().await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp.len(), big.len(), "response truncated by half-close");
        assert_eq!(resp, big);

        upstream_task.await.unwrap();
        spliced.await.unwrap().unwrap();
    }

    #[test]
    fn negotiable_alpn_filters_and_reorders() {
        fn v<'a>(s: &[&'a str]) -> Option<Vec<&'a [u8]>> {
            Some(s.iter().map(|x| x.as_bytes()).collect())
        }
        // Our preference wins over the client's ordering.
        assert_eq!(
            negotiable_alpn(v(&["http/1.1", "h2"])),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // Unsupported protocols are dropped.
        assert_eq!(
            negotiable_alpn(v(&["h3", "spdy/3", "http/1.1"])),
            vec![b"http/1.1".to_vec()]
        );
        // Nothing we can carry, and no extension at all, both yield an empty
        // offer — meaning "send no ALPN extension upstream".
        assert!(negotiable_alpn(v(&["h3"])).is_empty());
        assert!(negotiable_alpn(None).is_empty());
    }

    /// The mirroring rule: the inbound answer always follows the upstream.
    #[test]
    fn mirror_choice_follows_the_upstream() {
        let configs = test_configs();
        let picked = |sel: Option<&[u8]>, offered: bool| {
            let c = mirror_choice(&configs, sel, offered);
            c.alpn_protocols.clone()
        };

        // Upstream chose h2 -> we advertise h2. Upstream chose http/1.1 -> h1,
        // even though the client would have preferred h2. This is the whole
        // point: no mismatch is possible.
        assert_eq!(picked(Some(b"h2"), true), vec![b"h2".to_vec()]);
        assert_eq!(picked(Some(b"http/1.1"), true), vec![b"http/1.1".to_vec()]);

        // Upstream named nothing but the client did offer -> settle on http/1.1.
        assert_eq!(picked(None, true), vec![b"http/1.1".to_vec()]);
        // Neither side used ALPN -> answer with no ALPN extension.
        assert!(picked(None, false).is_empty());
        // An unrecognized upstream selection is treated like "nothing named".
        assert_eq!(picked(Some(b"h3"), true), vec![b"http/1.1".to_vec()]);
    }

    /// Build the four ALPN variants over a dummy cert resolver, mirroring how
    /// `main.rs` assembles them.
    fn test_configs() -> ServerConfigs {
        #[derive(Debug)]
        struct NoCerts;
        impl rustls::server::ResolvesServerCert for NoCerts {
            fn resolve(
                &self,
                _hello: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                None
            }
        }
        // `main()` installs this process-wide; tests must do it themselves.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let base = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCerts));
        let with = |p: Vec<Vec<u8>>| {
            let mut c = base.clone();
            c.alpn_protocols = p;
            Arc::new(c)
        };
        ServerConfigs {
            none: with(Vec::new()),
            h1: with(vec![b"http/1.1".to_vec()]),
            h2: with(vec![b"h2".to_vec()]),
            h2h1: with(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        }
    }

    #[test]
    fn ech_reject_detection_is_typed() {
        // A plain io::Error that merely mentions ECH must NOT be treated as a
        // rustls ECH rejection (the old string-match bug).
        let bogus = std::io::Error::other("connection to ECH-named-host failed");
        assert!(!is_ech_reject(&bogus));
        // The real signal is a downcastable rustls PeerIncompatible variant.
        let real = std::io::Error::other(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(None),
        ));
        assert!(is_ech_reject(&real));
    }
}
