//! HTTP/3 semantic proxy data path.
//!
//! The shared UDP dispatcher and Quinn own transport demultiplexing. This
//! module starts at an already-established inbound QUIC connection and handles
//! HTTP/3 request semantics. Request authority is re-routed per stream so H3
//! connection coalescing can never bypass the listener's route boundaries.

use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Buf;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::{timeout, Instant};
use tracing::{debug, warn};

use crate::config::{RouteType, SniPolicy};
use crate::proxy::{upstream_certs, ListenerState, RouteRuntime};
use crate::resolver::DynamicResolver;
use crate::router::Router;

#[cfg(test)]
#[path = "h3_proxy/tests.rs"]
mod tests;

/// A terminating H3 connection owns an inbound QUIC connection, H3/QPACK
/// state, and potentially many request-stream tasks. Keep a process-wide hard
/// ceiling even before these knobs become configurable so a burst of
/// successfully authenticated handshakes cannot grow state without bound. Raw
/// QUIC forwarding has its own independent flow quotas.
const MAX_ACTIVE_H3_CONNECTIONS: usize = 1024;

/// Bound semantic request work independently of QUIC's transport stream
/// accounting. Once this many requests are active on one inbound connection we
/// stop accepting more until an existing request finishes, which applies
/// backpressure instead of creating an unbounded number of Tokio tasks.
const MAX_CONCURRENT_H3_REQUESTS_PER_CONNECTION: usize = 256;

/// Bound the peer-advertised HTTP/3 field section size in both directions.
/// 64 KiB is intentionally generous for ordinary browser/API traffic while
/// preventing an unbounded header/QPACK memory commitment per connection.
const MAX_H3_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// Pooling avoids paying a fresh UDP socket + QUIC/TLS/H3 handshake for every
/// inbound H3 connection. Keys use logical upstream identity rather than the
/// resolved address, so healthy pool hits do not perform DNS. DNS is refreshed
/// naturally when a connection is evicted or ages out and must be rebuilt.
const MAX_UPSTREAM_H3_POOL_ENTRIES: usize = 256;
const UPSTREAM_H3_POOL_IDLE: Duration = Duration::from_secs(60);

static H3_CONNECTION_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static UPSTREAM_H3_POOL: OnceLock<Arc<Mutex<HashMap<UpstreamPoolKey, UpstreamPoolEntry>>>> =
    OnceLock::new();

fn h3_connection_limit() -> Arc<Semaphore> {
    H3_CONNECTION_LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(MAX_ACTIVE_H3_CONNECTIONS)))
        .clone()
}

fn upstream_h3_pool() -> Arc<Mutex<HashMap<UpstreamPoolKey, UpstreamPoolEntry>>> {
    UPSTREAM_H3_POOL
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

#[derive(Clone)]
struct H3ProxyContext {
    router: Arc<Router>,
    handshake_route: usize,
    handshake_sni: String,
    route_name: String,
    reflects_dial_host: bool,
    reflects_server_name: bool,
    idle_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UpstreamPoolKey {
    listener: SocketAddr,
    route_id: usize,
    host: String,
    port: u16,
    server_name: String,
    ech: bool,
}

struct UpstreamPoolEntry {
    upstream: UpstreamH3,
    upstream_addr: SocketAddr,
    closed: Arc<AtomicBool>,
    last_used: Instant,
}

struct UpstreamIdentity {
    host: String,
    server_name: String,
}

struct UpstreamTarget {
    host: String,
    server_name: String,
    upstream_addr: SocketAddr,
}

struct CreatedUpstream {
    upstream: UpstreamH3,
    closed: Arc<AtomicBool>,
}

#[derive(Clone)]
struct PooledUpstreamContext {
    listener: SocketAddr,
    route_id: usize,
    route: Arc<RouteRuntime>,
    handshake_sni: String,
    peer: SocketAddr,
    cert_resolver: Arc<DynamicResolver>,
}

#[derive(Clone)]
enum UpstreamProvider {
    #[cfg(test)]
    Fixed(UpstreamH3),
    Pooled(PooledUpstreamContext),
}

struct UpstreamLease {
    upstream: UpstreamH3,
    pool_key: Option<UpstreamPoolKey>,
}

impl UpstreamProvider {
    async fn acquire(&self) -> Result<UpstreamLease> {
        match self {
            #[cfg(test)]
            Self::Fixed(upstream) => Ok(UpstreamLease {
                upstream: upstream.clone(),
                pool_key: None,
            }),
            Self::Pooled(context) => {
                let (pool_key, upstream) = pooled_upstream_h3(
                    context.listener,
                    context.route_id,
                    &context.route,
                    &context.handshake_sni,
                    context.peer,
                    &context.cert_resolver,
                )
                .await?;
                Ok(UpstreamLease {
                    upstream,
                    pool_key: Some(pool_key),
                })
            }
        }
    }
}

impl UpstreamLease {
    async fn invalidate(self) {
        if let Some(key) = self.pool_key {
            upstream_h3_pool().lock().await.remove(&key);
        }
    }
}

pub async fn serve_inbound(
    connection: quinn::Connection,
    peer: SocketAddr,
    state: Arc<ListenerState>,
    handshake_route: usize,
    handshake_sni: String,
) -> Result<()> {
    let _connection_permit = match h3_connection_limit().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            debug!(
                %peer,
                max_connections = MAX_ACTIVE_H3_CONNECTIONS,
                "rejecting H3 connection because the active connection limit is reached"
            );
            connection.close(0u32.into(), b"H3 connection capacity exhausted");
            return Ok(());
        }
    };

    let route = state
        .routes
        .get(handshake_route)
        .cloned()
        .ok_or_else(|| anyhow!("invalid H3 route index {handshake_route}"))?;
    let context = H3ProxyContext {
        router: state.router.clone(),
        handshake_route,
        handshake_sni: handshake_sni.clone(),
        route_name: route.name.clone(),
        reflects_dial_host: route.upstream_host.is_none(),
        reflects_server_name: matches!(route.sni_policy, SniPolicy::Reflect | SniPolicy::Omit),
        idle_timeout: route.idle_timeout,
    };
    let upstream = UpstreamProvider::Pooled(PooledUpstreamContext {
        listener: state.addr,
        route_id: handshake_route,
        route,
        handshake_sni,
        peer,
        cert_resolver: state.cert_resolver.clone(),
    });
    proxy_inbound_h3_inner(connection, peer, context, upstream).await
}

/// Proxy an established inbound HTTP/3 connection. Production acquires a
/// healthy pooled upstream lazily per request; tests can inject a fixed sender.
/// Lazy acquisition matters operationally: an unavailable upstream becomes an
/// HTTP 502/504 for the request instead of tearing down an otherwise valid
/// inbound QUIC connection before the H3 layer can respond.
async fn proxy_inbound_h3_inner(
    connection: quinn::Connection,
    peer: SocketAddr,
    context: H3ProxyContext,
    upstream: UpstreamProvider,
) -> Result<()> {
    let quic = h3_quinn::Connection::new(connection);
    let mut inbound_builder = h3::server::builder();
    inbound_builder.max_field_section_size(MAX_H3_FIELD_SECTION_SIZE);
    let mut inbound = inbound_builder
        .build(quic)
        .await
        .context("starting inbound HTTP/3 connection")?;
    let activity = Arc::new(Notify::new());
    let request_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_H3_REQUESTS_PER_CONNECTION));
    let idle_timeout = context.idle_timeout;

    let serve = async {
        loop {
            let resolver = match inbound.accept().await {
                Ok(Some(resolver)) => resolver,
                Ok(None) => break,
                Err(error) if error.is_h3_no_error() => {
                    debug!(
                        %peer,
                        route = %context.route_name,
                        "H3 connection closed normally"
                    );
                    break;
                }
                Err(error) => {
                    return Err(error).context("accepting HTTP/3 request");
                }
            };
            let request_permit = request_limit
                .clone()
                .acquire_owned()
                .await
                .context("H3 request limiter closed")?;
            let context = context.clone();
            let activity = activity.clone();
            let upstream = upstream.clone();
            tokio::spawn(async move {
                let _request_permit = request_permit;
                let result = async {
                    let (request, stream) = resolver
                        .resolve_request()
                        .await
                        .context("resolving HTTP/3 request headers")?;
                    activity.notify_one();

                    let authority = request
                        .uri()
                        .authority()
                        .map(|authority| authority.host().to_string())
                        .unwrap_or_else(|| context.handshake_sni.clone());
                    let request_route = context.router.match_host(&authority);
                    if !authority_reuses_upstream(
                        request_route,
                        context.handshake_route,
                        &authority,
                        &context.handshake_sni,
                        context.reflects_dial_host,
                        context.reflects_server_name,
                    ) {
                        debug!(
                            %peer,
                            sni = %context.handshake_sni,
                            %authority,
                            handshake_route = context.handshake_route,
                            request_route = ?request_route,
                            reflects_dial_host = context.reflects_dial_host,
                            reflects_server_name = context.reflects_server_name,
                            "rejecting coalesced H3 request that would change upstream identity"
                        );
                        return empty_response(stream, StatusCode::MISDIRECTED_REQUEST).await;
                    }

                    debug!(
                        %peer,
                        route = %context.route_name,
                        %authority,
                        method = %request.method(),
                        "forwarding HTTP/3 request"
                    );

                    let lease = match upstream.acquire().await {
                        Ok(lease) => lease,
                        Err(error) => {
                            let status = upstream_failure_status(&error);
                            warn!(
                                %peer,
                                route = %context.route_name,
                                %authority,
                                %status,
                                error = %format!("{error:#}"),
                                "upstream H3 connection unavailable"
                            );
                            return empty_response(stream, status).await;
                        }
                    };
                    let mut sender = lease.upstream.sender.clone();
                    let upstream_stream = match sender.send_request(request).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            // A send failure means this pooled connection is no
                            // longer safe to hand to subsequent requests. Do not
                            // replay the current request automatically: the peer
                            // may have received enough header bytes to make a
                            // non-idempotent retry unsafe. Evict it and let the
                            // next request establish a fresh connection.
                            lease.invalidate().await;
                            warn!(
                                %peer,
                                route = %context.route_name,
                                %authority,
                                error = %error,
                                "pooled upstream H3 send failed; evicted connection"
                            );
                            return empty_response(stream, StatusCode::BAD_GATEWAY).await;
                        }
                    };
                    proxy_stream(stream, upstream_stream, &activity).await
                }
                .await;

                if let Err(error) = result {
                    warn!(
                        %peer,
                        route = %context.route_name,
                        error = %format!("{error:#}"),
                        "HTTP/3 request failed"
                    );
                }
            });
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = serve => result,
        _ = h3_idle_guard(&activity, idle_timeout) => {
            Err(anyhow!("H3 route {} idle timeout", context.route_name))
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn proxy_inbound_h3(
    connection: quinn::Connection,
    peer: SocketAddr,
    router: Arc<Router>,
    handshake_route: usize,
    handshake_sni: String,
    route_name: String,
    reflects_dial_host: bool,
    reflects_server_name: bool,
    upstream: UpstreamH3,
) -> Result<()> {
    proxy_inbound_h3_inner(
        connection,
        peer,
        H3ProxyContext {
            router,
            handshake_route,
            handshake_sni,
            route_name,
            reflects_dial_host,
            reflects_server_name,
            idle_timeout: Duration::ZERO,
        },
        UpstreamProvider::Fixed(upstream),
    )
    .await
}

/// Whether a request on an already-established inbound H3 connection can reuse
/// the single upstream H3 connection created for the handshake SNI.
///
/// Crossing route IDs is always unsafe. Even within one route, a different
/// authority cannot reuse the upstream connection when either the dial host or
/// the upstream verification/SNI name reflects the inbound name; those values
/// were fixed when the upstream QUIC handshake was established. Fixed dial host
/// + fixed SNI routes may safely coalesce within the same route.
fn authority_reuses_upstream(
    request_route: Option<usize>,
    handshake_route: usize,
    authority: &str,
    handshake_sni: &str,
    reflects_dial_host: bool,
    reflects_server_name: bool,
) -> bool {
    if request_route != Some(handshake_route) {
        return false;
    }
    if authority.eq_ignore_ascii_case(handshake_sni) {
        return true;
    }
    !(reflects_dial_host || reflects_server_name)
}

fn upstream_failure_status(error: &anyhow::Error) -> StatusCode {
    if error.chain().any(|source| {
        source
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    }) {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    }
}

/// Resolve only after the H3 application layer has seen no request/response
/// headers, DATA, or trailers for `idle`. QUIC keepalives and transport ACKs do
/// not count as application activity. Zero disables the route-level timeout.
async fn h3_idle_guard(activity: &Notify, idle: Duration) {
    if idle.is_zero() {
        std::future::pending::<()>().await;
        return;
    }
    loop {
        match timeout(idle, activity.notified()).await {
            Ok(()) => continue,
            Err(_) => return,
        }
    }
}

#[derive(Clone)]
struct UpstreamH3 {
    /// Keep the endpoint alive for at least as long as the H3 sender. Quinn
    /// closes all of an endpoint's connections when the last handle is dropped.
    _endpoint: quinn::Endpoint,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

async fn pooled_upstream_h3(
    listener: SocketAddr,
    route_id: usize,
    route: &RouteRuntime,
    handshake_sni: &str,
    peer: SocketAddr,
    cert_resolver: &Arc<DynamicResolver>,
) -> Result<(UpstreamPoolKey, UpstreamH3)> {
    let identity = upstream_identity(route, handshake_sni)?;
    let key = UpstreamPoolKey {
        listener,
        route_id,
        host: identity.host.clone(),
        port: route.upstream_port,
        server_name: identity.server_name.clone(),
        ech: route.route_type == RouteType::H3Ech,
    };
    let pool = upstream_h3_pool();
    let now = Instant::now();

    {
        let mut entries = pool.lock().await;
        entries.retain(|_, entry| {
            !entry.closed.load(Ordering::Acquire)
                && now.duration_since(entry.last_used) < UPSTREAM_H3_POOL_IDLE
        });
        if let Some(entry) = entries.get_mut(&key) {
            entry.last_used = now;
            debug!(
                %peer,
                route = %route.name,
                host = %identity.host,
                upstream = %entry.upstream_addr,
                sni = %identity.server_name,
                "reusing pooled upstream H3 connection"
            );
            return Ok((key, entry.upstream.clone()));
        }
    }

    let target = resolve_upstream_target(route, &identity).await?;
    let created =
        connect_upstream_h3_target(route, handshake_sni, peer, cert_resolver, &target).await?;

    let mut entries = pool.lock().await;
    // Another task may have connected the same logical key while we were
    // resolving/handshaking. Prefer its healthy connection and let our
    // duplicate drop naturally.
    if let Some(entry) = entries.get_mut(&key) {
        if !entry.closed.load(Ordering::Acquire) {
            entry.last_used = Instant::now();
            return Ok((key, entry.upstream.clone()));
        }
        entries.remove(&key);
    }

    if entries.len() >= MAX_UPSTREAM_H3_POOL_ENTRIES {
        if let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
    }
    let upstream = created.upstream.clone();
    entries.insert(
        key.clone(),
        UpstreamPoolEntry {
            upstream: created.upstream,
            upstream_addr: target.upstream_addr,
            closed: created.closed,
            last_used: Instant::now(),
        },
    );
    Ok((key, upstream))
}

fn upstream_identity(route: &RouteRuntime, handshake_sni: &str) -> Result<UpstreamIdentity> {
    let host = route
        .upstream_host
        .clone()
        .or_else(|| (!handshake_sni.is_empty()).then(|| handshake_sni.to_string()))
        .ok_or_else(|| {
            anyhow!(
                "H3 route {} reflects SNI upstream but none was presented",
                route.name
            )
        })?;
    let server_name = match &route.sni_policy {
        SniPolicy::Fixed(name) => name.clone(),
        SniPolicy::Reflect | SniPolicy::Omit if !handshake_sni.is_empty() => {
            handshake_sni.to_string()
        }
        SniPolicy::Reflect | SniPolicy::Omit => host.clone(),
    };
    Ok(UpstreamIdentity { host, server_name })
}

async fn resolve_upstream_target(
    route: &RouteRuntime,
    identity: &UpstreamIdentity,
) -> Result<UpstreamTarget> {
    let upstream_addr = route
        .addr_resolver
        .lookup_addr(
            &identity.host,
            route.upstream_port,
            route.address_family,
            route.nat64.as_ref(),
        )
        .await
        .with_context(|| format!("resolving H3 upstream {}", identity.host))?;

    Ok(UpstreamTarget {
        host: identity.host.clone(),
        server_name: identity.server_name.clone(),
        upstream_addr,
    })
}

async fn connect_upstream_h3_target(
    route: &RouteRuntime,
    handshake_sni: &str,
    peer: SocketAddr,
    cert_resolver: &Arc<DynamicResolver>,
    target: &UpstreamTarget,
) -> Result<CreatedUpstream> {
    let bind_addr = match target.upstream_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let endpoint = quinn::Endpoint::client(bind_addr).context("binding H3 client endpoint")?;
    let connection = match route.route_type {
        RouteType::H3 => {
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(route.root_store.as_ref().clone())
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            if route.sni_policy == SniPolicy::Omit {
                tls.enable_sni = false;
            }
            let crypto = QuicClientConfig::try_from(tls)
                .context("converting H3 rustls client config to Quinn")?;
            connect_quinn(
                &endpoint,
                quinn::ClientConfig::new(Arc::new(crypto)),
                target.upstream_addr,
                &target.server_name,
                route.connect_timeout,
            )
            .await?
        }
        RouteType::H3Ech => {
            connect_ech_quinn(
                &endpoint,
                target.upstream_addr,
                &target.server_name,
                route,
                peer,
            )
            .await?
        }
        _ => return Err(anyhow!("route {} is not an HTTP/3 route", route.name)),
    };

    let negotiated_h3 = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .is_some_and(|protocol| protocol.as_slice() == b"h3");
    if !negotiated_h3 {
        return Err(anyhow!(
            "upstream QUIC connection did not negotiate h3 ALPN"
        ));
    }

    if let Some(chain) = connection.peer_identity().and_then(|identity| {
        identity
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .ok()
    }) {
        upstream_certs::observe_upstream_certificate(
            cert_resolver,
            &route.name,
            &route.sni_policy,
            Some(handshake_sni),
            chain.as_slice(),
        );
    }

    debug!(
        %peer,
        route = %route.name,
        host = %target.host,
        upstream = %target.upstream_addr,
        sni = %target.server_name,
        "upstream H3 connection established"
    );

    let quic = h3_quinn::Connection::new(connection);
    let mut upstream_builder = h3::client::builder();
    upstream_builder.max_field_section_size(MAX_H3_FIELD_SECTION_SIZE);
    let (mut driver, sender) = upstream_builder
        .build(quic)
        .await
        .context("starting upstream HTTP/3 client")?;
    let route_name = route.name.clone();
    let closed = Arc::new(AtomicBool::new(false));
    let driver_closed = closed.clone();
    tokio::spawn(async move {
        let close = poll_fn(|cx| driver.poll_close(cx)).await;
        driver_closed.store(true, Ordering::Release);
        if close.is_h3_no_error() {
            debug!(route = %route_name, "upstream H3 driver closed normally");
        } else {
            debug!(
                route = %route_name,
                error = %close,
                "upstream H3 driver closed with error"
            );
        }
    });

    Ok(CreatedUpstream {
        upstream: UpstreamH3 {
            _endpoint: endpoint,
            sender,
        },
        closed,
    })
}

async fn connect_quinn(
    endpoint: &quinn::Endpoint,
    config: quinn::ClientConfig,
    addr: SocketAddr,
    server_name: &str,
    connect_timeout: std::time::Duration,
) -> Result<quinn::Connection> {
    let connecting = endpoint
        .connect_with(config, addr, server_name)
        .with_context(|| format!("starting H3 QUIC connection to {server_name}"))?;
    timeout(connect_timeout, connecting)
        .await
        .context("upstream H3 QUIC handshake timed out")?
        .context("upstream H3 QUIC handshake")
}

async fn connect_ech_quinn(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    inner: &str,
    route: &RouteRuntime,
    peer: SocketAddr,
) -> Result<quinn::Connection> {
    let ech = route
        .ech
        .as_ref()
        .ok_or_else(|| anyhow!("h3-ech route {} missing ECH provider", route.name))?;
    let alpn = [b"h3".to_vec()];
    let mut attempt = 0u32;
    loop {
        let client = ech
            .client(inner, &alpn)
            .await
            .context("assembling H3 ECH client config")?;
        let crypto = QuicClientConfig::try_from(client.client_config)
            .context("converting H3 ECH rustls config to Quinn")?;
        match connect_quinn(
            endpoint,
            quinn::ClientConfig::new(Arc::new(crypto)),
            addr,
            inner,
            route.connect_timeout,
        )
        .await
        {
            Ok(connection) => {
                debug!(%peer, route = %route.name, attempt, "H3 ECH handshake established");
                return Ok(connection);
            }
            Err(error) if is_ech_reject_quinn(&error) && attempt < route.max_retries => {
                attempt += 1;
                warn!(
                    %peer,
                    route = %route.name,
                    attempt,
                    "H3 ECH rejected; refreshing config and retrying"
                );
                ech.invalidate(inner).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Quinn 0.11.11 / quinn-proto 0.11.x flatten the rustls handshake error into
/// a QUIC transport error and retain only its human-readable reason. Keep the
/// matching deliberately narrow so unrelated TLS failures are never retried as
/// ECH rotations. A successful real-ECH rustls handshake is necessarily ECH-
/// accepted; rejection terminates the handshake with rustls `RejectedEch`.
fn is_ech_reject_quinn(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<quinn::ConnectionError>()
            .and_then(|error| match error {
                quinn::ConnectionError::TransportError(error) => Some(error.reason.as_str()),
                _ => None,
            })
            .is_some_and(|reason| {
                let reason = reason.to_ascii_lowercase();
                reason.contains("rejected")
                    && (reason.contains("encrypted client hello") || reason.contains("ech"))
            })
    })
}

async fn empty_response<S, B>(
    mut stream: h3::server::RequestStream<S, B>,
    status: StatusCode,
) -> Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: Buf,
{
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())?;
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}

async fn proxy_stream<SI, SO>(
    inbound: h3::server::RequestStream<SI, bytes::Bytes>,
    upstream: h3::client::RequestStream<SO, bytes::Bytes>,
    activity: &Notify,
) -> Result<()>
where
    SI: h3::quic::BidiStream<bytes::Bytes>,
    SO: h3::quic::BidiStream<bytes::Bytes>,
{
    let (mut inbound_send, mut inbound_recv) = inbound.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();

    let upload = async {
        while let Some(mut chunk) = inbound_recv.recv_data().await? {
            activity.notify_one();
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            upstream_send.send_data(bytes).await?;
        }
        if let Some(trailers) = inbound_recv.recv_trailers().await? {
            activity.notify_one();
            upstream_send.send_trailers(trailers).await?;
        }
        upstream_send.finish().await?;
        Ok::<(), h3::error::StreamError>(())
    };

    let download = async {
        let response = upstream_recv.recv_response().await?;
        activity.notify_one();
        inbound_send.send_response(response).await?;
        while let Some(mut chunk) = upstream_recv.recv_data().await? {
            activity.notify_one();
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            inbound_send.send_data(bytes).await?;
        }
        if let Some(trailers) = upstream_recv.recv_trailers().await? {
            activity.notify_one();
            inbound_send.send_trailers(trailers).await?;
        }
        inbound_send.finish().await?;
        Ok::<(), h3::error::StreamError>(())
    };

    tokio::try_join!(upload, download).context("proxying HTTP/3 stream")?;
    Ok(())
}
