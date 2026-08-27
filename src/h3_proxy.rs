//! HTTP/3 semantic proxy data path.
//!
//! The shared UDP dispatcher and Quinn own transport demultiplexing. This
//! module starts at an already-established inbound QUIC connection and handles
//! HTTP/3 request semantics. Request authority is re-routed per stream so H3
//! connection coalescing can never bypass the listener's route boundaries.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::future::poll_fn;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Buf;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};
use tracing::{debug, warn};

use super::quic_runtime;
use crate::config::{RouteType, SniPolicy};
use crate::proxy::{upstream_certs, ListenerState, RouteRuntime};
use crate::resolver::DynamicResolver;
use crate::router::Router;

#[cfg(test)]
#[path = "h3_proxy/tests.rs"]
mod tests;

static H3_CONNECTION_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static UPSTREAM_H3_CONNECT_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static UPSTREAM_H3_POOL_ENTRY_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static UPSTREAM_H3_POOL: OnceLock<Arc<UpstreamH3Pool>> = OnceLock::new();
type UpstreamConnectFlight = Arc<Mutex<()>>;
type UpstreamConnectFlights = Arc<Mutex<HashMap<UpstreamPoolKey, Weak<Mutex<()>>>>>;
static UPSTREAM_H3_CONNECT_FLIGHTS: OnceLock<UpstreamConnectFlights> = OnceLock::new();
static OUTBOUND_H3_ENDPOINTS: OnceLock<Arc<Mutex<HashMap<OutboundEndpointKey, quinn::Endpoint>>>> =
    OnceLock::new();
static PLAIN_H3_CLIENT_CONFIGS: OnceLock<
    Arc<Mutex<HashMap<OutboundRouteKey, quinn::ClientConfig>>>,
> = OnceLock::new();

fn h3_connection_limit() -> Arc<Semaphore> {
    H3_CONNECTION_LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(quic_runtime::limits().max_h3_connections)))
        .clone()
}

fn upstream_h3_connect_limit() -> Arc<Semaphore> {
    UPSTREAM_H3_CONNECT_LIMIT
        .get_or_init(|| {
            Arc::new(Semaphore::new(
                quic_runtime::limits().max_pending_upstream_connects,
            ))
        })
        .clone()
}

const UPSTREAM_H3_POOL_SHARDS: usize = 16;

fn upstream_h3_pool_entry_limit() -> Arc<Semaphore> {
    UPSTREAM_H3_POOL_ENTRY_LIMIT
        .get_or_init(|| {
            Arc::new(Semaphore::new(
                quic_runtime::limits().max_upstream_pool_entries,
            ))
        })
        .clone()
}

fn upstream_h3_pool() -> Arc<UpstreamH3Pool> {
    UPSTREAM_H3_POOL
        .get_or_init(|| Arc::new(UpstreamH3Pool::new()))
        .clone()
}

fn upstream_h3_connect_flights() -> UpstreamConnectFlights {
    UPSTREAM_H3_CONNECT_FLIGHTS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn outbound_h3_endpoints() -> Arc<Mutex<HashMap<OutboundEndpointKey, quinn::Endpoint>>> {
    OUTBOUND_H3_ENDPOINTS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn plain_h3_client_configs() -> Arc<Mutex<HashMap<OutboundRouteKey, quinn::ClientConfig>>> {
    PLAIN_H3_CLIENT_CONFIGS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn upstream_h3_transport_config() -> Result<Arc<quinn::TransportConfig>> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quic_runtime::limits()
            .upstream_pool_idle
            .try_into()
            .context("converting upstream H3 pool idle timeout to QUIC transport units")?,
    ));
    Ok(Arc::new(transport))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OutboundRouteKey {
    listener: SocketAddr,
    route_id: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum OutboundAddressFamily {
    Ipv4,
    Ipv6,
}

impl From<IpAddr> for OutboundAddressFamily {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OutboundEndpointKey {
    route: OutboundRouteKey,
    family: OutboundAddressFamily,
}

struct UpstreamPoolEntry {
    upstream: UpstreamH3,
    upstream_addr: SocketAddr,
    closed: Arc<AtomicBool>,
    last_used: Instant,
    _pool_slot: OwnedSemaphorePermit,
}

struct UpstreamH3Pool {
    shards: Box<[Mutex<HashMap<UpstreamPoolKey, UpstreamPoolEntry>>]>,
}

impl UpstreamH3Pool {
    fn new() -> Self {
        let shards = (0..UPSTREAM_H3_POOL_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { shards }
    }

    fn shard_index(&self, key: &UpstreamPoolKey) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize % self.shards.len()
    }

    fn shard(&self, key: &UpstreamPoolKey) -> &Mutex<HashMap<UpstreamPoolKey, UpstreamPoolEntry>> {
        &self.shards[self.shard_index(key)]
    }

    async fn evict_one(&self) -> bool {
        for shard in &self.shards {
            let mut entries = shard.lock().await;
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            if let Some(key) = oldest {
                entries.remove(&key);
                return true;
            }
        }
        false
    }
}

struct UpstreamIdentity {
    host: String,
    server_name: String,
}

struct UpstreamTarget {
    host: String,
    server_name: String,
    upstream_addrs: Vec<SocketAddr>,
}

struct CreatedUpstream {
    upstream: UpstreamH3,
    upstream_addr: SocketAddr,
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
    pool_generation: Option<Arc<AtomicBool>>,
}

impl UpstreamProvider {
    async fn acquire(&self) -> Result<UpstreamLease> {
        match self {
            #[cfg(test)]
            Self::Fixed(upstream) => Ok(UpstreamLease {
                upstream: upstream.clone(),
                pool_key: None,
                pool_generation: None,
            }),
            Self::Pooled(context) => {
                let (pool_key, upstream, pool_generation) = pooled_upstream_h3(
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
                    pool_generation: Some(pool_generation),
                })
            }
        }
    }
}

impl UpstreamLease {
    async fn invalidate(self) {
        let (Some(key), Some(generation)) = (self.pool_key, self.pool_generation) else {
            return;
        };

        // Mark this generation unusable immediately, then remove it only if the
        // pool still points at the same generation. A stale request from an old
        // connection must never evict a healthy replacement inserted under the
        // same logical key while that request was in flight.
        generation.store(true, Ordering::Release);
        let pool = upstream_h3_pool();
        let mut entries = pool.shard(&key).lock().await;
        let same_generation = entries
            .get(&key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.closed, &generation));
        if same_generation {
            entries.remove(&key);
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
    let limits = quic_runtime::limits();
    let _connection_permit = match h3_connection_limit().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            debug!(
                %peer,
                max_connections = limits.max_h3_connections,
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
    let limits = quic_runtime::limits();
    let quic = h3_quinn::Connection::new(connection);
    let mut inbound_builder = h3::server::builder();
    inbound_builder.max_field_section_size(limits.max_field_section_size);
    let mut inbound = inbound_builder
        .build(quic)
        .await
        .context("starting inbound HTTP/3 connection")?;
    let activity = Arc::new(Notify::new());
    let request_limit = Arc::new(Semaphore::new(limits.max_requests_per_connection));
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
                    // Keep a generation handle alive for the complete stream
                    // lifetime. The shared endpoint registry outlives pool
                    // eviction, while this sender clone ensures an active
                    // request never depends on the reusable map entry itself.
                    let upstream_guard = lease.upstream.clone();
                    let mut sender = upstream_guard.sender.clone();
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
                    let result = proxy_stream(stream, upstream_stream, &activity).await;
                    drop(upstream_guard);
                    result
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
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

struct UpstreamPoolHit {
    upstream: UpstreamH3,
    upstream_addr: SocketAddr,
    closed: Arc<AtomicBool>,
}

async fn lookup_upstream_h3_pool(
    pool: &UpstreamH3Pool,
    key: &UpstreamPoolKey,
    now: Instant,
) -> Option<UpstreamPoolHit> {
    let idle = quic_runtime::limits().upstream_pool_idle;
    let mut entries = pool.shard(key).lock().await;
    entries.retain(|_, entry| {
        !entry.closed.load(Ordering::Acquire) && now.duration_since(entry.last_used) < idle
    });
    let entry = entries.get_mut(key)?;
    entry.last_used = now;
    Some(UpstreamPoolHit {
        upstream: entry.upstream.clone(),
        upstream_addr: entry.upstream_addr,
        closed: entry.closed.clone(),
    })
}

async fn upstream_h3_connect_flight(key: &UpstreamPoolKey) -> UpstreamConnectFlight {
    let flights = upstream_h3_connect_flights();
    let mut flights = flights.lock().await;
    if flights.len()
        > quic_runtime::limits()
            .max_upstream_pool_entries
            .saturating_mul(4)
    {
        flights.retain(|_, flight| flight.strong_count() > 0);
    }
    if let Some(flight) = flights.get(key).and_then(Weak::upgrade) {
        return flight;
    }
    let flight = Arc::new(Mutex::new(()));
    flights.insert(key.clone(), Arc::downgrade(&flight));
    flight
}

async fn reserve_upstream_h3_pool_slot(pool: &UpstreamH3Pool) -> Result<OwnedSemaphorePermit> {
    let limit = upstream_h3_pool_entry_limit();
    if let Ok(permit) = limit.clone().try_acquire_owned() {
        return Ok(permit);
    }
    if !pool.evict_one().await {
        return Err(anyhow!(
            "upstream H3 pool capacity exhausted without an evictable entry"
        ));
    }
    limit
        .try_acquire_owned()
        .context("upstream H3 pool slot was not released after eviction")
}

async fn pooled_upstream_h3(
    listener: SocketAddr,
    route_id: usize,
    route: &RouteRuntime,
    handshake_sni: &str,
    peer: SocketAddr,
    cert_resolver: &Arc<DynamicResolver>,
) -> Result<(UpstreamPoolKey, UpstreamH3, Arc<AtomicBool>)> {
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
    if let Some(hit) = lookup_upstream_h3_pool(&pool, &key, Instant::now()).await {
        debug!(
            %peer,
            route = %route.name,
            host = %identity.host,
            upstream = %hit.upstream_addr,
            sni = %identity.server_name,
            "reusing pooled upstream H3 connection"
        );
        return Ok((key, hit.upstream, hit.closed));
    }

    let flight = upstream_h3_connect_flight(&key).await;
    let _flight_guard = timeout(route.connect_timeout, flight.lock())
        .await
        .context("waiting for same-key upstream H3 connection timed out")?;

    // The task that owned this key's flight may have populated the pool while
    // we waited. Only the flight owner reaches DNS and QUIC establishment.
    if let Some(hit) = lookup_upstream_h3_pool(&pool, &key, Instant::now()).await {
        debug!(
            %peer,
            route = %route.name,
            host = %identity.host,
            upstream = %hit.upstream_addr,
            sni = %identity.server_name,
            "reusing upstream H3 connection after same-key wait"
        );
        return Ok((key, hit.upstream, hit.closed));
    }

    let _connect_permit = timeout(
        route.connect_timeout,
        upstream_h3_connect_limit().acquire_owned(),
    )
    .await
    .context("waiting for upstream H3 connect capacity timed out")?
    .context("upstream H3 connect limiter closed")?;

    // Reserve exact process-wide pool capacity before starting an operation
    // whose successful result must be retained. A failed resolve/handshake
    // drops this permit automatically; concurrent connects can never create an
    // unbounded set of completed-but-not-yet-inserted connections.
    let pool_slot = reserve_upstream_h3_pool_slot(&pool).await?;
    let target = resolve_upstream_target(route, &identity).await?;
    let created = connect_upstream_h3_target(
        listener,
        route_id,
        route,
        handshake_sni,
        peer,
        cert_resolver,
        &target,
    )
    .await?;

    let mut entries = pool.shard(&key).lock().await;
    // Defensive re-check: per-key singleflight should make a duplicate
    // impossible, but invalidation and future pool callers must not replace a
    // healthy generation accidentally.
    if let Some(entry) = entries.get_mut(&key) {
        if !entry.closed.load(Ordering::Acquire) {
            entry.last_used = Instant::now();
            return Ok((key, entry.upstream.clone(), entry.closed.clone()));
        }
        entries.remove(&key);
    }
    let upstream = created.upstream.clone();
    let generation = created.closed.clone();
    entries.insert(
        key.clone(),
        UpstreamPoolEntry {
            upstream: created.upstream,
            upstream_addr: created.upstream_addr,
            closed: created.closed,
            last_used: Instant::now(),
            _pool_slot: pool_slot,
        },
    );
    Ok((key, upstream, generation))
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
    let upstream_addrs = route
        .addr_resolver
        .lookup_addrs(
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
        upstream_addrs,
    })
}

async fn connect_upstream_h3_target(
    listener: SocketAddr,
    route_id: usize,
    route: &RouteRuntime,
    handshake_sni: &str,
    peer: SocketAddr,
    cert_resolver: &Arc<DynamicResolver>,
    target: &UpstreamTarget,
) -> Result<CreatedUpstream> {
    let route_key = OutboundRouteKey { listener, route_id };
    let (connection, upstream_addr) = match route.route_type {
        RouteType::H3 => {
            let config = plain_h3_client_config(route_key, route).await?;
            crate::connect::race(&target.upstream_addrs, route.connect_timeout, |addr| {
                let config = config.clone();
                async move {
                    let endpoint = outbound_h3_endpoint(route_key, addr.ip()).await?;
                    connect_quinn(
                        &endpoint,
                        config,
                        addr,
                        &target.server_name,
                        route.connect_timeout,
                    )
                    .await
                }
            })
            .await?
        }
        RouteType::H3Ech => {
            crate::connect::race(
                &target.upstream_addrs,
                route.connect_timeout,
                |addr| async move {
                    let endpoint = outbound_h3_endpoint(route_key, addr.ip()).await?;
                    connect_ech_quinn(&endpoint, addr, &target.server_name, route, peer).await
                },
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
        upstream = %upstream_addr,
        sni = %target.server_name,
        "upstream H3 connection established"
    );

    let quic = h3_quinn::Connection::new(connection);
    let mut upstream_builder = h3::client::builder();
    upstream_builder.max_field_section_size(quic_runtime::limits().max_field_section_size);
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
        upstream: UpstreamH3 { sender },
        upstream_addr,
        closed,
    })
}

async fn outbound_h3_endpoint(
    route: OutboundRouteKey,
    upstream_ip: IpAddr,
) -> Result<quinn::Endpoint> {
    let family = OutboundAddressFamily::from(upstream_ip);
    let key = OutboundEndpointKey { route, family };
    let endpoints = outbound_h3_endpoints();
    let mut endpoints = endpoints.lock().await;
    if let Some(endpoint) = endpoints.get(&key) {
        return Ok(endpoint.clone());
    }

    let bind_addr = match family {
        OutboundAddressFamily::Ipv4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        OutboundAddressFamily::Ipv6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let endpoint =
        quinn::Endpoint::client(bind_addr).context("binding shared H3 client endpoint")?;
    endpoints.insert(key, endpoint.clone());
    Ok(endpoint)
}

async fn plain_h3_client_config(
    key: OutboundRouteKey,
    route: &RouteRuntime,
) -> Result<quinn::ClientConfig> {
    let configs = plain_h3_client_configs();
    let mut configs = configs.lock().await;
    if let Some(config) = configs.get(&key) {
        return Ok(config.clone());
    }

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(route.root_store.as_ref().clone())
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    if route.sni_policy == SniPolicy::Omit {
        tls.enable_sni = false;
    }
    let crypto = QuicClientConfig::try_from(tls)
        .context("converting shared H3 rustls client config to Quinn")?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(upstream_h3_transport_config()?);
    configs.insert(key, config.clone());
    Ok(config)
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
    let transport = upstream_h3_transport_config()?;
    let mut attempt = 0u32;
    loop {
        let client = ech
            .client(inner, &alpn)
            .await
            .context("assembling H3 ECH client config")?;
        let crypto = QuicClientConfig::try_from(client.client_config)
            .context("converting H3 ECH rustls config to Quinn")?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport.clone());
        match connect_quinn(
            endpoint,
            config,
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
