//! Named DNS resolvers: `[resolvers.<name>]` built into live hickory resolvers,
//! with a nominated bootstrap for their own address and ECH on their own TLS
//! handshake (reactive retry + proactive rotation).
//!
//! # Why this exists separately from [`crate::dns`]
//!
//! [`crate::dns::ResolverSpec`] parses an *inline* spec and resolves a DoH/DoT
//! host through the OS at parse time. That is exactly what a blocked endpoint
//! cannot rely on: if `dns.example` does not resolve (or resolves somewhere
//! useless), the resolver is unbuildable and there is no way to point it
//! elsewhere. So [`Endpoint::parse`] here performs **no I/O at all** — it keeps
//! the host verbatim, and the address is obtained later through whichever
//! resolver the config nominated as `bootstrap`. That separation is the whole
//! feature: it is what lets a blocked name be dialed at a different address
//! while its TLS identity stays put.
//!
//! # The dial/name split
//!
//! Two knobs move independently, which is why they are stored separately:
//!
//! * `upstream` moves **where we dial** (`dial_host` / `dial_port`).
//! * `override_sni` moves **what name we present** (`server_name`).
//!
//! `NameServerConfig::https(ip, server_name, path)` and `::tls(ip, server_name)`
//! take the address and the name as separate arguments, so both are expressible
//! at once: dial a CDN edge, present the real endpoint name. On DoH the name is
//! also the HTTP `:authority` (hickory uses one field for both, and RFC 8484
//! addresses the query to that origin), so `override_sni` moves both together on
//! that transport. To *hide* a name rather than change it, use ECH.
//!
//! # ECH rotation replaces the resolver, not its keys
//!
//! hickory fixes its `rustls::ClientConfig` when the resolver is built, and
//! exposes no way to swap it afterwards. `ResolverBuilder::with_tls_config` is
//! the only injection seam. So "rotating ECH keys" necessarily means building a
//! whole new `TokioResolver` from a fresh ECHConfigList and swapping it in
//! atomically — which is what [`DnsResolver::swap`] does.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use rustls::RootCertStore;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::{AddressFamily, EffectiveEch};
use crate::dns;
use crate::ech::{self, ResolverEch};
use crate::nat64::Nat64Prefix;

// ---------------------------------------------------------------------------
// Endpoint: the transport, parsed without touching the network
// ---------------------------------------------------------------------------

/// A named resolver's transport, parsed with **no I/O**.
///
/// Contrast [`crate::dns::ResolverSpec`], which resolves DoH/DoT hosts to an
/// `IpAddr` during parsing (a blocking `to_socket_addrs()` call). Here the host
/// is kept as written so it can be resolved later, through a nominated
/// bootstrap, rather than through whatever the OS would have said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// The OS resolver. Has no dial host of its own and takes no transport
    /// overrides.
    System,
    /// DNS-over-HTTPS. `host` is verbatim from the config.
    Doh {
        host: String,
        port: u16,
        path: String,
    },
    /// DNS-over-TLS. `host` is verbatim from the config.
    Dot { host: String, port: u16 },
    /// Plain DNS over UDP+TCP. Can be either a literal IP or a hostname that
    /// needs bootstrap resolution.
    Plain { target: String, port: u16 },
}

impl Endpoint {
    /// Parse an endpoint spec. Never performs I/O.
    ///
    /// `system` and the empty string both select the OS resolver.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("system") {
            return Ok(Endpoint::System);
        }

        if let Some(rest) = s.strip_prefix("https://") {
            let (host, port, path) = split_authority_path(rest);
            if host.is_empty() {
                return Err(anyhow!("endpoint {s:?} has no host"));
            }
            return Ok(Endpoint::Doh {
                host,
                port: port.unwrap_or(443),
                path: if path.is_empty() {
                    "/dns-query".to_string()
                } else {
                    path
                },
            });
        }

        if let Some(rest) = s.strip_prefix("tls://") {
            let (host, port, _) = split_authority_path(rest);
            if host.is_empty() {
                return Err(anyhow!("endpoint {s:?} has no host"));
            }
            return Ok(Endpoint::Dot {
                host,
                port: port.unwrap_or(853),
            });
        }

        // udp:// / tcp:// can have hostname or IP; bare string must be IP only.
        // This keeps the namespace disjoint from resolver references.
        let (body, allow_hostname) = if let Some(rest) = s.strip_prefix("udp://") {
            (rest, true)
        } else if let Some(rest) = s.strip_prefix("tcp://") {
            (rest, true)
        } else {
            (s, false)
        };

        // Try to parse as ip:port or bare ip
        let (target, port) = if let Ok(addr) = parse_ip_addr(body) {
            (addr.ip().to_string(), addr.port())
        } else if allow_hostname {
            // With udp:// or tcp:// prefix, accept hostname:port
            match body.rsplit_once(':') {
                Some((host, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (
                    host.to_string(),
                    p.parse().map_err(|_| anyhow!("invalid port"))?,
                ),
                _ => (body.to_string(), 53),
            }
        } else {
            // Without prefix, must be a valid IP address
            return Err(anyhow!(
                "endpoint {s:?} is not a valid ip[:port]. Plain DNS without udp:// or tcp:// \
                 prefix requires a literal IP address. Use udp://{s} to specify a hostname, \
                 or https:// / tls:// for encrypted DNS"
            ));
        };

        Ok(Endpoint::Plain { target, port })
    }

    /// The endpoint's own host as written: the default dial target *and* the
    /// default TLS name. `None` for [`Endpoint::System`], which has neither.
    pub fn host(&self) -> Option<&str> {
        match self {
            Endpoint::System => None,
            Endpoint::Doh { host, .. } | Endpoint::Dot { host, .. } => Some(host),
            Endpoint::Plain { target, .. } => {
                // Return the target if it's not a bare IP address
                if target.parse::<std::net::IpAddr>().is_ok() {
                    None
                } else {
                    Some(target)
                }
            }
        }
    }

    /// The endpoint's own port. Meaningless for [`Endpoint::System`].
    pub fn port(&self) -> u16 {
        match self {
            Endpoint::System => 53,
            Endpoint::Doh { port, .. }
            | Endpoint::Dot { port, .. }
            | Endpoint::Plain { port, .. } => *port,
        }
    }

    /// Whether this transport performs a TLS handshake, and therefore whether
    /// `override_sni` and `ech` mean anything for it.
    pub fn is_tls(&self) -> bool {
        matches!(self, Endpoint::Doh { .. } | Endpoint::Dot { .. })
    }

    /// A short label for diagnostics.
    fn kind(&self) -> &'static str {
        match self {
            Endpoint::System => "system",
            Endpoint::Doh { .. } => "DoH",
            Endpoint::Dot { .. } => "DoT",
            Endpoint::Plain { .. } => "plain DNS",
        }
    }
}

/// Split `host[:port][/path]` into (host, port?, path). Path is `""` when absent.
fn split_authority_path(s: &str) -> (String, Option<u16>, String) {
    let (authority, path) = match s.find('/') {
        Some(i) => (&s[..i], s[i..].to_string()),
        None => (s, String::new()),
    };
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().ok(), path)
        }
        _ => (authority.to_string(), None, path),
    }
}

/// Parse `ip` or `ip:port` (v4, or bracketed v6) with a default of port 53.
fn parse_ip_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(anyhow!("invalid IP address {s:?}"))
}

// ---------------------------------------------------------------------------
// The rebuild plan
// ---------------------------------------------------------------------------

/// Everything needed to build — and later *re*build — one named resolver.
///
/// A rebuild re-runs the whole plan: re-resolve the dial address through the
/// bootstrap, re-fetch the ECHConfigList, reassemble the TLS config. That is
/// deliberate. An ECH rotation is usually accompanied by the edge moving, and a
/// plan that only refreshed the keys would keep dialing a stale address.
pub struct ResolverPlan {
    /// Declared name, for diagnostics.
    pub label: String,
    pub endpoint: Endpoint,
    /// Host to dial: `upstream`'s host if given, else the endpoint's own.
    /// Empty for [`Endpoint::System`], which is never dialed by us.
    pub dial_host: String,
    /// Port to dial: `upstream`'s port if given, else the endpoint's own.
    pub dial_port: u16,
    /// TLS server name to present (also the DoH `:authority`). `None` for
    /// transports without TLS.
    pub server_name: Option<String>,
    /// Whether to send a `server_name` extension at all. False only when
    /// `override_sni = ""`; the certificate is still verified against
    /// `server_name`.
    pub enable_sni: bool,
    /// Address family used when resolving `dial_host`.
    pub family: AddressFamily,
    pub nat64: Option<Nat64Prefix>,
    /// Per-query timeout handed to hickory.
    pub connect_timeout: Duration,
    /// Who resolves `dial_host`. Always present: an omitted `bootstrap` is the
    /// system resolver, wrapped so this type has one uniform path.
    pub bootstrap: Arc<DnsResolver>,
    /// ECH for this resolver's own handshake. `None` when not opted in.
    pub ech: Option<EchPlan>,
}

/// ECH parameters for a resolver's own TLS handshake.
pub struct EchPlan {
    pub settings: EffectiveEch,
    /// Fail to build rather than fall back to GREASE when no ECHConfig is
    /// published.
    ///
    /// **This is weaker than a route's `require_ech`.** See [`EchPlan`] docs.
    pub require_ech: bool,
    /// Proactive rotation interval.
    pub refresh: Duration,
    /// Resolver performing this resolver's own HTTPS-record lookup.
    pub resolver: Arc<DnsResolver>,
    pub root_store: Arc<RootCertStore>,
    /// Bound on reactive rebuild-and-retry attempts per lookup.
    pub max_retries: u32,
}

impl ResolverPlan {
    /// The DNS name whose HTTPS record carries this resolver's `ech=` parameter.
    fn ech_lookup_name(&self, settings: &EffectiveEch) -> Option<String> {
        let base = settings
            .ech_domain
            .as_deref()
            .or(self.server_name.as_deref())?;
        Some(ech::https_lookup_name(base, self.dial_port))
    }

    /// Reactive retry budget. Zero unless this resolver uses ECH — without ECH
    /// there is no rejection to recover from.
    fn max_retries(&self) -> u32 {
        self.ech.as_ref().map_or(0, |e| e.max_retries)
    }
}

// ---------------------------------------------------------------------------
// The live resolver handle
// ---------------------------------------------------------------------------

/// A live resolver behind an atomically swappable handle.
///
/// # Locking
///
/// * `inner: RwLock<Arc<TokioResolver>>` — a query clones the `Arc` out under a
///   read lock and releases it immediately, so a swap never blocks queries and a
///   query in flight keeps running against the resolver it started with. This is
///   a `std` lock on purpose: the critical section is a pointer clone with no
///   `.await` in it.
/// * `rebuilding: tokio::sync::Mutex<()>` — **held across `.await`** (a rebuild
///   performs DNS lookups), so it must be the async mutex. A `std::sync::Mutex`
///   here would block a runtime worker thread for the length of a network round
///   trip, and `clippy::await_holding_lock` rejects it outright.
/// * `ech_bytes: RwLock<Option<Vec<u8>>>` — the ECHConfigList currently in use,
///   so the proactive path can compare raw bytes and skip a needless rebuild.
///
/// # Generation counter
///
/// A caller records the generation it observed *before* its failed query. If the
/// counter has already moved by the time it takes the rebuild lock, some other
/// task rebuilt for the same rotation and this task simply retries against the
/// new resolver. That makes concurrent rebuilds idempotent: N tasks hitting one
/// rotation cause one rebuild, not N.
pub struct DnsResolver {
    label: String,
    inner: RwLock<Arc<TokioResolver>>,
    /// Rebuild plan. `None` for an inline spec, which has nothing to rebuild
    /// from and never rotates.
    plan: Option<Arc<ResolverPlan>>,
    generation: AtomicU64,
    rebuilding: Mutex<()>,
    ech_bytes: RwLock<Option<Vec<u8>>>,
}

impl DnsResolver {
    /// Wrap an already-built resolver.
    pub fn new(
        label: String,
        resolver: Arc<TokioResolver>,
        plan: Option<Arc<ResolverPlan>>,
        ech_bytes: Option<Vec<u8>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            label,
            inner: RwLock::new(resolver),
            plan,
            generation: AtomicU64::new(0),
            rebuilding: Mutex::new(()),
            ech_bytes: RwLock::new(ech_bytes),
        })
    }

    /// The declared name (or inline spec) this resolver was built from.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// How many times this resolver has been replaced. Observable in tests and
    /// used to make concurrent rebuilds idempotent.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The live resolver, for callers that need the raw hickory handle.
    ///
    /// The returned `Arc` is a snapshot: a later rotation will not affect it.
    /// Callers on the data path should re-take it per operation rather than
    /// caching it, which is what [`Self::lookup_addr`] does internally.
    pub fn snapshot(&self) -> Arc<TokioResolver> {
        self.inner.read().expect("resolver lock poisoned").clone()
    }

    fn swap(&self, new: Arc<TokioResolver>, ech: Option<Vec<u8>>) {
        *self.inner.write().expect("resolver lock poisoned") = new;
        *self.ech_bytes.write().expect("ech lock poisoned") = ech;
        // Release ordering pairs with the Acquire in `generation()`: a task that
        // sees the new generation is guaranteed to see the new resolver.
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn ech_bytes(&self) -> Option<Vec<u8>> {
        self.ech_bytes.read().expect("ech lock poisoned").clone()
    }

    /// Resolve `host:port` to every connectable address, applying the caller's
    /// address family and NAT64 prefix.
    ///
    /// `family` and `nat64` belong to the *caller* (a route decides the family
    /// of its own upstream); the plan's own family governs only how this
    /// resolver reaches its endpoint.
    ///
    /// On an ECH rejection the resolver is rebuilt from a fresh ECHConfigList
    /// and the lookup is retried, up to the plan's `max_retries`.
    pub async fn lookup_addrs(
        &self,
        host: &str,
        port: u16,
        family: AddressFamily,
        nat64: Option<&Nat64Prefix>,
    ) -> Result<Vec<SocketAddr>> {
        let max_retries = self.plan.as_ref().map_or(0, |p| p.max_retries());
        let mut attempt = 0u32;
        loop {
            let seen = self.generation();
            let resolver = self.snapshot();
            match dns::resolve_upstream_addrs(&resolver, host, port, family, nat64).await {
                Err(e) if attempt < max_retries && ech::is_ech_reject_chain(&e) => {
                    warn!(
                        resolver = %self.label,
                        attempt = attempt + 1,
                        "resolver endpoint rejected ECH; rebuilding from a fresh ECHConfig"
                    );
                    self.rebuild(seen, RebuildCause::Rejected).await;
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    /// Resolve to the first preferred address. DNS endpoint bootstrapping and
    /// startup probes use one concrete target; data-plane connections should
    /// use [`Self::lookup_addrs`] so they can race all candidates.
    pub async fn lookup_addr(
        &self,
        host: &str,
        port: u16,
        family: AddressFamily,
        nat64: Option<&Nat64Prefix>,
    ) -> Result<SocketAddr> {
        self.lookup_addrs(host, port, family, nat64)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no address for {host}"))
    }

    /// Run a raw record lookup through this resolver, with the same reactive ECH
    /// rebuild-and-retry as [`Self::lookup_addr`].
    ///
    /// Used for HTTPS/`ech=` lookups, which is how one resolver fetches
    /// another's ECHConfigList.
    pub async fn lookup(&self, name: &str, rtype: RecordType) -> Result<Lookup> {
        let max_retries = self.plan.as_ref().map_or(0, |p| p.max_retries());
        let mut attempt = 0u32;
        loop {
            let seen = self.generation();
            let resolver = self.snapshot();
            let out = resolver
                .lookup(name, rtype)
                .await
                .map_err(anyhow::Error::new)
                .with_context(|| format!("{rtype} lookup for {name}"));
            match out {
                Err(e) if attempt < max_retries && ech::is_ech_reject_chain(&e) => {
                    warn!(
                        resolver = %self.label,
                        attempt = attempt + 1,
                        "resolver endpoint rejected ECH; rebuilding from a fresh ECHConfig"
                    );
                    self.rebuild(seen, RebuildCause::Rejected).await;
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    /// Rebuild and swap, unless another task already did it for this generation.
    ///
    /// # Why this returns a boxed future
    ///
    /// The async call graph is mutually recursive: a rebuild resolves its dial
    /// host (and fetches its ECHConfig) *through other resolvers*, whose own
    /// lookups may in turn rebuild. An `async fn` that can reach itself has an
    /// infinitely-sized state type, so exactly one edge of the cycle must be
    /// boxed to give it a concrete size. This is the right edge to box: a
    /// rebuild happens on rotation or rejection — never on the query fast path —
    /// so the one allocation is unmeasurable, whereas boxing `lookup_addr` would
    /// put an allocation on every DNS query.
    ///
    /// The recursion terminates because the resolver graph is validated acyclic
    /// at config load (`Config::resolver_build_order`), so the chain of
    /// bootstraps is finite.
    fn rebuild<'a>(
        &'a self,
        seen: u64,
        cause: RebuildCause,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(plan) = self.plan.clone() else {
                // An inline spec has no plan: nothing to rebuild from.
                return;
            };

            let _guard = self.rebuilding.lock().await;

            // Someone else rebuilt while we waited for the lock. Their resolver
            // is at least as fresh as ours would have been, so retrying against
            // it is strictly better than rebuilding again.
            if self.generation() != seen {
                debug!(
                    resolver = %self.label,
                    "another task already rebuilt this resolver; using theirs"
                );
                return;
            }

            match build(&plan).await {
                Ok(built) => {
                    // Proactive rotation is a no-op unless the published bytes
                    // actually differ, so the steady state is one HTTPS lookup
                    // per interval with no reconnect. A rejection always
                    // rebuilds: the endpoint told us the keys we hold are wrong,
                    // and identical bytes there mean a stale cache, not a
                    // no-change.
                    if cause == RebuildCause::Rotation && built.ech_bytes == self.ech_bytes() {
                        debug!(
                            resolver = %self.label,
                            "published ECHConfig unchanged; keeping the live resolver"
                        );
                        return;
                    }
                    self.swap(built.resolver, built.ech_bytes);
                    info!(
                        resolver = %self.label,
                        generation = self.generation(),
                        cause = cause.as_str(),
                        "rebuilt resolver"
                    );
                }
                Err(e) => {
                    // Keeping a working-but-stale resolver beats having none:
                    // the next query may still succeed, and if it does not, the
                    // reactive path will try again.
                    warn!(
                        resolver = %self.label,
                        error = %format!("{e:#}"),
                        cause = cause.as_str(),
                        "rebuild failed; keeping the existing resolver"
                    );
                }
            }
        })
    }
}

/// Why a rebuild was triggered. Decides whether unchanged ECH bytes are a reason
/// to skip the swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebuildCause {
    /// The endpoint rejected our ECH extension.
    Rejected,
    /// The proactive timer fired.
    Rotation,
}

impl RebuildCause {
    fn as_str(self) -> &'static str {
        match self {
            RebuildCause::Rejected => "ech-rejected",
            RebuildCause::Rotation => "ech-rotation",
        }
    }
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

/// A freshly built resolver plus the ECHConfigList it was built from.
pub struct Built {
    pub resolver: Arc<TokioResolver>,
    /// The ECHConfigList in use, for byte-comparison on the next rotation.
    pub ech_bytes: Option<Vec<u8>>,
}

/// Build a resolver from its plan: resolve the dial address through the
/// bootstrap, fetch the ECHConfigList, assemble the TLS config, and construct
/// the hickory resolver.
pub async fn build(plan: &ResolverPlan) -> Result<Built> {
    // --- 1. Where to dial ---
    //
    // System is the one transport we do not dial ourselves.
    let dial_ip = match &plan.endpoint {
        Endpoint::System => None,
        Endpoint::Plain { target, .. } => {
            // Plain endpoint: if target is an IP, use it directly; otherwise resolve via bootstrap
            if let Ok(ip) = target.parse::<std::net::IpAddr>() {
                Some(ip)
            } else if plan.dial_host.is_empty() {
                // No upstream override - resolve the endpoint's target
                Some(
                    plan.bootstrap
                        .lookup_addr(
                            target,
                            plan.dial_port,
                            plan.family,
                            plan.nat64.as_ref(),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "[resolvers.{}]: resolving plain endpoint target {:?} through bootstrap {:?}",
                                plan.label,
                                target,
                                plan.bootstrap.label()
                            )
                        })?
                        .ip(),
                )
            } else {
                // Upstream override specified - resolve dial_host
                Some(
                    plan.bootstrap
                        .lookup_addr(
                            &plan.dial_host,
                            plan.dial_port,
                            plan.family,
                            plan.nat64.as_ref(),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "[resolvers.{}]: resolving dial host {:?} through bootstrap {:?}",
                                plan.label,
                                plan.dial_host,
                                plan.bootstrap.label()
                            )
                        })?
                        .ip(),
                )
            }
        }
        _ => Some(
            plan.bootstrap
                .lookup_addr(
                    &plan.dial_host,
                    plan.dial_port,
                    plan.family,
                    plan.nat64.as_ref(),
                )
                .await
                .with_context(|| {
                    format!(
                        "[resolvers.{}]: resolving dial host {:?} through bootstrap {:?}",
                        plan.label,
                        plan.dial_host,
                        plan.bootstrap.label()
                    )
                })?
                .ip(),
        ),
    };

    // --- 2. ECHConfigList, if this resolver uses ECH ---
    let mut ech_bytes: Option<Vec<u8>> = None;
    if let Some(ep) = &plan.ech {
        let name = plan.ech_lookup_name(&ep.settings).ok_or_else(|| {
            anyhow!(
                "[resolvers.{}.ech]: no name to look up an ECHConfig for; set \
                 `ech_domain`",
                plan.label
            )
        })?;
        ech_bytes = ech::acquire_resolver_ech(&ep.settings, &name, &ep.resolver)
            .await
            .with_context(|| format!("[resolvers.{}]: acquiring ECHConfig", plan.label))?;
        if ech_bytes.is_none() && ep.require_ech {
            return Err(anyhow!(
                "[resolvers.{}]: require_ech is set but no ECHConfig is published \
                 for {name:?}",
                plan.label
            ));
        }
    }

    // --- 3. Name server config: dial address and TLS name move separately ---
    let (config, system_opts) = match &plan.endpoint {
        Endpoint::System => {
            let (config, opts) = dns::system_resolver_config()?;
            (config, Some(opts))
        }
        Endpoint::Doh { path, .. } => {
            let ip = dial_ip.expect("non-system endpoints resolve a dial IP");
            let name = plan
                .server_name
                .as_deref()
                .expect("a DoH endpoint always has a server name");
            let mut ns =
                NameServerConfig::https(ip, Arc::from(name), Some(Arc::from(path.as_str())));
            // The constructor has no port argument; hickory takes the port from
            // each connection entry (origin does the same for plain DNS).
            ns.connections
                .iter_mut()
                .for_each(|c| c.port = plan.dial_port);
            (ResolverConfig::from_parts(None, vec![], vec![ns]), None)
        }
        Endpoint::Dot { .. } => {
            let ip = dial_ip.expect("non-system endpoints resolve a dial IP");
            let name = plan
                .server_name
                .as_deref()
                .expect("a DoT endpoint always has a server name");
            let mut ns = NameServerConfig::tls(ip, Arc::from(name));
            ns.connections
                .iter_mut()
                .for_each(|c| c.port = plan.dial_port);
            (ResolverConfig::from_parts(None, vec![], vec![ns]), None)
        }
        Endpoint::Plain { .. } => {
            let ip = dial_ip.expect("non-system endpoints resolve a dial IP");
            let mut ns = NameServerConfig::udp_and_tcp(ip);
            ns.connections
                .iter_mut()
                .for_each(|c| c.port = plan.dial_port);
            (ResolverConfig::from_parts(None, vec![], vec![ns]), None)
        }
    };

    // --- 4. Options ---
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        if let Some(system_opts) = system_opts {
            *opts = system_opts;
        }
        opts.ip_strategy = dns::strategy_for(plan.family);
        // An explicitly configured resolver must answer purely from its own
        // server, never from the local hosts file; only `system` honours hosts,
        // because that is what "system resolution" means. Keeps routing
        // independent of local overrides.
        opts.use_hosts_file = match plan.endpoint {
            Endpoint::System => ResolveHosts::Auto,
            _ => ResolveHosts::Never,
        };
        // `connect_timeout` bounds a query end to end, which is the bound an
        // operator actually cares about for a resolver.
        opts.timeout = plan.connect_timeout;
    }

    // --- 5. TLS config, injected only when we need to change it ---
    //
    // hickory's default TLS config already has sensible roots and ALPN. We
    // replace it only to add ECH or to suppress the SNI extension, so an
    // ordinary DoH/DoT resolver keeps hickory's own defaults.
    if plan.endpoint.is_tls() {
        let needs_custom = plan.ech.is_some() || !plan.enable_sni;
        if needs_custom {
            let root_store = plan
                .ech
                .as_ref()
                .map(|e| e.root_store.clone())
                .unwrap_or_else(|| Arc::new(ech::webpki_root_store()));
            let mode = match (&plan.ech, ech_bytes.as_deref()) {
                (Some(_), Some(b)) => ResolverEch::Config(b),
                // ECH opted into but nothing published, and `require_ech` is
                // false (a true value returned above): GREASE keeps the
                // handshake shaped like an ECH one without asserting anything.
                (Some(_), None) => ResolverEch::Grease,
                (None, _) => ResolverEch::Disabled,
            };
            let tls = ech::resolver_client_config(mode, plan.enable_sni, &root_store)
                .with_context(|| format!("[resolvers.{}]: building the TLS config", plan.label))?;
            // ALPN is deliberately left empty: hickory sets `h2` itself for DoH
            // when the injected config does not specify one, so leaving it unset
            // keeps that behaviour correct for both transports.
            builder = builder.with_tls_config(tls);
        }
    }

    let resolver = builder
        .build()
        .with_context(|| format!("[resolvers.{}]: building the resolver", plan.label))?;

    debug!(
        resolver = %plan.label,
        kind = plan.endpoint.kind(),
        dial = ?dial_ip.map(|ip| SocketAddr::new(ip, plan.dial_port)),
        server_name = ?plan.server_name,
        ech = ech_bytes.is_some(),
        "built resolver"
    );

    Ok(Built {
        resolver: Arc::new(resolver),
        ech_bytes,
    })
}

/// Spawn the proactive ECH rotation timer.
///
/// Every `refresh` this re-runs the plan and compares the published
/// ECHConfigList against the one in use **by raw bytes**, swapping only on a
/// real change. That is what keeps the steady state cheap: one HTTPS lookup per
/// interval, and no reconnect at all while the keys hold still.
///
/// The task holds only a `Weak` reference, so it stops on its own if the
/// resolver is ever dropped instead of keeping it alive forever.
pub fn spawn_ech_refresher(handle: &Arc<DnsResolver>, refresh: Duration) {
    // A zero or absurdly small interval would spin; clamp to something sane.
    let period = refresh.max(Duration::from_secs(5));
    let weak = Arc::downgrade(handle);
    let label = handle.label().to_string();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        // The first tick fires immediately; skip it, since the resolver was just
        // built from a fresh config.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(resolver) = weak.upgrade() else {
                debug!(resolver = %label, "resolver dropped; stopping ECH refresher");
                return;
            };
            let seen = resolver.generation();
            resolver.rebuild(seen, RebuildCause::Rotation).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SniPolicy;

    #[test]
    fn parses_system() {
        assert_eq!(Endpoint::parse("system").unwrap(), Endpoint::System);
        assert_eq!(Endpoint::parse("SYSTEM").unwrap(), Endpoint::System);
        assert_eq!(Endpoint::parse("").unwrap(), Endpoint::System);
        assert_eq!(Endpoint::parse("  ").unwrap(), Endpoint::System);
    }

    /// The core of the feature: a DoH host is kept verbatim, never resolved at
    /// parse time. If this ever regressed to doing I/O, a blocked endpoint would
    /// become unbuildable again.
    #[test]
    fn doh_host_is_kept_verbatim_and_not_resolved() {
        let e = Endpoint::parse("https://dns.cloudflare.com/dns-query").unwrap();
        assert_eq!(
            e,
            Endpoint::Doh {
                host: "dns.cloudflare.com".into(),
                port: 443,
                path: "/dns-query".into(),
            }
        );
        assert_eq!(e.host(), Some("dns.cloudflare.com"));
        assert!(e.is_tls());
    }

    /// A name that cannot resolve anywhere must still parse: resolving it is the
    /// bootstrap's job, later.
    #[test]
    fn unresolvable_doh_host_still_parses() {
        let e = Endpoint::parse("https://blocked.invalid/dns-query").unwrap();
        assert_eq!(e.host(), Some("blocked.invalid"));
    }

    #[test]
    fn doh_default_path_and_explicit_port() {
        assert_eq!(
            Endpoint::parse("https://example.test").unwrap(),
            Endpoint::Doh {
                host: "example.test".into(),
                port: 443,
                path: "/dns-query".into(),
            }
        );
        assert_eq!(
            Endpoint::parse("https://example.test:8443/query").unwrap(),
            Endpoint::Doh {
                host: "example.test".into(),
                port: 8443,
                path: "/query".into(),
            }
        );
    }

    #[test]
    fn parses_dot_with_default_and_explicit_port() {
        assert_eq!(
            Endpoint::parse("tls://one.one.one.one").unwrap(),
            Endpoint::Dot {
                host: "one.one.one.one".into(),
                port: 853,
            }
        );
        assert_eq!(
            Endpoint::parse("tls://dot.test:8853").unwrap(),
            Endpoint::Dot {
                host: "dot.test".into(),
                port: 8853,
            }
        );
    }

    #[test]
    fn parses_plain_forms() {
        let expect = |target: &str, port: u16| Endpoint::Plain {
            target: target.to_string(),
            port,
        };
        assert_eq!(Endpoint::parse("1.1.1.1").unwrap(), expect("1.1.1.1", 53));
        assert_eq!(
            Endpoint::parse("udp://8.8.8.8:5353").unwrap(),
            expect("8.8.8.8", 5353)
        );
        assert_eq!(
            Endpoint::parse("tcp://9.9.9.9").unwrap(),
            expect("9.9.9.9", 53)
        );
        assert_eq!(
            Endpoint::parse("[2606:4700:4700::1111]:5353").unwrap(),
            expect("2606:4700:4700::1111", 5353)
        );
        // Plain DNS endpoints can now have hostnames too
        assert_eq!(
            Endpoint::parse("udp://dns.example:5353").unwrap(),
            expect("dns.example", 5353)
        );
        // For IP endpoints, host() returns None
        let e = Endpoint::parse("1.1.1.1").unwrap();
        assert_eq!(e.host(), None);
        assert!(!e.is_tls());
        // For hostname endpoints, host() returns the hostname
        let e = Endpoint::parse("udp://dns.example:53").unwrap();
        assert_eq!(e.host(), Some("dns.example"));
    }

    /// Named resolver references use `@` prefix to maintain symmetry with named
    /// regex references. A bare word without `@` is never a reference.
    #[test]
    fn bare_word_is_not_an_endpoint_or_reference() {
        for s in ["cf-doh", "boot", "my-resolver", "not-an-ip"] {
            assert!(
                Endpoint::parse(s).is_err(),
                "{s:?} must not parse as an endpoint"
            );
            assert!(
                !crate::config::Config::is_resolver_ref(s),
                "{s:?} without @ prefix must not be a resolver reference"
            );
        }

        // With @ prefix, they are references
        for s in ["@cf-doh", "@boot", "@my-resolver"] {
            assert!(
                crate::config::Config::is_resolver_ref(s),
                "{s:?} with @ prefix must be a resolver reference"
            );
        }
    }

    #[test]
    fn plain_endpoint_with_prefix_accepts_hostname() {
        // With udp:// or tcp:// prefix, hostnames are allowed
        let e = Endpoint::parse("udp://dns.example.test:5353").unwrap();
        assert_eq!(e.host(), Some("dns.example.test"));

        let e = Endpoint::parse("tcp://resolver.example:53").unwrap();
        assert_eq!(e.host(), Some("resolver.example"));
    }

    #[test]
    fn missing_host_is_rejected() {
        assert!(Endpoint::parse("https:///dns-query").is_err());
        assert!(Endpoint::parse("tls://").is_err());
    }

    /// `upstream` moves the dial target while `override_sni` moves the TLS name;
    /// the two are independent. This asserts the split that
    /// `NameServerConfig::https(ip, server_name, path)` makes expressible.
    #[test]
    fn dial_target_and_tls_name_are_independent() {
        let endpoint = Endpoint::parse("https://dns.blocked.test/dns-query").unwrap();

        // Default: both come from the endpoint.
        let (host, port, name) = plan_targets(&endpoint, None, None);
        assert_eq!((host.as_str(), port), ("dns.blocked.test", 443));
        assert_eq!(name.as_deref(), Some("dns.blocked.test"));

        // `upstream` moves only the dial target.
        let (host, port, name) = plan_targets(&endpoint, Some("cdn.edge.test"), None);
        assert_eq!((host.as_str(), port), ("cdn.edge.test", 443));
        assert_eq!(
            name.as_deref(),
            Some("dns.blocked.test"),
            "overriding the dial target must not move the TLS name"
        );

        // `upstream` may move the port alone, keeping the endpoint's host.
        let (host, port, _) = plan_targets(&endpoint, Some("8443"), None);
        assert_eq!((host.as_str(), port), ("dns.blocked.test", 8443));

        // ...or both.
        let (host, port, _) = plan_targets(&endpoint, Some("cdn.edge.test:8443"), None);
        assert_eq!((host.as_str(), port), ("cdn.edge.test", 8443));

        // `override_sni` moves only the TLS name.
        let (host, _, name) = plan_targets(&endpoint, None, Some("other.test"));
        assert_eq!(host.as_str(), "dns.blocked.test");
        assert_eq!(name.as_deref(), Some("other.test"));
    }

    /// Mirror of the resolution `ResolverPlan` construction performs, so the
    /// dial/name split can be asserted without building a live resolver (which
    /// would need a network).
    fn plan_targets(
        endpoint: &Endpoint,
        upstream: Option<&str>,
        override_sni: Option<&str>,
    ) -> (String, u16, Option<String>) {
        let endpoint_host = endpoint.host().unwrap_or_default().to_string();
        let (up_host, port) =
            crate::config::resolved_upstream_from(upstream, endpoint.port()).unwrap();
        let dial_host = up_host.unwrap_or_else(|| endpoint_host.clone());
        let name = match SniPolicy::resolve(override_sni) {
            SniPolicy::Reflect | SniPolicy::Omit => endpoint.host().map(str::to_string),
            SniPolicy::Fixed(n) => Some(n),
        };
        (dial_host, port, name)
    }

    #[test]
    fn omitted_sni_keeps_the_name_for_verification() {
        // `override_sni = ""` suppresses the extension but must keep the name,
        // because the certificate is still verified against it.
        let policy = SniPolicy::resolve(Some(""));
        assert_eq!(policy, SniPolicy::Omit);
        let endpoint = Endpoint::parse("tls://dot.test").unwrap();
        let (_, _, name) = plan_targets(&endpoint, None, Some(""));
        assert_eq!(name.as_deref(), Some("dot.test"));
    }
}
