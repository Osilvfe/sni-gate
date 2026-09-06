//! Adaptive upstream endpoint selection.
//!
//! A pool is a named set of upstream endpoints with background health probing
//! and adaptive selection. It solves one problem: when several candidates serve
//! the same role, send traffic to the best one and fail over when it degrades.
//!
//! # Targets and candidates
//!
//! The two layers are distinct throughout this module, and keeping them apart is
//! what makes every index in the configuration well-defined:
//!
//! * A **target** is one `targets` entry. It has a stable index, and that index
//!   is the only addressing unit in the config: `fallback`, `nat64.from` and
//!   `select` all name targets.
//! * A **candidate** is one probed endpoint — an address. One target yields many:
//!   a domain yields one per A/AAAA record, a CIDR one per sampled address, and
//!   the NAT64 projection adds one per (IPv4 candidate × prefix).
//!
//! Tags live on candidates, because that is where they are *knowable*: whether a
//! domain contributes an `ipv4` or an `ipv6` endpoint is a fact about its DNS
//! answer, not about the line the operator wrote. This is why no load-time rule
//! can require that an index "references an `ipv4` candidate" — at load time
//! there are no candidates. Indices are bounds-checked at load; tag mismatches
//! are reported at runtime, where they are first observable.
//!
//! # What is measured, and on which port
//!
//! The probe measures *link quality to an edge node*: `sni` and `port` belong to
//! the pool, not to any consuming route. A pool referenced by twenty routes with
//! twenty different names is still one ranking of one set of edges. A consumer
//! then applies its own port to the address the pool selected, which is why
//! `@pool:8443` needs no separate pool.
//!
//! # Where the work happens
//!
//! One task per pool does all of it: re-resolving domain targets, probing due
//! candidates, and recomputing the ranking. The data path only reads a snapshot
//! — see [`Pool::pick`]. Nothing on the data path can trigger a probe, so a burst
//! of traffic cannot turn into a burst of probes.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::config::{AddressFamily, EffectiveProbe, PoolDef, ProbeMode, Selector, TargetDef};
use crate::dns_resolvers::DnsResolver;
use crate::nat64::Nat64Prefix;

/// The tag vocabulary. These three strings are the *only* automatic tags, and
/// they are also what `address_family` uses, so an operator learns one set of
/// words. No abbreviations, no alternative spellings.
const TAG_IPV4: &str = "ipv4";
const TAG_IPV6: &str = "ipv6";
const TAG_NAT64: &str = "nat64";

/// Hard cap on candidates produced by expanding one CIDR target without an
/// explicit `[N]` sample count.
///
/// A `/12` holds a million addresses; expanding it would probe forever and
/// allocate accordingly. A documented warning cannot prevent that, so the limit
/// is enforced at load time with an error naming the fix.
const MAX_CIDR_EXPANSION: usize = 64;

/// Upper bound on concurrent probes within one pool, so a large pool cannot open
/// hundreds of sockets in one cycle.
const MAX_CONCURRENT_PROBES: usize = 16;

/// Weight of a new sample in the RTT moving average.
///
/// An exponentially-weighted average rather than the last measurement: a single
/// unlucky sample must not hand the top of the ranking to a worse endpoint, and a
/// genuinely faster endpoint should still take it within a few cycles. This
/// replaces the "wait N successful probes before ranking" rule it supersedes —
/// smoothing the value is what that rule was reaching for, and it costs no
/// startup delay.
const RTT_EWMA_ALPHA: f64 = 0.3;

/// Relative margin a challenger must beat the incumbent by to overtake it.
const HYSTERESIS_FRACTION: u32 = 5; // 1/5 == 20%

/// Absolute floor on that margin, for endpoints that are all fast.
const HYSTERESIS_FLOOR: Duration = Duration::from_millis(5);

// ---------------------------------------------------------------------------
// Target specifications
// ---------------------------------------------------------------------------

/// A parsed `targets` entry: what kind of endpoint source it is.
///
/// The kind is inferred from the string so the common case stays one token.
/// Checked at config load, so a malformed target is a startup error rather than a
/// pool that silently contributes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    /// A DNS name, re-resolved on every probe cycle.
    Domain(String),
    /// A literal address.
    Ip(IpAddr),
    /// A network, sampled or fully expanded.
    Cidr { net: IpNet, sample: Option<usize> },
}

impl TargetSpec {
    /// Parse one target address specification.
    ///
    /// Inference order matters: `/` marks a CIDR before anything else, because
    /// `10.0.0.0/8` also "contains no colon" and would otherwise read as a
    /// hostname. Then a successful IP parse, then a domain.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            bail!("empty target");
        }

        // Optional `[N]` sampling suffix, only meaningful on a CIDR.
        let (body, sample) = match s.strip_suffix(']') {
            Some(head) => match head.rsplit_once('[') {
                Some((base, n)) => {
                    let n: usize = n.trim().parse().with_context(|| {
                        format!("sample count in {s:?} must be a positive integer")
                    })?;
                    if n == 0 {
                        bail!("sample count in {s:?} must be at least 1");
                    }
                    (base.trim(), Some(n))
                }
                None => bail!("unmatched ']' in target {s:?}"),
            },
            None => (s, None),
        };

        if body.contains('/') {
            let net: IpNet = body
                .parse()
                .with_context(|| format!("target {s:?} is not a valid CIDR"))?;
            if sample.is_none() {
                let size = network_size(&net);
                if size > MAX_CIDR_EXPANSION as u128 {
                    bail!(
                        "target {s:?} expands to {size} addresses, over the limit of \
                         {MAX_CIDR_EXPANSION}; append a sample count, e.g. \"{body}[4]\""
                    );
                }
            }
            return Ok(TargetSpec::Cidr { net, sample });
        }

        if sample.is_some() {
            bail!("sample count in {s:?} only applies to a CIDR target");
        }

        if let Ok(ip) = body.parse::<IpAddr>() {
            return Ok(TargetSpec::Ip(ip));
        }

        // A domain. Reject the shapes that indicate a mistyped address rather
        // than a name, so they fail at load instead of as an NXDOMAIN later.
        if body.contains(':') {
            bail!(
                "target {s:?} looks like an IPv6 address but does not parse as one \
                 (a domain target must not contain ':')"
            );
        }
        Ok(TargetSpec::Domain(body.to_string()))
    }
}

/// Number of addresses in a network, saturating for very large IPv6 prefixes.
fn network_size(net: &IpNet) -> u128 {
    let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
    if host_bits >= 128 {
        u128::MAX
    } else {
        1u128 << host_bits
    }
}

/// A target after load-time parsing, with CIDR sampling already drawn.
///
/// Samples are drawn once, at startup, rather than per cycle: re-drawing would
/// discard every RTT measurement each cycle and make the ranking meaningless. A
/// sampled address that turns out to be dead is instead replaced through the
/// normal degradation path (see [`PoolState::resample_dead`]).
struct Target {
    /// Index in the config's `targets` array. The addressing unit for
    /// `select`, `fallback` and `nat64.from`.
    index: usize,
    spec: TargetSpec,
    /// Operator-supplied tags, appended to the automatic ones.
    custom_tags: Arc<[String]>,
    /// For a CIDR: the addresses drawn from it. Empty for other kinds.
    sampled: Vec<IpAddr>,
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

/// One probed endpoint.
#[derive(Debug, Clone)]
struct Candidate {
    addr: IpAddr,
    /// Which target produced it.
    target: usize,
    /// Automatic tags plus the target's custom ones.
    tags: Vec<String>,
}

impl Candidate {
    fn matches(&self, sel: &[Selector]) -> bool {
        // An empty selector list is "no filter": written explicitly, it widens a
        // template's filter back to everything.
        if sel.is_empty() {
            return true;
        }
        sel.iter().any(|s| match s {
            Selector::Index(i) => *i == self.target,
            Selector::Tag(t) => self.tags.iter().any(|own| own == t),
        })
    }
}

/// Health of one endpoint, keyed by address so it survives a candidate-set
/// change (a domain's records rotating, a dead sample being replaced).
#[derive(Debug, Clone)]
struct Health {
    /// Smoothed round-trip time. `None` until the first success.
    rtt: Option<Duration>,
    consecutive_failures: u32,
    degraded: bool,
    /// When this endpoint is next due. Per-candidate, which is what lets a
    /// permanently dead endpoint back off without slowing the whole pool.
    next_probe: Instant,
    /// Current backoff delay, doubling on each failure up to `interval`.
    backoff: Duration,
}

impl Health {
    fn new(due: Instant, backoff: Duration) -> Self {
        Self {
            rtt: None,
            consecutive_failures: 0,
            degraded: false,
            next_probe: due,
            backoff,
        }
    }

    fn record_success(&mut self, sample: Duration, interval: Duration, base_backoff: Duration) {
        self.rtt = Some(match self.rtt {
            None => sample,
            Some(prev) => ewma(prev, sample),
        });
        self.consecutive_failures = 0;
        self.degraded = false;
        self.backoff = base_backoff;
        self.next_probe = Instant::now() + interval;
    }

    fn record_failure(&mut self, threshold: u32, interval: Duration, base_backoff: Duration) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let newly_degraded = !self.degraded && self.consecutive_failures >= threshold;
        if newly_degraded {
            self.degraded = true;
            self.backoff = base_backoff;
        } else if self.degraded {
            // Exponential backoff, capped at the healthy interval: a dead
            // endpoint settles at the same cost as a live one instead of
            // probing forever at the fast rate.
            self.backoff = (self.backoff * 2).min(interval);
        }
        // A candidate below the threshold retries at the base delay: it may be a
        // single dropped packet, and waiting a full interval to find out would
        // leave a healthy endpoint out of the ranking for minutes.
        let delay = if self.degraded {
            self.backoff
        } else {
            base_backoff
        };
        self.next_probe = Instant::now() + delay;
    }
}

/// Blend a new RTT sample into the running average.
fn ewma(prev: Duration, sample: Duration) -> Duration {
    let prev_ns = prev.as_nanos() as f64;
    let new_ns = sample.as_nanos() as f64;
    Duration::from_nanos((prev_ns * (1.0 - RTT_EWMA_ALPHA) + new_ns * RTT_EWMA_ALPHA) as u64)
}

// ---------------------------------------------------------------------------
// Views and the published ranking
// ---------------------------------------------------------------------------

/// One consumer's registered candidate filter.
///
/// Views are registered while routes are built, so by the time traffic arrives
/// the probe task already knows every filter that will ever be asked about and
/// publishes a finished, ordered list for each. That is what keeps `select`
/// evaluation off the data path entirely: it is not evaluated per connection, it
/// is evaluated per probe cycle.
struct View {
    selectors: Vec<Selector>,
}

/// A finished, ordered answer for one view.
struct ViewRanking {
    /// Healthy addresses, best first.
    ordered: Vec<IpAddr>,
    /// The safety net, used only while `ordered` is empty.
    fallback: Option<IpAddr>,
}

/// The published snapshot the data path reads. Replaced wholesale by the probe
/// task; never mutated in place.
struct Ranking {
    per_view: Vec<ViewRanking>,
}

impl Ranking {
    /// An empty ranking, published before the first probe cycle completes so the
    /// data path always has something well-formed to read.
    fn empty(views: usize) -> Self {
        Self {
            per_view: (0..views)
                .map(|_| ViewRanking {
                    ordered: Vec::new(),
                    fallback: None,
                })
                .collect(),
        }
    }
}

/// A route's handle on a pool: the pool plus which registered view it reads.
///
/// Cloneable and cheap; one per route that references the pool.
pub struct PoolHandle {
    pool: Arc<Pool>,
    view: usize,
}

impl PoolHandle {
    /// The pool's declared name, for diagnostics.
    pub fn name(&self) -> &str {
        &self.pool.name
    }

    /// The address to dial right now, on `port`.
    ///
    /// Zero I/O, zero allocation, and no evaluation of `select`: one lock-free
    /// read of a published snapshot and an index into it. The probe task writes;
    /// this only reads.
    pub fn pick(&self, port: u16) -> Result<SocketAddr> {
        self.pool.pick(self.view, port)
    }
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// Everything a pool needs at runtime, plus its published ranking.
pub struct Pool {
    name: String,
    targets: Vec<Target>,
    probe: EffectiveProbe,
    /// NAT64 projection, if configured.
    nat64: Option<Nat64Projection>,
    /// Index into `targets` for the fallback, if configured.
    fallback: Option<usize>,
    resolver: Arc<DnsResolver>,
    views: Vec<View>,
    /// TLS config for `tls` / `http` probes. Built once.
    tls: Option<Arc<ClientConfig>>,
    /// The current answer for every view.
    ///
    /// `RwLock<Arc<_>>` and never a lock held across work: a reader clones the
    /// `Arc` out and releases the lock immediately, so publishing a new ranking
    /// never blocks the data path and a reader in flight keeps using the snapshot
    /// it started with. Same shape as [`crate::dns_resolvers::DnsResolver`].
    ranking: RwLock<Arc<Ranking>>,
}

/// NAT64 projection parameters, resolved at build.
struct Nat64Projection {
    prefixes: Vec<Nat64Prefix>,
    /// Target indices whose IPv4 candidates participate; `None` = all.
    from: Option<Vec<usize>>,
    timeout: Duration,
}

impl Pool {
    /// The view id matching `selectors`, registered during the build pass.
    ///
    /// Views are registered before any pool is spawned, so this is a lookup and
    /// never a mutation: by the time routes are built, every filter that will
    /// ever be asked about is already published.
    pub fn view_for(&self, selectors: Option<&[Selector]>) -> Option<usize> {
        let wanted = selectors.unwrap_or(&[]);
        self.views.iter().position(|v| v.selectors == wanted)
    }

    /// The address to dial for `view`, on `port`.
    fn pick(&self, view: usize, port: u16) -> Result<SocketAddr> {
        let snapshot = {
            let guard = self.ranking.read().expect("pool ranking lock poisoned");
            guard.clone()
        };
        let vr = snapshot
            .per_view
            .get(view)
            .ok_or_else(|| anyhow!("pool {}: unregistered view {view}", self.name))?;

        if let Some(ip) = vr.ordered.first() {
            return Ok(SocketAddr::new(*ip, port));
        }
        if let Some(ip) = vr.fallback {
            return Ok(SocketAddr::new(ip, port));
        }
        // No healthy candidate and no usable fallback. An error rather than a
        // guess: the route's own fail policy is the right place to decide what
        // happens to the connection.
        Err(anyhow!(
            "pool {}: no healthy candidate and no usable fallback",
            self.name
        ))
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// A pool under construction, collecting the views its consumers need.
///
/// Two-phase on purpose: routes are built before anything is spawned, so every
/// `select` is known by the time the probe task starts and no view has to be
/// registered against a running pool.
pub struct PoolBuilder {
    name: String,
    def: PoolDef,
    targets: Vec<Target>,
    probe: EffectiveProbe,
    resolver: Arc<DnsResolver>,
    root_store: Arc<RootCertStore>,
    views: Vec<View>,
}

impl PoolBuilder {
    /// Parse and prepare one pool definition. Draws CIDR samples; performs no
    /// I/O and starts nothing.
    pub fn new(
        name: &str,
        def: &PoolDef,
        resolver: Arc<DnsResolver>,
        root_store: Arc<RootCertStore>,
    ) -> Result<Self> {
        let mut targets = Vec::with_capacity(def.targets.len());
        for (index, t) in def.targets.iter().enumerate() {
            let spec = TargetSpec::parse(t.addr())
                .with_context(|| format!("[pools.{name}]: targets[{index}]"))?;
            let sampled = match &spec {
                TargetSpec::Cidr { net, sample } => draw_sample(net, *sample),
                _ => Vec::new(),
            };
            targets.push(Target {
                index,
                spec,
                custom_tags: tags_of(t),
                sampled,
            });
        }

        Ok(Self {
            name: name.to_string(),
            def: def.clone(),
            targets,
            probe: def.probe.effective(),
            resolver,
            root_store,
            views: Vec::new(),
        })
    }

    /// Register a consumer's filter, returning the view id it should read.
    ///
    /// Identical filters share a view: many routes usually want the same subset,
    /// and one ordered list per distinct filter is all the probe task should have
    /// to compute.
    pub fn register_view(&mut self, selectors: Option<&[Selector]>) -> usize {
        let selectors: Vec<Selector> = selectors.unwrap_or(&[]).to_vec();
        if let Some(existing) = self.views.iter().position(|v| v.selectors == selectors) {
            return existing;
        }
        self.views.push(View { selectors });
        self.views.len() - 1
    }

    /// Whether any route actually reads this pool.
    pub fn is_used(&self) -> bool {
        !self.views.is_empty()
    }

    /// Finish the pool and spawn its probe task.
    pub fn spawn(self) -> Result<Arc<Pool>> {
        let nat64 =
            match &self.def.nat64 {
                None => None,
                Some(n) => {
                    let mut prefixes = Vec::with_capacity(n.prefixes.len());
                    for p in &n.prefixes {
                        prefixes.push(p.parse::<Nat64Prefix>().with_context(|| {
                            format!("[pools.{}.nat64]: prefix {p:?}", self.name)
                        })?);
                    }
                    Some(Nat64Projection {
                        prefixes,
                        from: n.from.clone(),
                        timeout: n.timeout.unwrap_or(self.probe.timeout),
                    })
                }
            };

        let tls = match self.probe.mode {
            ProbeMode::Tcp => None,
            ProbeMode::Tls | ProbeMode::Http => {
                let mut cfg = ClientConfig::builder()
                    .with_root_certificates(self.root_store.as_ref().clone())
                    .with_no_client_auth();
                // A probe measures reachability and latency, not content, so it
                // has no protocol to negotiate.
                cfg.alpn_protocols.clear();
                Some(Arc::new(cfg))
            }
        };

        let view_count = self.views.len();
        let pool = Arc::new(Pool {
            name: self.name,
            targets: self.targets,
            probe: self.probe,
            nat64,
            fallback: self.def.fallback,
            resolver: self.resolver,
            views: self.views,
            tls,
            ranking: RwLock::new(Arc::new(Ranking::empty(view_count))),
        });

        // The task holds only a `Weak`, so it stops on its own if the pool is
        // dropped rather than keeping it alive forever. Same pattern as the ECH
        // refresher in `dns_resolvers`, and the reason no cancellation-token
        // plumbing is needed to shut a pool down.
        let weak = Arc::downgrade(&pool);
        tokio::spawn(async move { run_probe_loop(weak).await });

        Ok(pool)
    }

    /// A handle for one consumer, reading `view`.
    pub fn handle(pool: Arc<Pool>, view: usize) -> PoolHandle {
        PoolHandle { pool, view }
    }
}

/// Automatic-plus-custom tags for a target definition. Automatic tags are added
/// per candidate (they depend on the resolved address family), so this carries
/// only the operator's own.
fn tags_of(t: &TargetDef) -> Arc<[String]> {
    t.tags()
        .iter()
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>()
        .into()
}

/// Draw `sample` random addresses from `net`, or expand it fully when no sample
/// count was given.
///
/// Sampling avoids materializing a large range and is what makes a `/12` usable
/// as a target at all. Duplicates are avoided where the range allows it.
fn draw_sample(net: &IpNet, sample: Option<usize>) -> Vec<IpAddr> {
    let size = network_size(net);
    let Some(want) = sample else {
        // Full expansion; the load-time check already bounded the size.
        return net.hosts().take(MAX_CIDR_EXPANSION).collect();
    };

    let want = (want as u128).min(size) as usize;
    let mut out = Vec::with_capacity(want);
    let mut seen: HashSet<IpAddr> = HashSet::with_capacity(want);
    // Bounded attempts: with `want` close to `size` the last few draws collide
    // often, and an unbounded loop would spin. Falling short is harmless — the
    // pool simply has fewer candidates.
    let mut attempts = 0usize;
    let max_attempts = want.saturating_mul(8).max(16);
    while out.len() < want && attempts < max_attempts {
        attempts += 1;
        let offset = rand::random_range(0..size);
        let addr = offset_into(net, offset);
        if seen.insert(addr) {
            out.push(addr);
        }
    }
    out
}

/// The address at `offset` within `net`.
fn offset_into(net: &IpNet, offset: u128) -> IpAddr {
    match net {
        IpNet::V4(n) => {
            let base = u32::from(n.network());
            IpAddr::V4(Ipv4Addr::from(base.wrapping_add(offset as u32)))
        }
        IpNet::V6(n) => {
            let base = u128::from(n.network());
            IpAddr::V6(Ipv6Addr::from(base.wrapping_add(offset)))
        }
    }
}

// ---------------------------------------------------------------------------
// The probe loop
// ---------------------------------------------------------------------------

/// Mutable state owned solely by the probe task.
struct PoolState {
    /// Health per address, surviving candidate-set changes.
    health: HashMap<IpAddr, Health>,
    /// The previous global order, used to apply hysteresis.
    order: Vec<IpAddr>,
    /// Addresses replaced because they never came up, so a dead CIDR sample is
    /// not retried forever.
    resampled: HashSet<IpAddr>,
    /// Extra addresses drawn to replace dead samples, per target index.
    replacements: HashMap<usize, Vec<IpAddr>>,
    /// Last DNS answer per domain target index, and when it was obtained.
    ///
    /// Cached rather than re-queried each pass because the loop wakes on the
    /// *earliest due candidate*, not on `interval`. A single candidate backing off
    /// at `degraded_interval` would otherwise drag every domain target through a
    /// fresh lookup at that cadence — DNS load rising precisely when part of the
    /// pool is already unhealthy. Refreshed on `interval`, which is the cadence
    /// the operator asked for.
    resolved: HashMap<usize, Vec<IpAddr>>,
    /// When `resolved` was last refreshed. `None` before the first resolution.
    resolved_at: Option<Instant>,
}

async fn run_probe_loop(weak: Weak<Pool>) {
    let mut state = PoolState::new();

    // Small startup jitter so several pools starting together do not fire their
    // first cycle in the same instant. This delays the first fallback publish by
    // under half a second, which is immaterial next to a probe cycle.
    let jitter = Duration::from_millis(rand::random_range(0..400));
    tokio::time::sleep(jitter).await;

    loop {
        let Some(pool) = weak.upgrade() else {
            debug!("pool dropped; stopping probe loop");
            return;
        };

        let candidates = build_candidates(&pool, &mut state).await;

        // Publish *before* probing, so the fallback is usable during the first
        // cycle rather than only after it.
        //
        // This is load-bearing, not an optimization. A cycle takes as long as its
        // candidates need: a few hundred sampled addresses probed with `mode =
        // "http"` at the concurrency cap can run for a minute or more. Without
        // this, `pick` returns an error for that whole window — and on a
        // `tls`/`ech` route with HTTP/2 enabled the upstream is dialed *before*
        // the inbound handshake completes, so the failure surfaces to the client
        // as a broken TLS handshake rather than as an upstream error. A pool that
        // declares a fallback must honour it from the first connection.
        //
        // Nothing is ranked yet at this point, so this publishes fallback only;
        // on later cycles it republishes the previous order, which is still the
        // best answer available until this cycle finishes.
        publish(&pool, &state, &candidates);

        run_cycle(&pool, &mut state, &candidates).await;
        recompute_order(&mut state, &candidates);
        publish(&pool, &state, &candidates);
        log_cycle(&pool, &state, &candidates);

        // Sleep until the next scheduled work. Holding no `Arc` across the sleep
        // is what lets the pool actually be dropped while idle.
        let sleep_for = next_due(&pool, &state, &candidates);
        drop(pool);
        tokio::time::sleep(sleep_for).await;
    }
}

/// How long to wait before re-resolving domain targets.
///
/// `interval` once every domain target has an answer, but `degraded_interval`
/// while any of them has none. Without that distinction a failed *first*
/// resolution would be retried only after a full `interval` — five minutes, by
/// default, during which a pool whose only target is a domain has no candidates
/// and serves nothing. The fast path is for acquiring an answer, not for
/// refreshing one.
fn dns_refresh(pool: &Pool, state: &PoolState) -> Duration {
    let missing = pool
        .targets
        .iter()
        .filter(|t| matches!(t.spec, TargetSpec::Domain(_)))
        .any(|t| !state.resolved.contains_key(&t.index));
    if missing {
        pool.probe.degraded_interval
    } else {
        pool.probe.interval
    }
}

/// How long until this pool next has work: the earliest due candidate, or the
/// next domain re-resolution, whichever comes first.
///
/// The DNS deadline has to be part of this. A pool whose only target is a domain
/// that has not resolved yet has *no candidates*, so a candidate-only calculation
/// would sleep for a full `interval` and strand the pool for five minutes — which
/// is exactly the case the faster first-resolution retry exists to cover.
fn next_due(pool: &Pool, state: &PoolState, candidates: &[Candidate]) -> Duration {
    let now = Instant::now();
    let soonest_probe = candidates
        .iter()
        .filter_map(|c| state.health.get(&c.addr))
        .map(|h| h.next_probe.saturating_duration_since(now))
        .min();
    let dns_deadline = match state.resolved_at {
        None => Duration::ZERO,
        Some(at) => dns_refresh(pool, state).saturating_sub(at.elapsed()),
    };
    // Only domain targets need re-resolution; a pool of literals and CIDRs has no
    // DNS deadline to honour at all.
    let has_domain = pool
        .targets
        .iter()
        .any(|t| matches!(t.spec, TargetSpec::Domain(_)));

    let wait = match (soonest_probe, has_domain) {
        (Some(p), true) => p.min(dns_deadline),
        (Some(p), false) => p,
        (None, true) => dns_deadline,
        // No candidates and nothing to resolve: every target is a literal or a
        // CIDR whose samples were all retired. Re-check on the healthy interval
        // rather than spinning.
        (None, false) => pool.probe.interval,
    };
    // Never busy-loop, even when several deadlines are already past.
    wait.max(Duration::from_millis(50))
}

/// Expand every target into candidates, re-resolving domains and applying the
/// NAT64 projection.
async fn build_candidates(pool: &Arc<Pool>, state: &mut PoolState) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();

    // Domain targets are re-resolved on `interval`, not on every pass. The loop
    // wakes on the earliest *due candidate*, which can be far more often than
    // `interval` while anything is backing off — and DNS load must not rise just
    // because part of the pool is unhealthy.
    let dns_due = match state.resolved_at {
        None => true,
        Some(at) => at.elapsed() >= dns_refresh(pool, state),
    };
    if dns_due {
        state.resolved_at = Some(Instant::now());
    }

    for target in &pool.targets {
        match &target.spec {
            TargetSpec::Ip(ip) => push_candidate(&mut out, target, *ip),
            TargetSpec::Cidr { .. } => {
                for ip in &target.sampled {
                    if !state.resampled.contains(ip) {
                        push_candidate(&mut out, target, *ip);
                    }
                }
                for ip in state.replacements.get(&target.index).into_iter().flatten() {
                    push_candidate(&mut out, target, *ip);
                }
            }
            TargetSpec::Domain(name) => {
                if dns_due {
                    // Every address, both families. `Dual` rather than two
                    // separate lookups because which family a pool should use is
                    // the *consumer's* decision, expressed with `select` — so the
                    // pool gathers everything the name publishes and tags each
                    // candidate.
                    //
                    // And every address, not just the first: a name fronting
                    // several edges is the ordinary case for the CDNs pools exist
                    // to rank, and taking one record would silently discard the
                    // alternatives this whole module is for.
                    match pool.resolver.resolve_all(name, AddressFamily::Dual).await {
                        Ok(ips) => {
                            state.resolved.insert(target.index, ips);
                        }
                        // Keep the previous answer: a working-but-stale address
                        // list beats none, since the endpoints behind it are still
                        // measured and probably still up. Same reasoning the
                        // resolver rebuild path uses on a failed refresh.
                        Err(e) => warn!(
                            pool = %pool.name,
                            target = target.index,
                            domain = %name,
                            error = %format!("{e:#}"),
                            cached = state.resolved.contains_key(&target.index),
                            "pool target did not resolve; keeping the previous addresses"
                        ),
                    }
                }
                for ip in state.resolved.get(&target.index).into_iter().flatten() {
                    push_candidate(&mut out, target, *ip);
                }
            }
        }
    }

    // NAT64 projection: for each participating IPv4 candidate × prefix, one
    // synthesized IPv6 candidate. Ranked independently of its original, because
    // a slow NAT64 gateway says nothing about the native IPv4 path.
    if let Some(n) = &pool.nat64 {
        let mut synthesized: Vec<Candidate> = Vec::new();
        for c in &out {
            let IpAddr::V4(v4) = c.addr else { continue };
            let participates = match &n.from {
                None => true,
                Some(list) => list.contains(&c.target),
            };
            if !participates {
                continue;
            }
            for prefix in &n.prefixes {
                let addr = IpAddr::V6(prefix.synthesize(v4));
                let mut tags = vec![TAG_NAT64.to_string(), TAG_IPV6.to_string()];
                // Custom tags follow the target, so a `select` on a custom tag
                // reaches the projection of that target too.
                for t in pool.targets[c.target].custom_tags.iter() {
                    tags.push(t.clone());
                }
                synthesized.push(Candidate {
                    addr,
                    target: c.target,
                    tags,
                });
            }
        }
        out.extend(synthesized);
    }

    // `from` naming a target that yields no IPv4 is not an error — a domain's
    // records can change — but it is worth saying once per cycle.
    if let Some(n) = &pool.nat64 {
        for i in n.from.iter().flatten() {
            let has_v4 = out
                .iter()
                .any(|c| c.target == *i && matches!(c.addr, IpAddr::V4(_)));
            if !has_v4 {
                warn!(
                    pool = %pool.name,
                    target = *i,
                    "nat64.from names a target with no IPv4 candidate, so it contributes no \
                     synthesized address"
                );
            }
        }
    }

    // Deduplicate: two targets may legitimately resolve to one address, and
    // probing it twice would double-count it in the ranking.
    let mut seen: HashSet<IpAddr> = HashSet::with_capacity(out.len());
    out.retain(|c| seen.insert(c.addr));

    // Give every new address a health entry, due immediately.
    let now = Instant::now();
    for c in &out {
        state
            .health
            .entry(c.addr)
            .or_insert_with(|| Health::new(now, pool.probe.degraded_interval));
    }
    // Forget addresses that are no longer candidates, so a rotating domain does
    // not grow the map without bound.
    let live: HashSet<IpAddr> = out.iter().map(|c| c.addr).collect();
    state.health.retain(|addr, _| live.contains(addr));

    out
}

fn push_candidate(out: &mut Vec<Candidate>, target: &Target, addr: IpAddr) {
    let mut tags = Vec::with_capacity(target.custom_tags.len() + 1);
    tags.push(
        match addr {
            IpAddr::V4(_) => TAG_IPV4,
            IpAddr::V6(_) => TAG_IPV6,
        }
        .to_string(),
    );
    for t in target.custom_tags.iter() {
        tags.push(t.clone());
    }
    out.push(Candidate {
        addr,
        target: target.index,
        tags,
    });
}

/// Probe every due candidate and fold the results into health.
async fn run_cycle(pool: &Arc<Pool>, state: &mut PoolState, candidates: &[Candidate]) {
    let now = Instant::now();
    let due: Vec<Candidate> = candidates
        .iter()
        .filter(|c| match state.health.get(&c.addr) {
            Some(h) => h.next_probe <= now,
            // A candidate with no health entry yet has never been probed, so it
            // is due immediately.
            None => true,
        })
        .cloned()
        .collect();
    if due.is_empty() {
        return;
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
    let mut set = tokio::task::JoinSet::new();
    for c in due {
        let pool = pool.clone();
        let semaphore = semaphore.clone();
        // A NAT64 path carries an extra hop, so it may have its own bound.
        let is_nat64 = c.tags.iter().any(|t| t == TAG_NAT64);
        let budget = match (&pool.nat64, is_nat64) {
            (Some(n), true) => n.timeout,
            _ => pool.probe.timeout,
        };
        set.spawn(async move {
            let _permit = semaphore.acquire().await;
            let outcome = probe_one(&pool, c.addr, budget).await;
            (c.addr, outcome)
        });
    }

    while let Some(joined) = set.join_next().await {
        let Ok((addr, outcome)) = joined else {
            warn!(pool = %pool.name, "a probe task panicked");
            continue;
        };
        let Some(h) = state.health.get_mut(&addr) else {
            continue;
        };
        match outcome {
            Ok(rtt) => {
                let was_degraded = h.degraded;
                h.record_success(rtt, pool.probe.interval, pool.probe.degraded_interval);
                if was_degraded {
                    info!(
                        pool = %pool.name,
                        candidate = %addr,
                        rtt_ms = rtt.as_millis(),
                        "candidate recovered and re-entered the ranking"
                    );
                }
            }
            Err(e) => {
                let was_degraded = h.degraded;
                h.record_failure(
                    pool.probe.fail_threshold,
                    pool.probe.interval,
                    pool.probe.degraded_interval,
                );
                if !was_degraded && h.degraded {
                    warn!(
                        pool = %pool.name,
                        candidate = %addr,
                        failures = h.consecutive_failures,
                        error = %format!("{e:#}"),
                        "candidate degraded; excluded from the ranking"
                    );
                } else {
                    debug!(
                        pool = %pool.name,
                        candidate = %addr,
                        failures = h.consecutive_failures,
                        error = %format!("{e:#}"),
                        "probe failed"
                    );
                }
            }
        }
    }

    state.resample_dead(pool, candidates);
}

impl PoolState {
    fn new() -> Self {
        Self {
            health: HashMap::new(),
            order: Vec::new(),
            resampled: HashSet::new(),
            replacements: HashMap::new(),
            resolved: HashMap::new(),
            resolved_at: None,
        }
    }

    /// Replace a CIDR sample that has backed off to the cap without ever
    /// succeeding.
    ///
    /// Sampling a `/12` will sometimes draw an address nothing answers on.
    /// Without this the pool would carry that dead weight for the life of the
    /// process; with it, the sample space is eventually explored while measured
    /// endpoints are never discarded.
    fn resample_dead(&mut self, pool: &Arc<Pool>, candidates: &[Candidate]) {
        for c in candidates {
            let Some(h) = self.health.get(&c.addr) else {
                continue;
            };
            // Only ever replace an endpoint that has *never* answered: one that
            // worked before may simply be having an outage, and its measured RTT
            // is worth keeping.
            if !h.degraded || h.rtt.is_some() || h.backoff < pool.probe.interval {
                continue;
            }
            let target = &pool.targets[c.target];
            let TargetSpec::Cidr { net, sample } = &target.spec else {
                continue;
            };
            if sample.is_none() {
                continue; // fully expanded: there is nothing else to draw
            }
            let fresh = draw_sample(net, Some(1));
            let Some(&new_addr) = fresh.first() else {
                continue;
            };
            if self.health.contains_key(&new_addr) || self.resampled.contains(&new_addr) {
                continue;
            }
            info!(
                pool = %pool.name,
                target = c.target,
                dead = %c.addr,
                replacement = %new_addr,
                "replacing a CIDR sample that never answered"
            );
            self.resampled.insert(c.addr);
            self.health.remove(&c.addr);
            self.replacements
                .entry(c.target)
                .or_default()
                .push(new_addr);
            // Drop the replaced address from the recorded order too, so
            // hysteresis does not keep referring to it.
            self.order.retain(|a| *a != c.addr);
        }
    }
}

/// Recompute the preference order and store it back on the state.
///
/// Storing it is what makes hysteresis work at all: the margin is applied
/// relative to the *previous* order, so an order that is recomputed and then
/// discarded leaves every cycle starting from scratch — which is a plain sort, and
/// exactly the churn the margin exists to prevent.
fn recompute_order(state: &mut PoolState, candidates: &[Candidate]) {
    let order = reorder_with_hysteresis(&state.order, state, candidates);
    state.order = order;
}

/// Publish the current order and every view's answer.
fn publish(pool: &Arc<Pool>, state: &PoolState, candidates: &[Candidate]) {
    let order = &state.order;

    let per_view = pool
        .views
        .iter()
        .map(|view| {
            let ordered: Vec<IpAddr> = order
                .iter()
                .filter(|addr| {
                    candidates
                        .iter()
                        .find(|c| c.addr == **addr)
                        .is_some_and(|c| c.matches(&view.selectors))
                })
                .copied()
                .collect();

            // The fallback is drawn from the fallback *target* under this view's
            // own filter, so a `select = ["nat64"]` consumer falls back to a
            // synthesized address rather than to a bare IPv4 its host may have
            // no route to.
            let fallback = pool.fallback.and_then(|t| {
                candidates
                    .iter()
                    .find(|c| c.target == t && c.matches(&view.selectors))
                    .map(|c| c.addr)
            });

            ViewRanking { ordered, fallback }
        })
        .collect();

    *pool.ranking.write().expect("pool ranking lock poisoned") = Arc::new(Ranking { per_view });
}

/// Rebuild the preference order from the previous one, promoting a candidate
/// only when it beats the one ahead of it by a margin.
///
/// Starting from the previous order rather than sorting afresh is what gives
/// stability: two endpoints a millisecond apart would otherwise trade places
/// every cycle, moving traffic between edges for no gain and invalidating the
/// upstream-certificate mirror each time. The margin is applied pairwise, so no
/// pair reorders on noise — not merely the top two.
fn reorder_with_hysteresis(
    prev: &[IpAddr],
    state: &PoolState,
    candidates: &[Candidate],
) -> Vec<IpAddr> {
    let healthy = |addr: &IpAddr| -> Option<Duration> {
        let h = state.health.get(addr)?;
        if h.degraded {
            return None;
        }
        h.rtt
    };
    let live: HashSet<IpAddr> = candidates.iter().map(|c| c.addr).collect();

    // Keep the previous order for endpoints still healthy and still present.
    let mut order: Vec<IpAddr> = prev
        .iter()
        .filter(|a| live.contains(*a) && healthy(a).is_some())
        .copied()
        .collect();

    // Append newcomers, best first, so a new endpoint enters at its measured
    // position rather than at the front.
    let mut fresh: Vec<(IpAddr, Duration)> = candidates
        .iter()
        .filter(|c| !order.contains(&c.addr))
        .filter_map(|c| healthy(&c.addr).map(|rtt| (c.addr, rtt)))
        .collect();
    fresh.sort_by_key(|(_, rtt)| *rtt);
    order.extend(fresh.into_iter().map(|(a, _)| a));

    // Insertion pass with a threshold: move each entry forward only while it
    // beats its predecessor by the margin.
    for i in 1..order.len() {
        let mut j = i;
        while j > 0 {
            let Some(cur) = healthy(&order[j]) else { break };
            let Some(ahead) = healthy(&order[j - 1]) else {
                break;
            };
            if beats(cur, ahead) {
                order.swap(j, j - 1);
                j -= 1;
            } else {
                break;
            }
        }
    }
    order
}

/// Whether `challenger` is enough faster than `incumbent` to overtake it.
fn beats(challenger: Duration, incumbent: Duration) -> bool {
    let margin = (incumbent / HYSTERESIS_FRACTION).max(HYSTERESIS_FLOOR);
    challenger + margin < incumbent
}

fn log_cycle(pool: &Arc<Pool>, state: &PoolState, candidates: &[Candidate]) {
    let total = candidates.len();
    let healthy = candidates
        .iter()
        .filter(|c| state.health.get(&c.addr).is_some_and(|h| !h.degraded))
        .count();
    let snapshot = {
        let guard = pool.ranking.read().expect("pool ranking lock poisoned");
        guard.clone()
    };
    let best = snapshot
        .per_view
        .first()
        .and_then(|v| v.ordered.first().copied());
    let best_rtt = best
        .and_then(|a| state.health.get(&a))
        .and_then(|h| h.rtt)
        .map(|d| d.as_millis());

    info!(
        pool = %pool.name,
        healthy,
        total,
        best = best.map(|b| b.to_string()).unwrap_or_else(|| "<none>".into()),
        best_rtt_ms = best_rtt.unwrap_or(0),
        "probe cycle complete"
    );

    if healthy == 0 && total > 0 {
        warn!(
            pool = %pool.name,
            total,
            "every candidate is degraded; consumers fall back until one recovers"
        );
    }
}

// ---------------------------------------------------------------------------
// Probing one candidate
// ---------------------------------------------------------------------------

/// Probe one address, returning the measured round-trip time.
///
/// Which instant stops the clock differs per mode, and each is the last moment
/// that says something about the path: connect completion for `tcp`, handshake
/// completion for `tls`, first response byte for `http`.
async fn probe_one(pool: &Pool, addr: IpAddr, budget: Duration) -> Result<Duration> {
    let target = SocketAddr::new(addr, pool.probe.port);
    timeout(budget, probe_exchange(pool, target))
        .await
        .map_err(|_| anyhow!("probe timed out after {budget:?}"))?
}

async fn probe_exchange(pool: &Pool, target: SocketAddr) -> Result<Duration> {
    let started = Instant::now();
    let tcp = TcpStream::connect(target)
        .await
        .with_context(|| format!("connecting to {target}"))?;
    tcp.set_nodelay(true).ok();

    if pool.probe.mode == ProbeMode::Tcp {
        return Ok(started.elapsed());
    }

    let sni = pool
        .probe
        .sni
        .as_deref()
        .ok_or_else(|| anyhow!("probe mode requires an sni"))?;
    let config = pool
        .tls
        .clone()
        .ok_or_else(|| anyhow!("probe mode requires a TLS config"))?;
    let name =
        ServerName::try_from(sni.to_string()).map_err(|_| anyhow!("invalid probe sni {sni:?}"))?;

    let mut tls = TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .context("probe TLS handshake")?;

    if pool.probe.mode == ProbeMode::Tls {
        return Ok(started.elapsed());
    }

    let path = pool
        .probe
        .path
        .as_deref()
        .ok_or_else(|| anyhow!("http probe requires a path"))?;
    // `Connection: close` so the server does not hold the socket open waiting
    // for a second request that will never come.
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: sni-gate-probe\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes())
        .await
        .context("sending the probe request")?;
    tls.flush().await.context("flushing the probe request")?;

    // Read just enough for the status line. The clock stops at the first byte:
    // that is when the origin demonstrably answered, and waiting for a body
    // would measure its size instead of the path.
    let mut buf = [0u8; 128];
    let mut have = 0usize;
    let mut rtt = None;
    loop {
        let n = tls
            .read(&mut buf[have..])
            .await
            .context("reading the probe response")?;
        if n == 0 {
            break;
        }
        if rtt.is_none() {
            rtt = Some(started.elapsed());
        }
        have += n;
        if buf[..have].windows(2).any(|w| w == b"\r\n") || have == buf.len() {
            break;
        }
    }
    let rtt = rtt.ok_or_else(|| anyhow!("upstream closed without sending a response"))?;

    let status = parse_status(&buf[..have])?;
    if !pool.probe.status.contains(&status) {
        bail!(
            "probe response status {status} is not among the accepted {:?}",
            pool.probe.status
        );
    }
    Ok(rtt)
}

/// Extract the status code from an HTTP response's first line.
fn parse_status(bytes: &[u8]) -> Result<u16> {
    let text = std::str::from_utf8(bytes).context("probe response is not valid UTF-8")?;
    let line = text.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("empty probe response"))?;
    if !version.starts_with("HTTP/") {
        bail!("probe response does not start with an HTTP status line: {line:?}");
    }
    let code = parts
        .next()
        .ok_or_else(|| anyhow!("probe response has no status code: {line:?}"))?;
    code.parse::<u16>()
        .with_context(|| format!("probe response status {code:?} is not a number"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kind_is_inferred() {
        assert_eq!(
            TargetSpec::parse("cf.example.com").unwrap(),
            TargetSpec::Domain("cf.example.com".into())
        );
        assert_eq!(
            TargetSpec::parse("1.2.3.4").unwrap(),
            TargetSpec::Ip("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            TargetSpec::parse("2606:4700::1").unwrap(),
            TargetSpec::Ip("2606:4700::1".parse().unwrap())
        );
        // A CIDR is detected before the hostname rule, which is why a value with
        // no colon still reads as a network.
        match TargetSpec::parse("104.16.0.0/12[4]").unwrap() {
            TargetSpec::Cidr { net, sample } => {
                assert_eq!(net, "104.16.0.0/12".parse::<IpNet>().unwrap());
                assert_eq!(sample, Some(4));
            }
            other => panic!("expected CIDR, got {other:?}"),
        }
    }

    /// The guard that a documentation note cannot provide: a large prefix
    /// without a sample count is refused, naming the fix.
    #[test]
    fn unbounded_cidr_expansion_is_rejected() {
        let err = TargetSpec::parse("104.16.0.0/12").unwrap_err().to_string();
        assert!(err.contains("sample count"), "unhelpful message: {err}");
        // A small prefix needs no sample count.
        assert!(TargetSpec::parse("192.0.2.0/29").is_ok());
    }

    #[test]
    fn malformed_targets_are_rejected() {
        for bad in [
            "",
            "   ",
            "not a cidr/xx",
            "10.0.0.0/33",
            "1.2.3.4[2]",         // sampling only applies to a CIDR
            "192.0.2.0/29[0]",    // zero samples
            "192.0.2.0/29[abc]",  // non-numeric
            "2606:4700::/32[4]x", // trailing junk
            "bad:host",           // colon in a domain
        ] {
            assert!(
                TargetSpec::parse(bad).is_err(),
                "{bad:?} must not parse as a target"
            );
        }
    }

    #[test]
    fn sampling_stays_inside_the_network_and_is_bounded() {
        let net: IpNet = "104.16.0.0/12".parse().unwrap();
        let drawn = draw_sample(&net, Some(4));
        assert_eq!(drawn.len(), 4);
        for a in &drawn {
            assert!(net.contains(a), "{a} outside {net}");
        }
        // Asking for more than the network holds yields only what exists, and
        // terminates rather than spinning on collisions.
        let tiny: IpNet = "192.0.2.0/30".parse().unwrap();
        let all = draw_sample(&tiny, Some(50));
        assert!(all.len() <= 4, "drew {} from a /30", all.len());
    }

    #[test]
    fn ipv6_sampling_stays_inside_the_network() {
        let net: IpNet = "2606:4700::/32".parse().unwrap();
        let drawn = draw_sample(&net, Some(4));
        assert_eq!(drawn.len(), 4);
        for a in &drawn {
            assert!(net.contains(a), "{a} outside {net}");
        }
    }

    fn candidate(addr: &str, target: usize, tags: &[&str]) -> Candidate {
        Candidate {
            addr: addr.parse().unwrap(),
            target,
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Indices address *targets* and tags address candidates; both are unioned.
    #[test]
    fn select_unions_indices_and_tags() {
        let c = candidate("1.2.3.4", 1, &["ipv4", "edge"]);

        assert!(c.matches(&[]), "an empty filter selects everything");
        assert!(c.matches(&[Selector::Index(1)]));
        assert!(!c.matches(&[Selector::Index(0)]));
        assert!(c.matches(&[Selector::Tag("ipv4".into())]));
        assert!(c.matches(&[Selector::Tag("edge".into())]));
        assert!(!c.matches(&[Selector::Tag("ipv6".into())]));
        // OR across kinds.
        assert!(c.matches(&[Selector::Tag("ipv6".into()), Selector::Index(1)]));
        assert!(!c.matches(&[Selector::Tag("ipv6".into()), Selector::Index(0)]));
    }

    #[test]
    fn ewma_smooths_a_single_outlier() {
        let base = Duration::from_millis(20);
        // One 200ms spike must not move the average anywhere near 200ms.
        let after = ewma(base, Duration::from_millis(200));
        assert!(
            after < Duration::from_millis(90),
            "a single spike moved the average to {after:?}"
        );
        // Repeated high samples do converge upward.
        let mut v = base;
        for _ in 0..20 {
            v = ewma(v, Duration::from_millis(200));
        }
        assert!(v > Duration::from_millis(180), "did not converge: {v:?}");
    }

    #[test]
    fn hysteresis_margin_ignores_noise_but_yields_to_real_gains() {
        // 1ms apart at 50ms: noise, no overtake.
        assert!(!beats(Duration::from_millis(49), Duration::from_millis(50)));
        // 20% better: overtake.
        assert!(beats(Duration::from_millis(35), Duration::from_millis(50)));
        // At sub-millisecond RTTs the absolute floor governs.
        assert!(!beats(Duration::from_micros(900), Duration::from_millis(1)));
        assert!(beats(Duration::from_millis(1), Duration::from_millis(10)));
    }

    fn state_with(rtts: &[(&str, Option<u64>, bool)]) -> PoolState {
        let mut health = HashMap::new();
        for (addr, ms, degraded) in rtts {
            let mut h = Health::new(Instant::now(), Duration::from_secs(30));
            h.rtt = ms.map(Duration::from_millis);
            h.degraded = *degraded;
            health.insert(addr.parse::<IpAddr>().unwrap(), h);
        }
        PoolState {
            health,
            ..PoolState::new()
        }
    }

    /// Hysteresis only works if the computed order is *kept*.
    ///
    /// A regression test for a real defect: `publish` computed the order and
    /// dropped it, leaving `state.order` permanently empty. Every cycle then
    /// started from scratch — a plain RTT sort, which is exactly the churn the
    /// margin exists to prevent. Asserting through `recompute_order` catches that,
    /// where a test calling `reorder_with_hysteresis` directly cannot: passing
    /// `prev` by hand is precisely the step that was missing in production.
    #[test]
    fn the_computed_order_is_stored_so_hysteresis_persists() {
        let candidates = vec![
            candidate("1.1.1.1", 0, &["ipv4"]),
            candidate("2.2.2.2", 0, &["ipv4"]),
        ];

        // Cycle 1: nothing measured yet, so nothing is ranked.
        let mut state = state_with(&[("1.1.1.1", None, false), ("2.2.2.2", None, false)]);
        recompute_order(&mut state, &candidates);
        assert!(state.order.is_empty());

        // Cycle 2: 1.1.1.1 measured first and leads.
        state
            .health
            .get_mut(&"1.1.1.1".parse().unwrap())
            .unwrap()
            .rtt = Some(Duration::from_millis(50));
        recompute_order(&mut state, &candidates);
        assert_eq!(
            state.order,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()],
            "the order must be stored, not recomputed and discarded"
        );

        // Cycle 3: 2.2.2.2 arrives 1ms faster. Stored order + margin means the
        // leader holds; without storage this would flip to a bare sort.
        state
            .health
            .get_mut(&"2.2.2.2".parse().unwrap())
            .unwrap()
            .rtt = Some(Duration::from_millis(49));
        recompute_order(&mut state, &candidates);
        assert_eq!(
            state.order.first(),
            Some(&"1.1.1.1".parse::<IpAddr>().unwrap()),
            "a 1ms gain must not flip the leader across cycles"
        );

        // Cycle 4: a decisive gain does take the lead.
        state
            .health
            .get_mut(&"2.2.2.2".parse().unwrap())
            .unwrap()
            .rtt = Some(Duration::from_millis(20));
        recompute_order(&mut state, &candidates);
        assert_eq!(
            state.order.first(),
            Some(&"2.2.2.2".parse::<IpAddr>().unwrap()),
            "a decisive gain must take the lead"
        );
    }

    /// The leader must not change on a 1ms difference, which is what keeps
    /// connections and the upstream-certificate mirror stable.
    #[test]
    fn ranking_is_stable_under_noise() {
        let candidates = vec![
            candidate("1.1.1.1", 0, &["ipv4"]),
            candidate("2.2.2.2", 0, &["ipv4"]),
        ];
        let state = state_with(&[("1.1.1.1", Some(50), false), ("2.2.2.2", Some(49), false)]);
        let prev = vec!["1.1.1.1".parse().unwrap()];
        let order = reorder_with_hysteresis(&prev, &state, &candidates);
        assert_eq!(
            order[0],
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "a 1ms gain must not flip the leader"
        );

        // A decisive gain does flip it.
        let state = state_with(&[("1.1.1.1", Some(50), false), ("2.2.2.2", Some(20), false)]);
        let order = reorder_with_hysteresis(&prev, &state, &candidates);
        assert_eq!(order[0], "2.2.2.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn degraded_and_unmeasured_candidates_leave_the_order() {
        let candidates = vec![
            candidate("1.1.1.1", 0, &["ipv4"]),
            candidate("2.2.2.2", 0, &["ipv4"]),
            candidate("3.3.3.3", 0, &["ipv4"]),
        ];
        let state = state_with(&[
            ("1.1.1.1", Some(10), true), // degraded
            ("2.2.2.2", Some(30), false),
            ("3.3.3.3", None, false), // never measured
        ]);
        let order = reorder_with_hysteresis(&[], &state, &candidates);
        assert_eq!(order, vec!["2.2.2.2".parse::<IpAddr>().unwrap()]);
    }

    /// Backoff must double up to the healthy interval and no further, so a dead
    /// endpoint costs the same as a live one instead of probing forever fast.
    #[test]
    fn degraded_backoff_doubles_and_caps() {
        let interval = Duration::from_secs(300);
        let base = Duration::from_secs(30);
        let mut h = Health::new(Instant::now(), base);

        h.record_failure(2, interval, base);
        assert!(!h.degraded, "one failure is below the threshold of 2");
        h.record_failure(2, interval, base);
        assert!(h.degraded);
        assert_eq!(h.backoff, base);

        for expected in [60u64, 120, 240, 300, 300] {
            h.record_failure(2, interval, base);
            assert_eq!(h.backoff, Duration::from_secs(expected));
        }
    }

    #[test]
    fn recovery_clears_degradation_and_resets_backoff() {
        let interval = Duration::from_secs(300);
        let base = Duration::from_secs(30);
        let mut h = Health::new(Instant::now(), base);
        h.record_failure(1, interval, base);
        h.record_failure(1, interval, base);
        assert!(h.degraded);

        h.record_success(Duration::from_millis(25), interval, base);
        assert!(!h.degraded);
        assert_eq!(h.consecutive_failures, 0);
        assert_eq!(h.backoff, base);
        assert_eq!(h.rtt, Some(Duration::from_millis(25)));
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n").unwrap(), 200);
        assert_eq!(parse_status(b"HTTP/1.0 403 Forbidden\r\n").unwrap(), 403);
        assert_eq!(parse_status(b"HTTP/2 204 \r\n").unwrap(), 204);
        // Not HTTP at all: a TLS record or a raw banner must not read as 200.
        assert!(parse_status(b"\x16\x03\x01\x00\x01").is_err());
        assert!(parse_status(b"SSH-2.0-OpenSSH\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1 abc OK\r\n").is_err());
    }
}
