//! `ResolvesServerCert` implementation that mints (and caches) a certificate for
//! whatever SNI host name the client presents during the TLS handshake.
//!
//! # The invariant
//!
//! A certificate served on a connection routed to some destination must not be
//! valid for any name this listener would route to a *different* destination,
//! nor for any name the **upstream itself** would refuse to answer for on that
//! connection.
//!
//! Violating either half is not a cosmetic over-claim. A browser that holds a
//! connection whose certificate also covers a second origin may coalesce a
//! request for that origin onto the existing connection (RFC 9113 §9.1.1) — no
//! new TCP, no new TLS handshake, no new SNI. sni-gate routes per connection from
//! the SNI, so the coalesced request is never routed at all: it is delivered to
//! whatever upstream the connection was already wired to. See
//! [`crate::certscope`] for the full account.
//!
//! # Mirroring, not planning
//!
//! Coverage is not chosen by configuration. It is **mirrored from the upstream's
//! own certificate**, because that certificate is the only authority on which
//! names the upstream will serve over one connection.
//!
//! The failure this fixes is concrete. A gateway that invents a wildcard
//! `*.example.com` for `example.com` lets a browser coalesce `sub.example.com`
//! onto that connection — but if the upstream's real certificate for
//! `example.com` covers only `{example.com, mail.example.com}`, the upstream sees
//! an `:authority` outside what its own handshake authorized and answers **403**.
//! The gateway invented an authority the origin never granted.
//!
//! So three rules hold, and each is load-bearing:
//!
//! * **Exact first.** A host whose upstream has never been observed is served an
//!   exact certificate — the narrowest thing that can complete the handshake, and
//!   never a licence to coalesce. Nothing blocks on the upstream: the first
//!   handshake completes immediately.
//! * **Mirror what was observed, per requested name.** SANs are learned from the
//!   upstream handshake that the *same* SNI produced, and recorded against that
//!   SNI ([`DynamicResolver::record_upstream_sans`]). A CDN commonly answers two
//!   sibling names with two *different* certificates — `cf.0sm.com` returns
//!   `{qy0.ru, mzz.qy0.ru}` for `qy0.ru` but `{qy0.ru, *.qy0.ru}` for
//!   `t4.qy0.ru` — so what was learned for one name must never be served for the
//!   other. Keying the cache by the exact SNI is what prevents that.
//! * **Clip to this listener's routes.** An upstream SAN is adopted only if every
//!   host it covers routes back into the requesting connection's certificate
//!   scope. The upstream is authoritative about what *it* will serve; it knows
//!   nothing about how this gateway routes, and a name it happens to cover may be
//!   configured here to go somewhere else entirely.
//!
//! # Rotation
//!
//! Upstream certificates change. Every upstream handshake re-reports its SANs, so
//! a mirrored certificate is re-issued whenever the observed set differs from the
//! one it was built from — including when it *narrows*, which is the direction
//! that reintroduces 403s if ignored. The comparison is against the raw observed
//! set, not the post-clipping result, so a change upstream is always noticed even
//! when clipping would erase the difference.
//!
//! # Lookup order
//!
//! For each SNI host, within its scope:
//!   1. In-memory cache, keyed by `(scope, sni_host)`.
//!   2. On-disk store (if persistence is enabled), re-hydrated into the cache.
//!   3. Fresh exact issuance from the CA, then persisted and cached.
//!
//! Issuance is de-duplicated per `(scope, sni_host)` (single-flight), so a burst
//! of concurrent first-time handshakes signs the certificate only once.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::ca::CertificateAuthority;
use crate::certscope::CertScope;
use crate::router::{RouteId, Router};
use crate::store::CertStore;
use crate::suffix::{host_covered_by, SuffixList};

/// The issuance machinery shared by every listener: the CA, the public-suffix
/// list, the on-disk store, and the caches.
///
/// Caches are keyed by `(CertScope, sni_host)`. [`CertScope`] folds in the
/// routing table's fingerprint — so two listeners with identical route tables
/// (the usual `0.0.0.0:443` + `[::]:443` pair) share cached certificates, while
/// listeners that route differently cannot, because a clipping decision is only
/// ever established against one routing table.
pub struct Issuer {
    ca: CertificateAuthority,
    suffix: Arc<SuffixList>,
    store: Option<CertStore>,
    cache: moka::sync::Cache<CacheKey, Arc<CachedCert>>,
    /// Per-key locks providing single-flight issuance.
    locks: moka::sync::Cache<CacheKey, Arc<std::sync::Mutex<()>>>,
}

/// Construction parameters for [`Issuer`].
pub struct IssuerParams {
    pub ca: CertificateAuthority,
    pub suffix: Arc<SuffixList>,
    pub store: Option<CertStore>,
    pub cache_capacity: u64,
    pub cache_ttl: Duration,
}

impl Issuer {
    pub fn new(params: IssuerParams) -> Self {
        let cache = moka::sync::Cache::builder()
            .max_capacity(params.cache_capacity)
            .time_to_live(params.cache_ttl)
            .build();
        let locks = moka::sync::Cache::builder()
            .max_capacity(params.cache_capacity)
            .time_to_idle(Duration::from_secs(60))
            .build();
        Self {
            ca: params.ca,
            suffix: params.suffix,
            store: params.store,
            cache,
            locks,
        }
    }
}

/// Certificate cache key: a partition and the **exact** SNI host within it.
///
/// Keying by the requested name rather than a shared anchor is what keeps two
/// sibling names from inheriting each other's mirrored coverage. The upstream may
/// answer them with different certificates, and the certificate this gateway
/// serves for a name must reflect the one the upstream returned *for that name*.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    scope: CertScope,
    /// Normalized SNI host (lowercase, no trailing dot).
    sni_host: String,
}

/// A cached certificate together with the upstream observation it was built from.
struct CachedCert {
    certified: Arc<CertifiedKey>,
    /// The raw SANs observed on the upstream certificate, before clipping.
    /// `None` when the upstream has not been observed yet (an exact certificate).
    ///
    /// Compared against each new observation to detect rotation. It must be the
    /// *raw* set: clipping can map two different upstream certificates onto the
    /// same issued SANs, and comparing post-clipping would then miss a rotation
    /// that later widens back.
    observed: Option<Arc<[String]>>,
}

/// One listener's certificate resolver: the shared [`Issuer`] plus the routing
/// context that decides which names may share a certificate here.
///
/// Bound to a single listener because clipping is a property of a specific
/// routing table. A listener-agnostic resolver could prove a name safe under one
/// listener's routes and then serve it on another where it is not.
pub struct DynamicResolver {
    issuer: Arc<Issuer>,
    router: Arc<Router>,
    /// The certificate scope of each route id, indexed by id.
    scopes: Arc<[CertScope]>,
}

impl std::fmt::Debug for DynamicResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicResolver")
            .field("cache_entries", &self.issuer.cache.entry_count())
            .field("routes", &self.scopes.len())
            .finish()
    }
}

/// What clipping decided for one observed upstream certificate: the names that
/// will be issued, and the observed SANs that were dropped with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MirrorPlan {
    /// Names that survived clipping and will be issued. Always covers the host.
    kept: Vec<String>,
    /// Observed SANs dropped because adopting them would over-claim.
    dropped: Vec<(String, Drop)>,
}

/// Why one observed upstream SAN was not mirrored.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Drop {
    /// Some host the name covers routes out of the requesting connection's
    /// certificate scope, so mirroring it would authorize coalescing past this
    /// gateway's routing.
    OutOfScope(crate::router::Escape),
    /// A wildcard whose parent is a public suffix (`*.com`, `*.co.uk`). No real
    /// CA would issue it, and under a locally-trusted CA it would be valid across
    /// an entire registry.
    CrossesRegistryBoundary,
    /// Not a name this gateway can mint: an IP literal, a malformed entry, or a
    /// multi-level wildcard no TLS client would honor anyway.
    Unmintable,
}

impl DynamicResolver {
    /// Bind `issuer` to one listener's routing table. `scopes[i]` is the
    /// certificate scope of route id `i`.
    pub fn new(issuer: Arc<Issuer>, router: Arc<Router>, scopes: Arc<[CertScope]>) -> Self {
        Self {
            issuer,
            router,
            scopes,
        }
    }

    /// The certificate scope of a route id.
    fn scope_of(&self, id: RouteId) -> &CertScope {
        // Indices come from this listener's own router, whose ids are built from
        // the same route vector as `scopes`.
        &self.scopes[id]
    }

    /// Clip an observed upstream SAN set down to the names this listener may
    /// mirror for `sni_host`, without issuing anything.
    ///
    /// Returns `None` when the host matches no route — nothing is ever issued for
    /// a name this listener would not serve.
    ///
    /// Exposed so a test can inspect the decision directly rather than infer it
    /// from a signed certificate.
    #[cfg(test)]
    fn mirror_plan(&self, sni_host: &str, observed: &[String]) -> Option<MirrorPlan> {
        let owner = self.router.match_host(sni_host)?;
        Some(self.clip(sni_host, owner, observed))
    }

    /// Clip `observed` to the names that are safe to mirror for `sni_host` on
    /// this listener.
    ///
    /// Two independent filters, both required:
    ///
    /// * **Mintability** — the name must be one this CA may legitimately sign
    ///   (see [`SuffixList::wildcard_is_mintable`]).
    /// * **Confinement** — every host the name covers must route into `owner`'s
    ///   certificate scope, or a client could coalesce past this gateway's
    ///   routing.
    ///
    /// The requesting host is always included: it is what selected `owner` in the
    /// first place, so it is confined by construction, and the handshake cannot
    /// complete without it.
    fn clip(&self, sni_host: &str, owner: RouteId, observed: &[String]) -> MirrorPlan {
        let host = normalize_host(sni_host);
        let scope = self.scope_of(owner).clone();
        let in_scope = |id: RouteId| *self.scope_of(id) == scope;

        let mut kept: Vec<String> = Vec::with_capacity(observed.len() + 1);
        let mut dropped: Vec<(String, Drop)> = Vec::new();

        for san in observed {
            let name = normalize_host(san);
            if name.is_empty() || kept.contains(&name) {
                continue;
            }

            match name.strip_prefix("*.") {
                Some(parent) => {
                    // A wildcard is only ever single-level, and its parent must
                    // stay inside one registrable domain.
                    if parent.is_empty() || parent.contains('*') {
                        dropped.push((name, Drop::Unmintable));
                        continue;
                    }
                    if !self.issuer.suffix.wildcard_is_mintable(parent) {
                        dropped.push((name, Drop::CrossesRegistryBoundary));
                        continue;
                    }
                    match self.router.wildcard_confined(parent, &in_scope) {
                        Ok(()) => kept.push(name),
                        Err(escape) => dropped.push((name, Drop::OutOfScope(escape))),
                    }
                }
                None => {
                    if name.contains('*') || name.parse::<std::net::IpAddr>().is_ok() {
                        // An upstream may legitimately carry an IP SAN; this
                        // gateway is asked for names, and mirroring an address
                        // would claim authority over a host it never routed.
                        dropped.push((name, Drop::Unmintable));
                        continue;
                    }
                    match self.router.name_confined(&name, &in_scope) {
                        Ok(()) => kept.push(name),
                        Err(escape) => dropped.push((name, Drop::OutOfScope(escape))),
                    }
                }
            }
        }

        // The requesting host is always safe for its own scope. Needed whenever
        // every observed name was dropped, and whenever the survivors do not
        // happen to cover it (an upstream wildcard `*.example.com` does not cover
        // the apex `example.com`).
        if !host_covered_by(&kept, &host) {
            kept.push(host);
        }

        MirrorPlan { kept, dropped }
    }

    /// Return a certificate valid for `sni_host`.
    ///
    /// On the first handshake for a name, this is an **exact** certificate: the
    /// upstream has not been observed, so no broader claim is justified. Once
    /// [`record_upstream_sans`](Self::record_upstream_sans) has mirrored the
    /// upstream's real coverage, subsequent handshakes serve that instead.
    ///
    /// Nothing here waits on the upstream. The exact certificate is always enough
    /// to complete the handshake the client is currently in.
    fn get_or_issue(&self, sni_host: &str, owner: RouteId) -> anyhow::Result<Arc<CertifiedKey>> {
        let issuer = &self.issuer;
        let host = normalize_host(sni_host);
        let scope = self.scope_of(owner).clone();
        let key = CacheKey {
            scope: scope.clone(),
            sni_host: host.clone(),
        };

        if let Some(existing) = issuer.cache.get(&key) {
            return Ok(existing.certified.clone());
        }

        // Single-flight: only one task issues for a given (scope, sni_host).
        let lock = issuer
            .locks
            .get_with(key.clone(), || Arc::new(std::sync::Mutex::new(())));
        let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());

        if let Some(existing) = issuer.cache.get(&key) {
            return Ok(existing.certified.clone());
        }

        // A persisted certificate carries the upstream observation it was built
        // from, so a restart resumes with the coverage it had already learned
        // rather than falling back to exact and re-widening on the next request.
        if let Some(store) = &issuer.store {
            if let Some(stored) = store.load(&scope, &host) {
                // An absent sidecar means "never observed", and an unobserved
                // certificate this version wrote covers exactly its own host. A
                // file that is broader than that was minted by something else —
                // a configuration whose wildcards were declared rather than
                // mirrored. Serving it would hand the client coalescing coverage
                // no upstream ever vouched for, which is the stale-wildcard 403
                // this design exists to prevent. Re-issue instead.
                let unobserved_but_broad =
                    stored.observed.is_none() && stored.sans.as_slice() != [host.clone()];
                if unobserved_but_broad {
                    tracing::warn!(
                        scope = %scope,
                        host = %host,
                        sans = ?stored.sans,
                        "persisted certificate claims coverage no upstream was observed to \
                         authorize; re-issuing as exact"
                    );
                } else if host_covered_by(&stored.sans, &host) {
                    let signing_key = any_ecdsa_type(&stored.key)
                        .map_err(|e| anyhow::anyhow!("loading persisted key for {host}: {e}"))?;
                    let certified = Arc::new(CertifiedKey::new(stored.chain, signing_key));
                    issuer.cache.insert(
                        key,
                        Arc::new(CachedCert {
                            certified: certified.clone(),
                            observed: stored.observed.map(Arc::from),
                        }),
                    );
                    tracing::info!(scope = %scope, host = %host, "loaded certificate from store");
                    return Ok(certified);
                }
                // Does not cover the host it is filed under: re-issue rather than
                // serve a certificate the client would reject.
                tracing::warn!(
                    scope = %scope,
                    host = %host,
                    sans = ?stored.sans,
                    "persisted certificate does not cover its own host; re-issuing"
                );
            }
        }

        let sans = vec![host.clone()];
        let certified = self.sign(&scope, &host, &sans, None)?;
        tracing::info!(
            scope = %scope,
            host = %host,
            "issued exact certificate; coverage will mirror the upstream once observed"
        );
        issuer.cache.insert(
            key,
            Arc::new(CachedCert {
                certified: certified.clone(),
                observed: None,
            }),
        );
        Ok(certified)
    }

    /// Whether the certificate currently cached for `sni_host` already mirrors
    /// `observed` — i.e. [`record_upstream_sans`](Self::record_upstream_sans)
    /// would do nothing.
    ///
    /// Cheap by construction: one cache lookup and a slice comparison, no signing
    /// and no I/O. The data path calls this on **every** upstream handshake and
    /// only hands the update to the blocking pool when it returns `false`, so the
    /// steady state — an upstream whose certificate has not changed — costs
    /// nothing beyond this check.
    pub fn mirror_is_current(&self, sni_host: &str, observed: &[String]) -> bool {
        let Some(owner) = self.router.match_host(sni_host) else {
            // Not a name this listener serves: nothing to mirror, so there is
            // nothing out of date either.
            return true;
        };
        let key = CacheKey {
            scope: self.scope_of(owner).clone(),
            sni_host: normalize_host(sni_host),
        };
        self.issuer
            .cache
            .get(&key)
            .is_some_and(|cached| cached.observed.as_deref() == Some(observed))
    }

    /// Record the SANs of the certificate the upstream presented for `sni_host`,
    /// re-issuing this gateway's certificate to mirror them when they differ from
    /// the observation the current one was built from.
    ///
    /// Called from the data path after a successful upstream handshake. It runs
    /// *off* the handshake that triggered it: that connection is already served,
    /// and the mirrored certificate is what the client's **next** connection —
    /// the one it could coalesce onto — will receive.
    ///
    /// Handles rotation in both directions. A widened upstream certificate grants
    /// coalescing that is now genuinely authorized; a narrowed one revokes it,
    /// and revoking promptly is what keeps a stale wildcard from producing 403s.
    pub fn record_upstream_sans(&self, sni_host: &str, observed: &[String]) {
        let Some(owner) = self.router.match_host(sni_host) else {
            return;
        };
        let host = normalize_host(sni_host);
        let scope = self.scope_of(owner).clone();
        let key = CacheKey {
            scope: scope.clone(),
            sni_host: host.clone(),
        };

        // Cheap pre-check outside the lock: the overwhelmingly common case is an
        // unchanged upstream on every subsequent connection.
        if let Some(existing) = self.issuer.cache.get(&key) {
            if existing.observed.as_deref() == Some(observed) {
                return;
            }
        }

        // Same lock as issuance, so a concurrent first handshake cannot overwrite
        // the mirrored certificate with the exact one it is about to insert.
        let lock = self
            .issuer
            .locks
            .get_with(key.clone(), || Arc::new(std::sync::Mutex::new(())));
        let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());

        if let Some(existing) = self.issuer.cache.get(&key) {
            if existing.observed.as_deref() == Some(observed) {
                return;
            }
        }

        let plan = self.clip(&host, owner, observed);

        match self.sign(&scope, &host, &plan.kept, Some(observed)) {
            Ok(certified) => {
                if plan.dropped.is_empty() {
                    tracing::info!(
                        scope = %scope,
                        host = %host,
                        sans = ?plan.kept,
                        "mirrored upstream certificate coverage"
                    );
                } else {
                    // Not a warning: dropping is the mechanism working. An
                    // upstream wildcard that this listener routes elsewhere is
                    // exactly what must not be mirrored.
                    tracing::info!(
                        scope = %scope,
                        host = %host,
                        sans = ?plan.kept,
                        dropped = ?plan.dropped.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                        "mirrored upstream certificate coverage (clipped to this route scope)"
                    );
                }
                self.issuer.cache.insert(
                    key,
                    Arc::new(CachedCert {
                        certified,
                        observed: Some(Arc::from(observed.to_vec())),
                    }),
                );
            }
            Err(err) => {
                // The exact certificate already in the cache stays valid, so the
                // gateway keeps serving — just without the mirrored breadth.
                tracing::error!(
                    scope = %scope,
                    host = %host,
                    error = %format!("{err:#}"),
                    "failed to issue mirrored certificate; keeping current coverage"
                );
            }
        }
    }

    /// Sign `sans` for `host` and persist the result alongside the upstream
    /// observation it was built from. Persistence is best-effort: a certificate
    /// that cannot be written is still served from memory.
    fn sign(
        &self,
        scope: &CertScope,
        host: &str,
        sans: &[String],
        observed: Option<&[String]>,
    ) -> anyhow::Result<Arc<CertifiedKey>> {
        let issued = self.issuer.ca.issue(host, sans)?;
        let signing_key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(issued.key_der.clone().into()))
            .map_err(|e| anyhow::anyhow!("loading issued key for {host}: {e}"))?;

        if let Some(store) = &self.issuer.store {
            if let Err(err) = store.save(scope, host, &issued.chain_pem, &issued.key_pem, observed)
            {
                tracing::warn!(
                    scope = %scope,
                    host = %host,
                    error = %format!("{err:#}"),
                    "failed to persist certificate"
                );
            }
        }

        Ok(Arc::new(CertifiedKey::new(issued.chain, signing_key)))
    }
}

/// Normalize an SNI host the way coverage checks expect: lowercase, no trailing
/// dot. Ports never appear in a TLS SNI, so none is stripped here.
fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The DNS names an upstream's leaf certificate claims — the observation that
/// drives mirroring.
///
/// Only `dNSName` entries are returned. An `iPAddress` SAN says nothing about
/// which *names* the upstream will answer for over the connection, which is the
/// only question mirroring asks.
///
/// An empty result is meaningful, not an error: an upstream certificate with no
/// DNS names authorizes no coalescing at all, and recording that is how a
/// rotation *away* from a wildcard narrows this gateway's certificate in step.
pub fn observed_dns_sans(chain: &[rustls::pki_types::CertificateDer<'_>]) -> Vec<String> {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    let Some(leaf) = chain.first() else {
        return Vec::new();
    };
    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        // A certificate rustls accepted but x509-parser cannot read is not worth
        // failing a served connection over; it simply yields no observation.
        return Vec::new();
    };
    let Ok(Some(ext)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    ext.value
        .general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::DNSName(d) => Some((*d).to_string()),
            _ => None,
        })
        .collect()
}

/// Run blocking work without stalling an async worker thread, on whatever
/// context the caller happens to be in.
///
/// [`tokio::task::block_in_place`] is the right tool on a multi-threaded runtime:
/// it moves the current task's worker out of the async pool for the duration, so
/// sibling tasks are migrated rather than blocked. It *panics* on a
/// current-thread runtime, though, and it is unavailable outside one entirely.
/// Both cases are real here — unit tests call the resolver directly — so the
/// flavor is checked rather than assumed. Silently depending on how the caller
/// built its runtime is exactly the kind of coupling that turns into a panic in
/// someone else's process.
fn in_blocking_context<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        // Current-thread runtime, or no runtime at all: nothing to yield to.
        _ => work(),
    }
}

impl ResolvesServerCert for DynamicResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = match client_hello.server_name() {
            Some(name) => name,
            None => {
                tracing::debug!("handshake without SNI; no certificate resolved");
                return None;
            }
        };

        // Resolve the route here, not just in the data path: the route decides
        // which scope this connection's certificate belongs to, and hence what it
        // may cover. A name this listener would not serve gets no certificate.
        let Some(owner) = self.router.match_host(host) else {
            tracing::debug!(host, "no route matches; no certificate resolved");
            return None;
        };

        // `ResolvesServerCert` is a synchronous trait called from inside rustls's
        // handshake, which runs on a tokio worker thread. On a cache miss the work
        // below blocks: a keygen and signature, and — the dominant cost by roughly
        // 40x, measured — two file writes plus renames. Blocking a worker on file
        // I/O stalls every other task queued on it, so hand it to the blocking pool
        // instead of the async worker.
        //
        // `block_in_place` rather than `spawn_blocking`: this thread must produce a
        // value before returning, and the certificate must be persisted before it
        // is served, so the work cannot be detached. Moving the save out of the
        // single-flight lock would decouple it, but two successive issuances for one
        // key could then land out of order and persist the stale certificate.
        // Correct ordering is worth more than the few milliseconds.
        match in_blocking_context(|| self.get_or_issue(host, owner)) {
            Ok(key) => Some(key),
            Err(err) => {
                tracing::error!(host, error = %format!("{err:#}"), "certificate issuance failed");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certscope::{CertScope, Forwarding};
    use crate::config::{AddressFamily, RouteType, SniPolicy};
    use crate::router::Escape;

    fn scope(port: u16) -> CertScope {
        CertScope::new(
            1,
            &Forwarding {
                route_type: RouteType::Http,
                host: Some("127.0.0.1".into()),
                port,
                sni: SniPolicy::Reflect,
                family: AddressFamily::Dual,
                nat64: None,
                addr_resolver: "system".into(),
                ech: None,
            },
        )
    }

    /// Build a resolver over a real CA, PSL and router — no store, no network.
    fn resolver(
        patterns: &[Vec<String>],
        default: Option<usize>,
        scopes: &[CertScope],
    ) -> DynamicResolver {
        resolver_with_store(patterns, default, scopes, None)
    }

    fn resolver_with_store(
        patterns: &[Vec<String>],
        default: Option<usize>,
        scopes: &[CertScope],
        store: Option<CertStore>,
    ) -> DynamicResolver {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("sni-gate-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = crate::ca::CertificateAuthority::load_or_generate(crate::ca::CaParams {
            cert_path: &dir.join("ca.crt"),
            key_path: &dir.join("ca.key"),
            common_name: "Test CA",
            organization: "",
            country: "",
            leaf_validity_days: 30,
        })
        .unwrap();
        let issuer = Arc::new(Issuer::new(IssuerParams {
            ca,
            suffix: Arc::new(SuffixList::embedded().unwrap()),
            store,
            cache_capacity: 64,
            cache_ttl: Duration::from_secs(60),
        }));
        let router =
            Arc::new(Router::build(patterns, default, &std::collections::HashMap::new()).unwrap());
        DynamicResolver::new(issuer, router, scopes.to_vec().into())
    }

    fn sans(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    /// The SANs a certificate actually carries, read back from the signed DER —
    /// so these assert what a client would see, not what we intended to sign.
    fn issued_sans(key: &CertifiedKey) -> Vec<String> {
        use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
        let (_, cert) = X509Certificate::from_der(key.cert[0].as_ref()).unwrap();
        let ext = cert.subject_alternative_name().unwrap().unwrap();
        ext.value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(d) => Some((*d).to_string()),
                _ => None,
            })
            .collect()
    }

    // -- First contact: exact, never speculative ---------------------------

    #[test]
    fn first_handshake_issues_an_exact_certificate() {
        // Nothing is known about the upstream yet, so nothing beyond the
        // requested name may be claimed — a speculative wildcard here is exactly
        // what authorizes the coalescing that ends in a 403.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        let key = r.get_or_issue("a.site.test", 0).unwrap();
        assert_eq!(issued_sans(&key), vec!["a.site.test"]);
    }

    #[test]
    fn an_unrouted_name_is_never_issued_a_certificate() {
        let scopes = [scope(443)];
        let r = resolver(&[vec!["site.test".into()]], None, &scopes);
        assert!(r
            .mirror_plan("elsewhere.test", &sans(&["elsewhere.test"]))
            .is_none());
    }

    // -- The reported bug --------------------------------------------------

    #[test]
    fn a_siblings_wildcard_is_never_served_for_the_apex() {
        // The exact shape of the reported failure. One upstream (`cf.0sm.com`)
        // answers two names with two different certificates:
        //
        //   qy0.ru    -> {qy0.ru, mzz.qy0.ru}     (no wildcard)
        //   t4.qy0.ru -> {qy0.ru, *.qy0.ru}       (wildcard)
        //
        // Serving t4's wildcard for a `qy0.ru` connection would let the browser
        // coalesce `t4.qy0.ru` onto it; the upstream then sees an `:authority`
        // its own handshake certificate never authorized, and answers 403.
        //
        // One scope, so routing permits sharing — the *upstream observation* is
        // the only thing keeping them apart, which is precisely the claim.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".qy0.ru".into()]], None, &scopes);

        r.record_upstream_sans("t4.qy0.ru", &sans(&["qy0.ru", "*.qy0.ru"]));
        r.record_upstream_sans("qy0.ru", &sans(&["qy0.ru", "mzz.qy0.ru"]));

        let apex = issued_sans(&r.get_or_issue("qy0.ru", 0).unwrap());
        assert!(
            !apex.iter().any(|s| s == "*.qy0.ru"),
            "the apex must not inherit the sibling's wildcard, got {apex:?}"
        );
        assert!(
            !host_covered_by(&apex, "t4.qy0.ru"),
            "the apex certificate must not be valid for t4.qy0.ru, got {apex:?}"
        );
        assert!(host_covered_by(&apex, "qy0.ru"), "got {apex:?}");

        // And the sibling keeps the coverage its own upstream really granted, so
        // legitimate coalescing is not sacrificed to fix the illegitimate kind.
        let sub = issued_sans(&r.get_or_issue("t4.qy0.ru", 0).unwrap());
        assert!(
            sub.iter().any(|s| s == "*.qy0.ru"),
            "the sibling must keep the wildcard its upstream returned, got {sub:?}"
        );
    }

    #[test]
    fn mirroring_preserves_the_upstreams_own_coverage() {
        // The performance half of the contract: when the upstream really does
        // serve a wildcard, HTTP/2 reuse across siblings must survive.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        r.record_upstream_sans("a.site.test", &sans(&["*.site.test", "site.test"]));

        let issued = issued_sans(&r.get_or_issue("a.site.test", 0).unwrap());
        assert!(issued.iter().any(|s| s == "*.site.test"), "got {issued:?}");
        assert!(
            host_covered_by(&issued, "b.site.test"),
            "a sibling must be coalescible when the upstream authorizes it, got {issued:?}"
        );
    }

    // -- Rotation ----------------------------------------------------------

    #[test]
    fn a_narrowed_upstream_certificate_revokes_the_mirrored_wildcard() {
        // The forward-looking case: the upstream rotates from a wildcard to a
        // single name. Keeping the old wildcard would reintroduce the 403 — the
        // gateway would still be authorizing coalescing the upstream no longer
        // honors.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        r.record_upstream_sans("a.site.test", &sans(&["*.site.test", "site.test"]));
        let wide = issued_sans(&r.get_or_issue("a.site.test", 0).unwrap());
        assert!(wide.iter().any(|s| s == "*.site.test"), "got {wide:?}");

        r.record_upstream_sans("a.site.test", &sans(&["a.site.test"]));
        let narrow = issued_sans(&r.get_or_issue("a.site.test", 0).unwrap());
        assert_eq!(
            narrow,
            vec!["a.site.test"],
            "a narrowed upstream must narrow the mirror"
        );
        assert!(!host_covered_by(&narrow, "b.site.test"));
    }

    #[test]
    fn a_widened_upstream_certificate_extends_the_mirror() {
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        r.record_upstream_sans("a.site.test", &sans(&["a.site.test"]));
        r.record_upstream_sans("a.site.test", &sans(&["*.site.test", "site.test"]));

        let issued = issued_sans(&r.get_or_issue("a.site.test", 0).unwrap());
        assert!(issued.iter().any(|s| s == "*.site.test"), "got {issued:?}");
    }

    #[test]
    fn an_unchanged_observation_does_not_resign() {
        // Every connection re-reports the upstream's SANs; only a *change* may
        // cost a signature. Identity of the Arc is the observable proof that no
        // re-issuance happened.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        r.record_upstream_sans("a.site.test", &sans(&["*.site.test", "site.test"]));
        let first = r.get_or_issue("a.site.test", 0).unwrap();
        r.record_upstream_sans("a.site.test", &sans(&["*.site.test", "site.test"]));
        let second = r.get_or_issue("a.site.test", 0).unwrap();

        assert!(
            Arc::ptr_eq(&first, &second),
            "an unchanged upstream must not trigger a re-signature"
        );
    }

    // -- The store may hold files this version would never have written -----

    #[test]
    fn a_persisted_wildcard_with_no_observation_is_never_served() {
        // The poisoning case: a certificate left on disk by a configuration that
        // declared wildcards instead of mirroring them. It covers the host it is
        // filed under, so it would load cleanly — but no upstream was ever
        // observed to authorize that wildcard, so serving it would grant exactly
        // the coalescing this design refuses. The absent sidecar is the tell.
        let dir = std::env::temp_dir().join(format!(
            "sni-gate-poison-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        // A renewal margin well inside the planted certificate's 30-day validity,
        // so `load` returns the file instead of discarding it as near-expiry.
        let store = CertStore::new(dir.clone(), 1);
        store.init().unwrap();

        let scopes = [scope(443)];
        let sc = scopes[0].clone();

        // Plant a real wildcard certificate with no sidecar, standing in for what
        // the previous configuration left behind. Signed by a throwaway CA: the
        // store is read back by SANs, and the file's own issuer is irrelevant to
        // what this test asserts.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = crate::ca::CertificateAuthority::load_or_generate(crate::ca::CaParams {
            cert_path: &dir.join("plant-ca.crt"),
            key_path: &dir.join("plant-ca.key"),
            common_name: "Plant CA",
            organization: "",
            country: "",
            leaf_validity_days: 30,
        })
        .unwrap();
        let planted = ca
            .issue("site.test", &sans(&["site.test", "*.site.test"]))
            .unwrap();
        store
            .save(&sc, "site.test", &planted.chain_pem, &planted.key_pem, None)
            .unwrap();

        // A fresh resolver over that store: cold cache, so the file is the only
        // source of coverage.
        let r = resolver_with_store(&[vec![".site.test".into()]], None, &scopes, Some(store));
        let served = issued_sans(&r.get_or_issue("site.test", 0).unwrap());

        assert_eq!(
            served,
            vec!["site.test"],
            "an unobserved persisted certificate must be reduced to exact, got {served:?}"
        );
        assert!(
            !host_covered_by(&served, "a.site.test"),
            "the re-issued certificate must not authorize coalescing, got {served:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Clipping: the upstream is not authoritative about our routing -----

    #[test]
    fn an_upstream_wildcard_is_dropped_when_a_sibling_routes_elsewhere() {
        // The upstream serves `*.site.test`, but on *this* listener one sibling
        // under it is pinned to a different upstream. Mirroring the wildcard would
        // cover that sibling too, letting a client coalesce its traffic onto this
        // connection and bypass routing entirely — the upstream knows nothing
        // about that, so its SANs cannot be the last word.
        let scopes = [scope(443), scope(22222)];
        let r = resolver(
            &[vec!["b.site.test".into()], vec![".site.test".into()]],
            None,
            &scopes,
        );

        let plan = r
            .mirror_plan("a.site.test", &sans(&["*.site.test", "site.test"]))
            .unwrap();
        assert_eq!(
            plan.dropped,
            vec![(
                "*.site.test".to_string(),
                Drop::OutOfScope(Escape::Host {
                    host: "b.site.test".into(),
                    route: 0
                })
            )]
        );
        // The apex SAN routes into this same scope, so it survives; the requested
        // host is added because the survivors do not cover it.
        assert_eq!(plan.kept, vec!["site.test", "a.site.test"]);
        assert!(!host_covered_by(&plan.kept, "b.site.test"));
    }

    #[test]
    fn a_pinned_apex_drops_only_the_apex_san() {
        // The neighbouring case, and the reason clipping is per-name rather than
        // all-or-nothing: a single-level `*.site.test` does not cover the apex, so
        // pinning `site.test` elsewhere cannot be coalesced onto the wildcard. The
        // wildcard stays; only the apex SAN is dropped.
        let scopes = [scope(443), scope(22222)];
        let r = resolver(
            &[vec!["site.test".into()], vec![".site.test".into()]],
            None,
            &scopes,
        );

        let plan = r
            .mirror_plan("a.site.test", &sans(&["*.site.test", "site.test"]))
            .unwrap();
        assert_eq!(plan.kept, vec!["*.site.test"]);
        assert_eq!(
            plan.dropped,
            vec![(
                "site.test".to_string(),
                Drop::OutOfScope(Escape::Host {
                    host: "site.test".into(),
                    route: 0
                })
            )]
        );

        // Stated as the invariant: neither certificate is valid for a name the
        // other's route owns, so no client can coalesce between them.
        let sibling = r.clip("a.site.test", 1, &sans(&["*.site.test", "site.test"]));
        let apex = r.clip("site.test", 0, &sans(&["site.test"]));
        assert!(!host_covered_by(&sibling.kept, "site.test"));
        assert!(!host_covered_by(&apex.kept, "a.site.test"));
    }

    #[test]
    fn an_upstream_wildcard_crossing_a_registry_boundary_is_never_minted() {
        // A compromised or misconfigured upstream claiming `*.com` must not be
        // mirrored: under a locally-trusted CA that certificate would be valid
        // for every `.com` name the client visits.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        let plan = r
            .mirror_plan("a.site.test", &sans(&["*.com", "*.site.test"]))
            .unwrap();
        assert_eq!(
            plan.dropped,
            vec![("*.com".to_string(), Drop::CrossesRegistryBoundary)]
        );
        assert_eq!(plan.kept, vec!["*.site.test"]);
    }

    #[test]
    fn unmintable_upstream_sans_are_dropped() {
        // Real certificates carry IP SANs and, very occasionally, malformed
        // entries. This gateway is asked for names; mirroring an address would
        // claim authority over a host it never routed.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        let plan = r
            .mirror_plan(
                "a.site.test",
                &sans(&["203.0.113.7", "*.*.site.test", "", "a.site.test"]),
            )
            .unwrap();
        assert_eq!(plan.kept, vec!["a.site.test"]);
        assert_eq!(
            plan.dropped,
            vec![
                ("203.0.113.7".to_string(), Drop::Unmintable),
                ("*.*.site.test".to_string(), Drop::Unmintable),
            ]
        );
    }

    #[test]
    fn the_requested_host_is_always_covered() {
        // An upstream wildcard does not cover the apex it names, and an upstream
        // may answer with a certificate that does not mention the requested name
        // at all. Either way the handshake must still complete.
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        let apex = r.mirror_plan("site.test", &sans(&["*.site.test"])).unwrap();
        assert!(host_covered_by(&apex.kept, "site.test"), "got {apex:?}");

        let unrelated = r
            .mirror_plan("a.site.test", &sans(&["other.example"]))
            .unwrap();
        assert!(host_covered_by(&unrelated.kept, "a.site.test"));
    }

    #[test]
    fn observed_sans_are_normalized_and_deduplicated() {
        let scopes = [scope(443)];
        let r = resolver(&[vec![".site.test".into()]], None, &scopes);

        let plan = r
            .mirror_plan(
                "a.site.test",
                &sans(&["A.SITE.TEST", "a.site.test.", "*.SITE.test"]),
            )
            .unwrap();
        assert_eq!(plan.kept, vec!["a.site.test", "*.site.test"]);
    }

    // -- Scope partitioning ------------------------------------------------

    #[test]
    fn identical_forwarding_shares_one_scope() {
        // The optimization must survive: two routes that forward identically are
        // one scope, so a wildcard confined to them is still mirrored.
        let scopes = [scope(443), scope(443)];
        let r = resolver(
            &[vec!["a.site.test".into()], vec![".site.test".into()]],
            None,
            &scopes,
        );

        let plan = r
            .mirror_plan("a.site.test", &sans(&["*.site.test"]))
            .unwrap();
        assert!(plan.dropped.is_empty(), "got {:?}", plan.dropped);
        assert!(plan.kept.iter().any(|s| s == "*.site.test"));
    }

    #[test]
    fn two_scopes_do_not_share_a_mirrored_certificate() {
        // Same name, two listeners' worth of scopes: an observation recorded for
        // one must not leak into the other's cache entry.
        let scopes = [scope(443), scope(22222)];
        let r = resolver(
            &[vec!["a.site.test".into()], vec!["b.site.test".into()]],
            None,
            &scopes,
        );

        r.record_upstream_sans("a.site.test", &sans(&["*.site.test"]));

        let other = issued_sans(&r.get_or_issue("b.site.test", 1).unwrap());
        assert_eq!(
            other,
            vec!["b.site.test"],
            "a mirror learned in one scope must not be served in another"
        );
    }
}
