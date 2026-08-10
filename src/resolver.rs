//! `ResolvesServerCert` implementation that mints (and caches) a certificate for
//! whatever SNI host name the client presents during the TLS handshake.
//!
//! # The invariant
//!
//! A certificate served on a connection routed to some destination must not be
//! valid for any name this listener would route to a *different* destination.
//!
//! Violating it is not a cosmetic over-claim. A browser that holds a connection
//! whose certificate also covers a second origin may coalesce a request for that
//! origin onto the existing connection (RFC 9113 §9.1.1) — no new TCP, no new TLS
//! handshake, no new SNI. sni-gate routes per connection from the SNI, so the
//! coalesced request is never routed at all: it is delivered to whatever upstream
//! the connection was already wired to. See [`crate::certscope`] for the full
//! account.
//!
//! Two mechanisms hold the invariant, and both are load-bearing:
//!
//! * **Clipping.** The issuance mode proposes a name set; every proposed name is
//!   then checked against this listener's routing table and dropped unless every
//!   host it covers routes into the requesting connection's certificate scope.
//!   `mode` is therefore an upper bound on breadth, not a promise of it.
//! * **Partitioning.** The in-memory cache and the on-disk store are keyed by
//!   `(scope, anchor)`. Clipping alone would not survive accumulation: a later
//!   host under the same anchor but a different destination would otherwise be
//!   merged into the existing certificate, re-widening it after the fact.
//!
//! # Lookup order
//!
//! For each SNI host, within its scope:
//!   1. In-memory cache, keyed by `(scope, anchor)`.
//!   2. On-disk store (if persistence is enabled), re-hydrated into the cache.
//!   3. Fresh issuance from the CA, then persisted and cached.
//!
//! Issuance is de-duplicated per `(scope, anchor)` (single-flight), so a burst of
//! concurrent first-time handshakes signs the certificate only once.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::ca::CertificateAuthority;
use crate::certscope::CertScope;
use crate::config::IssuanceMode;
use crate::router::{Escape, RouteId, Router};
use crate::store::CertStore;
use crate::suffix::{host_covered_by, SuffixList};

/// The issuance machinery shared by every listener: the CA, the public-suffix
/// list, the on-disk store, and the caches.
///
/// Caches are keyed by [`CertScope`], which folds in the routing table's
/// fingerprint — so two listeners with identical route tables (the usual
/// `0.0.0.0:443` + `[::]:443` pair) share cached certificates, while listeners
/// that route differently cannot, because a confinement proof is only ever
/// established against one routing table.
pub struct Issuer {
    ca: CertificateAuthority,
    suffix: Arc<SuffixList>,
    store: Option<CertStore>,
    mode: IssuanceMode,
    cache: moka::sync::Cache<CacheKey, Arc<CachedCert>>,
    /// Per-key locks providing single-flight issuance.
    locks: moka::sync::Cache<CacheKey, Arc<std::sync::Mutex<()>>>,
}

/// Construction parameters for [`Issuer`].
pub struct IssuerParams {
    pub ca: CertificateAuthority,
    pub suffix: Arc<SuffixList>,
    pub store: Option<CertStore>,
    pub mode: IssuanceMode,
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
            mode: params.mode,
            cache,
            locks,
        }
    }
}

/// Certificate cache key: a partition and a coverage anchor within it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    scope: CertScope,
    base: String,
}

/// A cached certificate plus the names it covers, so a sibling host in the same
/// scope can reuse it (via [`host_covered_by`]) instead of triggering a redundant
/// signature.
struct CachedCert {
    certified: Arc<CertifiedKey>,
    sans: Arc<[String]>,
}

/// One listener's certificate resolver: the shared [`Issuer`] plus the routing
/// context that decides which names may share a certificate here.
///
/// Bound to a single listener because confinement is a property of a specific
/// routing table. A listener-agnostic resolver could prove a wildcard safe under
/// one listener's routes and then serve it on another where it is not.
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

/// What clipping decided for one host: the names that will be issued, and the
/// proposals that were withheld with the reason for each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipReport {
    /// The coverage anchor (cache/store key within the scope).
    pub base: String,
    /// Names that survived clipping and will be issued.
    pub kept: Vec<String>,
    /// Proposals dropped because some host they cover routes out of scope.
    pub withheld: Vec<(String, Escape)>,
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

    /// Plan the certificate for `sni_host` without issuing it: the anchor, the
    /// names that survive clipping, and what was withheld and why.
    ///
    /// Used by the startup report so an operator can see the effective coverage
    /// (and every clipped wildcard) before any traffic arrives. Returns `None`
    /// when the host matches no route — nothing would be issued for it.
    pub fn plan(&self, sni_host: &str) -> Option<ClipReport> {
        let owner = self.router.match_host(sni_host)?;
        Some(self.clip(sni_host, owner))
    }

    /// The certificate scope of a route id.
    fn scope_of(&self, id: RouteId) -> &CertScope {
        // Indices come from this listener's own router, whose ids are built from
        // the same route vector as `scopes`.
        &self.scopes[id]
    }

    /// Clip the issuance mode's proposal for `sni_host` down to the names that
    /// are confined to `owner`'s certificate scope.
    fn clip(&self, sni_host: &str, owner: RouteId) -> ClipReport {
        let proposal = self.issuer.suffix.plan(sni_host, self.issuer.mode);
        let host = normalize_host(sni_host);
        let scope = self.scope_of(owner).clone();
        let in_scope = |id: RouteId| *self.scope_of(id) == scope;

        let mut kept = Vec::with_capacity(proposal.sans.len());
        let mut withheld = Vec::new();

        for name in &proposal.sans {
            let verdict = match name.strip_prefix("*.") {
                Some(parent) => self.router.wildcard_confined(parent, &in_scope),
                None => self.router.name_confined(name, &in_scope),
            };
            match verdict {
                Ok(()) => kept.push(name.clone()),
                Err(escape) => withheld.push((name.clone(), escape)),
            }
        }

        // The requesting host is always safe for its own scope — it is what
        // resolved `owner` in the first place — so it can be added
        // unconditionally. Needed whenever every proposal was withheld, and
        // whenever the surviving ones do not happen to cover it.
        if !host_covered_by(&kept, &host) {
            kept.push(host);
        }

        ClipReport {
            base: proposal.base,
            kept,
            withheld,
        }
    }

    /// Return a certificate valid for `sni_host`, reusing the scope's cached or
    /// persisted certificate whenever it already covers the host. On a miss the
    /// host's clipped names are **merged** into that certificate and it is
    /// re-issued, so one certificate per `(scope, anchor)` accumulates coverage
    /// and an already-covered host is never re-signed.
    ///
    /// Every name that can enter the accumulator has been clipped against this
    /// listener's routing table for this same scope, so accumulation cannot widen
    /// a certificate past the invariant.
    fn get_or_issue(&self, sni_host: &str, owner: RouteId) -> anyhow::Result<Arc<CertifiedKey>> {
        let issuer = &self.issuer;
        let report = self.clip(sni_host, owner);
        let host = normalize_host(sni_host);
        let scope = self.scope_of(owner).clone();
        let key = CacheKey {
            scope: scope.clone(),
            base: report.base.clone(),
        };

        if let Some(existing) = issuer.cache.get(&key) {
            if host_covered_by(&existing.sans[..], &host) {
                return Ok(existing.certified.clone());
            }
        }

        // Single-flight: only one task issues for a given (scope, anchor).
        let lock = issuer
            .locks
            .get_with(key.clone(), || Arc::new(std::sync::Mutex::new(())));
        let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());

        // Seed the accumulator from the freshest prior coverage for this key
        // (cache, else the on-disk store), so re-issuance never drops names the
        // certificate already covered.
        let mut sans: Vec<String> = Vec::new();

        if let Some(existing) = issuer.cache.get(&key) {
            if host_covered_by(&existing.sans[..], &host) {
                return Ok(existing.certified.clone());
            }
            sans = existing.sans.to_vec();
        } else if let Some(store) = &issuer.store {
            if let Some(stored) = store.load(&scope, &report.base) {
                if host_covered_by(&stored.sans, &host) {
                    let issued_key = any_ecdsa_type(&stored.key).map_err(|e| {
                        anyhow::anyhow!("loading persisted key for {}: {e}", report.base)
                    })?;
                    let certified = Arc::new(CertifiedKey::new(stored.chain, issued_key));
                    issuer.cache.insert(
                        key,
                        Arc::new(CachedCert {
                            certified: certified.clone(),
                            sans: stored.sans.into(),
                        }),
                    );
                    tracing::info!(scope = %scope, base = %report.base, "loaded certificate from store");
                    return Ok(certified);
                }
                sans = stored.sans;
            }
        }

        // Merge in this host's clipped names (dedup) and (re)issue the anchor.
        for name in &report.kept {
            if !sans.iter().any(|s| s == name) {
                sans.push(name.clone());
            }
        }

        let issued = issuer.ca.issue(&report.base, &sans)?;
        let signing_key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(issued.key_der.clone().into()))
            .map_err(|e| anyhow::anyhow!("loading issued key for {}: {e}", report.base))?;
        let certified = Arc::new(CertifiedKey::new(issued.chain.clone(), signing_key));

        if let Some(store) = &issuer.store {
            if let Err(err) = store.save(&scope, &report.base, &issued.chain_pem, &issued.key_pem) {
                // Persistence is best-effort; serving continues from memory.
                tracing::warn!(scope = %scope, base = %report.base, error = %err, "failed to persist certificate");
            }
        }

        if report.withheld.is_empty() {
            tracing::info!(scope = %scope, base = %report.base, sans = ?sans, "issued certificate");
        } else {
            // Not a warning: withholding is the fix doing its job, and it was
            // already reported in full at startup.
            tracing::info!(
                scope = %scope,
                base = %report.base,
                sans = ?sans,
                withheld = ?report.withheld.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                "issued certificate (coverage clipped to this route scope)"
            );
        }
        issuer.cache.insert(
            key,
            Arc::new(CachedCert {
                certified: certified.clone(),
                sans: sans.into(),
            }),
        );
        Ok(certified)
    }
}

/// Normalize an SNI host the way coverage checks expect: lowercase, no trailing
/// dot. Ports never appear in a TLS SNI, so none is stripped here.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
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
        // below blocks: a public-suffix lookup, a keygen and signature, and — the
        // dominant cost by roughly 40x, measured — two file writes plus renames.
        // Blocking a worker on file I/O stalls every other task queued on it, so
        // hand it to the blocking pool instead of the async worker.
        //
        // `block_in_place` rather than `spawn_blocking`: this thread must produce a
        // value before returning, and the certificate must be persisted before it
        // is served, so the work cannot be detached. Moving the save out of the
        // single-flight lock would decouple it, but two successive issuances for one
        // key could then land out of order and persist the narrower certificate.
        // Correct ordering is worth more than the few milliseconds.
        match in_blocking_context(|| self.get_or_issue(host, owner)) {
            Ok(key) => Some(key),
            Err(err) => {
                tracing::error!(host, error = %err, "certificate issuance failed");
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
        mode: IssuanceMode,
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
            store: None,
            mode,
            cache_capacity: 64,
            cache_ttl: Duration::from_secs(60),
        }));
        let router = Arc::new(Router::build(patterns, default).unwrap());
        DynamicResolver::new(issuer, router, scopes.to_vec().into())
    }

    /// The reported bug, at the level where it is decided: an apex on an `ech`
    /// route and its siblings on the default route must not share a wildcard.
    #[test]
    fn wildcard_is_withheld_when_a_sibling_routes_elsewhere() {
        let scopes = [scope(443), scope(22222)];
        let r = resolver(
            &[vec!["site.test".into()], vec![]],
            Some(1),
            &scopes,
            IssuanceMode::Ladder,
        );

        // The apex: ladder would propose {*.site.test, site.test}; the wildcard is
        // withheld because siblings fall to the default route.
        let apex = r.plan("site.test").unwrap();
        assert_eq!(apex.base, "site.test");
        assert_eq!(apex.kept, vec!["site.test"]);
        assert_eq!(
            apex.withheld,
            vec![("*.site.test".to_string(), Escape::DefaultRoute { route: 1 })]
        );

        // The sibling, on the default route. It keeps `*.site.test`: a wildcard
        // matches exactly one label, so it never covers the apex — the only name
        // pinned to another route — and every host it does cover falls to the
        // default route, i.e. its own scope. Clipping takes the *widest safe*
        // certificate, not the narrowest one. What it must drop is the bare apex.
        let sib = r.plan("static.site.test").unwrap();
        assert!(sib.kept.iter().any(|s| s == "*.site.test"));
        assert_eq!(
            sib.withheld,
            vec![(
                "site.test".to_string(),
                Escape::Host {
                    host: "site.test".into(),
                    route: 0
                }
            )]
        );

        // The invariant, stated directly: neither certificate is valid for a name
        // the other's route owns, so no client can coalesce between them.
        assert!(!host_covered_by(&apex.kept, "static.site.test"));
        assert!(!host_covered_by(&sib.kept, "site.test"));
    }

    /// The optimization must survive: names that forward identically still share.
    #[test]
    fn wildcard_is_kept_when_the_whole_domain_shares_one_scope() {
        let scopes = [scope(443)];
        let r = resolver(
            &[vec![".site.test".into()]],
            None,
            &scopes,
            IssuanceMode::Ladder,
        );
        let plan = r.plan("a.site.test").unwrap();
        assert!(
            plan.withheld.is_empty(),
            "nothing should be withheld: {:?}",
            plan.withheld
        );
        assert!(plan.kept.iter().any(|s| s == "*.site.test"));
        // A sibling is covered, so it reuses this certificate with no re-signing.
        assert!(host_covered_by(&plan.kept, "b.site.test"));
    }

    /// Two routes that forward identically are one scope, so they share.
    #[test]
    fn identical_forwarding_shares_one_scope() {
        let scopes = [scope(443), scope(443)];
        let r = resolver(
            &[vec!["a.site.test".into()], vec![".site.test".into()]],
            None,
            &scopes,
            IssuanceMode::Ladder,
        );
        let plan = r.plan("a.site.test").unwrap();
        assert!(
            plan.withheld.is_empty(),
            "same-scope routes must not clip each other: {:?}",
            plan.withheld
        );
        assert!(plan.kept.iter().any(|s| s == "*.site.test"));
    }

    /// `exact` mode needs no clipping — it never proposes a name but the host.
    #[test]
    fn exact_mode_proposes_only_the_host() {
        let scopes = [scope(443), scope(22222)];
        let r = resolver(
            &[vec!["site.test".into()], vec![]],
            Some(1),
            &scopes,
            IssuanceMode::Exact,
        );
        let plan = r.plan("site.test").unwrap();
        assert_eq!(plan.kept, vec!["site.test"]);
        assert!(plan.withheld.is_empty());
    }

    /// A host that matches no route is never issued a certificate.
    #[test]
    fn unmatched_host_has_no_plan() {
        let scopes = [scope(443)];
        let r = resolver(
            &[vec!["site.test".into()]],
            None,
            &scopes,
            IssuanceMode::Ladder,
        );
        assert!(r.plan("elsewhere.test").is_none());
    }

    /// Clipping must still leave a usable certificate for a deep host whose every
    /// ancestor wildcard is withheld.
    #[test]
    fn deep_host_always_gets_at_least_itself() {
        let scopes = [scope(443), scope(22222)];
        let r = resolver(
            &[vec!["b.a.site.test".into()], vec![]],
            Some(1),
            &scopes,
            IssuanceMode::Ladder,
        );
        let plan = r.plan("b.a.site.test").unwrap();
        assert!(host_covered_by(&plan.kept, "b.a.site.test"));
        assert!(
            !plan.withheld.is_empty(),
            "ancestor wildcards must be clipped"
        );
    }
}
