//! `ResolvesServerCert` implementation that mints (and caches) a certificate
//! for whatever SNI host name the client presents during the TLS handshake.
//!
//! Lookup order for each SNI host:
//!   1. In-memory cache, keyed by the wildcard base (so every sibling
//!      subdomain of `a.com` shares one cached certificate).
//!   2. On-disk store (if persistence is enabled), re-hydrated into the cache.
//!   3. Fresh issuance from the CA, then persisted and cached.
//!
//! Issuance for a given base is de-duplicated (single-flight), so a burst of
//! concurrent first-time handshakes signs the certificate only once.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::ca::CertificateAuthority;
use crate::config::IssuanceMode;
use crate::store::CertStore;
use crate::suffix::{host_covered_by, SuffixList};

/// Resolves a server certificate per SNI, issuing on demand and caching the
/// result by wildcard base name.
pub struct DynamicResolver {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for DynamicResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicResolver")
            .field("cache_entries", &self.inner.cache.entry_count())
            .finish()
    }
}

/// A cached certificate plus the names it covers, so a sibling host can reuse it
/// (via [`host_covered_by`]) instead of triggering a redundant signature.
struct CachedCert {
    certified: Arc<CertifiedKey>,
    sans: Arc<[String]>,
}

struct Inner {
    ca: CertificateAuthority,
    suffix: Arc<SuffixList>,
    store: Option<CertStore>,
    mode: IssuanceMode,
    cache: moka::sync::Cache<String, Arc<CachedCert>>,
    /// Per-base locks providing single-flight issuance.
    locks: moka::sync::Cache<String, Arc<std::sync::Mutex<()>>>,
}

/// Construction parameters for [`DynamicResolver`].
pub struct ResolverParams {
    pub ca: CertificateAuthority,
    pub suffix: Arc<SuffixList>,
    pub store: Option<CertStore>,
    pub mode: IssuanceMode,
    pub cache_capacity: u64,
    pub cache_ttl: Duration,
}

impl DynamicResolver {
    pub fn new(params: ResolverParams) -> Self {
        let cache = moka::sync::Cache::builder()
            .max_capacity(params.cache_capacity)
            .time_to_live(params.cache_ttl)
            .build();
        let locks = moka::sync::Cache::builder()
            .max_capacity(params.cache_capacity)
            .time_to_idle(Duration::from_secs(60))
            .build();
        Self {
            inner: Arc::new(Inner {
                ca: params.ca,
                suffix: params.suffix,
                store: params.store,
                mode: params.mode,
                cache,
                locks,
            }),
        }
    }

    /// Return a certificate valid for `sni_host`, reusing the registrable
    /// domain's cached or persisted certificate whenever it already covers the
    /// host. On a miss, the host's required names are **merged** into that
    /// certificate and it is re-issued, so one `<registrable>.crt` accumulates
    /// coverage for the whole domain and an already-covered host is never
    /// re-signed.
    fn get_or_issue(&self, sni_host: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        let inner = &self.inner;

        // Plan the anchor (cache/store key = registrable domain) and the names
        // this host needs. `host` is the normalized SNI we check coverage for.
        let certificand = inner.suffix.plan(sni_host, inner.mode);
        let base = certificand.base.clone();
        let host = sni_host.trim_end_matches('.').to_ascii_lowercase();

        if let Some(existing) = inner.cache.get(&base) {
            if host_covered_by(&existing.sans[..], &host) {
                return Ok(existing.certified.clone());
            }
        }

        // Single-flight: only one task issues for a given anchor at a time.
        let lock = inner
            .locks
            .get_with(base.clone(), || Arc::new(std::sync::Mutex::new(())));
        let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());

        // Seed the accumulator from the freshest prior coverage for this anchor
        // (cache, else the on-disk store), so re-issuance never drops names the
        // certificate already covered.
        let mut sans: Vec<String> = Vec::new();

        if let Some(existing) = inner.cache.get(&base) {
            if host_covered_by(&existing.sans[..], &host) {
                return Ok(existing.certified.clone());
            }
            sans = existing.sans.to_vec();
        } else if let Some(store) = &inner.store {
            if let Some(stored) = store.load(&base) {
                if host_covered_by(&stored.sans, &host) {
                    let key = any_ecdsa_type(&stored.key)
                        .map_err(|e| anyhow::anyhow!("loading persisted key for {base}: {e}"))?;
                    let certified = Arc::new(CertifiedKey::new(stored.chain, key));
                    inner.cache.insert(
                        base.clone(),
                        Arc::new(CachedCert {
                            certified: certified.clone(),
                            sans: stored.sans.into(),
                        }),
                    );
                    tracing::info!(base = %base, "loaded certificate from store");
                    return Ok(certified);
                }
                sans = stored.sans;
            }
        }

        // Merge in this host's required names (dedup) and (re)issue the anchor.
        for name in &certificand.sans {
            if !sans.iter().any(|s| s == name) {
                sans.push(name.clone());
            }
        }

        let issued = inner.ca.issue(&base, &sans)?;
        let key = any_ecdsa_type(&PrivateKeyDer::Pkcs8(issued.key_der.clone().into()))
            .map_err(|e| anyhow::anyhow!("loading issued key for {base}: {e}"))?;
        let certified = Arc::new(CertifiedKey::new(issued.chain.clone(), key));

        if let Some(store) = &inner.store {
            if let Err(err) = store.save(&base, &issued.chain_pem, &issued.key_pem) {
                // Persistence is best-effort; serving continues from memory.
                tracing::warn!(base = %base, error = %err, "failed to persist certificate");
            }
        }

        tracing::info!(base = %base, sans = ?sans, "issued certificate");
        inner.cache.insert(
            base,
            Arc::new(CachedCert {
                certified: certified.clone(),
                sans: sans.into(),
            }),
        );
        Ok(certified)
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

        match self.get_or_issue(host) {
            Ok(key) => Some(key),
            Err(err) => {
                tracing::error!(host, error = %err, "certificate issuance failed");
                None
            }
        }
    }
}
