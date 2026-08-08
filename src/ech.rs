//! ECH client-config acquisition and assembly.
//!
//! For a route of `type = "ech"`, this resolves the ECHConfigList (from DoH, a
//! static inline value, or DoH-with-static-fallback), turns it into a rustls
//! `ClientConfig` with ECH + TLS 1.3, and caches the result per inner name with
//! background-free TTL refresh. It also supports rebuilding from server-provided
//! `retry_configs` for the ECH retry path (driven by the proxy).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
use hickory_resolver::proto::rr::{RData, RecordType};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke::{ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128};
use rustls::crypto::hpke::Hpke as _;
use rustls::pki_types::EchConfigListBytes;
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::config::{EchMode as SourceMode, EffectiveEch};
use crate::dns_resolvers::DnsResolver;
use crate::error::EchError;

/// A resolved ECH mode plus its refresh deadline, and the `ClientConfig`s
/// assembled from it so far.
///
/// The ECHConfigList is fetched once per inner name, but the ALPN protocols we
/// offer upstream vary per connection (they are the intersection of what the
/// client offered and what the route allows — see the ALPN mirroring path in
/// `proxy.rs`). Since ALPN is a `ClientConfig` field, each distinct offer needs
/// its own config. We therefore keep the expensive part (the resolved
/// [`EchMode`], which required a DoH lookup) and memoize the cheap assembly
/// keyed by the ALPN list. The key space is tiny and bounded: `[]`, `[h2]`,
/// `[http/1.1]`, `[h2, http/1.1]`.
#[derive(Clone)]
struct Cached {
    ech_mode: EchMode,
    configs: HashMap<Vec<Vec<u8>>, Arc<ClientConfig>>,
    refresh_at: Instant,
}

/// Per-route ECH provider, caching a client config per inner name.
pub struct EchProvider {
    settings: EffectiveEch,
    /// Fixed upstream port, used for RFC 9460 port-prefix HTTPS lookups.
    upstream_port: u16,
    require_ech: bool,
    /// Whether the protected ClientHelloInner carries a `server_name`
    /// extension. False when the route sets `override_sni = ""`; RFC 9849 §5
    /// permits an inner hello with no SNI. The ECHConfig's public name is still
    /// sent in the *outer* hello either way (the client-facing server needs it),
    /// and the upstream certificate is still verified against the inner name.
    enable_sni: bool,
    resolver: Arc<DnsResolver>,
    root_store: Arc<RootCertStore>,
    refresh_bound: Duration,
    cache: RwLock<HashMap<String, Cached>>,
}

/// A ready-to-use ECH client config handed to the connection path.
pub struct EchClient {
    pub client_config: Arc<ClientConfig>,
}

impl EchProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settings: EffectiveEch,
        upstream_port: u16,
        require_ech: bool,
        enable_sni: bool,
        resolver: Arc<DnsResolver>,
        root_store: Arc<RootCertStore>,
        refresh_bound: Duration,
    ) -> Self {
        Self {
            settings,
            upstream_port,
            require_ech,
            enable_sni,
            resolver,
            root_store,
            refresh_bound,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Return a client config with ECH set up for `inner_name` offering `alpn`
    /// upstream, (re)building from the source when the cached entry is missing or
    /// stale. On refresh failure the previous good entry is kept.
    ///
    /// `alpn` is the ALPN protocol list to advertise to the upstream (empty for
    /// no ALPN extension at all). Configs are memoized per (inner name, ALPN), so
    /// varying ALPN never triggers a redundant DoH lookup.
    pub async fn client(&self, inner_name: &str, alpn: &[Vec<u8>]) -> Result<EchClient, EchError> {
        // Fast path: a fresh entry that has already assembled this ALPN offer.
        {
            let guard = self.cache.read().await;
            if let Some(c) = guard.get(inner_name) {
                if Instant::now() < c.refresh_at {
                    if let Some(cfg) = c.configs.get(alpn) {
                        return Ok(EchClient {
                            client_config: cfg.clone(),
                        });
                    }
                }
            }
        }

        let mut guard = self.cache.write().await;
        if let Some(c) = guard.get_mut(inner_name) {
            if Instant::now() < c.refresh_at {
                // Fresh ECH config, but this ALPN offer is new: assemble it from
                // the already-resolved mode without re-fetching.
                return Ok(EchClient {
                    client_config: self.config_for(c, alpn)?,
                });
            }
        }

        match self.build(inner_name).await {
            Ok(fresh) => {
                // Replace any stale entry outright: the ECHConfig (and therefore
                // every config assembled from it) is superseded.
                guard.insert(inner_name.to_string(), fresh);
                let entry = guard.get_mut(inner_name).expect("just inserted this entry");
                let client_config = self.config_for(entry, alpn)?;
                Ok(EchClient { client_config })
            }
            Err(e) => {
                if let Some(c) = guard.get_mut(inner_name) {
                    warn!(inner = %inner_name, error = %e, "ECH refresh failed; keeping cached config");
                    c.refresh_at = Instant::now() + Duration::from_secs(30);
                    return Ok(EchClient {
                        client_config: self.config_for(c, alpn)?,
                    });
                }
                Err(e)
            }
        }
    }

    /// Get (or assemble and memoize) the `ClientConfig` for `alpn` from an
    /// already-resolved cache entry.
    fn config_for(
        &self,
        cached: &mut Cached,
        alpn: &[Vec<u8>],
    ) -> Result<Arc<ClientConfig>, EchError> {
        if let Some(cfg) = cached.configs.get(alpn) {
            return Ok(cfg.clone());
        }
        let mut config = self.assemble_client_config(cached.ech_mode.clone())?;
        config.alpn_protocols = alpn.to_vec();
        let config = Arc::new(config);
        cached.configs.insert(alpn.to_vec(), Arc::clone(&config));
        Ok(config)
    }

    /// Evict the cached config for `inner_name` so the next `client()` call
    /// re-fetches a fresh ECHConfig. Used by the ECH retry path after the server
    /// rejects ECH (its published key rotated).
    pub async fn invalidate(&self, inner_name: &str) {
        self.cache.write().await.remove(inner_name);
    }

    async fn build(&self, inner_name: &str) -> Result<Cached, EchError> {
        let (ech_bytes, ttl) = self.acquire_config_list(inner_name).await?;

        let (mode, real_ech) = match ech_bytes {
            Some(bytes) => (build_real_ech_mode(bytes)?, true),
            None => {
                if self.require_ech {
                    return Err(EchError::NoRecord(self.lookup_name(inner_name)));
                }
                warn!(inner = %inner_name, "no ECHConfig; sending GREASE (require_ech = false)");
                (grease_mode()?, false)
            }
        };

        let refresh = ttl
            .map(|t| t.min(self.refresh_bound))
            .unwrap_or(self.refresh_bound)
            .max(Duration::from_secs(5));

        debug!(inner = %inner_name, real_ech, refresh_secs = refresh.as_secs(), "resolved ECH mode");
        Ok(Cached {
            ech_mode: mode,
            configs: HashMap::new(),
            refresh_at: Instant::now() + refresh,
        })
    }

    async fn acquire_config_list(
        &self,
        inner_name: &str,
    ) -> Result<(Option<EchConfigListBytes<'static>>, Option<Duration>), EchError> {
        match self.settings.mode {
            SourceMode::Static => {
                let cfg = self
                    .settings
                    .config
                    .as_deref()
                    .ok_or_else(|| EchError::NoCompatibleConfig)?;
                Ok((Some(decode_ech_b64(cfg)?), None))
            }
            SourceMode::Doh => match self.lookup_doh(inner_name).await {
                Ok(Some((b, ttl))) => Ok((Some(b), ttl)),
                Ok(None) => Ok((None, None)),
                Err(e) => Err(e),
            },
            SourceMode::DohWithFallback => match self.lookup_doh(inner_name).await {
                Ok(Some((b, ttl))) => Ok((Some(b), ttl)),
                _ => {
                    let cfg = self
                        .settings
                        .config
                        .as_deref()
                        .ok_or_else(|| EchError::NoCompatibleConfig)?;
                    warn!(inner = %inner_name, "DoH ECH lookup empty; using static fallback");
                    Ok((Some(decode_ech_b64(cfg)?), None))
                }
            },
        }
    }

    /// The DNS name whose HTTPS record carries `ech=`. Uses the configured
    /// `ech_domain` if set, else the inner name; RFC 9460 port-prefix for non-443.
    fn lookup_name(&self, inner_name: &str) -> String {
        let base = self.settings.ech_domain.as_deref().unwrap_or(inner_name);
        https_lookup_name(base, self.upstream_port)
    }

    async fn lookup_doh(
        &self,
        inner_name: &str,
    ) -> Result<Option<(EchConfigListBytes<'static>, Option<Duration>)>, EchError> {
        let name = self.lookup_name(inner_name);
        let lookup = self
            .resolver
            .lookup(&name, RecordType::HTTPS)
            .await
            .map_err(|e| EchError::Lookup {
                name: name.clone(),
                source: e,
            })?;

        for record in lookup.answers() {
            let ttl = Some(Duration::from_secs(record.ttl as u64));
            if let RData::HTTPS(https) = &record.data {
                for (_key, value) in &https.svc_params {
                    if let SvcParamValue::EchConfigList(list) = value {
                        let bytes = EchConfigListBytes::from(list.0.clone());
                        return Ok(Some((bytes, ttl)));
                    }
                }
            }
        }
        Ok(None)
    }

    fn assemble_client_config(&self, ech_mode: EchMode) -> Result<ClientConfig, EchError> {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let mut config = ClientConfig::builder_with_provider(provider.into())
            .with_ech(ech_mode)
            .map_err(EchError::Rustls)?
            .with_root_certificates(self.root_store.as_ref().clone())
            .with_no_client_auth();
        config.enable_sni = self.enable_sni;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for route and resolver ECH
// ---------------------------------------------------------------------------

/// Port-prefixed HTTPS record name per RFC 9460.
pub fn https_lookup_name(base: &str, port: u16) -> String {
    match port {
        443 => base.to_string(),
        p => format!("_{p}._https.{base}"),
    }
}

/// Web-PKI root store from webpki-roots.
pub fn webpki_root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// ECH rejection detection (shared by the route path and the resolver path)
// ---------------------------------------------------------------------------

/// Whether an `io::Error` is rustls's "server rejected ECH" signal.
///
/// tokio-rustls surfaces rustls errors wrapped in `io::Error`, so this downcasts
/// to the typed `rustls::Error` and matches the exact
/// `PeerIncompatible::ServerRejectedEncryptedClientHello` variant. It
/// deliberately does **not** match on the Display string: an unrelated error
/// that merely contains "ECH" would false-positive, and a false positive here
/// triggers a pointless refetch-and-retry cycle that hides the real failure.
///
/// This lives in `ech` rather than in `proxy` because two independent paths need
/// the same verdict — a route's upstream handshake and a resolver's own
/// handshake. Sharing the function is what keeps them from drifting apart.
pub fn is_ech_reject_io(e: &std::io::Error) -> bool {
    matches!(
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
        ))
    )
}

/// Whether anything in an `anyhow` error chain is an ECH rejection.
///
/// The resolver path returns `anyhow::Error`, and hickory wraps transport errors
/// several layers deep, so the rejection can be at any depth. Both the
/// `rustls::Error` case and the `io::Error`-wrapping-`rustls::Error` case are
/// checked at every link: the inner error of an `io::Error` is not part of the
/// `source()` chain, so walking sources alone would miss it.
pub fn is_ech_reject_chain(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(r) = cause.downcast_ref::<rustls::Error>() {
            if matches!(
                r,
                rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
                )
            ) {
                return true;
            }
        }
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(is_ech_reject_io)
    })
}

/// Decode a base64 ECHConfigList.
fn decode_ech_b64(s: &str) -> Result<EchConfigListBytes<'static>, EchError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(EchError::Base64)?;
    Ok(EchConfigListBytes::from(raw))
}

/// Build a real-ECH mode, selecting a compatible HPKE suite.
fn build_real_ech_mode(bytes: EchConfigListBytes<'static>) -> Result<EchMode, EchError> {
    let config =
        EchConfig::new(bytes, ALL_SUPPORTED_SUITES).map_err(|_| EchError::NoCompatibleConfig)?;
    Ok(EchMode::from(config))
}

/// Build a GREASE mode (anti-ossification placeholder).
fn grease_mode() -> Result<EchMode, EchError> {
    let suite = DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (public_key, _secret) = suite.generate_key_pair().map_err(EchError::Rustls)?;
    Ok(EchMode::from(EchGreaseConfig::new(suite, public_key)))
}

// ---------------------------------------------------------------------------
// Resolver-side ECH
// ---------------------------------------------------------------------------

/// ECH mode for a resolver: real config, GREASE, or disabled.
#[derive(Debug, Clone, Copy)]
pub enum ResolverEch<'a> {
    /// No ECH for this resolver.
    Disabled,
    /// Real ECH from these bytes.
    Config(&'a [u8]),
    /// ECH wanted but no published config; send GREASE.
    Grease,
}

/// Build a `ClientConfig` for a resolver, with ECH when configured.
///
/// This is the resolver analogue of `EchProvider::assemble_client_config`.
pub fn resolver_client_config(
    mode: ResolverEch<'_>,
    enable_sni: bool,
    root_store: &RootCertStore,
) -> Result<ClientConfig, EchError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut config = match mode {
        ResolverEch::Config(bytes) => {
            let list = EchConfigListBytes::from(bytes.to_vec());
            let ech_mode = build_real_ech_mode(list)?;
            ClientConfig::builder_with_provider(provider.into())
                .with_ech(ech_mode)
                .map_err(EchError::Rustls)?
                .with_root_certificates(root_store.clone())
                .with_no_client_auth()
        }
        ResolverEch::Grease => {
            let ech_mode = grease_mode()?;
            ClientConfig::builder_with_provider(provider.into())
                .with_ech(ech_mode)
                .map_err(EchError::Rustls)?
                .with_root_certificates(root_store.clone())
                .with_no_client_auth()
        }
        ResolverEch::Disabled => {
            // Plain TLS without ECH.
            ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(EchError::Rustls)?
                .with_root_certificates(root_store.clone())
                .with_no_client_auth()
        }
    };
    config.enable_sni = enable_sni;
    // ALPN deliberately left empty: hickory sets h2 for DoH when unset.
    Ok(config)
}

/// Acquire the ECHConfigList for a resolver, honoring the mode.
pub async fn acquire_resolver_ech(
    settings: &crate::config::EffectiveEch,
    name: &str,
    resolver: &Arc<crate::dns_resolvers::DnsResolver>,
) -> Result<Option<Vec<u8>>, anyhow::Error> {
    use crate::config::EchMode as SourceMode;
    match settings.mode {
        SourceMode::Static => {
            let cfg = settings
                .config
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("static ECH mode needs a config"))?;
            Ok(Some(decode_ech_b64(cfg)?.as_ref().to_vec()))
        }
        SourceMode::Doh => {
            let lookup = resolver.lookup(name, RecordType::HTTPS).await?;
            Ok(extract_ech_from_lookup(&lookup))
        }
        SourceMode::DohWithFallback => {
            match resolver.lookup(name, RecordType::HTTPS).await {
                Ok(lookup) => {
                    if let Some(bytes) = extract_ech_from_lookup(&lookup) {
                        return Ok(Some(bytes));
                    }
                    // DoH lookup succeeded but no ech= param: fall back.
                    let cfg = settings
                        .config
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("doh-with-fallback needs a config"))?;
                    Ok(Some(decode_ech_b64(cfg)?.as_ref().to_vec()))
                }
                Err(_) => {
                    // DoH lookup failed: fall back to static.
                    let cfg = settings
                        .config
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("doh-with-fallback needs a config"))?;
                    Ok(Some(decode_ech_b64(cfg)?.as_ref().to_vec()))
                }
            }
        }
    }
}

/// Extract the ech= SvcParam from an HTTPS lookup.
fn extract_ech_from_lookup(lookup: &hickory_resolver::lookup::Lookup) -> Option<Vec<u8>> {
    use hickory_resolver::proto::rr::{rdata::svcb::SvcParamValue, RData};
    for record in lookup.answers() {
        if let RData::HTTPS(https) = &record.data {
            for (_key, value) in &https.svc_params {
                if let SvcParamValue::EchConfigList(list) = value {
                    return Some(list.0.clone());
                }
            }
        }
    }
    None
}
