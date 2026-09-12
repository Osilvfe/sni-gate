//! ECH client-config acquisition and assembly.
//!
//! For a route of `type = "ech"`, this resolves the ECHConfigList (from DoH, a
//! static inline value, or DoH-with-static-fallback), turns it into a rustls
//! `ClientConfig` with ECH + TLS 1.3, and caches the result per inner name with
//! background-free TTL refresh. It also supports rebuilding from server-provided
//! `retry_configs` for the ECH retry path (driven by the proxy).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Identifies the resolved ECHConfig generation handed to a connection.
    /// A rejection may evict only the generation that connection actually used.
    generation: u64,
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
    next_generation: AtomicU64,
}

/// A ready-to-use ECH client config handed to the connection path.
pub struct EchClient {
    pub client_config: Arc<ClientConfig>,
    /// Generation of the resolved ECHConfig used by `client_config`.
    pub generation: u64,
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
            next_generation: AtomicU64::new(1),
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
                            generation: c.generation,
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
                    generation: c.generation,
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
                Ok(EchClient {
                    client_config,
                    generation: entry.generation,
                })
            }
            Err(e) => {
                if let Some(c) = guard.get_mut(inner_name) {
                    warn!(inner = %inner_name, error = %e, "ECH refresh failed; keeping cached config");
                    c.refresh_at = Instant::now() + Duration::from_secs(30);
                    return Ok(EchClient {
                        client_config: self.config_for(c, alpn)?,
                        generation: c.generation,
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

    /// Evict the generation rejected by the server and force its next DNS
    /// lookup past hickory's response cache.
    ///
    /// Returns false when another connection has already replaced or evicted
    /// `generation`. In that case its replacement is newer than the config the
    /// caller used, so an old, slower handshake must not remove it again.
    pub async fn invalidate_after_rejection(&self, inner_name: &str, generation: u64) -> bool {
        let mut guard = self.cache.write().await;
        let is_current = guard
            .get(inner_name)
            .is_some_and(|cached| cached.generation == generation);
        if !is_current {
            return false;
        }

        if matches!(
            self.settings.mode,
            SourceMode::Doh | SourceMode::DohWithFallback
        ) {
            self.resolver
                .clear_lookup_cache(&self.lookup_name(inner_name), RecordType::HTTPS);
        }
        guard.remove(inner_name);
        true
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
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AddressFamily;
    use crate::dns::ResolverSpec;
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::thread;

    struct MockHttpsDns {
        port: u16,
        queries: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl MockHttpsDns {
        fn start() -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = socket.local_addr().unwrap().port();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let queries = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_queries = queries.clone();
            let thread_stop = stop.clone();
            let thread = thread::spawn(move || {
                let mut buf = [0u8; 1500];
                while !thread_stop.load(Ordering::Relaxed) {
                    let (len, peer) = match socket.recv_from(&mut buf) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let Some(reply) = https_reply(&buf[..len]) else {
                        continue;
                    };
                    thread_queries.fetch_add(1, Ordering::Relaxed);
                    let _ = socket.send_to(&reply, peer);
                }
            });
            Self {
                port,
                queries,
                stop,
                thread: Some(thread),
            }
        }

        fn query_count(&self) -> usize {
            self.queries.load(Ordering::Relaxed)
        }
    }

    impl Drop for MockHttpsDns {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let wake = UdpSocket::bind("127.0.0.1:0").unwrap();
            let _ = wake.send_to(&[0; 12], ("127.0.0.1", self.port));
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    /// Build a minimal successful DNS response containing one HTTPS RR. Its
    /// service binding has priority 1, target ".", no parameters, and a long
    /// enough TTL for a second lookup to prove that hickory used its cache.
    fn https_reply(query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 17 {
            return None;
        }
        let mut end = 12usize;
        loop {
            let label = *query.get(end)? as usize;
            end += 1;
            if label == 0 {
                break;
            }
            if label & 0xc0 != 0 || end.checked_add(label)? > query.len() {
                return None;
            }
            end += label;
        }
        end = end.checked_add(4)?;
        if end > query.len() || query.get(end - 4..end - 2)? != [0, 65] {
            return None;
        }

        let mut reply = Vec::with_capacity(end + 15);
        reply.extend_from_slice(&query[..2]); // transaction ID
        reply.extend_from_slice(&[0x81, 0x80]); // response, recursion available, no error
        reply.extend_from_slice(&[0, 1]); // one question
        reply.extend_from_slice(&[0, 1]); // one answer
        reply.extend_from_slice(&[0, 0, 0, 0]); // no authority/additional records
        reply.extend_from_slice(&query[12..end]);
        reply.extend_from_slice(&[0xc0, 0x0c]); // answer name points to the question
        reply.extend_from_slice(&[0, 65, 0, 1]); // HTTPS, IN
        reply.extend_from_slice(&60u32.to_be_bytes());
        reply.extend_from_slice(&[0, 3, 0, 1, 0]); // priority 1, target root, no params
        Some(reply)
    }

    fn resolver(spec: &str) -> Arc<DnsResolver> {
        let resolver = ResolverSpec::parse(spec)
            .unwrap()
            .build(AddressFamily::Dual)
            .unwrap();
        DnsResolver::new("test".to_string(), resolver, None, None)
    }

    fn test_provider() -> EchProvider {
        EchProvider::new(
            EffectiveEch {
                mode: SourceMode::Static,
                config: Some(String::new()),
                ech_domain: None,
                max_retries: 1,
            },
            443,
            true,
            true,
            resolver("udp://127.0.0.1:9"),
            Arc::new(webpki_root_store()),
            Duration::from_secs(60),
        )
    }

    fn cached(generation: u64) -> Cached {
        Cached {
            ech_mode: grease_mode().unwrap(),
            configs: HashMap::new(),
            refresh_at: Instant::now() + Duration::from_secs(60),
            generation,
        }
    }

    /// A handshake that started on generation 1 may finish after another task
    /// has installed generation 2. Its late rejection must preserve generation
    /// 2 instead of causing another refresh storm.
    #[tokio::test]
    async fn a_stale_rejection_cannot_evict_a_newer_generation() {
        let provider = test_provider();
        provider
            .cache
            .write()
            .await
            .insert("inner.test".to_string(), cached(2));

        assert!(!provider.invalidate_after_rejection("inner.test", 1).await);
        assert_eq!(
            provider
                .cache
                .read()
                .await
                .get("inner.test")
                .unwrap()
                .generation,
            2
        );

        assert!(provider.invalidate_after_rejection("inner.test", 2).await);
        assert!(!provider.cache.read().await.contains_key("inner.test"));
    }

    /// All probes for one pool normally share a generation and can be rejected
    /// together. Exactly one of them may evict it; the others observe that a
    /// refresh is already in progress instead of starting a refresh storm.
    #[tokio::test]
    async fn concurrent_rejections_grant_one_refresh_for_a_generation() {
        const TASKS: usize = 16;

        let provider = Arc::new(test_provider());
        provider
            .cache
            .write()
            .await
            .insert("inner.test".to_string(), cached(7));
        let barrier = Arc::new(tokio::sync::Barrier::new(TASKS + 1));
        let mut tasks = Vec::with_capacity(TASKS);
        for _ in 0..TASKS {
            let provider = provider.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                provider.invalidate_after_rejection("inner.test", 7).await
            }));
        }
        barrier.wait().await;

        let mut granted = 0usize;
        for task in tasks {
            granted += usize::from(task.await.unwrap());
        }
        assert_eq!(granted, 1);
    }

    /// The provider cache and hickory's DNS response cache are two separate
    /// layers. An ECH rejection must evict both or the rebuild simply receives
    /// the same stale HTTPS RR without touching the upstream resolver.
    #[tokio::test]
    async fn a_rejection_bypasses_the_cached_https_record() {
        let dns = MockHttpsDns::start();
        let resolver = resolver(&format!("udp://127.0.0.1:{}", dns.port));
        let provider = EchProvider::new(
            EffectiveEch {
                mode: SourceMode::Doh,
                config: None,
                ech_domain: None,
                max_retries: 1,
            },
            443,
            true,
            true,
            resolver.clone(),
            Arc::new(webpki_root_store()),
            Duration::from_secs(60),
        );

        resolver
            .lookup("inner.test", RecordType::HTTPS)
            .await
            .unwrap();
        resolver
            .lookup("inner.test", RecordType::HTTPS)
            .await
            .unwrap();
        assert_eq!(dns.query_count(), 1, "the second lookup should be cached");

        provider
            .cache
            .write()
            .await
            .insert("inner.test".to_string(), cached(9));
        assert!(provider.invalidate_after_rejection("inner.test", 9).await);

        resolver
            .lookup("inner.test", RecordType::HTTPS)
            .await
            .unwrap();
        assert_eq!(
            dns.query_count(),
            2,
            "the post-rejection lookup must reach DNS again"
        );
    }
}
