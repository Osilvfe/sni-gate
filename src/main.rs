//! sni-gate — a multi-listener SNI/Host-routing TLS gateway.
//!
//! Each inbound port routes connections by TLS SNI (or HTTP Host) to an
//! upstream that may be ECH, plain TLS, cleartext HTTP, or raw passthrough.
//! Whenever it terminates TLS it issues a certificate for that name and its
//! wildcard from a local CA (persisted, cached, public-suffix-aware).

mod ca;
mod certscope;
pub mod config;
mod dns;
mod dns_resolvers;
mod ech;
mod error;
mod nat64;
mod peek;
mod probe;
mod proxy;
mod psl;
mod quic_initial;
mod quic_proxy;
mod resolver;
mod router;
mod store;
mod suffix;
mod trust;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use rustls::{RootCertStore, ServerConfig};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::ca::{CaParams, CertificateAuthority};
use crate::certscope::{CertScope, EchIdentity, Forwarding};
use crate::config::{Config, Listener, ListenerTransport, Route, RouteType};
use crate::dns::ResolverSpec;
use crate::ech::EchProvider;
use crate::nat64::Nat64Prefix;
use crate::proxy::{ListenerState, RouteRuntime, ServerConfigs};
use crate::resolver::{DynamicResolver, Issuer, IssuerParams};
use crate::router::Router;
use crate::store::CertStore;

/// Resolver cache key: (spec string, address family).
type ResolverCache = HashMap<(String, config::AddressFamily), Arc<hickory_resolver::TokioResolver>>;

/// One `http` route whose backend should be checked for h2c at startup.
///
/// Collected while building routes (the only place the effective HTTP/2 policy
/// and the resolved upstream are both in hand) and consumed once, before the
/// listeners start accepting. Kept out of `RouteRuntime` because none of it is
/// needed on the data path.
struct ProbeTarget {
    route: String,
    host: String,
    port: u16,
    policy: config::H2Probe,
    budget: Duration,
    resolver: Arc<dns_resolvers::DnsResolver>,
    family: config::AddressFamily,
    nat64: Option<Nat64Prefix>,
}

#[derive(Debug, Parser)]
#[command(
    name = "sni-gate",
    version,
    about = "SNI/Host-routing TLS gateway with dynamic cert issuance and ECH"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "sni-gate.toml")]
    config: PathBuf,

    /// Install the CA into the OS trusted-root store, then exit. Generates the
    /// CA first if the `[ca]` paths are empty. Idempotent; needs elevated
    /// privileges (Administrator on Windows, root/sudo on macOS/Linux).
    #[arg(long)]
    install_ca: bool,
}

fn main() -> ExitCode {
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("fatal: failed to install the aws-lc-rs crypto provider");
        return ExitCode::FAILURE;
    }

    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::FAILURE;
        }
    };
    init_tracing(&cfg.global.log);

    if cli.install_ca {
        return match install_ca(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!(error = %format!("{e:#}"), "CA installation failed");
                ExitCode::FAILURE
            }
        };
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "failed to build tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %format!("{e:#}"), "fatal");
            ExitCode::FAILURE
        }
    }
}

/// Load the configured CA, generating it on first use.
fn load_ca(cfg: &Config) -> Result<CertificateAuthority> {
    CertificateAuthority::load_or_generate(CaParams {
        cert_path: &cfg.ca.cert_path,
        key_path: &cfg.ca.key_path,
        common_name: &cfg.ca.common_name,
        organization: &cfg.ca.organization,
        country: &cfg.ca.country,
        leaf_validity_days: cfg.ca.leaf_validity_days,
    })
    .context("initializing certificate authority")
}

/// `--install-ca`: put the CA in the OS trusted-root store and stop.
///
/// Unlike the startup path, a failure here is the whole point of the run, so
/// it propagates and sets a non-zero exit code.
fn install_ca(cfg: &Config) -> Result<()> {
    let ca = load_ca(cfg)?;
    let outcome = trust::ensure_installed(ca.cert_der())
        .context("installing the CA into the OS trusted-root store")?;
    log_ca_installed(&outcome);
    Ok(())
}

fn log_ca_installed(outcome: &trust::Outcome) {
    let fingerprint = outcome.fingerprint();
    match outcome {
        trust::Outcome::Installed { .. } => {
            tracing::warn!(fingerprint, "installed CA into the OS trusted-root store");
        }
        trust::Outcome::AlreadyTrusted { .. } => {
            info!(fingerprint, "CA already trusted; store unchanged");
        }
    }
}

async fn run(cfg: Config) -> Result<()> {
    let runtime_listeners = cfg
        .expanded_listeners()
        .context("expanding automatic HTTP/3 companion listeners")?;
    log_http3_expansion(&cfg)?;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        configured_listeners = cfg.listeners.len(),
        listeners = runtime_listeners.len(),
        "starting sni-gate"
    );

    // --- Dynamic certificate stack (shared across all listeners) ---
    let ca = load_ca(&cfg)?;

    if cfg.ca.install_to_system_root {
        // A gateway that cannot reach the root store still serves traffic, so
        // this is a warning rather than a startup failure.
        match trust::ensure_installed(ca.cert_der()) {
            Ok(outcome) => log_ca_installed(&outcome),
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "could not install CA into system root store");
            }
        }
    }

    let suffix = psl::init(&cfg.psl)
        .await
        .context("initializing public suffix list")?;

    let store = if cfg.store.enabled {
        let s = CertStore::new(cfg.store.dir.clone(), cfg.store.renew_margin_days);
        s.init().context("initializing certificate store")?;
        Some(s)
    } else {
        None
    };

    // The issuance machinery, shared by every listener. Each listener then binds
    // it to its own routing table (see `build_listener`), because which names may
    // share a certificate is a property of *that listener's* routes.
    let issuer = Arc::new(Issuer::new(IssuerParams {
        ca,
        suffix,
        store,
        cache_capacity: cfg.cache.capacity,
        cache_ttl: Duration::from_secs(cfg.cache.ttl_secs),
    }));

    // Shared web-PKI roots for upstream TLS verification.
    let root_store = Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    });

    let mut resolver_cache: ResolverCache = HashMap::new();

    // --- Build named resolvers in dependency order ---
    let named_resolvers = build_named_resolvers(&cfg, &mut resolver_cache).await?;

    let mut probe_targets: Vec<ProbeTarget> = Vec::new();

    // --- Build configured listeners plus automatic HTTP/3 companions ---
    let mut listener_states: Vec<Arc<ListenerState>> = Vec::new();
    for listener in &runtime_listeners {
        let state = build_listener(
            &cfg,
            listener,
            issuer.clone(),
            root_store.clone(),
            &named_resolvers,
            &mut resolver_cache,
            &mut probe_targets,
        )?;
        listener_states.push(Arc::new(state));
    }

    // --- Validate h2c backends before serving ---
    run_probes(probe_targets).await?;

    // --- Spawn all listeners ---
    let mut set = tokio::task::JoinSet::new();
    for st in listener_states {
        let addr = st.addr;
        set.spawn(async move {
            match st.transport {
                ListenerTransport::Tcp => proxy::serve(st).await,
                ListenerTransport::Quic => quic_proxy::serve(st).await,
            }
            .with_context(|| format!("listener {addr}"))
        });
    }

    tokio::select! {
        Some(joined) = set.join_next() => {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(e).context("listener task panicked"),
            }
        }
        _ = shutdown_signal() => info!("shutdown signal received; exiting"),
    }
    Ok(())
}

/// Log automatic HTTP/3 expansion decisions that matter to operators.
fn log_http3_expansion(cfg: &Config) -> Result<()> {
    for listener in cfg
        .listeners
        .iter()
        .filter(|l| l.transport == ListenerTransport::Tcp)
    {
        let explicit_quic = cfg
            .listeners
            .iter()
            .any(|q| q.transport == ListenerTransport::Quic && q.addr == listener.addr);
        let companion = cfg.http3_companion_listener(listener)?;
        if explicit_quic {
            if companion.is_some() {
                info!(
                    addr = %listener.addr,
                    "explicit QUIC listener owns this address; automatic HTTP/3 companion suppressed"
                );
            }
            continue;
        }

        let ln_tpl = cfg.template_for(&listener.use_template)?;
        for route in listener.routes.iter().chain(listener.default_route.iter()) {
            let rt_tpl = cfg.template_for(&route.use_template)?;
            if !cfg.effective_http3(listener, route, rt_tpl, ln_tpl).enabled {
                continue;
            }
            let Some(route_type) = Config::effective_route_type(route, rt_tpl) else {
                continue;
            };
            if Config::http3_companion_route_type(route_type).is_none() {
                warn!(
                    addr = %listener.addr,
                    route = %route.label(),
                    route_type = ?route_type,
                    "automatic HTTP/3 companion skipped: route type has no H3 mapping"
                );
            }
        }
        if let Some(companion) = companion {
            info!(
                addr = %companion.addr,
                routes = companion.routes.len(),
                has_default_route = companion.default_route.is_some(),
                "automatic HTTP/3 companion listener enabled"
            );
        }
    }
    Ok(())
}

/// Assemble one listener's router + route runtimes from config.
fn build_listener(
    cfg: &Config,
    listener: &Listener,
    issuer: Arc<Issuer>,
    root_store: Arc<RootCertStore>,
    named_resolvers: &HashMap<String, Arc<dns_resolvers::DnsResolver>>,
    resolver_cache: &mut ResolverCache,
    probe_targets: &mut Vec<ProbeTarget>,
) -> Result<ListenerState> {
    let mut runtimes: Vec<Arc<RouteRuntime>> = Vec::new();
    let mut patterns: Vec<Vec<String>> = Vec::new();
    let mut forwardings: Vec<Forwarding> = Vec::new();

    for route in &listener.routes {
        let built = build_route(
            cfg,
            listener,
            route,
            &root_store,
            named_resolvers,
            resolver_cache,
            probe_targets,
        )?;
        runtimes.push(Arc::new(built.runtime));
        forwardings.push(built.forwarding);
        patterns.push(route.match_sni.clone());
    }

    let default_id = if let Some(d) = &listener.default_route {
        let id = runtimes.len();
        let built = build_route(
            cfg,
            listener,
            d,
            &root_store,
            named_resolvers,
            resolver_cache,
            probe_targets,
        )?;
        runtimes.push(Arc::new(built.runtime));
        forwardings.push(built.forwarding);
        patterns.push(Vec::new());
        Some(id)
    } else {
        None
    };

    let router = Arc::new(
        Router::build(&patterns, default_id, &cfg.regexes)
            .map_err(|e| anyhow::anyhow!("listener {}: {e}", listener.addr))?,
    );

    // Certificate scopes. The routing table is part of a scope's identity because
    // a wildcard proven confined under these routes may not be confined under
    // another listener's — see `certscope`.
    let router_fp = certscope::router_fingerprint(&patterns, default_id, &cfg.regexes);
    let scopes: Arc<[CertScope]> = forwardings
        .iter()
        .map(|f| CertScope::new(router_fp, f))
        .collect::<Vec<_>>()
        .into();

    // This listener's certificate resolver: the shared issuer bound to this
    // routing table.
    let cert_resolver = Arc::new(DynamicResolver::new(issuer, router.clone(), scopes.clone()));

    warn_on_raw_overlap(listener, &runtimes, &patterns, cfg);

    // One base server config for local termination; the resolver issues for any
    // routable SNI. It is then cloned into the ALPN variants the data path selects
    // between (see `ServerConfigs`): the clones share the cert resolver, ticketer
    // and session cache, and differ only in `alpn_protocols`.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver.clone());
    if let Ok(t) = rustls::crypto::aws_lc_rs::Ticketer::new() {
        server_config.ticketer = t;
    }
    server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(8192);

    let with_alpn = |protocols: Vec<Vec<u8>>| {
        let mut c = server_config.clone();
        c.alpn_protocols = protocols;
        Arc::new(c)
    };
    let server_configs = Arc::new(ServerConfigs {
        none: with_alpn(Vec::new()),
        h1: with_alpn(vec![b"http/1.1".to_vec()]),
        h2: with_alpn(vec![b"h2".to_vec()]),
        h2h1: with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        h3: with_alpn(vec![b"h3".to_vec()]),
    });

    Ok(ListenerState {
        addr: listener.addr,
        transport: listener.transport,
        router,
        routes: runtimes,
        server_configs,
        cert_resolver,
        unmatched: cfg.global.unmatched.clone(),
    })
}

/// Warn when a `raw` route shares a registrable domain with a terminating route.
///
/// A `raw` route never terminates TLS, so the client sees the **upstream's** own
/// certificate and this gateway cannot clip it. If that certificate is a wildcard
/// covering names this listener routes elsewhere, a client can coalesce onto the
/// raw connection and escape routing — a case the issuance-side fix cannot reach.
/// Detect the shape and say so plainly rather than imply it is covered.
fn warn_on_raw_overlap(
    listener: &Listener,
    runtimes: &[Arc<RouteRuntime>],
    patterns: &[Vec<String>],
    cfg: &Config,
) {
    // Registrable-domain approximation good enough for a warning: the last two
    // labels of a pattern's base name. Being over-eager here only widens a
    // warning, never narrows a certificate.
    let apex = |pat: &str| -> Vec<String> {
        let pat = pat.trim();

        // Named regex: extract apex from its declared scope_suffix
        if let Some(name) = pat.strip_prefix('@') {
            if let Ok(def) = cfg.regex_def(name) {
                return def
                    .scope_suffix
                    .iter()
                    .filter_map(|scope| {
                        let base = scope
                            .trim()
                            .trim_start_matches("*.")
                            .trim_start_matches('.');
                        if base.is_empty() || base.contains('^') || base.contains('\\') {
                            return None;
                        }
                        let labels: Vec<&str> = base.split('.').collect();
                        (labels.len() >= 2).then(|| labels[labels.len() - 2..].join("."))
                    })
                    .collect();
            }
            return Vec::new();
        }

        // Exact/wildcard/suffix patterns
        let base = pat.trim_start_matches("*.").trim_start_matches('.');
        if base.is_empty() || base.contains('^') || base.contains('\\') {
            return Vec::new();
        }
        let labels: Vec<&str> = base.split('.').collect();
        if labels.len() >= 2 {
            vec![labels[labels.len() - 2..].join(".")]
        } else {
            Vec::new()
        }
    };

    let mut raw_apexes: Vec<(String, String)> = Vec::new();
    let mut term_apexes: Vec<(String, String)> = Vec::new();
    for (id, pats) in patterns.iter().enumerate() {
        let route = &runtimes[id];
        for pat in pats {
            for a in apex(pat) {
                if route.route_type == RouteType::Raw {
                    raw_apexes.push((a, route.name.clone()));
                } else {
                    term_apexes.push((a, route.name.clone()));
                }
            }
        }
    }

    for (apex, raw_route) in &raw_apexes {
        let clashing: Vec<&String> = term_apexes
            .iter()
            .filter(|(a, _)| a == apex)
            .map(|(_, n)| n)
            .collect();
        if !clashing.is_empty() {
            tracing::warn!(
                listener = %listener.addr,
                route = %raw_route,
                domain = %apex,
                also_routed_by = ?clashing,
                "a raw route shares a registrable domain with terminating routes. \
                 raw never terminates TLS, so the client sees the upstream's own \
                 certificate and sni-gate cannot narrow it. If that certificate \
                 covers a name routed elsewhere here, a client may reuse the raw \
                 connection for it and bypass routing. Give the raw route its own \
                 registrable domain, or use a terminating type, if that matters."
            );
        }
    }
}

/// One built route: its data-path runtime plus the forwarding identity that
/// decides which names may share its certificates.
struct BuiltRoute {
    runtime: RouteRuntime,
    forwarding: Forwarding,
}

/// Build one route's runtime, flattening effective settings and building (or
/// reusing) its resolvers and ECH provider.
fn build_route(
    cfg: &Config,
    listener: &Listener,
    route: &Route,
    root_store: &Arc<RootCertStore>,
    named_resolvers: &HashMap<String, Arc<dns_resolvers::DnsResolver>>,
    resolver_cache: &mut ResolverCache,
    probe_targets: &mut Vec<ProbeTarget>,
) -> Result<BuiltRoute> {
    // Templates were validated at load, so name lookups cannot fail here.
    let rt_tpl = cfg.template_for(&route.use_template)?;
    let ln_tpl = cfg.template_for(&listener.use_template)?;

    let eff = cfg.effective(listener, route, rt_tpl, ln_tpl);

    // Public route type is transport-agnostic. Normalize it exactly once into
    // the concrete runtime path: QUIC+tls => H3 and QUIC+ech => H3-ECH.
    let configured_route_type = Config::effective_route_type(route, rt_tpl)
        .ok_or_else(|| anyhow::anyhow!("route {}: missing type", route.label()))?;
    let route_type = Config::runtime_route_type(listener.transport, configured_route_type)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "route {}: type {:?} is incompatible with {:?}",
                route.label(),
                configured_route_type,
                listener.transport
            )
        })?;

    // Upstream comes from the route or its template (route scope only). Defaulted
    // parts resolve against this listener's port; a `None` host reflects the
    // matched source SNI/Host per connection.
    let upstream_spec = route
        .upstream
        .as_deref()
        .or_else(|| rt_tpl.and_then(|t| t.upstream.as_deref()));
    let (host, port) = config::resolved_upstream_from(upstream_spec, listener.addr.port())
        .ok_or_else(|| anyhow::anyhow!("route {}: invalid upstream", route.label()))?;

    // SNI presented upstream: route → template (deeper wins). A present-but-blank
    // value means "send no SNI extension" rather than "inherit".
    let sni_policy = route.sni_policy(rt_tpl);

    // NAT64 disabled in ipv6-only mode.
    let nat64 = match (&eff.nat64_prefix, eff.address_family) {
        (_, config::AddressFamily::Ipv6) => None,
        (Some(p), _) => Some(
            p.parse::<Nat64Prefix>()
                .with_context(|| format!("route {}: invalid nat64_prefix", route.label()))?,
        ),
        (None, _) => None,
    };

    let addr_spec = eff.addr_resolver.clone().unwrap_or_default();
    let addr_resolver = get_resolver(
        named_resolvers,
        resolver_cache,
        &addr_spec,
        eff.address_family,
    )?;

    let eff_ech = cfg.effective_ech(listener, route, rt_tpl, ln_tpl);
    // Which ECHConfigList source this route uses, for the certificate scope: two
    // ECH routes to one socket that draw their keys from different sources are not
    // interchangeable, so they must not share a certificate.
    let mut ech_identity: Option<EchIdentity> = None;
    let ech = if matches!(route_type, RouteType::Ech | RouteType::H3Ech) {
        let ech_spec = eff.ech_resolver.clone().unwrap_or_else(|| {
            // Default ECH resolver: use addr_resolver if present, else system resolver
            eff.addr_resolver
                .clone()
                .unwrap_or_else(|| "system".to_string())
        });
        ech_identity = Some(EchIdentity {
            mode: eff_ech.mode,
            domain: eff_ech.ech_domain.clone(),
            resolver: ech_spec.clone(),
            inline_config: eff_ech.config.is_some(),
        });
        // HTTPS records are resolved dual-family regardless of upstream family.
        let ech_resolver = get_resolver(
            named_resolvers,
            resolver_cache,
            &ech_spec,
            config::AddressFamily::Dual,
        )?;
        Some(EchProvider::new(
            eff_ech.clone(),
            port,
            eff.require_ech,
            // RFC 9849 permits an inner hello with no SNI; `override_sni = ""`
            // asks for exactly that.
            sni_policy != config::SniPolicy::Omit,
            ech_resolver,
            root_store.clone(),
            eff.ech_refresh,
        ))
    } else {
        None
    };

    let eff_http2 = cfg.effective_http2(listener, route, rt_tpl, ln_tpl);

    // Only `http` routes need the h2c probe: tls/ech mirror the upstream's live
    // ALPN choice and so cannot be wrong about it.
    if eff_http2.enabled && route_type == RouteType::Http && eff_http2.probe != config::H2Probe::Off
    {
        match &host {
            Some(h) => probe_targets.push(ProbeTarget {
                route: route.label(),
                host: h.clone(),
                port,
                policy: eff_http2.probe,
                budget: eff_http2.probe_timeout,
                resolver: addr_resolver.clone(),
                family: eff.address_family,
                nat64,
            }),
            // A reflecting route has no fixed upstream host at startup — the
            // target is whichever name each connection carries — so there is
            // nothing to probe.
            None => debug!(
                route = %route.label(),
                "skipping h2c probe: the route reflects the source SNI/Host, so \
                 it has no fixed upstream to probe at startup"
            ),
        }
    }

    // The forwarding identity that decides which names may share this route's
    // certificates. Everything here can change where a connection goes or under
    // what name it is presented; nothing that cannot (timeouts, the fail policy,
    // the HTTP/2 switch, ECH refresh cadence) is included, since that would
    // fragment scopes without buying any safety.
    let forwarding = Forwarding {
        route_type,
        host: host.clone(),
        port,
        sni: sni_policy.clone(),
        family: eff.address_family,
        nat64: eff.nat64_prefix.clone(),
        addr_resolver: addr_spec.clone(),
        ech: ech_identity,
    };

    Ok(BuiltRoute {
        runtime: RouteRuntime {
            name: route.label(),
            route_type,
            upstream_host: host,
            upstream_port: port,
            sni_policy,
            http2: eff_http2.enabled,
            require_ech: eff.require_ech,
            max_retries: eff_ech.max_retries,
            connect_timeout: eff.connect_timeout,
            idle_timeout: eff.idle_timeout,
            address_family: eff.address_family,
            nat64,
            fail: eff.fail,
            addr_resolver,
            ech,
            root_store: root_store.clone(),
        },
        forwarding,
    })
}

/// Resolve and probe every collected h2c target concurrently, then apply each
/// one's policy.
///
/// Backends are deduplicated by resolved address, so several routes pointing at
/// the same upstream cost one probe. A `require` failure aborts startup; a `warn`
/// failure is logged loudly and startup continues with HTTP/2 still enabled — the
/// probe validates, it never decides (see [`probe`]).
async fn run_probes(targets: Vec<ProbeTarget>) -> Result<()> {
    if targets.is_empty() {
        return Ok(());
    }

    let mut set = tokio::task::JoinSet::new();
    for t in targets {
        set.spawn(async move {
            // Resolution shares the route's own resolver/family/NAT64 settings so
            // the probe reaches exactly the address the data path would dial.
            let resolved = t
                .resolver
                .lookup_addr(&t.host, t.port, t.family, t.nat64.as_ref())
                .await
                .with_context(|| format!("resolving h2c probe target {}:{}", t.host, t.port));
            let outcome = match resolved {
                Ok(addr) => probe::probe_h2c(addr, t.budget).await,
                Err(e) => Err(e),
            };
            (t.route, t.host, t.port, t.policy, outcome)
        });
    }

    // Deduplicate by (host, port): routes sharing a backend need only one verdict.
    let mut seen: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
    let mut failures: Vec<String> = Vec::new();

    while let Some(joined) = set.join_next().await {
        let (route, host, port, policy, outcome) = joined.context("h2c probe task panicked")?;
        if !seen.insert((host.clone(), port)) {
            continue;
        }
        match outcome {
            Ok(()) => info!(route = %route, upstream = %format!("{host}:{port}"), "h2c probe ok"),
            Err(e) => {
                let detail = format!("{e:#}");
                match policy {
                    config::H2Probe::Require => failures.push(format!(
                        "route {route}: upstream {host}:{port} failed the h2c probe: {detail}"
                    )),
                    // Keep HTTP/2 enabled: the config says the backend speaks it,
                    // and a transient failure at boot (backend not up yet) must
                    // not silently reshape the running configuration.
                    config::H2Probe::Warn => tracing::warn!(
                        route = %route,
                        upstream = %format!("{host}:{port}"),
                        error = %detail,
                        "h2c probe failed; HTTP/2 stays enabled for this route as configured. \
                         If the backend really cannot do h2c, either enable HTTP/2 on it or set \
                         http2.enabled = false for this route. If it simply had not started yet, \
                         this warning is harmless."
                    ),
                    config::H2Probe::Off => unreachable!("off targets are never collected"),
                }
            }
        }
    }

    if !failures.is_empty() {
        return Err(anyhow::anyhow!(
            "h2c probe failed with probe = \"require\":\n  {}",
            failures.join("\n  ")
        ));
    }
    Ok(())
}

/// Get or build a resolver for `spec` under `family`.
///
/// Checks the named registry first; if `spec` is a reference, returns that
/// resolver (and ignores `family` — a named resolver has its own). Otherwise
/// parses as an inline spec, builds, and wraps in a DnsResolver.
fn get_resolver(
    registry: &HashMap<String, Arc<dns_resolvers::DnsResolver>>,
    cache: &mut ResolverCache,
    spec: &str,
    family: config::AddressFamily,
) -> Result<Arc<dns_resolvers::DnsResolver>> {
    // Named reference: return from registry.
    if Config::is_resolver_ref(spec) {
        let name = spec
            .trim()
            .strip_prefix('@')
            .ok_or_else(|| anyhow::anyhow!("invalid resolver reference {spec:?}"))?;
        return registry
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown resolver @{name}"));
    }

    // Inline spec: check cache, or build and wrap.
    let key = (spec.to_string(), family);
    if let Some(r) = cache.get(&key) {
        // Wrap cached TokioResolver in DnsResolver (no plan = no rebuild).
        return Ok(dns_resolvers::DnsResolver::new(
            spec.to_string(),
            r.clone(),
            None,
            None,
        ));
    }
    let parsed = ResolverSpec::parse(spec).with_context(|| format!("resolver spec {spec:?}"))?;
    let r = parsed
        .build(family)
        .with_context(|| format!("building resolver {spec:?}"))?;
    cache.insert(key, r.clone());
    Ok(dns_resolvers::DnsResolver::new(
        spec.to_string(),
        r,
        None,
        None,
    ))
}

/// Build all declared `[resolvers.<name>]` in dependency order, returning a
/// registry keyed by name.
async fn build_named_resolvers(
    cfg: &Config,
    _cache: &mut ResolverCache,
) -> Result<HashMap<String, Arc<dns_resolvers::DnsResolver>>> {
    let mut registry: HashMap<String, Arc<dns_resolvers::DnsResolver>> = HashMap::new();
    let root_store = Arc::new(ech::webpki_root_store());

    // Topological order so each resolver's dependencies are already built.
    let order = cfg.resolver_build_order()?;

    for name in order {
        let eff = cfg.effective_resolver(&name)?;

        // Parse the endpoint (no I/O).
        let endpoint = dns_resolvers::Endpoint::parse(&eff.endpoint)
            .with_context(|| format!("[resolvers.{name}] endpoint"))?;

        // Resolve bootstrap: inline spec or named reference.
        let bootstrap = match &eff.bootstrap {
            Some(spec) if Config::is_resolver_ref(spec) => {
                let bootstrap_name = spec.trim().strip_prefix('@').ok_or_else(|| {
                    anyhow::anyhow!("[resolvers.{name}]: invalid bootstrap reference {spec:?}")
                })?;
                registry.get(bootstrap_name).cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "[resolvers.{name}]: bootstrap @{bootstrap_name} not found (build order error)"
                    )
                })?
            }
            Some(spec) => {
                // Inline spec: build and wrap.
                let parsed = dns::ResolverSpec::parse(spec)
                    .with_context(|| format!("[resolvers.{name}] bootstrap spec"))?;
                let resolver = parsed.build(eff.address_family)?;
                dns_resolvers::DnsResolver::new(format!("{name}:bootstrap"), resolver, None, None)
            }
            None => {
                // OS resolution.
                let resolver = dns::ResolverSpec::System.build(eff.address_family)?;
                dns_resolvers::DnsResolver::new(format!("{name}:system"), resolver, None, None)
            }
        };

        // Dial host and port after upstream override.
        let endpoint_host = endpoint.host().unwrap_or_default().to_string();
        let (up_host, port) =
            config::resolved_upstream_from(eff.upstream.as_deref(), endpoint.port()).unwrap();
        let dial_host = up_host.unwrap_or_else(|| endpoint_host.clone());
        let dial_port = port;

        // For Plain endpoints (IP addresses), we don't need to resolve the dial_host
        // through bootstrap - it's already an IP that will be used directly in dns_resolvers::build.
        // Only DoH/DoT endpoints with hostnames need bootstrap resolution.
        // An empty dial_host here means a Plain endpoint with no upstream override,
        // which is handled correctly in dns_resolvers::build (it extracts the IP directly).

        // Server name after override_sni.
        let server_name = match eff.sni_policy {
            config::SniPolicy::Reflect | config::SniPolicy::Omit => {
                endpoint.host().map(str::to_string)
            }
            config::SniPolicy::Fixed(ref n) => Some(n.clone()),
        };
        let enable_sni = eff.sni_policy != config::SniPolicy::Omit;

        // NAT64 prefix.
        let nat64 = eff
            .nat64_prefix
            .as_ref()
            .map(|s| s.parse::<nat64::Nat64Prefix>())
            .transpose()
            .with_context(|| format!("[resolvers.{name}] nat64_prefix"))?;

        // ECH plan.
        let ech = eff
            .ech
            .as_ref()
            .map(|e_settings| {
                let ech_resolver = match &eff.ech_resolver {
                    Some(spec) if Config::is_resolver_ref(spec) => {
                        let ech_name = spec.trim().strip_prefix('@').ok_or_else(|| {
                            anyhow::anyhow!(
                                "[resolvers.{name}.ech]: invalid ech_resolver reference {spec:?}"
                            )
                        })?;
                        registry.get(ech_name).cloned().ok_or_else(|| {
                            anyhow::anyhow!(
                                "[resolvers.{name}.ech]: ech_resolver @{ech_name} not found"
                            )
                        })?
                    }
                    Some(spec) => {
                        // Inline spec.
                        let parsed = dns::ResolverSpec::parse(spec)
                            .with_context(|| format!("[resolvers.{name}] ech_resolver spec"))?;
                        let resolver = parsed.build(config::AddressFamily::Dual)?;
                        dns_resolvers::DnsResolver::new(
                            format!("{name}:ech_resolver"),
                            resolver,
                            None,
                            None,
                        )
                    }
                    None => {
                        // OS resolution for ECH lookups.
                        let resolver =
                            dns::ResolverSpec::System.build(config::AddressFamily::Dual)?;
                        dns_resolvers::DnsResolver::new(
                            format!("{name}:ech:system"),
                            resolver,
                            None,
                            None,
                        )
                    }
                };

                Ok::<_, anyhow::Error>(dns_resolvers::EchPlan {
                    settings: e_settings.clone(),
                    require_ech: eff.require_ech,
                    refresh: eff.ech_refresh,
                    resolver: ech_resolver,
                    root_store: root_store.clone(),
                    max_retries: e_settings.max_retries,
                })
            })
            .transpose()?;

        let plan = Arc::new(dns_resolvers::ResolverPlan {
            // `eff.name` is the declared name, carried through by
            // `effective_resolver` precisely so diagnostics can quote it.
            label: eff.name.clone(),
            endpoint,
            dial_host,
            dial_port,
            server_name,
            enable_sni,
            family: eff.address_family,
            nat64,
            connect_timeout: eff.connect_timeout,
            bootstrap,
            ech,
        });

        // Build the resolver from the plan.
        let built = dns_resolvers::build(&plan)
            .await
            .with_context(|| format!("[resolvers.{name}]"))?;

        let handle = dns_resolvers::DnsResolver::new(
            name.clone(),
            built.resolver,
            Some(plan.clone()),
            built.ech_bytes,
        );

        // Proactive ECH rotation: only a resolver that actually uses ECH has
        // anything to refresh.
        if let Some(ech) = &plan.ech {
            dns_resolvers::spawn_ech_refresher(&handle, ech.refresh);
        }

        info!(name, endpoint = %eff.endpoint, "built named resolver");
        registry.insert(name, handle);
    }

    Ok(registry)
}

fn init_tracing(directive: &str) {
    let filter = EnvFilter::try_from_env("SNI_GATE_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new(directive));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).with_ansi(false))
        .init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
