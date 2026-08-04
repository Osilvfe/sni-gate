//! sni-gate — a multi-listener SNI/Host-routing TLS gateway.
//!
//! Each inbound port routes connections by TLS SNI (or HTTP Host) to an
//! upstream that may be ECH, plain TLS, cleartext HTTP, or raw passthrough.
//! Whenever it terminates TLS it issues a certificate for that name and its
//! wildcard from a local CA (persisted, cached, public-suffix-aware).

mod ca;
mod config;
mod dns;
mod ech;
mod error;
mod nat64;
mod peek;
mod probe;
mod proxy;
mod psl_source;
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
use tracing::{debug, error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::ca::{CaParams, CertificateAuthority};
use crate::config::{Config, Listener, Route, RouteType};
use crate::dns::ResolverSpec;
use crate::ech::EchProvider;
use crate::nat64::Nat64Prefix;
use crate::proxy::{ListenerState, RouteRuntime, ServerConfigs};
use crate::resolver::{DynamicResolver, ResolverParams};
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
    resolver: Arc<hickory_resolver::TokioResolver>,
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

async fn run(cfg: Config) -> Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        listeners = cfg.listeners.len(),
        "starting sni-gate"
    );

    // --- Dynamic certificate stack (shared across all listeners) ---
    let ca = CertificateAuthority::load_or_generate(CaParams {
        cert_path: &cfg.ca.cert_path,
        key_path: &cfg.ca.key_path,
        common_name: &cfg.ca.common_name,
        organization: &cfg.ca.organization,
        country: &cfg.ca.country,
        leaf_validity_days: cfg.ca.leaf_validity_days,
    })
    .context("initializing certificate authority")?;

    if cfg.ca.install_to_system_root {
        if let Err(e) = trust::ensure_installed(ca.cert_der()) {
            tracing::warn!(error = %e, "could not install CA into system root store");
        }
    }

    let suffix = psl_source::load(&cfg.cache.psl).context("initializing public suffix list")?;
    psl_source::spawn_refresher(&cfg.cache.psl, suffix.clone());

    let issuance_mode = cfg.issuance.resolved_mode();

    let store = if cfg.store.enabled {
        let s = CertStore::new(cfg.store.dir.clone(), cfg.store.renew_margin_days);
        s.init().context("initializing certificate store")?;
        Some(s)
    } else {
        None
    };

    let dyn_resolver = Arc::new(DynamicResolver::new(ResolverParams {
        ca,
        suffix,
        store,
        mode: issuance_mode,
        cache_capacity: cfg.cache.capacity,
        cache_ttl: Duration::from_secs(cfg.cache.ttl_secs),
    }));

    // One base server config for local termination; the resolver issues for any
    // SNI. It is then cloned into the ALPN variants the data path selects
    // between (see `ServerConfigs`): the clones share the cert resolver,
    // ticketer and session cache, and differ only in `alpn_protocols`.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(dyn_resolver);
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
    });

    // Shared web-PKI roots for upstream TLS verification.
    let root_store = Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    });

    let mut resolver_cache: ResolverCache = HashMap::new();
    let mut probe_targets: Vec<ProbeTarget> = Vec::new();

    // --- Build every listener ---
    let mut listener_states: Vec<Arc<ListenerState>> = Vec::new();
    for listener in &cfg.listeners {
        let state = build_listener(
            &cfg,
            listener,
            server_configs.clone(),
            root_store.clone(),
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
            proxy::serve(st)
                .await
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

/// Assemble one listener's router + route runtimes from config.
fn build_listener(
    cfg: &Config,
    listener: &Listener,
    server_configs: Arc<ServerConfigs>,
    root_store: Arc<RootCertStore>,
    resolver_cache: &mut ResolverCache,
    probe_targets: &mut Vec<ProbeTarget>,
) -> Result<ListenerState> {
    let mut runtimes: Vec<Arc<RouteRuntime>> = Vec::new();
    let mut patterns: Vec<Vec<String>> = Vec::new();

    for route in &listener.routes {
        runtimes.push(Arc::new(build_route(
            cfg,
            listener,
            route,
            &root_store,
            resolver_cache,
            probe_targets,
        )?));
        patterns.push(route.match_sni.clone());
    }

    let default_id = if let Some(d) = &listener.default_route {
        let id = runtimes.len();
        runtimes.push(Arc::new(build_route(
            cfg,
            listener,
            d,
            &root_store,
            resolver_cache,
            probe_targets,
        )?));
        patterns.push(Vec::new());
        Some(id)
    } else {
        None
    };

    let router = Router::build(&patterns, default_id)
        .map_err(|e| anyhow::anyhow!("listener {}: {e}", listener.addr))?;

    Ok(ListenerState {
        addr: listener.addr,
        router,
        routes: runtimes,
        server_configs,
        unmatched: cfg.global.unmatched.clone(),
    })
}

/// Build one route's runtime, flattening effective settings and building (or
/// reusing) its resolvers and ECH provider.
fn build_route(
    cfg: &Config,
    listener: &Listener,
    route: &Route,
    root_store: &Arc<RootCertStore>,
    resolver_cache: &mut ResolverCache,
    probe_targets: &mut Vec<ProbeTarget>,
) -> Result<RouteRuntime> {
    // Templates were validated at load, so name lookups cannot fail here.
    let rt_tpl = cfg.template_for(&route.use_template)?;
    let ln_tpl = cfg.template_for(&listener.use_template)?;

    let eff = cfg.effective(listener, route, rt_tpl, ln_tpl);

    // Concrete protocol type (route → template), guaranteed present by validation.
    let route_type = Config::effective_route_type(route, rt_tpl)
        .ok_or_else(|| anyhow::anyhow!("route {}: missing type", route.label()))?;

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
    let addr_resolver = get_resolver(resolver_cache, &addr_spec, eff.address_family)?;

    let eff_ech = cfg.effective_ech(listener, route, rt_tpl, ln_tpl);
    let ech = if route_type == RouteType::Ech {
        let ech_spec = eff.ech_resolver.clone().unwrap_or_default();
        // HTTPS records are resolved dual-family regardless of upstream family.
        let ech_resolver = get_resolver(resolver_cache, &ech_spec, config::AddressFamily::Dual)?;
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

    Ok(RouteRuntime {
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
            let resolved =
                dns::resolve_upstream(&t.resolver, &t.host, t.port, t.family, t.nat64.as_ref())
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
fn get_resolver(
    cache: &mut ResolverCache,
    spec: &str,
    family: config::AddressFamily,
) -> Result<Arc<hickory_resolver::TokioResolver>> {
    let key = (spec.to_string(), family);
    if let Some(r) = cache.get(&key) {
        return Ok(r.clone());
    }
    let parsed = ResolverSpec::parse(spec).with_context(|| format!("resolver spec {spec:?}"))?;
    let r = parsed
        .build(family)
        .with_context(|| format!("building resolver {spec:?}"))?;
    cache.insert(key, r.clone());
    Ok(r)
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
