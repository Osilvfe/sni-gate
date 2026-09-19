//! DNS resolution: a generic resolver spec (DoH / DoT / plain IP / system) plus
//! address-family-aware upstream host resolution with optional NAT64 synthesis.
//!
//! A resolver "spec" is a short string chosen per scope:
//!   * `system`                         — the OS resolver
//!   * `https://host[:port]/dns-query`  — DoH (host resolved once via system DNS)
//!   * `tls://host[:port]`              — DoT
//!   * `udp://ip[:port]` / `tcp://ip[:port]` / bare `ip[:port]` — plain DNS to an IP
//!
//! Resolvers are built once and shared. Two purposes are distinguished so a
//! deployment can send ECH HTTPS-record lookups and upstream A/AAAA lookups to
//! different servers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;

use crate::config::AddressFamily;
use crate::nat64::Nat64Prefix;

/// Where to dial an upstream: one address, or two from different families for
/// the connection layer to race.
///
/// A second address is present only when it is a genuinely different *path* to
/// the upstream — a native A record alongside a native AAAA. Under NAT64 there
/// is no such thing: a synthesized address is another IPv6 address on the same
/// stack, so racing it would prove nothing about reachability, and the raw IPv4
/// it was synthesized from is unroutable on the v6-only host the prefix
/// declares. Those cases collapse to [`Self::single`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAddrs {
    /// The address to dial first; IPv6 whenever both families answered.
    pub primary: SocketAddr,
    /// A different-family address to race `primary` against, or `None` when
    /// only one path to the upstream exists.
    pub fallback: Option<SocketAddr>,
}

impl ResolvedAddrs {
    /// The one address this name resolves to.
    pub fn single(addr: SocketAddr) -> Self {
        Self {
            primary: addr,
            fallback: None,
        }
    }

    /// Two paths to the same upstream. IPv6 leads, per RFC 6724 destination
    /// address selection; the race in [`crate::proxy`] decides what actually
    /// carries the connection.
    pub fn dual(v6: SocketAddr, v4: SocketAddr) -> Self {
        Self {
            primary: v6,
            fallback: Some(v4),
        }
    }
}

/// A parsed resolver specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverSpec {
    /// Use the operating system's configured resolver.
    System,
    /// DoH endpoint: IP the host resolves to (once), TLS server name, path.
    Doh {
        ip: IpAddr,
        server_name: String,
        path: String,
    },
    /// DoT endpoint.
    Dot { ip: IpAddr, server_name: String },
    /// Plain DNS over UDP+TCP to a fixed IP:port.
    Plain { addr: SocketAddr },
}

impl ResolverSpec {
    /// Parse a spec string. `system` and empty both mean the system resolver.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("system") {
            return Ok(ResolverSpec::System);
        }
        if let Some(rest) = s.strip_prefix("https://") {
            let (host, port, path) = split_authority_path(rest);
            let ip = resolve_bootstrap(&host, port.unwrap_or(443))
                .with_context(|| format!("resolving DoH host {host}"))?;
            return Ok(ResolverSpec::Doh {
                ip,
                server_name: host,
                path: if path.is_empty() {
                    "/dns-query".to_string()
                } else {
                    path
                },
            });
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            let (host, port, _) = split_authority_path(rest);
            let ip = resolve_bootstrap(&host, port.unwrap_or(853))
                .with_context(|| format!("resolving DoT host {host}"))?;
            return Ok(ResolverSpec::Dot {
                ip,
                server_name: host,
            });
        }
        // udp:// / tcp:// / bare ip[:port] all mean plain DNS to an IP.
        let body = s
            .strip_prefix("udp://")
            .or_else(|| s.strip_prefix("tcp://"))
            .unwrap_or(s);
        let addr = parse_ip_addr(body)
            .with_context(|| format!("resolver spec {s:?} is not a valid ip[:port]"))?;
        Ok(ResolverSpec::Plain { addr })
    }

    /// Build a shared Tokio resolver honoring `family` for A/AAAA strategy.
    pub fn build(&self, family: AddressFamily) -> Result<Arc<TokioResolver>> {
        let config = match self {
            ResolverSpec::System => system_resolver_config()?,
            ResolverSpec::Doh {
                ip,
                server_name,
                path,
            } => {
                let ns = NameServerConfig::https(
                    *ip,
                    Arc::from(server_name.as_str()),
                    Some(Arc::from(path.as_str())),
                );
                ResolverConfig::from_parts(None, vec![], vec![ns])
            }
            ResolverSpec::Dot { ip, server_name } => {
                let ns = NameServerConfig::tls(*ip, Arc::from(server_name.as_str()));
                ResolverConfig::from_parts(None, vec![], vec![ns])
            }
            ResolverSpec::Plain { addr } => {
                let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
                ns.connections.iter_mut().for_each(|c| c.port = addr.port());
                ResolverConfig::from_parts(None, vec![], vec![ns])
            }
        };

        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let opts = builder.options_mut();
        opts.ip_strategy = strategy_for(family);
        // An explicitly configured DoH/DoT/plain-IP resolver is an upstream DNS
        // choice: it must answer purely from that server, never the local hosts
        // file. Only `system` honors hosts (that is what "system resolution"
        // means). This keeps a proxy's routing independent of local overrides.
        opts.use_hosts_file = match self {
            ResolverSpec::System => hickory_resolver::config::ResolveHosts::Auto,
            _ => hickory_resolver::config::ResolveHosts::Never,
        };
        Ok(Arc::new(builder.build()?))
    }
}

/// Resolve an upstream host to a connectable address, honoring the address
/// family and applying NAT64 synthesis when only IPv4 is available.
///
/// Under `Dual` a name that publishes both families yields both, because DNS
/// cannot tell whether either path actually carries traffic — an AAAA record
/// exists for the *destination*, and says nothing about whether this host has a
/// working route to it. Deciding that is [`crate::proxy`]'s job, and it needs
/// both addresses to do it.
pub async fn resolve_upstream(
    resolver: &TokioResolver,
    host: &str,
    port: u16,
    family: AddressFamily,
    nat64: Option<&Nat64Prefix>,
) -> Result<ResolvedAddrs> {
    // A literal IP needs no lookup. A literal IPv4 still goes through NAT64
    // synthesis when a prefix is configured (unless ipv6-only mode, where NAT64
    // is disabled), so a v4 destination is reachable from a v6-only host.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = match ip {
            IpAddr::V4(v4) if family != AddressFamily::Ipv6 => nat64_or_v4(v4, port, nat64),
            other => SocketAddr::new(other, port),
        };
        return Ok(ResolvedAddrs::single(addr));
    }

    let resolved = match family {
        AddressFamily::Ipv6 => {
            // AAAA only; NAT64 disabled.
            let v6 = lookup_v6(resolver, host).await?;
            ResolvedAddrs::single(SocketAddr::new(IpAddr::V6(v6), port))
        }
        AddressFamily::Ipv4 => {
            let v4 = lookup_v4(resolver, host).await?;
            ResolvedAddrs::single(nat64_or_v4(v4, port, nat64))
        }
        // A NAT64 prefix declares a v6-only host, so every destination is
        // reached over IPv6 and there is no second path to find. That makes the
        // A record dead weight whenever an AAAA answers — ask for it only when
        // there is no AAAA to use.
        AddressFamily::Dual if nat64.is_some() => match lookup_v6(resolver, host).await {
            Ok(v6) => ResolvedAddrs::single(SocketAddr::new(IpAddr::V6(v6), port)),
            Err(v6_err) => match lookup_v4(resolver, host).await {
                Ok(v4) => ResolvedAddrs::single(nat64_or_v4(v4, port, nat64)),
                Err(v4_err) => return Err(neither_family_resolved(host, &v6_err, v4_err)),
            },
        },
        AddressFamily::Dual => {
            // Both records are real alternatives here, so both are worth having
            // and neither lookup depends on the other's answer — issue them
            // together rather than paying two round trips in series.
            let (v6, v4) = tokio::join!(lookup_v6(resolver, host), lookup_v4(resolver, host));
            match (v6, v4) {
                (Ok(v6), Ok(v4)) => ResolvedAddrs::dual(
                    SocketAddr::new(IpAddr::V6(v6), port),
                    nat64_or_v4(v4, port, nat64),
                ),
                (Ok(v6), Err(_)) => ResolvedAddrs::single(SocketAddr::new(IpAddr::V6(v6), port)),
                (Err(_), Ok(v4)) => ResolvedAddrs::single(nat64_or_v4(v4, port, nat64)),
                (Err(v6_err), Err(v4_err)) => {
                    return Err(neither_family_resolved(host, &v6_err, v4_err))
                }
            }
        }
    };
    tracing::debug!(host, primary = %resolved.primary, fallback = ?resolved.fallback, ?family, nat64 = nat64.is_some(), "resolved upstream");
    Ok(resolved)
}

/// Both families failed for `host`, so report both reasons.
///
/// "No AAAA record" on its own is not why a dual-stack lookup gave up, and an
/// operator reading a startup failure needs to see which half was the real
/// problem. The A error keeps its chain intact because callers inspect it —
/// [`crate::ech::is_ech_reject_chain`] decides from it whether the resolver
/// itself needs rebuilding — so the AAAA reason is folded in as text.
fn neither_family_resolved(
    host: &str,
    v6_err: &anyhow::Error,
    v4_err: anyhow::Error,
) -> anyhow::Error {
    v4_err.context(format!("resolving {host}: AAAA also failed: {v6_err:#}"))
}

fn nat64_or_v4(v4: Ipv4Addr, port: u16, nat64: Option<&Nat64Prefix>) -> SocketAddr {
    match nat64 {
        Some(prefix) => SocketAddr::new(IpAddr::V6(prefix.synthesize(v4)), port),
        None => SocketAddr::new(IpAddr::V4(v4), port),
    }
}

/// Resolve `host` to **every** address it publishes in `family`.
///
/// A different question from [`resolve_upstream`], which answers "where do I
/// dial?" with one address. A pool asks "what are all the candidate endpoints?" —
/// comparing several edges is its entire purpose, so collapsing the answer to its
/// first record would discard exactly the alternatives it exists to rank.
///
/// A literal IP resolves to itself when it matches `family`. NAT64 is
/// deliberately **not** applied here: a pool synthesizes its own projected
/// addresses so they can be probed and ranked independently of their IPv4
/// originals (see [`crate::pool`]).
///
/// With `Dual`, both families are queried and the results concatenated. One
/// family failing is not an error as long as the other answered — a name with
/// only A records is ordinary, and hickory reports the missing AAAA as a failed
/// lookup rather than an empty one.
pub async fn resolve_all_ips(
    resolver: &TokioResolver,
    host: &str,
    family: AddressFamily,
) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let usable = !matches!(
            (ip, family),
            (IpAddr::V4(_), AddressFamily::Ipv6) | (IpAddr::V6(_), AddressFamily::Ipv4)
        );
        return Ok(if usable { vec![ip] } else { Vec::new() });
    }

    let mut out: Vec<IpAddr> = Vec::new();
    let mut last_err: Option<anyhow::Error> = None;

    if family != AddressFamily::Ipv6 {
        match lookup_all_v4(resolver, host).await {
            Ok(v) => out.extend(v.into_iter().map(IpAddr::V4)),
            Err(e) => last_err = Some(e),
        }
    }
    if family != AddressFamily::Ipv4 {
        match lookup_all_v6(resolver, host).await {
            Ok(v) => out.extend(v.into_iter().map(IpAddr::V6)),
            Err(e) => last_err = Some(e),
        }
    }

    if out.is_empty() {
        return Err(last_err.unwrap_or_else(|| anyhow!("no A or AAAA records for {host}")));
    }
    Ok(out)
}

async fn lookup_all_v4(resolver: &TokioResolver, host: &str) -> Result<Vec<Ipv4Addr>> {
    use hickory_resolver::proto::rr::RData;
    let lookup = resolver
        .lookup(host, RecordType::A)
        .await
        .with_context(|| format!("A lookup for {host}"))?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect())
}

async fn lookup_all_v6(resolver: &TokioResolver, host: &str) -> Result<Vec<Ipv6Addr>> {
    use hickory_resolver::proto::rr::RData;
    let lookup = resolver
        .lookup(host, RecordType::AAAA)
        .await
        .with_context(|| format!("AAAA lookup for {host}"))?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|r| match &r.data {
            RData::AAAA(a) => Some(a.0),
            _ => None,
        })
        .collect())
}

async fn lookup_v4(resolver: &TokioResolver, host: &str) -> Result<Ipv4Addr> {
    use hickory_resolver::proto::rr::RData;
    let lookup = resolver
        .lookup(host, RecordType::A)
        .await
        .with_context(|| format!("A lookup for {host}"))?;
    lookup
        .answers()
        .iter()
        .find_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no A record for {host}"))
}

async fn lookup_v6(resolver: &TokioResolver, host: &str) -> Result<Ipv6Addr> {
    use hickory_resolver::proto::rr::RData;
    let lookup = resolver
        .lookup(host, RecordType::AAAA)
        .await
        .with_context(|| format!("AAAA lookup for {host}"))?;
    lookup
        .answers()
        .iter()
        .find_map(|r| match &r.data {
            RData::AAAA(a) => Some(a.0),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no AAAA record for {host}"))
}

pub fn strategy_for(family: AddressFamily) -> LookupIpStrategy {
    match family {
        AddressFamily::Dual => LookupIpStrategy::Ipv6thenIpv4,
        AddressFamily::Ipv4 => LookupIpStrategy::Ipv4Only,
        AddressFamily::Ipv6 => LookupIpStrategy::Ipv6Only,
    }
}

/// Build the system resolver config.
///
/// hickory's `read_system_conf` is feature/platform-gated and not always
/// available; to keep `system` dependable everywhere we resolve through a
/// well-known public resolver (Cloudflare) over UDP+TCP. Deployments that need
/// the exact OS resolver can point `resolver` at a specific server instead.
pub fn system_resolver_config() -> Result<ResolverConfig> {
    let ns = NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    Ok(ResolverConfig::from_parts(None, vec![], vec![ns]))
}

/// Split `host[:port]/path` into (host, Some(port)?, path). Path is "" if none.
fn split_authority_path(s: &str) -> (String, Option<u16>, String) {
    let (authority, path) = match s.find('/') {
        Some(i) => (&s[..i], s[i..].to_string()),
        None => (s, String::new()),
    };
    // authority may be host or host:port (host is never an IPv6 literal here).
    match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().ok(), path)
        }
        _ => (authority.to_string(), None, path),
    }
}

/// Parse `ip` or `ip:port` (v4 or bracketed v6) into a SocketAddr (default :53).
fn parse_ip_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(sa) = SocketAddr::from_str(s) {
        return Ok(sa);
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(anyhow!("invalid IP address {s:?}"))
}

/// Resolve a DoH/DoT host to a single IP via the system resolver, once.
fn resolve_bootstrap(host: &str, port: u16) -> Result<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("bootstrap-resolving {host}"))?
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| anyhow!("could not resolve {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_system() {
        assert_eq!(ResolverSpec::parse("system").unwrap(), ResolverSpec::System);
        assert_eq!(ResolverSpec::parse("").unwrap(), ResolverSpec::System);
    }

    #[tokio::test]
    async fn literal_ipv4_gets_nat64_synthesized() {
        // A literal IPv4 upstream with a NAT64 prefix must be synthesized to v6
        // (short-circuits DNS but still applies NAT64), except in ipv6 mode.
        let resolver = ResolverSpec::System.build(AddressFamily::Ipv4).unwrap();
        let prefix = "64:ff9b::".parse::<Nat64Prefix>().unwrap();

        let out = resolve_upstream(
            &resolver,
            "1.2.3.4",
            443,
            AddressFamily::Ipv4,
            Some(&prefix),
        )
        .await
        .unwrap();
        assert_eq!(
            out,
            ResolvedAddrs::single("[64:ff9b::102:304]:443".parse().unwrap())
        );

        // A literal IPv6 upstream is returned as-is.
        let out6 = resolve_upstream(
            &resolver,
            "2a01:4f8::1",
            443,
            AddressFamily::Dual,
            Some(&prefix),
        )
        .await
        .unwrap();
        assert_eq!(
            out6,
            ResolvedAddrs::single("[2a01:4f8::1]:443".parse().unwrap())
        );
    }

    /// A literal address is one path by definition — there is no second record
    /// to race it against, whatever the family setting says.
    #[tokio::test]
    async fn a_literal_never_produces_a_second_address() {
        let resolver = ResolverSpec::System.build(AddressFamily::Dual).unwrap();
        for host in ["1.2.3.4", "2a01:4f8::1"] {
            let out = resolve_upstream(&resolver, host, 443, AddressFamily::Dual, None)
                .await
                .unwrap();
            assert_eq!(out.fallback, None, "{host} should resolve to one address");
        }
    }

    /// The two shapes a resolution can take, and the ordering the dialer relies
    /// on: IPv6 leads whenever both families are present.
    #[test]
    fn resolved_addrs_orders_ipv6_first() {
        let v6: SocketAddr = "[2606:4700::1]:443".parse().unwrap();
        let v4: SocketAddr = "1.1.1.1:443".parse().unwrap();

        let single = ResolvedAddrs::single(v4);
        assert_eq!(single.primary, v4);
        assert_eq!(single.fallback, None);

        let dual = ResolvedAddrs::dual(v6, v4);
        assert_eq!(dual.primary, v6);
        assert_eq!(dual.fallback, Some(v4));
    }

    /// Both families failing must report both reasons — "no AAAA" alone would
    /// send an operator looking in the wrong place — while keeping the A error's
    /// chain intact for the ECH-rejection check that inspects it.
    #[test]
    fn a_dual_failure_names_both_families() {
        let v6 = anyhow!("AAAA lookup for h.test: no records");
        let v4 = anyhow!("A lookup for h.test: refused").context("through bootstrap");
        let err = neither_family_resolved("h.test", &v6, v4);

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("no records"),
            "lost the AAAA reason: {rendered}"
        );
        assert!(
            rendered.contains("refused"),
            "lost the A reason: {rendered}"
        );
        assert!(
            err.chain()
                .any(|c| c.to_string().contains("through bootstrap")),
            "the A error's chain must survive: {rendered}"
        );
    }

    /// A literal address needs no lookup, and the family filter still applies —
    /// so a `select = ["ipv6"]` consumer never receives a v4 literal.
    #[tokio::test]
    async fn resolve_all_handles_literals_and_filters_by_family() {
        let r = ResolverSpec::System.build(AddressFamily::Dual).unwrap();
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "2606:4700::1".parse().unwrap();

        // Matching or unconstrained: returned as-is.
        for family in [AddressFamily::Dual, AddressFamily::Ipv4] {
            assert_eq!(
                resolve_all_ips(&r, "1.2.3.4", family).await.unwrap(),
                vec![v4]
            );
        }
        for family in [AddressFamily::Dual, AddressFamily::Ipv6] {
            assert_eq!(
                resolve_all_ips(&r, "2606:4700::1", family).await.unwrap(),
                vec![v6]
            );
        }

        // Mismatched: no candidates rather than a wrong-family one.
        assert!(resolve_all_ips(&r, "1.2.3.4", AddressFamily::Ipv6)
            .await
            .unwrap()
            .is_empty());
        assert!(resolve_all_ips(&r, "2606:4700::1", AddressFamily::Ipv4)
            .await
            .unwrap()
            .is_empty());

        // NAT64 is deliberately not applied here: a pool synthesizes its own
        // projected addresses so they can be ranked independently.
        assert_eq!(
            resolve_all_ips(&r, "1.2.3.4", AddressFamily::Dual)
                .await
                .unwrap(),
            vec![v4],
            "resolve_all_ips must not synthesize NAT64 addresses"
        );
    }

    #[test]
    fn parse_bare_ip() {
        assert_eq!(
            ResolverSpec::parse("1.1.1.1").unwrap(),
            ResolverSpec::Plain {
                addr: "1.1.1.1:53".parse().unwrap()
            }
        );
        assert_eq!(
            ResolverSpec::parse("udp://8.8.8.8:5353").unwrap(),
            ResolverSpec::Plain {
                addr: "8.8.8.8:5353".parse().unwrap()
            }
        );
    }

    #[test]
    fn parse_doh_and_dot() {
        // DoH/DoT hosts given as IPs skip bootstrap resolution.
        match ResolverSpec::parse("https://1.1.1.1/dns-query").unwrap() {
            ResolverSpec::Doh { ip, path, .. } => {
                assert_eq!(ip, "1.1.1.1".parse::<IpAddr>().unwrap());
                assert_eq!(path, "/dns-query");
            }
            other => panic!("expected DoH, got {other:?}"),
        }
        match ResolverSpec::parse("tls://9.9.9.9").unwrap() {
            ResolverSpec::Dot { ip, .. } => {
                assert_eq!(ip, "9.9.9.9".parse::<IpAddr>().unwrap())
            }
            other => panic!("expected DoT, got {other:?}"),
        }
    }

    #[test]
    fn doh_default_path() {
        match ResolverSpec::parse("https://1.1.1.1").unwrap() {
            ResolverSpec::Doh { path, .. } => assert_eq!(path, "/dns-query"),
            _ => panic!(),
        }
    }
}
