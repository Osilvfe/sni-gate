//! Certificate partitioning — which names may safely share one certificate.
//!
//! # Why this exists
//!
//! A browser may reuse ("coalesce") an existing HTTP/2 connection for a *second*
//! origin when both of these hold (RFC 9113 §9.1.1):
//!
//! 1. the second origin resolves to an address already in the connection's set, and
//! 2. the certificate on that connection is valid for the second origin.
//!
//! A coalesced request travels on the **existing** connection: no new TCP, no new
//! TLS handshake, and therefore **no new SNI**. sni-gate routes per connection, at
//! handshake time, from the SNI — so it never sees the second name and cannot
//! re-route. Whatever upstream the connection was already wired to receives the
//! request.
//!
//! Condition 1 is a property of the deployment (every name pointed at this
//! gateway shares its address) and condition 2 is the only one this program
//! controls. So the invariant that keeps routing honest is:
//!
//! > A certificate served on a connection routed to some destination must not be
//! > valid for any name this gateway would route to a *different* destination.
//!
//! Two mechanisms enforce it together, and both are needed:
//!
//! * **SAN clipping** (see [`crate::resolver`]) drops a proposed wildcard when
//!   some host it would cover routes elsewhere, so a freshly issued certificate
//!   never over-claims.
//! * **Partitioning** — this module — keys the certificate cache and the on-disk
//!   store by *scope*, so a certificate can never later accumulate a name from a
//!   different destination, and two destinations can never overwrite each other's
//!   file.
//!
//! # What a scope is
//!
//! A [`CertScope`] identifies a set of names that may share a certificate. Two
//! routes belong to the same scope when they forward identically **and** are
//! matched by the same routing table:
//!
//! * **Forwarding target** ([`Forwarding`]) — the protocol, dial host (or the
//!   marker for reflecting routes), port, upstream SNI policy, address family,
//!   NAT64 prefix, resolver, and ECH source. Everything that decides where a
//!   connection for a given name goes and under what name it is presented.
//! * **Routing table** — the router's own fingerprint. A scope's safety is
//!   established *against a specific routing table*: a wildcard proven confined
//!   under listener A's routes may not be confined under listener B's. Folding
//!   the router fingerprint into the scope means listeners with identical route
//!   tables (the usual `0.0.0.0:443` + `[::]:443` pair) still share certificates,
//!   while listeners that route differently never do.
//!
//! # What sharing within a scope means
//!
//! Names in one scope may share a wildcard, so a client can still coalesce
//! between them. That is deliberate: it is exactly what the real origin's own
//! wildcard certificate already permits, and the request reaches the same
//! configured destination, which demultiplexes on `:authority` as any origin
//! does. For a reflecting route the sibling's socket was dialed for a sibling
//! name — again precisely what coalescing against a wildcard-serving origin does
//! without this gateway in the path. An operator who wants no coalescing at all
//! can set `[issuance] mode = "exact"`, which reduces every certificate to the
//! single name that requested it.

use std::sync::Arc;

use crate::config::{AddressFamily, EchMode, RouteType, SniPolicy};

/// Everything about a route that determines how a connection is forwarded.
///
/// Two routes with equal `Forwarding` send a connection for a given name to the
/// same place, presented the same way — so names matched by either may share a
/// certificate. Fields that cannot change the destination (timeouts, the fail
/// policy, the HTTP/2 switch, ECH refresh cadence) are deliberately absent: they
/// would fragment scopes without buying any safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarding {
    /// Upstream protocol handling.
    pub route_type: RouteType,
    /// Fixed dial host, or `None` when the route reflects the routing key.
    pub host: Option<String>,
    /// Upstream port.
    pub port: u16,
    /// SNI presented upstream. Distinguishes two routes to the same socket that
    /// would ask it for different virtual hosts.
    pub sni: SniPolicy,
    /// Address family used to resolve the dial host.
    pub family: AddressFamily,
    /// NAT64 prefix as written in the configuration, if any.
    pub nat64: Option<String>,
    /// Resolver spec used for upstream A/AAAA.
    pub addr_resolver: String,
    /// ECH source identity; `Some` only for `ech` routes.
    pub ech: Option<EchIdentity>,
}

/// The identity of an ECH configuration source.
///
/// Only the parts that select *which* ECHConfigList is used — not the refresh
/// interval or the retry budget, which do not change the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchIdentity {
    pub mode: EchMode,
    /// Name whose HTTPS record supplies `ech=`, when pinned.
    pub domain: Option<String>,
    /// Resolver that performs the HTTPS-record lookup.
    pub resolver: String,
    /// Whether an inline base64 config is available as a source.
    pub inline_config: bool,
}

/// A certificate partition: names in the same scope may share a certificate.
///
/// Cheap to clone and hash; used as the certificate cache key and as the
/// subdirectory name in the on-disk store.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertScope(Arc<str>);

impl CertScope {
    /// Derive the scope for a route with forwarding target `f`, matched by a
    /// routing table whose fingerprint is `router_fp`.
    ///
    /// The rendered key leads with a human-readable summary so `certs/` stays
    /// legible (`ech_cf.0sm.com_443-1f3a9c07b2d45e18`), and ends with a digest
    /// over the full identity so that two scopes differing in any field —
    /// including the routing table — never collide.
    ///
    /// The digest carries all 64 bits rather than a shorter, prettier suffix. A
    /// collision here would silently place two different forwarding targets in one
    /// partition, which is precisely the bug this module exists to prevent, so the
    /// trade is eight more characters against a failure mode that cannot be
    /// detected at runtime.
    pub fn new(router_fp: u64, f: &Forwarding) -> Self {
        let host = f.host.as_deref().unwrap_or(REFLECT);
        let readable = sanitize(&format!(
            "{}_{}_{}",
            route_type_str(f.route_type),
            host,
            f.port
        ));
        let digest = fnv1a(canonical(router_fp, f).as_bytes());
        Self(format!("{readable}-{digest:016x}").into())
    }

    /// The scope key: a stable, filesystem-safe identifier.
    pub fn key(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CertScope {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}

/// Stands in for the dial host of a route that reflects the routing key.
const REFLECT: &str = "reflect";

/// Fingerprint a routing table by the exact inputs that define its behavior:
/// each route's patterns, in route order, plus the default route, plus any
/// regex scope_suffix declarations.
///
/// Two tables with equal fingerprints resolve every host identically **and**
/// make identical wildcard confinement decisions, so a certificate proven safe
/// under one is safe under the other.
///
/// The fingerprint includes regex scope information because changing a regex's
/// scope_suffix changes which wildcards are confined: a certificate issued when
/// a regex had scope ".example.com" must not be reused after the scope narrows
/// to "*.example.com", even if the match_sni reference ("@regex-name") stayed
/// the same.
pub fn router_fingerprint(
    patterns: &[Vec<String>],
    default: Option<usize>,
    regexes: &std::collections::HashMap<String, crate::config::RegexDef>,
) -> u64 {
    let mut buf = String::new();
    for (id, pats) in patterns.iter().enumerate() {
        buf.push_str(&id.to_string());
        buf.push('=');
        // Patterns are order-insensitive within a route: sort so a cosmetic
        // reordering does not churn every certificate path.
        let mut sorted: Vec<&str> = pats.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        buf.push_str(&sorted.join(","));
        buf.push(';');
    }
    buf.push_str("default=");
    match default {
        Some(id) => buf.push_str(&id.to_string()),
        None => buf.push_str("none"),
    }
    // Include regex scope_suffix in the fingerprint. A regex reference in
    // match_sni alone is not enough: changing the scope_suffix changes
    // wildcard confinement decisions, so certificates must not survive that.
    if !regexes.is_empty() {
        buf.push_str(";regexes={");
        let mut regex_vec: Vec<_> = regexes.iter().collect();
        regex_vec.sort_by_key(|(name, _)| *name);
        for (name, def) in regex_vec {
            buf.push_str(name);
            buf.push(':');
            buf.push_str(&def.pattern);
            buf.push('[');
            let mut scopes = def.scope_suffix.clone();
            scopes.sort();
            buf.push_str(&scopes.join(","));
            buf.push_str("];");
        }
        buf.push('}');
    }
    fnv1a(buf.as_bytes())
}

/// The canonical, order-stable rendering of a scope's full identity. Only ever
/// hashed, never parsed — but written to be readable in a debugger.
fn canonical(router_fp: u64, f: &Forwarding) -> String {
    let mut s = String::with_capacity(192);
    s.push_str(&format!("router={router_fp:016x};"));
    s.push_str(&format!("type={};", route_type_str(f.route_type)));
    s.push_str(&format!("host={};", f.host.as_deref().unwrap_or(REFLECT)));
    s.push_str(&format!("port={};", f.port));
    s.push_str(&format!("sni={};", sni_str(&f.sni)));
    s.push_str(&format!("family={:?};", f.family));
    s.push_str(&format!("nat64={};", f.nat64.as_deref().unwrap_or("-")));
    s.push_str(&format!("addr_resolver={};", f.addr_resolver));
    match &f.ech {
        Some(e) => s.push_str(&format!(
            "ech=mode:{:?},domain:{},resolver:{},inline:{};",
            e.mode,
            e.domain.as_deref().unwrap_or("-"),
            e.resolver,
            e.inline_config
        )),
        None => s.push_str("ech=-;"),
    }
    s
}

fn route_type_str(t: RouteType) -> &'static str {
    match t {
        RouteType::Ech => "ech",
        RouteType::Tls => "tls",
        RouteType::Http => "http",
        RouteType::Raw => "raw",
    }
}

fn sni_str(p: &SniPolicy) -> String {
    match p {
        SniPolicy::Reflect => "reflect".to_string(),
        SniPolicy::Omit => "omit".to_string(),
        SniPolicy::Fixed(n) => format!("fixed:{n}"),
    }
}

/// Reduce a string to characters that are safe in a path component on every
/// supported platform, collapsing runs so the result stays readable.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
            out.push(c);
        } else if !out.ends_with('_') {
            // Underscore is the separator, so a literal one and a replaced
            // character are the same thing: any run of them collapses to one.
            out.push('_');
        }
    }
    // Leading dots would create hidden directories; trailing dots are invalid on
    // Windows. Neither can occur for a host:port, but the input is config-driven.
    let trimmed = out.trim_matches('.').to_string();
    if trimmed.is_empty() {
        "_".to_string()
    } else {
        trimmed
    }
}

/// FNV-1a, 64-bit.
///
/// Chosen over `DefaultHasher` because that one's output is explicitly not
/// guaranteed stable across Rust versions, and these values name directories that
/// must survive a toolchain upgrade. Not cryptographic, and does not need to be:
/// the inputs are this process's own configuration, not attacker-chosen.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd() -> Forwarding {
        Forwarding {
            route_type: RouteType::Ech,
            host: Some("cf.0sm.com".into()),
            port: 443,
            sni: SniPolicy::Reflect,
            family: AddressFamily::Ipv4,
            nat64: None,
            addr_resolver: "dnspod-doh".into(),
            ech: Some(EchIdentity {
                mode: EchMode::Doh,
                domain: Some("cloudflare-ech.com".into()),
                resolver: "system".into(),
                inline_config: false,
            }),
        }
    }

    #[test]
    fn key_is_readable_and_stable() {
        let a = CertScope::new(7, &fwd());
        let b = CertScope::new(7, &fwd());
        assert_eq!(a, b, "same identity must yield the same scope");
        assert!(
            a.key().starts_with("ech_cf.0sm.com_443-"),
            "unexpected key {}",
            a.key()
        );
        // Filesystem-safe: one path component, no separators.
        assert!(!a.key().contains('/') && !a.key().contains('\\'));
    }

    #[test]
    fn every_forwarding_field_changes_the_scope() {
        let base = CertScope::new(1, &fwd());
        let mut cases: Vec<(&str, Forwarding)> = Vec::new();

        let mut f = fwd();
        f.route_type = RouteType::Tls;
        cases.push(("route_type", f));
        let mut f = fwd();
        f.host = None;
        cases.push(("host->reflect", f));
        let mut f = fwd();
        f.host = Some("other.example".into());
        cases.push(("host", f));
        let mut f = fwd();
        f.port = 8443;
        cases.push(("port", f));
        let mut f = fwd();
        f.sni = SniPolicy::Omit;
        cases.push(("sni omit", f));
        let mut f = fwd();
        f.sni = SniPolicy::Fixed("x.example".into());
        cases.push(("sni fixed", f));
        let mut f = fwd();
        f.family = AddressFamily::Dual;
        cases.push(("family", f));
        let mut f = fwd();
        f.nat64 = Some("64:ff9b::".into());
        cases.push(("nat64", f));
        let mut f = fwd();
        f.addr_resolver = "system".into();
        cases.push(("addr_resolver", f));
        let mut f = fwd();
        f.ech = None;
        cases.push(("ech absent", f));
        let mut f = fwd();
        f.ech.as_mut().unwrap().mode = EchMode::Static;
        cases.push(("ech mode", f));
        let mut f = fwd();
        f.ech.as_mut().unwrap().domain = None;
        cases.push(("ech domain", f));
        let mut f = fwd();
        f.ech.as_mut().unwrap().resolver = "cloudflare-doh".into();
        cases.push(("ech resolver", f));
        let mut f = fwd();
        f.ech.as_mut().unwrap().inline_config = true;
        cases.push(("ech inline", f));

        for (what, f) in cases {
            assert_ne!(
                base,
                CertScope::new(1, &f),
                "changing {what} must change the scope"
            );
        }
    }

    #[test]
    fn routing_table_is_part_of_the_scope() {
        // The same forwarding target under a different routing table is a
        // different scope: confinement is only ever proven against one table.
        assert_ne!(CertScope::new(1, &fwd()), CertScope::new(2, &fwd()));
    }

    #[test]
    fn router_fingerprint_ignores_pattern_order_but_not_content() {
        use std::collections::HashMap;
        let empty = HashMap::new();

        let a = router_fingerprint(&[vec![".a.test".into(), ".b.test".into()]], Some(0), &empty);
        let b = router_fingerprint(&[vec![".b.test".into(), ".a.test".into()]], Some(0), &empty);
        assert_eq!(a, b, "pattern order within a route must not matter");

        let c = router_fingerprint(&[vec![".a.test".into(), ".c.test".into()]], Some(0), &empty);
        assert_ne!(a, c, "different patterns must differ");

        let d = router_fingerprint(&[vec![".a.test".into(), ".b.test".into()]], None, &empty);
        assert_ne!(a, d, "presence of a default route must differ");

        // Route order matters: ids are how routes are referenced.
        let e = router_fingerprint(
            &[vec![".a.test".into()], vec![".b.test".into()]],
            Some(0),
            &empty,
        );
        let f = router_fingerprint(
            &[vec![".b.test".into()], vec![".a.test".into()]],
            Some(0),
            &empty,
        );
        assert_ne!(e, f);
    }

    #[test]
    fn router_fingerprint_includes_regex_scopes() {
        use crate::config::RegexDef;
        use std::collections::HashMap;

        let empty = HashMap::new();
        let patterns = vec![vec!["@cdn".into()]];

        // Base fingerprint without regex
        let base = router_fingerprint(&patterns, None, &empty);

        // Add a regex definition
        let mut regexes1 = HashMap::new();
        regexes1.insert(
            "cdn".to_string(),
            RegexDef {
                pattern: "^cdn-[0-9]+\\.example\\.com$".to_string(),
                scope_suffix: vec!["*.example.com".to_string()],
            },
        );
        let fp1 = router_fingerprint(&patterns, None, &regexes1);
        assert_ne!(base, fp1, "adding regex must change fingerprint");

        // Same regex name, different scope_suffix
        let mut regexes2 = HashMap::new();
        regexes2.insert(
            "cdn".to_string(),
            RegexDef {
                pattern: "^cdn-[0-9]+\\.example\\.com$".to_string(),
                scope_suffix: vec![".example.com".to_string()], // Different scope!
            },
        );
        let fp2 = router_fingerprint(&patterns, None, &regexes2);
        assert_ne!(fp1, fp2, "changing scope_suffix must change fingerprint");

        // Same scope_suffix, different pattern
        let mut regexes3 = HashMap::new();
        regexes3.insert(
            "cdn".to_string(),
            RegexDef {
                pattern: "^cdn-[a-z]+\\.example\\.com$".to_string(), // Different pattern
                scope_suffix: vec!["*.example.com".to_string()],
            },
        );
        let fp3 = router_fingerprint(&patterns, None, &regexes3);
        assert_ne!(fp1, fp3, "changing pattern must change fingerprint");

        // Multiple scope_suffix entries, order should not matter
        let mut regexes4 = HashMap::new();
        regexes4.insert(
            "cdn".to_string(),
            RegexDef {
                pattern: "^test$".to_string(),
                scope_suffix: vec!["*.a.com".to_string(), "*.b.com".to_string()],
            },
        );
        let mut regexes5 = HashMap::new();
        regexes5.insert(
            "cdn".to_string(),
            RegexDef {
                pattern: "^test$".to_string(),
                scope_suffix: vec!["*.b.com".to_string(), "*.a.com".to_string()], // Reversed
            },
        );
        let fp4 = router_fingerprint(&patterns, None, &regexes4);
        let fp5 = router_fingerprint(&patterns, None, &regexes5);
        assert_eq!(fp4, fp5, "scope_suffix order should not matter");
    }

    #[test]
    fn sanitize_produces_one_safe_component() {
        assert_eq!(sanitize("ech_cf.0sm.com_443"), "ech_cf.0sm.com_443");
        assert_eq!(sanitize("tls_[2a01:4f8::1]_443"), "tls_2a01_4f8_1_443");
        assert_eq!(sanitize("a//b\\c"), "a_b_c");
        assert_eq!(sanitize("..."), "_");
        assert!(!sanitize("../escape").contains(".."));
    }
}
