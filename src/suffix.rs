//! Public-suffix handling and certificate planning.
//!
//! The list can be sourced three ways (embedded, file, network) and swapped at
//! runtime behind an `ArcSwap`-style lock, so a background refresh never blocks
//! the hot path.
//!
//! Given an SNI host name and issuance mode, [`SuffixList::plan`] returns the
//! certificate to (re)issue: a coverage anchor — the **registrable domain** —
//! that keys the cache/store, and the names this host contributes to it. Every
//! certificate is anchored at the registrable domain, so a whole domain shares
//! one `<registrable>.crt` and siblings reuse it via [`host_covered_by`].
//!
//! Two deliberate choices shape the SANs:
//!
//! * **Anchor at the parent, not the host.** The only wildcard that usefully
//!   covers a host `H` is `*.parent(H)` (`*.H` would cover children `H` usually
//!   never has). So a level's `*.X` wildcard is emitted only when some accessed
//!   host actually has `X` as its parent — a leaf like `rr5.googlevideo.com`
//!   never yields the useless `*.rr5.googlevideo.com`.
//! * **ICANN suffixes only.** The registrable domain is computed against the
//!   PSL's ICANN section, ignoring private-section entries. Real registry
//!   suffixes (`co.uk`, `co.jp`) remain boundaries — `*.co.jp` is never issued —
//!   while vendor self-registrations (`withgoogle.com`, `github.io`) are treated
//!   as ordinary registrable domains, so `csp.withgoogle.com` can be served by
//!   `withgoogle.com.crt: {*.withgoogle.com, withgoogle.com}`.

use std::sync::RwLock;

use anyhow::Result;
use publicsuffix::{List, Psl, Type};

use crate::config::IssuanceMode;

/// A public-suffix list, replaceable at runtime.
pub struct SuffixList {
    list: RwLock<List>,
}

/// The list compiled into the binary as an always-available fallback.
const EMBEDDED_LIST: &[u8] = include_bytes!("../assets/public_suffix_list.dat");

impl SuffixList {
    /// Build from the embedded list.
    pub fn embedded() -> Result<Self> {
        let list = List::from_bytes(EMBEDDED_LIST)
            .map_err(|e| anyhow::anyhow!("parsing embedded public suffix list: {e}"))?;
        Ok(Self {
            list: RwLock::new(list),
        })
    }

    /// Build from a `.dat` file on disk.
    pub fn from_file(bytes: &[u8]) -> Result<Self> {
        let list = List::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("parsing public suffix list file: {e}"))?;
        Ok(Self {
            list: RwLock::new(list),
        })
    }

    /// Replace the active list (used by the background network refresher).
    /// Rejects an obviously-broken download rather than swapping it in.
    pub fn replace_from_bytes(&self, bytes: &[u8]) -> Result<()> {
        let parsed = List::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("parsing downloaded public suffix list: {e}"))?;
        // Sanity check: a valid list resolves a well-known multi-level suffix.
        anyhow::ensure!(
            parsed.domain(b"example.co.uk").is_some(),
            "downloaded list failed a sanity check; keeping the current list"
        );
        *self.list.write().unwrap() = parsed;
        Ok(())
    }

    /// Plan the names an inbound SNI host contributes to its registrable
    /// domain's certificate, under the configured [`IssuanceMode`].
    ///
    /// The returned [`Certificand::base`] is the coverage anchor — the
    /// registrable domain (ICANN-only; see the module docs) that keys the
    /// cache/store and is the CN candidate. It is always a plain name, so it
    /// maps to a safe file stem. `sans` are the names this host needs; the
    /// resolver merges them into the anchor's existing certificate, so a domain
    /// accumulates coverage in one `<registrable>.crt` and already-covered hosts
    /// are never re-signed. Per mode, for a host `H` with registrable `R`:
    ///
    /// * [`IssuanceMode::Exact`] — `{H}`. No wildcard.
    /// * [`IssuanceMode::Wildcard`] — `{*.parent(H)}` (and `{*.R, R}` when
    ///   `H == R`): the host and its siblings, via the parent's wildcard. Never
    ///   `*.H`.
    /// * [`IssuanceMode::Ladder`] — `{*.parent(H), *.grandparent(H), …, *.R, R}`:
    ///   the host, every ancestor domain, and their siblings. For
    ///   `b.a.example.com` / `example.com`:
    ///   `{*.a.example.com, *.example.com, example.com}`. Never `*.H`, and the
    ///   wildcard is never lifted above `R`, so `*.com` can never be produced.
    ///
    /// IP literals and hosts with no ICANN registrable domain fall back to an
    /// exact, host-keyed certificate. The returned SANs always cover `host`.
    pub fn plan(&self, host: &str, mode: IssuanceMode) -> Certificand {
        // IP literals never get a wildcard.
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Certificand::exact(host);
        }

        let host = host.trim_end_matches('.').to_ascii_lowercase();

        let list = self.list.read().unwrap();
        let Some(registrable) = registrable_icann(&list, &host) else {
            // No registrable domain (bare suffix, single label): exact only.
            return Certificand::exact(&host);
        };
        drop(list);

        let sans = match mode {
            IssuanceMode::Exact => vec![host.clone()],
            IssuanceMode::Wildcard => {
                if host == registrable {
                    vec![format!("*.{registrable}"), registrable.clone()]
                } else {
                    // `*.parent(H)` covers H and its siblings — never `*.H`.
                    vec![format!("*.{}", parent_domain(&host))]
                }
            }
            IssuanceMode::Ladder => ladder_sans(&host, &registrable),
        };

        Certificand {
            base: registrable,
            sans,
        }
    }
}

/// The registrable domain of `host`, ignoring the PSL's **private** section so
/// private-section entries (e.g. `github.io`, `withgoogle.com`) are treated as
/// ordinary registrable domains rather than issuance boundaries. Real registry
/// suffixes (ICANN) and unknown TLDs both remain boundaries. Returns `None` when
/// `host` has no registrable domain (it is itself a public suffix, a bare TLD,
/// or a single label).
fn registrable_icann(list: &List, host: &str) -> Option<String> {
    let suffix = list.suffix(host.as_bytes())?;
    let suffix_str = std::str::from_utf8(suffix.as_bytes()).ok()?;

    // The effective boundary suffix. If the longest matching suffix is private,
    // walk down its labels to the enclosing non-private suffix (the private
    // `withgoogle.com` resolves to `com`; `github.io` to `io`). ICANN suffixes
    // and unknown TLDs (`typ() == None`) are boundaries as-is.
    let boundary = if suffix.typ() == Some(Type::Private) {
        let mut cur = suffix_str;
        loop {
            let rest = cur.split_once('.').map(|(_, r)| r)?;
            let s = list.suffix(rest.as_bytes())?;
            if s.typ() != Some(Type::Private) {
                break std::str::from_utf8(s.as_bytes()).ok()?.to_string();
            }
            cur = rest;
        }
    } else {
        suffix_str.to_string()
    };

    one_label_below(host, &boundary)
}

/// The domain one label below `suffix` within `host` (the registrable domain),
/// or `None` when `host` is the suffix itself.
fn one_label_below(host: &str, suffix: &str) -> Option<String> {
    if host == suffix {
        return None;
    }
    let left = host.strip_suffix(suffix)?.strip_suffix('.')?;
    let last = left.rsplit('.').next()?;
    if last.is_empty() {
        None
    } else {
        Some(format!("{last}.{suffix}"))
    }
}

/// `host` with its leftmost label removed (its parent domain). A single-label
/// input is returned unchanged.
fn parent_domain(host: &str) -> &str {
    host.split_once('.')
        .map(|(_, parent)| parent)
        .unwrap_or(host)
}

/// The ladder SANs a host contributes: `*.parent(H)`, `*.grandparent(H)`, … up
/// to `*.registrable`, plus the bare registrable domain. `host` and
/// `registrable` must be normalized, with `registrable` a label-boundary suffix
/// of `host`.
fn ladder_sans(host: &str, registrable: &str) -> Vec<String> {
    if host == registrable {
        return vec![format!("*.{registrable}"), registrable.to_string()];
    }
    let mut sans = Vec::new();
    let mut cur = parent_domain(host);
    loop {
        sans.push(format!("*.{cur}"));
        if cur == registrable {
            break;
        }
        let next = parent_domain(cur);
        // Progress guard: `registrable` is a suffix of `host`, so climbing always
        // reaches it; stop if a label could not be removed.
        if next.len() >= cur.len() {
            break;
        }
        cur = next;
    }
    // The registrable apex has no covering parent wildcard (`*.<suffix>` is
    // forbidden), so it is the one bare name we must emit.
    sans.push(registrable.to_string());
    sans
}

/// Whether a certificate carrying `sans` is valid for `host` — i.e. some SAN
/// equals `host`, or a single-level wildcard SAN `*.<parent>` matches it. Used
/// to reuse an already-issued certificate for a sibling host instead of signing
/// a redundant one. `host` must be normalized (lowercase, no trailing dot).
pub fn host_covered_by(sans: &[String], host: &str) -> bool {
    sans.iter().any(|san| {
        if san == host {
            return true;
        }
        // `*.suffix` matches exactly one label to the left of `suffix`.
        match san.strip_prefix("*.") {
            Some(suffix) => match host.split_once('.') {
                Some((label, rest)) => !label.is_empty() && rest == suffix,
                None => false,
            },
            None => false,
        }
    })
}

/// The names a certificate should be issued for, plus the cache/store key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificand {
    /// Cache/store key and certificate CN candidate — the registrable domain
    /// (or the host itself for IP / no-registrable fallbacks). Always a plain
    /// name, so it maps to a safe file stem.
    pub base: String,
    /// Subject alternative names this host contributes. Always covers the host.
    pub sans: Vec<String>,
}

impl Certificand {
    /// An exact (non-wildcard) certificate keyed by and covering a single host.
    pub fn exact(host: &str) -> Self {
        Self {
            base: host.to_string(),
            sans: vec![host.to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> SuffixList {
        SuffixList::embedded().unwrap()
    }

    use IssuanceMode::{Exact, Ladder, Wildcard};

    // Everything anchors at the registrable domain.
    #[test]
    fn everything_is_keyed_at_the_registrable_domain() {
        for (host, mode) in [
            ("b.a.example.com", Exact),
            ("b.a.example.com", Wildcard),
            ("b.a.example.com", Ladder),
        ] {
            assert_eq!(list().plan(host, mode).base, "example.com");
        }
    }

    // -- Exact mode: just the host (no wildcard) ----------------------------

    #[test]
    fn exact_contributes_only_the_bare_host() {
        let c = list().plan("b.a.example.com", Exact);
        assert_eq!(c.base, "example.com");
        assert_eq!(c.sans, vec!["b.a.example.com"]);
    }

    // -- Wildcard mode: parent wildcard, never *.host -----------------------

    #[test]
    fn wildcard_uses_the_parent_wildcard_not_the_leaf() {
        // The motivating case: a leaf CDN host must NOT get a `*.leaf` wildcard;
        // `*.parent` is what actually covers it and its siblings.
        let c = list().plan("rr5.googlevideo.com", Wildcard);
        assert_eq!(c.base, "googlevideo.com");
        assert_eq!(c.sans, vec!["*.googlevideo.com"]);
        assert!(host_covered_by(&c.sans, "rr5.googlevideo.com"));
        assert!(!c.sans.iter().any(|s| s == "*.rr5.googlevideo.com"));
    }

    #[test]
    fn wildcard_deep_host_anchors_at_its_parent() {
        let c = list().plan("b.a.example.com", Wildcard);
        assert_eq!(c.sans, vec!["*.a.example.com"]);
        assert!(host_covered_by(&c.sans, "b.a.example.com"));
    }

    #[test]
    fn wildcard_apex_access_covers_self_and_children() {
        let c = list().plan("example.com", Wildcard);
        assert_eq!(c.sans, vec!["*.example.com", "example.com"]);
    }

    // -- Ladder mode: parent..registrable wildcards, never *.host -----------

    #[test]
    fn ladder_is_the_ancestor_chain_without_the_leaf_wildcard() {
        let c = list().plan("b.a.example.com", Ladder);
        assert_eq!(c.base, "example.com");
        assert_eq!(
            c.sans,
            vec!["*.a.example.com", "*.example.com", "example.com"]
        );
        // No useless leaf wildcard.
        assert!(!c.sans.iter().any(|s| s == "*.b.a.example.com"));
        // Covers the host, its ancestors, and their siblings.
        for h in [
            "b.a.example.com",
            "a.example.com",
            "other.a.example.com",
            "example.com",
            "www.example.com",
        ] {
            assert!(host_covered_by(&c.sans, h), "ladder must cover {h}");
        }
        // But not a deeper, unseen branch.
        assert!(!host_covered_by(&c.sans, "x.b.a.example.com"));
    }

    #[test]
    fn ladder_apex_access() {
        let c = list().plan("example.com", Ladder);
        assert_eq!(c.sans, vec!["*.example.com", "example.com"]);
    }

    #[test]
    fn ladder_never_emits_wildcard_above_registrable() {
        // co.uk is an ICANN public suffix: the ladder anchors at a.co.uk and
        // never emits *.co.uk.
        let c = list().plan("www.a.co.uk", Ladder);
        assert_eq!(c.base, "a.co.uk");
        assert_eq!(c.sans, vec!["*.a.co.uk", "a.co.uk"]);
        assert!(!c.sans.iter().any(|s| s == "*.co.uk"));
    }

    // -- ICANN-only registrable: private-section entries are ordinary -------

    #[test]
    fn psl_private_section_is_treated_as_ordinary_domain() {
        // github.io is a PSL *private*-section suffix. Under ICANN-only rules it
        // is an ordinary registrable domain, so we can serve `*.github.io`
        // rather than being forced down to `<user>.github.io`.
        let c = list().plan("user.github.io", Ladder);
        assert_eq!(c.base, "github.io");
        assert_eq!(c.sans, vec!["*.github.io", "github.io"]);

        // The user's case: csp.withgoogle.com (withgoogle.com is private) is
        // served by the withgoogle.com certificate.
        let c2 = list().plan("csp.withgoogle.com", Ladder);
        assert_eq!(c2.base, "withgoogle.com");
        assert_eq!(c2.sans, vec!["*.withgoogle.com", "withgoogle.com"]);
        assert!(host_covered_by(&c2.sans, "csp.withgoogle.com"));
        assert!(host_covered_by(&c2.sans, "withgoogle.com"));
    }

    // -- Coverage predicate -------------------------------------------------

    #[test]
    fn coverage_predicate_matches_single_level_wildcards_only() {
        let sans = vec!["*.a.example.com".to_string(), "example.com".to_string()];
        // Exact and single-label-left of a wildcard match.
        assert!(host_covered_by(&sans, "example.com"));
        assert!(host_covered_by(&sans, "b.a.example.com"));
        // Two labels left of the wildcard suffix do NOT match.
        assert!(!host_covered_by(&sans, "x.b.a.example.com"));
        // Sibling of the wildcard suffix is not the suffix itself.
        assert!(!host_covered_by(&sans, "a.example.com"));
        assert!(!host_covered_by(&sans, "other.com"));
    }

    // -- Degenerate inputs: always exact, regardless of mode ----------------

    #[test]
    fn ip_literal_is_exact_in_every_mode() {
        for m in [Exact, Wildcard, Ladder] {
            let c = list().plan("127.0.0.1", m);
            assert_eq!(c.base, "127.0.0.1");
            assert_eq!(c.sans, vec!["127.0.0.1"]);
        }
    }

    #[test]
    fn bare_suffix_has_no_registrable_and_is_exact() {
        // "com" is a public suffix with no registrable domain.
        let c = list().plan("com", Ladder);
        assert_eq!(c.base, "com");
        assert_eq!(c.sans, vec!["com"]);
    }
}
