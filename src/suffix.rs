//! Public-suffix handling.
//!
//! The list can be sourced three ways (embedded, file, network) and swapped at
//! runtime behind an `ArcSwap`-style lock, so a background refresh never blocks
//! the hot path.
//!
//! # What the list is for
//!
//! Certificate coverage is **mirrored from the upstream's own certificate** (see
//! [`crate::resolver`]), so the list no longer plans SANs. It answers one
//! question instead, and that question is load-bearing:
//!
//! > Is a wildcard this gateway is about to mint confined to a single registrable
//! > domain?
//!
//! A mirrored SAN arrives from a *remote* certificate, and this gateway re-signs
//! it with a CA the client's own trust store accepts. A wildcard that spans a
//! registry boundary — `*.com`, `*.co.uk` — must therefore never be minted, no
//! matter what the upstream claimed: no real CA would issue it, and under a
//! locally-trusted CA it would be valid for the entire suffix. See
//! [`SuffixList::wildcard_is_mintable`].
//!
//! **ICANN suffixes only.** The boundary is computed against the PSL's ICANN
//! section, ignoring private-section entries. Real registry suffixes (`co.uk`,
//! `co.jp`) remain boundaries, while vendor self-registrations (`withgoogle.com`,
//! `github.io`) are treated as ordinary registrable domains — so an upstream that
//! genuinely serves `*.github.io` can still be mirrored faithfully.

use std::sync::RwLock;

use anyhow::Result;
use publicsuffix::{List, Psl, Type};

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
        *self
            .list
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = parsed;
        Ok(())
    }

    /// Whether the single-level wildcard `*.<parent>` stays inside one
    /// registrable domain, and may therefore be minted by this gateway's CA.
    ///
    /// `true` when `parent` is a registrable domain or something below one:
    /// `*.example.com`, `*.a.example.com`, `*.github.io` (private-section entries
    /// are ordinary domains; see the module docs).
    ///
    /// `false` when `parent` is itself a public suffix, a bare TLD, or an unknown
    /// single label — `*.com`, `*.co.uk`, `*.localhost` — because such a wildcard
    /// would be valid across a registry boundary. An upstream certificate that
    /// claims one is not mirrored; the wildcard is dropped and narrower coverage
    /// is issued instead.
    ///
    /// An IP literal is never a wildcard parent, so it is refused too.
    pub fn wildcard_is_mintable(&self, parent: &str) -> bool {
        if parent.parse::<std::net::IpAddr>().is_ok() {
            return false;
        }
        let parent = parent.trim_end_matches('.').to_ascii_lowercase();
        let list = self
            .list
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registrable_icann(&list, &parent).is_some()
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

/// Whether a certificate carrying `sans` is valid for `host` — i.e. some SAN
/// equals `host`, or a single-level wildcard SAN `*.<parent>` matches it. This is
/// the coverage rule a TLS client applies (RFC 6125 §6.4.3), used both to decide
/// whether an upstream certificate actually speaks for the name we asked it about
/// and whether a persisted certificate can still be served. `host` must be
/// normalized (lowercase, no trailing dot).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> SuffixList {
        SuffixList::embedded().unwrap()
    }

    // -- The registry boundary: which mirrored wildcards may be minted ------

    #[test]
    fn wildcard_inside_a_registrable_domain_is_mintable() {
        let l = list();
        // Parent is the registrable domain itself, or below it.
        assert!(l.wildcard_is_mintable("example.com"));
        assert!(l.wildcard_is_mintable("a.example.com"));
        assert!(l.wildcard_is_mintable("b.a.example.com"));
        // Multi-level ICANN suffix: one label below it is registrable.
        assert!(l.wildcard_is_mintable("a.co.uk"));
        assert!(l.wildcard_is_mintable("www.a.co.uk"));
    }

    #[test]
    fn wildcard_spanning_a_registry_boundary_is_refused() {
        let l = list();
        // A bare TLD and a multi-level ICANN suffix are boundaries: `*.com` and
        // `*.co.uk` would be valid across an entire registry.
        assert!(!l.wildcard_is_mintable("com"));
        assert!(!l.wildcard_is_mintable("co.uk"));
        assert!(!l.wildcard_is_mintable("co.jp"));
        // An unknown single label is also a boundary (`*.localhost`).
        assert!(!l.wildcard_is_mintable("localhost"));
        // Trailing dot and case are normalized before the check.
        assert!(!l.wildcard_is_mintable("CO.UK."));
    }

    #[test]
    fn ip_literal_is_never_a_wildcard_parent() {
        let l = list();
        assert!(!l.wildcard_is_mintable("127.0.0.1"));
        assert!(!l.wildcard_is_mintable("::1"));
    }

    #[test]
    fn psl_private_section_is_treated_as_ordinary_domain() {
        // `github.io` and `withgoogle.com` are PSL *private*-section suffixes.
        // Under ICANN-only rules they are ordinary registrable domains, so an
        // upstream that genuinely serves `*.github.io` can be mirrored as-is.
        let l = list();
        assert!(l.wildcard_is_mintable("github.io"));
        assert!(l.wildcard_is_mintable("withgoogle.com"));
        // The ICANN suffix underneath them is still a boundary.
        assert!(!l.wildcard_is_mintable("io"));
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

    #[test]
    fn coverage_predicate_rejects_an_empty_wildcard_label() {
        // `.example.com` has an empty leftmost label, so it is not a host a
        // wildcard may cover, and a bare `*` never covers anything.
        let sans = vec!["*.example.com".to_string()];
        assert!(!host_covered_by(&sans, ".example.com"));
        assert!(!host_covered_by(&["*".to_string()], "example.com"));
        // An empty SAN list covers nothing.
        assert!(!host_covered_by(&[], "example.com"));
    }

    #[test]
    fn coverage_predicate_rejects_a_wildcard_at_the_apex_it_names() {
        // `*.example.com` does not cover `example.com` itself — the rule a client
        // applies, and the reason an apex needs its own bare SAN.
        let sans = vec!["*.example.com".to_string()];
        assert!(!host_covered_by(&sans, "example.com"));
        assert!(host_covered_by(&sans, "www.example.com"));
    }
}
