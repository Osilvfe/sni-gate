//! SNI/Host router.
//!
//! Patterns are compiled once at startup into O(1) lookup maps (exact, wildcard,
//! suffix) plus a precompiled regex list. Matching follows a fixed precedence so
//! the most specific rule always wins:
//!
//!   1. exact       `p.example.com`
//!   2. wildcard    `*.example.com`  (one left label)
//!   3. suffix      `.example.com`   (example.com and any subdomain)
//!   4. regex       `~<pattern>`     (config order)
//!   5. default server
//!
//! Hosts are normalized (lowercased, trailing dot removed) before matching.

use std::collections::HashMap;

use regex::Regex;

use crate::error::ConfigError;

/// Index into the runtime route table. The default server, if present, is a
/// route like any other and is referenced by its own id.
pub type RouteId = usize;

/// A compiled router. Cheap to share behind an `Arc`.
#[derive(Debug)]
pub struct Router {
    exact: HashMap<String, RouteId>,
    /// Keyed by the parent domain: `*.example.com` -> "example.com".
    wildcard: HashMap<String, RouteId>,
    /// Keyed by the domain: `.example.com` -> "example.com".
    suffix: HashMap<String, RouteId>,
    regex: Vec<(Regex, RouteId)>,
    default: Option<RouteId>,
}

impl Router {
    /// Build a router from each route's patterns. `patterns[i]` are the raw
    /// `match_sni` entries for route id `i`. `default` is the id of the default
    /// server route, if any.
    ///
    /// Later duplicate keys within the same tier are rejected so routing is
    /// deterministic and misconfiguration is caught at load time.
    pub fn build(patterns: &[Vec<String>], default: Option<RouteId>) -> Result<Self, ConfigError> {
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        let mut suffix = HashMap::new();
        let mut regex = Vec::new();

        for (id, pats) in patterns.iter().enumerate() {
            for pat in pats {
                let pat = pat.trim();
                if pat.is_empty() {
                    continue;
                }
                if let Some(rest) = pat.strip_prefix('~') {
                    let re = Regex::new(rest).map_err(|e| {
                        ConfigError::Invalid(format!("invalid regex pattern `{pat}`: {e}"))
                    })?;
                    regex.push((re, id));
                } else if let Some(rest) = pat.strip_prefix("*.") {
                    insert_unique(&mut wildcard, normalize(rest), id, pat)?;
                } else if let Some(rest) = pat.strip_prefix('.') {
                    insert_unique(&mut suffix, normalize(rest), id, pat)?;
                } else {
                    insert_unique(&mut exact, normalize(pat), id, pat)?;
                }
            }
        }

        Ok(Router {
            exact,
            wildcard,
            suffix,
            regex,
            default,
        })
    }

    /// Resolve a host to a route id following the precedence order. Returns the
    /// default server id when nothing else matches (or `None` if there is none).
    pub fn match_host(&self, host: &str) -> Option<RouteId> {
        let host = normalize(host);
        if host.is_empty() {
            return self.default;
        }

        // 1. exact
        if let Some(&id) = self.exact.get(&host) {
            return Some(id);
        }

        // 2. wildcard: strip exactly one leftmost label, match the parent.
        if let Some(parent) = host.split_once('.').map(|(_, rest)| rest) {
            if let Some(&id) = self.wildcard.get(parent) {
                return Some(id);
            }
        }

        // 3. suffix: the domain itself, or any ancestor domain.
        //    e.g. host = a.b.example.com is checked against a.b.example.com,
        //    b.example.com, example.com, com — the first present in the suffix
        //    map wins. `.example.com` is stored as key "example.com" so it
        //    matches both example.com and any subdomain.
        if !self.suffix.is_empty() {
            let mut cur = host.as_str();
            loop {
                if let Some(&id) = self.suffix.get(cur) {
                    return Some(id);
                }
                match cur.split_once('.') {
                    Some((_, rest)) => cur = rest,
                    None => break,
                }
            }
        }

        // 4. regex, in config order
        for (re, id) in &self.regex {
            if re.is_match(&host) {
                return Some(*id);
            }
        }

        // 5. default
        self.default
    }
}

/// Why a candidate wildcard SAN is **not** confined to one certificate scope —
/// i.e. why issuing it could let a client coalesce a connection into the wrong
/// upstream. Carries enough detail to name the culprit in a startup warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Escape {
    /// A concrete host the wildcard would cover routes to a different scope.
    Host { host: String, route: RouteId },
    /// Hosts under the wildcard fall through to the regex tier, and some regex
    /// route belongs to a different scope. Regex match sets are not statically
    /// decidable, so this is refused conservatively.
    RegexTier { route: RouteId },
    /// Hosts under the wildcard reach the `default_route`, which is in a
    /// different scope.
    DefaultRoute { route: RouteId },
    /// Hosts under the wildcard match no route at all. Serving a certificate for
    /// a name this listener would refuse is itself a misdirection.
    Unmatched,
}

impl Router {
    /// Whether every host a single-level wildcard `*.<parent>` would cover routes
    /// into the caller's certificate scope. `Ok(())` means the wildcard is safe
    /// to put in a certificate for that scope; `Err(escape)` names a reason it is
    /// not.
    ///
    /// `in_scope` answers "does this route id share the owner's certificate
    /// scope?" — see [`crate::certscope`]. The predicate rather than a bare
    /// `RouteId` is what lets routes that forward identically keep sharing one
    /// certificate.
    ///
    /// # Why this is decidable
    ///
    /// `*.P` covers the infinitely many hosts `L.P` for a single label `L`, but
    /// the router resolves them in a fixed tier order and only finitely much of
    /// that depends on `L`:
    ///
    /// * Hosts named **explicitly** — an `exact` or `suffix` pattern that is
    ///   itself one label above `P` — are enumerable, and each is resolved here
    ///   through [`Router::match_host`] itself, so this check can never disagree
    ///   with real routing.
    /// * Every **other** `L.P` shares one verdict: the `*.P` wildcard entry if
    ///   present, else the suffix walk starting at `P` (independent of `L`), else
    ///   the regex tier, else `default_route`.
    ///
    /// The regex tier is the only undecidable step, and it is reached only when
    /// the wildcard and suffix tiers both miss. When every regex route is already
    /// in scope, a regex match is harmless and the verdict falls to the default
    /// route; otherwise the wildcard is refused.
    pub fn wildcard_confined<F>(&self, parent: &str, in_scope: &F) -> Result<(), Escape>
    where
        F: Fn(RouteId) -> bool,
    {
        let parent = normalize(parent);

        // 1. Explicitly named hosts one label above `parent`, resolved through the
        //    real matcher. Sorted so the reported escape is deterministic.
        let mut named: Vec<&String> = self
            .exact
            .keys()
            .chain(self.suffix.keys())
            .filter(|k| one_label_above(k, &parent).is_some())
            .collect();
        named.sort_unstable();
        for host in named {
            match self.match_host(host) {
                Some(id) if in_scope(id) => {}
                Some(id) => {
                    return Err(Escape::Host {
                        host: host.clone(),
                        route: id,
                    })
                }
                None => return Err(Escape::Unmatched),
            }
        }

        // 2. The generic verdict shared by every other `L.parent`.
        if let Some(&id) = self.wildcard.get(&parent) {
            return if in_scope(id) {
                Ok(())
            } else {
                Err(Escape::Host {
                    host: format!("*.{parent}"),
                    route: id,
                })
            };
        }

        // Suffix walk starts at `parent`: the `L.parent` step is a named host,
        // already handled above.
        let mut cur = parent.as_str();
        loop {
            if let Some(&id) = self.suffix.get(cur) {
                return if in_scope(id) {
                    Ok(())
                } else {
                    Err(Escape::Host {
                        host: format!(".{cur}"),
                        route: id,
                    })
                };
            }
            match cur.split_once('.') {
                Some((_, rest)) => cur = rest,
                None => break,
            }
        }

        // 3. Whatever the regex tier does not claim lands on the default route.
        //    Checked *before* the regex tier: when both are escapes either verdict
        //    is sound, but this one names a concrete route the operator can act on,
        //    whereas `RegexTier` only says "a regex might match". Testing it first
        //    also means the conservative regex rule below only ever decides a case
        //    that would otherwise have been confined.
        match self.default {
            Some(id) if !in_scope(id) => return Err(Escape::DefaultRoute { route: id }),
            None => return Err(Escape::Unmatched),
            Some(_) => {}
        }

        // 4. Regex tier, reached only because the tiers above missed. Whether a
        //    regex can match some `L.parent` is not statically decidable, so a
        //    regex route outside this scope refuses the wildcard even if it could
        //    never actually match one of these hosts.
        for (_, id) in &self.regex {
            if !in_scope(*id) {
                return Err(Escape::RegexTier { route: *id });
            }
        }

        Ok(())
    }

    /// Whether an exact (non-wildcard) name routes into the caller's certificate
    /// scope. A certificate must not assert a bare name this listener would send
    /// somewhere else.
    pub fn name_confined<F>(&self, name: &str, in_scope: &F) -> Result<(), Escape>
    where
        F: Fn(RouteId) -> bool,
    {
        match self.match_host(name) {
            Some(id) if in_scope(id) => Ok(()),
            Some(id) => Err(Escape::Host {
                host: normalize(name),
                route: id,
            }),
            None => Err(Escape::Unmatched),
        }
    }
}

/// The single label of `key` directly above `parent`, or `None` when `key` is not
/// exactly one label above it. `"b.a.com"` is one label above `"a.com"`;
/// `"c.b.a.com"` and `"a.com"` are not.
fn one_label_above<'k>(key: &'k str, parent: &str) -> Option<&'k str> {
    let left = key.strip_suffix(parent)?.strip_suffix('.')?;
    if left.is_empty() || left.contains('.') {
        None
    } else {
        Some(left)
    }
}

/// Normalize a host for matching: lowercase, strip a trailing dot, strip a
/// port suffix if present (Host headers may carry `:port`).
fn normalize(host: &str) -> String {
    let host = host.trim();
    // Strip a :port (but not part of an IPv6 literal in brackets).
    let host = if host.starts_with('[') {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn insert_unique(
    map: &mut HashMap<String, RouteId>,
    key: String,
    id: RouteId,
    pat: &str,
) -> Result<(), ConfigError> {
    if map.contains_key(&key) {
        return Err(ConfigError::Invalid(format!(
            "duplicate match pattern `{pat}` maps to more than one route"
        )));
    }
    map.insert(key, id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        // id 0: exact p.nginxsni.com
        // id 1: suffix .nginxsni.com
        // id 2: wildcard *.wild.com
        // id 3: regex ^p[0-9]+\.re\.com$
        Router::build(
            &[
                vec!["p.nginxsni.com".into()],
                vec![".nginxsni.com".into()],
                vec!["*.wild.com".into()],
                vec!["~^p[0-9]+\\.re\\.com$".into()],
            ],
            Some(9),
        )
        .unwrap()
    }

    #[test]
    fn exact_beats_suffix() {
        assert_eq!(router().match_host("p.nginxsni.com"), Some(0));
    }

    #[test]
    fn suffix_matches_sub_and_root() {
        let r = router();
        assert_eq!(r.match_host("x.nginxsni.com"), Some(1));
        assert_eq!(r.match_host("nginxsni.com"), Some(1));
        assert_eq!(r.match_host("a.b.nginxsni.com"), Some(1));
    }

    #[test]
    fn wildcard_one_label_only() {
        let r = router();
        assert_eq!(r.match_host("a.wild.com"), Some(2));
        // two labels left of wild.com must NOT match the wildcard
        assert_eq!(r.match_host("a.b.wild.com"), Some(9)); // falls to default
    }

    #[test]
    fn regex_matches() {
        assert_eq!(router().match_host("p12.re.com"), Some(3));
    }

    #[test]
    fn default_and_empty() {
        let r = router();
        assert_eq!(r.match_host("nope.example.org"), Some(9));
        assert_eq!(r.match_host(""), Some(9));
    }

    #[test]
    fn normalize_port_and_case() {
        assert_eq!(router().match_host("P.NginxSNI.com:443"), Some(0));
    }

    // -- Certificate-scope confinement -------------------------------------
    //
    // These cover the decision procedure that makes SAN clipping sound. The
    // predicate stands in for "shares the owner's certificate scope".

    /// Only route `owner` is in scope.
    fn only(owner: RouteId) -> impl Fn(RouteId) -> bool {
        move |id| id == owner
    }

    #[test]
    fn wildcard_is_confined_when_the_suffix_tier_owns_everything() {
        // .site.test -> 0, and nothing else touches it. `*.site.test` is safe.
        let r = Router::build(&[vec![".site.test".into()]], None).unwrap();
        assert_eq!(r.wildcard_confined("site.test", &only(0)), Ok(()));
    }

    #[test]
    fn wildcard_escapes_via_an_exact_exception() {
        // The motivating shape: a suffix route owns the domain, but one sibling
        // is pinned to a different route. `*.site.test` must be refused.
        let r = Router::build(
            &[vec![".site.test".into()], vec!["odd.site.test".into()]],
            None,
        )
        .unwrap();
        assert_eq!(
            r.wildcard_confined("site.test", &only(0)),
            Err(Escape::Host {
                host: "odd.site.test".into(),
                route: 1
            })
        );
        // From the other side, the exception's own bare name is fine.
        assert_eq!(r.name_confined("odd.site.test", &only(1)), Ok(()));
    }

    #[test]
    fn wildcard_escapes_to_the_default_route() {
        // Exactly the reported bug: an exact route for the apex, siblings falling
        // through to default_route. `*.site.test` must not be issued.
        let r = Router::build(&[vec!["site.test".into()], vec![]], Some(1)).unwrap();
        assert_eq!(
            r.wildcard_confined("site.test", &only(0)),
            Err(Escape::DefaultRoute { route: 1 })
        );
        // The apex's own name is still confined to its route.
        assert_eq!(r.name_confined("site.test", &only(0)), Ok(()));
        // And from the default route's side, a sibling's bare name is confined.
        assert_eq!(r.name_confined("static.site.test", &only(1)), Ok(()));
        // But the default route must not claim the apex, which routes elsewhere.
        assert_eq!(
            r.name_confined("site.test", &only(1)),
            Err(Escape::Host {
                host: "site.test".into(),
                route: 0
            })
        );
    }

    #[test]
    fn wildcard_escapes_when_nothing_matches() {
        // No default route: hosts under the wildcard match nothing. Serving a
        // certificate for a name we would refuse is itself a misdirection.
        let r = Router::build(&[vec!["site.test".into()]], None).unwrap();
        assert_eq!(
            r.wildcard_confined("site.test", &only(0)),
            Err(Escape::Unmatched)
        );
    }

    #[test]
    fn regex_tier_only_matters_when_it_is_reachable() {
        // A regex route in a different scope, but the suffix tier answers first,
        // so the regex is never consulted for these hosts: still confined.
        let r = Router::build(
            &[
                vec![".site.test".into()],
                vec!["~^host[0-9]+\\.other\\.test$".into()],
            ],
            None,
        )
        .unwrap();
        assert_eq!(r.wildcard_confined("site.test", &only(0)), Ok(()));

        // Same regex, but now nothing above the regex tier answers for
        // `*.bare.test`, so it is refused conservatively. The default route is in
        // scope here, which is what isolates the regex tier as the sole cause —
        // an out-of-scope default would (correctly) be reported instead.
        let r2 = Router::build(
            &[
                vec!["bare.test".into()],
                vec!["~^host[0-9]+\\.other\\.test$".into()],
                vec![],
            ],
            Some(2),
        )
        .unwrap();
        let owner_and_default = |id: RouteId| id == 0 || id == 2;
        assert_eq!(
            r2.wildcard_confined("bare.test", &owner_and_default),
            Err(Escape::RegexTier { route: 1 })
        );
    }

    #[test]
    fn the_actionable_escape_is_reported_when_several_apply() {
        // The shape of a real config: an exact route for the apex, siblings falling
        // to `default_route`, and an unrelated anchored regex route elsewhere. Both
        // the default route and (conservatively) the regex tier are escapes, so
        // either verdict would be sound — but only the default route names
        // something the operator can act on, so that is what must be reported.
        let r = Router::build(
            &[
                vec!["site.test".into()],
                vec!["~^upos-[a-z0-9-]+\\.cdn\\.test$".into()],
                vec![],
            ],
            Some(2),
        )
        .unwrap();
        assert_eq!(
            r.wildcard_confined("site.test", &only(0)),
            Err(Escape::DefaultRoute { route: 2 }),
            "must not blame a regex that could never match under this parent"
        );
    }

    #[test]
    fn regex_in_the_same_scope_does_not_block_a_wildcard() {
        // Every regex route is in scope, so reaching the regex tier is harmless
        // and the verdict falls through to the default route.
        let r = Router::build(
            &[vec!["bare.test".into(), "~^anything$".into()], vec![]],
            Some(1),
        )
        .unwrap();
        // Default route is out of scope -> that is the reported escape, not regex.
        assert_eq!(
            r.wildcard_confined("bare.test", &only(0)),
            Err(Escape::DefaultRoute { route: 1 })
        );
        // With the default route in scope too, the wildcard is confined.
        let both = |id: RouteId| id == 0 || id == 1;
        assert_eq!(r.wildcard_confined("bare.test", &both), Ok(()));
    }

    #[test]
    fn wildcard_tier_entry_decides_directly() {
        // An explicit `*.p` entry is the generic verdict for every `L.p`.
        let r = Router::build(&[vec!["*.site.test".into()], vec![]], Some(1)).unwrap();
        assert_eq!(r.wildcard_confined("site.test", &only(0)), Ok(()));
        assert_eq!(
            r.wildcard_confined("site.test", &only(1)),
            Err(Escape::Host {
                host: "*.site.test".into(),
                route: 0
            })
        );
    }

    #[test]
    fn deeper_wildcard_key_is_not_a_one_label_exception() {
        // `*.deep.site.test` matches `x.deep.site.test`, never `deep.site.test`,
        // so it must not be treated as an exception when checking `*.site.test`.
        let r = Router::build(
            &[vec![".site.test".into()], vec!["*.deep.site.test".into()]],
            None,
        )
        .unwrap();
        assert_eq!(r.wildcard_confined("site.test", &only(0)), Ok(()));
    }

    #[test]
    fn confinement_never_disagrees_with_match_host() {
        // The property that makes clipping trustworthy: for every host the
        // wildcard covers, if confinement says OK then match_host agrees.
        let r = Router::build(
            &[
                vec![".site.test".into()],
                vec!["odd.site.test".into()],
                vec![],
            ],
            Some(2),
        )
        .unwrap();
        let scope = only(0);
        // Refused because of the exception...
        assert!(r.wildcard_confined("site.test", &scope).is_err());
        // ...and indeed a host exists that routes out of scope.
        assert_eq!(r.match_host("odd.site.test"), Some(1));
        // Every other probe stays in scope.
        for h in ["a.site.test", "zz.site.test", "x1.site.test"] {
            assert_eq!(r.match_host(h), Some(0), "{h}");
        }
    }

    #[test]
    fn one_label_above_boundaries() {
        assert_eq!(one_label_above("b.a.com", "a.com"), Some("b"));
        assert_eq!(one_label_above("c.b.a.com", "a.com"), None);
        assert_eq!(one_label_above("a.com", "a.com"), None);
        assert_eq!(one_label_above("xa.com", "a.com"), None);
        assert_eq!(one_label_above("b.other.com", "a.com"), None);
    }
}
