//! SNI/Host router.
//!
//! Patterns are compiled once at startup into O(1) lookup maps (exact, wildcard,
//! suffix) plus a precompiled regex list. Matching follows a fixed precedence so
//! the most specific rule always wins:
//!
//!   1. exact       `p.example.com`
//!   2. wildcard    `*.example.com`  (one left label)
//!   3. suffix      `.example.com`   (example.com and any subdomain)
//!   4. regex       `@<name>`        (config order, requires [regexes.<name>])
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
    regex: Vec<RegexRoute>,
    default: Option<RouteId>,
}

/// A compiled regex route with its scope information.
///
/// The scope suffixes enable wildcard certificate issuance to coexist with
/// regex routes: a wildcard `*.parent` is refused only if some out-of-scope
/// regex declares a scope suffix that overlaps with `parent`.
#[derive(Debug)]
struct RegexRoute {
    pattern: Regex,
    route_id: RouteId,
    /// The normalized scope suffixes declared for this regex. Each entry uses
    /// route pattern syntax (`*.domain.com`, `.domain.com`, `domain.com`).
    /// Guaranteed non-empty by config validation.
    scope_suffix: Vec<String>,
}

impl Router {
    /// Build a router from each route's patterns. `patterns[i]` are the raw
    /// `match_sni` entries for route id `i`. `default` is the id of the default
    /// server route, if any. `regexes` is the resolved `[regexes.*]` table from
    /// the config.
    ///
    /// Regex references in `patterns` (prefixed with `@`) are resolved against
    /// `regexes` and compiled with their scope information. Inline regex syntax
    /// (`~pattern`) is rejected — all regexes must be declared and named.
    ///
    /// Later duplicate keys within the same tier are rejected so routing is
    /// deterministic and misconfiguration is caught at load time.
    pub fn build(
        patterns: &[Vec<String>],
        default: Option<RouteId>,
        regexes: &HashMap<String, crate::config::RegexDef>,
    ) -> Result<Self, ConfigError> {
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        let mut suffix = HashMap::new();
        let mut regex_routes = Vec::new();

        for (id, pats) in patterns.iter().enumerate() {
            for pat in pats {
                let pat = pat.trim();
                if pat.is_empty() {
                    continue;
                }

                if let Some(name) = pat.strip_prefix('@') {
                    // Named regex reference
                    let def = regexes.get(name).ok_or_else(|| {
                        ConfigError::Invalid(format!(
                            "route {id}: unknown regex {name:?} (no [regexes.{name}])"
                        ))
                    })?;

                    let re = Regex::new(&def.pattern).map_err(|e| {
                        ConfigError::Invalid(format!("[regexes.{name}]: invalid pattern: {e}"))
                    })?;

                    // Normalize scope_suffix entries
                    let scope_suffix: Vec<String> = def
                        .scope_suffix
                        .iter()
                        .map(|s| normalize_scope_suffix(s))
                        .collect();

                    regex_routes.push(RegexRoute {
                        pattern: re,
                        route_id: id,
                        scope_suffix,
                    });
                } else if pat.starts_with('~') {
                    // Inline regex syntax is no longer supported
                    return Err(ConfigError::Invalid(format!(
                        "route {id}: inline regex {pat:?} is no longer supported; \
                         define it in [regexes.<name>] with a scope_suffix, then \
                         reference it as @<name>"
                    )));
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
            regex: regex_routes,
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
        for regex_route in &self.regex {
            if regex_route.pattern.is_match(&host) {
                return Some(regex_route.route_id);
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
    /// route belongs to a different scope. The regex's declared scope_suffix
    /// overlaps with the wildcard being checked, indicating a potential conflict.
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
        //    regex can match some `L.parent` is not statically decidable, so each
        //    regex route carries an explicit `scope_suffix` declaration. A wildcard
        //    is refused when some out-of-scope regex declares a scope that overlaps
        //    with `parent`.
        for regex_route in &self.regex {
            if !in_scope(regex_route.route_id) {
                // Check if *.parent overlaps with any of this regex's scope suffixes
                let has_overlap = regex_route
                    .scope_suffix
                    .iter()
                    .any(|scope| match_scope_pattern(scope, &parent));

                if has_overlap {
                    return Err(Escape::RegexTier {
                        route: regex_route.route_id,
                    });
                }
                // No overlap: this regex cannot match hosts under *.parent, safe to ignore
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

/// Normalize a scope_suffix pattern: strip whitespace, lowercase, remove trailing
/// dot. The pattern prefix (`*.`, `.`) is preserved as-is.
fn normalize_scope_suffix(scope: &str) -> String {
    let scope = scope.trim();

    if let Some(rest) = scope.strip_prefix("*.") {
        format!("*.{}", normalize(rest))
    } else if let Some(rest) = scope.strip_prefix('.') {
        format!(".{}", normalize(rest))
    } else {
        normalize(scope)
    }
}

/// Check if a scope pattern matches a given parent domain.
///
/// This determines whether a wildcard `*.parent` would conflict with a regex
/// route that declares `scope` as one of its scope suffixes.
///
/// * `scope = "*.domain.com"` matches `parent = "domain.com"` (and only that)
/// * `scope = ".domain.com"` matches `parent = "domain.com"` and any ancestor
///   (e.g., `"a.domain.com"`, `"sub.a.domain.com"`)
/// * `scope = "domain.com"` never matches (exact scopes don't overlap with wildcards)
///
/// The scope must already be normalized via [`normalize_scope_suffix`].
fn match_scope_pattern(scope: &str, parent: &str) -> bool {
    if let Some(suffix) = scope.strip_prefix("*.") {
        // Wildcard scope: "*.domain.com"
        // Matches only when parent is exactly the suffix
        // e.g., scope "*.akamaized.net" matches parent "akamaized.net"
        parent == suffix
    } else if let Some(suffix) = scope.strip_prefix('.') {
        // Suffix scope: ".domain.com"
        // Matches parent if parent is the suffix or any subdomain of it
        // e.g., scope ".example.com" matches "example.com", "a.example.com", etc.
        is_suffix_of_or_equal(parent, suffix)
    } else {
        // Exact scope: "domain.com"
        // Wildcard *.parent does not include parent itself, so exact scopes
        // never conflict with wildcards in the context of wildcard_confined.
        // They would only matter for name_confined (checking exact names).
        false
    }
}

/// Check if `candidate` is equal to `suffix` or is a subdomain of it.
///
/// Examples:
/// * `is_suffix_of_or_equal("example.com", "example.com")` → `true`
/// * `is_suffix_of_or_equal("a.example.com", "example.com")` → `true`
/// * `is_suffix_of_or_equal("google.com", "example.com")` → `false`
fn is_suffix_of_or_equal(candidate: &str, suffix: &str) -> bool {
    if candidate == suffix {
        return true;
    }
    candidate.ends_with(&format!(".{}", suffix))
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
    use std::collections::HashMap;

    fn make_regex_def(pattern: &str, scope_suffix: Vec<&str>) -> crate::config::RegexDef {
        crate::config::RegexDef {
            pattern: pattern.to_string(),
            scope_suffix: scope_suffix.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn router_with_regexes(
        patterns: &[Vec<String>],
        default: Option<RouteId>,
        regexes: &HashMap<String, crate::config::RegexDef>,
    ) -> Router {
        Router::build(patterns, default, regexes).unwrap()
    }

    #[test]
    fn exact_beats_suffix() {
        let r = router_with_regexes(
            &[vec!["p.nginxsni.com".into()], vec![".nginxsni.com".into()]],
            None,
            &HashMap::new(),
        );
        assert_eq!(r.match_host("p.nginxsni.com"), Some(0));
    }

    #[test]
    fn suffix_matches_sub_and_root() {
        let r = router_with_regexes(&[vec![".nginxsni.com".into()]], None, &HashMap::new());
        assert_eq!(r.match_host("x.nginxsni.com"), Some(0));
        assert_eq!(r.match_host("nginxsni.com"), Some(0));
        assert_eq!(r.match_host("a.b.nginxsni.com"), Some(0));
    }

    #[test]
    fn wildcard_one_label_only() {
        let r = router_with_regexes(&[vec!["*.wild.com".into()]], Some(9), &HashMap::new());
        assert_eq!(r.match_host("a.wild.com"), Some(0));
        // two labels left of wild.com must NOT match the wildcard
        assert_eq!(r.match_host("a.b.wild.com"), Some(9)); // falls to default
    }

    #[test]
    fn regex_matches() {
        let mut regexes = HashMap::new();
        regexes.insert(
            "test-regex".to_string(),
            make_regex_def("^p[0-9]+\\.re\\.com$", vec!["*.re.com"]),
        );

        let r = router_with_regexes(&[vec!["@test-regex".into()]], None, &regexes);
        assert_eq!(r.match_host("p12.re.com"), Some(0));
        assert_eq!(r.match_host("px.re.com"), None);
    }

    #[test]
    fn default_and_empty() {
        let r = router_with_regexes(&[vec![".example.com".into()]], Some(9), &HashMap::new());
        assert_eq!(r.match_host("nope.example.org"), Some(9));
        assert_eq!(r.match_host(""), Some(9));
    }

    #[test]
    fn normalize_port_and_case() {
        let r = router_with_regexes(&[vec!["p.nginxsni.com".into()]], None, &HashMap::new());
        assert_eq!(r.match_host("P.NginxSNI.com:443"), Some(0));
    }

    #[test]
    fn inline_regex_is_rejected() {
        let result = Router::build(&[vec!["~^test\\.com$".into()]], None, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("inline regex"));
        assert!(err.contains("no longer supported"));
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
        let r = router_with_regexes(&[vec![".site.test".into()]], None, &HashMap::new());
        assert_eq!(r.wildcard_confined("site.test", &only(0)), Ok(()));
    }

    #[test]
    fn wildcard_escapes_via_an_exact_exception() {
        // The motivating shape: a suffix route owns the domain, but one sibling
        // is pinned to a different route. `*.site.test` must be refused.
        let r = router_with_regexes(
            &[vec![".site.test".into()], vec!["odd.site.test".into()]],
            None,
            &HashMap::new(),
        );
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
        let r = router_with_regexes(
            &[vec!["site.test".into()], vec![]],
            Some(1),
            &HashMap::new(),
        );
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
        let r = router_with_regexes(&[vec!["site.test".into()]], None, &HashMap::new());
        assert_eq!(
            r.wildcard_confined("site.test", &only(0)),
            Err(Escape::Unmatched)
        );
    }

    // -- Named regex with scope_suffix tests --------------------------------

    #[test]
    fn regex_with_non_overlapping_scope_allows_wildcard() {
        // The user's actual use case: regex for *.akamaized.net, wildcard for *.google.com
        let mut regexes = HashMap::new();
        regexes.insert(
            "cdn-upos".to_string(),
            make_regex_def(
                "^upos-[a-z0-9-]+\\.akamaized\\.net$",
                vec!["*.akamaized.net"],
            ),
        );

        let r = router_with_regexes(
            &[
                vec!["@cdn-upos".into()],   // route 0: cdn regex
                vec![".google.com".into()], // route 1: google suffix
            ],
            Some(2), // route 2: default
            &regexes,
        );

        // *.google.com should be allowed: cdn-upos scope is *.akamaized.net, no overlap
        assert_eq!(r.wildcard_confined("google.com", &only(1)), Ok(()));
    }

    #[test]
    fn regex_with_overlapping_scope_blocks_wildcard() {
        // Regex declares scope *.example.com; when checking *.example.com for a
        // different route, the overlap should be detected.
        let mut regexes = HashMap::new();
        regexes.insert(
            "test".to_string(),
            make_regex_def("^test-[0-9]+\\.example\\.com$", vec!["*.example.com"]),
        );

        // Route 0: regex for *.example.com
        // Route 1: exact match for apex only
        // Route 2: default (in-scope)
        // When checking *.example.com for route 1's scope, the regex in route 0
        // declares overlap, so it should be blocked.
        let r = router_with_regexes(
            &[
                vec!["@test".into()],       // route 0: regex
                vec!["example.com".into()], // route 1: exact (apex only)
                vec![],                     // route 2: default
            ],
            Some(2),
            &regexes,
        );

        // Checking *.example.com for route 1's scope (which includes default route 2)
        let in_scope = |id: usize| id == 1 || id == 2;
        assert_eq!(
            r.wildcard_confined("example.com", &in_scope),
            Err(Escape::RegexTier { route: 0 })
        );
    }

    #[test]
    fn regex_with_suffix_scope_blocks_wildcards_under_it() {
        // Regex declares scope .example.com (all subdomains); when checking
        // wildcards under example.com for a different scope, the overlap should
        // be detected.
        let mut regexes = HashMap::new();
        regexes.insert(
            "all".to_string(),
            make_regex_def("^.*\\.example\\.com$", vec![".example.com"]),
        );

        // Route 0: regex with scope .example.com
        // Route 1: exact matches for specific hosts
        // Route 2: default (in-scope with route 1)
        let r = router_with_regexes(
            &[
                vec!["@all".into()],            // route 0: regex
                vec!["sub.example.com".into()], // route 1: exact
                vec![],                         // route 2: default
            ],
            Some(2),
            &regexes,
        );

        let in_scope = |id: usize| id == 1 || id == 2;

        // *.sub.example.com should be blocked: regex scope .example.com covers it
        assert_eq!(
            r.wildcard_confined("sub.example.com", &in_scope),
            Err(Escape::RegexTier { route: 0 })
        );

        // *.example.com should also be blocked
        assert_eq!(
            r.wildcard_confined("example.com", &in_scope),
            Err(Escape::RegexTier { route: 0 })
        );
    }

    #[test]
    fn regex_with_exact_scope_never_blocks_wildcards() {
        // Regex declares scope "example.com" (exact, no prefix)
        // This should never block *.example.com because exact doesn't overlap with wildcards
        let mut regexes = HashMap::new();
        regexes.insert(
            "apex-only".to_string(),
            make_regex_def("^example\\.com$", vec!["example.com"]),
        );

        let r = router_with_regexes(
            &[
                vec!["@apex-only".into()],    // route 0: regex (apex only)
                vec!["*.example.com".into()], // route 1: wildcard
            ],
            None,
            &regexes,
        );

        // *.example.com should be allowed: exact scope "example.com" doesn't overlap
        assert_eq!(r.wildcard_confined("example.com", &only(1)), Ok(()));
    }

    #[test]
    fn regex_in_same_scope_is_ignored() {
        // Regex in the same scope doesn't block wildcards
        let mut regexes = HashMap::new();
        regexes.insert(
            "cdn".to_string(),
            make_regex_def("^cdn-[0-9]+\\.example\\.com$", vec!["*.example.com"]),
        );

        let r = router_with_regexes(
            &[vec!["@cdn".into(), ".example.com".into()]], // both in route 0
            None,
            &regexes,
        );

        // *.example.com should be allowed: regex is in the same scope
        assert_eq!(r.wildcard_confined("example.com", &only(0)), Ok(()));
    }

    #[test]
    fn multiple_regex_routes_with_different_scopes() {
        let mut regexes = HashMap::new();
        regexes.insert(
            "cdn1".to_string(),
            make_regex_def("^cdn1-[0-9]+\\.example\\.com$", vec!["*.example.com"]),
        );
        regexes.insert(
            "cdn2".to_string(),
            make_regex_def("^cdn2-[0-9]+\\.other\\.com$", vec!["*.other.com"]),
        );

        // Route 0: cdn1 regex
        // Route 1: cdn2 regex
        // Route 2: exact matches
        // Route 3: default (in-scope with route 2)
        let r = router_with_regexes(
            &[
                vec!["@cdn1".into()], // route 0
                vec!["@cdn2".into()], // route 1
                vec![
                    "google.com".into(),
                    "example.com".into(),
                    "other.com".into(),
                ], // route 2: exact
                vec![],               // route 3: default
            ],
            Some(3),
            &regexes,
        );

        let in_scope = |id: usize| id == 2 || id == 3;

        // *.google.com should be allowed: no regex scope overlaps with google.com
        assert_eq!(r.wildcard_confined("google.com", &in_scope), Ok(()));

        // *.example.com blocked by cdn1
        assert_eq!(
            r.wildcard_confined("example.com", &in_scope),
            Err(Escape::RegexTier { route: 0 })
        );

        // *.other.com blocked by cdn2
        assert_eq!(
            r.wildcard_confined("other.com", &in_scope),
            Err(Escape::RegexTier { route: 1 })
        );
    }

    // -- Scope pattern matching tests ---------------------------------------

    #[test]
    fn match_scope_pattern_wildcard() {
        // "*.example.com" matches only "example.com"
        assert!(match_scope_pattern("*.example.com", "example.com"));
        assert!(!match_scope_pattern("*.example.com", "sub.example.com"));
        assert!(!match_scope_pattern("*.example.com", "google.com"));
    }

    #[test]
    fn match_scope_pattern_suffix() {
        // ".example.com" matches example.com and all subdomains
        assert!(match_scope_pattern(".example.com", "example.com"));
        assert!(match_scope_pattern(".example.com", "a.example.com"));
        assert!(match_scope_pattern(".example.com", "sub.a.example.com"));
        assert!(!match_scope_pattern(".example.com", "google.com"));
    }

    #[test]
    fn match_scope_pattern_exact() {
        // "example.com" (no prefix) never matches in wildcard context
        assert!(!match_scope_pattern("example.com", "example.com"));
        assert!(!match_scope_pattern("example.com", "sub.example.com"));
    }

    #[test]
    fn normalize_scope_suffix_preserves_pattern() {
        assert_eq!(normalize_scope_suffix("*.Example.Com"), "*.example.com");
        assert_eq!(normalize_scope_suffix(".Example.Com"), ".example.com");
        assert_eq!(normalize_scope_suffix("Example.Com"), "example.com");
        assert_eq!(normalize_scope_suffix("  *.example.com  "), "*.example.com");
    }

    #[test]
    fn wildcard_tier_entry_decides_directly() {
        // An explicit `*.p` entry is the generic verdict for every `L.p`.
        let r = router_with_regexes(
            &[vec!["*.site.test".into()], vec![]],
            Some(1),
            &HashMap::new(),
        );
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
        let r = router_with_regexes(
            &[vec![".site.test".into()], vec!["*.deep.site.test".into()]],
            None,
            &HashMap::new(),
        );
        assert_eq!(r.wildcard_confined("site.test", &only(0)), Ok(()));
    }

    #[test]
    fn confinement_never_disagrees_with_match_host() {
        // The property that makes clipping trustworthy: for every host the
        // wildcard covers, if confinement says OK then match_host agrees.
        let r = router_with_regexes(
            &[
                vec![".site.test".into()],
                vec!["odd.site.test".into()],
                vec![],
            ],
            Some(2),
            &HashMap::new(),
        );
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
