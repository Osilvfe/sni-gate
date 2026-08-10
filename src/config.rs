//! Configuration model and hierarchical resolution.
//!
//! The document is TOML. It has a `[global]` block, one or more `[[listener]]`
//! blocks (each binding an address), and within each listener a set of
//! `[[listener.route]]` rules plus an optional `[listener.default_route]`.
//!
//! Many settings are *overridable* and resolved by walking outward from the
//! most specific scope to the least:
//!
//!   route (explicit)  →  route's template  →  listener (explicit)  →
//!   listener's template  →  global
//!
//! A scope's own explicit value beats the template it `use`s, which in turn
//! beats the enclosing scope. An unset value at a deeper scope inherits from
//! the next scope out. The `[ech]` block resolves field-by-field along the same
//! ladder (a shared `[global.ech]` / `[listener.ech]` supplies defaults). Named
//! `[templates.<name>]` bundles capture reusable settings referenced by a single
//! `use = "<name>"`. The [`Effective`] view computes the flattened settings for
//! one route so the data path never has to re-walk the hierarchy.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::error::ConfigError;

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

/// Top-level configuration document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub global: Global,

    /// Certificate authority + issuance settings (dynamic per-SNI certs).
    pub ca: CaConfig,

    #[serde(default)]
    pub issuance: IssuanceConfig,

    #[serde(default)]
    pub store: StoreConfig,

    #[serde(default)]
    pub cache: CacheConfig,

    /// Public suffix list configuration.
    #[serde(default)]
    pub psl: PslConfig,

    /// Reusable, named bundles of route/listener settings. A `route`,
    /// `default_route`, or `listener` references one with `use = "<name>"`.
    /// Templates cannot reference other templates (no nesting).
    #[serde(default)]
    pub templates: HashMap<String, Template>,

    /// Named DNS resolvers. A `[resolvers.<name>]` table declares a resolver
    /// endpoint together with the same transport controls a route gets —
    /// `upstream`, `override_sni`, an `[ech]` block, `address_family`,
    /// `nat64_prefix` — and is referenced by name anywhere a resolver spec
    /// string is accepted (`resolver`, `ech_resolver`, `addr_resolver`, or
    /// another resolver's `bootstrap`). See [`ResolverDef`].
    #[serde(default)]
    pub resolvers: HashMap<String, ResolverDef>,

    /// Named regular expressions for SNI/Host matching. A `[regexes.<name>]`
    /// table declares a regex pattern together with its scope suffix — the set
    /// of domain suffixes the pattern may match. This scope information enables
    /// wildcard certificate issuance to safely coexist with regex routes: a
    /// wildcard is refused only when it would cover a name some regex in a
    /// different route scope could match.
    ///
    /// Regex routes are referenced in `match_sni` with an `@` prefix:
    /// `match_sni = ["@cdn-pattern", ".example.com"]`. Inline regex syntax
    /// (`~pattern`) is no longer supported; all regexes must be declared and
    /// named here. See [`RegexDef`].
    #[serde(default)]
    pub regexes: HashMap<String, RegexDef>,

    /// One or more inbound listeners.
    #[serde(rename = "listener")]
    pub listeners: Vec<Listener>,
}

/// Process-wide defaults and the outermost fallback scope.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Global {
    /// `tracing` filter directive; env `SNI_GATE_LOG` / `RUST_LOG` override it.
    #[serde(default = "default_log")]
    pub log: String,

    /// Overridable knobs shared with deeper scopes.
    #[serde(flatten)]
    pub common: CommonOpts,

    /// Outermost `[ech]` defaults, inherited field-by-field by every ECH route
    /// that does not override them at a deeper scope.
    #[serde(default)]
    pub ech: Option<EchConfig>,

    /// Outermost `[http2]` defaults, inherited field-by-field by every route.
    #[serde(default)]
    pub http2: Option<Http2Config>,

    /// Policy for connections matching no route and no default_route.
    #[serde(default)]
    pub unmatched: FailPolicy,
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// One inbound bind address and its routes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// Address to accept on.
    ///
    /// Either a full socket address — `"0.0.0.0:443"`, `"127.0.0.1:8443"`,
    /// `"[::]:443"` (IPv6 in brackets) — or, as shorthand, a bare port written
    /// as a string or an integer: `"443"` and `443` both mean `0.0.0.0:443`.
    ///
    /// The shorthand binds the **IPv4** wildcard, which is exactly what nginx's
    /// `listen 443` does. It is not "every interface": a dual-stack deployment
    /// still needs a second listener on `"[::]:443"`, just as nginx needs a
    /// second `listen [::]:443`.
    ///
    /// Shorthand is normalized here, at parse time, so the duplicate-address
    /// check in [`Config::validate`] sees `"443"` and `"0.0.0.0:443"` as the
    /// same bind and rejects the pair.
    #[serde(deserialize_with = "de_listen_addr")]
    pub addr: SocketAddr,

    /// Name of a `[templates.<name>]` bundle whose settings apply to this
    /// listener's scope (below the listener's own explicit values, above global).
    #[serde(default, rename = "use")]
    pub use_template: Option<String>,

    /// Overridable knobs; inherit from `[global]`, override per route.
    #[serde(flatten)]
    pub common: CommonOpts,

    /// Listener-scope `[ech]` defaults, between `[global.ech]` and per-route.
    #[serde(default)]
    pub ech: Option<EchConfig>,

    /// Listener-scope `[http2]` defaults, between `[global.http2]` and per-route.
    #[serde(default)]
    pub http2: Option<Http2Config>,

    /// Routes matched by inbound SNI/Host.
    #[serde(default, rename = "route")]
    pub routes: Vec<Route>,

    /// Catch-all for SNI/Host matching no route.
    #[serde(default)]
    pub default_route: Option<Route>,
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

/// How an upstream connection is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteType {
    /// Re-originate to the upstream over TLS 1.3 + Encrypted Client Hello.
    Ech,
    /// Re-originate over plain TLS (optionally with an overridden SNI).
    Tls,
    /// Forward as cleartext HTTP (no upstream TLS).
    Http,
    /// Do not terminate: splice the raw TCP byte stream to the upstream.
    /// No certificate is issued.
    Raw,
}

/// What SNI to present on the upstream handshake (`tls` / `ech` routes).
///
/// Resolved from `override_sni` by [`SniPolicy::resolve`]. The empty-string case
/// is deliberately distinct from "unset": omitting the field means *reflect*,
/// whereas writing `override_sni = ""` is an explicit request to send no SNI
/// extension at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniPolicy {
    /// Present the inbound SNI/Host verbatim (the default).
    Reflect,
    /// Present this fixed name.
    Fixed(String),
    /// Send no `server_name` extension.
    ///
    /// Legal and useful: RFC 9849 §5 allows a ClientHelloInner to carry no SNI,
    /// and for a plain `tls` upstream that is addressed by IP (or one that keys
    /// only off the certificate it serves) an SNI is not always wanted. The
    /// upstream certificate is still verified against the name the route would
    /// otherwise have sent — suppressing SNI changes what is *transmitted*, not
    /// what is *trusted*.
    Omit,
}

impl SniPolicy {
    /// Map a raw `override_sni` value onto a policy. A value that is present but
    /// blank (empty or all whitespace) selects [`SniPolicy::Omit`].
    pub fn resolve(override_sni: Option<&str>) -> Self {
        match override_sni {
            None => SniPolicy::Reflect,
            Some(s) if s.trim().is_empty() => SniPolicy::Omit,
            Some(s) => SniPolicy::Fixed(s.trim().to_string()),
        }
    }
}

/// One SNI/Host-matched forwarding rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Human-readable name for logs.
    #[serde(default)]
    pub name: Option<String>,

    /// Name of a `[templates.<name>]` bundle supplying defaults for this route,
    /// below the route's own explicit values and above the listener scope.
    #[serde(default, rename = "use")]
    pub use_template: Option<String>,

    /// Upstream protocol handling. May be omitted when a referenced template
    /// provides it; resolved to a concrete type at load time.
    #[serde(default, rename = "type")]
    pub route_type: Option<RouteType>,

    /// Patterns matched against the inbound SNI/Host. Each is one of:
    ///   exact `p.example.com` · wildcard `*.example.com` (one left label) ·
    ///   suffix `.example.com` (domain and any subdomain) · regex `~<re>`.
    /// Not used by `default_route`.
    #[serde(default)]
    pub match_sni: Vec<String>,

    /// Upstream to dial. Both the host and the port may be defaulted:
    ///
    ///   * `"host:port"`  — fixed host and port (IPv6 in brackets).
    ///   * `"host"`       — fixed host; port = this listener's port.
    ///   * `"8443"`       — port only; host = the matched source SNI/Host.
    ///   * *(omitted)*    — host = the matched source SNI/Host; port = this
    ///     listener's port.
    ///
    /// When the host is defaulted it is the *routing key* the connection was
    /// matched on (the inbound SNI/Host, port-stripped) — resolved per
    /// connection. `override_sni` does not affect the dial target; it only sets
    /// the upstream TLS server name for `tls`/`ech`.
    ///
    /// Accepts a string or an integer port number: `upstream = 8443` is
    /// identical to `upstream = "8443"`.
    #[serde(default, deserialize_with = "de_option_upstream")]
    pub upstream: Option<String>,

    /// SNI sent to the upstream. For `ech` routes this is the inner (protected)
    /// name; for `tls` the SNI on the upstream handshake. Ignored for
    /// `http`/`raw`. Three cases, see [`SniPolicy`]:
    ///
    ///   * *(omitted)*  — reflect the inbound SNI/Host verbatim.
    ///   * `"name"`     — send exactly `name`.
    ///   * `""`         — send **no** SNI extension at all.
    #[serde(default)]
    pub override_sni: Option<String>,

    /// ECH settings. Required in practice for `type = "ech"`.
    #[serde(default)]
    pub ech: Option<EchConfig>,

    /// HTTP/2 settings (deepest scope).
    #[serde(default)]
    pub http2: Option<Http2Config>,

    /// Optional PEM cert chain pinned for local termination when this route's
    /// name is presented. Falls back to the dynamic CA issuer.
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,

    /// Overridable knobs; inherit from listener then global.
    #[serde(flatten)]
    pub common: CommonOpts,

    /// Per-route failure policy (e.g. ECH unavailable, upstream unreachable).
    #[serde(default)]
    pub fail: Option<FailPolicy>,
}

/// Per-route ECH settings (deepest scope for ECH-related overrides).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchConfig {
    /// Where the ECHConfigList comes from. `None` inherits the enclosing scope;
    /// the [`EchMode::Doh`] default is applied only after full resolution, so an
    /// omitted `mode` is distinct from an explicit `mode = "doh"`.
    #[serde(default)]
    pub mode: Option<EchMode>,

    /// Base64 ECHConfigList for `static` / `doh-with-fallback`.
    #[serde(default)]
    pub config: Option<String>,

    /// Name whose HTTPS record is queried for `ech=` (doh modes). Unset = the
    /// effective inner name (override_sni or inbound SNI).
    #[serde(default)]
    pub ech_domain: Option<String>,

    /// Fail closed unless ECH is negotiated. Inherits, default true.
    #[serde(default)]
    pub require_ech: Option<bool>,

    /// Max ECH retry attempts on server rejection (retry_configs). Default 2.
    #[serde(default)]
    pub max_retries: Option<u32>,

    /// ECH refresh bound override (deepest scope).
    #[serde(default, with = "humantime_serde::option")]
    pub ech_refresh: Option<Duration>,

    /// Resolver override used specifically for the ECH HTTPS-record lookup.
    #[serde(default)]
    pub ech_resolver: Option<String>,
}

/// Per-scope HTTP/2 settings (deepest scope for HTTP/2-related overrides).
///
/// Every field is `Option`; `None` means "inherit from the enclosing scope". The
/// block resolves field-by-field along the same five-tier ladder as [`EchConfig`].
///
/// HTTP/2 here is a *coupled* switch: sni-gate splices bytes rather than parsing
/// HTTP, so the inbound and upstream framing are necessarily the same protocol.
/// See [`Http2Config::enabled`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http2Config {
    /// Allow HTTP/2 on this route. Inherits; default false.
    ///
    /// For `tls`/`ech` the upstream's own ALPN choice is mirrored back to the
    /// client, so enabling this only *permits* h2 — it is used when the upstream
    /// actually selects it. For `http` the negotiated protocol is spliced to the
    /// cleartext backend as prior-knowledge h2c. Meaningless for `raw` (which
    /// never terminates TLS), where setting it explicitly is a load-time error.
    #[serde(default)]
    pub enabled: Option<bool>,

    /// What a failed startup h2c probe does. Only applies to `http` routes
    /// (`tls`/`ech` mirror the live upstream and need no probe).
    #[serde(default)]
    pub probe: Option<H2Probe>,

    /// Per-backend timeout for the startup h2c probe. Default 3s.
    #[serde(default, with = "humantime_serde::option")]
    pub probe_timeout: Option<Duration>,
}

/// What a failed startup h2c probe should do.
///
/// The probe *validates*, it never *decides*: no mode silently downgrades a route
/// to HTTP/1.1, because a probe result goes stale the moment the backend is
/// reconfigured. A wrong config should be visible, not quietly absorbed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum H2Probe {
    /// Do not probe at all.
    Off,
    /// Log a loud warning and keep HTTP/2 enabled as configured. The default:
    /// it surfaces a misconfigured backend without coupling startup to backend
    /// availability (which would make boot order fragile).
    #[default]
    Warn,
    /// Fail startup outright when the backend does not speak h2c.
    Require,
}

/// How the ECHConfigList for a route is sourced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EchMode {
    /// Look up the HTTPS record via the resolver and extract `ech=`.
    #[default]
    Doh,
    /// Use a fixed inline base64 ECHConfigList. Never refreshed.
    Static,
    /// Prefer DoH, fall back to the inline `config` if lookup fails.
    DohWithFallback,
}

// ---------------------------------------------------------------------------
// Named templates
// ---------------------------------------------------------------------------

/// A reusable bundle of route/listener settings, defined under
/// `[templates.<name>]` and referenced by a single `use = "<name>"`.
///
/// A template may carry every *reusable* setting — the protocol `type`, the
/// `upstream`, `override_sni`, the pinned cert/key, a whole `[ech]` block, the
/// per-route `fail` policy, and all [`CommonOpts`] knobs. It deliberately omits
/// the route *identity* fields (`name`, `match_sni`) and cannot itself `use`
/// another template: the absence of a `use` field means a stray `use` inside a
/// `[templates.*]` table is rejected as an unknown field, so there is no nesting.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// Upstream protocol handling.
    #[serde(default, rename = "type")]
    pub route_type: Option<RouteType>,

    /// Upstream to dial (see [`Route::upstream`] for the accepted forms).
    /// Accepts a string or an integer port: `upstream = 443` == `upstream = "443"`.
    #[serde(default, deserialize_with = "de_option_upstream")]
    pub upstream: Option<String>,

    /// SNI presented to the upstream (see [`Route::override_sni`]); `""` sends
    /// no SNI extension.
    #[serde(default)]
    pub override_sni: Option<String>,

    /// Pinned local termination cert/key (both or neither, after resolution).
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,

    /// ECH settings; merged field-by-field into the ECH ladder at this scope.
    #[serde(default)]
    pub ech: Option<EchConfig>,

    /// HTTP/2 settings; merged field-by-field into the HTTP/2 ladder here.
    #[serde(default)]
    pub http2: Option<Http2Config>,

    /// Overridable knobs; inserted into the fallback ladder at this scope.
    #[serde(flatten)]
    pub common: CommonOpts,

    /// Per-route failure policy.
    #[serde(default)]
    pub fail: Option<FailPolicy>,
}

// ---------------------------------------------------------------------------
// Named regexes
// ---------------------------------------------------------------------------

/// A named regular expression for SNI/Host matching, declared as
/// `[regexes.<name>]` and referenced in `match_sni` with an `@` prefix.
///
/// # Why this exists
///
/// Regular expressions in route patterns cannot be statically analyzed to
/// determine their match scope, which creates a correctness problem for wildcard
/// certificate issuance: a wildcard `*.example.com` must not be issued if some
/// regex in a *different* route scope could match hosts under `example.com`,
/// because HTTP/2 connection coalescing would let the browser send a request for
/// that regex-matched host on the wildcard connection, bypassing SNI-based
/// routing entirely. See [`crate::certscope`] for the full rationale.
///
/// The inline regex syntax (`~pattern`) cannot carry scope information, so it
/// forces a conservative refusal: *any* out-of-scope regex blocks *all*
/// wildcards. Named regexes solve this by requiring an explicit `scope_suffix`
/// declaration: the operator states which domain suffixes the pattern may match,
/// and wildcard issuance uses that to precisely determine when a conflict exists.
///
/// # Configuration
///
/// ```toml
/// [regexes.cdn-upos]
/// pattern = "^upos-[a-z0-9-]+\\.akamaized\\.net$"
/// scope_suffix = ["*.akamaized.net"]
/// ```
///
/// Reference in a route with `@`:
/// ```toml
/// [[listener.route]]
/// match_sni = ["@cdn-upos", ".example.com"]
/// upstream = "cdn.example.com"
/// type = "tls"
/// ```
///
/// # Scope suffix syntax
///
/// The `scope_suffix` field uses the same pattern grammar as route matching:
///
/// * **`"*.domain.com"`** — matches only direct subdomains of `domain.com`
///   (one label above it). Example: `a.domain.com` matches, `sub.a.domain.com`
///   does not.
/// * **`".domain.com"`** — matches `domain.com` itself plus all subdomains at
///   any depth. Example: `domain.com`, `a.domain.com`, `sub.a.domain.com` all
///   match.
/// * **`"domain.com"`** — matches only the apex domain `domain.com` exactly.
///
/// A regex may declare multiple suffixes:
/// ```toml
/// scope_suffix = ["*.cdn1.example.com", "*.cdn2.example.com"]
/// ```
///
/// # Validation
///
/// At startup, each `scope_suffix` entry is validated for correct syntax (must
/// be a multi-level domain, cannot be a bare TLD). The pattern itself is
/// compiled to verify it is a valid regex. No attempt is made to verify that
/// the pattern's actual matches align with the declared scope — that
/// responsibility lies with the operator. An incorrect declaration is a
/// configuration error, not a runtime failure: it may cause wildcards to be
/// refused when they would be safe, or (if the scope is under-declared) allow
/// wildcards that should be refused, leading to incorrect routing.
///
/// # Inline regex deprecation
///
/// The inline syntax `match_sni = ["~^pattern$"]` is no longer supported. All
/// regex patterns must be declared as named `[regexes.<name>]` entries with an
/// explicit `scope_suffix`. This is enforced at config load time.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegexDef {
    /// The regular expression pattern. Do not prefix with `~` — that was the
    /// inline syntax marker and is not part of the pattern itself.
    ///
    /// The pattern is matched against normalized host names (lowercased, trailing
    /// dot removed, port stripped if present). It is compiled with the `regex`
    /// crate's default settings.
    pub pattern: String,

    /// The set of domain suffixes this pattern may match, using route pattern
    /// syntax. Required and must not be empty.
    ///
    /// * `"*.example.com"` — one-label subdomains of `example.com`
    /// * `".example.com"` — `example.com` and all its subdomains
    /// * `"example.com"` — only the apex `example.com`
    ///
    /// This is a **conservative declaration**: it is the operator's responsibility
    /// to ensure the pattern does not match hosts outside the declared scope. An
    /// incorrect declaration may allow wildcard certificates to be issued when
    /// they should be refused, leading to incorrect routing via HTTP/2 connection
    /// coalescing.
    pub scope_suffix: Vec<String>,
}

// ---------------------------------------------------------------------------
// Named resolvers
// ---------------------------------------------------------------------------

/// A named DNS resolver, declared as `[resolvers.<name>]` and referenced by name
/// anywhere a resolver spec string is accepted (`resolver`, `addr_resolver`,
/// `ech_resolver`, or another resolver's `bootstrap`).
///
/// # Why this exists
///
/// A DoH endpoint is an HTTPS origin. Nothing makes it less subject to SNI
/// blocking than the origins `[[listener.route]]` already handles, and nothing
/// makes the countermeasures different: dial a CDN edge instead of the blocked
/// name, keep (or override) the TLS name, hide that name with ECH. So a resolver
/// gets the same vocabulary a route has rather than a special-cased subset.
///
/// # Inheritance
///
/// A resolver is a scope in the ladder with `[global]` as its only parent:
///
/// ```text
/// resolver.ech  →  resolver  →  global.ech  →  global
/// ```
///
/// `address_family`, `nat64_prefix` and `connect_timeout` inherit from
/// `[global]`, and the `[ech]` block inherits field-by-field from `[global.ech]`
/// — `mode`, `config`, `ech_domain`, `max_retries`, `require_ech`, `ech_refresh`
/// each resolve independently, exactly as for a route. So `[resolvers.x.ech]` may
/// be written empty to mean "the same ECH settings my routes use".
///
/// Three things deliberately do **not** inherit, each for a specific reason
/// rather than a general principle:
///
/// * **`bootstrap`** — a *dependency edge*, not a setting. Inheriting it from
///   `[global].resolver` would make the graph implicitly cyclic in the most
///   ordinary configuration there is: `global.resolver = "@cf-doh"` plus a
///   `cf-doh` with no explicit bootstrap would have `cf-doh` bootstrapping from
///   itself. The cycle detector would catch it, but the operator would face an
///   error about a cycle they never wrote.
/// * **`ech.ech_resolver`** — the same argument: it is the edge naming who
///   fetches this resolver's ECH keys.
/// * **The *presence* of `[ech]`** — the block's fields inherit, but the block
///   itself must be declared. A bare `[global.ech]` (present in any config with
///   ECH routes) would otherwise silently switch ECH on for every resolver,
///   including the bootstrap resolver that must stay reachable when nothing else
///   is — the exact failure that leaves the gateway unable to resolve at all. It
///   would also apply a route's `ech_domain` to an unrelated DoH host.
///
/// `endpoint`, `upstream` and `override_sni` have no `[global]` counterpart:
/// the first is this resolver's identity, and the other two are meaningful only
/// relative to a specific endpoint.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResolverDef {
    /// The transport, in the same grammar accepted everywhere else:
    /// `system` · `https://host[:port][/path]` · `tls://host[:port]` ·
    /// `udp://ip[:port]` · `tcp://ip[:port]` · bare `ip[:port]`.
    ///
    /// Called `endpoint` rather than `url` because `system` and `udp://1.1.1.1`
    /// are not URLs.
    pub endpoint: String,

    /// Where to actually dial, when that differs from the endpoint's own host.
    /// Accepts the same forms as a route's `upstream`:
    ///
    ///   * `"host:port"` — both overridden
    ///   * `"host"`      — host overridden, endpoint's port kept
    ///   * `"8443"`      — port overridden, endpoint's host kept
    ///   * *(omitted)*   — dial the endpoint's own host and port
    ///
    /// Overriding the dial target does **not** change the TLS server name; that
    /// is exactly what makes `endpoint = "https://blocked.example/dns-query"`
    /// plus `upstream = "cdn.example"` work.
    ///
    /// Unlike a route's `upstream`, the host is never omitted-to-reflect: there
    /// is no inbound connection to reflect.
    /// Accepts a string or an integer port: `upstream = 443` == `upstream = "443"`.
    #[serde(default, deserialize_with = "de_option_upstream")]
    pub upstream: Option<String>,

    /// TLS server name presented to the endpoint. Same three cases as a route's
    /// `override_sni`: omitted reflects the endpoint's own host, a value sends
    /// exactly that name, and `""` sends no `server_name` extension while the
    /// certificate is still verified against the endpoint host.
    ///
    /// On **DoH** this also moves the HTTP `:authority`, because hickory uses one
    /// field for both and RFC 8484 carries the query to that origin. They are one
    /// knob on this transport, not two that happen to agree — to *hide* a name
    /// rather than change it, use ECH.
    #[serde(default)]
    pub override_sni: Option<String>,

    /// Resolver that turns this resolver's dial host into an address. A name from
    /// `[resolvers.*]`, or a bare spec. Omitted means OS resolution, which is
    /// correct for a bootstrap resolver addressed by IP.
    ///
    /// Never inherited — see the type-level note.
    #[serde(default)]
    pub bootstrap: Option<String>,

    /// ECH for this resolver's own TLS handshake. Opt-in: the *presence* of this
    /// block is never inherited from `[global.ech]`, though its fields are.
    #[serde(default)]
    pub ech: Option<EchConfig>,

    /// Address family used when resolving the dial host. Inherits from `[global]`.
    #[serde(default)]
    pub address_family: Option<AddressFamily>,

    /// NAT64 /96 prefix applied when the dial host resolves only to IPv4.
    /// Inherits from `[global]`.
    #[serde(default)]
    pub nat64_prefix: Option<String>,

    /// Per-query timeout handed to hickory, and the bound on dialing this
    /// resolver's own endpoint. Inherits from `[global]`.
    #[serde(default, with = "humantime_serde::option")]
    pub connect_timeout: Option<Duration>,
}

/// The fully-resolved settings for one named resolver.
///
/// Unlike [`Effective`] this is not the product of a five-tier ladder — a
/// resolver has only itself and `[global]` — so it is a validated,
/// defaults-applied view of one [`ResolverDef`].
#[derive(Debug, Clone)]
pub struct EffectiveResolver {
    /// The name it was declared under, for diagnostics.
    pub name: String,
    pub endpoint: String,
    pub upstream: Option<String>,
    pub sni_policy: SniPolicy,
    pub bootstrap: Option<String>,
    pub address_family: AddressFamily,
    pub nat64_prefix: Option<String>,
    pub connect_timeout: Duration,
    /// `Some` only when the definition carries an explicit `[ech]` block.
    /// `None` means this resolver does not use ECH at all.
    pub ech: Option<EffectiveEch>,
    /// Only meaningful when `ech` is `Some`.
    pub require_ech: bool,
    /// Only meaningful when `ech` is `Some`.
    pub ech_refresh: Duration,
    /// Resolver performing this resolver's own ECH HTTPS-record lookup.
    /// Never inherited.
    pub ech_resolver: Option<String>,
}

impl ResolverDef {
    /// Flatten one definition, applying inheritance from `[global]` and defaults.
    ///
    /// Nothing here can fail: the fallible parts (endpoint grammar, reference
    /// existence, cycles, a `static` mode with no resolvable config) are checked
    /// by [`Config::validate_resolvers`], which reads *this* result rather than
    /// the raw definition so that validation and runtime never disagree.
    pub fn effective(&self, name: &str, global: &Global) -> EffectiveResolver {
        let g = &global.common;
        let ge = global.ech.as_ref();

        // The `[ech]` block inherits field-by-field from `[global.ech]` exactly as
        // a route's does — but only once this resolver has *declared* an `[ech]`
        // table. Presence is the opt-in gate; see the type-level note.
        let ech = self.ech.as_ref().map(|e| EffectiveEch {
            mode: e
                .mode
                .or_else(|| ge.and_then(|g| g.mode))
                .unwrap_or_default(),
            config: e
                .config
                .clone()
                .or_else(|| ge.and_then(|g| g.config.clone())),
            ech_domain: e
                .ech_domain
                .clone()
                .or_else(|| ge.and_then(|g| g.ech_domain.clone())),
            max_retries: e
                .max_retries
                .or_else(|| ge.and_then(|g| g.max_retries))
                .unwrap_or(2),
        });

        EffectiveResolver {
            name: name.to_string(),
            endpoint: self.endpoint.clone(),
            upstream: self.upstream.clone(),
            sni_policy: SniPolicy::resolve(self.override_sni.as_deref()),
            // Never inherited — a dependency edge, not a setting.
            bootstrap: self.bootstrap.clone(),
            address_family: self.address_family.or(g.address_family).unwrap_or_default(),
            nat64_prefix: self.nat64_prefix.clone().or_else(|| g.nat64_prefix.clone()),
            connect_timeout: self
                .connect_timeout
                .or(g.connect_timeout)
                .unwrap_or_else(default_connect_timeout),
            ech,
            // Gated on this resolver having its own `[ech]`: without one these are
            // never read. With one, they inherit like a route's, and a resolver
            // that opts into ECH defaults to requiring it.
            require_ech: self
                .ech
                .as_ref()
                .and_then(|e| {
                    e.require_ech
                        .or_else(|| ge.and_then(|g| g.require_ech))
                        .or(g.require_ech)
                })
                .unwrap_or(true),
            ech_refresh: self
                .ech
                .as_ref()
                .and_then(|e| {
                    e.ech_refresh
                        .or_else(|| ge.and_then(|g| g.ech_refresh))
                        .or(g.ech_refresh)
                })
                .unwrap_or_else(default_ech_refresh),
            // Never inherited — a dependency edge, like `bootstrap`.
            ech_resolver: self.ech.as_ref().and_then(|e| e.ech_resolver.clone()),
        }
    }

    /// The other resolvers this one depends on: its bootstrap, and whoever
    /// fetches its ECH config. These are the edges of the dependency graph.
    fn references(&self) -> impl Iterator<Item = &str> {
        [
            self.bootstrap.as_deref(),
            self.ech.as_ref().and_then(|e| e.ech_resolver.as_deref()),
        ]
        .into_iter()
        .flatten()
    }
}

// ---------------------------------------------------------------------------
// Overridable common options (the fallback ladder)
// ---------------------------------------------------------------------------

/// Settings that may be set at any scope and inherit outward. Every field is
/// `Option`; `None` means "inherit from the enclosing scope".
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CommonOpts {
    /// Generic resolver spec (DoH/DoT/IP/system). Used for both ECH lookups and
    /// upstream A/AAAA unless a purpose-specific resolver overrides it.
    #[serde(default)]
    pub resolver: Option<String>,

    /// Resolver used specifically for ECH HTTPS-record lookups.
    #[serde(default)]
    pub ech_resolver: Option<String>,

    /// Resolver used specifically for upstream A/AAAA resolution.
    #[serde(default)]
    pub addr_resolver: Option<String>,

    /// Default ECH refresh bound.
    #[serde(default, with = "humantime_serde::option")]
    pub ech_refresh: Option<Duration>,

    /// NAT64 /96 prefix for synthesizing IPv6 from a resolved IPv4 upstream.
    #[serde(default)]
    pub nat64_prefix: Option<String>,

    /// Address family for upstream hostname resolution.
    #[serde(default)]
    pub address_family: Option<AddressFamily>,

    /// Fail closed unless ECH negotiated (ech routes).
    #[serde(default)]
    pub require_ech: Option<bool>,

    /// Upstream connect + handshake timeout.
    #[serde(default, with = "humantime_serde::option")]
    pub connect_timeout: Option<Duration>,

    /// Idle timeout for the proxied byte stream in each direction.
    #[serde(default, with = "humantime_serde::option")]
    pub idle_timeout: Option<Duration>,
}

/// Upstream address family selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// Prefer AAAA, fall back to A; NAT64 may synthesize v6 from an A record.
    #[default]
    Dual,
    /// A records only (NAT64 may still synthesize v6 from the A record).
    Ipv4,
    /// AAAA records only; NAT64 disabled.
    Ipv6,
}

/// What to do when a connection cannot be served (unmatched, or a route's
/// failure). Applied to the (possibly never-decrypted) stream.
///
/// Accepts two spellings in TOML for convenience:
///   * a bare string for field-less modes — `unmatched = "close"` /
///     `unmatched = "system-outbound"`
///   * a table for modes that carry data — `unmatched = { mode = "passthrough",
///     addr = "127.0.0.1:80" }`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum FailPolicy {
    /// Drop the connection. Safe default.
    #[default]
    Close,
    /// Transparent egress: dial the real target named by the SNI/Host directly.
    SystemOutbound,
    /// Splice the raw stream to a fixed address.
    Passthrough { addr: SocketAddr },
}

impl<'de> Deserialize<'de> for FailPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // A bare string selects a field-less mode; a table selects any mode
        // (and is required for modes carrying data, e.g. passthrough's addr).
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Str(String),
            Table {
                mode: String,
                #[serde(default)]
                addr: Option<SocketAddr>,
            },
        }

        let (mode, addr) = match Repr::deserialize(deserializer)? {
            Repr::Str(s) => (s, None),
            Repr::Table { mode, addr } => (mode, addr),
        };

        match mode.as_str() {
            "close" => Ok(FailPolicy::Close),
            "system-outbound" => Ok(FailPolicy::SystemOutbound),
            "passthrough" => {
                let addr = addr.ok_or_else(|| {
                    serde::de::Error::custom("fail mode \"passthrough\" requires an `addr`")
                })?;
                Ok(FailPolicy::Passthrough { addr })
            }
            other => Err(serde::de::Error::custom(format!(
                "unknown fail mode {other:?} (expected close | system-outbound | passthrough)"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// CA / issuance / store / cache (dynamic certificate stack)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    #[serde(default = "default_ca_common_name")]
    pub common_name: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub country: String,
    #[serde(default = "default_leaf_validity_days")]
    pub leaf_validity_days: u32,
    #[serde(default)]
    pub install_to_system_root: bool,
}

/// What set of names a per-SNI leaf certificate should cover. Evaluated against
/// the registrable domain via the public-suffix list; IP literals and hosts with
/// no registrable domain always fall back to [`IssuanceMode::Exact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IssuanceMode {
    /// Only the requested host itself — no wildcard.
    Exact,
    /// The host and its direct subdomains: `{host, *.host}`. The default.
    #[default]
    Wildcard,
    /// The host and every ancestor domain up to the registrable domain, each
    /// with its single-level wildcard (e.g. `b.a.example.com` →
    /// `{b.a.example.com, *.b.a.example.com, a.example.com, *.a.example.com,
    /// example.com, *.example.com}`).
    Ladder,
}

/// Per-SNI issuance policy.
///
/// `mode` is an **upper bound** on how much one certificate may cover, not a
/// promise: a proposed wildcard is withheld when some host it would cover routes
/// to a different upstream on the same listener, because issuing it would let a
/// client reuse one HTTP/2 connection for both and bypass routing entirely (see
/// [`crate::certscope`]). The effective coverage of every route is printed at
/// startup.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceConfig {
    /// Name-coverage mode; the upper bound before route-scope clipping.
    #[serde(default)]
    pub mode: IssuanceMode,
}

impl IssuanceConfig {
    /// The configured issuance mode.
    pub fn resolved_mode(&self) -> IssuanceMode {
        self.mode
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_store_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_renew_margin_days")]
    pub renew_margin_days: u32,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: default_store_dir(),
            renew_margin_days: default_renew_margin_days(),
        }
    }
}

/// Public-suffix list configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PslConfig {
    /// PSL data source.
    #[serde(default)]
    pub source: PslSource,

    /// File path (only used when `source = "file"`).
    #[serde(default = "default_psl_path")]
    pub path: PathBuf,

    /// Whether to auto-download the PSL when it's stale.
    #[serde(default)]
    pub auto_update: bool,

    /// URL to download PSL from (only used when `auto_update = true`).
    #[serde(default = "default_psl_update_url")]
    pub update_url: String,

    /// Maximum age before PSL is considered stale.
    #[serde(default = "default_psl_max_age", with = "humantime_serde")]
    pub max_age: Duration,

    /// How often to check PSL age at runtime (None = only at startup).
    #[serde(default, with = "humantime_serde")]
    pub check_interval: Option<Duration>,

    /// Download timeout.
    #[serde(default = "default_psl_update_timeout", with = "humantime_serde")]
    pub update_timeout: Duration,

    /// Whether to hot-reload PSL when the file changes.
    #[serde(default)]
    pub auto_reload: bool,
}

impl Default for PslConfig {
    fn default() -> Self {
        Self {
            source: PslSource::Embedded,
            path: default_psl_path(),
            auto_update: false,
            update_url: default_psl_update_url(),
            max_age: default_psl_max_age(),
            check_interval: None,
            update_timeout: default_psl_update_timeout(),
            auto_reload: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PslSource {
    #[default]
    Embedded,
    File,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "default_cache_capacity")]
    pub capacity: u64,
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            ttl_secs: default_cache_ttl_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// Effective (flattened) route settings
// ---------------------------------------------------------------------------

/// The fully-resolved settings for one route after applying the fallback
/// ladder. Computed once at startup; the data path reads these directly.
#[derive(Debug, Clone)]
pub struct Effective {
    pub ech_resolver: Option<String>,
    pub addr_resolver: Option<String>,
    pub ech_refresh: Duration,
    pub nat64_prefix: Option<String>,
    pub address_family: AddressFamily,
    pub require_ech: bool,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub fail: FailPolicy,
}

/// The fully-resolved `[ech]` block for one ECH route, after merging the five
/// tiers of the ladder field-by-field. `require_ech` / `ech_refresh` /
/// `ech_resolver` are carried by [`Effective`] instead (they are shared with the
/// generic knobs); this struct holds the ECH-only identity fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEch {
    pub mode: EchMode,
    pub config: Option<String>,
    pub ech_domain: Option<String>,
    pub max_retries: u32,
}

/// The fully-resolved `[http2]` block for one route, after merging the five tiers
/// of the ladder field-by-field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveHttp2 {
    pub enabled: bool,
    pub probe: H2Probe,
    pub probe_timeout: Duration,
}

impl Config {
    /// Load and validate a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        let cfg: Config = toml::from_str(&text).map_err(ConfigError::Parse)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve a `use = "<name>"` reference to its template, or an error when the
    /// name is unknown. `None` (no reference) resolves to `Ok(None)`.
    pub fn template_for(&self, name: &Option<String>) -> Result<Option<&Template>, ConfigError> {
        match name {
            None => Ok(None),
            Some(n) => self.templates.get(n).map(Some).ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "unknown template {n:?} (no matching [templates.{n}])"
                ))
            }),
        }
    }

    /// Whether `pattern` is a `[regexes.<name>]` reference (starts with `@`).
    ///
    /// Named regex references are distinguished by an `@` prefix to avoid ambiguity
    /// with exact-match patterns. A pattern `@cdn-pattern` references
    /// `[regexes.cdn-pattern]`. The prefix is required and unambiguous: exact-match
    /// patterns never start with `@` in valid domain names.
    pub fn is_regex_ref(pattern: &str) -> bool {
        pattern.trim().starts_with('@')
    }

    /// Look up a declared regex by name (without the `@` prefix).
    pub fn regex_def(&self, name: &str) -> Result<&RegexDef, ConfigError> {
        self.regexes.get(name).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "unknown regex {name:?} (no matching [regexes.{name}])"
            ))
        })
    }

    /// Parse a regex reference pattern (with `@` prefix) and return the definition.
    pub fn resolve_regex_ref(&self, pattern: &str) -> Result<&RegexDef, ConfigError> {
        let name = pattern.trim().strip_prefix('@').ok_or_else(|| {
            ConfigError::Invalid(format!(
                "invalid regex reference {pattern:?} (must start with @)"
            ))
        })?;

        if name.is_empty() {
            return Err(ConfigError::Invalid(
                "regex reference cannot be bare '@' (expected @<name>)".into(),
            ));
        }

        self.regex_def(name)
    }

    /// Whether `spec` is a `[resolvers.<name>]` reference rather than an inline
    /// endpoint spec.
    ///
    /// Named resolver references are distinguished by an `@` prefix to maintain
    /// symmetry with named regex references. A spec `@my-resolver` references
    /// `[resolvers.my-resolver]`. The prefix is required and unambiguous: inline
    /// specs never start with `@`.
    pub fn is_resolver_ref(spec: &str) -> bool {
        spec.trim().starts_with('@')
    }

    /// Look up a declared resolver by name (without the `@` prefix).
    pub fn resolver_def(&self, name: &str) -> Result<&ResolverDef, ConfigError> {
        self.resolvers.get(name).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "unknown resolver {name:?} (no matching [resolvers.{name}])"
            ))
        })
    }

    /// Parse a resolver reference (with `@` prefix) and return the definition.
    pub fn resolve_resolver_ref(&self, spec: &str) -> Result<&ResolverDef, ConfigError> {
        let name = spec.trim().strip_prefix('@').ok_or_else(|| {
            ConfigError::Invalid(format!(
                "invalid resolver reference {spec:?} (must start with @)"
            ))
        })?;

        if name.is_empty() {
            return Err(ConfigError::Invalid(
                "resolver reference cannot be bare '@' (expected @<name>)".into(),
            ));
        }

        self.resolver_def(name)
    }

    /// The effective settings for a declared resolver, by name.
    pub fn effective_resolver(&self, name: &str) -> Result<EffectiveResolver, ConfigError> {
        Ok(self.resolver_def(name)?.effective(name, &self.global))
    }

    /// Every resolver spec written anywhere in the document, each tagged with a
    /// human-readable origin so an error can point at the line the user wrote.
    fn resolver_refs(&self) -> Vec<(String, String)> {
        fn push_common(out: &mut Vec<(String, String)>, origin: String, c: &CommonOpts) {
            for s in [&c.resolver, &c.ech_resolver, &c.addr_resolver]
                .into_iter()
                .flatten()
            {
                out.push((origin.clone(), s.clone()));
            }
        }

        let mut out: Vec<(String, String)> = Vec::new();

        push_common(&mut out, "[global]".to_string(), &self.global.common);
        if let Some(e) = &self.global.ech {
            if let Some(s) = &e.ech_resolver {
                out.push(("[global.ech]".to_string(), s.clone()));
            }
        }
        for (name, t) in &self.templates {
            push_common(&mut out, format!("[templates.{name}]"), &t.common);
            if let Some(e) = &t.ech {
                if let Some(s) = &e.ech_resolver {
                    out.push((format!("[templates.{name}.ech]"), s.clone()));
                }
            }
        }
        for l in &self.listeners {
            let origin = format!("listener {}", l.addr);
            push_common(&mut out, origin.clone(), &l.common);
            if let Some(e) = &l.ech {
                if let Some(s) = &e.ech_resolver {
                    out.push((format!("{origin} [ech]"), s.clone()));
                }
            }
            for r in l.routes.iter().chain(l.default_route.iter()) {
                let ro = format!("route {}", r.label());
                push_common(&mut out, ro.clone(), &r.common);
                if let Some(e) = &r.ech {
                    if let Some(s) = &e.ech_resolver {
                        out.push((format!("{ro} [ech]"), s.clone()));
                    }
                }
            }
        }
        for (name, r) in &self.resolvers {
            let origin = format!("[resolvers.{name}]");
            if let Some(s) = &r.bootstrap {
                out.push((format!("{origin} bootstrap"), s.clone()));
            }
            if let Some(e) = &r.ech {
                if let Some(s) = &e.ech_resolver {
                    out.push((format!("{origin}.ech ech_resolver"), s.clone()));
                }
            }
        }
        out
    }

    /// Validate the `[resolvers]` table: reference existence, endpoint grammar,
    /// acyclicity, and ECH completeness.
    ///
    /// Cycles must be a **load-time** refusal rather than a runtime timeout,
    /// because building a resolver is exactly what resolving its own address
    /// requires: a cycle would deadlock startup with no useful diagnostic. The
    /// error names the whole path so the user can see which edge to break.
    fn validate_resolvers(&self) -> Result<(), ConfigError> {
        // Every reference resolves.
        for (origin, spec) in self.resolver_refs() {
            if Self::is_resolver_ref(&spec) {
                // Validate the reference resolves
                self.resolve_resolver_ref(&spec)
                    .map_err(|e| ConfigError::Invalid(format!("{origin}: {e}")))?;
            }
        }

        for (name, def) in &self.resolvers {
            if def.endpoint.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "[resolvers.{name}]: `endpoint` must not be empty (use \"system\" for \
                     the OS resolver)"
                )));
            }
            // A resolver's own `endpoint` must be an inline spec: allowing a name
            // there would mean "this resolver *is* that resolver", which is a
            // reference, not a transport.
            if Self::is_resolver_ref(&def.endpoint) {
                return Err(ConfigError::Invalid(format!(
                    "[resolvers.{name}]: `endpoint` must be an inline spec, not a reference \
                     to another resolver (got {:?}); use `bootstrap` to say who resolves \
                     this endpoint's own address",
                    def.endpoint
                )));
            }

            let eff = def.effective(name, &self.global);

            // `static` / `doh-with-fallback` need a config from *somewhere*. This
            // reads the **effective** block, not the raw one: `config` may be
            // inherited from [global.ech], and checking the raw table would reject
            // exactly the case inheritance exists to serve.
            if let Some(ech) = &eff.ech {
                if matches!(ech.mode, EchMode::Static | EchMode::DohWithFallback)
                    && ech.config.is_none()
                {
                    return Err(ConfigError::Invalid(format!(
                        "[resolvers.{name}.ech]: mode = \"{}\" requires a base64 `config`, \
                         resolvable from [resolvers.{name}.ech] or [global.ech]",
                        match ech.mode {
                            EchMode::Static => "static",
                            _ => "doh-with-fallback",
                        }
                    )));
                }
                // An ECH-enabled resolver whose ECH lookup is answered by itself
                // cannot bootstrap: fetching its own ECHConfig needs the resolver
                // the fetch is for. The generic cycle check below catches named
                // self-reference, but `ech_resolver` omitted entirely means "the
                // system resolver", which is fine — only naming *itself* is not.
                if let Some(spec) = &eff.ech_resolver {
                    if Self::is_resolver_ref(spec) {
                        if let Some(resolved_name) = spec.strip_prefix('@') {
                            if resolved_name == name {
                                return Err(ConfigError::Invalid(format!(
                                    "[resolvers.{name}.ech]: ech_resolver = {spec:?} would have this \
                                     resolver fetch its own ECHConfig through itself; name a different \
                                     resolver, or omit it to use OS resolution"
                                )));
                            }
                        }
                    }
                }
            }
            if let Some(spec) = &eff.bootstrap {
                if Self::is_resolver_ref(spec) {
                    if let Some(resolved_name) = spec.strip_prefix('@') {
                        if resolved_name == name {
                            return Err(ConfigError::Invalid(format!(
                                "[resolvers.{name}]: bootstrap = {spec:?} would have this resolver \
                                 resolve its own address through itself; name a different resolver, \
                                 or omit it to use OS resolution"
                            )));
                        }
                    }
                }
            }
        }

        // Acyclicity. `build_order` performs the DFS and reports the path.
        self.resolver_build_order().map(|_| ())
    }

    /// The declared resolvers in dependency order: every resolver appears after
    /// the ones it depends on, so a single forward pass can build them all with
    /// each dependency already available.
    ///
    /// Returns an error naming the full cycle path when the graph is cyclic.
    pub fn resolver_build_order(&self) -> Result<Vec<String>, ConfigError> {
        #[derive(Clone, Copy, PartialEq)]
        enum Mark {
            Open,
            Done,
        }

        let mut marks: HashMap<&str, Mark> = HashMap::new();
        let mut order: Vec<String> = Vec::new();

        // Deterministic iteration: a HashMap's order varies per process, and an
        // error message (or a build order) that changes run to run is a bad
        // diagnostic. Sorting costs nothing at startup.
        let mut names: Vec<&str> = self.resolvers.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();

        // Explicit stack rather than recursion: a deep chain must not be able to
        // overflow the stack during config load.
        enum Step<'a> {
            Enter(&'a str, Vec<&'a str>),
            Exit(&'a str),
        }

        for root in names {
            if marks.get(root) == Some(&Mark::Done) {
                continue;
            }
            let mut stack = vec![Step::Enter(root, vec![root])];
            while let Some(step) = stack.pop() {
                match step {
                    Step::Exit(name) => {
                        marks.insert(name, Mark::Done);
                        order.push(name.to_string());
                    }
                    Step::Enter(name, path) => {
                        match marks.get(name) {
                            Some(Mark::Done) => continue,
                            Some(Mark::Open) => {
                                // `path` ends at the repeated name, so it already
                                // reads as the cycle.
                                return Err(ConfigError::Invalid(format!(
                                    "[resolvers]: dependency cycle {} — every resolver in a \
                                     cycle needs another one in it to find its own address. \
                                     Break the chain by pointing one `bootstrap` at a literal \
                                     IP, or by omitting it to use OS resolution",
                                    path.join(" -> ")
                                )));
                            }
                            None => {}
                        }
                        marks.insert(name, Mark::Open);
                        stack.push(Step::Exit(name));

                        // Only declared names are edges; inline specs are leaves.
                        let def = self.resolver_def(name)?;
                        let mut edges: Vec<&str> = def
                            .references()
                            .filter(|s| Self::is_resolver_ref(s))
                            .collect();
                        edges.sort_unstable();
                        edges.dedup();
                        for e in edges {
                            // Strip the @ prefix to get the bare name for lookup
                            let bare_name = e.strip_prefix('@').ok_or_else(|| {
                                ConfigError::Invalid(format!(
                                    "[resolvers.{name}]: invalid resolver reference {e:?}"
                                ))
                            })?;
                            // Resolve to the declared key so the reported path uses
                            // the canonical spelling.
                            let key = self
                                .resolvers
                                .get_key_value(bare_name)
                                .map(|(k, _)| k.as_str())
                                .ok_or_else(|| {
                                    ConfigError::Invalid(format!(
                                        "[resolvers.{name}]: unknown resolver {e:?}"
                                    ))
                                })?;
                            let mut next = path.clone();
                            next.push(key);
                            stack.push(Step::Enter(key, next));
                        }
                    }
                }
            }
        }
        Ok(order)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.listeners.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[listener]] is required".into(),
            ));
        }
        // Reject duplicate listen addresses.
        for (i, a) in self.listeners.iter().enumerate() {
            for b in &self.listeners[i + 1..] {
                if a.addr == b.addr {
                    return Err(ConfigError::Invalid(format!(
                        "duplicate listener address {}",
                        a.addr
                    )));
                }
            }
            let port = a.addr.port();
            let ln_tpl = self.template_for(&a.use_template)?;
            for r in &a.routes {
                let rt_tpl = self.template_for(&r.use_template)?;
                r.validate(false, port, rt_tpl)?;
                self.validate_ech(a, r, rt_tpl, ln_tpl)?;
                self.validate_http2(r, rt_tpl)?;
            }
            if let Some(d) = &a.default_route {
                let rt_tpl = self.template_for(&d.use_template)?;
                d.validate(true, port, rt_tpl)?;
                self.validate_ech(a, d, rt_tpl, ln_tpl)?;
                self.validate_http2(d, rt_tpl)?;
            }
        }
        if self.ca.leaf_validity_days < 1 {
            return Err(ConfigError::Invalid(
                "ca.leaf_validity_days must be >= 1".into(),
            ));
        }
        if self.store.renew_margin_days >= self.ca.leaf_validity_days {
            return Err(ConfigError::Invalid(
                "store.renew_margin_days must be < ca.leaf_validity_days".into(),
            ));
        }
        self.validate_resolvers()?;
        self.validate_regexes()?;
        Ok(())
    }

    /// Validate the `[regexes]` table: pattern compilation, scope_suffix presence
    /// and syntax, and reference resolution from routes.
    fn validate_regexes(&self) -> Result<(), ConfigError> {
        use regex::Regex;

        for (name, def) in &self.regexes {
            // 1. Pattern must compile
            Regex::new(&def.pattern).map_err(|e| {
                ConfigError::Invalid(format!("[regexes.{name}]: invalid pattern: {e}"))
            })?;

            // 2. scope_suffix must not be empty
            if def.scope_suffix.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "[regexes.{name}]: scope_suffix must not be empty (declare at least one \
                     domain suffix this pattern may match, e.g., [\"*.example.com\"])"
                )));
            }

            // 3. Each scope_suffix entry must be valid
            for scope in &def.scope_suffix {
                validate_scope_pattern(name, scope)?;
            }
        }

        // 4. Every regex reference in routes must resolve
        for listener in &self.listeners {
            for route in listener.routes.iter().chain(listener.default_route.iter()) {
                for pattern in &route.match_sni {
                    if Self::is_regex_ref(pattern) {
                        // Validate the reference resolves
                        self.resolve_regex_ref(pattern)?;
                    } else if pattern.trim().starts_with('~') {
                        // Inline regex syntax is no longer supported
                        return Err(ConfigError::Invalid(format!(
                            "route {}: inline regex {pattern:?} is no longer supported; \
                             declare it in [regexes.<name>] with a scope_suffix, then \
                             reference it as @<name>",
                            route.label()
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Compute the effective settings for `route` within `listener`, applying
    /// the ladder
    ///
    ///   route.ech → route → route-template → listener → listener-template → global
    ///
    /// with each scope's ECH block sitting deepest for the fields it shares with
    /// the generic knobs. `rt_tpl` / `ln_tpl` are the route's and listener's
    /// resolved templates (validated at load, so passed in rather than looked up).
    pub fn effective(
        &self,
        listener: &Listener,
        route: &Route,
        rt_tpl: Option<&Template>,
        ln_tpl: Option<&Template>,
    ) -> Effective {
        let g = &self.global.common;
        let l = &listener.common;
        let r = &route.common;
        let rt = rt_tpl.map(|t| &t.common);
        let lt = ln_tpl.map(|t| &t.common);

        // The resolved ECH block is the deepest tier for its shared fields, so
        // its require_ech / ech_refresh / ech_resolver still win over `common`.
        let eff_ech_shared = self.effective_ech_shared(listener, route, rt_tpl, ln_tpl);

        // Helper: first Some in deepest→shallowest order. Accepts the optional
        // template `common` refs via `.and_then`.
        macro_rules! pick {
            ($($opt:expr),+ $(,)?) => {{ None $(.or_else(|| $opt.clone()))+ }};
        }

        let ech_resolver = pick!(
            eff_ech_shared.ech_resolver,
            r.ech_resolver,
            r.resolver,
            rt.and_then(|t| t.ech_resolver.clone()),
            rt.and_then(|t| t.resolver.clone()),
            l.ech_resolver,
            l.resolver,
            lt.and_then(|t| t.ech_resolver.clone()),
            lt.and_then(|t| t.resolver.clone()),
            g.ech_resolver,
            g.resolver,
        );
        let addr_resolver = pick!(
            r.addr_resolver,
            r.resolver,
            rt.and_then(|t| t.addr_resolver.clone()),
            rt.and_then(|t| t.resolver.clone()),
            l.addr_resolver,
            l.resolver,
            lt.and_then(|t| t.addr_resolver.clone()),
            lt.and_then(|t| t.resolver.clone()),
            g.addr_resolver,
            g.resolver,
        );

        let ech_refresh = eff_ech_shared
            .ech_refresh
            .or(r.ech_refresh)
            .or_else(|| rt.and_then(|t| t.ech_refresh))
            .or(l.ech_refresh)
            .or_else(|| lt.and_then(|t| t.ech_refresh))
            .or(g.ech_refresh)
            .unwrap_or_else(default_ech_refresh);

        let nat64_prefix = pick!(
            r.nat64_prefix,
            rt.and_then(|t| t.nat64_prefix.clone()),
            l.nat64_prefix,
            lt.and_then(|t| t.nat64_prefix.clone()),
            g.nat64_prefix,
        );

        let address_family = r
            .address_family
            .or_else(|| rt.and_then(|t| t.address_family))
            .or(l.address_family)
            .or_else(|| lt.and_then(|t| t.address_family))
            .or(g.address_family)
            .unwrap_or_default();

        let require_ech = eff_ech_shared
            .require_ech
            .or(r.require_ech)
            .or_else(|| rt.and_then(|t| t.require_ech))
            .or(l.require_ech)
            .or_else(|| lt.and_then(|t| t.require_ech))
            .or(g.require_ech)
            .unwrap_or(true);

        let connect_timeout = r
            .connect_timeout
            .or_else(|| rt.and_then(|t| t.connect_timeout))
            .or(l.connect_timeout)
            .or_else(|| lt.and_then(|t| t.connect_timeout))
            .or(g.connect_timeout)
            .unwrap_or_else(default_connect_timeout);

        let idle_timeout = r
            .idle_timeout
            .or_else(|| rt.and_then(|t| t.idle_timeout))
            .or(l.idle_timeout)
            .or_else(|| lt.and_then(|t| t.idle_timeout))
            .or(g.idle_timeout)
            .unwrap_or_else(default_idle_timeout);

        let fail = route
            .fail
            .clone()
            .or_else(|| rt_tpl.and_then(|t| t.fail.clone()))
            .unwrap_or_else(|| self.global.unmatched.clone());

        Effective {
            ech_resolver,
            addr_resolver,
            ech_refresh,
            nat64_prefix,
            address_family,
            require_ech,
            connect_timeout,
            idle_timeout,
            fail,
        }
    }

    /// The ECH-only shared fields (`require_ech` / `ech_refresh` / `ech_resolver`)
    /// picked from the five-tier ECH ladder. Kept separate so [`effective`] can
    /// treat them as the deepest tier of the corresponding generic chains.
    fn effective_ech_shared(
        &self,
        listener: &Listener,
        route: &Route,
        rt_tpl: Option<&Template>,
        ln_tpl: Option<&Template>,
    ) -> EchShared {
        let tiers = self.ech_tiers(listener, route, rt_tpl, ln_tpl);
        EchShared {
            require_ech: tiers.iter().find_map(|e| e.require_ech),
            ech_refresh: tiers.iter().find_map(|e| e.ech_refresh),
            ech_resolver: tiers.iter().find_map(|e| e.ech_resolver.clone()),
        }
    }

    /// The five ECH tiers in deepest→shallowest order:
    /// `route.ech → route-template.ech → listener.ech → listener-template.ech → global.ech`.
    fn ech_tiers<'a>(
        &'a self,
        listener: &'a Listener,
        route: &'a Route,
        rt_tpl: Option<&'a Template>,
        ln_tpl: Option<&'a Template>,
    ) -> Vec<&'a EchConfig> {
        [
            route.ech.as_ref(),
            rt_tpl.and_then(|t| t.ech.as_ref()),
            listener.ech.as_ref(),
            ln_tpl.and_then(|t| t.ech.as_ref()),
            self.global.ech.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The fully-resolved ECH identity block for `route`, merging the five tiers
    /// field-by-field. `None` when nothing in any tier configures ECH *and* the
    /// route is not otherwise an ECH route — callers pass this only for ech
    /// routes, where the [`EchMode::Doh`] default guarantees `Some`.
    pub fn effective_ech(
        &self,
        listener: &Listener,
        route: &Route,
        rt_tpl: Option<&Template>,
        ln_tpl: Option<&Template>,
    ) -> EffectiveEch {
        let tiers = self.ech_tiers(listener, route, rt_tpl, ln_tpl);
        EffectiveEch {
            mode: tiers.iter().find_map(|e| e.mode).unwrap_or_default(),
            config: tiers.iter().find_map(|e| e.config.clone()),
            ech_domain: tiers.iter().find_map(|e| e.ech_domain.clone()),
            max_retries: tiers.iter().find_map(|e| e.max_retries).unwrap_or(2),
        }
    }

    /// The five HTTP/2 tiers in deepest→shallowest order, exactly mirroring
    /// [`ech_tiers`](Self::ech_tiers).
    fn http2_tiers<'a>(
        &'a self,
        listener: &'a Listener,
        route: &'a Route,
        rt_tpl: Option<&'a Template>,
        ln_tpl: Option<&'a Template>,
    ) -> Vec<&'a Http2Config> {
        [
            route.http2.as_ref(),
            rt_tpl.and_then(|t| t.http2.as_ref()),
            listener.http2.as_ref(),
            ln_tpl.and_then(|t| t.http2.as_ref()),
            self.global.http2.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The fully-resolved HTTP/2 block for `route`, merging the five tiers
    /// field-by-field.
    ///
    /// `raw` routes never terminate TLS, so there is no ALPN to negotiate and no
    /// bytes to reframe: `enabled` is forced to false for them. An *explicit*
    /// route-scope opt-in on a `raw` route is rejected at load time
    /// ([`validate_http2`](Self::validate_http2)); this only silently drops a
    /// value the route merely *inherited* from a broader scope, which is what
    /// makes a global `enabled = true` usable alongside `raw` routes.
    pub fn effective_http2(
        &self,
        listener: &Listener,
        route: &Route,
        rt_tpl: Option<&Template>,
        ln_tpl: Option<&Template>,
    ) -> EffectiveHttp2 {
        let tiers = self.http2_tiers(listener, route, rt_tpl, ln_tpl);
        let is_raw = Self::effective_route_type(route, rt_tpl) == Some(RouteType::Raw);
        EffectiveHttp2 {
            enabled: !is_raw && tiers.iter().find_map(|h| h.enabled).unwrap_or(false),
            probe: tiers.iter().find_map(|h| h.probe).unwrap_or_default(),
            probe_timeout: tiers
                .iter()
                .find_map(|h| h.probe_timeout)
                .unwrap_or_else(default_probe_timeout),
        }
    }

    /// Reject an *explicit* HTTP/2 opt-in on a `raw` route. Only the two
    /// route-scope tiers count: a value inherited from the listener or global
    /// scope is a broad default that `raw` routes simply ignore, whereas writing
    /// `enabled = true` on the route itself (or on the template it `use`s) can
    /// only be a mistake.
    fn validate_http2(&self, route: &Route, rt_tpl: Option<&Template>) -> Result<(), ConfigError> {
        if Self::effective_route_type(route, rt_tpl) != Some(RouteType::Raw) {
            return Ok(());
        }
        let explicit = [route.http2.as_ref(), rt_tpl.and_then(|t| t.http2.as_ref())]
            .into_iter()
            .flatten()
            .any(|h| h.enabled == Some(true));
        if explicit {
            return Err(ConfigError::Invalid(format!(
                "route {}: http2 cannot be enabled on a `raw` route (raw never \
                 terminates TLS, so there is no ALPN to negotiate)",
                route.label()
            )));
        }
        Ok(())
    }

    /// Resolve the concrete protocol type for `route`, taking the route's own
    /// `type` first and otherwise the referenced template's.
    pub fn effective_route_type(route: &Route, rt_tpl: Option<&Template>) -> Option<RouteType> {
        route
            .route_type
            .or_else(|| rt_tpl.and_then(|t| t.route_type))
    }

    /// Post-resolution ECH validation for one route: an ECH route must resolve to
    /// a usable config. `static` / `doh-with-fallback` additionally require an
    /// inline `config` to exist somewhere in the ladder.
    fn validate_ech(
        &self,
        listener: &Listener,
        route: &Route,
        rt_tpl: Option<&Template>,
        ln_tpl: Option<&Template>,
    ) -> Result<(), ConfigError> {
        if Self::effective_route_type(route, rt_tpl) != Some(RouteType::Ech) {
            return Ok(());
        }
        let eff = self.effective_ech(listener, route, rt_tpl, ln_tpl);
        if matches!(eff.mode, EchMode::Static | EchMode::DohWithFallback) && eff.config.is_none() {
            return Err(ConfigError::Invalid(format!(
                "route {}: ech mode {:?} requires an inline `config` (set it on the \
                 route, its template, or a [listener.ech]/[global.ech] default)",
                route.label(),
                eff.mode
            )));
        }
        Ok(())
    }
}

/// The ECH-only shared fields lifted out of the ECH ladder for [`Effective`].
struct EchShared {
    require_ech: Option<bool>,
    ech_refresh: Option<Duration>,
    ech_resolver: Option<String>,
}

impl Route {
    /// Display name for logs.
    pub fn label(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.match_sni.first().cloned())
            .or_else(|| self.route_type.map(|t| format!("{t:?}").to_lowercase()))
            .unwrap_or_else(|| "route".to_string())
    }

    /// The upstream spec this route dials, taking the route's own value first
    /// and otherwise the value from its template (route scope only — `upstream`
    /// is not a listener/global setting).
    fn upstream_spec<'a>(&'a self, tpl: Option<&'a Template>) -> Option<&'a str> {
        self.upstream
            .as_deref()
            .or_else(|| tpl.and_then(|t| t.upstream.as_deref()))
    }

    /// The pinned cert/key pair for local termination, resolved atomically from
    /// the first scope (route → route-template) that sets *either*.
    fn cert_key<'a>(&'a self, tpl: Option<&'a Template>) -> (Option<&'a Path>, Option<&'a Path>) {
        if self.cert_file.is_some() || self.key_file.is_some() {
            return (self.cert_file.as_deref(), self.key_file.as_deref());
        }
        match tpl {
            Some(t) => (t.cert_file.as_deref(), t.key_file.as_deref()),
            None => (None, None),
        }
    }

    fn validate(
        &self,
        is_default: bool,
        listener_port: u16,
        tpl: Option<&Template>,
    ) -> Result<(), ConfigError> {
        // `upstream` may be omitted (dynamic host + listener port) or supplied by
        // a template. When set, it must parse; an explicitly empty string is a
        // mistake, not a defaulting request.
        let spec = self.upstream_spec(tpl);
        if let Some(s) = spec {
            if s.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "route {}: upstream, when set, must not be empty (omit it to \
                     reflect the source SNI/Host to this listener's port)",
                    self.label()
                )));
            }
        }
        resolved_upstream_from(spec, listener_port).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "route {}: invalid upstream {:?}",
                self.label(),
                spec.unwrap_or_default()
            ))
        })?;

        if !is_default && self.match_sni.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "route {}: match_sni needs at least one pattern (or use default_route)",
                self.label()
            )));
        }

        // A concrete protocol type must come from the route or its template.
        if self.route_type.or(tpl.and_then(|t| t.route_type)).is_none() {
            return Err(ConfigError::Invalid(format!(
                "route {}: missing type (set `type` or a template that provides it)",
                self.label()
            )));
        }

        // cert/key must be set together after resolving them as a unit.
        let (cert, key) = self.cert_key(tpl);
        if cert.is_some() != key.is_some() {
            return Err(ConfigError::Invalid(format!(
                "route {}: cert_file and key_file must be set together",
                self.label()
            )));
        }

        // `override_sni` needs no validation: every value is meaningful. A blank
        // one is an explicit "send no SNI extension" (see `SniPolicy`), not the
        // mistake it was once treated as.
        Ok(())
    }

    /// The upstream SNI policy for this route, taking the route's own
    /// `override_sni` first and otherwise its template's.
    ///
    /// The two scopes are resolved on *presence*, so a route may deliberately
    /// blank out a name inherited from its template by setting
    /// `override_sni = ""` — that reads as [`SniPolicy::Omit`], not as "unset,
    /// fall through to the template".
    pub fn sni_policy(&self, tpl: Option<&Template>) -> SniPolicy {
        SniPolicy::resolve(
            self.override_sni
                .as_deref()
                .or_else(|| tpl.and_then(|t| t.override_sni.as_deref())),
        )
    }
}

/// Parse an upstream address into (host, port).
///
/// Accepted forms:
///   * `host:port`        — a DNS name or IPv4 with a port
///   * `[v6]:port`        — an IPv6 literal in brackets with a port
///
/// A bare IPv6 literal without brackets (e.g. `2a01:4f8::1:443`) is rejected:
/// it is ambiguous because the colons cannot be split reliably. Such addresses
/// must be written in bracket form `[2a01:4f8::1]:443`. Returns `None` on any
/// malformed input.
pub fn split_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let (host, tail) = rest.split_once(']')?;
        // Validate it really is an IPv6 literal.
        host.parse::<std::net::Ipv6Addr>().ok()?;
        let port = tail.strip_prefix(':')?;
        Some((host.to_string(), port.parse().ok()?))
    } else {
        // Exactly one colon is required: host:port. More than one colon means an
        // unbracketed IPv6 literal, which is ambiguous and must use [..] form.
        let (host, port) = s.rsplit_once(':')?;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        Some((host.to_string(), port.parse().ok()?))
    }
}

/// A parsed `upstream` value with independently-optional host and port.
///
/// `host = None` means "use the matched source SNI/Host"; `port = None` means
/// "use the parent listener's port". The two are resolved by
/// [`resolved_upstream_from`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSpec {
    pub host: Option<String>,
    pub port: Option<u16>,
}

/// Parse a non-empty `upstream` value into an [`UpstreamSpec`].
///
/// Accepted forms (after trimming):
///   * `"8443"`        — a bare port (all digits): host defaulted, port fixed.
///   * `"host:port"`   — a DNS name or IPv4 with a port.
///   * `"[v6]:port"`   — an IPv6 literal in brackets with a port.
///   * `"host"`        — a bare host with no port: port defaulted.
///
/// A bare, unbracketed IPv6 literal is rejected (ambiguous — must use `[v6]`),
/// as are malformed ports. Returns `None` on any unrecognized input. The empty
/// string is *not* a valid spec here; omit the field to default both parts.
pub fn parse_upstream(s: &str) -> Option<UpstreamSpec> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // A bare port (all digits) defaults the host. Checked first because a value
    // like "443" is both a valid u16 and a colon-free "host".
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return Some(UpstreamSpec {
            host: None,
            port: Some(s.parse().ok()?),
        });
    }
    // A colon (bracketed or not) means an explicit port is present; delegate to
    // the strict host:port / [v6]:port parser.
    if s.contains(':') {
        let (host, port) = split_host_port(s)?;
        return Some(UpstreamSpec {
            host: Some(host),
            port: Some(port),
        });
    }
    // Otherwise a bare host with no port; the port defaults to the listener's.
    Some(UpstreamSpec {
        host: Some(s.to_string()),
        port: None,
    })
}

/// Resolve an (already scope-picked) upstream spec against `listener_port`,
/// filling in the defaulted pieces. Returns `(host, port)` where `host` is
/// `None` when it should be taken from the matched source SNI/Host at connection
/// time (dynamic). Returns `None` only when a present spec fails to parse.
///
///   * `None` spec       → `(None, listener_port)`   (omitted: reflect + inherit)
///   * `"8443"`          → `(None, 8443)`
///   * `"host"`          → `(Some(host), listener_port)`
///   * `"host:port"`     → `(Some(host), port)`
pub fn resolved_upstream_from(
    spec: Option<&str>,
    listener_port: u16,
) -> Option<(Option<String>, u16)> {
    let Some(spec) = spec else {
        return Some((None, listener_port));
    };
    let parsed = parse_upstream(spec)?;
    Some((parsed.host, parsed.port.unwrap_or(listener_port)))
}

// ---------------------------------------------------------------------------
// upstream deserialization (Option<String> that also accepts integers)
// ---------------------------------------------------------------------------

/// Deserialize an optional upstream spec, accepting both string and integer
/// values. An integer is treated as a bare port and stored as its decimal
/// string so that the existing [`parse_upstream`] path handles it unchanged.
///
/// `upstream = 443` is therefore identical to `upstream = "443"`, both
/// meaning "use the matched source SNI/Host as the dial host and port 443".
/// The value is validated as a `u16` at deserialization, before `parse_upstream`
/// gets to it, so an out-of-range integer is caught with a clear message.
fn de_option_upstream<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Outer;

    impl<'de> serde::de::Visitor<'de> for Outer {
        type Value = Option<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "an upstream string or port number, or absent")
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Option<String>, E> {
            Ok(None)
        }

        fn visit_some<D2: serde::Deserializer<'de>>(
            self,
            d: D2,
        ) -> Result<Option<String>, D2::Error> {
            d.deserialize_any(Inner).map(Some)
        }
    }

    struct Inner;

    impl<'de> serde::de::Visitor<'de> for Inner {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "an upstream string or port number")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_string())
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<String, E> {
            u16::try_from(v)
                .map_err(|_| E::custom(format!("port {v} out of range (0..=65535)")))?;
            Ok(v.to_string())
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<String, E> {
            u16::try_from(v)
                .map_err(|_| E::custom(format!("port {v} out of range (0..=65535)")))?;
            Ok(v.to_string())
        }
    }

    deserializer.deserialize_option(Outer)
}

// ---------------------------------------------------------------------------
// Scope pattern validation
// ---------------------------------------------------------------------------

/// Validate a single scope_suffix pattern for syntactic correctness.
///
/// Accepted forms:
/// * `"*.domain.com"` — wildcard (one-label subdomains)
/// * `".domain.com"` — suffix (domain and all subdomains)
/// * `"domain.com"` — exact apex
///
/// The domain part must be multi-level (contain at least one dot) and consist
/// of valid domain-name characters. Bare TLDs like `"com"` or `"*.com"` are
/// rejected.
fn validate_scope_pattern(regex_name: &str, scope: &str) -> Result<(), ConfigError> {
    let scope = scope.trim();

    if scope.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "[regexes.{regex_name}]: scope_suffix contains empty entry"
        )));
    }

    // Extract the domain part by stripping pattern prefixes
    let domain = if let Some(rest) = scope.strip_prefix("*.") {
        rest
    } else if let Some(rest) = scope.strip_prefix('.') {
        rest
    } else {
        scope
    };

    if domain.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "[regexes.{regex_name}]: invalid scope_suffix {scope:?} (pattern prefix with no domain)"
        )));
    }

    // Must contain at least one dot (multi-level domain, not a bare TLD)
    if !domain.contains('.') {
        return Err(ConfigError::Invalid(format!(
            "[regexes.{regex_name}]: scope_suffix {scope:?} must be a multi-level domain \
             (e.g., \"*.example.com\", \".example.com\", or \"example.com\"); \
             bare TLDs are not allowed"
        )));
    }

    // Basic validation: domain-name characters only
    // Allow: alphanumeric, hyphen, dot. Hyphen cannot be at start/end of a label.
    let labels: Vec<&str> = domain.split('.').collect();
    for label in labels {
        if label.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "[regexes.{regex_name}]: scope_suffix {scope:?} contains empty label \
                 (consecutive dots or leading/trailing dot)"
            )));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(ConfigError::Invalid(format!(
                "[regexes.{regex_name}]: scope_suffix {scope:?} contains invalid label \
                 {label:?} (hyphens cannot be at the start or end)"
            )));
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ConfigError::Invalid(format!(
                "[regexes.{regex_name}]: scope_suffix {scope:?} contains invalid characters \
                 in label {label:?} (only alphanumeric and hyphen allowed)"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Listener address deserialization
// ---------------------------------------------------------------------------

/// Deserialize a listener bind address.
///
/// Accepts three forms:
///
/// * Full socket address strings: `"0.0.0.0:443"`, `"[::]:443"`.
/// * Bare port **string**: `"443"` → `0.0.0.0:443`.
/// * Bare port **integer**: `443` → `0.0.0.0:443`.
///
/// The bare-port shorthand binds the IPv4 wildcard only, matching
/// nginx's `listen 443` semantics. Normalising here means the
/// duplicate-address check in [`Config::validate`] sees `"443"` and
/// `"0.0.0.0:443"` as the same address and correctly rejects the pair.
fn de_listen_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = SocketAddr;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "a socket address (\"ip:port\", \"[v6]:port\") \
                 or a bare port number (\"443\" or 443)"
            )
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SocketAddr, E> {
            parse_listen_addr(v).map_err(E::custom)
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<SocketAddr, E> {
            let port = u16::try_from(v)
                .map_err(|_| E::custom(format!("port {v} out of range (0..=65535)")))?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port,
            ))
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<SocketAddr, E> {
            let port = u16::try_from(v)
                .map_err(|_| E::custom(format!("port {v} out of range (0..=65535)")))?;
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port,
            ))
        }
    }

    deserializer.deserialize_any(Visitor)
}

/// Parse a listener address string.
///
/// * Bare decimal port (`"443"`) → `0.0.0.0:<port>`.
/// * Full socket address (`"ip:port"`, `"[v6]:port"`) → passed through.
/// * Anything else (hostname, bare IPv6, colon-only) → error.
pub fn parse_listen_addr(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("listener addr must not be empty".to_string());
    }
    // All-digit string: bare port shorthand.
    if s.bytes().all(|b| b.is_ascii_digit()) {
        let port: u16 = s
            .parse()
            .map_err(|_| format!("port {s:?} out of range (0..=65535)"))?;
        return Ok(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
        ));
    }
    // Full socket address; no hostname resolution.
    s.parse::<SocketAddr>().map_err(|_| {
        "invalid socket address (expected \"ip:port\", \"[v6]:port\", or a bare port)".to_string()
    })
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_log() -> String {
    "info".to_string()
}
fn default_true() -> bool {
    true
}
fn default_ca_common_name() -> String {
    "SNI Gate Local CA".to_string()
}
fn default_leaf_validity_days() -> u32 {
    397
}
fn default_store_dir() -> PathBuf {
    PathBuf::from("certs")
}
fn default_renew_margin_days() -> u32 {
    30
}
fn default_cache_capacity() -> u64 {
    8_192
}
fn default_cache_ttl_secs() -> u64 {
    24 * 60 * 60
}
fn default_ech_refresh() -> Duration {
    Duration::from_secs(3600)
}
fn default_connect_timeout() -> Duration {
    Duration::from_secs(15)
}
fn default_idle_timeout() -> Duration {
    // A true idle timeout (reset on every chunk). 5 minutes tolerates
    // WebSocket/streaming connections that are quiet between messages while
    // still reaping genuinely dead ones. Set `idle_timeout = "0s"` to disable.
    Duration::from_secs(300)
}
fn default_probe_timeout() -> Duration {
    // The probe is a single TCP connect plus one frame exchange against a local
    // or nearby backend; 3s is generous while keeping startup snappy when a
    // backend is unreachable.
    Duration::from_secs(3)
}
fn default_psl_path() -> PathBuf {
    PathBuf::from("cache/public_suffix_list.dat")
}
fn default_psl_update_url() -> String {
    "https://publicsuffix.org/list/public_suffix_list.dat".to_string()
}
fn default_psl_max_age() -> Duration {
    Duration::from_secs(30 * 24 * 60 * 60) // 30 days
}
fn default_psl_update_timeout() -> Duration {
    Duration::from_secs(30)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_variants() {
        // host:port and IPv4:port
        assert_eq!(split_host_port("a.com:443"), Some(("a.com".into(), 443)));
        assert_eq!(
            split_host_port("1.2.3.4:443"),
            Some(("1.2.3.4".into(), 443))
        );
        // Bracketed IPv6 is accepted.
        assert_eq!(
            split_host_port("[2a01:4f8::1]:443"),
            Some(("2a01:4f8::1".into(), 443))
        );
        assert_eq!(
            split_host_port("[2a01:4f8:c2c:123f:64:5:6812:202f]:443"),
            Some(("2a01:4f8:c2c:123f:64:5:6812:202f".into(), 443))
        );
        // A bare (unbracketed) IPv6 literal is ambiguous and rejected: the user
        // must write [v6]:port. This is the bug from the field report where
        // "2a01:...:202f:443" was mis-split with the IP treated as a hostname.
        assert_eq!(
            split_host_port("2a01:4f8:c2c:123f:64:5:6812:202f:443"),
            None
        );
        assert_eq!(split_host_port("2a01:4f8::1:443"), None);
        // Malformed.
        assert_eq!(split_host_port("no-port"), None);
        assert_eq!(split_host_port("a.com:bad"), None);
        // A bracketed non-IPv6 is rejected.
        assert_eq!(split_host_port("[not-v6]:443"), None);
    }

    #[test]
    fn parse_upstream_variants() {
        let spec = |host: Option<&str>, port: Option<u16>| {
            Some(UpstreamSpec {
                host: host.map(str::to_string),
                port,
            })
        };
        // Bare port: host defaulted, port fixed.
        assert_eq!(parse_upstream("8443"), spec(None, Some(8443)));
        assert_eq!(parse_upstream("443"), spec(None, Some(443)));
        // Bare host: port defaulted.
        assert_eq!(
            parse_upstream("cdn.example.com"),
            spec(Some("cdn.example.com"), None)
        );
        // host:port and IPv4:port.
        assert_eq!(parse_upstream("a.com:443"), spec(Some("a.com"), Some(443)));
        assert_eq!(
            parse_upstream("1.2.3.4:8443"),
            spec(Some("1.2.3.4"), Some(8443))
        );
        // Bracketed IPv6 with a port.
        assert_eq!(
            parse_upstream("[2a01:4f8::1]:443"),
            spec(Some("2a01:4f8::1"), Some(443))
        );
        // Surrounding whitespace is tolerated.
        assert_eq!(parse_upstream("  9000  "), spec(None, Some(9000)));
        // Rejected: empty, bare v6, bad port, port overflow, bracketed non-v6.
        assert_eq!(parse_upstream(""), None);
        assert_eq!(parse_upstream("   "), None);
        assert_eq!(parse_upstream("2a01:4f8::1:443"), None);
        assert_eq!(parse_upstream("a.com:bad"), None);
        assert_eq!(parse_upstream("99999"), None);
        assert_eq!(parse_upstream("[not-v6]:443"), None);
    }

    #[test]
    fn resolved_upstream_defaults() {
        // Omitted: dynamic host, listener port.
        assert_eq!(resolved_upstream_from(None, 8443), Some((None, 8443)));
        // Port-only: dynamic host, explicit port.
        assert_eq!(
            resolved_upstream_from(Some("9001"), 443),
            Some((None, 9001))
        );
        // Bare host: fixed host, listener port.
        assert_eq!(
            resolved_upstream_from(Some("cdn.x"), 443),
            Some((Some("cdn.x".into()), 443))
        );
        // host:port: both fixed.
        assert_eq!(
            resolved_upstream_from(Some("cdn.x:8080"), 443),
            Some((Some("cdn.x".into()), 8080))
        );
        // A present-but-unparseable spec is an error (None).
        assert_eq!(resolved_upstream_from(Some("a.com:bad"), 443), None);
    }

    #[test]
    fn fail_policy_string_and_table_forms() {
        #[derive(Deserialize)]
        struct W {
            p: FailPolicy,
        }
        // Bare-string forms.
        let close: W = toml::from_str(r#"p = "close""#).unwrap();
        assert_eq!(close.p, FailPolicy::Close);
        let sysout: W = toml::from_str(r#"p = "system-outbound""#).unwrap();
        assert_eq!(sysout.p, FailPolicy::SystemOutbound);
        // Table form for passthrough (needs addr).
        let pass: W =
            toml::from_str(r#"p = { mode = "passthrough", addr = "127.0.0.1:80" }"#).unwrap();
        assert_eq!(
            pass.p,
            FailPolicy::Passthrough {
                addr: "127.0.0.1:80".parse().unwrap()
            }
        );
        // Table form for a field-less mode is also accepted (back-compat).
        let close2: W = toml::from_str(r#"p = { mode = "close" }"#).unwrap();
        assert_eq!(close2.p, FailPolicy::Close);
        // passthrough without addr is an error.
        assert!(toml::from_str::<W>(r#"p = { mode = "passthrough" }"#).is_err());
        // Unknown mode is an error.
        assert!(toml::from_str::<W>(r#"p = "bogus""#).is_err());
    }

    // A config exercising the fallback ladder: global sets defaults, the
    // listener overrides some, and one route overrides more.
    const HIER: &str = r#"
[global]
resolver = "https://global.example/dns-query"
nat64_prefix = "64:ff9b::"
connect_timeout = "9s"

[ca]
cert_path = "ca.crt"
key_path = "ca.key"

[[listener]]
addr = "0.0.0.0:443"
addr_resolver = "tls://1.1.1.1:853"
connect_timeout = "3s"

  [[listener.route]]
  name = "inherits"
  type = "tls"
  match_sni = [".inherit.com"]
  upstream = "u1:443"

  [[listener.route]]
  name = "overrides"
  type = "tls"
  match_sni = [".override.com"]
  upstream = "u2:443"
  nat64_prefix = "2a01:4f8:c2c:123f:64:5"
  connect_timeout = "1s"
  addr_resolver = "9.9.9.9"
"#;

    #[test]
    fn hierarchical_fallback() {
        let cfg: Config = toml::from_str(HIER).unwrap();
        cfg.validate().unwrap();
        let listener = &cfg.listeners[0];

        // Route 0 inherits: addr_resolver from listener, nat64 from global,
        // connect_timeout from the listener (nearer than global).
        let e0 = cfg.effective(listener, &listener.routes[0], None, None);
        assert_eq!(e0.addr_resolver.as_deref(), Some("tls://1.1.1.1:853"));
        assert_eq!(e0.nat64_prefix.as_deref(), Some("64:ff9b::"));
        assert_eq!(e0.connect_timeout, Duration::from_secs(3));

        // Route 1 overrides all three at the route scope.
        let e1 = cfg.effective(listener, &listener.routes[1], None, None);
        assert_eq!(e1.addr_resolver.as_deref(), Some("9.9.9.9"));
        assert_eq!(e1.nat64_prefix.as_deref(), Some("2a01:4f8:c2c:123f:64:5"));
        assert_eq!(e1.connect_timeout, Duration::from_secs(1));
    }

    // -----------------------------------------------------------------------
    // ECH field-by-field inheritance + named templates
    // -----------------------------------------------------------------------

    /// Minimal CA block so a `Config` validates.
    const CA: &str = "[ca]\ncert_path = \"ca.crt\"\nkey_path = \"ca.key\"\n";

    fn parse(cfg: &str) -> Config {
        let full = format!("{CA}{cfg}");
        toml::from_str(&full).unwrap()
    }

    /// Resolve the effective ECH block of listener 0's route `idx`.
    fn route_ech(cfg: &Config, idx: usize) -> EffectiveEch {
        let l = &cfg.listeners[0];
        let r = &l.routes[idx];
        let rt = cfg.template_for(&r.use_template).unwrap();
        let lt = cfg.template_for(&l.use_template).unwrap();
        cfg.effective_ech(l, r, rt, lt)
    }

    #[test]
    fn ech_inherits_field_by_field() {
        let cfg = parse(
            r#"
[global.ech]
mode = "static"
config = "GLOBALCFG"
ech_domain = "global-ech.example"

[[listener]]
addr = "0.0.0.0:443"

  [listener.ech]
  ech_domain = "listener-ech.example"

  [[listener.route]]
  name = "a"
  type = "ech"
  match_sni = [".a.com"]
    [listener.route.ech]
    max_retries = 5

  [[listener.route]]
  name = "b"
  type = "ech"
  match_sni = [".b.com"]
"#,
        );
        cfg.validate().unwrap();

        // Route a: mode+config from global, ech_domain from listener (nearer),
        // max_retries from the route's own [ech].
        let a = route_ech(&cfg, 0);
        assert_eq!(a.mode, EchMode::Static);
        assert_eq!(a.config.as_deref(), Some("GLOBALCFG"));
        assert_eq!(a.ech_domain.as_deref(), Some("listener-ech.example"));
        assert_eq!(a.max_retries, 5);

        // Route b has no [ech] block at all yet still resolves the full config.
        let b = route_ech(&cfg, 1);
        assert_eq!(b.mode, EchMode::Static);
        assert_eq!(b.config.as_deref(), Some("GLOBALCFG"));
        assert_eq!(b.ech_domain.as_deref(), Some("listener-ech.example"));
        assert_eq!(b.max_retries, 2); // default
    }

    #[test]
    fn ech_mode_unset_is_distinct_from_doh() {
        // A route [ech] that sets only require_ech must NOT pin mode=doh; it
        // inherits mode=static (and its config) from global. This is the crux of
        // making the whole [ech] block inheritable.
        let cfg = parse(
            r#"
[global.ech]
mode = "static"
config = "GLOBALCFG"

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "ech"
  match_sni = [".a.com"]
    [listener.route.ech]
    require_ech = false
"#,
        );
        cfg.validate().unwrap();
        let a = route_ech(&cfg, 0);
        assert_eq!(a.mode, EchMode::Static);
        assert_eq!(a.config.as_deref(), Some("GLOBALCFG"));
    }

    #[test]
    fn template_supplies_type_upstream_and_ech() {
        let cfg = parse(
            r#"
[templates.edge]
type = "ech"
upstream = "cdn.example:443"
  [templates.edge.ech]
  mode = "static"
  config = "EDGECFG"

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  use = "edge"
  match_sni = [".a.com"]
"#,
        );
        cfg.validate().unwrap();
        let l = &cfg.listeners[0];
        let r = &l.routes[0];
        let rt = cfg.template_for(&r.use_template).unwrap();
        assert_eq!(Config::effective_route_type(r, rt), Some(RouteType::Ech));
        let spec = r
            .upstream
            .as_deref()
            .or(rt.and_then(|t| t.upstream.as_deref()));
        assert_eq!(
            resolved_upstream_from(spec, 443),
            Some((Some("cdn.example".into()), 443))
        );
        let e = cfg.effective_ech(l, r, rt, None);
        assert_eq!(e.mode, EchMode::Static);
        assert_eq!(e.config.as_deref(), Some("EDGECFG"));
    }

    #[test]
    fn template_precedence_walks_all_tiers() {
        // Five scopes each set connect_timeout; peel them off one at a time and
        // watch the resolved value walk route → route-tpl → listener →
        // listener-tpl → global.
        let base = |route_ct: Option<&str>| {
            let route_line = route_ct
                .map(|v| format!("  connect_timeout = \"{v}\"\n"))
                .unwrap_or_default();
            format!(
                r#"
[global]
connect_timeout = "5s"

[templates.rtpl]
connect_timeout = "2s"

[templates.ltpl]
connect_timeout = "4s"

[[listener]]
addr = "0.0.0.0:443"
use = "ltpl"
connect_timeout = "3s"
  [[listener.route]]
  name = "a"
  type = "raw"
  use = "rtpl"
  match_sni = [".a.com"]
  upstream = "127.0.0.1:9"
{route_line}"#
            )
        };
        let eff = |cfg: &Config| {
            let l = &cfg.listeners[0];
            let r = &l.routes[0];
            let rt = cfg.template_for(&r.use_template).unwrap();
            let lt = cfg.template_for(&l.use_template).unwrap();
            cfg.effective(l, r, rt, lt).connect_timeout
        };

        // Route explicit wins.
        assert_eq!(eff(&parse(&base(Some("1s")))), Duration::from_secs(1));
        // Drop route → route template (2s).
        assert_eq!(eff(&parse(&base(None))), Duration::from_secs(2));
    }

    #[test]
    fn template_precedence_listener_then_global() {
        // Without route/route-tpl values, listener-explicit (3s) wins; drop it and
        // the listener template (4s) wins; drop that and global (5s) wins.
        let cfg = parse(
            r#"
[global]
connect_timeout = "5s"

[templates.ltpl]
connect_timeout = "4s"

[[listener]]
addr = "0.0.0.0:443"
use = "ltpl"
connect_timeout = "3s"
  [[listener.route]]
  name = "a"
  type = "raw"
  match_sni = [".a.com"]
  upstream = "127.0.0.1:9"
"#,
        );
        let l = &cfg.listeners[0];
        let r = &l.routes[0];
        let lt = cfg.template_for(&l.use_template).unwrap();
        assert_eq!(
            cfg.effective(l, r, None, lt).connect_timeout,
            Duration::from_secs(3)
        );
        // Listener template only (no listener-explicit).
        let cfg2 = parse(
            r#"
[global]
connect_timeout = "5s"
[templates.ltpl]
connect_timeout = "4s"
[[listener]]
addr = "0.0.0.0:443"
use = "ltpl"
  [[listener.route]]
  name = "a"
  type = "raw"
  match_sni = [".a.com"]
  upstream = "127.0.0.1:9"
"#,
        );
        let l2 = &cfg2.listeners[0];
        let lt2 = cfg2.template_for(&l2.use_template).unwrap();
        assert_eq!(
            cfg2.effective(l2, &l2.routes[0], None, lt2).connect_timeout,
            Duration::from_secs(4)
        );
    }

    #[test]
    fn listener_template_upstream_does_not_reach_route() {
        // `upstream` is a route-scope setting; a listener's template must never
        // change a route's dial target.
        let cfg = parse(
            r#"
[templates.ltpl]
upstream = "wrong.example:1"

[[listener]]
addr = "0.0.0.0:8443"
use = "ltpl"
  [[listener.route]]
  name = "a"
  type = "raw"
  match_sni = [".a.com"]
"#,
        );
        cfg.validate().unwrap();
        let r = &cfg.listeners[0].routes[0];
        // Route + its (absent) template only → omitted → reflect on listener port.
        let rt = cfg.template_for(&r.use_template).unwrap();
        let spec = r
            .upstream
            .as_deref()
            .or(rt.and_then(|t| t.upstream.as_deref()));
        assert_eq!(resolved_upstream_from(spec, 8443), Some((None, 8443)));
    }

    #[test]
    fn unknown_template_name_is_an_error() {
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "raw"
  use = "nope"
  match_sni = [".a.com"]
  upstream = "127.0.0.1:9"
"#,
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn templates_cannot_nest() {
        // A `use` key inside a [templates.*] table is an unknown field.
        let err = toml::from_str::<Config>(&format!(
            "{CA}[templates.a]\nuse = \"b\"\ntype = \"raw\"\n\n[[listener]]\naddr = \"0.0.0.0:443\"\n"
        ));
        assert!(err.is_err());
    }

    #[test]
    fn missing_type_is_an_error() {
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  match_sni = [".a.com"]
  upstream = "127.0.0.1:9"
"#,
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn type_from_template_is_accepted() {
        let cfg = parse(
            r#"
[templates.web]
type = "http"
upstream = "127.0.0.1:8080"

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  use = "web"
  match_sni = [".a.com"]
"#,
        );
        cfg.validate().unwrap();
        let r = &cfg.listeners[0].routes[0];
        let rt = cfg.template_for(&r.use_template).unwrap();
        assert_eq!(Config::effective_route_type(r, rt), Some(RouteType::Http));
    }

    #[test]
    fn ech_static_without_config_is_an_error() {
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "ech"
  match_sni = [".a.com"]
    [listener.route.ech]
    mode = "static"
"#,
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn issuance_mode_resolution() {
        for (toml_src, want) in [
            (r#"mode = "exact""#, IssuanceMode::Exact),
            (r#"mode = "wildcard""#, IssuanceMode::Wildcard),
            (r#"mode = "ladder""#, IssuanceMode::Ladder),
        ] {
            let c: IssuanceConfig = toml::from_str(toml_src).unwrap();
            assert_eq!(c.resolved_mode(), want, "for {toml_src}");
        }
        // Unset → the default.
        let c = IssuanceConfig::default();
        assert_eq!(c.resolved_mode(), IssuanceMode::Wildcard);
        let c: IssuanceConfig = toml::from_str("").unwrap();
        assert_eq!(c.resolved_mode(), IssuanceMode::Wildcard);

        // There is exactly one way to express the mode: the removed legacy
        // boolean is now an unknown field, so a stale config fails loudly at load
        // rather than being silently reinterpreted.
        assert!(
            toml::from_str::<IssuanceConfig>(r#"wildcard = true"#).is_err(),
            "the legacy `wildcard` flag must be rejected, not ignored"
        );
    }

    // -----------------------------------------------------------------------
    // override_sni / SniPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn sni_policy_resolution() {
        // Omitted reflects; a name is used verbatim (trimmed).
        assert_eq!(SniPolicy::resolve(None), SniPolicy::Reflect);
        assert_eq!(
            SniPolicy::resolve(Some("inner.example")),
            SniPolicy::Fixed("inner.example".into())
        );
        assert_eq!(
            SniPolicy::resolve(Some("  inner.example  ")),
            SniPolicy::Fixed("inner.example".into())
        );
        // Present-but-blank means "send no SNI", distinct from unset.
        assert_eq!(SniPolicy::resolve(Some("")), SniPolicy::Omit);
        assert_eq!(SniPolicy::resolve(Some("   ")), SniPolicy::Omit);
    }

    #[test]
    fn empty_override_sni_is_accepted_and_means_omit() {
        // Previously a load-time error; now the way to suppress SNI entirely.
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "no-sni"
  type = "tls"
  match_sni = [".a.com"]
  override_sni = ""
"#,
        );
        cfg.validate().unwrap();
        let r = &cfg.listeners[0].routes[0];
        assert_eq!(r.sni_policy(None), SniPolicy::Omit);
    }

    #[test]
    fn route_can_blank_out_a_templates_override_sni() {
        // Resolution is on *presence*, so an explicit "" at the deeper scope wins
        // over a name from the template rather than falling through to it.
        let cfg = parse(
            r#"
[templates.edge]
type = "tls"
override_sni = "from-template.example"

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "inherits"
  use = "edge"
  match_sni = [".a.com"]

  [[listener.route]]
  name = "blanks-it"
  use = "edge"
  match_sni = [".b.com"]
  override_sni = ""
"#,
        );
        cfg.validate().unwrap();
        let l = &cfg.listeners[0];
        let tpl = cfg.template_for(&l.routes[0].use_template).unwrap();
        assert_eq!(
            l.routes[0].sni_policy(tpl),
            SniPolicy::Fixed("from-template.example".into())
        );
        let tpl2 = cfg.template_for(&l.routes[1].use_template).unwrap();
        assert_eq!(l.routes[1].sni_policy(tpl2), SniPolicy::Omit);
    }

    // -----------------------------------------------------------------------
    // HTTP/2 field-by-field inheritance
    // -----------------------------------------------------------------------

    /// Resolve the effective HTTP/2 block of listener 0's route `idx`.
    fn route_http2(cfg: &Config, idx: usize) -> EffectiveHttp2 {
        let l = &cfg.listeners[0];
        let r = &l.routes[idx];
        let rt = cfg.template_for(&r.use_template).unwrap();
        let lt = cfg.template_for(&l.use_template).unwrap();
        cfg.effective_http2(l, r, rt, lt)
    }

    #[test]
    fn http2_inherits_field_by_field() {
        let cfg = parse(
            r#"
[global.http2]
enabled = true
probe = "require"
probe_timeout = "9s"

[[listener]]
addr = "0.0.0.0:443"

  [listener.http2]
  probe = "off"

  [[listener.route]]
  name = "a"
  type = "http"
  match_sni = [".a.com"]
    [listener.route.http2]
    probe_timeout = "1s"

  [[listener.route]]
  name = "b"
  type = "http"
  match_sni = [".b.com"]
"#,
        );
        cfg.validate().unwrap();

        // Route a: enabled from global, probe from the listener (nearer than
        // global), probe_timeout from the route's own [http2].
        let a = route_http2(&cfg, 0);
        assert!(a.enabled);
        assert_eq!(a.probe, H2Probe::Off);
        assert_eq!(a.probe_timeout, Duration::from_secs(1));

        // Route b has no [http2] block at all yet still resolves the full config.
        let b = route_http2(&cfg, 1);
        assert!(b.enabled);
        assert_eq!(b.probe, H2Probe::Off);
        assert_eq!(b.probe_timeout, Duration::from_secs(9));
    }

    #[test]
    fn http2_defaults_when_unconfigured() {
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "http"
  match_sni = [".a.com"]
"#,
        );
        cfg.validate().unwrap();
        let a = route_http2(&cfg, 0);
        assert!(!a.enabled, "http2 must be opt-in");
        assert_eq!(a.probe, H2Probe::Warn, "probe defaults to warn");
        assert_eq!(a.probe_timeout, Duration::from_secs(3));
    }

    #[test]
    fn http2_explicitly_enabled_on_raw_route_is_an_error() {
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "raw"
  match_sni = [".a.com"]
    [listener.route.http2]
    enabled = true
"#,
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn http2_enabled_on_a_raw_routes_template_is_an_error() {
        let cfg = parse(
            r#"
[templates.rawtpl]
type = "raw"
  [templates.rawtpl.http2]
  enabled = true

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  use = "rawtpl"
  match_sni = [".a.com"]
"#,
        );
        assert!(cfg.validate().is_err());
    }

    // -----------------------------------------------------------------------
    // parse_listen_addr / bare-port shorthand
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // upstream integer shorthand
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_integer_equals_string() {
        // Integer form must parse to the same value as the equivalent string.
        let with_int = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "raw"
  match_sni = [".a.com"]
  upstream = 8443
"#,
        );
        let with_str = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "raw"
  match_sni = [".a.com"]
  upstream = "8443"
"#,
        );
        with_int.validate().unwrap();
        with_str.validate().unwrap();
        assert_eq!(
            with_int.listeners[0].routes[0].upstream,
            with_str.listeners[0].routes[0].upstream,
        );
    }

    #[test]
    fn upstream_integer_in_template() {
        let cfg = parse(
            r#"
[templates.web]
type = "http"
upstream = 8080

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  use = "web"
  match_sni = [".a.com"]
"#,
        );
        cfg.validate().unwrap();
        assert_eq!(cfg.templates["web"].upstream.as_deref(), Some("8080"));
    }

    #[test]
    fn upstream_integer_out_of_range_is_rejected() {
        let result = toml::from_str::<Config>(&format!(
            "{CA}[[listener]]\naddr = \"0.0.0.0:443\"\n[[listener.route]]\nname = \"a\"\ntype = \"raw\"\nmatch_sni = [\".a.com\"]\nupstream = 99999\n"
        ));
        assert!(result.is_err(), "port 99999 must be rejected");
    }

    #[test]
    fn listen_addr_bare_port_string() {
        let unspec = std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            parse_listen_addr("443").unwrap(),
            SocketAddr::new(unspec, 443)
        );
        assert_eq!(
            parse_listen_addr("8443").unwrap(),
            SocketAddr::new(unspec, 8443)
        );
        // Port 0 is valid (OS picks a free port).
        assert_eq!(parse_listen_addr("0").unwrap(), SocketAddr::new(unspec, 0));
        // Surrounding whitespace is tolerated.
        assert_eq!(
            parse_listen_addr("  443  ").unwrap(),
            SocketAddr::new(unspec, 443)
        );
    }

    #[test]
    fn listen_addr_full_forms_pass_through() {
        assert_eq!(
            parse_listen_addr("127.0.0.1:443").unwrap(),
            "127.0.0.1:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen_addr("[::1]:443").unwrap(),
            "[::1]:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen_addr("[::]:8443").unwrap(),
            "[::]:8443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_listen_addr("0.0.0.0:443").unwrap(),
            "0.0.0.0:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn listen_addr_port_out_of_range() {
        assert!(parse_listen_addr("65536").is_err());
        assert!(parse_listen_addr("99999").is_err());
    }

    #[test]
    fn listen_addr_rejected_forms() {
        // Hostname — no DNS resolution at parse time.
        assert!(parse_listen_addr("localhost:443").is_err());
        // Leading colon without IP.
        assert!(parse_listen_addr(":443").is_err());
        // Bare unbracketed IPv6 (ambiguous colons).
        assert!(parse_listen_addr("::1:443").is_err());
        assert!(parse_listen_addr("::1").is_err());
        // Empty.
        assert!(parse_listen_addr("").is_err());
        // Nonsense.
        assert!(parse_listen_addr("not-an-addr").is_err());
    }

    /// `"443"` and `"0.0.0.0:443"` must normalize to the same address so
    /// the duplicate-listener check in [`Config::validate`] catches the pair.
    #[test]
    fn listen_addr_shorthand_deduplication() {
        let shorthand = parse_listen_addr("443").unwrap();
        let explicit: SocketAddr = "0.0.0.0:443".parse().unwrap();
        assert_eq!(
            shorthand, explicit,
            "shorthand must equal the explicit form"
        );

        let cfg = parse(
            r#"
[[listener]]
addr = "443"
  [[listener.route]]
  name = "a"
  type = "raw"
  match_sni = [".a.com"]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "b"
  type = "raw"
  match_sni = [".b.com"]
"#,
        );
        assert!(
            cfg.validate().is_err(),
            "duplicate listeners must be rejected"
        );
    }

    #[test]
    fn http2_inherited_by_a_raw_route_is_ignored_not_an_error() {
        // The whole point of an inheriting block: a global opt-in must coexist
        // with raw routes, which simply ignore it.
        let cfg = parse(
            r#"
[global.http2]
enabled = true

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "raw"
  type = "raw"
  match_sni = [".raw.com"]

  [[listener.route]]
  name = "web"
  type = "http"
  match_sni = [".web.com"]
"#,
        );
        cfg.validate().unwrap();
        assert!(!route_http2(&cfg, 0).enabled, "raw ignores inherited http2");
        assert!(route_http2(&cfg, 1).enabled, "http route still gets it");
    }

    #[test]
    fn ech_doh_without_config_is_ok() {
        // Plain DoH mode does not need an inline config.
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  name = "a"
  type = "ech"
  match_sni = [".a.com"]
    [listener.route.ech]
    ech_domain = "cloudflare-ech.com"
"#,
        );
        cfg.validate().unwrap();
        assert_eq!(route_ech(&cfg, 0).mode, EchMode::Doh);
    }

    // -- Named regex validation tests ---------------------------------------

    #[test]
    fn regex_with_valid_scope_suffix() {
        let cfg = parse(
            r#"
[regexes.cdn]
pattern = "^cdn-[0-9]+\\.example\\.com$"
scope_suffix = ["*.example.com"]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@cdn"]
"#,
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn regex_with_multiple_scope_suffixes() {
        let cfg = parse(
            r#"
[regexes.multi]
pattern = "^test.*$"
scope_suffix = ["*.example.com", ".other.com", "apex.com"]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@multi"]
"#,
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn regex_with_empty_scope_suffix_is_rejected() {
        let cfg = parse(
            r#"
[regexes.bad]
pattern = "^test\\.com$"
scope_suffix = []

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@bad"]
"#,
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("scope_suffix must not be empty"));
    }

    #[test]
    fn regex_with_invalid_pattern_is_rejected() {
        let cfg = parse(
            r#"
[regexes.bad]
pattern = "^[invalid"
scope_suffix = ["*.example.com"]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@bad"]
"#,
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("invalid pattern"));
    }

    #[test]
    fn regex_with_bare_tld_scope_is_rejected() {
        let cfg = parse(
            r#"
[regexes.bad]
pattern = "^.*\\.com$"
scope_suffix = ["*.com"]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@bad"]
"#,
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("multi-level domain"));
        assert!(err.to_string().contains("bare TLDs"));
    }

    #[test]
    fn regex_with_empty_scope_entry_is_rejected() {
        let cfg = parse(
            r#"
[regexes.bad]
pattern = "^test\\.example\\.com$"
scope_suffix = ["*.example.com", ""]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@bad"]
"#,
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("empty entry"));
    }

    #[test]
    fn regex_with_invalid_label_is_rejected() {
        let cfg = parse(
            r#"
[regexes.bad]
pattern = "^test$"
scope_suffix = ["*.-invalid.com"]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@bad"]
"#,
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("hyphens cannot be at the start"));
    }

    #[test]
    fn inline_regex_is_rejected() {
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["~^test\\.com$"]
"#,
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("inline regex"));
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn regex_reference_to_nonexistent_regex_is_rejected() {
        let cfg = parse(
            r#"
[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = ["@nonexistent"]
"#,
        );
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("unknown regex"));
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn is_regex_ref_identifies_at_prefix() {
        assert!(Config::is_regex_ref("@cdn-pattern"));
        assert!(Config::is_regex_ref("  @name  "));
        assert!(!Config::is_regex_ref("example.com"));
        assert!(!Config::is_regex_ref("*.example.com"));
        assert!(!Config::is_regex_ref(".example.com"));
        assert!(!Config::is_regex_ref(""));
    }

    #[test]
    fn resolve_regex_ref_extracts_name() {
        let cfg = parse(
            r#"
[regexes.test-cdn]
pattern = "^test$"
scope_suffix = ["*.example.com"]

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  type = "tls"
  match_sni = [".example.com"]
"#,
        );
        cfg.validate().unwrap();

        let def = cfg.resolve_regex_ref("@test-cdn").unwrap();
        assert_eq!(def.pattern, "^test$");
        assert_eq!(def.scope_suffix, vec!["*.example.com"]);

        assert!(cfg.resolve_regex_ref("@nonexistent").is_err());
        assert!(cfg.resolve_regex_ref("not-a-ref").is_err());
        assert!(cfg.resolve_regex_ref("@").is_err());
    }
}
