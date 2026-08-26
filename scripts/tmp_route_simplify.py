from pathlib import Path
import re


def replace(path, old, new, count=1):
    p = Path(path)
    text = p.read_text()
    actual = text.count(old)
    if actual != count:
        raise SystemExit(f"{path}: expected {count} occurrence(s), found {actual}: {old[:80]!r}")
    p.write_text(text.replace(old, new, count))


def sub(path, pattern, replacement, count=1):
    p = Path(path)
    text = p.read_text()
    new, actual = re.subn(pattern, replacement, text, count=count, flags=re.S)
    if actual != count:
        raise SystemExit(f"{path}: expected {count} regex replacement(s), found {actual}: {pattern[:80]!r}")
    p.write_text(new)


# ---------------------------------------------------------------------------
# src/config.rs: public route types are transport-agnostic; H3 variants remain
# runtime-only implementation details.
# ---------------------------------------------------------------------------
replace(
    "src/config.rs",
    '''    /// Inbound transport. TCP is the historical/default data path; QUIC binds
    /// the same numeric address as UDP and accepts `raw`, `h3`, and `h3-ech`
    /// routes.
''',
    '''    /// Inbound transport. TCP is the historical/default data path; QUIC binds
    /// the same numeric address as UDP. Route `type` stays transport-agnostic:
    /// `raw` is transparent on either transport, while `tls` / `ech` terminate
    /// TCP as HTTP/1.1-or-h2 and QUIC as HTTP/3.
''',
)

replace(
    "src/config.rs",
    '''/// How an upstream connection is made.
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
    /// Terminate inbound QUIC/HTTP/3 and re-originate HTTP/3 over ordinary
    /// QUIC TLS.
    H3,
    /// Terminate inbound QUIC/HTTP/3 and re-originate HTTP/3 over QUIC with an
    /// ECH-protected TLS ClientHello.
    #[serde(rename = "h3-ech", alias = "h3ech")]
    H3Ech,
}
''',
    '''/// How an upstream connection is made. The public TOML vocabulary is
/// transport-agnostic: `raw`, `http`, `tls`, and `ech`. The listener transport
/// decides whether a terminating TLS/ECH route becomes the TCP or HTTP/3 data
/// path at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteType {
    /// Terminate and re-originate with ECH. TCP uses TLS 1.3 + ECH; QUIC uses
    /// HTTP/3 over QUIC TLS + ECH.
    Ech,
    /// Terminate and re-originate without ECH. TCP uses ordinary TLS; QUIC uses
    /// HTTP/3 over ordinary QUIC TLS.
    Tls,
    /// Forward to a cleartext HTTP upstream. Currently TCP-only.
    Http,
    /// Do not terminate: splice the transport unchanged (TCP bytes or QUIC UDP
    /// datagrams after Initial-SNI routing). No certificate is issued.
    Raw,
    /// Runtime-only normalized form of `transport = "quic"` + `type = "tls"`.
    #[doc(hidden)]
    #[serde(skip)]
    H3,
    /// Runtime-only normalized form of `transport = "quic"` + `type = "ech"`.
    #[doc(hidden)]
    #[serde(skip)]
    H3Ech,
}
''',
)

replace(
    "src/config.rs",
    '''                self.validate_ech(a, r, rt_tpl, ln_tpl)?;
                self.validate_http2(r, rt_tpl)?;
                self.validate_http3(a, r, rt_tpl)?;
''',
    '''                self.validate_ech(a, r, rt_tpl, ln_tpl)?;
                self.validate_http2(a, r, rt_tpl)?;
                self.validate_http3(a, r, rt_tpl)?;
''',
)
replace(
    "src/config.rs",
    '''                self.validate_ech(a, d, rt_tpl, ln_tpl)?;
                self.validate_http2(d, rt_tpl)?;
                self.validate_http3(a, d, rt_tpl)?;
''',
    '''                self.validate_ech(a, d, rt_tpl, ln_tpl)?;
                self.validate_http2(a, d, rt_tpl)?;
                self.validate_http3(a, d, rt_tpl)?;
''',
)

replace(
    "src/config.rs",
    '''        let supports_http2 = matches!(
            Self::effective_route_type(route, rt_tpl),
            Some(RouteType::Http | RouteType::Tls | RouteType::Ech)
        );
''',
    '''        let supports_http2 = listener.transport == ListenerTransport::Tcp
            && matches!(
                Self::effective_route_type(route, rt_tpl),
                Some(RouteType::Http | RouteType::Tls | RouteType::Ech)
            );
''',
)

replace(
    "src/config.rs",
    '''    /// Map a TCP route type to the route type used by its QUIC companion.
    pub fn http3_companion_route_type(route_type: RouteType) -> Option<RouteType> {
        match route_type {
            RouteType::Tls => Some(RouteType::H3),
            RouteType::Ech => Some(RouteType::H3Ech),
            RouteType::Raw => Some(RouteType::Raw),
            RouteType::Http | RouteType::H3 | RouteType::H3Ech => None,
        }
    }
''',
    '''    /// Whether a TCP route type can be copied into an automatic QUIC
    /// companion. The public route type itself is preserved; transport-specific
    /// normalization happens only when the runtime route is built.
    pub fn http3_companion_route_type(route_type: RouteType) -> Option<RouteType> {
        match route_type {
            RouteType::Tls | RouteType::Ech | RouteType::Raw => Some(route_type),
            RouteType::Http | RouteType::H3 | RouteType::H3Ech => None,
        }
    }
''',
)

replace(
    "src/config.rs",
    '''        let Some(companion_type) = Self::http3_companion_route_type(route_type) else {
            return Ok(None);
        };
        let mut companion = route.clone();
        // Explicitly mapped type wins over a route template carrying the TCP type.
        companion.route_type = Some(companion_type);
        companion.http3 = None;
''',
    '''        if Self::http3_companion_route_type(route_type).is_none() {
            return Ok(None);
        }
        let mut companion = route.clone();
        // Preserve the public type (`tls`, `ech`, or `raw`). QUIC transport is
        // what selects H3/H3-ECH semantics when this route is built at runtime.
        companion.http3 = None;
''',
)

replace(
    "src/config.rs",
    '''    fn validate_http2(&self, route: &Route, rt_tpl: Option<&Template>) -> Result<(), ConfigError> {
        let route_type = Self::effective_route_type(route, rt_tpl);
        if matches!(
            route_type,
            Some(RouteType::Http | RouteType::Tls | RouteType::Ech)
        ) {
            return Ok(());
        }
''',
    '''    fn validate_http2(
        &self,
        listener: &Listener,
        route: &Route,
        rt_tpl: Option<&Template>,
    ) -> Result<(), ConfigError> {
        let route_type = Self::effective_route_type(route, rt_tpl);
        if listener.transport == ListenerTransport::Tcp
            && matches!(
                route_type,
                Some(RouteType::Http | RouteType::Tls | RouteType::Ech)
            )
        {
            return Ok(());
        }
''',
)
replace(
    "src/config.rs",
    '''                "route {}: http2 cannot be enabled on a `{}` route",
                route.label(),
                route_type.map(route_type_name).unwrap_or("unknown")
''',
    '''                "route {}: http2 cannot be enabled on a `{}` route over {:?}",
                route.label(),
                route_type.map(route_type_name).unwrap_or("unknown"),
                listener.transport
''',
)

replace(
    "src/config.rs",
    '''    /// Resolve the concrete protocol type for `route`, taking the route's own
    /// `type` first and otherwise the referenced template's.
    pub fn effective_route_type(route: &Route, rt_tpl: Option<&Template>) -> Option<RouteType> {
        route
            .route_type
            .or_else(|| rt_tpl.and_then(|t| t.route_type))
    }
''',
    '''    /// Resolve the public/configured route type, taking the route's own `type`
    /// first and otherwise the referenced template's.
    pub fn effective_route_type(route: &Route, rt_tpl: Option<&Template>) -> Option<RouteType> {
        route
            .route_type
            .or_else(|| rt_tpl.and_then(|t| t.route_type))
    }

    /// Normalize the transport-agnostic public type into the concrete runtime
    /// data path. H3/H3-ECH exist only after this point; they are not TOML types.
    pub fn runtime_route_type(
        transport: ListenerTransport,
        route_type: RouteType,
    ) -> Option<RouteType> {
        match (transport, route_type) {
            (ListenerTransport::Tcp, RouteType::Raw | RouteType::Http | RouteType::Tls | RouteType::Ech) => {
                Some(route_type)
            }
            (ListenerTransport::Quic, RouteType::Raw) => Some(RouteType::Raw),
            (ListenerTransport::Quic, RouteType::Tls) => Some(RouteType::H3),
            (ListenerTransport::Quic, RouteType::Ech) => Some(RouteType::H3Ech),
            _ => None,
        }
    }
''',
)

replace(
    "src/config.rs",
    '''        let valid = match listener.transport {
            ListenerTransport::Tcp => matches!(
                route_type,
                RouteType::Raw | RouteType::Http | RouteType::Tls | RouteType::Ech
            ),
            ListenerTransport::Quic => {
                matches!(
                    route_type,
                    RouteType::Raw | RouteType::H3 | RouteType::H3Ech
                )
            }
        };
''',
    '''        let valid = Self::runtime_route_type(listener.transport, route_type).is_some();
''',
)

# ---------------------------------------------------------------------------
# src/main.rs: normalize config type to transport-specific runtime type once.
# ---------------------------------------------------------------------------
replace(
    "src/main.rs",
    '''    // Concrete protocol type (route → template), guaranteed present by validation.
    let route_type = Config::effective_route_type(route, rt_tpl)
        .ok_or_else(|| anyhow::anyhow!("route {}: missing type", route.label()))?;
''',
    '''    // Public route type is transport-agnostic. Normalize it exactly once into
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
''',
)

# ---------------------------------------------------------------------------
# Config boundary tests.
# ---------------------------------------------------------------------------
sub(
    "tests/quic_config.rs",
    r'''#\[test\]\nfn quic_listener_accepts_h3_route\(\) \{.*?\n\}\n\n#\[test\]\nfn canonical_h3_ech_route_spelling_is_accepted\(\) \{.*?\n\}\n\n#\[test\]\nfn legacy_h3ech_route_spelling_remains_accepted\(\) \{.*?\n\}\n\n#\[test\]\nfn tcp_listener_rejects_h3_route\(\) \{.*?\n\}\n\n#\[test\]\nfn quic_listener_rejects_tls_route\(\) \{.*?\n\}\n''',
    '''#[test]
fn quic_listener_accepts_tls_route_as_h3_runtime() {
    let cfg = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  name = "web-h3"
  type = "tls"
  match_sni = ["h3.example"]
"#,
    )
    .expect("tls is a valid terminating QUIC route");

    let route_type = cfg.listeners[0].routes[0].route_type.unwrap();
    assert_eq!(route_type, RouteType::Tls);
    assert_eq!(
        Config::runtime_route_type(ListenerTransport::Quic, route_type),
        Some(RouteType::H3)
    );
}

#[test]
fn quic_listener_accepts_ech_route_as_h3_ech_runtime() {
    let cfg = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  name = "web-h3-ech"
  type = "ech"
  match_sni = ["h3-ech.example"]
"#,
    )
    .expect("ech is a valid terminating QUIC route");

    let route_type = cfg.listeners[0].routes[0].route_type.unwrap();
    assert_eq!(route_type, RouteType::Ech);
    assert_eq!(
        Config::runtime_route_type(ListenerTransport::Quic, route_type),
        Some(RouteType::H3Ech)
    );
}

#[test]
fn h3_names_are_not_public_route_types() {
    for route_type in ["h3", "h3-ech", "h3ech"] {
        let error = load(&format!(
            r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  type = "{route_type}"
  match_sni = ["h3.example"]
"#
        ))
        .expect_err("H3 naming is runtime-only, not a public route type");
        assert!(error.to_string().contains(route_type));
    }
}

#[test]
fn quic_listener_rejects_cleartext_http_route() {
    let error = load(
        r#"
[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
  [[listener.route]]
  type = "http"
  match_sni = ["http.example"]
"#,
    )
    .expect_err("cleartext HTTP upstream translation is not implemented for QUIC");

    assert!(error
        .to_string()
        .contains("incompatible with a Quic listener"));
}
''',
)

replace(
    "tests/quic_config.rs",
    '''    assert_eq!(expanded[1].transport, ListenerTransport::Quic);
    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::H3));
''',
    '''    assert_eq!(expanded[1].transport, ListenerTransport::Quic);
    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::Tls));
    assert_eq!(
        Config::runtime_route_type(
            expanded[1].transport,
            expanded[1].routes[0].route_type.unwrap()
        ),
        Some(RouteType::H3)
    );
''',
)
replace(
    "tests/quic_config.rs",
    '''    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::H3));
''',
    '''    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::Tls));
''',
)
replace(
    "tests/quic_config.rs",
    '''    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::H3Ech));
    assert_eq!(expanded[1].routes[1].route_type, Some(RouteType::Raw));
''',
    '''    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::Ech));
    assert_eq!(expanded[1].routes[1].route_type, Some(RouteType::Raw));
    assert_eq!(
        Config::runtime_route_type(
            expanded[1].transport,
            expanded[1].routes[0].route_type.unwrap()
        ),
        Some(RouteType::H3Ech)
    );
''',
)

# ---------------------------------------------------------------------------
# README: expose only the four transport-agnostic route types.
# ---------------------------------------------------------------------------
replace(
    "README.md",
    '''TCP routes support **ECH**, plain **TLS**, cleartext **HTTP**, and **raw** byte
passthrough. QUIC/UDP routes support **raw** datagram passthrough, **HTTP/3**, and
**HTTP/3 + ECH** (`h3-ech`). Configuration is hierarchical (route → listener →
''',
    '''Route types are transport-agnostic: **ECH**, plain **TLS**, cleartext **HTTP**,
and **raw**. On TCP, terminating `tls`/`ech` routes carry HTTP/1.1 or HTTP/2; on
QUIC/UDP, the same `tls`/`ech` types terminate and proxy HTTP/3. Configuration is
hierarchical (route → listener →
''',
)
replace(
    "README.md",
    '''- **ECH re-origination** — hide the true SNI from the path to a CDN edge, for both
  TCP TLS (`ech`) and QUIC HTTP/3 (`h3-ech`) upstreams.
- **Shared QUIC dispatch** — one UDP listener can inspect QUIC Initial packets to
  route transparent `raw` flows while also terminating `h3` / `h3-ech` flows on
  that same UDP socket.
''',
    '''- **ECH re-origination** — hide the true SNI from the path to a CDN edge; the
  same `ech` route type works on TCP and QUIC/HTTP/3 listeners.
- **Shared QUIC dispatch** — one UDP listener can inspect QUIC Initial packets to
  route transparent `raw` flows while also terminating `tls` / `ech` HTTP/3 flows
  on that same UDP socket.
''',
)
replace(
    "README.md",
    '''QUIC client ── QUIC Initial ───▶ sni-gate :443/UDP
                                  │ inspect Initial SNI (v1/v2)
                                  ├─ raw ──────────────▶ untouched UDP datagrams
                                  ├─ h3 ───────────────▶ H3 → H3 semantic proxy
                                  └─ h3-ech ───────────▶ H3 → H3 + upstream ECH
''',
    '''QUIC client ── QUIC Initial ───▶ sni-gate :443/UDP
                                  │ inspect Initial SNI (v1/v2)
                                  ├─ raw ──────────────▶ untouched UDP datagrams
                                  ├─ tls ──────────────▶ H3 → H3 semantic proxy
                                  └─ ech ──────────────▶ H3 → H3 + upstream ECH
''',
)
replace(
    "README.md",
    '''QUIC/TLS endpoint. `h3` and `h3-ech` instead terminate inbound QUIC and proxy
HTTP/3 messages semantically.
''',
    '''QUIC/TLS endpoint. `tls` and `ech` instead terminate inbound QUIC and proxy
HTTP/3 messages semantically.
''',
)
replace(
    "README.md",
    '''sni-gate keeps the configured TCP listener and synthesizes a QUIC companion on
`0.0.0.0:443/UDP`. Eligible route types map as `tls -> h3`, `ech -> h3-ech`,
and `raw -> raw`. Cleartext `http` is skipped because H3-to-HTTP/1.1/h2c
translation is not implemented. `[http3]` inherits through route, template,
''',
    '''sni-gate keeps the configured TCP listener and synthesizes a QUIC companion on
`0.0.0.0:443/UDP`. Eligible route types are copied unchanged: `tls`, `ech`, and
`raw`. On the QUIC companion, `tls` means ordinary H3 termination/re-origination
and `ech` means H3 with upstream ECH. Cleartext `http` is skipped because
H3-to-HTTP/1.1/h2c translation is not implemented. `[http3]` inherits through route, template,
''',
)
replace(
    "README.md",
    '''HTTP/3 can use an automatic `[http3]` companion or an explicit `transport = "quic"` listener. The resulting QUIC listener accepts only `raw`, `h3`, and `h3-ech` routes; both paths use the same dispatcher and H3 implementation.
''',
    '''HTTP/3 can use an automatic `[http3]` companion or an explicit `transport = "quic"` listener. The resulting QUIC listener accepts `raw`, `tls`, and `ech`; both automatic and explicit paths use the same dispatcher and H3 implementation.
''',
)
replace(
    "README.md",
    '''### `h3` and `h3-ech`

These are terminating HTTP/3 routes. sni-gate accepts the inbound QUIC
connection with `h3` ALPN, opens a separate upstream QUIC/H3 connection, and
forwards HTTP/3 **headers, body DATA, trailers, and response semantics**. This is
not a UDP byte splice and currently does not translate H3 into HTTP/1.1 or
HTTP/2.

`h3` uses ordinary upstream QUIC TLS. `h3-ech` uses ECH on the upstream QUIC TLS
ClientHello. The canonical config spelling is `type = "h3-ech"`; the earlier
development spelling `h3ech` remains accepted as a compatibility alias.
''',
    '''### `tls` and `ech` on QUIC

These are terminating HTTP/3 routes when used on `transport = "quic"`.
sni-gate accepts the inbound QUIC connection with `h3` ALPN, opens a separate
upstream QUIC/H3 connection, and forwards HTTP/3 **headers, body DATA, trailers,
and response semantics**. This is not a UDP byte splice and currently does not
translate H3 into HTTP/1.1 or HTTP/2.

`type = "tls"` uses ordinary upstream QUIC TLS. `type = "ech"` uses ECH on the
upstream QUIC TLS ClientHello. No H3-specific route type is needed: the listener's
QUIC transport selects HTTP/3 semantics.
''',
)
replace(
    "README.md",
    '''`idle_timeout` on `h3` / `h3-ech` is measured at the HTTP/3 application layer and is
''',
    '''`idle_timeout` on terminating QUIC `tls` / `ech` routes is measured at the HTTP/3 application layer and is
''',
)
replace(
    "README.md",
    '''| Type | Listener transport | Terminates inbound TLS/QUIC? | Issues cert? | Upstream |
|---|---|---:|---:|---|
| `ech` | TCP | yes | yes | TLS 1.3 + Encrypted Client Hello |
| `tls` | TCP | yes | yes | plain TLS (optional override SNI) |
| `http` | TCP | TLS when present | yes when TLS | cleartext HTTP; optional h2 → h2c |
| `raw` | TCP | no | no | untouched TCP byte stream |
| `raw` | QUIC/UDP | no | no | untouched UDP datagrams after Initial-SNI routing |
| `h3` | QUIC/UDP | yes | yes | HTTP/3 over ordinary QUIC TLS |
| `h3-ech` | QUIC/UDP | yes | yes | HTTP/3 over QUIC TLS + ECH |

`override_sni` works for terminating upstream TLS modes. For `ech` and `h3-ech`
it is the protected inner name; for `tls` and `h3` it is the SNI presented to
the upstream TLS handshake:
''',
    '''| Type | Listener transport | Terminates inbound TLS/QUIC? | Issues cert? | Upstream |
|---|---|---:|---:|---|
| `ech` | TCP / QUIC | yes | yes | TCP: TLS 1.3 + ECH; QUIC: HTTP/3 over QUIC TLS + ECH |
| `tls` | TCP / QUIC | yes | yes | TCP: ordinary TLS; QUIC: HTTP/3 over ordinary QUIC TLS |
| `http` | TCP | TLS when present | yes when TLS | cleartext HTTP; optional h2 → h2c |
| `raw` | TCP / QUIC | no | no | transport-preserving TCP bytes / QUIC UDP datagrams |

`override_sni` works for terminating upstream TLS modes. For `ech` it is the
protected inner name on either transport; for `tls` it is the SNI presented to
the upstream TLS/QUIC handshake:
''',
)

# ---------------------------------------------------------------------------
# Example config: same public type on TCP and QUIC.
# ---------------------------------------------------------------------------
replace(
    "sni-gate.example.toml",
    '''# HTTP/3 companion generation is independent from HTTP/2. Set this true to
# bind UDP automatically beside eligible TCP listeners. Mapping:
# tls -> h3, ech -> h3-ech, raw -> raw; cleartext http is skipped.
''',
    '''# HTTP/3 companion generation is independent from HTTP/2. Set this true to
# bind UDP automatically beside eligible TCP listeners. Public route types are
# preserved: tls/ech become terminating H3/H3+ECH on QUIC, raw stays transparent;
# cleartext http is skipped because H3-to-H1/H2 translation is not implemented.
''',
)
replace(
    "sni-gate.example.toml",
    '''  [[listener.route]]
  name = "h3-direct"
  type = "h3"
''',
    '''  [[listener.route]]
  name = "h3-direct"
  type = "tls"
''',
)
replace(
    "sni-gate.example.toml",
    '''  # Same HTTP/3 semantics, but the upstream QUIC TLS ClientHello uses ECH.
  # Canonical route spelling is "h3-ech"; the old development spelling "h3ech"
  # remains accepted for compatibility. This route inherits [global.ech] here;
  # put a route-specific [listener.route.ech] block below if needed.
  [[listener.route]]
  name = "h3-private-sni"
  type = "h3-ech"
''',
    '''  # Same HTTP/3 semantics, but the upstream QUIC TLS ClientHello uses ECH.
  # The route type remains simply "ech"; transport = "quic" selects H3 semantics.
  # This route inherits [global.ech] here; put a route-specific
  # [listener.route.ech] block below if needed.
  [[listener.route]]
  name = "h3-private-sni"
  type = "ech"
''',
)

# Update the one E2E comment that described implementation mapping as a type rewrite.
replace(
    "tests/http23_auto_e2e.rs",
    '''  # This TCP TLS route is mapped to h3 in the synthetic UDP companion.
''',
    '''  # This TCP TLS route keeps type=tls in the synthetic UDP companion; the
  # QUIC transport normalizes it to the H3 runtime path.
''',
)

# Sanity: public docs/example must not advertise H3-specific type spellings.
for path in ["README.md", "sni-gate.example.toml"]:
    text = Path(path).read_text()
    for forbidden in ['type = "h3"', 'type = "h3-ech"', '`h3-ech`', '`h3` and `h3-ech`']:
        if forbidden in text:
            raise SystemExit(f"{path}: stale public H3 route type spelling remains: {forbidden}")

print("route type simplification applied")
