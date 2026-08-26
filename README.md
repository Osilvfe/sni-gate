# sni-gate

A multi-listener **TCP and QUIC** gateway that routes connections by **SNI
(TLS/QUIC) or Host (HTTP)** to an upstream, and — whenever it terminates TLS —
**issues a certificate for that name on the fly** from a local CA.

TCP routes support **ECH**, plain **TLS**, cleartext **HTTP**, and **raw** byte
passthrough. QUIC/UDP routes support **raw** datagram passthrough, **HTTP/3**, and
**HTTP/3 + ECH** (`h3-ech`). Configuration is hierarchical (route → listener →
global) for maximum flexibility: almost every setting can be pinned per route and
otherwise inherits outward.

It combines three capabilities:
- **Dynamic per-SNI certificate issuance** — no per-site cert maintenance; any
  terminating name gets a valid cert the first time it is requested, from a local
  CA you trust once. Coverage is not guessed: the first handshake is answered
  exactly, and wider coverage is mirrored from the upstream's own certificate.
  Certs are cached and persisted.
- **ECH re-origination** — hide the true SNI from the path to a CDN edge, for both
  TCP TLS (`ech`) and QUIC HTTP/3 (`h3-ech`) upstreams.
- **Shared QUIC dispatch** — one UDP listener can inspect QUIC Initial packets to
  route transparent `raw` flows while also terminating `h3` / `h3-ech` flows on
  that same UDP socket.

## How it works

```text
TCP client ── TLS(SNI)/HTTP ──▶ sni-gate :443/TCP
                                  │
                                  ├─ raw  ─────────────▶ untouched TCP stream
                                  ├─ http ─────────────▶ cleartext HTTP
                                  ├─ tls  ─────────────▶ upstream TLS
                                  └─ ech  ─────────────▶ upstream TLS + ECH

QUIC client ── QUIC Initial ───▶ sni-gate :443/UDP
                                  │ inspect Initial SNI (v1/v2)
                                  ├─ raw ──────────────▶ untouched UDP datagrams
                                  ├─ h3 ───────────────▶ H3 → H3 semantic proxy
                                  └─ h3-ech ───────────▶ H3 → H3 + upstream ECH
```

For TCP, sni-gate peeks without consuming bytes, routes by TLS SNI or HTTP Host,
and either splices the raw stream or terminates/re-originates TLS. For QUIC, the
shared UDP dispatcher decrypts only enough of a QUIC v1/v2 **Initial** to recover
the ClientHello SNI and choose the route. A `raw` QUIC flow then forwards the
buffered and subsequent UDP datagrams unchanged; the upstream remains the actual
QUIC/TLS endpoint. `h3` and `h3-ech` instead terminate inbound QUIC and proxy
HTTP/3 messages semantically.

Routing precedence is `exact` > `wildcard *.x` > `suffix .x` > `regex @name` >
the listener's `default_route`. On TCP, no match and no default route applies the
global `unmatched` policy. QUIC is deliberately fail-closed: unmatched datagrams
are dropped and failed H3/raw routes are closed rather than transparently switched
to another UDP destination.

## Listener address

Each `[[listener]]` must have an `addr` field. Three accepted forms:

| Form | Example | Result |
|---|---|---|
| Full IPv4 socket address | `"0.0.0.0:443"` | bind exactly as written |
| Full IPv6 socket address | `"[::]:443"` | bind exactly as written |
| Bare port (string or integer) | `"443"` or `443` | `0.0.0.0:<port>` |

The bare-port shorthand binds the **IPv4 wildcard only**, matching nginx's
`listen 443` semantics. On a dual-stack host, add a second listener on
`"[::]:443"` to also accept IPv6 connections. Hostnames are not accepted; use a
literal IP address.

Listeners default to `transport = "tcp"`. Set `transport = "quic"` to bind UDP
and enable QUIC routes. TCP and QUIC may deliberately share the same numeric
address because they are different transport namespaces:

```toml
[[listener]]
addr = "0.0.0.0:443"
transport = "tcp"
# ... TCP routes ...

[[listener]]
addr = "0.0.0.0:443"
transport = "quic"
# ... raw / h3 / h3-ech routes ...
```

A duplicate address on the **same** transport is rejected at startup. Thus two
TCP listeners on `0.0.0.0:443` are invalid, as are two QUIC listeners there, but
one of each is valid.

## QUIC / HTTP/3

A QUIC listener accepts only `raw`, `h3`, and `h3-ech` routes.

### Raw QUIC

`type = "raw"` on a QUIC listener is transparent UDP forwarding. sni-gate
inspects the client QUIC v1/v2 Initial to recover SNI, buffers the Initial
packets until the route is known, then sends those packets and subsequent
packets to the selected upstream **without modifying the datagrams**. It does
not terminate QUIC or issue a certificate for the raw flow.

Raw-flow ownership tracks QUIC connection IDs in addition to the client's UDP
address. The dispatcher learns the client's Initial DCID and server SCIDs that are
visible in upstream long headers, so a flow using a **known server CID** can follow
ordinary NAT/source-port rebinding instead of being permanently tied to its first
`(IP, port)` tuple. CID sets are bounded per flow, Initial inspection has separate
flow/memory quotas, and idle flows are reaped.

This is intentionally **not a claim of full QUIC migration or arbitrary CID
rotation support**. A transparent raw proxy cannot decrypt 1-RTT
`NEW_CONNECTION_ID` frames, so it cannot learn every future server CID. Zero-length
CIDs also provide no CID token to route on. A raw-only listener may use the unique
peer tuple as a limited fallback for short-header traffic; a mixed raw + H3 listener
deliberately disables that fallback for unknown packets so H3 traffic cannot be
captured by a raw flow.

### `h3` and `h3-ech`

These are terminating HTTP/3 routes. sni-gate accepts the inbound QUIC
connection with `h3` ALPN, opens a separate upstream QUIC/H3 connection, and
forwards HTTP/3 **headers, body DATA, trailers, and response semantics**. This is
not a UDP byte splice and currently does not translate H3 into HTTP/1.1 or
HTTP/2.

`h3` uses ordinary upstream QUIC TLS. `h3-ech` uses ECH on the upstream QUIC TLS
ClientHello. The canonical config spelling is `type = "h3-ech"`; the earlier
development spelling `h3ech` remains accepted as a compatibility alias.

HTTP/3 connection coalescing cannot bypass routing: every inbound request's
`:authority` is checked against the listener router again. Crossing to a different
route always yields **421 Misdirected Request**. The same-route case is also rejected
when the new authority would change the already-established upstream identity — for
example when the route reflects its dial host or its upstream SNI/verification name.
Same-route coalescing across authorities is allowed only when both the dial target
and upstream TLS identity are fixed and therefore remain the same connection target.

`idle_timeout` on `h3` / `h3-ech` is measured at the HTTP/3 application layer and is
refreshed by request/response headers, DATA, and trailers. QUIC ACKs or transport
keepalives alone do not keep an otherwise idle proxied request alive.

A complete QUIC example is included in
[`sni-gate.example.toml`](sni-gate.example.toml).

## Route types

| Type | Listener transport | Terminates inbound TLS/QUIC? | Issues cert? | Upstream |
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

| `override_sni`  | SNI sent upstream                        |
|-----------------|------------------------------------------|
| *(omitted)*     | the inbound SNI verbatim                 |
| `"name"`        | exactly `name`                           |
| `""`            | **none** — no `server_name` extension    |

The empty string is deliberately distinct from omitting the field: it suppresses
the extension entirely. That is useful for an upstream addressed by IP or one
that keys only off the certificate it serves, and for ECH, where [RFC 9849 §5]
explicitly allows a ClientHelloInner to carry no SNI. With ECH the ECHConfig's
public name is still sent in the *outer* hello; only the protected inner hello
omits its `server_name`.

Suppressing SNI changes what is **transmitted**, not what is **trusted**: the
upstream certificate is still verified against the name the route would
otherwise have sent. An ECH route with `override_sni = ""` on a connection that
carries no usable reflected name therefore has no inner name to verify against
and is closed.

Because resolution keys on *presence*, a route can blank out a name inherited
from its template with `override_sni = ""`.

[RFC 9849 §5]: https://www.rfc-editor.org/rfc/rfc9849.html#section-5

## Named regular expressions

Regular expressions in `match_sni` must be declared as `[regexes.<name>]` entries
and referenced with an `@` prefix. Each regex carries a `scope_suffix` declaration
that lets mirrored wildcards coexist safely with regex routes.

```toml
[regexes.cdn-upos]
pattern = "^upos-[a-z0-9-]+\\.akamaized\\.net$"
scope_suffix = ["*.akamaized.net"]

[[listener.route]]
match_sni = ["@cdn-upos", ".google.com"]
upstream = "cdn.example.com"
type = "tls"
```

### Why scope_suffix is required

When deciding whether to issue a wildcard certificate like `*.example.com`, the
router must verify that all hosts it would cover route to the same destination.
For exact/wildcard/suffix patterns, this is statically decidable. For regex
patterns, it is not—the program cannot determine which hosts a regex will match.

`scope_suffix` is the operator's declaration: "this regex may match hosts under
these domain suffixes." The router uses this to check for overlaps. If a wildcard
`*.example.com` is requested for route A, and a regex in route B declares
`scope_suffix = ["*.example.com"]`, the wildcard is refused to prevent incorrect
HTTP/2 connection coalescing.

### Syntax

`scope_suffix` uses the same pattern grammar as route matching:

- `"*.domain.com"` — matches only direct subdomains of `domain.com` (one label above it)
- `".domain.com"` — matches `domain.com` itself plus all subdomains at any depth
- `"domain.com"` — matches only the apex domain exactly

A regex may declare multiple suffixes:
```toml
scope_suffix = ["*.cdn1.example.com", "*.cdn2.example.com"]
```

**The operator is responsible for ensuring the pattern does not match hosts outside
the declared scope.** An under-declared scope may allow wildcard certificates that
should be refused, leading to incorrect routing via HTTP/2 connection coalescing.

## Upstream address

`upstream` names the target to dial. Either part may be defaulted:

| `upstream`          | dial host                       | dial port            |
|---------------------|---------------------------------|----------------------|
| `"host:port"`       | fixed host (IPv6 in `[...]`)    | fixed port           |
| `"host"`            | fixed host                      | this listener's port |
| `"8443"`            | matched source SNI/Host         | `8443`               |
| *(omitted)*         | matched source SNI/Host         | this listener's port |

When the host is defaulted it is the **matched source SNI/Host** — the routing
key the connection matched on (the inbound SNI or Host, with any `:port`
stripped), resolved per connection. This "reflects" each connection back to its
own name, so a listener can forward every matched name to that same name
upstream without a per-route host. `override_sni` does **not** change the dial
target; it only sets the upstream TLS server name for terminating TLS/QUIC
routes. A connection routed to a reflecting route that carries no SNI/Host is
closed because there is nothing to reflect.

## Certificate coverage

How much a certificate covers is **not configurable**. Guessing it is what breaks
HTTP/2: a certificate broader than the upstream's own authorizes the browser to
coalesce requests the upstream will answer with `403`. Coverage is therefore
**mirrored from the upstream's real certificate**, never proposed by this gateway.

**Exact first.** The first connection for a host whose upstream has never been
observed is answered with a certificate for that one name — no wildcard. Nothing
can coalesce onto it, so no request can arrive that the upstream has not vouched
for.

**Then mirror what the upstream presented.** When a TLS-terminating route hands
the connection to a TLS/ECH upstream, the upstream's leaf is read as part of the
handshake that was happening anyway — no extra probe, no blocking — and its DNS
SANs become this gateway's coverage for that host. The same observation mechanism
is shared by TCP TLS and QUIC/H3 upstream TLS. If `cf.example.net` answers a
handshake for `qy0.ru` with `{qy0.ru, mzz.qy0.ru}`, that is exactly what the
client is served, so `t4.qy0.ru` cannot coalesce onto it. If the same upstream
answers a handshake for `t4.qy0.ru` with `{qy0.ru, *.qy0.ru}`, that connection
does carry the wildcard — coalescing is preserved precisely where the upstream
accepts it.

Observed SANs are keyed by the **requested** name, so a set learned for
`t4.qy0.ru` is never served to a client asking for `qy0.ru`.

**Rotation is handled by comparing every handshake.** The raw observed set is
stored alongside the certificate. When a later handshake presents a different set
— including a *narrower* one, which is the case that reintroduces `403` if ignored
— the cached leaf is invalidated and re-signed against the new set.

**Clipping.** A mirrored name is dropped when the upstream vouches for it but this
listener would route it elsewhere (see [Certificate
scopes](#certificate-scopes)), or when it is a wildcard directly above a public
suffix (`*.com`, `*.co.uk`) — no real upstream needs one, and honoring it would
hand out a certificate for an entire registry. The public-suffix list's **ICANN
section only** decides that: `co.uk` and `co.jp` are boundaries, while
private-section entries (`github.io`, `withgoogle.com`) are ordinary domains, so a
genuine `*.withgoogle.com` from an upstream is mirrored. Dropped names are logged
with the reason. If clipping removes everything, the exact name is served.

Certificates are persisted per `(scope, host)` as `certs/<scope>/<host>.crt`
together with the observed set that produced them, so a restart resumes mirroring
instead of re-learning it. There is nothing to migrate and no mode to switch: a
leaf that does not match what the upstream currently presents is simply re-issued.

## Certificate scopes

A browser may reuse ("coalesce") an existing HTTP/2 connection for a **second**
origin when both of these hold ([RFC 9113 §9.1.1]):

1. the second origin resolves to an address already in that connection's set, and
2. the certificate on that connection is valid for the second origin.

A coalesced HTTP/2 request travels on the **existing** TCP connection: no new TCP,
no new TLS handshake, and therefore **no new SNI**. A byte-splicing TCP route
cannot re-route it after the handshake, so certificate scope is the safety
boundary there.

HTTP/3 can coalesce origins too, but `h3`/`h3-ech` are semantic rather than byte
splices. They therefore have an additional guard: every request's `:authority` is
routed again and a request crossing the handshake route boundary gets **421
Misdirected Request** before it reaches the existing upstream H3 connection.
Certificate clipping still applies because it limits what coalescing the client
may attempt in the first place.

Every name pointed at this gateway shares its address, so the certificate remains
a critical part of the boundary. The invariant is:

> A certificate served on a connection routed to some destination is never valid
> for a name this listener would route to a **different** destination.

Two mechanisms hold it, and both are load-bearing:

- **Clipping.** Each proposed name is checked against this listener's routing
  table and dropped unless *every* host it would cover routes into the same scope.
  A wildcard is refused when a sibling is pinned elsewhere, when subdomains fall
  through to a `default_route` in another scope, when they would match no route at
  all, or when a regex route in another scope declares a `scope_suffix` that
  overlaps with the wildcard. The requesting host itself is always covered, so a
  clipped certificate is still usable.
- **Partitioning.** The certificate cache and the on-disk store are keyed by
  scope. Clipping alone would not survive accumulation: a later host under the
  same anchor but a different destination would otherwise be merged into the
  existing certificate, re-widening it after the fact.

A **scope** is a set of names that may share a certificate. Two routes share one
when they forward identically *and* are matched by the same routing table:

- **Forwarding target** — route type, dial host (or the reflecting marker), port,
  `override_sni` policy, `address_family`, `nat64_prefix`, `addr_resolver`, and
  the ECH config source. Everything that decides where a connection goes and under
  what name it is presented. Settings that cannot change the destination
  (timeouts, `fail`, the HTTP/2 switch, `ech_refresh`) are excluded: they would
  fragment scopes without buying safety.
- **Routing table** — a fingerprint of the listener's routes. A wildcard proven
  confined under one listener's routes may not be confined under another's, so a
  proof is only ever reused where it still holds. Listeners with identical route
  tables (the usual `0.0.0.0:443` + `[::]:443` pair) therefore still share
  certificates.

Certificates are persisted as `certs/<scope>/<registrable>.crt` (plus `.key`).
The scope directory is what stops two destinations from overwriting each other's
file — without it, a reload would serve one certificate to both routes and
re-widen coverage.

Names **within** one scope may share a mirrored wildcard, so a client can still
coalesce between them. That is deliberate: the upstream's own certificate already
permits it, and the request reaches the same configured destination, which
demultiplexes on `:authority` as any origin does. Nothing needs to be turned off
to stay safe — a host whose upstream has not been observed is served an exact
certificate, and an upstream that never presents a wildcard never yields one.

Every mirroring decision is logged at `INFO`, including each name clipping
dropped:

```
mirrored upstream certificate coverage (clipped to this route scope)
  scope=ech_cf.0sm.com_443-1f3a9c07b2d45e18 host=t4.example.com
  sans=["t4.example.com", "example.com"] dropped=["*.example.com"]
```

That is a report, not a failure — routing is unaffected. It means the routing
table sends two names under one registrable domain to different upstreams. To
widen coverage, give the conflicting hosts the same upstream or move them under a
different registrable domain.

**One case this cannot reach:** a `raw` route never terminates TLS/QUIC, so the
client sees the **upstream's own** certificate and sni-gate cannot narrow it. If
that certificate covers a name routed elsewhere on the same listener, a client
may coalesce onto the raw connection and escape routing. sni-gate detects this
shape for TCP raw overlap and warns at startup; transparent raw traffic itself
cannot be repaired by certificate issuance because no local certificate is
served. Give such routes distinct certificate/routing boundaries, or use a
terminating type.

[RFC 9113 §9.1.1]: https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1

## Hierarchical configuration

Overridable settings resolve from the most specific scope outward, with each
scope's optional template sitting just below that scope's own explicit values:

```
route (explicit)  →  route's template  →  listener (explicit)  →
listener's template  →  global
```

An unset value at a deeper scope inherits the next one out. This applies to
`resolver` / `ech_resolver` / `addr_resolver`, `nat64_prefix`, `address_family`,
`ech_refresh`, `require_ech`, `connect_timeout`, `idle_timeout`, and the fail
policy. So you can set, say, a different `addr_resolver` or `nat64_prefix` on a
single route while everything else inherits the global value.

`system-outbound` and fixed-address `passthrough` failure fallback are currently
**TCP-only**. QUIC listeners always fail closed on unmatched traffic or route
failure. If a QUIC route inherits or explicitly resolves to a non-`close` fail
policy, startup logs a warning so the unsupported policy is never silently ignored;
mixed TCP+QUIC configurations remain valid and the TCP listener still honors it.

The **`[http2]` block** inherits field-by-field along this same ladder, so
`enabled` / `probe` / `probe_timeout` each resolve independently — see
[HTTP/2](#http2).

The entire **`[ech]` block inherits field-by-field along the same ladder**:
`mode`, `config`, `ech_domain`, `max_retries` (and `require_ech` / `ech_refresh`
/ `ech_resolver`) each resolve independently. Put the shared parts in
`[global.ech]` (or `[listener.ech]`) once and let each ECH route override only
what differs — a route may even omit `[ech]` entirely and inherit the whole thing.

## Templates

A `[templates.<name>]` table is a reusable bundle of settings referenced by a
single `use = "<name>"` on a `route`, `default_route`, or `listener`:

```toml
[templates.ech-edge]
type = "ech"
  [templates.ech-edge.ech]
  mode = "doh"
  ech_domain = "ech.example"

[[listener]]
addr = "0.0.0.0:443"
  [[listener.route]]
  match_sni = [".site-b.example", ".site-c.example"]
  use = "ech-edge"
  address_family = "ipv4"
  nat64_prefix = "64:ff9b::"
```

A template may carry every reusable field — `type`, `upstream`, `override_sni`,
the pinned `cert_file`/`key_file`, a whole `[ech]` block, `fail`, and all the
overridable knobs — but not the route *identity* (`name`, `match_sni`). It sits
in the ladder just below its scope's explicit values (see above), so a route's
own setting always wins over its template. Each scope references at most one
template, and templates cannot reference other templates (no nesting). An
unknown template name is a load-time error. `upstream` in a template only
applies when the template is used by a *route* (listeners have no upstream).

## DNS resolvers

### Quick reference: Inline resolver specs

A resolver spec may appear at any scope and takes one of these forms:

| Form                              | Meaning                         |
|-----------------------------------|---------------------------------|
| `system`                          | the OS resolver                 |
| `https://host[:port]/dns-query`   | DoH                             |
| `tls://host[:port]`               | DoT                             |
| `udp://host[:port]` or `tcp://host[:port]` | plain DNS with hostname (requires bootstrap) |
| `ip[:port]` (bare IP)             | plain DNS to an IP              |

`resolver` is the generic default. `ech_resolver` overrides it for ECH
HTTPS-record lookups; `addr_resolver` overrides it for upstream A/AAAA. Each is
independently overridable per scope.

### Named resolvers: `[resolvers.<name>]`

**Named resolvers** let you declare DNS resolvers as first-class configuration
entities with full transport control, including bootstrap chains, upstream
overrides, and ECH-on-ECH protection. Reference them by name anywhere a resolver
spec is accepted.

#### Why named resolvers?

1. **Bootstrap chains** — When the resolver endpoint itself is blocked or
   requires circumvention, resolve its hostname through a different resolver:
   ```toml
   [resolvers.bootstrap]
   endpoint = "1.1.1.1"
   
   [resolvers.primary]
   endpoint = "https://dns.blocked.example/dns-query"
   bootstrap = "@bootstrap"  # Resolve dns.blocked.example via bootstrap
   ```

2. **Upstream override (CDN fronting)** — Dial a CDN edge while presenting the
   real resolver's TLS server name:
   ```toml
   [resolvers.fronted]
   endpoint = "https://dns.blocked.example/dns-query"
   upstream = "cdn-edge.cloudfront.net"
   # Dials cdn-edge.cloudfront.net, but TLS SNI remains dns.blocked.example
   ```

3. **ECH-on-ECH** — Protect the resolver's own TLS handshake with Encrypted
   Client Hello:
   ```toml
   [resolvers.secure]
   endpoint = "https://doh.example/dns-query"
   bootstrap = "@bootstrap"
     [resolvers.secure.ech]
     mode = "doh"
     require_ech = true
   ```

#### Configuration reference

```toml
[resolvers.<name>]
endpoint = "..."           # Required: transport spec (see formats below)
upstream = "..."           # Optional: override dial target (host, port, or both)
override_sni = "..."       # Optional: TLS server name (omit=reflect, "name"=fixed, ""=suppress)
bootstrap = "..."          # Optional: @resolver-name or inline spec for endpoint resolution
address_family = "..."     # Optional: dual/ipv4/ipv6 (inherits from [global])
nat64_prefix = "..."       # Optional: e.g. "64:ff9b::/96" (inherits from [global])
connect_timeout = "..."    # Optional: per-query timeout (inherits from [global])

[resolvers.<name>.ech]     # Optional: ECH for this resolver's handshake
mode = "doh"               # or "static", "doh-with-fallback"
config = "<base64>"        # Required for static/fallback modes
ech_domain = "..."         # Override HTTPS lookup name
require_ech = true         # Fail rather than GREASE (default: true)
max_retries = 2            # ECH rejection retry budget
ech_refresh = "1h"         # Proactive rotation interval
ech_resolver = "..."       # @resolver-name or inline spec for ECH config fetch
```

#### Endpoint formats

- `system` or `""` — OS resolver (default bootstrap)
- `https://host[:port][/path]` — DNS-over-HTTPS (default port 443, path `/dns-query`)
- `tls://host[:port]` — DNS-over-TLS (default port 853)
- `udp://hostname:port` or `tcp://hostname:port` — Plain DNS with hostname (resolved via bootstrap)
- `ip[:port]` — Plain DNS to literal IP address (default port 53, no bootstrap needed)

**Note:** Bare words (without prefix) must be IP addresses to avoid collision with
resolver references. Use `udp://` or `tcp://` prefix to specify a hostname.

#### Using named resolvers

Reference by name with `@` prefix anywhere a resolver spec is accepted:

```toml
[global]
resolver = "@my-doh"          # Default for everything
addr_resolver = "@fast"       # Override for A/AAAA lookups
ech_resolver = "@secure"      # Override for HTTPS/ECH lookups

[resolvers.my-doh]
endpoint = "https://1.1.1.1/dns-query"

[resolvers.fast]
endpoint = "1.1.1.1"
address_family = "ipv4"

[resolvers.secure]
endpoint = "https://dns.google/dns-query"
```

**Fallback order:**
- `addr_resolver` → `resolver` → system
- `ech_resolver` → `addr_resolver` → `resolver` → system

#### Inheritance rules

| Setting | Inherits from `[global]` | Notes |
|---------|--------------------------|-------|
| `address_family` | ✅ Yes | IP version preference |
| `nat64_prefix` | ✅ Yes | IPv6 synthesis |
| `connect_timeout` | ✅ Yes | Per-query timeout |
| `[ech]` fields | ✅ Yes (field-by-field) | Only if `[ech]` block declared |
| `[ech]` presence | ❌ No | Must opt-in explicitly |
| `bootstrap` | ❌ No | Dependency edge, never inherited |
| `ech_resolver` | ❌ No | Dependency edge, never inherited |

**Dependency edges** (`bootstrap`, `ech_resolver`) are never inherited to prevent
implicit cycles. The `[ech]` block itself must be explicitly declared, but its
fields then inherit from `[global.ech]` field-by-field.

#### Validation

Named resolvers are validated at load time:

- **Cycle detection**: `a → b → a` dependency cycles are rejected
- **Unknown references**: `bootstrap = "@typo"` when no such resolver exists
- **Self-bootstrap**: `bootstrap = "@self"` is rejected

#### Advanced example: Multi-layer bootstrap chain

```toml
[global]
resolver = "@layer-3"

# Layer 1: IP-addressed, no dependencies
[resolvers.layer-1]
endpoint = "1.1.1.1"

# Layer 2: First DoH hop
[resolvers.layer-2]
endpoint = "https://doh-a.example/dns-query"
bootstrap = "@layer-1"

# Layer 3: Final resolver with ECH
[resolvers.layer-3]
endpoint = "https://doh-b.example/dns-query"
bootstrap = "@layer-2"
  [resolvers.layer-3.ech]
  mode = "doh"
  require_ech = true
  ech_resolver = "@layer-2"  # layer-2 fetches layer-3's ECH config
```

#### ECH rotation mechanism

Named resolvers with ECH support automatic key rotation:

**Reactive (on rejection):**
1. Query fails with ECH rejection error
2. Resolver detects the error pattern
3. Re-resolves dial address through bootstrap
4. Fetches fresh ECHConfigList via `ech_resolver`
5. Builds new resolver with new config
6. Atomically swaps the resolver
7. Retries the query (up to `max_retries`)

**Proactive (on timer):**
1. Timer fires every `ech_refresh` interval
2. Re-runs full build plan
3. Byte-compares new ECHConfigList against current
4. If unchanged: no-op (keeps existing resolver)
5. If changed: atomic swap to new resolver

Concurrent rebuilds are idempotent via generation counters.

## Upstream address family & NAT64

- `address_family = "dual"` (default) prefers AAAA and falls back to A;
  `"ipv4"` uses A only; `"ipv6"` uses AAAA only.
- `nat64_prefix` (a /96 prefix such as `64:ff9b::` or `2a01:4f8:c2c:123f:64:5`)
  synthesizes an IPv6 target from a resolved IPv4 (RFC 6052). NAT64 is applied
  in `dual`/`ipv4` when only an A record is available; it is **disabled** in
  `ipv6` mode. You can also write a literal IPv6 upstream in bracket form,
  e.g. `upstream = "[2a01:4f8:c2c:123f:64:5:203:405]:443"`.

## ECH

For `type = "ech"` and `type = "h3-ech"` routes, the ECHConfigList is sourced by
an `[ech]` block. Its fields inherit field-by-field from `[listener.ech]` and
`[global.ech]` (and any template), so shared settings need to be written only
once; a route's `[ech]` overrides only what differs, and may be omitted entirely
when the enclosing scopes already provide a complete config:
- `mode = "static"` — a fixed inline base64 `config`.
- `mode = "doh"` — looked up in the HTTPS record of `ech_domain` (or the inner
  name) via the ECH resolver; refreshed on `ech_refresh` / the record TTL.
- `mode = "doh-with-fallback"` — DoH, falling back to the inline `config`.

An omitted `mode` inherits (it is *not* silently `doh`); `static` and
`doh-with-fallback` require a `config` to be resolvable from some scope, checked
at load time. The upstream certificate is verified against the **inner (true)
name** using the web-PKI roots. `require_ech` (default true) fails closed unless
ECH is negotiated. **ECH retry**: if the server rejects ECH (its key rotated),
the cached config is invalidated, a fresh one is fetched, and the handshake is
retried up to `max_retries` times before the fail policy applies.

## HTTP/2

HTTP/2 is opt-in per route via an inheriting `[http2]` block:

```toml
[global.http2]
enabled = false        # opt-in
probe = "warn"         # off | warn | require   (http routes only)
probe_timeout = "3s"

[[listener.route]]
type = "http"
match_sni = [".web.example"]
upstream = "127.0.0.1:8080"
  [listener.route.http2]
  enabled = true
```

**Inbound and upstream always speak the same protocol.** sni-gate splices bytes
rather than parsing HTTP on these TCP routes, so it cannot translate between
framings: there is no "HTTP/2 in, HTTP/1.1 out" mode. `enabled` is a single
coupled switch. (HTTP/3 is handled separately by the semantic H3 proxy described
above.) In exchange, the TCP data path stays a transparent byte pump, so
WebSockets and other upgrades keep working.

How the protocol is chosen depends on whether the upstream speaks ALPN:

- **`tls` / `ech` — ALPN mirroring.** The upstream is dialed *first*, offering
  the intersection of what the client offered and what sni-gate can carry
  (`h2`, `http/1.1`). Whatever the upstream selects is then advertised verbatim
  on the inbound handshake. A mismatch is structurally impossible, and an
  upstream that only does HTTP/1.1 transparently downgrades that connection —
  decided per connection against the live upstream, never from a cached guess.
  Note this dials the upstream slightly earlier in the connection's life than a
  non-HTTP/2 route does.
- **`http` — the client decides.** The upstream is cleartext and has no ALPN to
  mirror, so `[h2, http/1.1]` is offered inbound (h2 preferred). If the client
  picks h2, the decrypted bytes are spliced to the backend as **prior-knowledge
  h2c** (RFC 9113 §3.4), which is byte-identical to h2 over TLS. The backend must
  therefore be configured for h2c.
- **TCP `raw`** never terminates TLS, so there is no ALPN to negotiate. Enabling
  `http2` on a `raw` route is a load-time error; a value merely *inherited* from
  a broader scope is ignored, so a global `enabled = true` coexists fine with
  `raw` routes.

### The h2c probe

Because nothing in the `http` data path can discover that a backend only speaks
HTTP/1.1, that one case is checked at startup: sni-gate opens a connection,
sends the HTTP/2 preface, and expects a `SETTINGS` frame back.

The probe **validates; it never decides.** No mode silently downgrades a route to
HTTP/1.1 — a probe result goes stale the moment the backend is reconfigured (an
`nginx reload` that drops `http2 on` would leave a cached verdict quietly wrong),
and a silent downgrade would hide exactly the misconfiguration this exists to
surface.

| `probe`   | On failure                                                        |
|-----------|-------------------------------------------------------------------|
| `off`     | no probe                                                          |
| `warn`    | log loudly, keep HTTP/2 enabled as configured *(default)*         |
| `require` | fail startup                                                      |

`warn` is the default so that a backend which merely has not started yet cannot
stop the gateway from booting. Backends are deduplicated, probed concurrently,
and each is bounded by `probe_timeout`. Routes that reflect the source SNI/Host
have no fixed upstream at startup and are skipped.

Cleartext (non-TLS) inbound connections cannot use HTTP/2: a prior-knowledge h2c
request carries its `:authority` in HPACK-compressed HEADERS, which cannot be
read without decoder state, so there is no routing key. Such connections carry no
key and fall through to `default_route`.

## Download

Each release publishes prebuilt binaries for the major platforms. Linux and
Windows come in two flavors:

- **static** (`*-linux-static`, `*-windows-static.exe`) — no runtime
  dependencies; runs on any Linux (musl) or Windows without the VC++
  redistributable. Best for portability and containers.
- **dynamic** (`*-linux`, `*-windows.exe`) — smaller; links the platform's
  libc / CRT.

macOS ships a single (dynamic) binary per architecture, as libSystem cannot be
linked statically on that platform. `SHA256SUMS` accompanies every release.

## Build

Requires a stable Rust toolchain and (on Windows) NASM + a C toolchain for the
aws-lc-rs dependency, which provides the HPKE suites ECH needs.

```sh
cargo build --release
# or, reproducible & privacy-hardened (strips symbols, remaps build paths):
./build-release.sh

# Fully static Linux build (no glibc dependency):
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# Fully static Windows CRT (like C's /MT):
RUSTFLAGS="-Ctarget-feature=+crt-static" cargo build --release
```

## Configure and run

```sh
cp sni-gate.example.toml sni-gate.toml
# edit sni-gate.toml
sni-gate.exe               # loads ./sni-gate.toml
sni-gate.exe -c <path>     # or an explicit path
```

See [`sni-gate.example.toml`](sni-gate.example.toml) for every option, including
TCP and QUIC listeners that share port 443.

## Trusting the CA

The CA is generated on first run at the `[ca]` paths. Import the **certificate**
(never the key) into each device that should trust issued certs:

```sh
# this machine; generates the CA first if needed
# Windows: needs Administrator
# macOS/Linux: needs root/sudo
sni-gate.exe --install-ca          # Windows
sudo ./sni-gate --install-ca       # macOS/Linux
```

**Windows** writes to the Local Machine Trusted Root Certification Authorities
store through CryptoAPI in-process — no PowerShell, no `certutil`, no temp
file. **macOS** uses the standard `security add-trusted-cert` tool.
**Linux** detects your distribution (Debian/Ubuntu/RHEL/Fedora/Arch) and uses
the appropriate certificate-management command (`update-ca-certificates`,
`update-ca-trust`, or `trust extract-compat`).

Installation is idempotent across all platforms: if a certificate with the same
fingerprint is already trusted, the store is left untouched. Restart the
browser afterwards to pick up the change.

Setting `ca.install_to_system_root = true` does the same thing on every startup
instead, and only warns if the store cannot be reached, so the gateway still
serves traffic. For other devices, distribute `ca/ca.crt` and import it into
their trusted-root store.

## Security notes

- `ca/ca.key` is a trusted-root private key. Keep it local; it is gitignored.
- Terminating TLS/QUIC means sni-gate sees plaintext for terminating route types.
- A QUIC `raw` route does not terminate the upstream QUIC/TLS connection; its
  datagrams and upstream certificate remain end-to-end with the origin.
- Binding to 443/80 requires elevated privileges: Administrator on Windows,
  root/sudo on macOS/Linux.

## Logging

`SNI_GATE_LOG` / `RUST_LOG` override the config `log` directive:

```sh
SNI_GATE_LOG=debug sni-gate.exe
```

## License

Dual-licensed under MIT or Apache-2.0.
