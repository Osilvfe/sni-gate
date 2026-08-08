# sni-gate

A multi-listener TLS gateway that routes each connection by **SNI (TLS) or Host
(HTTP)** to an upstream, and — whenever it terminates TLS — **issues a
certificate for that name and its wildcard on the fly** from a local CA.

Upstreams can be reached four ways: **ECH** (TLS 1.3 Encrypted Client Hello),
plain **TLS**, cleartext **HTTP**, or **raw** TCP passthrough. Configuration is
hierarchical (route → listener → global) for maximum flexibility: almost every
setting can be pinned per route and otherwise inherits outward.

It merges two capabilities:
- **Dynamic per-SNI certificate issuance** — no per-site cert maintenance;
  any subdomain gets a valid (wildcard) cert the first time it is requested,
  from a local CA you trust once. Wildcards are public-suffix-aware; certs are
  persisted and cached.
- **ECH re-origination** — hide the true SNI from the path to a CDN edge, giving
  ECH to clients/environments that can't do it themselves.

## How it works

```
                         issue per-SNI cert (wildcard, cached, persisted)
                         ┌───────────────────────────────────────┐
                         │                                        ▼
 client ──TLS(SNI)/HTTP──▶ sni-gate :443 ── route by SNI/Host ──▶ upstream
                              peek (no consume)                    · ech  → TLS1.3 + ECH
                              exact>wildcard>suffix>regex          · tls  → plain TLS
                                                                   · http → cleartext
                                                                   · raw  → bare TCP (no termination)
```

1. **Peek** the connection without consuming bytes to learn the routing key
   (TLS SNI, or the HTTP `Host` header).
2. **Route** it: `exact` > `wildcard *.x` > `suffix .x` > `regex ~…` > the
   listener's `default_route`.
3. For any type except `raw`, **terminate inbound TLS**, issuing a certificate
   for the SNI (and its wildcard) from the local CA, then **re-originate** to the
   upstream per the route type. `raw` splices the untouched TCP stream through.
4. No route and no `default_route` → apply the global `unmatched` policy.

## Listener address

Each `[[listener]]` must have an `addr` field. Three accepted forms:

| Form | Example | Result |
|---|---|---|
| Full IPv4 socket address | `"0.0.0.0:443"` | bind exactly as written |
| Full IPv6 socket address | `"[::]:443"` | bind exactly as written |
| Bare port (string or integer) | `"443"` or `443` | `0.0.0.0:<port>` |

The bare-port shorthand binds the **IPv4 wildcard only**, matching nginx's
`listen 443` semantics. On a dual-stack host, add a second listener on
`"[::]:443"` to also accept IPv6 connections. Hostnames are not accepted;
use a literal IP address.

`"443"` and `"0.0.0.0:443"` normalize to the same address, so writing both
in the same config is caught as a duplicate-listener error at startup.

## Route types

| Type   | Terminates inbound TLS? | Issues cert? | Upstream                         | HTTP/2                    |
|--------|-------------------------|--------------|----------------------------------|---------------------------|
| `ech`  | yes                     | yes          | TLS 1.3 + Encrypted Client Hello | mirrors upstream ALPN     |
| `tls`  | yes                     | yes          | plain TLS (optional override SNI)| mirrors upstream ALPN     |
| `http` | (cleartext in)          | yes (if TLS) | cleartext HTTP                   | h2 in → h2c out           |
| `raw`  | no                      | no           | bare TCP byte-pump               | n/a (never terminates)    |

`override_sni` works for **all** terminating types. For `ech` it is the inner
(protected) name; for `tls` it is the SNI presented to the upstream:

| `override_sni`  | SNI sent upstream                        |
|-----------------|------------------------------------------|
| *(omitted)*     | the inbound SNI verbatim                 |
| `"name"`        | exactly `name`                           |
| `""`            | **none** — no `server_name` extension    |

The empty string is deliberately distinct from omitting the field: it suppresses
the extension entirely. That is useful for an upstream addressed by IP or one
that keys only off the certificate it serves, and for ECH, where [RFC 9849 §5]
explicitly allows a ClientHelloInner to carry no SNI. With ECH the ECHConfig's
public name is still sent in the *outer* hello (the client-facing server needs
it); only the protected inner hello omits its `server_name`.

Suppressing SNI changes what is **transmitted**, not what is **trusted**: the
upstream certificate is still verified against the name the route would otherwise
have sent (the fixed name, or the reflected inbound one). An `ech` route with
`override_sni = ""` on a connection that carries no SNI/Host therefore has no
inner name to verify against and is closed.

Because resolution keys on *presence*, a route can blank out a name inherited
from its template with `override_sni = ""`.

[RFC 9849 §5]: https://www.rfc-editor.org/rfc/rfc9849.html#section-5

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
target; it only sets the upstream TLS server name for `tls`/`ech`. A connection
routed to a reflecting route that carries no SNI/Host is closed (there is
nothing to reflect).

## Certificate issuance modes

Every per-SNI leaf is anchored at the **registrable domain**, so one
`certs/<registrable>.crt` serves a whole domain and `[issuance] mode` chooses how
much of it a request contributes. For an inbound SNI of `b.a.example.com`
(registrable `example.com`):

| `mode`     | key (`certs/<key>.crt`) | names this host contributes                          |
|------------|-------------------------|------------------------------------------------------|
| `exact`    | `example.com`           | `b.a.example.com`                                     |
| `wildcard` | `example.com`           | `*.a.example.com`                                     |
| `ladder`   | `example.com`           | `*.a.example.com`, `*.example.com`, `example.com`     |

The only wildcard that usefully covers a host `H` is `*.parent(H)` — `*.H` would
cover subdomains a leaf host usually never has. So a level's `*.X` wildcard is
emitted **only when some accessed host actually has `X` as its parent**: a CDN
leaf like `rr5.googlevideo.com` never yields the useless `*.rr5.googlevideo.com`.
`wildcard` contributes just the parent wildcard (host + siblings); `ladder`
contributes the whole ancestor chain (host, every ancestor domain, and their
siblings). `exact` contributes only the bare host.

**One certificate per registrable domain, accumulating, never re-signed for a
name it already covers.** Before signing, the resolver checks whether the anchor's
cached/persisted certificate already covers the host; if so it is reused. If not,
the host's names are **merged** into it and it is re-issued — so siblings
(`c.a.example.com`, `www.example.com`, …) and even deeper new branches all fold
into the one `example.com.crt` rather than each minting a redundant leaf. All
modes share one `certs/` directory and switching modes is seamless (a certificate
that does not cover the host is just re-issued). Leaves stay small — bounded by
the distinct sub-hierarchies actually seen.

The registrable domain is computed from the public-suffix list's **ICANN section
only**. Real registry suffixes (`co.uk`, `co.jp`) remain boundaries, so `*.co.jp`
is never issued; private-section entries (`github.io`, `withgoogle.com`) are
treated as ordinary registrable domains, so `csp.withgoogle.com` is served by
`withgoogle.com.crt` (`{*.withgoogle.com, withgoogle.com}`). IP literals and hosts
with no registrable domain always fall back to `exact`. The wildcard is never
lifted above the registrable domain, so `*.com` can never be produced.

```toml
[issuance]
mode = "wildcard"   # exact | wildcard | ladder
```

The legacy boolean `wildcard = true|false` is still accepted (`true` → `wildcard`,
`false` → `exact`) and is ignored when `mode` is set.

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
   bootstrap = "bootstrap"  # Resolve dns.blocked.example via bootstrap
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
   bootstrap = "bootstrap"
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
bootstrap = "..."          # Optional: resolver name or inline spec for endpoint resolution
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
ech_resolver = "..."       # Who fetches this resolver's ECH config
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

Reference by name anywhere a resolver spec is accepted:

```toml
[global]
resolver = "my-doh"          # Default for everything
addr_resolver = "fast"       # Override for A/AAAA lookups
ech_resolver = "secure"      # Override for HTTPS/ECH lookups

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
- **Unknown references**: `bootstrap = "typo"` when no such resolver exists
- **Self-bootstrap**: `bootstrap = "self"` is rejected
- **Name collision**: Resolver names cannot look like inline specs (e.g., can't name a resolver "1.1.1.1")

#### Advanced example: Multi-layer bootstrap chain

```toml
[global]
resolver = "layer-3"

# Layer 1: IP-addressed, no dependencies
[resolvers.layer-1]
endpoint = "1.1.1.1"

# Layer 2: First DoH hop
[resolvers.layer-2]
endpoint = "https://doh-a.example/dns-query"
bootstrap = "layer-1"

# Layer 3: Final resolver with ECH
[resolvers.layer-3]
endpoint = "https://doh-b.example/dns-query"
bootstrap = "layer-2"
  [resolvers.layer-3.ech]
  mode = "doh"
  require_ech = true
  ech_resolver = "layer-2"  # layer-2 fetches layer-3's ECH config
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

For `type = "ech"` routes, the ECHConfigList is sourced by an `[ech]` block. Its
fields inherit field-by-field from `[listener.ech]` and `[global.ech]` (and any
template), so shared settings need to be written only once; a route's `[ech]`
overrides only what differs, and may be omitted entirely when the enclosing
scopes already provide a complete config:
- `mode = "static"` — a fixed inline base64 `config`.
- `mode = "doh"` — looked up in the HTTPS record of `ech_domain` (or the inner
  name) via the ECH resolver; refreshed on `ech_refresh` / the record TTL.
- `mode = "doh-with-fallback"` — DoH, falling back to the inline `config`.

An omitted `mode` inherits (it is *not* silently `doh`); `static` and
`doh-with-fallback` require a `config` to be resolvable from some scope, checked
at load time. The upstream certificate is verified against the **inner (true) name** using the
web-PKI roots. `require_ech` (default true) fails closed unless ECH is
negotiated. **ECH retry**: if the server rejects ECH (its key rotated), the
cached config is invalidated, a fresh one is fetched, and the handshake is
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
rather than parsing HTTP, so it cannot translate between framings: there is no
"HTTP/2 in, HTTP/1.1 out" mode. `enabled` is a single coupled switch. (Doing
otherwise would mean reassembling requests, remapping streams and handling
trailers, upgrades and CONNECT — a different program.) In exchange, the data path
stays a transparent byte pump, so WebSockets and other upgrades keep working.

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
- **`raw`** never terminates TLS, so there is no ALPN to negotiate. Enabling
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

See [`sni-gate.example.toml`](sni-gate.example.toml) for every option.

## Trusting the CA

The CA is generated on first run at the `[ca]` paths. Import the **certificate**
(never the key) into each device that should trust issued certs:

```powershell
# this machine, as Administrator
powershell -ExecutionPolicy Bypass -File scripts\install-ca-windows.ps1
```

Or set `ca.install_to_system_root = true` to install it automatically on startup
(idempotent; Administrator required). For other devices, distribute `ca/ca.crt`
and import it into their trusted-root store.

## Security notes

- `ca/ca.key` is a trusted-root private key. Keep it local; it is gitignored.
- Terminating TLS means sni-gate sees plaintext for terminating route types.
- Binding to 443/80 requires Administrator on Windows.

## Logging

`SNI_GATE_LOG` / `RUST_LOG` override the config `log` directive:

```sh
SNI_GATE_LOG=debug sni-gate.exe
```

## License

Dual-licensed under MIT or Apache-2.0.
