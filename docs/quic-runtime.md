# QUIC / HTTP/3 runtime policy

The public route model stays transport-agnostic: `tls`, `ech`, `raw`, and `http` keep the same meaning in configuration, while a QUIC listener maps terminating `tls` / `ech` routes to HTTP/3 internally.

Resource limits for the QUIC/H3 data path are deliberately **process-wide runtime policy**, not route-level `[http3]` settings. `[http3]` controls automatic UDP companion generation and inherits through the normal config hierarchy; admission, pooling, and memory limits must not accidentally vary per route.

## Runtime environment variables

All values are parsed once when the first QUIC listener starts. Invalid or zero values fail startup. Omitting a variable keeps the production default.

| Environment variable | Default | Purpose |
|---|---:|---|
| `SNI_GATE_QUIC_MAX_PENDING_HANDSHAKES` | `256` | Maximum simultaneous inbound QUIC handshakes. When saturated, unvalidated peers receive stateless Retry and already-validated peers are refused. |
| `SNI_GATE_QUIC_MAX_H3_CONNECTIONS` | `1024` | Maximum active terminating HTTP/3 connections across the process. |
| `SNI_GATE_QUIC_MAX_REQUESTS_PER_CONNECTION` | `256` | Maximum concurrent semantic HTTP/3 request tasks on one inbound connection. Further requests are backpressured until capacity is available. |
| `SNI_GATE_QUIC_MAX_FIELD_SECTION_SIZE` | `65536` | HTTP/3 field-section limit in bytes advertised/applied by both inbound server and upstream client H3 builders. |
| `SNI_GATE_QUIC_MAX_UPSTREAM_POOL_ENTRIES` | `256` | Maximum number of reusable upstream HTTP/3 connections retained by the process. |
| `SNI_GATE_QUIC_UPSTREAM_POOL_IDLE_SECS` | `60` | Idle age in seconds after which a reusable upstream H3 pool entry is discarded. Active request streams keep their endpoint alive even if the reusable pool entry is evicted. |
| `SNI_GATE_QUIC_MAX_PENDING_UPSTREAM_CONNECTS` | `64` | Maximum simultaneous upstream DNS + UDP bind + QUIC/TLS/ECH/H3 establishment operations. Waiting for this capacity is bounded by the route's existing `connect_timeout`. |
| `SNI_GATE_QUIC_MAX_H3_INGRESS_BYTES` | `8388608` | Maximum bytes queued between all shared UDP dispatchers and terminating Quinn endpoints across the process. |
| `SNI_GATE_QUIC_MAX_RAW_FLOWS` | `4096` | Maximum active routed raw QUIC flows across the process. The existing per-listener flow-table limit remains an independent ceiling. |
| `SNI_GATE_QUIC_MAX_PENDING_RAW_CONNECTS` | `64` | Maximum simultaneous raw QUIC DNS + UDP/Happy-Eyeballs establishment operations across the process. New raw flows fail closed when this capacity is exhausted. |
| `SNI_GATE_QUIC_MAX_RAW_FORWARDING_BYTES` | `67108864` | Maximum bytes retained by all routed raw QUIC flows while upstream setup or forwarding is pending. |

Example:

```sh
SNI_GATE_QUIC_MAX_H3_CONNECTIONS=4096 \
SNI_GATE_QUIC_MAX_PENDING_HANDSHAKES=512 \
SNI_GATE_QUIC_MAX_H3_INGRESS_BYTES=16777216 \
SNI_GATE_QUIC_MAX_RAW_FLOWS=4096 \
SNI_GATE_QUIC_MAX_PENDING_RAW_CONNECTS=64 \
SNI_GATE_QUIC_MAX_RAW_FORWARDING_BYTES=134217728 \
SNI_GATE_QUIC_MAX_UPSTREAM_POOL_ENTRIES=512 \
SNI_GATE_QUIC_UPSTREAM_POOL_IDLE_SECS=120 \
./sni-gate --config sni-gate.toml
```

These are capacity controls rather than performance targets. Raising them increases the maximum amount of live QUIC/H3 state the process may retain; tune them together with OS UDP socket buffers, memory limits, and expected concurrency.

The inbound H3 handshake semaphore, raw flow/setup semaphores, and both byte budgets are shared by every listener. H3 and raw queues still retain their packet-count bounds as a second limit. Each queued allocation owns its byte permit, so consuming or dropping a datagram, closing a queue, or tearing down a raw flow returns capacity automatically.

## H3 connection idle lifetime

Inbound H3 keeps the route-level `idle_timeout` as the authoritative local application-idle policy. One Quinn server transport is shared by every terminating H3 route on a QUIC listener, so its transport idle timeout is set to the longest non-zero `idle_timeout` among those H3/H3-ECH routes. This prevents Quinn's shorter library default from closing a connection before the selected route's configured policy permits it.

If any terminating H3 route on that listener sets `idle_timeout = 0`, the listener's local Quinn transport idle timeout is disabled. The existing per-route H3 activity guard still enforces finite timeouts for the other routes, so sharing one listener does not lengthen their application-idle lifetime. A peer can still advertise its own smaller QUIC idle timeout; QUIC uses the minimum of the two endpoints' transport values, which is outside the gateway's local policy control.

## Upstream HTTP/3 pooling

Terminating H3 requests acquire upstream connections lazily. Healthy connections are pooled by listener, route, logical dial host/port, upstream TLS server name, and ECH mode. A pool hit happens before DNS resolution, so normal reuse avoids both DNS and a fresh QUIC/TLS/H3 handshake.

Closed or idle entries are removed, and cold-start/upstream-outage connection storms are bounded by `SNI_GATE_QUIC_MAX_PENDING_UPSTREAM_CONNECTS`. A request rechecks the pool after acquiring its same-key flight, before it consumes global connect capacity or performs DNS and a QUIC/TLS/H3 handshake.

The pool is split into 16 independently locked shards. Misses for the same logical key share a per-key singleflight lock, so only one task performs DNS and QUIC/TLS/H3 establishment while other keys continue independently. Pool capacity remains an exact process-wide limit; each retained entry or connection being prepared for retention owns one global slot permit, and capacity eviction happens only when all permits are occupied.

Outbound Quinn endpoints are reused by listener, route, and address family. A route therefore normally owns one IPv4 and/or one IPv6 UDP client socket rather than one socket per upstream connection. Plain-H3 routes also reuse one Quinn/rustls client configuration per listener and route, preserving TLS session tickets across reconnects. ECH routes reuse the `EchProvider`'s cached `Arc<ClientConfig>` for the same inner name and ALPN.

On a pool miss, DNS keeps all A/AAAA answers and H3 races complete QUIC
handshakes with an IPv6-first, 250 ms Happy Eyeballs stagger. The retained pool
entry records the address that actually won. Raw QUIC performs the equivalent
race using the first upstream response datagram as the success signal; merely
calling UDP `connect` would not detect an unreachable or selectively blocked
address.

A request that already opened an upstream stream holds a generation-specific sender guard for the complete stream lifetime, while the shared endpoint registry remains process-owned. Pool eviction therefore affects only future reuse and does not terminate an active response. Failed stale leases are generation-checked before eviction so an old request cannot remove a newer healthy replacement stored under the same logical pool key.

Upstream acquisition timeout returns HTTP `504`; other acquisition failures return `502`. A `send_request` failure evicts that specific pooled generation and returns `502`. The proxy intentionally does not automatically replay the current request because replay can be unsafe for non-idempotent methods.

## Shared UDP fast path

A QUIC listener containing only terminating `tls` / `ech` routes uses an H3-only fast path:

- QUIC Initial packets still enter the stateless SNI inspection path.
- Handshake, 0-RTT, 1-RTT/short-header, and other non-Initial datagrams are sent directly to Quinn ingress without taking the raw `FlowTable` mutex.

The fast path is **disabled whenever any `raw` route is present**. Mixed raw + H3 listeners continue to use conservative CID/flow ownership logic for every datagram, preserving transparent raw routing and avoiding accidental capture of raw traffic by the terminating endpoint.

## Raw QUIC admission and flow lifetime

A routed raw QUIC flow must acquire a process-wide active-flow permit before it is promoted to forwarding state. That permit is retained for the complete raw flow lifetime, so multiple listeners cannot multiply the previous per-listener `MAX_FLOWS` bound into an unbounded process-wide set of forwarding sockets/tasks.

Upstream setup has a separate process-wide limit. A new raw flow acquires a pending-connect permit before it starts DNS resolution, UDP socket creation, and first-response Happy Eyeballs racing. Admission is fail-fast rather than queued: raw forwarding has no application-layer response with which to report overload, and retaining thousands of setup waiters would defeat the purpose of the limit. The pending-connect permit is released immediately after one upstream path wins; the active-flow permit remains until forwarding ends.

The raw limits are deliberately separate from H3's upstream-connect limiter. A raw Initial flood therefore cannot consume the terminating-H3 upstream establishment budget, and an H3 outage cannot prevent unrelated raw flows from reaching their own admission ceiling.

Client peer migration remains live while upstream setup is in progress. The first upstream response reads the current peer from the same watch channel used by later responses, so a NAT rebinding observed during DNS/Happy-Eyeballs setup does not send the winning response to a stale source address.

## Raw QUIC flow-table fast path

Inspection flow count and retained bytes are maintained incrementally. Inspection expiry uses a bounded, generation-checked deadline heap, so ordinary forwarding packets do not scan every live flow to update admission state or find stale Initials. Stale heap entries are compacted under churn to keep the expiry index itself bounded.

Short-header lookup probes only CID lengths currently learned from upstream server SCIDs. Upstream short-header responses bypass the flow-table lock entirely; only long-header responses take the lock to teach a newly observed server CID.

A release-mode microbenchmark for the short-header lookup path can be run manually with:

```sh
cargo test --release benchmark_flow_table_short_header_lookup -- --ignored --nocapture
```

## Defaults and compatibility

The raw active-flow default of `4096` preserves the previous maximum forwarding-flow count for a single listener while making that ceiling process-wide across multiple listeners. The raw pending-connect limit adds an independent setup-storm ceiling; the existing per-listener flow table and process-wide forwarding byte budget remain in force as secondary limits.

The runtime policy is intentionally separate from `[http3] enabled = true`: the latter decides whether automatic QUIC companion listeners exist; the former controls process resource budgets once QUIC/H3 traffic is running.
