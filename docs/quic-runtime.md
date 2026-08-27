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
| `SNI_GATE_QUIC_MAX_RAW_FORWARDING_BYTES` | `67108864` | Maximum bytes retained by all routed raw QUIC flows while upstream setup or forwarding is pending. |

Example:

```sh
SNI_GATE_QUIC_MAX_H3_CONNECTIONS=4096 \
SNI_GATE_QUIC_MAX_PENDING_HANDSHAKES=512 \
SNI_GATE_QUIC_MAX_H3_INGRESS_BYTES=16777216 \
SNI_GATE_QUIC_MAX_RAW_FORWARDING_BYTES=134217728 \
SNI_GATE_QUIC_MAX_UPSTREAM_POOL_ENTRIES=512 \
SNI_GATE_QUIC_UPSTREAM_POOL_IDLE_SECS=120 \
./sni-gate --config sni-gate.toml
```

These are capacity controls rather than performance targets. Raising them increases the maximum amount of live QUIC/H3 state the process may retain; tune them together with OS UDP socket buffers, memory limits, and expected concurrency.

The inbound handshake semaphore and both byte budgets are shared by every listener. H3 and raw queues still retain their packet-count bounds as a second limit. Each queued allocation owns its byte permit, so consuming or dropping a datagram, closing a queue, or tearing down a raw flow returns capacity automatically.

## Upstream HTTP/3 pooling

Terminating H3 requests acquire upstream connections lazily. Healthy connections are pooled by listener, route, logical dial host/port, upstream TLS server name, and ECH mode. A pool hit happens before DNS resolution, so normal reuse avoids both DNS and a fresh QUIC/TLS/H3 handshake.

Closed or idle entries are removed, and cold-start/upstream-outage connection storms are bounded by `SNI_GATE_QUIC_MAX_PENDING_UPSTREAM_CONNECTS`. After waiting for connect capacity, the pool is checked again before DNS/handshake so concurrent misses can reuse a connection another request established while they waited.

A request that already opened an upstream stream holds an endpoint-owning guard for the complete stream lifetime. Pool eviction therefore affects only future reuse and does not terminate an active response. Failed stale leases are generation-checked before eviction so an old request cannot remove a newer healthy replacement stored under the same logical pool key.

Upstream acquisition timeout returns HTTP `504`; other acquisition failures return `502`. A `send_request` failure evicts that specific pooled generation and returns `502`. The proxy intentionally does not automatically replay the current request because replay can be unsafe for non-idempotent methods.

## Shared UDP fast path

A QUIC listener containing only terminating `tls` / `ech` routes uses an H3-only fast path:

- QUIC Initial packets still enter the stateless SNI inspection path.
- Handshake, 0-RTT, 1-RTT/short-header, and other non-Initial datagrams are sent directly to Quinn ingress without taking the raw `FlowTable` mutex.

The fast path is **disabled whenever any `raw` route is present**. Mixed raw + H3 listeners continue to use conservative CID/flow ownership logic for every datagram, preserving transparent raw routing and avoiding accidental capture of raw traffic by the terminating endpoint.

## Raw QUIC flow-table fast path

Inspection flow count and retained bytes are maintained incrementally. Inspection expiry uses a bounded, generation-checked deadline heap, so ordinary forwarding packets do not scan every live flow to update admission state or find stale Initials. Stale heap entries are compacted under churn to keep the expiry index itself bounded.

Short-header lookup probes only CID lengths currently learned from upstream server SCIDs. Upstream short-header responses bypass the flow-table lock entirely; only long-header responses take the lock to teach a newly observed server CID.

A release-mode microbenchmark for the short-header lookup path can be run manually with:

```sh
cargo test --release benchmark_flow_table_short_header_lookup -- --ignored --nocapture
```

## Defaults and compatibility

Existing admission and pool defaults retain their previous values. The H3 ingress and raw forwarding byte budgets add new fail-closed memory ceilings; leaving their variables unset applies the defaults shown above and only changes behavior when queued traffic reaches those ceilings.

The runtime policy is intentionally separate from `[http3] enabled = true`: the latter decides whether automatic QUIC companion listeners exist; the former controls process resource budgets once QUIC/H3 traffic is running.
