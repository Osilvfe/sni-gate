# QUIC / HTTP/3 example tests

This page collects the smallest useful checks for the two QUIC data paths in sni-gate:

- terminating HTTP/3 (`tls` / `ech` routes on a QUIC listener), where sni-gate owns both QUIC connections and proxies HTTP/3 semantics;
- raw QUIC (`raw` routes), where sni-gate decrypts only the Initial far enough to route by SNI and then forwards the encrypted datagrams unchanged.

The automated tests are hermetic and are the preferred regression checks. The final H3 smoke recipe deliberately uses a public HTTP/3 endpoint because production upstream certificate verification uses WebPKI; the gateway has no test-only insecure verifier.

## Automated checks

Run the QUIC-focused integration tests individually while developing:

```sh
cargo test --test quic_raw_e2e -- --nocapture
cargo test --test quic_raw_admission -- --nocapture
cargo test --test quic_h3_resilience -- --nocapture
cargo test --test http23_auto_e2e -- --nocapture
```

What they prove:

| Test | Coverage |
|---|---|
| `quic_raw_e2e` | Real Quinn client → raw sni-gate route → real Quinn upstream. Covers Initial inspection, buffered flight forwarding, bidirectional passthrough, and post-handshake short-header traffic. |
| `quic_raw_admission` | Two raw QUIC listeners share one process-wide active-flow limit. It verifies admission failure while the slot is occupied and permit recovery after the first flow becomes idle. |
| `quic_h3_resilience` | Oversized UDP input cannot tear down the shared Quinn/H3 endpoint; a later real QUIC handshake still negotiates ALPN `h3`. |
| `http23_auto_e2e` | One configured TCP listener can keep HTTP/2 while `[http3] enabled = true` creates a working H3/UDP companion on the same numeric port. |

For the complete normal suite:

```sh
cargo test
```

## Manual terminating-H3 smoke test

This check exercises an actual semantic HTTP/3 request through both QUIC legs:

```text
curl --HTTP/3--> sni-gate --HTTP/3--> cloudflare-quic.com
```

It requires:

- outbound UDP/443 access;
- a curl build with HTTP/3 support (`curl --version` should advertise `HTTP3`);
- `cloudflare-quic.com` to be reachable from the test machine.

Create `h3-smoke.toml` in the repository root:

```toml
[global]
log = "debug"
resolver = "udp://1.1.1.1:53"
unmatched = "close"

[ca]
cert_path = "ca/ca.crt"
key_path = "ca/ca.key"
common_name = "sni-gate H3 smoke CA"
leaf_validity_days = 30

[psl]
source = "embedded"

[[listener]]
addr = "127.0.0.1:8443"
transport = "quic"
connect_timeout = "5s"
idle_timeout = "30s"

  [[listener.route]]
  name = "h3-smoke"
  type = "tls"
  match_sni = ["cloudflare-quic.com"]
  upstream = "cloudflare-quic.com:443"
```

Build and start the gateway:

```sh
cargo build
SNI_GATE_LOG=debug ./target/debug/sni-gate -c h3-smoke.toml
```

In another terminal, keep the URL/SNI/authority as `cloudflare-quic.com` but redirect the actual client socket to the local gateway:

```sh
curl --http3-only \
  --connect-to cloudflare-quic.com:443:127.0.0.1:8443 \
  --cacert ca/ca.crt \
  -sv https://cloudflare-quic.com/ -o /dev/null
```

A successful smoke test has all of these properties:

1. curl reports that it negotiated HTTP/3 rather than falling back to HTTP/2 or HTTP/1.1;
2. sni-gate logs an inbound H3/QUIC handshake for `cloudflare-quic.com`;
3. sni-gate establishes an upstream H3 connection and forwards the request;
4. curl receives an HTTP response through the gateway.

Run the curl command again without restarting sni-gate. The second request is also useful when inspecting the upstream pool path: a still-healthy pooled connection can be reused without another DNS lookup and QUIC/TLS/H3 establishment. Pool reuse is opportunistic because the upstream may close its connection earlier than the gateway's local idle policy.

## Raw QUIC runtime-pressure example

The new raw limits are process-wide. To make admission behavior easy to observe manually, start a raw configuration with deliberately tiny values:

```sh
SNI_GATE_QUIC_MAX_RAW_FLOWS=1 \
SNI_GATE_QUIC_MAX_PENDING_RAW_CONNECTS=1 \
SNI_GATE_QUIC_MAX_RAW_FORWARDING_BYTES=65536 \
SNI_GATE_LOG=debug \
./target/debug/sni-gate -c sni-gate.toml
```

With one raw QUIC connection kept active, a second routed raw connection must fail closed rather than create another forwarding socket/task. After the first flow reaches its configured `idle_timeout`, capacity is returned automatically and a new connection can be admitted. The hermetic `quic_raw_admission` integration test above is the reproducible CI version of this scenario.

## Suggested pre-release sequence

For a QUIC/H3-focused release candidate, use this order:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test quic_raw_e2e
cargo test --test quic_raw_admission
cargo test --test quic_h3_resilience
cargo test --test http23_auto_e2e
cargo test
```

Then run the manual terminating-H3 smoke test once from a network that permits UDP/443. This separates deterministic regression coverage from public-network interoperability checks.
