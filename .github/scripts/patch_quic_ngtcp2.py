from pathlib import Path

p = Path('src/quic_proxy.rs')
s = p.read_text()
old = '''                        InspectResult::Invalid => {
                            table.remove(id);
                            debug!(%peer, flow_id = id, "dropping malformed or oversized QUIC Initial flight");
                            None
                        }
'''
new = '''                        InspectResult::Invalid => {
                            table.remove(id);
                            if let Some(ingress) = &h3_ingress {
                                // A live QUIC connection can legitimately send a later Initial
                                // using connection state that the stateless inspector does not
                                // possess. Let Quinn, which owns that state, make the authoritative
                                // validity decision instead of dropping the datagram here.
                                dispatch_to_h3(ingress, peer, datagram);
                                debug!(
                                    %peer,
                                    flow_id = id,
                                    "forwarding statelessly-uninspectable QUIC Initial to H3 endpoint"
                                );
                            } else {
                                debug!(%peer, flow_id = id, "dropping malformed or oversized QUIC Initial flight");
                            }
                            None
                        }
'''
if old not in s:
    raise SystemExit('invalid Initial arm anchor missing')
s = s.replace(old, new, 1)

old = '''                        if let Err(error) =
                            h3_proxy::serve_inbound(connection, peer, state, route_id, sni).await
                        {
                            debug!(%peer, error = %format!("{error:#}"), "H3 connection failed");
                        }
'''
new = '''                        let diagnostics = connection.clone();
                        if let Err(error) =
                            h3_proxy::serve_inbound(connection, peer, state, route_id, sni).await
                        {
                            debug!(
                                %peer,
                                error = %format!("{error:#}"),
                                close_reason = ?diagnostics.close_reason(),
                                stats = ?diagnostics.stats(),
                                "H3 connection failed"
                            );
                        }
'''
if old not in s:
    raise SystemExit('H3 diagnostics anchor missing')
s = s.replace(old, new, 1)
p.write_text(s)

p = Path('tests/quic_h3_resilience.rs')
s = p.read_text()
old = '    let oversized = vec![0u8; 60_000];\n'
new = (
    '    // Stay above the historical 1,472-byte cap while remaining portable to\n'
    '    // macOS, whose default UDP socket limit rejects very large loopback payloads.\n'
    '    let oversized = vec![0u8; 8 * 1024];\n'
)
if old not in s:
    raise SystemExit('oversized test anchor missing')
s = s.replace(old, new, 1)
p.write_text(s)
