//! QUIC listener, including raw SNI-routed UDP forwarding.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::RouteType;
use crate::proxy::{ListenerState, RouteRuntime};
use crate::quic_initial::{InitialInspector, InitialSni};

const MAX_INITIAL_DATAGRAMS: usize = 8;
const MAX_INITIAL_BYTES: usize = 32 * 1024;
const MAX_FLOWS: usize = 4096;
const INITIAL_INSPECTION_TIMEOUT: Duration = Duration::from_secs(10);
const FLOW_QUEUE: usize = 128;
const UDP_BUF: usize = 65_535;

enum Flow {
    Inspecting(InspectingFlow),
    /// The queue exists before upstream setup finishes, so packets arriving
    /// during DNS/socket setup are retained without blocking the listener.
    Forwarding(mpsc::Sender<Vec<u8>>),
}

struct InspectingFlow {
    inspector: InitialInspector,
    packets: Vec<Vec<u8>>,
    bytes: usize,
    last_activity: Instant,
}

impl InspectingFlow {
    fn new(now: Instant) -> Self {
        Self {
            inspector: InitialInspector::default(),
            packets: Vec::new(),
            bytes: 0,
            last_activity: now,
        }
    }

    fn push(&mut self, packet: &[u8], now: Instant) -> Result<(), ()> {
        if self.packets.len() == MAX_INITIAL_DATAGRAMS
            || self.bytes.saturating_add(packet.len()) > MAX_INITIAL_BYTES
        {
            return Err(());
        }
        self.last_activity = now;
        self.bytes += packet.len();
        self.packets.push(packet.to_vec());
        Ok(())
    }
}

type Flows = Arc<Mutex<HashMap<SocketAddr, Flow>>>;

/// Serve one UDP/QUIC listener.
///
/// Raw routes are completely transparent after the Initial flight has yielded
/// an SNI: a dedicated connected UDP socket carries each client's QUIC flow so
/// upstream replies can be mapped safely without interpreting short-header
/// connection IDs. This intentionally does not support client migration yet;
/// its mapping key is the source UDP socket address.
pub async fn serve(state: Arc<ListenerState>) -> Result<()> {
    let listener = Arc::new(
        UdpSocket::bind(state.addr)
            .await
            .with_context(|| format!("binding QUIC listener {}", state.addr))?,
    );
    let flows: Flows = Arc::new(Mutex::new(HashMap::new()));
    info!(addr = %state.addr, routes = state.routes.len(), "QUIC listening");

    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, peer) = listener.recv_from(&mut buf).await?;
        let datagram = &buf[..n];

        let forwarding = {
            let map = flows.lock().await;
            match map.get(&peer) {
                Some(Flow::Forwarding(tx)) => Some(tx.clone()),
                Some(Flow::Inspecting(_)) | None => None,
            }
        };
        if let Some(tx) = forwarding {
            match tx.try_send(datagram.to_vec()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    debug!(%peer, "dropping QUIC datagram because raw flow queue is full");
                }
                Err(TrySendError::Closed(_)) => {
                    flows.lock().await.remove(&peer);
                }
            }
            continue;
        }

        let decision = {
            let now = Instant::now();
            let mut map = flows.lock().await;
            prune_stale_inspecting(&mut map, now);
            if !map.contains_key(&peer) && map.len() >= MAX_FLOWS {
                warn!(%peer, max_flows = MAX_FLOWS, "dropping new QUIC flow because listener flow limit is reached");
                continue;
            }
            let flow = map
                .entry(peer)
                .or_insert_with(|| Flow::Inspecting(InspectingFlow::new(now)));
            let Flow::Inspecting(flow) = flow else {
                continue;
            };
            if flow.push(datagram, now).is_err() {
                map.remove(&peer);
                warn!(%peer, "dropping QUIC Initial flight that exceeds inspection limits");
                continue;
            }
            match flow.inspector.ingest(datagram) {
                InitialSni::NeedMore => continue,
                InitialSni::Invalid => {
                    map.remove(&peer);
                    debug!(%peer, "dropping malformed or unsupported QUIC Initial");
                    continue;
                }
                InitialSni::Name(name) => {
                    let route = state.router.match_host(&name);
                    Some((name, route, take_packets(&mut map, peer)))
                }
                InitialSni::NoSni => {
                    let route = state.router.match_host("");
                    Some((String::new(), route, take_packets(&mut map, peer)))
                }
            }
        };

        let Some((sni, route_id, packets)) = decision else {
            continue;
        };
        let Some(route_id) = route_id else {
            debug!(%peer, sni = %display_sni(&sni), "unmatched QUIC Initial");
            continue;
        };
        let route = state.routes[route_id].clone();
        if route.route_type != RouteType::Raw {
            // H3/H3-ECH termination is installed in the next stage. Refusing
            // rather than forwarding avoids accidentally treating it as raw.
            debug!(%peer, route = %route.name, "QUIC terminating route not available yet");
            continue;
        }

        spawn_raw_flow(listener.clone(), flows.clone(), peer, route, sni, packets).await;
    }
}

fn prune_stale_inspecting(map: &mut HashMap<SocketAddr, Flow>, now: Instant) {
    map.retain(|_, flow| match flow {
        Flow::Inspecting(flow) => now.duration_since(flow.last_activity) < INITIAL_INSPECTION_TIMEOUT,
        Flow::Forwarding(_) => true,
    });
}

fn take_packets(map: &mut HashMap<SocketAddr, Flow>, peer: SocketAddr) -> Vec<Vec<u8>> {
    match map.remove(&peer) {
        Some(Flow::Inspecting(flow)) => flow.packets,
        Some(Flow::Forwarding(_)) | None => Vec::new(),
    }
}

async fn spawn_raw_flow(
    listener: Arc<UdpSocket>,
    flows: Flows,
    peer: SocketAddr,
    route: Arc<RouteRuntime>,
    sni: String,
    packets: Vec<Vec<u8>>,
) {
    let (tx, rx) = mpsc::channel(FLOW_QUEUE);
    flows.lock().await.insert(peer, Flow::Forwarding(tx));

    tokio::spawn(async move {
        if let Err(error) = run_raw_flow(listener, peer, route, sni, packets, rx).await {
            debug!(%peer, error = %format!("{error:#}"), "QUIC raw flow failed");
        }
        flows.lock().await.remove(&peer);
        debug!(%peer, "QUIC raw flow closed");
    });
}

async fn run_raw_flow(
    listener: Arc<UdpSocket>,
    peer: SocketAddr,
    route: Arc<RouteRuntime>,
    sni: String,
    packets: Vec<Vec<u8>>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let host = route
        .upstream_host
        .clone()
        .or_else(|| (!sni.is_empty()).then_some(sni))
        .ok_or_else(|| {
            anyhow!(
                "raw QUIC route {} reflects SNI but none was presented",
                route.name
            )
        })?;
    let upstream_addr = route
        .addr_resolver
        .lookup_addr(
            &host,
            route.upstream_port,
            route.address_family,
            route.nat64.as_ref(),
        )
        .await
        .with_context(|| format!("resolving QUIC upstream {host}"))?;

    let bind = match upstream_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let upstream = UdpSocket::bind(bind).await?;
    upstream.connect(upstream_addr).await?;
    for packet in &packets {
        upstream.send(packet).await?;
    }

    info!(%peer, route = %route.name, upstream = %upstream_addr, "QUIC raw flow established");
    let idle = route.idle_timeout;
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        tokio::select! {
            packet = rx.recv() => match packet {
                Some(packet) => upstream.send(&packet).await.map(|_| ())?,
                None => break,
            },
            received = upstream.recv(&mut buf) => {
                let n = received?;
                listener.send_to(&buf[..n], peer).await?;
            },
            _ = tokio::time::sleep(idle), if !idle.is_zero() => {
                debug!(%peer, route = %route.name, "QUIC raw flow idle timeout");
                break;
            }
        }
    }
    Ok(())
}

fn display_sni(sni: &str) -> &str {
    if sni.is_empty() {
        "<none>"
    } else {
        sni
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_initial_flows_are_pruned_but_forwarding_flows_remain() {
        let now = Instant::now();
        let stale = now - INITIAL_INSPECTION_TIMEOUT - Duration::from_millis(1);
        let (tx, _rx) = mpsc::channel(1);
        let mut flows = HashMap::from([
            (
                "127.0.0.1:1000".parse().unwrap(),
                Flow::Inspecting(InspectingFlow::new(stale)),
            ),
            (
                "127.0.0.1:1001".parse().unwrap(),
                Flow::Inspecting(InspectingFlow::new(now)),
            ),
            ("127.0.0.1:1002".parse().unwrap(), Flow::Forwarding(tx)),
        ]);

        prune_stale_inspecting(&mut flows, now);

        assert!(!flows.contains_key(&"127.0.0.1:1000".parse().unwrap()));
        assert!(flows.contains_key(&"127.0.0.1:1001".parse().unwrap()));
        assert!(flows.contains_key(&"127.0.0.1:1002".parse().unwrap()));
    }
}
