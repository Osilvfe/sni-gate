//! QUIC listener, including raw SNI-routed UDP forwarding.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::config::RouteType;
use crate::proxy::{ListenerState, RouteRuntime};
use crate::quic_initial::{InitialInspector, InitialSni};

const MAX_INITIAL_DATAGRAMS: usize = 8;
const MAX_INITIAL_BYTES: usize = 32 * 1024;
const FLOW_QUEUE: usize = 128;
const UDP_BUF: usize = 65_535;

enum Flow {
    Inspecting(InspectingFlow),
    Forwarding(mpsc::Sender<Vec<u8>>),
}

struct InspectingFlow {
    inspector: InitialInspector,
    packets: Vec<Vec<u8>>,
    bytes: usize,
}

impl InspectingFlow {
    fn new() -> Self {
        Self {
            inspector: InitialInspector::default(),
            packets: Vec::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, packet: &[u8]) -> Result<(), ()> {
        if self.packets.len() == MAX_INITIAL_DATAGRAMS
            || self.bytes.saturating_add(packet.len()) > MAX_INITIAL_BYTES
        {
            return Err(());
        }
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
            if tx.send(datagram.to_vec()).await.is_err() {
                flows.lock().await.remove(&peer);
            }
            continue;
        }

        let decision = {
            let mut map = flows.lock().await;
            let flow = map
                .entry(peer)
                .or_insert_with(|| Flow::Inspecting(InspectingFlow::new()));
            let Flow::Inspecting(flow) = flow else {
                continue;
            };
            if flow.push(datagram).is_err() {
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

        if let Err(error) =
            start_raw_flow(listener.clone(), flows.clone(), peer, route, sni, packets).await
        {
            debug!(%peer, error = %format!("{error:#}"), "QUIC raw route setup failed");
        }
    }
}

fn take_packets(map: &mut HashMap<SocketAddr, Flow>, peer: SocketAddr) -> Vec<Vec<u8>> {
    match map.remove(&peer) {
        Some(Flow::Inspecting(flow)) => flow.packets,
        Some(Flow::Forwarding(_)) | None => Vec::new(),
    }
}

async fn start_raw_flow(
    listener: Arc<UdpSocket>,
    flows: Flows,
    peer: SocketAddr,
    route: Arc<RouteRuntime>,
    sni: String,
    packets: Vec<Vec<u8>>,
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

    let (tx, mut rx) = mpsc::channel(FLOW_QUEUE);
    flows.lock().await.insert(peer, Flow::Forwarding(tx));
    info!(%peer, route = %route.name, upstream = %upstream_addr, "QUIC raw flow established");
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF];
        loop {
            tokio::select! {
                packet = rx.recv() => match packet {
                    Some(packet) => {
                        if upstream.send(&packet).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                received = upstream.recv(&mut buf) => match received {
                    Ok(n) => {
                        if listener.send_to(&buf[..n], peer).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        flows.lock().await.remove(&peer);
        debug!(%peer, "QUIC raw flow closed");
    });
    Ok(())
}

fn display_sni(sni: &str) -> &str {
    if sni.is_empty() {
        "<none>"
    } else {
        sni
    }
}
