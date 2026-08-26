//! QUIC listener, including raw SNI-routed UDP forwarding and H3 dispatch.

#[path = "h3_proxy.rs"]
mod h3_proxy;
#[path = "quic_socket.rs"]
mod quic_socket;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::{FailPolicy, RouteType};
use crate::proxy::{ListenerState, RouteRuntime};
use crate::quic_initial::{InitialInspector, InitialSni};
use quic_socket::{InboundDatagram, QuicIngress, SharedQuicSocket};

const MAX_INITIAL_DATAGRAMS: usize = 8;
const MAX_INITIAL_BYTES: usize = 32 * 1024;
const MAX_FLOWS: usize = 4096;
const MAX_INSPECTING_FLOWS: usize = 256;
const MAX_INSPECTION_BYTES: usize = 8 * 1024 * 1024;
const MAX_CID_LEN: usize = 20;
const MAX_CIDS_PER_FLOW: usize = 32;
const INITIAL_INSPECTION_TIMEOUT: Duration = Duration::from_secs(10);
const FLOW_QUEUE: usize = 128;
const UDP_BUF: usize = 65_535;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;

type FlowId = u64;
type Flows = Arc<Mutex<FlowTable>>;

struct FlowTable {
    next_id: FlowId,
    entries: HashMap<FlowId, FlowEntry>,
    peers: HashMap<SocketAddr, HashSet<FlowId>>,
    /// CIDs accepted for long-header lookup. This contains the client's one
    /// initial DCID plus server-issued SCIDs observed from the configured
    /// upstream. It is deliberately not expanded from arbitrary client packets.
    routing_cids: HashMap<Vec<u8>, HashSet<FlowId>>,
    /// Only server-issued CIDs are eligible for short-header matching. A
    /// client-chosen Initial DCID must never become a short-header prefix token.
    short_cids: HashMap<Vec<u8>, HashSet<FlowId>>,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self {
            next_id: 1,
            entries: HashMap::new(),
            peers: HashMap::new(),
            routing_cids: HashMap::new(),
            short_cids: HashMap::new(),
        }
    }
}

struct FlowEntry {
    peer: SocketAddr,
    routing_cids: HashSet<Vec<u8>>,
    short_cids: HashSet<Vec<u8>>,
    state: FlowState,
}

enum FlowState {
    Inspecting(InspectingFlow),
    /// The queue exists before upstream setup finishes, so packets arriving
    /// during DNS/socket setup are retained without blocking the listener.
    Forwarding {
        tx: mpsc::Sender<Vec<u8>>,
        /// Raw upstream replies are sent to the latest observed client address.
        /// Updating this when a known DCID arrives from a new address is what
        /// makes NAT rebinding/path migration work without changing payloads.
        peer_tx: watch::Sender<SocketAddr>,
    },
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

    fn retained_bytes(&self) -> usize {
        self.bytes.saturating_add(self.inspector.buffered_bytes())
    }

    fn take_packets_and_release_inspector(&mut self) -> Vec<Vec<u8>> {
        self.bytes = 0;
        self.inspector = InitialInspector::default();
        std::mem::take(&mut self.packets)
    }
}

#[derive(Debug)]
struct LongHeader<'a> {
    first: u8,
    version: u32,
    dcid: &'a [u8],
    scid: &'a [u8],
}

impl<'a> LongHeader<'a> {
    fn parse(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < 7 || packet[0] & 0x80 == 0 {
            return None;
        }
        let version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
        let mut at = 5usize;
        let dcid_len = usize::from(*packet.get(at)?);
        if dcid_len > MAX_CID_LEN {
            return None;
        }
        at += 1;
        let dcid = packet.get(at..at.checked_add(dcid_len)?)?;
        at += dcid_len;
        let scid_len = usize::from(*packet.get(at)?);
        if scid_len > MAX_CID_LEN {
            return None;
        }
        at += 1;
        let scid = packet.get(at..at.checked_add(scid_len)?)?;
        Some(Self {
            first: packet[0],
            version,
            dcid,
            scid,
        })
    }

    fn is_initial(&self) -> bool {
        let ty = self.first & 0x30;
        match self.version {
            QUIC_V1 => ty == 0x00,
            QUIC_V2 => ty == 0x10,
            _ => false,
        }
    }
}

impl FlowTable {
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Resolve a client datagram to an existing flow.
    ///
    /// Known CID lookup wins over the source UDP address. Unknown long headers
    /// never fall back to the peer address: accepting one that way would let a
    /// client continuously invent DCIDs and poison the flow's ownership state.
    /// Peer fallback is reserved for raw-only short-header traffic, whose CID
    /// length is not encoded on the wire.
    fn flow_id_for(
        &self,
        peer: SocketAddr,
        datagram: &[u8],
        allow_peer_fallback: bool,
    ) -> Option<FlowId> {
        if let Some(header) = LongHeader::parse(datagram) {
            return self.unique_routing_cid_owner(header.dcid);
        }
        if let Some(id) = self.short_header_owner(datagram) {
            return Some(id);
        }
        allow_peer_fallback
            .then(|| self.unique_peer_owner(peer))
            .flatten()
    }

    fn unique_routing_cid_owner(&self, cid: &[u8]) -> Option<FlowId> {
        if cid.is_empty() {
            return None;
        }
        let owners = self.routing_cids.get(cid)?;
        (owners.len() == 1).then(|| *owners.iter().next().expect("one CID owner"))
    }

    fn unique_peer_owner(&self, peer: SocketAddr) -> Option<FlowId> {
        let owners = self.peers.get(&peer)?;
        (owners.len() == 1).then(|| *owners.iter().next().expect("one peer owner"))
    }

    /// Short headers do not carry a CID length. Try every legal length against
    /// server-issued CIDs only and accept one unambiguous owning flow.
    fn short_header_owner(&self, datagram: &[u8]) -> Option<FlowId> {
        let first = datagram.first()?;
        if first & 0x80 != 0 || datagram.len() <= 1 {
            return None;
        }
        let mut candidate = None;
        let max = MAX_CID_LEN.min(datagram.len() - 1);
        for len in 1..=max {
            let Some(owners) = self.short_cids.get(&datagram[1..1 + len]) else {
                continue;
            };
            if owners.len() != 1 {
                return None;
            }
            let id = *owners.iter().next().expect("one CID owner");
            match candidate {
                None => candidate = Some(id),
                Some(previous) if previous == id => {}
                Some(_) => return None,
            }
        }
        candidate
    }

    fn insert_inspecting(
        &mut self,
        peer: SocketAddr,
        now: Instant,
        initial_dcid: Option<&[u8]>,
    ) -> FlowId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.entries.insert(
            id,
            FlowEntry {
                peer,
                routing_cids: HashSet::new(),
                short_cids: HashSet::new(),
                state: FlowState::Inspecting(InspectingFlow::new(now)),
            },
        );
        self.peers.entry(peer).or_default().insert(id);
        if let Some(cid) = initial_dcid {
            self.add_routing_cid(id, cid, false);
        }
        id
    }

    fn peer(&self, id: FlowId) -> Option<SocketAddr> {
        self.entries.get(&id).map(|entry| entry.peer)
    }

    fn migrate_peer(&mut self, id: FlowId, new_peer: SocketAddr) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        let old_peer = entry.peer;
        if old_peer == new_peer {
            return false;
        }
        entry.peer = new_peer;
        let peer_tx = match &entry.state {
            FlowState::Forwarding { peer_tx, .. } => Some(peer_tx.clone()),
            FlowState::Inspecting(_) => None,
        };

        let remove_old_peer = if let Some(ids) = self.peers.get_mut(&old_peer) {
            ids.remove(&id);
            ids.is_empty()
        } else {
            false
        };
        if remove_old_peer {
            self.peers.remove(&old_peer);
        }
        self.peers.entry(new_peer).or_default().insert(id);
        if let Some(peer_tx) = peer_tx {
            let _ = peer_tx.send(new_peer);
        }
        true
    }

    fn add_routing_cid(&mut self, id: FlowId, cid: &[u8], short_header: bool) {
        if cid.is_empty() || cid.len() > MAX_CID_LEN {
            return;
        }
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        let already_known = entry.routing_cids.contains(cid);
        if !already_known && entry.routing_cids.len() >= MAX_CIDS_PER_FLOW {
            return;
        }
        let inserted = entry.routing_cids.insert(cid.to_vec());
        if inserted {
            self.routing_cids
                .entry(cid.to_vec())
                .or_default()
                .insert(id);
        }
        if short_header && entry.short_cids.insert(cid.to_vec()) {
            self.short_cids.entry(cid.to_vec()).or_default().insert(id);
        }
    }

    /// A server long-header SCID is a CID the client can use as its future DCID.
    /// Upstream packets arrive through a connected UDP socket, so this is the
    /// only dynamic CID-learning direction trusted by the raw flow table.
    fn observe_upstream_datagram(&mut self, id: FlowId, datagram: &[u8]) {
        if let Some(header) = LongHeader::parse(datagram) {
            self.add_routing_cid(id, header.scid, true);
        }
    }

    fn forwarding_sender(&self, id: FlowId) -> Option<mpsc::Sender<Vec<u8>>> {
        match &self.entries.get(&id)?.state {
            FlowState::Forwarding { tx, .. } => Some(tx.clone()),
            FlowState::Inspecting(_) => None,
        }
    }

    fn inspecting_mut(&mut self, id: FlowId) -> Option<&mut InspectingFlow> {
        match &mut self.entries.get_mut(&id)?.state {
            FlowState::Inspecting(flow) => Some(flow),
            FlowState::Forwarding { .. } => None,
        }
    }

    fn inspecting_stats(&self) -> (usize, usize) {
        self.entries
            .values()
            .fold((0usize, 0usize), |stats, entry| match &entry.state {
                FlowState::Inspecting(flow) => {
                    (stats.0 + 1, stats.1.saturating_add(flow.retained_bytes()))
                }
                FlowState::Forwarding { .. } => stats,
            })
    }

    fn evict_oldest_inspecting(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .filter_map(|(&id, entry)| match &entry.state {
                FlowState::Inspecting(flow) => Some((id, flow.last_activity)),
                FlowState::Forwarding { .. } => None,
            })
            .min_by_key(|(_, activity)| *activity)
            .map(|(id, _)| id);
        if let Some(id) = oldest {
            self.remove(id);
            true
        } else {
            false
        }
    }

    /// Reserve one slot for a new unauthenticated Initial flow. Pressure only
    /// evicts inspecting entries; already-routed forwarding flows are never
    /// sacrificed to make room for attacker-controlled pre-routing state.
    fn make_room_for_inspecting(&mut self) -> bool {
        loop {
            let (inspecting, bytes) = self.inspecting_stats();
            if self.len() < MAX_FLOWS
                && inspecting < MAX_INSPECTING_FLOWS
                && bytes < MAX_INSPECTION_BYTES
            {
                return true;
            }
            if !self.evict_oldest_inspecting() {
                return false;
            }
        }
    }

    fn promote(
        &mut self,
        id: FlowId,
        tx: mpsc::Sender<Vec<u8>>,
        peer_tx: watch::Sender<SocketAddr>,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        entry.state = FlowState::Forwarding { tx, peer_tx };
        true
    }

    fn remove(&mut self, id: FlowId) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        let remove_peer = if let Some(ids) = self.peers.get_mut(&entry.peer) {
            ids.remove(&id);
            ids.is_empty()
        } else {
            false
        };
        if remove_peer {
            self.peers.remove(&entry.peer);
        }
        for cid in entry.routing_cids {
            let remove_cid = if let Some(ids) = self.routing_cids.get_mut(&cid) {
                ids.remove(&id);
                ids.is_empty()
            } else {
                false
            };
            if remove_cid {
                self.routing_cids.remove(&cid);
            }
        }
        for cid in entry.short_cids {
            let remove_cid = if let Some(ids) = self.short_cids.get_mut(&cid) {
                ids.remove(&id);
                ids.is_empty()
            } else {
                false
            };
            if remove_cid {
                self.short_cids.remove(&cid);
            }
        }
    }

    fn prune_stale_inspecting(&mut self, now: Instant) {
        let stale: Vec<FlowId> = self
            .entries
            .iter()
            .filter_map(|(&id, entry)| match &entry.state {
                FlowState::Inspecting(flow)
                    if now.duration_since(flow.last_activity) >= INITIAL_INSPECTION_TIMEOUT =>
                {
                    Some(id)
                }
                FlowState::Inspecting(_) | FlowState::Forwarding { .. } => None,
            })
            .collect();
        for id in stale {
            self.remove(id);
        }
    }
}

enum InspectResult {
    NeedMore,
    Invalid,
    Routed { sni: String, packets: Vec<Vec<u8>> },
}

fn warn_unsupported_fail_policies(state: &ListenerState) {
    if state.unmatched != FailPolicy::Close {
        warn!(
            addr = %state.addr,
            policy = ?state.unmatched,
            "QUIC unmatched/inherited fail policy is unsupported; QUIC failures are fail-closed"
        );
    }
    for route in &state.routes {
        if route.fail != FailPolicy::Close && route.fail != state.unmatched {
            warn!(
                addr = %state.addr,
                route = %route.name,
                policy = ?route.fail,
                "QUIC route fail policy is unsupported; QUIC route failures are fail-closed"
            );
        }
    }
}

/// Serve one UDP/QUIC listener.
pub async fn serve(state: Arc<ListenerState>) -> Result<()> {
    let listener = Arc::new(
        UdpSocket::bind(state.addr)
            .await
            .with_context(|| format!("binding QUIC listener {}", state.addr))?,
    );
    warn_unsupported_fail_policies(&state);
    let flows: Flows = Arc::new(Mutex::new(FlowTable::default()));
    let h3 = start_h3_endpoint(listener.clone(), state.clone())?;
    let h3_ingress = h3.as_ref().map(|(_, ingress)| ingress.clone());
    // Keep the endpoint alive for the lifetime of the listener.
    let _h3_endpoint = h3.map(|(endpoint, _)| endpoint);
    let allow_peer_fallback = h3_ingress.is_none();
    info!(
        addr = %state.addr,
        routes = state.routes.len(),
        h3 = h3_ingress.is_some(),
        "QUIC listening"
    );

    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, peer) = listener.recv_from(&mut buf).await?;
        let datagram = &buf[..n];

        let action = {
            let now = Instant::now();
            let mut table = flows.lock().await;
            table.prune_stale_inspecting(now);

            let id = match table.flow_id_for(peer, datagram, allow_peer_fallback) {
                Some(id) => id,
                None => {
                    let initial_dcid = LongHeader::parse(datagram)
                        .filter(LongHeader::is_initial)
                        .map(|header| header.dcid);
                    let Some(initial_dcid) = initial_dcid else {
                        if let Some(ingress) = &h3_ingress {
                            dispatch_to_h3(ingress, peer, datagram);
                        } else {
                            debug!(%peer, "dropping QUIC datagram with no known raw flow/CID");
                        }
                        continue;
                    };
                    if !table.make_room_for_inspecting() {
                        warn!(
                            %peer,
                            max_flows = MAX_FLOWS,
                            max_inspecting = MAX_INSPECTING_FLOWS,
                            max_inspection_bytes = MAX_INSPECTION_BYTES,
                            "dropping new QUIC Initial because inspection capacity is exhausted by forwarding flows"
                        );
                        continue;
                    }
                    table.insert_inspecting(peer, now, Some(initial_dcid))
                }
            };

            if table.migrate_peer(id, peer) {
                debug!(%peer, flow_id = id, "QUIC flow client address changed");
            }

            if let Some(tx) = table.forwarding_sender(id) {
                Some((id, Some(tx), None))
            } else {
                let inspection = {
                    let Some(flow) = table.inspecting_mut(id) else {
                        continue;
                    };
                    if flow.push(datagram, now).is_err() {
                        InspectResult::Invalid
                    } else {
                        match flow.inspector.ingest(datagram) {
                            InitialSni::NeedMore => InspectResult::NeedMore,
                            InitialSni::Invalid => InspectResult::Invalid,
                            InitialSni::Name(sni) => InspectResult::Routed {
                                sni,
                                packets: flow.take_packets_and_release_inspector(),
                            },
                            InitialSni::NoSni => InspectResult::Routed {
                                sni: String::new(),
                                packets: flow.take_packets_and_release_inspector(),
                            },
                        }
                    }
                };

                let (_, inspection_bytes) = table.inspecting_stats();
                if inspection_bytes > MAX_INSPECTION_BYTES {
                    table.remove(id);
                    debug!(
                        %peer,
                        flow_id = id,
                        inspection_bytes,
                        max_inspection_bytes = MAX_INSPECTION_BYTES,
                        "dropping QUIC Initial flow because global inspection memory budget was exceeded"
                    );
                    None
                } else {
                    match inspection {
                        InspectResult::NeedMore => None,
                        InspectResult::Invalid => {
                            table.remove(id);
                            debug!(%peer, flow_id = id, "dropping malformed or oversized QUIC Initial flight");
                            None
                        }
                        InspectResult::Routed { sni, packets } => {
                            Some((id, None, Some((sni, packets))))
                        }
                    }
                }
            }
        };

        let Some((flow_id, forwarding, decision)) = action else {
            continue;
        };
        if let Some(tx) = forwarding {
            match tx.try_send(datagram.to_vec()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    debug!(%peer, flow_id, "dropping QUIC datagram because raw flow queue is full");
                }
                Err(TrySendError::Closed(_)) => {
                    flows.lock().await.remove(flow_id);
                }
            }
            continue;
        }

        let Some((sni, packets)) = decision else {
            continue;
        };
        let route_id = if sni.is_empty() {
            state.router.match_host("")
        } else {
            state.router.match_host(&sni)
        };
        let Some(route_id) = route_id else {
            flows.lock().await.remove(flow_id);
            debug!(%peer, flow_id, sni = %display_sni(&sni), "unmatched QUIC Initial");
            continue;
        };
        let route = state.routes[route_id].clone();
        match route.route_type {
            RouteType::Raw => {
                spawn_raw_flow(
                    listener.clone(),
                    flows.clone(),
                    flow_id,
                    route,
                    sni,
                    packets,
                )
                .await;
            }
            RouteType::H3 | RouteType::H3Ech => {
                flows.lock().await.remove(flow_id);
                let Some(ingress) = &h3_ingress else {
                    warn!(%peer, route = %route.name, "H3 route selected without a Quinn endpoint");
                    continue;
                };
                for packet in packets {
                    dispatch_to_h3(ingress, peer, &packet);
                }
                debug!(%peer, route = %route.name, sni = %display_sni(&sni), "dispatched QUIC flow to H3 endpoint");
            }
            RouteType::Tls | RouteType::Ech | RouteType::Http => {
                flows.lock().await.remove(flow_id);
                warn!(%peer, route = %route.name, "invalid non-QUIC route reached QUIC dispatcher");
            }
        }
    }
}

fn start_h3_endpoint(
    listener: Arc<UdpSocket>,
    state: Arc<ListenerState>,
) -> Result<Option<(quinn::Endpoint, QuicIngress)>> {
    let enabled = state
        .routes
        .iter()
        .any(|route| matches!(route.route_type, RouteType::H3 | RouteType::H3Ech));
    if !enabled {
        return Ok(None);
    }

    let server_crypto = state.server_configs.h3.as_ref().clone();
    let quic_crypto = QuicServerConfig::try_from(server_crypto)
        .context("converting H3 rustls config to Quinn server crypto")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let endpoint_config = quic_socket::h3_endpoint_config()
        .context("configuring shared Quinn endpoint receive limit")?;
    let max_datagram_size = endpoint_config.get_max_udp_payload_size() as usize;
    let (socket, ingress) = SharedQuicSocket::new(listener, max_datagram_size)
        .context("initializing shared Quinn UDP socket")?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("creating shared Quinn endpoint")?;

    let accept_endpoint = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                let peer = incoming.remote_address();
                match incoming.await {
                    Ok(connection) => {
                        let handshake = connection.handshake_data().and_then(|data| {
                            data.downcast::<quinn::crypto::rustls::HandshakeData>().ok()
                        });
                        let sni = handshake
                            .as_ref()
                            .and_then(|data| data.server_name.as_deref())
                            .unwrap_or("")
                            .to_string();
                        let route_id = state.router.match_host(&sni);
                        let route = route_id.and_then(|id| state.routes.get(id));
                        debug!(
                            %peer,
                            sni = %display_sni(&sni),
                            route = route.map(|route| route.name.as_str()).unwrap_or("<unmatched>"),
                            "H3 QUIC handshake established"
                        );
                        let Some(route_id) = route_id else {
                            connection.close(0u32.into(), b"unmatched H3 SNI");
                            return;
                        };
                        let Some(route) = state.routes.get(route_id) else {
                            connection.close(0u32.into(), b"invalid H3 route");
                            return;
                        };
                        if !matches!(route.route_type, RouteType::H3 | RouteType::H3Ech) {
                            connection.close(0u32.into(), b"route is not HTTP/3");
                            return;
                        }
                        if let Err(error) =
                            h3_proxy::serve_inbound(connection, peer, state, route_id, sni).await
                        {
                            debug!(%peer, error = %format!("{error:#}"), "H3 connection failed");
                        }
                    }
                    Err(error) => {
                        debug!(%peer, error = %error, "H3 QUIC handshake failed");
                    }
                }
            });
        }
    });

    Ok(Some((endpoint, ingress)))
}

fn dispatch_to_h3(ingress: &QuicIngress, peer: SocketAddr, datagram: &[u8]) {
    if datagram.len() > ingress.max_datagram_size() {
        debug!(
            %peer,
            bytes = datagram.len(),
            max_bytes = ingress.max_datagram_size(),
            "dropping oversized QUIC datagram before H3 ingress"
        );
        return;
    }
    match ingress.try_send(peer, datagram) {
        Ok(()) => {}
        Err(TrySendError::Full(InboundDatagram { .. })) => {
            debug!(%peer, "dropping QUIC datagram because H3 dispatcher queue is full");
        }
        Err(TrySendError::Closed(InboundDatagram { .. })) => {
            debug!(%peer, "dropping QUIC datagram because H3 endpoint is closed");
        }
    }
}

struct RawFlowContext {
    listener: Arc<UdpSocket>,
    flows: Flows,
    flow_id: FlowId,
    route: Arc<RouteRuntime>,
    sni: String,
    packets: Vec<Vec<u8>>,
}

async fn spawn_raw_flow(
    listener: Arc<UdpSocket>,
    flows: Flows,
    flow_id: FlowId,
    route: Arc<RouteRuntime>,
    sni: String,
    packets: Vec<Vec<u8>>,
) {
    let peer = {
        let table = flows.lock().await;
        table.peer(flow_id)
    };
    let Some(peer) = peer else {
        return;
    };
    let (tx, rx) = mpsc::channel(FLOW_QUEUE);
    let (peer_tx, peer_rx) = watch::channel(peer);
    if !flows.lock().await.promote(flow_id, tx, peer_tx) {
        return;
    }

    let cleanup_flows = flows.clone();
    let context = RawFlowContext {
        listener,
        flows,
        flow_id,
        route,
        sni,
        packets,
    };
    tokio::spawn(async move {
        if let Err(error) = run_raw_flow(context, rx, peer_rx).await {
            debug!(flow_id, error = %format!("{error:#}"), "QUIC raw flow failed");
        }
        cleanup_flows.lock().await.remove(flow_id);
        debug!(flow_id, "QUIC raw flow closed");
    });
}

async fn run_raw_flow(
    context: RawFlowContext,
    mut rx: mpsc::Receiver<Vec<u8>>,
    peer_rx: watch::Receiver<SocketAddr>,
) -> Result<()> {
    let RawFlowContext {
        listener,
        flows,
        flow_id,
        route,
        sni,
        packets,
    } = context;
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

    let peer = *peer_rx.borrow();
    info!(flow_id, %peer, route = %route.name, upstream = %upstream_addr, "QUIC raw flow established");
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
                flows.lock().await.observe_upstream_datagram(flow_id, &buf[..n]);
                let current_peer = *peer_rx.borrow();
                listener.send_to(&buf[..n], current_peer).await?;
            },
            _ = tokio::time::sleep(idle), if !idle.is_zero() => {
                debug!(flow_id, route = %route.name, "QUIC raw flow idle timeout");
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

    fn long_header(version: u32, first: u8, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut packet = vec![first];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);
        packet
    }

    #[test]
    fn stale_initial_flows_are_pruned_but_forwarding_flows_remain() {
        let now = Instant::now();
        let stale = now - INITIAL_INSPECTION_TIMEOUT - Duration::from_millis(1);
        let mut flows = FlowTable::default();
        let stale_id = flows.insert_inspecting("127.0.0.1:1000".parse().unwrap(), stale, None);
        let live_id = flows.insert_inspecting("127.0.0.1:1001".parse().unwrap(), now, None);
        let forwarding_id = flows.insert_inspecting("127.0.0.1:1002".parse().unwrap(), now, None);
        let (tx, _rx) = mpsc::channel(1);
        let (peer_tx, _peer_rx) = watch::channel("127.0.0.1:1002".parse().unwrap());
        assert!(flows.promote(forwarding_id, tx, peer_tx));

        flows.prune_stale_inspecting(now);

        assert!(!flows.entries.contains_key(&stale_id));
        assert!(flows.entries.contains_key(&live_id));
        assert!(flows.entries.contains_key(&forwarding_id));
    }

    #[test]
    fn inspection_capacity_evicts_oldest_without_touching_forwarding() {
        let now = Instant::now();
        let mut flows = FlowTable::default();
        let forwarding_id = flows.insert_inspecting(
            "127.0.0.1:8000".parse().unwrap(),
            now - Duration::from_secs(60),
            None,
        );
        let (tx, _rx) = mpsc::channel(1);
        let (peer_tx, _peer_rx) = watch::channel("127.0.0.1:8000".parse().unwrap());
        assert!(flows.promote(forwarding_id, tx, peer_tx));

        let mut oldest = None;
        for index in 0..MAX_INSPECTING_FLOWS {
            let peer: SocketAddr = format!("127.0.0.1:{}", 10_000 + index).parse().unwrap();
            let id = flows.insert_inspecting(peer, now + Duration::from_millis(index as u64), None);
            oldest.get_or_insert(id);
        }
        assert_eq!(flows.inspecting_stats().0, MAX_INSPECTING_FLOWS);

        assert!(flows.make_room_for_inspecting());
        assert!(!flows.entries.contains_key(&oldest.unwrap()));
        assert!(flows.entries.contains_key(&forwarding_id));
        assert_eq!(flows.inspecting_stats().0, MAX_INSPECTING_FLOWS - 1);
    }

    #[test]
    fn inspection_byte_budget_evicts_oldest_inspecting() {
        let now = Instant::now();
        let mut flows = FlowTable::default();
        let id = flows.insert_inspecting("127.0.0.1:9000".parse().unwrap(), now, None);
        flows.inspecting_mut(id).unwrap().bytes = MAX_INSPECTION_BYTES;
        assert!(flows.make_room_for_inspecting());
        assert!(!flows.entries.contains_key(&id));
        assert_eq!(flows.inspecting_stats(), (0, 0));
    }

    #[test]
    fn known_server_cid_rebinds_forwarding_flow_to_new_peer() {
        let now = Instant::now();
        let old_peer: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let new_peer: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut flows = FlowTable::default();
        let id = flows.insert_inspecting(old_peer, now, Some(b"initial1"));
        let server_cid = b"server01";
        let response = long_header(QUIC_V1, 0xc0, b"client01", server_cid);
        flows.observe_upstream_datagram(id, &response);
        let (tx, _rx) = mpsc::channel(1);
        let (peer_tx, peer_rx) = watch::channel(old_peer);
        assert!(flows.promote(id, tx, peer_tx));

        let packet = long_header(QUIC_V1, 0xe0, server_cid, b"client02");
        assert_eq!(flows.flow_id_for(new_peer, &packet, true), Some(id));
        assert!(flows.migrate_peer(id, new_peer));
        assert_eq!(*peer_rx.borrow(), new_peer);
        assert_eq!(flows.unique_peer_owner(old_peer), None);
        assert_eq!(flows.unique_peer_owner(new_peer), Some(id));
    }

    #[test]
    fn unknown_initial_on_same_peer_is_not_misrouted_to_existing_flow() {
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let mut flows = FlowTable::default();
        let _ = flows.insert_inspecting(peer, now, Some(b"firstcid"));

        let second = long_header(QUIC_V1, 0xc0, b"secondid", b"client02");
        assert_eq!(flows.flow_id_for(peer, &second, true), None);
    }

    #[test]
    fn unknown_non_initial_long_header_does_not_peer_fallback() {
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:4500".parse().unwrap();
        let mut flows = FlowTable::default();
        let _ = flows.insert_inspecting(peer, now, Some(b"firstcid"));

        let unknown = long_header(QUIC_V1, 0xe0, b"invented", b"client03");
        assert_eq!(flows.flow_id_for(peer, &unknown, true), None);
    }

    #[test]
    fn client_initial_cid_is_not_eligible_for_short_header_matching() {
        let peer: SocketAddr = "127.0.0.1:4700".parse().unwrap();
        let mut flows = FlowTable::default();
        let _ = flows.insert_inspecting(peer, Instant::now(), Some(b"clientcid"));
        let mut short = vec![0x40];
        short.extend_from_slice(b"clientcid");
        short.extend_from_slice(b"ciphertext");
        assert_eq!(flows.short_header_owner(&short), None);
    }

    #[test]
    fn upstream_scid_routes_short_header_after_rebinding() {
        let now = Instant::now();
        let old_peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let new_peer: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let mut flows = FlowTable::default();
        let id = flows.insert_inspecting(old_peer, now, Some(b"initial1"));
        let server_cid = b"srv-short";
        let response = long_header(QUIC_V1, 0xc0, b"client03", server_cid);
        flows.observe_upstream_datagram(id, &response);

        let mut short = vec![0x40];
        short.extend_from_slice(server_cid);
        short.extend_from_slice(b"ciphertext");
        assert_eq!(flows.flow_id_for(new_peer, &short, true), Some(id));
    }

    #[test]
    fn learned_cids_are_bounded_per_flow() {
        let peer: SocketAddr = "127.0.0.1:6250".parse().unwrap();
        let mut flows = FlowTable::default();
        let id = flows.insert_inspecting(peer, Instant::now(), Some(b"initial1"));

        for value in 0u8..100 {
            let scid = [value; 8];
            let response = long_header(QUIC_V1, 0xc0, b"client04", &scid);
            flows.observe_upstream_datagram(id, &response);
        }

        let entry = flows.entries.get(&id).unwrap();
        assert_eq!(entry.routing_cids.len(), MAX_CIDS_PER_FLOW);
        assert_eq!(entry.short_cids.len(), MAX_CIDS_PER_FLOW - 1);
        assert_eq!(flows.routing_cids.len(), MAX_CIDS_PER_FLOW);
        assert_eq!(flows.short_cids.len(), MAX_CIDS_PER_FLOW - 1);
    }

    #[test]
    fn mixed_listener_does_not_peer_fallback_unknown_datagram_to_raw() {
        let peer: SocketAddr = "127.0.0.1:6500".parse().unwrap();
        let mut flows = FlowTable::default();
        let _ = flows.insert_inspecting(peer, Instant::now(), Some(b"raw-flow"));

        let unknown_short = [0x40, 0xaa, 0xbb, 0xcc];
        assert_eq!(flows.flow_id_for(peer, &unknown_short, false), None);
        assert!(flows.flow_id_for(peer, &unknown_short, true).is_some());
    }

    #[test]
    fn quic_v2_initial_is_recognized_as_a_new_flow_boundary() {
        let peer: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let mut flows = FlowTable::default();
        let _ = flows.insert_inspecting(peer, Instant::now(), Some(b"v2-first"));
        let second = long_header(QUIC_V2, 0xd0, b"v2-second", b"client04");
        let parsed = LongHeader::parse(&second).unwrap();
        assert!(parsed.is_initial());
        assert_eq!(flows.flow_id_for(peer, &second, true), None);
    }
}
