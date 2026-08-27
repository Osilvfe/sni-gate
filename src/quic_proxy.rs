//! QUIC listener, including raw SNI-routed UDP forwarding and H3 dispatch.

#[path = "h3_proxy.rs"]
mod h3_proxy;
#[path = "quic_runtime.rs"]
mod quic_runtime;
#[path = "quic_socket.rs"]
mod quic_socket;

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::{FailPolicy, RouteType};
use crate::proxy::{ListenerState, RouteRuntime};
use crate::quic_initial::{InitialInspector, InitialSni};
use quic_runtime::ByteBudget;
use quic_socket::{IngressSendError, QuicIngress, SharedQuicSocket};

const MAX_INITIAL_DATAGRAMS: usize = 8;
const MAX_INITIAL_BYTES: usize = 32 * 1024;
const MAX_FLOWS: usize = 4096;
const MAX_INSPECTING_FLOWS: usize = 256;
const MAX_INSPECTION_BYTES: usize = 8 * 1024 * 1024;
const MAX_CID_LEN: usize = 20;
const MAX_CIDS_PER_FLOW: usize = 32;
const MAX_INSPECTION_DEADLINE_ENTRIES: usize = MAX_INSPECTING_FLOWS * 4;
const INITIAL_INSPECTION_TIMEOUT: Duration = Duration::from_secs(10);
const FLOW_QUEUE: usize = 128;
const UDP_BUF: usize = 65_535;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;

type FlowId = u64;
type Flows = Arc<Mutex<FlowTable>>;

#[derive(Debug)]
struct QueuedDatagram {
    bytes: Vec<u8>,
    _queued_bytes: OwnedSemaphorePermit,
}

impl QueuedDatagram {
    fn reserve(bytes: Vec<u8>, budget: &ByteBudget) -> std::result::Result<Self, Vec<u8>> {
        let queued_bytes = match budget.try_acquire(bytes.len()) {
            Ok(permit) => permit,
            Err(_) => return Err(bytes),
        };
        Ok(Self {
            bytes,
            _queued_bytes: queued_bytes,
        })
    }
}

struct FlowTable {
    next_id: FlowId,
    entries: HashMap<FlowId, FlowEntry>,
    inspecting_count: usize,
    inspection_bytes: usize,
    inspection_deadlines: BinaryHeap<Reverse<(Instant, FlowId, u64)>>,
    peers: HashMap<SocketAddr, HashSet<FlowId>>,
    /// CIDs accepted for long-header lookup. This contains the client's one
    /// initial DCID plus server-issued SCIDs observed from the configured
    /// upstream. It is deliberately not expanded from arbitrary client packets.
    routing_cids: HashMap<Vec<u8>, HashSet<FlowId>>,
    /// Only server-issued CIDs are eligible for short-header matching. A
    /// client-chosen Initial DCID must never become a short-header prefix token.
    short_cids: HashMap<Vec<u8>, HashSet<FlowId>>,
    /// Number of active short-header CID keys at each legal length. This avoids
    /// probing lengths that cannot possibly match on every 1-RTT datagram.
    short_cid_lengths: [usize; MAX_CID_LEN + 1],
}

impl Default for FlowTable {
    fn default() -> Self {
        Self {
            next_id: 1,
            entries: HashMap::new(),
            inspecting_count: 0,
            inspection_bytes: 0,
            inspection_deadlines: BinaryHeap::new(),
            peers: HashMap::new(),
            routing_cids: HashMap::new(),
            short_cids: HashMap::new(),
            short_cid_lengths: [0; MAX_CID_LEN + 1],
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
        tx: mpsc::Sender<QueuedDatagram>,
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
    deadline_generation: u64,
}

impl InspectingFlow {
    fn new(now: Instant) -> Self {
        Self {
            inspector: InitialInspector::default(),
            packets: Vec::new(),
            bytes: 0,
            last_activity: now,
            deadline_generation: 0,
        }
    }

    fn push(&mut self, packet: &[u8], now: Instant) -> Result<(), ()> {
        if self.packets.len() == MAX_INITIAL_DATAGRAMS
            || self.bytes.saturating_add(packet.len()) > MAX_INITIAL_BYTES
        {
            return Err(());
        }
        self.last_activity = now;
        self.deadline_generation = self.deadline_generation.wrapping_add(1);
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

fn is_quic_initial(datagram: &[u8]) -> bool {
    LongHeader::parse(datagram).is_some_and(|header| header.is_initial())
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
            if self.short_cid_lengths[len] == 0 {
                continue;
            }
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
        self.inspecting_count += 1;
        self.schedule_inspection_deadline(id, now, 0);
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
            let owners = self.short_cids.entry(cid.to_vec()).or_default();
            if owners.is_empty() {
                self.short_cid_lengths[cid.len()] += 1;
            }
            owners.insert(id);
        }
    }

    /// A server long-header SCID is a CID the client can use as its future DCID.
    /// Version Negotiation is the exception: its SCID echoes the client's
    /// original DCID, so learning it would turn a client-chosen CID into a
    /// short-header routing token.
    fn observe_upstream_header(&mut self, id: FlowId, header: &LongHeader<'_>) {
        if header.version == 0 {
            return;
        }
        self.add_routing_cid(id, header.scid, true);
    }

    fn forwarding_sender(&self, id: FlowId) -> Option<mpsc::Sender<QueuedDatagram>> {
        match &self.entries.get(&id)?.state {
            FlowState::Forwarding { tx, .. } => Some(tx.clone()),
            FlowState::Inspecting(_) => None,
        }
    }

    fn inspecting_stats(&self) -> (usize, usize) {
        (self.inspecting_count, self.inspection_bytes)
    }

    fn schedule_inspection_deadline(&mut self, id: FlowId, activity: Instant, generation: u64) {
        self.inspection_deadlines.push(Reverse((
            activity + INITIAL_INSPECTION_TIMEOUT,
            id,
            generation,
        )));
        if self.inspection_deadlines.len() <= MAX_INSPECTION_DEADLINE_ENTRIES {
            return;
        }
        let entries = &self.entries;
        self.inspection_deadlines
            .retain(|Reverse((deadline, id, generation))| {
                entries.get(id).is_some_and(|entry| {
                    matches!(
                        &entry.state,
                        FlowState::Inspecting(flow)
                            if flow.deadline_generation == *generation
                                && flow.last_activity + INITIAL_INSPECTION_TIMEOUT == *deadline
                    )
                })
            });
    }

    fn inspect_datagram(&mut self, id: FlowId, datagram: &[u8], now: Instant) -> InspectResult {
        let Some(entry) = self.entries.get_mut(&id) else {
            return InspectResult::Invalid;
        };
        let FlowState::Inspecting(flow) = &mut entry.state else {
            return InspectResult::Invalid;
        };
        let before = flow.retained_bytes();
        let pushed = flow.push(datagram, now).is_ok();
        let inspection = if !pushed {
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
        };
        let after = flow.retained_bytes();
        let generation = flow.deadline_generation;
        self.inspection_bytes = self
            .inspection_bytes
            .saturating_sub(before)
            .saturating_add(after);
        if pushed {
            self.schedule_inspection_deadline(id, now, generation);
        }
        inspection
    }

    fn evict_oldest_inspecting(&mut self) -> bool {
        while let Some(Reverse((deadline, id, generation))) = self.inspection_deadlines.pop() {
            let is_current = self.entries.get(&id).is_some_and(|entry| {
                matches!(
                    &entry.state,
                    FlowState::Inspecting(flow)
                        if flow.deadline_generation == generation
                            && flow.last_activity + INITIAL_INSPECTION_TIMEOUT == deadline
                )
            });
            if is_current {
                self.remove(id);
                return true;
            }
        }
        false
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
        tx: mpsc::Sender<QueuedDatagram>,
        peer_tx: watch::Sender<SocketAddr>,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        if let FlowState::Inspecting(flow) = &entry.state {
            self.inspecting_count = self.inspecting_count.saturating_sub(1);
            self.inspection_bytes = self.inspection_bytes.saturating_sub(flow.retained_bytes());
        }
        entry.state = FlowState::Forwarding { tx, peer_tx };
        true
    }

    fn remove(&mut self, id: FlowId) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        if let FlowState::Inspecting(flow) = &entry.state {
            self.inspecting_count = self.inspecting_count.saturating_sub(1);
            self.inspection_bytes = self.inspection_bytes.saturating_sub(flow.retained_bytes());
        }
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
                self.short_cid_lengths[cid.len()] =
                    self.short_cid_lengths[cid.len()].saturating_sub(1);
            }
        }
    }

    fn prune_stale_inspecting(&mut self, now: Instant) {
        while let Some(Reverse((deadline, id, generation))) =
            self.inspection_deadlines.peek().copied()
        {
            if deadline > now {
                break;
            }
            self.inspection_deadlines.pop();
            let is_current = self.entries.get(&id).is_some_and(|entry| {
                matches!(
                    &entry.state,
                    FlowState::Inspecting(flow)
                        if flow.deadline_generation == generation
                            && flow.last_activity + INITIAL_INSPECTION_TIMEOUT == deadline
                )
            });
            if is_current {
                self.remove(id);
            }
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
    let limits = quic_runtime::init_from_env().context("loading QUIC runtime limits")?;
    let raw_forwarding_budget = quic_runtime::raw_forwarding_byte_budget();
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
    let h3_only = h3_ingress.is_some()
        && state
            .routes
            .iter()
            .all(|route| matches!(route.route_type, RouteType::H3 | RouteType::H3Ech));
    info!(
        addr = %state.addr,
        routes = state.routes.len(),
        h3 = h3_ingress.is_some(),
        h3_fast_path = h3_only,
        max_pending_h3_handshakes = limits.max_pending_handshakes,
        max_h3_connections = limits.max_h3_connections,
        max_h3_ingress_bytes = limits.max_h3_ingress_bytes,
        max_raw_flows = limits.max_raw_flows,
        max_pending_raw_connects = limits.max_pending_raw_connects,
        max_raw_forwarding_bytes = limits.max_raw_forwarding_bytes,
        "QUIC listening"
    );

    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, peer) = listener.recv_from(&mut buf).await?;
        let datagram = &buf[..n];

        // On a pure terminating-H3 listener, only Initial packets need the
        // stateless SNI inspector. Every other QUIC packet belongs to Quinn, so
        // bypass the shared raw-flow table entirely. Mixed raw+H3 listeners keep
        // the conservative CID ownership path below.
        if h3_only && !is_quic_initial(datagram) {
            if let Some(ingress) = &h3_ingress {
                dispatch_to_h3(ingress, peer, datagram);
            }
            continue;
        }

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
                let inspection = table.inspect_datagram(id, datagram, now);

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
            let queued = match QueuedDatagram::reserve(datagram.to_vec(), &raw_forwarding_budget) {
                Ok(queued) => queued,
                Err(_) => {
                    debug!(
                        %peer,
                        flow_id,
                        bytes = datagram.len(),
                        max_bytes = raw_forwarding_budget.capacity(),
                        "dropping QUIC datagram because raw forwarding byte budget is exhausted"
                    );
                    continue;
                }
            };
            match tx.try_send(queued) {
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
                    raw_forwarding_budget.clone(),
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

fn h3_transport_idle_timeout<I>(routes: I) -> Option<Duration>
where
    I: IntoIterator<Item = (RouteType, Duration)>,
{
    let mut maximum = None;
    for (route_type, idle) in routes {
        if !matches!(route_type, RouteType::H3 | RouteType::H3Ech) {
            continue;
        }
        if idle.is_zero() {
            return None;
        }
        maximum = Some(maximum.map_or(idle, |current: Duration| current.max(idle)));
    }
    maximum
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
    let mut transport_config = quinn::TransportConfig::default();
    let transport_idle = h3_transport_idle_timeout(
        state
            .routes
            .iter()
            .map(|route| (route.route_type, route.idle_timeout)),
    );
    if let Some(idle) = transport_idle {
        transport_config.max_idle_timeout(Some(
            idle.try_into()
                .context("converting H3 listener idle timeout to QUIC transport units")?,
        ));
    } else {
        transport_config.max_idle_timeout(None);
    }
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(transport_config));
    let endpoint_config = quic_socket::h3_endpoint_config()
        .context("configuring shared Quinn endpoint receive limit")?;
    let max_datagram_size = endpoint_config.get_max_udp_payload_size() as usize;
    let (socket, ingress) = SharedQuicSocket::new(
        listener,
        max_datagram_size,
        quic_runtime::h3_ingress_byte_budget(),
    )
    .context("initializing shared Quinn UDP socket")?;
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("creating shared Quinn endpoint")?;

    let accept_endpoint = endpoint.clone();
    let max_pending_handshakes = quic_runtime::limits().max_pending_handshakes;
    let handshake_limit = quic_runtime::inbound_handshake_limit();
    tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            let handshake_permit = match handshake_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let peer = incoming.remote_address();
                    if !incoming.remote_address_validated() {
                        match incoming.retry() {
                            Ok(()) => {
                                debug!(
                                    %peer,
                                    max_pending = max_pending_handshakes,
                                    "sent QUIC Retry because H3 handshake capacity is exhausted"
                                );
                            }
                            Err(error) => {
                                error.into_incoming().refuse();
                                debug!(
                                    %peer,
                                    max_pending = max_pending_handshakes,
                                    "refused QUIC handshake after Retry became unavailable"
                                );
                            }
                        }
                    } else {
                        incoming.refuse();
                        debug!(
                            %peer,
                            max_pending = max_pending_handshakes,
                            "refused validated QUIC handshake because H3 handshake capacity is exhausted"
                        );
                    }
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                let peer = incoming.remote_address();
                let established = incoming.await;
                drop(handshake_permit);
                match established {
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
                        let diagnostics = connection.clone();
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
        Err(IngressSendError::Oversized) => {
            debug!(%peer, "dropping oversized QUIC datagram before H3 ingress");
        }
        Err(IngressSendError::ByteBudgetExhausted) => {
            debug!(
                %peer,
                bytes = datagram.len(),
                "dropping QUIC datagram because process-wide H3 ingress byte budget is exhausted"
            );
        }
        Err(IngressSendError::QueueFull) => {
            debug!(%peer, "dropping QUIC datagram because H3 dispatcher queue is full");
        }
        Err(IngressSendError::Closed) => {
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
    packets: Vec<QueuedDatagram>,
    _flow_permit: OwnedSemaphorePermit,
    connect_permit: OwnedSemaphorePermit,
}

async fn spawn_raw_flow(
    listener: Arc<UdpSocket>,
    flows: Flows,
    flow_id: FlowId,
    route: Arc<RouteRuntime>,
    sni: String,
    packets: Vec<Vec<u8>>,
    byte_budget: Arc<ByteBudget>,
) {
    let flow_permit = match quic_runtime::raw_flow_limit().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            flows.lock().await.remove(flow_id);
            debug!(
                flow_id,
                max_raw_flows = quic_runtime::limits().max_raw_flows,
                "dropping QUIC raw flow because process-wide active flow capacity is exhausted"
            );
            return;
        }
    };
    let connect_permit = match quic_runtime::raw_connect_limit().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            flows.lock().await.remove(flow_id);
            debug!(
                flow_id,
                max_pending = quic_runtime::limits().max_pending_raw_connects,
                "dropping QUIC raw flow because upstream setup capacity is exhausted"
            );
            return;
        }
    };

    let mut reserved_packets = Vec::with_capacity(packets.len());
    for packet in packets {
        match QueuedDatagram::reserve(packet, &byte_budget) {
            Ok(packet) => reserved_packets.push(packet),
            Err(packet) => {
                flows.lock().await.remove(flow_id);
                debug!(
                    flow_id,
                    bytes = packet.len(),
                    max_bytes = byte_budget.capacity(),
                    "dropping QUIC raw flow because forwarding byte budget is exhausted during upstream setup"
                );
                return;
            }
        }
    }
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
        packets: reserved_packets,
        _flow_permit: flow_permit,
        connect_permit,
    };
    tokio::spawn(async move {
        if let Err(error) = run_raw_flow(context, rx, peer_rx).await {
            debug!(flow_id, error = %format!("{error:#}"), "QUIC raw flow failed");
        }
        cleanup_flows.lock().await.remove(flow_id);
        debug!(flow_id, "QUIC raw flow closed");
    });
}

async fn send_to_current_raw_peer(
    listener: &UdpSocket,
    peer_rx: &watch::Receiver<SocketAddr>,
    datagram: &[u8],
) -> Result<SocketAddr> {
    let peer = *peer_rx.borrow();
    listener.send_to(datagram, peer).await?;
    Ok(peer)
}

async fn run_raw_flow(
    context: RawFlowContext,
    mut rx: mpsc::Receiver<QueuedDatagram>,
    peer_rx: watch::Receiver<SocketAddr>,
) -> Result<()> {
    let RawFlowContext {
        listener,
        flows,
        flow_id,
        route,
        sni,
        packets,
        _flow_permit,
        connect_permit,
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
    let upstream_addrs = route
        .addr_resolver
        .lookup_addrs(
            &host,
            route.upstream_port,
            route.address_family,
            route.nat64.as_ref(),
        )
        .await
        .with_context(|| format!("resolving QUIC upstream {host}"))?;

    // UDP connect alone cannot prove that an address is reachable. Race the
    // complete initial exchange instead: each staggered candidate receives the
    // buffered client flight and the first upstream response selects the path.
    // Losing sockets are dropped, so later packets go to exactly one upstream.
    let packets = &packets;
    let ((upstream, first_response), upstream_addr) = crate::connect::race(
        &upstream_addrs,
        route.connect_timeout,
        move |upstream_addr| async move {
            let bind = match upstream_addr.ip() {
                IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let upstream = UdpSocket::bind(bind).await?;
            upstream.connect(upstream_addr).await?;
            for packet in packets {
                upstream.send(&packet.bytes).await?;
            }
            let mut response = vec![0u8; UDP_BUF];
            let n = upstream.recv(&mut response).await?;
            response.truncate(n);
            Ok((upstream, response))
        },
    )
    .await?;
    drop(connect_permit);

    if let Some(header) = LongHeader::parse(&first_response) {
        flows.lock().await.observe_upstream_header(flow_id, &header);
    }
    // The client may have rebound while DNS/Happy Eyeballs was in progress.
    // Read the watch channel only after upstream setup so the first response is
    // sent to the same latest peer used by every later response.
    let peer = send_to_current_raw_peer(&listener, &peer_rx, &first_response).await?;
    info!(flow_id, %peer, route = %route.name, upstream = %upstream_addr, "QUIC raw flow established");
    let idle = route.idle_timeout;
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        tokio::select! {
            packet = rx.recv() => match packet {
                Some(packet) => upstream.send(&packet.bytes).await.map(|_| ())?,
                None => break,
            },
            received = upstream.recv(&mut buf) => {
                let n = received?;
                if let Some(header) = LongHeader::parse(&buf[..n]) {
                    flows.lock().await.observe_upstream_header(flow_id, &header);
                }
                send_to_current_raw_peer(&listener, &peer_rx, &buf[..n]).await?;
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
    fn h3_fast_path_keeps_initial_packets_on_inspection_path() {
        let v1_initial = long_header(QUIC_V1, 0xc0, b"v1initial", b"client01");
        let v2_initial = long_header(QUIC_V2, 0xd0, b"v2initial", b"client02");
        let v1_handshake = long_header(QUIC_V1, 0xe0, b"handshake", b"client03");
        let short_header = [0x40, 0xaa, 0xbb, 0xcc];

        assert!(is_quic_initial(&v1_initial));
        assert!(is_quic_initial(&v2_initial));
        assert!(!is_quic_initial(&v1_handshake));
        assert!(!is_quic_initial(&short_header));
    }

    #[test]
    fn h3_transport_idle_uses_longest_terminating_route() {
        assert_eq!(
            h3_transport_idle_timeout([
                (RouteType::Raw, Duration::from_secs(120)),
                (RouteType::H3, Duration::from_secs(10)),
                (RouteType::H3Ech, Duration::from_secs(45)),
            ]),
            Some(Duration::from_secs(45))
        );
    }

    #[test]
    fn zero_h3_idle_disables_listener_transport_timeout() {
        assert_eq!(
            h3_transport_idle_timeout([
                (RouteType::H3, Duration::from_secs(60)),
                (RouteType::H3Ech, Duration::ZERO),
            ]),
            None
        );
    }

    #[tokio::test]
    async fn raw_response_uses_latest_migrated_peer() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (peer_tx, peer_rx) = watch::channel(old_peer.local_addr().unwrap());
        peer_tx.send(new_peer.local_addr().unwrap()).unwrap();

        let selected = send_to_current_raw_peer(&sender, &peer_rx, b"reply")
            .await
            .unwrap();
        assert_eq!(selected, new_peer.local_addr().unwrap());

        let mut buf = [0u8; 16];
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(1), new_peer.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(source, sender.local_addr().unwrap());
    }

    #[test]
    fn raw_forwarding_budget_tracks_queued_datagram_lifetime() {
        let budget = ByteBudget::new(4);
        let queued = QueuedDatagram::reserve(b"four".to_vec(), &budget).unwrap();
        assert_eq!(budget.available(), 0);
        assert!(QueuedDatagram::reserve(b"x".to_vec(), &budget).is_err());

        drop(queued);
        assert_eq!(budget.available(), 4);
        assert!(QueuedDatagram::reserve(b"x".to_vec(), &budget).is_ok());
    }

    #[test]
    fn dropping_raw_flow_queue_releases_all_queued_bytes() {
        let budget = ByteBudget::new(8);
        let (tx, rx) = mpsc::channel(2);
        tx.try_send(QueuedDatagram::reserve(b"four".to_vec(), &budget).unwrap())
            .unwrap();
        tx.try_send(QueuedDatagram::reserve(b"more".to_vec(), &budget).unwrap())
            .unwrap();
        assert_eq!(budget.available(), 0);

        drop(rx);
        assert_eq!(budget.available(), 8);
    }

    #[test]
    fn full_raw_flow_queue_releases_rejected_datagram_bytes() {
        let budget = ByteBudget::new(3);
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(QueuedDatagram::reserve(b"x".to_vec(), &budget).unwrap())
            .unwrap();
        assert_eq!(budget.available(), 2);

        let error = tx
            .try_send(QueuedDatagram::reserve(b"y".to_vec(), &budget).unwrap())
            .unwrap_err();
        drop(error);
        assert_eq!(budget.available(), 2);

        drop(rx);
        assert_eq!(budget.available(), 3);
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
    fn refreshed_inspection_deadline_ignores_stale_heap_entry() {
        let now = Instant::now();
        let initial = now - INITIAL_INSPECTION_TIMEOUT - Duration::from_millis(1);
        let mut flows = FlowTable::default();
        let id = flows.insert_inspecting("127.0.0.1:1500".parse().unwrap(), initial, None);

        let _ = flows.inspect_datagram(id, b"partial", now);
        flows.prune_stale_inspecting(now);
        assert!(flows.entries.contains_key(&id));
        assert_eq!(flows.inspecting_stats().0, 1);

        flows.prune_stale_inspecting(now + INITIAL_INSPECTION_TIMEOUT);
        assert!(!flows.entries.contains_key(&id));
        assert_eq!(flows.inspecting_stats(), (0, 0));
    }

    #[test]
    fn inspection_counters_update_on_buffer_promote_and_remove() {
        let now = Instant::now();
        let mut flows = FlowTable::default();
        let first = flows.insert_inspecting("127.0.0.1:1600".parse().unwrap(), now, None);
        let second = flows.insert_inspecting("127.0.0.1:1601".parse().unwrap(), now, None);
        assert_eq!(flows.inspecting_stats(), (2, 0));

        let _ = flows.inspect_datagram(first, b"partial", now + Duration::from_millis(1));
        assert_eq!(flows.inspecting_stats(), (2, b"partial".len()));

        let (tx, _rx) = mpsc::channel(1);
        let (peer_tx, _peer_rx) = watch::channel("127.0.0.1:1600".parse().unwrap());
        assert!(flows.promote(first, tx, peer_tx));
        assert_eq!(flows.inspecting_stats(), (1, 0));

        flows.remove(second);
        assert_eq!(flows.inspecting_stats(), (0, 0));
    }

    #[test]
    fn stale_deadline_entries_are_compacted_under_flow_churn() {
        let now = Instant::now();
        let mut flows = FlowTable::default();
        for index in 0..=MAX_INSPECTION_DEADLINE_ENTRIES {
            let peer: SocketAddr = format!("127.0.0.1:{}", 20_000 + index).parse().unwrap();
            let id = flows.insert_inspecting(peer, now, None);
            flows.remove(id);
        }

        assert!(flows.inspection_deadlines.len() <= MAX_INSPECTION_DEADLINE_ENTRIES);
        assert_eq!(flows.inspecting_stats(), (0, 0));
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
        let FlowState::Inspecting(flow) = &mut flows.entries.get_mut(&id).unwrap().state else {
            unreachable!();
        };
        flow.bytes = MAX_INSPECTION_BYTES;
        flows.inspection_bytes = MAX_INSPECTION_BYTES;
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
        let header = LongHeader::parse(&response).unwrap();
        flows.observe_upstream_header(id, &header);
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
    fn version_negotiation_scid_is_not_learned_as_a_short_header_cid() {
        let peer: SocketAddr = "127.0.0.1:4800".parse().unwrap();
        let mut flows = FlowTable::default();
        let client_initial_dcid = b"clientcid";
        let id = flows.insert_inspecting(peer, Instant::now(), Some(client_initial_dcid));

        // A Version Negotiation packet reverses the client's Initial CID pair:
        // the server SCID is the client's original DCID, not a server-issued CID.
        let version_negotiation = long_header(0, 0x80, b"clientsci", client_initial_dcid);
        let header = LongHeader::parse(&version_negotiation).unwrap();
        flows.observe_upstream_header(id, &header);

        let entry = flows.entries.get(&id).unwrap();
        assert_eq!(entry.routing_cids.len(), 1);
        assert!(entry.short_cids.is_empty());
        assert_eq!(flows.short_cid_lengths[client_initial_dcid.len()], 0);

        let mut short = vec![0x40];
        short.extend_from_slice(client_initial_dcid);
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
        let header = LongHeader::parse(&response).unwrap();
        flows.observe_upstream_header(id, &header);

        let mut short = vec![0x40];
        short.extend_from_slice(server_cid);
        short.extend_from_slice(b"ciphertext");
        assert_eq!(flows.flow_id_for(new_peer, &short, true), Some(id));
        assert_eq!(flows.short_cid_lengths[server_cid.len()], 1);
        flows.remove(id);
        assert_eq!(flows.short_cid_lengths[server_cid.len()], 0);
    }

    #[test]
    fn learned_cids_are_bounded_per_flow() {
        let peer: SocketAddr = "127.0.0.1:6250".parse().unwrap();
        let mut flows = FlowTable::default();
        let id = flows.insert_inspecting(peer, Instant::now(), Some(b"initial1"));

        for value in 0u8..100 {
            let scid = [value; 8];
            let response = long_header(QUIC_V1, 0xc0, b"client04", &scid);
            let header = LongHeader::parse(&response).unwrap();
            flows.observe_upstream_header(id, &header);
        }

        let entry = flows.entries.get(&id).unwrap();
        assert_eq!(entry.routing_cids.len(), MAX_CIDS_PER_FLOW);
        assert_eq!(entry.short_cids.len(), MAX_CIDS_PER_FLOW - 1);
        assert_eq!(flows.routing_cids.len(), MAX_CIDS_PER_FLOW);
        assert_eq!(flows.short_cids.len(), MAX_CIDS_PER_FLOW - 1);
    }

    #[test]
    fn shared_short_cid_length_stays_active_until_last_key_is_removed() {
        let now = Instant::now();
        let mut flows = FlowTable::default();
        let first = flows.insert_inspecting("127.0.0.1:6300".parse().unwrap(), now, None);
        let second = flows.insert_inspecting("127.0.0.1:6301".parse().unwrap(), now, None);
        let response = long_header(QUIC_V1, 0xc0, b"client05", b"same-cid");
        let header = LongHeader::parse(&response).unwrap();
        flows.observe_upstream_header(first, &header);
        flows.observe_upstream_header(second, &header);
        assert_eq!(flows.short_cid_lengths[8], 1);

        flows.remove(first);
        assert_eq!(flows.short_cid_lengths[8], 1);
        flows.remove(second);
        assert_eq!(flows.short_cid_lengths[8], 0);
    }

    #[test]
    #[ignore = "manual release-mode FlowTable microbenchmark"]
    fn benchmark_flow_table_short_header_lookup() {
        const FLOWS: usize = 4096;
        const LOOKUPS: usize = 1_000_000;

        let now = Instant::now();
        let mut flows = FlowTable::default();
        let mut target = Vec::new();
        for index in 0..FLOWS {
            let peer = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                u16::try_from(10_000 + index).unwrap(),
            );
            let id = flows.insert_inspecting(peer, now, None);
            let cid = (index as u64).to_be_bytes();
            let response = long_header(QUIC_V1, 0xc0, b"client06", &cid);
            let header = LongHeader::parse(&response).unwrap();
            flows.observe_upstream_header(id, &header);
            let (tx, _rx) = mpsc::channel(1);
            let (peer_tx, _peer_rx) = watch::channel(peer);
            assert!(flows.promote(id, tx, peer_tx));
            if index + 1 == FLOWS {
                target.push(0x40);
                target.extend_from_slice(&cid);
                target.extend_from_slice(b"ciphertext");
            }
        }

        let started = std::time::Instant::now();
        for _ in 0..LOOKUPS {
            std::hint::black_box(flows.short_header_owner(std::hint::black_box(&target)));
        }
        let elapsed = started.elapsed();
        eprintln!(
            "FlowTable short-header lookup: {LOOKUPS} operations over {FLOWS} flows in {elapsed:?} ({:.1} ns/op)",
            elapsed.as_nanos() as f64 / LOOKUPS as f64
        );
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
