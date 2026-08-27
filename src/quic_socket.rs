//! Quinn socket adapter fed by the shared UDP dispatcher.
//!
//! Only the dispatcher receives from the real UDP socket. Datagrams selected
//! for terminated QUIC/H3 are injected here, while Quinn's writes go straight
//! back through that same socket. This prevents two independent receivers from
//! racing on one UDP port.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, OwnedSemaphorePermit};

use super::quic_runtime::ByteBudget;

pub const DISPATCH_QUEUE: usize = 1024;
/// Receive contract shared by the dispatcher and Quinn endpoint.
/// RFC 9000 allows max_udp_payload_size up to 65,527 bytes. Quinn's
/// 1,472-byte default is a conservative Ethernet-MTU choice, not a
/// protocol validity limit; loopback/jumbo paths can legitimately
/// deliver larger datagrams before transport parameters are known.
pub const H3_MAX_UDP_PAYLOAD_SIZE: u16 = 65_527;

pub fn h3_endpoint_config() -> io::Result<quinn::EndpointConfig> {
    let mut config = quinn::EndpointConfig::default();
    config
        .max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    Ok(config)
}

#[derive(Debug)]
pub struct InboundDatagram {
    pub peer: SocketAddr,
    pub bytes: Vec<u8>,
    _queued_bytes: Option<OwnedSemaphorePermit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressSendError {
    Oversized,
    ByteBudgetExhausted,
    QueueFull,
    Closed,
}

/// The dispatcher-owned injection handle for Quinn-bound datagrams.
#[derive(Clone)]
pub struct QuicIngress {
    tx: mpsc::Sender<InboundDatagram>,
    max_datagram_size: usize,
    byte_budget: Arc<ByteBudget>,
}

impl QuicIngress {
    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn try_send(&self, peer: SocketAddr, bytes: &[u8]) -> Result<(), IngressSendError> {
        // Quinn sizes its receive buffers from EndpointConfig's maximum UDP
        // payload. Reject larger datagrams before copying them into the bounded
        // channel; otherwise an attacker-controlled packet can surface as a
        // fatal AsyncUdpSocket receive error and tear down the whole endpoint.
        if bytes.len() > self.max_datagram_size {
            return Err(IngressSendError::Oversized);
        }
        let queued_bytes = self
            .byte_budget
            .try_acquire(bytes.len())
            .map_err(|_| IngressSendError::ByteBudgetExhausted)?;
        self.tx
            .try_send(InboundDatagram {
                peer,
                bytes: bytes.to_vec(),
                _queued_bytes: Some(queued_bytes),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => IngressSendError::QueueFull,
                mpsc::error::TrySendError::Closed(_) => IngressSendError::Closed,
            })
    }
}

/// A virtual UDP socket for Quinn. Receive readiness is driven by the ingress
/// channel; send readiness comes from the shared Tokio UDP socket.
pub struct SharedQuicSocket {
    socket: Arc<UdpSocket>,
    state: UdpSocketState,
    rx: Mutex<mpsc::Receiver<InboundDatagram>>,
}

impl SharedQuicSocket {
    pub fn new(
        socket: Arc<UdpSocket>,
        max_datagram_size: usize,
        byte_budget: Arc<ByteBudget>,
    ) -> io::Result<(Arc<Self>, QuicIngress)> {
        let state = UdpSocketState::new((&*socket).into())?;
        let (tx, rx) = mpsc::channel(DISPATCH_QUEUE);
        Ok((
            Arc::new(Self {
                socket,
                state,
                rx: Mutex::new(rx),
            }),
            QuicIngress {
                tx,
                max_datagram_size,
                byte_budget,
            },
        ))
    }
}

impl fmt::Debug for SharedQuicSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedQuicSocket")
            .field("local_addr", &self.socket.local_addr())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for SharedQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SharedUdpPoller {
            socket: self.socket.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.state.send((&*self.socket).into(), transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut rx = match self.rx.lock() {
            Ok(rx) => rx,
            Err(_) => {
                return Poll::Ready(Err(io::Error::other("shared QUIC receive queue poisoned")))
            }
        };
        loop {
            match Pin::new(&mut *rx).poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "shared QUIC dispatcher closed",
                    )))
                }
                Poll::Ready(Some(datagram)) => {
                    let capacity = bufs[0].len();
                    if datagram.bytes.len() > capacity {
                        // Defense in depth: try_send() prevents this in normal
                        // operation, but a size mismatch must never become a
                        // socket-level error because Quinn treats that as a
                        // fatal endpoint failure. Model a real UDP receive path
                        // by dropping the one offending datagram and continuing.
                        continue;
                    }
                    bufs[0][..datagram.bytes.len()].copy_from_slice(&datagram.bytes);
                    meta[0] = RecvMeta {
                        addr: datagram.peer,
                        len: datagram.bytes.len(),
                        stride: datagram.bytes.len(),
                        ecn: None,
                        // recv_from() does not expose the destination address
                        // on wildcard binds. None lets Quinn avoid assuming one.
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
}

struct SharedUdpPoller {
    socket: Arc<UdpSocket>,
}

impl fmt::Debug for SharedUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedUdpPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for SharedUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    fn ingress_budget() -> Arc<ByteBudget> {
        Arc::new(ByteBudget::new(1024 * 1024))
    }

    #[tokio::test]
    async fn ingress_is_exposed_as_one_quinn_receive() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (socket, ingress) =
            SharedQuicSocket::new(udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, ingress_budget()).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        ingress.try_send(peer, b"quic-packet").unwrap();

        let mut storage = [0u8; 64];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let count = poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(&storage[..meta[0].len], b"quic-packet");
        assert_eq!(meta[0].addr, peer);
        assert_eq!(meta[0].stride, b"quic-packet".len());
    }

    #[tokio::test]
    async fn oversized_ingress_is_rejected_before_allocation() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let budget = ingress_budget();
        let before = budget.available();
        let (_socket, ingress) =
            SharedQuicSocket::new(udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, budget.clone()).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let oversized = vec![0u8; ingress.max_datagram_size + 1];

        assert_eq!(
            ingress.try_send(peer, &oversized),
            Err(IngressSendError::Oversized)
        );
        assert_eq!(budget.available(), before);
    }

    #[tokio::test]
    async fn oversized_queued_datagram_does_not_kill_receive_path() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let budget = ingress_budget();
        let (socket, ingress) =
            SharedQuicSocket::new(udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, budget.clone()).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let queued_bytes = budget.try_acquire(65).unwrap();
        ingress
            .tx
            .try_send(InboundDatagram {
                peer,
                bytes: vec![0u8; 65],
                _queued_bytes: Some(queued_bytes),
            })
            .unwrap();
        ingress.try_send(peer, b"good").unwrap();

        let mut storage = [0u8; 64];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        let count = poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(&storage[..meta[0].len], b"good");
    }

    #[tokio::test]
    async fn outbound_transmit_uses_the_shared_socket() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let (socket, _ingress) =
            SharedQuicSocket::new(udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, ingress_budget()).unwrap();
        let transmit = Transmit {
            destination,
            ecn: None,
            contents: b"reply",
            segment_size: None,
            src_ip: None,
        };
        socket.try_send(&transmit).unwrap();

        let mut buf = [0u8; 16];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply");
    }

    #[tokio::test]
    async fn ingress_byte_budget_is_released_after_receive() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let budget = Arc::new(ByteBudget::new(4));
        let (socket, ingress) =
            SharedQuicSocket::new(udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, budget.clone()).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        ingress.try_send(peer, b"four").unwrap();
        assert_eq!(budget.available(), 0);
        assert_eq!(
            ingress.try_send(peer, b"x"),
            Err(IngressSendError::ByteBudgetExhausted)
        );

        let mut storage = [0u8; 8];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta::default()];
        poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        assert_eq!(budget.available(), 4);
        ingress.try_send(peer, b"x").unwrap();
    }

    #[tokio::test]
    async fn closed_ingress_releases_reserved_bytes() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let budget = Arc::new(ByteBudget::new(4));
        let (socket, ingress) =
            SharedQuicSocket::new(udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, budget.clone()).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        drop(socket);

        assert_eq!(
            ingress.try_send(peer, b"four"),
            Err(IngressSendError::Closed)
        );
        assert_eq!(budget.available(), 4);
    }

    #[tokio::test]
    async fn full_ingress_queue_releases_rejected_datagram_bytes() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let budget = Arc::new(ByteBudget::new(DISPATCH_QUEUE + 1));
        let (socket, ingress) =
            SharedQuicSocket::new(udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, budget.clone()).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        for _ in 0..DISPATCH_QUEUE {
            ingress.try_send(peer, b"x").unwrap();
        }
        assert_eq!(budget.available(), 1);
        assert_eq!(
            ingress.try_send(peer, b"x"),
            Err(IngressSendError::QueueFull)
        );
        assert_eq!(budget.available(), 1);

        drop(socket);
        assert_eq!(budget.available(), DISPATCH_QUEUE + 1);
    }

    #[tokio::test]
    async fn ingress_budget_is_shared_across_virtual_sockets() {
        let first_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let second_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let budget = Arc::new(ByteBudget::new(4));
        let (first_socket, first) =
            SharedQuicSocket::new(first_udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, budget.clone())
                .unwrap();
        let (_second_socket, second) =
            SharedQuicSocket::new(second_udp, H3_MAX_UDP_PAYLOAD_SIZE as usize, budget.clone())
                .unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        first.try_send(peer, b"four").unwrap();
        assert_eq!(
            second.try_send(peer, b"x"),
            Err(IngressSendError::ByteBudgetExhausted)
        );
        drop(first_socket);
        assert_eq!(budget.available(), 4);
        second.try_send(peer, b"x").unwrap();
    }
}
