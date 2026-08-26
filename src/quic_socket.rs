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
use tokio::sync::mpsc;

pub const DISPATCH_QUEUE: usize = 1024;

#[derive(Debug)]
pub struct InboundDatagram {
    pub peer: SocketAddr,
    pub bytes: Vec<u8>,
}

/// The dispatcher-owned injection handle for Quinn-bound datagrams.
#[derive(Clone)]
pub struct QuicIngress {
    tx: mpsc::Sender<InboundDatagram>,
    max_datagram_size: usize,
}

impl QuicIngress {
    pub fn try_send(
        &self,
        peer: SocketAddr,
        bytes: &[u8],
    ) -> Result<(), mpsc::error::TrySendError<InboundDatagram>> {
        // Quinn sizes its receive buffers from EndpointConfig's maximum UDP
        // payload. Reject larger datagrams before copying them into the bounded
        // channel; otherwise an attacker-controlled packet can surface as a
        // fatal AsyncUdpSocket receive error and tear down the whole endpoint.
        if bytes.len() > self.max_datagram_size {
            return Err(mpsc::error::TrySendError::Full(InboundDatagram {
                peer,
                bytes: Vec::new(),
            }));
        }
        self.tx.try_send(InboundDatagram {
            peer,
            bytes: bytes.to_vec(),
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
    pub fn new(socket: Arc<UdpSocket>) -> io::Result<(Arc<Self>, QuicIngress)> {
        let state = UdpSocketState::new((&*socket).into())?;
        let (tx, rx) = mpsc::channel(DISPATCH_QUEUE);
        // start_h3_endpoint currently uses EndpointConfig::default() as well.
        // Derive the ingress cap from that config instead of baking in Quinn's
        // current default value so a dependency upgrade cannot silently drift.
        let max_datagram_size =
            quinn::EndpointConfig::default().get_max_udp_payload_size() as usize;
        Ok((
            Arc::new(Self {
                socket,
                state,
                rx: Mutex::new(rx),
            }),
            QuicIngress {
                tx,
                max_datagram_size,
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

    #[tokio::test]
    async fn ingress_is_exposed_as_one_quinn_receive() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (socket, ingress) = SharedQuicSocket::new(udp).unwrap();
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
        let (_socket, ingress) = SharedQuicSocket::new(udp).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let oversized = vec![0u8; ingress.max_datagram_size + 1];

        let error = ingress.try_send(peer, &oversized).unwrap_err();
        match error {
            mpsc::error::TrySendError::Full(datagram) => {
                assert_eq!(datagram.peer, peer);
                assert!(datagram.bytes.is_empty());
            }
            mpsc::error::TrySendError::Closed(_) => panic!("ingress unexpectedly closed"),
        }
    }

    #[tokio::test]
    async fn oversized_queued_datagram_does_not_kill_receive_path() {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (socket, ingress) = SharedQuicSocket::new(udp).unwrap();
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        ingress
            .tx
            .try_send(InboundDatagram {
                peer,
                bytes: vec![0u8; 65],
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
        let (socket, _ingress) = SharedQuicSocket::new(udp).unwrap();
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
}
