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
}

impl QuicIngress {
    pub fn try_send(
        &self,
        peer: SocketAddr,
        bytes: &[u8],
    ) -> Result<(), mpsc::error::TrySendError<InboundDatagram>> {
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
        Ok((
            Arc::new(Self {
                socket,
                state,
                rx: Mutex::new(rx),
            }),
            QuicIngress { tx },
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
                return Poll::Ready(Err(io::Error::other(
                    "shared QUIC receive queue poisoned",
                )))
            }
        };
        match Pin::new(&mut *rx).poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "shared QUIC dispatcher closed",
            ))),
            Poll::Ready(Some(datagram)) => {
                let capacity = bufs[0].len();
                if datagram.bytes.len() > capacity {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "QUIC datagram of {} bytes exceeds receive buffer of {capacity} bytes",
                            datagram.bytes.len()
                        ),
                    )));
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
                Poll::Ready(Ok(1))
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
