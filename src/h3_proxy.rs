//! HTTP/3 semantic proxy data path.
//!
//! The shared UDP dispatcher and Quinn own transport demultiplexing. This
//! module starts at an already-established inbound QUIC connection and handles
//! HTTP/3 request semantics. Request authority is re-routed per stream so H3
//! connection coalescing can never bypass the listener's route boundaries.

#[path = "upstream_certs.rs"]
mod upstream_certs;

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Buf;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::{RouteType, SniPolicy};
use crate::proxy::{ListenerState, RouteRuntime};
use crate::resolver::DynamicResolver;

pub async fn serve_inbound(
    connection: quinn::Connection,
    peer: SocketAddr,
    state: Arc<ListenerState>,
    handshake_route: usize,
    handshake_sni: String,
) -> Result<()> {
    let route = state
        .routes
        .get(handshake_route)
        .cloned()
        .ok_or_else(|| anyhow!("invalid H3 route index {handshake_route}"))?;

    let upstream = connect_upstream_h3(&route, &handshake_sni, peer, &state.cert_resolver).await?;

    let quic = h3_quinn::Connection::new(connection);
    let mut inbound = h3::server::Connection::new(quic)
        .await
        .context("starting inbound HTTP/3 connection")?;

    while let Some(resolver) = inbound.accept().await.context("accepting HTTP/3 request")? {
        let state = state.clone();
        let sni = handshake_sni.clone();
        let route = route.clone();
        let mut sender = upstream.sender.clone();
        tokio::spawn(async move {
            let result = async {
                let (request, stream) = resolver
                    .resolve_request()
                    .await
                    .context("resolving HTTP/3 request headers")?;

                let authority = request
                    .uri()
                    .authority()
                    .map(|authority| authority.host())
                    .unwrap_or(sni.as_str());
                let request_route = state.router.match_host(authority);
                if request_route != Some(handshake_route) {
                    debug!(
                        %peer,
                        sni = %sni,
                        %authority,
                        handshake_route,
                        request_route = ?request_route,
                        "rejecting coalesced H3 request that crosses route boundary"
                    );
                    return empty_response(stream, StatusCode::MISDIRECTED_REQUEST).await;
                }

                debug!(
                    %peer,
                    route = %route.name,
                    %authority,
                    method = %request.method(),
                    "forwarding HTTP/3 request"
                );
                let upstream_stream = sender
                    .send_request(request)
                    .await
                    .context("sending upstream HTTP/3 request headers")?;
                proxy_stream(stream, upstream_stream).await
            }
            .await;

            if let Err(error) = result {
                warn!(
                    %peer,
                    route = %route.name,
                    error = %format!("{error:#}"),
                    "HTTP/3 request failed"
                );
            }
        });
    }
    Ok(())
}

struct UpstreamH3 {
    /// Keep the endpoint alive for at least as long as the H3 sender. Quinn
    /// closes all of an endpoint's connections when the last handle is dropped.
    _endpoint: quinn::Endpoint,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

async fn connect_upstream_h3(
    route: &RouteRuntime,
    handshake_sni: &str,
    peer: SocketAddr,
    cert_resolver: &Arc<DynamicResolver>,
) -> Result<UpstreamH3> {
    let host = route
        .upstream_host
        .clone()
        .or_else(|| (!handshake_sni.is_empty()).then(|| handshake_sni.to_string()))
        .ok_or_else(|| {
            anyhow!(
                "H3 route {} reflects SNI upstream but none was presented",
                route.name
            )
        })?;
    let server_name = match &route.sni_policy {
        SniPolicy::Fixed(name) => name.clone(),
        SniPolicy::Reflect | SniPolicy::Omit if !handshake_sni.is_empty() => {
            handshake_sni.to_string()
        }
        SniPolicy::Reflect | SniPolicy::Omit => host.clone(),
    };
    let upstream_addr = route
        .addr_resolver
        .lookup_addr(
            &host,
            route.upstream_port,
            route.address_family,
            route.nat64.as_ref(),
        )
        .await
        .with_context(|| format!("resolving H3 upstream {host}"))?;

    let bind_addr = match upstream_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let endpoint = quinn::Endpoint::client(bind_addr).context("binding H3 client endpoint")?;
    let connection = match route.route_type {
        RouteType::H3 => {
            let mut tls = rustls::ClientConfig::builder()
                .with_root_certificates(route.root_store.as_ref().clone())
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];
            if route.sni_policy == SniPolicy::Omit {
                tls.enable_sni = false;
            }
            let crypto = QuicClientConfig::try_from(tls)
                .context("converting H3 rustls client config to Quinn")?;
            connect_quinn(
                &endpoint,
                quinn::ClientConfig::new(Arc::new(crypto)),
                upstream_addr,
                &server_name,
                route.connect_timeout,
            )
            .await?
        }
        RouteType::H3Ech => {
            connect_ech_quinn(&endpoint, upstream_addr, &server_name, route, peer).await?
        }
        _ => return Err(anyhow!("route {} is not an HTTP/3 route", route.name)),
    };

    let negotiated_h3 = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .is_some_and(|protocol| protocol.as_slice() == b"h3");
    if !negotiated_h3 {
        return Err(anyhow!(
            "upstream QUIC connection did not negotiate h3 ALPN"
        ));
    }

    if let Some(chain) = connection.peer_identity().and_then(|identity| {
        identity
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .ok()
    }) {
        upstream_certs::observe_upstream_certificate(
            cert_resolver,
            &route.name,
            &route.sni_policy,
            Some(handshake_sni),
            chain.as_slice(),
        );
    }

    debug!(
        %peer,
        route = %route.name,
        upstream = %upstream_addr,
        sni = %server_name,
        "upstream H3 connection established"
    );

    let quic = h3_quinn::Connection::new(connection);
    let (mut driver, sender) = h3::client::new(quic)
        .await
        .context("starting upstream HTTP/3 client")?;
    let route_name = route.name.clone();
    tokio::spawn(async move {
        let error = poll_fn(|cx| driver.poll_close(cx)).await;
        debug!(route = %route_name, error = %error, "upstream H3 driver closed");
    });

    Ok(UpstreamH3 {
        _endpoint: endpoint,
        sender,
    })
}

async fn connect_quinn(
    endpoint: &quinn::Endpoint,
    config: quinn::ClientConfig,
    addr: SocketAddr,
    server_name: &str,
    connect_timeout: std::time::Duration,
) -> Result<quinn::Connection> {
    let connecting = endpoint
        .connect_with(config, addr, server_name)
        .with_context(|| format!("starting H3 QUIC connection to {server_name}"))?;
    timeout(connect_timeout, connecting)
        .await
        .map_err(|_| anyhow!("upstream H3 QUIC handshake timed out"))?
        .context("upstream H3 QUIC handshake")
}

async fn connect_ech_quinn(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    inner: &str,
    route: &RouteRuntime,
    peer: SocketAddr,
) -> Result<quinn::Connection> {
    let ech = route
        .ech
        .as_ref()
        .ok_or_else(|| anyhow!("h3-ech route {} missing ECH provider", route.name))?;
    let alpn = [b"h3".to_vec()];
    let mut attempt = 0u32;
    loop {
        let client = ech
            .client(inner, &alpn)
            .await
            .context("assembling H3 ECH client config")?;
        let crypto = QuicClientConfig::try_from(client.client_config)
            .context("converting H3 ECH rustls config to Quinn")?;
        match connect_quinn(
            endpoint,
            quinn::ClientConfig::new(Arc::new(crypto)),
            addr,
            inner,
            route.connect_timeout,
        )
        .await
        {
            Ok(connection) => {
                debug!(%peer, route = %route.name, attempt, "H3 ECH handshake established");
                return Ok(connection);
            }
            Err(error) if is_ech_reject_quinn(&error) && attempt < route.max_retries => {
                attempt += 1;
                warn!(
                    %peer,
                    route = %route.name,
                    attempt,
                    "H3 ECH rejected; refreshing config and retrying"
                );
                ech.invalidate(inner).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Quinn 0.11.11 / quinn-proto 0.11.15 flatten the rustls handshake error into
/// a QUIC transport error and retain only its human-readable reason. Keep the
/// matching deliberately narrow so unrelated TLS failures are never retried as
/// ECH rotations. A successful real-ECH rustls handshake is necessarily ECH-
/// accepted; rejection terminates the handshake with rustls `RejectedEch`.
fn is_ech_reject_quinn(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<quinn::ConnectionError>()
            .and_then(|error| match error {
                quinn::ConnectionError::TransportError(error) => Some(error.reason.as_str()),
                _ => None,
            })
            .is_some_and(|reason| {
                let reason = reason.to_ascii_lowercase();
                reason.contains("rejected")
                    && (reason.contains("encrypted client hello") || reason.contains("ech"))
            })
    })
}

async fn empty_response<S, B>(
    mut stream: h3::server::RequestStream<S, B>,
    status: StatusCode,
) -> Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: Buf,
{
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())?;
    stream.send_response(response).await?;
    stream.finish().await?;
    Ok(())
}

async fn proxy_stream<SI, SO>(
    inbound: h3::server::RequestStream<SI, bytes::Bytes>,
    upstream: h3::client::RequestStream<SO, bytes::Bytes>,
) -> Result<()>
where
    SI: h3::quic::BidiStream<bytes::Bytes>,
    SO: h3::quic::BidiStream<bytes::Bytes>,
{
    let (mut inbound_send, mut inbound_recv) = inbound.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();

    let upload = async {
        while let Some(mut chunk) = inbound_recv.recv_data().await? {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            upstream_send.send_data(bytes).await?;
        }
        if let Some(trailers) = inbound_recv.recv_trailers().await? {
            upstream_send.send_trailers(trailers).await?;
        } else {
            upstream_send.finish().await?;
        }
        Ok::<(), h3::error::StreamError>(())
    };

    let download = async {
        let response = upstream_recv.recv_response().await?;
        inbound_send.send_response(response).await?;
        while let Some(mut chunk) = upstream_recv.recv_data().await? {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            inbound_send.send_data(bytes).await?;
        }
        if let Some(trailers) = upstream_recv.recv_trailers().await? {
            inbound_send.send_trailers(trailers).await?;
        } else {
            inbound_send.finish().await?;
        }
        Ok::<(), h3::error::StreamError>(())
    };

    tokio::try_join!(upload, download).context("proxying HTTP/3 stream")?;
    Ok(())
}
