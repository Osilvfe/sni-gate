//! HTTP/3 semantic proxy data path.
//!
//! The shared UDP dispatcher and Quinn own transport demultiplexing. This
//! module starts at an already-established inbound QUIC connection and handles
//! HTTP/3 request semantics. Request authority is re-routed per stream so H3
//! connection coalescing can never bypass the listener's route boundaries.

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

    // Stage 4A deliberately enables only ordinary H3. H3-ECH stays fail-closed
    // until its QUIC TLS setup is implemented in the next commit; never silently
    // downgrade a route that explicitly requires ECH.
    let upstream = if route.route_type == RouteType::H3 {
        Some(connect_plain_h3(&route, &handshake_sni, peer).await?)
    } else {
        None
    };

    let quic = h3_quinn::Connection::new(connection);
    let mut inbound = h3::server::Connection::new(quic)
        .await
        .context("starting inbound HTTP/3 connection")?;

    while let Some(resolver) = inbound
        .accept()
        .await
        .context("accepting HTTP/3 request")?
    {
        let state = state.clone();
        let sni = handshake_sni.clone();
        let route = route.clone();
        let upstream = upstream.as_ref().map(|upstream| upstream.sender.clone());
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

                let Some(mut sender) = upstream else {
                    // H3-ECH remains explicitly unavailable until 4B. This is a
                    // development-branch fail-closed response, not a downgrade.
                    return empty_response(stream, StatusCode::SERVICE_UNAVAILABLE).await;
                };

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

struct PlainUpstream {
    /// Keep the endpoint alive for at least as long as the H3 sender. Quinn
    /// closes all of an endpoint's connections when the last handle is dropped.
    _endpoint: quinn::Endpoint,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

async fn connect_plain_h3(
    route: &RouteRuntime,
    handshake_sni: &str,
    peer: SocketAddr,
) -> Result<PlainUpstream> {
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

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(route.root_store.as_ref().clone())
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    if route.sni_policy == SniPolicy::Omit {
        tls.enable_sni = false;
    }
    let crypto = QuicClientConfig::try_from(tls)
        .context("converting H3 rustls client config to Quinn")?;
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));

    let bind_addr = match upstream_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let endpoint = quinn::Endpoint::client(bind_addr).context("binding H3 client endpoint")?;
    let connecting = endpoint
        .connect_with(client_config, upstream_addr, &server_name)
        .with_context(|| format!("starting H3 QUIC connection to {server_name}"))?;
    let connection = timeout(route.connect_timeout, connecting)
        .await
        .map_err(|_| anyhow!("upstream H3 QUIC handshake timed out"))?
        .context("upstream H3 QUIC handshake")?;

    let negotiated_h3 = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .is_some_and(|protocol| protocol.as_slice() == b"h3");
    if !negotiated_h3 {
        return Err(anyhow!("upstream QUIC connection did not negotiate h3 ALPN"));
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
        if let Err(error) = poll_fn(|cx| driver.poll_close(cx)).await {
            debug!(route = %route_name, error = %error, "upstream H3 driver closed with error");
        }
    });

    Ok(PlainUpstream {
        _endpoint: endpoint,
        sender,
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
