//! HTTP/3 semantic proxy data path.
//!
//! The shared UDP dispatcher and Quinn own transport demultiplexing. This
//! module starts at an already-established inbound QUIC connection and handles
//! HTTP/3 request semantics. Request authority is re-routed per stream so H3
//! connection coalescing can never bypass the listener's route boundaries.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use http::{Response, StatusCode};
use tracing::{debug, warn};

use crate::proxy::ListenerState;

pub async fn serve_inbound(
    connection: quinn::Connection,
    peer: SocketAddr,
    state: Arc<ListenerState>,
    handshake_route: usize,
    handshake_sni: String,
) -> Result<()> {
    let quic = h3_quinn::Connection::new(connection);
    let mut h3 = h3::server::Connection::new(quic)
        .await
        .context("starting inbound HTTP/3 connection")?;

    while let Some(resolver) = h3.accept().await.context("accepting HTTP/3 request")? {
        let state = state.clone();
        let sni = handshake_sni.clone();
        tokio::spawn(async move {
            let result = async {
                let (request, mut stream) = resolver
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
                    let response = Response::builder()
                        .status(StatusCode::MISDIRECTED_REQUEST)
                        .header(http::header::CONTENT_LENGTH, "0")
                        .body(())?;
                    stream.send_response(response).await?;
                    stream.finish().await?;
                    return Ok::<(), anyhow::Error>(());
                }

                // Stage 4 replaces this explicit unavailable response with an
                // upstream h3 client stream. Keeping the response explicit is
                // safer than accidentally advertising a working semantic proxy
                // before request/response body and trailer forwarding exists.
                let response = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header(http::header::CONTENT_LENGTH, "0")
                    .body(())?;
                stream.send_response(response).await?;
                stream.finish().await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(error) = result {
                warn!(%peer, error = %format!("{error:#}"), "HTTP/3 request failed");
            }
        });
    }
    Ok(())
}
