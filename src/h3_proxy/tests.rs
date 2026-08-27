use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, Request, Response, StatusCode};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::time::{sleep, timeout};

use super::{
    authority_reuses_upstream, proxy_inbound_h3, upstream_failure_status, Router, UpstreamH3,
    UpstreamPoolKey,
};

const FRONT_SNI: &str = "front.h3.test";
const SIBLING_SNI: &str = "sibling.h3.test";
const UPSTREAM_SNI: &str = "upstream.h3.test";
const OTHER_SNI: &str = "other.h3.test";
const REQUEST_BODY: &[u8] = b"request-through-h3-proxy";
const RESPONSE_BODY: &[u8] = b"response-through-h3-proxy";

#[test]
fn same_route_coalescing_requires_stable_upstream_identity() {
    assert!(authority_reuses_upstream(
        Some(0),
        0,
        FRONT_SNI,
        FRONT_SNI,
        true,
        true
    ));
    assert!(!authority_reuses_upstream(
        Some(0),
        0,
        SIBLING_SNI,
        FRONT_SNI,
        true,
        false
    ));
    assert!(!authority_reuses_upstream(
        Some(0),
        0,
        SIBLING_SNI,
        FRONT_SNI,
        false,
        true
    ));
    assert!(authority_reuses_upstream(
        Some(0),
        0,
        SIBLING_SNI,
        FRONT_SNI,
        false,
        false
    ));
    assert!(!authority_reuses_upstream(
        Some(1),
        0,
        OTHER_SNI,
        FRONT_SNI,
        false,
        false
    ));
}

#[test]
fn upstream_pool_key_is_scoped_by_route_and_tls_identity() {
    let base = UpstreamPoolKey {
        listener: "127.0.0.1:443".parse().unwrap(),
        route_id: 3,
        host: "origin.example".to_string(),
        port: 443,
        server_name: "origin.example".to_string(),
        ech: false,
    };

    assert_eq!(base, base.clone());

    let mut other_route = base.clone();
    other_route.route_id += 1;
    assert_ne!(base, other_route);

    let mut other_host = base.clone();
    other_host.host = "other.example".to_string();
    assert_ne!(base, other_host);

    let mut other_tls_name = base.clone();
    other_tls_name.server_name = "tls.example".to_string();
    assert_ne!(base, other_tls_name);

    let mut ech = base.clone();
    ech.ech = true;
    assert_ne!(base, ech);
}

#[tokio::test]
async fn upstream_failures_map_to_gateway_statuses() {
    let elapsed = timeout(Duration::ZERO, std::future::pending::<()>())
        .await
        .expect_err("zero timeout should elapse");
    let timeout_error = anyhow::Error::new(elapsed);
    assert_eq!(
        upstream_failure_status(&timeout_error),
        StatusCode::GATEWAY_TIMEOUT
    );

    let ordinary_error = anyhow::anyhow!("upstream refused connection");
    assert_eq!(
        upstream_failure_status(&ordinary_error),
        StatusCode::BAD_GATEWAY
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_handle_clone_keeps_active_request_alive() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![UPSTREAM_SNI.to_string()])
            .expect("generate upstream lifetime test certificate");
    let cert_der = cert.der().clone();
    let key_der = signing_key.serialize_der();

    let server_endpoint = quinn::Endpoint::server(
        h3_server_config(cert_der.clone(), key_der),
        localhost_ephemeral(),
    )
    .expect("bind upstream lifetime test server");
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_task = tokio::spawn({
        let endpoint = server_endpoint.clone();
        async move {
            let connection = endpoint
                .accept()
                .await
                .expect("lifetime test QUIC connection")
                .await
                .expect("lifetime test QUIC handshake");
            let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection))
                .await
                .expect("start lifetime test H3 server");
            let resolver = h3
                .accept()
                .await
                .expect("accept lifetime test H3 request")
                .expect("one lifetime test request");
            let (_, mut stream) = resolver
                .resolve_request()
                .await
                .expect("resolve lifetime test request");
            while stream
                .recv_data()
                .await
                .expect("read lifetime test request body")
                .is_some()
            {}

            // Give the client time to drop the original pool-owned handle. The
            // request-scoped clone must keep the Quinn endpoint alive here.
            sleep(Duration::from_millis(75)).await;
            stream
                .send_response(Response::builder().status(StatusCode::NO_CONTENT).body(()).unwrap())
                .await
                .expect("send lifetime test response");
            stream.finish().await.expect("finish lifetime test response");
        }
    });

    let client_endpoint =
        quinn::Endpoint::client(localhost_ephemeral()).expect("bind lifetime test client");
    let connection = client_endpoint
        .connect_with(
            h3_client_config(cert_der),
            server_addr,
            UPSTREAM_SNI,
        )
        .expect("start lifetime test upstream QUIC connection")
        .await
        .expect("lifetime test upstream QUIC handshake");
    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("start lifetime test H3 client");
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let pooled_handle = UpstreamH3 {
        _endpoint: client_endpoint,
        sender,
    };
    let request_guard = pooled_handle.clone();
    let mut request_sender = request_guard.sender.clone();
    let request = Request::get(format!("https://{UPSTREAM_SNI}/lifetime"))
        .body(())
        .unwrap();
    let mut stream = request_sender
        .send_request(request)
        .await
        .expect("open lifetime test H3 request");
    stream.finish().await.expect("finish lifetime test request");

    drop(request_sender);
    drop(pooled_handle);

    let response = timeout(Duration::from_secs(2), stream.recv_response())
        .await
        .expect("active request should survive pool-handle eviction")
        .expect("receive lifetime test response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    drop(request_guard);
    server_task.await.expect("lifetime test server task");
    driver_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn semantic_proxy_preserves_h3_message_and_blocks_unsafe_coalescing() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![FRONT_SNI.to_string(), UPSTREAM_SNI.to_string()])
            .expect("generate H3 test certificate");
    let cert_der = cert.der().clone();
    let key_der = signing_key.serialize_der();

    let upstream_endpoint = quinn::Endpoint::server(
        h3_server_config(cert_der.clone(), key_der.clone()),
        localhost_ephemeral(),
    )
    .expect("bind upstream H3 server");
    let upstream_addr = upstream_endpoint.local_addr().unwrap();
    let upstream_server = tokio::spawn({
        let endpoint = upstream_endpoint.clone();
        async move {
            let connection = endpoint
                .accept()
                .await
                .expect("upstream QUIC connection")
                .await
                .expect("upstream QUIC handshake");
            let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection))
                .await
                .expect("start upstream H3 server");

            let resolver = h3
                .accept()
                .await
                .expect("accept upstream H3 request")
                .expect("one upstream H3 request");
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .expect("resolve upstream H3 request");
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().authority().unwrap().as_str(), FRONT_SNI);
            assert_eq!(request.headers()["x-request-header"], "preserved");

            let mut request_body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("read request data") {
                request_body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            assert_eq!(request_body, REQUEST_BODY);
            let request_trailers = stream
                .recv_trailers()
                .await
                .expect("read request trailers")
                .expect("request trailers present");
            assert_eq!(request_trailers["x-request-trailer"], "preserved");

            let response = Response::builder()
                .status(StatusCode::CREATED)
                .header("x-response-header", "preserved")
                .body(())
                .unwrap();
            stream
                .send_response(response)
                .await
                .expect("send upstream response headers");
            stream
                .send_data(Bytes::from_static(RESPONSE_BODY))
                .await
                .expect("send upstream response body");
            let mut response_trailers = HeaderMap::new();
            response_trailers.insert("x-response-trailer", "preserved".parse().unwrap());
            stream
                .send_trailers(response_trailers)
                .await
                .expect("send upstream response trailers");
            stream.finish().await.expect("finish upstream response");

            match timeout(Duration::from_millis(500), h3.accept()).await {
                Err(_) | Ok(Ok(None)) | Ok(Err(_)) => {}
                Ok(Ok(Some(_))) => {
                    panic!("unsafe coalesced request must not reach the upstream H3 connection")
                }
            }
        }
    });

    let upstream_client_endpoint =
        quinn::Endpoint::client(localhost_ephemeral()).expect("bind proxy upstream client");
    let upstream_connection = upstream_client_endpoint
        .connect_with(
            h3_client_config(cert_der.clone()),
            upstream_addr,
            UPSTREAM_SNI,
        )
        .expect("start proxy upstream QUIC connection")
        .await
        .expect("proxy upstream QUIC handshake");
    let (mut upstream_driver, upstream_sender) =
        h3::client::new(h3_quinn::Connection::new(upstream_connection))
            .await
            .expect("start proxy upstream H3 client");
    let upstream_driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| upstream_driver.poll_close(cx)).await;
    });
    let upstream = UpstreamH3 {
        _endpoint: upstream_client_endpoint,
        sender: upstream_sender,
    };

    let gateway_endpoint = quinn::Endpoint::server(
        h3_server_config(cert_der.clone(), key_der),
        localhost_ephemeral(),
    )
    .expect("bind gateway H3 server");
    let gateway_addr = gateway_endpoint.local_addr().unwrap();
    let router = Arc::new(
        Router::build(
            &[
                vec![FRONT_SNI.to_string(), SIBLING_SNI.to_string()],
                vec![OTHER_SNI.to_string()],
            ],
            None,
            &HashMap::new(),
        )
        .expect("build H3 test router"),
    );
    let gateway_task = tokio::spawn({
        let endpoint = gateway_endpoint.clone();
        async move {
            let connection = endpoint
                .accept()
                .await
                .expect("inbound QUIC connection")
                .await
                .expect("inbound QUIC handshake");
            let peer = connection.remote_address();
            let _ = proxy_inbound_h3(
                connection,
                peer,
                router,
                0,
                FRONT_SNI.to_string(),
                "h3-test".to_string(),
                true,
                true,
                upstream,
            )
            .await;
        }
    });

    let client_endpoint =
        quinn::Endpoint::client(localhost_ephemeral()).expect("bind H3 test client");
    let connection = client_endpoint
        .connect_with(h3_client_config(cert_der), gateway_addr, FRONT_SNI)
        .expect("start inbound QUIC connection")
        .await
        .expect("inbound QUIC handshake");
    let close_handle = connection.clone();
    let (mut client_driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .expect("start inbound H3 client");
    let client_driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| client_driver.poll_close(cx)).await;
    });

    let request = Request::post(format!("https://{FRONT_SNI}/upload"))
        .header("x-request-header", "preserved")
        .body(())
        .unwrap();
    let mut stream = sender
        .send_request(request)
        .await
        .expect("send proxied H3 request");
    stream
        .send_data(Bytes::from_static(REQUEST_BODY))
        .await
        .expect("send proxied H3 body");
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("x-request-trailer", "preserved".parse().unwrap());
    stream
        .send_trailers(request_trailers)
        .await
        .expect("send proxied H3 trailers");
    stream.finish().await.expect("finish proxied H3 request");

    let response = stream
        .recv_response()
        .await
        .expect("receive proxied H3 response");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-response-header"], "preserved");
    let mut response_body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.expect("read response data") {
        response_body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    assert_eq!(response_body, RESPONSE_BODY);
    let response_trailers = stream
        .recv_trailers()
        .await
        .expect("read response trailers")
        .expect("response trailers present");
    assert_eq!(response_trailers["x-response-trailer"], "preserved");

    for blocked_host in [SIBLING_SNI, OTHER_SNI] {
        let blocked = Request::get(format!("https://{blocked_host}/blocked"))
            .body(())
            .unwrap();
        let mut blocked_stream = sender
            .send_request(blocked)
            .await
            .expect("send unsafe coalesced H3 request");
        blocked_stream
            .finish()
            .await
            .expect("finish blocked request");
        let blocked_response = blocked_stream
            .recv_response()
            .await
            .expect("receive 421 response");
        assert_eq!(blocked_response.status(), StatusCode::MISDIRECTED_REQUEST);
        assert!(blocked_stream
            .recv_data()
            .await
            .expect("read empty 421 body")
            .is_none());
    }

    drop(sender);
    close_handle.close(0u32.into(), b"test complete");
    upstream_server.await.expect("upstream H3 task");
    let _ = timeout(Duration::from_secs(2), gateway_task).await;
    upstream_driver_task.abort();
    client_driver_task.abort();
}

fn localhost_ephemeral() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
}

fn h3_server_config(cert: CertificateDer<'static>, key_der: Vec<u8>) -> quinn::ServerConfig {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], PrivatePkcs8KeyDer::from(key_der).into())
        .expect("build H3 rustls server config");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicServerConfig::try_from(tls).expect("build H3 Quinn server crypto");
    quinn::ServerConfig::with_crypto(Arc::new(crypto))
}

fn h3_client_config(cert: CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("trust H3 test certificate");
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicClientConfig::try_from(tls).expect("build H3 Quinn client crypto");
    quinn::ClientConfig::new(Arc::new(crypto))
}
