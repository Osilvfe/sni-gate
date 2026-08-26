//! Transport-independent observation of upstream certificate coverage.
//!
//! TCP rustls and QUIC/Quinn expose peer certificates through different APIs,
//! but the routing/certificate policy is identical. Keep that policy here so
//! every terminating transport mirrors upstream SAN coverage consistently.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use tracing::debug;

use crate::config::SniPolicy;
use crate::resolver::{observed_dns_sans, DynamicResolver};

/// Record the DNS SAN coverage an upstream authenticated for one inbound name.
///
/// Fixed/omitted upstream SNI policies are deliberately not mirrored: the
/// certificate observed for a fixed upstream identity says nothing about the
/// inbound host whose local certificate would otherwise be widened.
pub fn observe_upstream_certificate(
    resolver: &Arc<DynamicResolver>,
    route_name: &str,
    sni_policy: &SniPolicy,
    inbound_name: Option<&str>,
    chain: &[CertificateDer<'_>],
) {
    if sni_policy != &SniPolicy::Reflect {
        return;
    }
    let Some(host) = inbound_name.filter(|host| !host.is_empty()) else {
        return;
    };

    let observed = observed_dns_sans(chain);
    if resolver.mirror_is_current(host, &observed) {
        return;
    }

    let resolver = resolver.clone();
    let host = host.to_string();
    let route = route_name.to_string();
    // The current connection already has its local certificate. Updating the
    // mirror affects a future handshake, so signing/persistence never needs to
    // block the transport data path.
    tokio::task::spawn_blocking(move || {
        debug!(route = %route, host = %host, sans = ?observed, "observed upstream certificate");
        resolver.record_upstream_sans(&host, &observed);
    });
}
