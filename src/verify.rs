//! Upstream certificate verification — what this gateway demands of a
//! certificate presented by an upstream it dials.
//!
//! # Why this is configurable at all
//!
//! Every terminating route re-originates the connection, and by default the
//! upstream certificate must chain to the web-PKI roots *and* be valid for the
//! name the route asked for. That is the right default and it is what almost
//! every route should keep.
//!
//! It is nevertheless not always satisfiable, and the reason is structural
//! rather than accidental. This gateway exists to decouple three things a
//! browser keeps welded together: **who we dial**, **what name we transmit**,
//! and **what name we trust**. `upstream` moves the first, `override_sni` the
//! second — and once the second has moved, the third no longer follows from it.
//! A route that suppresses SNI (`override_sni = ""`) reaches a virtual host that
//! answers with its *default* certificate, and that certificate is for whatever
//! name the operator of the upstream chose, not for the one the client asked
//! for. The handshake is perfectly sound; it simply does not prove the
//! proposition the default policy checks.
//!
//! `[verify]` is where that proposition is stated, so the operator can name the
//! assurance their deployment actually has instead of being pushed into having
//! none.
//!
//! # The three modes, and the two things worth preferring over them
//!
//! | `mode`   | chains to a trust anchor | certificate name checked |
//! |----------|--------------------------|--------------------------|
//! | `full`   | yes                      | yes *(the default)*      |
//! | `chain`  | yes                      | no                       |
//! | `none`   | no                       | no                       |
//!
//! Two fields are almost always the better answer than reaching for a weaker
//! mode, and both keep a real assurance in place:
//!
//! * **`name`** — verify against a *different* name, in `full` mode. When the
//!   upstream answers a no-SNI handshake with a certificate for
//!   `default.example`, `name = "default.example"` verifies exactly what the
//!   upstream really proves. Chain, expiry and name are all still checked; only
//!   the *subject* of the claim moved.
//! * **`pins`** — SPKI pins (`sha256/<base64>`, the `curl --pinnedpubkey`
//!   spelling). A pin binds the peer to one public key, which no CA and no name
//!   can be substituted for, so it is strictly stronger than a name check. Pins
//!   apply in every mode and are the *only* assurance under `mode = "none"`,
//!   which is why a pinned `none` is reported as information while an unpinned
//!   one is reported as a warning.
//!
//! `ca_file` adds trust anchors (a private CA), and `trust_webpki = false`
//! narrows trust to only those anchors.
//!
//! # What a weakened policy means elsewhere
//!
//! Mirrored certificate coverage (see [`crate::resolver`]) is learned from the
//! upstream's own certificate, so what that certificate was *proven to be* is
//! what the coverage is worth. Under a weakened policy it is worth less: `chain`
//! proves no name, `none` proves nothing at all, and a `name` override proves a
//! different identity than the one requested.
//!
//! Mirroring nevertheless stays on in every mode, because the policy is part of
//! the certificate scope ([`crate::certscope`]). A route shares mirrored
//! coverage only with names held to the *same* policy against the *same*
//! destination, so weakened evidence can never reach a certificate a fully
//! verified route serves, and a client can never coalesce a strictly verified
//! name onto a connection whose far end was never checked. The operator's
//! decision costs exactly what they decided and no more — in particular it does
//! not cost the route its connection coalescing.
//!
//! # One construction path
//!
//! Every upstream `ClientConfig` in the program — route, resolver, pool probe —
//! is built through `dangerous().with_custom_certificate_verifier()` with the
//! verifier produced here, including for the default policy (where it is
//! byte-for-byte the check `with_root_certificates` installs, minus revocation,
//! which that path does not configure either). Uniformity is the point: there is
//! exactly one place where "what must the upstream prove" is decided, so no
//! call site can accidentally be the one that forgot.
//!
//! Verifiers are built once per distinct policy and shared by `Arc`
//! ([`VerifierFactory`]): the trust anchors are the expensive part, and a
//! hundred routes on the default policy must not mean a hundred copies of the
//! web-PKI root store.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, DigitallySignedStruct, Error as TlsError, OtherError, RootCertStore,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::{parse_spki_pin, EffectiveVerify, VerifyMode, SPKI_PIN_PREFIX};

/// A built verification policy: the rustls verifier, plus what the rest of the
/// program needs to know about the policy behind it.
pub struct UpstreamVerify {
    verifier: Arc<dyn ServerCertVerifier>,
    /// Whether this is the default policy — full verification against the
    /// web-PKI roots. Lets a caller that would otherwise keep a library's own
    /// TLS defaults (hickory, for its DoH/DoT transports) know that replacing
    /// them would buy nothing.
    is_default: bool,
    /// The name every certificate is verified against, when the policy pins one.
    name: Option<String>,
    /// One-line rendering of the policy, for diagnostics.
    label: String,
}

impl UpstreamVerify {
    /// The verifier to install on a `ClientConfig`.
    pub fn verifier(&self) -> Arc<dyn ServerCertVerifier> {
        self.verifier.clone()
    }

    /// Whether this policy is full verification against the web-PKI roots.
    pub fn is_default(&self) -> bool {
        self.is_default
    }

    /// The policy's fixed verification name, if it sets one.
    ///
    /// Read by a route that transmits no name and has none to offer: rustls
    /// requires *some* `ServerName` to open a connection with, and under a
    /// `name` override that value no longer decides anything that is checked.
    /// See `proxy::silent_name_override` for why only that case may use it.
    pub fn name_override(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// One-line rendering of the policy, for diagnostics.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Debug for UpstreamVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamVerify")
            .field("policy", &self.label)
            .finish()
    }
}

/// Builds (and shares) one verifier per distinct policy.
///
/// Held by the startup path and consulted once per scope that dials a TLS
/// upstream. Two scopes with equal policies get the same `Arc`, so the web-PKI
/// anchors are parsed once for the whole process and a `ca_file` is read once
/// per distinct policy that names it.
pub struct VerifierFactory {
    /// Signature algorithms of the one crypto provider this binary uses.
    algorithms: WebPkiSupportedAlgorithms,
    /// The web-PKI anchors, shared by every policy that trusts them.
    webpki: Arc<RootCertStore>,
    cache: HashMap<EffectiveVerify, Arc<UpstreamVerify>>,
}

impl Default for VerifierFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierFactory {
    pub fn new() -> Self {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        Self {
            algorithms: provider.signature_verification_algorithms,
            webpki: Arc::new(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            }),
            cache: HashMap::new(),
        }
    }

    /// The verifier for `policy`, building it on first use.
    ///
    /// `scope` names the configuration scope asking for it (`route web`,
    /// `[resolvers.doh]`, …) and is used only for diagnostics — including the
    /// report that a scope weakened its verification, which is emitted per
    /// asking scope even when the verifier itself is shared.
    pub fn get(&mut self, policy: &EffectiveVerify, scope: &str) -> Result<Arc<UpstreamVerify>> {
        report(policy, scope);
        if let Some(existing) = self.cache.get(policy) {
            return Ok(existing.clone());
        }
        let built = Arc::new(
            self.build(policy)
                .with_context(|| format!("{scope}: [verify]"))?,
        );
        self.cache.insert(policy.clone(), built.clone());
        Ok(built)
    }

    fn build(&self, policy: &EffectiveVerify) -> Result<UpstreamVerify> {
        // Load-time validation has already accepted every field; each parse here
        // still reports rather than panics, because this is also the path a test
        // or a future caller constructing a policy directly takes.
        let mut pins: Vec<[u8; 32]> = Vec::with_capacity(policy.pins.len());
        for pin in &policy.pins {
            let parsed = parse_spki_pin(pin).map_err(|e| anyhow::anyhow!("{e}"))?;
            if !pins.contains(&parsed) {
                pins.push(parsed);
            }
        }

        let name = match (&policy.name, policy.mode) {
            // A fixed name is only ever checked in `full` mode; the other modes
            // check no name at all, and writing one there is a load-time error.
            (Some(name), VerifyMode::Full) => {
                NameCheck::Fixed(ServerName::try_from(name.clone()).map_err(|_| {
                    anyhow::anyhow!("`name` {name:?} is not a valid DNS name or IP")
                })?)
            }
            (_, VerifyMode::Full) => NameCheck::Requested,
            (_, VerifyMode::Chain | VerifyMode::None) => NameCheck::Skip,
        };

        let roots = match policy.mode {
            VerifyMode::None => None,
            VerifyMode::Full | VerifyMode::Chain => Some(self.roots_for(policy)?),
        };

        Ok(UpstreamVerify {
            is_default: *policy == EffectiveVerify::default(),
            name: policy.name.clone(),
            label: describe(policy),
            verifier: Arc::new(UpstreamCertVerifier {
                roots,
                name,
                pins: pins.into(),
                algorithms: self.algorithms,
            }),
        })
    }

    /// The trust anchors for a chain-building policy.
    fn roots_for(&self, policy: &EffectiveVerify) -> Result<Arc<RootCertStore>> {
        let Some(path) = policy.ca_file.as_deref() else {
            if !policy.trust_webpki {
                bail!(
                    "`trust_webpki = false` leaves no trust anchors at all; supply a `ca_file`, \
                     or keep the web-PKI roots"
                );
            }
            return Ok(self.webpki.clone());
        };

        let mut store = if policy.trust_webpki {
            RootCertStore {
                roots: self.webpki.roots.clone(),
            }
        } else {
            RootCertStore::empty()
        };
        let added = add_anchors(path, &mut store)?;
        debug!(
            ca_file = %path.display(),
            anchors = added,
            webpki = policy.trust_webpki,
            "loaded upstream trust anchors"
        );
        Ok(Arc::new(store))
    }
}

/// Add every certificate in a PEM bundle to `store` as a trust anchor.
fn add_anchors(path: &Path, store: &mut RootCertStore) -> Result<usize> {
    let pem =
        std::fs::read(path).with_context(|| format!("reading `ca_file` {}", path.display()))?;
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        let cert = cert.with_context(|| {
            format!("reading PEM certificates from `ca_file` {}", path.display())
        })?;
        store
            .add(cert)
            .with_context(|| format!("adding a trust anchor from {}", path.display()))?;
        added += 1;
    }
    if added == 0 {
        bail!("`ca_file` {} contains no PEM certificates", path.display());
    }
    Ok(added)
}

/// Report one scope's policy: silent for the default, informational when a real
/// assurance remains, and a warning when none does.
///
/// A weakened policy is the operator's decision and never blocks startup, but it
/// is not allowed to be invisible either: with `mode = "none"` and no pins, this
/// gateway serves a locally-trusted certificate to its client for a connection
/// whose far end it did not authenticate at all, and the client cannot tell.
fn report(policy: &EffectiveVerify, scope: &str) {
    let label = describe(policy);
    let pinned = !policy.pins.is_empty();
    match policy.mode {
        VerifyMode::Full if policy.name.is_none() => {
            // The default proposition, plus any private anchors. Nothing to say.
            debug!(scope, policy = %label, "upstream verification");
        }
        VerifyMode::Full => info!(
            scope,
            policy = %label,
            "upstream certificates are verified against a fixed name instead of the name the \
             route requested; chain and validity are still enforced. This scope keeps its own \
             certificate partition, so the coverage it mirrors is shared only with names \
             verified the same way"
        ),
        VerifyMode::Chain if pinned => info!(
            scope,
            policy = %label,
            "upstream certificate names are not checked; the configured SPKI pins bind the \
             upstream to a specific public key instead"
        ),
        VerifyMode::Chain => warn!(
            scope,
            policy = %label,
            "upstream certificate names are NOT checked: any certificate a public CA has \
             issued for any name is accepted here, so whoever controls the path can present \
             one of their own. Prefer `verify.name` (verify the name the upstream really \
             proves) or `verify.pins` (bind it to a key)"
        ),
        VerifyMode::None if pinned => info!(
            scope,
            policy = %label,
            "upstream certificates are not validated against any trust anchor; the configured \
             SPKI pins are the assurance that the far end is the intended one"
        ),
        VerifyMode::None => warn!(
            scope,
            policy = %label,
            "upstream certificates are NOT verified at all: anyone able to intercept this \
             connection can impersonate the upstream and read or rewrite the traffic, while \
             the client still sees a certificate this gateway's CA signed. Add `verify.pins` \
             to bind the upstream to a public key"
        ),
    }
}

/// One-line rendering of a policy, e.g. `full`, `full name=a.example`,
/// `chain +2 pins`, `none ca_file=corp.pem`.
fn describe(policy: &EffectiveVerify) -> String {
    let mut out = String::with_capacity(32);
    out.push_str(policy.mode.as_str());
    if let Some(name) = &policy.name {
        out.push_str(" name=");
        out.push_str(name);
    }
    match policy.pins.len() {
        0 => {}
        1 => out.push_str(" +1 pin"),
        n => {
            out.push_str(" +");
            out.push_str(&n.to_string());
            out.push_str(" pins");
        }
    }
    if let Some(path) = &policy.ca_file {
        out.push_str(" ca_file=");
        out.push_str(&path.display().to_string());
        if !policy.trust_webpki {
            out.push_str(" (only)");
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

/// Which name the certificate must be valid for.
#[derive(Debug)]
enum NameCheck {
    /// The name the connection asked for — the `ServerName` the dial used.
    Requested,
    /// A fixed name from `verify.name`, whatever the connection asked for.
    Fixed(ServerName<'static>),
    /// No name is checked (`mode = "chain"` / `"none"`).
    Skip,
}

/// The one server-certificate verifier this program installs.
///
/// Built from the three independent questions a policy answers — does the chain
/// have to reach a trust anchor, which name must it be valid for, and must the
/// key match a pin — rather than by wrapping and second-guessing rustls's own
/// verifier. rustls exposes the two halves of its check separately
/// ([`verify_server_cert_signed_by_trust_anchor`] and [`verify_server_name`]),
/// so "chain but not name" is expressed by *not calling* the second one. No
/// error is reinterpreted, and no step is skipped that the policy did not
/// explicitly drop.
#[derive(Debug)]
struct UpstreamCertVerifier {
    /// Trust anchors, or `None` to build no chain at all (`mode = "none"`).
    roots: Option<Arc<RootCertStore>>,
    name: NameCheck,
    /// Accepted end-entity SPKI digests. Empty means "no pinning".
    pins: Arc<[[u8; 32]]>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for UpstreamCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        // Pinning first: it is the cheapest check and the most specific
        // diagnostic. It is an *additional* requirement in every mode, never a
        // substitute for one the policy also asked for.
        if !self.pins.is_empty() {
            let presented = spki_sha256(end_entity)?;
            if !self.pins.contains(&presented) {
                return Err(TlsError::InvalidCertificate(CertificateError::Other(
                    OtherError(Arc::new(PinMismatch {
                        presented: encode_pin(&presented),
                        configured: self.pins.len(),
                    })),
                )));
            }
        }

        if let Some(roots) = &self.roots {
            verify_server_cert_signed_by_trust_anchor(
                &cert,
                roots,
                intermediates,
                now,
                self.algorithms.all,
            )?;
        }

        match &self.name {
            NameCheck::Requested => verify_server_name(&cert, server_name)?,
            NameCheck::Fixed(fixed) => verify_server_name(&cert, fixed)?,
            NameCheck::Skip => {}
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A presented key that matched no configured pin.
///
/// `Debug` delegates to `Display` because rustls renders
/// `CertificateError::Other` through `Debug`, and an operator reading a
/// handshake failure needs the sentence, not a struct dump.
struct PinMismatch {
    presented: String,
    configured: usize,
}

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upstream public key {} matches none of the {} configured verify.pins",
            self.presented, self.configured
        )
    }
}

impl fmt::Debug for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for PinMismatch {}

/// SHA-256 over the certificate's DER-encoded SubjectPublicKeyInfo — the value
/// an `sha256/<base64>` pin names (RFC 7469 §2.1.1, and what
/// `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256sum`
/// produces).
fn spki_sha256(cert: &CertificateDer<'_>) -> Result<[u8; 32], TlsError> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, parsed) = X509Certificate::from_der(cert.as_ref())
        .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    Ok(Sha256::digest(parsed.tbs_certificate.subject_pki.raw).into())
}

/// Render a digest in the `sha256/<base64>` pin spelling.
fn encode_pin(digest: &[u8; 32]) -> String {
    use base64::Engine as _;
    format!(
        "{SPKI_PIN_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EffectiveVerify;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use std::io::Write as _;

    /// A CA and one leaf issued by it, in the DER forms a verifier needs.
    struct Chain {
        ca_pem: String,
        leaf: CertificateDer<'static>,
        /// The leaf's `sha256/<base64>` SPKI pin.
        pin: String,
    }

    /// Issue `names` from a fresh CA. Every test gets its own CA, so no test can
    /// accidentally trust another's.
    fn chain_for(names: &[&str]) -> Chain {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "verify-test CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(Vec::new()).unwrap();
        leaf_params.subject_alt_names = names
            .iter()
            .map(|n| SanType::DnsName((*n).try_into().unwrap()))
            .collect();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, names[0]);
        let ca_der = CertificateDer::from(ca.der().to_vec());
        let issuer = rcgen::Issuer::from_ca_cert_der(&ca_der, ca_key).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

        let leaf_der = CertificateDer::from(leaf.der().to_vec());
        let pin = encode_pin(&spki_sha256(&leaf_der).unwrap());
        // Keep the key material alive only as long as it is needed to sign.
        let _ = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());

        Chain {
            ca_pem: ca.pem(),
            leaf: leaf_der,
            pin,
        }
    }

    /// Write a PEM bundle into a temp file and return its path. The file is left
    /// behind on purpose: a `NamedTempFile` dependency is not worth it, and the
    /// OS temp directory is the right place for a few kilobytes.
    fn ca_file(pem: &str, tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sni-gate-verify-test-{}-{tag}.pem",
            std::process::id()
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        path
    }

    /// Run one policy against one leaf, as rustls would.
    fn check(policy: &EffectiveVerify, chain: &Chain, requested: &str) -> Result<(), TlsError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let built = VerifierFactory::new()
            .get(policy, "test")
            .expect("policy builds");
        let name = ServerName::try_from(requested.to_string()).unwrap();
        built
            .verifier()
            .verify_server_cert(
                &chain.leaf,
                &[],
                &name,
                &[],
                // rcgen's default validity starts "now", so verify against now.
                UnixTime::now(),
            )
            .map(|_| ())
    }

    fn policy(mode: VerifyMode) -> EffectiveVerify {
        EffectiveVerify {
            mode,
            ..EffectiveVerify::default()
        }
    }

    /// The default policy is exactly the web-PKI check: a private CA's leaf is
    /// refused, and nothing about the name can rescue it.
    #[test]
    fn the_default_policy_rejects_an_untrusted_chain() {
        let chain = chain_for(&["right.test"]);
        let err = check(&EffectiveVerify::default(), &chain, "right.test")
            .expect_err("an unknown CA must not be trusted");
        assert!(
            matches!(err, TlsError::InvalidCertificate(_)),
            "unexpected error {err:?}"
        );
    }

    /// The reported bug, reduced: the upstream answers with a certificate for a
    /// name the route never asked for.
    #[test]
    fn full_verification_refuses_a_certificate_for_another_name() {
        let chain = chain_for(&["default.test"]);
        let trusted = EffectiveVerify {
            ca_file: Some(ca_file(&chain.ca_pem, "wrong-name")),
            ..EffectiveVerify::default()
        };
        let err = check(&trusted, &chain, "asked.test").expect_err("name mismatch must fail");
        assert!(
            matches!(
                err,
                TlsError::InvalidCertificate(
                    CertificateError::NotValidForName
                        | CertificateError::NotValidForNameContext { .. }
                )
            ),
            "unexpected error {err:?}"
        );

        // …and the two ways to accept it deliberately: name the certificate the
        // upstream really serves, or stop checking the name.
        let by_name = EffectiveVerify {
            name: Some("default.test".to_string()),
            ..trusted.clone()
        };
        check(&by_name, &chain, "asked.test").expect("a matching `name` override verifies");

        let by_mode = EffectiveVerify {
            mode: VerifyMode::Chain,
            ..trusted
        };
        check(&by_mode, &chain, "asked.test").expect("chain mode ignores the name");
    }

    /// `chain` drops the name check and *only* the name check: an untrusted
    /// chain is still refused.
    #[test]
    fn chain_mode_still_requires_a_trust_anchor() {
        let chain = chain_for(&["default.test"]);
        let err = check(&policy(VerifyMode::Chain), &chain, "asked.test")
            .expect_err("chain mode must still build a chain");
        assert!(
            matches!(err, TlsError::InvalidCertificate(_)),
            "unexpected error {err:?}"
        );
    }

    /// A `name` override is checked as strictly as the requested name would be.
    #[test]
    fn a_name_override_is_not_a_free_pass() {
        let chain = chain_for(&["default.test"]);
        let wrong = EffectiveVerify {
            name: Some("elsewhere.test".to_string()),
            ca_file: Some(ca_file(&chain.ca_pem, "override")),
            ..EffectiveVerify::default()
        };
        assert!(
            check(&wrong, &chain, "default.test").is_err(),
            "a `name` that the certificate does not cover must fail, even though the \
             requested name would have matched"
        );
    }

    /// `none` accepts an unrelated self-signed certificate — and pins are what
    /// make that configuration sound again.
    #[test]
    fn pins_bind_an_unverified_upstream_to_one_key() {
        let chain = chain_for(&["default.test"]);
        let other = chain_for(&["default.test"]);

        check(&policy(VerifyMode::None), &chain, "asked.test")
            .expect("mode none accepts any certificate");

        let pinned = EffectiveVerify {
            mode: VerifyMode::None,
            pins: vec![chain.pin.clone()],
            ..EffectiveVerify::default()
        };
        check(&pinned, &chain, "asked.test").expect("the pinned key is accepted");
        let err = check(&pinned, &other, "asked.test")
            .expect_err("a different key must be refused even with the same name");
        assert!(
            format!("{err}").contains("verify.pins"),
            "the error should name the pins: {err}"
        );
    }

    /// Pins compose with, rather than replace, the mode's own requirements.
    #[test]
    fn pins_do_not_relax_the_mode() {
        let chain = chain_for(&["default.test"]);
        let full_and_pinned = EffectiveVerify {
            pins: vec![chain.pin.clone()],
            ..EffectiveVerify::default()
        };
        assert!(
            check(&full_and_pinned, &chain, "default.test").is_err(),
            "a correct pin must not excuse an untrusted chain under mode = full"
        );
    }

    /// `trust_webpki = false` narrows trust to the supplied anchors: the private
    /// leaf verifies, and the public roots are gone.
    #[test]
    fn trust_webpki_false_replaces_the_public_roots() {
        let chain = chain_for(&["private.test"]);
        let only_private = EffectiveVerify {
            ca_file: Some(ca_file(&chain.ca_pem, "only")),
            trust_webpki: false,
            ..EffectiveVerify::default()
        };
        check(&only_private, &chain, "private.test").expect("the private anchor verifies");

        let public = chain_for(&["private.test"]);
        assert!(
            check(&only_private, &public, "private.test").is_err(),
            "another CA must not be trusted"
        );
    }

    /// A policy that names no anchors at all cannot verify anything, so it is
    /// refused at build time rather than accepting everything at runtime.
    #[test]
    fn no_anchors_at_all_is_a_build_error() {
        let policy = EffectiveVerify {
            trust_webpki: false,
            ..EffectiveVerify::default()
        };
        let err = VerifierFactory::new()
            .get(&policy, "test")
            .expect_err("no anchors must be an error");
        assert!(
            format!("{err:#}").contains("trust anchors"),
            "unexpected error {err:#}"
        );
    }

    /// Only the untouched policy reports itself as default — the signal a caller
    /// uses to leave a library's own equivalent defaults alone.
    #[test]
    fn only_the_untouched_policy_is_the_default_one() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut factory = VerifierFactory::new();
        assert!(factory
            .get(&EffectiveVerify::default(), "test")
            .unwrap()
            .is_default());

        for weaker in [
            policy(VerifyMode::Chain),
            policy(VerifyMode::None),
            EffectiveVerify {
                name: Some("other.test".to_string()),
                ..EffectiveVerify::default()
            },
            EffectiveVerify {
                pins: vec![encode_pin(&[0u8; 32])],
                ..EffectiveVerify::default()
            },
        ] {
            let built = factory.get(&weaker, "test").unwrap();
            assert!(!built.is_default(), "{} is not the default", built.label());
        }
    }

    /// Equal policies share one verifier, so a hundred routes on the default
    /// policy do not mean a hundred copies of the root store.
    #[test]
    fn equal_policies_share_one_verifier() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut factory = VerifierFactory::new();
        let a = factory.get(&EffectiveVerify::default(), "a").unwrap();
        let b = factory.get(&EffectiveVerify::default(), "b").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn policies_render_readably() {
        assert_eq!(describe(&EffectiveVerify::default()), "full");
        assert_eq!(
            describe(&EffectiveVerify {
                name: Some("a.example".into()),
                ..EffectiveVerify::default()
            }),
            "full name=a.example"
        );
        assert_eq!(
            describe(&EffectiveVerify {
                mode: VerifyMode::None,
                pins: vec!["sha256/AA".into(), "sha256/BB".into()],
                ..EffectiveVerify::default()
            }),
            "none +2 pins"
        );
    }
}
