//! On-disk persistence of issued certificates.
//!
//! Certificates live at `<dir>/<scope>/<base>.crt` (PEM chain, leaf first) with a
//! matching `.key` (PEM PKCS#8). Two keys address a certificate:
//!
//! * **scope** — the certificate partition ([`crate::certscope::CertScope`]).
//!   Names that route to different upstreams must never share a certificate, so
//!   they must never share a file either: without this level, two partitions for
//!   one registrable domain would overwrite each other, and a reload would serve
//!   whichever wrote last to *both* — reintroducing exactly the cross-route
//!   coverage the partitioning exists to prevent.
//! * **base** — the coverage anchor within that scope (the registrable domain, or
//!   the host for IP literals and names with no registrable domain).
//!
//! Both components are plain, path-safe names (a scope key is sanitized at
//! construction; a base is never a wildcard), so each maps directly to one path
//! component. A stored certificate is only reused when it actually covers the
//! requested host (see [`crate::suffix::host_covered_by`]), so a change to
//! `[issuance] mode` can never serve a certificate whose coverage no longer fits
//! — it is simply re-issued.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::{Duration, OffsetDateTime};

use crate::certscope::CertScope;

/// Manages the certificate directory.
pub struct CertStore {
    dir: PathBuf,
    /// Re-issue when a persisted certificate is within this margin of expiry.
    renew_margin: Duration,
}

/// Certificate material loaded from disk.
pub struct StoredCertificate {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub not_after: OffsetDateTime,
    /// The leaf's subject alternative names, used to decide whether this
    /// certificate covers the requested host before reusing it.
    pub sans: Vec<String>,
}

impl CertStore {
    pub fn new(dir: PathBuf, renew_margin_days: u32) -> Self {
        Self {
            dir,
            renew_margin: Duration::days(i64::from(renew_margin_days)),
        }
    }

    /// Ensure the store directory exists.
    pub fn init(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating certificate store {}", self.dir.display()))
    }

    /// Directory holding one scope's certificates.
    fn scope_dir(&self, scope: &CertScope) -> PathBuf {
        self.dir.join(scope.key())
    }

    fn cert_path(&self, scope: &CertScope, base: &str) -> PathBuf {
        self.scope_dir(scope).join(format!("{base}.crt"))
    }

    fn key_path(&self, scope: &CertScope, base: &str) -> PathBuf {
        self.scope_dir(scope).join(format!("{base}.key"))
    }

    /// Load the persisted certificate for `base` **within `scope`**, if present
    /// and not within the renewal margin of expiry. Returns `None` to signal
    /// "issue a fresh one".
    pub fn load(&self, scope: &CertScope, base: &str) -> Option<StoredCertificate> {
        let cert_path = self.cert_path(scope, base);
        let key_path = self.key_path(scope, base);
        if !cert_path.exists() || !key_path.exists() {
            return None;
        }
        match self.load_inner(&cert_path, &key_path) {
            Ok(stored) if !self.needs_renewal(stored.not_after) => Some(stored),
            Ok(_) => {
                tracing::debug!(scope = %scope, base, "persisted certificate near expiry; will re-issue");
                None
            }
            Err(err) => {
                tracing::warn!(
                    scope = %scope,
                    base,
                    error = %err,
                    "failed to load persisted certificate; re-issuing"
                );
                None
            }
        }
    }

    fn load_inner(&self, cert_path: &Path, key_path: &Path) -> Result<StoredCertificate> {
        let cert_pem = std::fs::read(cert_path).context("reading persisted certificate")?;
        let key_pem = std::fs::read(key_path).context("reading persisted key")?;

        let chain = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parsing persisted certificate chain")?;
        anyhow::ensure!(!chain.is_empty(), "persisted certificate chain is empty");

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("parsing persisted private key")?
            .context("persisted key file contains no private key")?;

        let (not_after, sans) =
            leaf_metadata(&chain[0]).context("reading persisted certificate metadata")?;

        Ok(StoredCertificate {
            chain,
            key,
            not_after,
            sans,
        })
    }

    /// Persist a certificate chain and key for `base` **within `scope`**, written
    /// atomically so a crash mid-write never leaves a half-file that would fail
    /// to load. The scope directory is created on demand.
    pub fn save(
        &self,
        scope: &CertScope,
        base: &str,
        chain_pem: &str,
        key_pem: &str,
    ) -> Result<()> {
        let dir = self.scope_dir(scope);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating scope directory {}", dir.display()))?;
        write_atomic(&self.cert_path(scope, base), chain_pem.as_bytes())
            .context("persisting certificate chain")?;
        write_atomic_private(&self.key_path(scope, base), key_pem.as_bytes())
            .context("persisting private key")?;
        Ok(())
    }

    fn needs_renewal(&self, not_after: OffsetDateTime) -> bool {
        OffsetDateTime::now_utc() + self.renew_margin >= not_after
    }
}

/// Extract the `notAfter` time and the DNS/IP subject-alternative-names from a
/// DER-encoded certificate, so a reload knows both when it expires and which
/// hosts it covers.
fn leaf_metadata(der: &CertificateDer<'_>) -> Result<(OffsetDateTime, Vec<String>)> {
    use x509_parser::prelude::{FromDer, GeneralName};
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
        .map_err(|e| anyhow::anyhow!("parsing certificate DER: {e}"))?;

    let ts = cert.validity().not_after.timestamp();
    let not_after =
        OffsetDateTime::from_unix_timestamp(ts).context("certificate notAfter out of range")?;

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                GeneralName::DNSName(d) => sans.push((*d).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_from_bytes(bytes) {
                        sans.push(ip);
                    }
                }
                _ => {}
            }
        }
    }
    Ok((not_after, sans))
}

/// Render a SAN IP-address octet string (4 or 16 bytes) back to its textual form.
fn ip_from_bytes(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let a: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::Ipv4Addr::from(a).to_string())
        }
        16 => {
            let a: [u8; 16] = bytes.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(a).to_string())
        }
        _ => None,
    }
}

/// The staging path for an atomic write: the target with `.tmp` **appended**.
///
/// Appending rather than replacing the extension matters: `with_extension("tmp")`
/// maps both `x.crt` and `x.key` onto the same `x.tmp`, so the chain and key of
/// one certificate would stage through a single file. Today the resolver's
/// single-flight lock serializes them, but that is an accident of the caller, not
/// a property of this function.
fn staging_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.file_name().unwrap_or_default());
    name.push(".tmp");
    path.with_file_name(name)
}

/// Atomically write `bytes` to `path` via a temporary file + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = staging_path(path);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Atomically write a private key, restricting permissions where supported.
fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = staging_path(path);
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_paths_do_not_collide_between_chain_and_key() {
        let crt = Path::new("certs/scope/example.com.crt");
        let key = Path::new("certs/scope/example.com.key");
        assert_ne!(
            staging_path(crt),
            staging_path(key),
            "chain and key must stage through distinct files"
        );
        assert_eq!(
            staging_path(crt).file_name().unwrap(),
            "example.com.crt.tmp"
        );
        // Staging stays in the same directory, so the rename is atomic.
        assert_eq!(staging_path(crt).parent(), crt.parent());
    }
}
