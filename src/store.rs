//! On-disk persistence of issued certificates.
//!
//! Certificates live at `<dir>/<scope>/<host>.crt` (PEM chain, leaf first) with a
//! matching `.key` (PEM PKCS#8) and an optional `.observed` sidecar. Two keys
//! address a certificate:
//!
//! * **scope** — the certificate partition ([`crate::certscope::CertScope`]).
//!   Names that route to different upstreams must never share a certificate, so
//!   they must never share a file either: without this level, two partitions for
//!   one host would overwrite each other, and a reload would serve whichever
//!   wrote last to *both* — reintroducing exactly the cross-route coverage the
//!   partitioning exists to prevent.
//! * **host** — the exact SNI name the certificate was issued for. Sibling names
//!   get sibling files, because the upstream may answer them with different
//!   certificates and this gateway mirrors each one separately (see
//!   [`crate::resolver`]).
//!
//! Both components are plain, path-safe names (a scope key is sanitized at
//! construction; a host is never a wildcard), so each maps directly to one path
//! component. A stored certificate is only reused when it actually covers the
//! requested host (see [`crate::suffix::host_covered_by`]), so a file that no
//! longer fits is re-issued rather than served.
//!
//! # The `.observed` sidecar
//!
//! A mirrored certificate is only meaningful together with the upstream SANs it
//! was built from: that set is what a later handshake is compared against to
//! detect rotation. Without it a restart would treat every mirrored certificate
//! as unobserved and re-sign on the next connection, and — worse — could not tell
//! a *narrowed* upstream from an unchanged one.
//!
//! The format is one DNS name per line, UTF-8, no escaping: DNS names cannot
//! contain a newline, so the encoding is unambiguous without a parser. File
//! presence is the discriminant — an absent sidecar means "never observed"
//! (an exact certificate), while an empty one means "observed, and it carried no
//! DNS names".

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
    /// The upstream SANs this certificate was mirrored from, if it was mirrored
    /// at all. `None` means the certificate is exact and the upstream has never
    /// been observed — the next observation will mirror it for the first time.
    pub observed: Option<Vec<String>>,
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

    fn cert_path(&self, scope: &CertScope, host: &str) -> PathBuf {
        self.scope_dir(scope).join(format!("{host}.crt"))
    }

    fn key_path(&self, scope: &CertScope, host: &str) -> PathBuf {
        self.scope_dir(scope).join(format!("{host}.key"))
    }

    /// Sidecar recording the upstream SANs a mirrored certificate was built from.
    fn observed_path(&self, scope: &CertScope, host: &str) -> PathBuf {
        self.scope_dir(scope).join(format!("{host}.observed"))
    }

    /// Load the persisted certificate for `host` **within `scope`**, if present
    /// and not within the renewal margin of expiry. Returns `None` to signal
    /// "issue a fresh one".
    pub fn load(&self, scope: &CertScope, host: &str) -> Option<StoredCertificate> {
        let cert_path = self.cert_path(scope, host);
        let key_path = self.key_path(scope, host);
        if !cert_path.exists() || !key_path.exists() {
            return None;
        }
        match self.load_inner(&cert_path, &key_path, &self.observed_path(scope, host)) {
            Ok(stored) if !self.needs_renewal(stored.not_after) => Some(stored),
            Ok(_) => {
                tracing::debug!(scope = %scope, host, "persisted certificate near expiry; will re-issue");
                None
            }
            Err(err) => {
                tracing::warn!(
                    scope = %scope,
                    host,
                    error = %err,
                    "failed to load persisted certificate; re-issuing"
                );
                None
            }
        }
    }

    fn load_inner(
        &self,
        cert_path: &Path,
        key_path: &Path,
        observed_path: &Path,
    ) -> Result<StoredCertificate> {
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

        // A missing sidecar means "never observed"; an unreadable one is treated
        // the same way, costing one re-mirror rather than failing the load and
        // discarding a perfectly good certificate.
        let observed = match std::fs::read_to_string(observed_path) {
            Ok(text) => Some(decode_observed(&text)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                tracing::warn!(
                    path = %observed_path.display(),
                    error = %err,
                    "failed to read upstream-SAN sidecar; the upstream will be re-observed"
                );
                None
            }
        };

        Ok(StoredCertificate {
            chain,
            key,
            not_after,
            sans,
            observed,
        })
    }

    /// Persist a certificate chain and key for `host` **within `scope`**, written
    /// atomically so a crash mid-write never leaves a half-file that would fail
    /// to load. The scope directory is created on demand.
    ///
    /// `observed` is the upstream SAN set this certificate mirrors, or `None` for
    /// an exact certificate issued before the upstream was ever seen. Writing it
    /// is what lets a restart tell an unchanged upstream from a rotated one.
    pub fn save(
        &self,
        scope: &CertScope,
        host: &str,
        chain_pem: &str,
        key_pem: &str,
        observed: Option<&[String]>,
    ) -> Result<()> {
        let dir = self.scope_dir(scope);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating scope directory {}", dir.display()))?;
        write_atomic(&self.cert_path(scope, host), chain_pem.as_bytes())
            .context("persisting certificate chain")?;
        write_atomic_private(&self.key_path(scope, host), key_pem.as_bytes())
            .context("persisting private key")?;

        // Written last, and removed rather than left behind: the sidecar claims
        // "this certificate mirrors that upstream", so it must never survive a
        // certificate it no longer describes. A stale sidecar would make a
        // rotated upstream look unchanged, which is the one comparison that must
        // not produce a false negative.
        let observed_path = self.observed_path(scope, host);
        match observed {
            Some(sans) => write_atomic(&observed_path, encode_observed(sans).as_bytes())
                .context("persisting upstream SAN sidecar")?,
            None => match std::fs::remove_file(&observed_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("removing stale sidecar {}", observed_path.display())
                    })
                }
            },
        }
        Ok(())
    }

    fn needs_renewal(&self, not_after: OffsetDateTime) -> bool {
        OffsetDateTime::now_utc() + self.renew_margin >= not_after
    }
}

/// Encode an observed upstream SAN set: one name per line, trailing newline.
///
/// A DNS name cannot contain a newline, so no escaping or quoting is needed and
/// the file stays greppable next to the certificate it describes.
fn encode_observed(sans: &[String]) -> String {
    let mut out = String::new();
    for san in sans {
        out.push_str(san);
        out.push('\n');
    }
    out
}

/// Decode an observed upstream SAN set, tolerating either line ending and
/// ignoring blank lines. Order is preserved: it is compared for equality against
/// a freshly observed set, and the upstream reports its SANs in a stable order.
fn decode_observed(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
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

    #[test]
    fn staging_path_of_the_sidecar_collides_with_neither() {
        let crt = Path::new("certs/scope/example.com.crt");
        let obs = Path::new("certs/scope/example.com.observed");
        assert_ne!(staging_path(crt), staging_path(obs));
        assert_eq!(
            staging_path(obs).file_name().unwrap(),
            "example.com.observed.tmp"
        );
    }

    #[test]
    fn observed_sidecar_round_trips() {
        let sans = vec![
            "qy0.ru".to_string(),
            "*.qy0.ru".to_string(),
            "mzz.qy0.ru".to_string(),
        ];
        assert_eq!(decode_observed(&encode_observed(&sans)), sans);
    }

    #[test]
    fn observed_sidecar_preserves_order_and_distinguishes_empty_from_absent() {
        // Order is part of the comparison against a fresh observation, so it must
        // survive the round trip rather than being normalized away.
        let a = vec!["b.example".to_string(), "a.example".to_string()];
        assert_eq!(decode_observed(&encode_observed(&a)), a);
        assert_ne!(
            decode_observed(&encode_observed(&a)),
            vec!["a.example".to_string(), "b.example".to_string()]
        );

        // An observed-but-empty set encodes to an empty file. "Absent" is a
        // missing file, which `load_inner` reports as `None` — never confused
        // with this.
        assert_eq!(encode_observed(&[]), "");
        assert_eq!(decode_observed(""), Vec::<String>::new());
    }

    #[test]
    fn observed_sidecar_tolerates_crlf_and_blank_lines() {
        // A file that has been through a Windows editor must still parse.
        assert_eq!(
            decode_observed("qy0.ru\r\n\r\n*.qy0.ru\r\n"),
            vec!["qy0.ru".to_string(), "*.qy0.ru".to_string()]
        );
    }
}
