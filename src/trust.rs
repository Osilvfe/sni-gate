//! Installation of the CA certificate into the OS trusted-root store.
//!
//! This is a sensitive, privileged operation, so it is reached only through
//! `ca.install_to_system_root` or `--install-ca`. It is idempotent: a
//! certificate with the same thumbprint already in the store is left alone.
//!
//! **Windows** uses CryptoAPI (`crypt32`) in-process — no PowerShell, no
//! `certutil`, no temp files. **macOS** uses the `security` command-line tool,
//! which is the standard Apple-recommended method. **Linux** detects the
//! distribution and uses the appropriate certificate-management tooling
//! (update-ca-certificates, update-ca-trust, or trust extract-compat).

use anyhow::Result;
use rustls::pki_types::CertificateDer;

/// What `ensure_installed` had to do, for the caller to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The certificate was added to the trusted-root store.
    Installed { fingerprint: String },
    /// A certificate with this thumbprint was already trusted; the store is
    /// unchanged.
    AlreadyTrusted { fingerprint: String },
}

impl Outcome {
    /// Uppercase hex SHA-1 thumbprint (Windows) or SHA-256 (macOS/Linux), the
    /// form the OS store displays.
    pub fn fingerprint(&self) -> &str {
        match self {
            Self::Installed { fingerprint } | Self::AlreadyTrusted { fingerprint } => fingerprint,
        }
    }
}

/// Ensure the CA certificate is present in the OS trusted-root store.
///
/// Requires elevated privileges: Administrator on Windows, root/sudo on
/// macOS/Linux. The implementation is platform-native and idempotent.
pub fn ensure_installed(ca_der: &CertificateDer<'_>) -> Result<Outcome> {
    #[cfg(windows)]
    {
        windows::ensure_installed(ca_der.as_ref())
    }
    #[cfg(target_os = "macos")]
    {
        macos::ensure_installed(ca_der.as_ref())
    }
    #[cfg(target_os = "linux")]
    {
        linux::ensure_installed(ca_der.as_ref())
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = ca_der;
        anyhow::bail!(
            "automatic CA installation is not implemented for this platform; \
             import the CA certificate with this platform's trust-store tooling"
        );
    }
}

// ===========================================================================
// Windows: CryptoAPI (crypt32.dll) in-process
// ===========================================================================

#[cfg(windows)]
mod windows {
    use super::Outcome;
    use anyhow::{Context, Result};
    use std::ffi::c_void;
    use std::fmt::Write as _;
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, CRYPT_E_EXISTS};
    use windows_sys::Win32::Security::Cryptography::{
        CertAddCertificateContextToStore, CertCloseStore, CertCreateCertificateContext,
        CertFindCertificateInStore, CertFreeCertificateContext, CertGetCertificateContextProperty,
        CertOpenStore, CERT_CONTEXT, CERT_FIND_SHA1_HASH, CERT_SHA1_HASH_PROP_ID,
        CERT_STORE_ADD_NEW, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB, HCERTSTORE, X509_ASN_ENCODING,
    };

    /// `GetLastError` value for "a certificate with this identity is already in
    /// the store", which `CERT_STORE_ADD_NEW` reports instead of overwriting.
    const ALREADY_IN_STORE: u32 = CRYPT_E_EXISTS as u32;

    /// UTF-16, NUL-terminated name of the Trusted Root Certification
    /// Authorities store, as `CERT_STORE_PROV_SYSTEM_W` expects in `pvPara`.
    const ROOT_STORE_W: [u16; 5] = [b'R' as u16, b'O' as u16, b'O' as u16, b'T' as u16, 0];

    pub fn ensure_installed(der: &[u8]) -> Result<Outcome> {
        let cert = CertContext::decode(der)?;
        let mut thumbprint = cert.sha1_thumbprint()?;
        let fingerprint = hex_upper(&thumbprint);
        let store = CertStore::open_machine_root()?;

        if store.contains_thumbprint(&mut thumbprint) {
            return Ok(Outcome::AlreadyTrusted { fingerprint });
        }

        store.add_new(&cert).with_context(|| {
            format!("installing CA {fingerprint} into the LocalMachine Root store")
        })?;
        Ok(Outcome::Installed { fingerprint })
    }

    /// Owned `CERT_CONTEXT`, freed on drop.
    struct CertContext {
        ptr: *const CERT_CONTEXT,
    }

    impl CertContext {
        /// Decode a DER certificate into an in-memory context.
        fn decode(der: &[u8]) -> Result<Self> {
            let len = u32::try_from(der.len())
                .context("CA certificate is too large for CryptoAPI to decode")?;

            // SAFETY: `der` is a readable range of exactly `len` bytes, and
            // CryptoAPI copies what it needs into the returned context.
            let ptr = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), len) };
            if ptr.is_null() {
                return Err(last_os_error()).context("decoding the CA certificate");
            }
            Ok(Self { ptr })
        }

        /// The SHA-1 thumbprint CryptoAPI computes for this certificate.
        fn sha1_thumbprint(&self) -> Result<Vec<u8>> {
            let mut len: u32 = 0;
            // SAFETY: a null buffer with a valid length out-pointer is the
            // documented way to ask for the required size.
            let sized = unsafe {
                CertGetCertificateContextProperty(
                    self.ptr,
                    CERT_SHA1_HASH_PROP_ID,
                    ptr::null_mut(),
                    &mut len,
                )
            };
            if sized == 0 {
                return Err(last_os_error()).context("sizing the CA certificate thumbprint");
            }

            let mut hash = vec![0u8; len as usize];
            // SAFETY: `hash` holds exactly the `len` bytes just asked for, and
            // `len` is updated in place with the count actually written.
            let read = unsafe {
                CertGetCertificateContextProperty(
                    self.ptr,
                    CERT_SHA1_HASH_PROP_ID,
                    hash.as_mut_ptr().cast::<c_void>(),
                    &mut len,
                )
            };
            if read == 0 {
                return Err(last_os_error()).context("reading the CA certificate thumbprint");
            }
            hash.truncate(len as usize);
            Ok(hash)
        }
    }

    impl Drop for CertContext {
        fn drop(&mut self) {
            // SAFETY: `ptr` came from CertCreateCertificateContext, is
            // non-null, and is freed exactly once.
            unsafe { CertFreeCertificateContext(self.ptr) };
        }
    }

    /// Owned system-store handle, closed on drop.
    struct CertStore {
        handle: HCERTSTORE,
    }

    impl CertStore {
        /// Open `LocalMachine\ROOT` for writing, without creating it.
        fn open_machine_root() -> Result<Self> {
            // SAFETY: the provider is the integer pseudo-pointer CryptoAPI
            // defines for system stores, and `pvPara` is the NUL-terminated
            // wide store name it reads for that provider.
            let handle = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    0,
                    CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG,
                    ROOT_STORE_W.as_ptr().cast::<c_void>(),
                )
            };
            if handle.is_null() {
                return Err(last_os_error()).context(
                    "opening the LocalMachine Root certificate store for writing \
                     (Administrator is required)",
                );
            }
            Ok(Self { handle })
        }

        /// True if some certificate in the store has this SHA-1 thumbprint.
        ///
        /// The thumbprint covers the whole encoded certificate, so a match
        /// means the identical certificate is already trusted.
        fn contains_thumbprint(&self, thumbprint: &mut [u8]) -> bool {
            let blob = CRYPT_INTEGER_BLOB {
                cbData: thumbprint.len() as u32,
                pbData: thumbprint.as_mut_ptr(),
            };

            // SAFETY: the store handle is live, `blob` is the search parameter
            // CERT_FIND_SHA1_HASH expects and outlives the call, and a null
            // `pPrevCertContext` starts the search from the beginning.
            let found = unsafe {
                CertFindCertificateInStore(
                    self.handle,
                    X509_ASN_ENCODING,
                    0,
                    CERT_FIND_SHA1_HASH,
                    ptr::from_ref(&blob).cast::<c_void>(),
                    ptr::null(),
                )
            };
            if found.is_null() {
                return false;
            }

            // The search hands back a context we own; we only needed its
            // existence.
            drop(CertContext { ptr: found });
            true
        }

        /// Add a certificate, failing rather than replacing an existing entry.
        fn add_new(&self, cert: &CertContext) -> Result<()> {
            // SAFETY: both handles are live for this call, and a null
            // `ppStoreContext` declines the copy the store would otherwise
            // hand back for us to free.
            let added = unsafe {
                CertAddCertificateContextToStore(
                    self.handle,
                    cert.ptr,
                    CERT_STORE_ADD_NEW,
                    ptr::null_mut(),
                )
            };
            if added != 0 {
                return Ok(());
            }

            // Losing a race with a concurrent install is still success: the
            // thumbprint check above found nothing, so whatever landed first
            // is this same certificate.
            match unsafe { GetLastError() } {
                ALREADY_IN_STORE => Ok(()),
                code => Err(os_error(code).into()),
            }
        }
    }

    impl Drop for CertStore {
        fn drop(&mut self) {
            // SAFETY: `handle` came from CertOpenStore and is closed once;
            // zero flags means "just release our reference".
            unsafe { CertCloseStore(self.handle, 0) };
        }
    }

    /// Uppercase hex, the thumbprint form the OS store displays.
    fn hex_upper(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(hex, "{b:02X}");
        }
        hex
    }

    /// The calling thread's last CryptoAPI error, as an `io::Error` so it
    /// renders with the system's own message.
    fn last_os_error() -> anyhow::Error {
        // SAFETY: no preconditions; reads thread-local state.
        os_error(unsafe { GetLastError() }).into()
    }

    fn os_error(code: u32) -> std::io::Error {
        std::io::Error::from_raw_os_error(code as i32)
    }
}

// ===========================================================================
// macOS: `security` command-line tool
// ===========================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::Outcome;
    use anyhow::{bail, Context, Result};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::process::Command;

    const KEYCHAIN: &str = "/Library/Keychains/System.keychain";

    pub fn ensure_installed(der: &[u8]) -> Result<Outcome> {
        let fingerprint = sha256_hex(der);

        if is_present(&fingerprint)? {
            return Ok(Outcome::AlreadyTrusted { fingerprint });
        }

        // The `security` tool reads from a file, so write the DER to a temp
        // location. Use a deterministic name so concurrent installs of the
        // same CA don't trip over each other.
        let tmp = std::env::temp_dir().join(format!("sni-gate-ca-{fingerprint}.cer"));
        fs::write(&tmp, der)
            .with_context(|| format!("writing CA to temp file {}", tmp.display()))?;

        let result = add_cert(&tmp);
        let _ = fs::remove_file(&tmp);

        result.with_context(|| format!("installing CA {fingerprint} into {KEYCHAIN}"))?;
        Ok(Outcome::Installed { fingerprint })
    }

    /// True if a certificate with this SHA-256 fingerprint is already trusted
    /// in the system keychain.
    fn is_present(fingerprint: &str) -> Result<bool> {
        let output = Command::new("security")
            .args(["find-certificate", "-Z", "-a", KEYCHAIN])
            .output()
            .context("running `security find-certificate`")?;

        if !output.status.success() {
            // If the keychain doesn't exist or is unreadable, treat it as
            // "not present" rather than failing — the subsequent add will
            // fail with a more actionable error.
            return Ok(false);
        }

        // Output format: "SHA-256 hash: ABCD1234...\n" repeated for each cert.
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .filter_map(|line| line.strip_prefix("SHA-256 hash: "))
            .any(|hash| hash.eq_ignore_ascii_case(fingerprint)))
    }

    fn add_cert(path: &std::path::Path) -> Result<()> {
        let output = Command::new("security")
            .args([
                "add-trusted-cert",
                "-d",        // Add to admin trust settings
                "-r",        // Result type
                "trustRoot", // Trust as a root CA
                "-k",        // Target keychain
                KEYCHAIN,
                path.to_str().unwrap(),
            ])
            .output()
            .context("running `security add-trusted-cert` (requires root/sudo)")?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`security add-trusted-cert` failed (need root/sudo?): {}",
            stderr.trim()
        );
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let hash = Sha256::digest(bytes);
        let mut hex = String::with_capacity(hash.len() * 2);
        use std::fmt::Write as _;
        for b in hash {
            let _ = write!(hex, "{b:02X}");
        }
        hex
    }
}

// ===========================================================================
// Linux: distribution-specific certificate stores
// ===========================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::Outcome;
    use anyhow::{bail, Context, Result};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    pub fn ensure_installed(der: &[u8]) -> Result<Outcome> {
        let fingerprint = sha256_hex(der);
        let distro = detect_distro()?;

        let cert_path = distro
            .cert_dir
            .join(format!("sni-gate-ca-{}.crt", &fingerprint[..16]));

        if cert_path.exists() {
            return Ok(Outcome::AlreadyTrusted { fingerprint });
        }

        // Write the certificate in PEM format (most tools expect PEM).
        let pem = pem_encode(der);
        fs::write(&cert_path, pem).with_context(|| {
            format!("writing CA to {} (requires root/sudo)", cert_path.display())
        })?;

        // Run the distribution's update command to register the new cert.
        let output = Command::new(&distro.update_cmd[0])
            .args(&distro.update_cmd[1..])
            .output()
            .with_context(|| format!("running {:?}", distro.update_cmd))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = fs::remove_file(&cert_path);
            bail!("{} failed: {}", distro.update_cmd[0], stderr.trim());
        }

        Ok(Outcome::Installed { fingerprint })
    }

    struct Distro {
        cert_dir: PathBuf,
        update_cmd: Vec<String>,
    }

    fn detect_distro() -> Result<Distro> {
        // Read /etc/os-release to identify the distribution.
        let os_release = fs::read_to_string("/etc/os-release")
            .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
            .context("reading /etc/os-release to detect Linux distribution")?;

        let id = os_release
            .lines()
            .find_map(|line| line.strip_prefix("ID="))
            .map(|s| s.trim_matches('"'))
            .unwrap_or("");

        let id_like = os_release
            .lines()
            .find_map(|line| line.strip_prefix("ID_LIKE="))
            .map(|s| s.trim_matches('"'))
            .unwrap_or("");

        // Match by ID, falling back to ID_LIKE for derivatives.
        let all_ids = format!("{id} {id_like}");

        if all_ids.contains("debian") || all_ids.contains("ubuntu") {
            return Ok(Distro {
                cert_dir: PathBuf::from("/usr/local/share/ca-certificates"),
                update_cmd: vec!["update-ca-certificates".into()],
            });
        }

        if all_ids.contains("rhel") || all_ids.contains("fedora") || all_ids.contains("centos") {
            return Ok(Distro {
                cert_dir: PathBuf::from("/etc/pki/ca-trust/source/anchors"),
                update_cmd: vec!["update-ca-trust".into()],
            });
        }

        if all_ids.contains("arch") || all_ids.contains("manjaro") {
            return Ok(Distro {
                cert_dir: PathBuf::from("/etc/ca-certificates/trust-source/anchors"),
                update_cmd: vec!["trust".into(), "extract-compat".into()],
            });
        }

        bail!(
            "unsupported Linux distribution (ID={id:?}, ID_LIKE={id_like:?}); \
             manually import the CA certificate into your system trust store"
        );
    }

    fn pem_encode(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut pem = String::with_capacity(der.len() * 4 / 3 + 128);
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let hash = Sha256::digest(bytes);
        let mut hex = String::with_capacity(hash.len() * 2);
        use std::fmt::Write as _;
        for b in hash {
            let _ = write!(hex, "{b:02X}");
        }
        hex
    }
}
