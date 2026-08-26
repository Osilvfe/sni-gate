//! Public Suffix List management: loading, auto-update, and hot-reload.
//!
//! The PSL marks the registry boundaries a minted wildcard must not cross (see
//! [`crate::suffix`]). This module supports three modes:
//!
//! - **Embedded**: compiled-in PSL, zero dependencies, may be stale.
//! - **File (manual)**: user maintains the file, sni-gate loads it.
//! - **File (auto-update)**: sni-gate downloads and refreshes the file.
//!
//! When `auto_update = true`, the file is checked against `max_age` at startup
//! and optionally at runtime (if `check_interval` is set). When `auto_reload = true`,
//! file changes (from any source) trigger a hot-reload via file-system watching.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use crate::config::{PslConfig, PslSource};
use crate::suffix::SuffixList;

const UPDATE_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";

/// Initialize PSL and spawn background tasks.
pub async fn init(cfg: &PslConfig) -> Result<Arc<SuffixList>> {
    let psl = Arc::new(load_initial(cfg).await?);

    if cfg.auto_reload && cfg.source == PslSource::File {
        // Only start file watcher if the file exists. When auto_update downloads
        // the file later, the watcher will be absent, but that's acceptable:
        // the update task will write the file and subsequent restarts will arm
        // the watcher. Without this guard, a missing file causes inotify to fail
        // on Linux and startup aborts even though load_initial succeeded via the
        // embedded fallback.
        if cfg.path.exists() {
            spawn_reload_task(cfg.clone(), psl.clone())?;
        } else {
            tracing::info!(
                path = %cfg.path.display(),
                "auto_reload requested but PSL file does not exist; watcher will not start \
                 until file is created"
            );
        }
    }

    if let Some(interval) = cfg.check_interval {
        if cfg.auto_update && cfg.source == PslSource::File {
            spawn_update_task(cfg.clone(), interval);
        }
    }

    #[cfg(unix)]
    spawn_sighup_handler(cfg.clone(), psl.clone());

    Ok(psl)
}

/// Load initial PSL, auto-downloading if configured and file is stale/missing.
async fn load_initial(cfg: &PslConfig) -> Result<SuffixList> {
    match cfg.source {
        PslSource::Embedded => SuffixList::embedded(),
        PslSource::File => {
            if cfg.auto_update {
                // Check if file exists and is fresh
                match file_age(&cfg.path) {
                    Ok(age) if age <= cfg.max_age => {
                        // File is fresh, load it
                        tracing::info!(
                            path = %cfg.path.display(),
                            age = ?age,
                            "loading PSL from file"
                        );
                        load_from_file(&cfg.path).await
                    }
                    Ok(age) => {
                        // File is stale, try to download
                        tracing::info!(
                            path = %cfg.path.display(),
                            age = ?age,
                            max_age = ?cfg.max_age,
                            "PSL file stale, attempting download"
                        );
                        match download_and_save(cfg).await {
                            Ok(()) => load_from_file(&cfg.path).await,
                            Err(e) => {
                                // Download failed but file exists, use stale file
                                tracing::warn!(
                                    error = %e,
                                    age = ?age,
                                    "PSL download failed, using stale file"
                                );
                                load_from_file(&cfg.path).await
                            }
                        }
                    }
                    Err(_) => {
                        // File missing, try to download
                        tracing::info!(
                            path = %cfg.path.display(),
                            "PSL file not found, attempting download"
                        );
                        match download_and_save(cfg).await {
                            Ok(()) => load_from_file(&cfg.path).await,
                            Err(e) => {
                                // Download failed and no file — fall back to embedded
                                tracing::warn!(
                                    error = %e,
                                    "PSL download failed and no cached file, falling back to embedded PSL"
                                );
                                SuffixList::embedded()
                            }
                        }
                    }
                }
            } else {
                // No auto-update, just load
                load_from_file(&cfg.path).await
            }
        }
    }
}

/// Load PSL from file.
async fn load_from_file(path: &Path) -> Result<SuffixList> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let bytes =
            std::fs::read(&path).with_context(|| format!("reading PSL from {}", path.display()))?;
        SuffixList::from_file(&bytes)
    })
    .await
    .context("load task panicked")?
}

/// Download PSL and save to file atomically.
async fn download_and_save(cfg: &PslConfig) -> Result<()> {
    let url = if cfg.update_url.is_empty() {
        UPDATE_URL.to_string()
    } else {
        cfg.update_url.clone()
    };
    let timeout = cfg.update_timeout;

    tracing::info!(%url, "downloading PSL");

    // Use ureq in blocking task since it's a sync HTTP client
    let bytes = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::config::Config::builder()
            .timeout_global(Some(timeout))
            .build()
            .into();

        let mut resp = agent.get(&url).call().context("PSL download request")?;

        let bytes = resp
            .body_mut()
            .read_to_vec()
            .context("reading PSL response body")?;

        anyhow::ensure!(!bytes.is_empty(), "downloaded PSL is empty");
        Ok::<_, anyhow::Error>(bytes)
    })
    .await
    .context("download task panicked")??;

    // Validate before saving
    SuffixList::from_file(&bytes).context("validating downloaded PSL")?;

    save_to_file(&cfg.path, &bytes).await?;
    tracing::info!(path = %cfg.path.display(), "PSL downloaded and saved");
    Ok(())
}

/// Save data to file atomically (write to tmp, then rename), creating the
/// parent directory if it does not exist yet.
///
/// The directory is created here rather than in [`load_initial`] so the two
/// cases stay distinguishable: a path sni-gate populates itself is one it may
/// also lay out, whereas a file the operator maintains by hand should still
/// fail loudly when it is missing — silently creating an empty directory for it
/// would turn a typo'd path into a configuration that merely looks fine.
async fn save_to_file(path: &Path, data: &[u8]) -> Result<()> {
    let path = path.to_path_buf();
    let data = data.to_vec();

    tokio::task::spawn_blocking(move || {
        // A relative filename has an empty parent, which `create_dir_all`
        // rejects; there is nothing to create in that case anyway.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating PSL cache directory {}", parent.display()))?;
        }
        let tmp = staging_path(&path);
        std::fs::write(&tmp, &data).with_context(|| format!("writing to {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
        Ok(())
    })
    .await
    .context("save task panicked")?
}

/// Staging path: append .tmp to the full filename to avoid collisions.
fn staging_path(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(path.file_name().unwrap_or_default());
    name.push(".tmp");
    path.with_file_name(name)
}

/// File age (now - mtime).
fn file_age(path: &Path) -> Result<Duration> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mtime = meta
        .modified()
        .with_context(|| format!("reading mtime of {}", path.display()))?;
    let age = SystemTime::now()
        .duration_since(mtime)
        .unwrap_or(Duration::ZERO);
    Ok(age)
}

/// Spawn background task that periodically checks file age and downloads if stale.
fn spawn_update_task(cfg: PslConfig, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

            match file_age(&cfg.path) {
                Ok(age) if age > cfg.max_age => {
                    tracing::info!(age = ?age, max_age = ?cfg.max_age, "PSL file stale, updating");
                    if let Err(e) = download_and_save(&cfg).await {
                        tracing::warn!(error = %e, "failed to update PSL");
                    }
                    // Note: reload happens via file watcher if auto_reload is enabled
                }
                Ok(_) => {
                    // File is fresh, no action needed
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to check PSL file age");
                }
            }
        }
    });
}

/// Spawn background task that watches file for changes and reloads PSL.
fn spawn_reload_task(cfg: PslConfig, psl: Arc<SuffixList>) -> Result<()> {
    use notify::{Event, EventKind, RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::channel(32);

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                // Only reload on modify or create events
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    let _ = tx.blocking_send(());
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "file watcher error");
            }
        }
    })
    .context("creating file watcher")?;

    watcher
        .watch(&cfg.path, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching {}", cfg.path.display()))?;

    tokio::spawn(async move {
        // Keep watcher alive
        let _watcher = watcher;

        while rx.recv().await.is_some() {
            tracing::info!(path = %cfg.path.display(), "PSL file changed, reloading");
            let path = cfg.path.clone();
            let psl_ref = psl.clone();

            tokio::task::spawn_blocking(move || match std::fs::read(&path) {
                Ok(bytes) => match psl_ref.replace_from_bytes(&bytes) {
                    Ok(()) => {
                        tracing::info!("PSL reloaded successfully");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to reload PSL (invalid file)");
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read PSL file");
                }
            })
            .await
            .ok();
        }
    });

    Ok(())
}

/// Spawn SIGHUP handler for manual reload (Unix only).
#[cfg(unix)]
fn spawn_sighup_handler(cfg: PslConfig, psl: Arc<SuffixList>) {
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async move {
        let mut sighup = signal(SignalKind::hangup()).expect("failed to register SIGHUP handler");

        while sighup.recv().await.is_some() {
            tracing::info!("received SIGHUP, reloading PSL");
            let path = cfg.path.clone();
            let psl_ref = psl.clone();

            tokio::task::spawn_blocking(move || match std::fs::read(&path) {
                Ok(bytes) => match psl_ref.replace_from_bytes(&bytes) {
                    Ok(()) => {
                        tracing::info!("PSL reloaded successfully");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "PSL reload failed");
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read PSL file");
                }
            })
            .await
            .ok();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PslSource;

    /// Whether a *genuine* PSL is in effect: `example.com` sits under a
    /// registrable domain while `co.uk` is a registry boundary. Only a real list
    /// separates the two — the implicit "the last label is the suffix" rule that
    /// an empty or truncated list falls back to would call both registrable, so
    /// this distinguishes a loaded list from a silently broken one.
    fn real_psl_loaded(psl: &SuffixList) -> bool {
        psl.wildcard_is_mintable("example.com") && !psl.wildcard_is_mintable("co.uk")
    }

    #[tokio::test]
    async fn load_embedded() {
        let cfg = PslConfig {
            source: PslSource::Embedded,
            ..Default::default()
        };
        let psl = load_initial(&cfg).await.unwrap();
        assert!(
            real_psl_loaded(&psl),
            "the embedded list must be a real PSL"
        );
    }

    #[tokio::test]
    async fn load_from_file_simple() {
        let dir = std::env::temp_dir().join(format!("psl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("psl.dat");

        // Minimal valid PSL format
        let psl_content = r#"// Test PSL
// BEGIN ICANN DOMAINS
test
com
// END ICANN DOMAINS
"#;
        std::fs::write(&path, psl_content).unwrap();

        let psl = load_from_file(&path).await.unwrap();
        // `test` is a declared suffix, so `example.test` is registrable below it.
        assert!(psl.wildcard_is_mintable("example.test"));
        assert!(!psl.wildcard_is_mintable("test"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn auto_update_downloads_when_missing() {
        let dir = std::env::temp_dir().join(format!("psl-auto-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("psl.dat");

        // File doesn't exist, auto_update should download it
        let cfg = PslConfig {
            source: PslSource::File,
            path: path.clone(),
            auto_update: true,
            max_age: Duration::from_secs(1),
            update_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        // This test requires network access, skip if download fails
        match load_initial(&cfg).await {
            Ok(psl) => {
                // Should have downloaded and loaded
                assert!(path.exists());
                assert!(
                    real_psl_loaded(&psl),
                    "the downloaded list must be a real PSL"
                );
            }
            Err(e) => {
                // Network failure is acceptable in tests
                eprintln!("Skipping test (network unavailable): {}", e);
            }
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn auto_update_skips_when_fresh() {
        let dir = std::env::temp_dir().join(format!("psl-fresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("psl.dat");

        // Write a minimal valid PSL
        let psl_content = r#"// Test PSL
// BEGIN ICANN DOMAINS
test
com
// END ICANN DOMAINS
"#;
        std::fs::write(&path, psl_content).unwrap();

        let cfg = PslConfig {
            source: PslSource::File,
            path: path.clone(),
            auto_update: true,
            max_age: Duration::from_secs(3600), // 1 hour
            ..Default::default()
        };

        let psl = load_initial(&cfg).await.unwrap();
        // Should use the existing file (not download): it declares `test`, which
        // the real list does not, so this proves *which* list is in effect.
        assert!(psl.wildcard_is_mintable("example.test"));
        assert!(!psl.wildcard_is_mintable("test"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn file_age_calculation() {
        let dir = std::env::temp_dir().join(format!("psl-age-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.dat");

        std::fs::write(&path, "data").unwrap();
        let age = file_age(&path).unwrap();
        // Should be very recent (< 1 second)
        assert!(age < Duration::from_secs(1));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// An auto-updated path is one sni-gate owns, so a missing parent directory
    /// is laid out rather than reported. Before this, the download succeeded and
    /// the write of the staging file failed, leaving the gateway on the embedded
    /// list with only a warning to explain it.
    #[tokio::test]
    async fn save_creates_missing_parent_directories() {
        let dir = std::env::temp_dir().join(format!("psl-mkdir-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        // Two levels deep, so this covers more than a single missing component.
        let path = dir.join("cache").join("nested").join("psl.dat");

        save_to_file(&path, b"test data").await.unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"test data");
        assert!(
            !staging_path(&path).exists(),
            "staging file must not survive"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A bare relative filename has an empty parent, which `create_dir_all`
    /// rejects — so the guard, not the OS, must decide there is nothing to
    /// create. Asserted on the condition rather than by running a save, because
    /// reaching that path means changing the process working directory, which
    /// would race every other test in this binary.
    #[test]
    fn a_bare_filename_has_nothing_to_create() {
        let bare = Path::new("public_suffix_list.dat");
        assert!(
            bare.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .is_none(),
            "a bare filename must be skipped by the directory guard"
        );
        assert!(
            Path::new("cache/public_suffix_list.dat")
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .is_some(),
            "a relative path with a directory component must still be created"
        );
    }

    #[tokio::test]
    async fn atomic_save() {
        let dir = std::env::temp_dir().join(format!("psl-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.dat");

        let data = b"test data";
        save_to_file(&path, data).await.unwrap();

        let read = std::fs::read(&path).unwrap();
        assert_eq!(read, data);

        // .tmp file should not exist
        assert!(!path.with_extension("tmp").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn init_with_auto_update_and_reload() {
        let dir = std::env::temp_dir().join(format!("psl-init-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("psl.dat");

        let cfg = PslConfig {
            source: PslSource::File,
            path: path.clone(),
            auto_update: true,
            auto_reload: true,
            max_age: Duration::from_secs(1),
            check_interval: Some(Duration::from_secs(60)),
            update_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        // This test requires network access, skip if download fails
        match init(&cfg).await {
            Ok(psl) => {
                // Should have downloaded
                assert!(path.exists());

                // Should be readable
                assert!(
                    real_psl_loaded(&psl),
                    "the downloaded list must be a real PSL"
                );
            }
            Err(e) => {
                // Network failure is acceptable in tests
                eprintln!("Skipping test (network unavailable): {}", e);
            }
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn auto_reload_with_missing_file_does_not_abort_startup() {
        let dir = std::env::temp_dir().join(format!("psl-reload-missing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nonexistent.dat");

        let cfg = PslConfig {
            source: PslSource::File,
            path: path.clone(),
            auto_update: true,
            auto_reload: true,
            update_url: "http://127.0.0.1:1/nonexistent".to_string(),
            update_timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let result = init(&cfg).await;
        assert!(
            result.is_ok(),
            "init should succeed with embedded fallback when auto_reload is set, \
             auto_update fails, and file is absent"
        );

        let psl = result.unwrap();
        assert!(
            real_psl_loaded(&psl),
            "the embedded fallback must be a real PSL"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fallback_to_stale_file_when_download_fails() {
        let dir = std::env::temp_dir().join(format!("psl-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("psl.dat");

        let psl_content = r#"// Test PSL
// BEGIN ICANN DOMAINS
test
com
// END ICANN DOMAINS
"#;
        std::fs::write(&path, psl_content).unwrap();

        let mtime = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(mtime)).unwrap();

        let cfg = PslConfig {
            source: PslSource::File,
            path: path.clone(),
            auto_update: true,
            max_age: Duration::from_secs(3600),
            update_url: "http://127.0.0.1:1/nonexistent".to_string(),
            update_timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let psl = load_initial(&cfg).await.unwrap();
        // The stale file, not the embedded list: it declares `test`.
        assert!(psl.wildcard_is_mintable("example.test"));
        assert!(!psl.wildcard_is_mintable("test"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fallback_to_embedded_when_no_file_and_download_fails() {
        let dir = std::env::temp_dir().join(format!("psl-embedded-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nonexistent.dat");

        let cfg = PslConfig {
            source: PslSource::File,
            path: path.clone(),
            auto_update: true,
            update_url: "http://127.0.0.1:1/nonexistent".to_string(),
            update_timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let psl = load_initial(&cfg).await.unwrap();
        assert!(
            real_psl_loaded(&psl),
            "the embedded fallback must be a real PSL"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn invalid_psl_is_rejected() {
        let dir = std::env::temp_dir().join(format!("psl-invalid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("invalid.dat");

        std::fs::write(&path, "not a valid PSL file").unwrap();

        let result = load_from_file(&path).await;
        assert!(result.is_err(), "invalid PSL should be rejected");

        std::fs::remove_dir_all(&dir).ok();
    }
}
