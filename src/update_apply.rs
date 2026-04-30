//! Apply a downloaded release asset: extract → verify signature → stage
//! `<exe>.new` → swap → re-launch. Pairs with `update_check.rs`, which
//! handles discovery and the network download.
//!
//! ## Signing & threat model
//!
//! TLS proves "GitHub's CDN served this", not provenance. If the release
//! pipeline or a maintainer GitHub account is compromised, an updater that
//! ships unsigned is a malware vector — the binary it pulls would
//! happily install. To close that gap we verify a minisign signature
//! against an embedded public key.
//!
//! Setup, one time:
//!
//! ```text
//! minisign -G -p mhrv.pub -s mhrv.key      # keep mhrv.key offline
//! ```
//!
//! Build with:
//!
//! ```text
//! MHRV_UPDATE_PUBKEY="$(tail -n1 mhrv.pub)" cargo build --release
//! ```
//!
//! Per release, in CI:
//!
//! ```text
//! minisign -Sm <asset> -s mhrv.key
//! ```
//!
//! Upload `<asset>.minisig` next to the asset in the release.
//!
//! Until the public key is set (or when the build env var is empty), the
//! updater still works but logs a loud warning and applies updates
//! without a signature check. Intentional: ship the feature first, layer
//! signing on once the keypair is generated.
//!
//! ## Binary swap, per platform
//!
//! - **Unix**: `rename` of the new binary over the running exe is
//!   permitted while the process is alive (the kernel keeps the old
//!   inode for the running process). After rename we `execv` self with
//!   the original argv — single seamless restart.
//! - **Windows**: cannot `replace` a running .exe, but **can** rename
//!   one. So `stage_update_*` writes `<exe>.new`; `restart_to_apply`
//!   spawns `<exe>.new`, exits. The new process detects it is running
//!   from a `.new` path, renames the old `<exe>` → `<exe>.old`, renames
//!   itself (the `.new`) → `<exe>`, re-execs. Brief flash, one swap.
//!
//! Android is not handled here — APK install goes through
//! `PackageInstaller` on the Kotlin side. On Android this module compiles
//! to a single no-op `finalize_pending_at_startup` stub so callers in
//! `main.rs` don't need a `cfg` gate.

/// Compile-time public key for verifying release assets. Set via
/// `MHRV_UPDATE_PUBKEY` env var at build time. The expected format is the
/// base64 line from a minisign `.pub` file (the line *after* the `untrusted
/// comment:` line).
const PUBKEY_B64_RAW: Option<&str> = option_env!("MHRV_UPDATE_PUBKEY");

fn normalize_embedded_pubkey(raw: Option<&'static str>) -> Option<&'static str> {
    raw.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

/// Embedded minisign public key, if this build enforces signature checks.
/// Empty/whitespace env vars are treated as unset so GitHub Actions repo
/// variables can default cleanly to rollout mode.
pub fn embedded_update_pubkey() -> Option<&'static str> {
    normalize_embedded_pubkey(PUBKEY_B64_RAW)
}

/// `true` if the build embedded a minisign public key. UI can use this to
/// distinguish "verified update" from "rollout-mode update".
pub fn signature_verification_enabled() -> bool {
    embedded_update_pubkey().is_some()
}

/// Verify `archive` against minisign signature text and a base64 public
/// key. Shared by the desktop self-updater and Android sideload flow.
pub fn verify_minisign_signature(
    pubkey_b64: &str,
    archive: &std::path::Path,
    sig_text: &str,
) -> Result<(), String> {
    let pk = minisign_verify::PublicKey::from_base64(pubkey_b64.trim())
        .map_err(|e| format!("bad pubkey: {}", e))?;
    let sig = minisign_verify::Signature::decode(sig_text)
        .map_err(|e| format!("decode sig: {}", e))?;
    let mut f = std::fs::File::open(archive)
        .map_err(|e| format!("open archive: {}", e))?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut buf)
        .map_err(|e| format!("read archive: {}", e))?;
    pk.verify(&buf, &sig, false)
        .map_err(|e| e.to_string())
}

/// Return the sibling minisign URL for a release asset URL.
///
/// GitHub's current `browser_download_url` values have no query string, but
/// signed/CDN URLs can. In that case the signature asset path still gets the
/// `.minisig` suffix before the query parameters.
pub fn signature_url_for_asset(asset_url: &str) -> String {
    if let Some((base, query)) = asset_url.split_once('?') {
        format!("{}.minisig?{}", base, query)
    } else {
        format!("{}.minisig", asset_url)
    }
}

#[cfg(target_os = "android")]
pub fn finalize_pending_at_startup() {}

#[cfg(test)]
mod shared_tests {
    use super::*;

    #[test]
    fn embedded_pubkey_normalization_treats_empty_as_unset() {
        assert_eq!(normalize_embedded_pubkey(None), None);
        assert_eq!(normalize_embedded_pubkey(Some("")), None);
        assert_eq!(normalize_embedded_pubkey(Some("   \n\t")), None);
        assert_eq!(normalize_embedded_pubkey(Some("  abc123\n")), Some("abc123"));
    }

    #[test]
    fn signature_url_keeps_query_on_signature_asset() {
        assert_eq!(
            signature_url_for_asset("https://x/y/archive.tar.gz"),
            "https://x/y/archive.tar.gz.minisig"
        );
        assert_eq!(
            signature_url_for_asset("https://x/y/archive.tar.gz?token=abc"),
            "https://x/y/archive.tar.gz.minisig?token=abc"
        );
    }
}

#[cfg(not(target_os = "android"))]
mod desktop {

use std::path::{Path, PathBuf};

use super::{embedded_update_pubkey, signature_url_for_asset, verify_minisign_signature};

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("download: {0}")]
    Download(String),
    #[error("extract: {0}")]
    Extract(String),
    #[error("signature missing — refusing to apply unsigned update (rebuild without MHRV_UPDATE_PUBKEY to allow this)")]
    SignatureMissing,
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),
    #[error("no compatible binary found in archive")]
    BinaryNotFound,
    #[error("ambiguous archive: more than one binary matched {0}")]
    AmbiguousBinary(String),
    #[error("staging: {0}")]
    Staging(String),
}

/// Result of staging an update. `staged_path` always ends in `.new` and
/// is the path that gets renamed at apply time. `relaunch_path` is the
/// exe to `execv` after the swap completes.
///
/// For binary-only updates `staged_path` is a regular file (e.g.
/// `<current_exe>.new`) and `relaunch_path == swap_target()`.
///
/// For macOS `.app` bundle updates `staged_path` is a directory (e.g.
/// `<bundle>.new`) and `relaunch_path` points at the new exe inside
/// (`<bundle>/Contents/MacOS/<name>`).
#[derive(Debug, Clone)]
pub struct StagedUpdate {
    pub staged_path: PathBuf,
    pub relaunch_path: PathBuf,
}

impl StagedUpdate {
    /// The path the staged content swaps into — i.e. `staged_path` with
    /// the trailing `.new` stripped.
    pub fn swap_target(&self) -> PathBuf {
        let s = self.staged_path.to_string_lossy();
        let stripped = s.strip_suffix(".new").unwrap_or(&s);
        PathBuf::from(stripped.to_string())
    }
}

/// Download a release archive into a temp dir, fetch its `.minisig`,
/// verify (if a pubkey is embedded), extract, and stage the new binary
/// next to the current exe as `<exe>.new`. On Ok, call `restart_to_apply`
/// to perform the swap.
pub async fn download_and_stage(
    route: crate::update_check::Route,
    archive_url: &str,
    archive_name: &str,
) -> Result<StagedUpdate, ApplyError> {
    let scratch = tempfile::tempdir()
        .map_err(|e| ApplyError::Staging(format!("tempdir: {}", e)))?;
    let archive_path = scratch.path().join(archive_name);
    crate::update_check::download_asset(route.clone(), archive_url, &archive_path)
        .await
        .map_err(ApplyError::Download)?;

    // Try to fetch the matching `.minisig` alongside. We tolerate a missing
    // sig file only when no pubkey was embedded at build time; with a
    // pubkey, missing sig is a hard failure.
    let sig_url = signature_url_for_asset(archive_url);
    let sig_path = scratch.path().join(format!("{}.minisig", archive_name));
    let sig_result =
        crate::update_check::download_asset(route, &sig_url, &sig_path).await;

    match (embedded_update_pubkey(), &sig_result) {
        (Some(pubkey), Ok(_)) => {
            let sig_text = std::fs::read_to_string(&sig_path).map_err(|e| {
                ApplyError::SignatureInvalid(format!("read sig: {}", e))
            })?;
            verify_minisign_signature(pubkey, &archive_path, &sig_text)
                .map_err(ApplyError::SignatureInvalid)?;
            tracing::info!(
                "update_apply: minisign signature verified for {}",
                archive_name
            );
        }
        (Some(_), Err(e)) => {
            tracing::error!("update_apply: missing .minisig for {}: {}", archive_name, e);
            return Err(ApplyError::SignatureMissing);
        }
        (None, _) => {
            tracing::warn!(
                "update_apply: MHRV_UPDATE_PUBKEY was not set at build time — \
                 applying update without signature check (insecure)."
            );
        }
    }

    stage_from_archive(&archive_path)
}

/// Extract `archive` to a scratch dir, find the binary (or `.app`
/// bundle) that matches our running install, stage it as `<x>.new` next
/// to the existing exe/bundle.
///
/// Three modes:
///
/// 1. **macOS `.app` bundle**: if the running exe lives inside
///    `Foo.app/Contents/MacOS/<bin>` AND the archive contains a `.app`,
///    we swap the whole bundle (so `Info.plist`, future framework
///    additions, etc. all come along). Staged path is `<bundle>.new`,
///    a directory.
/// 2. **macOS bare binary**: running outside any `.app`, archive
///    contains the bare binary at the top level. Single-file swap.
/// 3. **Linux / Windows / etc.**: single-file swap.
pub fn stage_from_archive(archive: &Path) -> Result<StagedUpdate, ApplyError> {
    let current_exe = std::env::current_exe()
        .map_err(|e| ApplyError::Staging(format!("current_exe: {}", e)))?;
    let exe_name = current_exe
        .file_name()
        .ok_or_else(|| ApplyError::Staging("current_exe has no filename".into()))?
        .to_string_lossy()
        .into_owned();

    let scratch = tempfile::tempdir()
        .map_err(|e| ApplyError::Staging(format!("scratch tempdir: {}", e)))?;
    extract_archive(archive, scratch.path())?;

    // macOS .app bundle case — only attempted when both the running
    // install AND the archive have a bundle. Otherwise fall through to
    // the binary-only path (which still works on macOS for users who
    // unpacked the .tar.gz onto e.g. /usr/local/bin).
    #[cfg(target_os = "macos")]
    {
        if let Some(target_bundle) = macos_bundle_for_exe(&current_exe) {
            if let Some(extracted_bundle) = find_app_bundle(scratch.path()) {
                let staged = staged_path(&target_bundle);
                cleanup_path(&staged);
                copy_dir_all(&extracted_bundle, &staged)?;
                let staged_inner_exe = staged
                    .join("Contents/MacOS")
                    .join(&exe_name);
                if !staged_inner_exe.exists() {
                    return Err(ApplyError::BinaryNotFound);
                }
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&staged_inner_exe) {
                    let mut p = meta.permissions();
                    p.set_mode(0o755);
                    let _ = std::fs::set_permissions(&staged_inner_exe, p);
                }
                let relaunch_path = target_bundle
                    .join("Contents/MacOS")
                    .join(&exe_name);
                tracing::info!(
                    "update_apply: staged macOS bundle → {}",
                    staged.display()
                );
                return Ok(StagedUpdate {
                    staged_path: staged,
                    relaunch_path,
                });
            }
        }
    }

    // Binary-only path.
    let extracted = find_binary(scratch.path(), &exe_name)?;

    let staged = staged_path(&current_exe);
    let _ = std::fs::remove_file(&staged);
    std::fs::copy(&extracted, &staged)
        .map_err(|e| ApplyError::Staging(format!("copy staged: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&staged)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&staged, perm)?;
    }

    tracing::info!("update_apply: staged → {}", staged.display());
    Ok(StagedUpdate {
        staged_path: staged,
        relaunch_path: current_exe,
    })
}

fn staged_path(current: &Path) -> PathBuf {
    let mut name = current.file_name().unwrap().to_owned();
    name.push(".new");
    current.with_file_name(name)
}

/// Walk up from a binary path looking for an enclosing `Foo.app` —
/// specifically the layout `Foo.app/Contents/MacOS/<bin>` that macOS
/// app bundles use. Returns the bundle root (`.../Foo.app`) on match.
#[cfg(target_os = "macos")]
fn macos_bundle_for_exe(exe: &Path) -> Option<PathBuf> {
    let macos_dir = exe.parent()?;            // Foo.app/Contents/MacOS
    if macos_dir.file_name()? != "MacOS" {
        return None;
    }
    let contents = macos_dir.parent()?;       // Foo.app/Contents
    if contents.file_name()? != "Contents" {
        return None;
    }
    let app = contents.parent()?;             // Foo.app
    if app.extension().map(|e| e == "app").unwrap_or(false) {
        Some(app.to_path_buf())
    } else {
        None
    }
}

/// Locate the first `*.app` directory under `root`. Returns None if the
/// archive isn't a bundle archive (e.g. `.tar.gz` of bare binaries).
#[cfg(target_os = "macos")]
fn find_app_bundle(root: &Path) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.extension().map(|x| x == "app").unwrap_or(false) {
                    return Some(p);
                }
                stack.push(p);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), ApplyError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_all(&from, &to)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            std::os::unix::fs::symlink(&target, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
            // Preserve mode (rcgen / build-app.sh chmod +x's the inner
            // binary; we want that to survive the copy).
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&from)?.permissions().mode();
            let _ = std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cleanup_path(p: &Path) {
    if p.is_dir() {
        let _ = std::fs::remove_dir_all(p);
    } else if p.exists() {
        let _ = std::fs::remove_file(p);
    }
}

fn extract_archive(archive: &Path, dest: &Path) -> Result<(), ApplyError> {
    let lower = archive
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if lower.ends_with(".zip") {
        extract_zip(archive, dest)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        extract_tar_gz(archive, dest)
    } else {
        Err(ApplyError::Extract(format!(
            "unsupported archive type: {}",
            lower
        )))
    }
}

fn extract_zip(path: &Path, dest: &Path) -> Result<(), ApplyError> {
    let f = std::fs::File::open(path)
        .map_err(|e| ApplyError::Extract(format!("open zip: {}", e)))?;
    let mut zip = zip::ZipArchive::new(f)
        .map_err(|e| ApplyError::Extract(format!("zip: {}", e)))?;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| ApplyError::Extract(format!("zip entry {}: {}", i, e)))?;
        // `enclosed_name` rejects path-traversal (`..`) entries.
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let out_path = dest.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
            continue;
        }
        if let Some(p) = out_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut out_f = std::fs::File::create(&out_path)?;
        std::io::copy(&mut entry, &mut out_f)
            .map_err(|e| ApplyError::Extract(format!("zip copy: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                let _ = std::fs::set_permissions(
                    &out_path,
                    std::fs::Permissions::from_mode(mode),
                );
            }
        }
    }
    Ok(())
}

fn extract_tar_gz(path: &Path, dest: &Path) -> Result<(), ApplyError> {
    let f = std::fs::File::open(path)
        .map_err(|e| ApplyError::Extract(format!("open tar.gz: {}", e)))?;
    let gz = flate2::read::GzDecoder::new(f);
    let mut archive = tar::Archive::new(gz);
    std::fs::create_dir_all(dest)
        .map_err(|e| ApplyError::Extract(format!("create tar.gz destination: {}", e)))?;
    for entry in archive
        .entries()
        .map_err(|e| ApplyError::Extract(format!("tar.gz entries: {}", e)))?
    {
        let mut entry = entry.map_err(|e| ApplyError::Extract(format!("tar.gz entry: {}", e)))?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let path = entry
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<invalid path>".to_string());
            return Err(ApplyError::Extract(format!(
                "tar.gz link entries are not supported: {}",
                path
            )));
        }
        entry
            .unpack_in(dest)
            .map_err(|e| ApplyError::Extract(format!("tar.gz unpack: {}", e)))?;
    }
    Ok(())
}

/// Walk `root` for regular files whose name matches `target_name` or
/// its stem (handles archives that ship the binary without a `.exe`
/// extension, or with one when current_exe doesn't). Errors if more
/// than one match — defensive against future multi-binary archives
/// where multiple files could plausibly satisfy the same name (e.g.
/// `mhrv-rs-ui` shipped at root AND inside an `extras/` dir would
/// otherwise pick whichever `read_dir` returned first).
fn find_binary(root: &Path, target_name: &str) -> Result<PathBuf, ApplyError> {
    let stem = Path::new(target_name)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| target_name.to_string());
    let with_exe = format!("{}.exe", stem);

    let mut matches = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if ft.is_file() {
                let n = entry.file_name().to_string_lossy().into_owned();
                if n.eq_ignore_ascii_case(target_name)
                    || n.eq_ignore_ascii_case(&stem)
                    || n.eq_ignore_ascii_case(&with_exe)
                {
                    matches.push(path);
                }
            }
        }
    }
    match matches.len() {
        0 => Err(ApplyError::BinaryNotFound),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => {
            tracing::error!(
                "update_apply: multiple binaries in archive matched {}: {:?}",
                target_name,
                matches
            );
            Err(ApplyError::AmbiguousBinary(target_name.to_string()))
        }
    }
}

/// Perform the swap and re-launch. Does not return on success.
///
/// Unix:
///   - **File swap**: a single `rename` over the running exe is the
///     atomic POSIX trick — the running process keeps its open inode so
///     it doesn't crash, the new content takes the path. No `.old`
///     bookkeeping needed.
///   - **Directory swap (.app bundle)**: a directory rename can't
///     atomically replace a non-empty target, so we do a 2-step: move
///     the existing bundle to `<bundle>.old`, then rename `.new` →
///     target. The `.old` is cleaned up on next launch by
///     `cleanup_stale_old`.
///
/// Windows: stages `.new` and spawns it; the new process detects it's
/// running from a `.new` path and finalizes the swap in
/// `finalize_pending_at_startup`.
pub fn restart_to_apply(staged: &StagedUpdate) -> Result<(), ApplyError> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    #[cfg(unix)]
    {
        let swap_target = staged.swap_target();
        if staged.staged_path.is_dir() {
            // Directory swap (macOS .app bundle). Two-step: backup
            // existing, rename new into place. Both renames are
            // POSIX-allowed even while the running process is execed
            // out of the old bundle (open file descriptors keep the
            // mapping alive across the rename).
            let backup_name = format!(
                "{}.old",
                swap_target.file_name().unwrap().to_string_lossy()
            );
            let backup = swap_target.with_file_name(backup_name);
            // Stale .old from a previous half-applied swap, if any.
            if backup.is_dir() {
                let _ = std::fs::remove_dir_all(&backup);
            } else if backup.exists() {
                let _ = std::fs::remove_file(&backup);
            }
            if swap_target.exists() {
                std::fs::rename(&swap_target, &backup).map_err(|e| {
                    ApplyError::Staging(format!(
                        "backup {} → {}: {}",
                        swap_target.display(),
                        backup.display(),
                        e
                    ))
                })?;
            }
            std::fs::rename(&staged.staged_path, &swap_target).map_err(|e| {
                ApplyError::Staging(format!(
                    "rename {} → {}: {}",
                    staged.staged_path.display(),
                    swap_target.display(),
                    e
                ))
            })?;
        } else {
            // Atomic file swap.
            std::fs::rename(&staged.staged_path, &swap_target).map_err(|e| {
                ApplyError::Staging(format!(
                    "rename {} → {}: {}",
                    staged.staged_path.display(),
                    swap_target.display(),
                    e
                ))
            })?;
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&swap_target)?.permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&swap_target, p)?;
        }

        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&staged.relaunch_path)
            .args(&args)
            .exec();
        // exec returns only on failure.
        Err(ApplyError::Staging(format!("execv: {}", err)))
    }

    #[cfg(windows)]
    {
        // Windows binary-only path. (No .app bundles on Windows so we
        // never reach the directory branch here.)
        std::process::Command::new(&staged.staged_path)
            .args(&args)
            .spawn()
            .map_err(|e| {
                ApplyError::Staging(format!("spawn .new: {}", e))
            })?;
        // Give the new process a moment so it's past startup before we
        // exit and free our exe lock. Not strictly required because the
        // .new code retries the rename, but smoother UX.
        std::thread::sleep(std::time::Duration::from_millis(150));
        std::process::exit(0);
    }
}

/// Run as the very first thing in `main()`. Two responsibilities:
///
/// 1. **Windows finalize**: if we're running from a `<exe>.new` path it
///    means the old process exited and we need to complete the swap —
///    rename old → `.old`, rename ourselves → target, re-exec.
/// 2. **Unix late apply**: if a previous `restart_to_apply` failed
///    before the final rename, a stale `<exe>.new` file or macOS
///    `<bundle>.new` directory may be sitting next to us. Pick it up now.
///
/// Always best-effort. A swap failure here logs and falls through so the
/// app still starts (running the old version) rather than hard-failing
/// at boot.
pub fn finalize_pending_at_startup() {
    let Ok(current) = std::env::current_exe() else {
        return;
    };
    let Some(name_os) = current.file_name() else {
        return;
    };
    let name = name_os.to_string_lossy().into_owned();

    cleanup_stale_old(&current, &name);

    #[cfg(windows)]
    {
        if let Some(target_name) = name.strip_suffix(".new") {
            let target = current.with_file_name(target_name);
            let backup =
                current.with_file_name(format!("{}.old", target_name));
            let _ = std::fs::remove_file(&backup);
            // Old process may not have fully exited yet; brief retry loop.
            for _ in 0..30 {
                if !target.exists() {
                    break;
                }
                if std::fs::rename(&target, &backup).is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            // Rename self (.new) → target. Allowed on Windows even while
            // running.
            match std::fs::rename(&current, &target) {
                Ok(_) => {
                    tracing::info!(
                        "update_apply: finalized swap → {}",
                        target.display()
                    );
                    let args: Vec<String> = std::env::args().skip(1).collect();
                    let _ = std::process::Command::new(&target)
                        .args(args)
                        .spawn();
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::error!(
                        "update_apply: failed to finalize swap {} → {}: {}",
                        current.display(),
                        target.display(),
                        e
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        if late_apply_macos_bundle(&current) {
            return;
        }

        let staged = current.with_file_name(format!("{}.new", name));
        if staged.exists() {
            match std::fs::rename(&staged, &current) {
                Ok(_) => tracing::info!(
                    "update_apply: late-applied staged update → {}",
                    current.display()
                ),
                Err(e) => tracing::warn!(
                    "update_apply: late-apply rename failed: {}",
                    e
                ),
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn late_apply_macos_bundle(current: &Path) -> bool {
    let Some(target_bundle) = macos_bundle_for_exe(current) else {
        return false;
    };
    let staged_bundle = staged_path(&target_bundle);
    if !staged_bundle.exists() {
        return false;
    }

    let backup_name = format!(
        "{}.old",
        target_bundle.file_name().unwrap().to_string_lossy()
    );
    let backup = target_bundle.with_file_name(backup_name);
    cleanup_path(&backup);

    if target_bundle.exists() {
        if let Err(e) = std::fs::rename(&target_bundle, &backup) {
            tracing::warn!(
                "update_apply: late-apply bundle backup failed {} → {}: {}",
                target_bundle.display(),
                backup.display(),
                e
            );
            return true;
        }
    }

    match std::fs::rename(&staged_bundle, &target_bundle) {
        Ok(_) => tracing::info!(
            "update_apply: late-applied staged macOS bundle → {}",
            target_bundle.display()
        ),
        Err(e) => {
            tracing::warn!(
                "update_apply: late-apply bundle rename failed {} → {}: {}",
                staged_bundle.display(),
                target_bundle.display(),
                e
            );
            if backup.exists() && !target_bundle.exists() {
                let _ = std::fs::rename(&backup, &target_bundle);
            }
        }
    }
    true
}

/// Wipe a stale `<exe>.old` file from a previous swap, if any. Scoped to
/// our specific name — earlier versions deleted *every* `.old` in the
/// parent dir, which would blast away unrelated `.old` backups when the
/// binary lived in a shared dir like `~/Downloads`.
fn cleanup_stale_old(current: &Path, current_name: &str) {
    let stale_name = format!("{}.old", current_name);
    let stale = current.with_file_name(&stale_name);
    if stale.is_dir() {
        // macOS .app bundle backup — directory.
        let _ = std::fs::remove_dir_all(&stale);
    } else if stale.exists() {
        let _ = std::fs::remove_file(&stale);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn staged_path_appends_new() {
        let p = Path::new("/tmp/foo/mhrv-rs-ui");
        assert_eq!(
            staged_path(p),
            PathBuf::from("/tmp/foo/mhrv-rs-ui.new")
        );
        let p = Path::new("C:/x/mhrv-rs-ui.exe");
        assert_eq!(
            staged_path(p).file_name().unwrap().to_string_lossy(),
            "mhrv-rs-ui.exe.new"
        );
    }

    #[test]
    fn find_binary_matches_with_or_without_exe() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("mhrv-rs-1.0");
        std::fs::create_dir_all(&nested).unwrap();
        let bin = nested.join("mhrv-rs-ui");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        // current_exe has .exe, archive has bare name → still match by stem.
        let found = find_binary(dir.path(), "mhrv-rs-ui.exe").unwrap();
        assert_eq!(found, bin);
        // current_exe has bare name, archive has bare name → match.
        let found = find_binary(dir.path(), "mhrv-rs-ui").unwrap();
        assert_eq!(found, bin);
    }

    #[test]
    fn find_binary_errors_on_ambiguous_match() {
        let dir = tempfile::tempdir().unwrap();
        // Two files would both satisfy the stem `mhrv-rs-ui`: one at root
        // and one inside a subdir. We want the function to refuse rather
        // than silently pick by `read_dir` order.
        std::fs::write(dir.path().join("mhrv-rs-ui"), b"a").unwrap();
        let sub = dir.path().join("inner");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("mhrv-rs-ui"), b"b").unwrap();
        let res = find_binary(dir.path(), "mhrv-rs-ui");
        assert!(matches!(res, Err(ApplyError::AmbiguousBinary(_))));
    }

    #[test]
    fn find_binary_skips_unrelated_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mhrv-rs"), b"cli").unwrap();
        std::fs::write(dir.path().join("mhrv-rs-ui-extras"), b"x").unwrap();
        std::fs::write(dir.path().join("mhrv-rs-ui"), b"ui").unwrap();
        let found = find_binary(dir.path(), "mhrv-rs-ui").unwrap();
        assert_eq!(found.file_name().unwrap(), "mhrv-rs-ui");
    }

    #[test]
    fn extract_zip_rejects_path_traversal() {
        // zip-rs `enclosed_name` returns None for `..` entries, which we
        // then `continue` past. Build an archive that includes one
        // traversal entry and one safe one — only the safe one should
        // land on disk.
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("evil.zip");
        let f = std::fs::File::create(&zip_path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zw.start_file("../escape.txt", opts).unwrap();
        zw.write_all(b"would-be-traversal").unwrap();
        zw.start_file("safe.txt", opts).unwrap();
        zw.write_all(b"ok").unwrap();
        zw.finish().unwrap();

        let dest = tmp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        extract_zip(&zip_path, &dest).unwrap();
        // The safe file lands; the traversal entry is silently skipped.
        assert!(dest.join("safe.txt").is_file());
        // Walk the parent of `dest` to verify no `escape.txt` leaked
        // upward — i.e. the path-traversal didn't write outside `dest`.
        let leaked = tmp.path().join("escape.txt");
        assert!(
            !leaked.exists(),
            "path traversal wrote outside dest: {}",
            leaked.display()
        );
    }

    #[test]
    fn extract_tar_gz_unpacks_files() {
        let tmp = tempfile::tempdir().unwrap();
        let tgz = tmp.path().join("a.tar.gz");
        // Build a minimal tar.gz containing one file.
        let f = std::fs::File::create(&tgz).unwrap();
        let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut tar_w = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        let payload = b"hello-world";
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_w.append_data(&mut header, "greeting.txt", &payload[..]).unwrap();
        tar_w.into_inner().unwrap().finish().unwrap();

        let dest = tmp.path().join("out");
        extract_tar_gz(&tgz, &dest).unwrap();
        let contents = std::fs::read_to_string(dest.join("greeting.txt")).unwrap();
        assert_eq!(contents, "hello-world");
    }

    #[test]
    fn extract_tar_gz_rejects_link_entries() {
        for (entry_type, name) in [
            (tar::EntryType::Symlink, "symlink"),
            (tar::EntryType::Link, "hardlink"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let tgz = tmp.path().join(format!("{name}.tar.gz"));
            let f = std::fs::File::create(&tgz).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            let mut tar_w = tar::Builder::new(gz);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_size(0);
            tar_w
                .append_link(&mut header, format!("{name}.txt"), "target.txt")
                .unwrap();
            tar_w.into_inner().unwrap().finish().unwrap();

            let dest = tmp.path().join("out");
            let res = extract_tar_gz(&tgz, &dest);
            assert!(
                matches!(res, Err(ApplyError::Extract(ref msg)) if msg.contains("link entries")),
                "{name} archive should be rejected, got {res:?}"
            );
        }
    }

    #[test]
    fn cleanup_stale_old_only_touches_our_name() {
        let dir = tempfile::tempdir().unwrap();
        let our = dir.path().join("mhrv-rs-ui.old");
        let theirs = dir.path().join("someone-elses.old");
        std::fs::write(&our, b"x").unwrap();
        std::fs::write(&theirs, b"y").unwrap();
        // current would normally be the actual exe path; we simulate by
        // pointing at a name in this dir.
        let current = dir.path().join("mhrv-rs-ui");
        cleanup_stale_old(&current, "mhrv-rs-ui");
        assert!(!our.exists(), "ours should be removed");
        assert!(theirs.exists(), "unrelated .old must NOT be removed");
    }

    #[test]
    fn staged_update_swap_target_strips_new() {
        let s = StagedUpdate {
            staged_path: PathBuf::from("/p/foo.exe.new"),
            relaunch_path: PathBuf::from("/p/foo.exe"),
        };
        assert_eq!(s.swap_target(), PathBuf::from("/p/foo.exe"));
        let s = StagedUpdate {
            staged_path: PathBuf::from("/Apps/Mhrv.app.new"),
            relaunch_path: PathBuf::from("/Apps/Mhrv.app/Contents/MacOS/mhrv-rs-ui"),
        };
        assert_eq!(s.swap_target(), PathBuf::from("/Apps/Mhrv.app"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bundle_for_exe_detects_layout() {
        let inside = Path::new("/Applications/Mhrv.app/Contents/MacOS/mhrv-rs-ui");
        assert_eq!(
            macos_bundle_for_exe(inside),
            Some(PathBuf::from("/Applications/Mhrv.app"))
        );
        let outside = Path::new("/usr/local/bin/mhrv-rs-ui");
        assert!(macos_bundle_for_exe(outside).is_none());
        let near_miss = Path::new("/X/NotAnApp/Contents/MacOS/foo");
        assert!(macos_bundle_for_exe(near_miss).is_none());
    }
}

} // mod desktop

#[cfg(not(target_os = "android"))]
pub use desktop::*;
