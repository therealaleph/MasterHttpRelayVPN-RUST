use std::path::{Path, PathBuf};
use std::process::Command;

use crate::mitm::{CA_DIR, CERT_NAME};

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("certificate file not found: {0}")]
    NotFound(String),
    #[error("install failed on this platform")]
    Failed,
    #[error("unsupported platform: {0}")]
    Unsupported(String),
    #[error("io {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("CA still trusted after removal — re-run with admin/sudo")]
    RemovalIncomplete,
}

/// Structured outcome of a successful `remove_ca` call. The OS trust
/// store is always fully clean when we return `Ok(_)` (that's verified
/// by `is_ca_trusted_by_name` before file deletion), but NSS cleanup is
/// best-effort — callers need the nuance to print accurate status.
///
/// UI/CLI should treat `Clean` as "nothing more to do" and
/// `NssIncomplete` as a non-fatal warning ("OS CA removed, browser
/// cleanup partial — follow the logged hint").
#[derive(Debug, Clone, Copy)]
pub enum RemovalOutcome {
    Clean,
    NssIncomplete(NssReport),
}

impl RemovalOutcome {
    /// One-line summary suitable for a log line or status banner.
    pub fn summary(&self) -> String {
        match self {
            RemovalOutcome::Clean => "CA removed.".to_string(),
            RemovalOutcome::NssIncomplete(r) if r.tool_missing_with_stores_present => {
                "OS CA removed. NSS cleanup skipped — NSS certutil not found.".to_string()
            }
            RemovalOutcome::NssIncomplete(r) => format!(
                "OS CA removed. NSS cleanup partial: {}/{} browser stores updated.",
                r.ok, r.tried
            ),
        }
    }
}

/// When running as root via `sudo`, the process's `HOME` / `USER`
/// environment reflects **root**, not the user who invoked the command.
/// That breaks every user-scoped cert path this module touches —
/// `data_dir()` resolves to root's config dir, `firefox_profile_dirs()`
/// scans root's profiles, macOS `login.keychain-db` is root's. The
/// removal then operates on paths that probably don't exist, reports
/// success, and leaves the real user's CA trusted.
///
/// This helper detects the real `sudo` case (`geteuid() == 0` AND
/// `SUDO_USER` set to a non-root user), resolves the invoking user's
/// home dir (SUDO_HOME, `getent passwd`, or `/Users/$SUDO_USER` /
/// `/home/$SUDO_USER` fallback), and rewrites `HOME` for the remainder
/// of the process. The EUID gate is load-bearing: `SUDO_USER` alone is
/// not proof of elevation (a user can export it, inherit it, or use
/// `sudo -E`), and blindly trusting it would let a non-root process
/// redirect config/CA/profile operations to another user's files.
/// Call once at the top of `main` in every binary (CLI + UI) before
/// anything else reads HOME. No-op on Windows (UAC keeps the user's
/// HOME intact) and on non-sudo Unix invocations.
pub fn reconcile_sudo_environment() {
    #[cfg(unix)]
    unix::reconcile_sudo_home();
}

#[cfg(unix)]
mod unix {
    use super::sudo_parse_passwd_home;
    use std::path::Path;
    use std::process::Command;

    pub(super) fn reconcile_sudo_home() {
        // EUID gate: only act when we are *actually* running with root
        // privileges. A process running as a normal user might have
        // SUDO_USER exported (inherited from a shell init, set in
        // user env, or via `sudo -E`) — without the EUID check we'd
        // happily rewrite HOME to another user's dir and redirect
        // every subsequent data_dir / cert path there. `geteuid()` is
        // the cheap, reliable discriminator.
        //
        // SAFETY: geteuid() is async-signal-safe and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return;
        }
        let Ok(sudo_user) = std::env::var("SUDO_USER") else {
            return;
        };
        if sudo_user.is_empty() || sudo_user == "root" {
            return;
        }
        match resolve_home(&sudo_user) {
            Some(home) => {
                tracing::info!(
                    "Detected sudo invocation (SUDO_USER={}): re-rooting HOME to {} \
                     so user-scoped cert paths target the real user.",
                    sudo_user,
                    home
                );
                // SAFETY: reconcile_sudo_environment runs at the top of
                // main() before any other thread is spawned and before
                // any code has cached HOME.
                std::env::set_var("HOME", home);
            }
            None => {
                tracing::warn!(
                    "Running under sudo (SUDO_USER={}), but could not resolve \
                     the user's home dir. Cert paths will operate on root's \
                     HOME — which may NOT match where you installed the CA. \
                     Prefer running without sudo; the app invokes sudo \
                     internally for system-level steps.",
                    sudo_user
                );
            }
        }
    }

    fn resolve_home(sudo_user: &str) -> Option<String> {
        // Some sudoers configs export SUDO_HOME; prefer it when present.
        if let Ok(h) = std::env::var("SUDO_HOME") {
            if !h.is_empty() {
                return Some(h);
            }
        }
        // Linux: `getent passwd <user>` returns the full passwd entry.
        if let Ok(out) = Command::new("getent").args(["passwd", sudo_user]).output() {
            if out.status.success() {
                let line = String::from_utf8_lossy(&out.stdout);
                if let Some(h) = sudo_parse_passwd_home(&line) {
                    return Some(h);
                }
            }
        }
        // macOS has no getent. Fall back to the convention for both
        // platforms — verify the dir actually exists before returning.
        for root in ["/Users", "/home"] {
            let candidate = format!("{}/{}", root, sudo_user);
            if Path::new(&candidate).exists() {
                return Some(candidate);
            }
        }
        None
    }
}

/// Pure parser for a single-line `getent passwd` entry.
/// Always compiled so unit tests can run on every host.
fn sudo_parse_passwd_home(content: &str) -> Option<String> {
    let line = content.lines().next()?;
    let fields: Vec<&str> = line.split(':').collect();
    // passwd format: name:pw:uid:gid:gecos:home:shell
    if fields.len() < 7 {
        return None;
    }
    let home = fields[5].trim();
    if home.is_empty() {
        return None;
    }
    Some(home.to_string())
}

/// Install the CA certificate at `path` into the system trust store.
/// Platform-specific — requires admin/sudo on most systems.
pub fn install_ca(path: &Path) -> Result<(), InstallError> {
    if !path.exists() {
        return Err(InstallError::NotFound(path.display().to_string()));
    }

    let path_s = path.to_string_lossy().to_string();

    let os = std::env::consts::OS;
    tracing::info!("Installing CA certificate on {}...", os);

    let ok = match os {
        "macos" => install_macos(&path_s),
        "linux" => install_linux(&path_s),
        "windows" => install_windows(&path_s),
        other => return Err(InstallError::Unsupported(other.to_string())),
    };

    // Best-effort: also install into NSS stores if `certutil` is available.
    // Both Firefox AND Chrome/Chromium on Linux maintain NSS databases that
    // are independent of the OS trust store — which is why running
    // update-ca-certificates alone wasn't enough for a lot of users
    // (issue #11 on Linux was this).
    install_nss_stores(&path_s);

    if ok {
        Ok(())
    } else {
        Err(InstallError::Failed)
    }
}

/// Remove the CA from the OS trust store, best-effort NSS stores (Firefox
/// profiles + Chrome/Chromium on Linux), and delete the on-disk
/// `ca/ca.crt` + `ca/ca.key`. A fresh CA will be regenerated the next
/// time the proxy starts — and since the Apps Script deployment lives on
/// Google's side and `config.json` is never touched here, the user does
/// not have to redeploy `Code.gs` or re-enter their deployment ID.
/// Platform-specific — may require admin/sudo for system stores.
///
/// Safety property: we verify the OS trust store with `is_ca_trusted`
/// before deleting `ca/`. If the stale root is still trusted (e.g.
/// because the system-store delete needed admin and we didn't have it),
/// we return `RemovalIncomplete` and leave the on-disk files alone — a
/// regenerated CA with a fresh keypair would otherwise mismatch the
/// stale trusted root and silently break every HTTPS MITM leaf.
pub fn remove_ca(base: &Path) -> Result<RemovalOutcome, InstallError> {
    let os = std::env::consts::OS;
    tracing::info!("Removing CA certificate on {}...", os);

    // Platforms that merge anchor files into a bundle/database (Linux)
    // must report whether the refresh step succeeded — the bundle may
    // still contain the CA even after the anchor file is gone. macOS
    // and Windows write directly to their stores, so there's nothing
    // separate to refresh; they rely entirely on the by-name probe.
    let platform_ok = match os {
        "macos" => {
            remove_macos();
            true
        }
        "linux" => remove_linux(),
        "windows" => {
            remove_windows();
            true
        }
        other => return Err(InstallError::Unsupported(other.to_string())),
    };

    // Verify OS trust store removal BEFORE touching browser state. If
    // the OS removal didn't actually land (e.g. machine-store delete
    // needed admin we don't have, or a Linux refresh cmd failed), we
    // must not also strip NSS entries + the Firefox enterprise_roots
    // pref — that leaves the system in an inconsistent "half-removed"
    // state (OS still trusts, but Firefox is newly reconfigured) that
    // only confuses the user. Returning RemovalIncomplete here keeps
    // the install pristine so a retry is idempotent.
    //
    // Must be path-independent — the on-disk cert file may already be
    // missing for unrelated reasons, and a file-gated check would then
    // mask a still-trusted stale root.
    if !platform_ok || is_ca_trusted_by_name() {
        tracing::error!(
            "MITM CA is still trusted after OS removal attempt \
             (platform_ok={}) — refusing to touch browser state or \
             delete on-disk files. Re-run with admin/sudo to complete \
             revocation.",
            platform_ok
        );
        return Err(InstallError::RemovalIncomplete);
    }

    // OS store is clean — only now mutate browser state.
    let nss = remove_nss_stores();

    let ca_dir = base.join(CA_DIR);
    if ca_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&ca_dir) {
            tracing::error!("failed to delete {}: {}", ca_dir.display(), e);
            return Err(InstallError::Io {
                path: ca_dir.clone(),
                source: e,
            });
        }
        tracing::info!("Deleted CA files at {}", ca_dir.display());
    }

    if nss.is_clean() {
        Ok(RemovalOutcome::Clean)
    } else {
        Ok(RemovalOutcome::NssIncomplete(nss))
    }
}

/// Heuristic check: is the CA already in the trust store?
/// Best-effort — on unknown state we return false to always attempt install.
///
/// The `path` guard skips the trust-store probe when the local CA file
/// is missing, because at install time "no file = nothing to trust" is a
/// useful shortcut. Revocation uses `is_ca_trusted_by_name` instead —
/// that path must verify the store regardless of whether the file still
/// exists, otherwise a pre-deleted `ca.crt` would mask a lingering
/// trusted root.
pub fn is_ca_trusted(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    is_ca_trusted_by_name()
}

/// Path-independent variant of `is_ca_trusted`: queries the OS trust
/// store by cert name (CERT_NAME) without requiring the on-disk cert
/// file. Used by `remove_ca` to verify revocation completed even if the
/// local `ca.crt` was already missing or deleted mid-flight.
pub fn is_ca_trusted_by_name() -> bool {
    match std::env::consts::OS {
        "macos" => is_trusted_macos(),
        "linux" => is_trusted_linux(),
        "windows" => is_trusted_windows(),
        _ => false,
    }
}

// ---------- macOS ----------

fn install_macos(cert_path: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let login_kc_db = format!("{}/Library/Keychains/login.keychain-db", home);
    let login_kc = format!("{}/Library/Keychains/login.keychain", home);
    let login_keychain = if Path::new(&login_kc_db).exists() {
        login_kc_db
    } else {
        login_kc
    };

    // Try login keychain first (no sudo).
    let res = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            &login_keychain,
            cert_path,
        ])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed into login keychain.");
            return true;
        }
    }

    // Fall back to system keychain (needs sudo).
    tracing::warn!("login keychain install failed — trying system keychain (needs sudo).");
    let res = Command::new("sudo")
        .args([
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            cert_path,
        ])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed into System keychain.");
            return true;
        }
    }
    tracing::error!("macOS install failed — run with sudo or install manually.");
    false
}

/// Delete the CA from the login keychain (no sudo) and, only when a
/// probe confirms the cert actually lives there, the system keychain
/// (sudo). Probing first avoids prompting the user — or hanging the
/// UI's GUI-spawned `sudo` — for a password they don't need when the
/// cert was only ever installed in the login keychain (the default
/// path). Exit status is best-effort: `security delete-certificate`
/// exits non-zero for "not found", which is indistinguishable from
/// real failures, so the final trust state is verified by the caller
/// via `is_ca_trusted_by_name`.
fn remove_macos() {
    let home = std::env::var("HOME").unwrap_or_default();
    let login_kc_db = format!("{}/Library/Keychains/login.keychain-db", home);
    let login_kc = format!("{}/Library/Keychains/login.keychain", home);
    let login_keychain = if Path::new(&login_kc_db).exists() {
        login_kc_db
    } else {
        login_kc
    };

    let res = Command::new("security")
        .args(["delete-certificate", "-c", CERT_NAME, &login_keychain])
        .status();
    if matches!(res, Ok(s) if s.success()) {
        tracing::info!("Removed CA from login keychain.");
    }

    if macos_system_keychain_has() {
        let res = Command::new("sudo")
            .args([
                "security",
                "delete-certificate",
                "-c",
                CERT_NAME,
                "/Library/Keychains/System.keychain",
            ])
            .status();
        if matches!(res, Ok(s) if s.success()) {
            tracing::info!("Removed CA from System keychain.");
        } else {
            tracing::warn!(
                "System keychain still has the CA and the sudo delete did not \
                 succeed — re-run with an admin password available."
            );
        }
    }
}

/// Probe-without-sudo: does the System keychain currently contain our
/// cert? `security find-certificate` against the system keychain path
/// does not require admin; only `delete-certificate` does. Used to
/// decide whether to escalate at all.
fn macos_system_keychain_has() -> bool {
    let out = Command::new("security")
        .args([
            "find-certificate",
            "-a",
            "-c",
            CERT_NAME,
            "/Library/Keychains/System.keychain",
        ])
        .output();
    match out {
        Ok(o) => o.status.success() && !o.stdout.is_empty(),
        Err(_) => false,
    }
}

fn is_trusted_macos() -> bool {
    let out = Command::new("security")
        .args(["find-certificate", "-a", "-c", CERT_NAME])
        .output();
    match out {
        Ok(o) => !o.stdout.is_empty() && o.status.success(),
        Err(_) => false,
    }
}

// ---------- Linux ----------

fn install_linux(cert_path: &str) -> bool {
    let distro = detect_linux_distro();
    tracing::info!("Detected Linux distro family: {}", distro);
    let safe_name = CERT_NAME.replace(' ', "_");

    match distro.as_str() {
        "debian" => {
            let dest = format!("/usr/local/share/ca-certificates/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["update-ca-certificates"]])
        }
        "rhel" => {
            let dest = format!("/etc/pki/ca-trust/source/anchors/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["update-ca-trust", "extract"]])
        }
        "arch" => {
            let dest = format!(
                "/etc/ca-certificates/trust-source/anchors/{}.crt",
                safe_name
            );
            try_copy_and_run(cert_path, &dest, &[&["trust", "extract-compat"]])
        }
        "openwrt" => {
            // OpenWRT itself doesn't open HTTPS connections through the proxy —
            // LAN clients do. The CA needs to be trusted on the CLIENTS, not on
            // the router. So this is a no-op success with guidance rather than
            // an error.
            tracing::info!(
                "OpenWRT detected: the router doesn't need to trust the MITM CA. \
                 Copy {} to each LAN client (browser / OS trust store) instead. \
                 Example: scp root@<router>:{} ./ and import from there.",
                cert_path,
                cert_path
            );
            true
        }
        _ => {
            tracing::warn!(
                "Unknown Linux distro — CA file is at {}. Copy it into your system's \
                 trust anchors dir (e.g. /usr/local/share/ca-certificates/ for \
                 Debian-like, /etc/pki/ca-trust/source/anchors/ for RHEL-like) and \
                 run the corresponding refresh command.",
                cert_path
            );
            false
        }
    }
}

fn try_copy_and_run(src: &str, dest: &str, cmds: &[&[&str]]) -> bool {
    // First try without sudo.
    let mut ok = true;
    if let Some(parent) = Path::new(dest).parent() {
        if std::fs::create_dir_all(parent).is_err() {
            ok = false;
        }
    }
    if ok && std::fs::copy(src, dest).is_err() {
        ok = false;
    }
    if ok {
        for cmd in cmds {
            if !run_cmd(cmd) {
                ok = false;
                break;
            }
        }
    }
    if ok {
        tracing::info!("CA installed via {}.", cmds[0].join(" "));
        return true;
    }

    // Retry with sudo.
    tracing::warn!("direct install failed — retrying with sudo.");
    if !run_cmd(&["sudo", "cp", src, dest]) {
        return false;
    }
    for cmd in cmds {
        let mut full: Vec<&str> = vec!["sudo"];
        full.extend_from_slice(cmd);
        if !run_cmd(&full) {
            return false;
        }
    }
    tracing::info!("CA installed via sudo.");
    true
}

fn run_cmd(args: &[&str]) -> bool {
    if args.is_empty() {
        return false;
    }
    let out = Command::new(args[0]).args(&args[1..]).status();
    matches!(out, Ok(s) if s.success())
}

fn detect_linux_distro() -> String {
    // Marker-file shortcuts (most reliable).
    if Path::new("/etc/openwrt_release").exists() {
        return "openwrt".into();
    }
    if Path::new("/etc/debian_version").exists() {
        return "debian".into();
    }
    if Path::new("/etc/redhat-release").exists() || Path::new("/etc/fedora-release").exists() {
        return "rhel".into();
    }
    if Path::new("/etc/arch-release").exists() {
        return "arch".into();
    }
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        return classify_os_release(&content);
    }
    "unknown".into()
}

/// Parse /etc/os-release content and return a distro family.
///
/// We specifically look at the `ID` and `ID_LIKE` fields (not a substring
/// search over the whole file) because random other fields like
/// `OPENWRT_DEVICE_ARCH=x86_64` contain substrings that false-positive on
/// "arch". Exposed for unit testing.
fn classify_os_release(content: &str) -> String {
    let mut id = String::new();
    let mut id_like = String::new();
    for line in content.lines() {
        let (k, v) = match line.split_once('=') {
            Some(x) => x,
            None => continue,
        };
        let v = v
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_ascii_lowercase();
        match k.trim() {
            "ID" => id = v,
            "ID_LIKE" => id_like = v,
            _ => {}
        }
    }
    let tokens: Vec<&str> = id
        .split(|c: char| c.is_whitespace() || c == ',')
        .chain(id_like.split(|c: char| c.is_whitespace() || c == ','))
        .filter(|t| !t.is_empty())
        .collect();
    let has = |needle: &str| tokens.iter().any(|t| *t == needle);
    if has("openwrt") {
        return "openwrt".into();
    }
    if has("debian") || has("ubuntu") || has("mint") || has("raspbian") {
        return "debian".into();
    }
    if has("fedora") || has("rhel") || has("centos") || has("rocky") || has("almalinux") {
        return "rhel".into();
    }
    if has("arch") || has("manjaro") || has("endeavouros") {
        return "arch".into();
    }
    "unknown".into()
}

/// Mirror of `install_linux`: for each known anchor dir, delete our cert
/// file and run the corresponding refresh command. Tries without sudo
/// first, falls back to sudo. Missing files are silently skipped —
/// removal is idempotent.
///
/// Key safety behavior: we refresh the trust bundle **regardless of
/// whether we found an anchor file to delete**. The concern is a retry
/// after a prior run that deleted the anchor but failed to refresh —
/// leaving the merged bundle still containing our PEM. On the next
/// invocation the anchor dir is empty, so a "delete file, then refresh"
/// contract would skip the refresh entirely and `remove_ca` would see
/// no anchor file left, declare success, and delete `ca/` while the
/// stale root is still trusted. Running the refresh unconditionally
/// catches this.
///
/// Returns `false` if any refresh command failed — callers must then
/// abort file deletion so a regenerated CA with a fresh keypair can't
/// mismatch the stale root.
fn remove_linux() -> bool {
    let safe_name = CERT_NAME.replace(' ', "_");
    let anchors: &[(&str, &[&str])] = &[
        (
            "/usr/local/share/ca-certificates",
            &["update-ca-certificates"],
        ),
        (
            "/etc/pki/ca-trust/source/anchors",
            &["update-ca-trust", "extract"],
        ),
        (
            "/etc/ca-certificates/trust-source/anchors",
            &["trust", "extract-compat"],
        ),
    ];

    let mut all_ok = true;
    for (dir, refresh) in anchors {
        // Skip distros whose anchor dir doesn't exist — running their
        // refresh tool (e.g. `trust extract-compat` on a Debian host)
        // would just error out and falsely mark the removal as failed.
        if !Path::new(dir).exists() {
            continue;
        }

        let path = format!("{}/{}.crt", dir, safe_name);
        let anchor_present = Path::new(&path).exists();
        if anchor_present {
            let deleted =
                std::fs::remove_file(&path).is_ok() || run_cmd(&["sudo", "rm", "-f", &path]);
            if !deleted {
                tracing::warn!("failed to remove {}", path);
                all_ok = false;
                continue;
            }
        }

        // Always refresh — see doc comment for the retry-safety rationale.
        let refreshed = run_cmd(refresh) || {
            let mut full: Vec<&str> = vec!["sudo"];
            full.extend_from_slice(refresh);
            run_cmd(&full)
        };
        if !refreshed {
            tracing::error!(
                "refresh {:?} failed for {} — CA may still be trusted via the merged bundle",
                refresh,
                dir
            );
            all_ok = false;
        } else if anchor_present {
            tracing::info!("Removed CA from {} (bundle refreshed).", dir);
        } else {
            tracing::debug!("Refreshed {} bundle (nothing to delete here).", dir);
        }
    }
    all_ok
}

fn is_trusted_linux() -> bool {
    // Check both the anchor dirs (what we write into on install) and
    // the post-extract dirs (where update-ca-certificates / `trust
    // extract-compat` etc. copy or symlink our PEM after refresh).
    // Checking the post-extract side catches the "anchor file already
    // removed but bundle not regenerated" case on a retry — if we only
    // looked at anchor dirs, a `remove_ca` retry after a prior refresh
    // failure could declare success while the merged bundle still
    // contains our stale root.
    let dirs = [
        "/usr/local/share/ca-certificates",
        "/etc/pki/ca-trust/source/anchors",
        "/etc/ca-certificates/trust-source/anchors",
        // Post-extract locations:
        "/etc/ssl/certs",
        "/etc/pki/ca-trust/extracted/pem/directory-hash",
        "/etc/ca-certificates/extracted/cadir",
    ];
    for d in dirs {
        if let Ok(entries) = std::fs::read_dir(d) {
            for e in entries.flatten() {
                let name = e.file_name();
                let s = name.to_string_lossy().to_lowercase();
                if s.contains("masterhttprelayvpn") || s.contains("mhrv") {
                    return true;
                }
            }
        }
    }
    false
}

// ---------- Windows ----------

/// Check whether our CA is present in the Windows Trusted Root store.
/// Looks in both the user store (no admin required to install) and the
/// machine store. Returns true if `certutil -store ... MasterHttpRelayVPN`
/// finds a match. Issue #13 follow-up: previously this always returned
/// false on Windows, so the Check-CA button was misleading users into
/// reinstalling a cert that was already trusted.
fn is_trusted_windows() -> bool {
    windows_store_has(true) || windows_store_has(false)
}

/// Query a single Windows Trusted Root store for our CA.
/// `user = true` hits the current-user store (no admin needed);
/// `user = false` hits the machine store. `certutil -store Root <name>`
/// prints the matching cert entries on success and exits non-zero with
/// "Not found" if nothing matches — we also check stdout for the cert
/// name because certutil in some locales returns 0 on no-match with
/// empty output.
fn windows_store_has(user: bool) -> bool {
    let mut args: Vec<&str> = Vec::new();
    if user {
        args.push("-user");
    }
    args.extend(["-store", "Root", CERT_NAME]);
    let out = Command::new("certutil").args(&args).output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            o.status.success()
                && stdout
                    .to_ascii_lowercase()
                    .contains(&CERT_NAME.to_ascii_lowercase())
        }
        Err(_) => false,
    }
}

fn install_windows(cert_path: &str) -> bool {
    // Per-user Root store (no admin required).
    let res = Command::new("certutil")
        .args(["-addstore", "-user", "Root", cert_path])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed in Windows user Trusted Root store.");
            return true;
        }
    }
    // System store (admin).
    let res = Command::new("certutil")
        .args(["-addstore", "Root", cert_path])
        .status();
    if let Ok(s) = res {
        if s.success() {
            tracing::info!("CA installed in Windows system Trusted Root store.");
            return true;
        }
    }
    tracing::error!("Windows install failed — run as administrator or install manually.");
    false
}

/// Delete from user and/or machine Trusted Root stores. We probe each
/// store first with `certutil -store` and only attempt the delete where
/// the cert actually lives — this avoids the confusing "needs elevation"
/// error that `-delstore Root` would print when the cert was only ever
/// installed in the per-user store (the default path for non-admin
/// runs). Final state is verified by the caller via `is_ca_trusted`.
fn remove_windows() {
    let mut any = false;

    if windows_store_has(true) {
        let res = Command::new("certutil")
            .args(["-delstore", "-user", "Root", CERT_NAME])
            .status();
        if matches!(res, Ok(s) if s.success()) {
            tracing::info!("Removed CA from Windows user Trusted Root store.");
            any = true;
        } else {
            tracing::warn!("failed to remove CA from Windows user Trusted Root store");
        }
    }

    if windows_store_has(false) {
        let res = Command::new("certutil")
            .args(["-delstore", "Root", CERT_NAME])
            .status();
        if matches!(res, Ok(s) if s.success()) {
            tracing::info!("Removed CA from Windows machine Trusted Root store.");
            any = true;
        } else {
            tracing::warn!(
                "failed to remove CA from Windows machine Trusted Root store \
                 (run as administrator to complete)"
            );
        }
    }

    if !any {
        tracing::info!("No MITM CA found in Windows Trusted Root stores.");
    }
}

// ---------- NSS (Firefox + Chrome/Chromium on Linux) ----------

/// Best-effort install of the CA into all discovered NSS stores:
///   1. Every Firefox profile (each has its own cert9.db).
///   2. On Linux, the shared Chrome/Chromium NSS DB at ~/.pki/nssdb —
///      this is the one update-ca-certificates does NOT populate, and
///      missing it was the real blocker for Chrome users who'd installed
///      the OS-level CA and still got cert errors (part of issue #11).
/// Silently no-ops if `certutil` (from libnss3-tools) isn't on PATH.
/// Browsers must be closed during install for changes to take effect.
fn install_nss_stores(cert_path: &str) {
    // First, try to make Firefox pick up the OS-level CA automatically by
    // flipping the `security.enterprise_roots.enabled` pref in user.js of
    // every Firefox profile we find. This is the cleanest cross-platform
    // fix because it doesn't depend on whether NSS certutil is installed
    // — Firefox just starts trusting whatever the OS trusts. Especially
    // important on Windows where NSS certutil isn't on PATH.
    enable_firefox_enterprise_roots();

    if !has_nss_certutil() {
        tracing::debug!(
            "NSS certutil not found — Firefox will still trust the CA via the \
             `security.enterprise_roots.enabled` user.js pref (flipped above). \
             For Chrome/Chromium on Linux, install `libnss3-tools` (Debian/Ubuntu) \
             or `nss-tools` (Fedora/RHEL), or import ca.crt manually via \
             chrome://settings/certificates → Authorities."
        );
        return;
    }

    let mut ok = 0;
    let mut tried = 0;

    // 1. Firefox profiles.
    for p in firefox_profile_dirs() {
        tried += 1;
        if install_nss_in_profile(&p, cert_path) {
            ok += 1;
        }
    }

    // 2. Chrome/Chromium shared NSS DB (Linux only).
    #[cfg(target_os = "linux")]
    {
        if let Some(nssdb) = chrome_nssdb_path() {
            // Ensure the DB exists. certutil -N creates an empty cert9.db in
            // the directory if none is there. An empty passphrase is fine
            // for a user-local DB.
            let dir_arg = format!("sql:{}", nssdb.display());
            if !nssdb.join("cert9.db").exists() && !nssdb.join("cert8.db").exists() {
                let _ = std::fs::create_dir_all(&nssdb);
                let _ = Command::new("certutil")
                    .args(["-N", "-d", &dir_arg, "--empty-password"])
                    .output();
            }
            tried += 1;
            if install_nss_in_dir(&dir_arg, cert_path) {
                ok += 1;
                tracing::info!(
                    "CA installed in Chrome/Chromium NSS DB: {}",
                    nssdb.display()
                );
            }
        }
    }

    if ok > 0 {
        tracing::info!("CA installed in {}/{} NSS store(s).", ok, tried);
    } else if tried > 0 {
        tracing::warn!(
            "NSS install: 0/{} stores updated. If Firefox/Chrome was running, close \
             them and retry. Otherwise, import ca.crt manually via browser settings.",
            tried
        );
    }
}

/// Write `user_pref("security.enterprise_roots.enabled", true);` to every
/// discovered Firefox profile's user.js. This makes Firefox trust the OS
/// trust store on next startup — so our already-successful system-level
/// CA install automatically propagates. Critical on Windows where Firefox
/// keeps its own NSS DB independent of Windows cert store, and NSS
/// certutil isn't typically installed so the certutil-based path doesn't
/// fire there.
///
/// We tag the block we write with a sentinel marker comment on the line
/// above the pref, so uninstall can prove ownership before removing it —
/// the user may have had `security.enterprise_roots.enabled = true`
/// before this app existed, and we must not silently revoke their
/// setting. Idempotent.
fn enable_firefox_enterprise_roots() {
    let mut touched = 0;
    for profile in firefox_profile_dirs() {
        let user_js = profile.join("user.js");
        let existing = std::fs::read_to_string(&user_js).unwrap_or_default();
        match add_enterprise_roots_block(&existing) {
            EnterpriseRootsEdit::AddedBlock(new) => {
                if let Err(e) = std::fs::write(&user_js, new) {
                    tracing::debug!(
                        "firefox profile {}: user.js write failed: {}",
                        profile.display(),
                        e
                    );
                    continue;
                }
                touched += 1;
            }
            EnterpriseRootsEdit::AlreadyOurs => {}
            EnterpriseRootsEdit::UserOwned => {
                tracing::debug!(
                    "firefox profile {} already has a user-owned enterprise_roots pref; leaving alone",
                    profile.display()
                );
            }
        }
    }
    if touched > 0 {
        tracing::info!(
            "enabled Firefox enterprise_roots in {} profile(s) — restart Firefox for it to take effect",
            touched
        );
    }
}

// ── Firefox enterprise_roots marker-block helpers (pure, testable) ──
//
// We write a two-line block into user.js — a sentinel comment followed
// by the pref itself. The marker proves we wrote it, so uninstall can
// distinguish our own line from a user-authored one with the same
// value. Any user-authored `security.enterprise_roots.enabled` line
// (with or without our marker above it) means "hands off".
const FX_MARKER: &str = "// mhrv-rs: auto-added, safe to strip with --remove-cert";
const FX_PREF: &str = r#"user_pref("security.enterprise_roots.enabled", true);"#;

#[derive(Debug, PartialEq, Eq)]
enum EnterpriseRootsEdit {
    AddedBlock(String),
    AlreadyOurs,
    UserOwned,
}

/// Append our marker+pref block to `existing` unless (a) it's already
/// there verbatim (idempotent no-op), or (b) the user has their own
/// `enterprise_roots` pref that we didn't write — in which case we
/// leave everything alone.
fn add_enterprise_roots_block(existing: &str) -> EnterpriseRootsEdit {
    if contains_our_block(existing) {
        return EnterpriseRootsEdit::AlreadyOurs;
    }
    if existing.contains("security.enterprise_roots.enabled") {
        return EnterpriseRootsEdit::UserOwned;
    }
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(FX_MARKER);
    out.push('\n');
    out.push_str(FX_PREF);
    out.push('\n');
    EnterpriseRootsEdit::AddedBlock(out)
}

/// Strip our marker+pref block from `existing` if present. If the pref
/// exists without our marker directly above it, the user owns it — we
/// cannot prove otherwise and leave user.js untouched.
///
/// Consequence for upgrades from pre-marker versions of this app: the
/// legacy bare pref line stays orphaned in user.js after uninstall.
/// That's cosmetic only (Firefox falls back to its built-in root store
/// the moment the CA leaves the OS trust store), and it's the
/// conservative tradeoff — a bare `enterprise_roots = true` line is
/// indistinguishable from a user- or enterprise-policy-authored one,
/// and silently revoking that would break unrelated Firefox trust
/// behavior. README documents the orphan.
fn strip_enterprise_roots_block(existing: &str) -> Option<String> {
    if !contains_our_block(existing) {
        return None;
    }
    let lines: Vec<&str> = existing.lines().collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let is_marker = lines[i].trim() == FX_MARKER;
        let next_is_our_pref = lines.get(i + 1).map_or(false, |l| l.trim() == FX_PREF);
        if is_marker && next_is_our_pref {
            i += 2;
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    let mut joined = out.join("\n");
    if existing.ends_with('\n') && !joined.is_empty() {
        joined.push('\n');
    }
    Some(joined)
}

/// True iff `existing` contains our sentinel directly above our pref.
fn contains_our_block(existing: &str) -> bool {
    let mut prev: Option<&str> = None;
    for line in existing.lines() {
        if prev.map(|p| p.trim()) == Some(FX_MARKER) && line.trim() == FX_PREF {
            return true;
        }
        prev = Some(line);
    }
    false
}

fn has_nss_certutil() -> bool {
    // We want NSS's `certutil` (from libnss3-tools), not Windows's
    // built-in `certutil.exe` which shares the binary name but has
    // completely different semantics. The previous heuristic looked
    // for "-d" in help output, which false-positived on Windows
    // because `-dump` / `-dumpPFX` are in the Windows help text.
    //
    // "nickname" is an NSS-specific concept (single-letter batch verbs
    // like `-A`/`-D`/`-n nickname`); the Windows and macOS built-in
    // certutils don't use that term. Matching on it reliably
    // discriminates.
    Command::new("certutil")
        .arg("--help")
        .output()
        .ok()
        .map(|o| {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stderr),
                String::from_utf8_lossy(&o.stdout)
            );
            combined.to_ascii_lowercase().contains("nickname")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn chrome_nssdb_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(format!("{}/.pki/nssdb", home)))
}

/// Install into a given sql: or legacy NSS DB path. Factored out so both
/// Firefox-per-profile and Chrome-shared paths share one code path.
fn install_nss_in_dir(dir_arg: &str, cert_path: &str) -> bool {
    // Delete any stale entry first (ignore errors).
    let _ = Command::new("certutil")
        .args(["-D", "-n", CERT_NAME, "-d", dir_arg])
        .output();

    let res = Command::new("certutil")
        .args([
            "-A", "-n", CERT_NAME, "-t", "C,,", "-d", dir_arg, "-i", cert_path,
        ])
        .output();
    match res {
        Ok(o) if o.status.success() => {
            tracing::debug!("NSS install ok: {}", dir_arg);
            true
        }
        Ok(o) => {
            tracing::debug!(
                "NSS install failed for {}: {}",
                dir_arg,
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::debug!("NSS certutil exec failed for {}: {}", dir_arg, e);
            false
        }
    }
}

fn install_nss_in_profile(profile: &Path, cert_path: &str) -> bool {
    let prefix = if profile.join("cert9.db").exists() {
        "sql:"
    } else if profile.join("cert8.db").exists() {
        ""
    } else {
        return false;
    };
    let dir_arg = format!("{}{}", prefix, profile.display());
    install_nss_in_dir(&dir_arg, cert_path)
}

/// Best-effort reverse of `install_nss_stores`: delete our cert from
/// every Firefox profile NSS DB we can find, plus the shared Chrome/
/// Chromium NSS DB on Linux, and remove the user.js pref we added.
///
/// NSS cleanup is explicitly best-effort — `certutil` from libnss3-tools
/// may be missing, a DB may be locked by a running Firefox/Chrome, or
/// the delete may fail for reasons we can't distinguish. When that
/// happens we log a manual-cleanup hint but don't fail the whole
/// revocation. Callers of `remove_ca` should convey this to users so
/// the `--remove-cert` promise is "OS trust store + best-effort NSS",
/// not "guaranteed NSS".
/// Outcome of an NSS cleanup pass. `tried` / `ok` let callers render
/// accurate messages like "NSS cleanup partial: 1/3 stores updated".
/// `tool_missing_with_stores_present` flags the case where we found
/// Firefox/Chrome NSS DBs but NSS `certutil` isn't on PATH — surfaced
/// so the UI/CLI can tell the user why the cleanup is incomplete.
#[derive(Debug, Clone, Copy, Default)]
pub struct NssReport {
    pub tried: usize,
    pub ok: usize,
    pub tool_missing_with_stores_present: bool,
}

impl NssReport {
    pub fn is_clean(&self) -> bool {
        !self.tool_missing_with_stores_present && self.tried == self.ok
    }
}

fn remove_nss_stores() -> NssReport {
    disable_firefox_enterprise_roots();

    if !has_nss_certutil() {
        // Only warn if there's actually an NSS store we can see — if the
        // user never ran Firefox/Chrome on this machine there's nothing
        // to clean up either way.
        let profiles = firefox_profile_dirs();
        let chrome_present: bool;
        #[cfg(target_os = "linux")]
        {
            chrome_present = chrome_nssdb_path()
                .map(|p| p.join("cert9.db").exists() || p.join("cert8.db").exists())
                .unwrap_or(false);
        }
        #[cfg(not(target_os = "linux"))]
        {
            chrome_present = false;
        }
        let stores_present = !profiles.is_empty() || chrome_present;
        if stores_present {
            tracing::warn!(
                "NSS certutil not found — cannot automatically remove CA from \
                 Firefox/Chrome NSS stores. Remove `MasterHttpRelayVPN` manually \
                 via each browser's certificate settings, or install NSS tools \
                 (`libnss3-tools` on Debian/Ubuntu, `nss-tools` on Fedora/RHEL) \
                 and re-run --remove-cert."
            );
        }
        return NssReport {
            tried: 0,
            ok: 0,
            tool_missing_with_stores_present: stores_present,
        };
    }

    let mut report = NssReport::default();

    for p in firefox_profile_dirs() {
        report.tried += 1;
        if remove_nss_in_profile(&p) {
            report.ok += 1;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(nssdb) = chrome_nssdb_path() {
            if nssdb.join("cert9.db").exists() || nssdb.join("cert8.db").exists() {
                report.tried += 1;
                let dir_arg = format!("sql:{}", nssdb.display());
                if remove_nss_in_dir(&dir_arg) {
                    report.ok += 1;
                    tracing::info!(
                        "Removed CA from Chrome/Chromium NSS DB: {}",
                        nssdb.display()
                    );
                }
            }
        }
    }

    if report.tried > 0 {
        if report.ok == report.tried {
            tracing::info!("Removed CA from {} NSS store(s).", report.ok);
        } else {
            tracing::warn!(
                "NSS cleanup partial: {}/{} stores updated. If Firefox/Chrome \
                 was running, close it and re-run --remove-cert. Otherwise \
                 remove `MasterHttpRelayVPN` manually via each browser's cert \
                 settings.",
                report.ok,
                report.tried
            );
        }
    }
    report
}

/// Best-effort remove our cert from one NSS DB.
///
/// Idempotent contract: "cert was never in this DB" is success.
/// Critical distinction from probe *failure*: if `certutil -L` fails
/// because the DB is locked by a running Firefox/Chrome, corrupt, or
/// inaccessible, we must NOT return `true` — that would silently mask
/// an incomplete revocation the user can't see, and NSS would keep
/// trusting the stale root. We parse stderr: only the specific
/// "could not find cert" message means absent.
fn remove_nss_in_dir(dir_arg: &str) -> bool {
    let list = Command::new("certutil")
        .args(["-L", "-n", CERT_NAME, "-d", dir_arg])
        .output();
    match list {
        Ok(o) if o.status.success() => {
            // Cert is present — fall through to delete.
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if is_nss_not_found(&stderr) {
                tracing::debug!("NSS {}: no `{}` entry — already clean", dir_arg, CERT_NAME);
                return true;
            }
            tracing::warn!(
                "NSS {}: probe failed (DB locked / inaccessible / other error): {}",
                dir_arg,
                stderr.trim()
            );
            return false;
        }
        Err(e) => {
            tracing::warn!("NSS {}: probe exec failed: {}", dir_arg, e);
            return false;
        }
    }

    let res = Command::new("certutil")
        .args(["-D", "-n", CERT_NAME, "-d", dir_arg])
        .output();
    match res {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            tracing::warn!(
                "NSS {}: delete failed: {}",
                dir_arg,
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("NSS {}: delete exec failed: {}", dir_arg, e);
            false
        }
    }
}

/// Classify NSS `certutil` stderr as "nickname not present" (idempotent
/// success signal) vs any other failure mode (DB locked, DB corrupt,
/// permission, etc.). Exposed for unit testing. Matches only the
/// specific not-found messages NSS emits — anything else is treated as
/// a real failure so silent bugs can't hide behind false positives.
fn is_nss_not_found(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("could not find cert") || s.contains("could not find a certificate")
}

fn remove_nss_in_profile(profile: &Path) -> bool {
    let prefix = if profile.join("cert9.db").exists() {
        "sql:"
    } else if profile.join("cert8.db").exists() {
        ""
    } else {
        return false;
    };
    let dir_arg = format!("{}{}", prefix, profile.display());
    remove_nss_in_dir(&dir_arg)
}

/// Undo `enable_firefox_enterprise_roots`: for each profile, strip the
/// marker+pref block if (and only if) we wrote it. If the user owns
/// their own `enterprise_roots` pref — indicated by the absence of our
/// marker line — leave user.js alone entirely.
fn disable_firefox_enterprise_roots() {
    for profile in firefox_profile_dirs() {
        let user_js = profile.join("user.js");
        let Ok(existing) = std::fs::read_to_string(&user_js) else {
            continue;
        };
        if let Some(new) = strip_enterprise_roots_block(&existing) {
            let _ = std::fs::write(&user_js, new);
        }
    }
}

fn firefox_profile_dirs() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut roots: Vec<PathBuf> = Vec::new();
    let home = std::env::var("HOME").unwrap_or_default();
    match std::env::consts::OS {
        "macos" => {
            roots.push(PathBuf::from(format!(
                "{}/Library/Application Support/Firefox/Profiles",
                home
            )));
        }
        "linux" => {
            roots.push(PathBuf::from(format!("{}/.mozilla/firefox", home)));
            roots.push(PathBuf::from(format!(
                "{}/snap/firefox/common/.mozilla/firefox",
                home
            )));
        }
        "windows" => {
            if let Ok(appdata) = std::env::var("APPDATA") {
                roots.push(PathBuf::from(format!(
                    "{}\\Mozilla\\Firefox\\Profiles",
                    appdata
                )));
            }
        }
        _ => {}
    }

    let mut out: Vec<PathBuf> = Vec::new();
    for root in &roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if !p.is_dir() {
                continue;
            }
            // A profile has cert9.db or cert8.db.
            if p.join("cert9.db").exists() || p.join("cert8.db").exists() {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openwrt_os_release_is_not_arch() {
        // Real OpenWRT 23.05 /etc/os-release. Contains OPENWRT_DEVICE_ARCH
        // which substring-matches "arch" — the old detector would mis-classify
        // this as Arch Linux. Regression guard for issue #2.
        let content = r#"
NAME="OpenWrt"
VERSION="23.05.3"
ID="openwrt"
ID_LIKE="lede openwrt"
PRETTY_NAME="OpenWrt 23.05.3"
VERSION_ID="23.05.3"
HOME_URL="https://openwrt.org/"
BUG_URL="https://bugs.openwrt.org/"
SUPPORT_URL="https://forum.openwrt.org/"
BUILD_ID="r23809-234f1a2efa"
OPENWRT_BOARD="x86/64"
OPENWRT_ARCH="x86_64"
OPENWRT_TAINTS=""
OPENWRT_DEVICE_MANUFACTURER="OpenWrt"
OPENWRT_DEVICE_MANUFACTURER_URL="https://openwrt.org/"
OPENWRT_DEVICE_PRODUCT="Generic"
OPENWRT_DEVICE_REVISION="v0"
OPENWRT_RELEASE="OpenWrt 23.05.3 r23809-234f1a2efa"
"#;
        assert_eq!(classify_os_release(content), "openwrt");
    }

    #[test]
    fn debian_bullseye_classified_as_debian() {
        let content = r#"
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
"#;
        assert_eq!(classify_os_release(content), "debian");
    }

    #[test]
    fn ubuntu_classified_as_debian_via_id_like() {
        let content = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
"#;
        assert_eq!(classify_os_release(content), "debian");
    }

    #[test]
    fn fedora_classified_as_rhel() {
        let content = "ID=fedora\nVERSION_ID=39\n";
        assert_eq!(classify_os_release(content), "rhel");
    }

    #[test]
    fn arch_classified_as_arch() {
        let content = "ID=arch\nID_LIKE=\n";
        assert_eq!(classify_os_release(content), "arch");
    }

    #[test]
    fn manjaro_classified_as_arch() {
        let content = "ID=manjaro\nID_LIKE=arch\n";
        assert_eq!(classify_os_release(content), "arch");
    }

    #[test]
    fn empty_os_release_is_unknown() {
        assert_eq!(classify_os_release(""), "unknown");
    }

    #[test]
    fn random_file_with_arch_substring_does_not_match() {
        // Make sure we don't regress to the old substring-match bug.
        let content = "SOMEFIELD=maybearchived\nFOO=bar\n";
        assert_eq!(classify_os_release(content), "unknown");
    }

    // ── Firefox user.js block install / uninstall ──

    #[test]
    fn enterprise_roots_block_added_to_empty_userjs() {
        let got = add_enterprise_roots_block("");
        let expected = format!("{}\n{}\n", FX_MARKER, FX_PREF);
        assert_eq!(got, EnterpriseRootsEdit::AddedBlock(expected));
    }

    #[test]
    fn enterprise_roots_block_appended_preserving_existing_prefs() {
        let existing = "user_pref(\"some.other\", 1);\n";
        let got = add_enterprise_roots_block(existing);
        let expected = format!(
            "user_pref(\"some.other\", 1);\n{}\n{}\n",
            FX_MARKER, FX_PREF
        );
        assert_eq!(got, EnterpriseRootsEdit::AddedBlock(expected));
    }

    #[test]
    fn enterprise_roots_block_is_idempotent_when_marker_present() {
        let existing = format!(
            "user_pref(\"a\", 1);\n{}\n{}\nuser_pref(\"b\", 2);\n",
            FX_MARKER, FX_PREF
        );
        assert_eq!(
            add_enterprise_roots_block(&existing),
            EnterpriseRootsEdit::AlreadyOurs
        );
    }

    #[test]
    fn enterprise_roots_block_respects_user_owned_pref_without_marker() {
        // User has enterprise_roots set themselves — no marker above it.
        // We must NOT write our line, and we must NOT claim ownership on
        // uninstall (tested separately below).
        let existing = "user_pref(\"security.enterprise_roots.enabled\", true);\n";
        assert_eq!(
            add_enterprise_roots_block(existing),
            EnterpriseRootsEdit::UserOwned
        );
    }

    #[test]
    fn enterprise_roots_block_respects_user_owned_pref_set_to_false() {
        // User explicitly disabled it — also a user-owned pref, leave alone.
        let existing = "user_pref(\"security.enterprise_roots.enabled\", false);\n";
        assert_eq!(
            add_enterprise_roots_block(existing),
            EnterpriseRootsEdit::UserOwned
        );
    }

    #[test]
    fn strip_enterprise_roots_removes_our_block_and_preserves_others() {
        let before = format!(
            "user_pref(\"a\", 1);\n{}\n{}\nuser_pref(\"b\", 2);\n",
            FX_MARKER, FX_PREF
        );
        let after = strip_enterprise_roots_block(&before).expect("should strip");
        assert_eq!(after, "user_pref(\"a\", 1);\nuser_pref(\"b\", 2);\n");
    }

    #[test]
    fn strip_enterprise_roots_refuses_when_pref_is_bare() {
        // No marker above — indistinguishable from a user- or
        // enterprise-policy-authored line. Must return None so caller
        // leaves user.js untouched. Legacy upgrade users get one
        // cosmetic orphan line; revoking user-owned Firefox trust
        // behavior silently is worse.
        let before = "user_pref(\"security.enterprise_roots.enabled\", true);\n";
        assert_eq!(strip_enterprise_roots_block(before), None);
    }

    #[test]
    fn strip_enterprise_roots_refuses_when_marker_is_elsewhere() {
        // Marker present but not directly above the pref — user may
        // have copied our marker line as a comment somewhere else. We
        // still can't prove ownership of the pref itself, so leave
        // alone.
        let before = format!(
            "{}\nuser_pref(\"unrelated\", 1);\n\
             user_pref(\"security.enterprise_roots.enabled\", true);\n",
            FX_MARKER
        );
        assert_eq!(strip_enterprise_roots_block(&before), None);
    }

    #[test]
    fn strip_enterprise_roots_leaves_user_false_pref_alone() {
        let before = "user_pref(\"security.enterprise_roots.enabled\", false);\n";
        assert_eq!(strip_enterprise_roots_block(before), None);
    }

    #[test]
    fn strip_enterprise_roots_returns_none_when_pref_absent() {
        let before = "user_pref(\"other\", 1);\nuser_pref(\"another\", 2);\n";
        assert_eq!(strip_enterprise_roots_block(before), None);
    }

    #[test]
    fn strip_enterprise_roots_roundtrip_from_empty() {
        // add_block("") -> strip_block(added) -> "" (no trailing garbage).
        let added = match add_enterprise_roots_block("") {
            EnterpriseRootsEdit::AddedBlock(s) => s,
            other => panic!("unexpected: {:?}", other),
        };
        let stripped = strip_enterprise_roots_block(&added).expect("should strip");
        assert_eq!(stripped, "");
    }

    // ── sudo_parse_passwd_home ──

    #[test]
    fn parses_debian_passwd_entry() {
        let line = "liyon:x:1000:1000:Liyon,,,:/home/liyon:/bin/bash\n";
        assert_eq!(sudo_parse_passwd_home(line), Some("/home/liyon".into()));
    }

    #[test]
    fn macos_passwd_format_does_not_parse_and_falls_back_to_convention() {
        // macOS `dscl`-sourced passwd lines have extra fields
        // (pw_class, chg, exp) before home, so index 5 lands on a
        // non-home field. sudo_parse_passwd_home is intentionally
        // Linux-shaped — the macOS path relies on the `/Users/<user>`
        // convention in `unix::resolve_home` rather than on this
        // parser. This test pins that contract.
        let line = "liyon:*:501:20::0:0:Liyon Bonakdar:/Users/liyon:/bin/zsh";
        assert_ne!(sudo_parse_passwd_home(line), Some("/Users/liyon".into()));
    }

    #[test]
    fn rejects_malformed_passwd_line_too_few_fields() {
        let line = "liyon:x:1000:1000\n";
        assert_eq!(sudo_parse_passwd_home(line), None);
    }

    #[test]
    fn rejects_empty_home_field() {
        let line = "svcacct:x:999:999:gecos::/bin/false\n";
        assert_eq!(sudo_parse_passwd_home(line), None);
    }

    #[test]
    fn returns_first_matching_line_when_multiple() {
        // getent only prints one line, but guard against future change.
        let content = "liyon:x:1000:1000::/home/liyon:/bin/bash\n\
                       other:x:1001:1001::/home/other:/bin/bash\n";
        assert_eq!(sudo_parse_passwd_home(content), Some("/home/liyon".into()));
    }

    // ── NssReport::is_clean ──

    #[test]
    fn nss_report_is_clean_when_nothing_tried() {
        let r = NssReport::default();
        assert!(r.is_clean());
    }

    #[test]
    fn nss_report_is_clean_when_all_attempts_succeeded() {
        let r = NssReport {
            tried: 3,
            ok: 3,
            tool_missing_with_stores_present: false,
        };
        assert!(r.is_clean());
    }

    #[test]
    fn nss_report_not_clean_on_partial_failure() {
        let r = NssReport {
            tried: 3,
            ok: 2,
            tool_missing_with_stores_present: false,
        };
        assert!(!r.is_clean());
    }

    #[test]
    fn nss_report_not_clean_when_tool_missing_with_stores() {
        // Even with tried=0 (we couldn't try anything), the presence
        // of NSS stores plus a missing tool means cleanup is NOT
        // complete — callers should flag this to the user.
        let r = NssReport {
            tried: 0,
            ok: 0,
            tool_missing_with_stores_present: true,
        };
        assert!(!r.is_clean());
    }

    // ── is_nss_not_found ──

    #[test]
    fn nss_not_found_classifies_standard_not_found_message() {
        // Typical NSS certutil output when the nickname is absent.
        let stderr = "certutil: Could not find cert: MasterHttpRelayVPN\n";
        assert!(is_nss_not_found(stderr));
    }

    #[test]
    fn nss_not_found_classifies_alt_wording_some_versions_emit() {
        let stderr = "certutil: could not find a certificate named 'MasterHttpRelayVPN'\n";
        assert!(is_nss_not_found(stderr));
    }

    #[test]
    fn nss_not_found_rejects_locked_database_error() {
        // Regression guard for the critical bug: DB locked (Firefox
        // running) must NOT be treated as "cert absent" — that would
        // silently report clean revocation while NSS keeps trusting
        // the stale root.
        let stderr = "certutil: function failed: SEC_ERROR_LOCKED_DATABASE: \
                      the certificate/key database is locked.\n";
        assert!(!is_nss_not_found(stderr));
    }

    #[test]
    fn nss_not_found_rejects_bad_database_error() {
        let stderr = "certutil: function failed: SEC_ERROR_BAD_DATABASE: \
                      security library: bad database.\n";
        assert!(!is_nss_not_found(stderr));
    }

    #[test]
    fn nss_not_found_rejects_permission_error() {
        let stderr = "certutil: unable to open \"sql:/home/x/.mozilla/firefox/profile\" \
                      (Permission denied)\n";
        assert!(!is_nss_not_found(stderr));
    }

    #[test]
    fn nss_not_found_rejects_empty_stderr() {
        // An empty stderr with a non-zero exit is ambiguous — safer
        // to classify as "not found is NOT proven", i.e. failure.
        assert!(!is_nss_not_found(""));
    }
}
