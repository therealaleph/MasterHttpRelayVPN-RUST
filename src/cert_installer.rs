use std::path::Path;
use std::process::Command;

use crate::mitm::CERT_NAME;

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("certificate file not found: {0}")]
    NotFound(String),
    #[error("install failed on this platform")]
    Failed,
    #[error("unsupported platform: {0}")]
    Unsupported(String),
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

    // Best-effort: also try to install into Firefox NSS stores if certutil
    // is available. Firefox maintains its own trust store separate from the OS.
    install_firefox_nss(&path_s);

    if ok {
        Ok(())
    } else {
        Err(InstallError::Failed)
    }
}

/// Heuristic check: is the CA already in the trust store?
/// Best-effort — on unknown state we return false to always attempt install.
pub fn is_ca_trusted(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    match std::env::consts::OS {
        "macos" => is_trusted_macos(),
        "linux" => is_trusted_linux(),
        "windows" => false,
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
            let dest = format!("/etc/ca-certificates/trust-source/anchors/{}.crt", safe_name);
            try_copy_and_run(cert_path, &dest, &[&["trust", "extract-compat"]])
        }
        _ => {
            tracing::warn!("Unknown Linux distro — install {} manually.", cert_path);
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
        let lc = content.to_lowercase();
        if lc.contains("debian") || lc.contains("ubuntu") || lc.contains("mint") {
            return "debian".into();
        }
        if lc.contains("fedora") || lc.contains("rhel") || lc.contains("centos") {
            return "rhel".into();
        }
        if lc.contains("arch") || lc.contains("manjaro") {
            return "arch".into();
        }
    }
    "unknown".into()
}

fn is_trusted_linux() -> bool {
    let anchor_dirs = [
        "/usr/local/share/ca-certificates",
        "/etc/pki/ca-trust/source/anchors",
        "/etc/ca-certificates/trust-source/anchors",
    ];
    for d in anchor_dirs {
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

// ---------- Firefox (NSS) ----------

/// Best-effort install of the CA into all discovered Firefox profiles.
/// Silently no-ops if `certutil` (from libnss3-tools) is not available.
/// Firefox must be closed during install for changes to take effect.
fn install_firefox_nss(cert_path: &str) {
    // Check if certutil exists at all.
    if Command::new("certutil")
        .arg("--help")
        .output()
        .ok()
        .map(|o| {
            // macOS has a different certutil (built-in) that doesn't support -d.
            // Look for NSS-specific flags in the help output.
            String::from_utf8_lossy(&o.stderr).contains("-d")
                || String::from_utf8_lossy(&o.stdout).contains("-d")
        })
        .unwrap_or(false)
        == false
    {
        tracing::debug!(
            "NSS certutil not found — Firefox users must import ca.crt manually \
             via Settings -> Privacy & Security -> Certificates."
        );
        return;
    }

    let profiles = firefox_profile_dirs();
    if profiles.is_empty() {
        tracing::debug!("no Firefox profiles found");
        return;
    }

    let mut ok = 0;
    for p in &profiles {
        if install_nss_in_profile(p, cert_path) {
            ok += 1;
        }
    }
    if ok > 0 {
        tracing::info!("CA installed in {} Firefox profile(s).", ok);
    } else {
        tracing::debug!(
            "No Firefox profiles updated. If Firefox wasn't running, try installing manually."
        );
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

    // Delete any stale entry first (ignore errors).
    let _ = Command::new("certutil")
        .args(["-D", "-n", CERT_NAME, "-d", &dir_arg])
        .output();

    let res = Command::new("certutil")
        .args([
            "-A",
            "-n",
            CERT_NAME,
            "-t",
            "C,,",
            "-d",
            &dir_arg,
            "-i",
            cert_path,
        ])
        .output();
    match res {
        Ok(o) if o.status.success() => {
            tracing::debug!("NSS install ok: {}", profile.display());
            true
        }
        Ok(o) => {
            tracing::debug!(
                "NSS install failed for {}: {}",
                profile.display(),
                String::from_utf8_lossy(&o.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::debug!("NSS certutil exec failed for {}: {}", profile.display(), e);
            false
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
                roots.push(PathBuf::from(format!("{}\\Mozilla\\Firefox\\Profiles", appdata)));
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
