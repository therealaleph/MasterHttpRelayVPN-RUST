use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const APP_NAME: &str = "mhrv-rs";

/// Global override. On Android the app sets this to its private files dir
/// before any other mhrv-rs code runs — avoids `directories` crate returning
/// a questionable path inside `/data/data/...` that the app may not own.
/// On desktop platforms nobody sets this and the normal fallback applies.
static DATA_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Set the data directory. Takes effect ONLY on the first call — later
/// calls are no-ops (OnceLock semantics). Intended for Android's JNI init
/// path; don't call from desktop builds.
pub fn set_data_dir(path: PathBuf) {
    let _ = DATA_DIR_OVERRIDE.set(path);
}

/// Returns the platform-appropriate user-data directory for this app, creating
/// it if necessary. Falls back to the current directory if the dir can't be
/// determined (rare).
///
/// - macOS:   `~/Library/Application Support/mhrv-rs`
/// - Linux:   `~/.config/mhrv-rs` (or `$XDG_CONFIG_HOME/mhrv-rs`)
/// - Windows: `%APPDATA%\mhrv-rs`
/// - Android: whatever the app passed to `set_data_dir()` (typically the
///   app's private `filesDir`).
pub fn data_dir() -> PathBuf {
    if let Some(p) = DATA_DIR_OVERRIDE.get() {
        let _ = std::fs::create_dir_all(p);
        return p.clone();
    }
    let dir = directories::ProjectDirs::from("", "", APP_NAME)
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Path to config.toml in the platform data dir (the canonical location
/// for new users and post-migration installs).
pub fn config_path() -> PathBuf {
    data_dir().join("config.toml")
}

/// Path to the legacy config.json. Used only by resolve_config_path to
/// detect a JSON config that needs auto-migration to TOML.
pub fn json_config_path() -> PathBuf {
    data_dir().join("config.json")
}

/// Path to the CA cert inside the data dir (the MITM CA).
pub fn ca_cert_path() -> PathBuf {
    data_dir().join("ca").join("ca.crt")
}

/// Path to the CA private key inside the data dir.
pub fn ca_key_path() -> PathBuf {
    data_dir().join("ca").join("ca.key")
}

/// Resolve a config path: if the user supplied an explicit path, use it.
/// 
/// Otherwise search in preference order, TOML before JSON in both the
/// user-data dir and the current working directory. JSON hits trigger the
/// auto-migration in Config::load so the user is upgraded transparently.
/// 
/// Falls back to data_dir/config.toml (non-existent) so new-user error
/// messages and Save-config operations point to the right place.
pub fn resolve_config_path(cli_arg: Option<&Path>) -> PathBuf {
    if let Some(p) = cli_arg {
        return p.to_path_buf();
    }
    let user_toml = config_path();
    if user_toml.exists() {
        return user_toml;
    }
    let user_json = json_config_path();
    if user_json.exists() {
        return user_json;
    }
    let cwd_toml = PathBuf::from("config.toml");
    if cwd_toml.exists() {
        return cwd_toml;
    }
    let cwd_json = PathBuf::from("config.json");
    if cwd_json.exists() {
        return cwd_json;
    }
    // No config found anywhere - return the canonical new-user location.
    user_toml
}
