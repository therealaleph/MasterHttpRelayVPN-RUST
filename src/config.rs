use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Read(String, #[source] std::io::Error),
    #[error("failed to parse config json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Operating mode. `AppsScript` is the full client — MITMs TLS locally and
/// relays HTTP/HTTPS through a user-deployed Apps Script endpoint.
/// `GoogleOnly` is a bootstrap: no relay, no Apps Script config needed,
/// only the SNI-rewrite tunnel to the Google edge is active. Intended for
/// users who need to reach `script.google.com` to deploy `Code.gs` in the
/// first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    AppsScript,
    GoogleOnly,
    Full,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::AppsScript => "apps_script",
            Mode::GoogleOnly => "google_only",
            Mode::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ScriptId {
    One(String),
    Many(Vec<String>),
}

impl ScriptId {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            ScriptId::One(s) => vec![s],
            ScriptId::Many(v) => v,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: String,
    #[serde(default = "default_google_ip")]
    pub google_ip: String,
    #[serde(default = "default_front_domain")]
    pub front_domain: String,
    #[serde(default)]
    pub script_id: Option<ScriptId>,
    #[serde(default)]
    pub script_ids: Option<ScriptId>,
    #[serde(default)]
    pub auth_key: String,
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub socks5_port: Option<u16>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_verify_ssl")]
    pub verify_ssl: bool,
    #[serde(default)]
    pub hosts: HashMap<String, String>,
    #[serde(default)]
    pub enable_batching: bool,
    /// Optional upstream SOCKS5 proxy for non-HTTP / raw-TCP traffic
    /// (e.g. `"127.0.0.1:50529"` pointing at a local xray / v2ray instance).
    /// When set, the SOCKS5 listener forwards raw-TCP flows through it
    /// instead of connecting directly. HTTP/HTTPS traffic (which goes
    /// through the Apps Script relay) and SNI-rewrite tunnels are
    /// unaffected.
    #[serde(default)]
    pub upstream_socks5: Option<String>,
    /// Fan-out factor for non-cached relay requests when multiple
    /// `script_id`s are configured. `0` or `1` = off (round-robin, the
    /// default). `2` or more = fire that many Apps Script instances in
    /// parallel per request and return the first successful response —
    /// kills long-tail latency caused by a single slow Apps Script
    /// instance, at the cost of using that much more daily quota.
    /// Value is clamped to the number of available (non-blacklisted)
    /// script IDs.
    #[serde(default)]
    pub parallel_relay: u8,
    /// Optional explicit SNI rotation pool for outbound TLS to `google_ip`.
    /// Empty / missing = auto-expand from `front_domain` (current default of
    /// {www, mail, drive, docs, calendar}.google.com). Set to an explicit list
    /// to pick exactly which SNI names get rotated through — useful when one
    /// of the defaults is locally blocked (e.g. mail.google.com in Iran at
    /// various times). Can be tested per-name via the UI or `mhrv-rs test-sni`.
    #[serde(default)]
    pub sni_hosts: Option<Vec<String>>,
    #[serde(default = "default_fetch_ips_from_api")]
    pub fetch_ips_from_api: bool,

    #[serde(default = "default_max_ips_to_scan")]
    pub max_ips_to_scan: usize,

    #[serde(default = "default_scan_batch_size")]
    pub scan_batch_size:usize,

    #[serde(default = "default_google_ip_validation")]
    pub google_ip_validation: bool,
    /// When true, GET requests to `x.com/i/api/graphql/<hash>/<op>?variables=…`
    /// have their query trimmed to just the `variables=` param before being
    /// relayed. The `features` / `fieldToggles` params that X ships with
    /// these requests change frequently and bust the response cache —
    /// stripping them dramatically improves hit rate on Twitter/X browsing.
    ///
    /// Credit: idea from seramo_ir, originally adapted to the Python
    /// MasterHttpRelayVPN by the Persian community
    /// (https://gist.github.com/seramo/0ae9e5d30ac23a73d5eb3bd2710fcd67).
    ///
    /// Off by default — some X endpoints may reject calls that omit
    /// features. Turn on and observe.
    #[serde(default)]
    pub normalize_x_graphql: bool,

    /// Route YouTube traffic through the Apps Script relay instead of
    /// the direct SNI-rewrite tunnel. Ported from upstream Python
    /// `youtube_via_relay` (issue #102).
    ///
    /// Why this exists: when YouTube is SNI-rewritten to `google_ip`
    /// with `SNI=www.google.com`, Google's frontend can enforce
    /// SafeSearch / Restricted Mode based on the SNI → some videos show
    /// as "restricted." Routing through Apps Script bypasses that check
    /// (it hits YouTube from Google's own backend, not via www.google.com
    /// SNI) but introduces the UrlFetchApp User-Agent and quota costs.
    ///
    /// Trade-off: enabling removes SafeSearch-on-SNI, adds `User-Agent:
    /// Google-Apps-Script` header and counts YouTube traffic against
    /// your Apps Script quota. Off by default.
    #[serde(default)]
    pub youtube_via_relay: bool,

    /// User-configurable passthrough list. Any host whose name matches
    /// one of these entries bypasses the Apps Script relay entirely and
    /// is plain-TCP-passthroughed (optionally through `upstream_socks5`).
    ///
    /// Accepts exact hostnames ("example.com") and leading-dot suffixes
    /// (".internal.example" matches "a.b.internal.example"). Matches are
    /// case-insensitive.
    ///
    /// Dispatched BEFORE SNI-rewrite and Apps Script, so a passthrough
    /// entry wins over the default Google-edge routing. Useful for
    /// sites where you already have reachability without the relay
    /// (saving Apps Script quota) or for hosts that break under MITM.
    ///
    /// Issues #39, #127.
    #[serde(default)]
    pub passthrough_hosts: Vec<String>,
}

fn default_fetch_ips_from_api() -> bool { false }
fn default_max_ips_to_scan() -> usize { 100 }
fn default_scan_batch_size() -> usize {500}
fn default_google_ip_validation() -> bool {true}

fn default_google_ip() -> String {
    "216.239.38.120".into()
}
fn default_front_domain() -> String {
    "www.google.com".into()
}
fn default_listen_host() -> String {
    "127.0.0.1".into()
}
fn default_listen_port() -> u16 {
    8085
}
fn default_log_level() -> String {
    "warn".into()
}
fn default_verify_ssl() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.display().to_string(), e))?;
        let cfg: Config = serde_json::from_str(&data)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mode = self.mode_kind()?;
        if mode == Mode::AppsScript || mode == Mode::Full {
            if self.auth_key.trim().is_empty() || self.auth_key == "CHANGE_ME_TO_A_STRONG_SECRET" {
                return Err(ConfigError::Invalid(
                    "auth_key must be set to a strong secret".into(),
                ));
            }
            let ids = self.script_ids_resolved();
            if ids.is_empty() {
                return Err(ConfigError::Invalid(
                    "script_id (or script_ids) is required".into(),
                ));
            }
            for id in &ids {
                if id.is_empty() || id == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID" {
                    return Err(ConfigError::Invalid(
                        "script_id is not set — deploy Code.gs and paste its Deployment ID".into(),
                    ));
                }
            }
        }
        if self.scan_batch_size == 0 {
            return Err(ConfigError::Invalid(
                "scan_batch_size must be greater than 0".into(),
            ));
        }
        if self.socks5_port == Some(self.listen_port) {
            return Err(ConfigError::Invalid(
                "listen_port and socks5_port must be different".into(),
            ));
        }
        Ok(())
    }

    pub fn mode_kind(&self) -> Result<Mode, ConfigError> {
        match self.mode.as_str() {
            "apps_script" => Ok(Mode::AppsScript),
            "google_only" => Ok(Mode::GoogleOnly),
            "full" => Ok(Mode::Full),
            other => Err(ConfigError::Invalid(format!(
                "unknown mode '{}' (expected 'apps_script', 'google_only', or 'full')",
                other
            ))),
        }
    }

    pub fn script_ids_resolved(&self) -> Vec<String> {
        if let Some(s) = &self.script_ids {
            return s.clone().into_vec();
        }
        if let Some(s) = &self.script_id {
            return s.clone().into_vec();
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": "ABCDEF"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert_eq!(cfg.script_ids_resolved(), vec!["ABCDEF".to_string()]);
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_multi_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": ["A", "B", "C"]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert_eq!(cfg.script_ids_resolved(), vec!["A", "B", "C"]);
    }

    #[test]
    fn rejects_placeholder_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "SECRET",
            "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_wrong_mode() {
        let s = r#"{
            "mode": "domain_fronting",
            "auth_key": "SECRET",
            "script_id": "X"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_google_only_without_script_id() {
        // Bootstrap mode: no script_id, no auth_key — both are only meaningful
        // once the Apps Script relay exists.
        let s = r#"{
            "mode": "google_only"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().expect("google_only must validate without script_id / auth_key");
        assert_eq!(cfg.mode_kind().unwrap(), Mode::GoogleOnly);
    }

    #[test]
    fn google_only_ignores_placeholder_script_id() {
        // UI round-trip: user saved config in apps_script with the placeholder,
        // then switched mode to google_only. The placeholder should not block
        // validation in the bootstrap mode.
        let s = r#"{
            "mode": "google_only",
            "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_full_mode() {
        let s = r#"{
            "mode": "full",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": "ABCDEF"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.mode_kind().unwrap(), Mode::Full);
    }

    #[test]
    fn full_mode_requires_script_id() {
        let s = r#"{
            "mode": "full",
            "auth_key": "SECRET"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_mode_value() {
        let s = r#"{
            "mode": "hybrid",
            "auth_key": "X",
            "script_id": "X"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_scan_batch_size() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "SECRET",
            "script_id": "X",
            "scan_batch_size": 0
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_same_http_and_socks5_port() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "SECRET",
            "script_id": "X",
            "listen_port": 8085,
            "socks5_port": 8085
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }
}

#[cfg(test)]
mod rt_tests {
    use super::*;

    #[test]
    fn round_trip_all_current_fields() {
        // Regression guard: make sure a config written by the UI (all current
        // optional fields present and populated) loads back cleanly.
        let json = r#"{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "AKfyc_TEST",
  "auth_key": "testtesttest",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_port": 8086,
  "log_level": "info",
  "verify_ssl": true,
  "upstream_socks5": "127.0.0.1:50529",
  "parallel_relay": 2,
  "sni_hosts": ["www.google.com", "drive.google.com"],
  "fetch_ips_from_api": true,
  "max_ips_to_scan": 50,
  "scan_batch_size": 100,
  "google_ip_validation": true
}"#;
        let tmp = std::env::temp_dir().join("mhrv-rt-test.json");
        std::fs::write(&tmp, json).unwrap();
        let cfg = Config::load(&tmp).expect("config should load");
        assert_eq!(cfg.mode, "apps_script");
        assert_eq!(cfg.auth_key, "testtesttest");
        assert_eq!(cfg.listen_port, 8085);
        assert_eq!(cfg.upstream_socks5.as_deref(), Some("127.0.0.1:50529"));
        assert_eq!(cfg.parallel_relay, 2);
        assert_eq!(
            cfg.sni_hosts.as_ref().unwrap(),
            &vec!["www.google.com".to_string(), "drive.google.com".to_string()]
        );
        assert_eq!(cfg.fetch_ips_from_api, true);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn round_trip_minimal_fields_only() {
        // User saves with defaults for everything optional. This is what the
        // UI's save button actually writes for a first-run user.
        let json = r#"{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "A",
  "auth_key": "secretkey123",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "log_level": "info",
  "verify_ssl": true
}"#;
        let tmp = std::env::temp_dir().join("mhrv-rt-min.json");
        std::fs::write(&tmp, json).unwrap();
        let cfg = Config::load(&tmp).expect("minimal config should load");
        assert_eq!(cfg.mode, "apps_script");
        let _ = std::fs::remove_file(&tmp);
    }
}
