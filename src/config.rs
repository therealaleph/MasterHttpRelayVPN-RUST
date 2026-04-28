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
    GoogleDrive,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::AppsScript => "apps_script",
            Mode::GoogleOnly => "google_only",
            Mode::Full => "full",
            Mode::GoogleDrive => "google_drive",
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
    pub scan_batch_size: usize,

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

    /// Block outbound QUIC (UDP/443) at the SOCKS5 listener.
    ///
    /// QUIC is HTTP/3-over-UDP. In `apps_script` mode it's hopeless —
    /// Apps Script is HTTP-only, so QUIC datagrams either get refused
    /// outright (UDP ASSOCIATE rejected) or silently fall through to
    /// `raw-tcp direct` and fail in interesting ways. In `full` mode
    /// the tunnel-node CAN carry UDP, but QUIC's congestion control
    /// stacked on top of TCP-encapsulated transport produces TCP
    /// meltdown for any non-trivial bandwidth — browsers see <1 Mbps
    /// where the same site over plain HTTPS would do >50.
    ///
    /// With `block_quic = true`, the SOCKS5 UDP relay drops any
    /// datagram destined for port 443 (silent UDP — caller's stack
    /// retries a few times then falls back). Browsers then re-issue
    /// the same request as TCP/HTTPS through the regular CONNECT
    /// path, which goes through the relay normally.
    ///
    /// Why this is opt-in rather than always-on: for users on Full
    /// mode + udpgw (a recent path; v1.7.0+) the QUIC TCP-meltdown
    /// is partially mitigated by udpgw's persistent-socket reuse,
    /// and a tiny minority of sites only support HTTP/3 (rare). The
    /// flag lets users who care about consistency over peak speed
    /// opt out of QUIC at the source rather than discovering its
    /// failure modes later. Issue #213.
    #[serde(default)]
    pub block_quic: bool,

    /// When true, suppress the random `_pad` field that v1.8.0+ adds
    /// to outbound Apps Script requests for DPI evasion. Default off
    /// (padding active). Some users on heavily-throttled ISPs find
    /// the +25% bandwidth cost from padding compounds with the
    /// throttle to push borderline-working batches into timeouts;
    /// turning padding off recovers a bit of headroom at the cost of
    /// length-distribution defense against DPI fingerprinting. Issue
    /// #391 (EBRAHIM-AM).
    ///
    /// Don't flip this on speculatively — for users where Apps Script
    /// outbound is uncongested, padding is free DPI defense. Only
    /// turn off if you've measured throughput improvement after the
    /// flip on your specific ISP path.
    #[serde(default)]
    pub disable_padding: bool,

    /// Google Drive queue mode (`mode = "google_drive"`). This is the
    /// FlowDriver-style transport: both client and `mhrv-drive-node` poll
    /// a shared Drive folder and exchange multiplexed binary envelopes as
    /// short-lived files. It does not use Apps Script, `script_id`, or
    /// `auth_key`; OAuth credentials are loaded from this desktop-client
    /// JSON instead.
    #[serde(default = "default_drive_credentials_path")]
    pub drive_credentials_path: String,
    /// Optional override for the cached OAuth refresh token path. When
    /// omitted, `<drive_credentials_path>.token` is used.
    #[serde(default)]
    pub drive_token_path: Option<String>,
    /// Shared Google Drive folder ID. If empty, the client/node will find
    /// or create `drive_folder_name` in the authorized account.
    #[serde(default)]
    pub drive_folder_id: String,
    #[serde(default = "default_drive_folder_name")]
    pub drive_folder_name: String,
    /// Stable client ID used in Drive filenames. If empty, a short random
    /// ID is generated for this process.
    #[serde(default)]
    pub drive_client_id: String,
    #[serde(default = "default_drive_poll_ms")]
    pub drive_poll_ms: u64,
    #[serde(default = "default_drive_flush_ms")]
    pub drive_flush_ms: u64,
    /// Per-session inactivity cutoff. Long-poll HTTP, idle WebSockets and
    /// the like need this above their own keepalive interval; the FlowDriver
    /// default of 15 s was too aggressive for real protocols.
    #[serde(default = "default_drive_idle_timeout_secs")]
    pub drive_idle_timeout_secs: u64,
    /// Max concurrent in-flight Drive uploads/downloads. `0` (default)
    /// uses the built-in [`drive_tunnel::STORAGE_CONCURRENCY`] of 8.
    /// Bump up if you have a fat pipe and many sessions; HTTP/2
    /// multiplexes everything onto one TLS connection so the cost of
    /// raising this is just a few more in-flight streams.
    #[serde(default)]
    pub drive_storage_concurrency: usize,
}

fn default_fetch_ips_from_api() -> bool {
    false
}
fn default_max_ips_to_scan() -> usize {
    100
}
fn default_scan_batch_size() -> usize {
    500
}
fn default_google_ip_validation() -> bool {
    true
}
fn default_drive_credentials_path() -> String {
    "credentials.json".into()
}
fn default_drive_folder_name() -> String {
    "MHRV-Drive".into()
}
fn default_drive_poll_ms() -> u64 {
    500
}
fn default_drive_flush_ms() -> u64 {
    300
}
fn default_drive_idle_timeout_secs() -> u64 {
    300
}

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
        if mode == Mode::GoogleDrive {
            if self.drive_credentials_path.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "drive_credentials_path is required in google_drive mode".into(),
                ));
            }
            if self.drive_poll_ms == 0 || self.drive_flush_ms == 0 {
                return Err(ConfigError::Invalid(
                    "drive_poll_ms and drive_flush_ms must be greater than 0".into(),
                ));
            }
            // Floor at 15s to match the UI sliders. Lower values
            // force-close real protocols (TLS, long-poll HTTP, idle
            // WebSockets) on every flush and were previously only
            // rejected at zero — a hand-edited `config.json` could
            // still set 1 and silently break every connection.
            if self.drive_idle_timeout_secs < 15 {
                return Err(ConfigError::Invalid(
                    "drive_idle_timeout_secs must be at least 15".into(),
                ));
            }
            // The id is concatenated unsanitised into Drive filenames and
            // the `name contains '...'` query, so reject anything that
            // could break the wire format or query string.
            let cid = self.drive_client_id.trim();
            if !cid.is_empty()
                && (cid.len() > 32
                    || !cid
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            {
                return Err(ConfigError::Invalid(
                    "drive_client_id must be <=32 chars, ASCII alphanumeric / '-' / '_'".into(),
                ));
            }
            // Folder name shows up inside a single-quoted Drive query; the
            // helper escapes \\ and ', but a stray newline could still
            // throw the query off. Disallow control chars defensively.
            if self
                .drive_folder_name
                .chars()
                .any(|c| c.is_control() || c == '\r' || c == '\n')
            {
                return Err(ConfigError::Invalid(
                    "drive_folder_name must not contain control characters".into(),
                ));
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
            "google_drive" => Ok(Mode::GoogleDrive),
            other => Err(ConfigError::Invalid(format!(
                "unknown mode '{}' (expected 'apps_script', 'google_only', 'full', or 'google_drive')",
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
        cfg.validate()
            .expect("google_only must validate without script_id / auth_key");
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
    fn parses_google_drive_without_apps_script_fields() {
        let s = r#"{
            "mode": "google_drive",
            "drive_credentials_path": "credentials.json"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.mode_kind().unwrap(), Mode::GoogleDrive);
        assert_eq!(cfg.drive_folder_name, "MHRV-Drive");
        assert_eq!(cfg.drive_poll_ms, 500);
        assert_eq!(cfg.drive_flush_ms, 300);
        assert_eq!(cfg.drive_idle_timeout_secs, 300);
    }

    #[test]
    fn rejects_google_drive_idle_timeout_below_floor() {
        // Validator floor is 15s — below it a hand-edited config could
        // set 1 and force-close every session on each flush. Verify both
        // 0 and a low-but-positive value are rejected, and exactly 15
        // is accepted.
        let mk = |idle: u64| {
            format!(
                "{{\"mode\":\"google_drive\",\"drive_credentials_path\":\"c.json\",\"drive_idle_timeout_secs\":{}}}",
                idle
            )
        };
        for bad in [0u64, 1, 14] {
            let cfg: Config = serde_json::from_str(&mk(bad)).unwrap();
            assert!(
                cfg.validate().is_err(),
                "drive_idle_timeout_secs = {} should reject",
                bad
            );
        }
        let cfg: Config = serde_json::from_str(&mk(15)).unwrap();
        cfg.validate().expect("15s should be accepted");
    }

    #[test]
    fn rejects_google_drive_client_id_with_special_chars() {
        let s = r#"{
            "mode": "google_drive",
            "drive_credentials_path": "credentials.json",
            "drive_client_id": "bad client id"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_google_drive_folder_name_with_control_chars() {
        let s = "{\"mode\":\"google_drive\",\"drive_credentials_path\":\"c.json\",\"drive_folder_name\":\"bad\\nname\"}";
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
