use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use mhrv_rs::cert_installer::{install_ca, reconcile_sudo_environment, remove_ca};
use mhrv_rs::config::{Config, FrontingGroup, ScriptId};
use mhrv_rs::data_dir;
use mhrv_rs::domain_fronter::{DomainFronter, DEFAULT_GOOGLE_SNI_POOL};
use mhrv_rs::lan_utils::{detect_lan_ip, is_share_on_lan};
use mhrv_rs::mitm::{MitmCertManager, CA_CERT_FILE};
use mhrv_rs::proxy_server::ProxyServer;
use mhrv_rs::{scan_ips, scan_sni, test_cmd};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const WIN_WIDTH: f32 = 520.0;
const WIN_HEIGHT: f32 = 680.0;
const LOG_MAX: usize = 200;

fn main() -> eframe::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Re-point HOME at the invoking user if this binary was launched
    // under sudo (see cert_installer::reconcile_sudo_environment). Must
    // run before any data_dir / firefox_profile_dirs call.
    reconcile_sudo_environment();
    mhrv_rs::rlimit::raise_nofile_limit_best_effort();

    let shared = Arc::new(Shared::default());
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Cmd>();

    // Load the user's saved form first so we can seed the tracing filter
    // with their saved log level. Otherwise the form's log-level combobox
    // would only ever take effect via env var or after Save → restart, and
    // users on the UI binary (issue #401) reasonably expect the saved
    // config.json `log_level` to apply at boot like it does for the CLI.
    let (form, load_err) = load_form();
    let initial_toast = load_err.map(|e| (e, Instant::now()));

    // Hook tracing events into the Recent log panel. Without this every
    // tracing::info! / debug! / trace! the proxy emits gets swallowed and
    // the panel only ever shows our manual push_log calls, making the log
    // level selector look useless (issue #12 bug 2).
    //
    // Filter precedence (issue #401 fix in v1.8.2):
    //   1. RUST_LOG env var if set                         — explicit override
    //   2. Saved config's `log_level` (passed from form)   — what users mean
    //      when they pick a level in the UI
    //   3. "info,hyper=warn"                               — sensible default
    //
    // Save inside the running UI also installs the new filter via the
    // reload handle (see `LOG_RELOAD` below), so users don't need to
    // restart for a config change to take effect.
    install_ui_tracing(shared.clone(), &form.log_level);

    let shared_bg = shared.clone();
    std::thread::Builder::new()
        .name("mhrv-bg".into())
        .spawn(move || background_thread(shared_bg, cmd_rx))
        .expect("failed to spawn background thread");

    // Pick the renderer. Default is `glow` (OpenGL 2+) because that's
    // what we shipped through v1.0.x and it has the least binary-size
    // overhead. Users on older Windows boxes / RDP sessions / headless
    // VMs that crashed with `egui_glow requires opengl 2.0+` (issue
    // #28) can force the wgpu backend — DX12 on Windows, Vulkan on
    // Linux, Metal on macOS — by setting the env var:
    //
    //     MHRV_RENDERER=wgpu mhrv-rs-ui
    //
    // The launcher scripts (run.bat / run.command / run.sh) honour
    // the same variable and forward it through.
    let use_wgpu = std::env::var("MHRV_RENDERER")
        .map(|v| v.eq_ignore_ascii_case("wgpu"))
        .unwrap_or(false);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([WIN_WIDTH, WIN_HEIGHT])
            .with_min_inner_size([420.0, 400.0])
            .with_title(format!("mhrv-rs {}", VERSION)),
        renderer: if use_wgpu {
            eframe::Renderer::Wgpu
        } else {
            eframe::Renderer::Glow
        },
        ..Default::default()
    };

    eframe::run_native(
        "mhrv-rs",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App {
                shared,
                cmd_tx,
                form,
                last_poll: Instant::now(),
                toast: initial_toast,
            }))
        }),
    )
}

#[derive(Default)]
struct Shared {
    state: Mutex<UiState>,
}

#[derive(Default)]
struct UiState {
    running: bool,
    started_at: Option<Instant>,
    last_stats: Option<mhrv_rs::domain_fronter::StatsSnapshot>,
    last_per_site: Vec<(String, mhrv_rs::domain_fronter::HostStat)>,
    log: VecDeque<String>,
    /// Result + timestamp for transient status banners (auto-hide after 10s).
    ca_trusted: Option<bool>,
    ca_trusted_at: Option<Instant>,
    last_test_ok: Option<bool>,
    last_test_msg: String,
    last_test_msg_at: Option<Instant>,
    /// Per-SNI probe results, populated by Cmd::TestSni / TestAllSni.
    sni_probe: HashMap<String, SniProbeState>,
    /// Most recent result of the Check-for-updates button (issue #15).
    /// `None` = never checked this session. `Some(InFlight)` during the
    /// probe, then the resolved outcome.
    last_update_check: Option<UpdateProbeState>,
    last_update_check_at: Option<Instant>,
    /// Set while a download of a release asset is in flight. `None` when
    /// idle or after a completed download has been acknowledged.
    download_in_progress: bool,
    /// Set while an install-or-remove cert op is in flight. Install and
    /// Remove share this single flag so they can't race each other:
    /// clicking Install → Remove back-to-back would otherwise leave the
    /// final trust/file state dependent on thread scheduling — an
    /// in-flight install could re-trust the CA after Remove had already
    /// deleted it, or vice versa. Both UI buttons disable while this
    /// is set, and both handlers gate-and-flip it.
    cert_op_in_progress: bool,
    /// Set synchronously when `Cmd::Start` is received by the background
    /// thread, cleared synchronously when `Cmd::Stop` completes. Broader
    /// than `running` (which only flips after the MITM manager has
    /// finished loading). Used to block `Remove CA` during the window
    /// between start-click and `running = true` — otherwise a queued
    /// `Cmd::RemoveCa` could delete `ca/` while the server is partway
    /// through loading the keypair into memory.
    proxy_active: bool,
    /// One-line status of the most recent download (Ok(path) or Err(msg)).
    last_download: Option<Result<std::path::PathBuf, String>>,
    last_download_at: Option<Instant>,
}

#[derive(Clone, Debug)]
enum UpdateProbeState {
    InFlight,
    Done(mhrv_rs::update_check::UpdateCheck),
}

#[derive(Clone, Debug)]
enum SniProbeState {
    InFlight,
    Ok(u32),
    Failed(String),
}

enum Cmd {
    Start(Config),
    Stop,
    Test(Config),
    InstallCa,
    RemoveCa,
    CheckCaTrusted,
    PollStats,
    /// Probe a single SNI against the given google_ip. Result is written
    /// into UiState::sni_probe keyed by the SNI string.
    TestSni {
        google_ip: String,
        sni: String,
    },
    /// Probe a batch of SNI names. Results appear in UiState::sni_probe one
    /// by one as each probe finishes.
    TestAllSni {
        google_ip: String,
        snis: Vec<String>,
    },
    /// Hit github.com + the Releases API and compare the running version
    /// to the latest tag. Result is written to UiState::last_update_check.
    /// `route` controls whether the request goes direct or is tunnelled
    /// through our local HTTP proxy (useful when the user's ISP IP has
    /// exhausted GitHub's unauthenticated rate limit).
    CheckUpdate {
        route: mhrv_rs::update_check::Route,
    },
    /// Download a release asset to ~/Downloads. Fires when the user clicks
    /// the "Download update" button after a successful CheckUpdate surfaces
    /// an UpdateAvailable with a matching platform asset.
    DownloadUpdate {
        route: mhrv_rs::update_check::Route,
        url: String,
        name: String,
    },
}

struct App {
    shared: Arc<Shared>,
    cmd_tx: Sender<Cmd>,
    form: FormState,
    last_poll: Instant,
    toast: Option<(String, Instant)>,
}

#[derive(Clone)]
struct FormState {
    /// `"apps_script"` (default), `"direct"`, or `"full"`. Controls
    /// whether the Apps Script relay is wired up at all. In `direct`,
    /// the form tolerates an empty script_id / auth_key.
    /// On load we normalize the legacy `"google_only"` string to
    /// `"direct"` so the next save rewrites the on-disk config.
    mode: String,
    script_id: String,
    auth_key: String,
    google_ip: String,
    front_domain: String,
    listen_host: String,
    listen_port: String,
    socks5_port: String,
    log_level: String,
    verify_ssl: bool,
    upstream_socks5: String,
    parallel_relay: u8,
    show_auth_key: bool,
    /// SNI rotation pool entries. Each item has a sni name + a checkbox
    /// flag indicating whether it's in the active rotation.
    sni_pool: Vec<SniRow>,
    /// Text field buffer for the "+ add custom SNI" input at the bottom of
    /// the SNI editor window.
    sni_custom_input: String,
    /// Whether the floating SNI editor window is open.
    sni_editor_open: bool,
    /// Whether the Recent log panel is shown. User toggles with a checkbox.
    show_log: bool,
    fetch_ips_from_api: bool,
    max_ips_to_scan: usize,
    scan_batch_size: usize,
    google_ip_validation: bool,
    normalize_x_graphql: bool,
    youtube_via_relay: bool,
    /// See `config::Config::relay_url_patterns` for semantics + defaults.
    /// No UI control; round-tripped so a hand-edited list survives Save.
    relay_url_patterns: Vec<String>,
    /// See `config::Config::sabr_strip` for trade-off + when to flip.
    /// No UI control; round-tripped so a hand-edited `false` survives Save.
    sabr_strip: bool,
    passthrough_hosts: Vec<String>,
    /// Round-tripped from config.json so the UI's save path doesn't
    /// drop the user's setting. Not currently exposed as a UI control;
    /// users edit `block_quic` directly in `config.json` (Issue #213).
    block_quic: bool,
    /// Round-tripped from config.json and exposed beside QUIC blocking.
    /// Default true to push WebRTC apps toward TCP TURN instead of slow
    /// UDP ICE retries.
    block_stun: bool,
    /// Round-tripped from config.json. Not exposed as a UI control —
    /// users edit `disable_padding` directly when needed (Issue #391).
    /// Default false (padding active).
    disable_padding: bool,
    /// Round-tripped from config.json. Not exposed as a UI control —
    /// users edit `force_http1` directly when needed. Default false
    /// (HTTP/2 multiplexing on the relay leg active).
    force_http1: bool,
    /// Round-tripped from config.json. Not exposed in the UI form yet —
    /// the bypass-DoH default is the right answer for almost everyone
    /// (DoH already encrypts, the tunnel was just adding latency), so
    /// this is a config-only opt-out. See config.rs `tunnel_doh`.
    tunnel_doh: bool,
    /// User-supplied DoH hostnames added to the built-in default list,
    /// round-tripped from config.json. See config.rs `bypass_doh_hosts`.
    bypass_doh_hosts: Vec<String>,
    /// PR #763: when true, immediately reject browser DoH CONNECTs so the
    /// browser falls back to system DNS (tun2proxy virtual DNS — instant).
    /// Round-tripped from config.json. Desktop UI doesn't expose a toggle
    /// yet — Android does. See config.rs `block_doh`.
    block_doh: bool,
    /// Multi-edge fronting groups. Round-tripped from config.json so
    /// the UI's Save doesn't drop the user's hand-edited groups —
    /// there is no UI editor for these yet, only file-edited config.
    /// See config.rs `fronting_groups`.
    fronting_groups: Vec<FrontingGroup>,
    /// Auto-blacklist tuning + per-batch timeout. Config-only knobs (no UI
    /// fields yet — power-user file edit). Round-tripped through FormState
    /// so Save preserves the user's hand-edited values. See config.rs
    /// `auto_blacklist_*` and `request_timeout_secs`.
    auto_blacklist_strikes: u32,
    auto_blacklist_window_secs: u64,
    auto_blacklist_cooldown_secs: u64,
    request_timeout_secs: u64,
    /// Optional second-hop exit node for CF-anti-bot bypass (chatgpt.com /
    /// claude.ai / grok.com / x.com). Config-only — no UI editor yet.
    /// See `assets/exit_node/` for the generic exit-node handler.
    exit_node: mhrv_rs::config::ExitNodeConfig,
}

#[derive(Clone, Debug)]
struct SniRow {
    name: String,
    enabled: bool,
}

fn load_form() -> (FormState, Option<String>) {
    // Try the user-data config first, then the cwd fallback. Report WHY load
    // fails so the user isn't silently shown a blank form (issue: user reports
    // 'settings saved to file but not loaded back'). Without this signal the
    // failure is invisible — `.ok()` swallows it and the form looks fresh.
    let path = data_dir::config_path();
    let cwd = PathBuf::from("config.json");

    let (existing, load_err): (Option<Config>, Option<String>) = if path.exists() {
        tracing::info!("config: attempting load from {}", path.display());
        match Config::load(&path) {
            Ok(c) => {
                tracing::info!("config: loaded OK from {}", path.display());
                (Some(c), None)
            }
            Err(e) => {
                let msg = format!("Config at {} failed to load: {}", path.display(), e);
                tracing::warn!("{}", msg);
                (None, Some(msg))
            }
        }
    } else if cwd.exists() {
        tracing::info!("config: attempting fallback load from {}", cwd.display());
        match Config::load(&cwd) {
            Ok(c) => (Some(c), None),
            Err(e) => {
                let msg = format!("Config at {} failed to load: {}", cwd.display(), e);
                tracing::warn!("{}", msg);
                (None, Some(msg))
            }
        }
    } else {
        tracing::info!(
            "config: no config found at {} — starting with defaults",
            path.display()
        );
        (None, None)
    };
    let form = if let Some(c) = existing {
        let sid = match &c.script_id {
            Some(ScriptId::One(s)) => s.clone(),
            Some(ScriptId::Many(v)) => v.join("\n"),
            None => match &c.script_ids {
                Some(ScriptId::One(s)) => s.clone(),
                Some(ScriptId::Many(v)) => v.join("\n"),
                None => String::new(),
            },
        };
        let sni_pool = sni_pool_for_form(c.sni_hosts.as_deref(), &c.front_domain);
        // Normalize the legacy `google_only` mode string on load. The
        // backend's `mode_kind()` accepts the alias forever, but storing
        // it as `direct` in the form means the next Save rewrites the
        // on-disk config to the new name — one-way migration, no warn
        // on every startup.
        let mode_normalized = if c.mode == "google_only" {
            "direct".to_string()
        } else {
            c.mode.clone()
        };
        FormState {
            mode: mode_normalized,
            script_id: sid,
            auth_key: c.auth_key,
            google_ip: c.google_ip,
            front_domain: c.front_domain,
            listen_host: c.listen_host,
            listen_port: c.listen_port.to_string(),
            socks5_port: c.socks5_port.map(|p| p.to_string()).unwrap_or_default(),
            log_level: c.log_level,
            verify_ssl: c.verify_ssl,
            upstream_socks5: c.upstream_socks5.unwrap_or_default(),
            parallel_relay: c.parallel_relay,
            show_auth_key: false,
            sni_pool,
            sni_custom_input: String::new(),
            sni_editor_open: false,
            show_log: true,
            fetch_ips_from_api: c.fetch_ips_from_api,
            max_ips_to_scan: c.max_ips_to_scan,
            google_ip_validation: c.google_ip_validation,
            scan_batch_size: c.scan_batch_size,
            normalize_x_graphql: c.normalize_x_graphql,
            youtube_via_relay: c.youtube_via_relay,
            relay_url_patterns: c.relay_url_patterns.clone(),
            sabr_strip: c.sabr_strip,
            passthrough_hosts: c.passthrough_hosts.clone(),
            block_quic: c.block_quic,
            block_stun: c.block_stun,
            disable_padding: c.disable_padding,
            force_http1: c.force_http1,
            tunnel_doh: c.tunnel_doh,
            bypass_doh_hosts: c.bypass_doh_hosts.clone(),
            block_doh: c.block_doh,
            fronting_groups: c.fronting_groups.clone(),
            auto_blacklist_strikes: c.auto_blacklist_strikes,
            auto_blacklist_window_secs: c.auto_blacklist_window_secs,
            auto_blacklist_cooldown_secs: c.auto_blacklist_cooldown_secs,
            request_timeout_secs: c.request_timeout_secs,
            exit_node: c.exit_node.clone(),
        }
    } else {
        FormState {
            mode: "apps_script".into(),
            script_id: String::new(),
            auth_key: String::new(),
            google_ip: "216.239.38.120".into(),
            front_domain: "www.google.com".into(),
            listen_host: "127.0.0.1".into(),
            listen_port: "8085".into(),
            socks5_port: "8086".into(),
            log_level: "info".into(),
            verify_ssl: true,
            upstream_socks5: String::new(),
            parallel_relay: 0,
            show_auth_key: false,
            sni_pool: sni_pool_for_form(None, "www.google.com"),
            sni_custom_input: String::new(),
            sni_editor_open: false,
            show_log: true,
            fetch_ips_from_api: false,
            max_ips_to_scan: 100,
            google_ip_validation: true,
            scan_batch_size: 500,
            normalize_x_graphql: false,
            youtube_via_relay: false,
            relay_url_patterns: Vec::new(),
            sabr_strip: false,
            passthrough_hosts: Vec::new(),
            block_quic: true,
            block_stun: true,
            disable_padding: false,
            force_http1: false,
            tunnel_doh: true,
            bypass_doh_hosts: Vec::new(),
            block_doh: true,
            fronting_groups: Vec::new(),
            // Defaults match `default_auto_blacklist_*` and
            // `default_request_timeout_secs` in src/config.rs.
            auto_blacklist_strikes: 3,
            auto_blacklist_window_secs: 30,
            auto_blacklist_cooldown_secs: 120,
            request_timeout_secs: 30,
            exit_node: mhrv_rs::config::ExitNodeConfig::default(),
        }
    };
    (form, load_err)
}

/// Build the initial `sni_pool` list shown in the editor.
///
/// If the user has explicit `sni_hosts` configured, we show exactly those
/// rows (all enabled). Otherwise we show the default Google pool plus any
/// missing entries, all enabled, with the user's `front_domain` first.
fn sni_pool_for_form(user: Option<&[String]>, front_domain: &str) -> Vec<SniRow> {
    let user_clean: Vec<String> = user
        .unwrap_or(&[])
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !user_clean.is_empty() {
        return user_clean
            .into_iter()
            .map(|name| SniRow {
                name,
                enabled: true,
            })
            .collect();
    }
    // Default: primary + the other Google-edge subdomains, primary first,
    // all enabled.
    let primary = front_domain.trim().to_string();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    if !primary.is_empty() {
        seen.insert(primary.clone());
        out.push(SniRow {
            name: primary,
            enabled: true,
        });
    }
    for s in DEFAULT_GOOGLE_SNI_POOL {
        if seen.insert(s.to_string()) {
            out.push(SniRow {
                name: (*s).to_string(),
                enabled: true,
            });
        }
    }
    out
}

impl FormState {
    fn to_config(&self) -> Result<Config, String> {
        // `direct` and the legacy `google_only` alias both run without
        // an Apps Script relay, so neither requires a script_id.
        let is_direct = self.mode == "direct" || self.mode == "google_only";
        if !is_direct {
            if self.script_id.trim().is_empty() {
                return Err("Apps Script ID is required".into());
            }
            if self.auth_key.trim().is_empty() {
                return Err("Auth key is required".into());
            }
        }
        let listen_port: u16 = self
            .listen_port
            .parse()
            .map_err(|_| "HTTP port must be a number".to_string())?;
        let socks5_port: Option<u16> = if self.socks5_port.trim().is_empty() {
            None
        } else {
            Some(
                self.socks5_port
                    .parse()
                    .map_err(|_| "SOCKS5 port must be a number".to_string())?,
            )
        };
        if socks5_port == Some(listen_port) {
            return Err("HTTP and SOCKS5 ports must be different".into());
        }
        let ids: Vec<String> = self
            .script_id
            .split(|c: char| c == '\n' || c == ',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let script_id = if ids.is_empty() {
            None
        } else if ids.len() == 1 {
            Some(ScriptId::One(ids[0].clone()))
        } else {
            Some(ScriptId::Many(ids))
        };
        Ok(Config {
            mode: self.mode.clone(),
            google_ip: self.google_ip.trim().to_string(),
            front_domain: self.front_domain.trim().to_string(),
            script_id,
            script_ids: None,
            auth_key: self.auth_key.clone(),
            listen_host: self.listen_host.trim().to_string(),
            listen_port,
            socks5_port,
            log_level: self.log_level.trim().to_string(),
            verify_ssl: self.verify_ssl,
            hosts: std::collections::HashMap::new(),
            enable_batching: false,
            upstream_socks5: {
                let v = self.upstream_socks5.trim();
                if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                }
            },
            parallel_relay: self.parallel_relay,
            sni_hosts: {
                let active: Vec<String> = self
                    .sni_pool
                    .iter()
                    .filter(|r| r.enabled)
                    .map(|r| r.name.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                // None = "use auto-expansion default", Some(list) = explicit.
                // If the user's pool is empty/all-off we still save as None so
                // the backend falls back to sensible defaults instead of dying
                // on an empty pool.
                if active.is_empty() {
                    None
                } else {
                    Some(active)
                }
            },
            fetch_ips_from_api: self.fetch_ips_from_api,
            max_ips_to_scan: self.max_ips_to_scan,
            google_ip_validation: self.google_ip_validation,
            scan_batch_size: self.scan_batch_size,
            normalize_x_graphql: self.normalize_x_graphql,
            // UI form doesn't expose youtube_via_relay yet — it's a
            // config-only flag for now. Passed through from the loaded
            // config if set, otherwise defaults to false.
            youtube_via_relay: self.youtube_via_relay,
            // Config-only round-trips. Source of truth for both fields
            // is `config::Config` (defaults, gating, trade-offs).
            relay_url_patterns: self.relay_url_patterns.clone(),
            sabr_strip: self.sabr_strip,
            // Similarly config-only for now; round-trips through the
            // file so the UI doesn't drop the user's entries on save.
            passthrough_hosts: self.passthrough_hosts.clone(),
            // Issue #213: block_quic is config-only for now (no UI
            // control yet). Round-trip through the file so save
            // doesn't drop a user-set true.
            block_quic: self.block_quic,
            block_stun: self.block_stun,
            // Issue #391: disable_padding is config-only for now.
            // Round-trip preserves the user's choice.
            disable_padding: self.disable_padding,
            // HTTP/2 multiplexing kill switch. Config-only for now;
            // round-trip preserves the user's choice across Save.
            force_http1: self.force_http1,
            // DoH bypass is enabled-by-default with `tunnel_doh = false`.
            // Round-trip the user's choice (and any extra hostnames they
            // added) so save doesn't drop them.
            tunnel_doh: self.tunnel_doh,
            bypass_doh_hosts: self.bypass_doh_hosts.clone(),
            // PR #763: block_doh defaults to true (rejects browser DoH so
            // tun2proxy's virtual DNS handles name lookups, saving the
            // ~1.5s tunnel round-trip per DNS query). Desktop UI doesn't
            // expose a toggle yet (Android does), so this is a config-only
            // round-trip — we keep whatever the user has in config.json.
            block_doh: self.block_doh,
            // Multi-edge fronting groups: file-edited only for now,
            // round-tripped through the UI so Save doesn't drop them.
            fronting_groups: self.fronting_groups.clone(),
            // PR #448 (Android): adaptive coalesce window. Desktop UI
            // doesn't expose sliders for these yet (Android does), so
            // we pass 0 to keep the compiled defaults (40ms step,
            // 1000ms max). Round-trip planned for the v1.8.x desktop UI
            // batch alongside the system-proxy toggle (#432).
            coalesce_step_ms: 0,
            coalesce_max_ms: 0,
            // Auto-blacklist + batch timeout: config-only knobs (#391,
            // #444, #430). Round-trip through FormState so Save doesn't
            // drop hand-edited values. UI editor planned alongside the
            // v1.8.x desktop UI batch.
            auto_blacklist_strikes: self.auto_blacklist_strikes,
            auto_blacklist_window_secs: self.auto_blacklist_window_secs,
            auto_blacklist_cooldown_secs: self.auto_blacklist_cooldown_secs,
            request_timeout_secs: self.request_timeout_secs,
            // Exit-node config (CF-anti-bot bypass for chatgpt.com / claude.ai
            // / grok.com / x.com). Round-trip through FormState — config-only
            // editing for now, UI editor planned for v1.9.x desktop UI batch.
            exit_node: self.exit_node.clone(),
        })
    }
}

fn save_config(cfg: &Config) -> Result<PathBuf, String> {
    let path = data_dir::config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(&ConfigWire::from(cfg)).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok(path)
}

#[derive(serde::Serialize)]
struct ConfigWire<'a> {
    mode: &'a str,
    google_ip: &'a str,
    front_domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_id: Option<ScriptIdWire<'a>>,
    auth_key: &'a str,
    listen_host: &'a str,
    listen_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    socks5_port: Option<u16>,
    log_level: &'a str,
    verify_ssl: bool,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    hosts: &'a std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_socks5: Option<&'a str>,
    #[serde(skip_serializing_if = "is_zero_u8")]
    parallel_relay: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni_hosts: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "is_false")]
    normalize_x_graphql: bool,
    #[serde(skip_serializing_if = "is_false")]
    youtube_via_relay: bool,
    /// See `config::Config::relay_url_patterns`. Skipped when empty so
    /// the proxy-applied default isn't echoed into config.json.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relay_url_patterns: &'a Vec<String>,
    /// See `config::Config::sabr_strip`. Default `false` (opt-in
    /// after #977); emitted only when explicitly enabled so unchanged
    /// configs stay clean.
    #[serde(skip_serializing_if = "is_false")]
    sabr_strip: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    passthrough_hosts: &'a Vec<String>,
    // IP-scan knobs. These used to be missing from the wire struct, so
    // every Save-config silently dropped them — the user would toggle
    // "fetch from API" on, save, reopen, and find it off again. Add
    // them here and keep them in sync if Config ever grows more.
    #[serde(skip_serializing_if = "is_false")]
    fetch_ips_from_api: bool,
    max_ips_to_scan: usize,
    scan_batch_size: usize,
    google_ip_validation: bool,
    /// Default false (= bypass DoH). Only emitted when explicitly true
    /// so unchanged configs stay clean.
    #[serde(skip_serializing_if = "is_false")]
    tunnel_doh: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bypass_doh_hosts: &'a Vec<String>,
    /// PR #763: default true (= browser DoH rejected, system DNS used).
    /// Skip when matching default to keep unchanged configs clean —
    /// emit only when the user has explicitly disabled the block.
    #[serde(skip_serializing_if = "is_true")]
    block_doh: bool,
    /// Default true. Emit only when the user disables STUN/TURN blocking.
    #[serde(skip_serializing_if = "is_true")]
    block_stun: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fronting_groups: &'a Vec<FrontingGroup>,
    /// Auto-blacklist tuning + batch timeout (#391, #444, #430). Skip
    /// serialization when matching the historical defaults so unchanged
    /// configs stay clean — only emitted when the user has explicitly
    /// tuned them.
    #[serde(skip_serializing_if = "is_default_strikes")]
    auto_blacklist_strikes: u32,
    #[serde(skip_serializing_if = "is_default_window_secs")]
    auto_blacklist_window_secs: u64,
    #[serde(skip_serializing_if = "is_default_cooldown_secs")]
    auto_blacklist_cooldown_secs: u64,
    #[serde(skip_serializing_if = "is_default_timeout_secs")]
    request_timeout_secs: u64,
    /// HTTP/2 multiplexing kill switch. Default false (h2 active); only
    /// emitted on save when the user has explicitly disabled h2, so
    /// unchanged configs stay clean.
    #[serde(skip_serializing_if = "is_false")]
    force_http1: bool,
    /// Exit-node config (CF-anti-bot bypass for chatgpt.com / claude.ai /
    /// grok.com / x.com via exit-node second-hop relay). Skip when fully
    /// default (disabled with no URL/PSK/hosts) so configs without
    /// exit-node setup stay clean. Round-tripped through FormState so
    /// Save preserves user-edited values.
    #[serde(skip_serializing_if = "is_default_exit_node")]
    exit_node: &'a mhrv_rs::config::ExitNodeConfig,
}

fn is_default_strikes(v: &u32) -> bool { *v == 3 }
fn is_default_window_secs(v: &u64) -> bool { *v == 30 }
fn is_default_cooldown_secs(v: &u64) -> bool { *v == 120 }
fn is_default_timeout_secs(v: &u64) -> bool { *v == 30 }
fn is_default_exit_node(en: &&mhrv_rs::config::ExitNodeConfig) -> bool {
    !en.enabled
        && en.relay_url.is_empty()
        && en.psk.is_empty()
        && en.hosts.is_empty()
        && (en.mode.is_empty() || en.mode == "selective")
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum ScriptIdWire<'a> {
    One(&'a str),
    Many(Vec<&'a str>),
}

impl<'a> From<&'a Config> for ConfigWire<'a> {
    fn from(c: &'a Config) -> Self {
        let script_id = c.script_id.as_ref().map(|s| match s {
            ScriptId::One(v) => ScriptIdWire::One(v.as_str()),
            ScriptId::Many(v) => ScriptIdWire::Many(v.iter().map(String::as_str).collect()),
        });
        ConfigWire {
            mode: c.mode.as_str(),
            google_ip: c.google_ip.as_str(),
            front_domain: c.front_domain.as_str(),
            script_id,
            auth_key: c.auth_key.as_str(),
            listen_host: c.listen_host.as_str(),
            listen_port: c.listen_port,
            socks5_port: c.socks5_port,
            log_level: c.log_level.as_str(),
            verify_ssl: c.verify_ssl,
            hosts: &c.hosts,
            upstream_socks5: c.upstream_socks5.as_deref(),
            parallel_relay: c.parallel_relay,
            sni_hosts: c
                .sni_hosts
                .as_ref()
                .map(|v| v.iter().map(String::as_str).collect()),
            normalize_x_graphql: c.normalize_x_graphql,
            youtube_via_relay: c.youtube_via_relay,
            relay_url_patterns: &c.relay_url_patterns,
            sabr_strip: c.sabr_strip,
            passthrough_hosts: &c.passthrough_hosts,
            fetch_ips_from_api: c.fetch_ips_from_api,
            max_ips_to_scan: c.max_ips_to_scan,
            scan_batch_size: c.scan_batch_size,
            google_ip_validation: c.google_ip_validation,
            tunnel_doh: c.tunnel_doh,
            bypass_doh_hosts: &c.bypass_doh_hosts,
            block_doh: c.block_doh,
            block_stun: c.block_stun,
            fronting_groups: &c.fronting_groups,
            auto_blacklist_strikes: c.auto_blacklist_strikes,
            auto_blacklist_window_secs: c.auto_blacklist_window_secs,
            auto_blacklist_cooldown_secs: c.auto_blacklist_cooldown_secs,
            request_timeout_secs: c.request_timeout_secs,
            force_http1: c.force_http1,
            exit_node: &c.exit_node,
        }
    }
}

/// Accent color — same blue used throughout the UI for primary actions.
const ACCENT: egui::Color32 = egui::Color32::from_rgb(70, 120, 180);
const ACCENT_HOVER: egui::Color32 = egui::Color32::from_rgb(90, 145, 205);
const OK_GREEN: egui::Color32 = egui::Color32::from_rgb(80, 180, 100);
const ERR_RED: egui::Color32 = egui::Color32::from_rgb(220, 110, 110);

/// Draw a "section card" — a rounded frame with a faint fill and a small
/// heading above it. Used to visually group related form rows.
fn section(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(6.0);
    ui.label(
        egui::RichText::new(title)
            .size(12.0)
            .color(egui::Color32::from_gray(180))
            .strong(),
    );
    ui.add_space(2.0);
    let frame = egui::Frame::none()
        .fill(egui::Color32::from_rgb(28, 30, 34))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 54, 60)))
        .rounding(6.0)
        .inner_margin(egui::Margin::same(10.0));
    frame.show(ui, body);
}

/// A primary accent-filled button. Used for the headline action in a row
/// (Start / Stop / SNI pool).
fn primary_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(egui::Color32::WHITE)
            .strong(),
    )
    .fill(ACCENT)
    .min_size(egui::vec2(120.0, 28.0))
    .rounding(4.0)
}

/// A compact form row: label on the left (fixed width for vertical alignment),
/// widget on the right filling the remaining space.
fn form_row(
    ui: &mut egui::Ui,
    label: &str,
    hover: Option<&str>,
    widget: impl FnOnce(&mut egui::Ui, egui::Id),
) {
    ui.horizontal(|ui| {
        let resp = ui.add_sized(
            [120.0, 20.0],
            egui::Label::new(egui::RichText::new(label).color(egui::Color32::from_gray(200))),
        );
        let label_id = resp.id;
        if let Some(h) = hover {
            resp.on_hover_text(h);
        }
        widget(ui, label_id);
    });
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if self.last_poll.elapsed() > Duration::from_millis(700) {
            let _ = self.cmd_tx.send(Cmd::PollStats);
            self.last_poll = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(500));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.style_mut().spacing.item_spacing = egui::vec2(8.0, 6.0);

            // Wrap the whole central panel in a vertical scroll area so the
            // form + stats + log panel stay accessible on short screens
            // (~13" laptops at default scaling). Nested scroll areas still
            // work fine within this outer scroller.
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {

            // ── Header row: project name, version (→ github), status pill ─
            let running = self.shared.state.lock().unwrap().running;
            ui.horizontal(|ui| {
                ui.hyperlink_to(
                    egui::RichText::new("mhrv-rs").size(20.0).strong(),
                    "https://github.com/therealaleph/MasterHttpRelayVPN-RUST",
                );
                ui.hyperlink_to(
                    egui::RichText::new(format!("v{}", VERSION))
                        .color(egui::Color32::from_gray(140))
                        .monospace(),
                    format!(
                        "https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases/tag/v{}",
                        VERSION
                    ),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (fill, dot, label) = if running {
                        (
                            egui::Color32::from_rgb(30, 60, 40),
                            OK_GREEN,
                            "running",
                        )
                    } else {
                        (
                            egui::Color32::from_rgb(60, 35, 35),
                            ERR_RED,
                            "stopped",
                        )
                    };
                    egui::Frame::none()
                        .fill(fill)
                        .rounding(12.0)
                        .inner_margin(egui::Margin::symmetric(10.0, 3.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(8.0, 8.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(rect.center(), 4.0, dot);
                                ui.label(
                                    egui::RichText::new(label)
                                        .color(dot)
                                        .monospace()
                                        .strong(),
                                );
                            });
                        });
                });
            });

            ui.add_space(2.0);

            // ── Section: Mode ─────────────────────────────────────────────
            // Surfacing the mode at the top of the form because it changes
            // which of the sections below are actually used. `direct` runs
            // without the Apps Script relay (Google edge + any configured
            // fronting_groups via the SNI-rewrite tunnel only) — useful as
            // a bootstrap to deploy Code.gs, or as a standalone mode for
            // users who only need access to fronting-group targets.
            section(ui, "Mode", |ui| {
                form_row(ui, "Mode", Some(
                    "apps_script: DPI bypass via Apps Script relay (needs cert).\n\
                     full: tunnel ALL traffic through Apps Script + tunnel node (no cert needed).\n\
                     direct: SNI-rewrite tunnel only — no relay (Google edge + any fronting_groups)."
                ), |ui, _label_id| {
                    egui::ComboBox::from_id_source("mode")
                        .selected_text(match self.form.mode.as_str() {
                            "direct" | "google_only" => "Direct (no relay)",
                            "full" => "Full tunnel (no cert)",
                            _ => "Apps Script (MITM)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.form.mode,
                                "apps_script".into(),
                                "Apps Script (MITM)",
                            );
                            ui.selectable_value(
                                &mut self.form.mode,
                                "full".into(),
                                "Full tunnel (no cert)",
                            );
                            ui.selectable_value(
                                &mut self.form.mode,
                                "direct".into(),
                                "Direct (no relay)",
                            );
                        });
                });
                if self.form.mode == "direct" || self.form.mode == "google_only" {
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.small(egui::RichText::new(
                            "Direct mode — SNI-rewrite tunnel only. Reach the Google edge (and any configured fronting_groups) without an Apps Script relay.",
                        )
                        .color(OK_GREEN));
                    });
                }
                if self.form.mode == "full" {
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.small(egui::RichText::new(
                            "Full tunnel — all traffic tunneled end-to-end via Apps Script + remote tunnel node. No certificate needed.",
                        )
                        .color(OK_GREEN));
                    });
                }
            });

            let direct_mode = self.form.mode == "direct" || self.form.mode == "google_only";

            // ── Section: Apps Script relay ────────────────────────────────
            section(ui, "Apps Script relay", |ui| {
                ui.add_enabled_ui(!direct_mode, |ui| {
                    form_row(ui, "Deployment IDs", Some(
                        "One deployment ID per line. Proxy round-robins between them and sidelines \
                         any ID that hits its daily quota for 10 minutes before retrying."
                    ), |ui, label_id| {
                        ui.add(egui::TextEdit::multiline(&mut self.form.script_id)
                            .hint_text("one deployment ID per line")
                            .desired_width(f32::INFINITY)
                            .desired_rows(3))
                        .labelled_by(label_id);
                    });

                    let id_count = self.form.script_id
                        .split(|c: char| c == '\n' || c == ',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .count();
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        if id_count <= 1 {
                            ui.small(egui::RichText::new("Tip: add more IDs for round-robin with auto-failover.")
                                .color(egui::Color32::from_gray(140)));
                        } else {
                            ui.small(egui::RichText::new(format!(
                                "{} IDs — round-robin with auto-failover on quota.", id_count
                            )).color(OK_GREEN));
                        }
                    });

                    form_row(ui, "Auth key", Some(
                        "Same value as AUTH_KEY inside your Code.gs."
                    ), |ui, label_id| {
                        ui.add(egui::TextEdit::singleline(&mut self.form.auth_key)
                            .password(!self.form.show_auth_key)
                            .desired_width(f32::INFINITY))
                        .labelled_by(label_id);
                    });
                });
            });

            // ── Section: Network ──────────────────────────────────────────
            section(ui, "Network", |ui| {
                form_row(ui, "Google IP", None, |ui, label_id| {
                    ui.add(egui::TextEdit::singleline(&mut self.form.google_ip)
                        .desired_width(f32::INFINITY))
                    .labelled_by(label_id);
                });
                ui.horizontal(|ui| {
                    ui.add_space(120.0 + 8.0);
                    if ui.small_button("scan IPs")
                        .on_hover_text(
                            "Probe known Google frontend IPs; report which are reachable \
                             (results go to the log panel)."
                        )
                        .clicked()
                    {
                        if let Ok(cfg) = self.form.to_config() {
                            let _ = self.cmd_tx.send(Cmd::Test(cfg.clone()));
                            self.toast = Some((
                                "Scan started — check the Recent log below.".into(),
                                Instant::now(),
                            ));
                        }
                    }
                    let active_sni = self.form.sni_pool.iter().filter(|r| r.enabled).count();
                    let total_sni = self.form.sni_pool.len();
                    let sni_btn = egui::Button::new(
                        egui::RichText::new(format!("SNI pool… ({}/{})", active_sni, total_sni))
                            .color(egui::Color32::WHITE),
                    )
                    .fill(ACCENT)
                    .rounding(4.0);
                    if ui.add(sni_btn)
                        .on_hover_text(
                            "Open the SNI rotation pool editor. Test which front-domain \
                             names get through your network's DPI."
                        )
                        .clicked()
                    {
                        self.form.sni_editor_open = true;
                    }
                });

                form_row(ui, "Front domain", None, |ui, label_id| {
                    ui.add(egui::TextEdit::singleline(&mut self.form.front_domain)
                        .desired_width(f32::INFINITY))
                    .labelled_by(label_id);
                });

                // Network sharing: phones, tablets, other laptops on the
                // same Wi-Fi can use this proxy when the bind address is
                // 0.0.0.0 instead of 127.0.0.1. We expose this as a
                // single-checkbox UI rather than the raw `listen_host`
                // text field — typing `0.0.0.0` from memory is enough of
                // a friction point that almost no one does it. Power
                // users with a custom bind IP (specific NIC) can still
                // edit `listen_host` directly in `config.json`; we
                // detect that case and show a "Custom bind" badge so
                // the checkbox doesn't silently overwrite their setting
                // on the next Save.
                //
                // Snapshot the relevant flags before entering form_row's
                // closure — we need to mutate `self.form.listen_host`
                // inside the closure when the checkbox toggles, so we
                // can't hold a borrow on it through the closure.
                let listen_host_snapshot = self.form.listen_host.trim().to_string();
                let listen_port_snapshot = self.form.listen_port.trim().to_string();
                let socks5_port_snapshot = self.form.socks5_port.trim().to_string();
                let was_share_on_lan = is_share_on_lan(&listen_host_snapshot);
                let lower_snapshot = listen_host_snapshot.to_ascii_lowercase();
                let is_custom_bind = !listen_host_snapshot.is_empty()
                    && !was_share_on_lan
                    && lower_snapshot != "127.0.0.1"
                    && lower_snapshot != "localhost";
                let mut new_listen_host: Option<String> = None;
                form_row(ui, "Network", Some(
                    "By default the proxy is reachable only from this computer. \
                     Turn this on to let phones, tablets, and other laptops on the \
                     same Wi-Fi (or a hotspot you're sharing) use it too. The \
                     other devices then point their HTTP / SOCKS5 proxy at the \
                     LAN IP shown below. Make sure your firewall lets in the proxy \
                     port — macOS pops up a Firewall prompt the first time."
                ), |ui, _label_id| {
                    if is_custom_bind {
                        // The user manually wrote a specific bind IP —
                        // don't let the checkbox stomp on it. Show what
                        // they have and tell them to edit config.json
                        // if they want to change it.
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(format!(
                                "Custom bind: {}",
                                listen_host_snapshot
                            )).color(egui::Color32::from_rgb(220, 180, 100)));
                            ui.small("Edit `listen_host` in config.json to change.");
                        });
                    } else {
                        let mut share = was_share_on_lan;
                        if ui.checkbox(&mut share, "Share with other devices on my Wi-Fi / network").changed() {
                            new_listen_host = Some(if share {
                                "0.0.0.0".to_string()
                            } else {
                                "127.0.0.1".to_string()
                            });
                        }
                        if share {
                            // detect_lan_ip() opens a UDP socket and
                            // asks the kernel which interface a packet
                            // to a public IP would use. Cheap (no
                            // syscall does network I/O) and accurate
                            // (it's the same selection any outbound
                            // connection would make).
                            match detect_lan_ip() {
                                Some(ip) => {
                                    let port = if listen_port_snapshot.is_empty() {
                                        "8085"
                                    } else {
                                        listen_port_snapshot.as_str()
                                    };
                                    let socks_port = if socks5_port_snapshot.is_empty() {
                                        "8086"
                                    } else {
                                        socks5_port_snapshot.as_str()
                                    };
                                    ui.small(egui::RichText::new(format!(
                                        "Other devices: HTTP {}:{}  ·  SOCKS5 {}:{}",
                                        ip, port, ip, socks_port,
                                    )).color(egui::Color32::from_rgb(120, 200, 140)));
                                }
                                None => {
                                    ui.small(egui::RichText::new(
                                        "Couldn't detect your LAN IP. Find it in System Settings \
                                         → Network → Wi-Fi → Details (macOS) or `ipconfig` (Windows)."
                                    ).color(egui::Color32::from_rgb(220, 180, 100)));
                                }
                            }
                        }
                    }
                });
                if let Some(updated) = new_listen_host {
                    self.form.listen_host = updated;
                }

                ui.horizontal(|ui| {
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::Label::new(egui::RichText::new("Ports")
                            .color(egui::Color32::from_gray(200))),
                    );
                    let http_label = ui.label(egui::RichText::new("HTTP").small());
                    ui.add(egui::TextEdit::singleline(&mut self.form.listen_port)
                        .desired_width(70.0))
                    .labelled_by(http_label.id);
                    ui.add_space(10.0);
                    let socks_label = ui.label(egui::RichText::new("SOCKS5").small());
                    ui.add(egui::TextEdit::singleline(&mut self.form.socks5_port)
                        .desired_width(70.0))
                    .labelled_by(socks_label.id);
                });
            });

            // ── Section: Advanced (collapsed by default) ──────────────────
            ui.add_space(6.0);
            egui::CollapsingHeader::new(
                egui::RichText::new("Advanced")
                    .size(12.0)
                    .color(egui::Color32::from_gray(180))
                    .strong(),
            )
            .default_open(false)
            .show(ui, |ui| {
                let frame = egui::Frame::none()
                    .fill(egui::Color32::from_rgb(28, 30, 34))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(50, 54, 60)))
                    .rounding(6.0)
                    .inner_margin(egui::Margin::same(10.0));
                frame.show(ui, |ui| {
                    form_row(ui, "Upstream SOCKS5", Some(
                        "Optional. host:port of a local xray / v2ray / sing-box SOCKS5 inbound. \
                         When set, non-HTTP / raw-TCP traffic (Telegram MTProto, IMAP, SSH, …) \
                         is chained through it instead of direct. HTTP/HTTPS still go through \
                         the Apps Script relay."
                    ), |ui, label_id| {
                        ui.add(egui::TextEdit::singleline(&mut self.form.upstream_socks5)
                            .hint_text("empty = direct; 127.0.0.1:50529 for local xray")
                            .desired_width(f32::INFINITY))
                        .labelled_by(label_id);
                    });

                    form_row(ui, "Parallel dispatch", Some(
                        "Fire N Apps Script IDs in parallel per request and take the first \
                         response. 0/1 = off. 2-3 kills long-tail latency at N× quota cost. \
                         Only effective with multiple IDs configured."
                    ), |ui, _label_id| {
                        ui.add(egui::DragValue::new(&mut self.form.parallel_relay)
                            .speed(1)
                            .range(0..=8));
                    });

                    form_row(ui, "Log level", None, |ui, _label_id| {
                        egui::ComboBox::from_id_source("loglevel")
                            .selected_text(&self.form.log_level)
                            .show_ui(ui, |ui| {
                                for lvl in ["warn", "info", "debug", "trace"] {
                                    ui.selectable_value(&mut self.form.log_level, lvl.into(), lvl);
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.verify_ssl, "Verify TLS server certificate (recommended)");
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.show_auth_key, "Show auth key");
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.normalize_x_graphql, "Normalize X/Twitter GraphQL URLs")
                            .on_hover_text(
                                "Trim the `features` / `fieldToggles` query params from x.com/i/api/graphql/… \
                                 requests before relaying. Massively improves cache hit rate when browsing \
                                 Twitter/X. Off by default — some endpoints may reject trimmed requests. \
                                 Credit: seramo_ir + Persian Python community (issue #16).",
                            );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(
                            &mut self.form.youtube_via_relay,
                            "Send YouTube through relay (no SNI rewrite)",
                        )
                        .on_hover_text(
                            "YouTube normally uses the same direct Google-edge tunnel as google.com (TLS SNI is \
                             the front domain, not youtube.com). That can trigger restricted mode or sign-out \
                             prompts. Enable this to route youtube.com / youtu.be / ytimg.com through the Apps \
                             Script relay instead — slower for video, but the visible SNI matches the site.",
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.block_quic, "Block QUIC (UDP/443)")
                            .on_hover_text(
                                "Drop QUIC (UDP port 443) so browsers fall back to TCP/HTTPS. \
                                 QUIC over the TCP-based tunnel causes TCP-over-TCP meltdown \
                                 (<1 Mbps). Browsers detect the drop and switch to TCP within seconds. \
                                 Issue #213, #793.",
                            );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(120.0 + 8.0);
                        ui.checkbox(&mut self.form.block_stun, "Block STUN/TURN UDP")
                            .on_hover_text(
                                "Drop WebRTC STUN/TURN UDP ports 3478, 5349, and 19302 so apps \
                                 such as Meet, Discord, and WhatsApp move to TCP TURN instead of \
                                 waiting on UDP ICE retries.",
                            );
                    });
                });
            });

            // ── Bottom of form: Save + config-path hint ───────────────────
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add(primary_button("Save config")).clicked() {
                    match self.form.to_config().and_then(|c| save_config(&c)) {
                        Ok(p) => {
                            // Apply the new log level live so users don't have to
                            // restart for the combobox to take effect (#401).
                            apply_log_level(&self.form.log_level);
                            self.toast = Some((format!("Saved to {}", p.display()), Instant::now()));
                        }
                        Err(e) => self.toast = Some((format!("Save failed: {}", e), Instant::now())),
                    }
                }
                ui.small(egui::RichText::new(format!("→ {}", data_dir::config_path().display()))
                    .color(egui::Color32::from_gray(130)));
            });

            // Floating SNI editor window. Rendered here so it's inside the
            // same egui context but visually pops out with its own title bar.
            self.show_sni_editor(ctx);

            ui.add_space(8.0);

            // ── Status + stats card ────────────────────────────────────────
            let (running, started_at, stats, ca_trusted, last_test_msg, per_site) = {
                let s = self.shared.state.lock().unwrap();
                (
                    s.running,
                    s.started_at,
                    s.last_stats.clone(),
                    s.ca_trusted,
                    s.last_test_msg.clone(),
                    s.last_per_site.clone(),
                )
            };

            let status_title = if running {
                let up = started_at.map(|t| t.elapsed()).unwrap_or_default();
                format!("Traffic  ·  uptime {}", fmt_duration(up))
            } else {
                "Traffic  ·  (not running)".to_string()
            };
            section(ui, &status_title, |ui| {
                if let Some(s) = &stats {
                    // Compact two-column layout so 7 metrics fit in ~4 rows
                    // instead of a tall vertical strip.
                    let mut rows: Vec<(&str, String)> = vec![
                        ("relay calls", s.relay_calls.to_string()),
                        ("failures", s.relay_failures.to_string()),
                        ("coalesced", s.coalesced.to_string()),
                        (
                            "cache hits",
                            format!(
                                "{} / {}  ({:.0}%)",
                                s.cache_hits,
                                s.cache_hits + s.cache_misses,
                                s.hit_rate()
                            ),
                        ),
                        ("cache size", format!("{} KB", s.cache_bytes / 1024)),
                        ("bytes relayed", fmt_bytes(s.bytes_relayed)),
                        (
                            "active scripts",
                            format!(
                                "{} / {}",
                                s.total_scripts - s.blacklisted_scripts,
                                s.total_scripts
                            ),
                        ),
                    ];
                    // Forwarder rows only appear once the path filter
                    // has fired at least once — otherwise the typical
                    // (no-pattern-hit / non-AppsScript) user sees an
                    // empty pair of "0" rows that adds noise without
                    // signal. `err` is fast-path-miss count; combine
                    // with `relay_failures` to gauge end-to-end health.
                    if s.forwarder_calls + s.forwarder_errors > 0 {
                        rows.push((
                            "fwd calls",
                            format!(
                                "{} (err {})",
                                s.forwarder_calls, s.forwarder_errors
                            ),
                        ));
                        rows.push(("fwd bytes", fmt_bytes(s.forwarder_bytes)));
                    }
                    egui::Grid::new("stats")
                        .num_columns(4)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for chunk in rows.chunks(2) {
                                for (label, value) in chunk.iter() {
                                    ui.add_sized(
                                        [110.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(*label)
                                                .color(egui::Color32::from_gray(150)),
                                        ),
                                    );
                                    ui.add_sized(
                                        [140.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(value).monospace(),
                                        ),
                                    );
                                }
                                // Pad the final short row so grid columns stay aligned.
                                if chunk.len() == 1 {
                                    ui.label("");
                                    ui.label("");
                                }
                                ui.end_row();
                            }
                        });
                } else {
                    ui.label(
                        egui::RichText::new("No traffic yet — click Start and send a request.")
                            .color(egui::Color32::from_gray(150))
                            .italics(),
                    );
                }
            });

            // ── Usage today (estimated) — daily budget tracker ───────────────
            // Client-side estimate from our own atomic counters. Counts only
            // successful relay calls this process saw since 00:00 UTC. Google's
            // actual quota bucket is per-Apps-Script-project and per-Google
            // account — if multiple devices share the same deployment, each
            // client only sees its own share. We link to the Google dashboard
            // for the authoritative number.
            if let Some(s) = &stats {
                ui.add_space(2.0);
                section(ui, "Usage today (estimated)", |ui| {
                    // Free-tier Apps Script UrlFetchApp quota. Workspace /
                    // paid accounts get 100k but most users are on free.
                    const FREE_QUOTA_PER_DAY: u64 = 20_000;
                    let pct = if FREE_QUOTA_PER_DAY > 0 {
                        (s.today_calls as f64 / FREE_QUOTA_PER_DAY as f64) * 100.0
                    } else { 0.0 };
                    let reset = s.today_reset_secs;
                    let reset_str = format!(
                        "{}h {}m",
                        reset / 3600,
                        (reset / 60) % 60,
                    );
                    let rows: Vec<(&str, String)> = vec![
                        (
                            "calls today",
                            format!(
                                "{} / {}  ({:.1}%)",
                                s.today_calls, FREE_QUOTA_PER_DAY, pct
                            ),
                        ),
                        ("bytes today", fmt_bytes(s.today_bytes)),
                        ("PT day", s.today_key.clone()),
                        ("resets in", reset_str),
                    ];
                    egui::Grid::new("usage_today")
                        .num_columns(4)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            for chunk in rows.chunks(2) {
                                for (label, value) in chunk.iter() {
                                    ui.add_sized(
                                        [110.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(*label)
                                                .color(egui::Color32::from_gray(150)),
                                        ),
                                    );
                                    ui.add_sized(
                                        [140.0, 18.0],
                                        egui::Label::new(
                                            egui::RichText::new(value).monospace(),
                                        ),
                                    );
                                }
                                if chunk.len() == 1 {
                                    ui.label("");
                                    ui.label("");
                                }
                                ui.end_row();
                            }
                        });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.hyperlink_to(
                            egui::RichText::new("View quota on Google →"),
                            "https://script.google.com/home/usage",
                        );
                        ui.label(
                            egui::RichText::new(
                                "  (authoritative — estimate is what this device relayed)",
                            )
                            .color(egui::Color32::from_gray(130))
                            .italics()
                            .small(),
                        );
                    });
                });
            }

            if !per_site.is_empty() {
                ui.add_space(2.0);
                egui::CollapsingHeader::new(format!("Per-site ({} hosts)", per_site.len()))
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(140.0)
                            .show(ui, |ui| {
                                egui::Grid::new("per_site")
                                    .num_columns(5)
                                    .spacing([8.0, 2.0])
                                    .striped(true)
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("host").strong());
                                        ui.label(egui::RichText::new("req").strong());
                                        ui.label(egui::RichText::new("hit%").strong());
                                        ui.label(egui::RichText::new("bytes").strong());
                                        ui.label(egui::RichText::new("avg ms").strong());
                                        ui.end_row();
                                        for (host, st) in per_site.iter().take(60) {
                                            let hit_pct = if st.requests > 0 {
                                                (st.cache_hits as f64 / st.requests as f64) * 100.0
                                            } else { 0.0 };
                                            ui.label(egui::RichText::new(host).monospace());
                                            ui.label(egui::RichText::new(st.requests.to_string()).monospace());
                                            ui.label(egui::RichText::new(format!("{:.0}%", hit_pct)).monospace());
                                            ui.label(egui::RichText::new(fmt_bytes(st.bytes)).monospace());
                                            ui.label(egui::RichText::new(format!("{:.0}", st.avg_latency_ms())).monospace());
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
            }

            ui.add_space(8.0);

            // ── Primary action: Start / Stop is the headline; others smaller ──
            ui.horizontal(|ui| {
                if !running {
                    let btn = egui::Button::new(
                        egui::RichText::new("▶  Start").color(egui::Color32::WHITE).strong(),
                    )
                    .fill(OK_GREEN)
                    .min_size(egui::vec2(120.0, 32.0))
                    .rounding(4.0);
                    if ui.add(btn).clicked() {
                        match self.form.to_config() {
                            Ok(cfg) => {
                                let _ = self.cmd_tx.send(Cmd::Start(cfg));
                            }
                            Err(e) => {
                                self.toast = Some((format!("Cannot start: {}", e), Instant::now()));
                            }
                        }
                    }
                } else {
                    let btn = egui::Button::new(
                        egui::RichText::new("■  Stop").color(egui::Color32::WHITE).strong(),
                    )
                    .fill(ERR_RED)
                    .min_size(egui::vec2(120.0, 32.0))
                    .rounding(4.0);
                    if ui.add(btn).clicked() {
                        let _ = self.cmd_tx.send(Cmd::Stop);
                    }
                }

                if ui.add(
                    egui::Button::new("Test relay")
                        .min_size(egui::vec2(0.0, 32.0))
                        .rounding(4.0),
                ).on_hover_text("Send one request through the Apps Script relay end-to-end and report the result.").clicked() {
                    match self.form.to_config() {
                        Ok(cfg) => {
                            let _ = self.cmd_tx.send(Cmd::Test(cfg));
                        }
                        Err(e) => {
                            self.toast = Some((format!("Cannot test: {}", e), Instant::now()));
                        }
                    }
                }
            });

            // Secondary actions — smaller, grouped together on their own line.
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                // Install CA and Remove CA share a single in-flight flag
                // so back-to-back clicks can't race — an in-flight
                // install would otherwise re-trust the CA after Remove
                // deleted it (or vice versa). Both buttons disable when
                // either op is running.
                let (cert_op_in_flight, proxy_active) = {
                    let s = self.shared.state.lock().unwrap();
                    (s.cert_op_in_progress, s.proxy_active)
                };

                let install_hover = if cert_op_in_flight {
                    "A cert install/remove is already in progress."
                } else {
                    "Install the MITM CA into the OS trust store (and NSS if certutil \
                     is available)."
                };
                ui.add_enabled_ui(!cert_op_in_flight, |ui| {
                    if ui
                        .small_button("Install CA")
                        .on_hover_text(install_hover)
                        .clicked()
                    {
                        let _ = self.cmd_tx.send(Cmd::InstallCa);
                    }
                });

                let remove_hover = if proxy_active || running {
                    "Stop the proxy first — the CA keypair is held in memory by the \
                     running MITM engine, and removing it now would break HTTPS for \
                     every site until restart."
                } else if cert_op_in_flight {
                    "A cert install/remove is already in progress."
                } else {
                    "Remove the MITM CA from the OS trust store (verified by name) \
                     and delete the on-disk ca/ directory. NSS cleanup (Firefox/Chrome) \
                     is best-effort and logs a hint if certutil is missing or a browser \
                     has the DB locked. A fresh CA is generated the next time you start \
                     the proxy. Your config.json and the Apps Script deployment are NOT \
                     touched — no need to redeploy Code.gs."
                };
                ui.add_enabled_ui(!proxy_active && !running && !cert_op_in_flight, |ui| {
                    if ui.small_button("Remove CA")
                        .on_hover_text(remove_hover)
                        .clicked()
                    {
                        let _ = self.cmd_tx.send(Cmd::RemoveCa);
                    }
                });
                if ui.small_button("Check CA").clicked() {
                    let _ = self.cmd_tx.send(Cmd::CheckCaTrusted);
                }
                if ui.small_button("Check for updates")
                    .on_hover_text(
                        "Ask GitHub's Releases API for the latest tag and compare against this \
                         running version. When the proxy is running, the request is tunnelled \
                         through it — so GitHub sees an Apps Script IP instead of your ISP IP \
                         (different rate-limit bucket, and works even if GitHub is blocked on \
                         your network). No background polling — only fires when you click."
                    )
                    .clicked()
                {
                    let route = self.update_check_route();
                    let _ = self.cmd_tx.send(Cmd::CheckUpdate { route });
                }
                let _ = ACCENT_HOVER; // silence unused const warning if it occurs
            });

            // ── Transient status line ─────────────────────────────────────
            // One compact line at most. Everything auto-hides after 10s so
            // stale messages don't keep pushing the log panel off-screen.
            // Priority: update-check in flight > fresh test msg > fresh CA
            // result > update-check result. Old/expired entries are dropped.
            const TRANSIENT_TTL: Duration = Duration::from_secs(10);
            let (test_msg_fresh, ca_trusted_fresh, update_check_fresh, download_fresh) = {
                let s = self.shared.state.lock().unwrap();
                (
                    s.last_test_msg_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                    s.ca_trusted_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                    s.last_update_check_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                    s.last_download_at
                        .map_or(false, |t| t.elapsed() < TRANSIENT_TTL),
                )
            };

            let mut shown_any = false;
            let update_is_inflight = matches!(
                self.shared.state.lock().unwrap().last_update_check,
                Some(UpdateProbeState::InFlight)
            );
            if update_is_inflight {
                ui.small(
                    egui::RichText::new("Checking for updates…")
                        .color(egui::Color32::GRAY),
                );
                shown_any = true;
            } else if update_check_fresh {
                let done = self.shared.state.lock().unwrap().last_update_check.clone();
                if let Some(UpdateProbeState::Done(r)) = done {
                    use mhrv_rs::update_check::UpdateCheck;
                    let color = match &r {
                        UpdateCheck::UpToDate { .. } => OK_GREEN,
                        UpdateCheck::UpdateAvailable { .. } => {
                            egui::Color32::from_rgb(220, 170, 80)
                        }
                        _ => ERR_RED,
                    };
                    ui.horizontal(|ui| {
                        ui.small(egui::RichText::new(r.summary()).color(color));
                        if let UpdateCheck::UpdateAvailable {
                            release_url, asset, ..
                        } = &r
                        {
                            ui.hyperlink_to("open release", release_url);
                            if let Some(a) = asset {
                                let dl_in_flight = self.shared.state.lock().unwrap().download_in_progress;
                                if dl_in_flight {
                                    ui.small(
                                        egui::RichText::new("downloading…")
                                            .color(egui::Color32::GRAY),
                                    );
                                } else {
                                    let btn = egui::Button::new(
                                        egui::RichText::new(format!(
                                            "⤓ Download {} ({:.1} MB)",
                                            a.name,
                                            a.size_bytes as f64 / 1_048_576.0
                                        ))
                                        .color(egui::Color32::WHITE),
                                    )
                                    .fill(ACCENT)
                                    .rounding(4.0);
                                    if ui.add(btn).clicked() {
                                        let route = self.update_check_route();
                                        let _ = self.cmd_tx.send(Cmd::DownloadUpdate {
                                            route,
                                            url: a.download_url.clone(),
                                            name: a.name.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    });
                    shown_any = true;
                }
            } else if test_msg_fresh && !last_test_msg.is_empty() {
                let color = if last_test_msg.starts_with("Test passed") {
                    OK_GREEN
                } else {
                    ERR_RED
                };
                ui.small(egui::RichText::new(last_test_msg).color(color));
                shown_any = true;
            } else if download_fresh {
                let dl = self.shared.state.lock().unwrap().last_download.clone();
                match dl {
                    Some(Ok(path)) => {
                        ui.horizontal(|ui| {
                            ui.small(
                                egui::RichText::new(format!("Downloaded → {}", path.display()))
                                    .color(OK_GREEN),
                            );
                            if ui.small_button("show in folder").clicked() {
                                reveal_in_file_manager(&path);
                            }
                        });
                    }
                    Some(Err(msg)) => {
                        ui.small(
                            egui::RichText::new(format!("Download failed: {}", msg))
                                .color(ERR_RED),
                        );
                    }
                    None => {
                        ui.small(
                            egui::RichText::new("Downloading…")
                                .color(egui::Color32::GRAY),
                        );
                    }
                }
                shown_any = true;
            } else if ca_trusted_fresh {
                match ca_trusted {
                    Some(true) => {
                        ui.small(
                            egui::RichText::new("CA appears trusted on this machine.")
                                .color(OK_GREEN),
                        );
                    }
                    Some(false) => {
                        ui.small(
                            egui::RichText::new(
                                "CA is NOT trusted in the system store. Click Install CA.",
                            )
                            .color(ERR_RED),
                        );
                    }
                    None => {}
                }
                shown_any = true;
            }
            // Reserve a line of space even when empty so the log below doesn't
            // jump when a transient message appears / disappears.
            if !shown_any {
                ui.small(" ");
            }

            ui.add_space(4.0);

            // ── Recent log ────────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Recent log").strong());
                ui.checkbox(&mut self.form.show_log, "show");
                if ui.small_button("save…")
                    .on_hover_text(
                        "Write every line in the log panel to a timestamped file in the \
                         user-data dir. Useful for filing bug reports."
                    )
                    .clicked()
                {
                    let log = self.shared.state.lock().unwrap().log.clone();
                    let fname = format!(
                        "log-{}.txt",
                        time::OffsetDateTime::now_utc()
                            .format(&time::macros::format_description!(
                                "[year][month][day]-[hour][minute][second]"
                            ))
                            .unwrap_or_default(),
                    );
                    let path = data_dir::data_dir().join(&fname);
                    let body: String = log.iter().cloned().collect::<Vec<_>>().join("\n");
                    match std::fs::write(&path, body) {
                        Ok(_) => self.toast = Some((
                            format!("Log saved to {}", path.display()),
                            Instant::now(),
                        )),
                        Err(e) => self.toast = Some((
                            format!("Log save failed: {}", e),
                            Instant::now(),
                        )),
                    }
                }
                if ui.small_button("clear").clicked() {
                    self.shared.state.lock().unwrap().log.clear();
                }
            });
            if self.form.show_log {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(22, 23, 26))
                    .stroke(egui::Stroke::new(
                        1.0,
                        egui::Color32::from_rgb(45, 48, 52),
                    ))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::same(6.0))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(220.0)
                            .min_scrolled_height(220.0)
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                let log = self.shared.state.lock().unwrap().log.clone();
                                if log.is_empty() {
                                    ui.small(
                                        egui::RichText::new("(empty — run some traffic or click Test)")
                                            .color(egui::Color32::from_gray(120))
                                            .italics(),
                                    );
                                }
                                for line in log.iter() {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(line).monospace().size(11.0),
                                        )
                                        .wrap(),
                                    );
                                }
                            });
                    });
            }

            // Transient toast at the bottom. Config-load failures stick for
            // 30s instead of 5 because they explain why the form looks empty.
            if let Some((msg, t)) = &self.toast {
                let ttl = if msg.contains("failed to load") {
                    Duration::from_secs(30)
                } else {
                    Duration::from_secs(5)
                };
                if t.elapsed() < ttl {
                    ui.add_space(4.0);
                    ui.colored_label(egui::Color32::from_rgb(200, 170, 80), msg);
                } else {
                    self.toast = None;
                }
            }
                }); // end ScrollArea
        });
    }
}

impl App {
    /// Pick the route for an update-check or download request: if the
    /// proxy is running and we have a local HTTP listen_port, tunnel
    /// through it (GitHub sees Apps Script's IP instead of the user's
    /// rate-limited ISP IP). Otherwise go direct.
    fn update_check_route(&self) -> mhrv_rs::update_check::Route {
        let running = self.shared.state.lock().unwrap().running;
        if running {
            if let Ok(port) = self.form.listen_port.trim().parse::<u16>() {
                let host = if self.form.listen_host.trim().is_empty() {
                    "127.0.0.1".to_string()
                } else {
                    self.form.listen_host.trim().to_string()
                };
                return mhrv_rs::update_check::Route::Proxy { host, port };
            }
        }
        mhrv_rs::update_check::Route::Direct
    }

    /// Floating editor window for the SNI rotation pool. Opens from the
    /// **SNI pool…** button in the main form. The list is live-editable
    /// (reorder / toggle / add / remove); changes only persist when the user
    /// hits **Save config** in the main window. Probe results are cached in
    /// `UiState::sni_probe` so they survive opening and closing the editor.
    fn show_sni_editor(&mut self, ctx: &egui::Context) {
        if !self.form.sni_editor_open {
            return;
        }
        let mut keep_open = true;
        egui::Window::new("SNI rotation pool")
            .open(&mut keep_open)
            .resizable(true)
            .default_size(egui::vec2(520.0, 420.0))
            .min_width(460.0)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Which SNI names to rotate through when opening TLS connections \
                         to your Google IP. Some names may be locally blocked (Iran has \
                         dropped mail.google.com at times, for example); use the Test \
                         buttons to check — TLS handshake + HTTP HEAD against the \
                         configured google_ip, per name.",
                    )
                    .small(),
                );
                ui.add_space(4.0);

                // Action row.
                let google_ip = self.form.google_ip.trim().to_string();
                let probe_map = self.shared.state.lock().unwrap().sni_probe.clone();
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Test all").on_hover_text(
                        "Probe every SNI in the list against the configured google_ip in parallel."
                    ).clicked() {
                        let snis: Vec<String> = self
                            .form
                            .sni_pool
                            .iter()
                            .map(|r| r.name.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if !snis.is_empty() && !google_ip.is_empty() {
                            let _ = self.cmd_tx.send(Cmd::TestAllSni {
                                google_ip: google_ip.clone(),
                                snis,
                            });
                        }
                    }
                    if ui
                        .button("Keep working only")
                        .on_hover_text("Uncheck every SNI that didn't pass the last probe.")
                        .clicked()
                    {
                        for row in &mut self.form.sni_pool {
                            let ok = matches!(probe_map.get(&row.name), Some(SniProbeState::Ok(_)));
                            row.enabled = ok;
                        }
                    }
                    if ui.button("Enable all").clicked() {
                        for row in &mut self.form.sni_pool {
                            row.enabled = true;
                        }
                    }
                    if ui.button("Clear status").clicked() {
                        self.shared.state.lock().unwrap().sni_probe.clear();
                    }
                    if ui
                        .button("Reset to defaults")
                        .on_hover_text(
                            "Replace the list with the built-in Google SNI pool. Custom entries \
                         are dropped.",
                        )
                        .clicked()
                    {
                        self.form.sni_pool = DEFAULT_GOOGLE_SNI_POOL
                            .iter()
                            .map(|s| SniRow {
                                name: (*s).to_string(),
                                enabled: true,
                            })
                            .collect();
                        self.shared.state.lock().unwrap().sni_probe.clear();
                    }
                });
                ui.separator();

                // Main list — one horizontal row per SNI, explicit widths so
                // the domain text field gets the room it needs.
                let mut to_remove: Option<usize> = None;
                let mut test_name: Option<String> = None;
                const STATUS_W: f32 = 150.0;
                const NAME_W: f32 = 230.0;
                egui::ScrollArea::vertical()
                    .max_height(280.0)
                    .show(ui, |ui| {
                        for (i, row) in self.form.sni_pool.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut row.enabled, "");
                                let sni_label = ui.add_sized(
                                    [0.0, 0.0],
                                    egui::Label::new(
                                        egui::RichText::new(format!("SNI name {}", i))
                                            .color(egui::Color32::TRANSPARENT),
                                    ),
                                );
                                ui.add(
                                    egui::TextEdit::singleline(&mut row.name)
                                        .desired_width(NAME_W)
                                        .font(egui::TextStyle::Monospace),
                                )
                                .labelled_by(sni_label.id);
                                let status_txt = match probe_map.get(&row.name) {
                                    Some(SniProbeState::Ok(ms)) => {
                                        egui::RichText::new(format!("ok  {} ms", ms))
                                            .color(egui::Color32::from_rgb(80, 180, 100))
                                            .monospace()
                                    }
                                    Some(SniProbeState::Failed(e)) => {
                                        let short = if e.len() > 22 { &e[..22] } else { e };
                                        egui::RichText::new(format!("fail {}", short))
                                            .color(egui::Color32::from_rgb(220, 110, 110))
                                            .monospace()
                                    }
                                    Some(SniProbeState::InFlight) => {
                                        egui::RichText::new("testing…")
                                            .color(egui::Color32::GRAY)
                                            .monospace()
                                    }
                                    None => egui::RichText::new("untested")
                                        .color(egui::Color32::GRAY)
                                        .monospace(),
                                };
                                ui.add_sized(
                                    [STATUS_W, 18.0],
                                    egui::Label::new(status_txt).truncate(),
                                );
                                if ui.small_button("Test").clicked() {
                                    test_name = Some(row.name.clone());
                                }
                                if ui
                                    .small_button("remove")
                                    .on_hover_text("Remove this row")
                                    .clicked()
                                {
                                    to_remove = Some(i);
                                }
                            });
                        }
                    });

                if let Some(name) = test_name {
                    let name = name.trim().to_string();
                    if !name.is_empty() && !google_ip.is_empty() {
                        let _ = self.cmd_tx.send(Cmd::TestSni {
                            google_ip: google_ip.clone(),
                            sni: name,
                        });
                    }
                }
                if let Some(i) = to_remove {
                    self.form.sni_pool.remove(i);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    let custom_label = ui.add_sized(
                        [0.0, 0.0],
                        egui::Label::new(
                            egui::RichText::new("Custom SNI")
                                .color(egui::Color32::TRANSPARENT),
                        ),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.form.sni_custom_input)
                            .hint_text("add a custom SNI (e.g. translate.google.com)")
                            .desired_width(280.0),
                    )
                    .labelled_by(custom_label.id);
                    let add_clicked = ui.button("+ Add").clicked();
                    if add_clicked {
                        let new_name = self.form.sni_custom_input.trim().to_string();
                        if !new_name.is_empty()
                            && !self.form.sni_pool.iter().any(|r| r.name == new_name)
                        {
                            self.form.sni_pool.push(SniRow {
                                name: new_name.clone(),
                                enabled: true,
                            });
                            self.form.sni_custom_input.clear();
                            // Auto-probe the freshly added name so the user gets
                            // immediate feedback instead of a silent "untested"
                            // row. Needs a non-empty google_ip to have meaning.
                            if !google_ip.is_empty() {
                                let _ = self.cmd_tx.send(Cmd::TestSni {
                                    google_ip: google_ip.clone(),
                                    sni: new_name,
                                });
                            }
                        }
                    }
                });

                ui.add_space(6.0);
                ui.separator();
                ui.small(
                    "Changes take effect on the next Start of the proxy. \
                     Don't forget to press Save config in the main window to persist.",
                );
            });
        self.form.sni_editor_open = keep_open;
    }
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn fmt_bytes(b: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = K * K;
    const G: u64 = M * K;
    if b >= G {
        format!("{:.2} GB", b as f64 / G as f64)
    } else if b >= M {
        format!("{:.2} MB", b as f64 / M as f64)
    } else if b >= K {
        format!("{:.1} KB", b as f64 / K as f64)
    } else {
        format!("{} B", b)
    }
}

// ---------- Background thread: owns the tokio runtime + proxy lifecycle ----------

fn background_thread(shared: Arc<Shared>, rx: Receiver<Cmd>) {
    let rt = Runtime::new().expect("failed to create tokio runtime");

    let mut active: Option<(
        JoinHandle<()>,
        Arc<AsyncMutex<Option<Arc<DomainFronter>>>>,
        tokio::sync::oneshot::Sender<()>,
    )> = None;

    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Cmd::PollStats) => {
                if let Some((_, fronter_slot, _)) = &active {
                    let slot = fronter_slot.clone();
                    let shared = shared.clone();
                    rt.spawn(async move {
                        let f = slot.lock().await;
                        if let Some(fronter) = f.as_ref() {
                            let s = fronter.snapshot_stats();
                            let per_site = fronter.snapshot_per_site();
                            let mut st = shared.state.lock().unwrap();
                            st.last_stats = Some(s);
                            st.last_per_site = per_site;
                        }
                    });
                }
            }
            Ok(Cmd::Start(cfg)) => {
                if active.is_some() {
                    push_log(&shared, "[ui] already running");
                    continue;
                }
                push_log(&shared, "[ui] starting proxy...");
                // Flip proxy_active synchronously so a `Remove CA` click
                // queued in the same frame as Start is rejected before
                // the MITM manager begins loading.
                shared.state.lock().unwrap().proxy_active = true;
                let shared2 = shared.clone();
                let fronter_slot: Arc<AsyncMutex<Option<Arc<DomainFronter>>>> =
                    Arc::new(AsyncMutex::new(None));
                let fronter_slot2 = fronter_slot.clone();

                let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

                let handle = rt.spawn(async move {
                    let base = data_dir::data_dir();
                    let mitm = match MitmCertManager::new_in(&base) {
                        Ok(m) => m,
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] MITM init failed: {}", e));
                            let mut s = shared2.state.lock().unwrap();
                            s.running = false;
                            s.proxy_active = false;
                            return;
                        }
                    };
                    let mitm = Arc::new(AsyncMutex::new(mitm));
                    let server = match ProxyServer::new(&cfg, mitm) {
                        Ok(s) => s,
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] proxy build failed: {}", e));
                            let mut st = shared2.state.lock().unwrap();
                            st.running = false;
                            st.proxy_active = false;
                            return;
                        }
                    };
                    // `fronter()` is `None` in direct mode — the
                    // status panel's relay stats simply show no data in that case.
                    *fronter_slot2.lock().await = server.fronter();
                    {
                        let mut s = shared2.state.lock().unwrap();
                        s.running = true;
                        s.started_at = Some(Instant::now());
                    }
                    push_log(
                        &shared2,
                        &format!(
                            "[ui] listening HTTP {}:{} SOCKS5 {}:{}",
                            cfg.listen_host,
                            cfg.listen_port,
                            cfg.listen_host,
                            cfg.socks5_port.unwrap_or(cfg.listen_port + 1)
                        ),
                    );

                    if let Err(e) = server.run(shutdown_rx).await {
                        push_log(&shared2, &format!("[ui] proxy error: {}", e));
                    }

                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.running = false;
                        st.started_at = None;
                        // Self-exit path (e.g. bind error after startup,
                        // or normal shutdown without Cmd::Stop). The
                        // Stop handler clears this too — either is fine.
                        st.proxy_active = false;
                    }
                    push_log(&shared2, "[ui] proxy stopped");
                });

                active = Some((handle, fronter_slot, shutdown_tx));
            }

            Ok(Cmd::Stop) => {
                if let Some((mut handle, _, shutdown_tx)) = active.take() {
                    push_log(&shared, "[ui] stop requested");
                    let _ = shutdown_tx.send(());

                    // Give the proxy 2 seconds to shut down gracefully
                    rt.block_on(async {
                        tokio::select! {
                            _ = &mut handle => {
                                push_log(&shared, "[ui] proxy stopped gracefully");
                            }
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                                handle.abort();
                                let _ = handle.await;
                                push_log(&shared, "[ui] shutdown timeout, forced abort");
                            }
                        }
                    });

                    let mut st = shared.state.lock().unwrap();
                    st.running = false;
                    st.started_at = None;
                    st.proxy_active = false;
                }
            }

            Ok(Cmd::Test(cfg)) => {
                let shared2 = shared.clone();
                // Short-circuit modes where `test_cmd::run` deliberately
                // refuses (full mode, direct mode). Those return false
                // even when the proxy is healthy, which surfaced as
                // "Test failed" + alarming red status — see #665. Show
                // a friendly notice instead and skip the test path.
                let mode_kind = cfg.mode_kind().ok();
                let mode_explainer = match mode_kind {
                    Some(mhrv_rs::config::Mode::Full) => Some(
                        "Test Relay is wired only for apps_script mode. \
                         In full mode the data plane is the tunnel-node — \
                         to verify it end-to-end, start the proxy and load \
                         https://whatismyipaddress.com in your browser \
                         via 127.0.0.1:8085. The IP shown should be your \
                         tunnel-node's VPS IP. Tracking a real Full-mode \
                         test in #160."
                    ),
                    Some(mhrv_rs::config::Mode::Direct) => Some(
                        "Test Relay is wired only for apps_script mode. \
                         In direct mode there is no Apps Script relay — \
                         every request goes through the SNI-rewrite tunnel \
                         straight to Google's edge. Verify by loading \
                         https://www.google.com via the proxy."
                    ),
                    _ => None,
                };
                if let Some(msg) = mode_explainer {
                    {
                        let mut st = shared.state.lock().unwrap();
                        st.last_test_ok = None;
                        st.last_test_msg = msg.into();
                        st.last_test_msg_at = Some(Instant::now());
                    }
                    push_log(&shared, &format!("[ui] test skipped: {}", msg));
                    continue;
                }
                push_log(&shared, "[ui] running test...");
                rt.spawn(async move {
                    let ok = test_cmd::run(&cfg).await;
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.last_test_ok = Some(ok);
                        st.last_test_msg = if ok {
                            "Test passed — relay is working.".into()
                        } else {
                            "Test failed — see Recent log below for details.".into()
                        };
                        st.last_test_msg_at = Some(Instant::now());
                    }
                    push_log(
                        &shared2,
                        &format!("[ui] test result: {}", if ok { "pass" } else { "fail" }),
                    );
                    // Also run ip scan on demand (cheap).
                    let _ = scan_ips::run(&cfg).await;
                });
            }
            Ok(Cmd::InstallCa) => {
                // Share the cert-op flag with Remove CA so the two
                // can't race. Gate and flip before spawning; the worker
                // clears on exit.
                {
                    let mut st = shared.state.lock().unwrap();
                    if st.cert_op_in_progress {
                        push_log(
                            &shared,
                            "[ui] cert op already in progress — ignoring duplicate install",
                        );
                        continue;
                    }
                    st.cert_op_in_progress = true;
                }
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    push_log(&shared2, "[ui] installing CA...");
                    let base = data_dir::data_dir();
                    let result = (|| -> Result<(), String> {
                        if let Err(e) = MitmCertManager::new_in(&base) {
                            return Err(format!("CA init failed: {}", e));
                        }
                        let ca = base.join(CA_CERT_FILE);
                        install_ca(&ca).map_err(|e| format!("CA install failed: {}", e))
                    })();
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.cert_op_in_progress = false;
                        if result.is_ok() {
                            st.ca_trusted = Some(true);
                            st.ca_trusted_at = Some(Instant::now());
                        }
                    }
                    match result {
                        Ok(()) => push_log(&shared2, "[ui] CA install ok"),
                        Err(msg) => {
                            push_log(&shared2, &format!("[ui] {}", msg));
                            push_log(&shared2, "[ui] hint: run the terminal binary with sudo/admin: mhrv-rs --install-cert");
                        }
                    }
                });
            }
            Ok(Cmd::RemoveCa) => {
                // Authoritative proxy-active guard: the UI button is
                // disabled when proxy_active/running is set, but a
                // Cmd::RemoveCa may already be queued by the time the
                // Start handler flips the flag. `active` is owned by
                // this thread so its state is the real source of truth
                // — reject removal any time a proxy handle is alive,
                // whether it's still starting or fully running.
                if active.is_some() {
                    push_log(
                        &shared,
                        "[ui] cannot remove CA: proxy is running or starting — stop it first",
                    );
                    continue;
                }
                // Shared cert-op gate: covers Install CA too, so back-
                // to-back Install → Remove clicks can't race. The
                // button is already disabled while this is set, but a
                // queued command can still arrive here.
                {
                    let mut st = shared.state.lock().unwrap();
                    if st.cert_op_in_progress {
                        push_log(
                            &shared,
                            "[ui] cert op already in progress — ignoring duplicate remove",
                        );
                        continue;
                    }
                    st.cert_op_in_progress = true;
                }
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    push_log(&shared2, "[ui] removing CA (trust store + files)...");
                    let base = data_dir::data_dir();
                    let result = remove_ca(&base);
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.cert_op_in_progress = false;
                        if result.is_ok() {
                            st.ca_trusted = Some(false);
                            st.ca_trusted_at = Some(Instant::now());
                        }
                    }
                    match result {
                        Ok(outcome) => {
                            push_log(&shared2, &format!("[ui] {}", outcome.summary()));
                            push_log(
                                &shared2,
                                "[ui] config.json and Apps Script deployment untouched",
                            );
                        }
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] CA remove failed: {}", e));
                            push_log(&shared2, "[ui] hint: run the terminal binary with sudo/admin: mhrv-rs --remove-cert");
                        }
                    }
                });
            }
            Ok(Cmd::TestSni { google_ip, sni }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    st.sni_probe.insert(sni.clone(), SniProbeState::InFlight);
                }
                rt.spawn(async move {
                    let result = scan_sni::probe_one(&google_ip, &sni).await;
                    let state = match result.latency_ms {
                        Some(ms) => SniProbeState::Ok(ms),
                        None => {
                            SniProbeState::Failed(result.error.unwrap_or_else(|| "failed".into()))
                        }
                    };
                    shared2.state.lock().unwrap().sni_probe.insert(sni, state);
                });
            }
            Ok(Cmd::TestAllSni { google_ip, snis }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    for s in &snis {
                        st.sni_probe.insert(s.clone(), SniProbeState::InFlight);
                    }
                }
                rt.spawn(async move {
                    let results = scan_sni::probe_all(&google_ip, snis).await;
                    let mut st = shared2.state.lock().unwrap();
                    for (sni, r) in results {
                        let state = match r.latency_ms {
                            Some(ms) => SniProbeState::Ok(ms),
                            None => {
                                SniProbeState::Failed(r.error.unwrap_or_else(|| "failed".into()))
                            }
                        };
                        st.sni_probe.insert(sni, state);
                    }
                });
            }
            Ok(Cmd::CheckCaTrusted) => {
                let shared2 = shared.clone();
                std::thread::spawn(move || {
                    let base = data_dir::data_dir();
                    let ca = base.join(CA_CERT_FILE);
                    let file_exists = ca.exists();
                    // Probe the trust store by name — independent of
                    // whether the on-disk ca.crt happens to be there.
                    // The file and the trust-store entry can be out of
                    // sync (e.g. after a partial removal), and that
                    // mismatch is exactly what Check CA must surface.
                    let trusted = mhrv_rs::cert_installer::is_ca_trusted_by_name();
                    push_log(
                        &shared2,
                        &format!(
                            "[ui] check CA: file={} trust_store={}",
                            if file_exists { "present" } else { "missing" },
                            if trusted { "trusted" } else { "not trusted" },
                        ),
                    );
                    let mut st = shared2.state.lock().unwrap();
                    st.ca_trusted = Some(trusted);
                    st.ca_trusted_at = Some(Instant::now());
                });
            }
            Ok(Cmd::CheckUpdate { route }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    st.last_update_check = Some(UpdateProbeState::InFlight);
                    st.last_update_check_at = Some(Instant::now());
                }
                rt.spawn(async move {
                    let result = mhrv_rs::update_check::check(route).await;
                    push_log(
                        &shared2,
                        &format!("[ui] update check: {}", result.summary()),
                    );
                    {
                        let mut st = shared2.state.lock().unwrap();
                        st.last_update_check = Some(UpdateProbeState::Done(result));
                        st.last_update_check_at = Some(Instant::now());
                    }
                });
            }
            Ok(Cmd::DownloadUpdate { route, url, name }) => {
                let shared2 = shared.clone();
                {
                    let mut st = shared2.state.lock().unwrap();
                    st.download_in_progress = true;
                    st.last_download = None;
                }
                push_log(&shared, &format!("[ui] downloading {}", name));
                rt.spawn(async move {
                    let dir = downloads_dir();
                    let out = dir.join(&name);
                    let result = mhrv_rs::update_check::download_asset(route, &url, &out).await;
                    let mut st = shared2.state.lock().unwrap();
                    st.download_in_progress = false;
                    st.last_download_at = Some(Instant::now());
                    match result {
                        Ok(bytes) => {
                            push_log(
                                &shared2,
                                &format!(
                                    "[ui] download ok: {} ({} bytes) -> {}",
                                    name,
                                    bytes,
                                    out.display()
                                ),
                            );
                            st.last_download = Some(Ok(out));
                        }
                        Err(e) => {
                            push_log(&shared2, &format!("[ui] download failed: {}", e));
                            st.last_download = Some(Err(e));
                        }
                    }
                });
            }
            Err(_) => {}
        }

        // Clean up finished task.
        if let Some((handle, _, _)) = &active {
            if handle.is_finished() {
                active = None;
                shared.state.lock().unwrap().running = false;
                shared.state.lock().unwrap().started_at = None;
            }
        }
    }
}

/// Install a tracing subscriber that mirrors every log event into the UI's
/// Recent log panel.
///
/// Filter precedence (issue #401, v1.8.2):
///   1. `RUST_LOG` env var, if set
///   2. The saved form's `log_level` (passed in from the loaded config)
///   3. `info,hyper=warn` as a sensible default
///
/// The constructed filter is wrapped in a `reload::Layer` and the handle
/// is stashed in `LOG_RELOAD` so that a Save inside the running UI can
/// reinstall the filter without a restart. See `apply_log_level`.
fn install_ui_tracing(shared: Arc<Shared>, config_level: &str) {
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{reload, EnvFilter};

    /// A MakeWriter that pushes each line into the shared log panel.
    struct UiLogWriter {
        shared: Arc<Shared>,
    }

    struct UiWriterInst {
        shared: Arc<Shared>,
        buf: Vec<u8>,
    }

    impl<'a> MakeWriter<'a> for UiLogWriter {
        type Writer = UiWriterInst;
        fn make_writer(&'a self) -> Self::Writer {
            UiWriterInst {
                shared: self.shared.clone(),
                buf: Vec::with_capacity(128),
            }
        }
    }

    impl std::io::Write for UiWriterInst {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.buf.is_empty() {
                return Ok(());
            }
            let text = String::from_utf8_lossy(&self.buf).trim_end().to_string();
            self.buf.clear();
            // Split on newlines in case multiple events got buffered.
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }
                let mut s = self.shared.state.lock().unwrap();
                s.log.push_back(line.to_string());
                while s.log.len() > LOG_MAX {
                    s.log.pop_front();
                }
            }
            Ok(())
        }
    }

    impl Drop for UiWriterInst {
        fn drop(&mut self) {
            let _ = std::io::Write::flush(self);
        }
    }

    // RUST_LOG > config.log_level > "info,hyper=warn"
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let trimmed = config_level.trim();
        if trimmed.is_empty() {
            EnvFilter::new("info,hyper=warn")
        } else {
            EnvFilter::try_new(trimmed).unwrap_or_else(|_| EnvFilter::new("info,hyper=warn"))
        }
    });

    let (filter_layer, reload_handle) = reload::Layer::new(filter);
    if LOG_RELOAD.set(reload_handle).is_err() {
        // Already initialized — install_ui_tracing got called twice. Bail
        // silently rather than panic; the existing subscriber stays live.
        return;
    }

    let writer = UiLogWriter { shared };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(writer);

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}

/// Reload handle for the UI's tracing EnvFilter — populated once at startup
/// by `install_ui_tracing`. `apply_log_level` uses it to swap in a new
/// filter when the user clicks Save with a different log level (#401).
static LOG_RELOAD: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<
        tracing_subscriber::EnvFilter,
        tracing_subscriber::Registry,
    >,
> = std::sync::OnceLock::new();

/// Reinstall the tracing filter at runtime. Called from the Save handler
/// so the user's new `log_level` takes effect without a restart. RUST_LOG
/// still wins if it was set at process start — explicit override beats
/// config in both directions.
fn apply_log_level(level: &str) {
    use tracing_subscriber::EnvFilter;
    let Some(handle) = LOG_RELOAD.get() else {
        return;
    };
    if std::env::var_os("RUST_LOG").is_some() {
        // RUST_LOG was set explicitly at boot — don't silently override.
        return;
    }
    let trimmed = level.trim();
    let new = if trimmed.is_empty() {
        EnvFilter::new("info,hyper=warn")
    } else {
        match EnvFilter::try_new(trimmed) {
            Ok(f) => f,
            Err(_) => return,
        }
    };
    let _ = handle.modify(|f| *f = new);
}

/// Where we drop downloaded release assets. Prefer the OS user Downloads
/// dir (via the directories crate that's already in our tree), fall back
/// to the user-data dir for platforms that don't expose one (edge case).
fn downloads_dir() -> std::path::PathBuf {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
        .unwrap_or_else(data_dir::data_dir)
}

/// Open the OS file manager with the given file highlighted/selected.
/// Best-effort: fires the platform-specific command and swallows errors.
fn reveal_in_file_manager(p: &std::path::Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg("-R").arg(p).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let arg = format!("/select,\"{}\"", p.display());
        let _ = std::process::Command::new("explorer").arg(arg).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // No universal "select this file" primitive on Linux; just open
        // the containing folder.
        if let Some(parent) = p.parent() {
            let _ = std::process::Command::new("xdg-open").arg(parent).spawn();
        }
    }
}

fn push_log(shared: &Shared, msg: &str) {
    let line = format!(
        "{}  {}",
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Iso8601::DEFAULT)
            .unwrap_or_default(),
        msg
    );
    let mut s = shared.state.lock().unwrap();
    s.log.push_back(line);
    while s.log.len() > LOG_MAX {
        s.log.pop_front();
    }
}
