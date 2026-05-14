use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
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
/// `Direct` runs without any Apps Script relay: only the SNI-rewrite tunnel
/// is active, targeting the Google edge by default plus any user-configured
/// `fronting_groups`. Originally introduced as a `script.google.com`
/// bootstrap (when this mode could only reach Google's edge it was named
/// `google_only`), now generalized to any user-configured CDN edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    AppsScript,
    /// Was named `GoogleOnly` before v1.9 and the introduction of
    /// `fronting_groups`. The string `"google_only"` is still accepted
    /// in `mode_kind()` as a deprecated alias so existing configs do
    /// not break.
    Direct,
    Full,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::AppsScript => "apps_script",
            Mode::Direct => "direct",
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
    /// Adaptive batch coalesce: after each op arrives, wait this many ms
    /// for more ops before firing the batch. Resets on every arrival.
    /// 0 = use compiled default (10ms).
    #[serde(default)]
    pub coalesce_step_ms: u16,
    /// Hard cap on total coalesce wait (ms). 0 = use compiled default (1000ms).
    #[serde(default)]
    pub coalesce_max_ms: u16,
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
    /// Block STUN/TURN UDP ports (3478, 5349, 19302) at the SOCKS5 listener.
    /// Forces WebRTC apps (Google Meet, Discord, WhatsApp) to fall back to
    /// TCP TURN on port 443, skipping the 10-30s UDP ICE timeout. Default
    /// true — TCP fallback works for all tested apps and connects instantly.
    #[serde(default = "default_block_stun")]
    pub block_stun: bool,

    #[serde(default = "default_block_quic")]
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

    /// Disable HTTP/2 multiplexing on the Apps Script relay leg.
    /// Default `false` (= h2 enabled): the TLS handshake to the Google
    /// edge advertises ALPN `["h2", "http/1.1"]`; if the server picks
    /// h2 we route all relay traffic over a single multiplexed
    /// connection (~100 concurrent streams) instead of the legacy
    /// per-request TLS pool of 8-80 sockets. Kills head-of-line
    /// blocking on slow Apps Script responses (one stalled call no
    /// longer pins a whole socket). Set to `true` to force the
    /// pre-v1.9.x HTTP/1.1 path — useful as a kill switch if a specific
    /// deployment, fronting domain, or middlebox refuses h2.
    #[serde(default)]
    pub force_http1: bool,

    /// Opt-out for the DoH bypass. Default `false` (= bypass active):
    /// CONNECTs to well-known DoH hostnames (Cloudflare, Google, Quad9,
    /// AdGuard, NextDNS, OpenDNS, browser-pinned variants like
    /// `chrome.cloudflare-dns.com` and `mozilla.cloudflare-dns.com`)
    /// skip the Apps Script tunnel and exit via plain TCP (or
    /// `upstream_socks5` if set). DoH already encrypts the queries
    /// themselves, so the only privacy property the tunnel was adding
    /// is hiding *the fact that you're doing DoH* from the local
    /// network — a marginal gain not worth the ~2 s Apps Script
    /// round-trip cost paid on every name lookup. In Full mode this
    /// was the dominant DNS slowdown source.
    ///
    /// Set `tunnel_doh: false` to enable the bypass and let DoH go
    /// direct (saves the ~2 s Apps Script round-trip per name on
    /// networks where the DoH endpoints are reachable). With the
    /// bypass off, browsers that find their pinned DoH host
    /// unreachable already fall back to OS DNS on their own, so
    /// failure modes are graceful in either direction.
    ///
    /// **Default flipped to `true` in v1.9.0** (issue #468). The
    /// previous default (`false` = bypass active) silently broke for
    /// Iranian users because Iran ISPs filter direct connections to
    /// `dns.google`, `chrome.cloudflare-dns.com`, etc. — exactly the
    /// "pinned DoH" hosts that the bypass was sending through. The
    /// safe default keeps DoH inside the tunnel; users on networks
    /// where direct DoH works can opt back into the bypass.
    ///
    /// Port-gated to TCP/443 only. A private DoH on a non-standard port
    /// (e.g. `doh.internal.example:8443`) won't take the bypass path —
    /// list it in `passthrough_hosts` instead, which has no port gate.
    #[serde(default = "default_tunnel_doh")]
    pub tunnel_doh: bool,

    /// Extra hostnames to treat as DoH endpoints in addition to the
    /// built-in default list. Case-insensitive; entries match exactly
    /// OR as a dot-anchored suffix unconditionally — `doh.acme.test`
    /// covers both `doh.acme.test` and `tenant.doh.acme.test`. (Unlike
    /// `passthrough_hosts`, no leading dot is required for suffix
    /// matching: every legitimate subdomain of a DoH host is itself
    /// a DoH endpoint, so the leading-dot convention would be a
    /// footgun.) Use this to cover private/enterprise DoH resolvers
    /// without waiting for a release.
    ///
    /// Inert when `tunnel_doh = true` — the bypass itself is off, so
    /// the extras have nothing to feed. The proxy logs a warning at
    /// startup if both are set together.
    #[serde(default)]
    pub bypass_doh_hosts: Vec<String>,

    /// When true, immediately reject (close) any CONNECT to a known DoH
    /// endpoint. Takes priority over `tunnel_doh` — the connection is
    /// never established in either direction. Browsers fall back to system
    /// DNS, which tun2proxy handles via virtual DNS (instant, no tunnel
    /// round-trip). This eliminates the ~1.5s per-domain DoH overhead
    /// that #468's `tunnel_doh: true` default introduced.
    ///
    /// Background: #468 changed `tunnel_doh` from false (bypass) to true
    /// (tunnel) because Iranian ISPs block direct DoH endpoints. But
    /// tunneling DoH costs an extra ~1.5s Apps Script round-trip per DNS
    /// lookup, which made every page load noticeably slower. Blocking
    /// DoH entirely avoids both problems: no ISP-visible DoH connection,
    /// no tunnel round-trip — browsers use the system DNS path instead.
    ///
    /// Default `true` (NOT `bool::default() = false`). Critical for
    /// upgrading users — see #773: with the v1.9.13 default-derive bug,
    /// existing configs got `block_doh = false` paired with `tunnel_doh
    /// = true` (the new tunnel-DoH default from #468), routing every
    /// browser DNS lookup through Apps Script and adding ~1.5s per page
    /// load. The named-default function fixes the upgrade path so the
    /// fast block-then-system-DNS behaviour is what users actually get.
    #[serde(default = "default_block_doh")]
    pub block_doh: bool,

    /// Multi-edge domain-fronting groups. Each group is a triple of
    /// (edge IP, front SNI, member domains): when a CONNECT to one of
    /// the member domains arrives, the proxy MITMs at the local CA
    /// then re-encrypts upstream against `ip` with `sni` as the TLS
    /// SNI — same trick we already do for `google_ip` + `front_domain`,
    /// but generalised so users can target Vercel's edge (sni=react.dev,
    /// fronting vercel.com / vercel.app / nextjs.org / ...) or Fastly's
    /// (sni=www.python.org, fronting reddit.com / githubassets.com / ...)
    /// directly without burning Apps Script quota or relying on the
    /// Google edge for non-Google traffic.
    ///
    /// The cert returned by the upstream is validated against `sni` by
    /// rustls as normal — no custom SAN-allowlist needed, the front SNI
    /// must itself be a real domain hosted by the same edge as the
    /// targets. Picking the right (ip, sni) pair is on the user; see
    /// `docs/fronting-groups.md` for the recipe.
    ///
    /// Group match wins over the built-in Google SNI-rewrite suffix list
    /// but loses to `passthrough_hosts` (explicit user opt-out wins) and
    /// to the DoH bypass. Empty / missing = feature off.
    #[serde(default)]
    pub fronting_groups: Vec<FrontingGroup>,

    /// Auto-blacklist tuning — how many timeouts within the window
    /// trip a per-deployment cooldown.
    ///
    /// Default `3` matches the historical behavior. Single-deployment
    /// users who hit transient network blips have reported (#391, #444)
    /// that 3 strikes are too few — one cold-start stall plus two
    /// network glitches lock out their only relay path. Bumping to
    /// `5` or `6` is a reasonable workaround for that case.
    ///
    /// Multi-deployment users with 10+ healthy alternatives can lower
    /// this (e.g. `2`) to fail-fast off a flaky deployment without
    /// burning latency on retries.
    #[serde(default = "default_auto_blacklist_strikes")]
    pub auto_blacklist_strikes: u32,

    /// Window (seconds) for the auto-blacklist strike counter. Strikes
    /// older than this are dropped. Default `30`. Larger windows make
    /// the heuristic less twitchy at the cost of holding state longer
    /// for deployments that have already recovered.
    #[serde(default = "default_auto_blacklist_window_secs")]
    pub auto_blacklist_window_secs: u64,

    /// Cooldown (seconds) when the strike threshold trips. Default
    /// `120`. Single-deployment users who can't afford a 2-min lockout
    /// when their only relay misbehaves can drop to `30` or `60`. Multi-
    /// deployment users with healthy alternatives can extend to `600`
    /// to keep a known-bad deployment out of rotation longer.
    #[serde(default = "default_auto_blacklist_cooldown_secs")]
    pub auto_blacklist_cooldown_secs: u64,

    /// Per-batch HTTP round-trip timeout (seconds). Default `30` —
    /// matches Apps Script's typical response cliff and historical
    /// `BATCH_TIMEOUT` constant. Slow Iran ISP networks may want `45`
    /// or `60` to give Apps Script time to respond past throttle
    /// windows. Networks with fail-fast preference may want `15` to
    /// retry sooner when a deployment hangs. Floor `5`, ceiling `300`
    /// (anything beyond exceeds Apps Script's hard 6-min cap with
    /// no benefit).
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,

    /// Optional second-hop exit node, for sites that block traffic
    /// from Google datacenter IPs (Apps Script's outbound IP space).
    /// Most visibly: Cloudflare-fronted services that flag the GCP IP
    /// block as bots — ChatGPT (chatgpt.com), Claude (claude.ai),
    /// Grok (grok.com / x.com), and a long tail of CF-protected SaaS.
    ///
    /// Architecture: chain becomes
    ///   `client → SNI rewrite → Apps Script (Google IP) → exit node
    ///    (Deno Deploy / fly.io / etc., non-Google IP) → destination`
    ///
    /// The destination sees the exit node's outbound IP, not Google's.
    /// CF anti-bot's "this is a Google datacenter" heuristic doesn't
    /// fire. mhrv-rs's DPI cover (Iran ISP only sees the SNI-rewritten
    /// TLS to a Google IP) is unchanged — the second hop happens
    /// inside Apps Script, invisible from the user's network.
    ///
    /// Setup walkthrough at `assets/exit_node/README.md`. Default off.
    #[serde(default)]
    pub exit_node: ExitNodeConfig,
}

/// Configuration for the optional second-hop exit node.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExitNodeConfig {
    /// Master switch. Default false. Even with `relay_url` and `psk`
    /// set, nothing routes through the exit node unless this is true.
    #[serde(default)]
    pub enabled: bool,

    /// HTTPS URL of the exit-node endpoint. Typically a Deno Deploy /
    /// fly.io serverless deployment (or your own VPS) running the
    /// `assets/exit_node/exit_node.ts` script (or an equivalent). The
    /// exit node is what makes the outbound `fetch()` call to the
    /// destination, so its IP is what the destination sees.
    #[serde(default)]
    pub relay_url: String,

    /// Pre-shared key — must match the `PSK` constant in the exit-node
    /// script. Without a matching PSK the exit node refuses the request
    /// (401). The PSK is what keeps the exit node from being usable as
    /// an open proxy by anyone who learns its URL. Treat like a
    /// password: do not commit, rotate if leaked. Generate with
    /// `openssl rand -hex 32`.
    #[serde(default)]
    pub psk: String,

    /// `"selective"` (default): only hosts in `hosts` go through the
    /// exit node; everything else takes the regular Apps Script path.
    /// Recommended — the exit-node hop adds ~200-500 ms per request,
    /// so reserve it for sites that need a non-Google IP.
    ///
    /// `"full"`: every request goes through the exit node. Useful only
    /// when the entire workload is CF-anti-bot affected, or when the
    /// exit node happens to be faster than Apps Script alone for the
    /// user's network path (rare but possible on very slow ISPs).
    #[serde(default = "default_exit_node_mode")]
    pub mode: String,

    /// In `"selective"` mode, the list of destination hostnames that
    /// route through the exit node. Matches exactly OR as a
    /// dot-anchored suffix, mirroring `passthrough_hosts` semantics:
    /// `"chatgpt.com"` covers `chatgpt.com` and `api.chatgpt.com` and
    /// `auth.chatgpt.com` etc. Leading dots are stripped at load.
    ///
    /// The recurring CF-anti-bot list from community reports:
    /// `chatgpt.com`, `claude.ai`, `x.com`, `grok.com`. Extend for
    /// any other CF-blocked sites you need.
    #[serde(default)]
    pub hosts: Vec<String>,
}

fn default_exit_node_mode() -> String {
    "selective".into()
}

/// One multi-edge fronting group. Edge CDNs like Vercel and Fastly
/// host hundreds of tenants behind a single set of edge IPs and use
/// the inner HTTP `Host` header (after TLS handshake) to dispatch to
/// the right backend. Pick one neutral domain hosted on the same edge
/// as `sni`; the cert it serves will be valid for that name (rustls
/// validates against `sni`, not against the inner `Host`), and the
/// edge will route based on the `Host` header.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrontingGroup {
    /// Human-readable name used in log lines. Free-form; uniqueness not
    /// enforced but recommended.
    pub name: String,
    /// Edge IP to dial. A single IP for now — most edges have many but
    /// one is enough to validate the technique. IP rotation per-group
    /// can come later.
    pub ip: String,
    /// SNI to send on the outbound TLS handshake. Must be a real domain
    /// served by the same edge as `domains`, otherwise the edge will
    /// either refuse the handshake or serve a default page that 404s
    /// the inner Host. Examples: `react.dev` for Vercel, `www.python.org`
    /// for Fastly.
    pub sni: String,
    /// Member domain list. Matching is case-insensitive: an entry
    /// matches the host exactly OR as an unconditional dot-anchored
    /// suffix (`vercel.com` matches `app.vercel.com` too). Same shape
    /// as the DoH host list.
    ///
    /// Canonical form for matching is lowercase and trailing-dot
    /// trimmed; entries are normalized to that form once at proxy
    /// startup. The on-disk representation is preserved as written
    /// (we don't mutate the user's config), so `Vercel.com.` and
    /// `vercel.com` both work — the matcher is the source of truth
    /// for equality.
    pub domains: Vec<String>,
}

fn default_fetch_ips_from_api() -> bool { false }
fn default_max_ips_to_scan() -> usize { 100 }
fn default_scan_batch_size() -> usize {500}
fn default_google_ip_validation() -> bool {true}

/// Default for `tunnel_doh`: `true` (DoH stays inside the tunnel).
/// Flipped from `false` in v1.9.0 per #468 — Iran ISPs filter direct
/// connections to pinned DoH hosts (`dns.google`, `chrome.cloudflare-dns.com`,
/// …) and the prior bypass-on default silently broke DNS for the
/// dominant userbase. Users on networks where direct DoH works can
/// opt back in with `tunnel_doh: false`.
fn default_tunnel_doh() -> bool { true }

/// Default for `block_quic`: `true`. QUIC over the TCP-based tunnel
/// causes TCP-over-TCP meltdown (<1 Mbps). Browsers fall back to
/// HTTPS/TCP within seconds of the silent UDP drop. Issue #793.
fn default_block_stun() -> bool { true }
fn default_block_quic() -> bool { true }

/// Default for `block_doh`: `true` (browser DoH is rejected so the
/// browser falls back to system DNS, which `tun2proxy` resolves
/// instantly via virtual DNS — saves the ~1.5s tunnel round-trip per
/// name lookup that #468's `tunnel_doh: true` default would otherwise
/// pay). #773 — without this named-default function, `#[serde(default)]`
/// on `bool` resolves to `false`, and existing configs upgrading to
/// v1.9.13 silently lost the block-and-fall-back behaviour, paying
/// the full DoH-via-Apps-Script penalty on every page load. Power
/// users who specifically want browser DoH (with the latency cost)
/// can opt back in by setting `block_doh: false`.
fn default_block_doh() -> bool { true }

/// Defaults for the auto-blacklist tuning knobs (#391, #444). These
/// preserve historical behavior — `3 strikes / 30s window / 120s cooldown`.
fn default_auto_blacklist_strikes() -> u32 { 3 }
fn default_auto_blacklist_window_secs() -> u64 { 30 }
fn default_auto_blacklist_cooldown_secs() -> u64 { 120 }

/// Default for `request_timeout_secs`: 30s, matching the historical
/// hard-coded `BATCH_TIMEOUT` and Apps Script's typical response cliff.
fn default_request_timeout_secs() -> u64 { 30 }

fn default_google_ip() -> String {
    "216.239.38.120".into()
}
fn default_front_domain() -> String {
    "www.google.com".into()
}
fn default_listen_host() -> String {
    "0.0.0.0".into()
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
            return Err(ConfigError::Invalid(format!(
                "listen_port and socks5_port must differ on the same host \
                 (both set to {} on {}). Change one of them in config.json.",
                self.listen_port, self.listen_host
            )));
        }
        for (i, g) in self.fronting_groups.iter().enumerate() {
            if g.name.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}]: name is empty", i
                )));
            }
            if g.ip.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): ip is empty", i, g.name
                )));
            }
            if g.sni.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): sni is empty", i, g.name
                )));
            }
            // Parse the SNI here so an invalid hostname fails the same
            // load path the UI / `mhrv-rs` CLI both use, rather than
            // surfacing later only when ProxyServer::new tries to build
            // the TLS server name. Same fail-fast contract as the rest
            // of validate(). The parse is cheap; runtime path repeats
            // it once at proxy startup, idempotently.
            if let Err(e) = ServerName::try_from(g.sni.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): invalid sni '{}': {}",
                    i, g.name, g.sni, e
                )));
            }
            if g.domains.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "fronting_groups[{}] ('{}'): domains list is empty", i, g.name
                )));
            }
            for d in &g.domains {
                if d.trim().is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "fronting_groups[{}] ('{}'): empty domain entry", i, g.name
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn mode_kind(&self) -> Result<Mode, ConfigError> {
        match self.mode.as_str() {
            "apps_script" => Ok(Mode::AppsScript),
            "direct" => Ok(Mode::Direct),
            // Deprecated alias. `google_only` was the name of `direct`
            // before fronting_groups generalized the mode beyond
            // Google's edge. Accepted forever so old configs keep
            // working — the UI rewrites it on next save.
            "google_only" => Ok(Mode::Direct),
            "full" => Ok(Mode::Full),
            other => Err(ConfigError::Invalid(format!(
                "unknown mode '{}' (expected 'apps_script', 'direct', or 'full')",
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
    fn parses_direct_without_script_id() {
        // Direct mode: no script_id, no auth_key — both are only meaningful
        // once the Apps Script relay exists.
        let s = r#"{
            "mode": "direct"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().expect("direct must validate without script_id / auth_key");
        assert_eq!(cfg.mode_kind().unwrap(), Mode::Direct);
    }

    #[test]
    fn google_only_alias_parses_as_direct() {
        // Backwards compat: `direct` was named `google_only` before
        // fronting_groups. Existing configs must continue to load.
        let s = r#"{
            "mode": "google_only"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().expect("google_only alias must still validate");
        assert_eq!(cfg.mode_kind().unwrap(), Mode::Direct);
    }

    #[test]
    fn direct_ignores_placeholder_script_id() {
        // UI round-trip: user saved config in apps_script with the placeholder,
        // then switched mode to direct. The placeholder should not block
        // validation in the no-relay mode.
        let s = r#"{
            "mode": "direct",
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
    fn fronting_groups_parse_and_validate() {
        let s = r#"{
            "mode": "direct",
            "fronting_groups": [
                {
                    "name": "vercel",
                    "ip": "76.76.21.21",
                    "sni": "react.dev",
                    "domains": ["vercel.com", "nextjs.org"]
                }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.fronting_groups.len(), 1);
        assert_eq!(cfg.fronting_groups[0].name, "vercel");
        assert_eq!(cfg.fronting_groups[0].domains.len(), 2);
    }

    #[test]
    fn fronting_group_rejects_invalid_sni_at_validate() {
        // SNI must parse as a DNS hostname at the same fail-fast point
        // as the rest of validate(), not later at proxy-startup time.
        // The CLI and UI both run validate() on Save / before serve.
        let s = r#"{
            "mode": "direct",
            "fronting_groups": [{
                "name": "bad",
                "ip": "1.2.3.4",
                "sni": "not a valid hostname",
                "domains": ["x.com"]
            }]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        let err = cfg.validate().expect_err("invalid sni must fail validate()");
        let msg = format!("{}", err);
        assert!(msg.contains("invalid sni"), "error should mention invalid sni: {}", msg);
    }

    #[test]
    fn fronting_group_rejects_empty_fields() {
        for bad in [
            r#"{ "name": "", "ip": "1.2.3.4", "sni": "a.b", "domains": ["x.com"] }"#,
            r#"{ "name": "n", "ip": "",       "sni": "a.b", "domains": ["x.com"] }"#,
            r#"{ "name": "n", "ip": "1.2.3.4","sni": "",    "domains": ["x.com"] }"#,
            r#"{ "name": "n", "ip": "1.2.3.4","sni": "a.b", "domains": []        }"#,
            r#"{ "name": "n", "ip": "1.2.3.4","sni": "a.b", "domains": ["  "]    }"#,
        ] {
            let s = format!(
                r#"{{ "mode": "direct", "fronting_groups": [{}] }}"#,
                bad
            );
            let cfg: Config = serde_json::from_str(&s).unwrap();
            assert!(
                cfg.validate().is_err(),
                "expected validation error for: {}",
                bad
            );
        }
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
    fn force_http1_round_trips_through_config() {
        let json = r#"{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "X",
  "auth_key": "secretkey123",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "log_level": "info",
  "verify_ssl": true,
  "force_http1": true
}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.force_http1, "force_http1=true must round-trip");
    }

    #[test]
    fn force_http1_defaults_false_when_omitted() {
        // Existing configs from before v1.9.13 don't have the field.
        // serde(default) must give false (h2 active) so older configs
        // continue to work and unchanged users get the optimization.
        let json = r#"{
  "mode": "apps_script",
  "auth_key": "secretkey123",
  "script_id": "X"
}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(!cfg.force_http1, "default must be false (h2 enabled)");
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
