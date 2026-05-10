use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};

use crate::config::{Config, FrontingGroup, Mode};
use crate::domain_fronter::DomainFronter;
use crate::mitm::MitmCertManager;
use crate::tunnel_client::{decode_udp_packets, TunnelMux};

// Domains that are served from Google's core frontend IP pool and therefore
// respond correctly when we connect to `google_ip` with SNI=`front_domain`
// and Host=<the real domain>. Routing these via the tunnel instead of the
// Apps Script relay also avoids Apps Script's fixed "Google-Apps-Script"
// User-Agent, which makes Google serve the bot/no-JS fallback for search.
// Kept conservative: anything on a separate CDN (googlevideo, ytimg,
// doubleclick, etc.) is DROPPED because routing to the wrong backend breaks
// rather than helps. Those fall through to MITM+relay (slower but works).
// Domains that are hosted on the Google Front End and therefore reachable via
// the same SNI-rewrite tunnel used for www.google.com itself. Adding a suffix
// here means "TLS CONNECT to google_ip, SNI = front_domain, Host = real name"
// for requests to it — bypassing the Apps Script relay entirely, so there's no
// User-Agent locking and no Apps Script quota.
// When in doubt leave it out: sites that aren't actually on GFE will 404 or
// return a wrong-cert error instead of loading.
const SNI_REWRITE_SUFFIXES: &[&str] = &[
    // Core Google
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "googleapis.com",
    "ggpht.com",
    // YouTube family
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "ytimg.com",
    // NOTE on `googlevideo.com`: v1.7.4 (#275) added this here on the
    // theory that video chunks should bypass the Apps Script relay.
    // **Reverted in v1.7.6** — multiple users (#275 amirabbas117, #281
    // mrerf) reported total YouTube breakage after v1.7.4. Root cause
    // is that googlevideo.com is served by Google's separate "EVA"
    // edge IPs, not the regular GFE IPs that the user's `google_ip`
    // typically points at. SNI-rewriting `googlevideo.com:443` to a
    // GFE IP got TLS handshake / wrong-cert errors for those users.
    // Pre-v1.7.4 behaviour (chunks via the Apps Script relay path —
    // slow but reliable on every GFE IP) is restored. If we ever want
    // direct googlevideo.com routing, it needs a separate config knob
    // that lets users specify their EVA edge IP independently.
    // Google Video Transport CDN — YouTube video chunks, Chrome
    // auto-updates, Google Play Store downloads. The single biggest
    // gap vs the upstream Python port: without these in the list
    // YouTube video playback stalls because every chunk tries to
    // traverse Apps Script instead of the direct GFE tunnel.
    "gvt1.com",
    "gvt2.com",
    // Ad + analytics infra. All on GFE, all previously broken the
    // same way YouTube was: SNI-blocked on Iranian DPI, but reachable
    // via `google_ip` with SNI rewritten.
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    // fonts.googleapis.com is technically covered by the googleapis.com
    // suffix above, but mirroring Python's explicit listing makes the
    // intent obvious at a glance.
    "fonts.googleapis.com",
    // Blogger / Blog.google
    "blogspot.com",
    "blogger.com",
];

/// YouTube hosts that should be routed through the Apps Script relay
/// when `youtube_via_relay` is enabled — the API + HTML surfaces where
/// Restricted Mode is actually enforced (via the SNI=www.google.com
/// edge looking at the request). Issue #102 / #275.
///
/// Deliberately narrower than the YouTube section of
/// `SNI_REWRITE_SUFFIXES`:
///   - `youtube.com` / `youtu.be` / `youtube-nocookie.com`: HTML pages
///     and player frames. These trigger Restricted Mode if served via
///     the SNI rewrite, so when the flag is on we relay them.
///   - `youtubei.googleapis.com`: the YouTube data API the player
///     queries for video metadata + manifest. Restricted Mode also
///     gates video availability here. Without this entry, the JSON
///     RPC layer would still hit the SNI-rewrite tunnel via the
///     broader `googleapis.com` suffix — the user-visible symptom of
///     that miss is "youtube_via_relay flips on but Restricted Mode
///     stays sticky on some videos."
///
/// **NOT** in this list (intentional, was a regression in #275):
///   - `ytimg.com`: thumbnails. No Restricted Mode logic on a static
///     image CDN; routing through Apps Script makes thumbnails slow
///     for zero gain.
///   - `googlevideo.com`: video chunk CDN. Routing through Apps Script
///     means every chunk eats Apps Script quota *and* risks the 6-min
///     execution cap aborting long videos mid-playback.
///   - `ggpht.com`: channel/profile images, same reasoning as ytimg.
const YOUTUBE_RELAY_HOSTS: &[&str] = &[
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
];

/// URL path-prefix patterns that are forced through the Apps Script relay.
/// Each entry is `host/path-prefix` (no scheme, lowercase). The host is
/// pulled out of `SNI_REWRITE_SUFFIXES` so the proxy MITMs and can inspect
/// paths; only URLs starting with the pattern go to relay, all other paths
/// on that host fall through to the SNI-rewrite HTTP forwarder
/// (`forward_via_sni_rewrite_http`) — same SNI-rewrite trick as the
/// CONNECT-tunnel path, but applied at the HTTP layer so we keep MITM
/// for the matching paths. User-supplied entries from
/// `Config::relay_url_patterns` are appended to this default.
///
/// `youtube.com/youtubei/`: YouTube's in-page RPC layer. Restricted Mode /
/// SafeSearch / live-stream gating decisions land here. Relaying just
/// this prefix recovers the SafeSearch fix that previously required the
/// full `youtube_via_relay = true` knob (which routed every static
/// asset through the relay too). Ported from upstream
/// `RELAY_URL_PATTERNS` (commit b3b9220).
const DEFAULT_RELAY_URL_PATTERNS: &[&str] = &[
    "youtube.com/youtubei/",
];

/// Built-in list of DNS-over-HTTPS endpoints. CONNECTs to these (when
/// `tunnel_doh` is left at the default of `false`, i.e. bypass enabled)
/// skip the Apps Script tunnel and exit via plain TCP. Mix of the
/// browser-pinned variants Chrome/Brave/Edge/Firefox/Safari use and the
/// well-known public DoH providers users wire up by hand. Suffix
/// matching means we don't need to enumerate every tenant subdomain
/// (e.g. `*.cloudflare-dns.com` covers Workers-hosted DoH too).
///
/// Entries are matched case-insensitively. Both exact-match (`dns.google`)
/// and dot-anchored suffix-match (a host whose suffix is `.cloudflare-dns.com`
/// or which equals `cloudflare-dns.com`) are accepted — same shape as
/// `passthrough_hosts`'s `.foo` rule.
const DEFAULT_DOH_HOSTS: &[&str] = &[
    // The base SLD covers every tenant subdomain via suffix matching;
    // the browser-pinned variants below are listed for grep/discovery
    // (so a user searching "chrome.cloudflare-dns.com" finds this list)
    // and are technically redundant under cloudflare-dns.com.
    "cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "dns11.quad9.net",
    "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    "family.adguard-dns.com",
    "dns.nextdns.io",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "doh.dns.sb",
    "dns0.eu",
    "dns.alidns.com",
    "doh.pub",
    "dns.mullvad.net",
];

fn matches_sni_rewrite(
    host: &str,
    youtube_via_relay: bool,
    force_mitm_hosts: &[String],
) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');

    // YouTube relay carve-out runs FIRST so it wins over the broad
    // `googleapis.com` suffix that would otherwise pull
    // `youtubei.googleapis.com` into the SNI-rewrite path. The earlier
    // implementation iterated SNI_REWRITE_SUFFIXES with a filter, which
    // works for sibling entries (e.g. `youtube.com` in both lists) but
    // not for nested ones (`youtubei.googleapis.com` matches the broad
    // `googleapis.com` even when its specific entry is filtered out).
    // The short-circuit here is unconditional — we don't need to check
    // SNI rewrite once we've decided this host goes to the relay.
    if youtube_via_relay {
        for s in YOUTUBE_RELAY_HOSTS {
            if h == *s || h.ends_with(&format!(".{}", s)) {
                return false;
            }
        }
    }

    // Hosts pulled out of SNI-rewrite by `relay_url_patterns` (b3b9220).
    // We need to MITM these so the per-path matcher in
    // `handle_mitm_request` can decide between relay and the SNI-rewrite
    // HTTP forwarder. Match shape MUST match `host_in_force_mitm_list`
    // exactly — otherwise a host pulled out here wouldn't be recognised
    // at dispatch and the path filter would silently no-op, which was a
    // real bug in the first cut where this list also matched in the
    // reverse direction (`forced.ends_with(.h)`). Reverse-matching
    // pulled parent SNI suffixes for entries like `studio.youtube.com`,
    // making the entire `youtube.com` subtree skip SNI-rewrite while
    // dispatch only force-MITM-recognised the literal `studio.youtube.com`.
    // One-directional match (`h == forced || h.ends_with(.forced)`)
    // pulls only the configured host and its subdomains, leaving sibling
    // subdomains on the natural SNI-rewrite path.
    for forced in force_mitm_hosts {
        if h == *forced || h.ends_with(&format!(".{}", forced)) {
            return false;
        }
    }

    SNI_REWRITE_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

/// True if `url` matches any entry in `patterns`. Each pattern is
/// `host/path-prefix` (no scheme, lowercase). The URL host may have extra
/// subdomains — `www.youtube.com` matches `youtube.com/youtubei/`. Path
/// match is a plain prefix on the URL's path component.
///
/// Same matching shape as the upstream Python `_url_matches_relay_pattern`
/// (b3b9220): scheme stripped, lowercased, host suffix-anchored, path
/// `startswith`. Used in MITM dispatch to decide relay vs. SNI-rewrite
/// HTTP forward for hosts pulled out of SNI-rewrite.
pub(crate) fn url_matches_relay_pattern(url: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    let stripped = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let (raw_host, url_path) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]),
        None => (stripped, "/"),
    };
    // Strip an authority's port (`:443`) and any FQDN trailing dot so
    // `www.youtube.com.` and `www.youtube.com:443` canonicalise to the
    // same form that `host_in_force_mitm_list` and `extract_host` use.
    // Without this, dispatch and pattern-match disagree: the host is
    // pulled from SNI-rewrite but its `/youtubei/` URL fails the
    // pattern check and ends up routed via the SNI-HTTP forwarder.
    let host_no_port = raw_host.split(':').next().unwrap_or(raw_host);
    let url_host = host_no_port.trim_end_matches('.');
    for p in patterns {
        let (pat_host, pat_path) = match p.find('/') {
            Some(i) => (&p[..i], &p[i..]),
            None => (p.as_str(), "/"),
        };
        let host_match = url_host == pat_host || url_host.ends_with(&format!(".{}", pat_host));
        if host_match && url_path.starts_with(pat_path) {
            return true;
        }
    }
    false
}

/// True if the request's host is one we pulled out of SNI-rewrite to
/// support `relay_url_patterns`. Used in `handle_mitm_request` as the
/// gate for the SNI-rewrite-HTTP fallback path: if the host was forced
/// to MITM but the URL didn't match any pattern, we forward over a fresh
/// SNI-rewrite TLS connection instead of burning Apps Script quota.
pub(crate) fn host_in_force_mitm_list(host: &str, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    list.iter()
        .any(|forced| h == *forced || h.ends_with(&format!(".{}", forced)))
}

fn hosts_override<'a>(
    hosts: &'a std::collections::HashMap<String, String>,
    host: &str,
) -> Option<&'a str> {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if let Some(ip) = hosts.get(h) {
        return Some(ip.as_str());
    }
    let parts: Vec<&str> = h.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if let Some(ip) = hosts.get(&parent) {
            return Some(ip.as_str());
        }
    }
    None
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ProxyServer {
    host: String,
    port: u16,
    socks5_port: u16,
    /// `None` in `direct` mode: no Apps Script relay is wired up,
    /// only the SNI-rewrite tunnel path (Google edge + any configured
    /// `fronting_groups`) is live.
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
    coalesce_step_ms: u64,
    coalesce_max_ms: u64,
}

pub struct RewriteCtx {
    pub google_ip: String,
    pub front_domain: String,
    pub hosts: std::collections::HashMap<String, String>,
    pub tls_connector: TlsConnector,
    pub upstream_socks5: Option<String>,
    pub mode: Mode,
    /// If true, YouTube traffic bypasses the SNI-rewrite tunnel and
    /// goes through the Apps Script relay instead. Effective value:
    /// `config.youtube_via_relay || (apps_script + exit_node.full)` —
    /// when the exit node is in full mode it must intercept all traffic
    /// including YouTube, so YT hosts get pulled from SNI-rewrite the
    /// same way the explicit toggle does it. Ported from upstream
    /// commit 88b2767. Issue #102.
    pub youtube_via_relay: bool,
    /// Resolved URL path-prefix patterns (`host/path-prefix`, lowercase,
    /// no scheme) that force the relay path inside MITM. Built at
    /// startup from `DEFAULT_RELAY_URL_PATTERNS` plus
    /// `Config::relay_url_patterns`. Empty when
    /// `youtube_via_relay = true` because YouTube is then fully relayed
    /// already and the per-path filter would just be redundant. Used
    /// by `handle_mitm_request` to decide relay vs. SNI-rewrite HTTP
    /// forward. Ported from upstream `_relay_url_patterns` (b3b9220).
    pub relay_url_patterns: Vec<String>,
    /// Hosts derived from `relay_url_patterns` that get pulled out of
    /// `SNI_REWRITE_SUFFIXES` so the proxy MITMs them and the per-path
    /// matcher can run. Lowercase, no scheme. Empty when
    /// `relay_url_patterns` is empty. Used in `matches_sni_rewrite`
    /// and `host_in_force_mitm_list`.
    pub force_mitm_hosts: Vec<String>,
    /// Set when `mode == AppsScript && exit_node.enabled &&
    /// exit_node.mode == "full"` — the same condition that promotes
    /// `youtube_via_relay_effective` (commit 88b2767). When true,
    /// `handle_mitm_request` MUST NOT use `forward_via_sni_rewrite_http`
    /// for non-matching paths, even on hosts in `force_mitm_hosts` —
    /// the forwarder dials the Google edge directly, which would
    /// completely bypass the second-hop exit node and violate the
    /// documented "every URL routes through the exit node" contract
    /// (`DomainFronter::exit_node_matches`). User-supplied
    /// `relay_url_patterns` are still honoured: matching paths and
    /// non-matching paths both end up in `DomainFronter::relay`,
    /// which then routes through the exit node.
    pub exit_node_full_mode_active: bool,
    /// User-configured hostnames that should skip the relay entirely
    /// and pass through as plain TCP (optionally via upstream_socks5).
    /// See config.rs `passthrough_hosts` for matching rules. Issues #39, #127.
    pub passthrough_hosts: Vec<String>,
    /// If true, drop SOCKS5 UDP datagrams destined for port 443 so
    /// callers fall back to TCP/HTTPS. See config.rs `block_quic` for
    /// the trade-off. Issue #213.
    pub block_quic: bool,
    /// If true, route DoH CONNECTs around the Apps Script tunnel via
    /// plain TCP. Default false via `Config::tunnel_doh = true` (flipped
    /// in v1.9.0, issue #468). See `DEFAULT_DOH_HOSTS` and
    /// `matches_doh_host` for matching, and config.rs `tunnel_doh` for
    /// the trade-off.
    pub bypass_doh: bool,
    /// When true, immediately reject connections to known DoH hosts.
    /// Takes priority over bypass_doh.
    pub block_doh: bool,
    /// User-supplied DoH hostnames added to the built-in default list.
    /// Same matching semantics as `passthrough_hosts`.
    pub bypass_doh_hosts: Vec<String>,
    /// Multi-edge fronting groups, resolved at startup. Each group's
    /// `ServerName` is parsed once so the per-connection dial path
    /// is allocation-free. Wrapped in `Arc` so a per-CONNECT match
    /// can hand the dispatcher a refcount-clone instead of cloning
    /// the whole struct (which holds a `Vec<String>` of normalized
    /// domains used only for matching). Empty = feature off (only
    /// the built-in Google edge SNI-rewrite is active).
    pub fronting_groups: Vec<Arc<FrontingGroupResolved>>,
}

/// One-shot resolution of the YouTube routing knobs (`youtube_via_relay`,
/// `relay_url_patterns`, `exit_node.mode == "full"`) for a given
/// `Config` + `Mode`. Pulled out of `ProxyServer::new` so it can be
/// unit-tested directly without spinning up the full proxy.
///
/// Two gates govern the resolved patterns:
///
/// 1. **Mode gate** — only `apps_script` mode has a relay path to route
///    patterns through. In `direct` mode there's no Apps Script, so
///    pulling hosts out of SNI-rewrite would just send them to raw-TCP
///    fallback (a routing regression). In `full` mode the dispatcher
///    short-circuits to the tunnel mux before MITM ever runs, so
///    patterns would never be consulted. Outside `apps_script` the
///    resolved sets are always empty.
///
/// 2. **youtube_via_relay-effective gate** — the explicit
///    `youtube_via_relay` toggle OR exit-node-full mode (commit 88b2767).
///    When *either* is on, YouTube is fully relayed already, so the
///    per-path filter is redundant. Worse, in exit-node-full mode the
///    filter is *harmful*: non-matching paths on `youtube.com` would
///    route via `forward_via_sni_rewrite_http`, bypassing
///    `DomainFronter::relay` and with it the exit node — defeating
///    the whole point of full mode.
///
/// User-supplied `relay_url_patterns` entries always run inside
/// `apps_script` mode regardless of the YT flag; they may target hosts
/// other than `youtube.com` that the user wants path-pinned
/// independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedRouting {
    /// Effective `youtube_via_relay` after OR-ing with exit-node-full
    /// mode. Mirrors what `RewriteCtx::youtube_via_relay` ends up with.
    pub youtube_via_relay_effective: bool,
    /// Resolved patterns, lowercased, scheme-stripped, deduplicated.
    /// Empty outside `apps_script` mode and when both gates above
    /// allow the defaults to be skipped.
    pub relay_url_patterns: Vec<String>,
    /// Host parts of `relay_url_patterns` that ARE
    /// SNI-rewrite-capable. Pulled out of SNI-rewrite at dispatch time
    /// so MITM can run for them.
    pub force_mitm_hosts: Vec<String>,
    /// Host parts of `relay_url_patterns` that are NOT
    /// SNI-rewrite-capable, retained only so `ProxyServer::new` can log
    /// a startup warning. Patterns referencing them stay in
    /// `relay_url_patterns` (so a matching path still routes through
    /// the relay if the host is MITM'd via the regular TLS-detect
    /// path), but the path-vs-forwarder filter is inert for them — the
    /// forwarder would return a wrong-origin response from the Google
    /// edge.
    pub skipped_force_mitm_hosts: Vec<String>,
    /// User patterns dropped because `youtube_via_relay_effective` is
    /// true AND the pattern's host is already covered by
    /// `YOUTUBE_RELAY_HOSTS`. Keeping them would partially defeat the
    /// "full YT through relay" contract: the path filter would flag
    /// non-matching paths as forwarder-eligible, and dispatch would
    /// route them via `forward_via_sni_rewrite_http` instead of the
    /// relay. Surfaced for the startup warning so the user knows their
    /// extra entry was redundant + harmful.
    pub suppressed_yt_patterns: Vec<String>,
    /// True iff `exit_node.enabled && mode == "full"` AND we're in
    /// apps_script mode. Used only for the startup log line that
    /// announces the YT-via-relay implication of exit-node-full.
    pub exit_node_full_mode_active: bool,
}

impl ResolvedRouting {
    pub(crate) fn from_config(config: &Config, mode: Mode) -> Self {
        let exit_node_full_mode = config.exit_node.enabled
            && config.exit_node.mode.eq_ignore_ascii_case("full")
            && !config.exit_node.relay_url.is_empty()
            && !config.exit_node.psk.is_empty();
        let exit_node_full_mode_active = exit_node_full_mode && mode == Mode::AppsScript;
        let youtube_via_relay_effective =
            config.youtube_via_relay || exit_node_full_mode_active;

        let mut relay_url_patterns: Vec<String> = Vec::new();
        let mut suppressed_yt_patterns: Vec<String> = Vec::new();
        if mode == Mode::AppsScript {
            if !youtube_via_relay_effective {
                for p in DEFAULT_RELAY_URL_PATTERNS {
                    relay_url_patterns.push((*p).to_string());
                }
            }
            for p in &config.relay_url_patterns {
                let trimmed = p.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let normalized = normalize_pattern(trimmed);
                // YT-overlap suppression: when `youtube_via_relay_effective`
                // is true, every YT-family host is already pulled out of
                // SNI-rewrite by the `YOUTUBE_RELAY_HOSTS` carve-out, so
                // every YT request flows through the relay regardless. A
                // user pattern targeting a YT host adds it to
                // `force_mitm_hosts`, which switches on the path filter;
                // non-matching YT paths then route through
                // `forward_via_sni_rewrite_http`, partially defeating the
                // user's `youtube_via_relay = true` opt-in. Drop the
                // pattern entirely (matching paths already go to relay
                // without it) and surface it for the startup warning.
                let pattern_host = normalized
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .trim_start_matches('.');
                if youtube_via_relay_effective && host_matches_youtube_relay(pattern_host) {
                    suppressed_yt_patterns.push(normalized);
                    continue;
                }
                relay_url_patterns.push(normalized);
            }
            let mut seen_patterns: std::collections::HashSet<String> = Default::default();
            relay_url_patterns.retain(|p| seen_patterns.insert(p.clone()));
        }

        // Only hosts that would naturally take the SNI-rewrite tunnel
        // (i.e. match `SNI_REWRITE_SUFFIXES`) are valid targets for the
        // path-level filter. The non-matching path goes through
        // `forward_via_sni_rewrite_http`, which dials `google_ip:443`
        // with `SNI=front_domain` — the Google edge dispatches by the
        // inner `Host` header, but only if that Host is actually served
        // by the same edge. A user-supplied pattern like
        // `evilsite.com/api/` would otherwise pull `evilsite.com` from
        // the (already-not-matching) SNI list as a no-op AND make
        // `host_in_force_mitm_list` true, sending non-matching paths
        // through the forwarder which would return a wrong-origin
        // response from the Google edge — silently treated as success.
        // Filter at startup, log the skip, leave the pattern itself
        // alone so a matching path still routes via relay if the host
        // is reached via a different path (TLS-detect → MITM → relay).
        // Fronting-group hosts are NOT eligible either: the forwarder
        // only knows `(google_ip, front_domain)`, not the group's
        // `(ip, sni)` pair. Path-routing on fronting groups is a
        // separate feature.
        let mut force_mitm_hosts: Vec<String> = Vec::new();
        let mut skipped_hosts: Vec<String> = Vec::new();
        let mut seen_hosts: std::collections::HashSet<String> = Default::default();
        for p in &relay_url_patterns {
            let host_part = p
                .split('/')
                .next()
                .unwrap_or("")
                .trim_start_matches('.')
                .to_string();
            if host_part.is_empty() || !seen_hosts.insert(host_part.clone()) {
                continue;
            }
            if host_is_sni_rewrite_capable(&host_part) {
                force_mitm_hosts.push(host_part);
            } else {
                skipped_hosts.push(host_part);
            }
        }

        Self {
            youtube_via_relay_effective,
            relay_url_patterns,
            force_mitm_hosts,
            skipped_force_mitm_hosts: skipped_hosts,
            suppressed_yt_patterns,
            exit_node_full_mode_active,
        }
    }
}

/// Canonicalise a `relay_url_patterns` entry to the form the runtime
/// matchers expect: lowercase, no scheme, no trailing dot on the host.
/// Lowercasing happens BEFORE scheme strip so `HTTPS://Foo.com/Bar/`
/// normalises cleanly (`trim_start_matches("https://")` is
/// case-sensitive). Trailing dots on the host (e.g. `foo.com./api/`,
/// FQDN-form) are stripped so they match against the `extract_host` →
/// trim-trailing-dot canonical form.
pub(crate) fn normalize_pattern(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    let no_scheme = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    // Split into host + path-prefix, trim a trailing dot from the host,
    // re-join. Patterns without a `/` are treated as host-only.
    match no_scheme.find('/') {
        Some(i) => {
            let host = no_scheme[..i].trim_end_matches('.');
            let rest = &no_scheme[i..];
            format!("{}{}", host, rest)
        }
        None => no_scheme.trim_end_matches('.').to_string(),
    }
}

/// True when `host` matches a `YOUTUBE_RELAY_HOSTS` entry under the
/// same one-directional suffix shape as `host_in_force_mitm_list`.
/// Used at startup to suppress user-supplied `relay_url_patterns`
/// whose host is already covered by the `youtube_via_relay` carve-out
/// — keeping such an entry would re-introduce the
/// `forward_via_sni_rewrite_http` bypass (the path filter would mark
/// non-matching paths as forwarder-eligible) and partially defeat the
/// "full YT through relay" contract the user opted into.
fn host_matches_youtube_relay(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    YOUTUBE_RELAY_HOSTS
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

/// True when `host` is served by the Google edge — i.e. matches one of
/// `SNI_REWRITE_SUFFIXES`. Used at startup to validate that
/// `relay_url_patterns` host parts are actually safe targets for the
/// SNI-rewrite HTTP forwarder. One-directional suffix match because we
/// only need to know "would this host be SNI-rewrite-capable in the
/// absence of force_mitm_hosts?" — bidirectional matching would falsely
/// validate sub-suffixes that the SNI list doesn't really cover.
fn host_is_sni_rewrite_capable(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    SNI_REWRITE_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

/// True if `host` matches a known DoH endpoint — either the built-in
/// `DEFAULT_DOH_HOSTS` list or a user-supplied entry in `extra`. Match
/// is case-insensitive, and entries match either exactly OR as a
/// dot-anchored suffix unconditionally (no leading-dot requirement,
/// unlike `passthrough_hosts`). The DoH list is *always* about a
/// service — every legitimate tenant subdomain of `cloudflare-dns.com`
/// or a user's private `doh.acme.test` is a DoH endpoint, so requiring
/// users to remember to write `.doh.acme.test` would be a footgun
/// without an obvious benefit.
fn host_matches_doh_entry(h: &str, entry: &str) -> bool {
    let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
    let e = e.strip_prefix('.').unwrap_or(&e);
    if e.is_empty() {
        return false;
    }
    h == e || h.ends_with(&format!(".{}", e))
}

pub fn matches_doh_host(host: &str, extra: &[String]) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if h.is_empty() {
        return false;
    }
    if DEFAULT_DOH_HOSTS
        .iter()
        .any(|s| host_matches_doh_entry(h, s))
    {
        return true;
    }
    extra.iter().any(|s| host_matches_doh_entry(h, s))
}

/// A `FrontingGroup` after one-time validation: the group's `sni` is
/// parsed into a `ServerName` so we don't repay that on every dialed
/// connection, and domain entries are pre-lower-cased + dot-trimmed
/// so the per-request match path is just byte comparisons.
#[derive(Debug, Clone)]
pub struct FrontingGroupResolved {
    pub name: String,
    pub ip: String,
    pub sni: String,
    pub server_name: ServerName<'static>,
    domains_normalized: Vec<String>,
}

impl FrontingGroupResolved {
    fn from_config(g: &FrontingGroup) -> Result<Self, String> {
        let server_name = ServerName::try_from(g.sni.clone())
            .map_err(|e| format!("invalid sni '{}': {}", g.sni, e))?;
        let domains_normalized = g
            .domains
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        Ok(Self {
            name: g.name.clone(),
            ip: g.ip.clone(),
            sni: g.sni.clone(),
            server_name,
            domains_normalized,
        })
    }
}

/// First fronting group whose domain list contains `host`, if any.
/// Match is case-insensitive and unconditionally suffix-anchored: an
/// entry `vercel.com` matches both `vercel.com` and `*.vercel.com`.
/// This is the right shape for fronting because every legitimate
/// subdomain of a fronted domain is itself fronted by the same edge
/// — requiring users to spell out every subdomain would be a footgun.
/// Same matching shape as the DoH host list. First match wins, so
/// users can put more-specific groups earlier when entries would
/// otherwise overlap.
pub fn match_fronting_group<'a>(
    host: &str,
    groups: &'a [Arc<FrontingGroupResolved>],
) -> Option<&'a Arc<FrontingGroupResolved>> {
    if groups.is_empty() {
        return None;
    }
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if h.is_empty() {
        return None;
    }
    for g in groups {
        for d in &g.domains_normalized {
            if is_dot_anchored_match(h, d) {
                return Some(g);
            }
        }
    }
    None
}

/// True if `host` equals `entry` exactly OR is a strict dot-anchored
/// suffix of it (i.e. `entry == "vercel.com"` matches `host ==
/// "app.vercel.com"` but not `host == "xvercel.com"`). Both inputs
/// must already be lowercase + trailing-dot trimmed; the function
/// does no allocation, unlike the obvious `format!(".{}", entry)`
/// implementation that allocates per call.
#[inline]
fn is_dot_anchored_match(host: &str, entry: &str) -> bool {
    if host == entry {
        return true;
    }
    let hb = host.as_bytes();
    let eb = entry.as_bytes();
    hb.len() > eb.len()
        && hb.ends_with(eb)
        && hb[hb.len() - eb.len() - 1] == b'.'
}

/// True if `host` matches any entry in the user's passthrough list.
/// Match is case-insensitive. Entries match either exactly, or as a
/// suffix if they start with "." (e.g. ".internal.example" matches
/// "a.b.internal.example" and the bare "internal.example"). Bare
/// entries like "example.com" only match the exact hostname — users
/// who want subdomains included should use ".example.com".
pub fn matches_passthrough(host: &str, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    list.iter().any(|entry| {
        let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if e.is_empty() {
            return false;
        }
        if let Some(suffix) = e.strip_prefix('.') {
            h == suffix || h.ends_with(&format!(".{}", suffix))
        } else {
            h == e
        }
    })
}

impl ProxyServer {
    pub fn new(config: &Config, mitm: Arc<Mutex<MitmCertManager>>) -> Result<Self, ProxyError> {
        let mode = config
            .mode_kind()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;

        // `direct` mode skips the Apps Script relay entirely, so we must
        // not try to construct the DomainFronter — it errors on a missing
        // `script_id`, which is exactly the state a direct-mode user is in.
        let fronter = match mode {
            Mode::AppsScript | Mode::Full => {
                let f = DomainFronter::new(config)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
                Some(Arc::new(f))
            }
            Mode::Direct => None,
        };

        let tls_config = if config.verify_ssl {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        };
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        // Surface a config combo that is otherwise silently inert: extras
        // listed under `bypass_doh_hosts` only take effect when the bypass
        // itself is on. A user who set `tunnel_doh: true` *and* populated
        // the extras list almost certainly didn't mean to disable the
        // feature their custom hosts feed into.
        if config.tunnel_doh && !config.bypass_doh_hosts.is_empty() {
            tracing::warn!(
                "config: bypass_doh_hosts has {} entries but tunnel_doh=true — \
                 the bypass is off, so the extras have no effect. Set \
                 tunnel_doh=false (or omit it) to use them.",
                config.bypass_doh_hosts.len()
            );
        }

        // Same-shape warning for fronting_groups in full mode. The dispatch
        // short-circuits to the tunnel mux before the fronting_groups check
        // (full mode preserves end-to-end TLS, fronting_groups requires
        // MITM), so groups configured here will never fire. Surface this
        // at startup rather than letting users wonder why their Vercel
        // domains never hit the configured edge.
        if mode == Mode::Full && !config.fronting_groups.is_empty() {
            tracing::warn!(
                "config: fronting_groups has {} entries but mode=full — \
                 full mode tunnels everything end-to-end through Apps Script \
                 (no MITM), so groups never fire. Switch to mode=apps_script \
                 or mode=direct to use them, or remove the groups to silence \
                 this warning.",
                config.fronting_groups.len()
            );
        }

        let mut fronting_groups: Vec<Arc<FrontingGroupResolved>> =
            Vec::with_capacity(config.fronting_groups.len());
        let mut seen_names: std::collections::HashSet<String> = Default::default();
        for g in &config.fronting_groups {
            let resolved = FrontingGroupResolved::from_config(g).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("fronting_groups['{}']: {}", g.name, e),
                )
            })?;
            // Surface duplicate group names at startup. Not a hard
            // error — copy-pasted configs can land here legitimately
            // — but log lines key on `name` and dedup ambiguity makes
            // them unreadable.
            if !seen_names.insert(resolved.name.clone()) {
                tracing::warn!(
                    "fronting group name '{}' is used by more than one group; \
                     log lines that reference the name will be ambiguous",
                    resolved.name
                );
            }
            tracing::info!(
                "fronting group '{}': sni={} ip={} domains={}",
                resolved.name,
                resolved.sni,
                resolved.ip,
                resolved.domains_normalized.len()
            );
            fronting_groups.push(Arc::new(resolved));
        }

        let resolved_routing = ResolvedRouting::from_config(config, mode);
        if resolved_routing.exit_node_full_mode_active && !config.youtube_via_relay {
            tracing::info!(
                "exit_node.mode=full → routing YouTube through relay (upstream commit 88b2767)"
            );
        }
        if !resolved_routing.relay_url_patterns.is_empty() {
            tracing::info!(
                "relay_url_patterns: MITM forced on {}; relay only for: {}",
                resolved_routing.force_mitm_hosts.join(", "),
                resolved_routing.relay_url_patterns.join(", "),
            );
        }
        if !resolved_routing.skipped_force_mitm_hosts.is_empty() {
            tracing::warn!(
                "relay_url_patterns: ignoring path-routing for {} — host is not in \
                 SNI_REWRITE_SUFFIXES, so the SNI-rewrite forwarder would return a \
                 wrong-origin response from the Google edge. Patterns matching this \
                 host still route through the relay if the host is reached, but \
                 non-matching paths fall back to the regular dispatch.",
                resolved_routing.skipped_force_mitm_hosts.join(", "),
            );
        }
        if !resolved_routing.suppressed_yt_patterns.is_empty() {
            tracing::warn!(
                "relay_url_patterns: dropped {} — youtube_via_relay (or \
                 exit_node.mode=full) routes all YouTube through the relay \
                 already, so a YT-host path filter would route non-matching \
                 paths through the SNI-rewrite forwarder and partially defeat \
                 the full-relay contract. Remove these entries from \
                 config.json to silence this warning.",
                resolved_routing.suppressed_yt_patterns.join(", "),
            );
        }

        // Fronting groups are dispatched BEFORE the force-MITM check
        // (`dispatch_tunnel` step 2a vs 2). That precedence is intentional
        // — a user adding `youtube.com` to a fronting group is making a
        // deliberate "send all of YT through this alternate edge" choice
        // and the path filter, which assumes the Google edge handles the
        // request, would land at the wrong upstream. But the silent
        // override is a footgun if the user didn't realise the two
        // features overlap, so surface it at startup with both names
        // and the resolved precedence.
        for forced in &resolved_routing.force_mitm_hosts {
            for g in &fronting_groups {
                let overlaps = g.domains_normalized.iter().any(|d| {
                    forced == d
                        || forced.ends_with(&format!(".{}", d))
                        || d.ends_with(&format!(".{}", forced))
                });
                if overlaps {
                    tracing::warn!(
                        "config: fronting group '{}' covers host '{}', which is also \
                         in relay_url_patterns. Fronting-group dispatch wins — the \
                         path filter will NOT run for this host. Remove the host \
                         from the fronting group if you want path-pinned relay routing.",
                        g.name,
                        forced,
                    );
                }
            }
        }
        let ResolvedRouting {
            youtube_via_relay_effective,
            relay_url_patterns: resolved_patterns,
            force_mitm_hosts,
            skipped_force_mitm_hosts: _,
            suppressed_yt_patterns: _,
            exit_node_full_mode_active,
        } = resolved_routing;

        let rewrite_ctx = Arc::new(RewriteCtx {
            google_ip: config.google_ip.clone(),
            front_domain: config.front_domain.clone(),
            hosts: config.hosts.clone(),
            tls_connector,
            upstream_socks5: config.upstream_socks5.clone(),
            mode,
            youtube_via_relay: youtube_via_relay_effective,
            relay_url_patterns: resolved_patterns,
            force_mitm_hosts,
            exit_node_full_mode_active,
            passthrough_hosts: config.passthrough_hosts.clone(),
            block_quic: config.block_quic,
            bypass_doh: !config.tunnel_doh,
            block_doh: config.block_doh,
            bypass_doh_hosts: config.bypass_doh_hosts.clone(),
            fronting_groups,
        });

        let socks5_port = config.socks5_port.unwrap_or(config.listen_port + 1);

        Ok(Self {
            host: config.listen_host.clone(),
            port: config.listen_port,
            socks5_port,
            fronter,
            mitm,
            rewrite_ctx,
            tunnel_mux: None, // initialized in run() inside the tokio runtime
            coalesce_step_ms: if config.coalesce_step_ms > 0 { config.coalesce_step_ms as u64 } else { 10 },
            coalesce_max_ms: if config.coalesce_max_ms > 0 { config.coalesce_max_ms as u64 } else { 1000 },
        })
    }

    pub fn fronter(&self) -> Option<Arc<DomainFronter>> {
        self.fronter.clone()
    }
    pub async fn run(
        mut self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        // Initialize TunnelMux inside the runtime (tokio::spawn requires it).
        if self.rewrite_ctx.mode == Mode::Full {
            if let Some(f) = self.fronter.as_ref() {
                self.tunnel_mux = Some(TunnelMux::start(f.clone(), self.coalesce_step_ms, self.coalesce_max_ms));
            }
        }

        let http_addr = format!("{}:{}", self.host, self.port);
        let socks_addr = format!("{}:{}", self.host, self.socks5_port);
        let http_listener = TcpListener::bind(&http_addr).await?;
        let socks_listener = TcpListener::bind(&socks_addr).await?;
        tracing::warn!(
            "Listening HTTP   on {} — set your browser HTTP proxy to this address.",
            http_addr
        );
        tracing::warn!(
            "Listening SOCKS5 on {} — xray / Telegram / app-level SOCKS5 clients use this.",
            socks_addr
        );
        // Pre-warm the outbound connection pool so the user's first request
        // doesn't pay a fresh TLS handshake to Google edge. Best-effort;
        // failures are logged and ignored. Skipped in `direct` mode —
        // there is no fronter to warm.
        //
        // Sized to roughly match a browser's parallel-connection burst at
        // startup. The previous fixed `3` was fine for a single deployment
        // but left requests 4-10 of the opening burst paying a cold TLS
        // handshake each (~300ms). Scaling with deployment count gives
        // multi-account configs a proportionally warmer pool, capped so
        // single-deployment users don't hammer Google edge unnecessarily.
        if let Some(warm_fronter) = self.fronter.clone() {
            let n = warm_fronter.num_scripts().clamp(6, 16);
            tokio::spawn(async move {
                warm_fronter.warm(n).await;
            });
        }

        // Apps Script container keepalive. `warm()` above keeps the TCP
        // pool warm at startup, but the V8 container behind UrlFetchApp
        // goes cold after ~5min idle and costs 1-3s to wake. A periodic
        // HEAD ping prevents the cold-start lag on the first request
        // after a quiet pause (most visible as YouTube player stalls).
        // Skipped in direct mode for the same reason as warm —
        // there's no fronter to ping.
        //
        // The handle is captured (not fire-and-forget) so the shutdown
        // arm of the select! below can abort it. Without that, hitting
        // Stop in the UI would leave the keepalive holding an
        // Arc<DomainFronter> on stale config and pinging Apps Script
        // every 240s — same class of bug that issue #99 hit for the
        // accept loops.
        let keepalive_task = if let Some(keepalive_fronter) = self.fronter.clone() {
            tokio::spawn(async move {
                keepalive_fronter.run_keepalive().await;
            })
        } else {
            tokio::spawn(async move { std::future::pending::<()>().await })
        };

        // Background pool refill: keeps at least POOL_MIN ready TLS
        // connections so acquire() never pays a cold handshake.
        let refill_task = if let Some(refill_fronter) = self.fronter.clone() {
            tokio::spawn(async move {
                refill_fronter.run_pool_refill().await;
            })
        } else {
            tokio::spawn(async move { std::future::pending::<()>().await })
        };

        let stats_task = if let Some(stats_fronter) = self.fronter.clone() {
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let s = stats_fronter.snapshot_stats();
                    if s.relay_calls > 0 || s.cache_hits > 0 {
                        tracing::info!("{}", s.fmt_line());
                    }
                }
            })
        } else {
            tokio::spawn(async move { std::future::pending::<()>().await })
        };

        let http_fronter = self.fronter.clone();
        let http_mitm = self.mitm.clone();
        let http_ctx = self.rewrite_ctx.clone();
        let http_mux = self.tunnel_mux.clone();
        let mut http_task = tokio::spawn(async move {
            let mut fd_exhaust_count: u64 = 0;
            // Track every per-client child task in a JoinSet so that when
            // this accept task is aborted on shutdown, dropping the JoinSet
            // aborts the children too. Previously children were bare
            // `tokio::spawn(...)` handles with no ownership — aborting the
            // parent accept loop stopped taking new connections but left
            // in-flight ones running with the OLD config. That manifested
            // as "hitting Stop in the UI doesn't actually stop anything
            // already running" (issue #99) and as "changing auth_key and
            // Start doesn't take effect for domains with a live
            // keep-alive" because the old DomainFronter stayed alive
            // inside those child tasks.
            let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            loop {
                // Opportunistic reap so completed children don't pile up
                // memory on long-running proxies.
                while children.try_join_next().is_some() {}

                let (sock, peer) = match http_listener.accept().await {
                    Ok(x) => {
                        fd_exhaust_count = 0;
                        x
                    }
                    Err(e) => {
                        accept_backoff("http", &e, &mut fd_exhaust_count).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let fronter = http_fronter.clone();
                let mitm = http_mitm.clone();
                let rewrite_ctx = http_ctx.clone();
                let mux = http_mux.clone();
                children.spawn(async move {
                    if let Err(e) = handle_http_client(sock, fronter, mitm, rewrite_ctx, mux).await
                    {
                        tracing::debug!("http client {} closed: {}", peer, e);
                    }
                });
            }
        });

        let socks_fronter = self.fronter.clone();
        let socks_mitm = self.mitm.clone();
        let socks_ctx = self.rewrite_ctx.clone();
        let socks_mux = self.tunnel_mux.clone();
        let mut socks_task = tokio::spawn(async move {
            let mut fd_exhaust_count: u64 = 0;
            // Same pattern as http_task above — JoinSet so shutdown
            // drops in-flight SOCKS5 clients instead of leaving them to
            // keep running on the stale config.
            let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            loop {
                while children.try_join_next().is_some() {}

                let (sock, peer) = match socks_listener.accept().await {
                    Ok(x) => {
                        fd_exhaust_count = 0;
                        x
                    }
                    Err(e) => {
                        accept_backoff("socks", &e, &mut fd_exhaust_count).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let fronter = socks_fronter.clone();
                let mitm = socks_mitm.clone();
                let rewrite_ctx = socks_ctx.clone();
                let mux = socks_mux.clone();
                children.spawn(async move {
                    if let Err(e) =
                        handle_socks5_client(sock, fronter, mitm, rewrite_ctx, mux).await
                    {
                        tracing::debug!("socks client {} closed: {}", peer, e);
                    }
                });
            }
        });

        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                tracing::info!("Shutdown signal received, stopping listeners");
                stats_task.abort();
                keepalive_task.abort();
                refill_task.abort();
                http_task.abort();
                socks_task.abort();
            }
            _ = &mut http_task => {}
            _ = &mut socks_task => {}
        }

        Ok(())
    }
}

/// Back-off helper for the accept() loop.
///
/// Motivated by issue #18: when the process hits its file-descriptor limit
/// (EMFILE — `No file descriptors available`), `accept()` returns that
/// error synchronously and is immediately ready to fire again. The old
/// loop just `continue`'d, producing a wall of identical ERROR lines
/// thousands per second and starving the tokio runtime of CPU that
/// existing connections would have used to drain and close.
///
/// Two things this does right:
///   1. Sleeps when `EMFILE` / `ENFILE` are seen, proportional to how long
///      the problem has been going on (exponential-ish, capped at 2s).
///      Gives existing connections a chance to finish and free fds.
///   2. Rate-limits the log line: first occurrence logs a full warning
///      with fix instructions, subsequent ones log once per 100 errors
///      so the log doesn't fill up.
async fn accept_backoff(kind: &str, err: &std::io::Error, count: &mut u64) {
    let is_fd_limit = matches!(
        err.raw_os_error(),
        Some(libc_emfile) if libc_emfile == 24 || libc_emfile == 23
    );

    *count = count.saturating_add(1);

    if is_fd_limit {
        if *count == 1 {
            tracing::warn!(
                "accept ({}) hit RLIMIT_NOFILE: {}. Backing off. Raise the fd limit: \
                 `ulimit -n 65536` before starting, or (OpenWRT) use the shipped procd \
                 init which sets nofile=16384. The listener will keep retrying.",
                kind,
                err
            );
        } else if *count % 100 == 0 {
            tracing::warn!(
                "accept ({}) still fd-limited after {} retries. Current connections \
                 need to finish before we can accept new ones.",
                kind,
                *count
            );
        }
        // Back off exponentially-ish up to 2s. First hit: 50ms, 10th hit:
        // ~500ms, 50th+: 2s cap.
        let backoff_ms = (50u64 * (*count).min(40)).min(2000);
        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
    } else {
        // Transient non-EMFILE error (e.g. ECONNABORTED from a client that
        // went away during the handshake). One-line log, short sleep to
        // avoid a tight loop in case it repeats.
        tracing::error!("accept ({}): {}", kind, err);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

async fn handle_http_client(
    mut sock: TcpStream,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    let (head, leftover) = match read_http_head(&mut sock).await? {
        HeadReadResult::Got { head, leftover } => (head, leftover),
        HeadReadResult::Closed => return Ok(()),
        HeadReadResult::Oversized => {
            // Reply with 431 instead of just dropping the socket so the
            // browser shows a real error rather than retrying the same
            // oversized request in a loop.
            tracing::warn!(
                "request head exceeds {} bytes — refusing with 431",
                MAX_HEADER_BYTES
            );
            let _ = sock
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
                      Connection: close\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
            let _ = sock.flush().await;
            return Ok(());
        }
    };

    let (method, target, _version, _headers) = parse_request_head(&head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target);
        // Mirror the SOCKS5 short-circuit: if the tunnel-node just failed
        // this (host, port) with unreachable, return 502 immediately rather
        // than acknowledging the CONNECT and blowing tunnel quota on a
        // guaranteed retry. See `TunnelMux::is_unreachable` for context.
        if let Some(ref mux) = tunnel_mux {
            if mux.is_unreachable(&host, port) {
                tracing::info!("CONNECT {}:{} (negative-cached, refusing)", host, port);
                let _ = sock
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = sock.flush().await;
                return Ok(());
            }
        }
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        sock.flush().await?;
        dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx, tunnel_mux).await
    } else {
        // Plain HTTP proxy request (e.g. `GET http://…`).
        //
        // apps_script mode: relay through the Apps Script fronter (which
        // is the whole point of the relay).
        //
        // direct mode: no fronter exists, so passthrough as raw TCP.
        // Same contract as `dispatch_tunnel` honors for CONNECT in
        // direct mode — anything not on the Google edge / not in a
        // configured fronting_group is forwarded direct (or via
        // `upstream_socks5`) so the user's browser still works while
        // they finish setting up Apps Script. Issue: typing a bare
        // `http://example.com` URL used to return a 502 here even
        // though `https://example.com` (CONNECT) worked fine.
        match fronter {
            Some(f) => do_plain_http(sock, &head, &leftover, f).await,
            None => do_plain_http_passthrough(sock, &head, &leftover, &rewrite_ctx).await,
        }
    }
}

// ---------- SOCKS5 ----------

async fn handle_socks5_client(
    mut sock: TcpStream,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    // RFC 1928 handshake: VER=5, NMETHODS, METHODS...
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    // Only "no auth" (0x00) is supported.
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    sock.write_all(&[0x05, 0x00]).await?;

    // Request: VER=5, CMD, RSV=0, ATYP, DST.ADDR, DST.PORT
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    let cmd = req[1];
    if cmd != 0x01 && cmd != 0x03 {
        // CONNECT and UDP ASSOCIATE only.
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let atyp = req[3];
    let host: String = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            sock.read_exact(&mut ip).await?;
            let addr = std::net::Ipv6Addr::from(ip);
            addr.to_string()
        }
        _ => {
            sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    if cmd == 0x03 {
        tracing::info!("SOCKS5 UDP ASSOCIATE requested for {}:{}", host, port);
        return handle_socks5_udp_associate(sock, rewrite_ctx, tunnel_mux).await;
    }

    // Negative-cache short-circuit: if the tunnel-node just failed to reach
    // this exact (host, port) with `Network is unreachable` / `No route to
    // host`, reply 0x04 (Host unreachable) immediately. Saves a 1.5–2s tunnel
    // round-trip on guaranteed-failing targets — the IPv6 probe retry loop
    // is the main offender on devices without IPv6.
    if let Some(ref mux) = tunnel_mux {
        if mux.is_unreachable(&host, port) {
            tracing::info!("SOCKS5 CONNECT -> {}:{} (negative-cached, refusing)", host, port);
            sock.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            sock.flush().await?;
            return Ok(());
        }
    }

    tracing::info!("SOCKS5 CONNECT -> {}:{}", host, port);

    // Success reply with zeroed BND.
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    sock.flush().await?;

    dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx, tunnel_mux).await
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SocksUdpTarget {
    host: String,
    port: u16,
    atyp: u8,
    addr: Vec<u8>,
}

/// Per-target relay session state shared between the dispatch loop and
/// the per-session task. The dispatch loop pushes uplink datagrams via
/// `uplink`; the task drains the upstream and serializes both directions
/// onto a single tunnel-mux call at a time. `sid` is held here so the
/// dispatch teardown path can issue close_session for any task it has
/// to abort mid-await.
struct UdpRelaySession {
    sid: String,
    uplink: mpsc::Sender<Bytes>,
}

/// All per-ASSOCIATE UDP relay state behind a single mutex so insertion
/// order, the live-session map, and per-task self-removal can all stay
/// consistent. Wrapping each separately invited a slow leak: the
/// previous design's `insertion_order` deque was only pruned on
/// overflow eviction, so a long-lived ASSOCIATE that opened many
/// short-lived sessions accumulated dead `SocksUdpTarget` entries.
struct UdpRelayState {
    sessions: HashMap<SocksUdpTarget, UdpRelaySession>,
    /// Insertion-order log for FIFO eviction. NOT a real LRU — repeated
    /// uplinks to a hot session do not move it to the back. We keep it
    /// in lockstep with `sessions` (insert appends; remove scans and
    /// erases the matching entry — O(N) but N ≤ 256).
    order: VecDeque<SocksUdpTarget>,
}

impl UdpRelayState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get_uplink(&self, target: &SocksUdpTarget) -> Option<mpsc::Sender<Bytes>> {
        self.sessions.get(target).map(|s| s.uplink.clone())
    }

    fn insert(&mut self, target: SocksUdpTarget, session: UdpRelaySession) {
        self.order.push_back(target.clone());
        self.sessions.insert(target, session);
    }

    fn remove(&mut self, target: &SocksUdpTarget) {
        if let Some(pos) = self.order.iter().position(|t| t == target) {
            self.order.remove(pos);
        }
        self.sessions.remove(target);
    }

    /// Pop the oldest session entries until `sessions.len() < cap`.
    /// Stale `order` entries (already removed by self-cleanup on a
    /// task's natural exit) are quietly skipped.
    fn evict_until_under(&mut self, cap: usize) -> Vec<SocksUdpTarget> {
        let mut evicted = Vec::new();
        while self.sessions.len() >= cap {
            let Some(victim) = self.order.pop_front() else {
                break;
            };
            if self.sessions.remove(&victim).is_some() {
                evicted.push(victim);
            }
        }
        evicted
    }

    /// Snapshot live sids for the teardown close_session sweep. We
    /// take a copy (not a drain) so the caller can decide whether to
    /// also clear the map.
    fn live_sids(&self) -> Vec<String> {
        self.sessions.values().map(|s| s.sid.clone()).collect()
    }

    fn clear(&mut self) {
        self.sessions.clear();
        self.order.clear();
    }
}

/// SOCKS5 UDP request frame: 4-byte header + atyp-specific address + 2-byte
/// port + payload. DOMAIN atyp uses a 1-byte length prefix + up to 255
/// bytes, so the largest header is `4 + 1 + 255 + 2 = 262`. Round to 300
/// for safety; payload itself can be a full 64 KB datagram.
const SOCKS5_UDP_RECV_BUF_BYTES: usize = 65535 + 300;

/// Bound on per-session uplink queue depth. UDP is lossy by design — if
/// the per-session task can't keep up, drop the newest datagram (caller
/// uses `try_send`) instead of stalling the whole UDP relay loop.
const UDP_UPLINK_QUEUE: usize = 64;

/// Initial poll spacing when a session is idle. Tunnel-node already
/// long-polls each empty `udp_data` for up to 5 s, so this is a
/// client-side floor — bursts of upstream packets reset back to this.
const UDP_INITIAL_POLL_DELAY: Duration = Duration::from_millis(500);

/// Cap on the exponential backoff for an idle session. After this many
/// seconds of zero traffic in either direction, polls happen at most
/// once per `UDP_MAX_POLL_DELAY` plus the tunnel-node long-poll window —
/// so an idle UDP destination costs roughly one batch slot every 35 s.
const UDP_MAX_POLL_DELAY: Duration = Duration::from_secs(30);

/// Cap on simultaneous UDP relay sessions per SOCKS5 ASSOCIATE. STUN
/// candidate gathering and DNS fanout produce dozens of distinct
/// targets; an abusive or runaway client could produce thousands.
/// 256 is generous for legitimate use and bounds tunnel-node UDP
/// sessions a single ASSOCIATE can hold open.
///
/// Eviction policy is FIFO by insertion time, not true LRU — repeated
/// uplinks to a hot session do not move it to the back. Real LRU
/// would need a touch on every uplink (extra lock acquisition per
/// datagram); the long-tail of dead targets gets cleaned up here just
/// fine without that cost, and live targets are typically also recently
/// inserted.
const MAX_UDP_SESSIONS_PER_ASSOCIATE: usize = 256;

/// Drop UDP datagrams larger than this (pre-base64). Standard MTU is
/// 1500B, jumbo frames are ~9000B; anything above that is either a
/// pathologically fragmented IP datagram or abusive traffic. Each
/// datagram carries ~33% base64 + JSON envelope overhead and consumes
/// Apps Script per-account quota, so a permissive ceiling here matters.
const MAX_UDP_PAYLOAD_BYTES: usize = 9 * 1024;

async fn handle_socks5_udp_associate(
    mut control: TcpStream,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    if rewrite_ctx.mode != Mode::Full {
        tracing::debug!("UDP ASSOCIATE rejected: only full mode supports UDP tunneling");
        write_socks5_reply(&mut control, 0x07, None).await?;
        return Ok(());
    }
    let Some(mux) = tunnel_mux else {
        tracing::debug!("UDP ASSOCIATE rejected: full mode has no tunnel mux");
        write_socks5_reply(&mut control, 0x01, None).await?;
        return Ok(());
    };

    // Per RFC 1928 §6 the UDP relay only accepts datagrams from the
    // SOCKS5 client. We pin the source IP to the control TCP peer up
    // front so a third party on the bind interface can't hijack the
    // session by sending the first datagram. THIS — not the bind IP
    // below — is what actually keeps unauthenticated traffic out.
    let client_peer_ip = control.peer_addr()?.ip();

    // Bind the UDP relay to the same local IP the SOCKS5 client used
    // to reach the control TCP socket. `TcpStream::local_addr()` on an
    // accepted socket returns the concrete terminating address (e.g.
    // 127.0.0.1 for a loopback client, 192.168.1.5 for a LAN client),
    // not the listener's bind specifier — so this naturally tracks the
    // path the client took. Source-IP filtering above is the security
    // boundary; the bind choice is just about reachability.
    let bind_ip = control.local_addr()?.ip();
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    write_socks5_reply(&mut control, 0x00, Some(udp.local_addr()?)).await?;
    tracing::info!(
        "SOCKS5 UDP relay bound on {} for client {}",
        udp.local_addr()?,
        client_peer_ip
    );

    // Fixed reusable recv buffer. We deliberately don't go the
    // `BytesMut::split().freeze()` route here even though `tunnel_loop`
    // does: in TCP the read region IS the payload, but UDP always
    // slices the SOCKS5 header off, so we'd be copying out anyway —
    // and a frozen `Bytes` from the recv buf would refcount-pin the
    // full ~65 KB allocation behind a tiny DNS reply, ballooning
    // memory under bursts. Right-sized `Bytes::copy_from_slice` on
    // accepted payloads keeps retention proportional to actual data.
    let mut recv_buf = vec![0u8; SOCKS5_UDP_RECV_BUF_BYTES];
    let mut control_buf = [0u8; 1];
    let mut client_addr: Option<SocketAddr> = None;
    let state: Arc<Mutex<UdpRelayState>> = Arc::new(Mutex::new(UdpRelayState::new()));
    // Tracking per-target tasks here — instead of bare `tokio::spawn`
    // — lets the teardown path call `abort_all()`, cancelling any
    // in-flight `mux.udp_data` await. Without it, a task mid-poll
    // could keep paying tunnel-node round trips for up to 5 s after
    // the SOCKS5 client went away.
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut oversized_dropped: u64 = 0;
    let mut sessions_evicted: u64 = 0;
    let mut foreign_ip_drops: u64 = 0;

    loop {
        tokio::select! {
            recv = udp.recv_from(&mut recv_buf) => {
                let (n, peer) = match recv {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("udp associate recv failed: {}", e);
                        break;
                    }
                };

                // Source-IP check: anything not from the SOCKS5 client's
                // host is dropped silently.
                if peer.ip() != client_peer_ip {
                    foreign_ip_drops += 1;
                    if foreign_ip_drops == 1 || foreign_ip_drops.is_multiple_of(100) {
                        tracing::debug!(
                            "udp dropped from unauthorized source {}: count={}",
                            peer.ip(),
                            foreign_ip_drops,
                        );
                    }
                    continue;
                }

                // Parse BEFORE port-locking. A malformed datagram from
                // the right IP must not pin client_addr to its source
                // port — otherwise a co-tenant on the bind interface
                // can race one bad packet to DoS the legitimate client
                // (whose real datagram, sent from a different ephemeral
                // port, would then be silently rejected).
                let Some((target, payload_off)) = parse_socks5_udp_packet_offsets(&recv_buf[..n]) else {
                    continue;
                };
                let payload_slice = &recv_buf[payload_off..n];

                // Issue #213: client-side QUIC block. UDP/443 is
                // HTTP/3 — drop the datagram silently so the client
                // stack retries a couple of times and then falls back
                // to TCP/HTTPS, which goes through the regular CONNECT
                // path. Skipping this at the SOCKS5 layer (rather than
                // letting it hit the tunnel-node) avoids paying the
                // 200–500 ms tunnel-node round-trip per dropped QUIC
                // datagram, which would otherwise compound during the
                // 1–3 retries before the browser falls back.
                //
                // Silent drop instead of an explicit error reply: the
                // SOCKS5 UDP wire has no "destination unreachable"
                // datagram — `0x04` only exists in TCP CONNECT replies
                // (RFC 1928 §6). The browser's QUIC stack already has
                // a "no response → fall back" timeout, so silent drop
                // is the contractually correct shape.
                if rewrite_ctx.block_quic && target.port == 443 {
                    tracing::debug!(
                        "udp dropped: block_quic=true, target {}:443",
                        target.host
                    );
                    continue;
                }

                // RFC 1928 §6: lock to the first VALID datagram's source
                // port. Subsequent datagrams must come from the same
                // (ip, port) pair.
                if let Some(existing) = client_addr {
                    if existing != peer {
                        continue;
                    }
                } else {
                    tracing::info!("UDP relay locked to client {}", peer);
                    client_addr = Some(peer);
                }

                // Size guard: drop oversize datagrams before they reach
                // the mux. Each datagram costs ~payload * 1.33 in the
                // batched JSON envelope plus tunnel-node CPU; uncapped,
                // a runaway client can exhaust Apps Script quota.
                if payload_slice.len() > MAX_UDP_PAYLOAD_BYTES {
                    oversized_dropped += 1;
                    if oversized_dropped == 1 || oversized_dropped.is_multiple_of(100) {
                        tracing::debug!(
                            "udp datagram dropped: {} B > {} B (count={})",
                            payload_slice.len(),
                            MAX_UDP_PAYLOAD_BYTES,
                            oversized_dropped,
                        );
                    }
                    continue;
                }

                // Right-sized copy: the queued/in-flight payload owns its
                // own allocation, so the recv buffer can be reused on the
                // next iteration without keeping every queued datagram
                // alive. Sized to the actual payload (≤ MAX_UDP_PAYLOAD_BYTES
                // = 9 KB after the guard above), not the full ~65 KB recv
                // buffer.
                let payload = Bytes::copy_from_slice(payload_slice);

                // Fast path: existing session — push payload onto its
                // bounded uplink queue, drop on overflow (UDP semantics).
                {
                    let st = state.lock().await;
                    if let Some(uplink) = st.get_uplink(&target) {
                        let _ = uplink.try_send(payload);
                        continue;
                    }
                }

                // Cap reached → evict oldest sessions before opening a
                // new one. Each evicted entry drops its uplink Sender,
                // which causes the per-session task to exit its select
                // and tell tunnel-node to close. Any uplink already in
                // that channel is delivered before the task exits.
                {
                    let mut st = state.lock().await;
                    let evicted = st.evict_until_under(MAX_UDP_SESSIONS_PER_ASSOCIATE);
                    for victim in evicted {
                        sessions_evicted += 1;
                        if sessions_evicted == 1 || sessions_evicted.is_multiple_of(50) {
                            tracing::debug!(
                                "udp session cap {} reached; evicted {}:{} (total evicted={})",
                                MAX_UDP_SESSIONS_PER_ASSOCIATE,
                                victim.host,
                                victim.port,
                                sessions_evicted,
                            );
                        }
                    }
                }

                // New target: open via tunnel-node and spawn the per-session
                // task. The first datagram rides the udp_open op so we
                // save one round trip on session establishment.
                let resp = match mux.udp_open(&target.host, target.port, payload).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(
                            "udp open {}:{} failed: {}",
                            target.host, target.port, e
                        );
                        continue;
                    }
                };
                if let Some(ref e) = resp.e {
                    tracing::debug!("udp open {}:{} failed: {}", target.host, target.port, e);
                    continue;
                }
                let Some(sid) = resp.sid.clone() else {
                    tracing::debug!(
                        "udp open {}:{} returned no sid",
                        target.host, target.port
                    );
                    continue;
                };
                send_udp_response_packets(&udp, peer, &target, &resp).await;

                // Tunnel-node may report eof on the open response if the
                // upstream socket died between bind and the first drain
                // (e.g., immediate ICMP unreachable). The session has
                // already been reaped on that side — skip insert/spawn
                // and let the next datagram from the client retry.
                if resp.eof.unwrap_or(false) {
                    tracing::debug!(
                        "udp open {}:{} returned eof; not tracking session",
                        target.host,
                        target.port,
                    );
                    continue;
                }

                let (uplink_tx, uplink_rx) = mpsc::channel::<Bytes>(UDP_UPLINK_QUEUE);
                let task_mux = mux.clone();
                let task_udp = udp.clone();
                let task_target = target.clone();
                let task_state = state.clone();
                let task_sid = sid.clone();
                tasks.spawn(async move {
                    udp_session_task(
                        task_mux,
                        task_udp,
                        task_sid,
                        task_target.clone(),
                        peer,
                        uplink_rx,
                    )
                    .await;
                    // Natural-exit cleanup (eof / mux error / channel
                    // close): remove from shared state so a future
                    // packet to the same target opens a fresh session,
                    // and so insertion_order doesn't leak. Skipped on
                    // teardown since abort_all cancels this await point.
                    task_state.lock().await.remove(&task_target);
                });

                state.lock().await.insert(
                    target,
                    UdpRelaySession {
                        sid,
                        uplink: uplink_tx,
                    },
                );
            }
            read = control.read(&mut control_buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }

    // Teardown. Snapshot live sids first; they're authoritative for
    // which tunnel-node sessions still exist. Then clear state — that
    // drops every uplink Sender, so any task waiting on `recv()` wakes
    // and exits naturally. Finally `abort_all` cancels tasks that were
    // mid-`mux.udp_data` await; for those the natural-exit close won't
    // run, so we send close_session here on their behalf.
    let live_sids: Vec<String>;
    {
        let mut st = state.lock().await;
        live_sids = st.live_sids();
        st.clear();
    }
    tasks.abort_all();
    for sid in live_sids {
        mux.close_session(&sid).await;
    }
    Ok(())
}

/// Per-target relay task. Owns one tunnel-node UDP session and shuttles
/// datagrams in both directions through a single in-flight tunnel call
/// at a time. Two cancellation points:
///   * `uplink_rx.recv()` returns `None` when the dispatch loop drops
///     the matching `Sender` (SOCKS5 client gone, or session evicted).
///   * `mux.udp_data` returns eof / error when the tunnel-node session
///     is reaped or the target is unreachable.
async fn udp_session_task(
    mux: Arc<TunnelMux>,
    udp: Arc<UdpSocket>,
    sid: String,
    target: SocksUdpTarget,
    client_addr: SocketAddr,
    mut uplink_rx: mpsc::Receiver<Bytes>,
) {
    let mut backoff = UDP_INITIAL_POLL_DELAY;
    loop {
        // `biased;` prefers uplink so an active client doesn't get
        // shadowed by a long sleep. Both branches are cancel-safe.
        let resp = tokio::select! {
            biased;
            uplink = uplink_rx.recv() => {
                let Some(payload) = uplink else { break; };
                // Active uplink — reset the empty-poll backoff so the
                // next inbound poll happens promptly.
                backoff = UDP_INITIAL_POLL_DELAY;
                match mux.udp_data(&sid, payload).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("udp data {} failed: {}", sid, e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(backoff) => {
                match mux.udp_data(&sid, Vec::new()).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("udp poll {} failed: {}", sid, e);
                        break;
                    }
                }
            }
        };
        if resp.e.is_some() || resp.eof.unwrap_or(false) {
            break;
        }
        let got_pkts = resp.pkts.as_ref().map(|p| !p.is_empty()).unwrap_or(false);
        if got_pkts {
            send_udp_response_packets(&udp, client_addr, &target, &resp).await;
            backoff = UDP_INITIAL_POLL_DELAY;
        } else {
            // Empty poll — back off so an idle destination doesn't
            // monopolize batch slots.
            backoff = (backoff * 2).min(UDP_MAX_POLL_DELAY);
        }
    }
    // Be polite even if the session is already gone server-side; the
    // tunnel-node tolerates close on an unknown sid.
    mux.close_session(&sid).await;
}

async fn send_udp_response_packets(
    udp: &UdpSocket,
    client_addr: SocketAddr,
    target: &SocksUdpTarget,
    resp: &crate::domain_fronter::TunnelResponse,
) {
    let packets = match decode_udp_packets(resp) {
        Ok(packets) => packets,
        Err(e) => {
            tracing::debug!("{}", e);
            return;
        }
    };
    for packet in packets {
        let framed = build_socks5_udp_packet(target, &packet);
        if let Err(e) = udp.send_to(&framed, client_addr).await {
            // Errors here mean the local socket can't reach the SOCKS5
            // client (ENETUNREACH, EHOSTDOWN, etc.). Surface at debug
            // so a "my UDP traffic isn't coming back" report has
            // something to grep for; volume is bounded by what we'd
            // have delivered anyway.
            tracing::debug!(
                "udp send to client {} failed for {}:{}: {}",
                client_addr,
                target.host,
                target.port,
                e,
            );
        }
    }
}

async fn write_socks5_reply(
    sock: &mut TcpStream,
    rep: u8,
    addr: Option<SocketAddr>,
) -> std::io::Result<()> {
    let mut out = vec![0x05, rep, 0x00];
    match addr {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            out.push(0x01);
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    sock.write_all(&out).await?;
    sock.flush().await
}

/// Parse the SOCKS5 UDP frame header and return the target plus the byte
/// offset at which the payload starts. Splitting "structure parsing"
/// from "give me a payload slice" lets the recv hot path stay on a
/// fixed reusable `Vec<u8>` buffer and only allocate a right-sized
/// `Bytes::copy_from_slice(&recv_buf[off..n])` for accepted payloads
/// (after the size guard). DO NOT change this back to a zero-copy
/// `Bytes::slice` path: that was tried and reverted because slicing
/// the recv buffer with `bytes` 1.x refcounts the whole ~65 KB
/// allocation, so a queued tiny DNS reply pinned the full datagram-
/// sized buffer until it drained — burst retention regressed by
/// orders of magnitude on UDP-heavy workloads. The thin
/// `parse_socks5_udp_packet` wrapper below keeps existing `&[u8]`
/// callers (tests) working.
fn parse_socks5_udp_packet_offsets(buf: &[u8]) -> Option<(SocksUdpTarget, usize)> {
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return None;
    }
    let atyp = buf[3];
    let mut pos = 4usize;
    let (host, addr) = match atyp {
        0x01 => {
            if buf.len() < pos + 4 + 2 {
                return None;
            }
            let addr = buf[pos..pos + 4].to_vec();
            pos += 4;
            let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            (ip.to_string(), addr)
        }
        0x03 => {
            if buf.len() < pos + 1 {
                return None;
            }
            let len = buf[pos] as usize;
            pos += 1;
            if len == 0 || buf.len() < pos + len + 2 {
                return None;
            }
            let addr = buf[pos..pos + len].to_vec();
            pos += len;
            // Reject non-UTF-8 hostnames at the parser. Lossy decoding
            // would forward U+FFFD into DNS and trigger an opaque
            // NXDOMAIN — failing fast here gives us a clean parse-level
            // drop that the test suite can assert on.
            let host = std::str::from_utf8(&addr).ok()?.to_owned();
            (host, addr)
        }
        0x04 => {
            if buf.len() < pos + 16 + 2 {
                return None;
            }
            let addr = buf[pos..pos + 16].to_vec();
            pos += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr);
            (std::net::Ipv6Addr::from(octets).to_string(), addr)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Some((
        SocksUdpTarget {
            host,
            port,
            atyp,
            addr,
        },
        pos,
    ))
}

fn parse_socks5_udp_packet(buf: &[u8]) -> Option<(SocksUdpTarget, &[u8])> {
    let (target, off) = parse_socks5_udp_packet_offsets(buf)?;
    Some((target, &buf[off..]))
}

fn build_socks5_udp_packet(target: &SocksUdpTarget, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + target.addr.len() + 2 + payload.len() + 1);
    out.extend_from_slice(&[0, 0, 0, target.atyp]);
    match target.atyp {
        0x03 => {
            out.push(target.addr.len() as u8);
            out.extend_from_slice(&target.addr);
        }
        _ => out.extend_from_slice(&target.addr),
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ---------- Smart dispatch (used by both HTTP CONNECT and SOCKS5) ----------

fn should_use_sni_rewrite(
    hosts: &std::collections::HashMap<String, String>,
    host: &str,
    port: u16,
    youtube_via_relay: bool,
    force_mitm_hosts: &[String],
) -> bool {
    // The SNI-rewrite path expects TLS from the client: it accepts inbound
    // TLS, then opens a second TLS connection to the Google edge with a front
    // SNI. Auto-forcing that path for non-TLS ports (for example a SOCKS5
    // CONNECT to google.com:80) makes the proxy wait for a ClientHello that
    // will never arrive.
    //
    // youtube_via_relay=true removes YouTube suffixes from the match so
    // YouTube traffic falls through to the Apps Script relay path instead
    // of the SNI-rewrite tunnel. An explicit hosts override still wins
    // over the config toggle, except for hosts pulled out by
    // `relay_url_patterns` — those need MITM for the per-path matcher
    // even if the user has a hosts override (the override is still used
    // as the upstream IP for the SNI-rewrite forwarder, just not as a
    // CONNECT-tunnel target).
    if port != 443 {
        return false;
    }
    if host_in_force_mitm_list(host, force_mitm_hosts) {
        return false;
    }
    matches_sni_rewrite(host, youtube_via_relay, force_mitm_hosts)
        || hosts_override(hosts, host).is_some()
}

async fn dispatch_tunnel(
    sock: TcpStream,
    host: String,
    port: u16,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    // 0. User-configured passthrough list wins over every other path.
    //    If the host matches `passthrough_hosts`, we raw-TCP it (through
    //    upstream_socks5 if set) and never touch Apps Script, SNI-rewrite,
    //    or MITM. Point: saves Apps Script quota on hosts the user already
    //    has reachability to, and avoids MITM-breaking cert pinning on
    //    hosts the user knows are cert-pinned. Issues #39, #127.
    if matches_passthrough(&host, &rewrite_ctx.passthrough_hosts) {
        let via = rewrite_ctx.upstream_socks5.as_deref();
        tracing::info!(
            "dispatch {}:{} -> raw-tcp ({}) (passthrough_hosts match)",
            host,
            port,
            via.unwrap_or("direct")
        );
        plain_tcp_passthrough(sock, &host, port, via).await;
        return Ok(());
    }

    // 0.4. DoH block. Reject connections to known DoH endpoints so browsers
    //      fall back to system DNS (tun2proxy virtual DNS — instant).
    //      Takes priority over bypass_doh.
    if rewrite_ctx.block_doh
        && port == 443
        && matches_doh_host(&host, &rewrite_ctx.bypass_doh_hosts)
    {
        tracing::info!("dispatch {}:{} -> blocked (block_doh)", host, port);
        drop(sock);
        return Ok(());
    }

    // 0.5. DoH bypass. DNS-over-HTTPS is the dominant per-flow DNS cost
    //      in Full mode (every browser name lookup costs a ~2 s Apps
    //      Script round-trip), and the tunnel adds no privacy beyond
    //      what DoH already provides. Route known DoH hosts directly.
    //      Port-gated to 443 so a non-TLS CONNECT to e.g. `dns.google:80`
    //      doesn't get diverted off-tunnel by accident.
    //      See `DEFAULT_DOH_HOSTS` and config.rs `tunnel_doh`.
    if rewrite_ctx.bypass_doh
        && port == 443
        && matches_doh_host(&host, &rewrite_ctx.bypass_doh_hosts)
    {
        let via = rewrite_ctx.upstream_socks5.as_deref();
        tracing::info!(
            "dispatch {}:{} -> raw-tcp ({}) (doh bypass)",
            host,
            port,
            via.unwrap_or("direct")
        );
        plain_tcp_passthrough(sock, &host, port, via).await;
        return Ok(());
    }

    // 1. Full tunnel mode: ALL traffic goes through the batch multiplexer
    //    (Apps Script → tunnel node → real TCP). No MITM, no cert.
    if rewrite_ctx.mode == Mode::Full {
        let mux = match tunnel_mux {
            Some(m) => m,
            None => {
                tracing::error!(
                    "dispatch {}:{} -> full mode but no tunnel mux (should not happen)",
                    host,
                    port
                );
                return Ok(());
            }
        };
        tracing::info!("dispatch {}:{} -> full tunnel (via batch mux)", host, port);
        crate::tunnel_client::tunnel_connection(sock, &host, port, &mux).await?;
        return Ok(());
    }

    // 2a. User-configured fronting groups (Vercel, Fastly, etc.). Wins
    //     over the built-in Google SNI-rewrite suffix list — if a user
    //     adds e.g. `vercel.com` to a Vercel fronting group, we hit
    //     Vercel's edge with sni=react.dev rather than trying to resolve
    //     it through Google's. Port-gated to 443: SNI-rewrite needs a
    //     real ClientHello and a non-TLS CONNECT to the same hostname
    //     would just hang. Only HTTPS sites are fronted by these CDNs in
    //     practice, so the gate has no false negatives we care about.
    if port == 443 {
        // `Arc::clone` here is refcount-only; we hold it across the
        // await below without keeping `rewrite_ctx` borrowed.
        let group_match =
            match_fronting_group(&host, &rewrite_ctx.fronting_groups).map(Arc::clone);
        if let Some(group) = group_match {
            tracing::info!(
                "dispatch {}:{} -> sni-rewrite tunnel (fronting group '{}', edge {} sni={})",
                host,
                port,
                group.name,
                group.ip,
                group.sni
            );
            return do_sni_rewrite_tunnel_from_tcp(
                sock,
                &host,
                port,
                mitm,
                rewrite_ctx,
                Some(group),
            )
            .await;
        }
    }

    // 2. Explicit hosts override or SNI-rewrite suffix: for HTTPS targets,
    //    use the TLS SNI-rewrite tunnel (skipped in full mode above).
    if should_use_sni_rewrite(
        &rewrite_ctx.hosts,
        &host,
        port,
        rewrite_ctx.youtube_via_relay,
        &rewrite_ctx.force_mitm_hosts,
    ) {
        tracing::info!(
            "dispatch {}:{} -> sni-rewrite tunnel (Google edge direct)",
            host,
            port
        );
        return do_sni_rewrite_tunnel_from_tcp(sock, &host, port, mitm, rewrite_ctx, None).await;
    }

    // 3. direct mode: no Apps Script relay exists. Anything that isn't
    //    SNI-rewrite-matched (Google edge or a configured fronting_group)
    //    gets raw TCP passthrough so the user's browser still works while
    //    they're deploying Code.gs. They'd switch to apps_script mode for
    //    full DPI bypass.
    if rewrite_ctx.mode == Mode::Direct {
        let via = rewrite_ctx.upstream_socks5.as_deref();
        tracing::info!(
            "dispatch {}:{} -> raw-tcp ({}) (direct mode: no relay)",
            host,
            port,
            via.unwrap_or("direct")
        );
        plain_tcp_passthrough(sock, &host, port, via).await;
        return Ok(());
    }

    // From here on we know mode == AppsScript, so `fronter` is Some.
    let fronter = match fronter {
        Some(f) => f,
        None => {
            // Defensive: mode says apps_script but the fronter is missing.
            // Fall back to raw TCP rather than panicking.
            tracing::error!(
                "dispatch {}:{} -> raw-tcp (unexpected: apps_script mode with no fronter)",
                host,
                port
            );
            plain_tcp_passthrough(sock, &host, port, rewrite_ctx.upstream_socks5.as_deref()).await;
            return Ok(());
        }
    };

    // 3. Peek at the first byte to detect TLS vs plain. Time-bounded — if the
    //    client doesn't send anything within 300ms, assume server-first
    //    protocol (SMTP, POP3, FTP banner) and jump straight to plain TCP.
    let mut peek_buf = [0u8; 8];
    let peek_n = match tokio::time::timeout(
        std::time::Duration::from_millis(300),
        sock.peek(&mut peek_buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return Ok(()),
        Err(_) => {
            // Client silent: likely a server-first protocol.
            let via = rewrite_ctx.upstream_socks5.as_deref();
            tracing::info!(
                "dispatch {}:{} -> raw-tcp ({}) (client silent, likely server-first)",
                host,
                port,
                via.unwrap_or("direct")
            );
            plain_tcp_passthrough(sock, &host, port, via).await;
            return Ok(());
        }
    };

    if peek_n >= 1 && peek_buf[0] == 0x16 {
        // Looks like TLS: MITM + relay via Apps Script. Note: upstream_socks5
        // is NOT consulted here by design — HTTPS goes through the Apps Script
        // relay, which is the whole reason mhrv-rs exists. If you want HTTPS
        // to flow through xray, disable mhrv-rs and point your browser at
        // xray directly.
        tracing::info!(
            "dispatch {}:{} -> MITM + Apps Script relay (TLS detected)",
            host,
            port
        );
        run_mitm_then_relay(sock, &host, port, mitm, &fronter, rewrite_ctx.clone()).await;
        return Ok(());
    }

    // 4. Not TLS. If bytes look like HTTP, relay on scheme=http. Otherwise
    //    fall back to plain TCP passthrough.
    if peek_n > 0 && looks_like_http(&peek_buf[..peek_n]) {
        let scheme = if port == 443 { "https" } else { "http" };
        tracing::info!(
            "dispatch {}:{} -> Apps Script relay (plain HTTP, scheme={})",
            host,
            port,
            scheme
        );
        relay_http_stream_raw(sock, &host, port, scheme, &fronter, rewrite_ctx.clone()).await;
        return Ok(());
    }

    let via = rewrite_ctx.upstream_socks5.as_deref();
    tracing::info!(
        "dispatch {}:{} -> raw-tcp ({}) (non-HTTP, non-TLS client payload)",
        host,
        port,
        via.unwrap_or("direct")
    );
    plain_tcp_passthrough(sock, &host, port, via).await;
    Ok(())
}

// ---------- Plain TCP passthrough ----------

async fn plain_tcp_passthrough(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    upstream_socks5: Option<&str>,
) {
    let target_host = host.trim_start_matches('[').trim_end_matches(']');
    // Shorter connect timeout for IP literals (4s vs 10s for hostnames).
    // Ported from upstream Python 7b1812c: when the target is an IP (i.e.
    // a raw Telegram DC, or an IP someone hardcoded), and that route is
    // DPI-dropped, the client speeds up its own DC-rotation / fallback if
    // we fail fast. Ten seconds of "waiting for a dead IP" translates
    // directly into Telegram's 10s-per-DC rotation delay — users see the
    // app sit on "connecting..." for nearly a minute as it walks through
    // DC1, DC2, DC3. At 4s we cut that in roughly half.
    // Hostnames still get 10s because DNS + first-hop TCP genuinely can
    // take that long on flaky links, and the resolver fallbacks already
    // trim the worst case.
    let connect_timeout = if looks_like_ip(target_host) {
        std::time::Duration::from_secs(4)
    } else {
        std::time::Duration::from_secs(10)
    };
    let upstream = if let Some(proxy) = upstream_socks5 {
        match socks5_connect_via(proxy, target_host, port).await {
            Ok(s) => {
                tracing::info!("tcp via upstream-socks5 {} -> {}:{}", proxy, host, port);
                s
            }
            Err(e) => {
                tracing::warn!(
                    "upstream-socks5 {} -> {}:{} failed: {} (falling back to direct)",
                    proxy,
                    host,
                    port,
                    e
                );
                match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port)))
                    .await
                {
                    Ok(Ok(s)) => s,
                    _ => return,
                }
            }
        }
    } else {
        match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port))).await {
            Ok(Ok(s)) => {
                tracing::info!("plain-tcp passthrough -> {}:{}", host, port);
                s
            }
            Ok(Err(e)) => {
                tracing::debug!("plain-tcp connect {}:{} failed: {}", host, port, e);
                return;
            }
            Err(_) => {
                tracing::debug!(
                    "plain-tcp connect {}:{} timeout (likely blocked; client should rotate)",
                    host,
                    port
                );
                return;
            }
        }
    };
    let _ = upstream.set_nodelay(true);
    let (mut ar, mut aw) = sock.split();
    let (mut br, mut bw) = {
        let (r, w) = upstream.into_split();
        (r, w)
    };
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
}

/// Open a TCP stream to `(host, port)` through an upstream SOCKS5 proxy
/// (no-auth only). Returns the connected stream after SOCKS5 negotiation.
async fn socks5_connect_via(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(proxy))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = s.set_nodelay(true);

    // Greeting: VER=5, NMETHODS=1, METHOD=no-auth
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("socks5 greet rejected: {:?}", reply),
        ));
    }

    // CONNECT request: VER=5, CMD=1, RSV=0, ATYP=3 (domain) | 1 (IPv4) | 4 (IPv6)
    let mut req: Vec<u8> = Vec::with_capacity(8 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hostname > 255",
            ));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply header: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("socks5 connect rejected rep=0x{:02x}", head[1]),
        ));
    }
    // Skip BND.ADDR + BND.PORT.
    match head[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut name).await?;
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("socks5 bad ATYP in reply: {}", other),
            ));
        }
    }
    Ok(s)
}

fn looks_like_http(first_bytes: &[u8]) -> bool {
    // Cheap sniff: must start with an ASCII HTTP method token followed by a space.
    for m in [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT ", "TRACE ",
    ] {
        if first_bytes.starts_with(m.as_bytes()) {
            return true;
        }
    }
    false
}

/// Read an HTTP head (request line + headers) up to the first \r\n\r\n.
/// Returns (head_bytes, leftover_after_head). The leftover may contain part
/// of the request body already received.
/// Maximum size of an HTTP request head (request line + all headers).
///
/// Set to match upstream Python's `MAX_HEADER_BYTES` (64 KB,
/// masterking32/MasterHttpRelayVPN constants.py). Real browsers
/// virtually never exceed ~16 KB; anything past 64 KB is either a
/// buggy client or a deliberate slowloris-style header bomb.
/// Previously 1 MB, which let a misbehaving client allocate a lot
/// of memory before failing.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Result of `read_http_head` / `read_http_head_io`.
/// `Oversized` is distinct from other I/O errors so the caller can
/// reply with `431 Request Header Fields Too Large` instead of just
/// dropping the connection (which a browser would silently retry,
/// reproducing the same problem).
enum HeadReadResult {
    Got { head: Vec<u8>, leftover: Vec<u8> },
    Closed,
    Oversized,
}

async fn read_http_head(sock: &mut TcpStream) -> std::io::Result<HeadReadResult> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(HeadReadResult::Closed)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(HeadReadResult::Got { head, leftover });
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(HeadReadResult::Oversized);
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_request_head(head: &[u8]) -> Option<(String, String, String, Vec<(String, String)>)> {
    let s = std::str::from_utf8(head).ok()?;
    let mut lines = s.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if !is_valid_http_method(&method) {
        return None;
    }

    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((method, target, version, headers))
}

fn is_valid_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

// ---------- CONNECT handling ----------

async fn run_mitm_then_relay(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    fronter: &DomainFronter,
    rewrite_ctx: Arc<RewriteCtx>,
) {
    // Peek the TLS ClientHello BEFORE minting the MITM cert. When the client
    // resolves the hostname itself (DoH in Chrome/Firefox) and hands us a raw
    // IP via SOCKS5, the only place the real hostname lives is the SNI. If we
    // mint a cert for the IP, Chrome rejects with ERR_CERT_COMMON_NAME_INVALID
    // — the IP isn't in the cert's SAN. Reading SNI up front and using it as
    // both the cert subject and the upstream Host for the Apps Script relay
    // is what unblocks Cloudflare-fronted sites and any browser on Android
    // where DoH is the default.
    let start = match LazyConfigAcceptor::new(Acceptor::default(), sock).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("TLS ClientHello peek failed for {}: {}", host, e);
            return;
        }
    };

    let sni_hostname = start.client_hello().server_name().map(String::from);

    // Effective host: SNI when present and looks like a hostname (anything
    // other than a bare IPv4 literal — IP SNIs exist for weird setups but
    // minting a cert for them still triggers ERR_CERT_COMMON_NAME_INVALID,
    // so we fall through to the raw host in that case).
    let effective_host: String = match sni_hostname.as_deref() {
        Some(s) if !looks_like_ip(s) && !s.is_empty() => s.to_string(),
        _ => host.to_string(),
    };

    tracing::info!(
        "MITM TLS -> {}:{} (socks_host={}, sni={})",
        effective_host,
        port,
        host,
        sni_hostname.as_deref().unwrap_or("<none>"),
    );

    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(&effective_host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", effective_host, e);
                return;
            }
        }
    };

    let mut tls = match start.into_stream(server_config).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("TLS accept failed for {}: {}", effective_host, e);
            return;
        }
    };

    // Keep-alive loop: read HTTP requests from the decrypted stream. Pass the
    // SNI-derived hostname so the Apps Script relay fetches
    // `https://<real hostname>/path` instead of `https://<raw IP>/path` — the
    // latter would produce an IP-in-Host request that Cloudflare/etc. reject
    // outright.
    loop {
        match handle_mitm_request(
            &mut tls,
            &effective_host,
            port,
            fronter,
            "https",
            &rewrite_ctx,
        )
        .await
        {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("MITM handler error for {}: {}", effective_host, e);
                break;
            }
        }
    }
}

/// True if `s` parses as an IPv4 or IPv6 literal. Used to decide whether
/// a string is a hostname we should mint a MITM leaf cert for — IP SANs
/// need their own cert extension and we don't bother emitting those,
/// so fall back to the SOCKS5-provided target in that case.
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

// ---------- Plain HTTP relay on a raw TCP stream (port 80 targets) ----------

async fn relay_http_stream_raw(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    scheme: &str,
    fronter: &DomainFronter,
    rewrite_ctx: Arc<RewriteCtx>,
) {
    loop {
        match handle_mitm_request(&mut sock, host, port, fronter, scheme, &rewrite_ctx).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("http relay error for {}: {}", host, e);
                break;
            }
        }
    }
}

async fn do_sni_rewrite_tunnel_from_tcp(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    // When Some, overrides the default Google edge target with a
    // user-configured fronting group's (ip, sni). `Arc` so the
    // dispatcher hands us a refcount-only clone — the resolved
    // group also carries the matcher's normalized domain list which
    // we don't need here. None = built-in Google edge path.
    group: Option<Arc<FrontingGroupResolved>>,
) -> std::io::Result<()> {
    let (target_ip, outbound_sni, server_name) = match &group {
        Some(g) => (g.ip.clone(), g.sni.clone(), g.server_name.clone()),
        None => {
            let ip = hosts_override(&rewrite_ctx.hosts, host)
                .map(|s| s.to_string())
                .unwrap_or_else(|| rewrite_ctx.google_ip.clone());
            let sni = rewrite_ctx.front_domain.clone();
            let sn = match ServerName::try_from(sni.clone()) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!("invalid front_domain '{}': {}", sni, e);
                    return Ok(());
                }
            };
            (ip, sni, sn)
        }
    };

    tracing::info!(
        "SNI-rewrite tunnel -> {}:{} via {} (outbound SNI={})",
        host,
        port,
        target_ip,
        outbound_sni
    );

    // Accept browser TLS with a cert we sign for `host`.
    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", host, e);
                return Ok(());
            }
        }
    };
    let inbound = match TlsAcceptor::from(server_config).accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("inbound TLS accept failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Open outbound TLS to google_ip with SNI=front_domain.
    let upstream_tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target_ip.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            s
        }
        Ok(Err(e)) => {
            tracing::debug!("upstream connect failed for {}: {}", host, e);
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("upstream connect timeout for {}", host);
            return Ok(());
        }
    };
    let _ = upstream_tcp.set_nodelay(true);

    let outbound = match rewrite_ctx
        .tls_connector
        .connect(server_name, upstream_tcp)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("outbound TLS connect failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Bridge decrypted bytes between the two TLS streams.
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let (mut or, mut ow) = tokio::io::split(outbound);
    let client_to_server = async { tokio::io::copy(&mut ir, &mut ow).await };
    let server_to_client = async { tokio::io::copy(&mut or, &mut iw).await };
    tokio::select! {
        _ = client_to_server => {}
        _ = server_to_client => {}
    }
    Ok(())
}

/// Build the HTTP/1.1 request bytes the SNI-rewrite forwarder writes
/// upstream. Pure function — pulled out of `forward_via_sni_rewrite_http`
/// so the request-rebuilding logic can be unit-tested directly without
/// standing up a TLS connector.
///
/// Forces `Host` to the real origin (the Google edge dispatches by the
/// inner Host even though the outer SNI is sanitised) and
/// `Connection: close` so the upstream signals end-of-response by
/// closing the TCP socket. That lets us read until EOF without parsing
/// HTTP framing on the response side.
///
/// **Framing-header rewrite**: by the time we run, `read_body` has
/// already decoded any chunked request body into a flat byte buffer.
/// Forwarding the inbound `Transfer-Encoding: chunked` verbatim would
/// leave the upstream waiting forever for chunk markers that aren't in
/// the bytes we send. Strip every framing header (`Transfer-Encoding`,
/// any pre-existing `Content-Length`, the hop-by-hop hints `TE`,
/// `Trailer`, `Upgrade`, plus the connection-management headers
/// `Connection`, `Proxy-Connection`, `Keep-Alive`) and emit a single
/// fresh `Content-Length: <decoded body length>` for any method that
/// can carry a body. The result is a request the upstream can frame
/// unambiguously regardless of how the browser originally framed it.
pub(crate) fn build_sni_forward_request_bytes(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let host_with_port = if port == 443 || port == 80 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    };
    let mut req: Vec<u8> = Vec::with_capacity(512 + body.len());
    req.extend_from_slice(method.as_bytes());
    req.extend_from_slice(b" ");
    req.extend_from_slice(path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\n");
    req.extend_from_slice(b"Host: ");
    req.extend_from_slice(host_with_port.as_bytes());
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(b"Connection: close\r\n");
    // Emit Content-Length whenever we have a body or whenever the method
    // is one that semantically carries a body (POST/PUT/PATCH). For body-
    // less safe methods like GET/HEAD we omit it — adding `Content-Length: 0`
    // is technically valid but some origins read it as "request expects
    // a body" which has caused 400s in the past.
    let needs_content_length = !body.is_empty()
        || method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("PATCH");
    if needs_content_length {
        req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("proxy-connection")
            || k.eq_ignore_ascii_case("keep-alive")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("te")
            || k.eq_ignore_ascii_case("trailer")
            || k.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);
    req
}

/// Forward an HTTP request via the SNI-rewrite trick at the HTTP layer.
///
/// Used by `handle_mitm_request` for hosts that were pulled out of
/// SNI-rewrite by `relay_url_patterns` but whose URL path did NOT match
/// any pattern. Saves the Apps Script quota the per-path filter is
/// designed to recover, while still letting matching paths fall through
/// to the relay.
///
/// Wire mechanics: dial `google_ip:443` (or a `hosts`-overridden IP) with
/// SNI=`front_domain`, then send a literal HTTP/1.1 request whose `Host`
/// header is the *real* origin name. The Google edge dispatches on the
/// inner `Host`, so the response comes from the right backend even though
/// the outer SNI is a sanitised one. `Connection: close` is forced so we
/// can read until EOF and never need to parse `Content-Length` /
/// `Transfer-Encoding` ourselves — and the browser side then sees
/// `Connection: close` and won't pipeline another request on the dead
/// MITM stream.
///
/// Ported from upstream `_forward_via_sni_rewrite` (commit b3b9220).
async fn forward_via_sni_rewrite_http(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    rewrite_ctx: &RewriteCtx,
) -> std::io::Result<Vec<u8>> {
    let target_ip = hosts_override(&rewrite_ctx.hosts, host)
        .map(|s| s.to_string())
        .unwrap_or_else(|| rewrite_ctx.google_ip.clone());
    let sni = rewrite_ctx.front_domain.clone();
    let server_name = ServerName::try_from(sni.clone()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid front_domain '{}': {}", sni, e),
        )
    })?;

    let upstream_tcp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target_ip.as_str(), port)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream connect timeout"))??;
    let _ = upstream_tcp.set_nodelay(true);

    let mut tls = rewrite_ctx
        .tls_connector
        .connect(server_name, upstream_tcp)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("tls: {}", e)))?;

    let req = build_sni_forward_request_bytes(method, host, port, path, headers, body);
    tls.write_all(&req).await?;
    tls.flush().await?;

    // Read response until EOF / ungraceful TLS close. The upstream is
    // `Connection: close`, so EOF is a complete response. UnexpectedEof
    // (rustls's signal for a TCP close without a close_notify alert) is
    // treated the same as a clean EOF — same compromise that
    // `read_http_response` makes.
    //
    // A read timeout means the upstream is hung mid-response and we
    // can't prove what we have is complete. Return an error so the
    // caller falls back to the relay path; serving a truncated
    // response to the browser would silently corrupt it.
    //
    // **Cap is much tighter than the global 200 MB response ceiling**:
    // this code path only runs for hosts in `force_mitm_hosts` AND paths
    // that did NOT match a `relay_url_patterns` entry. With the default
    // pattern set that's "non-`/youtubei/` GETs on `youtube.com`" —
    // realistic responses are HTML pages, JS bundles, and small inline
    // assets, capped at a few MB in practice. Cutting the per-call cap
    // to 32 MB shrinks the memory blast radius under concurrent load on
    // memory-constrained devices (OpenWRT routers, Android) by ~6× vs
    // the original 200 MB, while still leaving comfortable headroom
    // above the realistic max. Streaming the body straight back to the
    // browser would avoid the buffer entirely — see followup TODO; the
    // tighter cap is the cheap memory-pressure defense in the meantime.
    const MAX_RESP_BYTES: usize = 32 * 1024 * 1024;
    let mut response = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let read_res =
            tokio::time::timeout(std::time::Duration::from_secs(30), tls.read(&mut buf)).await;
        match read_res {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > MAX_RESP_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "sni-rewrite forward response exceeded cap",
                    ));
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "sni-rewrite forward read timeout (response may be truncated)",
                ));
            }
        }
    }
    if response.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "sni-rewrite forward got empty response",
        ));
    }
    Ok(response)
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn parse_host_port(target: &str) -> (String, u16) {
    if let Some((h, p)) = target.rsplit_once(':') {
        let port: u16 = p.parse().unwrap_or(443);
        (h.to_string(), port)
    } else {
        (target.to_string(), 443)
    }
}

async fn handle_mitm_request<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    fronter: &DomainFronter,
    scheme: &str,
    rewrite_ctx: &Arc<RewriteCtx>,
) -> std::io::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (head, leftover) = match read_http_head_io(stream).await? {
        HeadReadResult::Got { head, leftover } => (head, leftover),
        HeadReadResult::Closed => return Ok(false),
        HeadReadResult::Oversized => {
            // Inside MITM: same reasoning as the plaintext path. Return
            // 431 over the decrypted stream so the browser surfaces a
            // real error to the user instead of looping a connection
            // reset, which was the symptom upstream caught (Apps Script
            // ate malformed JSON when truncated header blocks were
            // forwarded blindly).
            tracing::warn!(
                "MITM header block exceeds {} bytes — closing ({}:{})",
                MAX_HEADER_BYTES,
                host,
                port
            );
            let _ = stream
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
                      Connection: close\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
            let _ = stream.flush().await;
            return Ok(false);
        }
    };

    let (method, path, _version, headers) = match parse_request_head(&head) {
        Some(v) => v,
        None => return Ok(false),
    };

    let body = read_body(stream, &leftover, &headers).await?;

    // ── Per-host URL fix-ups ──────────────────────────────────────────
    // x.com's GraphQL endpoints concatenate three huge JSON blobs into
    // the query string: `?variables=<json>&features=<json>&fieldToggles=<json>`.
    // The combined URL regularly exceeds Apps Script's URL length limit
    // (Apps Script returns "بیش از حد مجاز: طول نشانی وب URLFetch" /
    // "URLFetch URL length exceeded"). The `variables=` portion alone
    // is enough for x.com to serve the timeline — `features` /
    // `fieldToggles` are client-capability hints it tolerates being
    // absent. Truncating at the first `&` after `?variables=` ships a
    // working request that fits under the limit. Ported from upstream
    // Python 2d959d4 (p0u1ya's fix). Issue #64.
    //
    // Host matcher: browsers actually hit `www.x.com` (and sometimes
    // `api.x.com`), not bare `x.com`. The original check only matched
    // `x.com` exactly, so real traffic flew past the rewrite until
    // pourya-p's log in #64 showed the real Host header. Match every
    // subdomain of x.com here.
    let host_lower = host.to_ascii_lowercase();
    let is_x_com = host_lower == "x.com" || host_lower.ends_with(".x.com") || host_lower == "twitter.com" || host_lower.ends_with(".twitter.com");
    let path = if is_x_com && path.starts_with("/i/api/graphql/") && path.contains("?variables=") {
        match path.split_once('&') {
            Some((short, _)) => {
                tracing::debug!(
                    "x.com graphql URL truncated: {} chars -> {}",
                    path.len(),
                    short.len()
                );
                short.to_string()
            }
            None => path,
        }
    } else {
        path
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let url = if port == default_port {
        format!("{}://{}{}", scheme, host, path)
    } else {
        format!("{}://{}:{}{}", scheme, host, port, path)
    };

    // Short-circuit CORS preflight at the MITM boundary.
    //
    // Apps Script's UrlFetchApp.fetch() only accepts methods {get, delete,
    // patch, post, put} — OPTIONS triggers the Swedish-localized
    // "Ett attribut med ogiltigt värde har angetts: method" error, which
    // kills every XHR/fetch preflight and is the root cause of "JS doesn't
    // load" on sites like Discord, Yahoo finance widgets, etc.
    //
    // Answering the preflight ourselves is safe: we already terminate the
    // TLS for the browser (we minted the cert), so it's legitimate for us
    // to own the wire-level conversation. CORS is a browser-side
    // protection, not a network security one — responding 204 with
    // permissive ACL headers just tells the browser the *subsequent* real
    // request is allowed, and that real request still goes through the
    // Apps Script relay where the origin server gets final say on content.
    // The origin header is echoed (not "*") so Credentials-true responses
    // stay spec-valid.
    if method.eq_ignore_ascii_case("OPTIONS") {
        tracing::info!("preflight 204 {} (short-circuit, no relay)", url);
        let origin = header_value(&headers, "origin").unwrap_or("*");
        let acrm = header_value(&headers, "access-control-request-method")
            .unwrap_or("GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
        let acrh = header_value(&headers, "access-control-request-headers").unwrap_or("*");
        let resp = format!(
            "HTTP/1.1 204 No Content\r\n\
             Access-Control-Allow-Origin: {origin}\r\n\
             Access-Control-Allow-Methods: {acrm}\r\n\
             Access-Control-Allow-Headers: {acrh}\r\n\
             Access-Control-Allow-Credentials: true\r\n\
             Access-Control-Max-Age: 86400\r\n\
             Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        let connection_close = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
        return Ok(!connection_close);
    }

    // Path-level relay routing (b3b9220). Hosts that were pulled out of
    // SNI-rewrite by `relay_url_patterns` are MITM'd so we can inspect the
    // URL: paths that match a pattern go through the Apps Script relay
    // (this is what fixes YouTube SafeSearch / live-stream gating on
    // `/youtubei/`); every other path on the same host is forwarded over
    // a fresh SNI-rewrite TLS connection, saving the relay quota that the
    // pre-port `youtube_via_relay = true` knob would have spent on every
    // static asset. A failed forward falls through to the relay path so a
    // network blip on the Google edge doesn't take the host offline.
    //
    // **Safe-method gate**: the forwarder is only used for GET/HEAD/OPTIONS.
    // The fallback-on-error semantics combined with non-idempotent methods
    // (POST/PUT/PATCH/DELETE) would be a replay hazard: write_all may
    // succeed against the upstream and then a read timeout / cap-exceeded
    // / late TLS error fires fallback, which sends the same side-effecting
    // request through Apps Script. POSTs to non-`/youtubei/` paths on
    // youtube.com are uncommon, and the quota cost of routing them via
    // relay is acceptable next to the correctness risk of duplicating
    // them. Mirrors the same gate on idempotency that
    // `relay_parallel_range` and `parallel_relay` apply elsewhere.
    //
    // **Exit-node-full gate**: when `exit_node.mode = "full"` is active
    // (commit 88b2767), every relay request is required to route through
    // the second-hop exit node. The forwarder dials the Google edge
    // directly with no awareness of the exit node, so taking it for any
    // path — even ones that look "skippable" by the path filter —
    // silently bypasses the exit node and breaks the documented "every
    // URL routes through the exit node" contract on
    // `DomainFronter::exit_node_matches`. With the gate active,
    // user-supplied `relay_url_patterns` still pull their hosts out of
    // SNI-rewrite (so MITM runs); the path-vs-forwarder split just
    // collapses, and every path on those hosts goes to relay → exit
    // node. The default `youtube.com/youtubei/` is suppressed earlier
    // in `ResolvedRouting` (because `youtube_via_relay_effective` is
    // true here), so this only affects user-supplied entries — which
    // is the case the reviewer flagged.
    let method_is_safe_for_forwarder = method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("OPTIONS");
    if scheme == "https"
        && port == 443
        && method_is_safe_for_forwarder
        && !rewrite_ctx.exit_node_full_mode_active
        && !rewrite_ctx.relay_url_patterns.is_empty()
        && host_in_force_mitm_list(host, &rewrite_ctx.force_mitm_hosts)
        && !url_matches_relay_pattern(&url, &rewrite_ctx.relay_url_patterns)
    {
        // All forwarder log lines use `target = "yt_forwarder"` so users
        // diagnosing #977-style reports can `RUST_LOG=yt_forwarder=info`
        // (or =debug) and see exactly which requests took the fast path,
        // their sizes, and their latencies — without grepping the
        // general-relay info-spam.
        tracing::info!(target: "yt_forwarder", "dispatch {} {}", method, url);
        let t0 = std::time::Instant::now();
        match forward_via_sni_rewrite_http(
            &method,
            host,
            port,
            &path,
            &headers,
            &body,
            rewrite_ctx,
        )
        .await
        {
            Ok(response_bytes) => {
                let response_len = response_bytes.len();
                let elapsed_ms = t0.elapsed().as_millis();
                tracing::info!(
                    target: "yt_forwarder",
                    "ok {} {} bytes={} latency_ms={}",
                    method, url, response_len, elapsed_ms,
                );
                // Record BEFORE the downstream write: we want
                // `forwarder_calls` to reflect "the path filter
                // produced an upstream response," not "the browser
                // received it." A client disconnect during write would
                // otherwise leave the metric understating fast-path
                // utilisation — we'd see only relay-path traffic in
                // stats while the forwarder was actually doing work.
                fronter.record_forwarder_call(response_len as u64);
                stream.write_all(&response_bytes).await?;
                stream.flush().await?;
                // The forwarder always sets `Connection: close` on the
                // upstream request, so the upstream side has closed by
                // the time we get here — propagate that to the inbound
                // browser side too. The browser will reopen for the next
                // request (and we'll mint a new MITM session).
                return Ok(false);
            }
            Err(e) => {
                tracing::warn!(
                    target: "yt_forwarder",
                    "error {} {}: {} (latency_ms={}) — falling back to relay",
                    method, url, e, t0.elapsed().as_millis(),
                );
                // `record_forwarder_error` only describes what just
                // happened to the fast path. Whether the relay-path
                // fallback below recovers the request is reflected in
                // `relay_calls` / `relay_failures`; combining those
                // with `forwarder_errors` lets diagnostics tell apart
                // "fast path missed but request served" from "request
                // failed end-to-end."
                fronter.record_forwarder_error();
                // fall through
            }
        }
    }

    tracing::info!("relay {} {}", method, url);

    // For GETs without a body, take the range-parallel path — probes
    // with `Range: bytes=0-<chunk>`, and if the origin supports ranges,
    // fetches the rest in parallel 256 KB chunks. This is what lets
    // YouTube video streaming / gvt1.com Chrome-updates / big static
    // files not stall waiting on one ~2s Apps Script call per MB.
    // Anything with a body (POST/PUT/PATCH) goes through the normal
    // relay path — range semantics on mutating requests are undefined
    // and would break form submissions.
    let response = if method.eq_ignore_ascii_case("GET") && body.is_empty() {
        fronter
            .relay_parallel_range(&method, &url, &headers, &body)
            .await
    } else {
        fronter.relay(&method, &url, &headers, &body).await
    };

    // CORS response-header injection. The preflight short-circuit
    // above handles `OPTIONS`, but the *actual* fetch that follows
    // also needs CORS-compliant headers on the way back, or the
    // browser drops the response and the JS layer sees a CORS
    // failure. Apps Script's `UrlFetchApp.fetch()` preserves the
    // origin server's response headers inconsistently — sometimes the
    // destination returns `Access-Control-Allow-Origin: *` (which is
    // incompatible with `Allow-Credentials: true`), sometimes omits
    // ACL headers entirely. The visible symptom on YouTube is comments
    // not loading and the "restricted" gate firing on cross-origin
    // XHR responses that the browser rejected before the JS handler
    // could even read them. Idea credit: ThisIsDara/mhr-cfw-go.
    //
    // Only injects when the request had an `Origin` header — non-CORS
    // requests (top-level navigation, plain image fetches) don't need
    // the headers and adding them would be noise. The relay response
    // is otherwise byte-identical, so this never affects non-browser
    // clients (curl, wget, app-level HTTP clients).
    let response = if let Some(origin) = header_value(&headers, "origin") {
        inject_cors_response_headers(&response, origin)
    } else {
        response
    };

    stream.write_all(&response).await?;
    stream.flush().await?;

    // Keep-alive unless the client asked to close.
    let connection_close = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
    Ok(!connection_close)
}

async fn read_http_head_io<S>(stream: &mut S) -> std::io::Result<HeadReadResult>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(HeadReadResult::Closed)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(HeadReadResult::Got { head, leftover });
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(HeadReadResult::Oversized);
        }
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Strip any `Access-Control-*` response headers the origin server
/// emitted (or that Apps Script's `UrlFetchApp.fetch()` may have
/// mangled / dropped) and inject a permissive set keyed on the
/// browser's request `Origin`. Returns a new response buffer; never
/// mutates in place.
///
/// The body is preserved byte-for-byte; only the header block before
/// the first `\r\n\r\n` is rewritten. If the response can't be parsed
/// as HTTP/1.x (no header/body separator), it's returned unchanged so
/// edge-case responses (e.g. raw error blobs from upstream) aren't
/// corrupted.
///
/// Why permissive (`Allow-Methods: *`, `Allow-Headers: *`,
/// `Expose-Headers: *`): the browser already pre-cleared the request
/// via the preflight short-circuit (line ~2435), and the relay path
/// doesn't expose anything that wasn't already going to the
/// destination through the user's own MITM trust anchor. The wide
/// permissions only relax browser-side CORS gating; they don't widen
/// the underlying network reach. `Allow-Credentials: true` is
/// echo-only-with-explicit-origin (spec requires it; `*` is invalid
/// alongside credentials) — that's why we echo the request's origin
/// and never use `*`.
fn inject_cors_response_headers(response: &[u8], origin: &str) -> Vec<u8> {
    // Find the header / body separator. If we can't parse the
    // response as HTTP/1.x, hand it back unchanged.
    let sep = b"\r\n\r\n";
    let Some(idx) = response
        .windows(sep.len())
        .position(|w| w == sep)
    else {
        return response.to_vec();
    };
    let head = &response[..idx];
    let body = &response[idx + sep.len()..];

    // Rebuild the header block, dropping any pre-existing
    // `Access-Control-*` lines so the destination's value can't
    // conflict with ours.
    let head_str = match std::str::from_utf8(head) {
        Ok(s) => s,
        Err(_) => return response.to_vec(),
    };
    let mut out = String::with_capacity(head.len() + 256);
    let mut lines = head_str.split("\r\n");
    if let Some(status) = lines.next() {
        out.push_str(status);
        out.push_str("\r\n");
    }
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("access-control-") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    // Inject our own. `Vary: Origin` tells downstream caches that the
    // response varies per request origin (so CDN-shared caches don't
    // serve one user's CORS-tagged response to a different origin).
    out.push_str("Access-Control-Allow-Origin: ");
    out.push_str(origin);
    out.push_str("\r\n");
    out.push_str("Access-Control-Allow-Credentials: true\r\n");
    out.push_str("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD\r\n");
    out.push_str("Access-Control-Allow-Headers: *\r\n");
    out.push_str("Access-Control-Expose-Headers: *\r\n");
    out.push_str("Vary: Origin\r\n");
    out.push_str("\r\n");

    let mut buf = out.into_bytes();
    buf.extend_from_slice(body);
    buf
}

fn expects_100_continue(headers: &[(String, String)]) -> bool {
    header_value(headers, "expect")
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("100-continue"))
        })
        .unwrap_or(false)
}

fn invalid_body(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

async fn read_body<S>(
    stream: &mut S,
    leftover: &[u8],
    headers: &[(String, String)],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let transfer_encoding = header_value(headers, "transfer-encoding");
    let is_chunked = transfer_encoding
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false);

    let content_length = match header_value(headers, "content-length") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| invalid_body(format!("invalid Content-Length: {}", v)))?,
        ),
        None => None,
    };

    if transfer_encoding.is_some() && !is_chunked {
        return Err(invalid_body(format!(
            "unsupported Transfer-Encoding: {}",
            transfer_encoding.unwrap_or_default()
        )));
    }

    if is_chunked && content_length.is_some() {
        return Err(invalid_body(
            "both Transfer-Encoding: chunked and Content-Length are present",
        ));
    }

    if expects_100_continue(headers) && (is_chunked || content_length.is_some()) {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        stream.flush().await?;
    }

    if is_chunked {
        return read_chunked_request_body(stream, leftover.to_vec()).await;
    }

    let Some(content_length) = content_length else {
        return Ok(Vec::new());
    };

    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&leftover[..leftover.len().min(content_length)]);
    let mut tmp = [0u8; 8192];
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF mid-body",
            ));
        }
        let need = content_length - body.len();
        body.extend_from_slice(&tmp[..n.min(need)]);
    }
    Ok(body)
}

async fn read_chunked_request_body<S>(stream: &mut S, mut buf: Vec<u8>) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];

    loop {
        let line = read_crlf_line(stream, &mut buf, &mut tmp).await?;
        if line.is_empty() {
            continue;
        }

        let line_str = std::str::from_utf8(&line)
            .map_err(|_| invalid_body("non-utf8 chunk size line"))?
            .trim();
        let size_hex = line_str.split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| invalid_body(format!("bad chunk size '{}'", line_str)))?;

        if size == 0 {
            loop {
                let trailer = read_crlf_line(stream, &mut buf, &mut tmp).await?;
                if trailer.is_empty() {
                    return Ok(out);
                }
            }
        }

        fill_buffer(stream, &mut buf, &mut tmp, size + 2).await?;
        if &buf[size..size + 2] != b"\r\n" {
            return Err(invalid_body("chunk missing trailing CRLF"));
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(idx) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..idx].to_vec();
            buf.drain(..idx + 2);
            return Ok(line);
        }
        let n = stream.read(tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn fill_buffer<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
    want: usize,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    while buf.len() < want {
        let n = stream.read(tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

// ---------- Plain HTTP proxy ----------

async fn do_plain_http(
    mut sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    fronter: Arc<DomainFronter>,
) -> std::io::Result<()> {
    let (method, target, _version, headers) = parse_request_head(head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    let body = read_body(&mut sock, leftover, &headers).await?;

    // Browser sends `GET http://example.com/path HTTP/1.1` on plain proxy.
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.clone()
    } else {
        // Fallback: stitch Host header with path.
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        format!("http://{}{}", host, target)
    };

    tracing::info!("HTTP {} {}", method, url);
    // Plain HTTP proxy path — same range-parallel strategy as the
    // MITM-HTTPS path above. Large downloads on port 80 (package
    // mirrors, video poster streams, etc.) need the same acceleration
    // or the relay stalls per-chunk.
    let response = if method.eq_ignore_ascii_case("GET") && body.is_empty() {
        fronter
            .relay_parallel_range(&method, &url, &headers, &body)
            .await
    } else {
        fronter.relay(&method, &url, &headers, &body).await
    };
    sock.write_all(&response).await?;
    sock.flush().await?;
    Ok(())
}

/// `direct` mode plain-HTTP passthrough. The CONNECT path already
/// falls through to raw TCP for hosts outside the SNI-rewrite set in
/// `direct`; this is the same idea for the `GET http://…` proxy form
/// so a bare `http://example.com` typed in the address bar doesn't 502.
///
/// We rewrite the absolute-form request URI (`GET http://host/path`) to
/// origin form (`GET /path`), strip hop-by-hop headers, force
/// `Connection: close` so a keep-alive client can't pipeline a request
/// to a different host onto our spliced socket, then dial the origin
/// (honoring `upstream_socks5` if set) and splice both directions.
async fn do_plain_http_passthrough(
    mut sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    rewrite_ctx: &RewriteCtx,
) -> std::io::Result<()> {
    let (method, target, version, headers) = match parse_request_head(head) {
        Some(v) => v,
        None => return Ok(()),
    };

    let (host, port, path) = match resolve_plain_http_target(&target, &headers) {
        Some(v) => v,
        None => {
            tracing::debug!("plain-http passthrough: cannot parse target {}", target);
            return Ok(());
        }
    };

    tracing::info!(
        "dispatch http {}:{} -> raw-tcp ({}) (direct mode: no relay)",
        host,
        port,
        rewrite_ctx.upstream_socks5.as_deref().unwrap_or("direct"),
    );

    // Rewrite request line to origin form and drop hop-by-hop headers.
    let mut rewritten = Vec::with_capacity(head.len());
    rewritten.extend_from_slice(method.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(version.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    for (k, v) in &headers {
        let kl = k.to_ascii_lowercase();
        if kl == "proxy-connection" || kl == "connection" || kl == "keep-alive" {
            continue;
        }
        rewritten.extend_from_slice(k.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(v.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");

    let target_host = host.trim_start_matches('[').trim_end_matches(']');
    let connect_timeout = if looks_like_ip(target_host) {
        std::time::Duration::from_secs(4)
    } else {
        std::time::Duration::from_secs(10)
    };
    let upstream = if let Some(proxy) = rewrite_ctx.upstream_socks5.as_deref() {
        match socks5_connect_via(proxy, target_host, port).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "upstream-socks5 {} -> {}:{} failed: {} (falling back to direct)",
                    proxy,
                    host,
                    port,
                    e
                );
                match tokio::time::timeout(
                    connect_timeout,
                    TcpStream::connect((target_host, port)),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    _ => return Ok(()),
                }
            }
        }
    } else {
        match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port))).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!("plain-http connect {}:{} failed: {}", host, port, e);
                return Ok(());
            }
            Err(_) => {
                tracing::debug!("plain-http connect {}:{} timeout", host, port);
                return Ok(());
            }
        }
    };
    let _ = upstream.set_nodelay(true);

    let (mut ar, mut aw) = sock.split();
    let (mut br, mut bw) = upstream.into_split();
    bw.write_all(&rewritten).await?;
    if !leftover.is_empty() {
        bw.write_all(leftover).await?;
    }
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
    Ok(())
}

/// Parse the target of a plain-HTTP proxy request line into
/// `(host, port, origin-form-path)`. Browsers send absolute form
/// (`http://host[:port]/path`); we also accept the origin-form
/// fallback (`/path` with a `Host:` header) for transparent-proxy
/// clients. `https://` is accepted defensively, though browsers route
/// HTTPS through CONNECT and shouldn't hit this path.
fn resolve_plain_http_target(
    target: &str,
    headers: &[(String, String)],
) -> Option<(String, u16, String)> {
    let (rest, default_port) = if let Some(r) = target.strip_prefix("http://") {
        (r, 80u16)
    } else if let Some(r) = target.strip_prefix("https://") {
        (r, 443u16)
    } else if target.starts_with('/') {
        let host_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())?;
        let (host, port) = split_authority(host_header, 80);
        return Some((host, port, target.to_string()));
    } else {
        return None;
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = split_authority(authority, default_port);
    Some((host, port, path.to_string()))
}

/// Split an `authority` (`host[:port]`, with optional IPv6 brackets)
/// into a `(host, port)` pair, defaulting the port when absent.
fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    // Bare IPv6 (multiple colons, no brackets) — `rsplit_once(':')`
    // would otherwise mangle `::1` into `(":", 1)`. Take the whole
    // string as the host and use the default port.
    let colons = authority.bytes().filter(|&b| b == b':').count();
    if colons > 1 && !authority.starts_with('[') {
        return (authority.to_string(), default_port);
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (authority.to_string(), default_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn resolve_plain_http_target_parses_absolute_form() {
        let h = headers(&[]);
        let (host, port, path) =
            resolve_plain_http_target("http://example.com/", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");

        let (host, port, path) =
            resolve_plain_http_target("http://example.com:8080/foo?x=1", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo?x=1");

        let (host, port, path) =
            resolve_plain_http_target("http://example.com", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn resolve_plain_http_target_falls_back_to_host_header() {
        let h = headers(&[("Host", "example.com:8080")]);
        let (host, port, path) = resolve_plain_http_target("/foo", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo");
    }

    #[test]
    fn resolve_plain_http_target_rejects_bare_authority() {
        // No scheme, doesn't start with `/` — not something we can route.
        assert!(resolve_plain_http_target("example.com", &headers(&[])).is_none());
        assert!(resolve_plain_http_target("http://", &headers(&[])).is_none());
    }

    #[test]
    fn split_authority_handles_ports_and_ipv6() {
        assert_eq!(
            split_authority("example.com", 80),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            split_authority("example.com:8080", 80),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            split_authority("[::1]:8080", 80),
            ("[::1]".to_string(), 8080)
        );
        // Bare IPv6 without brackets — keep the whole string as the host
        // and use the default port instead of mis-splitting on a colon.
        assert_eq!(split_authority("::1", 80), ("::1".to_string(), 80));
    }

    #[test]
    fn socks5_udp_domain_packet_round_trips() {
        let mut raw = vec![0, 0, 0, 0x03, 11];
        raw.extend_from_slice(b"example.com");
        raw.extend_from_slice(&3478u16.to_be_bytes());
        raw.extend_from_slice(b"hello");

        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 3478);
        assert_eq!(payload, b"hello");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[test]
    fn socks5_udp_rejects_fragmented_packets() {
        let raw = [0, 0, 1, 0x01, 127, 0, 0, 1, 0x13, 0x8a, b'x'];
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_rejects_non_utf8_domain() {
        // Lone continuation byte (0x80) — not valid UTF-8. Lossy decode
        // would forward U+FFFD into DNS; strict parse should reject so
        // we fail fast instead of issuing a doomed lookup.
        let raw = [0, 0, 0, 0x03, 1, 0x80, 0, 80];
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_rejects_truncated_inputs() {
        // Header alone is not enough.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01]).is_none());
        // IPv4 with truncated address bytes (need 4 octets).
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01, 127, 0, 0]).is_none());
        // IPv4 with no port.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01, 127, 0, 0, 1]).is_none());
        // DOMAIN with zero-length.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x03, 0, 0, 80]).is_none());
        // DOMAIN with length exceeding remaining buffer.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x03, 5, b'a', b'b']).is_none());
        // Unknown atyp.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x09, 1, 2, 3, 4]).is_none());
        // IPv6 with truncated address.
        let raw = [0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 11 bytes < 16
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_ipv4_round_trips() {
        let mut raw = vec![0, 0, 0, 0x01, 1, 2, 3, 4];
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.extend_from_slice(b"\x00\x01");

        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "1.2.3.4");
        assert_eq!(target.port, 53);
        assert_eq!(payload, b"\x00\x01");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[test]
    fn socks5_udp_ipv6_round_trips() {
        let mut raw = vec![0, 0, 0, 0x04];
        raw.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        raw.extend_from_slice(&443u16.to_be_bytes());
        raw.extend_from_slice(b"q");
        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, 443);
        assert_eq!(payload, b"q");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_decodes_chunked_request() {
        let (mut client, mut server) = duplex(1024);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"llo\r\n6\r\n world\r\n0\r\nFoo: bar\r\n\r\n")
                .await
                .unwrap();
        });

        let body = read_body(
            &mut server,
            b"5\r\nhe",
            &headers(&[("Transfer-Encoding", "chunked")]),
        )
        .await
        .unwrap();

        writer.await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_sends_100_continue_before_waiting_for_body() {
        let (mut client, mut server) = duplex(1024);
        let client_task = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut tmp = [0u8; 64];
            loop {
                let n = client.read(&mut tmp).await.unwrap();
                assert!(n > 0, "proxy closed before sending 100 Continue");
                got.extend_from_slice(&tmp[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert_eq!(got, b"HTTP/1.1 100 Continue\r\n\r\n");
            client.write_all(b"hello").await.unwrap();
        });

        let body = read_body(
            &mut server,
            &[],
            &headers(&[("Content-Length", "5"), ("Expect", "100-continue")]),
        )
        .await
        .unwrap();

        client_task.await.unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn sni_rewrite_is_only_for_port_443() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("example.com".to_string(), "1.2.3.4".to_string());
        let no_force: Vec<String> = vec![];

        assert!(should_use_sni_rewrite(&hosts, "google.com", 443, false, &no_force));
        assert!(!should_use_sni_rewrite(&hosts, "google.com", 80, false, &no_force));
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.example.com",
            443,
            false,
            &no_force,
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.example.com",
            80,
            false,
            &no_force,
        ));
    }

    #[test]
    fn youtube_via_relay_routes_youtube_through_relay_path() {
        // Issue #102 + #275. When youtube_via_relay=true:
        //   - YouTube API + HTML hosts (where Restricted Mode lives)
        //     opt out of SNI rewrite so they go through the relay.
        //   - YouTube image / video / channel-asset CDNs STAY on SNI
        //     rewrite — Restricted Mode isn't enforced on those, and
        //     routing video chunks through Apps Script burns quota
        //     and risks the 6-min execution cap. Pre-#275 ytimg.com
        //     was incorrectly carved out alongside the API surfaces.
        //   - Non-YouTube Google suffixes are unaffected by the flag.
        let hosts = std::collections::HashMap::new();
        let no_force: Vec<String> = vec![];

        // Default behaviour (flag off): everything in the SNI pool
        // rewrites including all YouTube assets.
        assert!(should_use_sni_rewrite(&hosts, "www.youtube.com", 443, false, &no_force));
        assert!(should_use_sni_rewrite(&hosts, "i.ytimg.com", 443, false, &no_force));
        assert!(should_use_sni_rewrite(&hosts, "youtu.be", 443, false, &no_force));
        assert!(should_use_sni_rewrite(&hosts, "www.google.com", 443, false, &no_force));
        assert!(should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            false,
            &no_force,
        ));

        // googlevideo.com is INTENTIONALLY NOT in SNI_REWRITE_SUFFIXES
        // — see the long note at the top of the SNI list. v1.7.4 tried
        // adding it; reverted in v1.7.6 after user reports of total
        // YouTube breakage. If the project ever ships an EVA-edge-IP
        // config knob, this assertion can flip. Until then, video
        // chunks correctly fall through to the Apps Script relay path
        // and this assertion guards against a regression.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "rr1---sn-abc.googlevideo.com",
            443,
            false,
            &no_force,
        ));

        // Flag on: only the API + HTML hosts opt out.
        assert!(!should_use_sni_rewrite(&hosts, "www.youtube.com", 443, true, &no_force));
        assert!(!should_use_sni_rewrite(&hosts, "youtu.be", 443, true, &no_force));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube-nocookie.com",
            443,
            true,
            &no_force,
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            true,
            &no_force,
        ));

        // Flag on: image / channel-asset CDNs STAY on SNI rewrite. Pre-#275
        // ytimg.com was incorrectly carved out alongside the API surfaces.
        // googlevideo.com still goes through the relay path (not in the
        // SNI list at all — see note above the SNI_REWRITE_SUFFIXES
        // entries) so the same flag-on assertion isn't applicable to it.
        assert!(should_use_sni_rewrite(&hosts, "i.ytimg.com", 443, true, &no_force));
        assert!(should_use_sni_rewrite(&hosts, "yt3.ggpht.com", 443, true, &no_force));

        // Flag on: non-YouTube Google suffixes are unaffected. Note
        // youtubei.googleapis.com (above) is the *carve-out* — the
        // broader googleapis.com suffix is NOT carved out, so e.g.
        // Drive / Calendar / etc. continue to SNI-rewrite.
        assert!(should_use_sni_rewrite(&hosts, "www.google.com", 443, true, &no_force));
        assert!(should_use_sni_rewrite(&hosts, "fonts.gstatic.com", 443, true, &no_force));
        assert!(should_use_sni_rewrite(
            &hosts,
            "drive.googleapis.com",
            443,
            true,
            &no_force,
        ));
    }

    #[test]
    fn hosts_override_beats_youtube_via_relay() {
        // If the user added an explicit hosts override for a YouTube
        // subdomain, it should win — the override is a deliberate
        // user choice, the toggle is a default policy.
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("rr4.googlevideo.com".to_string(), "1.2.3.4".to_string());
        let no_force: Vec<String> = vec![];

        assert!(should_use_sni_rewrite(
            &hosts,
            "rr4.googlevideo.com",
            443,
            true,
            &no_force,
        ));
    }

    #[test]
    fn passthrough_hosts_exact_match() {
        let list = vec!["example.com".to_string(), "banking.local".to_string()];
        assert!(matches_passthrough("example.com", &list));
        assert!(matches_passthrough("banking.local", &list));
        assert!(matches_passthrough("EXAMPLE.COM", &list)); // case-insensitive
        assert!(!matches_passthrough("notexample.com", &list));
        assert!(!matches_passthrough("sub.example.com", &list)); // exact only, not suffix
    }

    #[test]
    fn passthrough_hosts_dot_prefix_is_suffix_match() {
        let list = vec![".internal.example".to_string()];
        assert!(matches_passthrough("internal.example", &list)); // bare parent matches
        assert!(matches_passthrough("a.internal.example", &list));
        assert!(matches_passthrough("a.b.c.internal.example", &list));
        assert!(!matches_passthrough("internal.exampleX", &list));
        assert!(!matches_passthrough("fakeinternal.example", &list));
    }

    #[test]
    fn passthrough_hosts_empty_list_never_matches() {
        let list: Vec<String> = vec![];
        assert!(!matches_passthrough("anything.com", &list));
        assert!(!matches_passthrough("", &list));
    }

    #[test]
    fn inject_cors_response_headers_replaces_existing_acl_with_origin_echo() {
        // Origin server returned `Access-Control-Allow-Origin: *` which
        // browsers reject when paired with `Allow-Credentials: true` (the
        // YouTube comments failure mode). Our injection must strip the
        // wildcard and substitute the request's actual origin so that
        // credentialed requests succeed.
        let response = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: application/json\r\n\
                        Access-Control-Allow-Origin: *\r\n\
                        Access-Control-Allow-Methods: GET\r\n\
                        Content-Length: 12\r\n\
                        \r\n\
                        {\"a\":\"b\"}xx";
        let injected = inject_cors_response_headers(response, "https://www.youtube.com");
        let s = std::str::from_utf8(&injected).unwrap();
        // Original wildcard must be gone.
        assert!(
            !s.contains("Access-Control-Allow-Origin: *"),
            "wildcard origin must be stripped, got: {}",
            s
        );
        // Echoed origin + credentials must be present.
        assert!(s.contains("Access-Control-Allow-Origin: https://www.youtube.com\r\n"));
        assert!(s.contains("Access-Control-Allow-Credentials: true\r\n"));
        // Body preserved byte-for-byte.
        assert!(injected.ends_with(b"{\"a\":\"b\"}xx"));
        // Status line preserved.
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn inject_cors_response_headers_preserves_non_acl_headers() {
        // Non-ACL headers (Content-Type, Set-Cookie, Cache-Control, …)
        // must pass through unchanged. Only `Access-Control-*` lines
        // are stripped.
        let response = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: text/html\r\n\
                        Set-Cookie: a=1\r\n\
                        Cache-Control: max-age=300\r\n\
                        Access-Control-Allow-Origin: https://other.example\r\n\
                        \r\n\
                        body";
        let injected = inject_cors_response_headers(response, "https://www.youtube.com");
        let s = std::str::from_utf8(&injected).unwrap();
        assert!(s.contains("Content-Type: text/html\r\n"));
        assert!(s.contains("Set-Cookie: a=1\r\n"));
        assert!(s.contains("Cache-Control: max-age=300\r\n"));
        // Wrong origin replaced.
        assert!(!s.contains("Access-Control-Allow-Origin: https://other.example\r\n"));
        assert!(s.contains("Access-Control-Allow-Origin: https://www.youtube.com\r\n"));
    }

    #[test]
    fn inject_cors_response_headers_returns_unchanged_when_no_header_terminator() {
        // A response missing the `\r\n\r\n` separator (e.g. raw error
        // blob, truncated upstream) must round-trip unchanged so we
        // don't corrupt non-HTTP/1.x bytes.
        let response = b"not an http response";
        let injected = inject_cors_response_headers(response, "https://x.com");
        assert_eq!(injected.as_slice(), response);
    }

    #[test]
    fn passthrough_hosts_ignores_empty_and_whitespace_entries() {
        let list = vec!["".to_string(), "   ".to_string(), "real.com".to_string()];
        assert!(!matches_passthrough("", &list));
        assert!(matches_passthrough("real.com", &list));
    }

    #[test]
    fn passthrough_hosts_trailing_dot_normalized() {
        // FQDNs sometimes have a trailing dot; both entry-side and host-side
        // trailing dots should be treated as equivalent to the un-dotted form.
        let list = vec!["example.com.".to_string()];
        assert!(matches_passthrough("example.com", &list));
        assert!(matches_passthrough("example.com.", &list));
    }

    #[test]
    fn doh_default_list_exact_matches() {
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("chrome.cloudflare-dns.com", &extra));
        assert!(matches_doh_host("dns.google", &extra));
        assert!(matches_doh_host("dns.quad9.net", &extra));
        assert!(matches_doh_host("doh.opendns.com", &extra));
    }

    #[test]
    fn doh_default_list_case_insensitive_and_trailing_dot() {
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("DNS.GOOGLE", &extra));
        assert!(matches_doh_host("dns.google.", &extra));
    }

    #[test]
    fn doh_default_list_suffix_match_for_tenant_subdomains() {
        // `cloudflare-dns.com` is in the default list — Workers-hosted
        // tenant DoH endpoints sit under it and should match too.
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("tenant.cloudflare-dns.com", &extra));
        // But a substring match must NOT pass: `xcloudflare-dns.com` is
        // a different domain.
        assert!(!matches_doh_host("xcloudflare-dns.com", &extra));
    }

    #[test]
    fn doh_default_list_unrelated_hosts_do_not_match() {
        let extra: Vec<String> = vec![];
        assert!(!matches_doh_host("example.com", &extra));
        assert!(!matches_doh_host("googlevideo.com", &extra));
        assert!(!matches_doh_host("", &extra));
    }

    #[test]
    fn doh_extra_list_extends_default() {
        let extra = vec![".internal-doh.example".to_string(), "doh.acme.test".to_string()];
        // Defaults still match.
        assert!(matches_doh_host("dns.google", &extra));
        // User additions match.
        assert!(matches_doh_host("doh.acme.test", &extra));
        assert!(matches_doh_host("a.b.internal-doh.example", &extra));
        // Unrelated still doesn't match.
        assert!(!matches_doh_host("example.com", &extra));
    }

    #[test]
    fn doh_extra_entries_match_subdomains_without_leading_dot() {
        // Asymmetry footgun guard: user adds `doh.acme.test` and expects
        // `tenant.doh.acme.test` to match too — same as `dns.google`
        // matching `tenant.dns.google` from the default list. Unlike
        // `passthrough_hosts`, DoH extras don't require a leading dot.
        let extra = vec!["doh.acme.test".to_string()];
        assert!(matches_doh_host("doh.acme.test", &extra));
        assert!(matches_doh_host("tenant.doh.acme.test", &extra));
        // But substring overlap must still be rejected.
        assert!(!matches_doh_host("xdoh.acme.test", &extra));
    }

    fn fg(name: &str, sni: &str, domains: &[&str]) -> Arc<FrontingGroupResolved> {
        Arc::new(
            FrontingGroupResolved::from_config(&FrontingGroup {
                name: name.into(),
                ip: "127.0.0.1".into(),
                sni: sni.into(),
                domains: domains.iter().map(|s| s.to_string()).collect(),
            })
            .expect("test fronting group should resolve"),
        )
    }

    #[test]
    fn fronting_group_match_exact_and_suffix() {
        let groups = vec![fg("vercel", "react.dev", &["vercel.com", "nextjs.org"])];
        // Exact.
        assert_eq!(
            match_fronting_group("vercel.com", &groups).map(|g| g.name.as_str()),
            Some("vercel")
        );
        // Suffix.
        assert_eq!(
            match_fronting_group("app.vercel.com", &groups).map(|g| g.name.as_str()),
            Some("vercel")
        );
        // Different member.
        assert_eq!(
            match_fronting_group("docs.nextjs.org", &groups).map(|g| g.name.as_str()),
            Some("vercel")
        );
        // Non-member.
        assert!(match_fronting_group("example.com", &groups).is_none());
        // Substring overlap is NOT a match (xvercel.com isn't *.vercel.com).
        assert!(match_fronting_group("xvercel.com", &groups).is_none());
    }

    #[test]
    fn fronting_group_match_case_and_trailing_dot() {
        let groups = vec![fg("fastly", "www.python.org", &["reddit.com"])];
        assert_eq!(
            match_fronting_group("Reddit.COM", &groups).map(|g| g.name.as_str()),
            Some("fastly")
        );
        assert_eq!(
            match_fronting_group("reddit.com.", &groups).map(|g| g.name.as_str()),
            Some("fastly")
        );
        assert_eq!(
            match_fronting_group("WWW.Reddit.com.", &groups).map(|g| g.name.as_str()),
            Some("fastly")
        );
    }

    #[test]
    fn fronting_group_match_first_wins() {
        // When a host is in two groups, the earlier group is chosen.
        // Lets users put more-specific groups first.
        let groups = vec![
            fg("specific", "a.example", &["api.example.com"]),
            fg("broad", "b.example", &["example.com"]),
        ];
        assert_eq!(
            match_fronting_group("api.example.com", &groups).map(|g| g.name.as_str()),
            Some("specific")
        );
        assert_eq!(
            match_fronting_group("example.com", &groups).map(|g| g.name.as_str()),
            Some("broad")
        );
    }

    #[test]
    fn fronting_group_match_empty_list() {
        let groups: Vec<Arc<FrontingGroupResolved>> = Vec::new();
        assert!(match_fronting_group("vercel.com", &groups).is_none());
    }

    // ── SNI-rewrite forwarder request builder (b3b9220) ──────────────────

    fn parse_request(req: &[u8]) -> (String, Vec<(String, String)>, Vec<u8>) {
        let s = std::str::from_utf8(req).expect("request bytes must be utf-8");
        let mut parts = s.split("\r\n\r\n");
        let head = parts.next().unwrap();
        let body_start = head.len() + 4;
        let body = req[body_start..].to_vec();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap().to_string();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (k, v) = line.split_once(": ").expect("malformed header line");
            headers.push((k.to_string(), v.to_string()));
        }
        (request_line, headers, body)
    }

    fn header_present(headers: &[(String, String)], name: &str) -> bool {
        headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    fn header_get_raw<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn forwarder_request_get_emits_correct_request_line_and_host() {
        let req = build_sni_forward_request_bytes(
            "GET",
            "www.youtube.com",
            443,
            "/watch?v=abc",
            &[("User-Agent".into(), "Mozilla/5.0".into())],
            b"",
        );
        let (line, headers, body) = parse_request(&req);
        assert_eq!(line, "GET /watch?v=abc HTTP/1.1");
        assert_eq!(header_get_raw(&headers, "Host"), Some("www.youtube.com"));
        assert_eq!(header_get_raw(&headers, "Connection"), Some("close"));
        assert_eq!(header_get_raw(&headers, "User-Agent"), Some("Mozilla/5.0"));
        // GET without body must not emit Content-Length.
        assert!(
            !header_present(&headers, "Content-Length"),
            "GET with no body must not emit Content-Length"
        );
        assert!(body.is_empty());
    }

    #[test]
    fn forwarder_request_strips_inbound_chunked_and_sets_fresh_content_length() {
        // `read_body` decodes chunked request bodies before they reach the
        // forwarder, so the Transfer-Encoding header is a lie about the
        // bytes we have. The builder MUST drop it AND any inbound
        // Content-Length, then emit a single fresh Content-Length matching
        // the decoded body length. Otherwise the upstream waits forever
        // for chunk markers that aren't there (or reads the wrong number
        // of bytes).
        let body = b"hello-decoded-body";
        let req = build_sni_forward_request_bytes(
            "POST",
            "example.com",
            443,
            "/api",
            &[
                ("Transfer-Encoding".into(), "chunked".into()),
                ("Content-Length".into(), "999".into()), // stale lie
                ("Content-Type".into(), "application/json".into()),
            ],
            body,
        );
        let (_line, headers, parsed_body) = parse_request(&req);
        assert!(
            !header_present(&headers, "Transfer-Encoding"),
            "Transfer-Encoding must be stripped: {:?}",
            headers
        );
        assert_eq!(
            header_get_raw(&headers, "Content-Length"),
            Some(body.len().to_string().as_str()),
            "Content-Length must reflect actual body length"
        );
        // Make sure there is exactly ONE Content-Length header.
        let cl_count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .count();
        assert_eq!(cl_count, 1, "must emit exactly one Content-Length header");
        // Non-framing headers like Content-Type pass through.
        assert_eq!(
            header_get_raw(&headers, "Content-Type"),
            Some("application/json")
        );
        assert_eq!(parsed_body, body);
    }

    #[test]
    fn forwarder_request_drops_hop_by_hop_and_connection_headers() {
        let req = build_sni_forward_request_bytes(
            "GET",
            "www.youtube.com",
            443,
            "/",
            &[
                ("Connection".into(), "keep-alive".into()),
                ("Proxy-Connection".into(), "keep-alive".into()),
                ("Keep-Alive".into(), "timeout=5".into()),
                ("TE".into(), "trailers".into()),
                ("Trailer".into(), "X-Foo".into()),
                ("Upgrade".into(), "websocket".into()),
                ("Host".into(), "spoofed.example.com".into()), // must be overwritten
                ("Accept".into(), "text/html".into()),
            ],
            b"",
        );
        let (_line, headers, _body) = parse_request(&req);
        // Forced headers we own.
        assert_eq!(header_get_raw(&headers, "Host"), Some("www.youtube.com"));
        assert_eq!(header_get_raw(&headers, "Connection"), Some("close"));
        // None of the inbound copies of the headers we own may pass through.
        let host_count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Host"))
            .count();
        assert_eq!(host_count, 1, "must emit exactly one Host header");
        // Hop-by-hop must be dropped.
        assert!(!header_present(&headers, "Proxy-Connection"));
        assert!(!header_present(&headers, "Keep-Alive"));
        assert!(!header_present(&headers, "TE"));
        assert!(!header_present(&headers, "Trailer"));
        assert!(!header_present(&headers, "Upgrade"));
        // Non-framing pass through.
        assert_eq!(header_get_raw(&headers, "Accept"), Some("text/html"));
    }

    #[test]
    fn forwarder_request_includes_port_in_host_for_nondefault_ports() {
        let req = build_sni_forward_request_bytes(
            "GET",
            "youtube.com",
            8443,
            "/",
            &[],
            b"",
        );
        let (_line, headers, _body) = parse_request(&req);
        assert_eq!(header_get_raw(&headers, "Host"), Some("youtube.com:8443"));
    }

    #[test]
    fn forwarder_request_post_with_empty_body_still_emits_content_length() {
        // POSTs may legitimately have no body, but origins generally
        // expect Content-Length: 0 on a body-bearing method. The
        // get/head/options branch is the one that omits CL.
        let req = build_sni_forward_request_bytes(
            "POST",
            "youtube.com",
            443,
            "/youtubei/v1/no-body",
            &[],
            b"",
        );
        let (_line, headers, _body) = parse_request(&req);
        assert_eq!(header_get_raw(&headers, "Content-Length"), Some("0"));
    }

    // ── normalize_pattern ─────────────────────────────────────────────────

    #[test]
    fn normalize_pattern_strips_scheme_case_insensitively() {
        // The original implementation lowercased AFTER trim_start_matches,
        // so `HTTPS://Foo.com/` slipped through with the scheme intact.
        // Now we lowercase first.
        assert_eq!(
            normalize_pattern("HTTPS://YouTube.com/YouTubei/"),
            "youtube.com/youtubei/"
        );
        assert_eq!(
            normalize_pattern("HTTP://Example.com/api/"),
            "example.com/api/"
        );
        // Bare patterns (no scheme) lower-cased.
        assert_eq!(
            normalize_pattern("YouTube.com/YouTubei/"),
            "youtube.com/youtubei/"
        );
    }

    #[test]
    fn normalize_pattern_trims_trailing_dot_on_host() {
        // FQDN-form host with trailing dot must canonicalise to the same
        // form `extract_host` returns (it trims the dot).
        assert_eq!(
            normalize_pattern("youtube.com./youtubei/"),
            "youtube.com/youtubei/"
        );
        assert_eq!(
            normalize_pattern("https://YouTube.com./api/"),
            "youtube.com/api/"
        );
        // Trailing dot on host-only patterns (no path) too.
        assert_eq!(normalize_pattern("foo.com."), "foo.com");
    }

    #[test]
    fn normalize_pattern_preserves_path_dots() {
        // Only the host component gets its trailing dot stripped — path
        // components keep theirs (a path like `/v1.0/` is legitimate).
        assert_eq!(
            normalize_pattern("youtube.com/v1.0/"),
            "youtube.com/v1.0/"
        );
        assert_eq!(
            normalize_pattern("youtube.com./v1.0/"),
            "youtube.com/v1.0/"
        );
    }

    #[test]
    fn normalize_pattern_handles_whitespace() {
        assert_eq!(
            normalize_pattern("  youtube.com/youtubei/  "),
            "youtube.com/youtubei/"
        );
    }

    // ── host_is_sni_rewrite_capable ──────────────────────────────────────

    #[test]
    fn sni_capable_recognises_google_edge_hosts() {
        // SNI_REWRITE_SUFFIXES coverage check.
        assert!(host_is_sni_rewrite_capable("youtube.com"));
        assert!(host_is_sni_rewrite_capable("www.youtube.com"));
        assert!(host_is_sni_rewrite_capable("studio.youtube.com"));
        assert!(host_is_sni_rewrite_capable("googleapis.com"));
        assert!(host_is_sni_rewrite_capable("youtubei.googleapis.com"));
        assert!(host_is_sni_rewrite_capable("YouTube.COM")); // case insensitive
        assert!(host_is_sni_rewrite_capable("youtube.com.")); // trailing dot
    }

    #[test]
    fn sni_capable_rejects_non_google_hosts() {
        // The whole point of the check: don't let users pull non-Google
        // hosts through the SNI-rewrite forwarder, which would return
        // wrong-origin responses from the Google edge.
        assert!(!host_is_sni_rewrite_capable("evilsite.com"));
        assert!(!host_is_sni_rewrite_capable("googlevideo.com")); // not in list
        assert!(!host_is_sni_rewrite_capable("api.example.com"));
        // Suffix-attack: "x" + matching suffix must not pass.
        assert!(!host_is_sni_rewrite_capable("notyoutube.com"));
        // Empty / pathological input.
        assert!(!host_is_sni_rewrite_capable(""));
    }

    #[test]
    fn resolved_routing_skips_non_sni_capable_user_pattern_hosts() {
        // Direct test of the wrong-origin defense: a user-supplied
        // pattern targeting a non-Google host must NOT add to
        // `force_mitm_hosts`, because the forwarder would dial Google's
        // edge and return a wrong-origin response. The pattern itself
        // is preserved in `relay_url_patterns` so a matching path still
        // routes via relay if the host is reached through the regular
        // TLS-detect → MITM → relay path.
        //
        // Uses `googleapis.com/api/` as the SNI-capable example —
        // intentionally NOT a YT-family host, so the
        // `youtube_via_relay`-driven YT-suppression doesn't drop it.
        // youtube_via_relay is left off here so the SNI-capable filter
        // is the only thing being exercised.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": [
                "evilsite.com/api/",
                "googleapis.com/inner/"
            ]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // Pattern preserved.
        assert!(r
            .relay_url_patterns
            .contains(&"evilsite.com/api/".to_string()));
        assert!(r
            .relay_url_patterns
            .contains(&"googleapis.com/inner/".to_string()));
        // Non-Google host filtered out of force_mitm_hosts.
        assert!(
            !r.force_mitm_hosts.contains(&"evilsite.com".to_string()),
            "evilsite.com must not be force-MITM'd: {:?}",
            r.force_mitm_hosts,
        );
        // Google-edge host kept.
        assert!(r
            .force_mitm_hosts
            .contains(&"googleapis.com".to_string()));
        // And the skip is surfaced for the startup warning.
        assert!(r
            .skipped_force_mitm_hosts
            .contains(&"evilsite.com".to_string()));
    }

    // ── Regression: exit_node.mode=full + user pattern ──────────────────

    #[test]
    fn youtube_via_relay_drops_user_supplied_yt_patterns() {
        // Critical: when youtube_via_relay is on, every YT request goes
        // through the relay via the YOUTUBE_RELAY_HOSTS carve-out, so a
        // user-supplied `youtube.com/youtubei/` pattern is redundant
        // AND harmful — it would re-add youtube.com to force_mitm_hosts
        // and the path filter would then route non-matching paths
        // through `forward_via_sni_rewrite_http`, partially defeating
        // the user's "full YT through relay" opt-in. Dropped at startup
        // with a warning.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "youtube_via_relay": true,
            "relay_url_patterns": [
                "youtube.com/youtubei/",
                "www.youtube.com/watch",
                "googleapis.com/specific-api/"
            ]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // Both YT-host entries dropped; non-YT entry survives.
        assert!(
            !r.relay_url_patterns
                .iter()
                .any(|p| p.starts_with("youtube.com/")),
            "youtube.com/* must be dropped: {:?}",
            r.relay_url_patterns,
        );
        assert!(
            !r.relay_url_patterns
                .iter()
                .any(|p| p.starts_with("www.youtube.com/")),
            "www.youtube.com/* must be dropped: {:?}",
            r.relay_url_patterns,
        );
        assert!(r
            .relay_url_patterns
            .contains(&"googleapis.com/specific-api/".to_string()));
        // youtube.com NOT in force_mitm_hosts (would reactivate the path
        // filter); googleapis.com IS.
        assert!(!r.force_mitm_hosts.contains(&"youtube.com".to_string()));
        assert!(!r.force_mitm_hosts.contains(&"www.youtube.com".to_string()));
        assert!(r
            .force_mitm_hosts
            .contains(&"googleapis.com".to_string()));
        // Suppressed list surfaces both for the startup warning.
        assert!(r
            .suppressed_yt_patterns
            .contains(&"youtube.com/youtubei/".to_string()));
        assert!(r
            .suppressed_yt_patterns
            .contains(&"www.youtube.com/watch".to_string()));
    }

    #[test]
    fn youtube_via_relay_off_keeps_user_supplied_yt_patterns() {
        // Sanity check the inverse: when youtube_via_relay is off, user
        // YT patterns should remain (the path filter is the whole point
        // of relay_url_patterns when YT isn't fully relayed).
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": ["youtube.com/youtubei/v2/"]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r.suppressed_yt_patterns.is_empty());
        // User pattern is in the resolved list (alongside the default).
        assert!(r
            .relay_url_patterns
            .contains(&"youtube.com/youtubei/v2/".to_string()));
        assert!(r.force_mitm_hosts.contains(&"youtube.com".to_string()));
    }

    #[test]
    fn exit_node_full_also_drops_user_supplied_yt_patterns() {
        // Belt-and-suspenders: in exit-node-full mode, the runtime
        // forwarder gate already blocks bypass, but
        // youtube_via_relay_effective is true and the same suppression
        // logic applies. A user-supplied YT pattern would be dropped
        // here too, which is fine — the exit-node-full contract makes
        // it a no-op anyway.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": ["youtube.com/youtubei/"],
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r.youtube_via_relay_effective);
        assert!(r.exit_node_full_mode_active);
        assert!(r
            .suppressed_yt_patterns
            .contains(&"youtube.com/youtubei/".to_string()));
        assert!(!r.force_mitm_hosts.contains(&"youtube.com".to_string()));
    }

    #[test]
    fn host_matches_youtube_relay_one_directional() {
        // Same shape as host_in_force_mitm_list — exact match or
        // dot-anchored subdomain.
        assert!(host_matches_youtube_relay("youtube.com"));
        assert!(host_matches_youtube_relay("www.youtube.com"));
        assert!(host_matches_youtube_relay("studio.youtube.com"));
        assert!(host_matches_youtube_relay("youtu.be"));
        assert!(host_matches_youtube_relay("youtube-nocookie.com"));
        assert!(host_matches_youtube_relay("youtubei.googleapis.com"));
        assert!(host_matches_youtube_relay("v1.youtubei.googleapis.com"));
        // Case-insensitive + trailing dot.
        assert!(host_matches_youtube_relay("YouTube.com"));
        assert!(host_matches_youtube_relay("youtube.com."));
        // Sibling subdomains of the parent SNI suffix don't match.
        assert!(!host_matches_youtube_relay("drive.googleapis.com"));
        // Substring attack must not match.
        assert!(!host_matches_youtube_relay("notyoutube.com"));
        assert!(!host_matches_youtube_relay("youtube.com.evil.test"));
    }

    #[test]
    fn exit_node_full_mode_active_propagates_through_resolved_routing() {
        // The flag must round-trip from config to ResolvedRouting so
        // RewriteCtx can carry it to handle_mitm_request and gate the
        // SNI-HTTP forwarder. Selective-mode exit-nodes don't set it.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r.exit_node_full_mode_active);

        // Same config but in selective mode → flag NOT set.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "selective",
                "hosts": ["chatgpt.com"]
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(!r.exit_node_full_mode_active);
    }

    #[test]
    fn exit_node_full_keeps_user_patterns_for_relay_routing() {
        // Critical correctness invariant: in exit_node.mode=full, a
        // user's `relay_url_patterns` entry must NOT cause non-matching
        // paths on its host to bypass the exit node. Two halves to the
        // contract:
        //   1. The user's pattern host is still pulled into
        //      `force_mitm_hosts` so MITM runs and the in-relay
        //      `exit_node_matches` can route through the second hop.
        //   2. `exit_node_full_mode_active` is true so dispatch knows
        //      to skip the SNI-HTTP forwarder for non-matching paths,
        //      sending them to relay → exit node instead of bypassing
        //      both via the Google edge.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": ["googleapis.com/specific-api/"],
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);

        // The user pattern survives — they want googleapis.com to be
        // MITM'd and routed via relay (which then routes through exit
        // node by the full-mode contract).
        assert_eq!(
            r.relay_url_patterns,
            vec!["googleapis.com/specific-api/".to_string()]
        );
        assert_eq!(r.force_mitm_hosts, vec!["googleapis.com".to_string()]);
        // The default `youtube.com/youtubei/` is correctly suppressed
        // because youtube_via_relay_effective is true via exit-node-full.
        assert!(!r
            .relay_url_patterns
            .iter()
            .any(|p| p.starts_with("youtube.com/youtubei/")));
        // And the runtime gate fires.
        assert!(r.exit_node_full_mode_active);
        assert!(r.youtube_via_relay_effective);
    }

    #[test]
    fn forwarder_dispatch_gate_off_when_exit_node_full() {
        // RewriteCtx-level invariant: with exit_node_full_mode_active,
        // the gate that decides whether to use the forwarder must be
        // observably off — even when every other condition would
        // dispatch through it.
        // Reconstruct the gate logic that lives in handle_mitm_request,
        // since pulling a real RewriteCtx through the test requires an
        // I/O-bound DomainFronter.
        let force_mitm_hosts = vec!["googleapis.com".to_string()];
        let patterns = vec!["googleapis.com/specific-api/".to_string()];
        let url = "https://api.googleapis.com/other-path";
        let host = "api.googleapis.com";
        let port = 443u16;
        let scheme = "https";
        let method = "GET";

        let method_safe = method.eq_ignore_ascii_case("GET")
            || method.eq_ignore_ascii_case("HEAD")
            || method.eq_ignore_ascii_case("OPTIONS");

        // Without the exit-node-full gate, every other condition would
        // dispatch through the forwarder.
        let pre_gate = scheme == "https"
            && port == 443
            && method_safe
            && !patterns.is_empty()
            && host_in_force_mitm_list(host, &force_mitm_hosts)
            && !url_matches_relay_pattern(url, &patterns);
        assert!(pre_gate, "test fixture must reach the forwarder gate");

        // With exit_node_full_mode_active = true, the actual gate is off.
        let exit_node_full_mode_active = true;
        let actual_gate = scheme == "https"
            && port == 443
            && method_safe
            && !exit_node_full_mode_active
            && !patterns.is_empty()
            && host_in_force_mitm_list(host, &force_mitm_hosts)
            && !url_matches_relay_pattern(url, &patterns);
        assert!(
            !actual_gate,
            "exit_node.mode=full must disable the forwarder dispatch even \
             when host/path/method would otherwise route through it",
        );
    }

    // ── Regression: trailing-dot URL hosts ────────────────────────────────

    #[test]
    fn url_matches_relay_pattern_trims_trailing_dot_on_url_host() {
        // `host_in_force_mitm_list` trims trailing dots, so dispatch
        // would force-MITM a `www.youtube.com.` request. Without the
        // matching trim here, the URL-host-vs-pattern-host suffix
        // check failed and `/youtubei/v1/...` would route through the
        // SNI-HTTP forwarder instead of the relay — observable as
        // SafeSearch staying sticky after a system that emits FQDN
        // hostnames (some Linux DNS resolvers, browser DoH paths) hits
        // YouTube.
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com./youtubei/v1/browse",
            &patterns,
        ));
        assert!(url_matches_relay_pattern(
            "https://youtube.com./youtubei/",
            &patterns,
        ));
    }

    #[test]
    fn url_matches_relay_pattern_strips_authority_port() {
        // Same canonicalisation: an authority with `:443` must match
        // pattern hosts that don't include the default port. Otherwise
        // the host-vs-pattern compare fails and the dispatcher treats
        // the URL as non-matching → forwarder dispatch.
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com:443/youtubei/v1/browse",
            &patterns,
        ));
        // Non-default port still match — the URL went through some
        // explicit-port flow; the host part is what matters.
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com:8443/youtubei/v1/browse",
            &patterns,
        ));
    }

    #[test]
    fn dispatch_matchers_agree_under_trailing_dot() {
        // End-to-end check: same input must lead to the same
        // membership decision in both matchers, otherwise the dispatch
        // and pattern-check layers disagree (the symptom the reviewer
        // flagged: host force-MITM'd but URL-pattern check fails).
        let force = vec!["youtube.com".to_string()];
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        for variant in [
            "www.youtube.com",
            "www.youtube.com.",
            "WWW.YouTube.COM",
            "WWW.YouTube.COM.",
        ] {
            assert!(host_in_force_mitm_list(variant, &force), "{}", variant);
            let url = format!("https://{}/youtubei/v1/browse", variant);
            assert!(url_matches_relay_pattern(&url, &patterns), "{}", url);
        }
    }

    // ── fronting_groups precedence ───────────────────────────────────────

    #[test]
    fn fronting_group_overlap_with_relay_pattern_resolves_dispatch_via_group() {
        // Documented precedence: dispatch_tunnel checks fronting_groups
        // BEFORE force_mitm_hosts (steps 2a vs 2 in dispatch_tunnel).
        // A user adding `youtube.com` to a fronting group is making a
        // deliberate "alternate edge for YT" choice; the path filter
        // assumes the Google edge handles the request and would land
        // at the wrong upstream if it ran. The override is intentional;
        // this test pins it so a future refactor doesn't accidentally
        // flip the precedence.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "fronting_groups": [{
                "name": "alt-yt-edge",
                "ip": "203.0.113.10",
                "sni": "react.dev",
                "domains": ["youtube.com"]
            }]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        // ResolvedRouting still includes the default pattern — patterns
        // are mode-gated, not fronting-group-gated. The actual override
        // happens at dispatch time.
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(r
            .relay_url_patterns
            .contains(&"youtube.com/youtubei/".to_string()));

        // Build the resolved fronting group and confirm
        // `match_fronting_group` returns it for the YT host. This is
        // the call dispatch_tunnel uses at step 2a, BEFORE the force-MITM
        // check at step 2 — the YT request never reaches the path filter.
        let group =
            FrontingGroupResolved::from_config(&cfg.fronting_groups[0]).unwrap();
        let groups = vec![Arc::new(group)];
        assert!(match_fronting_group("www.youtube.com", &groups).is_some());
        assert!(match_fronting_group("youtube.com", &groups).is_some());
    }

    #[test]
    fn fronting_group_with_disjoint_domain_does_not_interfere() {
        // Sanity check: a fronting group covering an unrelated host
        // (vercel.com) does not affect the YT path filter. Guards
        // against accidentally widening the precedence rule.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "fronting_groups": [{
                "name": "vercel",
                "ip": "76.76.21.21",
                "sni": "react.dev",
                "domains": ["vercel.com"]
            }]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // YT pattern survives untouched.
        assert!(r
            .relay_url_patterns
            .contains(&"youtube.com/youtubei/".to_string()));

        let group =
            FrontingGroupResolved::from_config(&cfg.fronting_groups[0]).unwrap();
        let groups = vec![Arc::new(group)];
        // YT host doesn't match the unrelated group.
        assert!(match_fronting_group("www.youtube.com", &groups).is_none());
    }

    #[test]
    fn fronting_group_resolve_rejects_invalid_sni() {
        let bad = FrontingGroup {
            name: "bad".into(),
            ip: "127.0.0.1".into(),
            sni: "not a valid hostname".into(),
            domains: vec!["x.com".into()],
        };
        assert!(FrontingGroupResolved::from_config(&bad).is_err());
    }

    #[test]
    fn url_matches_relay_pattern_basic() {
        // Default upstream pattern. Path-anchored — matches the
        // youtubei prefix, NOT a similarly-named query string.
        let patterns = vec!["youtube.com/youtubei/".to_string()];
        assert!(url_matches_relay_pattern(
            "https://www.youtube.com/youtubei/v1/browse",
            &patterns,
        ));
        assert!(url_matches_relay_pattern(
            "https://m.youtube.com/youtubei/v1/player",
            &patterns,
        ));
        // Bare scheme variant
        assert!(url_matches_relay_pattern(
            "http://youtube.com/youtubei/",
            &patterns,
        ));
        // Wrong path on the right host
        assert!(!url_matches_relay_pattern(
            "https://www.youtube.com/watch?v=abc",
            &patterns,
        ));
        // Right path-shape on the wrong host
        assert!(!url_matches_relay_pattern(
            "https://example.com/youtubei/v1",
            &patterns,
        ));
        // Suffix attack — trailing dot on host should not bypass match.
        // (URL parsing strips the trailing dot before reaching here in
        // practice; the matcher is strict on the host segment.)
        assert!(!url_matches_relay_pattern(
            "https://evil-youtube.com/youtubei/",
            &patterns,
        ));
    }

    #[test]
    fn url_matches_relay_pattern_empty_patterns_never_matches() {
        let empty: Vec<String> = vec![];
        assert!(!url_matches_relay_pattern("https://www.youtube.com/", &empty));
    }

    #[test]
    fn host_in_force_mitm_list_is_suffix_anchored() {
        let list = vec!["youtube.com".to_string()];
        assert!(host_in_force_mitm_list("youtube.com", &list));
        assert!(host_in_force_mitm_list("www.youtube.com", &list));
        assert!(host_in_force_mitm_list("m.youtube.com", &list));
        // Strict suffix — trailing-dot trim should still match.
        assert!(host_in_force_mitm_list("youtube.com.", &list));
        // Substring attack must NOT match.
        assert!(!host_in_force_mitm_list("notyoutube.com", &list));
        assert!(!host_in_force_mitm_list("youtube.com.evil.test", &list));
        // Empty list never matches.
        let empty: Vec<String> = vec![];
        assert!(!host_in_force_mitm_list("anything", &empty));
    }

    #[test]
    fn force_mitm_pulls_host_out_of_sni_rewrite() {
        // With `relay_url_patterns: ["youtube.com/youtubei/"]`, the host
        // youtube.com gets pulled out of SNI-rewrite so MITM can run
        // and inspect paths. Other YT-family hosts (ytimg, ggpht) stay
        // on SNI-rewrite — they aren't in the patterns and the user
        // hasn't asked for path-level routing on them.
        let hosts = std::collections::HashMap::new();
        let force = vec!["youtube.com".to_string()];

        // youtube.com itself is force-MITM'd → not SNI-rewrite.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            false,
            &force,
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "m.youtube.com",
            443,
            false,
            &force,
        ));
        // Sibling YT hosts NOT in the force list still SNI-rewrite.
        assert!(should_use_sni_rewrite(
            &hosts,
            "i.ytimg.com",
            443,
            false,
            &force,
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "yt3.ggpht.com",
            443,
            false,
            &force,
        ));
    }

    #[test]
    fn force_mitm_overrides_hosts_override() {
        // If the user has both an explicit hosts override AND a relay_url_patterns
        // entry that pulls the same host out of SNI-rewrite, the pattern wins —
        // we need MITM for the per-path matcher to run. The hosts override is
        // still used as the upstream IP by `forward_via_sni_rewrite_http` /
        // `do_sni_rewrite_tunnel_from_tcp`, just not as a CONNECT-tunnel target.
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("www.youtube.com".to_string(), "1.2.3.4".to_string());
        let force = vec!["youtube.com".to_string()];

        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            false,
            &force,
        ));
    }

    fn make_test_config(mode: &str) -> crate::config::Config {
        let s = format!(
            r#"{{
                "mode": "{mode}",
                "auth_key": "secret-test-secret-test",
                "script_id": "X"
            }}"#,
        );
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn resolved_routing_apps_script_default_prepends_youtubei_pattern() {
        // The default-shipped pattern is `youtube.com/youtubei/`. With no
        // user config and no exit node, apps_script mode should resolve
        // exactly that one pattern and pull `youtube.com` from
        // SNI-rewrite (so MITM can run for path inspection).
        let cfg = make_test_config("apps_script");
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert_eq!(r.relay_url_patterns, vec!["youtube.com/youtubei/".to_string()]);
        assert_eq!(r.force_mitm_hosts, vec!["youtube.com".to_string()]);
        assert!(!r.youtube_via_relay_effective);
        assert!(!r.exit_node_full_mode_active);
    }

    #[test]
    fn resolved_routing_direct_mode_skips_default_pattern() {
        // CRITICAL regression guard. In direct mode there is no
        // Apps Script relay path. The `youtube.com/youtubei/` default
        // would pull `youtube.com` from SNI-rewrite, and the dispatcher
        // would then send YT requests to RAW TCP fallback because nothing
        // would match SNI-rewrite OR Apps Script. Test asserts that
        // direct mode resolves to empty pattern + force-MITM lists.
        let cfg = make_test_config("direct");
        let r = ResolvedRouting::from_config(&cfg, Mode::Direct);
        assert!(
            r.relay_url_patterns.is_empty(),
            "direct mode must not populate relay_url_patterns: {:?}",
            r.relay_url_patterns,
        );
        assert!(
            r.force_mitm_hosts.is_empty(),
            "direct mode must not populate force_mitm_hosts: {:?}",
            r.force_mitm_hosts,
        );
    }

    #[test]
    fn resolved_routing_full_mode_skips_default_pattern() {
        // Mode::Full's dispatcher short-circuits to the tunnel mux
        // before MITM runs, so patterns would never be consulted —
        // resolving them is dead weight. Same gate as direct mode.
        let cfg = make_test_config("full");
        let r = ResolvedRouting::from_config(&cfg, Mode::Full);
        assert!(r.relay_url_patterns.is_empty());
        assert!(r.force_mitm_hosts.is_empty());
    }

    #[test]
    fn resolved_routing_direct_mode_youtube_still_sni_rewrites() {
        // End-to-end check of the direct-mode regression: with the
        // resolved sets empty, `should_use_sni_rewrite` should send
        // www.youtube.com:443 to the SNI-rewrite tunnel, not raw-TCP
        // fallback.
        let cfg = make_test_config("direct");
        let r = ResolvedRouting::from_config(&cfg, Mode::Direct);
        let hosts = std::collections::HashMap::new();
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            r.youtube_via_relay_effective,
            &r.force_mitm_hosts,
        ));
    }

    #[test]
    fn resolved_routing_youtube_via_relay_skips_default_pattern() {
        // When the user explicitly opts in to `youtube_via_relay = true`,
        // YouTube is fully relayed already — the per-path filter is
        // redundant. User extras still resolve, just not the default.
        // The user pattern host MUST be SNI-rewrite-capable to land in
        // `force_mitm_hosts`; here we use `googleapis.com` since it's
        // in `SNI_REWRITE_SUFFIXES`.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "youtube_via_relay": true,
            "relay_url_patterns": ["googleapis.com/api/"]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        // Default `youtube.com/youtubei/` NOT prepended; user entry kept.
        assert_eq!(r.relay_url_patterns, vec!["googleapis.com/api/".to_string()]);
        assert_eq!(r.force_mitm_hosts, vec!["googleapis.com".to_string()]);
        assert!(r.skipped_force_mitm_hosts.is_empty());
        assert!(r.youtube_via_relay_effective);
    }

    #[test]
    fn resolved_routing_exit_node_full_mode_skips_default_pattern() {
        // CRITICAL regression guard. With `exit_node.mode = "full"`
        // and `youtube_via_relay = false`, the prior code prepended
        // `youtube.com/youtubei/` even though the YT-via-relay flag
        // was effectively true. That made non-`/youtubei/` YouTube
        // requests route through `forward_via_sni_rewrite_http`,
        // bypassing `DomainFronter::relay` and with it the exit node
        // — defeating the whole point of full mode. Now the effective
        // flag gates the prepend, and YT goes fully through relay
        // (and thus through the exit node).
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "youtube_via_relay": false,
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(
            r.youtube_via_relay_effective,
            "exit_node.mode=full must imply youtube_via_relay (88b2767)",
        );
        assert!(r.exit_node_full_mode_active);
        assert!(
            r.relay_url_patterns.is_empty(),
            "exit_node.mode=full must NOT prepend default pattern \
             (would bypass exit node for non-/youtubei/ paths): {:?}",
            r.relay_url_patterns,
        );
        assert!(r.force_mitm_hosts.is_empty());
    }

    #[test]
    fn resolved_routing_exit_node_full_in_direct_mode_does_not_imply_yt_relay() {
        // exit_node config is shared across modes but only applies to
        // apps_script. In direct mode there's no relay → no exit node
        // → the OR with exit-node-full must NOT promote
        // youtube_via_relay_effective to true (would be misleading).
        let s = r#"{
            "mode": "direct",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "full"
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::Direct);
        assert!(!r.youtube_via_relay_effective);
        assert!(!r.exit_node_full_mode_active);
        assert!(r.relay_url_patterns.is_empty());
    }

    #[test]
    fn resolved_routing_exit_node_selective_does_not_imply_yt_relay() {
        // Exit-node `selective` (the default) only sends listed hosts
        // through the second hop. YouTube isn't in the typical CF-anti-bot
        // list, and the per-path filter is fine to keep — non-`/youtubei/`
        // YT paths going via SNI-rewrite forward is the win the filter
        // was designed for.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "exit_node": {
                "enabled": true,
                "relay_url": "https://exit.example.com/relay",
                "psk": "shared-psk-1234",
                "mode": "selective",
                "hosts": ["chatgpt.com"]
            }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert!(!r.youtube_via_relay_effective);
        assert!(!r.exit_node_full_mode_active);
        // Default pattern still prepended.
        assert_eq!(r.relay_url_patterns, vec!["youtube.com/youtubei/".to_string()]);
    }

    #[test]
    fn resolved_routing_user_patterns_dedup_against_default() {
        // If a user pastes the default pattern verbatim (or with stray
        // whitespace / scheme), dedup keeps a single entry.
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "secret-test-secret-test",
            "script_id": "X",
            "relay_url_patterns": [
                "https://YouTube.com/YouTubei/",
                "  example.com/api/  "
            ]
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        let r = ResolvedRouting::from_config(&cfg, Mode::AppsScript);
        assert_eq!(
            r.relay_url_patterns,
            vec![
                "youtube.com/youtubei/".to_string(),
                "example.com/api/".to_string(),
            ],
        );
    }

    #[test]
    fn force_mitm_pulls_only_configured_host_and_subdomains() {
        // One-directional suffix match: an entry like
        // `youtubei.googleapis.com` pulls itself and its subdomains, but
        // does NOT pull the parent `googleapis.com` or sibling
        // subdomains. Sibling traffic stays on SNI-rewrite. This is a
        // regression guard against the original bidirectional-match
        // implementation, which pulled parents and made
        // `host_in_force_mitm_list` disagree with `matches_sni_rewrite`.
        let hosts = std::collections::HashMap::new();
        let force = vec!["youtubei.googleapis.com".to_string()];

        // Exact force host: pulled.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            false,
            &force,
        ));
        // Subdomain of the force host: pulled.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "v1.youtubei.googleapis.com",
            443,
            false,
            &force,
        ));
        // Sibling subdomain of the parent: NOT pulled (stays on SNI-rewrite).
        assert!(should_use_sni_rewrite(
            &hosts,
            "drive.googleapis.com",
            443,
            false,
            &force,
        ));
    }

    #[test]
    fn force_mitm_subdomain_does_not_pull_parent_sni_suffix() {
        // Direct test of the asymmetry that motivated dropping the
        // bidirectional clause. force=`studio.youtube.com` must NOT
        // make `www.youtube.com` or bare `youtube.com` pull out of
        // SNI-rewrite — those should still take the SNI-rewrite tunnel
        // (matched via the `youtube.com` entry in SNI_REWRITE_SUFFIXES).
        // Otherwise the dispatch-side `host_in_force_mitm_list` would
        // disagree (no recognition of the parent), and parent-host
        // traffic would be force-MITM'd-then-blindly-relayed instead of
        // taking the fast SNI tunnel.
        let hosts = std::collections::HashMap::new();
        let force = vec!["studio.youtube.com".to_string()];

        // Configured host pulled.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "studio.youtube.com",
            443,
            false,
            &force,
        ));
        // Parent NOT pulled — still SNI-rewrites.
        assert!(should_use_sni_rewrite(
            &hosts,
            "youtube.com",
            443,
            false,
            &force,
        ));
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.youtube.com",
            443,
            false,
            &force,
        ));
        // Matchers must agree on membership of the parent.
        assert!(!host_in_force_mitm_list("youtube.com", &force));
        assert!(!host_in_force_mitm_list("www.youtube.com", &force));
    }
}
