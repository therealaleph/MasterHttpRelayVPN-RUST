//! Apps Script relay client.
//!
//! Opens a TLS connection to the configured Google IP while the TLS SNI is set
//! to `front_domain` (e.g. "www.google.com"). Inside the encrypted stream, HTTP
//! `Host` points to `script.google.com`, and we POST a JSON payload to
//! `/macros/s/{script_id}/exec`. Apps Script performs the actual upstream
//! HTTP fetch server-side and returns a JSON envelope.
//!
//! Multiplexes over HTTP/2 when the relay edge agrees via ALPN; falls back
//! to HTTP/1.1 keep-alive when h2 is refused or fails. Range-parallel
//! downloads are implemented by `relay_parallel_range`.

use std::collections::HashMap;
// AtomicU64 via portable-atomic: native on 64-bit / armv7, spinlock-
// backed on mipsel (MIPS32 has no 64-bit atomic instructions). API
// is identical to std::sync::atomic::AtomicU64 so call sites need
// no other changes.
use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use rand::{thread_rng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use crate::cache::{cache_key, is_cacheable_method, parse_ttl, ResponseCache};
use crate::config::Config;

#[derive(Debug, thiserror::Error)]
pub enum FronterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid dns name: {0}")]
    Dns(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("relay error: {0}")]
    Relay(String),
    #[error("timeout")]
    Timeout,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Wraps another error and tells outer retry/fallback layers
    /// (`do_relay_with_retry`, the exit-node→direct-Apps-Script
    /// fallback in `relay()`) NOT to replay the request. Used when an
    /// h2 attempt failed *after* `send_request` succeeded — the
    /// request may have already reached and been processed by Apps
    /// Script (or the exit node), and replaying via h1 / direct path
    /// would duplicate side effects for non-idempotent methods.
    ///
    /// `Display` is transparent so error messages look identical to
    /// the wrapped variant; tests/observability use `is_retryable()`
    /// and `into_inner()` to introspect.
    #[error(transparent)]
    NonRetryable(Box<FronterError>),
}

impl FronterError {
    /// True if outer retry/fallback layers may safely re-issue the
    /// request. False for `NonRetryable(_)` — those errors signal
    /// "request may have been sent; do not duplicate."
    pub fn is_retryable(&self) -> bool {
        !matches!(self, FronterError::NonRetryable(_))
    }

    /// Strip the `NonRetryable` wrapper, returning the underlying
    /// error. Useful for surfacing the original message after the
    /// retry/fallback policy has already done its job.
    pub fn into_inner(self) -> FronterError {
        match self {
            FronterError::NonRetryable(inner) => *inner,
            other => other,
        }
    }
}

type PooledStream = TlsStream<TcpStream>;
const POOL_TTL_SECS: u64 = 60;
const POOL_MIN: usize = 8;
const POOL_REFILL_INTERVAL_SECS: u64 = 5;
const POOL_MAX: usize = 80;
const REQUEST_TIMEOUT_SECS: u64 = 25;
const RANGE_PARALLEL_CHUNK_BYTES: u64 = 256 * 1024;
/// HTTP/2 connection lifetime before we proactively reopen. Apps Script's
/// edge has been observed to send GOAWAY at ~10 min anyway, so we cycle
/// at 9 min to do an orderly reconnect on our schedule rather than
/// letting an in-flight stream race a server-initiated close.
const H2_CONN_TTL_SECS: u64 = 540;
/// Bound on the h2 ready/back-pressure phase only. `SendRequest::ready()`
/// awaits a free slot under the server's `MAX_CONCURRENT_STREAMS`. A
/// stall here means the connection is overloaded (or dead at the
/// muxer level) but no stream has been opened yet — RequestSent::No,
/// safe to fall back to h1 without duplication risk. Kept short
/// (5 s) so a saturated conn doesn't burn the caller's whole budget.
///
/// The post-send phase (response headers + body drain) uses the
/// caller-supplied `response_deadline` instead — see
/// `h2_round_trip`. This way a slow but legitimate Apps Script call
/// isn't cut off at an arbitrary fixed cap, and Full-mode batches can
/// honor the user's `request_timeout_secs` setting.
const H2_READY_TIMEOUT_SECS: u64 = 5;
/// Default response-phase deadline used by `relay_uncoalesced` callers
/// (the Apps-Script direct path). Sized to be just under the outer
/// `REQUEST_TIMEOUT_SECS` (25 s) so an h2 timeout still leaves a few
/// seconds of outer budget for an h1 fallback round-trip when the
/// caller chose to retry.
const H2_RESPONSE_DEADLINE_DEFAULT_SECS: u64 = 20;
/// Bound on the TCP connect + TLS handshake + h2 handshake phase. A
/// blackholed `connect_host:443` previously stalled `ensure_h2` until
/// the outer 25 s timeout fired (returning 504 without ever falling
/// back). With this bound, a slow open trips after 8 s and the caller
/// drops to h1 with ~17 s of outer budget to spare.
const H2_OPEN_TIMEOUT_SECS: u64 = 8;
/// After an h2 open failure, suppress further open attempts for this
/// long. Prevents every concurrent caller during an h2 outage from
/// paying its own full handshake-timeout cost in turn.
const H2_OPEN_FAILURE_BACKOFF_SECS: u64 = 15;
/// Cadence for Apps Script container keepalive pings. Apps Script
/// containers go cold after ~5min idle and cost 1-3s on the first
/// request to wake back up — most painful on YouTube / streaming where
/// the first chunk after a quiet pause stalls the player.
const H1_KEEPALIVE_INTERVAL_SECS: u64 = 240;
// Keep synthetic range stitching bounded. Without this, a buggy or hostile
// origin can advertise `Content-Range: bytes 0-1/<huge>` and make us build a
// massive range plan or preallocate an enormous response buffer.
const MAX_STITCHED_RANGE_BYTES: u64 = 64 * 1024 * 1024;

struct PoolEntry {
    stream: PooledStream,
    created: Instant,
}

/// Single shared HTTP/2 connection to the Google edge. One TCP/TLS
/// socket carries up to ~100 concurrent streams (server's
/// `MAX_CONCURRENT_STREAMS` setting); each relay request takes a clone
/// of the `SendRequest` handle and opens its own stream. Cheaper than
/// the legacy per-request socket pool — no head-of-line blocking when
/// a single Apps Script call stalls.
///
/// `generation` is monotonic per fronter and lets `poison_h2_if_gen`
/// avoid the race where task A's stale failure clears task B's
/// freshly-reopened healthy cell.
struct H2Cell {
    send: h2::client::SendRequest<Bytes>,
    created: Instant,
    generation: u64,
}

/// "Did this request reach Apps Script?" signal carried out of every
/// h2 failure so callers know whether replaying via h1 is safe.
///
/// - `No`: the failure occurred before `send_request` returned. The
///   stream was never opened on the wire; replaying through h1 is
///   guaranteed not to duplicate any side effect.
/// - `Maybe`: `send_request` succeeded (headers queued for sending)
///   but a later step failed — server may have already received the
///   request and may already be processing it. Replaying a
///   non-idempotent op (POST/PUT/DELETE, tunnel write, batch ops)
///   risks duplicating side effects. Only safe to retry for methods
///   that are idempotent by HTTP semantics.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum RequestSent {
    No,
    Maybe,
}

/// Typed errors from `open_h2`. Used so `ensure_h2` can recognize the
/// "peer refused h2 in ALPN" outcome and sticky-disable the fast path
/// without resorting to string matching across function boundaries.
#[derive(Debug, thiserror::Error)]
enum OpenH2Error {
    #[error("ALPN did not negotiate h2; peer prefers http/1.1")]
    AlpnRefused,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("dns: {0}")]
    Dns(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("h2 handshake: {0}")]
    Handshake(String),
}

impl From<OpenH2Error> for FronterError {
    fn from(e: OpenH2Error) -> Self {
        match e {
            OpenH2Error::Io(e) => FronterError::Io(e),
            OpenH2Error::Tls(e) => FronterError::Tls(e),
            OpenH2Error::Dns(e) => FronterError::Dns(e),
            OpenH2Error::AlpnRefused => FronterError::Relay("alpn refused h2".into()),
            OpenH2Error::Handshake(m) => FronterError::Relay(format!("h2 handshake: {}", m)),
        }
    }
}

pub struct DomainFronter {
    connect_host: String,
    /// Pool of SNI domains to rotate through per outbound connection. All of
    /// them must be hosted on the same Google edge as `connect_host` (that's
    /// the whole point of domain fronting). Rotating across several of them
    /// defeats naive DPI that would count "too many connections to a single
    /// SNI". Populated from config's front_domain: if that's a single name we
    /// add a small pool of known-safe Google subdomains automatically.
    sni_hosts: Vec<String>,
    sni_idx: AtomicUsize,
    http_host: &'static str,
    auth_key: String,
    script_ids: Vec<String>,
    script_idx: AtomicUsize,
    /// Fan-out factor: fire this many Apps Script instances in parallel
    /// per request and return first success. `<= 1` = off.
    parallel_relay: usize,
    /// Enable the `normalize_x_graphql` URL rewrite (issue #16, credit
    /// seramo_ir). When true, GETs to `x.com/i/api/graphql/<hash>/<op>`
    /// have their query trimmed to the first `variables=` block so the
    /// response cache isn't busted by the constantly-changing `features`
    /// / `fieldToggles` params.
    normalize_x_graphql: bool,
    /// Set once we've emitted the "UnknownIssuer means ISP MITM" hint,
    /// so we don't spam it every time a cert-validation error repeats.
    cert_hint_shown: std::sync::atomic::AtomicBool,
    /// Connector used by `open_h2`: advertises ALPN `["h2", "http/1.1"]`
    /// when the h2 fast path is enabled, else just `["http/1.1"]`. Never
    /// used by the h1 pool path — see `tls_connector_h1`.
    tls_connector: TlsConnector,
    /// Connector used by `open()` (h1 pool warm/refill/acquire). ALPN
    /// is forced to `["http/1.1"]` so a Google edge that would have
    /// preferred h2 still negotiates h1 here. Without this, pooled
    /// sockets could end up speaking h2 frames after handshake, and
    /// the `write_all(b"GET / HTTP/1.1\r\n...")` fallback would land
    /// on a server that has no idea what we're doing.
    tls_connector_h1: TlsConnector,
    pool: Arc<Mutex<Vec<PoolEntry>>>,
    /// HTTP/2 fast path. `None` until first relay opens it; cleared on
    /// connection failure or expiry so the next call reopens. Skipped
    /// entirely when `force_http1` is set or when the peer refused h2
    /// during ALPN (sticky `h2_disabled`).
    h2_cell: Arc<Mutex<Option<H2Cell>>>,
    /// Serializes "open a new h2 connection" attempts so that during
    /// an outage, only one task pays the handshake cost — concurrent
    /// callers see the lock contended via `try_lock` and fall through
    /// to h1 immediately rather than queueing behind a slow handshake.
    /// Distinct from `h2_cell` so the cell mutex is never held across
    /// network I/O.
    h2_open_lock: Arc<Mutex<()>>,
    /// Wall-clock timestamp of the last failed `open_h2`. While within
    /// `H2_OPEN_FAILURE_BACKOFF_SECS` of this, `ensure_h2` returns None
    /// without retrying — prevents thundering-herd handshake attempts
    /// during transient h2 outages.
    h2_open_failed_at: Arc<Mutex<Option<Instant>>>,
    /// Monotonic counter for `H2Cell::generation`. Each successful
    /// `open_h2` increments and tags the new cell so `poison_h2_if_gen`
    /// can avoid the race where a stale failure clears a freshly-opened
    /// cell that another task just installed.
    h2_generation: Arc<AtomicU64>,
    /// Set when ALPN negotiates http/1.1 (peer refused h2) or when
    /// `force_http1` is true. Sticky for the lifetime of the fronter:
    /// once we know this peer doesn't speak h2, don't keep retrying
    /// the handshake on every relay call.
    h2_disabled: Arc<AtomicBool>,
    cache: Arc<ResponseCache>,
    inflight: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>>,
    coalesced: AtomicU64,
    blacklist: Arc<std::sync::Mutex<HashMap<String, Instant>>>,
    /// Per-deployment rolling timeout counter. Maps `script_id` →
    /// `(window_start, strike_count)`. Reset when the window expires
    /// or when a batch succeeds. Triggers a short-cooldown blacklist
    /// at `TIMEOUT_STRIKE_LIMIT`. Distinct from `blacklist` because
    /// strike state is per-deployment health bookkeeping, not the
    /// permanent ban list.
    script_timeouts: Arc<std::sync::Mutex<HashMap<String, (Instant, u32)>>>,
    relay_calls: AtomicU64,
    relay_failures: AtomicU64,
    bytes_relayed: AtomicU64,
    /// Relay calls that successfully completed over the h2 fast path,
    /// across **all** entry points: Apps-Script direct relays,
    /// exit-node outer calls, full-mode tunnel single ops, and
    /// full-mode tunnel batches.
    ///
    /// **Not** comparable to `relay_calls`: that counter only counts
    /// the Apps-Script-direct path (incremented in `relay_uncoalesced`).
    /// The other three paths bypass `relay_uncoalesced` entirely, so in
    /// full-mode deployments `h2_calls` can exceed `relay_calls` —
    /// reading their ratio as a "% on h2" gives a wrong number.
    ///
    /// To gauge h2 health, compute `h2_calls / (h2_calls + h2_fallbacks)`.
    /// That's the success ratio across all transports; a healthy
    /// deployment shows > 95 %.
    h2_calls: AtomicU64,
    /// Relay calls that attempted h2 but had to fall back to h1
    /// (transient handshake failure, mid-stream error, conn poisoned,
    /// open backoff, or `RequestSent::No` failure that the call site
    /// chose to retry on h1). Same all-entry-points scope as
    /// `h2_calls`. A persistently high `h2_fallbacks / (h2_calls +
    /// h2_fallbacks)` ratio indicates an unhealthy h2 conn or a flaky
    /// middlebox eating h2 frames; consider `force_http1: true`.
    h2_fallbacks: AtomicU64,
    /// Per-host breakdown of traffic going through this fronter. Keyed by
    /// the host of the URL (e.g. "api.x.com"). Read-mostly; only touched
    /// on the slow path (once per relayed request), so a plain Mutex is
    /// fine.
    per_site: Arc<std::sync::Mutex<HashMap<String, HostStat>>>,
    /// Daily-scoped counters, reset at 00:00 UTC. Tracks what *this
    /// mhrv-rs process* has observed today — NOT the authoritative
    /// Apps Script quota bucket on Google's side (which counts across
    /// every client hitting the same deployment). Useful as a local
    /// "budget used today" estimate in the UI.
    ///
    /// Both counters rebase to zero the first time any recording call
    /// crosses a UTC date boundary. `day_key` holds "YYYY-MM-DD" of
    /// the currently-counted day; when we see a new date we swap and
    /// clear the counters.
    today_calls: AtomicU64,
    today_bytes: AtomicU64,
    today_key: std::sync::Mutex<String>,
    /// Suppress the random `_pad` field that v1.8.0+ adds to outbound
    /// payloads. Mirrors `Config::disable_padding` (#391). Default false
    /// (padding active = stronger DPI defense at +25% bandwidth cost).
    disable_padding: bool,
    /// Per-instance auto-blacklist tuning. Mirrors `Config::auto_blacklist_*`
    /// (#391, #444). Cached here so the hot path in `record_timeout_strike`
    /// doesn't have to reach back through the Config (which we don't keep
    /// a reference to).
    auto_blacklist_strikes: u32,
    auto_blacklist_window: Duration,
    auto_blacklist_cooldown: Duration,
    /// Per-batch HTTP timeout. Mirrors `Config::request_timeout_secs`
    /// (#430, masterking32 PR #25). Read by `tunnel_client::fire_batch`
    /// so a single config field tunes the timeout used everywhere.
    batch_timeout: Duration,
    /// Optional second-hop exit node (Deno Deploy / fly.io / etc.)
    /// to bypass CF-anti-bot blocks on sites that flag Google datacenter
    /// IPs (chatgpt.com, claude.ai, grok.com, x.com). Mirrors
    /// `Config::exit_node`. When `exit_node_enabled` is false (the more
    /// common state), all relay traffic takes the regular Apps Script
    /// path. When true, hosts matching `exit_node_hosts` (or all hosts
    /// when `exit_node_full`) route through the exit-node URL inside
    /// the Apps Script call.
    exit_node_enabled: bool,
    exit_node_url: String,
    exit_node_psk: String,
    exit_node_full: bool,
    /// Pre-normalized (lowercased, leading-dot stripped) host list for
    /// fast O(N) match in `exit_node_matches`.
    exit_node_hosts: Vec<String>,
}

/// Aggregated stats for one remote host.
#[derive(Default, Clone, Debug)]
pub struct HostStat {
    pub requests: u64,
    pub cache_hits: u64,
    pub bytes: u64,
    pub total_latency_ns: u64,
}

impl HostStat {
    pub fn avg_latency_ms(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            (self.total_latency_ns as f64) / (self.requests as f64) / 1_000_000.0
        }
    }
}

const BLACKLIST_COOLDOWN_SECS: u64 = 600;

/// Auto-blacklist defaults are now per-instance fields on `DomainFronter`,
/// driven by `Config::auto_blacklist_strikes` / `_window_secs` /
/// `_cooldown_secs` (#391, #444). The constants below are gone — see the
/// `Config` doc comments for tuning guidance and `default_auto_blacklist_*`
/// for the historical defaults (3 strikes / 30s window / 120s cooldown).

/// Request payload sent to Apps Script (single, non-batch).
#[derive(Serialize)]
struct RelayRequest<'a> {
    k: &'a str,
    m: &'a str,
    u: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    h: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ct: Option<&'a str>,
    r: bool,
}

/// Parsed Apps Script response JSON (single mode).
#[derive(Deserialize, Default)]
struct RelayResponse {
    #[serde(default)]
    s: Option<u16>,
    #[serde(default)]
    h: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    b: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// Parsed tunnel response JSON (full mode).
#[derive(Deserialize, Debug, Clone)]
pub struct TunnelResponse {
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub d: Option<String>,
    /// UDP datagrams returned by tunnel-node, base64-encoded individually.
    #[serde(default)]
    pub pkts: Option<Vec<String>>,
    #[serde(default)]
    pub eof: Option<bool>,
    #[serde(default)]
    pub e: Option<String>,
    /// Structured error code from the tunnel-node (e.g. `UNSUPPORTED_OP`).
    /// `None` for legacy tunnel-nodes; clients should fall back to parsing
    /// `e` only when this is `None` and compatibility is needed.
    #[serde(default)]
    pub code: Option<String>,
}

/// A single op in a batch tunnel request.
#[derive(Serialize, Clone, Debug)]
pub struct BatchOp {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

/// Batch tunnel response from Apps Script / tunnel node.
#[derive(Deserialize, Debug)]
pub struct BatchTunnelResponse {
    #[serde(default)]
    pub r: Vec<TunnelResponse>,
    #[serde(default)]
    pub e: Option<String>,
}

impl DomainFronter {
    pub fn new(config: &Config) -> Result<Self, FronterError> {
        let script_ids = config.script_ids_resolved();
        if script_ids.is_empty() {
            return Err(FronterError::Relay("no script_id configured".into()));
        }
        // Helper that builds a fresh ClientConfig with the verifier
        // policy from config. We need two of these so the h2-capable
        // and h1-only paths can advertise different ALPN sets without
        // mutating one shared config across calls.
        let build_tls_config = || {
            if config.verify_ssl {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            } else {
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify))
                    .with_no_client_auth()
            }
        };

        // Connector for `open_h2`: advertises h2 first (or just h1 if
        // the kill switch is set, in which case both connectors end up
        // identical — fine, just slightly redundant).
        let mut tls_h2 = build_tls_config();
        if !config.force_http1 {
            tls_h2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        } else {
            tls_h2.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        let tls_connector = TlsConnector::from(Arc::new(tls_h2));

        // Connector for `open()` (h1 pool path). ALPN is forced to
        // http/1.1 so a Google edge that would otherwise prefer h2
        // still negotiates h1 here — pooled sockets always speak the
        // protocol the fallback path expects.
        let mut tls_h1 = build_tls_config();
        tls_h1.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_connector_h1 = TlsConnector::from(Arc::new(tls_h1));

        Ok(Self {
            connect_host: config.google_ip.clone(),
            sni_hosts: build_sni_pool_for(
                &config.front_domain,
                config.sni_hosts.as_deref().unwrap_or(&[]),
            ),
            sni_idx: AtomicUsize::new(0),
            http_host: "script.google.com",
            auth_key: config.auth_key.clone(),
            parallel_relay: config.parallel_relay as usize,
            normalize_x_graphql: config.normalize_x_graphql,
            cert_hint_shown: std::sync::atomic::AtomicBool::new(false),
            script_ids,
            script_idx: AtomicUsize::new(0),
            tls_connector,
            tls_connector_h1,
            pool: Arc::new(Mutex::new(Vec::new())),
            h2_cell: Arc::new(Mutex::new(None)),
            h2_open_lock: Arc::new(Mutex::new(())),
            h2_open_failed_at: Arc::new(Mutex::new(None)),
            h2_generation: Arc::new(AtomicU64::new(0)),
            h2_disabled: Arc::new(AtomicBool::new(config.force_http1)),
            cache: Arc::new(ResponseCache::with_default()),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            coalesced: AtomicU64::new(0),
            blacklist: Arc::new(std::sync::Mutex::new(HashMap::new())),
            script_timeouts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_calls: AtomicU64::new(0),
            relay_failures: AtomicU64::new(0),
            bytes_relayed: AtomicU64::new(0),
            h2_calls: AtomicU64::new(0),
            h2_fallbacks: AtomicU64::new(0),
            per_site: Arc::new(std::sync::Mutex::new(HashMap::new())),
            today_calls: AtomicU64::new(0),
            today_bytes: AtomicU64::new(0),
            today_key: std::sync::Mutex::new(current_pt_day_key()),
            disable_padding: config.disable_padding,
            auto_blacklist_strikes: config.auto_blacklist_strikes.max(1),
            auto_blacklist_window: Duration::from_secs(
                config.auto_blacklist_window_secs.clamp(1, 3600),
            ),
            auto_blacklist_cooldown: Duration::from_secs(
                config.auto_blacklist_cooldown_secs.clamp(1, 86400),
            ),
            batch_timeout: Duration::from_secs(
                config.request_timeout_secs.clamp(5, 300),
            ),
            exit_node_enabled: config.exit_node.enabled
                && !config.exit_node.relay_url.is_empty()
                && !config.exit_node.psk.is_empty(),
            exit_node_url: config
                .exit_node
                .relay_url
                .trim_end_matches('/')
                .to_string(),
            exit_node_psk: config.exit_node.psk.clone(),
            exit_node_full: matches!(
                config.exit_node.mode.to_ascii_lowercase().as_str(),
                "full"
            ),
            exit_node_hosts: config
                .exit_node
                .hosts
                .iter()
                .map(|h| h.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
        })
    }

    /// True when the configured exit node should handle this URL.
    /// In `selective` mode (default), checks the host against the
    /// pre-normalized `exit_node_hosts` list (exact match OR
    /// dot-anchored suffix, mirroring `passthrough_hosts` semantics).
    /// In `full` mode, every URL routes through the exit node.
    pub(crate) fn exit_node_matches(&self, url: &str) -> bool {
        if !self.exit_node_enabled {
            return false;
        }
        if self.exit_node_full {
            return true;
        }
        let host = match extract_host(url) {
            Some(h) => h,
            None => return false,
        };
        let host_lc = host.to_ascii_lowercase();
        for entry in &self.exit_node_hosts {
            if host_lc == *entry || host_lc.ends_with(&format!(".{}", entry)) {
                return true;
            }
        }
        false
    }

    /// Per-batch HTTP round-trip timeout. Read by `tunnel_client` so the
    /// `BATCH_TIMEOUT` constant doesn't have to be touched on every config
    /// change. Clamped to `[5s, 300s]` at construction.
    pub(crate) fn batch_timeout(&self) -> Duration {
        self.batch_timeout
    }

    /// Record one relay call toward the daily budget. Called once per
    /// outbound Apps Script fetch. Rolls over both daily counters at
    /// 00:00 Pacific Time, matching Apps Script's quota reset cadence
    /// (#230, #362). Crate-public so the Full-mode batch path in
    /// `tunnel_client::fire_batch` can wire into the same accounting
    /// (Apps Script sees Full-mode batches as ordinary `UrlFetchApp`
    /// calls and counts them against the same daily quota).
    pub(crate) fn record_today(&self, bytes: u64) {
        let today = current_pt_day_key();
        // Fast path: same day as what we last saw. No lock.
        let mut guard = self.today_key.lock().unwrap();
        if *guard != today {
            // Date rolled over — reset counters before this call is counted.
            *guard = today;
            self.today_calls.store(0, Ordering::Relaxed);
            self.today_bytes.store(0, Ordering::Relaxed);
        }
        drop(guard);
        self.today_calls.fetch_add(1, Ordering::Relaxed);
        self.today_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment the per-site counters. Called on every logical request
    /// (both cache hits and relay roundtrips).
    fn record_site(&self, url: &str, cache_hit: bool, bytes: u64, latency_ns: u64) {
        let host = match extract_host(url) {
            Some(h) => h,
            None => return,
        };
        let mut m = self.per_site.lock().unwrap();
        let e = m.entry(host).or_default();
        e.requests += 1;
        if cache_hit {
            e.cache_hits += 1;
        }
        e.bytes += bytes;
        e.total_latency_ns += latency_ns;
    }

    /// Snapshot per-site stats, sorted by request count descending.
    pub fn snapshot_per_site(&self) -> Vec<(String, HostStat)> {
        let m = self.per_site.lock().unwrap();
        let mut v: Vec<(String, HostStat)> =
            m.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort_by(|a, b| b.1.requests.cmp(&a.1.requests));
        v
    }

    pub fn snapshot_stats(&self) -> StatsSnapshot {
        let bl = self.blacklist.lock().unwrap();
        // Read today_key under lock and cheaply check rollover so the
        // UI never sees stale "today_calls=1847" on a day where no
        // traffic has flowed yet (e.g. user left the app open past
        // midnight PT).
        let today_now = current_pt_day_key();
        let today_key = {
            let mut guard = self.today_key.lock().unwrap();
            if *guard != today_now {
                *guard = today_now.clone();
                self.today_calls.store(0, Ordering::Relaxed);
                self.today_bytes.store(0, Ordering::Relaxed);
            }
            guard.clone()
        };
        StatsSnapshot {
            relay_calls: self.relay_calls.load(Ordering::Relaxed),
            relay_failures: self.relay_failures.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            bytes_relayed: self.bytes_relayed.load(Ordering::Relaxed),
            cache_hits: self.cache.hits(),
            cache_misses: self.cache.misses(),
            cache_bytes: self.cache.size(),
            blacklisted_scripts: bl.len(),
            total_scripts: self.script_ids.len(),
            today_calls: self.today_calls.load(Ordering::Relaxed),
            today_bytes: self.today_bytes.load(Ordering::Relaxed),
            today_key,
            today_reset_secs: seconds_until_pacific_midnight(),
            h2_calls: self.h2_calls.load(Ordering::Relaxed),
            h2_fallbacks: self.h2_fallbacks.load(Ordering::Relaxed),
            h2_disabled: self.h2_disabled.load(Ordering::Relaxed),
        }
    }

    pub fn num_scripts(&self) -> usize {
        self.script_ids.len()
    }

    pub fn script_id_list(&self) -> &[String] {
        &self.script_ids
    }

    pub fn cache(&self) -> &ResponseCache {
        &self.cache
    }

    pub fn coalesced_count(&self) -> u64 {
        self.coalesced.load(Ordering::Relaxed)
    }

    pub fn next_script_id(&self) -> String {
        let n = self.script_ids.len();
        let mut bl = self.blacklist.lock().unwrap();
        let now = Instant::now();
        bl.retain(|_, until| *until > now);

        for _ in 0..n {
            let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
            let sid = &self.script_ids[idx % n];
            if !bl.contains_key(sid) {
                return sid.clone();
            }
        }
        // All blacklisted: pick whichever comes off cooldown soonest.
        if let Some((sid, _)) = bl.iter().min_by_key(|(_, t)| **t) {
            let sid = sid.clone();
            bl.remove(&sid);
            return sid;
        }
        self.script_ids[0].clone()
    }

    /// Pick `want` distinct non-blacklisted script IDs for a parallel fan-out
    /// dispatch. Returns fewer than `want` if there aren't enough non-blacklisted
    /// IDs available. Advances the round-robin index by `want` to spread load
    /// across subsequent calls.
    fn next_script_ids(&self, want: usize) -> Vec<String> {
        let n = self.script_ids.len();
        if n == 0 {
            return vec![];
        }
        let mut bl = self.blacklist.lock().unwrap();
        let now = Instant::now();
        bl.retain(|_, until| *until > now);

        let mut picked: Vec<String> = Vec::with_capacity(want);
        for _ in 0..n {
            if picked.len() >= want {
                break;
            }
            let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
            let sid = &self.script_ids[idx % n];
            if !bl.contains_key(sid) && !picked.iter().any(|p| p == sid) {
                picked.push(sid.clone());
            }
        }
        if picked.is_empty() {
            picked.push(self.script_ids[0].clone());
        }
        picked
    }

    fn blacklist_script(&self, script_id: &str, reason: &str) {
        self.blacklist_script_for(
            script_id,
            Duration::from_secs(BLACKLIST_COOLDOWN_SECS),
            reason,
        );
    }

    fn blacklist_script_for(&self, script_id: &str, cooldown: Duration, reason: &str) {
        let until = Instant::now() + cooldown;
        let mut bl = self.blacklist.lock().unwrap();
        bl.insert(script_id.to_string(), until);
        tracing::warn!(
            "blacklisted script {} for {}s: {}",
            mask_script_id(script_id),
            cooldown.as_secs(),
            reason
        );
    }

    /// Record a batch timeout against `script_id`. After
    /// `TIMEOUT_STRIKE_LIMIT` timeouts inside `TIMEOUT_STRIKE_WINDOW`
    /// the deployment is blacklisted with a short cooldown so the
    /// round-robin stops sending real traffic to a deployment that's
    /// hung (most commonly: stale `TUNNEL_SERVER_URL` after the
    /// tunnel-node moved hosts).
    pub(crate) fn record_timeout_strike(&self, script_id: &str) {
        let now = Instant::now();
        let mut counts = self.script_timeouts.lock().unwrap();
        let entry = counts
            .entry(script_id.to_string())
            .or_insert((now, 0));
        if now.duration_since(entry.0) > self.auto_blacklist_window {
            *entry = (now, 1);
        } else {
            entry.1 += 1;
        }
        let strikes = entry.1;
        if strikes >= self.auto_blacklist_strikes {
            counts.remove(script_id);
            drop(counts);
            self.blacklist_script_for(
                script_id,
                self.auto_blacklist_cooldown,
                &format!(
                    "{} timeouts in {}s",
                    strikes,
                    self.auto_blacklist_window.as_secs()
                ),
            );
        }
    }

    /// Clear the timeout strike counter for `script_id`. Called after
    /// a batch succeeds so a recovered deployment doesn't keep stale
    /// strikes from hours ago — three strikes must occur within one
    /// real failure burst, not accumulate across unrelated incidents.
    pub(crate) fn record_batch_success(&self, script_id: &str) {
        let mut counts = self.script_timeouts.lock().unwrap();
        counts.remove(script_id);
    }

    /// Log a relay failure with extra guidance on cert-validation cases.
    /// Rate-limited so a flood of identical "UnknownIssuer" errors doesn't
    /// fill the log.
    fn log_relay_failure(&self, e: &FronterError) {
        let msg = e.to_string();
        let is_cert_issue = msg.contains("UnknownIssuer")
            || msg.contains("invalid peer certificate")
            || msg.contains("CertificateExpired")
            || msg.contains("CertNotValidYet")
            || msg.contains("NotValidForName");
        if is_cert_issue
            && !self
                .cert_hint_shown
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            // First time — print the full diagnostic. Subsequent hits
            // drop to debug so the log stays readable.
            tracing::error!(
                "Relay failed: {} — this almost always means one of:\n  \
                 (1) your ISP or a middlebox is intercepting TLS to the Google edge \
                 (common in Iran / IR);\n  \
                 (2) the `google_ip` in your config is pointing at a non-Google host;\n  \
                 (3) your system clock is way off (NTP not synced).\n\
                 Fixes (try in order): run `mhrv-rs scan-ips` to find a different Google \
                 frontend IP that isn't being MITM'd; check `date` on your host; as a \
                 LAST RESORT set `\"verify_ssl\": false` in config.json — this lets the \
                 relay work even through a middlebox, but your traffic is then only \
                 protected by the Apps Script relay's secret `auth_key`, not by outer TLS.",
                e
            );
        } else if is_cert_issue {
            tracing::debug!("Relay failed (cert): {}", e);
        } else {
            tracing::error!("Relay failed: {}", e);
        }
    }

    fn next_sni(&self) -> String {
        let n = self.sni_hosts.len();
        let i = self.sni_idx.fetch_add(1, Ordering::Relaxed) % n;
        self.sni_hosts[i].clone()
    }

    async fn open(&self) -> Result<PooledStream, FronterError> {
        let tcp = TcpStream::connect((self.connect_host.as_str(), 443u16)).await?;
        let _ = tcp.set_nodelay(true);
        let sni = self.next_sni();
        let name = ServerName::try_from(sni)?;
        // Always use the h1-only connector here — the pool only holds
        // sockets that the raw HTTP/1.1 fallback path can write to.
        // Using the shared connector would let some pooled sockets
        // negotiate h2, which would then misframe every fallback
        // request that lands on them.
        let tls = self.tls_connector_h1.connect(name, tcp).await?;
        Ok(tls)
    }

    /// Open outbound TLS connections eagerly so the first relay request
    /// doesn't pay a cold handshake.
    ///
    /// h2 and h1 prewarm run in parallel: a request that arrives while
    /// the h2 handshake is still in flight (or has just hit its 8 s
    /// timeout) needs a warm h1 socket waiting for it, otherwise the
    /// h1 fallback path pays a cold handshake on the same slow network
    /// and the 30 s outer batch budget elapses (#924). v1.9.14 warmed
    /// h1 unconditionally; v1.9.15 (PR #799) accidentally gated the h1
    /// prewarm behind `ensure_h2()` so the h1 pool stayed empty during
    /// the h2 init window.
    ///
    /// Staggered 500 ms apart so we don't burst N TLS handshakes at the
    /// Google edge simultaneously, and each connection gets an 8 s
    /// expiry offset so they roll off gradually instead of all hitting
    /// POOL_TTL_SECS at once. If h2 ends up the active fast path,
    /// `run_pool_refill` trims the pool back down to
    /// `POOL_MIN_H2_FALLBACK` on the next tick — the extra warm h1
    /// sockets just age out naturally instead of being kept alive.
    pub async fn warm(self: &Arc<Self>, n: usize) {
        // Spawn the h2 prewarm in parallel so the h1 prewarm loop
        // below isn't blocked on it. Capturing the join handle lets
        // us still log "h2 fast path active" / "h1 fallback only"
        // accurately at the end.
        let h2_self = self.clone();
        let h2_handle = tokio::spawn(async move {
            !h2_self.h2_disabled.load(Ordering::Relaxed)
                && h2_self.ensure_h2().await.is_some()
        });

        let mut warmed = 0usize;
        for i in 0..n {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            match self.open().await {
                Ok(s) => {
                    let entry = PoolEntry {
                        stream: s,
                        created: Instant::now() - Duration::from_secs(8 * i as u64),
                    };
                    let mut pool = self.pool.lock().await;
                    if pool.len() < POOL_MAX {
                        pool.push(entry);
                        warmed += 1;
                    }
                }
                Err(e) => {
                    tracing::debug!("pool warm: open failed: {}", e);
                }
            }
        }
        // Join the h2 prewarm here only to log whether it landed; the
        // h1 pool above is already populated either way. JoinError
        // collapses to "h2 not alive" — same as if ensure_h2 returned
        // None — so we still log a useful line.
        let h2_alive = h2_handle.await.unwrap_or(false);
        if h2_alive {
            tracing::info!(
                "h2 fast path active; h1 fallback pool pre-warmed with {} connection(s)",
                warmed
            );
        } else if warmed > 0 {
            tracing::info!("pool pre-warmed with {} connection(s)", warmed);
        }
    }

    /// Background loop that keeps the h1 fallback pool warm.
    ///
    /// Target depends on whether the h2 fast path is active:
    /// - h2 disabled (or peer refused ALPN h2): keep `POOL_MIN` (8)
    ///   sockets so the per-request acquire never pays a cold handshake
    ///   — the pre-h2 default behavior.
    /// - h2 active: keep just `POOL_MIN_H2_FALLBACK` (2). All real
    ///   traffic rides the multiplexed h2 connection; the h1 pool only
    ///   exists to cover the case where h2 dies and we need to fall
    ///   back instantly without a cold handshake.
    ///
    /// A connection only counts toward the minimum if it has at least
    /// 20 s of TTL remaining — nearly-expired entries don't help.
    /// Checks every `POOL_REFILL_INTERVAL_SECS`, evicts expired entries,
    /// and opens replacements one at a time so there's no burst.
    pub async fn run_pool_refill(self: Arc<Self>) {
        const MIN_REMAINING_SECS: u64 = 20;
        const POOL_MIN_H2_FALLBACK: usize = 2;
        loop {
            tokio::time::sleep(Duration::from_secs(POOL_REFILL_INTERVAL_SECS)).await;

            // Evict expired entries first.
            {
                let mut pool = self.pool.lock().await;
                pool.retain(|e| e.created.elapsed().as_secs() < POOL_TTL_SECS);
            }

            // Decide target. We treat "h2 active right now" as having a
            // fresh, non-poisoned cell. h2_disabled is the sticky flag
            // (peer never agreed to h2); a transient cell-poison after
            // h2 success briefly drops back to the larger target until
            // ensure_h2 reopens.
            let target = if self.h2_disabled.load(Ordering::Relaxed) {
                POOL_MIN
            } else {
                let cell = self.h2_cell.lock().await;
                let h2_alive = cell
                    .as_ref()
                    .map(|c| c.created.elapsed().as_secs() < H2_CONN_TTL_SECS)
                    .unwrap_or(false);
                if h2_alive { POOL_MIN_H2_FALLBACK } else { POOL_MIN }
            };

            // Count only connections with enough life left.
            // Refill one at a time to avoid bursting TLS handshakes.
            loop {
                let healthy = {
                    let pool = self.pool.lock().await;
                    pool.iter()
                        .filter(|e| {
                            let age = e.created.elapsed().as_secs();
                            age + MIN_REMAINING_SECS < POOL_TTL_SECS
                        })
                        .count()
                };
                if healthy >= target {
                    break;
                }
                match self.open().await {
                    Ok(s) => {
                        let mut pool = self.pool.lock().await;
                        if pool.len() < POOL_MAX {
                            pool.push(PoolEntry {
                                stream: s,
                                created: Instant::now(),
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!("pool refill: open failed: {}", e);
                        break;
                    }
                }
            }
        }
    }

    /// Keep the Apps Script container warm with a periodic HEAD ping.
    ///
    /// The TCP/TLS pool stays warm via `run_pool_refill`, but the V8
    /// container Apps Script runs in goes cold ~5min after the last
    /// `UrlFetchApp` call and costs 1-3s to spin back up. The symptom
    /// is "first request after a quiet period stalls" — most visible
    /// on YouTube where the player gives up on a 1.5s `googlevideo.com`
    /// chunk that's actually waiting on a cold-start.
    ///
    /// Transport-agnostic: the underlying call goes through the same
    /// `relay_uncoalesced` path everything else uses, so when h2 is
    /// up the keepalive rides the multiplexed connection too.
    ///
    /// Bypasses the response cache (`cache_key_opt = None`) and the
    /// inflight coalescer — otherwise the second iteration would just
    /// hit the cached response from the first and never reach Apps
    /// Script. The relay payload itself is the cheapest non-error one
    /// we can build: a HEAD against `http://example.com/` returns a few
    /// hundred bytes, no body decode, no auth.
    ///
    /// Best-effort. Failures are debug-logged so a flaky network or
    /// quota-exhausted account doesn't spam warnings every 4 minutes.
    /// Loops forever — caller is expected to drop the JoinHandle on
    /// shutdown (the task lives as long as the process).
    pub async fn run_keepalive(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(H1_KEEPALIVE_INTERVAL_SECS)).await;
            let t0 = Instant::now();
            // relay_uncoalesced returns Vec<u8> (always — errors are
            // baked into 5xx responses), so just observe the duration
            // for the debug line. We intentionally don't use relay()
            // here because that path goes through the cache + coalesce
            // layer, which would short-circuit subsequent pings.
            let _ = self
                .relay_uncoalesced("HEAD", "http://example.com/", &[], &[], None)
                .await;
            tracing::debug!(
                "container keepalive: {}ms",
                t0.elapsed().as_millis()
            );
        }
    }

    async fn acquire(&self) -> Result<PoolEntry, FronterError> {
        {
            let mut pool = self.pool.lock().await;
            // Evict expired, then hand out the freshest (most remaining TTL).
            pool.retain(|e| e.created.elapsed().as_secs() < POOL_TTL_SECS);
            if !pool.is_empty() {
                // Freshest = smallest elapsed time. swap_remove is O(1).
                let freshest = pool
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.created.elapsed())
                    .map(|(i, _)| i)
                    .unwrap();
                return Ok(pool.swap_remove(freshest));
            }
        }
        let stream = self.open().await?;
        Ok(PoolEntry {
            stream,
            created: Instant::now(),
        })
    }

    async fn release(&self, entry: PoolEntry) {
        if entry.created.elapsed().as_secs() >= POOL_TTL_SECS {
            return;
        }
        let mut pool = self.pool.lock().await;
        if pool.len() < POOL_MAX {
            pool.push(entry);
        }
    }

    /// Return a cloned `SendRequest` handle (paired with its cell
    /// generation) to the active HTTP/2 connection, opening a new one
    /// if needed. `None` means the h2 fast path is unavailable for
    /// this call — the caller should fall through to the h1 path.
    ///
    /// Reasons we may return `None`:
    ///   - `force_http1` set, or peer previously refused h2 via ALPN
    ///     (sticky `h2_disabled`).
    ///   - We're inside the `H2_OPEN_FAILURE_BACKOFF_SECS` cooldown
    ///     after a recent open failure.
    ///   - Another task is currently opening a connection and we
    ///     don't want to pile on (`try_lock` on `h2_open_lock`).
    ///   - The open we just attempted timed out within
    ///     `H2_OPEN_TIMEOUT_SECS` or otherwise failed.
    ///
    /// The lock on `h2_cell` is *never* held across network I/O —
    /// that's the whole point of `h2_open_lock`. Concurrent first-time
    /// callers compete for `h2_open_lock` via `try_lock`; the loser
    /// returns None immediately and uses h1 rather than serializing
    /// behind a slow handshake.
    ///
    /// The returned generation lets the caller later
    /// `poison_h2_if_gen(gen)` to clear *only* this specific cell on
    /// per-stream error, avoiding the race where a stale failure
    /// clobbers a freshly-reopened healthy cell.
    async fn ensure_h2(&self) -> Option<(h2::client::SendRequest<Bytes>, u64)> {
        if self.h2_disabled.load(Ordering::Relaxed) {
            return None;
        }

        // Fast path: existing cell, within TTL. Clone (Arc bump) and
        // return without touching the open machinery. We can't peek at
        // SendRequest liveness directly (h2 0.4 doesn't expose
        // `is_closed`), so a request against a dead conn fails at
        // `ready()`/`send_request` and the caller poisons by
        // generation from there.
        {
            let cell = self.h2_cell.lock().await;
            if let Some(c) = cell.as_ref() {
                if c.created.elapsed().as_secs() < H2_CONN_TTL_SECS {
                    return Some((c.send.clone(), c.generation));
                }
            }
        }

        // Backoff check — recent open failure means h2 is currently
        // unhealthy; don't pile on retries until the window expires.
        {
            let last = self.h2_open_failed_at.lock().await;
            if let Some(t) = *last {
                if t.elapsed().as_secs() < H2_OPEN_FAILURE_BACKOFF_SECS {
                    return None;
                }
            }
        }

        // Open dedup: only one task does the actual handshake at a
        // time. Concurrent callers see the lock contended and fall
        // through to h1 immediately — preserves cold-start latency
        // for the burst that arrives during a slow open.
        let _open_guard = match self.h2_open_lock.try_lock() {
            Ok(g) => g,
            Err(_) => return None,
        };

        // Re-check the cell under open_lock — another task may have
        // just stored a fresh connection while we were arbitrating.
        {
            let cell = self.h2_cell.lock().await;
            if let Some(c) = cell.as_ref() {
                if c.created.elapsed().as_secs() < H2_CONN_TTL_SECS {
                    return Some((c.send.clone(), c.generation));
                }
            }
        }

        // Bounded handshake. A blackholed connect target can stall
        // for many seconds otherwise, eating the outer budget that
        // should be reserved for an h1 fallback round-trip.
        let open_result =
            tokio::time::timeout(Duration::from_secs(H2_OPEN_TIMEOUT_SECS), self.open_h2())
                .await;

        let send = match open_result {
            Ok(Ok(s)) => s,
            Ok(Err(OpenH2Error::AlpnRefused)) => {
                // Definitive: this peer doesn't speak h2. Sticky-disable
                // so we never re-attempt the handshake.
                self.h2_disabled.store(true, Ordering::Relaxed);
                tracing::info!(
                    "relay peer refused h2 via ALPN; staying on http/1.1"
                );
                *self.h2_cell.lock().await = None;
                return None;
            }
            Ok(Err(e)) => {
                tracing::debug!("h2 open failed: {} — falling back to h1", e);
                *self.h2_open_failed_at.lock().await = Some(Instant::now());
                *self.h2_cell.lock().await = None;
                return None;
            }
            Err(_) => {
                tracing::debug!(
                    "h2 open timed out after {}s — falling back to h1",
                    H2_OPEN_TIMEOUT_SECS
                );
                *self.h2_open_failed_at.lock().await = Some(Instant::now());
                *self.h2_cell.lock().await = None;
                return None;
            }
        };

        // Open succeeded. Tag with a fresh generation, store, return.
        // Clear any stale backoff timestamp.
        let generation = self.h2_generation.fetch_add(1, Ordering::Relaxed) + 1;
        *self.h2_open_failed_at.lock().await = None;
        let mut cell = self.h2_cell.lock().await;
        *cell = Some(H2Cell {
            send: send.clone(),
            created: Instant::now(),
            generation,
        });
        Some((send, generation))
    }

    /// Open one TLS connection and run the h2 handshake. Returns a
    /// typed `OpenH2Error` so the caller can recognize ALPN refusal
    /// (sticky disable) without string-matching across boundaries.
    async fn open_h2(&self) -> Result<h2::client::SendRequest<Bytes>, OpenH2Error> {
        let tcp = TcpStream::connect((self.connect_host.as_str(), 443u16)).await?;
        let _ = tcp.set_nodelay(true);
        let sni = self.next_sni();
        let name = ServerName::try_from(sni)?;
        let tls = self.tls_connector.connect(name, tcp).await?;
        Self::h2_handshake_post_tls(tls).await
    }

    /// Post-TLS portion of the h2 open path: ALPN check + h2 handshake
    /// + connection-driver task spawn. Split out from `open_h2` so
    /// tests can drive it with a TLS stream from any local server,
    /// bypassing the hard-coded `connect_host:443` target.
    async fn h2_handshake_post_tls(
        tls: PooledStream,
    ) -> Result<h2::client::SendRequest<Bytes>, OpenH2Error> {
        let alpn_h2 = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| p == b"h2")
            .unwrap_or(false);
        if !alpn_h2 {
            return Err(OpenH2Error::AlpnRefused);
        }
        // Larger initial windows mean we don't have to call
        // `release_capacity` on every chunk for typical Apps Script
        // payloads (usually < 1 MB; range chunks are 256 KB). We still
        // release capacity in the body-read loop for safety on larger
        // bodies.
        let (send, conn) = h2::client::Builder::new()
            .initial_window_size(4 * 1024 * 1024)
            .initial_connection_window_size(8 * 1024 * 1024)
            .handshake(tls)
            .await
            .map_err(|e| OpenH2Error::Handshake(e.to_string()))?;
        // The connection task drives frame I/O independently of any
        // SendRequest handle. When it ends (GOAWAY, network error, TTL),
        // existing handles will start failing on `ready()` / `send_request`
        // and `ensure_h2` will reopen on the next call.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("h2 connection closed: {}", e);
            }
        });
        tracing::info!("h2 connection established to relay edge");
        Ok(send)
    }

    /// React to an h2-fronting-incompatibility HTTP response (status
    /// matched by `is_h2_fronting_refusal_status`) by:
    ///   * sticky-disabling the h2 fast path so subsequent calls go
    ///     straight to h1 without re-paying the handshake / refusal,
    ///   * clearing any current cell so the SendRequest is dropped,
    ///   * rebalancing the h2 stat counters so this request shows
    ///     up as a fallback, not a successful h2 call. (The
    ///     `run_h2_relay_with_send` Ok path bumps `h2_calls` for any
    ///     completed round-trip; for a 421 we want it counted as
    ///     `h2_fallbacks` instead since the request will take the
    ///     h1 path.)
    /// Logs at info because this is a meaningful state transition for
    /// the deployment, not a per-request hiccup.
    async fn sticky_disable_h2_for_fronting_refusal(&self, status: u16, context: &str) {
        if !self.h2_disabled.swap(true, Ordering::Relaxed) {
            tracing::info!(
                "h2 returned HTTP {} for {} — likely :authority/SNI mismatch via \
                 domain fronting. Disabling h2 fast path for this fronter and \
                 falling back to http/1.1.",
                status,
                context,
            );
        }
        *self.h2_cell.lock().await = None;
        // Reclassify: undo the h2_calls increment from
        // run_h2_relay_with_send and bill this attempt as a fallback.
        // saturating_sub-style guard: only decrement if non-zero so a
        // direct caller of this helper from a non-Ok path can't
        // underflow the counter.
        let _ = self.h2_calls.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |c| if c > 0 { Some(c - 1) } else { None },
        );
        self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    /// Clear the h2 cell *only if* its generation matches the one the
    /// caller observed. Prevents the race where:
    ///   1. Task A holds SendRequest from generation N
    ///   2. Generation N's connection dies; Task B reopens → cell now
    ///      holds generation N+1 (healthy)
    ///   3. Task A's stale stream errors → unconditionally clearing
    ///      the cell would kill the healthy N+1
    /// With generation matching, A's poison is a no-op against N+1.
    async fn poison_h2_if_gen(&self, generation: u64) {
        let mut cell = self.h2_cell.lock().await;
        if let Some(c) = cell.as_ref() {
            if c.generation == generation {
                *cell = None;
            }
        }
    }

    /// Send one POST through the active h2 connection, follow up to 5
    /// redirects, and return `(status, headers, body)` — the same shape
    /// the h1 path's `read_http_response` produces, so callers can stay
    /// transport-agnostic from this point on.
    ///
    /// `path` is the HTTP path including the leading slash. The Host /
    /// :authority header is taken from `self.http_host` for the initial
    /// request and from the `Location` URL on redirect. `payload` is the
    /// body bytes; `content_type` is set when non-None (for the JSON
    /// envelope). Empty body + None content_type → GET (used for redirect
    /// follow-up).
    /// Run one h2 stream and return `(status, headers, body)`. Errors
    /// carry a `RequestSent` flag so the caller can distinguish "never
    /// sent" (safe to retry on h1) from "may have been processed by
    /// origin" (only safe to retry for idempotent methods).
    ///
    /// Two phases, two timeouts:
    ///   * **Ready (back-pressure):** bounded by `H2_READY_TIMEOUT_SECS`
    ///     (5 s constant). A stall here means the conn is saturated
    ///     under `MAX_CONCURRENT_STREAMS` (or dead at the muxer level)
    ///     but no stream has opened — `RequestSent::No`.
    ///   * **Response (post-send):** bounded by the caller-provided
    ///     `response_deadline`. After `send_request` returns Ok the
    ///     headers are queued; we conservatively treat any later
    ///     failure or timeout as `RequestSent::Maybe`. Caller picks
    ///     the deadline so legitimate slow Apps Script calls and
    ///     Full-mode batches with custom `request_timeout_secs` aren't
    ///     cut off at an arbitrary fixed cap.
    async fn h2_round_trip(
        &self,
        send: h2::client::SendRequest<Bytes>,
        method: &str,
        path: &str,
        host: &str,
        payload: Bytes,
        content_type: Option<&str>,
        response_deadline: Duration,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), (FronterError, RequestSent)> {
        // h2 requires absolute-form URIs with the :authority pseudo-header
        // populated from the Host. http::Request's URI parser accepts
        // `https://{host}{path}` for that.
        let uri = format!("https://{}{}", host, path);
        let mut builder = http::Request::builder().method(method).uri(uri);
        // Apps Script accepts gzip on the response; mirror the h1 path so
        // payloads stay small.
        builder = builder.header("accept-encoding", "gzip");
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        let req = builder.body(()).map_err(|e| {
            (
                FronterError::Relay(format!("h2 request build: {}", e)),
                RequestSent::No,
            )
        })?;

        // Phase 1: ready/back-pressure. Bounded short. Timeout here
        // means saturation, not server-side processing — the stream
        // hasn't even opened, so `RequestSent::No`.
        let ready_result = tokio::time::timeout(
            Duration::from_secs(H2_READY_TIMEOUT_SECS),
            send.ready(),
        )
        .await;
        let mut send = match ready_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err((
                    FronterError::Relay(format!("h2 ready: {}", e)),
                    RequestSent::No,
                ));
            }
            Err(_) => {
                return Err((FronterError::Timeout, RequestSent::No));
            }
        };

        let has_body = !payload.is_empty();
        // send_request is synchronous; it queues the HEADERS frame.
        // After this returns Ok we conservatively assume the request
        // reached the server. An Err here means the stream couldn't
        // be opened (e.g. connection-level GOAWAY), safe to retry.
        let (response_fut, mut body_tx) = send.send_request(req, !has_body).map_err(|e| {
            (
                FronterError::Relay(format!("h2 send_request: {}", e)),
                RequestSent::No,
            )
        })?;

        if has_body {
            // body_tx errors here are RequestSent::Maybe — headers were
            // already queued, so we may have invoked Apps Script's doPost
            // even if the body never finished.
            body_tx.send_data(payload, true).map_err(|e| {
                (
                    FronterError::Relay(format!("h2 send_data: {}", e)),
                    RequestSent::Maybe,
                )
            })?;
        }

        // Phase 2: response headers + body drain. Bounded by the
        // caller's deadline. Errors and timeout here are
        // `RequestSent::Maybe` — the request is on the wire and may
        // already have side effects.
        let response_phase = async {
            let response = response_fut.await.map_err(|e| {
                (
                    FronterError::Relay(format!("h2 response: {}", e)),
                    RequestSent::Maybe,
                )
            })?;
            let (parts, mut body) = response.into_parts();
            let status = parts.status.as_u16();

            // Convert headers to the (String, String) Vec the rest of
            // the codebase expects. Multi-valued headers (set-cookie,
            // etc.) are expanded one entry per value, matching
            // httparse's emission.
            let mut headers: Vec<(String, String)> = Vec::with_capacity(parts.headers.len());
            for (name, value) in parts.headers.iter() {
                if let Ok(v) = value.to_str() {
                    headers.push((name.as_str().to_string(), v.to_string()));
                }
            }

            // Drain body. Release flow-control credit per chunk so
            // large responses don't stall after the initial 4 MB window.
            let mut buf: Vec<u8> = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|e| {
                    (
                        FronterError::Relay(format!("h2 body chunk: {}", e)),
                        RequestSent::Maybe,
                    )
                })?;
                let n = chunk.len();
                buf.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(n);
            }
            Ok::<_, (FronterError, RequestSent)>((status, headers, buf))
        };

        let (status, headers, mut buf) = match tokio::time::timeout(
            response_deadline,
            response_phase,
        )
        .await
        {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err((FronterError::Timeout, RequestSent::Maybe)),
        };

        // Mirror `read_http_response`: if the server gzipped the body
        // (we asked for it via accept-encoding), decompress before
        // handing back so downstream JSON / envelope parsers see plain
        // bytes regardless of transport.
        if let Some(enc) = header_get(&headers, "content-encoding") {
            if enc.eq_ignore_ascii_case("gzip") {
                if let Ok(decoded) = decode_gzip(&buf) {
                    buf = decoded;
                }
            }
        }

        Ok((status, headers, buf))
    }

    /// Run a full relay round-trip over h2: initial POST + up to 5
    /// redirect hops. `path` is the Apps Script `/macros/s/{id}/exec`
    /// path. Returns the same `(status, headers, body)` triple as the
    /// h1 path on success.
    ///
    /// `response_deadline` bounds the post-send phase of each round
    /// trip (response headers + body drain). The ready/back-pressure
    /// phase has its own short bound (`H2_READY_TIMEOUT_SECS`).
    /// Caller picks the deadline based on its own outer budget:
    ///   * Apps-Script direct (`relay_uncoalesced`): a few seconds
    ///     under `REQUEST_TIMEOUT_SECS` (25 s) so an h2 timeout still
    ///     leaves room for an h1 fallback.
    ///   * Full-mode tunnel (`tunnel_request` / `tunnel_batch_request_to`):
    ///     `self.batch_timeout` so the user's
    ///     `request_timeout_secs` setting actually applies.
    ///
    /// On error, the second tuple field is `RequestSent::No` if the
    /// request never reached Apps Script (safe to retry on h1) or
    /// `RequestSent::Maybe` if it may have been processed (replaying
    /// risks duplicating side effects for non-idempotent methods).
    /// `ensure_h2` returning None always reports `RequestSent::No`.
    ///
    /// Takes `payload` as `Bytes` so callers can clone (Arc bump,
    /// not memcpy) when they want to retain a copy for h1 fallback.
    async fn h2_relay_request(
        &self,
        path: &str,
        payload: Bytes,
        response_deadline: Duration,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), (FronterError, RequestSent)> {
        let (send, generation) = match self.ensure_h2().await {
            Some(s) => s,
            None => {
                // ensure_h2 returning None covers:
                //   1. force_http1 / sticky-disabled — never tried h2
                //      this call. NOT a fallback, don't count.
                //   2. open_h2 just failed / timed out / backoff active.
                //      We DID attempt h2 and lost it; count as fallback
                //      so the stat reflects reality. `ensure_h2` itself
                //      sets the backoff timestamp on failure.
                if !self.h2_disabled.load(Ordering::Relaxed) {
                    self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
                }
                return Err((
                    FronterError::Relay("h2 unavailable".into()),
                    RequestSent::No,
                ));
            }
        };

        self.run_h2_relay_with_send(send, generation, path, payload, response_deadline)
            .await
    }

    /// Inner h2 relay loop — split out so tests can inject a
    /// `SendRequest` (from a local h2c test server) without going
    /// through `ensure_h2`'s real-network handshake.
    ///
    /// Each h2_round_trip uses its own internal phase-split timeouts
    /// (ready=5s constant, response=`response_deadline`). No outer
    /// wrap is needed here — the inner timeouts are what poisons the
    /// cell on stall.
    async fn run_h2_relay_with_send(
        &self,
        send: h2::client::SendRequest<Bytes>,
        generation: u64,
        path: &str,
        payload: Bytes,
        response_deadline: Duration,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), (FronterError, RequestSent)> {
        let mut current_host = self.http_host.to_string();
        let mut current_path = path.to_string();

        let res = self
            .h2_round_trip(
                send.clone(),
                "POST",
                &current_path,
                &current_host,
                payload,
                Some("application/json"),
                response_deadline,
            )
            .await;
        let (mut status, mut hdrs, mut body) = match res {
            Ok(t) => t,
            Err((e, sent)) => {
                self.poison_h2_if_gen(generation).await;
                self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
                return Err((e, sent));
            }
        };

        // The initial POST already succeeded — the request reached
        // Apps Script. From here on, redirect-follow failures are
        // RequestSent::Maybe regardless of where they land in the
        // chain, because the *original* Apps Script call may have
        // already executed.
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&hdrs, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            current_host = rhost.unwrap_or(current_host);
            current_path = rpath;
            let res = self
                .h2_round_trip(
                    send.clone(),
                    "GET",
                    &current_path,
                    &current_host,
                    Bytes::new(),
                    None,
                    response_deadline,
                )
                .await;
            match res {
                Ok((s, h, b)) => {
                    status = s;
                    hdrs = h;
                    body = b;
                }
                Err((e, _)) => {
                    self.poison_h2_if_gen(generation).await;
                    self.h2_fallbacks.fetch_add(1, Ordering::Relaxed);
                    return Err((e, RequestSent::Maybe));
                }
            }
        }

        self.h2_calls.fetch_add(1, Ordering::Relaxed);
        Ok((status, hdrs, body))
    }

    /// Relay an HTTP request through Apps Script.
    /// Returns a raw HTTP/1.1 response (status line + headers + body) suitable
    /// for writing back to the browser over an MITM'd TLS stream.
    pub async fn relay(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        // Optional URL rewrite for X/Twitter GraphQL (issue #16). Applied
        // here, at the top of relay(), so it affects BOTH the cache key
        // (so matching requests collapse into one entry) AND the URL that
        // gets sent upstream to Apps Script (so Apps Script only has to
        // fetch the trimmed variant, cutting quota usage).
        let normalized;
        let url: &str = if self.normalize_x_graphql {
            normalized = normalize_x_graphql_url(url);
            normalized.as_str()
        } else {
            url
        };

        // Exit-node short-circuit: route through the configured second-hop
        // relay (Deno Deploy / fly.io / etc.) for hosts that need a
        // non-Google exit IP. The cache + coalesce layer below is bypassed
        // for these — exit-node-eligible hosts are the ones with active
        // anti-bot challenges (CF Turnstile, ChatGPT login, Claude.ai,
        // grok.com), and serving cached responses across users for those
        // would be wrong (auth tokens, session state, per-user
        // personalization). Falls back to the regular Apps Script relay
        // if the exit node fails (network error, 5xx from the exit node, etc.)
        // so a misconfigured or down exit node doesn't take the user
        // offline for the sites that DON'T need it.
        if self.exit_node_matches(url) {
            let t0 = Instant::now();
            match self.relay_via_exit_node(method, url, headers, body).await {
                Ok(bytes) => {
                    self.record_site(
                        url,
                        false,
                        bytes.len() as u64,
                        t0.elapsed().as_nanos() as u64,
                    );
                    return bytes;
                }
                Err(e) if !e.is_retryable() => {
                    // The exit node may have already processed this
                    // request (h2 post-send failure on a POST etc.).
                    // Don't fall through to the direct path — that
                    // would re-send to the same destination via Apps
                    // Script and duplicate the side effect.
                    tracing::warn!(
                        "exit node failed for {} and request was already sent ({}); not falling back to direct Apps Script",
                        url,
                        e,
                    );
                    self.relay_failures.fetch_add(1, Ordering::Relaxed);
                    let inner = e.into_inner();
                    self.record_site(url, false, 0, t0.elapsed().as_nanos() as u64);
                    return error_response(502, &format!("Relay error: {}", inner));
                }
                Err(e) => {
                    tracing::warn!(
                        "exit node failed for {}: {} — falling back to direct Apps Script",
                        url,
                        e
                    );
                    // fall through to the regular relay path below
                }
            }
        }

        // Range requests are partial-content responses; caching or
        // coalescing them against a non-range key would be catastrophic
        // (wrong bytes for the wrong consumer). The range-parallel
        // downloader calls `relay()` concurrently with N different Range
        // headers for the same URL, and absolutely needs each call to go
        // to the relay independently. Simplest correct answer: if any
        // Range header is present, skip cache and coalesce entirely.
        let has_range = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let coalescible = is_cacheable_method(method) && body.is_empty() && !has_range;
        let key = if coalescible { Some(cache_key(method, url)) } else { None };
        let t_start = Instant::now();

        if let Some(ref k) = key {
            if let Some(hit) = self.cache.get(k) {
                tracing::debug!("cache hit: {}", url);
                self.record_site(url, true, hit.len() as u64, t_start.elapsed().as_nanos() as u64);
                return hit;
            }
        }

        // Coalesce concurrent identical requests: only the first caller actually
        // hits the relay; waiters subscribe to the same broadcast channel.
        let waiter = if let Some(ref k) = key {
            let mut inflight = self.inflight.lock().await;
            match inflight.get(k) {
                Some(tx) => {
                    let rx = tx.subscribe();
                    self.coalesced.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("coalesced: {}", url);
                    Some(rx)
                }
                None => {
                    let (tx, _) = broadcast::channel(1);
                    inflight.insert(k.clone(), tx);
                    None
                }
            }
        } else {
            None
        };

        if let Some(mut rx) = waiter {
            match rx.recv().await {
                Ok(bytes) => return bytes,
                Err(_) => return error_response(502, "coalesced request dropped"),
            }
        }

        let bytes = self.relay_uncoalesced(method, url, headers, body, key.as_deref()).await;

        if let Some(ref k) = key {
            let mut inflight = self.inflight.lock().await;
            if let Some(tx) = inflight.remove(k) {
                let _ = tx.send(bytes.clone());
            }
        }

        self.record_site(url, false, bytes.len() as u64, t_start.elapsed().as_nanos() as u64);
        bytes
    }

    /// Range-parallel relay — the big difference between this port and
    /// the upstream Python version. Apps Script's per-call cost is
    /// ~flat (1-2s regardless of payload), so a 10MB single GET is
    /// ~10s round-trip; the same 10MB sliced into 40 x 256KB chunks
    /// and fetched 16-at-a-time is 3-4 round-trips, total ~6-8s, and
    /// the client sees the first byte in 1-2s instead of 10. This is
    /// what actually makes YouTube video playback viable through the
    /// relay — without it, googlevideo.com chunks timeout or stall
    /// while the player waits for the next 10s-away Apps Script call
    /// to finish.
    ///
    /// Flow (mirrors upstream `relay_parallel`):
    ///   1. For anything other than GET-without-body, defer to
    ///      `relay()` — range requests on POSTs / PUTs aren't well
    ///      defined, and the user-sent-Range-header case is handled
    ///      by relay() already (we skip cache for it).
    ///   2. Probe with `Range: bytes=0-<chunk-1>`.
    ///   3. 200 back (origin doesn't support ranges) → return as-is.
    ///   4. 206 back → parse Content-Range total. If Content-Range says
    ///      the entity fits in the first probe, rewrite the 206 to a 200
    ///      so the client — which never asked for a
    ///      range — doesn't choke on a stray Partial Content. (x.com
    ///      and Cloudflare turnstile in particular reject unsolicited
    ///      206 on XHR/fetch.)
    ///   5. Else: compute the remaining ranges, fetch them with
    ///      bounded concurrency, stitch, return as 200.
    ///
    /// If any later chunk fails validation or fetch, we fall back to the
    /// probe's single-chunk response as a graceful-degradation, but we do
    /// not stitch unchecked bytes into a fake full-success response.
    pub async fn relay_parallel_range(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        const MAX_PARALLEL: usize = 16;
        let chunk = RANGE_PARALLEL_CHUNK_BYTES;

        if method != "GET" || !body.is_empty() {
            return self.relay(method, url, headers, body).await;
        }
        // If the client already sent a Range header, honour it as-is —
        // don't second-guess a caller that knows what bytes they want.
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range")) {
            return self.relay(method, url, headers, body).await;
        }

        // Probe with the first chunk.
        let mut probe_headers: Vec<(String, String)> = headers.to_vec();
        probe_headers.push(("Range".into(), format!("bytes=0-{}", chunk - 1)));
        let first = self.relay(method, url, &probe_headers, body).await;

        let (status, resp_headers, resp_body) = match split_response(&first) {
            Some(v) => v,
            None => return first,
        };

        if status != 206 {
            // Origin returned the whole thing (or an error). Either way,
            // pass through.
            return first;
        }

        let probe_range = match validate_probe_range(status, &resp_headers, resp_body, chunk - 1)
        {
            Some(r) => r,
            None => {
                tracing::warn!(
                    "range-parallel: probe returned invalid 206 for {}; falling back to single GET",
                    url,
                );
                return self.relay(method, url, headers, body).await;
            }
        };
        let total = probe_range.total;

        if total <= chunk || (probe_range.end + 1) >= total {
            return rewrite_206_to_200(&first);
        }

        let total_usize = match checked_stitched_range_capacity(total) {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "range-parallel: Content-Range total {} for {} is too large; falling back to single GET",
                    total,
                    url,
                );
                return self.relay(method, url, headers, body).await;
            }
        };

        // Plan remaining ranges after what the probe already returned.
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut start = probe_range.end + 1;
        while start < total {
            let end = (start + chunk - 1).min(total - 1);
            ranges.push((start, end));
            start = end + 1;
        }

        tracing::info!(
            "range-parallel: {} bytes total, {} chunks remaining after probe, up to {} in flight",
            total, ranges.len(), MAX_PARALLEL,
        );

        // Concurrent fetch with `buffered` — preserves input order
        // (important for stitching) and caps in-flight count. Each task
        // calls back into `relay()`, which already has retry + fan-out
        // wiring on single-request granularity; we don't duplicate
        // those here.
        use futures_util::stream::{self, StreamExt};
        let url_owned = url.to_string();
        let base_headers = headers.to_vec();
        let fetches = stream::iter(ranges.into_iter())
            .map(|(s, e)| {
                let url = url_owned.clone();
                let mut h = base_headers.clone();
                // Force a single Range header — if the caller's headers
                // somehow already had one we wouldn't be here, but be
                // defensive anyway.
                h.retain(|(k, _)| !k.eq_ignore_ascii_case("range"));
                h.push(("Range".into(), format!("bytes={}-{}", s, e)));
                async move {
                    let raw = self.relay("GET", &url, &h, &[]).await;
                    (s, e, extract_exact_range_body(&raw, s, e, total))
                }
            })
            .buffered(MAX_PARALLEL)
            .collect::<Vec<_>>()
            .await;

        // Stitch: probe body first, then the chunks in order.
        let mut full = Vec::with_capacity(total_usize);
        full.extend_from_slice(resp_body);
        for (start, end, chunk) in fetches {
            match chunk {
                Ok(chunk) => full.extend_from_slice(&chunk),
                Err(reason) => {
                    // Issue #162: silently rewriting the probe to a 200
                    // here truncates the response to whatever the probe
                    // saw (typically 256 KiB — the chunk size). Browsers
                    // see HTTP 200 + Content-Length=262144 and treat
                    // the download as complete; users reported "every
                    // file capped at 256 KB" because every download
                    // that hit this failure path landed there. Common
                    // triggers: Apps Script stripping Content-Range,
                    // origin returning 200-instead-of-206 on later
                    // chunks, total mismatch across chunks. Correct
                    // recovery is a fresh single GET — Apps Script
                    // fetches the full URL up to its 50 MiB cap. Slow
                    // for big files vs. the parallel path but produces
                    // a complete response, which is what matters.
                    tracing::warn!(
                        "range-parallel: invalid chunk {}-{} for {} ({}); falling back to single GET",
                        start, end, url, reason,
                    );
                    return self.relay(method, url, headers, body).await;
                }
            }
        }

        if (full.len() as u64) != total {
            // Same fallback rationale as the chunk-validation case
            // above: returning the probe truncates to 256 KiB. Single
            // GET is the only way to give the user a complete file
            // when the parallel stitch can't be trusted.
            tracing::warn!(
                "range-parallel: stitched {}/{} bytes for {}; falling back to single GET",
                full.len(), total, url,
            );
            return self.relay(method, url, headers, body).await;
        }

        // Build a 200 OK with Content-Length = full body length. Drop
        // the Content-Range header (no longer applicable) and
        // Transfer-Encoding/Content-Encoding (origin already decoded
        // what we got; we ship plain bytes).
        assemble_full_200(&resp_headers, &full)
    }

    async fn relay_uncoalesced(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        cache_key_opt: Option<&str>,
    ) -> Vec<u8> {
        self.relay_calls.fetch_add(1, Ordering::Relaxed);
        let bytes = match timeout(
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
            self.do_relay_with_retry(method, url, headers, body),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                self.relay_failures.fetch_add(1, Ordering::Relaxed);
                self.log_relay_failure(&e);
                return error_response(502, &format!("Relay error: {}", e));
            }
            Err(_) => {
                // Timeout here means Apps Script didn't respond within
                // REQUEST_TIMEOUT_SECS (currently 25). The most common
                // cause by far is the account's daily UrlFetchApp quota
                // being exhausted — once Google kills the script mid-exec,
                // our relay hangs until timeout because no body ever comes
                // back. Surface that possibility in the message instead
                // of just "timeout", which has burned several users asking
                // "why did it work yesterday" (see issues #99, #111, #105).
                self.relay_failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!("Relay timeout — Apps Script unresponsive");
                return error_response(
                    504,
                    "Relay timeout — Apps Script did not respond. \
                     Most likely cause: daily UrlFetchApp quota exhausted \
                     (resets 00:00 UTC). Other possibilities: script.google.com \
                     unreachable from your network, or the Apps Script edge is having issues. \
                     Check the script's Executions tab at script.google.com for the real error.",
                );
            }
        };
        self.bytes_relayed.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        // Daily-budget counters (reset at 00:00 UTC). Only counts
        // successful relays — the two error branches above don't reach
        // here, matching what Google actually billed to quota.
        self.record_today(bytes.len() as u64);

        if let Some(k) = cache_key_opt {
            if let Some(ttl) = parse_ttl(&bytes, url) {
                tracing::debug!("cache store: {} ttl={}s", url, ttl.as_secs());
                self.cache.put(k.to_string(), bytes.clone(), ttl);
            }
        }
        bytes
    }

    async fn do_relay_with_retry(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        // Fan-out path: fire N instances in parallel, return first Ok, cancel
        // the rest. Clamps to number of available script IDs so the single-ID
        // case is a no-op even if parallel_relay>1 was configured.
        //
        // `select_ok` cancels the loser futures, but those futures only own
        // the OUR-side I/O (TLS write, response read) — the Apps Script
        // server has no idea the racing Rust task is gone, so every fan-out
        // call still completes server-side and Apps Script's
        // `UrlFetchApp.fetch()` to the destination still fires. For
        // **non-idempotent** methods (POST / PUT / PATCH / DELETE) this
        // surfaces as duplicate writes at the destination — a comment
        // posted twice, a vote double-counted, a payment double-charged.
        //
        // Reported in #743: parallel_relay=2 + a POST to GitHub created
        // two issue comments per submission. Same root cause as the
        // SAFE_REPLAY_METHODS guard in Code.gs's `_doBatch` fallback —
        // safe methods are idempotent, so re-firing is at worst wasteful;
        // unsafe methods can have side effects, so re-firing is incorrect.
        //
        // Drop to sequential for non-idempotent methods regardless of
        // `parallel_relay` setting. Users keep p95 wins on browsing /
        // GET-heavy traffic (the common case) and don't lose correctness
        // on form submits.
        let method_safe_for_fanout = is_method_safe_for_fanout(method);
        let fan = self.parallel_relay.min(self.script_ids.len()).max(1);
        if fan >= 2 && method_safe_for_fanout {
            return self.do_relay_parallel(method, url, headers, body, fan).await;
        }

        // Sequential path: one retry on connection failure, *unless*
        // the failure is `FronterError::NonRetryable` — that wrapper
        // says "the request may have already reached the server, do
        // not duplicate." Without this guard, an h2 post-send failure
        // on a non-idempotent method (POST/PUT/PATCH/DELETE) that the
        // h2 layer correctly refused to replay on h1 would be
        // re-issued here anyway, defeating the safety policy.
        match self.do_relay_once(method, url, headers, body).await {
            Ok(v) => Ok(v),
            Err(e) if !e.is_retryable() => {
                tracing::warn!(
                    "relay attempt 1 failed and is non-retryable ({}); not duplicating {} {}",
                    e,
                    method,
                    url,
                );
                Err(e.into_inner())
            }
            Err(e) => {
                tracing::debug!("relay attempt 1 failed: {}; retrying", e);
                self.do_relay_once(method, url, headers, body).await
            }
        }
    }

    async fn do_relay_parallel(
        self: &Self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        fan: usize,
    ) -> Result<Vec<u8>, FronterError> {
        use futures_util::future::FutureExt;
        let ids = self.next_script_ids(fan);
        if ids.is_empty() {
            return Err(FronterError::Relay("no script_ids available".into()));
        }

        // Build one future per script, each a pinned boxed future so we can
        // `select_ok` over them.
        let mut futs = Vec::with_capacity(ids.len());
        for sid in ids {
            let fut = self.do_relay_once_with(sid.clone(), method, url, headers, body).boxed();
            futs.push(fut);
        }

        // `select_ok`: drive all futures concurrently, return the first Ok
        // (cancelling the rest when the returned future is dropped). If all
        // error out, returns the last error.
        match futures_util::future::select_ok(futs).await {
            Ok((bytes, _remaining)) => Ok(bytes),
            Err(e) => Err(e),
        }
    }

    async fn do_relay_once(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let script_id = self.next_script_id();
        self.do_relay_once_with(script_id, method, url, headers, body).await
    }

    async fn do_relay_once_with(
        &self,
        script_id: String,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        // Build once, wrap in Bytes (zero-copy move). h2 takes a clone
        // (Arc bump, not memcpy); h1 fallback uses the same Bytes via
        // Deref<&[u8]>. Saves a full payload allocation+copy per call
        // — meaningful on range-parallel fan-out where N copies fire
        // in parallel for one user-facing GET.
        let payload: Bytes = Bytes::from(self.build_payload_json(method, url, headers, body)?);
        let path = format!("/macros/s/{}/exec", script_id);

        // h2 fast path: one shared TCP/TLS connection multiplexes all
        // streams.
        //
        // The h2 layer reports `RequestSent::No` when it can prove
        // the request never reached Apps Script (ensure_h2 unavailable,
        // ready/back-pressure timeout, send_request error). In that
        // case we fall through to h1 unconditionally — there's no
        // duplication risk.
        //
        // For `RequestSent::Maybe` (anything after send_request
        // succeeded) we only fall through for HTTP-idempotent methods.
        // POST / PUT / PATCH / DELETE get wrapped in
        // `FronterError::NonRetryable` so `do_relay_with_retry`'s
        // outer retry also skips replay — without that wrap, the
        // outer retry would re-issue the request anyway and the
        // safety policy would be illusory.
        match self
            .h2_relay_request(
                &path,
                payload.clone(),
                Duration::from_secs(H2_RESPONSE_DEADLINE_DEFAULT_SECS),
            )
            .await
        {
            Ok((status, _hdrs, _resp_body)) if is_h2_fronting_refusal_status(status) => {
                // Edge rejected the fronted h2 request before
                // forwarding to Apps Script. Sticky-disable h2,
                // log once, fall through to h1 — this request is
                // safe to replay because it never reached Apps Script.
                self.sticky_disable_h2_for_fronting_refusal(
                    status,
                    &format!("relay {} {}", method, url),
                )
                .await;
                // fall through to h1
            }
            Ok((status, _hdrs, resp_body)) => {
                if status != 200 {
                    let body_txt = String::from_utf8_lossy(&resp_body)
                        .chars()
                        .take(200)
                        .collect::<String>();
                    if should_blacklist(status, &body_txt) {
                        self.blacklist_script(&script_id, &format!("HTTP {}", status));
                    }
                    return Err(FronterError::Relay(format!(
                        "Apps Script HTTP {}: {}",
                        status, body_txt
                    )));
                }
                return parse_relay_json(&resp_body).map_err(|e| {
                    if let FronterError::Relay(ref msg) = e {
                        if looks_like_quota_error(msg) {
                            self.blacklist_script(&script_id, msg);
                        }
                    }
                    e
                });
            }
            Err((e, RequestSent::No)) => {
                tracing::debug!("h2 pre-send failure: {} — falling back to h1", e);
            }
            Err((e, RequestSent::Maybe)) => {
                if is_method_safe_for_fanout(method) {
                    tracing::debug!(
                        "h2 post-send failure for safe method {}: {} — falling back to h1",
                        method,
                        e
                    );
                } else {
                    tracing::warn!(
                        "h2 post-send failure for non-idempotent {} {}: {} — \
                         marking non-retryable to prevent duplicating side effects",
                        method,
                        url,
                        e
                    );
                    // NonRetryable wrapper bubbles all the way through
                    // do_relay_once_with → do_relay_with_retry, where
                    // the retry loop skips its second attempt. Without
                    // this wrap, returning a plain Err would let
                    // do_relay_with_retry re-issue the request via h1
                    // (or a fresh h2 cell), defeating the safety policy.
                    return Err(FronterError::NonRetryable(Box::new(e)));
                }
            }
        }

        let mut entry = self.acquire().await?;
        let reuse_ok = {
            let write_res = async {
                let req_head = format!(
                    "POST {path} HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {len}\r\n\
                     Accept-Encoding: gzip\r\n\
                     Connection: keep-alive\r\n\
                     \r\n",
                    path = path,
                    host = self.http_host,
                    len = payload.len(),
                );
                entry.stream.write_all(req_head.as_bytes()).await?;
                entry.stream.write_all(&payload).await?;
                entry.stream.flush().await?;

                let (status, resp_headers, resp_body) =
                    read_http_response(&mut entry.stream).await?;
                Ok::<_, FronterError>((status, resp_headers, resp_body))
            }
            .await;

            match write_res {
                Err(e) => {
                    // Connection may be dead — don't return to pool.
                    return Err(e);
                }
                Ok((mut status, mut resp_headers, mut resp_body)) => {
                    // Follow redirect chain (Apps Script usually redirects
                    // /exec to googleusercontent.com). Up to 5 hops, same
                    // connection.
                    for _ in 0..5 {
                        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                            break;
                        }
                        let Some(loc) = header_get(&resp_headers, "location") else {
                            break;
                        };
                        let (rpath, rhost) = parse_redirect(&loc);
                        let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
                        let req = format!(
                            "GET {rpath} HTTP/1.1\r\n\
                             Host: {rhost}\r\n\
                             Accept-Encoding: gzip\r\n\
                             Connection: keep-alive\r\n\
                             \r\n",
                        );
                        entry.stream.write_all(req.as_bytes()).await?;
                        entry.stream.flush().await?;
                        let (s, h, b) = read_http_response(&mut entry.stream).await?;
                        status = s;
                        resp_headers = h;
                        resp_body = b;
                    }

                    if status != 200 {
                        let body_txt = String::from_utf8_lossy(&resp_body)
                            .chars()
                            .take(200)
                            .collect::<String>();
                        if should_blacklist(status, &body_txt) {
                            self.blacklist_script(&script_id, &format!("HTTP {}", status));
                        }
                        return Err(FronterError::Relay(format!(
                            "Apps Script HTTP {}: {}",
                            status, body_txt
                        )));
                    }
                    match parse_relay_json(&resp_body) {
                        Ok(bytes) => Ok::<_, FronterError>((bytes, true)),
                        Err(e) => {
                            if let FronterError::Relay(ref msg) = e {
                                if looks_like_quota_error(msg) {
                                    self.blacklist_script(&script_id, msg);
                                }
                            }
                            Err(e)
                        }
                    }
                }
            }
        };

        match reuse_ok {
            Ok((bytes, reuse)) => {
                if reuse {
                    self.release(entry).await;
                }
                Ok(bytes)
            }
            Err(e) => Err(e),
        }
    }

    /// Send a request through the configured exit node, chained inside
    /// an Apps Script call. Path:
    ///
    /// ```text
    /// client → SNI rewrite → Apps Script (Google IP)
    ///        → UrlFetchApp.fetch(exit_node_url)
    ///        → exit node (non-Google IP)
    ///        → fetch(real_url)
    ///        → response back through both layers
    /// ```
    ///
    /// Apps Script sees the outer call (URL = exit_node_url, method =
    /// POST, body = inner relay JSON authenticated with the exit-node
    /// PSK). The exit node sees the inner JSON, fetches the real
    /// destination, returns a `{s, h, b}` JSON envelope. Apps Script
    /// returns that envelope as the body of its raw HTTP response
    /// (because we set `r: true`). We then unwrap one extra layer:
    /// extract Apps Script's body → parse the exit-node JSON → reconstruct
    /// the destination's raw HTTP response so the rest of the proxy
    /// pipeline (MITM TLS write-back) sees the same shape it gets from
    /// the regular path.
    async fn relay_via_exit_node(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let inner_json = self.build_exit_node_inner_payload(method, url, headers, body)?;

        // The outer payload is just a normal Apps Script relay request
        // pointing at the exit-node URL with POST + the inner JSON as body.
        // Reusing build_payload_json keeps the outer envelope consistent
        // with everything else (including the random padding for DPI
        // evasion). The `r: true` flag in RelayRequest makes Code.gs
        // return exit-node's raw HTTP response, which is what we want to
        // unwrap below.
        let exit_url = self.exit_node_url.clone();
        let outer_headers = vec![(
            "Content-Type".to_string(),
            "application/json".to_string(),
        )];
        let outer_payload: Bytes = Bytes::from(
            self.build_payload_json("POST", &exit_url, &outer_headers, &inner_json)?,
        );

        // Send the outer payload through the relay machinery and get back
        // Apps Script's response body (which is exit-node's JSON envelope).
        let app_body = self
            .send_prebuilt_payload_through_relay(outer_payload)
            .await?;

        // exit-node's JSON envelope: {s: u16, h: {...}, b: "<base64>"} on
        // success, {e: "..."} on its own internal error.
        parse_exit_node_response(&app_body)
    }

    /// Build the inner-layer payload that the exit node will execute.
    /// Same wire shape as a normal `RelayRequest` (`{k, m, u, h, b, ct, r}`)
    /// but `k` is the exit-node PSK rather than the user's Apps Script
    /// `auth_key`, and we skip the random-padding field — padding only
    /// helps DPI evasion on the Iran-side leg, which the inner payload
    /// is invisible to (it's encrypted inside the Apps Script HTTPS
    /// connection that the ISP can't inspect).
    fn build_exit_node_inner_payload(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let filtered = filter_forwarded_headers(headers);
        let hmap = if filtered.is_empty() {
            None
        } else {
            let mut m = serde_json::Map::with_capacity(filtered.len());
            for (k, v) in &filtered {
                m.insert(k.clone(), Value::String(v.clone()));
            }
            Some(m)
        };
        let b_encoded = if body.is_empty() {
            None
        } else {
            Some(B64.encode(body))
        };
        let ct = if body.is_empty() {
            None
        } else {
            find_header(headers, "content-type")
        };
        let req = RelayRequest {
            k: &self.exit_node_psk,
            m: method,
            u: url,
            h: hmap,
            b: b_encoded,
            ct,
            r: false, // the exit node returns its own JSON envelope, not raw HTTP
        };
        Ok(serde_json::to_vec(&req)?)
    }

    /// Drive the standard script-id rotation + TLS pool send path with
    /// a payload we already built. Mirrors `do_relay_once_with` but
    /// returns the **raw response body bytes** (Apps Script's HTTP body)
    /// instead of running the body through `parse_relay_json` — the
    /// exit-node path needs to peel off exit-node's JSON envelope, which
    /// has a different shape from Code.gs's raw-HTTP wrapping.
    async fn send_prebuilt_payload_through_relay(
        &self,
        payload: Bytes,
    ) -> Result<Vec<u8>, FronterError> {
        let script_id = self.next_script_id();
        let path = format!("/macros/s/{}/exec", script_id);

        // h2 fast path. The exit-node outer call is always POST and
        // carries the inner relay payload — replaying on h1 after the
        // outer reached Apps Script duplicates the inner request to
        // the exit node. Only fall back when h2 definitely never sent.
        // Same default response deadline as the direct path; the
        // exit-node leg ultimately exits via Apps Script too.
        match self
            .h2_relay_request(
                &path,
                payload.clone(),
                Duration::from_secs(H2_RESPONSE_DEADLINE_DEFAULT_SECS),
            )
            .await
        {
            Ok((status, _hdrs, _resp_body)) if is_h2_fronting_refusal_status(status) => {
                // Same fronting-refusal path as the direct relay.
                // Safe to fall back: 421 means the edge rejected
                // before invoking the exit node.
                self.sticky_disable_h2_for_fronting_refusal(
                    status,
                    "exit-node outer call",
                )
                .await;
                // fall through to h1
            }
            Ok((status, _hdrs, resp_body)) => {
                if status != 200 {
                    let body_txt = String::from_utf8_lossy(&resp_body)
                        .chars()
                        .take(200)
                        .collect::<String>();
                    return Err(FronterError::Relay(format!(
                        "Apps Script HTTP {} (exit-node outer call): {}",
                        status, body_txt
                    )));
                }
                return Ok(resp_body);
            }
            Err((e, RequestSent::No)) => {
                tracing::debug!(
                    "h2 exit-node outer call pre-send failure: {} — falling back to h1",
                    e
                );
            }
            Err((e, RequestSent::Maybe)) => {
                tracing::warn!(
                    "h2 exit-node outer call post-send failure: {} — \
                     marking non-retryable to prevent duplicating the inner request",
                    e
                );
                // NonRetryable propagates back to relay()'s exit-node
                // match arm, which will *not* fall through to the
                // direct Apps Script path (that fall-through would
                // re-send the outer call and could also re-trigger
                // the inner request to the destination).
                return Err(FronterError::NonRetryable(Box::new(e)));
            }
        }

        let mut entry = self.acquire().await?;
        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response(&mut entry.stream).await?;

        // Follow Apps Script's /exec → /macros/.../exec redirect chain
        // (typical: 1-2 hops to script.googleusercontent.com). Mirrors
        // the redirect handling in do_relay_once_with.
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&resp_headers, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\n\
                 Host: {rhost}\r\n\
                 Accept-Encoding: gzip\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) = read_http_response(&mut entry.stream).await?;
            status = s;
            resp_headers = h;
            resp_body = b;
        }

        // Don't return to pool — the exit-node path is rare enough that
        // the connection-reuse semantics aren't worth replicating here.
        drop(entry);

        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body)
                .chars()
                .take(200)
                .collect::<String>();
            return Err(FronterError::Relay(format!(
                "Apps Script HTTP {} (exit-node outer call): {}",
                status, body_txt
            )));
        }
        Ok(resp_body)
    }

    fn build_payload_json(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let filtered = filter_forwarded_headers(headers);
        let hmap = if filtered.is_empty() {
            None
        } else {
            let mut m = serde_json::Map::with_capacity(filtered.len());
            for (k, v) in &filtered {
                m.insert(k.clone(), Value::String(v.clone()));
            }
            Some(m)
        };
        let b_encoded = if body.is_empty() {
            None
        } else {
            Some(B64.encode(body))
        };
        let ct = if body.is_empty() {
            None
        } else {
            find_header(headers, "content-type")
        };
        let req = RelayRequest {
            k: &self.auth_key,
            m: method,
            u: url,
            h: hmap,
            b: b_encoded,
            ct,
            r: true,
        };
        // Serialize via Value so we can splice in the random `_pad` field
        // without changing RelayRequest's wire schema. Apps Script ignores
        // unknown JSON fields, so old Code.gs deployments stay compatible
        // — the pad is just bytes-on-the-wire that the server sees and
        // discards.
        let mut v = serde_json::to_value(&req)?;
        if let Value::Object(map) = &mut v {
            if !self.disable_padding {
                add_random_pad(map);
            }
        }
        Ok(serde_json::to_vec(&v)?)
    }

    // ────── Full-mode tunnel protocol ──────────────────────────────────

    /// Send a tunnel-protocol request through the domain-fronted connection
    /// to Apps Script. Reuses the same TLS pool as `relay()` but builds a
    /// tunnel JSON payload (the `t` field triggers `_doTunnel` in CodeFull.gs).
    pub async fn tunnel_request(
        &self,
        op: &str,
        host: Option<&str>,
        port: Option<u16>,
        sid: Option<&str>,
        data: Option<String>,
    ) -> Result<TunnelResponse, FronterError> {
        let payload: Bytes =
            Bytes::from(self.build_tunnel_payload(op, host, port, sid, data)?);
        let script_id = self.next_script_id();
        let path = format!("/macros/s/{}/exec", script_id);

        // h2 fast path. Tunnel ops are stateful — a `connect` may
        // have opened an upstream socket; a `data` op may have
        // forwarded bytes. Replaying on h1 after the op reached
        // Apps Script can corrupt the tunnel session. Only fall back
        // when h2 definitely never sent.
        // Use the user-configured batch_timeout so Full-mode tuning
        // (`request_timeout_secs`) is honored — a fixed cap would let
        // legitimately slow batches incorrectly trip strike counters
        // on healthy deployments at tunnel_client::fire_batch.
        match self
            .h2_relay_request(&path, payload.clone(), self.batch_timeout)
            .await
        {
            Ok((status, _hdrs, _resp_body)) if is_h2_fronting_refusal_status(status) => {
                // Edge rejected the fronted h2 request. Safe to fall
                // back to h1 — the tunnel op never executed because
                // Apps Script never received the request.
                self.sticky_disable_h2_for_fronting_refusal(
                    status,
                    &format!("tunnel op {}", op),
                )
                .await;
                // fall through to h1
            }
            Ok((status, _hdrs, resp_body)) => {
                return self.finalize_tunnel_response(&script_id, status, resp_body);
            }
            Err((e, RequestSent::No)) => {
                tracing::debug!(
                    "h2 tunnel request pre-send failure: {} — falling back to h1",
                    e
                );
            }
            Err((e, RequestSent::Maybe)) => {
                tracing::warn!(
                    "h2 tunnel request post-send failure (op={}): {} — \
                     not replaying on h1 to avoid corrupting the tunnel session",
                    op,
                    e
                );
                return Err(e);
            }
        }

        let mut entry = self.acquire().await?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response(&mut entry.stream).await?;

        // Follow redirect chain (Apps Script usually redirects /exec to
        // googleusercontent.com). Same logic as do_relay_once_with.
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&resp_headers, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\n\
                 Host: {rhost}\r\n\
                 Accept-Encoding: gzip\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) = read_http_response(&mut entry.stream).await?;
            status = s;
            resp_headers = h;
            resp_body = b;
        }

        let resp = self.finalize_tunnel_response(&script_id, status, resp_body)?;
        self.release(entry).await;
        Ok(resp)
    }

    /// Validate a tunnel-protocol response (status check + Apps-Script
    /// HTML-prefix tolerance + JSON parse). Used by both the h2 and h1
    /// branches of `tunnel_request` so the parsing logic doesn't drift
    /// across transports.
    fn finalize_tunnel_response(
        &self,
        script_id: &str,
        status: u16,
        resp_body: Vec<u8>,
    ) -> Result<TunnelResponse, FronterError> {
        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body)
                .chars()
                .take(200)
                .collect::<String>();
            if should_blacklist(status, &body_txt) {
                self.blacklist_script(script_id, &format!("HTTP {}", status));
            }
            return Err(FronterError::Relay(format!(
                "tunnel HTTP {}: {}",
                status, body_txt
            )));
        }
        let text = std::str::from_utf8(&resp_body)
            .map_err(|_| FronterError::BadResponse("non-utf8 tunnel response".into()))?
            .trim();
        // Apps Script may prepend HTML on cold-start or quota-exceeded
        // pages; extract the first {...} block tolerantly so we don't
        // bail on a recoverable warning frame.
        let json_str = if text.starts_with('{') {
            text
        } else {
            let start = text.find('{').ok_or_else(|| {
                FronterError::BadResponse(format!(
                    "no json in tunnel response: {}",
                    &text[..text.len().min(200)]
                ))
            })?;
            let end = text.rfind('}').ok_or_else(|| {
                FronterError::BadResponse("no json end in tunnel response".into())
            })?;
            &text[start..=end]
        };
        Ok(serde_json::from_str(json_str)?)
    }

    fn build_tunnel_payload(
        &self,
        op: &str,
        host: Option<&str>,
        port: Option<u16>,
        sid: Option<&str>,
        data: Option<String>,
    ) -> Result<Vec<u8>, FronterError> {
        let mut map = serde_json::Map::new();
        map.insert("k".into(), Value::String(self.auth_key.clone()));
        map.insert("t".into(), Value::String(op.to_string()));
        if let Some(h) = host {
            map.insert("h".into(), Value::String(h.to_string()));
        }
        if let Some(p) = port {
            map.insert("p".into(), Value::Number(serde_json::Number::from(p)));
        }
        if let Some(s) = sid {
            map.insert("sid".into(), Value::String(s.to_string()));
        }
        if let Some(d) = data {
            map.insert("d".into(), Value::String(d));
        }
        if !self.disable_padding {
            add_random_pad(&mut map);
        }
        Ok(serde_json::to_vec(&Value::Object(map))?)
    }

    /// Send a batch of tunnel operations in one Apps Script round trip.
    /// All active sessions' data is collected and sent together, and all
    /// responses come back in one response. This reduces N Apps Script
    /// calls to 1 per tick.
    pub async fn tunnel_batch_request(
        &self,
        ops: &[BatchOp],
    ) -> Result<BatchTunnelResponse, FronterError> {
        let script_id = self.next_script_id();
        self.tunnel_batch_request_to(&script_id, ops).await
    }

    /// Like `tunnel_batch_request` but targets a specific deployment ID.
    /// Used by the pipeline mux to pin a batch to a deployment whose
    /// per-account concurrency slot has already been acquired.
    pub async fn tunnel_batch_request_to(
        &self,
        script_id: &str,
        ops: &[BatchOp],
    ) -> Result<BatchTunnelResponse, FronterError> {
        let mut map = serde_json::Map::new();
        map.insert("k".into(), Value::String(self.auth_key.clone()));
        map.insert("t".into(), Value::String("batch".into()));
        map.insert("ops".into(), serde_json::to_value(ops)?);
        if !self.disable_padding {
            add_random_pad(&mut map);
        }
        let payload: Bytes = Bytes::from(serde_json::to_vec(&Value::Object(map))?);

        let path = format!("/macros/s/{}/exec", script_id);

        // h2 fast path. A batch carries N stateful tunnel ops — each
        // `data`/`udp_data`/`connect` may have already executed
        // upstream when the response framing failed. Replaying the
        // whole batch on h1 risks duplicating every op in it. Only
        // fall back when h2 definitely never sent. Honors
        // user-configured batch_timeout so a slow but legitimate
        // batch isn't cut off at an arbitrary fixed cap.
        match self
            .h2_relay_request(&path, payload.clone(), self.batch_timeout)
            .await
        {
            Ok((status, _hdrs, _resp_body)) if is_h2_fronting_refusal_status(status) => {
                // Edge rejected the batch before forwarding. Safe to
                // fall back: no batched op reached Apps Script, so
                // replaying via h1 won't double-fire any of them.
                self.sticky_disable_h2_for_fronting_refusal(status, "tunnel batch")
                    .await;
                // fall through to h1
            }
            Ok((status, _hdrs, resp_body)) => {
                return self.finalize_batch_response(script_id, status, resp_body);
            }
            Err((e, RequestSent::No)) => {
                tracing::debug!(
                    "h2 batch request pre-send failure: {} — falling back to h1",
                    e
                );
            }
            Err((e, RequestSent::Maybe)) => {
                tracing::warn!(
                    "h2 batch request post-send failure: {} — \
                     not replaying on h1 to avoid duplicating batched ops",
                    e
                );
                return Err(e);
            }
        }

        let mut entry = self.acquire().await?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response(&mut entry.stream).await?;

        // Follow redirect chain
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) { break; }
            let Some(loc) = header_get(&resp_headers, "location") else { break; };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\nHost: {rhost}\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) = read_http_response(&mut entry.stream).await?;
            status = s; resp_headers = h; resp_body = b;
        }

        // Route through the same `finalize_batch_response` helper the
        // h2 path uses. This keeps the redacted-logging policy in
        // exactly one place — the previous inline parse here logged
        // raw payload at debug AND error level, which leaked the
        // base64-encoded tunneled bytes (TCP/UDP packets, possibly
        // app data or credentials) into bug-report logs. Both
        // transports now emit only `status=` + `body_len=`, with the
        // raw body gated behind RUST_LOG=trace.
        let resp = self.finalize_batch_response(script_id, status, resp_body)?;
        self.release(entry).await;
        Ok(resp)
    }

    /// Parse a batch-tunnel response body once we already have it in
    /// hand — used by the h2 fast path in `tunnel_batch_request_to`,
    /// where the response is read off a multiplexed stream rather than
    /// drained from a checked-out socket. Mirrors the validate-and-parse
    /// tail of the h1 path (status check + JSON extraction +
    /// quota-blacklist book-keeping).
    fn finalize_batch_response(
        &self,
        script_id: &str,
        status: u16,
        resp_body: Vec<u8>,
    ) -> Result<BatchTunnelResponse, FronterError> {
        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body)
                .chars()
                .take(200)
                .collect::<String>();
            if should_blacklist(status, &body_txt) {
                self.blacklist_script(script_id, &format!("HTTP {}", status));
            }
            return Err(FronterError::Relay(format!(
                "batch tunnel HTTP {}: {}",
                status, body_txt
            )));
        }
        let text = std::str::from_utf8(&resp_body)
            .map_err(|_| FronterError::BadResponse("non-utf8 batch response".into()))?
            .trim();
        let json_str = if text.starts_with('{') {
            text
        } else {
            let start = text.find('{').ok_or_else(|| {
                FronterError::BadResponse(format!(
                    "no json in batch response: {}",
                    &text[..text.len().min(200)]
                ))
            })?;
            let end = text.rfind('}').ok_or_else(|| {
                FronterError::BadResponse("no json end in batch response".into())
            })?;
            &text[start..=end]
        };
        // Don't log payload content. Batch responses carry base64-encoded
        // tunneled bytes (TCP/UDP packets, possibly app data, possibly
        // credentials), and even at debug level a leaked log line ends
        // up in user-shared bug reports. Status + length are sufficient
        // for diagnosis; full body is available behind RUST_LOG=trace.
        tracing::debug!(
            "batch response: status={} body_len={}",
            status,
            json_str.len()
        );
        tracing::trace!(
            "batch response body (trace only): {}",
            &json_str[..json_str.len().min(500)]
        );
        match serde_json::from_str(json_str) {
            Ok(v) => Ok(v),
            Err(e) => {
                // Same redaction policy on the error path. Length and
                // the serde error message are enough to locate the
                // parse failure (offset / unexpected-token info comes
                // from `e` itself); the raw body is trace-only.
                tracing::error!(
                    "batch JSON parse error: {} (body_len={})",
                    e,
                    json_str.len()
                );
                tracing::trace!(
                    "batch parse-error body (trace only): {}",
                    &json_str[..json_str.len().min(300)]
                );
                Err(FronterError::Json(e))
            }
        }
    }
}

/// Strip connection-specific headers (matches Code.gs SKIP_HEADERS) and
/// strip Accept-Encoding: br (Apps Script can't decompress brotli).
/// Extract the host (no scheme, no port, no path) from a URL string.
/// Returns None for malformed / scheme-less inputs.
/// Trim X/Twitter GraphQL URLs down to just the `variables=` query param,
/// stripping everything from the first `&` in the query onward. See the
/// `normalize_x_graphql` config field for the why.
///
/// Exact pattern mirrored from the Python community patch (issue #16):
///
///   host == "x.com"
///   && path starts with "/i/api/graphql/"
///   && query starts with "variables="
///   → truncate at first `&` past the `?`.
///
/// Returns the possibly-rewritten URL. If the URL doesn't match the
/// pattern the input is returned unchanged (as an owned String — the
/// allocation is cheap on the slow path and keeps the caller's
/// type-signature-juggling simple).
// ─── HTTP response helpers used by relay_parallel_range ──────────────────

/// Split an HTTP/1.x response blob into `(status, headers, body)`.
/// Returns `None` if the buffer doesn't even have a status line + CRLFCRLF
/// separator — the caller should then pass the bytes through unchanged.
fn split_response(raw: &[u8]) -> Option<(u16, Vec<(String, String)>, &[u8])> {
    // Locate end-of-headers.
    let sep = b"\r\n\r\n";
    let sep_pos = raw.windows(sep.len()).position(|w| w == sep)?;
    let head = &raw[..sep_pos];
    let body = &raw[sep_pos + sep.len()..];

    let mut lines = head.split(|&b| b == b'\n');
    let status_line = lines.next()?;
    // Status line: "HTTP/1.1 206 Partial Content"
    let status_line = std::str::from_utf8(status_line).ok()?.trim_end_matches('\r');
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next()?;
    let code = parts.next()?.parse::<u16>().ok()?;

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Some((code, headers, body))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentRange {
    start: u64,
    end: u64,
    total: u64,
}

/// Parse `Content-Range: bytes START-END/TOTAL`.
fn parse_content_range(headers: &[(String, String)]) -> Option<ContentRange> {
    let cr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-range"))?;
    let value = cr.1.trim();
    let (unit, rest) = value.split_once(' ')?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (range, total) = rest.trim_start().split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = end.trim().parse::<u64>().ok()?;
    let total = total.trim().parse::<u64>().ok()?;
    if start > end || total == 0 || end >= total {
        return None;
    }
    Some(ContentRange { start, end, total })
}

/// Pull the total size out of a valid `Content-Range: bytes START-END/TOTAL` header.
fn parse_content_range_total(headers: &[(String, String)]) -> Option<u64> {
    parse_content_range(headers).map(|r| r.total)
}

fn content_range_matches_body(range: ContentRange, body_len: usize) -> bool {
    body_len > 0 && (range.end - range.start + 1) == body_len as u64
}

fn validate_probe_range(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    requested_end: u64,
) -> Option<ContentRange> {
    if status != 206 {
        return None;
    }
    let range = parse_content_range(headers)?;
    if range.start != 0 || range.end > requested_end {
        return None;
    }
    if content_range_matches_body(range, body.len())
        || probe_range_covers_complete_entity(range, requested_end)
    {
        return Some(range);
    }
    None
}

fn probe_range_covers_complete_entity(range: ContentRange, requested_end: u64) -> bool {
    // Apps Script may decode a gzip body while preserving the origin's
    // compressed Content-Range. For the synthetic first probe only, a
    // 0..total-1 range within the requested chunk is enough to prove we
    // already have the complete entity; later chunks still require exact
    // Content-Range/body length validation in extract_exact_range_body().
    range.start == 0
        && range.end.saturating_add(1) >= range.total
        && range.total <= requested_end.saturating_add(1)
}

fn checked_stitched_range_capacity(total: u64) -> Option<usize> {
    if total > MAX_STITCHED_RANGE_BYTES {
        return None;
    }
    usize::try_from(total).ok()
}

fn extract_exact_range_body(
    raw: &[u8],
    start: u64,
    end: u64,
    total: u64,
) -> Result<Vec<u8>, &'static str> {
    let (status, headers, body) = split_response(raw).ok_or("malformed HTTP response")?;
    if status != 206 {
        return Err("expected 206 Partial Content");
    }
    let range = parse_content_range(&headers).ok_or("missing or invalid Content-Range")?;
    if range.start != start || range.end != end || range.total != total {
        return Err("unexpected Content-Range");
    }
    if !content_range_matches_body(range, body.len()) {
        return Err("Content-Range/body length mismatch");
    }
    Ok(body.to_vec())
}

/// Rewrite a 206 response to a 200 OK, dropping Content-Range and
/// recomputing Content-Length. Used when we probed with a synthetic
/// Range header but the client sent a plain GET — handing a 206 back to
/// XHR/fetch code on some sites (x.com, Cloudflare Turnstile) makes them
/// treat the response as aborted. Same rationale as the upstream Python
/// `_rewrite_206_to_200`.
fn rewrite_206_to_200(raw: &[u8]) -> Vec<u8> {
    let (_status, headers, body) = match split_response(raw) {
        Some(v) => v,
        None => return raw.to_vec(),
    };
    assemble_full_200(&headers, body)
}

/// Build a complete `HTTP/1.1 200 OK` response with the given header
/// set + body. Skips headers the caller shouldn't be forwarding
/// verbatim (content-length/range/encoding, transfer-encoding, hop-by-hop
/// wire-level stuff) — we set Content-Length from the body we're
/// actually shipping.
fn assemble_full_200(src_headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let skip = |k: &str| {
        matches!(
            k.to_ascii_lowercase().as_str(),
            "content-length"
                | "content-range"
                | "content-encoding"
                | "transfer-encoding"
                | "connection"
                | "keep-alive",
        )
    };
    let mut out: Vec<u8> = b"HTTP/1.1 200 OK\r\n".to_vec();
    for (k, v) in src_headers {
        if skip(k) {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

fn normalize_x_graphql_url(url: &str) -> String {
    // Split host from the rest. We accept both "x.com" and common legacy
    // forms; the Python patch only checks x.com so we do the same to be
    // safe about the endpoint actually accepting truncated requests.
    let Some(rest) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) else {
        return url.to_string();
    };
    let Some(slash) = rest.find('/') else {
        return url.to_string();
    };
    let host = &rest[..slash];
    let path_and_query = &rest[slash..];

    // Strip port if present in host.
    let host_no_port = host.split(':').next().unwrap_or(host);
    if host_no_port != "x.com" {
        return url.to_string();
    }

    let Some(q_idx) = path_and_query.find('?') else {
        return url.to_string();
    };
    let path = &path_and_query[..q_idx];
    let query = &path_and_query[q_idx + 1..];

    if !path.starts_with("/i/api/graphql/") || !query.starts_with("variables=") {
        return url.to_string();
    }

    let new_query = match query.find('&') {
        Some(amp) => &query[..amp],
        None => query,
    };
    let scheme = if url.starts_with("https://") { "https://" } else { "http://" };
    format!("{}{}{}?{}", scheme, host, path, new_query)
}

/// Maximum bytes of random padding appended to outbound Apps Script
/// JSON request bodies. Picked so the per-request padding distribution
/// (uniformly 0..MAX) shifts the body length enough to defeat naive
/// length-fingerprint DPI without bloating bandwidth — at the average
/// 512-byte add, on a typical 2 KB tunnel batch this is +25%, which is
/// negligible compared to Apps Script's per-call latency floor anyway.
/// (Issue #313, #365 Section 1 — DPI evasion.)
const MAX_RANDOM_PAD_BYTES: usize = 1024;

/// Insert a `_pad` field of random length (0..MAX_RANDOM_PAD_BYTES)
/// into a request payload before serialization. Server-side ignores
/// unknown JSON fields, so this is fully backward-compatible with old
/// `Code.gs` / `CodeFull.gs` deployments — the pad is just along for
/// the ride.
///
/// Random bytes are base64-encoded (NO inner JSON-escape worries) and
/// the pad LENGTH itself is uniformly distributed, so packet sizes
/// land all over the place rather than clustering at a few discrete
/// peaks. That's the property DPI's length-distribution clustering
/// fingerprints can't match.
fn add_random_pad(map: &mut serde_json::Map<String, Value>) {
    let mut rng = thread_rng();
    let len = rng.gen_range(0..=MAX_RANDOM_PAD_BYTES);
    if len == 0 {
        // Skip the field entirely sometimes — adds another bit of
        // distribution variance (presence-vs-absence of `_pad` itself).
        return;
    }
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    map.insert("_pad".into(), Value::String(B64.encode(&buf)));
}

/// "YYYY-MM-DD" of the current Pacific Time date. Used as the daily-reset
/// boundary for `today_calls` / `today_bytes` because **Apps Script's
/// quota counter resets at midnight Pacific Time, not UTC** — that's
/// where Google's quota bookkeeping lives. We format manually so this
/// stays std-only and doesn't pull `time-tz` or `chrono` plus a ~3 MB
/// IANA tzdb just for one ~50-line helper. (Issue #230, #362.)
///
/// PT offset depends on DST: PST = UTC-8, PDT = UTC-7. We use the
/// stable US DST rule (2nd Sunday of March 02:00 → 1st Sunday of
/// November 02:00 = PDT, otherwise PST). The hour-of-day boundary on
/// transition days is approximated; this drifts by up to 1h for at
/// most 2h/year on the spring-forward / fall-back transitions, which
/// is fine for a daily countdown.
fn current_pt_day_key() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pt_secs = unix_to_pt_seconds(secs);
    let (y, m, d) = unix_to_ymd_utc(pt_secs);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Seconds until the next 00:00 Pacific Time. Used by the UI to render
/// a "resets in Xh Ym" countdown matching Apps Script's actual quota
/// reset cadence (#230, #362). Conservative: if the system clock is
/// broken we return 0 instead of a huge negative-looking number.
fn seconds_until_pacific_midnight() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pt_secs = unix_to_pt_seconds(secs);
    let day = 86_400u64;
    let rem = pt_secs % day;
    if rem == 0 {
        day
    } else {
        day - rem
    }
}

/// Convert Unix UTC seconds to "Pacific Time as if it were UTC" seconds,
/// i.e. add the PT-from-UTC offset (negative for the western hemisphere
/// becomes a subtraction). Result is suitable for feeding into
/// `unix_to_ymd_utc` to extract the PT calendar date, or for `% 86_400`
/// to find PT seconds-into-day.
fn unix_to_pt_seconds(utc_secs: u64) -> u64 {
    // First-pass guess at PT date using PST (-8) — used to determine
    // whether DST is currently in effect, which then settles the actual
    // offset. The two-pass approach avoids the chicken-and-egg of
    // "I need the PT date to know if it's DST, but I need the offset
    // to compute the PT date." A 1-hour fudge in the guess is harmless
    // because DST never starts within the first hour after midnight
    // PST or ends within the first hour after midnight PDT.
    let pst_guess = utc_secs.saturating_sub(8 * 3600);
    let (y, m, d) = unix_to_ymd_utc(pst_guess);
    let offset_secs = if pacific_is_dst(y, m, d) {
        7 * 3600
    } else {
        8 * 3600
    };
    utc_secs.saturating_sub(offset_secs)
}

/// Whether Pacific Time is observing daylight saving on the given
/// calendar date (year, month=1..12, day=1..31). US DST window:
/// 2nd Sunday of March through 1st Sunday of November. The transition
/// hour itself (02:00 local) is approximated to whole-day boundaries —
/// good enough for a daily-quota countdown.
fn pacific_is_dst(year: i64, month: u32, day: u32) -> bool {
    if month < 3 || month > 11 {
        return false;
    }
    if month > 3 && month < 11 {
        return true;
    }
    if month == 3 {
        let dst_start = nth_sunday_of_month(year, 3, 2);
        day >= dst_start
    } else {
        // month == 11
        let dst_end = nth_sunday_of_month(year, 11, 1);
        day < dst_end
    }
}

/// Day-of-month for the Nth Sunday (1-indexed) of (year, month). Uses
/// Sakamoto's method for the month's-1st day-of-week, then offsets to
/// the desired Sunday. Pure arithmetic, no calendar tables.
fn nth_sunday_of_month(year: i64, month: u32, nth: u32) -> u32 {
    // Sakamoto's day-of-week. 0 = Sunday.
    static T: [i64; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let y = if month < 3 { year - 1 } else { year };
    let m = month as i64;
    let dow_of_1st =
        ((y + y / 4 - y / 100 + y / 400 + T[(m - 1) as usize] + 1).rem_euclid(7)) as u32;
    let first_sunday = if dow_of_1st == 0 { 1 } else { 8 - dow_of_1st };
    first_sunday + (nth - 1) * 7
}

/// Convert a Unix timestamp (seconds since 1970-01-01 UTC) to a
/// (year, month, day) tuple, UTC. Standalone so we can stay
/// std-only — no chrono/time/jiff dependency pulled for one caller.
///
/// Algorithm: Howard Hinnant's civil_from_days, widely cited and
/// simple enough to audit by eye. Works for years 1970–9999 which
/// we'll outlive.
fn unix_to_ymd_utc(secs: u64) -> (i64, u32, u32) {
    let days = (secs / 86_400) as i64;
    // Shift so day 0 is 0000-03-01 (Hinnant's era-based trick).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Parse the exit-node JSON envelope back into a raw HTTP/1.1
/// response. The envelope shape is:
///
/// - On success: `{ "s": <status u16>, "h": { ... }, "b": "<base64>" }`
/// - On exit-node-side error: `{ "e": "<message>" }` with HTTP 4xx/5xx
///   from exit-node's own status code (decoded from the outer Apps Script
///   layer, not the inner field).
///
/// We synthesize a complete HTTP/1.1 response from these fields so the
/// MITM TLS write-back path sees the same shape it gets from the regular
/// Apps Script relay (status line + headers + body).
fn parse_exit_node_response(body: &[u8]) -> Result<Vec<u8>, FronterError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| {
        FronterError::Relay(format!(
            "exit-node response not valid JSON ({}): {}",
            e,
            String::from_utf8_lossy(&body[..body.len().min(200)])
        ))
    })?;

    // Surface exit-node's internal errors clearly rather than as a 502
    // from the outer envelope. The `{e: "..."}` shape is what the exit-node's
    // script emits on bad PSK, malformed URL, or any caught exception.
    if let Some(err_msg) = v.get("e").and_then(|x| x.as_str()) {
        return Err(FronterError::Relay(format!(
            "exit node refused or errored: {}",
            err_msg
        )));
    }

    let status = v
        .get("s")
        .and_then(|x| x.as_u64())
        .map(|n| n as u16)
        .unwrap_or(502);
    let body_b64 = v.get("b").and_then(|x| x.as_str()).unwrap_or("");
    let body_bytes = if body_b64.is_empty() {
        Vec::new()
    } else {
        B64.decode(body_b64).map_err(|e| {
            FronterError::Relay(format!("exit-node body base64 decode failed: {}", e))
        })?
    };

    // Reconstruct headers. Skip hop-by-hop / would-double-up headers
    // (Content-Length comes from our own length count below; the outer
    // Apps Script transport already handled Transfer-Encoding/chunked).
    const SKIP_RESPONSE_HEADERS: &[&str] = &[
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
    ];

    let mut out = Vec::with_capacity(body_bytes.len() + 256);
    let _ = std::io::Write::write_fmt(
        &mut out,
        format_args!("HTTP/1.1 {} {}\r\n", status, status_reason(status)),
    );
    if let Some(headers_obj) = v.get("h").and_then(|x| x.as_object()) {
        for (k, v_val) in headers_obj {
            let lc = k.to_ascii_lowercase();
            if SKIP_RESPONSE_HEADERS.contains(&lc.as_str()) {
                continue;
            }
            if let Some(val_str) = v_val.as_str() {
                let _ = std::io::Write::write_fmt(
                    &mut out,
                    format_args!("{}: {}\r\n", k, val_str),
                );
            }
        }
    }
    let _ = std::io::Write::write_fmt(
        &mut out,
        format_args!("Content-Length: {}\r\n\r\n", body_bytes.len()),
    );
    out.extend_from_slice(&body_bytes);
    Ok(out)
}

/// Minimal HTTP status reason-phrase table for synthesizing status
/// lines in `parse_exit_node_response`. Browsers don't actually parse
/// the reason phrase (only the status code matters), but a recognizable
/// string makes log lines readable.
fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or("");
    // Strip userinfo if present.
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    // Strip port. Handle IPv6 literals in brackets.
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // [::1]:443 -> ::1
        stripped.split_once(']').map(|(h, _)| h).unwrap_or(stripped)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// The default pool of SNI names that share the Google Front End with
/// `www.google.com`. Used both when auto-expanding from `front_domain` and
/// when the UI wants to show the starting candidates for the SNI editor.
pub const DEFAULT_GOOGLE_SNI_POOL: &[&str] = &[
    "www.google.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "calendar.google.com",
    // accounts.google.com — standard Google account service, covered by
    // the *.google.com wildcard cert. Previously listed as
    // accounts.googl.com (issue #42), but googl.com is NOT in the SAN
    // list of Google's GFE certificate — connections with verify_ssl=true
    // fail with "certificate not valid for name" when the round-robin
    // lands on it.
    "accounts.google.com",
    // scholar.google.com — reported
    // in #47 as a DPI-passing SNI on MCI / Samantel. Covered by the
    // core *.google.com cert so it handshakes normally against
    // google_ip:443.
    "scholar.google.com",
    // Additional Google properties for rotation. Ported from upstream
    // Python `FRONT_SNI_POOL_GOOGLE` (masterking32/MasterHttpRelayVPN
    // commit 57738ec, "Add additional Google services to exclusion
    // lists"). All served off the same GFE IP range, all covered by the
    // wildcard cert, all give the DPI-fingerprint spread without extra
    // config. A few of these (maps.google.com, play.google.com) reliably
    // pass DPI on carriers where the shorter `*.google.com` names don't.
    "maps.google.com",
    "chat.google.com",
    "translate.google.com",
    "play.google.com",
    "lens.google.com",
    // chromewebstore.google.com — reported in issue #75 as a working
    // SNI. Same family as the rest: wildcard cert, GFE-hosted,
    // handshake against google_ip:443 with no content negotiation.
    "chromewebstore.google.com",
];

/// Build the pool of SNI hosts used for outbound connections to the Google
/// edge.
///
/// Precedence:
/// 1. If `user_pool` is non-empty, use it verbatim (user is in charge).
/// 2. If `primary` is one of the DEFAULT_GOOGLE_SNI_POOL entries, auto-expand
///    to the full default list with `primary` first. This gives the per-SNI
///    connection-count fingerprint spread without the user configuring
///    anything.
/// 3. Otherwise — custom / non-Google `primary` — use just `[primary]`, since
///    we have no way to verify which sibling names share a non-Google edge.
///
/// All entries MUST be hosted on the same edge as `connect_host`, otherwise
/// the TLS handshake will land on the wrong server.
pub fn build_sni_pool_for(primary: &str, user_pool: &[String]) -> Vec<String> {
    let primary = primary.trim().to_string();
    let user_filtered: Vec<String> = user_pool
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !user_filtered.is_empty() {
        return user_filtered;
    }

    let looks_like_google_edge = DEFAULT_GOOGLE_SNI_POOL.iter().any(|s| *s == primary);
    let mut pool = vec![primary.clone()];
    if looks_like_google_edge {
        for s in DEFAULT_GOOGLE_SNI_POOL {
            if *s != primary {
                pool.push((*s).to_string());
            }
        }
    }
    pool
}

/// Back-compat thin wrapper for the old callers / tests.
fn build_sni_pool(primary: &str) -> Vec<String> {
    build_sni_pool_for(primary, &[])
}

pub fn filter_forwarded_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    const SKIP: &[&str] = &[
        // Hop-by-hop / framing — must not be forwarded across the proxy.
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "proxy-authorization",
        // Identity-revealing forwarding headers (issue #104).
        // If the user sits behind another proxy or uses a browser
        // extension that inserts any of these, they'd normally carry
        // the client's real IP. We strip every known variant so the
        // origin server only ever sees whatever source IP the Apps
        // Script or GFE path terminates on — never the user's home IP.
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-forwarded-server",
        "x-forwarded-ssl",
        "forwarded",
        "via",
        "x-real-ip",
        "x-client-ip",
        "x-originating-ip",
        "true-client-ip",
        "cf-connecting-ip",
        "fastly-client-ip",
        "x-cluster-client-ip",
        "client-ip",
    ];
    headers
        .iter()
        .filter_map(|(k, v)| {
            let lk = k.to_ascii_lowercase();
            if SKIP.contains(&lk.as_str()) {
                return None;
            }
            if lk == "accept-encoding" {
                let cleaned = strip_brotli_from_accept_encoding(v);
                if cleaned.is_empty() {
                    return None;
                }
                return Some((k.clone(), cleaned));
            }
            Some((k.clone(), v.clone()))
        })
        .collect()
}

fn strip_brotli_from_accept_encoding(value: &str) -> String {
    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
    let kept: Vec<&str> = parts
        .into_iter()
        .filter(|p| {
            let tok = p.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            tok != "br" && tok != "zstd"
        })
        .collect();
    kept.join(", ")
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn parse_redirect(location: &str) -> (String, Option<String>) {
    // Absolute URL: http(s)://host/path?query
    if let Some(rest) = location.strip_prefix("https://").or_else(|| location.strip_prefix("http://")) {
        let slash = rest.find('/').unwrap_or(rest.len());
        let host = rest[..slash].to_string();
        let path = if slash < rest.len() { rest[slash..].to_string() } else { "/".into() };
        return (path, Some(host));
    }
    // Relative path.
    (location.to_string(), None)
}

/// Read a single HTTP/1.1 response from the stream. Keep-alive safe: respects
/// Content-Length or chunked transfer-encoding.
async fn read_http_response<S>(stream: &mut S) -> Result<(u16, Vec<(String, String)>, Vec<u8>), FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = timeout(Duration::from_secs(10), stream.read(&mut tmp)).await
            .map_err(|_| FronterError::Timeout)??;
        if n == 0 {
            return Err(FronterError::BadResponse("connection closed before headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 1024 * 1024 {
            return Err(FronterError::BadResponse("headers too large".into()));
        }
    };

    let header_section = &buf[..header_end];
    let header_str = std::str::from_utf8(header_section)
        .map_err(|_| FronterError::BadResponse("non-utf8 headers".into()))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = parse_status_line(status_line)?;

    let mut headers_out: Vec<(String, String)> = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers_out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    let content_length: Option<usize> = header_get(&headers_out, "content-length")
        .and_then(|v| v.parse().ok());
    let te = header_get(&headers_out, "transfer-encoding").unwrap_or_default();
    let is_chunked = te.to_ascii_lowercase().contains("chunked");

    if is_chunked {
        body = read_chunked(stream, body).await?;
    } else if let Some(cl) = content_length {
        while body.len() < cl {
            let need = cl - body.len();
            let want = need.min(tmp.len());
            // Handle ungraceful TLS close-without-close_notify (rustls
            // surfaces this as `io::ErrorKind::UnexpectedEof`). Some
            // origins — notably exit-node path through Apps
            // Script (#585, v1.9.4) and certain Apps Script `Connection:
            // close` responses — terminate the underlying TCP without
            // sending the TLS close_notify alert first. Treat that the
            // same as a clean `n == 0`: if we already have the full body
            // declared by Content-Length, the response *is* complete.
            // Only propagate the error if Content-Length couldn't be
            // satisfied (real truncation, not a polite-protocol violation).
            let read_res = timeout(
                Duration::from_secs(20),
                stream.read(&mut tmp[..want]),
            )
            .await
            .map_err(|_| FronterError::Timeout)?;
            let n = match read_res {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(FronterError::BadResponse(
                    "connection closed before full response body".into(),
                ));
            }
            body.extend_from_slice(&tmp[..n]);
        }
    } else {
        // No framing — read until short timeout, EOF, or ungraceful
        // TLS close (UnexpectedEof). Each is treated as "we got what
        // the peer wanted to send"; the response we already have is
        // returned to the caller. UnexpectedEof here is the most common
        // case for `Connection: close` responses from servers that
        // don't bother with TLS close_notify (#585).
        loop {
            match timeout(Duration::from_secs(2), stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => body.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }
        }
    }

    // gzip decompress if content-encoding says so.
    if let Some(enc) = header_get(&headers_out, "content-encoding") {
        if enc.eq_ignore_ascii_case("gzip") {
            if let Ok(decoded) = decode_gzip(&body) {
                body = decoded;
            }
        }
    }

    Ok((status, headers_out, body))
}

async fn read_chunked<S>(stream: &mut S, mut buf: Vec<u8>) -> Result<Vec<u8>, FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 16384];
    loop {
        let size_line_owned = std::str::from_utf8(&read_crlf_line(stream, &mut buf, &mut tmp).await?)
            .map_err(|_| FronterError::BadResponse("bad chunk size".into()))?
            .trim()
            .to_string();
        if size_line_owned.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(
            size_line_owned.split(';').next().unwrap_or(""),
            16,
        )
        .map_err(|_| FronterError::BadResponse(format!("bad chunk size '{}'", size_line_owned)))?;
        if size == 0 {
            loop {
                if read_crlf_line(stream, &mut buf, &mut tmp).await?.is_empty() {
                    return Ok(out);
                }
            }
        }
        while buf.len() < size + 2 {
            // UnexpectedEof tolerance — see read_http_response for
            // rationale. Treated as `n == 0`; if we haven't accumulated
            // the full chunk yet, that's still a real truncation and
            // we return BadResponse below.
            let read_res = timeout(Duration::from_secs(20), stream.read(&mut tmp))
                .await
                .map_err(|_| FronterError::Timeout)?;
            let n = match read_res {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(FronterError::BadResponse(
                    "connection closed mid-chunked response".into(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        if &buf[size..size + 2] != b"\r\n" {
            return Err(FronterError::BadResponse(
                "chunk missing trailing CRLF".into(),
            ));
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<Vec<u8>, FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(idx) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..idx].to_vec();
            buf.drain(..idx + 2);
            return Ok(line);
        }
        let n = timeout(Duration::from_secs(20), stream.read(tmp)).await
            .map_err(|_| FronterError::Timeout)??;
        if n == 0 {
            return Err(FronterError::BadResponse(
                "connection closed mid-chunked response".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn decode_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut out = Vec::with_capacity(data.len() * 2);
    flate2::read::GzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<u16, FronterError> {
    // "HTTP/1.1 200 OK"
    let mut parts = line.split_whitespace();
    let _version = parts.next();
    let code = parts.next().ok_or_else(|| {
        FronterError::BadResponse(format!("bad status line: {}", line))
    })?;
    code.parse::<u16>().map_err(|_| FronterError::BadResponse(format!("bad status code: {}", code)))
}

/// Returns `true` if the HTTP method is safe to fan-out across multiple
/// Apps Script deployments (i.e. idempotent per RFC 9110 §9.2.2). Used
/// by `do_relay_with_retry` to gate the `parallel_relay` fan-out so that
/// non-idempotent operations (POST / PUT / PATCH / DELETE) don't double-
/// fire at the destination — Apps Script `UrlFetchApp.fetch()` can't be
/// cancelled mid-request from our side, so every parallel attempt
/// completes server-side even when our `select_ok` already returned a
/// winner. See #743 for the user-visible bug (duplicate POSTs).
fn is_method_safe_for_fanout(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
}

/// Recognize HTTP statuses from the h2 path that mean "this edge
/// won't accept your fronted h2 request, but might accept the same
/// request over h1." Used to trigger an automatic sticky-disable of
/// the h2 fast path + h1 fallback.
///
/// 421 (Misdirected Request) is the spec signal: per RFC 7540
/// §9.1.2, the server returns it when the connection's authority is
/// not appropriate for the request URI. With domain fronting that
/// means the edge enforced "TLS SNI must match :authority" — true
/// on h2 (the server sees both pseudo-headers in cleartext) but
/// historically lenient on h1 (the encrypted Host header is what
/// the bypass relies on). Treating 421 as h2-fallback rather than
/// "Apps Script error" prevents h2 default-on from breaking
/// previously-working h1 deployments.
///
/// Other edge-level rejects (403, etc.) are ambiguous — could be a
/// real Apps Script geoblock or a real upstream — so we don't
/// blanket-treat them.
///
/// The h2 layer treats this as a "request not sent upstream"
/// outcome (the edge rejected before forwarding to Apps Script),
/// so falling back to h1 is safe with no duplication risk.
fn is_h2_fronting_refusal_status(status: u16) -> bool {
    status == 421
}

/// Parse the JSON envelope from Apps Script and build a raw HTTP response.
fn parse_relay_json(body: &[u8]) -> Result<Vec<u8>, FronterError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| FronterError::BadResponse("non-utf8 json".into()))?
        .trim();
    if text.is_empty() {
        return Err(FronterError::BadResponse("empty relay body".into()));
    }

    let data: RelayResponse = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            // Some deployments (legacy Code.gs that used HtmlService for
            // _json, or our own doGet hit accidentally via a redirect
            // chain) wrap the JSON inside the goog.script sandbox iframe
            // as `goog.script.init("\x7b...userHtml...\x7d", "", undefined)`.
            // Try that unwrap first — if it succeeds, the inner userHtml
            // *is* our JSON. Mirrors upstream's Python client extractor.
            if let Some(unwrapped) = extract_apps_script_user_html(text) {
                if let Ok(v) = serde_json::from_str(&unwrapped) {
                    v
                } else {
                    return Err(FronterError::BadResponse(format!(
                        "no json in apps_script user_html: {}",
                        &unwrapped[..unwrapped.len().min(200)]
                    )));
                }
            } else {
                // Last resort: extract first { ... last }, in case Apps
                // Script prepended HTML preamble before the raw JSON.
                let start = text.find('{').ok_or_else(|| {
                    FronterError::BadResponse(format!(
                        "no json in: {}",
                        &text[..text.len().min(200)]
                    ))
                })?;
                let end = text.rfind('}').ok_or_else(|| {
                    FronterError::BadResponse(format!(
                        "no json end in: {}",
                        &text[..text.len().min(200)]
                    ))
                })?;
                serde_json::from_str(&text[start..=end])?
            }
        }
    };

    if let Some(e) = data.e {
        return Err(FronterError::Relay(e));
    }

    let status = data.s.unwrap_or(200);
    let status_text = status_text(status);
    let resp_body = match data.b {
        Some(b) => B64
            .decode(b)
            .map_err(|e| FronterError::BadResponse(format!("bad relay body base64: {}", e)))?,
        None => Vec::new(),
    };

    let mut out = Vec::with_capacity(resp_body.len() + 256);
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status, status_text).as_bytes());

    const SKIP: &[&str] = &[
        "transfer-encoding",
        "connection",
        "keep-alive",
        "content-length",
        "content-encoding",
    ];

    if let Some(hmap) = data.h {
        for (k, v) in hmap {
            let lk = k.to_ascii_lowercase();
            if SKIP.contains(&lk.as_str()) {
                continue;
            }
            match v {
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = value_to_header_str(&item) {
                            out.extend_from_slice(format!("{}: {}\r\n", k, s).as_bytes());
                        }
                    }
                }
                other => {
                    if let Some(s) = value_to_header_str(&other) {
                        out.extend_from_slice(format!("{}: {}\r\n", k, s).as_bytes());
                    }
                }
            }
        }
    }

    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", resp_body.len()).as_bytes());
    out.extend_from_slice(&resp_body);
    Ok(out)
}

/// Unwrap the `goog.script.init` sandbox iframe that wraps every
/// HtmlService web-app response. The wrapper text looks roughly like:
///
/// ```text
/// <html>...
/// goog.script.init("\x7b\x22userHtml\x22:\x22{...}\x22,...\x7d", "", undefined);
/// ...
/// ```
///
/// where the first parameter is a JSON string (with `\xNN` byte-escapes
/// for `{`, `"`, etc.) whose `userHtml` field carries our actual JSON
/// body. We find the marker, decode the byte-escapes, parse the outer
/// JSON, and return `userHtml`. Returns `None` if any step doesn't
/// match — the caller falls back to the brace-scan path.
///
/// Mirrors `_extract_apps_script_user_html` in upstream Python client.
fn extract_apps_script_user_html(text: &str) -> Option<String> {
    let marker = "goog.script.init(\"";
    let start_idx = text.find(marker)? + marker.len();
    // The marker is closed by `", "", undefined` (Apps Script always
    // emits this exact literal — there are two more positional args after
    // the JSON string, both empty / undefined).
    let end_marker = "\", \"\", undefined";
    let end_idx = text[start_idx..].find(end_marker)? + start_idx;
    let encoded = &text[start_idx..end_idx];

    // Decode `\xNN` and `\u00NN` byte-escapes that Apps Script uses to
    // protect `{`, `"`, `\`, etc. inside the JS string literal.
    let decoded = decode_js_string_escapes(encoded)?;

    // Outer JSON — typically `{"userHtml":"<our JSON>", ...}`.
    let outer: Value = serde_json::from_str(&decoded).ok()?;
    let user_html = outer.get("userHtml")?.as_str()?;
    Some(user_html.to_string())
}

/// Minimal JS string-literal escape decoder for `\xNN`, `\uNNNN`, and
/// the standard backslash forms (`\\`, `\"`, `\n`, `\r`, `\t`, `\/`).
/// Used to unwrap the `goog.script.init("...")` parameter — Apps Script
/// emits ASCII-only `\xNN` for every non-alphanumeric byte, so the
/// decoder doesn't need to handle full Unicode surrogates.
fn decode_js_string_escapes(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c != b'\\' {
            // Fast path: copy ASCII / valid UTF-8 byte through.
            out.push(c as char);
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            return None;
        }
        let esc = bytes[i + 1];
        match esc {
            b'x' => {
                if i + 3 >= bytes.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&bytes[i + 2..i + 4]).ok()?;
                let v = u8::from_str_radix(hex, 16).ok()?;
                out.push(v as char);
                i += 4;
            }
            b'u' => {
                if i + 5 >= bytes.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).ok()?;
                let v = u32::from_str_radix(hex, 16).ok()?;
                let ch = char::from_u32(v)?;
                out.push(ch);
                i += 6;
            }
            b'\\' => { out.push('\\'); i += 2; }
            b'"' => { out.push('"'); i += 2; }
            b'\'' => { out.push('\''); i += 2; }
            b'/' => { out.push('/'); i += 2; }
            b'n' => { out.push('\n'); i += 2; }
            b'r' => { out.push('\r'); i += 2; }
            b't' => { out.push('\t'); i += 2; }
            b'b' => { out.push('\x08'); i += 2; }
            b'f' => { out.push('\x0c'); i += 2; }
            _ => return None,
        }
    }
    Some(out)
}

#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub relay_calls: u64,
    pub relay_failures: u64,
    pub coalesced: u64,
    pub bytes_relayed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_bytes: usize,
    pub blacklisted_scripts: usize,
    pub total_scripts: usize,
    /// Relay calls attributed to the current Pacific Time day. Resets
    /// at 00:00 PT (midnight Pacific) — matches Apps Script's actual
    /// quota reset cadence (#230, #362). This is what-this-process-
    /// has-done today, not the Google-side bucket.
    pub today_calls: u64,
    /// Response bytes from relay calls attributed to the current PT day.
    pub today_bytes: u64,
    /// "YYYY-MM-DD" of the PT day `today_calls` / `today_bytes` refer
    /// to. Useful for cross-referencing against Google's dashboard,
    /// which is also PT-aligned.
    pub today_key: String,
    /// Seconds until the next 00:00 PT rollover. Convenient for the UI
    /// to render "Resets in Xh Ym" without importing time libraries.
    pub today_reset_secs: u64,
    /// Calls served by the HTTP/2 multiplexed transport, across all
    /// entry points (Apps-Script direct, exit-node outer call,
    /// full-mode tunnel single op, full-mode tunnel batch).
    ///
    /// Not comparable to `relay_calls` — that counter only sees the
    /// Apps-Script-direct path. To gauge h2 health, compute
    /// `h2_calls / (h2_calls + h2_fallbacks)`.
    pub h2_calls: u64,
    /// Calls that attempted h2 but had to fall back to h1 (per-call
    /// failures, open timeout, backoff, sticky ALPN refusal). Same
    /// all-entry-points scope as `h2_calls`.
    pub h2_fallbacks: u64,
    /// True when h2 is permanently off for this fronter (config kill
    /// switch set, or peer refused h2 during ALPN). All traffic on the
    /// h1 path.
    pub h2_disabled: bool,
}

impl StatsSnapshot {
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total as f64) * 100.0
        }
    }

    pub fn fmt_line(&self) -> String {
        // h2 segment is the success ratio across all transports
        // (h2_calls + h2_fallbacks). Showing "X/Y" against relay_calls
        // would mislead — relay_calls only counts the Apps-Script
        // direct path, while h2_calls also includes exit-node and
        // tunnel paths that bypass relay_uncoalesced.
        let h2_seg = if self.h2_disabled {
            " h2=off".to_string()
        } else {
            let total = self.h2_calls + self.h2_fallbacks;
            if total == 0 {
                String::new()
            } else {
                let pct = (self.h2_calls as f64 / total as f64) * 100.0;
                format!(
                    " h2-success={}/{} ({:.0}%)",
                    self.h2_calls, total, pct
                )
            }
        };
        format!(
            "stats: relay={} ({}KB) failures={} coalesced={} cache={}/{} ({:.0}% hit, {}KB) scripts={}/{} active{}",
            self.relay_calls,
            self.bytes_relayed / 1024,
            self.relay_failures,
            self.coalesced,
            self.cache_hits,
            self.cache_hits + self.cache_misses,
            self.hit_rate(),
            self.cache_bytes / 1024,
            self.total_scripts - self.blacklisted_scripts,
            self.total_scripts,
            h2_seg,
        )
    }

    /// Hand-rolled JSON serialization so the Android side can read the
    /// snapshot via JNI without pulling `serde_derive` through this struct.
    /// Field names match the Rust side verbatim so Kotlin can `JSONObject`
    /// parse them directly.
    pub fn to_json(&self) -> String {
        fn esc(s: &str) -> String {
            s.replace('\\', "\\\\").replace('"', "\\\"")
        }
        format!(
            r#"{{"relay_calls":{},"relay_failures":{},"coalesced":{},"bytes_relayed":{},"cache_hits":{},"cache_misses":{},"cache_bytes":{},"blacklisted_scripts":{},"total_scripts":{},"today_calls":{},"today_bytes":{},"today_key":"{}","today_reset_secs":{},"h2_calls":{},"h2_fallbacks":{},"h2_disabled":{}}}"#,
            self.relay_calls,
            self.relay_failures,
            self.coalesced,
            self.bytes_relayed,
            self.cache_hits,
            self.cache_misses,
            self.cache_bytes,
            self.blacklisted_scripts,
            self.total_scripts,
            self.today_calls,
            self.today_bytes,
            esc(&self.today_key),
            self.today_reset_secs,
            self.h2_calls,
            self.h2_fallbacks,
            self.h2_disabled,
        )
    }
}

fn should_blacklist(status: u16, body: &str) -> bool {
    if status == 429 || status == 403 {
        return true;
    }
    looks_like_quota_error(body)
}

fn looks_like_quota_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("quota")
        || lower.contains("daily limit")
        || lower.contains("rate limit")
        || lower.contains("too many times")
        || lower.contains("service invoked")
        || lower.contains("bandwidth")
        || lower.contains("bandbreitenkontingent")
        || lower.contains("datenübertragungsrate")
        || lower.contains("transfer rate")
        || lower.contains("limit exceeded")
}

fn mask_script_id(id: &str) -> String {
    let n = id.chars().count();
    if n <= 8 {
        return "***".into();
    }
    let head: String = id.chars().take(4).collect();
    let tail: String = id.chars().skip(n - 4).collect();
    format!("{}...{}", head, tail)
}

fn value_to_header_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        _ => None,
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

pub fn error_response(status: u16, message: &str) -> Vec<u8> {
    let body = format!(
        "<html><body><h1>{}</h1><p>{}</p></body></html>",
        status,
        html_escape(message)
    );
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
        status,
        status_text(status),
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

// Dangerous "accept anything" TLS verifier, used only when config.verify_ssl=false.
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
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{duplex, AsyncRead, AsyncWriteExt, ReadBuf};

    // Test fixture for ungraceful TLS close: emit a fixed prefix of bytes
    // then return io::ErrorKind::UnexpectedEof on the next read. Mirrors
    // what rustls surfaces when the peer closes TCP without sending a
    // TLS close_notify alert (#585).
    struct UnexpectedEofAfter {
        bytes: Vec<u8>,
        position: usize,
    }

    impl AsyncRead for UnexpectedEofAfter {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.position >= self.bytes.len() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed connection without sending TLS close_notify",
                )));
            }
            let remaining = &self.bytes[self.position..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.position += take;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn read_http_response_tolerates_unexpected_eof_with_content_length() {
        // Issue #585 / v1.9.4 exit-node bug. Some peers (the deployed exit-node in
        // particular, certain Apps Script `Connection: close` paths) close
        // the TCP without TLS close_notify. Body should still be returned
        // when Content-Length is satisfied, even though the read after
        // the body closes ungracefully.
        let body = b"{\"ok\":true}";
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut full = header.into_bytes();
        full.extend_from_slice(body);
        let mut stream = UnexpectedEofAfter {
            bytes: full,
            position: 0,
        };

        let (status, _headers, got_body) =
            read_http_response(&mut stream).await.expect("must succeed despite UnexpectedEof");
        assert_eq!(status, 200);
        assert_eq!(got_body, body);
    }

    #[tokio::test]
    async fn read_http_response_tolerates_unexpected_eof_no_framing() {
        // Same #585 fix, but for the no-framing branch (server didn't
        // send Content-Length or Transfer-Encoding). Read until peer
        // closes — UnexpectedEof should terminate the loop with the
        // body we accumulated so far, not bubble up as an error.
        let header = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        let body = b"hello world";
        let mut full = header.to_vec();
        full.extend_from_slice(body);
        let mut stream = UnexpectedEofAfter {
            bytes: full,
            position: 0,
        };

        let (status, _headers, got_body) =
            read_http_response(&mut stream).await.expect("must succeed despite UnexpectedEof");
        assert_eq!(status, 200);
        assert_eq!(got_body, body);
    }

    #[tokio::test]
    async fn parse_exit_node_response_unwraps_exit_node_envelope() {
        // The exit-node path through Apps Script returns exit node's JSON
        // envelope as the response body. parse_exit_node_response must
        // unwrap it back into a raw HTTP/1.1 response so the MITM TLS
        // write-back path sees the same shape it gets from the regular
        // Apps Script relay.
        let envelope = br#"{"s":200,"h":{"content-type":"application/json","x-cf-cache":"DYNAMIC"},"b":"eyJtZXNzYWdlIjoiaGVsbG8ifQ=="}"#;
        let raw = parse_exit_node_response(envelope).expect("envelope unwrap should succeed");
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(raw_str.contains("content-type: application/json\r\n"));
        assert!(raw_str.contains("x-cf-cache: DYNAMIC\r\n"));
        assert!(raw_str.contains("Content-Length: 19\r\n"));
        // Body is `{"message":"hello"}` (19 bytes; the base64-decoded
        // contents of the b field).
        assert!(raw.ends_with(b"{\"message\":\"hello\"}"));
    }

    #[tokio::test]
    async fn parse_exit_node_response_surfaces_explicit_error() {
        // When the exit node returns `{e: "..."}` instead of the {s,h,b} shape,
        // surface that error message specifically rather than letting
        // it through as an unparseable 502 — the message string is what
        // tells the user what went wrong (placeholder PSK, bad URL,
        // unauthorized, etc.).
        let envelope = br#"{"e":"unauthorized"}"#;
        let err = parse_exit_node_response(envelope).expect_err("must surface error");
        let msg = format!("{}", err);
        assert!(msg.contains("unauthorized"), "got: {}", msg);
        assert!(msg.contains("exit node"), "got: {}", msg);
    }

    #[test]
    fn unix_to_ymd_utc_handles_known_epochs() {
        // Anchors chosen to catch the common off-by-one errors (pre/post
        // leap day, pre/post epoch, year-end rollover).
        assert_eq!(unix_to_ymd_utc(0), (1970, 1, 1));                    // epoch
        assert_eq!(unix_to_ymd_utc(86_399), (1970, 1, 1));               // one sec before day 2
        assert_eq!(unix_to_ymd_utc(86_400), (1970, 1, 2));               // day 2 starts at midnight
        assert_eq!(unix_to_ymd_utc(951_782_400), (2000, 2, 29));         // leap day (Feb 29, 2000)
        assert_eq!(unix_to_ymd_utc(951_868_800), (2000, 3, 1));          // day after leap Feb
        assert_eq!(unix_to_ymd_utc(1_583_020_800), (2020, 3, 1));        // day after a leap Feb
        assert_eq!(unix_to_ymd_utc(1_735_689_599), (2024, 12, 31));      // last sec of 2024
        assert_eq!(unix_to_ymd_utc(1_735_689_600), (2025, 1, 1));        // first sec of 2025
    }

    #[test]
    fn seconds_until_pacific_midnight_is_bounded() {
        let n = seconds_until_pacific_midnight();
        // Must be in (0, 86400] for any valid system clock.
        assert!(n > 0 && n <= 86_400);
    }

    #[test]
    fn nth_sunday_of_month_anchors() {
        // Spot-check Sakamoto's day-of-week + offset arithmetic against
        // a few known Sundays. Mistakes here would silently shift the
        // DST transition by ±1 week.
        // March 2026: 2nd Sunday is March 8 (Sun Mar 1, Sun Mar 8).
        assert_eq!(nth_sunday_of_month(2026, 3, 2), 8);
        // November 2026: 1st Sunday is November 1 (Sun Nov 1).
        assert_eq!(nth_sunday_of_month(2026, 11, 1), 1);
        // March 2024: 2nd Sunday is March 10 (Sun Mar 3, Sun Mar 10).
        assert_eq!(nth_sunday_of_month(2024, 3, 2), 10);
        // November 2024: 1st Sunday is November 3.
        assert_eq!(nth_sunday_of_month(2024, 11, 1), 3);
        // March 2027: 2nd Sunday is March 14.
        assert_eq!(nth_sunday_of_month(2027, 3, 2), 14);
    }

    #[test]
    fn pacific_dst_window_anchors() {
        // Outside the DST window: PST.
        assert!(!pacific_is_dst(2026, 1, 15));
        assert!(!pacific_is_dst(2026, 12, 25));
        assert!(!pacific_is_dst(2026, 2, 28));
        assert!(!pacific_is_dst(2026, 11, 5)); // first Sun of Nov 2026 = Nov 1; Nov 5 is past
        // Inside: PDT.
        assert!(pacific_is_dst(2026, 6, 1));
        assert!(pacific_is_dst(2026, 9, 30));
        // Boundary: March 8, 2026 (DST start day) and after = PDT.
        assert!(!pacific_is_dst(2026, 3, 7));
        assert!(pacific_is_dst(2026, 3, 8));
        // Boundary: Oct 31 = PDT, Nov 1 = first Sunday = PST flips on.
        assert!(pacific_is_dst(2026, 10, 31));
        assert!(!pacific_is_dst(2026, 11, 1));
    }

    #[test]
    fn filter_forwarded_headers_strips_identity_revealing_headers() {
        // Issue #104: any proxy/extension that inserts these must not
        // leak the client's real IP to origin via the Apps Script relay.
        let input: Vec<(String, String)> = vec![
            ("X-Forwarded-For".into(), "203.0.113.42".into()),
            ("X-Real-IP".into(), "203.0.113.42".into()),
            ("Forwarded".into(), "for=203.0.113.42".into()),
            ("Via".into(), "1.1 squid".into()),
            ("CF-Connecting-IP".into(), "203.0.113.42".into()),
            ("True-Client-IP".into(), "203.0.113.42".into()),
            ("X-Client-IP".into(), "203.0.113.42".into()),
            ("Fastly-Client-IP".into(), "203.0.113.42".into()),
            ("X-Cluster-Client-IP".into(), "203.0.113.42".into()),
            ("Client-IP".into(), "203.0.113.42".into()),
            ("X-Originating-IP".into(), "203.0.113.42".into()),
            ("X-Forwarded-Host".into(), "internal.example".into()),
            ("X-Forwarded-Proto".into(), "https".into()),
            ("X-Forwarded-Port".into(), "8080".into()),
            ("X-Forwarded-Server".into(), "lb-01.example".into()),
            ("X-Forwarded-Ssl".into(), "on".into()),
            // Mix in a legitimate header that MUST pass through.
            ("User-Agent".into(), "Mozilla/5.0".into()),
            ("Accept".into(), "text/html".into()),
        ];
        let out = filter_forwarded_headers(&input);
        let keys: Vec<String> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        // All identity-revealing headers must be dropped.
        for h in [
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "via",
            "cf-connecting-ip",
            "true-client-ip",
            "x-client-ip",
            "fastly-client-ip",
            "x-cluster-client-ip",
            "client-ip",
            "x-originating-ip",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-forwarded-ssl",
        ] {
            assert!(!keys.iter().any(|k| k == h), "{} must be stripped", h);
        }
        // And legitimate headers must survive.
        assert!(keys.iter().any(|k| k == "user-agent"));
        assert!(keys.iter().any(|k| k == "accept"));
    }

    #[test]
    fn normalize_x_graphql_trims_after_variables() {
        // Real-looking x.com GraphQL URL with variables + features +
        // fieldToggles. Only the variables= prefix should survive.
        let in_url = "https://x.com/i/api/graphql/abcd1234/TweetDetail?variables=%7B%22focalTweetId%22%3A%221234%22%7D&features=%7B%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D&fieldToggles=%7B%22withArticleRichContentState%22%3Atrue%7D";
        let out = normalize_x_graphql_url(in_url);
        assert!(out.starts_with("https://x.com/i/api/graphql/abcd1234/TweetDetail?variables="));
        assert!(!out.contains("features="));
        assert!(!out.contains("fieldToggles="));
        assert!(!out.contains('&'));
    }

    #[test]
    fn normalize_x_graphql_leaves_non_x_hosts_alone() {
        let cases = [
            "https://twitter.com/i/api/graphql/x/y?variables=z&features=q",
            "https://x.co/i/api/graphql/x/y?variables=z&features=q",
            "https://api.x.com/i/api/graphql/x/y?variables=z&features=q",
            "https://example.com/?variables=1&other=2",
        ];
        for u in cases {
            assert_eq!(normalize_x_graphql_url(u), u, "should pass through: {}", u);
        }
    }

    #[test]
    fn normalize_x_graphql_leaves_non_graphql_paths_alone() {
        let cases = [
            "https://x.com/home",
            "https://x.com/i/api/2/notifications/view/generic.json",
            "https://x.com/i/api/graphql/x/y",       // no query
            "https://x.com/i/api/graphql/x/y?features=1&variables=2", // variables not first
        ];
        for u in cases {
            assert_eq!(normalize_x_graphql_url(u), u, "should pass through: {}", u);
        }
    }

    #[test]
    fn normalize_x_graphql_is_idempotent() {
        let once = normalize_x_graphql_url(
            "https://x.com/i/api/graphql/H/Op?variables=%7B%7D&features=%7B%7D",
        );
        let twice = normalize_x_graphql_url(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn extract_host_strips_scheme_port_path() {
        assert_eq!(extract_host("https://example.com/foo"), Some("example.com".into()));
        assert_eq!(extract_host("http://foo.bar:8080/x"), Some("foo.bar".into()));
        assert_eq!(extract_host("https://user:pw@host.test/x"), Some("host.test".into()));
        assert_eq!(extract_host("https://[2001:db8::1]:443/"), Some("2001:db8::1".into()));
        assert_eq!(extract_host("API.X.com/foo"), Some("api.x.com".into()));
        assert_eq!(extract_host(""), None);
    }

    #[test]
    fn build_sni_pool_extends_for_google() {
        let p = build_sni_pool("www.google.com");
        assert!(p.len() >= 2);
        assert_eq!(p[0], "www.google.com");
        assert!(p.iter().any(|s| s == "mail.google.com"));
    }

    #[test]
    fn build_sni_pool_preserves_custom_primary() {
        let p = build_sni_pool("mycustom.edge.example.com");
        assert_eq!(p, vec!["mycustom.edge.example.com".to_string()]);
    }

    #[test]
    fn filter_drops_connection_specific() {
        let h = vec![
            ("Host".into(), "example.com".into()),
            ("Connection".into(), "keep-alive".into()),
            ("Content-Length".into(), "5".into()),
            ("Cookie".into(), "a=b".into()),
            ("Proxy-Connection".into(), "close".into()),
        ];
        let out = filter_forwarded_headers(&h);
        let names: Vec<_> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        assert!(names.contains(&"cookie".to_string()));
        assert!(!names.contains(&"host".to_string()));
        assert!(!names.contains(&"connection".to_string()));
        assert!(!names.contains(&"content-length".to_string()));
        assert!(!names.contains(&"proxy-connection".to_string()));
    }

    #[test]
    fn strip_brotli_keeps_gzip() {
        let r = strip_brotli_from_accept_encoding("gzip, deflate, br");
        assert_eq!(r, "gzip, deflate");
        let r = strip_brotli_from_accept_encoding("br");
        assert_eq!(r, "");
        let r = strip_brotli_from_accept_encoding("gzip;q=1.0, br;q=0.5");
        assert_eq!(r, "gzip;q=1.0");
    }

    #[test]
    fn redirect_absolute_url() {
        let (p, h) = parse_redirect("https://script.googleusercontent.com/abc?x=1");
        assert_eq!(p, "/abc?x=1");
        assert_eq!(h.as_deref(), Some("script.googleusercontent.com"));
    }

    #[test]
    fn redirect_relative() {
        let (p, h) = parse_redirect("/somewhere");
        assert_eq!(p, "/somewhere");
        assert!(h.is_none());
    }

    #[test]
    fn parse_relay_basic_json() {
        let body = r#"{"s":200,"h":{"Content-Type":"text/plain"},"b":"SGVsbG8="}"#;
        let raw = parse_relay_json(body.as_bytes()).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("Hello"));
    }

    #[test]
    fn parse_content_range_total_accepts_mixed_case_unit() {
        let headers = vec![("Content-Range".to_string(), "Bytes 0-4/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), Some(20));
    }

    #[test]
    fn parse_content_range_total_rejects_descending_range() {
        let headers = vec![("Content-Range".to_string(), "bytes 10-4/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), None);
    }

    #[test]
    fn parse_content_range_total_rejects_end_past_total() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-20/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), None);
    }

    #[test]
    fn validate_probe_range_accepts_decoded_full_entity_body_mismatch() {
        let mut raw = b"HTTP/1.1 206 Partial Content\r\n\
Content-Range: bytes 0-11247/11248\r\n\
Content-Type: text/javascript\r\n\
Vary: Accept-Encoding\r\n\
Content-Length: 45812\r\n\r\n"
            .to_vec();
        raw.extend(std::iter::repeat(b'x').take(45_812));

        let (status, headers, body) = split_response(&raw).unwrap();
        assert_eq!(
            validate_probe_range(status, &headers, body, RANGE_PARALLEL_CHUNK_BYTES - 1),
            Some(ContentRange {
                start: 0,
                end: 11_247,
                total: 11_248,
            }),
        );

        let rewritten = rewrite_206_to_200(&raw);
        let (status, headers, body) = split_response(&rewritten).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.len(), 45_812);
        assert!(!headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-range")));
        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.as_str()),
            Some("45812"),
        );
    }

    #[test]
    fn validate_probe_range_rejects_missing_content_range() {
        assert!(validate_probe_range(206, &[], b"hello", 4).is_none());
    }

    #[test]
    fn validate_probe_range_rejects_nonzero_start() {
        let headers = vec![("Content-Range".to_string(), "bytes 1-4/20".to_string())];
        assert!(validate_probe_range(206, &headers, b"hell", 4).is_none());
    }

    #[test]
    fn validate_probe_range_rejects_end_past_requested_end() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-5/20".to_string())];
        assert!(validate_probe_range(206, &headers, b"hello!", 4).is_none());
    }

    #[test]
    fn validate_probe_range_rejects_body_length_mismatch() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-4/20".to_string())];
        assert!(validate_probe_range(206, &headers, b"hey", 4).is_none());
    }

    #[test]
    fn stitched_range_capacity_rejects_absurd_total() {
        assert_eq!(
            checked_stitched_range_capacity(MAX_STITCHED_RANGE_BYTES),
            Some(MAX_STITCHED_RANGE_BYTES as usize),
        );
        assert_eq!(checked_stitched_range_capacity(MAX_STITCHED_RANGE_BYTES + 1), None);
        assert_eq!(checked_stitched_range_capacity(u64::MAX), None);
    }

    #[test]
    fn extract_exact_range_body_rejects_body_length_mismatch() {
        let raw = b"HTTP/1.1 206 Partial Content\r\n\
Content-Range: bytes 5-9/20\r\n\
Content-Length: 3\r\n\r\n\
hey";
        let err = extract_exact_range_body(raw, 5, 9, 20).unwrap_err();
        assert_eq!(err, "Content-Range/body length mismatch");
    }

    #[test]
    fn extract_exact_range_body_rejects_mismatched_content_range() {
        let raw = b"HTTP/1.1 206 Partial Content\r\n\
Content-Range: bytes 5-9/20\r\n\
Content-Length: 5\r\n\r\n\
hello";
        let err = extract_exact_range_body(raw, 10, 14, 20).unwrap_err();
        assert_eq!(err, "unexpected Content-Range");
    }

    #[test]
    fn parse_relay_error_field() {
        let body = r#"{"e":"unauthorized"}"#;
        let err = parse_relay_json(body.as_bytes()).unwrap_err();
        assert!(matches!(err, FronterError::Relay(_)));
    }

    #[test]
    fn parse_relay_rejects_invalid_body_base64() {
        let body = r#"{"s":200,"b":"***not-base64***"}"#;
        let err = parse_relay_json(body.as_bytes()).unwrap_err();
        assert!(matches!(err, FronterError::BadResponse(_)));
    }

    #[test]
    fn blacklist_heuristics() {
        assert!(should_blacklist(429, ""));
        assert!(should_blacklist(403, "quota"));
        assert!(should_blacklist(500, "Service invoked too many times per day: urlfetch"));
        assert!(!should_blacklist(200, ""));
        assert!(!should_blacklist(502, "bad gateway"));
        assert!(looks_like_quota_error("Exception: Service invoked too many times per day"));
        assert!(looks_like_quota_error(
            "Exception: Bandbreitenkontingent überschritten: https://example.com. Verringern Sie die Datenübertragungsrate."
        ));
        assert!(!looks_like_quota_error("bad url"));
    }

    #[test]
    fn mask_script_id_hides_middle() {
        assert_eq!(mask_script_id("short"), "***");
        assert_eq!(mask_script_id("AKfycbx1234567890abcdef"), "AKfy...cdef");
    }

    #[test]
    fn parallel_relay_only_safe_for_idempotent_methods() {
        // Locks down #743: parallel_relay must never fan-out non-idempotent
        // methods because Apps Script can't be cancelled mid-request, so
        // every concurrent attempt completes server-side and side-effects
        // duplicate at the destination (comment posted twice, etc.).
        for safe in ["GET", "HEAD", "OPTIONS", "get", "head", "options"] {
            assert!(
                is_method_safe_for_fanout(safe),
                "{} should be safe for fan-out (idempotent per RFC 9110)",
                safe,
            );
        }
        for unsafe_m in ["POST", "PUT", "PATCH", "DELETE", "post", "put", "patch", "delete"] {
            assert!(
                !is_method_safe_for_fanout(unsafe_m),
                "{} must NOT be safe for fan-out (non-idempotent — duplicate side-effects)",
                unsafe_m,
            );
        }
        // Unknown methods (CONNECT, TRACE, custom verbs) default to NOT
        // safe — conservative call, matches the upstream `UrlFetchApp`
        // lookup behavior.
        for unknown in ["CONNECT", "TRACE", "PROPFIND", ""] {
            assert!(
                !is_method_safe_for_fanout(unknown),
                "{} must default to NOT safe for fan-out when unrecognised",
                unknown,
            );
        }
    }

    #[test]
    fn parse_relay_array_set_cookie() {
        let body = r#"{"s":200,"h":{"Set-Cookie":["a=1","b=2"]},"b":""}"#;
        let raw = parse_relay_json(body.as_bytes()).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("Set-Cookie: a=1\r\n"));
        assert!(s.contains("Set-Cookie: b=2\r\n"));
    }

    #[test]
    fn decode_js_string_escapes_xnn_and_unicode() {
        // \x7b = '{', \x22 = '"', \x7d = '}', \x5b = '[', \x5d = ']'
        let inner = r#"\x7b\x22s\x22:200,\x22b\x22:\x22\x22\x7d"#;
        let out = decode_js_string_escapes(inner).unwrap();
        assert_eq!(out, r#"{"s":200,"b":""}"#);

        // A = 'A', mixed with literal
        assert_eq!(decode_js_string_escapes(r"ABC").unwrap(), "ABC");

        // standard escapes
        assert_eq!(decode_js_string_escapes(r#"a\nb\t\\\"c"#).unwrap(), "a\nb\t\\\"c");

        // truncated escape returns None instead of panicking
        assert!(decode_js_string_escapes(r"\x7").is_none());
        assert!(decode_js_string_escapes(r"\u00").is_none());
    }

    /// Hand-build the `goog.script.init("...", "", undefined)` wrapper for
    /// a given inner relay JSON, matching the form Apps Script HtmlService
    /// emits when the deployment uses HtmlService for its response. Every
    /// `{`/`}` becomes `\x7b`/`\x7d`, every `"` becomes `\"`, every `:`
    /// stays — that's the realistic subset our unwrapper has to cope with.
    fn build_goog_script_init_wrapper(inner_relay_json: &str) -> String {
        // Step 1: build the outer JSON object {"userHtml": "<inner>", ...}
        // using serde so the inner JSON is properly JSON-escaped (including
        // each `"` → `\"`).
        let outer = serde_json::json!({ "userHtml": inner_relay_json });
        let outer_str = serde_json::to_string(&outer).unwrap();
        // Step 2: re-escape `{`/`}` → `\xNN` and `"` → `\"` to match the
        // form Apps Script wraps inside the `goog.script.init("…")`
        // JS string literal.
        let mut wire = String::with_capacity(outer_str.len() * 2);
        for ch in outer_str.chars() {
            match ch {
                '{' => wire.push_str(r"\x7b"),
                '}' => wire.push_str(r"\x7d"),
                '"' => wire.push_str(r#"\""#),
                other => wire.push(other),
            }
        }
        format!(
            "<html><body><script>goog.script.init(\"{}\", \"\", undefined);</script></body></html>",
            wire
        )
    }

    #[test]
    fn extract_apps_script_user_html_unwraps_goog_init() {
        let inner_json = r#"{"s":200,"h":{},"b":"aGk="}"#;
        let wrapped = build_goog_script_init_wrapper(inner_json);
        let extracted = extract_apps_script_user_html(&wrapped).unwrap();
        assert_eq!(extracted, inner_json);
    }

    #[test]
    fn parse_relay_json_unwraps_goog_script_init() {
        // End-to-end: an iframe-wrapped body should still parse correctly
        // through parse_relay_json. Without the unwrap helper this used
        // to fail with `key must be a string at line 2`.
        let inner_json = r#"{"s":200,"h":{},"b":""}"#;
        let wrapped = build_goog_script_init_wrapper(inner_json);
        let raw = parse_relay_json(wrapped.as_bytes()).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("HTTP/1.1 200 "), "got: {}", s);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_consumes_final_crlf_and_trailers() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\nX-Test: 1\r\n\r\n",
            )
            .await
            .unwrap();

        let (status, _headers, body) = read_http_response(&mut server).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"Hello");

        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();

        let (status2, _headers2, body2) = read_http_response(&mut server).await.unwrap();
        assert_eq!(status2, 200);
        assert_eq!(body2, b"OK");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn content_length_reader_rejects_truncated_body() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHel")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("full response body"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_rejects_truncated_chunk_body() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHel")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("mid-chunked"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_rejects_missing_chunk_crlf() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHelloXX")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("trailing CRLF"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    // ─── h2 transport ──────────────────────────────────────────────────

    /// Generous response-phase deadline used by transport tests. We
    /// pick something well above any expected latency on a localhost
    /// h2c hop so test flakiness can't be confused with a real timeout
    /// firing. Tests that *want* to observe a timeout pick a small
    /// value explicitly.
    const TEST_RESPONSE_DEADLINE: Duration = Duration::from_secs(10);

    /// Build a minimal valid `DomainFronter` for unit tests. The
    /// `connect_host` is unused unless a test actually opens a socket;
    /// `verify_ssl=true` and a placeholder `google_ip` are fine because
    /// `DomainFronter::new` doesn't touch the network.
    fn fronter_for_test(force_http1: bool) -> DomainFronter {
        let json = format!(
            r#"{{
                "mode": "apps_script",
                "google_ip": "127.0.0.1",
                "front_domain": "www.google.com",
                "script_id": "TEST",
                "auth_key": "test_auth_key",
                "listen_host": "127.0.0.1",
                "listen_port": 8085,
                "log_level": "info",
                "verify_ssl": true,
                "force_http1": {}
            }}"#,
            force_http1
        );
        let cfg: Config = serde_json::from_str(&json).unwrap();
        DomainFronter::new(&cfg).expect("test fronter must construct")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn force_http1_disables_h2_at_construction() {
        // The kill switch: force_http1=true must mark the fronter as
        // h2-disabled before the first call so ensure_h2 short-circuits
        // without ever trying ALPN.
        let fronter = fronter_for_test(true);
        assert!(
            fronter.h2_disabled.load(Ordering::Relaxed),
            "force_http1=true must set h2_disabled at construction"
        );
        assert!(
            fronter.ensure_h2().await.is_none(),
            "ensure_h2 must return None when h2 is disabled"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn force_http1_false_leaves_h2_enabled() {
        let fronter = fronter_for_test(false);
        assert!(
            !fronter.h2_disabled.load(Ordering::Relaxed),
            "default must leave h2 enabled"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poison_h2_if_gen_is_noop_when_cell_is_empty() {
        // Defensive: we call poison on every per-request error; cell
        // may already be None due to a concurrent poison. Must not
        // panic or wedge.
        let fronter = fronter_for_test(false);
        fronter.poison_h2_if_gen(0).await;
        let cell = fronter.h2_cell.lock().await;
        assert!(cell.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poison_h2_if_gen_only_clears_matching_generation() {
        // Race protection: task A holds gen=1 SendRequest, gen=1 dies,
        // task B reopens → cell now gen=2 (healthy). Task A's
        // poison(1) MUST NOT clear gen=2. Without generation matching
        // the previous code unconditionally cleared the cell, causing
        // connection churn during recovery.
        let (addr, server_handle) = spawn_h2c_server(|_req| {
            let resp = http::Response::builder().status(200).body(()).unwrap();
            (resp, Vec::new())
        })
        .await;
        let send_v2 = h2c_client(addr).await;

        let fronter = fronter_for_test(false);
        // Seed the cell with gen=2 (simulating "task B just reopened").
        {
            let mut cell = fronter.h2_cell.lock().await;
            *cell = Some(H2Cell {
                send: send_v2.clone(),
                created: Instant::now(),
                generation: 2,
            });
        }
        // Task A poisons with stale gen=1.
        fronter.poison_h2_if_gen(1).await;
        // gen=2 cell must survive.
        let cell = fronter.h2_cell.lock().await;
        assert!(
            cell.is_some(),
            "poison_h2_if_gen(1) must not clear gen=2 cell"
        );
        assert_eq!(cell.as_ref().unwrap().generation, 2);
        drop(cell);

        // And matching gen=2 actually does clear.
        fronter.poison_h2_if_gen(2).await;
        let cell = fronter.h2_cell.lock().await;
        assert!(cell.is_none(), "poison_h2_if_gen(2) must clear gen=2 cell");

        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ensure_h2_skips_reopen_during_failure_backoff() {
        // After an open failure, ensure_h2 must return None for at
        // least H2_OPEN_FAILURE_BACKOFF_SECS without attempting a
        // new handshake — otherwise concurrent callers each pay the
        // full handshake-timeout cost during an outage.
        let fronter = fronter_for_test(false);
        // Simulate a recent open failure.
        *fronter.h2_open_failed_at.lock().await = Some(Instant::now());

        // ensure_h2 must return None immediately, without trying open_h2
        // (open_h2 would try TCP-connect to 127.0.0.1:443 which would
        // either fail slowly or succeed against an unrelated service —
        // either way, this test would observably take longer if backoff
        // wasn't honored).
        let t0 = Instant::now();
        let result = fronter.ensure_h2().await;
        assert!(result.is_none(), "must return None during backoff");
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "must return immediately without open attempt; took {:?}",
            t0.elapsed()
        );
    }

    /// Spawn a minimal local h2c server (plaintext h2, no TLS) on a
    /// random port. The handler closure builds the response from the
    /// incoming request — used by `h2_round_trip_*` tests below.
    /// Returns the bound address and the JoinHandle so the test can
    /// `abort()` the server when done.
    async fn spawn_h2c_server<F>(
        handler: F,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: Fn(http::Request<h2::RecvStream>) -> (http::Response<()>, Vec<u8>)
            + Send
            + Sync
            + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let handle = tokio::spawn(async move {
            // Single-connection server is enough for these tests.
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (req, mut respond) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let (resp, body) = handler(req);
                let has_body = !body.is_empty();
                let mut send = respond
                    .send_response(resp, !has_body)
                    .expect("send_response in test");
                if has_body {
                    send.send_data(Bytes::from(body), true)
                        .expect("send_data in test");
                }
            }
        });
        (addr, handle)
    }

    /// Variant that gives the handler async access to the request body
    /// before producing the response. Needed to assert what the client
    /// actually sent (rather than relying on the request's existence).
    async fn spawn_h2c_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (req, mut respond) = match result {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let mut body = req.into_body();
                let mut received = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = match chunk {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let n = chunk.len();
                    received.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(n);
                }
                let resp = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::from(received), true).unwrap();
            }
        });
        (addr, handle)
    }

    /// Open a plaintext h2c connection to `addr` and return a usable
    /// `SendRequest<Bytes>`. The connection driver is spawned in the
    /// background and lives for the test's scope.
    async fn h2c_client(addr: std::net::SocketAddr) -> h2::client::SendRequest<Bytes> {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (send, conn) = h2::client::handshake(stream).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        send
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_round_trip_actually_transmits_post_body() {
        // Server reads the request body and echoes it. We assert the
        // server received the exact bytes we passed — proves the
        // send_data path works, not just that 200 came back.
        let (addr, server_handle) = spawn_h2c_echo_server().await;

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let req_body = b"the-actual-payload-sent-by-h2_round_trip";
        let (status, _hdrs, echoed) = fronter
            .h2_round_trip(
                send,
                "POST",
                "/echo",
                "127.0.0.1",
                Bytes::from_static(req_body),
                Some("application/json"),
                TEST_RESPONSE_DEADLINE,
            )
            .await
            .expect("h2 round trip should succeed");
        assert_eq!(status, 200);
        assert_eq!(
            echoed, req_body,
            "server must have received the exact bytes we sent"
        );
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_round_trip_decodes_gzip_responses() {
        // Mirror the h1 read_http_response behavior: gzip-encoded
        // bodies must be transparently decompressed before we hand
        // them back, so downstream JSON parsers see plain bytes
        // regardless of transport.
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let plain = b"{\"hello\":\"world\"}";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(plain).unwrap();
        let gzipped = enc.finish().unwrap();
        let gzipped_arc = Arc::new(gzipped);

        let g = gzipped_arc.clone();
        let (addr, server_handle) = spawn_h2c_server(move |_req| {
            let resp = http::Response::builder()
                .status(200)
                .header("content-encoding", "gzip")
                .body(())
                .unwrap();
            (resp, (*g).clone())
        })
        .await;

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let (status, _hdrs, body) = fronter
            .h2_round_trip(send, "GET", "/", "127.0.0.1", Bytes::new(), None, TEST_RESPONSE_DEADLINE)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, plain, "gzip body must be decoded transparently");
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_follows_redirect_chain() {
        // Now exercises run_h2_relay_with_send (the testable inner
        // of h2_relay_request) so the production redirect loop —
        // including timeout, RequestSent classification, and per-hop
        // poison-by-gen — is actually under test, not a hand-rolled
        // duplicate.
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = counter.clone();
        let (addr, server_handle) = spawn_h2c_server(move |req| {
            let n = c.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                let resp = http::Response::builder()
                    .status(302)
                    .header("location", "/next")
                    .body(())
                    .unwrap();
                (resp, Vec::new())
            } else {
                assert_eq!(req.uri().path(), "/next", "second hop must follow Location");
                let resp = http::Response::builder().status(200).body(()).unwrap();
                (resp, b"final".to_vec())
            }
        })
        .await;

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);

        let (status, _hdrs, body) = fronter
            .run_h2_relay_with_send(
                send,
                /* generation */ 1,
                "/start",
                Bytes::new(),
                TEST_RESPONSE_DEADLINE,
            )
            .await
            .expect("h2 relay should follow redirect to 200");
        assert_eq!(status, 200);
        assert_eq!(body, b"final");
        // Successful round-trip must increment h2_calls.
        assert_eq!(fronter.h2_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fronter.h2_fallbacks.load(Ordering::Relaxed), 0);
        server_handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_reports_request_sent_no_on_dead_connection() {
        // Set up an h2c client whose connection is severed before we
        // call run_h2_relay_with_send. The first `send.ready().await`
        // inside h2_round_trip should fail — RequestSent::No is the
        // correct classification (stream never opened on the wire).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // Accept the connection, do the h2 handshake, then drop.
            // After drop the client's SendRequest will fail at ready().
            let (sock, _) = listener.accept().await.unwrap();
            let _connection = h2::server::handshake(sock).await.unwrap();
            // Hold briefly so client can complete handshake, then drop.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let send = h2c_client(addr).await;
        // Wait for server to drop.
        server_task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fronter = fronter_for_test(false);
        let result = fronter
            .run_h2_relay_with_send(
                send,
                1,
                "/x",
                Bytes::from_static(b"some-body"),
                TEST_RESPONSE_DEADLINE,
            )
            .await;
        match result {
            Err((_, RequestSent::No)) => {} // expected
            Err((e, RequestSent::Maybe)) => {
                panic!("dead-conn failure classified as Maybe (unsafe to retry): {}", e)
            }
            Ok(_) => panic!("expected error against dropped server"),
        }
        // Failure must increment h2_fallbacks counter.
        assert_eq!(fronter.h2_fallbacks.load(Ordering::Relaxed), 1);
        assert_eq!(fronter.h2_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_reports_request_sent_maybe_on_post_send_reset() {
        // Server accepts headers (so the request reaches it) and then
        // resets the stream. The client sees a stream error AFTER
        // send_request returned Ok. RequestSent::Maybe is the only
        // safe classification — Apps Script may have started executing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(sock).await.unwrap();
            if let Some(Ok((_req, mut respond))) = connection.accept().await {
                // Reset the stream after receiving headers — simulates
                // the server starting to process and then bailing
                // (matches the "Apps Script started UrlFetchApp then
                // failed" scenario).
                respond.send_reset(h2::Reason::INTERNAL_ERROR);
            }
            // Keep the connection alive briefly so the client sees the
            // RST_STREAM rather than a connection-level close.
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        let result = fronter
            .run_h2_relay_with_send(
                send,
                1,
                "/x",
                Bytes::from_static(b"body"),
                TEST_RESPONSE_DEADLINE,
            )
            .await;
        match result {
            Err((_, RequestSent::Maybe)) => {} // expected
            Err((e, RequestSent::No)) => panic!(
                "post-send RST classified as No — would let caller \
                 unsafely replay non-idempotent request: {}",
                e
            ),
            Ok(_) => panic!("expected error against RST_STREAM"),
        }

        server_task.await.unwrap();
    }

    // ─── NonRetryable wrapper + retry/fallback policy ────────────────────

    #[test]
    fn nonretryable_wrapper_is_not_retryable_other_variants_are() {
        // Surfaces the contract that do_relay_with_retry and the
        // exit-node fallback rely on. If this ever flips, those
        // sites would silently start re-issuing post-send failures.
        let plain = FronterError::Relay("transient".into());
        assert!(plain.is_retryable(), "plain Relay error must be retryable");

        let plain2 = FronterError::Timeout;
        assert!(plain2.is_retryable(), "Timeout must be retryable");

        let wrapped = FronterError::NonRetryable(Box::new(FronterError::Relay("post-send".into())));
        assert!(!wrapped.is_retryable(), "NonRetryable must not be retryable");

        // Display must be transparent so log lines look identical.
        let inner_msg = "h2 response: stream RST".to_string();
        let inner = FronterError::Relay(inner_msg.clone());
        let wrapped = FronterError::NonRetryable(Box::new(inner));
        let displayed = wrapped.to_string();
        assert!(
            displayed.contains(&inner_msg),
            "transparent Display should surface inner: got {}",
            displayed
        );

        // into_inner unwraps once.
        let inner_again = wrapped.into_inner();
        assert!(matches!(inner_again, FronterError::Relay(_)));
        assert!(inner_again.is_retryable(), "unwrapped error is retryable");
    }

    // Note on test coverage gap: we don't have a deterministic test
    // that the ready/back-pressure phase's timeout reports
    // `RequestSent::No`. h2 client enforces remote
    // `MAX_CONCURRENT_STREAMS` at `send_request` time rather than at
    // `ready` time, so a "saturate the slots, expect ready to block"
    // setup actually races down the response-phase path instead.
    // The ready-arm code in `h2_round_trip` is small (single match
    // arm with `RequestSent::No` literally written next to the
    // timeout error) and covered by review. Other safety properties
    // (post-send Maybe via stream RST, pre-send No via dead conn,
    // NonRetryable wrap propagation) are covered by the tests above
    // and below.

    #[tokio::test(flavor = "current_thread")]
    async fn run_h2_relay_with_send_does_not_wrap_pre_send_in_nonretryable() {
        // Regression guard: the NonRetryable wrap is the *call site's*
        // job (do_relay_once_with applies it for unsafe methods only).
        // run_h2_relay_with_send returns the raw RequestSent::No so
        // the call site can decide. If h2_relay_request started
        // wrapping unconditionally, even safe-method requests would
        // become non-retryable on transient pre-send failures.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _connection = h2::server::handshake(sock).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let send = h2c_client(addr).await;
        server_task.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fronter = fronter_for_test(false);
        let result = fronter
            .run_h2_relay_with_send(
                send,
                1,
                "/x",
                Bytes::from_static(b"x"),
                TEST_RESPONSE_DEADLINE,
            )
            .await;
        match result {
            Err((e, RequestSent::No)) => {
                assert!(
                    e.is_retryable(),
                    "pre-send error must be raw FronterError, not pre-wrapped NonRetryable; got {:?}",
                    e
                );
            }
            other => panic!("expected (Err, RequestSent::No); got {:?}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sticky_disable_h2_for_fronting_refusal_flips_disabled_and_clears_cell() {
        // Verify the helper that runs from each call site's 421 arm:
        // sets h2_disabled, clears the cell, rebalances counters
        // (h2_calls -=1 since the round-trip already counted; h2_fallbacks +=1).
        // Tests the helper directly so we don't depend on a real h2
        // server returning 421 — call sites already exercise the
        // status-match wiring through code review.
        let (addr, server_handle) = spawn_h2c_server(|_req| {
            let resp = http::Response::builder().status(200).body(()).unwrap();
            (resp, Vec::new())
        })
        .await;
        let send = h2c_client(addr).await;
        let fronter = fronter_for_test(false);
        // Seed the cell so we can verify it gets cleared.
        {
            let mut cell = fronter.h2_cell.lock().await;
            *cell = Some(H2Cell {
                send: send.clone(),
                created: Instant::now(),
                generation: 7,
            });
        }
        // Pretend a round-trip just incremented h2_calls (which is
        // what run_h2_relay_with_send does on Ok before the call site
        // sees the 421 status).
        fronter.h2_calls.fetch_add(1, Ordering::Relaxed);

        fronter
            .sticky_disable_h2_for_fronting_refusal(421, "test context")
            .await;

        assert!(fronter.h2_disabled.load(Ordering::Relaxed), "must sticky-disable");
        let cell = fronter.h2_cell.lock().await;
        assert!(cell.is_none(), "cell must be cleared");
        assert_eq!(
            fronter.h2_calls.load(Ordering::Relaxed),
            0,
            "the h2_calls increment from the failed round-trip must be reversed"
        );
        assert_eq!(
            fronter.h2_fallbacks.load(Ordering::Relaxed),
            1,
            "must count as a fallback"
        );
        drop(cell);

        // Subsequent ensure_h2 must short-circuit to None without
        // attempting to open.
        let t0 = Instant::now();
        assert!(fronter.ensure_h2().await.is_none());
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "sticky-disabled ensure_h2 must return immediately"
        );

        // Calling the helper a second time must not log again or
        // double-count fallbacks beyond +1 per call.
        fronter
            .sticky_disable_h2_for_fronting_refusal(421, "test context")
            .await;
        // h2_calls would underflow without the saturating guard; assert
        // it stays at 0.
        assert_eq!(fronter.h2_calls.load(Ordering::Relaxed), 0);
        // h2_fallbacks goes up unconditionally (this is "another
        // attempt that ended up on h1") — that's fine.
        assert_eq!(fronter.h2_fallbacks.load(Ordering::Relaxed), 2);

        server_handle.abort();
    }

    #[test]
    fn is_h2_fronting_refusal_status_only_matches_421() {
        // Guard against the helper accidentally matching ambiguous
        // edge statuses (403 could be a real Apps Script geoblock,
        // 4xx generally is not a "this is h2's fault" signal).
        assert!(is_h2_fronting_refusal_status(421));
        for s in [200, 301, 400, 403, 404, 429, 500, 502, 503] {
            assert!(
                !is_h2_fronting_refusal_status(s),
                "status {} must NOT trigger sticky h2 disable",
                s
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_handshake_post_tls_returns_alpn_refused_when_peer_picks_h1() {
        // Verify the OpenH2Error::AlpnRefused path: if the TLS layer
        // negotiated http/1.1 (not h2), the post-TLS helper must
        // return the typed sentinel that ensure_h2 uses to sticky-
        // disable. We construct a fake TlsStream by short-circuiting
        // through a real local TLS server that only advertises h1.
        //
        // This needs a real TLS handshake (rustls + a self-signed
        // cert), so we set up the smallest possible test server with
        // ALPN forced to ["http/1.1"].
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // Drive the handshake; the test only needs the negotiation
            // to complete with ALPN=h1. After that we can drop.
            let _tls = acceptor.accept(sock).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        // Client side: open TLS with ALPN advertising h2 + h1.1; the
        // server picks h1 → alpn_protocol() returns "http/1.1" not "h2".
        let mut client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let tls = connector.connect(name, tcp).await.unwrap();

        let result = DomainFronter::h2_handshake_post_tls(tls).await;
        match result {
            Err(OpenH2Error::AlpnRefused) => {} // expected
            Err(other) => panic!("expected AlpnRefused, got {:?}", other),
            Ok(_) => panic!("expected AlpnRefused, got Ok"),
        }
        server.await.unwrap();
    }
}
