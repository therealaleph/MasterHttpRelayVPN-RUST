//! Full-mode tunnel client with pipelined batch multiplexer.
//!
//! A central multiplexer collects pending data from ALL active sessions
//! and fires batch requests without waiting for the previous one to return.
//! Each Apps Script deployment (account) gets its own concurrency pool of
//! 30 in-flight requests — matching the per-account Apps Script limit.

use std::collections::{BTreeMap, HashMap};
// `AtomicU64` from `std::sync::atomic` requires hardware-backed 64-bit
// atomics, which 32-bit MIPS (`mipsel-unknown-linux-musl` — our OpenWRT
// router target) does not provide — the std type isn't even defined
// there, so the build fails with `no AtomicU64 in sync::atomic`. We
// already pull `portable-atomic` for `domain_fronter.rs` for the same
// reason; reuse it here. `AtomicBool` works fine in std on every target.
use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::domain_fronter::{BatchOp, DomainFronter, FronterError, TunnelResponse};

/// Apps Script allows 30 concurrent executions per account / deployment.
const CONCURRENCY_PER_DEPLOYMENT: usize = 30;

/// Maximum total base64-encoded payload bytes in a single batch request.
/// Apps Script accepts up to 50 MB per fetch, but the tunnel-node must
/// parse and fan-out every op — keeping batches under ~4 MB avoids
/// hitting the 6-minute execution cap on the Apps Script side.
const MAX_BATCH_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Maximum number of ops in a single batch. Prevents one mega-batch from
/// serializing too many sessions behind a single HTTP round-trip.
const MAX_BATCH_OPS: usize = 50;

// Per-batch HTTP round-trip timeout is now read from
// `DomainFronter::batch_timeout()`, sourced from `Config::request_timeout_secs`
// (#430, masterking32 PR #25). The historical default — 30 s, matching Apps
// Script's typical response cliff — lives in `default_request_timeout_secs`
// in `config.rs`.

/// Slack added to the reply-timeout budget on top of `batch_timeout`.
/// Covers spawn/encode overhead and a small margin for clock skew, so
/// the session-side `reply_rx` doesn't fire just before `fire_batch`'s
/// HTTP round-trip would have completed. No retry budget here — each
/// batch makes exactly one attempt (see `fire_batch` docs).
const REPLY_TIMEOUT_SLACK: Duration = Duration::from_secs(5);

/// Per-inflight reply timeout used by the pipelined poll loop. Each
/// in-flight future independently times out after this duration so a
/// dead target on the tunnel-node side doesn't block the session.
const REPLY_TIMEOUT: Duration = Duration::from_secs(35);

/// How long we'll briefly hold the client socket after the local
/// CONNECT/SOCKS5 handshake, waiting for the client's first bytes (the
/// TLS ClientHello for HTTPS). Bundling those bytes with the tunnel-node
/// connect saves one Apps Script round-trip per new flow.
const CLIENT_FIRST_DATA_WAIT: Duration = Duration::from_millis(50);

/// Floor depth after a drop (first empty reply).
const INFLIGHT_IDLE: usize = 1;

/// Optimistic starting depth — every session gets 2 in-flight polls
/// without needing an elevation permit. Drops to IDLE on first empty.
const INFLIGHT_OPTIMIST: usize = 2;

/// Maximum pipeline depth when data is actively flowing. Ramps up on
/// data-bearing replies, drops back to IDLE after consecutive empties.
const INFLIGHT_ACTIVE: usize = 4;

/// How many consecutive empty replies before dropping from active to idle depth.
const INFLIGHT_COOLDOWN: u32 = 3;

/// Max sessions that can run at elevated pipeline depth per deployment.
const MAX_ELEVATED_PER_DEPLOYMENT: u64 = 30;

/// Adaptive coalesce defaults: after each new op arrives, wait another
/// step for more ops. Resets on every arrival, up to max from the first
/// op. Overridable via config `coalesce_step_ms` / `coalesce_max_ms`.
///
/// 200 ms balances latency against batching efficiency. The dominant
/// bottleneck is the Apps Script round-trip (~1.5 s), so the extra
/// 200 ms wait is negligible to the user but lets significantly more
/// ops land in each batch — a page load that would fire 10 separate
/// 1-op batches at 10 ms now packs 3–5 ops per batch, cutting the
/// number of round-trips roughly in half. On idle sessions the step
/// timer fires once with nothing queued (no cost); under load each
/// arriving op resets the timer, so rapid bursts still coalesce up to
/// `DEFAULT_COALESCE_MAX_MS` naturally.
const DEFAULT_COALESCE_STEP_MS: u64 = 200;
const DEFAULT_COALESCE_MAX_MS: u64 = 1000;

/// Structured error code the tunnel-node returns when it doesn't know the
/// op (version mismatch). Must match `tunnel-node/src/main.rs`.
const CODE_UNSUPPORTED_OP: &str = "UNSUPPORTED_OP";

/// Empty poll round-trip latency below which we conclude the tunnel-node
/// is *not* long-polling (legacy fixed-sleep drain instead). On a
/// long-poll-capable server an empty poll with no upstream push either
/// returns near `LONGPOLL_DEADLINE` (~5 s) or comes back early *with*
/// pushed bytes — neither matches a fast empty reply. Threshold sits
/// well above the legacy `~350 ms` drain and well below the long-poll
/// floor, so network jitter on either side won't false-trigger.
const LEGACY_DETECT_THRESHOLD: Duration = Duration::from_millis(1500);

/// How long a deployment stays in "legacy / no long-poll" mode after the
/// last detection. Must be much longer than `LEGACY_DETECT_THRESHOLD` so a
/// freshly-marked deployment doesn't immediately self-recover, but short
/// enough that a redeployed / recovered tunnel-node gets re-probed without
/// requiring a process restart. 60 s lets one stuck deployment widen its
/// own poll cadence without poisoning the others, and self-resets so an
/// upgraded tunnel-node returns to the long-poll fast path on its own.
const LEGACY_RECOVER_AFTER: Duration = Duration::from_secs(60);

/// How long to remember a `Network is unreachable` / `No route to host`
/// failure for a given `(host, port)`. While cached, the proxy short-circuits
/// repeat CONNECTs with an immediate "host unreachable" reply instead of
/// burning a 1.5–2s tunnel batch round-trip on a target that just failed.
/// Real motivator: IPv6-only probe hostnames (e.g. `ds6.probe.*`) on devices
/// without IPv6 — the OS retries the probe every ~1.5s for 10s+, generating
/// 5–10 wasted tunnel sessions per probe.
const UNREACHABLE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Hard cap on negative-cache size. Browsing pulls in dozens of distinct
/// hosts; we don't want a runaway map. Pruned opportunistically on insert.
const UNREACHABLE_CACHE_MAX: usize = 256;

// ---------------------------------------------------------------------------
// Pipeline debug overlay state — temporary, polled from Android UI.
// ---------------------------------------------------------------------------
pub(crate) mod pipeline_debug {
    use std::collections::VecDeque;
    use std::sync::{Mutex, OnceLock};
    use portable_atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    const EVENT_CAP: usize = 30;

    struct SessionInfo {
        depth: usize,
        inflight: usize,
        elevated: bool,
    }

    struct State {
        events: Mutex<VecDeque<String>>,
        elevated: AtomicU64,
        max_elevated: AtomicU64,
        active_batches: AtomicU64,
        max_batch_slots: AtomicU64,
        active_sessions: AtomicU64,
        sessions: Mutex<std::collections::HashMap<String, SessionInfo>>,
    }

    fn state() -> &'static State {
        static S: OnceLock<State> = OnceLock::new();
        S.get_or_init(|| State {
            events: Mutex::new(VecDeque::with_capacity(EVENT_CAP)),
            elevated: AtomicU64::new(0),
            max_elevated: AtomicU64::new(0),
            active_batches: AtomicU64::new(0),
            max_batch_slots: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            sessions: Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn push_event(_msg: String) {}
    pub fn set_limits(_max_elev: u64, _max_batches: u64) {}
    pub fn set_elevated(_n: u64) {}
    pub fn batch_acquire() {}
    pub fn batch_release() {}
    pub fn session_start(_sid: &str) {}
    pub fn session_end(_sid: &str) {}
    pub fn session_update(_sid: &str, _depth: usize, _inflight: usize, _elevated: bool) {}

    pub fn to_json() -> String {
        let s = state();
        let events_json = if let Ok(g) = s.events.lock() {
            let escaped: Vec<String> = g.iter().map(|e| {
                format!("\"{}\"", e.replace('\\', "\\\\").replace('"', "\\\""))
            }).collect();
            format!("[{}]", escaped.join(","))
        } else {
            "[]".to_string()
        };
        let sessions_json = if let Ok(g) = s.sessions.lock() {
            let entries: Vec<String> = g.iter().map(|(sid, info)| {
                format!(
                    r#"{{"sid":"{}","depth":{},"inflight":{},"elevated":{}}}"#,
                    sid, info.depth, info.inflight, info.elevated,
                )
            }).collect();
            format!("[{}]", entries.join(","))
        } else {
            "[]".to_string()
        };
        format!(
            r#"{{"elevated":{},"max_elevated":{},"active_batches":{},"max_batch_slots":{},"active_sessions":{},"sessions":{},"events":{}}}"#,
            s.elevated.load(Ordering::Relaxed),
            s.max_elevated.load(Ordering::Relaxed),
            s.active_batches.load(Ordering::Relaxed),
            s.max_batch_slots.load(Ordering::Relaxed),
            s.active_sessions.load(Ordering::Relaxed),
            sessions_json,
            events_json,
        )
    }
}

/// Ports where the *server* speaks first (SMTP banner, SSH identification,
/// POP3/IMAP greeting, FTP banner). On these, waiting for client bytes
/// gains nothing and just adds handshake latency — skip the pre-read.
/// HTTP on 80 also qualifies because a naive HTTP client may not flush
/// the request line immediately after the CONNECT reply.
fn is_server_speaks_first(port: u16) -> bool {
    matches!(port, 21 | 22 | 25 | 80 | 110 | 143 | 587)
}

/// Recognize the tunnel-node's connect-error strings that mean
/// "this destination is fundamentally unreachable from the tunnel-node's
/// network right now" — distinct from refused/reset/timeout, which can be
/// transient. These come through as the inner `e` of a `TunnelResponse`
/// after the tunnel-node's std::io::Error is stringified, so we match on
/// substrings rather than `ErrorKind`. Linux: errno 101 (ENETUNREACH),
/// errno 113 (EHOSTUNREACH). Format varies a bit across libc/Tokio
/// versions, so cover both the human text and the os-error tag.
fn is_unreachable_error_str(s: &str) -> bool {
    let lc = s.to_ascii_lowercase();
    lc.contains("network is unreachable")
        || lc.contains("no route to host")
        || lc.contains("os error 101")
        || lc.contains("os error 113")
}

/// Canonicalize a host string for use as a negative-cache key. DNS names
/// are case-insensitive and may carry a trailing root-label dot, so
/// `Example.COM:443`, `example.com:443`, and `example.com.:443` are all the
/// same destination. IPv4 / IPv6 literals are unaffected — IPv4 has no
/// letters, and `Ipv6Addr::to_string()` already emits lowercase.
fn normalize_cache_host(host: &str) -> String {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    trimmed.to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Multiplexer
// ---------------------------------------------------------------------------

/// Reply payload for ops that go through `fire_batch`. The `String` is the
/// `script_id` of the deployment that processed the batch — needed by
/// `tunnel_loop`'s legacy-detection and per-deployment skip-when-idle
/// decisions, which can't reach `fire_batch`'s local `script_id` any
/// other way. Plain `Connect` doesn't go through `fire_batch` and keeps
/// the simpler reply type.
type BatchedReply = oneshot::Sender<Result<(TunnelResponse, String), String>>;

enum MuxMsg {
    Connect {
        host: String,
        port: u16,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    ConnectData {
        host: String,
        port: u16,
        // `Bytes` is internally Arc-backed, so the caller can cheaply
        // clone() to keep its own reference for the unsupported-fallback
        // replay path without an extra 64 KB copy per session.
        data: Bytes,
        reply: BatchedReply,
    },
    Data {
        sid: String,
        data: Bytes,
        seq: Option<u64>,
        wseq: Option<u64>,
        reply: BatchedReply,
    },
    UdpOpen {
        host: String,
        port: u16,
        data: Bytes,
        reply: BatchedReply,
    },
    UdpData {
        sid: String,
        data: Bytes,
        reply: BatchedReply,
    },
    Close {
        sid: String,
    },
}

/// Raw, not-yet-encoded form of a batch operation. Lives only inside
/// `mux_loop` and gets converted to `BatchOp` (with base64-encoded `d`)
/// inside `fire_batch`'s spawned task — keeping the encoding work off
/// the single mux thread, which previously had to base64 every op
/// inline before it could move on to the next message.
struct PendingOp {
    op: &'static str,
    sid: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    /// Raw payload. `None` for empty polls / opless ops; `Some` even
    /// when empty preserves the connect_data shape (always emits `d`).
    data: Option<Bytes>,
    /// True for ops that must serialize `d` even when empty (currently
    /// only `connect_data`, which uses presence of `d` as the signal
    /// that the caller is opting into the bundled-first-bytes flow).
    encode_empty: bool,
    seq: Option<u64>,
    wseq: Option<u64>,
}

pub struct TunnelMux {
    tx: mpsc::UnboundedSender<MuxMsg>,
    /// Set to `true` after the first time the tunnel-node rejects
    /// `connect_data` as unsupported. Subsequent sessions skip the
    /// optimistic path entirely and go straight to plain connect + data.
    connect_data_unsupported: Arc<AtomicBool>,
    /// Per-deployment legacy state: `script_id` → time it was last
    /// observed serving an empty poll faster than `LEGACY_DETECT_THRESHOLD`.
    /// Absence means "long-poll capable, or untested." Entries expire after
    /// `LEGACY_RECOVER_AFTER` so a redeployed / recovered tunnel-node
    /// rejoins the long-poll fast path without requiring a process restart.
    ///
    /// Note: the per-deployment marks here do *not* drive a per-deployment
    /// poll cadence — the `tunnel_loop` cadence (read-timeout backoff and
    /// skip-empty-when-idle) is gated on the aggregate `all_legacy`,
    /// because the next op's deployment is chosen later by
    /// `next_script_id()` round-robin and the loop can't pre-select. What
    /// the per-deployment design *does* fix vs the old single AtomicBool:
    ///   * one slow / legacy deployment can no longer flip the aggregate
    ///     true on its own — every deployment has to be marked first;
    ///   * deployments recover individually on the TTL, so an upgraded
    ///     tunnel-node lifts the aggregate without needing the others to
    ///     also recover or the process to restart;
    ///   * the warn log fires once per (deployment, recovery cycle), so
    ///     re-detection after recovery is a real signal in the logs.
    /// The cost: legacy deployments still receive fast empty polls in
    /// mixed mode (round-robin doesn't know to avoid them). Worth it to
    /// keep pushed bytes flowing through the long-poll-capable peers.
    legacy_deployments: Mutex<HashMap<String, Instant>>,
    /// Lock-free hot-path snapshot of "every known deployment is currently
    /// in legacy mode." Recomputed under `legacy_deployments`'s mutex on
    /// every mark/expire and read with a relaxed load from `tunnel_loop`.
    /// True only when this process has fast-empty observations for *all*
    /// `num_scripts` deployments simultaneously — that's when the per-
    /// session 30 s read-timeout backoff (the only setting where there is
    /// no per-deployment alternative) is still appropriate. Invariant: the
    /// atomic is always written *after* the map insert, under the same
    /// lock, so any reader that sees `true` was preceded by a complete
    /// map update.
    all_legacy: Arc<AtomicBool>,
    /// Count of *unique* configured deployment IDs at start time.
    /// Snapshotted from `fronter.script_id_list()` deduped, since the
    /// aggregate gate compares this against `legacy_deployments.len()`
    /// (a HashMap, so unique-keyed) — using the raw configured count
    /// would make the gate unreachable whenever a user lists the same
    /// script_id twice. Blacklisted-but-configured deployments still
    /// count here; see `all_servers_legacy` for why.
    num_scripts: usize,
    /// Pre-read observability. Lets an operator see whether the 50 ms
    /// wait-for-first-bytes is pulling its weight:
    ///   * `preread_win` — client sent bytes in time, bundled with connect
    ///   * `preread_loss` — timed out empty; paid 50 ms for nothing
    ///   * `preread_skip_port` — port was server-speaks-first; skipped wait
    ///   * `preread_skip_unsupported` — tunnel-node said no; skipped wait
    /// A rolling sum of win-time (µs) drives a `mean_win_time` readout so
    /// you can tune `CLIENT_FIRST_DATA_WAIT` against real client flush
    /// timing. A summary line is logged every 100 preread events.
    preread_win: AtomicU64,
    preread_loss: AtomicU64,
    preread_skip_port: AtomicU64,
    preread_skip_unsupported: AtomicU64,
    preread_win_total_us: AtomicU64,
    /// Separate monotonic counter used only to trigger the summary log
    /// (avoids a race where two threads both see `total % 100 == 0`).
    preread_total_events: AtomicU64,
    /// Short-lived negative cache for targets the tunnel-node reported as
    /// unreachable (`Network is unreachable` / `No route to host`). Keyed by
    /// `(host, port)`, value is the expiry instant. Plain Mutex<HashMap> is
    /// fine: it's touched once per CONNECT (cheap) and once per failure.
    unreachable_cache: Mutex<HashMap<(String, u16), Instant>>,
    /// How long a session waits for its batch reply before giving up and
    /// retry-polling on the next tick. Computed at construction from
    /// `fronter.batch_timeout() + REPLY_TIMEOUT_SLACK` so the session-
    /// side `reply_rx` always outlives `fire_batch`'s single HTTP
    /// round-trip. Without runtime derivation, an operator who raises
    /// `request_timeout_secs` would see sessions abandon replies just
    /// before the batch would have completed.
    reply_timeout: Duration,
    /// How many sessions are currently at elevated pipeline depth (>= 3).
    elevated_sessions: AtomicU64,
    max_elevated: u64,
}

impl TunnelMux {
    pub fn start(fronter: Arc<DomainFronter>, coalesce_step_ms: u64, coalesce_max_ms: u64) -> Arc<Self> {
        // Dedupe before snapshotting: the aggregate `all_legacy` gate
        // compares `legacy_deployments.len()` (a HashMap, so unique
        // keys) against this count, so using the raw `num_scripts()`
        // would make the gate unreachable whenever a user lists the
        // same script_id twice in config.
        let unique: std::collections::HashSet<&str> = fronter
            .script_id_list()
            .iter()
            .map(String::as_str)
            .collect();
        let unique_n = unique.len();
        let raw_n = fronter.num_scripts();
        if unique_n != raw_n {
            tracing::warn!(
                "tunnel mux: {} deployments configured but only {} unique script_id(s) — duplicate entries ignored for legacy detection",
                raw_n,
                unique_n,
            );
        }
        tracing::info!(
            "tunnel mux: {} deployment(s), {} concurrent per deployment",
            unique_n,
            CONCURRENCY_PER_DEPLOYMENT
        );
        let step = if coalesce_step_ms > 0 { coalesce_step_ms } else { DEFAULT_COALESCE_STEP_MS };
        let max = if coalesce_max_ms > 0 { coalesce_max_ms } else { DEFAULT_COALESCE_MAX_MS };
        tracing::info!("batch coalesce: step={}ms max={}ms, pipeline max depth: {}, optimist: {}", step, max, INFLIGHT_ACTIVE, INFLIGHT_OPTIMIST);
        // Reply timeout co-varies with `request_timeout_secs` so an
        // operator who raises the batch budget doesn't have sessions
        // abandoning replies just before the HTTP round-trip would
        // have completed. See the `reply_timeout` field comment for
        // the invariant.
        let reply_timeout = fronter
            .batch_timeout()
            .saturating_add(REPLY_TIMEOUT_SLACK);
        pipeline_debug::set_limits(
            MAX_ELEVATED_PER_DEPLOYMENT * unique_n as u64,
            (CONCURRENCY_PER_DEPLOYMENT * unique_n) as u64,
        );
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(mux_loop(rx, fronter, step, max));
        Arc::new(Self {
            tx,
            connect_data_unsupported: Arc::new(AtomicBool::new(false)),
            legacy_deployments: Mutex::new(HashMap::new()),
            all_legacy: Arc::new(AtomicBool::new(false)),
            num_scripts: unique_n,
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
            unreachable_cache: Mutex::new(HashMap::new()),
            reply_timeout,
            elevated_sessions: AtomicU64::new(0),
            max_elevated: MAX_ELEVATED_PER_DEPLOYMENT * unique_n as u64,
        })
    }

    /// How long a session waits for its batch reply before retry-polling.
    /// Co-varies with `Config::request_timeout_secs` so `fire_batch`'s
    /// single HTTP round-trip is always covered.
    pub fn reply_timeout(&self) -> Duration {
        self.reply_timeout
    }

    fn send_sync(&self, msg: MuxMsg) {
        let _ = self.tx.send(msg);
    }

    async fn send(&self, msg: MuxMsg) {
        let _ = self.tx.send(msg);
    }

    pub async fn udp_open(
        &self,
        host: &str,
        port: u16,
        data: impl Into<Bytes>,
    ) -> Result<TunnelResponse, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MuxMsg::UdpOpen {
            host: host.to_string(),
            port,
            data: data.into(),
            reply: reply_tx,
        })
        .await;
        match reply_rx.await {
            Ok(Ok((resp, _script_id))) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("mux channel closed".into()),
        }
    }

    pub async fn udp_data(
        &self,
        sid: &str,
        data: impl Into<Bytes>,
    ) -> Result<TunnelResponse, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MuxMsg::UdpData {
            sid: sid.to_string(),
            data: data.into(),
            reply: reply_tx,
        })
        .await;
        match reply_rx.await {
            Ok(Ok((resp, _script_id))) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("mux channel closed".into()),
        }
    }

    pub async fn close_session(&self, sid: &str) {
        self.send(MuxMsg::Close {
            sid: sid.to_string(),
        })
        .await;
    }

    fn connect_data_unsupported(&self) -> bool {
        self.connect_data_unsupported.load(Ordering::Relaxed)
    }

    fn mark_connect_data_unsupported(&self) {
        if !self.connect_data_unsupported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "tunnel-node doesn't support connect_data (pre-v1.x); falling back to plain connect + data for all future sessions"
            );
        }
    }

    /// True only when *every* known deployment is currently in legacy
    /// mode. Both per-session decisions in `tunnel_loop` (the 30 s
    /// read-timeout backoff and the skip-empty-when-idle short-circuit)
    /// gate on this aggregate — they can't pick a per-deployment answer
    /// ahead of time because the next op's deployment is chosen by
    /// `next_script_id()` only when the batch fires. With one
    /// long-poll-capable peer still around, the loop must keep emitting
    /// empty polls so round-robin lands some on that peer (where the
    /// server can hold them open and deliver pushed bytes).
    ///
    /// Known limitation: the comparison is against *all configured*
    /// deployments (`num_scripts`), not currently-selectable ones. A
    /// fleet where most deployments are blacklisted in `DomainFronter`
    /// (10 min cooldown) and the only selectable deployment(s) are
    /// legacy will keep the fast cadence for up to that cooldown, even
    /// though every reachable peer is legacy. Accepted because
    /// integrating the blacklist would require a hot-path query on the
    /// fronter's mutex once per `tunnel_loop` iteration; a heavily-
    /// blacklisted fleet has bigger problems than quota optimization,
    /// and the worst-case quota cost is bounded by the cooldown.
    ///
    /// Hot path: lock-free relaxed load. If the cached value is `true`,
    /// double-check under the mutex with a sweep for expired entries —
    /// otherwise stale legacy marks would keep us in the slow path forever
    /// after every deployment recovers (the `mark_server_no_longpoll` sweep
    /// only fires on the next mark, which may never come).
    fn all_servers_legacy(&self) -> bool {
        if !self.all_legacy.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        let mut deps = match self.legacy_deployments.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        deps.retain(|_, marked_at| now.duration_since(*marked_at) < LEGACY_RECOVER_AFTER);
        let still_all = deps.len() == self.num_scripts;
        if !still_all {
            self.all_legacy.store(false, Ordering::Relaxed);
        }
        still_all
    }

    fn mark_server_no_longpoll(&self, script_id: &str) {
        let now = Instant::now();
        let mut deps = match self.legacy_deployments.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Inline expiry sweep: if any entry has aged past
        // LEGACY_RECOVER_AFTER, drop it before recomputing `all_legacy`.
        // Without this, an entry that should have recovered would still
        // count toward the aggregate.
        deps.retain(|_, marked_at| now.duration_since(*marked_at) < LEGACY_RECOVER_AFTER);
        let was_present = deps.contains_key(script_id);
        deps.insert(script_id.to_string(), now);
        let all = deps.len() == self.num_scripts;
        // Atomic written under the lock and *after* the map insert. Any
        // reader that observes `all_legacy = true` has seen a complete
        // map state where every deployment is marked.
        self.all_legacy.store(all, Ordering::Relaxed);
        drop(deps);
        // Only log on first-mark-for-this-cycle: after `LEGACY_RECOVER_AFTER`
        // expiry + re-detection we re-log, which is intentional — that's
        // a real signal that the deployment regressed back to legacy mode.
        if !was_present {
            let short = &script_id[..script_id.len().min(8)];
            tracing::warn!(
                "tunnel-node deployment {}... returned an empty poll faster than {:?}; assuming legacy (no long-poll) drain — this deployment will skip empty polls when idle for the next {:?}",
                short,
                LEGACY_DETECT_THRESHOLD,
                LEGACY_RECOVER_AFTER,
            );
        }
    }

    /// Returns true if `(host, port)` has a non-expired unreachable entry.
    /// The proxy front-end uses this to skip the tunnel and reply
    /// "host unreachable" immediately on follow-up CONNECTs.
    pub fn is_unreachable(&self, host: &str, port: u16) -> bool {
        let now = Instant::now();
        let mut cache = match self.unreachable_cache.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let key = (normalize_cache_host(host), port);
        match cache.get(&key) {
            Some(expiry) if *expiry > now => true,
            Some(_) => {
                cache.remove(&key);
                false
            }
            None => false,
        }
    }

    /// If `err` looks like a network-unreachable / no-route-to-host error
    /// from the tunnel-node, remember the target for `UNREACHABLE_CACHE_TTL`.
    /// No-op for any other error (timeouts, refused, EOF, etc.) — those can
    /// be transient and we don't want to lock out a host on a flaky moment.
    fn record_unreachable_if_match(&self, host: &str, port: u16, err: &str) {
        if !is_unreachable_error_str(err) {
            return;
        }
        let mut cache = match self.unreachable_cache.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Cap enforcement is two-stage: first drop anything already expired,
        // then if we're STILL at/above the cap (i.e. an unbounded burst of
        // unique unreachable hosts within the TTL), evict the entry that
        // would expire soonest. This bounds the map size at all times — a
        // pure `retain` on expiry alone would let the map grow unbounded
        // until the first entry's TTL elapses.
        if cache.len() >= UNREACHABLE_CACHE_MAX {
            let now = Instant::now();
            cache.retain(|_, expiry| *expiry > now);
            while cache.len() >= UNREACHABLE_CACHE_MAX {
                let victim = cache
                    .iter()
                    .min_by_key(|(_, expiry)| **expiry)
                    .map(|(k, _)| k.clone());
                match victim {
                    Some(k) => {
                        cache.remove(&k);
                    }
                    None => break,
                }
            }
        }
        let key = (normalize_cache_host(host), port);
        cache.insert(key, Instant::now() + UNREACHABLE_CACHE_TTL);
        tracing::debug!(
            "negative-cached {}:{} for {:?} ({})",
            host,
            port,
            UNREACHABLE_CACHE_TTL,
            err
        );
    }

    fn record_preread_win(&self, port: u16, elapsed: Duration) {
        self.preread_win.fetch_add(1, Ordering::Relaxed);
        self.preread_win_total_us
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        tracing::debug!("preread win: port={} took={:?}", port, elapsed);
        self.maybe_log_preread_summary();
    }

    fn record_preread_loss(&self, port: u16) {
        self.preread_loss.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            "preread loss: port={} (empty within {:?})",
            port,
            CLIENT_FIRST_DATA_WAIT
        );
        self.maybe_log_preread_summary();
    }

    fn record_preread_skip_port(&self, port: u16) {
        self.preread_skip_port.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("preread skip: port={} (server-speaks-first)", port);
        self.maybe_log_preread_summary();
    }

    fn record_preread_skip_unsupported(&self, port: u16) {
        self.preread_skip_unsupported
            .fetch_add(1, Ordering::Relaxed);
        tracing::debug!("preread skip: port={} (connect_data unsupported)", port);
        self.maybe_log_preread_summary();
    }

    /// Emit an aggregate summary exactly once per 100 preread events.
    /// Using a dedicated counter for the trigger avoids a race where two
    /// threads both observe the win/loss/skip totals summing to a
    /// multiple of 100 — here, exactly one thread gets the boundary.
    fn maybe_log_preread_summary(&self) {
        let new_count = self.preread_total_events.fetch_add(1, Ordering::Relaxed) + 1;
        if new_count % 100 != 0 {
            return;
        }
        let win = self.preread_win.load(Ordering::Relaxed);
        let loss = self.preread_loss.load(Ordering::Relaxed);
        let skip_port = self.preread_skip_port.load(Ordering::Relaxed);
        let skip_unsup = self.preread_skip_unsupported.load(Ordering::Relaxed);
        let total_us = self.preread_win_total_us.load(Ordering::Relaxed);
        let mean_us = if win > 0 { total_us / win } else { 0 };
        tracing::info!(
            "connect_data preread: {} win / {} loss / {} skip(port) / {} skip(unsup), mean win time {}µs (ceiling {}µs)",
            win,
            loss,
            skip_port,
            skip_unsup,
            mean_us,
            CLIENT_FIRST_DATA_WAIT.as_micros(),
        );
    }
}

async fn mux_loop(mut rx: mpsc::UnboundedReceiver<MuxMsg>, fronter: Arc<DomainFronter>, coalesce_step_ms: u64, coalesce_max_ms: u64) {
    let coalesce_step = Duration::from_millis(coalesce_step_ms);
    let coalesce_max = Duration::from_millis(coalesce_max_ms);
    // One semaphore per deployment ID, each allowing 30 concurrent requests.
    let sems: Arc<HashMap<String, Arc<Semaphore>>> = Arc::new(
        fronter
            .script_id_list()
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    Arc::new(Semaphore::new(CONCURRENCY_PER_DEPLOYMENT)),
                )
            })
            .collect(),
    );

    loop {
        let mut msgs = Vec::new();
        // Block on the first message — no point waking up to find an empty
        // queue. Once the first op lands, the adaptive coalesce loop waits
        // in `coalesce_step` increments (resetting on each new arrival, up
        // to `coalesce_max`) so concurrent ops land in the same batch.
        match rx.recv().await {
            Some(msg) => msgs.push(msg),
            None => break,
        }
        let hard_deadline = tokio::time::Instant::now() + coalesce_max;
        let mut soft_deadline = tokio::time::Instant::now() + coalesce_step;
        loop {
            // Drain anything that's already queued without waiting.
            while let Ok(msg) = rx.try_recv() {
                msgs.push(msg);
                // Reset the soft deadline — more ops are arriving.
                soft_deadline = tokio::time::Instant::now() + coalesce_step;
            }
            let now = tokio::time::Instant::now();
            let wait_until = soft_deadline.min(hard_deadline);
            if now >= wait_until {
                break;
            }
            match tokio::time::timeout(wait_until - now, rx.recv()).await {
                Ok(Some(msg)) => {
                    msgs.push(msg);
                    // New op arrived — extend the soft deadline.
                    soft_deadline = tokio::time::Instant::now() + coalesce_step;
                }
                Ok(None) => return,
                Err(_) => break, // soft or hard deadline hit, no more ops
            }
        }

        // Split: plain connects go parallel, data-bearing ops get batched.
        let mut accum = BatchAccum::new();
        let mut close_sids: Vec<String> = Vec::new();

        for msg in msgs {
            match msg {
                MuxMsg::Connect { host, port, reply } => {
                    let f = fronter.clone();
                    tokio::spawn(async move {
                        let result = f
                            .tunnel_request("connect", Some(&host), Some(port), None, None)
                            .await;
                        match result {
                            Ok(resp) => {
                                let _ = reply.send(Ok(resp));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(format!("{}", e)));
                            }
                        }
                    });
                }
                MuxMsg::ConnectData {
                    host,
                    port,
                    data,
                    reply,
                } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "connect_data",
                        sid: None,
                        host: Some(host),
                        port: Some(port),
                        data: Some(data),
                        encode_empty: true,
                        seq: None,
                        wseq: None,
                    };
                    accum.push_or_fire(op, op_bytes, reply, &sems, &fronter).await;
                }
                MuxMsg::Data { sid, data, seq, wseq, reply } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "data",
                        sid: Some(sid),
                        host: None,
                        port: None,
                        data: if data.is_empty() { None } else { Some(data) },
                        encode_empty: false,
                        seq,
                        wseq,
                    };
                    accum.push_or_fire(op, op_bytes, reply, &sems, &fronter).await;
                }
                MuxMsg::UdpOpen {
                    host,
                    port,
                    data,
                    reply,
                } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "udp_open",
                        sid: None,
                        host: Some(host),
                        port: Some(port),
                        data: if data.is_empty() { None } else { Some(data) },
                        encode_empty: false,
                        seq: None,
                        wseq: None,
                    };
                    accum.push_or_fire(op, op_bytes, reply, &sems, &fronter).await;
                }
                MuxMsg::UdpData { sid, data, reply } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "udp_data",
                        sid: Some(sid),
                        host: None,
                        port: None,
                        data: if data.is_empty() { None } else { Some(data) },
                        encode_empty: false,
                        seq: None,
                        wseq: None,
                    };
                    accum.push_or_fire(op, op_bytes, reply, &sems, &fronter).await;
                }
                MuxMsg::Close { sid } => {
                    close_sids.push(sid);
                }
            }
        }

        // `close` ops piggyback on whatever batch we're about to fire — no
        // reply channel, no payload, just tell tunnel-node to drop the sid.
        for sid in close_sids {
            accum.pending_ops.push(PendingOp {
                op: "close",
                sid: Some(sid),
                host: None,
                port: None,
                data: None,
                encode_empty: false,
                seq: None,
                wseq: None,
            });
        }

        if accum.pending_ops.is_empty() {
            continue;
        }

        fire_batch(&sems, &fronter, accum.pending_ops, accum.data_replies).await;
    }
}

/// Per-iteration accumulator for `mux_loop`. Owns the three fields that
/// the data-bearing arms used to mutate in lockstep, with a single
/// `push_or_fire` entry point so the cap-then-push pattern lives in one
/// place instead of being copy-pasted into every arm.
struct BatchAccum {
    pending_ops: Vec<PendingOp>,
    data_replies: Vec<(usize, BatchedReply)>,
    payload_bytes: usize,
}

impl BatchAccum {
    fn new() -> Self {
        Self {
            pending_ops: Vec::new(),
            data_replies: Vec::new(),
            payload_bytes: 0,
        }
    }

    /// Append `op` (with its `reply` channel and pre-computed `op_bytes`),
    /// firing the current accumulator first if `op` would push us past
    /// `MAX_BATCH_OPS` or `MAX_BATCH_PAYLOAD_BYTES`. After a fire the
    /// accumulator is fresh for the new op.
    async fn push_or_fire(
        &mut self,
        op: PendingOp,
        op_bytes: usize,
        reply: BatchedReply,
        sems: &Arc<HashMap<String, Arc<Semaphore>>>,
        fronter: &Arc<DomainFronter>,
    ) {
        if should_fire(self.pending_ops.len(), self.payload_bytes, op_bytes) {
            fire_batch(
                sems,
                fronter,
                std::mem::take(&mut self.pending_ops),
                std::mem::take(&mut self.data_replies),
            )
            .await;
            self.payload_bytes = 0;
        }
        let idx = self.pending_ops.len();
        self.pending_ops.push(op);
        self.data_replies.push((idx, reply));
        self.payload_bytes += op_bytes;
    }
}

/// Threshold predicate for `BatchAccum::push_or_fire`: would adding an
/// op of `op_bytes` to a batch already holding `pending_len` ops and
/// `payload_bytes` of base64 cross either the per-batch op cap or
/// the payload-size cap?
///
/// Extracted from the inline `if` so the tunable boundary — including
/// the "first op never fires" rule (`pending_len == 0`) — has direct
/// unit-test coverage without spinning up a real `fire_batch`.
///
/// `saturating_add` keeps the helper's contract self-contained: a
/// pathological `op_bytes` near `usize::MAX` clamps to "yes, fire"
/// rather than wrapping around and silently letting an oversized op
/// slip past the cap. Today's callers only feed `encoded_len(n)` on
/// reasonable buffer sizes, but the predicate is the wrong place to
/// rely on caller bounds.
fn should_fire(pending_len: usize, payload_bytes: usize, op_bytes: usize) -> bool {
    pending_len > 0
        && (pending_len >= MAX_BATCH_OPS
            || payload_bytes.saturating_add(op_bytes) > MAX_BATCH_PAYLOAD_BYTES)
}

/// Exact base64-encoded length of `n` raw bytes (standard padding):
/// `((n + 2) / 3) * 4`. Used by `mux_loop` to enforce
/// `MAX_BATCH_PAYLOAD_BYTES` without doing the actual encoding inline —
/// that work now happens in `fire_batch`'s spawned task.
fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Build the wire-shape `BatchOp` from an internal `PendingOp`. Free
/// function so the encoding contract — non-empty data → encoded,
/// empty connect_data → `Some("")`, anything else empty → `None` — is
/// directly testable without spinning up the mux loop.
fn encode_pending(p: PendingOp) -> BatchOp {
    let d = match (&p.data, p.encode_empty) {
        (Some(b), _) if !b.is_empty() => Some(B64.encode(b)),
        (Some(_), true) => Some(String::new()),
        _ => None,
    };
    BatchOp {
        op: p.op.into(),
        sid: p.sid,
        host: p.host,
        port: p.port,
        d,
        seq: p.seq,
        wseq: p.wseq,
    }
}

/// Pick a deployment, acquire its per-account concurrency slot, and spawn
/// a batch request task.
///
/// The batch HTTP round-trip is bounded by `DomainFronter::batch_timeout()`
/// so a slow or dead tunnel-node target cannot hold a pipeline slot (and
/// block waiting sessions) forever. Each batch makes a single attempt —
/// no client-side retry against a different deployment, because
/// tunnel-node's `drain_now` mutates the per-session buffer when building
/// a response, so a lost response means lost bytes (silent gap on the
/// client side). Without server-side ack / sequence support a replay
/// would either duplicate writes (payload ops) or silently skip bytes
/// (empty polls). Sessions whose batch times out re-poll on the next
/// tick — same recovery surface as pre-#1088.
async fn fire_batch(
    sems: &Arc<HashMap<String, Arc<Semaphore>>>,
    fronter: &Arc<DomainFronter>,
    pending_ops: Vec<PendingOp>,
    data_replies: Vec<(usize, BatchedReply)>,
) {
    let script_id = fronter.next_script_id();
    let sem = sems
        .get(&script_id)
        .cloned()
        .unwrap_or_else(|| Arc::new(Semaphore::new(CONCURRENCY_PER_DEPLOYMENT)));
    let permit = sem.acquire_owned().await.unwrap();
    pipeline_debug::batch_acquire();
    let f = fronter.clone();

    tokio::spawn(async move {
        struct BatchGuard;
        impl Drop for BatchGuard { fn drop(&mut self) { pipeline_debug::batch_release(); } }
        let _batch_guard = BatchGuard;
        let _permit = permit;
        let t0 = std::time::Instant::now();
        let n_ops = pending_ops.len();

        // Encode payloads to base64 here, off the single mux thread.
        // With 50 ops × 64 KB this is up to ~3 MB of work; doing it on
        // the mux task previously serialized every op behind whichever
        // batch was currently encoding.
        let data_ops: Vec<BatchOp> = pending_ops.into_iter().map(encode_pending).collect();

        // Bounded-wait: if the batch takes longer than the configured
        // batch timeout (Config::request_timeout_secs), all sessions in
        // this batch get an error and can retry-poll on the next tick.
        let batch_timeout = f.batch_timeout();
        let result = tokio::time::timeout(
            batch_timeout,
            f.tunnel_batch_request_to(&script_id, &data_ops),
        )
        .await;
        let sid_short = &script_id[..script_id.len().min(8)];
        tracing::info!(
            "batch: {} ops → {}, rtt={:?}",
            n_ops,
            sid_short,
            t0.elapsed()
        );

        match result {
            Ok(Ok(batch_resp)) => {
                f.record_batch_success(&script_id);
                // Wire the Full-mode usage counter that #230 / #362 flagged
                // as stuck-at-zero. Each successful batch is one
                // `UrlFetchApp.fetch()` call against the deploying Google
                // account's daily quota — bytes-counted is the inbound JSON
                // response which is the closest analogue to the apps_script
                // path's `record_today(bytes_received)` (we don't have the
                // exact response byte count post-deserialize, so we use a
                // proxy: sum of per-session response payload bytes the
                // batch carried back). Underestimates by JSON envelope
                // overhead but is in the right order of magnitude.
                let response_bytes: u64 = batch_resp
                    .r
                    .iter()
                    .map(|r| {
                        // `d` carries TCP payload (base64 string len ≈
                        // 4/3 of decoded bytes; close enough); `pkts`
                        // carries UDP datagrams (each base64); plus any
                        // error string. Sum gives a stable proxy for
                        // "how much did this batch move."
                        let d = r.d.as_ref().map(|s| s.len() as u64).unwrap_or(0);
                        let pkts = r
                            .pkts
                            .as_ref()
                            .map(|v| v.iter().map(|p| p.len() as u64).sum::<u64>())
                            .unwrap_or(0);
                        d + pkts
                    })
                    .sum();
                f.record_today(response_bytes);
                for (idx, reply) in data_replies {
                    if let Some(resp) = batch_resp.r.get(idx) {
                        let _ = reply.send(Ok((resp.clone(), script_id.clone())));
                    } else {
                        tracing::error!(
                            "batch response mismatch: idx={} but r.len()={} (sent {} ops) from script {}",
                            idx, batch_resp.r.len(), n_ops, sid_short,
                        );
                        let _ = reply.send(Err(format!(
                            "missing response in batch from script {}",
                            sid_short
                        )));
                    }
                }
            }
            Ok(Err(e)) => {
                // Read-side timeout from `domain_fronter`: Apps Script didn't
                // start streaming response bytes within the per-read deadline.
                // Common cause: deployment's `TUNNEL_SERVER_URL` points at a
                // dead host, so UrlFetchApp inside Apps Script hangs until its
                // own internal connect timeout. Strike-counter blacklists the
                // deployment after a sustained pattern.
                if matches!(e, FronterError::Timeout) {
                    f.record_timeout_strike(&script_id);
                }
                let err_msg = format!("{}", e);
                // Decoy / Apps-Script-flake detection. This body string can
                // mean any of 4 unrelated things (AUTH_KEY mismatch, Apps
                // Script execution timeout, Google-side flake, ISP-side
                // truncation #313), so surface all candidates rather than
                // asserting one. Operators can flip DIAGNOSTIC_MODE in
                // Code.gs to disambiguate (#404).
                if err_msg.contains("The script completed but did not return anything") {
                    tracing::error!(
                        "batch failed (script {}): got the v1.8.0 decoy/placeholder body — \
                         could be (1) AUTH_KEY mismatch between mhrv-rs config and Code.gs \
                         (run a direct curl probe against the deployment to verify), \
                         (2) Apps Script execution timeout or per-100s quota tear (try \
                         lowering parallel_concurrency in config), (3) Apps Script \
                         internal hiccup (transient, retry next batch), or (4) ISP-side \
                         response truncation (#313 pattern, try a different google_ip). \
                         To distinguish (1) from the rest: set DIAGNOSTIC_MODE=true at \
                         the top of Code.gs + redeploy as new version — only AUTH_KEY \
                         mismatch returns this body in diagnostic mode.",
                        sid_short
                    );
                } else {
                    tracing::warn!("batch failed (script {}): {}", sid_short, err_msg);
                }
                for (_, reply) in data_replies {
                    let _ = reply.send(Err(err_msg.clone()));
                }
            }
            Err(_) => {
                // Whole-batch budget elapsed. Even stronger signal than a
                // per-read timeout — count it the same way so a truly-stuck
                // deployment exits round-robin fast.
                f.record_timeout_strike(&script_id);
                tracing::warn!(
                    "batch timed out after {:?} (script {}, {} ops)",
                    batch_timeout,
                    sid_short,
                    n_ops
                );
                for (_, reply) in data_replies {
                    let _ = reply.send(Err("batch timed out".into()));
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub async fn tunnel_connection(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    mux: &Arc<TunnelMux>,
) -> std::io::Result<()> {
    // Only try the bundled connect+data optimization when it's likely to
    // pay off — client-speaks-first protocols (TLS on 443 et al.) — and
    // only if the tunnel-node has already accepted `connect_data` at least
    // once this process lifetime (or we haven't tried yet). Check the
    // fallback cache first so `skip(unsup)` shadows `skip(port)` in the
    // metrics once the feature is disabled process-wide.
    let initial_data = if mux.connect_data_unsupported() {
        mux.record_preread_skip_unsupported(port);
        None
    } else if is_server_speaks_first(port) {
        mux.record_preread_skip_port(port);
        None
    } else {
        let mut buf = BytesMut::with_capacity(65536);
        let t0 = Instant::now();
        match tokio::time::timeout(CLIENT_FIRST_DATA_WAIT, sock.read_buf(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => {
                mux.record_preread_win(port, t0.elapsed());
                Some(buf.freeze())
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                mux.record_preread_loss(port);
                None
            }
        }
    };

    let (sid, first_resp, pending_client_data) = match initial_data {
        Some(data) => match connect_with_initial_data(host, port, data.clone(), mux).await? {
            ConnectDataOutcome::Opened { sid, response } => (sid, Some(response), None),
            ConnectDataOutcome::Unsupported => {
                mux.mark_connect_data_unsupported();
                let sid = connect_plain(host, port, mux).await?;
                // Replay the buffered ClientHello on the first tunnel_loop
                // iteration. `Bytes::clone()` is a cheap Arc bump — no
                // copy of the 64 KB buffer.
                (sid, None, Some(data))
            }
        },
        None => (connect_plain(host, port, mux).await?, None, None),
    };

    tracing::info!("tunnel session {} opened for {}:{}", sid, host, port);
    pipeline_debug::session_start(&sid);

    // Run the first-response write + tunnel_loop inside an async block so
    // any io-error propagates via `?` without bypassing the Close below.
    // We deliberately don't use a Drop guard for Close: a Drop impl can't
    // .await cleanly, and tokio::spawn from inside Drop is unreliable
    // during runtime shutdown. The explicit send below covers every
    // non-panic path; a panic during tunnel_loop would leak the session
    // on the tunnel-node until its 5-minute idle reaper runs.
    let result = async {
        if let Some(resp) = first_resp {
            match write_tunnel_response(&mut sock, &resp).await? {
                WriteOutcome::Wrote | WriteOutcome::NoData => {}
                WriteOutcome::BadBase64 => {
                    tracing::error!(
                        "tunnel session {}: bad base64 in connect_data response",
                        sid
                    );
                    return Ok(());
                }
            }
            if resp.eof.unwrap_or(false) {
                return Ok(());
            }
        }
        tunnel_loop(&mut sock, &sid, mux, pending_client_data).await
    }
    .await;

    mux.send(MuxMsg::Close { sid: sid.clone() }).await;
    pipeline_debug::session_end(&sid);
    tracing::info!("tunnel session {} closed for {}:{}", sid, host, port);
    result
}

enum ConnectDataOutcome {
    Opened {
        sid: String,
        response: TunnelResponse,
    },
    Unsupported,
}

async fn connect_plain(host: &str, port: u16, mux: &Arc<TunnelMux>) -> std::io::Result<String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    mux.send(MuxMsg::Connect {
        host: host.to_string(),
        port,
        reply: reply_tx,
    })
    .await;

    match reply_rx.await {
        Ok(Ok(resp)) => {
            if let Some(ref e) = resp.e {
                tracing::error!("tunnel connect error for {}:{}: {}", host, port, e);
                // Only cache here: `resp.e` is the tunnel-node's own connect()
                // result against the target. The outer `Ok(Err(_))` arm below
                // is a transport-level failure (relay → Apps Script → tunnel-
                // node never reached) and tells us nothing about the target.
                mux.record_unreachable_if_match(host, port, e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e.clone(),
                ));
            }
            resp.sid.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "tunnel connect: no session id")
            })
        }
        Ok(Err(e)) => {
            tracing::error!("tunnel connect error for {}:{}: {}", host, port, e);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                e,
            ))
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "mux channel closed",
        )),
    }
}

async fn connect_with_initial_data(
    host: &str,
    port: u16,
    data: Bytes,
    mux: &Arc<TunnelMux>,
) -> std::io::Result<ConnectDataOutcome> {
    let (reply_tx, reply_rx) = oneshot::channel();
    mux.send(MuxMsg::ConnectData {
        host: host.to_string(),
        port,
        data,
        reply: reply_tx,
    })
    .await;

    let resp = match reply_rx.await {
        Ok(Ok((resp, _script_id))) => resp,
        Ok(Err(e)) => {
            if is_connect_data_unsupported_error_str(&e) {
                tracing::debug!("connect_data unsupported for {}:{}: {}", host, port, e);
                return Ok(ConnectDataOutcome::Unsupported);
            }
            tracing::error!("tunnel connect_data error for {}:{}: {}", host, port, e);
            // Outer transport failure (relay/Apps Script never reached the
            // tunnel-node). Don't poison the destination cache from here —
            // see `connect_plain` for the same reasoning.
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                e,
            ));
        }
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "mux channel closed",
            ));
        }
    };

    if is_connect_data_unsupported_response(&resp) {
        tracing::debug!(
            "connect_data unsupported for {}:{}: {:?}",
            host,
            port,
            resp.e
        );
        return Ok(ConnectDataOutcome::Unsupported);
    }

    if let Some(ref e) = resp.e {
        tracing::error!("tunnel connect_data error for {}:{}: {}", host, port, e);
        // `resp.e` is the tunnel-node's own connect result — cache it.
        mux.record_unreachable_if_match(host, port, e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            e.clone(),
        ));
    }

    let Some(sid) = resp.sid.clone() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "tunnel connect_data: no session id",
        ));
    };

    Ok(ConnectDataOutcome::Opened {
        sid,
        response: resp,
    })
}

/// Decide whether a response indicates the tunnel-node (or apps_script
/// layer in front of it) didn't recognize `connect_data`.
///
/// Primary signal: the structured `code` field (`UNSUPPORTED_OP`), emitted
/// by any tunnel-node or apps_script deployment that has this change.
/// Fallback signal (for legacy deployments, pre-connect_data): substring
/// match on the stable error string. The string-match is a one-way
/// compatibility hatch — newer deployments set `code` so future refactors
/// of the error text won't silently break detection.
///
/// Two error shapes are possible on the legacy path:
///   * tunnel-node's single-op/batch handler: `"unknown op: connect_data"`
///   * apps_script's `_doTunnel` default branch: `"unknown tunnel op: connect_data"`
///
/// Apps_script and tunnel-node ship on independent cadences, so it is
/// realistic for a user to upgrade one but not the other — detection has
/// to cover both shapes or the feature hard-fails on version skew.
fn is_connect_data_unsupported_response(resp: &TunnelResponse) -> bool {
    if resp.code.as_deref() == Some(CODE_UNSUPPORTED_OP) {
        return true;
    }
    resp.e
        .as_deref()
        .map(is_connect_data_unsupported_error_str)
        .unwrap_or(false)
}

fn is_connect_data_unsupported_error_str(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    (e.contains("unknown op") || e.contains("unknown tunnel op")) && e.contains("connect_data")
}

/// Metadata for one in-flight Data op, returned alongside its reply.
struct InflightMeta {
    seq: u64,
    was_empty_poll: bool,
    send_at: Instant,
}


async fn tunnel_loop(
    sock: &mut TcpStream,
    sid: &str,
    mux: &Arc<TunnelMux>,
    pending_client_data: Option<Bytes>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = sock.split();

    let inflight_cap = INFLIGHT_ACTIVE;
    let mut max_inflight = INFLIGHT_OPTIMIST.min(inflight_cap);
    let mut consecutive_empty = 0u32;
    let mut consecutive_data: u32 = 0;
    let mut is_elevated = false;
    let mut total_download_bytes: u64 = 0;
    let mut next_send_seq: u64 = 0;
    let mut next_write_seq: u64 = 0;
    let mut next_data_write_seq: u64 = 0;
    let mut eof_seen = false;
    let mut client_closed = false;
    let mut pending_writes: BTreeMap<u64, (TunnelResponse, String)> = BTreeMap::new();

    // Buffered upload data waiting to be sent (when pipeline is full).
    let mut buffered_upload: Option<Bytes> = None;

    enum ReplyOutcome {
        Ok(TunnelResponse, String),
        BatchErr(String),
        Timeout,
        Dropped,
    }
    type ReplyFut =
        std::pin::Pin<Box<dyn std::future::Future<Output = (InflightMeta, ReplyOutcome)> + Send>>;
    let mut inflight: FuturesUnordered<ReplyFut> = FuturesUnordered::new();

    // Helper: wrap a reply_rx into a ReplyFut with timeout.
    fn wrap_reply(
        meta: InflightMeta,
        reply_rx: oneshot::Receiver<Result<(TunnelResponse, String), String>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (InflightMeta, ReplyOutcome)> + Send>> {
        Box::pin(async move {
            match tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await {
                Ok(Ok(Ok((r, sid)))) => (meta, ReplyOutcome::Ok(r, sid)),
                Ok(Ok(Err(e))) => (meta, ReplyOutcome::BatchErr(e)),
                Ok(Err(_)) => (meta, ReplyOutcome::Dropped),
                Err(_) => (meta, ReplyOutcome::Timeout),
            }
        })
    }

    /// Send an empty poll Data op. Returns the InflightMeta and reply rx.
    #[inline]
    fn send_empty_poll(
        sid: &str,
        next_send_seq: &mut u64,
        mux: &Arc<TunnelMux>,
    ) -> (
        InflightMeta,
        oneshot::Receiver<Result<(TunnelResponse, String), String>>,
    ) {
        let seq = *next_send_seq;
        *next_send_seq += 1;
        let (reply_tx, reply_rx) = oneshot::channel();
        let send_at = Instant::now();
        mux.send_sync(MuxMsg::Data {
            sid: sid.to_string(),
            data: Bytes::new(),
            seq: Some(seq),
            wseq: None,
            reply: reply_tx,
        });
        let meta = InflightMeta { seq, was_empty_poll: true, send_at };
        (meta, reply_rx)
    }

    /// Send a data op with wseq. Returns the InflightMeta and reply rx.
    #[inline]
    fn send_data_op(
        sid: &str,
        data: Bytes,
        next_send_seq: &mut u64,
        next_data_write_seq: &mut u64,
        mux: &Arc<TunnelMux>,
    ) -> (
        InflightMeta,
        oneshot::Receiver<Result<(TunnelResponse, String), String>>,
    ) {
        let seq = *next_send_seq;
        *next_send_seq += 1;
        let wseq = *next_data_write_seq;
        *next_data_write_seq += 1;
        let (reply_tx, reply_rx) = oneshot::channel();
        let send_at = Instant::now();
        let sid_short = &sid[..sid.len().min(8)];
        tracing::info!(
            "sess {}: upload send seq={} wseq={} len={}B",
            sid_short, seq, wseq, data.len(),
        );
        mux.send_sync(MuxMsg::Data {
            sid: sid.to_string(),
            data,
            seq: Some(seq),
            wseq: Some(wseq),
            reply: reply_tx,
        });
        let meta = InflightMeta { seq, was_empty_poll: false, send_at };
        (meta, reply_rx)
    }

    // ── Initial path: send pending client data or read from client ──
    if let Some(data) = pending_client_data {
        if !data.is_empty() {
            let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
            tracing::debug!(
                "sess {}: pending data seq={}",
                &sid[..sid.len().min(8)],
                meta.seq,
            );
            inflight.push(wrap_reply(meta, reply_rx));
        }
    }

    // Send initial pre-fill empty polls (optimist depth), staggered
    // 1s apart so they land in separate batches. The pending data op
    // (if any) already occupies one slot.
    {
        let polls_to_send = max_inflight.saturating_sub(inflight.len());
        for i in 0..polls_to_send {
            if i > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            let (meta, reply_rx) = send_empty_poll(sid, &mut next_send_seq, mux);
            tracing::debug!(
                "sess {}: prefill poll seq={}, inflight={}",
                &sid[..sid.len().min(8)],
                meta.seq,
                inflight.len() + 1,
            );
            inflight.push(wrap_reply(meta, reply_rx));
        }
    }

    // Timer for staggered refill polls — fires in the select, never blocks.
    let mut refill_at: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    let mut refill_steps: u32 = 0;

    // Schedule initial refill if pre-fill didn't fill all slots.
    if inflight.len() < max_inflight {
        refill_at = Some(Box::pin(tokio::time::sleep(Duration::from_millis(100))));
        refill_steps = 0;
    }

    // Read buffer for client socket.
    let mut read_buf = BytesMut::with_capacity(65536);

    // Main select loop — handles both upload reads and download replies.
    loop {
        // If nothing in flight and tunnel EOF, we're done.
        if inflight.is_empty() && eof_seen {
            break;
        }

        // If nothing in flight and client closed, we're done.
        if inflight.is_empty() && client_closed {
            break;
        }

        // If eof was seen but inflight is not empty, give remaining
        // replies a short grace period to deliver any buffered data
        // before the remote connection closed. After 500ms, abandon them.
        if eof_seen && !inflight.is_empty() {
            match tokio::time::timeout(Duration::from_millis(500), inflight.next()).await {
                Ok(Some((meta, ReplyOutcome::Ok(resp, script_id)))) => {
                    if meta.seq == next_write_seq {
                        let _ = write_tunnel_response(&mut writer, &resp).await;
                        next_write_seq += 1;
                        while let Some(entry) = pending_writes.first_entry() {
                            if *entry.key() != next_write_seq { break; }
                            let (_, (buffered_resp, _)) = entry.remove_entry();
                            let _ = write_tunnel_response(&mut writer, &buffered_resp).await;
                            next_write_seq += 1;
                        }
                    } else {
                        pending_writes.insert(meta.seq, (resp, script_id));
                    }
                    continue;
                }
                _ => break,
            }
        }

        // When inflight is empty and we haven't seen eof, read from
        // client or send an empty poll to keep the session alive.
        if inflight.is_empty() && !eof_seen {
            let all_legacy = mux.all_servers_legacy();

            // If all servers are legacy and we've had many consecutive
            // empties, wait for client data before sending.
            if all_legacy && consecutive_empty > 3 && !client_closed {
                read_buf.reserve(65536);
                match reader.read_buf(&mut read_buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        consecutive_empty = 0;
                        let data = extract_bytes(&mut read_buf, n);
                        let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                        inflight.push(wrap_reply(meta, reply_rx));
                        continue;
                    }
                    Err(_) => break,
                }
            }

            let (meta, reply_rx) = send_empty_poll(sid, &mut next_send_seq, mux);
            tracing::debug!(
                "sess {}: keepalive poll seq={}", &sid[..sid.len().min(8)], meta.seq
            );
            inflight.push(wrap_reply(meta, reply_rx));
        }

        // Can we read from the client? Yes if not closed, not eof, and
        // we have room for more inflight ops (fast-path allows +4 extra).
        let can_read = !client_closed && !eof_seen && inflight.len() < max_inflight + 4;

        tokio::select! {
            biased;

            // Refill timer: 100ms steps, send empty poll after 10 steps
            // (1s) for batch separation.
            _ = async { refill_at.as_mut().unwrap().await }, if refill_at.is_some() => {
                refill_at = None;
                if !eof_seen && inflight.len() < max_inflight {
                    refill_steps += 1;

                    if refill_steps >= 10 {
                        // Check buffered upload first — merge into a data
                        // op instead of sending an empty poll.
                        if let Some(data) = buffered_upload.take() {
                            let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                            inflight.push(wrap_reply(meta, reply_rx));
                        } else {
                            let (meta, reply_rx) = send_empty_poll(sid, &mut next_send_seq, mux);
                            inflight.push(wrap_reply(meta, reply_rx));
                        }
                        refill_steps = 0;

                        if inflight.len() < max_inflight && max_inflight > INFLIGHT_IDLE {
                            refill_at = Some(Box::pin(tokio::time::sleep(Duration::from_millis(100))));
                        }
                    } else {
                        refill_at = Some(Box::pin(tokio::time::sleep(Duration::from_millis(100))));
                    }
                }
            }

            // Process completed replies.
            Some((meta, outcome)) = inflight.next() => {
                match outcome {
                    ReplyOutcome::Ok(resp, script_id) => {
                        let has_data = resp.d.as_ref().map(|d| !d.is_empty()).unwrap_or(false);
                        tracing::debug!(
                            "sess {}: recv seq={}, rtt={:?}, data={}, inflight={}",
                            &sid[..sid.len().min(8)],
                            meta.seq,
                            meta.send_at.elapsed(),
                            has_data,
                            inflight.len(),
                        );
                        if resp.seq.is_none() {
                            max_inflight = 1;
                        }

                        if let Some(ref e) = resp.e {
                            tracing::debug!("tunnel error: {}", e);
                            break;
                        }

                        let is_eof = resp.eof.unwrap_or(false);
                        let resp_has_seq = resp.seq.is_some();

                        // Write in-order to client.
                        if meta.seq == next_write_seq {
                            let got_data = match write_tunnel_response(&mut writer, &resp).await? {
                                WriteOutcome::Wrote => true,
                                WriteOutcome::NoData => false,
                                WriteOutcome::BadBase64 => break,
                            };
                            next_write_seq += 1;
                            if got_data {
                                consecutive_empty = 0;
                                consecutive_data = consecutive_data.saturating_add(1);
                                let bytes = resp.d.as_ref().map(|d| d.len() as u64 * 3 / 4).unwrap_or(0);
                                total_download_bytes += bytes;
                            } else {
                                consecutive_empty = consecutive_empty.saturating_add(1);
                            }
                            if is_eof {
                                eof_seen = true;
                            }

                            // Flush buffered out-of-order writes.
                            while let Some(entry) = pending_writes.first_entry() {
                                if *entry.key() != next_write_seq { break; }
                                let (_, (buffered_resp, _)) = entry.remove_entry();
                                let buf_eof = buffered_resp.eof.unwrap_or(false);
                                match write_tunnel_response(&mut writer, &buffered_resp).await? {
                                    WriteOutcome::Wrote => {
                                        consecutive_empty = 0;
                                        consecutive_data = consecutive_data.saturating_add(1);
                                        let bytes = buffered_resp.d.as_ref().map(|d| d.len() as u64 * 3 / 4).unwrap_or(0);
                                        total_download_bytes += bytes;
                                    }
                                    WriteOutcome::NoData => {
                                        consecutive_empty = consecutive_empty.saturating_add(1);
                                    }
                                    WriteOutcome::BadBase64 => break,
                                }
                                next_write_seq += 1;
                                if buf_eof {
                                    eof_seen = true;
                                }
                            }
                        } else {
                            pending_writes.insert(meta.seq, (resp, script_id));
                        }

                        // Send buffered upload data now that a slot freed up.
                        if let Some(data) = buffered_upload.take() {
                            if inflight.len() < max_inflight {
                                let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                                consecutive_empty = 0;
                                inflight.push(wrap_reply(meta, reply_rx));
                            } else {
                                buffered_upload = Some(data);
                            }
                        }

                        // Adaptive pipeline depth management.
                        tracing::info!(
                            "sess {}: depth={} cd={} ce={} inf={} has_seq={}",
                            &sid[..sid.len().min(8)],
                            max_inflight, consecutive_data, consecutive_empty, inflight.len(), resp_has_seq,
                        );
                        if resp_has_seq {
                            let prev = max_inflight;
                            if consecutive_empty >= 2 && max_inflight > INFLIGHT_IDLE {
                                max_inflight = INFLIGHT_IDLE.min(inflight_cap);
                                if is_elevated {
                                    let n = mux.elevated_sessions.fetch_sub(1, Ordering::Relaxed);
                                    pipeline_debug::set_elevated(n.saturating_sub(1));
                                    is_elevated = false;
                                }
                            } else if consecutive_data >= 1 && max_inflight < INFLIGHT_OPTIMIST {
                                max_inflight = INFLIGHT_OPTIMIST.min(inflight_cap);
                            } else if consecutive_data >= 2
                                && max_inflight >= INFLIGHT_OPTIMIST
                                && max_inflight < inflight_cap
                                && total_download_bytes >= 32 * 1024
                            {
                                if !is_elevated {
                                    let cur = mux.elevated_sessions.load(Ordering::Relaxed);
                                    if cur < mux.max_elevated {
                                        let n = mux.elevated_sessions.fetch_add(1, Ordering::Relaxed);
                                        pipeline_debug::set_elevated(n + 1);
                                        is_elevated = true;
                                        max_inflight = (max_inflight + 1).min(inflight_cap);
                                    }
                                } else {
                                    max_inflight = (max_inflight + 1).min(inflight_cap);
                                }
                            }
                            pipeline_debug::session_update(sid, max_inflight, inflight.len(), is_elevated);
                            if max_inflight != prev {
                                tracing::info!(
                                    "sess {}: pipeline {} -> {}{}",
                                    &sid[..sid.len().min(8)],
                                    prev,
                                    max_inflight,
                                    if is_elevated { " [elevated]" } else { "" },
                                );
                                pipeline_debug::push_event(format!(
                                    "{} {}->{}{}",
                                    &sid[..sid.len().min(8)],
                                    prev,
                                    max_inflight,
                                    if is_elevated { " E" } else { "" },
                                ));
                            }
                        }

                        // Schedule refill if pipeline needs more polls.
                        if !eof_seen
                            && inflight.len() < max_inflight
                            && refill_at.is_none()
                        {
                            refill_at = Some(Box::pin(tokio::time::sleep(
                                if max_inflight > INFLIGHT_IDLE { Duration::from_millis(100) } else { Duration::ZERO }
                            )));
                            refill_steps = 0;
                        }
                    }
                    ReplyOutcome::BatchErr(e) => {
                        tracing::debug!("tunnel data error: {}", e);
                        break;
                    }
                    ReplyOutcome::Timeout => {
                        tracing::warn!(
                            "sess {}: reply timeout (seq {}), retrying",
                            &sid[..sid.len().min(8)],
                            meta.seq,
                        );
                        consecutive_empty = consecutive_empty.saturating_add(1);
                    }
                    ReplyOutcome::Dropped => {
                        break;
                    }
                }
            }

            // Read from client (overlapped with reply processing).
            result = async {
                read_buf.reserve(65536);
                reader.read_buf(&mut read_buf).await
            }, if can_read => {
                match result {
                    Ok(0) => {
                        client_closed = true;
                    }
                    Ok(n) => {
                        let data = extract_bytes(&mut read_buf, n);
                        if inflight.len() < max_inflight {
                            // Normal path: send immediately as data op.
                            let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                            consecutive_empty = 0;
                            inflight.push(wrap_reply(meta, reply_rx));
                        } else if inflight.len() < max_inflight + 4 {
                            // Fast-path: pipeline full but under +4 extra.
                            let (meta, reply_rx) = send_data_op(sid, data, &mut next_send_seq, &mut next_data_write_seq, mux);
                            consecutive_empty = 0;
                            inflight.push(wrap_reply(meta, reply_rx));
                        } else {
                            // Buffer upload data until a slot frees up.
                            if let Some(ref mut existing) = buffered_upload {
                                // Merge: append new data to existing buffer.
                                let mut merged = BytesMut::with_capacity(existing.len() + data.len());
                                merged.extend_from_slice(existing);
                                merged.extend_from_slice(&data);
                                *existing = merged.freeze();
                            } else {
                                buffered_upload = Some(data);
                            }
                        }
                    }
                    Err(_) => {
                        client_closed = true;
                    }
                }
            }
        }
    }

    // Release elevation permit.
    if is_elevated {
        let n = mux.elevated_sessions.fetch_sub(1, Ordering::Relaxed);
        pipeline_debug::set_elevated(n.saturating_sub(1));
    }
    Ok(())
}

enum WriteOutcome {
    Wrote,
    NoData,
    BadBase64,
}

async fn write_tunnel_response<W>(
    writer: &mut W,
    resp: &TunnelResponse,
) -> std::io::Result<WriteOutcome>
where
    W: AsyncWrite + Unpin,
{
    let Some(ref d) = resp.d else {
        return Ok(WriteOutcome::NoData);
    };
    if d.is_empty() {
        return Ok(WriteOutcome::NoData);
    }

    match B64.decode(d) {
        Ok(bytes) if !bytes.is_empty() => {
            writer.write_all(&bytes).await?;
            writer.flush().await?;
            Ok(WriteOutcome::Wrote)
        }
        Ok(_) => Ok(WriteOutcome::NoData),
        Err(e) => {
            tracing::error!("tunnel bad base64: {}", e);
            Ok(WriteOutcome::BadBase64)
        }
    }
}

/// Extract bytes from the read buffer, applying the zero-copy threshold.
/// Reads >= half the buffer use split+freeze (zero-copy); smaller reads
/// copy out and clear so the buffer allocation is reused.
fn extract_bytes(buf: &mut BytesMut, n: usize) -> Bytes {
    const ZERO_COPY_THRESHOLD: usize = 65536 / 2;
    if n >= ZERO_COPY_THRESHOLD {
        buf.split().freeze()
    } else {
        let owned = Bytes::copy_from_slice(&buf[..n]);
        buf.clear();
        owned
    }
}

pub fn decode_udp_packets(resp: &TunnelResponse) -> Result<Vec<Vec<u8>>, String> {
    let Some(pkts) = resp.pkts.as_ref() else {
        return Ok(Vec::new());
    };
    pkts.iter()
        .map(|pkt| {
            B64.decode(pkt)
                .map_err(|e| format!("bad UDP packet base64: {}", e))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn resp_with(code: Option<&str>, e: Option<&str>) -> TunnelResponse {
        TunnelResponse {
            sid: None,
            d: None,
            pkts: None,
            eof: None,
            e: e.map(str::to_string),
            code: code.map(str::to_string),
            seq: None,
        }
    }

    #[test]
    fn unsupported_detection_via_structured_code() {
        assert!(is_connect_data_unsupported_response(&resp_with(
            Some("UNSUPPORTED_OP"),
            None
        )));
        assert!(is_connect_data_unsupported_response(&resp_with(
            Some("UNSUPPORTED_OP"),
            Some("unknown op: connect_data"),
        )));
    }

    #[test]
    fn unsupported_detection_via_legacy_tunnel_node_string() {
        // Pre-change tunnel-node: no code field, bare "unknown op: ...".
        assert!(is_connect_data_unsupported_response(&resp_with(
            None,
            Some("unknown op: connect_data"),
        )));
        assert!(is_connect_data_unsupported_response(&resp_with(
            None,
            Some("Unknown Op: CONNECT_DATA"),
        )));
    }

    #[test]
    fn unsupported_detection_via_legacy_apps_script_string() {
        // Pre-change apps_script: default branch emits "unknown tunnel op: ...".
        // This is the realistic skew case — user upgrades tunnel-node + client
        // binary but hasn't redeployed the Apps Script yet.
        assert!(is_connect_data_unsupported_response(&resp_with(
            None,
            Some("unknown tunnel op: connect_data"),
        )));
    }

    #[test]
    fn unsupported_detection_rejects_unrelated_errors() {
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None,
            Some("connect failed: refused"),
        )));
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None,
            Some("bad base64")
        )));
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None, None
        )));
        // "connect_data" alone (without "unknown op") shouldn't trigger.
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None,
            Some("connect_data: bad port"),
        )));
    }

    #[test]
    fn unreachable_error_str_matches_expected_variants() {
        assert!(is_unreachable_error_str(
            "connect failed: Network is unreachable (os error 101)"
        ));
        assert!(is_unreachable_error_str("No route to host"));
        assert!(is_unreachable_error_str("os error 113"));
        // Case-insensitive.
        assert!(is_unreachable_error_str(
            "CONNECT FAILED: NETWORK IS UNREACHABLE"
        ));
    }

    #[test]
    fn unreachable_error_str_rejects_unrelated() {
        assert!(!is_unreachable_error_str("connection refused"));
        assert!(!is_unreachable_error_str("connect timed out"));
        assert!(!is_unreachable_error_str("connection reset by peer"));
        assert!(!is_unreachable_error_str(""));
    }

    #[test]
    fn negative_cache_records_and_short_circuits() {
        let (mux, _rx) = mux_for_test();
        // Initially nothing is cached.
        assert!(!mux.is_unreachable("ds6.probe.example", 443));
        // Record a matching error.
        mux.record_unreachable_if_match(
            "ds6.probe.example",
            443,
            "connect failed: Network is unreachable (os error 101)",
        );
        assert!(mux.is_unreachable("ds6.probe.example", 443));
        // A different port for the same host is its own entry.
        assert!(!mux.is_unreachable("ds6.probe.example", 80));
    }

    #[test]
    fn negative_cache_ignores_non_unreachable_errors() {
        let (mux, _rx) = mux_for_test();
        mux.record_unreachable_if_match(
            "example.com",
            443,
            "connect failed: connection refused",
        );
        assert!(!mux.is_unreachable("example.com", 443));
    }

    #[test]
    fn negative_cache_normalizes_host_keys() {
        let (mux, _rx) = mux_for_test();
        // Cache under one casing/format...
        mux.record_unreachable_if_match(
            "Example.COM.",
            443,
            "Network is unreachable (os error 101)",
        );
        // ...and look up under several equivalent forms.
        assert!(mux.is_unreachable("example.com", 443));
        assert!(mux.is_unreachable("EXAMPLE.com", 443));
        assert!(mux.is_unreachable("example.com.", 443));
        // Different host should still miss.
        assert!(!mux.is_unreachable("other.com", 443));
    }

    /// Outer `Ok(Err(_))` from the mux channel means "the relay never
    /// reached the tunnel-node" (HTTP/TLS to Apps Script failed, batch
    /// timed out, etc.) — the destination wasn't even attempted. Even if
    /// that error string contains "Network is unreachable" (e.g. the
    /// client device's WAN was momentarily down), it must NOT poison the
    /// destination cache, or every host the user touched during a
    /// connectivity blip stays refused for 30s.
    #[tokio::test]
    async fn negative_cache_skips_outer_relay_errors() {
        let (mux, mut rx) = mux_for_test();
        let mux_for_task = mux.clone();
        let task = tokio::spawn(async move {
            connect_plain("real.target.example", 443, &mux_for_task).await
        });

        // Receive the Connect msg and reply with an outer Err whose string
        // would otherwise match `is_unreachable_error_str`.
        let msg = rx.recv().await.expect("connect msg");
        let reply = match msg {
            MuxMsg::Connect { reply, .. } => reply,
            other => panic!("expected Connect, got {:?}", std::mem::discriminant(&other)),
        };
        let _ = reply.send(Err(
            "relay failed: Network is unreachable (os error 101)".into(),
        ));

        let res = task.await.expect("task");
        assert!(res.is_err(), "connect_plain should surface the error");
        assert!(
            !mux.is_unreachable("real.target.example", 443),
            "outer relay error must not negative-cache the destination"
        );
    }

    #[test]
    fn negative_cache_enforces_hard_cap_under_unique_burst() {
        let (mux, _rx) = mux_for_test();
        // Insert enough unique still-live entries to exceed the cap. The
        // map size must never exceed UNREACHABLE_CACHE_MAX, even though
        // every entry is fresh and `retain(expired)` prunes nothing.
        let burst = UNREACHABLE_CACHE_MAX + 50;
        for i in 0..burst {
            let host = format!("h{}.example", i);
            mux.record_unreachable_if_match(
                &host,
                443,
                "connect failed: Network is unreachable (os error 101)",
            );
        }
        let len = mux
            .unreachable_cache
            .lock()
            .map(|g| g.len())
            .unwrap_or(0);
        assert!(
            len <= UNREACHABLE_CACHE_MAX,
            "cache size {} exceeded cap {}",
            len,
            UNREACHABLE_CACHE_MAX
        );
    }

    #[test]
    fn server_speaks_first_covers_common_protocols() {
        for p in [21u16, 22, 25, 80, 110, 143, 587] {
            assert!(
                is_server_speaks_first(p),
                "port {} should be server-first",
                p
            );
        }
        for p in [443u16, 8443, 853, 993, 1234] {
            assert!(
                !is_server_speaks_first(p),
                "port {} should NOT be server-first",
                p
            );
        }
    }

    /// Build a TunnelMux whose send channel is exposed to the test rather
    /// than wired to a real DomainFronter. Lets tests assert what messages
    /// the client would emit without needing network or apps_script.
    fn mux_for_test() -> (Arc<TunnelMux>, mpsc::UnboundedReceiver<MuxMsg>) {
        mux_for_test_with(2)
    }

    /// Build a TunnelMux for tests with a specific deployment count. The
    /// per-deployment legacy state's aggregate gate (`all_servers_legacy`)
    /// requires `legacy_deployments.len() == num_scripts`, so tests that
    /// exercise that gate need to control how many "deployments" exist.
    fn mux_for_test_with(num_scripts: usize) -> (Arc<TunnelMux>, mpsc::UnboundedReceiver<MuxMsg>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mux = Arc::new(TunnelMux {
            tx,
            connect_data_unsupported: Arc::new(AtomicBool::new(false)),
            legacy_deployments: Mutex::new(HashMap::new()),
            all_legacy: Arc::new(AtomicBool::new(false)),
            num_scripts,
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
            unreachable_cache: Mutex::new(HashMap::new()),
            // Tests that exercise the reply-timeout path expect a
            // generous fixed value here; production derives this from
            // `fronter.batch_timeout()` (see `TunnelMux::start`).
            reply_timeout: Duration::from_secs(35),
            elevated_sessions: AtomicU64::new(0),
            max_elevated: MAX_ELEVATED_PER_DEPLOYMENT * num_scripts as u64,
        });
        (mux, rx)
    }

    /// `TunnelMux::reply_timeout` must co-vary with the configured
    /// `request_timeout_secs` plus `REPLY_TIMEOUT_SLACK`. Without this
    /// runtime derivation, operators who raise `request_timeout_secs`
    /// see sessions abandon `reply_rx` just before `fire_batch`'s
    /// HTTP round-trip would have completed — silently orphaning
    /// in-flight responses. The test muxes hardcode a value for
    /// convenience, so a regression in `TunnelMux::start`'s formula
    /// could ship unnoticed unless we exercise the real construction
    /// path.
    #[tokio::test]
    async fn mux_reply_timeout_tracks_batch_timeout_plus_slack() {
        use crate::config::Config;

        // Pick a non-default `request_timeout_secs` so the assertion
        // would fail under any hardcoded value (35 s in tests, 75 s in
        // the previous patch).
        let cfg: Config = serde_json::from_str(
            r#"{
                "mode": "apps_script",
                "google_ip": "127.0.0.1",
                "front_domain": "www.google.com",
                "script_id": "TEST",
                "auth_key": "test_auth_key",
                "listen_host": "127.0.0.1",
                "listen_port": 8085,
                "log_level": "info",
                "verify_ssl": true,
                "request_timeout_secs": 60
            }"#,
        )
        .unwrap();
        let fronter = Arc::new(DomainFronter::new(&cfg).expect("test fronter must construct"));
        let mux = TunnelMux::start(fronter, 0, 0);

        assert_eq!(
            mux.reply_timeout(),
            Duration::from_secs(60) + REPLY_TIMEOUT_SLACK,
            "reply_timeout must equal batch_timeout + REPLY_TIMEOUT_SLACK"
        );
    }

    /// The buffered ClientHello from the pre-read window must reach the
    /// tunnel-node as the first `Data` op on the fallback path. If this
    /// regresses, every TLS handshake stalls until the 30 s read-timeout
    /// fires — catastrophic and silent without a test.
    #[tokio::test]
    async fn tunnel_loop_replays_pending_client_data_before_reading_socket() {
        use tokio::net::TcpListener;

        // Set up a loopback pair so tunnel_loop has a real TcpStream to
        // work with. We never write to its peer, so tunnel_loop's "read
        // from client" branch would block indefinitely — meaning any
        // `Data` msg it emits must have come from pending_client_data.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let _client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();
        let pending = Some(Bytes::from_static(b"CLIENTHELLO"));

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-under-test", &mux, pending).await
            }
        });

        // The first message tunnel_loop emits must be Data carrying the
        // replayed bytes — NOT whatever it would have read from the socket.
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("tunnel_loop did not send a message within 2s")
            .expect("mux channel closed unexpectedly");

        match msg {
            MuxMsg::Data { sid, data, reply, .. } => {
                assert_eq!(sid, "sid-under-test");
                assert_eq!(&data[..], b"CLIENTHELLO");
                // Reply with eof so tunnel_loop unwinds cleanly.
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-under-test".into()),
                        d: None,
                        pkts: None,
                        eof: Some(true),
                        e: None,
                        code: None,
                        seq: Some(0),
                    },
                    "test-script".to_string(),
                )));
            }
            other => panic!(
                "first mux message was not Data (expected replay); got {:?}",
                match other {
                    MuxMsg::Connect { .. } => "Connect",
                    MuxMsg::ConnectData { .. } => "ConnectData",
                    MuxMsg::Data { .. } => unreachable!(),
                    MuxMsg::UdpOpen { .. } => "UdpOpen",
                    MuxMsg::UdpData { .. } => "UdpData",
                    MuxMsg::Close { .. } => "Close",
                }
            ),
        }

        // With pipelining (INFLIGHT_OPTIMIST=2), the second op is
        // launched after a 1 s stagger sleep, so we need to wait long
        // enough for it to arrive. Reply to any remaining messages so the
        // loop can exit cleanly.
        let mut seq = 1u64;
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            if let MuxMsg::Data { reply, .. } = msg {
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-under-test".into()),
                        d: None, pkts: None, eof: Some(true),
                        e: None, code: None, seq: Some(seq),
                    },
                    "test-script".to_string(),
                )));
                seq += 1;
            }
        }

        let _ = tokio::time::timeout(Duration::from_secs(4), loop_handle)
            .await
            .expect("tunnel_loop did not exit after eof");
    }

    /// Regression for the mixed-mode stall: A is legacy, B is long-poll
    /// capable, the session's last reply came from A. A naive per-
    /// deployment skip (gated on the *previous* reply's `script_id`)
    /// would short-circuit every empty poll on this session — so B
    /// never gets a chance to long-poll for us, and remote→client data
    /// stalls until either the local client sends bytes or A's TTL
    /// expires. The fix gates skip-when-idle on the aggregate
    /// `all_servers_legacy()` instead, so the loop keeps emitting empty
    /// polls whenever at least one peer can still hold the request open.
    /// Replies are paced via `start_paused` time auto-advance — without
    /// it the test would take ~2 s of real wall-clock time per session.
    #[tokio::test(start_paused = true)]
    async fn tunnel_loop_keeps_polling_when_only_some_deployments_legacy() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let _client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        // 2 deployments, only A marked legacy → all_servers_legacy = false.
        let (mux, mut rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");
        assert!(!mux.all_servers_legacy());

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-mixed", &mux, None).await
            }
        });

        // Reply to 6 empty polls, all from A. With the regression
        // (per-deployment skip on `last_script_id == A`), the loop would
        // stop emitting at iteration 4 — `consecutive_empty > 3` plus
        // `last_was_legacy` would short-circuit the send. With the fix,
        // the aggregate gate stays false and the loop keeps polling.
        // The 60 s timeout below is paused-time, so it only "elapses"
        // if rx.recv() truly never resolves (i.e. the loop has stalled).
        let mut received = 0u32;
        while received < 6 {
            let msg = tokio::time::timeout(Duration::from_secs(60), rx.recv())
                .await
                .unwrap_or_else(|_| panic!(
                    "loop stopped emitting at iteration {} — regression: per-deployment skip-when-idle stalled session even though long-poll-capable peer was available",
                    received
                ))
                .expect("mux channel closed unexpectedly");
            match msg {
                MuxMsg::Data { sid, data, seq, reply, .. } => {
                    assert_eq!(sid, "sid-mixed");
                    assert!(data.is_empty(), "expected empty poll, got {} bytes", data.len());
                    let last = received == 5;
                    let _ = reply.send(Ok((
                        TunnelResponse {
                            sid: Some("sid-mixed".into()),
                            d: None,
                            pkts: None,
                            eof: if last { Some(true) } else { None },
                            e: None,
                            code: None,
                            seq,
                        },
                        "script-A".to_string(),
                    )));
                    received += 1;
                }
                _ => panic!(
                    "iteration {}: expected Data poll, got a different MuxMsg variant",
                    received
                ),
            }
        }

        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle)
            .await
            .expect("tunnel_loop did not exit after eof");
    }

    /// Once `mark_connect_data_unsupported` is called, future sessions
    /// must see the flag — no per-session repeat of the detect-and-fallback
    /// cost. If this regresses, every new flow pays an extra round trip
    /// against a tunnel-node that will never learn the new op.
    #[test]
    fn unsupported_cache_is_sticky() {
        let (mux, _rx) = mux_for_test();
        assert!(!mux.connect_data_unsupported());
        mux.mark_connect_data_unsupported();
        assert!(mux.connect_data_unsupported());
        mux.mark_connect_data_unsupported(); // idempotent
        assert!(mux.connect_data_unsupported());
    }

    /// Marking deployment A as legacy must NOT make B look legacy. This
    /// is the central guarantee of the per-deployment design: with the
    /// old global AtomicBool, one slow / legacy deployment dragged every
    /// session onto the 30 s legacy cadence even when the other 7 were
    /// long-polling fine.
    #[test]
    fn legacy_state_is_per_deployment() {
        let (mux, _rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");

        let deps = mux.legacy_deployments.lock().unwrap();
        assert!(deps.contains_key("script-A"));
        assert!(
            !deps.contains_key("script-B"),
            "marking A must not insert an entry for B"
        );
    }

    /// `all_servers_legacy` (the per-session 30 s read-timeout gate) flips
    /// to true *only* when every known deployment has been marked. With
    /// 2 deployments, marking one keeps the gate false; marking both
    /// flips it true.
    #[test]
    fn all_servers_legacy_requires_every_deployment() {
        let (mux, _rx) = mux_for_test_with(2);
        assert!(!mux.all_servers_legacy());

        mux.mark_server_no_longpoll("script-A");
        assert!(
            !mux.all_servers_legacy(),
            "1 of 2 marked: aggregate must stay false"
        );

        mux.mark_server_no_longpoll("script-B");
        assert!(
            mux.all_servers_legacy(),
            "all deployments marked: aggregate flips true"
        );

        // Idempotent re-mark of an already-legacy deployment doesn't
        // disturb the aggregate.
        mux.mark_server_no_longpoll("script-A");
        assert!(mux.all_servers_legacy());
    }

    /// After `LEGACY_RECOVER_AFTER`, an entry is treated as expired and
    /// the deployment rejoins the long-poll fast path. The next mark
    /// (against any deployment) sweeps stale entries before recomputing
    /// the aggregate gate, so a recovered peer doesn't keep counting
    /// toward `all_legacy`. Backdating the mark time avoids a real 60 s
    /// sleep in the test — same effect as the wall-clock moving forward.
    #[test]
    fn legacy_state_recovers_after_ttl() {
        let (mux, _rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");

        // Backdate A past LEGACY_RECOVER_AFTER, then mark B. B's mark
        // must trigger a sweep that drops the stale A entry.
        {
            let mut deps = mux.legacy_deployments.lock().unwrap();
            let stale = Instant::now()
                .checked_sub(LEGACY_RECOVER_AFTER + Duration::from_secs(1))
                .expect("test environment should have a non-trivial monotonic clock");
            deps.insert("script-A".to_string(), stale);
        }
        mux.mark_server_no_longpoll("script-B");

        let deps = mux.legacy_deployments.lock().unwrap();
        assert!(
            !deps.contains_key("script-A"),
            "expired entry must be swept on the next mark — otherwise stale legacy state never clears"
        );
        assert!(deps.contains_key("script-B"));
    }

    /// If every deployment is legacy and then time passes past
    /// `LEGACY_RECOVER_AFTER` *without any new mark*, the aggregate gate
    /// must self-correct on the next `all_servers_legacy()` call.
    /// Without the in-place sweep on read, stale legacy marks would keep
    /// the 30 s read-timeout active forever after every deployment
    /// recovers.
    #[test]
    fn all_servers_legacy_self_corrects_when_entries_expire() {
        let (mux, _rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");
        mux.mark_server_no_longpoll("script-B");
        assert!(mux.all_servers_legacy());

        // Backdate every entry past TTL.
        {
            let mut deps = mux.legacy_deployments.lock().unwrap();
            let stale = Instant::now()
                .checked_sub(LEGACY_RECOVER_AFTER + Duration::from_secs(1))
                .expect("monotonic clock should be far enough along");
            for (_, t) in deps.iter_mut() {
                *t = stale;
            }
        }

        assert!(
            !mux.all_servers_legacy(),
            "aggregate must self-correct when all entries expire — otherwise the 30 s read timeout sticks forever"
        );
    }

    #[test]
    fn should_fire_first_op_never_fires() {
        // Empty accumulator: even a single op larger than the payload cap
        // must not fire — there's nothing to fire yet, and the op gets
        // added (it will simply be the only op in the next batch).
        assert!(!should_fire(0, 0, 0));
        assert!(!should_fire(0, 0, MAX_BATCH_PAYLOAD_BYTES + 1_000_000));
    }

    #[test]
    fn should_fire_at_max_ops_threshold() {
        // 49 already-queued ops + 50th: still fits (boundary is `>=`).
        assert!(!should_fire(MAX_BATCH_OPS - 1, 0, 100));
        // 50 already-queued ops + 51st: must fire.
        assert!(should_fire(MAX_BATCH_OPS, 0, 100));
        // Well past the cap: must fire.
        assert!(should_fire(MAX_BATCH_OPS + 5, 0, 100));
    }

    #[test]
    fn should_fire_when_payload_would_exceed_cap() {
        // Exactly at the cap is fine — strict `>`.
        assert!(!should_fire(
            10,
            MAX_BATCH_PAYLOAD_BYTES - 100,
            100,
        ));
        // One byte over: fire.
        assert!(should_fire(
            10,
            MAX_BATCH_PAYLOAD_BYTES - 100,
            101,
        ));
        // Sum overflow well past the cap: fire.
        assert!(should_fire(
            10,
            MAX_BATCH_PAYLOAD_BYTES,
            1,
        ));
    }

    /// Reply indices must point at the slot the op occupies *within its
    /// batch*. Pre-flush ops are 0..N-1 in batch A; post-flush ops
    /// restart at 0 in batch B. If this regresses, `fire_batch`'s
    /// `batch_resp.r.get(idx)` lookup hands the wrong response (or
    /// `None`) to the wrong session — silent data corruption that
    /// the encode-layer tests can't catch.
    #[tokio::test]
    async fn batch_accum_reindexes_after_flush() {
        // Stand-alone helper that mirrors `push_or_fire`'s push step
        // without the fire_batch call — lets us simulate a flush with
        // `mem::take` and assert the post-flush indexing without
        // mocking the whole tunnel_request stack.
        fn push_no_fire(
            accum: &mut BatchAccum,
            op: PendingOp,
            op_bytes: usize,
            reply: BatchedReply,
        ) {
            let idx = accum.pending_ops.len();
            accum.pending_ops.push(op);
            accum.data_replies.push((idx, reply));
            accum.payload_bytes += op_bytes;
        }

        let mk_op = |sid: &str| PendingOp {
            op: "data",
            sid: Some(sid.into()),
            host: None,
            port: None,
            data: Some(Bytes::from_static(b"x")),
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        let mk_reply = || oneshot::channel::<Result<(TunnelResponse, String), String>>().0;

        let mut accum = BatchAccum::new();

        // Batch A: 3 ops at indices 0, 1, 2.
        push_no_fire(&mut accum, mk_op("a0"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("a1"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("a2"), 4, mk_reply());
        assert_eq!(accum.pending_ops.len(), 3);
        assert_eq!(
            accum.data_replies.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 1, 2],
        );
        assert_eq!(accum.payload_bytes, 12);

        // Simulate the flush: take the queued state and reset the byte
        // counter (matches what `push_or_fire` does after `fire_batch`).
        let _flushed_ops = std::mem::take(&mut accum.pending_ops);
        let _flushed_replies = std::mem::take(&mut accum.data_replies);
        accum.payload_bytes = 0;

        // Batch B: 2 ops, indices restart at 0.
        push_no_fire(&mut accum, mk_op("b0"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("b1"), 4, mk_reply());
        assert_eq!(accum.pending_ops.len(), 2);
        assert_eq!(
            accum.data_replies.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 1],
            "post-flush indices must restart at 0 — otherwise fire_batch's \
             batch_resp.r.get(idx) returns None and every session in the \
             second batch sees a missing-response error"
        );
        assert_eq!(accum.payload_bytes, 8);
    }

    #[test]
    fn encode_pending_data_op_with_payload_emits_base64() {
        let op = PendingOp {
            op: "data",
            sid: Some("sid-1".into()),
            host: None,
            port: None,
            data: Some(Bytes::from_static(b"hello")),
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        let b = encode_pending(op);
        assert_eq!(b.op, "data");
        assert_eq!(b.sid.as_deref(), Some("sid-1"));
        assert_eq!(b.d.as_deref(), Some(B64.encode(b"hello").as_str()));
    }

    #[test]
    fn encode_pending_omits_d_for_empty_polls_and_close() {
        // Empty-poll Data: mux_loop converts empty Bytes to data: None.
        let empty_poll = PendingOp {
            op: "data",
            sid: Some("sid-2".into()),
            host: None,
            port: None,
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        assert!(encode_pending(empty_poll).d.is_none());

        // UDP poll with no payload: same shape.
        let udp_poll = PendingOp {
            op: "udp_data",
            sid: Some("sid-3".into()),
            host: None,
            port: None,
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        assert!(encode_pending(udp_poll).d.is_none());

        // Close has no data and no reply — `d` must stay omitted.
        let close = PendingOp {
            op: "close",
            sid: Some("sid-4".into()),
            host: None,
            port: None,
            data: None,
            encode_empty: false,
            seq: None,
            wseq: None,
        };
        assert!(encode_pending(close).d.is_none());
    }

    #[test]
    fn encode_pending_connect_data_emits_empty_string_when_data_is_empty() {
        // Defensive: ConnectData's wire contract is that `d` is always
        // present (its presence is the signal that the caller is opting
        // into the bundled-first-bytes flow). If an empty Bytes ever
        // reaches the encoder, we must serialize `d: ""` not omit it.
        let op = PendingOp {
            op: "connect_data",
            sid: None,
            host: Some("example.com".into()),
            port: Some(443),
            data: Some(Bytes::new()),
            encode_empty: true,
            seq: None,
            wseq: None,
        };
        let b = encode_pending(op);
        assert_eq!(b.op, "connect_data");
        assert_eq!(b.d.as_deref(), Some(""));
    }

    #[test]
    fn encode_pending_connect_data_with_payload_encodes_normally() {
        let op = PendingOp {
            op: "connect_data",
            sid: None,
            host: Some("example.com".into()),
            port: Some(443),
            data: Some(Bytes::from_static(b"\x16\x03\x01")), // ClientHello prefix
            encode_empty: true,
            seq: None,
            wseq: None,
        };
        let b = encode_pending(op);
        assert_eq!(b.d.as_deref(), Some(B64.encode(b"\x16\x03\x01").as_str()));
    }

    #[test]
    fn preread_counters_track_each_outcome() {
        let (mux, _rx) = mux_for_test();

        mux.record_preread_win(443, Duration::from_micros(3_500));
        mux.record_preread_win(443, Duration::from_micros(1_500));
        mux.record_preread_loss(443);
        mux.record_preread_skip_port(80);
        mux.record_preread_skip_unsupported(443);

        assert_eq!(mux.preread_win.load(Ordering::Relaxed), 2);
        assert_eq!(mux.preread_loss.load(Ordering::Relaxed), 1);
        assert_eq!(mux.preread_skip_port.load(Ordering::Relaxed), 1);
        assert_eq!(mux.preread_skip_unsupported.load(Ordering::Relaxed), 1);
        // Two wins summing to 5000 µs.
        assert_eq!(mux.preread_win_total_us.load(Ordering::Relaxed), 5_000);
        // Five record_* calls, so trigger counter is at 5.
        assert_eq!(mux.preread_total_events.load(Ordering::Relaxed), 5);
    }

    /// Client data written to the socket *during* the reply wait must be
    /// buffered and sent in a subsequent op — not blocked until the reply
    /// arrives and a fresh read-timeout elapses.
    #[tokio::test]
    async fn tunnel_loop_reads_client_during_reply_wait() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                let mut server_side = server_side;
                tunnel_loop(&mut server_side, "sid-overlap", &mux, None).await
            }
        });

        // With pipelining (N=2), the loop may send two ops before we
        // can write client data. Collect all initial ops, reply to each,
        // then write data and check a subsequent op carries it.
        let mut pending_replies: Vec<BatchedReply> = Vec::new();
        let mut seq: u64 = 0;

        // Drain initial ops (up to N=2).
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            if let MuxMsg::Data { reply, .. } = msg {
                pending_replies.push(reply);
            }
            if pending_replies.len() >= INFLIGHT_ACTIVE { break; }
        }

        // Write client data while replies are pending.
        client.write_all(b"UPLOAD_DATA").await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Reply to all pending ops (no eof, no data).
        for reply in pending_replies.drain(..) {
            let _ = reply.send(Ok((
                TunnelResponse {
                    sid: Some("sid-overlap".into()),
                    d: None, pkts: None, eof: None,
                    e: None, code: None, seq: Some(seq),
                },
                "test-script".to_string(),
            )));
            seq += 1;
        }

        // Now check that a subsequent op carries the buffered upload data.
        let mut found_upload = false;
        for _ in 0..4 {
            let msg = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Some(m)) => m,
                _ => break,
            };
            if let MuxMsg::Data { data, reply, .. } = msg {
                if &data[..] == b"UPLOAD_DATA" {
                    found_upload = true;
                }
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-overlap".into()),
                        d: None, pkts: None,
                        eof: Some(found_upload),
                        e: None, code: None, seq: Some(seq),
                    },
                    "test-script".to_string(),
                )));
                seq += 1;
                if found_upload { break; }
            }
        }
        assert!(found_upload, "upload data must appear in a subsequent op");

        // Drain any remaining in-flight ops (stagger sleep is 1 s,
        // so allow enough time for late-arriving ops).
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(1500), rx.recv()).await {
            if let MuxMsg::Data { reply, .. } = msg {
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-overlap".into()),
                        d: None, pkts: None, eof: Some(true),
                        e: None, code: None, seq: Some(seq),
                    },
                    "test-script".to_string(),
                )));
                seq += 1;
            }
        }

        let _ = tokio::time::timeout(Duration::from_secs(4), loop_handle)
            .await
            .expect("tunnel_loop did not exit after eof");
    }
}
