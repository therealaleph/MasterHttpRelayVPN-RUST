//! Full-mode tunnel client with pipelined batch multiplexer.
//!
//! A central multiplexer collects pending data from ALL active sessions
//! and fires batch requests without waiting for the previous one to return.
//! Each Apps Script deployment (account) gets its own concurrency pool of
//! 30 in-flight requests — matching the per-account Apps Script limit.

use std::collections::HashMap;
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
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::domain_fronter::{
    BatchOp, DomainFronter, FronterError, TunnelResponse, CAPS_PIPELINE_SEQ,
};

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

/// Timeout for a session waiting for its batch reply. If the batch task
/// is slow (e.g. one op in the batch has a dead target on the tunnel-node
/// side), the session gives up and retries on the next tick rather than
/// blocking indefinitely.
const REPLY_TIMEOUT: Duration = Duration::from_secs(35);

/// Slack added to the effective batch timeout to derive the per-session
/// pipelined reply watchdog (`TunnelMux::pipelined_reply_timeout`).
/// Covers queueing stages the batch HTTP timeout doesn't include:
///
///   * coalesce wait (≤ `coalesce_max_ms`, default 1 s)
///   * per-deployment semaphore acquire (typical sub-second under
///     HTTP/2 multiplex; worst case bounded by another batch_timeout)
///   * mpsc channel hop into / out of `mux_loop`
///
/// Setting this any tighter risks the watchdog firing on legitimate
/// slow batches that are still inside their HTTP-layer budget; any
/// looser just delays detection of a genuinely broken mux. 15 s
/// covers the realistic queueing while keeping the upper bound
/// finite.
const PIPELINED_REPLY_SLACK: Duration = Duration::from_secs(15);

/// Floor on the per-batch HTTP timeout for batches that contain at
/// least one seq'd `data` op. The server-side worst-case wait for
/// a seq op is `SEQ_WAIT_TIMEOUT (~30 s) + LONGPOLL_DEADLINE (~15 s)
/// = ~45 s`. The default `Config::request_timeout_secs` is 30 s,
/// which would fire BEFORE a valid pipelined batch could complete —
/// triggering "batch timed out", closing the pipelined session, AND
/// recording a timeout strike against an otherwise-healthy
/// deployment (eventually blacklisting it). Take `max(configured,
/// 60 s)` for seq-bearing batches so the legitimate server wait
/// always fits inside the client budget. The per-session reply
/// watchdog (`TunnelMux::pipelined_reply_timeout`) is derived from
/// this same effective batch timeout plus `PIPELINED_REPLY_SLACK`
/// — the two agree on what counts as "definitely broken" without
/// the per-session watchdog ever firing on a still-valid batch.
const PIPELINED_BATCH_TIMEOUT_FLOOR: Duration = Duration::from_secs(60);

/// How long we'll briefly hold the client socket after the local
/// CONNECT/SOCKS5 handshake, waiting for the client's first bytes (the
/// TLS ClientHello for HTTPS). Bundling those bytes with the tunnel-node
/// connect saves one Apps Script round-trip per new flow.
const CLIENT_FIRST_DATA_WAIT: Duration = Duration::from_millis(50);

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
/// returns near `LONGPOLL_DEADLINE` (~15 s on current tunnel-nodes) or
/// comes back early *with* pushed bytes — neither matches a fast empty
/// reply. Threshold sits well above the legacy `~350 ms` drain and well
/// below the long-poll floor, so network jitter on either side won't
/// false-trigger.
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
        /// Per-session monotonic seq for pipelined sessions. `None` for
        /// non-pipelined sessions (and any session whose tunnel-node
        /// didn't advertise `CAPS_PIPELINE_SEQ`). When `Some`, the
        /// tunnel-node enforces in-order processing and echoes the
        /// value back in the response so the client can route it into
        /// its per-session reorder buffer.
        seq: Option<u64>,
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
    /// Per-session seq for pipelined `data` ops; `None` otherwise.
    /// Forwarded verbatim to `BatchOp::seq` by `encode_pending`.
    seq: Option<u64>,
}

pub struct TunnelMux {
    tx: mpsc::Sender<MuxMsg>,
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
    /// Snapshot of the configured `Config::request_timeout_secs` taken
    /// at mux construction. Used to derive the per-session pipelined
    /// reply timeout (see `pipelined_reply_timeout()`) so a user-tuned
    /// `request_timeout_secs > 60` doesn't cause sessions to close
    /// before the batch layer can legitimately complete.
    batch_timeout: Duration,
    /// Set when ANY pipelined reply observed the server dropping the
    /// `seq` field — i.e. the request reached an old tunnel-node
    /// that doesn't speak the pipelining protocol. Once set, new
    /// sessions skip the `caps` opt-in even if a connect_data reply
    /// advertises it; the safe fallback is the legacy single-in-flight
    /// loop. This protects mixed-version multi-deployment configs
    /// where round-robin can land a session's seq ops on an
    /// un-upgraded backend after a different deployment advertised
    /// the bit. The flag is process-wide (not per-deployment): once
    /// observed, downgrade everyone until restart.
    pipelining_globally_disabled: AtomicBool,
}

impl TunnelMux {
    pub fn start(
        fronter: Arc<DomainFronter>,
        coalesce_step_ms: u64,
        coalesce_max_ms: u64,
    ) -> Arc<Self> {
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
        let step = if coalesce_step_ms > 0 {
            coalesce_step_ms
        } else {
            DEFAULT_COALESCE_STEP_MS
        };
        let max = if coalesce_max_ms > 0 {
            coalesce_max_ms
        } else {
            DEFAULT_COALESCE_MAX_MS
        };
        tracing::info!("batch coalesce: step={}ms max={}ms", step, max);
        let batch_timeout = fronter.batch_timeout();
        let (tx, rx) = mpsc::channel(512);
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
            batch_timeout,
            pipelining_globally_disabled: AtomicBool::new(false),
        })
    }

    /// Effective per-session reply timeout for pipelined sessions.
    /// Has to exceed the actual batch layer's worst-case time —
    /// otherwise the session's reply watchdog fires before
    /// `fire_batch` returns, dropping in-flight oneshots and
    /// forcing avoidable disconnects on legitimate slow batches.
    ///
    /// `effective_batch_timeout = max(configured, PIPELINED_BATCH_TIMEOUT_FLOOR)`
    /// accounts for the server-side worst-case wait
    /// (`SEQ_WAIT_TIMEOUT + LONGPOLL_DEADLINE`) plus the h2/h1
    /// transport. The watchdog covers TWO of those (rather than
    /// one + small slack) because under per-deployment semaphore
    /// saturation — all 30 in-flight slots holding long-poll seq
    /// batches — a fresh op waits up to one full
    /// `effective_batch_timeout` for a permit BEFORE its own
    /// `effective_batch_timeout`-bounded request even starts. With
    /// a one-batch budget the watchdog fires while the op is still
    /// queued for a permit, dropping the oneshot and closing a
    /// healthy pipelined session under load.
    ///
    /// Additional `PIPELINED_REPLY_SLACK` covers the smaller
    /// queueing stages: mpsc hop into `mux_loop`, coalesce wait
    /// (≤ `coalesce_max_ms`), encode/transit overhead. Total
    /// default budget: 60 s × 2 + 15 s = 135 s. With a configured
    /// `request_timeout_secs = 120 s`: 120 × 2 + 15 = 255 s.
    pub(crate) fn pipelined_reply_timeout(&self) -> Duration {
        let effective_batch = self.batch_timeout.max(PIPELINED_BATCH_TIMEOUT_FLOOR);
        // 2× to cover saturated-semaphore permit wait + own request.
        effective_batch * 2 + PIPELINED_REPLY_SLACK
    }

    /// True once any pipelined reply observed a `None` seq from the
    /// server, indicating the deployment route reached an old
    /// tunnel-node that doesn't speak the protocol. Sticky for the
    /// process lifetime — downgrade all sessions to the legacy loop
    /// until restart.
    pub(crate) fn pipelining_disabled(&self) -> bool {
        self.pipelining_globally_disabled.load(Ordering::Acquire)
    }

    pub(crate) fn mark_pipelining_disabled(&self) {
        if !self
            .pipelining_globally_disabled
            .swap(true, Ordering::AcqRel)
        {
            tracing::warn!(
                "tunnel-node along the round-robin path dropped the seq \
                 field on a pipelined reply; disabling pipelining for new \
                 sessions until restart. Mixed-version config? Make sure \
                 every script_id forwards to the same upgraded tunnel-node."
            );
        }
    }

    async fn send(&self, msg: MuxMsg) {
        let _ = self.tx.send(msg).await;
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

async fn mux_loop(
    mut rx: mpsc::Receiver<MuxMsg>,
    fronter: Arc<DomainFronter>,
    coalesce_step_ms: u64,
    coalesce_max_ms: u64,
) {
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
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
                }
                MuxMsg::Data {
                    sid,
                    data,
                    seq,
                    reply,
                } => {
                    let op_bytes = encoded_len(data.len());
                    let op = PendingOp {
                        op: "data",
                        sid: Some(sid),
                        host: None,
                        port: None,
                        data: if data.is_empty() { None } else { Some(data) },
                        encode_empty: false,
                        seq,
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
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
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
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
                    };
                    accum
                        .push_or_fire(op, op_bytes, reply, &sems, &fronter)
                        .await;
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
        seq: p.seq,
        d,
    }
}

/// Pick a deployment, acquire its per-account concurrency slot, and spawn
/// a batch request task.
///
/// The batch HTTP round-trip is bounded by `BATCH_TIMEOUT` so a slow or
/// dead tunnel-node target cannot hold a pipeline slot (and block waiting
/// sessions) forever.
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
    let f = fronter.clone();

    tokio::spawn(async move {
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
        // this batch get an error and can retry.
        //
        // Pipelined-batch floor: if ANY op in this batch carries a
        // `seq`, the server-side worst-case wait is
        // `SEQ_WAIT_TIMEOUT + LONGPOLL_DEADLINE` (≈ 45 s). The default
        // configured timeout (30 s) would fire first, surface as
        // "batch timed out" client-side, AND record a timeout strike
        // against the deployment. `max(configured, 60 s)` keeps the
        // client budget aligned with what the server can legitimately
        // take, without changing legacy-batch behavior.
        let configured = f.batch_timeout();
        let has_seq_op = data_ops.iter().any(|op| op.seq.is_some());
        let batch_timeout = if has_seq_op {
            configured.max(PIPELINED_BATCH_TIMEOUT_FLOOR)
        } else {
            configured
        };
        // Pass the effective timeout into `tunnel_batch_request_to`
        // so the underlying h2 / h1 transports use it too. Without
        // this, the inner `h2_relay_request` (and h1
        // `read_http_response`) defaulted to `self.batch_timeout`
        // (30 s) and fired before our outer 60 s budget could ever
        // be reached on a pipelined batch — surfacing as "batch
        // timed out" client-side and recording an undeserved
        // timeout strike against the deployment. The outer
        // `tokio::time::timeout` stays as a defensive ceiling.
        let result = tokio::time::timeout(
            batch_timeout,
            f.tunnel_batch_request_with_timeout(&script_id, &data_ops, batch_timeout),
        )
        .await;
        tracing::info!(
            "batch: {} ops → {}, rtt={:?}",
            n_ops,
            &script_id[..script_id.len().min(8)],
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
                let sid_short = &script_id[..script_id.len().min(8)];
                for (idx, reply) in data_replies {
                    if let Some(resp) = batch_resp.r.get(idx) {
                        let _ = reply.send(Ok((resp.clone(), script_id.clone())));
                    } else {
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
                let sid_short = &script_id[..script_id.len().min(8)];
                // Detect the body string we ship as the v1.8.0 bad-auth
                // decoy. v1.8.1 asserted "AUTH_KEY mismatch" outright, but
                // #404 (w0l4i) found the same body comes back from Apps
                // Script in 3 other unrelated cases too:
                //
                //   1. AUTH_KEY mismatch                 — our intentional decoy
                //   2. Apps Script execution timeout/    — runtime hit 6-min
                //      mid-call quota tear                 cap or per-100s quota
                //   3. Apps Script internal hiccup       — Google-side flake,
                //                                          serves placeholder
                //   4. ISP-side response truncation      — #313 pattern, the
                //                                          response was assembled
                //                                          but ate an RST mid-flight
                //
                // So we surface all four candidates instead of asserting #1.
                // Users can flip DIAGNOSTIC_MODE=true in Code.gs to disambiguate:
                // only #1 still returns the decoy in diagnostic mode; the
                // others return real JSON or different errors.
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
                let sid_short = &script_id[..script_id.len().min(8)];
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

    let (sid, caps, first_resp, pending_client_data) = match initial_data {
        Some(data) => match connect_with_initial_data(host, port, data.clone(), mux).await? {
            ConnectDataOutcome::Opened { sid, response } => {
                let caps = response.caps;
                (sid, caps, Some(response), None)
            }
            ConnectDataOutcome::Unsupported => {
                mux.mark_connect_data_unsupported();
                let (sid, caps) = connect_plain(host, port, mux).await?;
                // Replay the buffered ClientHello on the first tunnel_loop
                // iteration. `Bytes::clone()` is a cheap Arc bump — no
                // copy of the 64 KB buffer.
                (sid, caps, None, Some(data))
            }
        },
        None => {
            let (sid, caps) = connect_plain(host, port, mux).await?;
            (sid, caps, None, None)
        }
    };

    // Opt into pipelining only when:
    //   1. THIS connect/connect_data reply advertised the bit, AND
    //   2. We haven't observed a stale-version reply previously
    //      (round-robin can land us on an un-upgraded backend after
    //      a different deployment served the connect with caps set).
    // The global toggle is sticky for the process lifetime — once
    // `mark_pipelining_disabled` fires (on a `seq=None` reply for a
    // pipelined session), every NEW session falls back to the legacy
    // single-in-flight loop instead of risking another disconnect on
    // the next mixed-version seq op.
    let pipeline_advertised = caps.map(|c| c & CAPS_PIPELINE_SEQ != 0).unwrap_or(false);
    let pipeline = pipeline_advertised && !mux.pipelining_disabled();
    tracing::info!(
        "tunnel session {} opened for {}:{} (pipeline={}{})",
        sid,
        host,
        port,
        pipeline,
        if pipeline_advertised && !pipeline {
            ", advertised but disabled (mixed-version backend observed)"
        } else {
            ""
        },
    );

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
        if pipeline {
            tunnel_loop_pipelined(&mut sock, &sid, mux, pending_client_data).await
        } else {
            tunnel_loop(&mut sock, &sid, mux, pending_client_data).await
        }
    }
    .await;

    mux.send(MuxMsg::Close { sid: sid.clone() }).await;
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

/// Open a tunnel session via plain `connect` (no bundled first bytes).
/// Returns the new sid plus the tunnel-node's `caps` advertisement —
/// `None` against legacy tunnel-nodes, `Some(bits)` against new ones.
/// The caller passes `caps` into `tunnel_loop` to pick between the
/// legacy single-in-flight loop and the pipelined variant.
async fn connect_plain(
    host: &str,
    port: u16,
    mux: &Arc<TunnelMux>,
) -> std::io::Result<(String, Option<u32>)> {
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
            let caps = resp.caps;
            let sid = resp.sid.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "tunnel connect: no session id")
            })?;
            Ok((sid, caps))
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

async fn tunnel_loop(
    sock: &mut TcpStream,
    sid: &str,
    mux: &Arc<TunnelMux>,
    mut pending_client_data: Option<Bytes>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = sock.split();
    // `BytesMut` + `read_buf` + a per-read decision between
    // `split().freeze()` (zero-copy) and `copy_from_slice` + `clear`
    // (right-sized copy, buffer reused).
    //
    // Why the split decision: `bytes` 1.x refcounts the *whole*
    // backing allocation, so a frozen `Bytes` from a partial read
    // pins all `READ_CHUNK` bytes until it drops. Under semaphore
    // saturation or reply timeouts, dozens of small TLS records or
    // HTTP/2 frames can each retain ~64 KB instead of their actual
    // payload size — order-of-magnitude memory regression on
    // constrained targets (router builds with 64 MB RAM).
    //
    // Threshold: at ≥ half-buffer the saved memcpy outweighs the
    // wasted slack, and these reads are typically streaming bulk
    // transfer where the `Bytes` flushes through the mux quickly.
    // Below that, copy out and `clear()` so the same allocation
    // serves the next read — equivalent memory profile to the old
    // `vec![0u8; 65536]` + `to_vec()` code on small-read workloads.
    const READ_CHUNK: usize = 65536;
    const ZERO_COPY_THRESHOLD: usize = READ_CHUNK / 2;
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    let mut consecutive_empty = 0u32;

    loop {
        // Cadence depends on whether the tunnel-node is doing long-poll
        // drains. With long-poll, the server holds empty polls open up
        // to its `LONGPOLL_DEADLINE` (~15 s on current tunnel-nodes), so the client
        // can keep this read timeout short — the wait is on the wire,
        // not here. Against *legacy* tunnel-nodes (no long-poll, fast
        // empty replies), the same short cadence + always-poll behavior
        // would generate continuous round-trips on idle sessions and
        // burn Apps Script quota.
        //
        // Both the read timeout and the skip-empty-when-idle decision
        // are gated on `all_legacy` — i.e. *every known deployment is
        // currently legacy*. Per-deployment "skip when this script is
        // legacy" sounds appealing but is unsafe: the next op's
        // deployment is chosen by `next_script_id()` only when the
        // batch fires, so the loop can't predict where the empty poll
        // will land. Suppressing polls based on the *previous* reply's
        // script would stall remote→client data on mixed setups —
        // round-robin would never reach the long-poll-capable peer for
        // this session if every iteration short-circuits before
        // sending. Cost of the conservative gate: legacy peers see
        // some wasted empty polls when at least one peer is healthy,
        // bounded by round-robin fan-out. Worth it to keep pushed
        // bytes flowing.
        let all_legacy = mux.all_servers_legacy();
        let client_data = if let Some(data) = pending_client_data.take() {
            Some(data)
        } else {
            let read_timeout = match (all_legacy, consecutive_empty) {
                (_, 0) => Duration::from_millis(20),
                (_, 1) => Duration::from_millis(80),
                (_, 2) => Duration::from_millis(200),
                (false, _) => Duration::from_millis(500),
                (true, _) => Duration::from_secs(30),
            };

            buf.reserve(READ_CHUNK);
            match tokio::time::timeout(read_timeout, reader.read_buf(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    consecutive_empty = 0;
                    if n >= ZERO_COPY_THRESHOLD {
                        // Big read: split off the filled region. The
                        // frozen `Bytes` is at-least-half-full, so the
                        // saved 64 KB memcpy outweighs the brief
                        // retention until the mux drains.
                        Some(buf.split().freeze())
                    } else {
                        // Small read: copy out a payload-sized `Bytes`
                        // and `clear()` so the buffer is reused on the
                        // next iter (no `reserve` allocation needed
                        // because the alloc stays uniquely owned).
                        // Bounds retention to actual data even when
                        // the mux is backpressured.
                        let owned = Bytes::copy_from_slice(&buf[..n]);
                        buf.clear();
                        Some(owned)
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => None,
            }
        };

        // Skip empty polls only when *every* deployment is legacy. With
        // even one long-poll-capable peer, round-robin will land some
        // empty polls there where the server holds them open and can
        // deliver pushed bytes — that's the whole point of long-poll,
        // so we must keep emitting. See the `all_legacy` comment above
        // for why a per-deployment gate here would stall mixed setups.
        if all_legacy && client_data.is_none() && consecutive_empty > 3 {
            continue;
        }

        let data = client_data.unwrap_or_else(Bytes::new);
        let was_empty_poll = data.is_empty();

        let (reply_tx, reply_rx) = oneshot::channel();
        let send_at = Instant::now();
        mux.send(MuxMsg::Data {
            sid: sid.to_string(),
            data,
            seq: None,
            reply: reply_tx,
        })
        .await;

        // Bounded-wait on reply: if the batch this op landed in is slow
        // (dead target on the tunnel-node side), don't block this session
        // forever — timeout and let it retry on the next tick.
        let (resp, script_id) = match tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await {
            Ok(Ok(Ok((r, sid_used)))) => (r, sid_used),
            Ok(Ok(Err(e))) => {
                tracing::debug!("tunnel data error: {}", e);
                break;
            }
            Ok(Err(_)) => break, // channel dropped
            Err(_) => {
                tracing::warn!("sess {}: reply timeout, retrying", &sid[..sid.len().min(8)]);
                consecutive_empty = consecutive_empty.saturating_add(1);
                continue;
            }
        };

        // Per-deployment legacy detection: an empty-in/empty-out round
        // trip that finishes well under `LEGACY_DETECT_THRESHOLD` is
        // structurally impossible on a long-poll-capable tunnel-node
        // (the server holds the response either until data arrives or
        // until its long-poll deadline). One observation marks *this
        // specific* deployment as legacy for `LEGACY_RECOVER_AFTER`;
        // peers stay on the fast path. The aggregate `all_legacy` gate
        // only flips once *every* deployment has been so marked.
        if was_empty_poll {
            let reply_was_empty = resp.d.as_deref().map(str::is_empty).unwrap_or(true);
            if reply_was_empty && send_at.elapsed() < LEGACY_DETECT_THRESHOLD {
                mux.mark_server_no_longpoll(&script_id);
            }
        }

        if let Some(ref e) = resp.e {
            tracing::debug!("tunnel error: {}", e);
            break;
        }

        let got_data = match write_tunnel_response(&mut writer, &resp).await? {
            WriteOutcome::Wrote => true,
            WriteOutcome::NoData => false,
            WriteOutcome::BadBase64 => {
                // Tunnel-node gave us garbage; tear the session down but
                // do NOT propagate as an io error — the caller's Close
                // guard will clean up on the tunnel-node side.
                break;
            }
        };

        if resp.eof.unwrap_or(false) {
            break;
        }

        if got_data {
            consecutive_empty = 0;
        } else {
            consecutive_empty = consecutive_empty.saturating_add(1);
        }
    }

    Ok(())
}

/// Maximum number of `data` ops a pipelined session keeps in flight
/// at any one time. Matches the TLS connection-pool minimum so a
/// single active session can fill every warm connection's transit
/// window when client→Apps Script is the dominant leg (the censored-
/// network case this project is built for).
///
/// Server-side processing stays serial via the per-session seq lock,
/// so this depth doesn't translate to parallel upstream writes — but
/// it does parallelize the slow client↔AS leg's RTT. With depth=8 the
/// slow leg is used for ~8 ops simultaneously instead of one at a
/// time, which is the actual bottleneck in throttled networks.
///
/// Costs that grow with depth:
///   * Client-side reorder-buffer memory: one oneshot receiver per
///     in-flight op, bounded by depth. With 64 KB chunks the per-
///     session worst case is `depth × 64 KB` of payload sitting in
///     the mux pipeline.
///   * Per-deployment semaphore pressure: a single session can
///     occupy up to `depth` of a deployment's 30 concurrent slots
///     (or spread across deployments via `next_script_id`
///     round-robin). With many active pipelined sessions this can
///     contend with new connects.
///   * Seq-loss cascade: if seq=N is permanently lost (rare —
///     requires the carrying batch to never reach the server), all
///     subsequent in-flight seqs wait `SEQ_WAIT_TIMEOUT` for it
///     before failing.
///
/// Idle sessions stay at depth=1 regardless of this constant — see
/// `target_depth` in `tunnel_loop_pipelined` — so the quota cost of
/// raising this only applies to actively-streaming sessions.
const PIPELINE_DEPTH: usize = 8;

/// Pipelined variant of `tunnel_loop`: keeps up to `PIPELINE_DEPTH`
/// `data` ops in flight per session, each tagged with a per-session
/// monotonic `seq`. The tunnel-node enforces in-order processing so
/// replies — which may travel back over different deployments and
/// arrive out of order on the wire — carry bytes that are correctly
/// sequenced within the session's stream.
///
/// The reorder concern is handled implicitly by FIFO `await` on the
/// in-flight oneshot queue: whichever reply arrived first stays in
/// its oneshot's buffer until our task reaches its turn in the
/// queue. Output to the local socket is therefore always in send
/// order, which (because the server processed the corresponding
/// uplinks in seq order) matches the upstream byte order.
async fn tunnel_loop_pipelined(
    sock: &mut TcpStream,
    sid: &str,
    mux: &Arc<TunnelMux>,
    mut pending_client_data: Option<Bytes>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = sock.split();
    const READ_CHUNK: usize = 65536;
    const ZERO_COPY_THRESHOLD: usize = READ_CHUNK / 2;
    let mut buf = BytesMut::with_capacity(READ_CHUNK);
    // FIFO of in-flight (seq, oneshot) pairs. Front = oldest seq
    // still awaiting a response; we always await the front so output
    // to the local socket is in seq order regardless of which reply
    // arrived first on the wire. The seq is kept alongside the
    // receiver so we can verify the server echoed the right value
    // (defends against a server bug or version skew silently
    // mis-routing bytes between sessions).
    let mut in_flight: std::collections::VecDeque<(
        u64,
        oneshot::Receiver<Result<(TunnelResponse, String), String>>,
    )> = std::collections::VecDeque::new();
    let mut next_send_seq: u64 = 0;
    let mut consecutive_empty: u32 = 0;
    // Flag set when the local client half-closes (TCP shutdown send,
    // returns Ok(0) from read) or its socket errors. Once set, we
    // stop queuing new uplink ops but continue draining replies for
    // seqs already in flight — those replies may carry downlink
    // bytes the server already produced. Returning early on EOF
    // (the previous shape) dropped the queued oneshot receivers
    // and silently lost any pending downlink, breaking valid
    // half-close patterns like HTTP request/response with the
    // client shutting its write half after the request.
    let mut client_send_closed = false;

    loop {
        // SEND PHASE. While we have room and either the client has
        // data or we're keeping the pipeline full, queue another op.
        // `consecutive_empty == 0` means the last reply brought
        // downlink bytes — we treat that as "active transfer" and
        // pre-fetch with PIPELINE_DEPTH polls. Otherwise (idle) we
        // keep just one in-flight poll so the server long-polls it
        // and we don't burn quota on speculative empties.
        //
        // When `client_send_closed` is set we skip the send phase
        // entirely and fall through to RECEIVE — the loop exits
        // cleanly once `in_flight` drains.
        let active = consecutive_empty == 0;
        let target_depth = if active { PIPELINE_DEPTH } else { 1 };
        while !client_send_closed && in_flight.len() < target_depth {
            // Decide what data to send: replay any pending preread
            // bytes first; then attempt a client read. If we have
            // nothing in flight we *must* send (otherwise the loop
            // stalls waiting for replies that aren't coming), so
            // use the legacy escalating timeout. With ops already
            // in flight we only send when the client has data
            // *immediately* available — speculative empty polls in
            // that branch would just burn Apps Script quota.
            //
            // `Option<Bytes>::None` from the inner match means EOF
            // / read-error: set `client_send_closed` and break out
            // of the send phase. The remaining in_flight ops still
            // get drained by the RECEIVE PHASE below.
            let data: Option<Bytes> = if let Some(d) = pending_client_data.take() {
                Some(d)
            } else if in_flight.is_empty() {
                let read_timeout = match (mux.all_servers_legacy(), consecutive_empty) {
                    (_, 0) => Duration::from_millis(20),
                    (_, 1) => Duration::from_millis(80),
                    (_, 2) => Duration::from_millis(200),
                    (false, _) => Duration::from_millis(500),
                    (true, _) => Duration::from_secs(30),
                };
                buf.reserve(READ_CHUNK);
                match tokio::time::timeout(read_timeout, reader.read_buf(&mut buf)).await {
                    Ok(Ok(0)) => None,
                    Ok(Ok(n)) => {
                        consecutive_empty = 0;
                        Some(if n >= ZERO_COPY_THRESHOLD {
                            buf.split().freeze()
                        } else {
                            let owned = Bytes::copy_from_slice(&buf[..n]);
                            buf.clear();
                            owned
                        })
                    }
                    Ok(Err(_)) => None,
                    Err(_) => Some(Bytes::new()),
                }
            } else {
                // Already have ops in flight. Non-blocking read: if
                // the client has data right now, pipeline another op;
                // otherwise drop out and await replies.
                buf.reserve(READ_CHUNK);
                match tokio::time::timeout(Duration::from_millis(0), reader.read_buf(&mut buf))
                    .await
                {
                    Ok(Ok(0)) => None,
                    Ok(Ok(n)) => {
                        consecutive_empty = 0;
                        Some(if n >= ZERO_COPY_THRESHOLD {
                            buf.split().freeze()
                        } else {
                            let owned = Bytes::copy_from_slice(&buf[..n]);
                            buf.clear();
                            owned
                        })
                    }
                    Ok(Err(_)) => None,
                    Err(_) => break, // no data ready, stop trying to send more
                }
            };

            let Some(data) = data else {
                // EOF or read error. Flag the close and let RECEIVE
                // drain whatever's already in flight before we exit.
                client_send_closed = true;
                break;
            };

            let seq = next_send_seq;
            next_send_seq = next_send_seq.saturating_add(1);
            let (reply_tx, reply_rx) = oneshot::channel();
            mux.send(MuxMsg::Data {
                sid: sid.to_string(),
                data,
                seq: Some(seq),
                reply: reply_tx,
            })
            .await;
            in_flight.push_back((seq, reply_rx));
        }

        // RECEIVE PHASE. Await the front-of-queue reply. Subsequent
        // replies (whose seqs come later) wait in their oneshot
        // buffers until we get to them — that's the reorder
        // mechanism, and it doesn't need its own data structure.
        let Some((expected_seq, reply_rx)) = in_flight.pop_front() else {
            // Nothing in flight. If the client has half-closed, we
            // can exit cleanly now — there are no more replies to
            // drain. Otherwise (defensive) loop back; the send
            // phase guarantees at least one op in flight when the
            // client is still active.
            if client_send_closed {
                return Ok(());
            }
            continue;
        };
        // Derive the per-session reply timeout from the effective
        // batch timeout (max(configured, PIPELINED_BATCH_TIMEOUT_FLOOR))
        // plus queueing slack — see `TunnelMux::pipelined_reply_timeout`.
        // Computing this dynamically (rather than the previous fixed
        // 60 s constant) closes the session-watchdog vs batch-layer
        // race: with `request_timeout_secs > 60`, the batch is still
        // inside its budget while the session watchdog would
        // otherwise close it, dropping in-flight oneshots.
        let reply_timeout = mux.pipelined_reply_timeout();
        let (resp, _script_id) = match tokio::time::timeout(reply_timeout, reply_rx).await {
            Ok(Ok(Ok((r, sid_used)))) => (r, sid_used),
            Ok(Ok(Err(e))) => {
                tracing::debug!("pipelined data error: {}", e);
                break;
            }
            Ok(Err(_)) => break, // channel dropped
            Err(_) => {
                // Pipelined timeout has to close the session
                // rather than retry. Continuing here drops the
                // oneshot for `expected_seq` — if the server
                // later completes it, any drained downlink bytes
                // it would have carried are lost, and subsequent
                // seq replies happily fill the local socket past
                // a now-invisible gap (silent stream corruption).
                // The dynamic `reply_timeout` is sized to exceed
                // any valid server-side wait + queueing, so
                // hitting it means the mux dropped a message or
                // the task panicked — closing is the only
                // bytes-correct response.
                tracing::warn!(
                    "pipelined sess {}: reply timeout for seq {} after {:?}, \
                         closing session (further ops would risk silent \
                         corruption from missing downlink bytes)",
                    &sid[..sid.len().min(8)],
                    expected_seq,
                    reply_timeout,
                );
                break;
            }
        };

        // Verify the server echoed the seq we expected. A mismatch
        // means either (a) the tunnel-node has a bug, or (b) a
        // version-skew situation where the response shape changed
        // — either way we can't trust the bytes belong to this
        // session position, so close the session rather than
        // silently writing potentially-misrouted bytes.
        match resp.seq {
            Some(s) if s == expected_seq => { /* match — proceed */ }
            Some(s) => {
                tracing::error!(
                    "pipelined sess {}: server echoed seq {} but we expected {}; \
                     closing session to avoid misordered output",
                    &sid[..sid.len().min(8)],
                    s,
                    expected_seq,
                );
                break;
            }
            None => {
                // The reply reached an old tunnel-node along the
                // round-robin path that doesn't speak the seq
                // protocol. Globally disable pipelining for new
                // sessions until the process restarts — the next
                // round-robin pick could repeat the disconnect, and
                // staying in legacy mode is strictly safer than
                // hoping the broken backend rotates out.
                mux.mark_pipelining_disabled();
                tracing::error!(
                    "pipelined sess {}: server reply for seq {} omitted seq field; \
                     closing session and disabling pipelining for new sessions \
                     (mixed-version backend along the round-robin path)",
                    &sid[..sid.len().min(8)],
                    expected_seq,
                );
                break;
            }
        }

        if let Some(ref e) = resp.e {
            tracing::debug!("pipelined tunnel error: {}", e);
            break;
        }

        let got_data = match write_tunnel_response(&mut writer, &resp).await? {
            WriteOutcome::Wrote => true,
            WriteOutcome::NoData => false,
            WriteOutcome::BadBase64 => break,
        };

        if resp.eof.unwrap_or(false) {
            break;
        }

        if got_data {
            consecutive_empty = 0;
        } else {
            consecutive_empty = consecutive_empty.saturating_add(1);
        }
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
            caps: None,
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
        mux.record_unreachable_if_match("example.com", 443, "connect failed: connection refused");
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
        let task =
            tokio::spawn(
                async move { connect_plain("real.target.example", 443, &mux_for_task).await },
            );

        // Receive the Connect msg and reply with an outer Err whose string
        // would otherwise match `is_unreachable_error_str`.
        let msg = rx.recv().await.expect("connect msg");
        let reply = match msg {
            MuxMsg::Connect { reply, .. } => reply,
            other => panic!("expected Connect, got {:?}", std::mem::discriminant(&other)),
        };
        let _ = reply.send(Err(
            "relay failed: Network is unreachable (os error 101)".into()
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
        let len = mux.unreachable_cache.lock().map(|g| g.len()).unwrap_or(0);
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
    fn mux_for_test() -> (Arc<TunnelMux>, mpsc::Receiver<MuxMsg>) {
        mux_for_test_with(2)
    }

    /// Build a TunnelMux for tests with a specific deployment count. The
    /// per-deployment legacy state's aggregate gate (`all_servers_legacy`)
    /// requires `legacy_deployments.len() == num_scripts`, so tests that
    /// exercise that gate need to control how many "deployments" exist.
    fn mux_for_test_with(num_scripts: usize) -> (Arc<TunnelMux>, mpsc::Receiver<MuxMsg>) {
        let (tx, rx) = mpsc::channel(16);
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
            // Tests don't go through `start()`, so we pick a
            // representative configured batch_timeout (matches the
            // 30s `default_request_timeout_secs`) for derivations
            // like `pipelined_reply_timeout`.
            batch_timeout: Duration::from_secs(30),
            pipelining_globally_disabled: AtomicBool::new(false),
        });
        (mux, rx)
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
        let mut server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();
        let pending = Some(Bytes::from_static(b"CLIENTHELLO"));

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move { tunnel_loop(&mut server_side, "sid-under-test", &mux, pending).await }
        });

        // The first message tunnel_loop emits must be Data carrying the
        // replayed bytes — NOT whatever it would have read from the socket.
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("tunnel_loop did not send a message within 2s")
            .expect("mux channel closed unexpectedly");

        match msg {
            MuxMsg::Data {
                sid,
                data,
                seq: _,
                reply,
            } => {
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
                        seq: None,
                        caps: None,
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

        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle)
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
        let mut server_side = accept.await.unwrap();

        // 2 deployments, only A marked legacy → all_servers_legacy = false.
        let (mux, mut rx) = mux_for_test_with(2);
        mux.mark_server_no_longpoll("script-A");
        assert!(!mux.all_servers_legacy());

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move { tunnel_loop(&mut server_side, "sid-mixed", &mux, None).await }
        });

        // Reply to 6 empty polls, all from A. With the regression
        // (per-deployment skip on `last_script_id == A`), the loop would
        // stop emitting at iteration 4 — `consecutive_empty > 3` plus
        // `last_was_legacy` would short-circuit the send. With the fix,
        // the aggregate gate stays false and the loop keeps polling.
        // The 60 s timeout below is paused-time, so it only "elapses"
        // if rx.recv() truly never resolves (i.e. the loop has stalled).
        for i in 0..6u32 {
            let msg = tokio::time::timeout(Duration::from_secs(60), rx.recv())
                .await
                .unwrap_or_else(|_| panic!(
                    "loop stopped emitting at iteration {} — regression: per-deployment skip-when-idle stalled session even though long-poll-capable peer was available",
                    i
                ))
                .expect("mux channel closed unexpectedly");
            match msg {
                MuxMsg::Data {
                    sid,
                    data,
                    seq: _,
                    reply,
                } => {
                    assert_eq!(sid, "sid-mixed");
                    assert!(
                        data.is_empty(),
                        "expected empty poll, got {} bytes",
                        data.len()
                    );
                    let last = i == 5;
                    let _ = reply.send(Ok((
                        TunnelResponse {
                            sid: Some("sid-mixed".into()),
                            d: None,
                            pkts: None,
                            eof: if last { Some(true) } else { None },
                            e: None,
                            code: None,
                            seq: None,
                            caps: None,
                        },
                        "script-A".to_string(),
                    )));
                }
                _ => panic!(
                    "iteration {}: expected Data poll, got a different MuxMsg variant",
                    i
                ),
            }
        }

        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle)
            .await
            .expect("tunnel_loop did not exit after eof");
    }

    /// Capability detection: a TunnelResponse whose `caps` field
    /// includes `CAPS_PIPELINE_SEQ` must enable pipelining for the
    /// session, including when the response shape is the batched
    /// `connect_data` reply (the dominant HTTPS fast path). Without
    /// this end-to-end check, we can regress the bit by serializing
    /// the wrong response shape on the server (the case the
    /// reviewer caught: batched connect_data went through
    /// `tcp_drain_response` which sets `caps: None`).
    #[test]
    fn caps_field_drives_pipeline_decision() {
        // Server response with caps bit set → pipeline opt-in.
        let resp_pipelined = TunnelResponse {
            sid: Some("s".into()),
            d: None,
            pkts: None,
            eof: None,
            e: None,
            code: None,
            seq: None,
            caps: Some(CAPS_PIPELINE_SEQ),
        };
        let pipeline = resp_pipelined
            .caps
            .map(|c| c & CAPS_PIPELINE_SEQ != 0)
            .unwrap_or(false);
        assert!(pipeline, "caps bit set must enable pipelining");

        // Old tunnel-node, no caps field → legacy path.
        let resp_legacy = TunnelResponse {
            sid: Some("s".into()),
            d: None,
            pkts: None,
            eof: None,
            e: None,
            code: None,
            seq: None,
            caps: None,
        };
        let pipeline = resp_legacy
            .caps
            .map(|c| c & CAPS_PIPELINE_SEQ != 0)
            .unwrap_or(false);
        assert!(!pipeline, "absent caps must NOT enable pipelining");

        // Caps present but bit cleared (forward-compat for future
        // capability bits the client doesn't recognize) → legacy.
        let resp_other_cap = TunnelResponse {
            sid: Some("s".into()),
            d: None,
            pkts: None,
            eof: None,
            e: None,
            code: None,
            seq: None,
            caps: Some(0),
        };
        let pipeline = resp_other_cap
            .caps
            .map(|c| c & CAPS_PIPELINE_SEQ != 0)
            .unwrap_or(false);
        assert!(
            !pipeline,
            "caps without the pipeline bit must NOT enable pipelining"
        );
    }

    /// `tunnel_loop_pipelined`'s first emitted op for a session must
    /// carry `seq: Some(0)`. The tunnel-node side relies on seqs being
    /// per-session monotonic from 0 — if this regresses, the very
    /// first op deadlocks the server's seq lock (it's waiting for
    /// expected=0, never sees it).
    #[tokio::test]
    async fn pipelined_loop_first_op_carries_seq_zero() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let _client = TcpStream::connect(addr).await.unwrap();
        let mut server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();
        let pending = Some(Bytes::from_static(b"FIRST"));

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move { tunnel_loop_pipelined(&mut server_side, "sid-pipe", &mux, pending).await }
        });

        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("pipelined loop did not emit a message within 2s")
            .expect("mux channel closed unexpectedly");

        match msg {
            MuxMsg::Data {
                sid,
                data,
                seq,
                reply,
            } => {
                assert_eq!(sid, "sid-pipe");
                assert_eq!(&data[..], b"FIRST");
                assert_eq!(
                    seq,
                    Some(0),
                    "first pipelined op for a session must be seq=0",
                );
                let _ = reply.send(Ok((
                    TunnelResponse {
                        sid: Some("sid-pipe".into()),
                        d: None,
                        pkts: None,
                        eof: Some(true),
                        e: None,
                        code: None,
                        seq: Some(0),
                        caps: None,
                    },
                    "test-script".to_string(),
                )));
            }
            _ => panic!("expected Data, got something else"),
        }

        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
    }

    /// Reordering correctness: when reply for seq=1 arrives at the
    /// client BEFORE reply for seq=0 (different batches racing back
    /// through different deployments), `tunnel_loop_pipelined` must
    /// still write seq=0's bytes to the local socket first. Failure
    /// mode if this regresses: silent stream corruption — the client
    /// app sees later bytes before earlier ones.
    ///
    /// We force two ops in flight by stuffing both `pending_client_data`
    /// (becomes seq=0) and a second chunk in the socket kernel buffer
    /// (read becomes seq=1) before the loop starts. The loop's send
    /// phase consumes both before entering the receive phase.
    #[tokio::test]
    async fn pipelined_loop_writes_in_seq_order_when_replies_arrive_reversed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut server_side = accept.await.unwrap();

        // Pre-stuff "SECOND" so the loop's non-blocking read picks it
        // up after consuming pending="FIRST".
        client.write_all(b"SECOND").await.unwrap();
        client.flush().await.unwrap();
        // Brief wait so the bytes definitely land in the kernel buffer.
        tokio::time::sleep(Duration::from_millis(30)).await;

        let (mux, mut rx) = mux_for_test();
        let pending = Some(Bytes::from_static(b"FIRST"));

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move { tunnel_loop_pipelined(&mut server_side, "sid-pipe", &mux, pending).await }
        });

        // Receive both ops back-to-back. Loop sends them before
        // entering the receive phase: target_depth ≥ 2 (PIPELINE_DEPTH)
        // and both reads succeed in the send phase.
        let msg0 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("first op not emitted")
            .expect("mux channel closed");
        let reply_0 = match msg0 {
            MuxMsg::Data {
                sid,
                data,
                seq,
                reply,
            } => {
                assert_eq!(sid, "sid-pipe");
                assert_eq!(seq, Some(0));
                assert_eq!(&data[..], b"FIRST");
                reply
            }
            _ => panic!("expected Data 0"),
        };

        let msg1 = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("second op not emitted")
            .expect("mux channel closed");
        let reply_1 = match msg1 {
            MuxMsg::Data {
                sid,
                data,
                seq,
                reply,
            } => {
                assert_eq!(sid, "sid-pipe");
                assert_eq!(seq, Some(1));
                assert_eq!(&data[..], b"SECOND");
                reply
            }
            _ => panic!("expected Data 1"),
        };

        // Fire reply for seq=1 FIRST (out of order on the wire) with
        // downlink bytes "B".
        let _ = reply_1.send(Ok((
            TunnelResponse {
                sid: Some("sid-pipe".into()),
                d: Some(B64.encode(b"B")),
                pkts: None,
                eof: Some(true), // eof so the loop exits after seq=1
                e: None,
                code: None,
                seq: Some(1),
                caps: None,
            },
            "test-script".to_string(),
        )));

        // Brief delay to let the seq=1 reply settle in its oneshot's
        // buffer. The loop is still awaiting the seq=0 oneshot at the
        // front of the in-flight queue, so it MUST NOT have written
        // anything yet.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let mut peek = [0u8; 16];
        match tokio::time::timeout(Duration::from_millis(20), client.read(&mut peek)).await {
            Ok(Ok(_)) => panic!(
                "loop wrote downlink bytes before seq=0 reply arrived — \
                 reorder invariant broken"
            ),
            Ok(Err(_)) | Err(_) => { /* expected: nothing written yet */ }
        }

        // Now fire reply for seq=0 with "A". Loop should write "A"
        // then immediately drain seq=1 from its oneshot and write "B".
        let _ = reply_0.send(Ok((
            TunnelResponse {
                sid: Some("sid-pipe".into()),
                d: Some(B64.encode(b"A")),
                pkts: None,
                eof: None,
                e: None,
                code: None,
                seq: Some(0),
                caps: None,
            },
            "test-script".to_string(),
        )));

        let mut received = vec![0u8; 16];
        let mut total = 0;
        // Read until we have both bytes or the loop closes.
        loop {
            match tokio::time::timeout(Duration::from_secs(2), client.read(&mut received[total..]))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    total += n;
                    if total >= 2 {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        assert_eq!(
            &received[..total],
            b"AB",
            "downlink bytes must be written in seq order (got {:?})",
            &received[..total],
        );

        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
    }

    /// Critical regression: `pipelined_reply_timeout` must cover
    /// BOTH the per-deployment semaphore wait AND the request's own
    /// budget — under saturation, a fresh op waits up to one full
    /// `effective_batch_timeout` for a permit before its own
    /// `effective_batch_timeout`-bounded request even starts. With
    /// a one-batch budget the watchdog fires while the op is still
    /// queued for a permit, dropping the oneshot and closing a
    /// healthy pipelined session under load.
    ///
    /// The test pins the `2× + slack` invariant so future changes
    /// to either the formula or PIPELINED_BATCH_TIMEOUT_FLOOR
    /// require an intentional update.
    #[test]
    fn pipelined_reply_timeout_covers_two_batch_budgets_for_semaphore_saturation() {
        let (mux, _rx) = mux_for_test();
        let reply = mux.pipelined_reply_timeout();
        // Default config has 30 s configured → 60 s floor → 60×2 = 120 s.
        let effective_batch = mux.batch_timeout.max(PIPELINED_BATCH_TIMEOUT_FLOOR);
        assert!(
            reply >= effective_batch * 2,
            "default-config reply timeout ({:?}) must cover 2× the \
             effective batch budget ({:?}) so a permit-saturated \
             pipeline has time to acquire a slot AND complete the \
             request before the session watchdog fires",
            reply,
            effective_batch * 2,
        );

        // Same invariant under a user-tuned long timeout.
        let (tx, _rx) = mpsc::channel(16);
        let custom_batch = Duration::from_secs(120);
        let mux = Arc::new(TunnelMux {
            tx,
            connect_data_unsupported: Arc::new(AtomicBool::new(false)),
            legacy_deployments: Mutex::new(HashMap::new()),
            all_legacy: Arc::new(AtomicBool::new(false)),
            num_scripts: 1,
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
            unreachable_cache: Mutex::new(HashMap::new()),
            batch_timeout: custom_batch,
            pipelining_globally_disabled: AtomicBool::new(false),
        });
        let reply = mux.pipelined_reply_timeout();
        assert!(
            reply >= custom_batch * 2,
            "with request_timeout_secs={:?}, reply timeout ({:?}) \
             must cover 2× the budget for permit + request",
            custom_batch,
            reply,
        );
    }

    /// `mark_pipelining_disabled` must flip the global toggle (sticky
    /// for the process lifetime) so subsequent connects fall back to
    /// the legacy loop, even when the connect_data reply still
    /// advertises `caps`. This protects mixed-version deployments
    /// where round-robin can land a session's seq ops on an
    /// un-upgraded backend after a different deployment served the
    /// connect with caps set.
    #[test]
    fn mark_pipelining_disabled_is_sticky_and_overrides_caps() {
        let (mux, _rx) = mux_for_test();
        assert!(!mux.pipelining_disabled());

        mux.mark_pipelining_disabled();
        assert!(mux.pipelining_disabled());

        // Idempotent — re-marking doesn't toggle off.
        mux.mark_pipelining_disabled();
        assert!(mux.pipelining_disabled());

        // The actual decision in `tunnel_connection` is
        // `pipeline_advertised && !mux.pipelining_disabled()`, so
        // even a caps-advertising connect_data reply must NOT
        // re-enable pipelining once the toggle is set.
        let advertised = true;
        let pipeline = advertised && !mux.pipelining_disabled();
        assert!(
            !pipeline,
            "advertised caps must not re-enable pipelining after the \
             mixed-version toggle has fired",
        );
    }

    /// Critical regression: when the local client half-closes (TCP
    /// shutdown send → `Ok(0)` on read) AFTER queuing request bytes,
    /// the loop has ops in flight whose replies may carry downlink
    /// data the server already produced. Returning early on EOF
    /// (the previous shape) dropped the queued oneshot receivers
    /// and silently lost those bytes — breaking valid request/
    /// response patterns where the client closes its write half
    /// after sending. The fix: set `client_send_closed` and continue
    /// draining `in_flight` before returning.
    #[tokio::test]
    async fn pipelined_loop_drains_in_flight_on_client_half_close() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();
        // Pre-stuff "REQUEST" so the loop's first iteration sends it
        // as seq=0, then half-closes from the client side. The loop
        // must still wait for seq=0's reply (with downlink bytes)
        // before returning.
        client.write_all(b"REQUEST").await.unwrap();
        client.flush().await.unwrap();
        // Half-close the client's write side. Subsequent reads on
        // server_side will return Ok(0) once the buffered "REQUEST"
        // is consumed.
        client.shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move {
                tunnel_loop_pipelined(&mut server_side, "sid-halfclose", &mux, None).await
            }
        });

        // The loop emits seq=0 with the buffered "REQUEST" bytes.
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("first op not emitted")
            .expect("mux channel closed");
        let reply = match msg {
            MuxMsg::Data { sid, data, seq, reply } => {
                assert_eq!(sid, "sid-halfclose");
                assert_eq!(seq, Some(0));
                assert_eq!(&data[..], b"REQUEST");
                reply
            }
            _ => panic!("expected Data 0"),
        };

        // Brief delay so the loop's next send-phase iteration sees
        // the half-closed socket (Ok(0)) and flips
        // `client_send_closed` — but stays parked on the in_flight
        // oneshot for seq=0.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The loop MUST still be alive — it's draining the pending
        // reply, not exiting on the half-close.
        assert!(
            !loop_handle.is_finished(),
            "loop must keep running while in_flight has pending replies; \
             returning on Ok(0) would drop seq=0's oneshot and lose its \
             downlink bytes",
        );

        // Now deliver the reply with downlink bytes "RESPONSE" + eof.
        let _ = reply.send(Ok((
            TunnelResponse {
                sid: Some("sid-halfclose".into()),
                d: Some(B64.encode(b"RESPONSE")),
                pkts: None,
                eof: Some(true),
                e: None,
                code: None,
                seq: Some(0),
                caps: None,
            },
            "test-script".to_string(),
        )));

        // Loop should write "RESPONSE" to the local socket and exit.
        let mut received = vec![0u8; 32];
        let mut total = 0;
        loop {
            match tokio::time::timeout(
                Duration::from_secs(2),
                client.read(&mut received[total..]),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    total += n;
                    if total >= 8 {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }
        assert_eq!(
            &received[..total],
            b"RESPONSE",
            "downlink bytes must be delivered even after client half-close \
             (got {:?})",
            &received[..total],
        );

        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
    }

    /// A pipelined session whose server reply carries the wrong echoed
    /// seq must close, not silently write potentially-misrouted bytes
    /// to the local socket. The reply we'd otherwise honor could
    /// contain bytes from a different session position (server bug or
    /// version skew where the response shape changed) — emitting them
    /// is the silent-corruption failure mode the seq protocol exists
    /// to prevent.
    #[tokio::test]
    async fn pipelined_loop_closes_on_seq_echo_mismatch() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut server_side = accept.await.unwrap();

        let (mux, mut rx) = mux_for_test();
        let pending = Some(Bytes::from_static(b"FIRST"));

        let loop_handle = tokio::spawn({
            let mux = mux.clone();
            async move { tunnel_loop_pipelined(&mut server_side, "sid-pipe", &mux, pending).await }
        });

        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("first op not emitted")
            .expect("mux channel closed");
        let reply = match msg {
            MuxMsg::Data {
                sid: _,
                data: _,
                seq,
                reply,
            } => {
                assert_eq!(seq, Some(0));
                reply
            }
            _ => panic!("expected Data 0"),
        };

        // Reply with a WRONG seq (echoed seq=99 for our seq=0 op).
        // The loop should detect the mismatch, close the session,
        // and write nothing to the local socket.
        let _ = reply.send(Ok((
            TunnelResponse {
                sid: Some("sid-pipe".into()),
                d: Some(B64.encode(b"BOGUS")), // bytes that would be wrong to write
                pkts: None,
                eof: None,
                e: None,
                code: None,
                seq: Some(99),
                caps: None,
            },
            "test-script".to_string(),
        )));

        // Wait for the loop to terminate.
        let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle)
            .await
            .expect("loop must exit on seq mismatch");

        // Local socket must NOT have received "BOGUS".
        let mut peek = [0u8; 16];
        match tokio::time::timeout(Duration::from_millis(100), client.read(&mut peek)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => { /* expected: socket closed or empty */ }
            Ok(Ok(n)) => panic!(
                "loop wrote {} bytes despite seq mismatch — should have closed silently \
                 (got: {:?})",
                n,
                &peek[..n]
            ),
        }
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
        assert!(!should_fire(10, MAX_BATCH_PAYLOAD_BYTES - 100, 100,));
        // One byte over: fire.
        assert!(should_fire(10, MAX_BATCH_PAYLOAD_BYTES - 100, 101,));
        // Sum overflow well past the cap: fire.
        assert!(should_fire(10, MAX_BATCH_PAYLOAD_BYTES, 1,));
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
        };
        let mk_reply = || oneshot::channel::<Result<(TunnelResponse, String), String>>().0;

        let mut accum = BatchAccum::new();

        // Batch A: 3 ops at indices 0, 1, 2.
        push_no_fire(&mut accum, mk_op("a0"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("a1"), 4, mk_reply());
        push_no_fire(&mut accum, mk_op("a2"), 4, mk_reply());
        assert_eq!(accum.pending_ops.len(), 3);
        assert_eq!(
            accum
                .data_replies
                .iter()
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
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
            accum
                .data_replies
                .iter()
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
            vec![0, 1],
            "post-flush indices must restart at 0 — otherwise fire_batch's \
             batch_resp.r.get(idx) returns None and every session in the \
             second batch sees a missing-response error"
        );
        assert_eq!(accum.payload_bytes, 8);
    }

    /// `seq` plumbs from `MuxMsg::Data` → `PendingOp` → `BatchOp` so
    /// the tunnel-node sees the seq we generated. Without this
    /// propagation the server would see a None seq and fall back to
    /// the legacy unordered path — the client would still process
    /// replies in oneshot-FIFO order, but the bytes inside would be
    /// in unspecified order (server drained read_buf in batch
    /// arrival order, not seq order).
    #[test]
    fn encode_pending_propagates_seq_to_batch_op() {
        let op = PendingOp {
            op: "data",
            sid: Some("sid".into()),
            host: None,
            port: None,
            data: Some(Bytes::from_static(b"x")),
            encode_empty: false,
            seq: Some(42),
        };
        let b = encode_pending(op);
        assert_eq!(b.seq, Some(42));
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
}
