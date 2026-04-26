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
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::domain_fronter::{BatchOp, DomainFronter, TunnelResponse};

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

/// Timeout for a single batch HTTP round-trip. If the tunnel-node or Apps
/// Script takes longer than this, the batch fails and sessions get error
/// replies rather than hanging forever.
const BATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for a session waiting for its batch reply. If the batch task
/// is slow (e.g. one op in the batch has a dead target on the tunnel-node
/// side), the session gives up and retries on the next tick rather than
/// blocking indefinitely.
const REPLY_TIMEOUT: Duration = Duration::from_secs(35);

/// How long we'll briefly hold the client socket after the local
/// CONNECT/SOCKS5 handshake, waiting for the client's first bytes (the
/// TLS ClientHello for HTTPS). Bundling those bytes with the tunnel-node
/// connect saves one Apps Script round-trip per new flow.
const CLIENT_FIRST_DATA_WAIT: Duration = Duration::from_millis(50);

/// How long the muxer holds open the batch buffer after the first op
/// arrives, waiting for more ops to coalesce. Issue #231 — the previous
/// implementation drained `try_recv()` *immediately* after the first
/// message landed, so under any non-bursty workload every batch held
/// exactly one op (defeating the entire batching premise). 8 ms is small
/// vs the ~2-7 s Apps Script round-trip the batch is amortizing, but
/// long enough that concurrent HTTP/2 stream openings, parallel fetches,
/// or any other burst lands in the same batch.
const BATCH_COALESCE_WINDOW: Duration = Duration::from_millis(8);

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

enum MuxMsg {
    Connect {
        host: String,
        port: u16,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    ConnectData {
        host: String,
        port: u16,
        // Arc so the caller can hand the buffer to the mux AND keep a ref
        // for the fallback path without an extra 64 KB copy per session.
        data: Arc<Vec<u8>>,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    Data {
        sid: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    UdpOpen {
        host: String,
        port: u16,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    UdpData {
        sid: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    Close {
        sid: String,
    },
}

pub struct TunnelMux {
    tx: mpsc::Sender<MuxMsg>,
    /// Set to `true` after the first time the tunnel-node rejects
    /// `connect_data` as unsupported. Subsequent sessions skip the
    /// optimistic path entirely and go straight to plain connect + data.
    connect_data_unsupported: Arc<AtomicBool>,
    /// Set to `true` after we observe an empty poll round-trip that
    /// returned in less than `LEGACY_DETECT_THRESHOLD` with no data.
    /// On a long-poll-capable tunnel-node, an empty poll either returns
    /// quickly *with data* (push arrived) or holds open until the
    /// server's `LONGPOLL_DEADLINE`. A fast empty reply means the server
    /// is doing the legacy fixed-sleep drain — in that mode, hammering
    /// idle sessions at the new 500 ms cadence wastes Apps Script quota
    /// for no benefit, so the loop reverts to the pre-long-poll
    /// "skip empty polls when idle" behavior.
    server_no_longpoll: Arc<AtomicBool>,
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
}

impl TunnelMux {
    pub fn start(fronter: Arc<DomainFronter>) -> Arc<Self> {
        let n = fronter.num_scripts();
        tracing::info!(
            "tunnel mux: {} deployment(s), {} concurrent per deployment",
            n,
            CONCURRENCY_PER_DEPLOYMENT
        );
        let (tx, rx) = mpsc::channel(512);
        tokio::spawn(mux_loop(rx, fronter));
        Arc::new(Self {
            tx,
            connect_data_unsupported: Arc::new(AtomicBool::new(false)),
            server_no_longpoll: Arc::new(AtomicBool::new(false)),
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
            unreachable_cache: Mutex::new(HashMap::new()),
        })
    }

    async fn send(&self, msg: MuxMsg) {
        let _ = self.tx.send(msg).await;
    }

    pub async fn udp_open(
        &self,
        host: &str,
        port: u16,
        data: Vec<u8>,
    ) -> Result<TunnelResponse, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MuxMsg::UdpOpen {
            host: host.to_string(),
            port,
            data,
            reply: reply_tx,
        })
        .await;
        match reply_rx.await {
            Ok(r) => r,
            Err(_) => Err("mux channel closed".into()),
        }
    }

    pub async fn udp_data(&self, sid: &str, data: Vec<u8>) -> Result<TunnelResponse, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(MuxMsg::UdpData {
            sid: sid.to_string(),
            data,
            reply: reply_tx,
        })
        .await;
        match reply_rx.await {
            Ok(r) => r,
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

    fn server_no_longpoll(&self) -> bool {
        self.server_no_longpoll.load(Ordering::Relaxed)
    }

    fn mark_server_no_longpoll(&self) {
        if !self.server_no_longpoll.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "tunnel-node returned an empty poll faster than {:?}; assuming legacy (no long-poll) drain — falling back to skip-empty-when-idle to avoid quota waste",
                LEGACY_DETECT_THRESHOLD,
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

async fn mux_loop(mut rx: mpsc::Receiver<MuxMsg>, fronter: Arc<DomainFronter>) {
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
        // queue. Once the first op lands, we hold open BATCH_COALESCE_WINDOW
        // so concurrent ops (parallel fetches, HTTP/2 stream openings, etc.)
        // land in the same batch instead of getting a fresh round-trip each.
        match rx.recv().await {
            Some(msg) => msgs.push(msg),
            None => break,
        }
        let deadline = tokio::time::Instant::now() + BATCH_COALESCE_WINDOW;
        loop {
            // Drain anything that's already queued without waiting.
            while let Ok(msg) = rx.try_recv() {
                msgs.push(msg);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            match tokio::time::timeout(deadline - now, rx.recv()).await {
                Ok(Some(msg)) => msgs.push(msg),
                Ok(None) => return,
                Err(_) => break,
            }
        }

        // Split: plain connects go parallel, data-bearing ops get batched.
        let mut data_ops: Vec<BatchOp> = Vec::new();
        let mut data_replies: Vec<(usize, oneshot::Sender<Result<TunnelResponse, String>>)> =
            Vec::new();
        let mut close_sids: Vec<String> = Vec::new();
        let mut batch_payload_bytes: usize = 0;

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
                    let encoded = Some(B64.encode(data.as_slice()));
                    let op_bytes = encoded.as_ref().map(|s| s.len()).unwrap_or(0);

                    if !data_ops.is_empty()
                        && (data_ops.len() >= MAX_BATCH_OPS
                            || batch_payload_bytes + op_bytes > MAX_BATCH_PAYLOAD_BYTES)
                    {
                        fire_batch(
                            &sems,
                            &fronter,
                            std::mem::take(&mut data_ops),
                            std::mem::take(&mut data_replies),
                        )
                        .await;
                        batch_payload_bytes = 0;
                    }

                    let idx = data_ops.len();
                    data_ops.push(BatchOp {
                        op: "connect_data".into(),
                        sid: None,
                        host: Some(host),
                        port: Some(port),
                        d: encoded,
                    });
                    data_replies.push((idx, reply));
                    batch_payload_bytes += op_bytes;
                }
                MuxMsg::Data { sid, data, reply } => {
                    let encoded = if data.is_empty() {
                        None
                    } else {
                        Some(B64.encode(&data))
                    };
                    let op_bytes = encoded.as_ref().map(|s| s.len()).unwrap_or(0);

                    // If adding this op would exceed limits, fire current
                    // batch first and start a new one.
                    if !data_ops.is_empty()
                        && (data_ops.len() >= MAX_BATCH_OPS
                            || batch_payload_bytes + op_bytes > MAX_BATCH_PAYLOAD_BYTES)
                    {
                        fire_batch(
                            &sems,
                            &fronter,
                            std::mem::take(&mut data_ops),
                            std::mem::take(&mut data_replies),
                        )
                        .await;
                        batch_payload_bytes = 0;
                    }

                    let idx = data_ops.len();
                    data_ops.push(BatchOp {
                        op: "data".into(),
                        sid: Some(sid),
                        host: None,
                        port: None,
                        d: encoded,
                    });
                    data_replies.push((idx, reply));
                    batch_payload_bytes += op_bytes;
                }
                MuxMsg::UdpOpen {
                    host,
                    port,
                    data,
                    reply,
                } => {
                    let encoded = if data.is_empty() {
                        None
                    } else {
                        Some(B64.encode(&data))
                    };
                    let op_bytes = encoded.as_ref().map(|s| s.len()).unwrap_or(0);

                    if !data_ops.is_empty()
                        && (data_ops.len() >= MAX_BATCH_OPS
                            || batch_payload_bytes + op_bytes > MAX_BATCH_PAYLOAD_BYTES)
                    {
                        fire_batch(
                            &sems,
                            &fronter,
                            std::mem::take(&mut data_ops),
                            std::mem::take(&mut data_replies),
                        )
                        .await;
                        batch_payload_bytes = 0;
                    }

                    let idx = data_ops.len();
                    data_ops.push(BatchOp {
                        op: "udp_open".into(),
                        sid: None,
                        host: Some(host),
                        port: Some(port),
                        d: encoded,
                    });
                    data_replies.push((idx, reply));
                    batch_payload_bytes += op_bytes;
                }
                MuxMsg::UdpData { sid, data, reply } => {
                    let encoded = if data.is_empty() {
                        None
                    } else {
                        Some(B64.encode(&data))
                    };
                    let op_bytes = encoded.as_ref().map(|s| s.len()).unwrap_or(0);

                    if !data_ops.is_empty()
                        && (data_ops.len() >= MAX_BATCH_OPS
                            || batch_payload_bytes + op_bytes > MAX_BATCH_PAYLOAD_BYTES)
                    {
                        fire_batch(
                            &sems,
                            &fronter,
                            std::mem::take(&mut data_ops),
                            std::mem::take(&mut data_replies),
                        )
                        .await;
                        batch_payload_bytes = 0;
                    }

                    let idx = data_ops.len();
                    data_ops.push(BatchOp {
                        op: "udp_data".into(),
                        sid: Some(sid),
                        host: None,
                        port: None,
                        d: encoded,
                    });
                    data_replies.push((idx, reply));
                    batch_payload_bytes += op_bytes;
                }
                MuxMsg::Close { sid } => {
                    close_sids.push(sid);
                }
            }
        }

        for sid in close_sids {
            data_ops.push(BatchOp {
                op: "close".into(),
                sid: Some(sid),
                host: None,
                port: None,
                d: None,
            });
        }

        if data_ops.is_empty() {
            continue;
        }

        fire_batch(&sems, &fronter, data_ops, data_replies).await;
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
    data_ops: Vec<BatchOp>,
    data_replies: Vec<(usize, oneshot::Sender<Result<TunnelResponse, String>>)>,
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
        let n_ops = data_ops.len();

        // Bounded-wait: if the batch takes longer than BATCH_TIMEOUT,
        // all sessions in this batch get an error and can retry.
        let result = tokio::time::timeout(
            BATCH_TIMEOUT,
            f.tunnel_batch_request_to(&script_id, &data_ops),
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
                for (idx, reply) in data_replies {
                    if let Some(resp) = batch_resp.r.get(idx) {
                        let _ = reply.send(Ok(resp.clone()));
                    } else {
                        let _ = reply.send(Err("missing response in batch".into()));
                    }
                }
            }
            Ok(Err(e)) => {
                let err_msg = format!("{}", e);
                tracing::warn!("batch failed: {}", err_msg);
                for (_, reply) in data_replies {
                    let _ = reply.send(Err(err_msg.clone()));
                }
            }
            Err(_) => {
                tracing::warn!("batch timed out after {:?} ({} ops)", BATCH_TIMEOUT, n_ops);
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
        let mut buf = vec![0u8; 65536];
        let t0 = Instant::now();
        match tokio::time::timeout(CLIENT_FIRST_DATA_WAIT, sock.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => {
                mux.record_preread_win(port, t0.elapsed());
                buf.truncate(n);
                Some(Arc::new(buf))
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
                // Recover the buffered ClientHello from the Arc so the
                // first tunnel_loop iteration can replay it. The mux task
                // may still hold the other ref during the unsupported
                // reply's settle window — fall back to a clone in that
                // race (rare; the reply path drops its ref before we
                // reach here in practice).
                let bytes = Arc::try_unwrap(data).unwrap_or_else(|a| (*a).clone());
                (sid, None, Some(bytes))
            }
        },
        None => (connect_plain(host, port, mux).await?, None, None),
    };

    tracing::info!("tunnel session {} opened for {}:{}", sid, host, port);

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
    data: Arc<Vec<u8>>,
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
        Ok(Ok(resp)) => resp,
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
    mut pending_client_data: Option<Vec<u8>>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = sock.split();
    let mut buf = vec![0u8; 65536];
    let mut consecutive_empty = 0u32;

    loop {
        // Cadence depends on whether the tunnel-node is doing long-poll
        // drains. With long-poll, the server holds empty polls open up
        // to its `LONGPOLL_DEADLINE` (~5 s currently), so the client
        // can keep this read timeout short — the wait is on the wire,
        // not here. Against a *legacy* tunnel-node (no long-poll, fast
        // empty replies), the same short cadence + always-poll behavior
        // would generate continuous round-trips on idle sessions and
        // burn Apps Script quota. The `server_no_longpoll` flag detects
        // the legacy case from reply latency below and reverts to the
        // pre-long-poll cadence: long sleep on local read, skip empty
        // polls when sustained-idle.
        let legacy_mode = mux.server_no_longpoll();
        let client_data = if let Some(data) = pending_client_data.take() {
            Some(data)
        } else {
            let read_timeout = match (legacy_mode, consecutive_empty) {
                (_, 0) => Duration::from_millis(20),
                (_, 1) => Duration::from_millis(80),
                (_, 2) => Duration::from_millis(200),
                (false, _) => Duration::from_millis(500),
                (true, _) => Duration::from_secs(30),
            };

            match tokio::time::timeout(read_timeout, reader.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    consecutive_empty = 0;
                    Some(buf[..n].to_vec())
                }
                Ok(Err(_)) => break,
                Err(_) => None,
            }
        };

        // Legacy-server skip: against a non-long-polling tunnel-node,
        // an empty poll is wasted work — fast-empty reply, no push
        // delivery benefit. Preserve the pre-long-poll behavior of
        // going quiet after a few empties. Long-poll-capable servers
        // skip this branch and always send the empty op so the server
        // can hold it open.
        if legacy_mode && client_data.is_none() && consecutive_empty > 3 {
            continue;
        }

        let data = client_data.unwrap_or_default();
        let was_empty_poll = data.is_empty();

        let (reply_tx, reply_rx) = oneshot::channel();
        let send_at = Instant::now();
        mux.send(MuxMsg::Data {
            sid: sid.to_string(),
            data,
            reply: reply_tx,
        })
        .await;

        // Bounded-wait on reply: if the batch this op landed in is slow
        // (dead target on the tunnel-node side), don't block this session
        // forever — timeout and let it retry on the next tick.
        let resp = match tokio::time::timeout(REPLY_TIMEOUT, reply_rx).await {
            Ok(Ok(Ok(r))) => r,
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

        // Legacy-server detection: an empty-in/empty-out round trip
        // that finishes well under `LEGACY_DETECT_THRESHOLD` is
        // structurally impossible on a long-poll-capable tunnel-node
        // (the server holds the response either until data arrives or
        // until its long-poll deadline). One observation flips the
        // sticky flag for the rest of this process. Skip the check
        // once already in legacy mode — the comparison is cheap, but
        // calling `mark_server_no_longpoll` repeatedly muddies logs.
        if !legacy_mode && was_empty_poll {
            let reply_was_empty = resp.d.as_deref().map(str::is_empty).unwrap_or(true);
            if reply_was_empty && send_at.elapsed() < LEGACY_DETECT_THRESHOLD {
                mux.mark_server_no_longpoll();
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
    fn mux_for_test() -> (Arc<TunnelMux>, mpsc::Receiver<MuxMsg>) {
        let (tx, rx) = mpsc::channel(16);
        let mux = Arc::new(TunnelMux {
            tx,
            connect_data_unsupported: Arc::new(AtomicBool::new(false)),
            server_no_longpoll: Arc::new(AtomicBool::new(false)),
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
            unreachable_cache: Mutex::new(HashMap::new()),
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
        let pending = Some(b"CLIENTHELLO".to_vec());

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
            MuxMsg::Data { sid, data, reply } => {
                assert_eq!(sid, "sid-under-test");
                assert_eq!(&data[..], b"CLIENTHELLO");
                // Reply with eof so tunnel_loop unwinds cleanly.
                let _ = reply.send(Ok(TunnelResponse {
                    sid: Some("sid-under-test".into()),
                    d: None,
                    pkts: None,
                    eof: Some(true),
                    e: None,
                    code: None,
                }));
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

    /// `server_no_longpoll` must be sticky too: once we see a legacy
    /// fast-empty reply, every subsequent session uses the legacy idle
    /// cadence (long read timeout + skip-empty) for the rest of the
    /// process. Flipping it back per-session would either thrash the
    /// cadence or double the detection cost.
    #[test]
    fn no_longpoll_cache_is_sticky() {
        let (mux, _rx) = mux_for_test();
        assert!(!mux.server_no_longpoll());
        mux.mark_server_no_longpoll();
        assert!(mux.server_no_longpoll());
        mux.mark_server_no_longpoll(); // idempotent
        assert!(mux.server_no_longpoll());
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
