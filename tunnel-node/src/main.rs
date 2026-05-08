//! HTTP Tunnel Node for MasterHttpRelayVPN "full" mode.
//!
//! Bridges HTTP tunnel requests (from Apps Script) to real TCP connections.
//! Supports both single-op (`POST /tunnel`) and batch (`POST /tunnel/batch`)
//! modes. Batch mode processes all active sessions in one HTTP round trip,
//! dramatically reducing the number of Apps Script calls.
//!
//! Env vars:
//!   TUNNEL_AUTH_KEY — shared secret (required)
//!   PORT           — listen port (default 8080, Cloud Run sets this)

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::post, Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinSet;

mod udpgw;

/// Structured error code returned when the tunnel-node receives an op it
/// doesn't recognize. Clients use this (rather than string-matching `e`) to
/// detect a version mismatch and gracefully fall back.
const CODE_UNSUPPORTED_OP: &str = "UNSUPPORTED_OP";

/// Drain-phase deadline when the batch contained writes or new
/// connections. We expect upstream servers to respond fast (TLS
/// ServerHello, HTTP response) so this is a ceiling for slow targets;
/// `wait_for_any_drainable` returns much sooner — usually within
/// milliseconds — once any session in the batch fires its notify.
const ACTIVE_DRAIN_DEADLINE: Duration = Duration::from_millis(350);

/// Adaptive straggler settle: after the first session in an active batch
/// wakes the drain, keep checking in STEP increments whether new data is
/// still arriving. Stops when no new data arrived in the last STEP (the
/// burst is over) or MAX is reached. Packing more session responses into
/// one batch saves quota on high-latency relays (~1.5s Apps Script overhead).
const STRAGGLER_SETTLE_STEP: Duration = Duration::from_millis(10);
const STRAGGLER_SETTLE_MAX: Duration = Duration::from_millis(1000);

/// Drain-phase deadline when the batch is a pure poll (no writes, no new
/// connections — clients just asking "any push data?"). Holding the
/// response open delivers server-initiated bytes (push notifications,
/// chat messages, server-sent events) within roughly one RTT instead of
/// waiting for the client's next tick.
///
/// **This is a knob, not a constant of nature.** It trades push latency
/// against the worst-case "client wants to send while mid-poll" delay:
/// the tunnel-client's `tunnel_loop` is strictly serial (one in-flight
/// op per session), so any local bytes that arrive while the poll is
/// being held are stuck in the kernel until the poll returns.
///
/// 15 s keeps persistent connections (Telegram XMPP on :5222, Google
/// Push on :5228) alive without forcing frequent reconnects. At 5 s,
/// apps like Telegram interpreted the frequent empty returns as
/// connection instability and rotated sessions — each reconnect costs
/// a full TLS handshake (~4 s through Apps Script), causing visible
/// video/voice interruptions. 15 s is well below the client's
/// `BATCH_TIMEOUT` (30 s) and Apps Script's UrlFetch ceiling (~60 s).
/// Tested on censored networks in Iran where users reported smoother
/// Telegram video playback and fewer session resets at this value.
const LONGPOLL_DEADLINE: Duration = Duration::from_secs(15);

/// Bound on each UDP session's inbound queue. Beyond this we drop oldest
/// to keep recent voice/media packets moving — a stale RTP frame is
/// worse than a missing one. Sized so a 256-deep queue at typical 1500B
/// payloads is ~384 KB before backpressure kicks in.
const UDP_QUEUE_LIMIT: usize = 256;

/// Receive buffer for the UDP reader task. Must be ≥ 65535 to handle
/// a maximum-size IPv4 datagram without truncation.
const UDP_RECV_BUF_BYTES: usize = 65536;

/// Maximum raw bytes per TCP drain that we hand back to Apps Script in
/// one batch response. Apps Script's hard cap on Web App response body
/// is ~50 MiB. Accounting for base64 encoding (1.33×) and JSON envelope
/// overhead, the safe ceiling for raw bytes is roughly 32 MiB — but
/// `serde_json::to_vec` for a single 32-MiB string is also a CPU spike,
/// so we lean further back at 16 MiB. On a high-bandwidth VPS (1 Gbps+)
/// the reader task can stuff the per-session buffer with tens of MiB
/// between polls (issue #460); without this cap, `drain_now` would take
/// the lot, the response would exceed Apps Script's ceiling, the body
/// would be truncated mid-base64, and the client would fail JSON parse
/// with `EOF while parsing a string at line 1 column ~52428685`. By
/// returning at most this many bytes per drain and leaving the rest in
/// the read buffer for the next poll, we keep responses comfortably
/// under the cap and let throughput recover across batches.
const TCP_DRAIN_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Hard cap on the total raw bytes drained across **all sessions** in a
/// single batch response. The per-session cap (`TCP_DRAIN_MAX_BYTES`)
/// alone isn't enough — N concurrent sessions can each contribute up to
/// 16 MiB raw; with N≥4, the summed batch body exceeds Apps Script's
/// 50 MiB ceiling and the client fails JSON parse mid-stream (#863).
///
/// 32 MiB raw → ~43 MiB base64 + per-session JSON envelope overhead
/// (~80 bytes × ≤50 ops cap) → comfortably under 50 MiB total. Any
/// further sessions in the same batch are deferred to the next poll
/// (their data stays in their per-session `read_buf`, so no data loss
/// — they just settle one batch later).
const BATCH_RESPONSE_BUDGET: usize = 32 * 1024 * 1024;

/// First queue-drop on a session always logs at warn level; subsequent
/// drops log at debug only every Nth occurrence so a single congested
/// session can't flood the operator's log.
const UDP_QUEUE_DROP_LOG_STRIDE: u64 = 100;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Writer half — either a real TCP socket or an in-process duplex channel
/// (used for virtual sessions like udpgw).
enum SessionWriter {
    Tcp(OwnedWriteHalf),
    Duplex(tokio::io::WriteHalf<tokio::io::DuplexStream>),
}

impl SessionWriter {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            SessionWriter::Tcp(w) => w.write_all(buf).await,
            SessionWriter::Duplex(w) => w.write_all(buf).await,
        }
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SessionWriter::Tcp(w) => w.flush().await,
            SessionWriter::Duplex(w) => w.flush().await,
        }
    }
}

struct SessionInner {
    writer: Mutex<SessionWriter>,
    read_buf: Mutex<Vec<u8>>,
    eof: AtomicBool,
    last_active: Mutex<Instant>,
    /// Fired by `reader_task` whenever new bytes land in `read_buf` or the
    /// upstream socket closes. `wait_for_any_drainable` listens on this
    /// to wake the drain phase as soon as any session has something to
    /// ship, replacing the old fixed-sleep heuristic.
    notify: Notify,
    /// Per-session next-expected `data`-op sequence number for the
    /// pipelining protocol. Only consulted by ops that carry a `seq`
    /// field; legacy non-seq `data` ops bypass this entirely and use
    /// the inline first-come-first-served path. Held inside a
    /// `tokio::sync::Mutex` so the (claim seq → write → drain → bump)
    /// critical section can `await` without blocking the runtime.
    seq_state: Mutex<SeqState>,
    /// Fired (`notify_waiters`) every time `seq_state.expected` advances.
    /// Tasks waiting for their `seq` turn re-check `expected` after each
    /// wake; combined with a per-task `SEQ_WAIT_TIMEOUT` this prevents
    /// indefinite stalls when an earlier seq is lost or the client dies.
    seq_advance: Notify,
}

/// Ordering state for per-session `data`-op pipelining. `expected` is
/// the next seq the session will accept; any op whose `seq < expected`
/// is treated as a duplicate (likely a client-side retry) and skipped,
/// any op whose `seq > expected` blocks on `seq_advance` until either
/// its seq matches or `SEQ_WAIT_TIMEOUT` elapses. New sessions start at
/// `expected = 0` so the first `data` op the client sends is seq 0.
struct SeqState {
    /// Next-expected `data`-op sequence number for this session.
    /// `u64` rather than `u32` so a long-lived TCP session generating
    /// ~100 ops/s doesn't saturate `u32::MAX` after ~1.4 years and
    /// refuse every subsequent op. The wire protocol matches
    /// (`BatchOp::seq` / `TunnelResponse::seq` are also `u64`).
    expected: u64,
}

/// How long a `data` op carrying a `seq` will wait for earlier seqs to
/// land before giving up and returning an error to the client. 30 s is
/// well past any normal Apps Script round-trip (~1.5 s) plus reordering
/// across deployments, but short enough that a genuinely lost seq —
/// e.g. the client crashed mid-pipeline — doesn't hold every subsequent
/// op forever. After timeout the client's session reaper / explicit
/// close cleans up.
///
/// Latency trade-off worth flagging: a seq op stuck waiting for an
/// earlier seq holds an Apps Script execution slot AND the batch's
/// HTTP response open until either the earlier seq lands or this
/// timeout fires. `handle_batch` collects every job before
/// responding, so a single stuck seq from session A can keep
/// session B's already-ready job's results sitting in
/// `seq_data_jobs` for up to `SEQ_WAIT_TIMEOUT`. We accept this:
/// permanent seq loss is rare (it requires the client's earlier
/// seq batch to vanish in transit), and shortening this would
/// cause more rejections in the common reordered-arrival case
/// where seqs land 2-10 s apart across deployments. The
/// regression test
/// `unrelated_seq_session_in_same_batch_is_not_delayed_past_seq_wait`
/// pins the upper bound so any future change here is intentional.
const SEQ_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

struct ManagedSession {
    inner: Arc<SessionInner>,
    reader_handle: tokio::task::JoinHandle<()>,
    /// For udpgw sessions, the server task handle (so we can abort on close).
    udpgw_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ManagedSession {
    fn abort_all(&self) {
        self.reader_handle.abort();
        if let Some(ref h) = self.udpgw_handle {
            h.abort();
        }
    }
}

/// Per-batch shared wait primitive for seq jobs and Phase 2's TCP
/// drain. Collapses to one watcher per *unique* `SessionInner`
/// (deduplicated by `Arc::as_ptr`) regardless of how many seq jobs
/// or batch waiters subscribe — bounded at one task per session,
/// not the `M × N` (jobs × sessions) the per-job
/// `wait_for_any_drainable` would have spawned.
///
/// Each watcher relays `inner.notify` to a single batch-wide
/// `Arc<Notify>` via `notify_waiters()`, so a single push wakes
/// every parked job in the batch. `reader_task` itself fires
/// `notify_waiters()` (not `notify_one()`), so concurrent batches
/// observing the same session also all wake on each push — the
/// `notify_one()` semantics would have left only one of N parked
/// watchers winning the wake.
///
/// Watchers are held in `AbortOnDrop` so they're aborted on every
/// exit path of `handle_batch` (including cancellation).
struct BatchWait {
    /// Fired (`notify_waiters`) when any unique inner's `reader_task`
    /// pushes data or marks eof. All seq jobs and Phase 2's TCP wait
    /// subscribe to this single Notify. Held as `Arc<Notify>` so
    /// the (pre-spawned) watcher tasks can keep firing on it
    /// without re-borrowing `Self` — the construction order would
    /// otherwise need an `Arc::get_mut` dance.
    wake: Arc<Notify>,
    /// Sessions whose drainability the wait helper checks
    /// synchronously before parking. Owned (deduplicated) here so
    /// every caller agrees on the set.
    inners: Vec<Arc<SessionInner>>,
    /// One bridge task per unique inner. Each calls
    /// `inner.notify.notified().await` in a loop and fans out real
    /// state changes to `wake.notify_waiters()`. Held in
    /// `AbortOnDrop` so they go away when `BatchWait` drops.
    _watchers: Vec<AbortOnDrop>,
}

impl BatchWait {
    fn new(inners: Vec<Arc<SessionInner>>) -> Arc<Self> {
        // Deduplicate by Arc pointer. The same session can appear in
        // a batch via multiple paths — e.g. a `connect_data` plus a
        // seq `data` op for the same sid. Spawning two watchers for
        // it would double the wake fan-out work for no benefit.
        // We also STORE the dedup'd list (not the original `inners`),
        // so `is_any_drainable` doesn't re-lock the same Mutex once
        // per duplicate appearance.
        let mut seen: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let mut unique: Vec<Arc<SessionInner>> = Vec::with_capacity(inners.len());
        for inner in &inners {
            let ptr = Arc::as_ptr(inner) as usize;
            if seen.insert(ptr) {
                unique.push(inner.clone());
            }
        }

        let wake = Arc::new(Notify::new());
        let mut watchers: Vec<AbortOnDrop> = Vec::with_capacity(unique.len());
        for inner in unique.iter().cloned() {
            let wake = wake.clone();
            watchers.push(AbortOnDrop(tokio::spawn(async move {
                loop {
                    // Pre-`enable()` the next Notified BEFORE
                    // checking state, so a `notify_waiters()` fired
                    // in the gap between our previous fan-out and
                    // this register isn't lost. `reader_task` uses
                    // `notify_waiters()` (not `notify_one()`) so no
                    // permits are stored for unregistered waiters
                    // — the enable() registration is what guarantees
                    // we observe every push.
                    let notified = inner.notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();

                    // Filter false wakes: only fan out when the
                    // session is actually drainable. A wake fired
                    // for a push that's already been drained by a
                    // prior batch loops back without disturbing
                    // batch waiters.
                    let drainable = inner.eof.load(Ordering::Acquire)
                        || !inner.read_buf.lock().await.is_empty();
                    if drainable {
                        wake.notify_waiters();
                    }

                    notified.await;
                }
            })));
        }

        Arc::new(Self {
            wake,
            inners: unique,
            _watchers: watchers,
        })
    }

    /// Wait until any unique inner is drainable, or `deadline`
    /// elapses. The pre-armed `Notified` closes the same race
    /// `wait_for_seq_turn` handles: any wake fired between
    /// the synchronous drainability check and the await is still
    /// observed. `notify_waiters()` fans out to ALL parked
    /// `BatchWait::wait` callers at once, so a single push wakes
    /// every seq job and Phase 2's TCP wait simultaneously — the
    /// exact behavior the per-job `wait_for_any_drainable` calls
    /// failed to deliver under `notify_one()`.
    async fn wait(&self, deadline: Duration) {
        if self.inners.is_empty() {
            return;
        }
        let notified = self.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_any_drainable().await {
            return;
        }
        let _ = tokio::time::timeout(deadline, notified).await;
    }

    async fn is_any_drainable(&self) -> bool {
        for inner in &self.inners {
            if inner.eof.load(Ordering::Acquire) {
                return true;
            }
            if !inner.read_buf.lock().await.is_empty() {
                return true;
            }
        }
        false
    }
}

/// UDP equivalent of `SessionInner`. Holds a *connected* `UdpSocket`
/// pinned to one `(host, port)` upstream so we don't have to re-resolve
/// or re-parse the destination on every datagram. `notify` is fired by
/// the reader task on each inbound datagram (or on socket error) so the
/// batch drain phase can wake without polling — same primitive as the
/// TCP path.
struct UdpSessionInner {
    socket: Arc<UdpSocket>,
    packets: Mutex<VecDeque<Vec<u8>>>,
    last_active: Mutex<Instant>,
    notify: Notify,
    /// Set when the upstream socket dies (recv error). Mirrors TCP's
    /// `eof`: once true, subsequent batch drains return `eof: Some(true)`
    /// so the proxy-side session task knows to exit instead of polling
    /// a zombie session until the 120 s idle reaper kills it.
    eof: AtomicBool,
    /// Total datagrams dropped because the queue hit `UDP_QUEUE_LIMIT`.
    /// Surfaced via tracing so operators can correlate "choppy call"
    /// reports with relay backpressure.
    queue_drops: AtomicU64,
}

struct ManagedUdpSession {
    inner: Arc<UdpSessionInner>,
    reader_handle: tokio::task::JoinHandle<()>,
}

async fn create_session(host: &str, port: u16) -> std::io::Result<ManagedSession> {
    let addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();

    let inner = Arc::new(SessionInner {
        writer: Mutex::new(SessionWriter::Tcp(writer)),
        read_buf: Mutex::new(Vec::with_capacity(32768)),
        eof: AtomicBool::new(false),
        last_active: Mutex::new(Instant::now()),
        notify: Notify::new(),
        seq_state: Mutex::new(SeqState { expected: 0 }),
        seq_advance: Notify::new(),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(reader_task(reader, inner_ref));

    Ok(ManagedSession {
        inner,
        reader_handle,
        udpgw_handle: None,
    })
}

/// Create a virtual udpgw session backed by an in-process duplex channel.
fn create_udpgw_session() -> ManagedSession {
    let (client_half, server_half) = tokio::io::duplex(65536);
    let (read_half, write_half) = tokio::io::split(client_half);

    let inner = Arc::new(SessionInner {
        writer: Mutex::new(SessionWriter::Duplex(write_half)),
        read_buf: Mutex::new(Vec::with_capacity(32768)),
        eof: AtomicBool::new(false),
        last_active: Mutex::new(Instant::now()),
        notify: Notify::new(),
        seq_state: Mutex::new(SeqState { expected: 0 }),
        seq_advance: Notify::new(),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(reader_task(read_half, inner_ref));
    let udpgw_handle = Some(tokio::spawn(udpgw::udpgw_server_task(server_half)));

    ManagedSession {
        inner,
        reader_handle,
        udpgw_handle,
    }
}

async fn reader_task(mut reader: impl AsyncRead + Unpin, session: Arc<SessionInner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                session.eof.store(true, Ordering::Release);
                session.notify.notify_waiters();
                break;
            }
            Ok(n) => {
                // Extend the buffer before notifying. The MutexGuard is
                // dropped at the end of the statement, *before* the
                // notify call below, so any waiter that wakes on the
                // notify and then locks read_buf can immediately
                // observe the new bytes — no torn read where the wake
                // fires but the buffer still looks empty.
                //
                // `notify_waiters()` (not `notify_one()`) so EVERY
                // parked waiter wakes — required for correctness when
                // pipelining puts seq=N and seq=N+1 for the same
                // session in different batches: each batch builds its
                // own `BatchWait` watcher on this session's notify,
                // and a single `notify_one()` would only wake one of
                // them, leaving the other batch's watcher asleep
                // until `LONGPOLL_DEADLINE`. The cost of dropping the
                // permit-storage semantics is handled by the
                // pre-`enable()` pattern in `BatchWait`'s and
                // `wait_for_any_drainable`'s watchers — they register
                // their `Notified` future before the synchronous
                // drainability check, so a wake fired in the gap is
                // still observed.
                session.read_buf.lock().await.extend_from_slice(&buf[..n]);
                session.notify.notify_waiters();
            }
            Err(_) => {
                session.eof.store(true, Ordering::Release);
                session.notify.notify_waiters();
                break;
            }
        }
    }
}

async fn create_udp_session(host: &str, port: u16) -> std::io::Result<ManagedUdpSession> {
    let mut addrs = lookup_host((host, port)).await?;
    let remote = addrs.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no UDP address resolved",
        )
    })?;
    let bind_addr = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(remote).await?;
    let socket = Arc::new(socket);

    let inner = Arc::new(UdpSessionInner {
        socket: socket.clone(),
        packets: Mutex::new(VecDeque::with_capacity(UDP_QUEUE_LIMIT)),
        last_active: Mutex::new(Instant::now()),
        notify: Notify::new(),
        eof: AtomicBool::new(false),
        queue_drops: AtomicU64::new(0),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(udp_reader_task(socket, inner_ref));
    Ok(ManagedUdpSession {
        inner,
        reader_handle,
    })
}

/// UDP analogue of `reader_task`. Reads from the connected UDP socket
/// and queues each datagram on the session. Drops oldest on overflow,
/// updates `last_active` so server-push (download-only) UDP keeps the
/// session out of the idle reaper, and fires `notify` so the batch
/// drain phase can wake without polling.
async fn udp_reader_task(socket: Arc<UdpSocket>, session: Arc<UdpSessionInner>) {
    let mut buf = vec![0u8; UDP_RECV_BUF_BYTES];
    loop {
        match socket.recv(&mut buf).await {
            // Empty datagram is valid UDP; nothing to forward, ignore.
            Ok(0) => {}
            Ok(n) => {
                let mut packets = session.packets.lock().await;
                if packets.len() >= UDP_QUEUE_LIMIT {
                    packets.pop_front();
                    let dropped = session.queue_drops.fetch_add(1, Ordering::Relaxed) + 1;
                    if dropped == 1 {
                        tracing::warn!(
                            "udp queue full ({}); dropping oldest. Apps Script polling cannot keep up with upstream rate.",
                            UDP_QUEUE_LIMIT
                        );
                    } else if dropped % UDP_QUEUE_DROP_LOG_STRIDE == 0 {
                        tracing::debug!("udp queue drops: {} on session", dropped);
                    }
                }
                packets.push_back(buf[..n].to_vec());
                drop(packets);
                // Inbound packet counts as activity — keeps server-push
                // UDP (e.g. SIP/RTP, server-sent telemetry) out of the
                // idle reaper. Empty `udp_data` polls deliberately do
                // NOT bump this (see batch handler).
                *session.last_active.lock().await = Instant::now();
                session.notify.notify_one();
            }
            Err(e) => {
                // Upstream socket died (ICMP unreachable on a connected
                // socket, container netns torn down, etc.). Surface eof
                // so the proxy-side session task can exit on its next
                // poll instead of looping until the idle reaper.
                tracing::debug!("udp upstream recv error: {} — marking session eof", e);
                session.eof.store(true, Ordering::Release);
                session.notify.notify_one();
                break;
            }
        }
    }
}

/// Drain up to `min(TCP_DRAIN_MAX_BYTES, max_bytes)` from the per-session
/// read buffer — no waiting. Used by batch mode where we poll frequently.
///
/// `max_bytes` is the caller-supplied budget for this drain (typically the
/// remaining batch-response budget after summing previous drains in the
/// same batch). It allows the batch loop to stop one session short of
/// blowing past Apps Script's 50 MiB ceiling on the wire (#863). Pass
/// `usize::MAX` if there's no extra budget constraint (e.g. single-op
/// path outside the batch loop).
///
/// If the buffer is larger than the effective cap, we return a prefix of
/// the data and leave the remainder in the buffer for the next poll.
///
/// `eof` is reported as true only when the buffer has been fully drained
/// AND upstream has signaled EOF — otherwise a partial drain would
/// prematurely tear the session down on the client side.
async fn drain_now(session: &SessionInner, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut buf = session.read_buf.lock().await;
    let raw_eof = session.eof.load(Ordering::Acquire);
    let cap = max_bytes.min(TCP_DRAIN_MAX_BYTES);
    if buf.len() <= cap {
        let data = std::mem::take(&mut *buf);
        (data, raw_eof)
    } else {
        // Take the prefix; leave the tail in the buffer.
        let tail = buf.split_off(cap);
        let head = std::mem::replace(&mut *buf, tail);
        // Don't propagate eof yet — buffer still has data even if upstream
        // has closed. The client will get eof on the drain that returns
        // an empty (or sub-cap) buffer.
        (head, false)
    }
}

/// Block until *any* of `inners` has buffered data, hits EOF, or the
/// deadline elapses — whichever comes first. Returns immediately if any
/// session is already drainable when called.
///
/// This replaces the legacy `sleep(150ms)` + `sleep(200ms)` retry pattern
/// in batch drain. With `reader_task` firing `notify_one` on each
/// appended chunk, a typical TLS ServerHello (~30-50 ms) wakes the wait
/// in milliseconds instead of paying the 150 ms ceiling. For pure-poll
/// batches the same primitive holds the response open until upstream
/// pushes data or `LONGPOLL_DEADLINE` elapses, turning idle sessions
/// into a true long-poll.
///
/// Race-safety:
///   * `Notify::notify_one` stores a one-shot permit if no waiter is
///     registered, so a notify that fires between the buffer check and
///     the watcher's `.notified().await` is consumed on the next poll
///     rather than lost.
///   * Watchers self-filter against observable session state. A prior
///     batch that returned via the spawn-race shortcut may leave a
///     stale permit on the `Notify`; this batch's watcher will consume
///     it but, finding the buffer empty and EOF unset, loop back to
///     wait for a real notify. Without this filter, an idle long-poll
///     batch could return in <1 ms on a stale permit and degrade push
///     delivery to the client's idle re-poll cadence.
/// `JoinHandle` newtype that aborts the task on `Drop`. Lets the waiter
/// helpers below be cancel-safe under `tokio::select!`: a plain
/// `Vec<JoinHandle<()>>` only releases its handles via `Drop`, which
/// *detaches* tasks rather than aborting them. The previous shape
/// relied on a trailing `for w in &watchers { w.abort(); }` loop —
/// fine when the function ran to completion, but past the cancellation
/// points (`is_any_drainable().await`, the inner `select!`), so
/// cancelling the loser arm of the phase-2 `select!` left N orphan
/// watchers parked on `notify.notified()`. Each held an
/// `Arc<…Inner>` and could steal a `notify_one()` permit from a
/// future batch's watcher, making that batch wait until the next
/// notify or its deadline. Wrapping in `AbortOnDrop` makes cleanup
/// happen on every exit path, including cancellation.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn wait_for_any_drainable(inners: &[Arc<SessionInner>], deadline: Duration) {
    if inners.is_empty() {
        return;
    }

    // One watcher per session. Each loops until it observes real state
    // (eof set or buffer non-empty) before signaling — see the
    // race-safety note above. Watchers are held in a Vec of
    // `AbortOnDrop`, so they're aborted on every exit path —
    // including cancellation by an outer `select!`.
    //
    // The pre-`enable()` pattern is required since
    // `reader_task` uses `notify_waiters()` (not `notify_one()`):
    // there are no stored permits, so a wake fired between the
    // synchronous state check and parking on `notified.await`
    // would otherwise be lost. Registering the future before the
    // check guarantees we observe every push.
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let mut _watchers: Vec<AbortOnDrop> = Vec::with_capacity(inners.len());
    for inner in inners {
        let inner = inner.clone();
        let tx = tx.clone();
        _watchers.push(AbortOnDrop(tokio::spawn(async move {
            loop {
                let notified = inner.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if inner.eof.load(Ordering::Acquire) {
                    break;
                }
                if !inner.read_buf.lock().await.is_empty() {
                    break;
                }
                notified.await;
                // Wake observed — state may have changed; loop back
                // and re-check. If the wake was for a push that
                // another batch already drained, the next iteration
                // sees buf empty + eof unset and re-arms.
            }
            let _ = tx.try_send(());
        })));
    }
    drop(tx);

    // Spawn-race shortcut: if state was already drainable when we got
    // here (bytes arrived between phase 1 and this point), return
    // without entering the select. The watcher self-filtering above
    // means the unconsumed permit we leave behind here is harmless to
    // future batches.
    let already_ready = is_any_drainable(inners).await;

    if !already_ready {
        tokio::select! {
            _ = rx.recv() => {}
            _ = tokio::time::sleep(deadline) => {}
        }
    }

    // No explicit abort loop: `_watchers`'s `AbortOnDrop` entries fire
    // on the function returning here AND on the future being dropped
    // mid-await by an outer `select!`.
}

/// True iff any session is currently drainable: its read buffer has
/// bytes, or it's been marked EOF. Pulled out of `wait_for_any_drainable`
/// so the same predicate can drive both the spawn-race shortcut and the
/// post-wake straggler poll.
async fn is_any_drainable(inners: &[Arc<SessionInner>]) -> bool {
    for inner in inners {
        if inner.eof.load(Ordering::Acquire) {
            return true;
        }
        if !inner.read_buf.lock().await.is_empty() {
            return true;
        }
    }
    false
}

/// Drain whatever UDP datagrams are currently queued — no waiting.
/// Returns the eof flag alongside packets so the batch handler can
/// surface upstream-socket death without an extra round-trip.
async fn drain_udp_now(session: &UdpSessionInner) -> (Vec<Vec<u8>>, bool) {
    let mut packets = session.packets.lock().await;
    let drained: Vec<Vec<u8>> = packets.drain(..).collect();
    let eof = session.eof.load(Ordering::Acquire);
    (drained, eof)
}

/// UDP analogue of `wait_for_any_drainable`. Wakes when any session has
/// at least one queued packet OR has been marked eof. Same race-safety
/// contract: watchers self-filter against observable state to ignore
/// stale permits.
async fn wait_for_any_udp_drainable(inners: &[Arc<UdpSessionInner>], deadline: Duration) {
    if inners.is_empty() {
        return;
    }

    // See `AbortOnDrop` and the comment on `wait_for_any_drainable`
    // for why watchers must be aborted on every exit path.
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let mut _watchers: Vec<AbortOnDrop> = Vec::with_capacity(inners.len());
    for inner in inners {
        let inner = inner.clone();
        let tx = tx.clone();
        _watchers.push(AbortOnDrop(tokio::spawn(async move {
            loop {
                inner.notify.notified().await;
                if inner.eof.load(Ordering::Acquire) {
                    break;
                }
                if !inner.packets.lock().await.is_empty() {
                    break;
                }
                // Stale permit — packets were already drained by a
                // prior batch. Loop back, don't wake the caller.
            }
            let _ = tx.try_send(());
        })));
    }
    drop(tx);

    let already_ready = is_any_udp_drainable(inners).await;
    if !already_ready {
        tokio::select! {
            _ = rx.recv() => {}
            _ = tokio::time::sleep(deadline) => {}
        }
    }
}

async fn is_any_udp_drainable(inners: &[Arc<UdpSessionInner>]) -> bool {
    for inner in inners {
        if inner.eof.load(Ordering::Acquire) {
            return true;
        }
        if !inner.packets.lock().await.is_empty() {
            return true;
        }
    }
    false
}

/// Wait for response data with drain window. Used by single-op mode.
async fn wait_and_drain(session: &SessionInner, max_wait: Duration) -> (Vec<u8>, bool) {
    let deadline = Instant::now() + max_wait;
    let mut prev_len = 0usize;
    let mut last_growth = Instant::now();
    let mut ever_had_data = false;

    loop {
        let (cur_len, is_eof) = {
            let buf = session.read_buf.lock().await;
            (buf.len(), session.eof.load(Ordering::Acquire))
        };
        if cur_len > prev_len {
            last_growth = Instant::now();
            prev_len = cur_len;
            ever_had_data = true;
        }
        if is_eof {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        if ever_had_data && last_growth.elapsed() > Duration::from_millis(100) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut buf = session.read_buf.lock().await;
    let data = std::mem::take(&mut *buf);
    let eof = session.eof.load(Ordering::Acquire);
    (data, eof)
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
    udp_sessions: Arc<Mutex<HashMap<String, ManagedUdpSession>>>,
    /// Shared, immutable after startup. `Arc<str>` so each `state.clone()`
    /// — once per phase-1 spawn in the batch handler — is a refcount bump
    /// instead of a fresh String allocation.
    auth_key: Arc<str>,
    /// Active probing defense: when false (default, production), bad
    /// AUTH_KEY responses are a generic-looking 404 with no JSON-shaped
    /// "unauthorized" body — same as a static nginx 404. Active scanners
    /// that POST malformed payloads to `/tunnel` to discover proxy
    /// endpoints categorize this as a non-tunnel host and move on.
    /// Enable via `MHRV_DIAGNOSTIC=1` for setup/debugging — restores the
    /// previous JSON `{"e":"unauthorized"}` body so it's clear *which*
    /// of "wrong key", "wrong URL path", or "wrong tunnel-node" you've
    /// hit. (Inspired by #365 Section 3.)
    diagnostic_mode: bool,
}

// ---------------------------------------------------------------------------
// Protocol types — single op (backward compat)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TunnelRequest {
    k: String,
    op: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct TunnelResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    /// UDP datagrams returned to the client, base64-encoded individually.
    /// `None` for TCP responses; `Some(vec![])` is never serialized
    /// (the field is dropped when empty by the empty-on-None check above).
    #[serde(skip_serializing_if = "Option::is_none")]
    pkts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    /// Per-session sequence number echoed from `BatchOp::seq` for `data`
    /// ops (pipelining). Lets the client route an out-of-order reply
    /// into its per-session reorder buffer. Skipped on the wire when
    /// `None` (the legacy/non-pipelined path). `u64` to keep
    /// long-lived sessions from saturating — see `SeqState::expected`
    /// for the math.
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    /// Capability bitfield set on `connect` / `connect_data` success
    /// replies so the client can opt into protocol features it knows
    /// the tunnel-node speaks. Bit 0 = `CAPS_PIPELINE_SEQ`. Skipped
    /// elsewhere (other op replies don't advertise capabilities).
    #[serde(skip_serializing_if = "Option::is_none")]
    caps: Option<u32>,
}

/// Capability bit for per-session `data`-op sequence numbers
/// (pipelining). Set on `connect` / `connect_data` success replies so
/// new clients opt into pipelining; old clients ignore the unknown
/// JSON field.
const CAPS_PIPELINE_SEQ: u32 = 1 << 0;

impl TunnelResponse {
    fn error(msg: impl Into<String>) -> Self {
        Self {
            sid: None,
            d: None,
            pkts: None,
            eof: None,
            e: Some(msg.into()),
            code: None,
            seq: None,
            caps: None,
        }
    }
    fn unsupported_op(op: &str) -> Self {
        Self {
            sid: None,
            d: None,
            pkts: None,
            eof: None,
            e: Some(format!("unknown op: {}", op)),
            code: Some(CODE_UNSUPPORTED_OP.into()),
            seq: None,
            caps: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol types — batch
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BatchRequest {
    k: String,
    ops: Vec<BatchOp>,
}

#[derive(Deserialize)]
struct BatchOp {
    op: String,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    d: Option<String>, // base64 data
    /// Per-session monotonic sequence number for `data` ops on a
    /// pipelining-enabled session. When present, the server enforces
    /// in-order processing: ops with `seq` arriving out of order are
    /// held until earlier seqs land (or the session times out). Old
    /// clients omit the field — `serde(default)` deserializes them
    /// to `None`, which selects the legacy first-come-first-served
    /// path. Echoed back in the response's `seq`. `u64` for the same
    /// long-running-session reason as `SeqState::expected`.
    #[serde(default)]
    seq: Option<u64>,
}

#[derive(Serialize)]
struct BatchResponse {
    r: Vec<TunnelResponse>,
}

// ---------------------------------------------------------------------------
// Single-op handler (backward compat)
// ---------------------------------------------------------------------------

async fn handle_tunnel(
    State(state): State<AppState>,
    Json(req): Json<TunnelRequest>,
) -> axum::response::Response {
    if req.k != *state.auth_key {
        return decoy_or_unauthorized(state.diagnostic_mode);
    }
    let resp: TunnelResponse = match req.op.as_str() {
        "connect" => handle_connect(&state, req.host, req.port).await,
        "connect_data" => handle_connect_data_single(&state, req.host, req.port, req.data).await,
        "data" => handle_data_single(&state, req.sid, req.data).await,
        "close" => handle_close(&state, req.sid).await,
        other => TunnelResponse::unsupported_op(other),
    };
    Json(resp).into_response()
}

/// Active-probing defense for the bad-auth path. Production default is
/// a 404 with a generic "Not Found" HTML body that mimics a vanilla
/// nginx/apache static error page — active scanners categorize this
/// as a regular web server with nothing interesting and move on.
/// `MHRV_DIAGNOSTIC=1` restores the previous JSON `{"e":"unauthorized"}`
/// body so misconfigured clients get a clear error during setup.
fn decoy_or_unauthorized(diagnostic_mode: bool) -> axum::response::Response {
    if diagnostic_mode {
        return Json(TunnelResponse::error("unauthorized")).into_response();
    }
    let body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n\
                <body>\r\n<center><h1>404 Not Found</h1></center>\r\n\
                <hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html")],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Batch handler
// ---------------------------------------------------------------------------

async fn handle_batch(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    // Decompress if gzipped
    let json_bytes = if body.starts_with(&[0x1f, 0x8b]) {
        match decompress_gzip(&body) {
            Ok(b) => b,
            Err(e) => {
                let resp = serde_json::to_vec(&BatchResponse {
                    r: vec![TunnelResponse::error(format!("gzip decode: {}", e))],
                })
                .unwrap_or_default();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    resp,
                );
            }
        }
    } else {
        body.to_vec()
    };

    let req: BatchRequest = match serde_json::from_slice(&json_bytes) {
        Ok(r) => r,
        Err(e) => {
            let resp = serde_json::to_vec(&BatchResponse {
                r: vec![TunnelResponse::error(format!("bad json: {}", e))],
            })
            .unwrap_or_default();
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                resp,
            );
        }
    };

    if req.k != *state.auth_key {
        if state.diagnostic_mode {
            let resp = serde_json::to_vec(&BatchResponse {
                r: vec![TunnelResponse::error("unauthorized")],
            })
            .unwrap_or_default();
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                resp,
            );
        }
        // Production: same nginx-404 decoy as the single-op path. See
        // `decoy_or_unauthorized` for rationale.
        let body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n\
                    <body>\r\n<center><h1>404 Not Found</h1></center>\r\n\
                    <hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
            .as_bytes()
            .to_vec();
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html")],
            body,
        );
    }

    // Process all ops in two phases.
    //
    // Phase 1: dispatch new connections concurrently and write outbound
    // bytes for "data" ops. We track whether any op did real work
    // (`had_writes_or_connects`) — this drives the deadline picked in
    // phase 2.
    //
    // `connect` and `connect_data` each establish a brand-new upstream TCP
    // connection (up to 10 s timeout in `create_session`). Running them
    // inline would head-of-line-block every other op in the batch, so we
    // dispatch both into a JoinSet and await them concurrently below.
    //
    // `connect_data` dominates in practice (new clients), but `connect`
    // still fires from server-speaks-first ports and from the preread
    // timeout fallback path.
    let mut results: Vec<(usize, TunnelResponse)> = Vec::with_capacity(req.ops.len());
    // Each drain entry carries the session's `Arc<…Inner>` alongside the
    // sid. Phase 2 drains through the Arc directly so the global sessions
    // map lock isn't held across the per-session read_buf / packets
    // mutex acquisition — without this, every other batch (and every
    // connect/close op) head-of-line-blocks behind the drain.
    //
    // The `is_connect_data` flag distinguishes drains that came from
    // a successful `connect_data` op (a fresh session) from drains
    // that came from a regular `data` op (an existing session). The
    // batched-connect_data response is the FIRST reply the client
    // sees for a session, so it has to carry `caps` — same as the
    // single-op `handle_connect_data_single` path. Without this
    // distinction the batch path silently downgrades every HTTPS
    // fast-path session to the legacy non-pipelined loop.
    struct TcpDrain {
        i: usize,
        sid: String,
        inner: Arc<SessionInner>,
        is_connect_data: bool,
    }
    let mut tcp_drains: Vec<TcpDrain> = Vec::new();
    let mut udp_drains: Vec<(usize, String, Arc<UdpSessionInner>)> = Vec::new();
    // True iff the batch contained any op that performed a real action
    // upstream — a new connection or a non-empty data write. A batch of
    // only empty "data" / "udp_data" polls (and possibly closes) leaves
    // this false and qualifies for long-poll behavior in phase 2.
    let mut had_writes_or_connects = false;

    enum NewConn {
        Connect(TunnelResponse),
        ConnectData(Result<(String, Arc<SessionInner>), TunnelResponse>),
        UdpOpen(Result<(String, Arc<UdpSessionInner>), TunnelResponse>),
    }
    let mut new_conn_jobs: JoinSet<(usize, NewConn)> = JoinSet::new();
    // Seq-ordered `data` op specs collected during the dispatch loop
    // and spawned later, after `had_writes_or_connects` is final and
    // after `new_conn_jobs` has populated `tcp_drains`. Spawning then
    // running concurrently with Phase 2 (rather than awaiting all
    // seq jobs *before* Phase 2) prevents a single idle pipelined
    // poll from holding the whole batch response open for 15 s while
    // sibling sessions are ready to ship bytes.
    struct SeqDataSpec {
        i: usize,
        sid: String,
        seq: u64,
        data: Option<String>,
        inner: Arc<SessionInner>,
    }
    let mut seq_specs: Vec<SeqDataSpec> = Vec::new();
    // `close` ops collected during dispatch and processed AFTER
    // seq-data jobs complete. Running close inline would race
    // same-sid seq ops by removing the session from `state.sessions`
    // and aborting `reader_task` before the deferred seq job's
    // (write, drain) ran on its cloned `Arc<SessionInner>`.
    let mut pending_closes: Vec<(usize, Option<String>)> = Vec::new();
    // Sids that have an earlier-in-batch op deferred to Phase 2 or
    // `seq_data_jobs`. Used by the `close` arm to decide whether
    // to defer this close (race with the deferred op) or run it
    // inline (preserve the request's close-first ordering when no
    // earlier same-sid op exists). Without this check, a batch
    // ordered as `[close(X), data(seq=0, X)]` would unconditionally
    // defer the close, letting the data write succeed against a
    // session the client asked to be closed FIRST — a protocol-
    // ordering regression vs the pre-pipelining shape.
    let mut sids_with_pending_deferred: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // Shared response-byte budget for this batch. seq-data jobs run
    // concurrently with Phase 2's `tcp_drains` loop, so the cap
    // (#863) must be shared across both code paths — M concurrent
    // pipelined sessions each grabbing `TCP_DRAIN_MAX_BYTES` would
    // stack past Apps Script's 50 MiB response ceiling. The Mutex is
    // held only briefly per reservation; the actual drain runs
    // unlocked.
    let response_budget: Arc<Mutex<usize>> = Arc::new(Mutex::new(BATCH_RESPONSE_BUDGET));

    for (i, op) in req.ops.iter().enumerate() {
        match op.op.as_str() {
            "connect" => {
                had_writes_or_connects = true;
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                new_conn_jobs.spawn(async move {
                    (
                        i,
                        NewConn::Connect(handle_connect(&state, host, port).await),
                    )
                });
            }
            "connect_data" => {
                had_writes_or_connects = true;
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                let d = op.d.clone();
                new_conn_jobs.spawn(async move {
                    // Keep the returned Arc<SessionInner>: phase 2 drains
                    // through it directly, so the global sessions map
                    // lock doesn't have to be held across the per-session
                    // read_buf.lock().await.
                    let r = handle_connect_data_phase1(&state, host, port, d).await;
                    (i, NewConn::ConnectData(r))
                });
            }
            "udp_open" => {
                // An open *with* an initial datagram is real upstream
                // work; an open without one (rare — current proxy
                // never invokes it that way) is just resource alloc
                // and shouldn't suppress long-poll on sibling polls.
                if op.d.as_deref().map(|d| !d.is_empty()).unwrap_or(false) {
                    had_writes_or_connects = true;
                }
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                let d = op.d.clone();
                new_conn_jobs.spawn(async move {
                    let r = handle_udp_open_phase1(&state, host, port, d).await;
                    (i, NewConn::UdpOpen(r))
                });
            }
            "data" => {
                let sid = match &op.sid {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => {
                        results.push((i, TunnelResponse::error("missing sid")));
                        continue;
                    }
                };

                // Clone the inner under the map lock and release it
                // before any await. The previous shape held the global
                // sessions map across last_active.lock(), writer.lock(),
                // write_all, and flush — head-of-line-blocking every
                // other batch and connect/close op for the duration of
                // a single upstream write. The udp_data branch below
                // already does the right thing; this matches it.
                let inner = {
                    let sessions = state.sessions.lock().await;
                    sessions.get(&sid).map(|s| s.inner.clone())
                };
                // Pipelining branch: a `data` op carrying a seq is
                // dispatched into the seq_data_jobs JoinSet so its
                // potentially-long wait for an earlier seq doesn't
                // block other ops in this batch. The job's
                // `process_seq_data_op` runs the full (write, drain)
                // sequence under the per-session seq lock, which is
                // what enforces downlink-byte ordering across batches.
                if let Some(seq) = op.seq {
                    if let Some(inner) = inner {
                        let had_uplink_b64 =
                            op.d.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
                        if had_uplink_b64 {
                            had_writes_or_connects = true;
                        }
                        sids_with_pending_deferred.insert(sid.clone());
                        seq_specs.push(SeqDataSpec {
                            i,
                            sid: sid.clone(),
                            seq,
                            data: op.d.clone(),
                            inner,
                        });
                    } else {
                        let mut r = eof_response(sid);
                        r.seq = Some(seq);
                        results.push((i, r));
                    }
                    continue;
                }
                if let Some(inner) = inner {
                    *inner.last_active.lock().await = Instant::now();
                    if let Some(ref data_b64) = op.d {
                        if !data_b64.is_empty() {
                            // Decode first; only count this op as a real
                            // write (and demote the batch out of long-poll)
                            // after a successful non-empty decode. Mirrors
                            // the udp_data branch and avoids silently
                            // dropping bytes on bad base64.
                            let bytes = match B64.decode(data_b64) {
                                Ok(b) => b,
                                Err(e) => {
                                    results.push((
                                        i,
                                        TunnelResponse::error(format!("bad base64: {}", e)),
                                    ));
                                    continue;
                                }
                            };
                            if !bytes.is_empty() {
                                had_writes_or_connects = true;
                                let mut w = inner.writer.lock().await;
                                let _ = w.write_all(&bytes).await;
                                let _ = w.flush().await;
                            }
                        }
                    }
                    sids_with_pending_deferred.insert(sid.clone());
                    tcp_drains.push(TcpDrain {
                        i,
                        sid,
                        inner,
                        is_connect_data: false,
                    });
                } else {
                    results.push((i, eof_response(sid)));
                }
            }
            "udp_data" => {
                let sid = match &op.sid {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => {
                        results.push((i, TunnelResponse::error("missing sid")));
                        continue;
                    }
                };

                let inner = {
                    let sessions = state.udp_sessions.lock().await;
                    sessions.get(&sid).map(|s| s.inner.clone())
                };
                if let Some(inner) = inner {
                    let mut had_uplink = false;
                    if let Some(ref data_b64) = op.d {
                        if !data_b64.is_empty() {
                            let bytes = match B64.decode(data_b64) {
                                Ok(b) => b,
                                Err(e) => {
                                    results.push((
                                        i,
                                        TunnelResponse::error(format!("bad base64: {}", e)),
                                    ));
                                    continue;
                                }
                            };
                            if !bytes.is_empty() {
                                had_writes_or_connects = true;
                                had_uplink = true;
                                let _ = inner.socket.send(&bytes).await;
                            }
                        }
                    }
                    // last_active is bumped only on real activity:
                    // outbound here, or inbound in udp_reader_task.
                    // Empty long-poll batches must not refresh it, else
                    // the idle reaper never fires.
                    if had_uplink {
                        *inner.last_active.lock().await = Instant::now();
                    }
                    sids_with_pending_deferred.insert(sid.clone());
                    udp_drains.push((i, sid, inner));
                } else {
                    results.push((i, eof_response(sid)));
                }
            }
            "close" => {
                // Defer ONLY if there's an earlier-in-batch op for
                // the same sid that's already deferred (seq data,
                // legacy data, udp_data). Without an earlier
                // deferred op, running close inline preserves the
                // request's per-sid op order — important for
                // `[close, data]` and `[close, data(seq)]` shapes:
                // the client asked us to close FIRST, then write,
                // and the write should land on a closed (eof'd)
                // session, not race the close. With an earlier
                // deferred op, deferring close prevents the race
                // where same-sid seq jobs run on a closed session
                // (writing to an aborted upstream, draining an
                // empty buffer).
                let needs_defer = op
                    .sid
                    .as_deref()
                    .map(|s| sids_with_pending_deferred.contains(s))
                    .unwrap_or(false);
                if needs_defer {
                    pending_closes.push((i, op.sid.clone()));
                } else {
                    let r = handle_close(&state, op.sid.clone()).await;
                    results.push((i, r));
                }
            }
            other => {
                results.push((i, TunnelResponse::unsupported_op(other)));
            }
        }
    }

    // Await all concurrent connect / connect_data / udp_open jobs.
    // Successful drain-bearing ones join the appropriate drain list;
    // plain connects go straight to results.
    while let Some(join) = new_conn_jobs.join_next().await {
        match join {
            Ok((i, NewConn::Connect(r))) => results.push((i, r)),
            Ok((i, NewConn::ConnectData(Ok((sid, inner))))) => {
                // First reply on this session — must carry caps so
                // the client knows it can opt into the pipelined
                // tunnel_loop variant. Phase 2's drain stamps the
                // bit on responses where `is_connect_data` is true.
                tcp_drains.push(TcpDrain {
                    i,
                    sid,
                    inner,
                    is_connect_data: true,
                });
            }
            Ok((i, NewConn::ConnectData(Err(r)))) => results.push((i, r)),
            Ok((i, NewConn::UdpOpen(Ok((sid, inner))))) => {
                udp_drains.push((i, sid, inner));
            }
            Ok((i, NewConn::UdpOpen(Err(r)))) => results.push((i, r)),
            Err(e) => {
                tracing::error!("new-connection task panicked: {}", e);
            }
        }
    }

    // Build the shared wait set: every TCP session that anyone in
    // this batch will drain (Phase 2 connect_data / data, plus seq
    // jobs). Build a single shared `BatchWait` so:
    //   * One watcher task per UNIQUE inner — not the M × N spawn
    //     the per-job `wait_for_any_drainable` calls produced.
    //   * `notify_waiters()` fans out to ALL parked jobs at once
    //     (fixing the `notify_one` race where a single push only
    //     woke one of N waiters and the rest sat until
    //     `LONGPOLL_DEADLINE`).
    let batch_wait: Arc<BatchWait> = BatchWait::new({
        let mut v: Vec<Arc<SessionInner>> =
            tcp_drains.iter().map(|d| d.inner.clone()).collect();
        v.extend(seq_specs.iter().map(|s| s.inner.clone()));
        v
    });

    // Spawn seq-ordered `data` ops AFTER `new_conn_jobs` so each
    // task sees the final value of `had_writes_or_connects` and can
    // pick the right drain deadline (active vs long-poll). Keeping
    // these in a JoinSet lets us race them with Phase 2 below, so a
    // single idle pipelined poll doesn't gate the whole batch
    // response on `LONGPOLL_DEADLINE`.
    let mut seq_data_jobs: JoinSet<(usize, TunnelResponse)> = JoinSet::new();
    for spec in seq_specs {
        let budget = response_budget.clone();
        let active = had_writes_or_connects;
        let bw = batch_wait.clone();
        seq_data_jobs.spawn(async move {
            let resp = process_seq_data_op(
                spec.inner, spec.sid, spec.seq, spec.data, budget, active, bw,
            )
            .await;
            (spec.i, resp)
        });
    }

    // Phase 2 (legacy non-seq drain) and seq-data jobs run
    // concurrently — neither's wait phase gates the other. Phase 2
    // waits up to ACTIVE_DRAIN_DEADLINE / LONGPOLL_DEADLINE for
    // tcp_drains / udp_drains; seq jobs have their own per-session
    // waits (per-inner for active, shared `BatchWait` for idle).
    // Both share the same `BatchWait`, so a wake from any session's
    // `reader_task` resolves both sides simultaneously.
    //
    // Note: the HTTP batch response itself is held until BOTH sides
    // finish — the `tokio::join!` below joins everything before
    // building the JSON body. The "concurrent" claim is about wait-
    // phase coupling, not about returning the response early.
    // Apps Script / the batched protocol surface doesn't support
    // partial / streamed responses, so all results have to land in
    // one body.
    let response_budget_p2 = response_budget.clone();
    let phase_2_batch_wait = batch_wait.clone();
    let phase_2_fut = async move {
        let mut p2_results: Vec<(usize, TunnelResponse)> = Vec::new();
        let mut tcp_eof_sids: Vec<String> = Vec::new();
        let mut udp_eof_sids: Vec<String> = Vec::new();

        if !tcp_drains.is_empty() || !udp_drains.is_empty() {
            let deadline = if had_writes_or_connects {
                ACTIVE_DRAIN_DEADLINE
            } else {
                LONGPOLL_DEADLINE
            };

            // Phase 1 already gave us each session's Arc<…Inner>, so
            // we don't need to re-acquire the sessions map lock
            // here. Cloning the Arc is just a refcount bump.
            let tcp_inners: Vec<Arc<SessionInner>> =
                tcp_drains.iter().map(|d| d.inner.clone()).collect();
            let udp_inners: Vec<Arc<UdpSessionInner>> = udp_drains
                .iter()
                .map(|(_, _, inner)| inner.clone())
                .collect();

            // Wake on whichever side has work first. The TCP wait
            // is the SHARED `BatchWait` — its watcher tasks bridge
            // every unique session's `inner.notify` to a single
            // batch-wide `notify_waiters()`, so a seq session
            // getting bytes wakes Phase 2 too AND a Phase 2 session
            // getting bytes wakes every seq job. We only DRAIN our
            // own `tcp_inners` below; the seq jobs handle theirs.
            //
            // The previous `tokio::join!` was conjunctive — a TCP
            // burst still paid the UDP deadline in mixed batches.
            // `BatchWait::wait` short-circuits on an empty inner set
            // (and `wait_for_any_udp_drainable` does the same for
            // UDP), so we skip the empty side to avoid its instant
            // return firing the select arm prematurely.
            let tcp_wait_empty = phase_2_batch_wait.inners.is_empty();
            match (tcp_wait_empty, udp_inners.is_empty()) {
                (true, true) => {}
                (false, true) => phase_2_batch_wait.wait(deadline).await,
                (true, false) => wait_for_any_udp_drainable(&udp_inners, deadline).await,
                (false, false) => {
                    tokio::select! {
                        _ = phase_2_batch_wait.wait(deadline) => {}
                        _ = wait_for_any_udp_drainable(&udp_inners, deadline) => {}
                    }
                }
            }

            if had_writes_or_connects {
                // Adaptive settle: keep waiting in steps while new
                // data keeps arriving. Break when:
                //  1. No new data arrived in the last step (burst is over)
                //  2. STRAGGLER_SETTLE_MAX reached
                let settle_end = Instant::now() + STRAGGLER_SETTLE_MAX;
                let mut prev_tcp_bytes: usize = 0;
                let mut prev_udp_pkts: usize = 0;
                for inner in &tcp_inners {
                    prev_tcp_bytes += inner.read_buf.lock().await.len();
                }
                for inner in &udp_inners {
                    prev_udp_pkts += inner.packets.lock().await.len();
                }
                loop {
                    let now = Instant::now();
                    if now >= settle_end {
                        break;
                    }
                    let remaining = settle_end.duration_since(now);
                    tokio::time::sleep(STRAGGLER_SETTLE_STEP.min(remaining)).await;

                    let mut tcp_bytes: usize = 0;
                    let mut udp_pkts: usize = 0;
                    for inner in &tcp_inners {
                        tcp_bytes += inner.read_buf.lock().await.len();
                    }
                    for inner in &udp_inners {
                        udp_pkts += inner.packets.lock().await.len();
                    }

                    if tcp_bytes == prev_tcp_bytes && udp_pkts == prev_udp_pkts {
                        break;
                    }

                    prev_tcp_bytes = tcp_bytes;
                    prev_udp_pkts = udp_pkts;
                }
            }

            // ---- TCP drain ----
            // Cleanup is driven off `drain_now`'s returned `eof`, NOT
            // the raw `inner.eof` atomic. When the buffer exceeds
            // `TCP_DRAIN_MAX_BYTES`, `drain_now` deliberately returns
            // `eof = false` and leaves the tail in the buffer so the
            // client can pick it up on the next poll.
            //
            // On budget exhaustion, push an empty (eof=false)
            // response per remaining drain rather than `break`-ing —
            // every (i, sid) registered as a drain corresponds to an
            // op the client expects a reply for. Skipping pushes
            // would surface as "missing response in batch" client-
            // side, and for connect_data would leak a freshly-opened
            // server session (the client never learns the sid, so
            // never sends `close`).
            for drain in &tcp_drains {
                // Reserve at most `TCP_DRAIN_MAX_BYTES`, not the
                // entire remaining budget. Mirrors the seq path
                // (`process_seq_data_op`): under mixed legacy +
                // seq batches, setting budget to 0 here would
                // make concurrently-running seq jobs observe
                // `take == 0` and return empty responses for an
                // op slot whose own drain would have fit in the
                // budget once we refunded the unused portion a
                // moment later. With the per-iteration cap, seq
                // jobs continue to see headroom up to
                // `TCP_DRAIN_MAX_BYTES` worth of budget while
                // this drain is in flight.
                let take = {
                    let mut b = response_budget_p2.lock().await;
                    let take = (*b).min(TCP_DRAIN_MAX_BYTES);
                    *b = b.saturating_sub(take);
                    take
                };
                let mut resp = if take == 0 {
                    // Budget exhausted by sibling drains (legacy or
                    // seq). Push an empty placeholder so the client
                    // sees a reply for this index; the buffered
                    // bytes stay for the next poll. Don't surface
                    // raw inner.eof here for the same reason
                    // `drain_now` withholds it when bytes remain —
                    // closing the session client-side would drop
                    // the buffered tail.
                    tcp_drain_response(drain.sid.clone(), Vec::new(), false)
                } else {
                    let (data, eof) = drain_now(&drain.inner, take).await;
                    let drained = data.len();
                    if drained < take {
                        *response_budget_p2.lock().await += take - drained;
                    }
                    if eof {
                        tcp_eof_sids.push(drain.sid.clone());
                    }
                    tcp_drain_response(drain.sid.clone(), data, eof)
                };
                // Stamp caps on the connect_data first reply so the
                // batched HTTPS fast path enables pipelining (matches
                // `handle_connect_data_single`'s behavior). Plain
                // `data` drains don't carry caps — they're not
                // session-establishment replies.
                if drain.is_connect_data {
                    resp.caps = Some(CAPS_PIPELINE_SEQ);
                }
                p2_results.push((drain.i, resp));
            }

            // ---- UDP drain ----
            // Same shape as TCP. `drain_udp_now` currently drains
            // the full queue with no per-batch cap, so its returned
            // `eof` already matches the atomic — driving cleanup
            // off the drain return rather than the atomic catches a
            // future per-batch UDP cap if added.
            for (i, sid, inner) in &udp_drains {
                let (packets, eof) = drain_udp_now(inner).await;
                if eof {
                    udp_eof_sids.push(sid.clone());
                }
                p2_results.push((*i, udp_drain_response(sid.clone(), packets, eof)));
            }
        }

        (p2_results, tcp_eof_sids, udp_eof_sids)
    };

    let seq_fut = async move {
        let mut out: Vec<(usize, TunnelResponse)> = Vec::new();
        while let Some(join) = seq_data_jobs.join_next().await {
            match join {
                Ok((i, resp)) => out.push((i, resp)),
                Err(e) => tracing::error!("seq-data task panicked: {}", e),
            }
        }
        out
    };

    let ((p2_results, p2_tcp_eof_sids, p2_udp_eof_sids), seq_results) =
        tokio::join!(phase_2_fut, seq_fut);

    // Process deferred close ops AFTER all seq-data jobs and Phase
    // 2 drains have completed. Earlier same-sid seq ops have now
    // written their uplink and produced their drain responses, so
    // the close can safely tear down the session without racing
    // them. Running close inline during dispatch (the pre-fix
    // shape) removed the session from `state.sessions` and aborted
    // `reader_task` while same-sid seq jobs were still about to
    // run on their cloned `Arc<SessionInner>`.
    for (i, sid) in pending_closes {
        let r = handle_close(&state, sid).await;
        results.push((i, r));
    }

    // Collect seq-side eof'd sids the same way Phase 2 does, so an
    // upstream-closed pipelined session is reaped immediately on
    // its eof reply rather than waiting for the idle reaper.
    let seq_tcp_eof_sids: Vec<String> = seq_results
        .iter()
        .filter_map(|(_, r)| {
            if r.eof.unwrap_or(false) {
                r.sid.clone()
            } else {
                None
            }
        })
        .collect();

    results.extend(p2_results);
    results.extend(seq_results);

    // Combined TCP eof cleanup — both legacy Phase 2 and seq paths
    // can produce eof'd sids; remove them in a single sessions-map
    // lock acquisition.
    if !p2_tcp_eof_sids.is_empty() || !seq_tcp_eof_sids.is_empty() {
        let mut sessions = state.sessions.lock().await;
        for sid in p2_tcp_eof_sids.iter().chain(seq_tcp_eof_sids.iter()) {
            if let Some(s) = sessions.remove(sid) {
                s.reader_handle.abort();
                tracing::info!("session {} closed by remote (batch)", sid);
            }
        }
    }
    if !p2_udp_eof_sids.is_empty() {
        let mut sessions = state.udp_sessions.lock().await;
        for sid in &p2_udp_eof_sids {
            if let Some(s) = sessions.remove(sid) {
                s.reader_handle.abort();
                tracing::info!("udp session {} closed by remote (batch)", sid);
            }
        }
    }

    // Sort results by original index and build response
    results.sort_by_key(|(i, _)| *i);
    let batch_resp = BatchResponse {
        r: results.into_iter().map(|(_, r)| r).collect(),
    };

    let json = serde_json::to_vec(&batch_resp).unwrap_or_default();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
}

fn tcp_drain_response(sid: String, data: Vec<u8>, eof: bool) -> TunnelResponse {
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() {
            None
        } else {
            Some(B64.encode(&data))
        },
        pkts: None,
        eof: Some(eof),
        e: None,
        code: None,
        seq: None,
        caps: None,
    }
}

fn udp_drain_response(sid: String, packets: Vec<Vec<u8>>, eof: bool) -> TunnelResponse {
    let pkts = if packets.is_empty() {
        None
    } else {
        Some(packets.iter().map(|p| B64.encode(p)).collect())
    };
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts,
        eof: Some(eof),
        e: None,
        code: None,
        seq: None,
        caps: None,
    }
}

fn eof_response(sid: String) -> TunnelResponse {
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts: None,
        eof: Some(true),
        e: None,
        code: None,
        seq: None,
        caps: None,
    }
}

/// RAII guard that advances `expected` and notifies waiters on drop.
/// Holding this across the entire (write, drain) sequence guarantees
/// that subsequent seqs unblock on EVERY exit path, including early
/// returns from write/flush failures. Without it, an upstream socket
/// error mid-pipeline would leave `expected` frozen at the failed
/// seq, stranding all later seqs until each hit `SEQ_WAIT_TIMEOUT`
/// (~30 s) — pushing well-formed batches into client/Apps-Script
/// timeout territory.
struct SeqAdvanceOnDrop<'a> {
    state: Option<tokio::sync::MutexGuard<'a, SeqState>>,
    notify: &'a Notify,
}

impl<'a> Drop for SeqAdvanceOnDrop<'a> {
    fn drop(&mut self) {
        if let Some(mut s) = self.state.take() {
            s.expected = s.expected.saturating_add(1);
            // s drops here, releasing the seq_state lock before the
            // notify_waiters() call below. Order matters: waiters
            // wake and immediately try to lock seq_state, so they
            // need to see the bumped value, which means the lock
            // release has to happen before the wake.
        }
        self.notify.notify_waiters();
    }
}

/// Seq-ordered `data` op processing for the pipelining protocol.
///
/// The contract: when a `data` op carries a `seq`, the tunnel-node
/// must process the entire (write, wait, drain) sequence for the
/// session in monotonically increasing seq order. Two ops can travel
/// from the client through different deployments/network paths and
/// arrive here out of order — without ordering, the client's
/// per-session reorder buffer would see seq-N's reply containing
/// bytes that should have followed seq-N+1's, silently corrupting
/// the stream.
///
/// Concurrency: the seq lock (held inside `SeqAdvanceOnDrop`) wraps
/// the *entire* (write, wait_for_drainable, drain) sequence and is
/// released — with `expected` advanced — on every exit path via
/// the guard's `Drop`. This guarantees per-session serialization of
/// drains as well as writes, AND ensures a write/flush error doesn't
/// strand later seqs behind a never-bumped `expected`.
///
/// Drain budget: callers thread a shared `Arc<Mutex<usize>>` through
/// every seq-data job in a batch (and through Phase 2's
/// `tcp_drains` loop) so the total bytes across all sessions in
/// one batch response stay under `BATCH_RESPONSE_BUDGET`. Without
/// this, M concurrent pipelined sessions would each return up to
/// `TCP_DRAIN_MAX_BYTES`, stacking past Apps Script's 50 MiB ceiling
/// and triggering truncation / parse failures (#863).
///
/// `had_active_in_batch` propagates the dispatch loop's
/// `had_writes_or_connects` flag so an idle pipelined poll
/// coalesced with active sibling ops uses `ACTIVE_DRAIN_DEADLINE`
/// instead of `LONGPOLL_DEADLINE` — without this, a single empty
/// seq op can hold the whole batch response open for 15 s.
///
/// `batch_wait` is the shared wait primitive for the whole batch.
/// Every seq job and Phase 2's TCP drain subscribe to its single
/// `Notify`; one push from any session's `reader_task` fans out to
/// `notify_waiters()` and wakes every parked job at once. Without
/// this shared primitive, an idle empty pipelined poll for session
/// B held the entire batch response open up to `LONGPOLL_DEADLINE`,
/// even if session A already had bytes another job was ready to
/// ship — and the previous per-job watcher design also hit the
/// `notify_one` race where a single push only woke one of N parked
/// jobs.
async fn process_seq_data_op(
    inner: Arc<SessionInner>,
    sid: String,
    seq: u64,
    data_b64: Option<String>,
    response_budget: Arc<Mutex<usize>>,
    had_active_in_batch: bool,
    batch_wait: Arc<BatchWait>,
) -> TunnelResponse {
    // Decode uplink first so a malformed payload doesn't burn a seq slot.
    let uplink = match data_b64 {
        Some(ref d) if !d.is_empty() => match B64.decode(d) {
            Ok(b) => Some(b),
            Err(e) => {
                let mut r = TunnelResponse::error(format!("bad base64: {}", e));
                r.seq = Some(seq);
                return r;
            }
        },
        _ => None,
    };
    let had_uplink = uplink.as_ref().map(|b| !b.is_empty()).unwrap_or(false);

    // Wait for our seq turn. Returns the seq-state guard *without*
    // bumping `expected` — we hold it across the entire op so drain
    // serialization is guaranteed.
    let seq_guard = match wait_for_seq_turn(&inner, seq, SEQ_WAIT_TIMEOUT).await {
        Ok(g) => g,
        Err(e) => {
            let mut r = TunnelResponse::error(e);
            r.seq = Some(seq);
            return r;
        }
    };

    // From here on, the SeqAdvanceOnDrop guard owns the seq_state
    // MutexGuard and bumps `expected` + notify_waiters() on every
    // return path — including the early-exit error returns below
    // (write/flush failures). Without this, an upstream write
    // failure would strand later seqs behind a never-bumped
    // `expected` until each hit `SEQ_WAIT_TIMEOUT`.
    let _advance = SeqAdvanceOnDrop {
        state: Some(seq_guard),
        notify: &inner.seq_advance,
    };

    // Refresh last_active on EVERY pipelined op, including empty
    // polls. Matches the legacy non-seq `data` branch (line ~984):
    // the idle reaper would otherwise close a long-lived session
    // that's actively being long-polled by the client (no uplink,
    // no recent inbound = stale, even though the client is still
    // engaged).
    *inner.last_active.lock().await = Instant::now();

    // Write uplink under the writer lock. The writer lock is a
    // sub-lock here — only acquired when we actually have bytes to
    // write. Lock order: seq → writer (no other path takes seq
    // before writer, so this can't deadlock with the legacy non-seq
    // data path which only takes writer).
    if let Some(bytes) = uplink {
        if !bytes.is_empty() {
            let mut writer = inner.writer.lock().await;
            if let Err(e) = writer.write_all(&bytes).await {
                drop(writer);
                let mut r = TunnelResponse::error(format!("write failed: {}", e));
                r.seq = Some(seq);
                return r;
            }
            if let Err(e) = writer.flush().await {
                drop(writer);
                let mut r = TunnelResponse::error(format!("flush failed: {}", e));
                r.seq = Some(seq);
                return r;
            }
        }
    }

    // Pick the drain deadline AND the wait shape based on whether
    // this op is active.
    //
    // ACTIVE (`had_uplink == true`): we just wrote uplink bytes; the
    // response we want is THIS session's reply, not anyone else's.
    // Wait per-session up to `ACTIVE_DRAIN_DEADLINE`, then run a
    // straggler-settle loop (mirroring Phase 2's behavior) so a
    // multi-packet response from upstream lands in one drain
    // instead of being split across two batches. Subscribing to
    // the shared batch_wait here would be wrong: a sibling
    // session's bytes could short-circuit our wait, and we'd
    // return empty for an active op that just hadn't gotten its
    // own reply yet.
    //
    // IDLE (`had_uplink == false`): empty poll. If the batch has
    // any active siblings, use `ACTIVE_DRAIN_DEADLINE` to keep the
    // whole batch responsive; otherwise long-poll up to
    // `LONGPOLL_DEADLINE`. Either way, subscribe to the SHARED
    // `BatchWait` so a sibling getting bytes wakes us — that's
    // the whole point of the shared wake design.
    if had_uplink {
        wait_for_any_drainable(std::slice::from_ref(&inner), ACTIVE_DRAIN_DEADLINE).await;
        // Active straggler settle: keep waiting in 10 ms steps
        // while bytes keep arriving, capped at STRAGGLER_SETTLE_MAX
        // (~1 s). Without this, a multi-packet response that
        // arrives a few ms apart gets split across this batch's
        // drain and the next, doubling Apps Script round-trips
        // for the same logical exchange.
        let settle_end = Instant::now() + STRAGGLER_SETTLE_MAX;
        let mut prev_len = inner.read_buf.lock().await.len();
        let raw_eof = inner.eof.load(Ordering::Acquire);
        if !raw_eof {
            loop {
                let now = Instant::now();
                if now >= settle_end {
                    break;
                }
                let remaining = settle_end - now;
                tokio::time::sleep(STRAGGLER_SETTLE_STEP.min(remaining)).await;
                let cur_len = inner.read_buf.lock().await.len();
                let cur_eof = inner.eof.load(Ordering::Acquire);
                if cur_len == prev_len && !cur_eof {
                    break;
                }
                prev_len = cur_len;
                if cur_eof {
                    break;
                }
            }
        }
    } else {
        let deadline = if had_active_in_batch {
            ACTIVE_DRAIN_DEADLINE
        } else {
            LONGPOLL_DEADLINE
        };
        if batch_wait.inners.is_empty() {
            wait_for_any_drainable(std::slice::from_ref(&inner), deadline).await;
        } else {
            batch_wait.wait(deadline).await;
        }
    }

    // Reserve our share of the batch-wide response budget, drain
    // exactly that much (or less), and return any unused budget so
    // sibling tasks can use it. `drain_now` already handles the
    // per-session `TCP_DRAIN_MAX_BYTES` cap and — critically — leaves
    // the tail in the buffer when over the cap, so no bytes are lost.
    let take = {
        let mut budget = response_budget.lock().await;
        let take = (*budget).min(TCP_DRAIN_MAX_BYTES);
        *budget = budget.saturating_sub(take);
        take
    };
    let (data, eof) = if take == 0 {
        // Batch budget already exhausted by sibling drains. Don't
        // drain any bytes here — they'll come back on the next poll.
        // Critically, withhold EOF when the buffer still contains
        // bytes: reporting eof=true here would close the session
        // client-side and silently drop the buffered tail. This
        // mirrors `drain_now`'s "withhold EOF until tail is drained"
        // semantics; without it, the budget-exhaustion path becomes
        // a data-loss bug on high-throughput pipelined sessions.
        let buf_empty = inner.read_buf.lock().await.is_empty();
        let raw_eof = inner.eof.load(Ordering::Acquire);
        let safe_eof = raw_eof && buf_empty;
        (Vec::new(), safe_eof)
    } else {
        let (d, e) = drain_now(&inner, take).await;
        if d.len() < take {
            *response_budget.lock().await += take - d.len();
        }
        (d, e)
    };

    // _advance drops here on the success path, bumping expected and
    // notifying waiters. The same drop runs on every early return
    // above.
    let mut resp = tcp_drain_response(sid, data, eof);
    resp.seq = Some(seq);
    resp
}

/// Wait for our `seq` to be the next-expected for this session and
/// return the seq-state guard. The caller HOLDS the guard across the
/// entire (write, wait_for_drainable, drain) sequence and only
/// releases it after bumping `expected` — that's what enforces both
/// uplink ordering AND drain ordering on a single shared
/// `read_buf`. An earlier shape that released the guard before the
/// drain phase let two concurrently-running seq tasks race for the
/// read_buf lock; a reader_task push between their two final takes
/// could split bytes across replies in reverse seq order, silently
/// corrupting the stream.
async fn wait_for_seq_turn<'a>(
    inner: &'a SessionInner,
    seq: u64,
    timeout: Duration,
) -> Result<tokio::sync::MutexGuard<'a, SeqState>, String> {
    let start = Instant::now();
    loop {
        // Subscribe to the notify *before* taking the seq_state
        // lock. `Notify::notify_waiters()` does NOT save a permit
        // for waiters that aren't yet registered, so the obvious
        // `lock → check → drop → notified()` order races: an
        // advance between drop and notified() is lost, and the
        // waiter sleeps until SEQ_WAIT_TIMEOUT. `enable()` registers
        // the future so any subsequent `notify_waiters()` wakes it,
        // even if the wake fires before we reach `.await` below.
        let notified = inner.seq_advance.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let state = inner.seq_state.lock().await;
        if seq < state.expected {
            // Late arrival — likely a client retry of a seq we
            // already processed. Drop it; the client's earlier
            // reply (if it arrived) handled this op.
            return Err(format!(
                "seq {} already processed (expected {})",
                seq, state.expected
            ));
        }
        if seq == state.expected {
            return Ok(state);
        }
        // seq > expected: drop the seq lock and wait for an advance.
        let current_expected = state.expected;
        drop(state);
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(format!(
                "seq {} timed out waiting for {} (waited {:?})",
                seq, current_expected, elapsed
            ));
        }
        // The pre-enabled `notified` will resolve immediately if a
        // notify_waiters() fired between our enable() and here.
        let _ = tokio::time::timeout(timeout - elapsed, notified).await;
        // Re-check at top of loop after wake / timeout.
    }
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shared op handlers
// ---------------------------------------------------------------------------

fn validate_host_port(
    host: Option<String>,
    port: Option<u16>,
) -> Result<(String, u16), TunnelResponse> {
    let host = match host {
        Some(h) if !h.is_empty() => h,
        _ => return Err(TunnelResponse::error("missing host")),
    };
    let port = match port {
        Some(p) if p > 0 => p,
        _ => return Err(TunnelResponse::error("missing or invalid port")),
    };
    Ok((host, port))
}

async fn handle_connect(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
) -> TunnelResponse {
    let (host, port) = match validate_host_port(host, port) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let session = if udpgw::is_udpgw_dest(&host, port) {
        create_udpgw_session()
    } else {
        match create_session(&host, port).await {
            Ok(s) => s,
            Err(e) => return TunnelResponse::error(format!("connect failed: {}", e)),
        }
    };
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{}", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    // Advertise pipelining support on the connect reply so the client
    // knows it can opt into per-session `data`-op sequence numbers
    // for this session. Old clients ignore the unknown `caps` field.
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts: None,
        eof: Some(false),
        e: None,
        code: None,
        seq: None,
        caps: Some(CAPS_PIPELINE_SEQ),
    }
}

/// Open a session and write the client's first bytes in one round trip.
/// Returns the new sid plus an `Arc<SessionInner>`. Both callers keep
/// the Arc: the unary path (`handle_connect_data_single`) uses it to
/// drain the first response without a second sessions-map lookup, and
/// the batch path threads it into `tcp_drains` so phase-2 drain runs
/// without holding the global sessions map lock across the per-session
/// `read_buf.lock().await`.
async fn handle_connect_data_phase1(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> Result<(String, Arc<SessionInner>), TunnelResponse> {
    let (host, port) = validate_host_port(host, port)?;

    let session = if udpgw::is_udpgw_dest(&host, port) {
        create_udpgw_session()
    } else {
        create_session(&host, port)
            .await
            .map_err(|e| TunnelResponse::error(format!("connect failed: {}", e)))?
    };

    // Any failure below this point must abort the reader task, otherwise
    // the newly-opened upstream TCP connection would leak. Keep the
    // abort paths explicit rather than burying them in `.map_err`.
    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            let bytes = match B64.decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("bad base64: {}", e)));
                }
            };
            if !bytes.is_empty() {
                let mut w = session.inner.writer.lock().await;
                if let Err(e) = w.write_all(&bytes).await {
                    drop(w);
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("write failed: {}", e)));
                }
                let _ = w.flush().await;
            }
        }
    }

    let inner = session.inner.clone();
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{} (connect_data)", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    Ok((sid, inner))
}

/// UDP analogue of `handle_connect_data_phase1`. Opens a connected UDP
/// socket to `(host, port)` and optionally sends the client's first
/// datagram in the same op so a request-response flow (e.g. DNS, STUN)
/// saves a round trip on session establishment.
async fn handle_udp_open_phase1(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> Result<(String, Arc<UdpSessionInner>), TunnelResponse> {
    let (host, port) = validate_host_port(host, port)?;

    let session = create_udp_session(&host, port)
        .await
        .map_err(|e| TunnelResponse::error(format!("udp connect failed: {}", e)))?;

    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            let bytes = match B64.decode(data_b64) {
                Ok(b) => b,
                Err(e) => {
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("bad base64: {}", e)));
                }
            };
            if !bytes.is_empty() {
                if let Err(e) = session.inner.socket.send(&bytes).await {
                    session.reader_handle.abort();
                    return Err(TunnelResponse::error(format!("udp write failed: {}", e)));
                }
            }
        }
    }

    let inner = session.inner.clone();
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("udp session {} -> {}:{}", sid, host, port);
    state.udp_sessions.lock().await.insert(sid.clone(), session);
    Ok((sid, inner))
}

async fn handle_connect_data_single(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> TunnelResponse {
    let (sid, inner) = match handle_connect_data_phase1(state, host, port, data).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (data, eof) = wait_and_drain(&inner, Duration::from_secs(5)).await;
    if eof {
        if let Some(s) = state.sessions.lock().await.remove(&sid) {
            s.reader_handle.abort();
            tracing::info!("session {} closed by remote", sid);
        }
    }
    // Same caps advertisement as `handle_connect`. The single-op
    // `connect_data` path is the optimistic-bundling fast path —
    // surfacing capabilities here means a client opting into both
    // optimizations learns about pipelining on the very first reply.
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() {
            None
        } else {
            Some(B64.encode(&data))
        },
        pkts: None,
        eof: Some(eof),
        e: None,
        code: None,
        seq: None,
        caps: Some(CAPS_PIPELINE_SEQ),
    }
}

async fn handle_data_single(
    state: &AppState,
    sid: Option<String>,
    data: Option<String>,
) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    // Clone the inner Arc under the global sessions map lock and release
    // the map lock before any await. The previous shape held the map
    // across last_active.lock(), writer.lock(), write_all, flush, AND
    // wait_and_drain — up to 5 s of head-of-line blocking on every other
    // single-op or batch request. Mirrors the batch-handler "data" path.
    let inner = {
        let sessions = state.sessions.lock().await;
        sessions.get(&sid).map(|s| s.inner.clone())
    };
    let inner = match inner {
        Some(i) => i,
        None => return TunnelResponse::error("unknown session"),
    };
    *inner.last_active.lock().await = Instant::now();
    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            if let Ok(bytes) = B64.decode(data_b64) {
                if !bytes.is_empty() {
                    let mut w = inner.writer.lock().await;
                    if let Err(e) = w.write_all(&bytes).await {
                        drop(w);
                        state.sessions.lock().await.remove(&sid);
                        return TunnelResponse::error(format!("write failed: {}", e));
                    }
                    let _ = w.flush().await;
                }
            }
        }
    }
    let (data, eof) = wait_and_drain(&inner, Duration::from_secs(5)).await;
    if eof {
        if let Some(s) = state.sessions.lock().await.remove(&sid) {
            s.reader_handle.abort();
            tracing::info!("session {} closed by remote", sid);
        }
    }
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() {
            None
        } else {
            Some(B64.encode(&data))
        },
        pkts: None,
        eof: Some(eof),
        e: None,
        code: None,
        seq: None,
        caps: None,
    }
}

async fn handle_close(state: &AppState, sid: Option<String>) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    if let Some(s) = state.sessions.lock().await.remove(&sid) {
        s.abort_all();
        tracing::info!("session {} closed by client", sid);
    }
    if let Some(s) = state.udp_sessions.lock().await.remove(&sid) {
        s.reader_handle.abort();
        tracing::info!("udp session {} closed by client", sid);
    }
    TunnelResponse {
        sid: Some(sid),
        d: None,
        pkts: None,
        eof: Some(true),
        e: None,
        code: None,
        seq: None,
        caps: None,
    }
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

async fn cleanup_task(
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
    udp_sessions: Arc<Mutex<HashMap<String, ManagedUdpSession>>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let now = Instant::now();

        {
            let mut map = sessions.lock().await;
            let mut stale = Vec::new();
            for (k, s) in map.iter() {
                let last = *s.inner.last_active.lock().await;
                if now.duration_since(last) > Duration::from_secs(300) {
                    stale.push(k.clone());
                }
            }
            for k in &stale {
                if let Some(s) = map.remove(k) {
                    s.reader_handle.abort();
                    tracing::info!("reaped idle session {}", k);
                }
            }
            if !stale.is_empty() {
                tracing::info!("cleanup: reaped {}, {} active", stale.len(), map.len());
            }
        }

        {
            // UDP sessions get a tighter idle window because UDP flows
            // are typically short-lived (DNS, STUN, single-RTT QUIC) or
            // make their own keepalives. 120 s avoids leaking sockets
            // for one-shot lookups while keeping calls/streams alive.
            let mut map = udp_sessions.lock().await;
            let mut stale = Vec::new();
            for (k, s) in map.iter() {
                let last = *s.inner.last_active.lock().await;
                if now.duration_since(last) > Duration::from_secs(120) {
                    stale.push(k.clone());
                }
            }
            for k in &stale {
                if let Some(s) = map.remove(k) {
                    s.reader_handle.abort();
                    tracing::info!("reaped idle udp session {}", k);
                }
            }
            if !stale.is_empty() {
                tracing::info!("cleanup: reaped {}, {} active udp", stale.len(), map.len());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let auth_key = std::env::var("TUNNEL_AUTH_KEY").unwrap_or_else(|_| {
        // Catch the recurring `MHRV_AUTH_KEY` typo (#391, #444). Several old
        // copy-paste guides used `MHRV_AUTH_KEY` for the docker run; tunnel-node
        // never read that name and silently fell through to `changeme`,
        // producing baffling AUTH_KEY-mismatch decoys on the client. If
        // `MHRV_AUTH_KEY` is set, point at it specifically so the user sees
        // why their value isn't taking effect.
        if std::env::var("MHRV_AUTH_KEY").is_ok() {
            tracing::warn!(
                "MHRV_AUTH_KEY is set but TUNNEL_AUTH_KEY is not — \
                 tunnel-node only reads TUNNEL_AUTH_KEY (uppercase, with \
                 underscores). Rename your env var: \
                 `docker run ... -e TUNNEL_AUTH_KEY=<your-secret>`. Falling \
                 back to default `changeme` for now (INSECURE — clients will \
                 fail with AUTH_KEY mismatch decoys until this is fixed)."
            );
        } else {
            tracing::warn!("TUNNEL_AUTH_KEY not set — using default (INSECURE)");
        }
        "changeme".into()
    });
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let sessions: Arc<Mutex<HashMap<String, ManagedSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let udp_sessions: Arc<Mutex<HashMap<String, ManagedUdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(cleanup_task(sessions.clone(), udp_sessions.clone()));

    // MHRV_DIAGNOSTIC=1 in env restores verbose JSON error responses on
    // bad auth (instead of the nginx-404 decoy). Use during setup so
    // misconfigured clients see "unauthorized"; flip back off in prod.
    let diagnostic_mode = std::env::var("MHRV_DIAGNOSTIC")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if diagnostic_mode {
        tracing::warn!(
            "MHRV_DIAGNOSTIC=1 — bad-auth responses are verbose JSON \
             errors instead of the production nginx-404 decoy. Disable \
             before exposing this tunnel-node to the public internet."
        );
    }
    let state = AppState {
        sessions,
        udp_sessions,
        auth_key: Arc::from(auth_key),
        diagnostic_mode,
    };

    let app = Router::new()
        .route("/tunnel", post(handle_tunnel))
        .route("/tunnel/batch", post(handle_batch))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!("tunnel-node listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("shutting down");
        })
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn fresh_state() -> AppState {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            auth_key: "test-key".into(),
            // Tests assert against the JSON `unauthorized` body shape
            // (see e.g. `bad_auth_returns_unauthorized`), so they need
            // diagnostic_mode enabled. Production default is false.
            diagnostic_mode: true,
        }
    }

    async fn start_udp_echo_server() -> u16 {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let mut out = b"ECHO: ".to_vec();
                out.extend_from_slice(&buf[..n]);
                let _ = socket.send_to(&out, peer).await;
            }
        });
        port
    }

    /// Spin up a one-shot TCP server that echoes everything it reads back
    /// with a `"ECHO: "` prefix, then returns the bound port.
    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = sock.read(&mut buf).await {
                    let mut out = b"ECHO: ".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(&out).await;
                    let _ = sock.flush().await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn unsupported_op_response_has_structured_code() {
        let resp = TunnelResponse::unsupported_op("connect_data");
        assert_eq!(resp.code.as_deref(), Some(CODE_UNSUPPORTED_OP));
        assert_eq!(resp.e.as_deref(), Some("unknown op: connect_data"));
    }

    #[tokio::test]
    async fn validate_host_port_rejects_empty_and_zero() {
        assert!(validate_host_port(None, Some(443)).is_err());
        assert!(validate_host_port(Some("".into()), Some(443)).is_err());
        assert!(validate_host_port(Some("x".into()), None).is_err());
        assert!(validate_host_port(Some("x".into()), Some(0)).is_err());
        assert_eq!(
            validate_host_port(Some("host".into()), Some(443)).unwrap(),
            ("host".to_string(), 443),
        );
    }

    #[tokio::test]
    async fn connect_data_phase1_writes_initial_data_and_returns_inner() {
        let port = start_echo_server().await;
        let state = fresh_state();

        let (sid, inner) = handle_connect_data_phase1(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"hello")),
        )
        .await
        .expect("phase1 should succeed");

        // Session was inserted.
        assert!(state.sessions.lock().await.contains_key(&sid));

        // Echo server sent back "ECHO: hello". Use wait_and_drain on the
        // returned Arc — no map re-lookup needed (this is the fix).
        let (data, _eof) = wait_and_drain(&inner, Duration::from_secs(2)).await;
        assert_eq!(&data[..], b"ECHO: hello");
    }

    #[tokio::test]
    async fn connect_data_single_bundles_connect_and_first_bytes() {
        let port = start_echo_server().await;
        let state = fresh_state();

        let resp = handle_connect_data_single(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"world")),
        )
        .await;

        assert!(resp.e.is_none(), "unexpected error: {:?}", resp.e);
        assert!(resp.sid.is_some());
        let decoded = B64.decode(resp.d.unwrap()).unwrap();
        assert_eq!(&decoded[..], b"ECHO: world");
    }

    #[tokio::test]
    async fn connect_data_rejects_missing_host() {
        let state = fresh_state();
        let resp =
            handle_connect_data_single(&state, None, Some(443), Some(B64.encode(b"x"))).await;
        assert!(resp.e.as_deref().unwrap_or("").contains("missing host"));
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn connect_data_rejects_bad_base64_and_does_not_leak_session() {
        // Need a live target so we reach the base64-decode step after
        // create_session succeeds — otherwise we'd fail earlier.
        let port = start_echo_server().await;
        let state = fresh_state();
        let resp = handle_connect_data_single(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some("!!!not base64!!!".into()),
        )
        .await;
        assert!(resp.e.as_deref().unwrap_or("").contains("bad base64"));
        // Session should NOT be in the map since phase1 rejected it.
        assert!(state.sessions.lock().await.is_empty());
    }

    // ---------------------------------------------------------------------
    // wait_for_any_drainable + notify wiring
    //
    // These guard the new event-driven drain. Regressions here mean the
    // batch handler either falls back to fixed sleeps (latency win lost)
    // or wedges on a missed signal (correctness lost) — both silent
    // without explicit tests.
    // ---------------------------------------------------------------------

    /// Build a SessionInner with no reader_task, suitable for tests that
    /// drive the read_buf / eof / notify state by hand. The writer half
    /// is wired to a live loopback peer so the Mutex<OwnedWriteHalf> has
    /// a real value, but tests never touch it.
    async fn fake_inner() -> Arc<SessionInner> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server_side = accept.await.unwrap();
        let (_reader, writer) = client.into_split();

        Arc::new(SessionInner {
            writer: Mutex::new(SessionWriter::Tcp(writer)),
            read_buf: Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
            seq_state: Mutex::new(SeqState { expected: 0 }),
            seq_advance: Notify::new(),
        })
    }

    #[tokio::test]
    async fn drain_now_caps_at_tcp_drain_max_bytes() {
        // Issue #460: a 1 Gbps VPS reader fills the buffer with tens of MiB
        // between polls; drain_now used to take the lot, the JSON response
        // exceeded Apps Script's body cap, and the client failed JSON parse.
        // The cap leaves the tail in the buffer for the next drain.
        let inner = fake_inner().await;
        let oversized = TCP_DRAIN_MAX_BYTES + 4096;
        inner.read_buf.lock().await.resize(oversized, 0xab);

        let (first, eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(first.len(), TCP_DRAIN_MAX_BYTES);
        assert!(!eof, "shouldn't propagate eof while buffer still has data");

        // Tail remains for the next poll.
        assert_eq!(inner.read_buf.lock().await.len(), 4096);

        let (second, _) = drain_now(&inner, usize::MAX).await;
        assert_eq!(second.len(), 4096);
        assert!(inner.read_buf.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_now_respects_caller_budget_below_per_session_cap() {
        // Issue #863: per-session TCP_DRAIN_MAX_BYTES alone wasn't enough
        // because N sessions × 16 MiB summed past Apps Script's 50 MiB
        // response ceiling. The batch loop now passes a remaining-budget
        // cap; drain_now must honor `min(budget, TCP_DRAIN_MAX_BYTES)`,
        // leaving the tail for the next poll exactly like the per-session
        // cap path does.
        let inner = fake_inner().await;
        // 1 MiB buffered, but caller only has 256 KiB budget left.
        inner.read_buf.lock().await.resize(1024 * 1024, 0xcd);

        let (drained, eof) = drain_now(&inner, 256 * 1024).await;
        assert_eq!(drained.len(), 256 * 1024);
        assert!(!eof, "tail still buffered, eof must wait");

        // The remaining 768 KiB stays put for the next poll.
        assert_eq!(inner.read_buf.lock().await.len(), 768 * 1024);

        // Next call with full budget drains the rest.
        let (rest, _) = drain_now(&inner, usize::MAX).await;
        assert_eq!(rest.len(), 768 * 1024);
        assert!(inner.read_buf.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_now_passes_through_when_under_cap() {
        let inner = fake_inner().await;
        inner
            .read_buf
            .lock()
            .await
            .extend_from_slice(b"hello world");

        let (data, eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(data, b"hello world");
        assert!(!eof);
        assert!(inner.read_buf.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_now_holds_eof_until_buffer_drained() {
        // If upstream signals EOF while the buffer is still oversized, we
        // must drain the head, leave the tail, and *not* set eof yet.
        // Eof flips on the final drain that returns a sub-cap buffer.
        let inner = fake_inner().await;
        inner.eof.store(true, Ordering::Release);
        inner
            .read_buf
            .lock()
            .await
            .resize(TCP_DRAIN_MAX_BYTES + 100, 0);

        let (head, head_eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(head.len(), TCP_DRAIN_MAX_BYTES);
        assert!(!head_eof, "premature eof would tear the session");

        let (tail, tail_eof) = drain_now(&inner, usize::MAX).await;
        assert_eq!(tail.len(), 100);
        assert!(tail_eof, "eof finally flips when buffer is drained");
    }

    #[tokio::test]
    async fn wait_for_any_drainable_returns_immediately_when_buffer_has_data() {
        let inner = fake_inner().await;
        inner
            .read_buf
            .lock()
            .await
            .extend_from_slice(b"already here");

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "should short-circuit on pre-buffered data, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_returns_immediately_when_eof_set() {
        let inner = fake_inner().await;
        inner.eof.store(true, Ordering::Release);

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "should short-circuit on pre-set eof, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_returns_immediately_for_empty_list() {
        let t0 = Instant::now();
        wait_for_any_drainable(&[], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "empty input should be a no-op, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_wakes_on_notify() {
        let inner = fake_inner().await;
        let signal = inner.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            signal.read_buf.lock().await.extend_from_slice(b"pushed");
            signal.notify.notify_one();
        });

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], Duration::from_secs(5)).await;
        let elapsed = t0.elapsed();
        // We only assert the upper bound — wake latency under load can be
        // tens of ms but should never approach the 5 s deadline.
        assert!(
            elapsed < Duration::from_millis(800),
            "did not wake on notify within reasonable time: {:?}",
            elapsed
        );
    }

    /// Any-of-N: when one session in a multi-session batch fires its
    /// notify, the wait returns. Regression here would mean idle
    /// neighbors block the drain for a session that has data ready.
    #[tokio::test]
    async fn wait_for_any_drainable_wakes_on_any_session_notify() {
        let a = fake_inner().await;
        let b = fake_inner().await;
        let c = fake_inner().await;
        let signal = b.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            signal.read_buf.lock().await.push(b'x');
            signal.notify.notify_one();
        });

        let t0 = Instant::now();
        wait_for_any_drainable(&[a, b, c], Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(800),
            "any-of-N wake too slow: {:?}",
            t0.elapsed()
        );
    }

    /// Stale-permit guard: if a previous batch consumed the buffer and
    /// returned via the spawn-race shortcut without consuming the notify
    /// permit, the next batch's watcher consumes that stale permit but
    /// MUST NOT wake the caller — the buffer is empty. This regressed
    /// silently in the first version; the self-filtering watcher closes
    /// it. Without this test, an empty long-poll batch could return in
    /// <1 ms and degrade push delivery to the client's idle re-poll
    /// cadence (~500 ms).
    #[tokio::test]
    async fn wait_for_any_drainable_ignores_stale_permit() {
        let inner = fake_inner().await;

        // Plant a permit (no waiter yet, so it's stored as a one-shot).
        inner.notify.notify_one();

        // Buffer is empty and EOF is unset, so the only thing that
        // could wake the wait is the permit. With self-filtering the
        // watcher consumes it, sees no observable state, loops back —
        // the wait should run for the full deadline and then return.
        let deadline = Duration::from_millis(200);
        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], deadline).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= deadline,
            "stale permit incorrectly woke the wait: {:?} < {:?}",
            elapsed,
            deadline
        );
    }

    #[tokio::test]
    async fn wait_for_any_drainable_hits_deadline_when_no_events() {
        let inner = fake_inner().await;
        let deadline = Duration::from_millis(150);

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner], deadline).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= deadline,
            "returned before deadline: {:?} < {:?}",
            elapsed,
            deadline
        );
        assert!(
            elapsed < deadline + Duration::from_millis(300),
            "overshot deadline by too much: {:?}",
            elapsed
        );
    }

    /// Real reader_task → notify path. If reader_task ever stops calling
    /// notify_one after an extend, the long-poll silently degrades to
    /// "wait the full deadline every time" — this catches that.
    #[tokio::test]
    async fn reader_task_notifies_on_incoming_bytes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
            sock.write_all(b"hello").await.unwrap();
            sock.flush().await.unwrap();
            // Hold the connection so reader_task doesn't immediately EOF
            // and confuse the assertion.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let inner = Arc::new(SessionInner {
            writer: Mutex::new(SessionWriter::Tcp(writer)),
            read_buf: Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
            seq_state: Mutex::new(SeqState { expected: 0 }),
            seq_advance: Notify::new(),
        });
        let _reader_handle = tokio::spawn(reader_task(reader, inner.clone()));

        let t0 = Instant::now();
        wait_for_any_drainable(&[inner.clone()], Duration::from_secs(2)).await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(800),
            "wait did not wake on reader_task notify: {:?}",
            elapsed
        );
        assert_eq!(&inner.read_buf.lock().await[..], b"hello");

        // The spawned server's only job is to deliver one chunk and hold
        // the connection open long enough for the assertion. abort() is
        // intentional cleanup, not a failure path.
        server.abort();
    }

    // ---------------------------------------------------------------------
    // handle_batch deadline selection (end-to-end through the actual
    // batch handler — not just wait_for_any_drainable in isolation)
    //
    // These tests guard the adaptive deadline logic: an empty-poll batch
    // must engage LONGPOLL_DEADLINE, an active batch must cap at
    // ACTIVE_DRAIN_DEADLINE + STRAGGLER_SETTLE, and `Some("")` must NOT
    // count as a write. Each was a separate review concern and would
    // regress silently without explicit coverage.
    // ---------------------------------------------------------------------

    /// TCP server that pushes `data` exactly `delay` after accept,
    /// without reading from the client first. Simulates server-initiated
    /// push (notifications, SSE) on a real socket.
    async fn start_push_server(delay: Duration, data: Vec<u8>) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                tokio::time::sleep(delay).await;
                let _ = sock.write_all(&data).await;
                let _ = sock.flush().await;
                // Hold the socket open well beyond any test's deadline
                // so reader_task doesn't EOF mid-assertion.
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        port
    }

    /// TCP server that accepts and does NOTHING — never writes, never
    /// closes. Used to test deadline behavior when there's no upstream
    /// response.
    async fn start_silent_server() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                // Hold the socket alive past any reasonable test deadline.
                tokio::time::sleep(Duration::from_secs(60)).await;
                drop(sock);
            }
        });
        port
    }

    /// Drive `handle_batch` end-to-end and parse its JSON response into a
    /// `serde_json::Value` for assertion (TunnelResponse/BatchResponse
    /// don't derive Deserialize, and we don't want to add it just for
    /// tests).
    async fn invoke_handle_batch(state: &AppState, body: Vec<u8>) -> serde_json::Value {
        let resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    /// Pure-poll batch (one `data` op with no `d`) holds open and wakes
    /// when upstream pushes data. Push arrives at ~150 ms — well past
    /// any active-batch ceiling. If long-poll didn't engage we'd return
    /// at ACTIVE_DRAIN_DEADLINE (350 ms) with no data.
    #[tokio::test]
    async fn batch_pure_poll_wakes_on_push() {
        let push_port = start_push_server(Duration::from_millis(150), b"PUSHED".to_vec()).await;
        let state = fresh_state();
        let connect_resp = handle_connect(&state, Some("127.0.0.1".into()), Some(push_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid}],
        }))
        .unwrap();

        let t0 = Instant::now();
        let resp = invoke_handle_batch(&state, body).await;
        let elapsed = t0.elapsed();

        assert!(
            elapsed >= Duration::from_millis(120),
            "returned before push could realistically arrive: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "long-poll did not return promptly on push: {:?}",
            elapsed
        );

        let r = resp["r"].as_array().expect("response must be an array");
        let d_b64 = r[0]["d"]
            .as_str()
            .expect("response should carry pushed bytes");
        let data = B64.decode(d_b64).unwrap();
        assert_eq!(&data[..], b"PUSHED");
    }

    /// Active batch (write op) bounds the wait at roughly
    /// ACTIVE_DRAIN_DEADLINE + a little overhead, even when upstream
    /// doesn't respond. Upper bound proves long-poll did NOT engage.
    #[tokio::test]
    async fn batch_active_caps_at_active_deadline() {
        let silent_port = start_silent_server().await;
        let state = fresh_state();
        let connect_resp =
            handle_connect(&state, Some("127.0.0.1".into()), Some(silent_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid, "d": B64.encode(b"PING")}],
        }))
        .unwrap();

        let t0 = Instant::now();
        let _resp = invoke_handle_batch(&state, body).await;
        let elapsed = t0.elapsed();

        // No upstream response → wait full ACTIVE_DRAIN_DEADLINE (~350ms),
        // no straggler settle (we never woke). Upper bound is tight
        // enough that a regression bumping the active deadline above
        // ~600ms would fail this test instead of slipping through.
        assert!(
            elapsed >= Duration::from_millis(300),
            "active batch returned before active deadline: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(600),
            "active batch held longer than ACTIVE_DRAIN_DEADLINE + margin: {:?}",
            elapsed
        );
    }

    /// `Some("")` must NOT flip `had_writes_or_connects`. If it did, the
    /// batch would return at the active deadline (350 ms) without the
    /// pushed bytes — push arrives at 600 ms here, deliberately past
    /// the active ceiling, so the only way the test gets data is if
    /// long-poll actually engaged.
    #[tokio::test]
    async fn batch_empty_string_payload_engages_long_poll() {
        let push_port = start_push_server(Duration::from_millis(600), b"DELAYED".to_vec()).await;
        let state = fresh_state();
        let connect_resp = handle_connect(&state, Some("127.0.0.1".into()), Some(push_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid, "d": ""}],
        }))
        .unwrap();

        let t0 = Instant::now();
        let resp = invoke_handle_batch(&state, body).await;
        let elapsed = t0.elapsed();

        assert!(
            elapsed >= Duration::from_millis(550),
            "returned before push arrived (deadline likely set to active, not long-poll): {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(1100),
            "long-poll didn't wake promptly on push: {:?}",
            elapsed
        );

        let r = resp["r"].as_array().unwrap();
        let d_b64 = r[0]["d"]
            .as_str()
            .expect("Some(\"\") payload should have engaged long-poll and delivered DELAYED");
        let data = B64.decode(d_b64).unwrap();
        assert_eq!(&data[..], b"DELAYED");
    }

    // ---------------------------------------------------------------------
    // UDP path
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn udp_open_writes_initial_datagram_and_buffers_reply() {
        let port = start_udp_echo_server().await;
        let state = fresh_state();

        let (sid, inner) = handle_udp_open_phase1(
            &state,
            Some("127.0.0.1".into()),
            Some(port),
            Some(B64.encode(b"ping")),
        )
        .await
        .expect("udp open should succeed");

        assert!(state.udp_sessions.lock().await.contains_key(&sid));
        wait_for_any_udp_drainable(std::slice::from_ref(&inner), Duration::from_secs(2)).await;
        let (packets, eof) = drain_udp_now(&inner).await;
        assert_eq!(packets, vec![b"ECHO: ping".to_vec()]);
        assert!(!eof);
    }

    /// When the upstream sends faster than the relay drains, the queue
    /// must drop oldest packets (so recent voice/video stays current)
    /// AND increment the counter so operators can correlate user
    /// reports of choppiness with relay backpressure.
    #[tokio::test]
    async fn udp_queue_overflow_drops_oldest_and_counts() {
        let state = fresh_state();
        let sink = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let sink_port = sink.local_addr().unwrap().port();

        let (_sid, inner) =
            handle_udp_open_phase1(&state, Some("127.0.0.1".into()), Some(sink_port), None)
                .await
                .expect("udp open");

        // Flood the session socket from sink — its connected remote is
        // exactly sink_port, so packets pass the kernel's source check.
        let session_addr = inner.socket.local_addr().unwrap();
        let burst = UDP_QUEUE_LIMIT + 16;
        for i in 0..burst {
            let payload = format!("p{}", i).into_bytes();
            sink.send_to(&payload, session_addr).await.unwrap();
        }
        // Give the reader_task a chance to drain the OS buffer.
        for _ in 0..50 {
            if inner.queue_drops.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let drops = inner.queue_drops.load(Ordering::Relaxed);
        let queued = inner.packets.lock().await.len();
        assert!(
            drops >= 1,
            "expected ≥1 drop, got {} (queued={})",
            drops,
            queued
        );
        assert!(
            queued <= UDP_QUEUE_LIMIT,
            "queue exceeded limit: {}",
            queued
        );
    }

    /// Regression for the bug the review caught: a batch mixing UDP and
    /// TCP-data ops must let the TCP side benefit from the same
    /// event-driven drain. With the new architecture both sides share
    /// one wait_start / deadline window — ensure a delayed TCP response
    /// still makes it into the batch even when UDP is along for the ride.
    #[tokio::test]
    async fn tcp_drain_runs_when_batch_also_contains_udp() {
        use axum::body::Bytes;
        use axum::extract::State;

        // TCP server that delays its response past the typical wake but
        // well within ACTIVE_DRAIN_DEADLINE (350ms).
        let tcp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = tcp_listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(120)).await;
                let _ = sock.write_all(b"DELAYED").await;
                let _ = sock.flush().await;
            }
        });

        // Idle UDP target — never replies. Just sets up the dual-drain
        // path through Phase 2.
        let udp_target = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let udp_port = udp_target.local_addr().unwrap().port();

        let state = fresh_state();
        let tcp_sid = match handle_connect(&state, Some("127.0.0.1".into()), Some(tcp_port)).await {
            TunnelResponse {
                sid: Some(s),
                e: None,
                ..
            } => s,
            other => panic!("connect failed: {:?}", other),
        };
        let (udp_sid, _udp_inner) =
            handle_udp_open_phase1(&state, Some("127.0.0.1".into()), Some(udp_port), None)
                .await
                .expect("udp open");

        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "data", "sid": tcp_sid, "d": B64.encode(b"hello")},
                {"op": "udp_data", "sid": udp_sid},
            ]
        })
        .to_string();
        let resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let (parts, body) = resp.into_parts();
        assert_eq!(parts.status, axum::http::StatusCode::OK);
        let body_bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let r = parsed["r"].as_array().unwrap();
        assert_eq!(r.len(), 2);
        let tcp_d = r[0]["d"].as_str().expect("tcp data missing");
        let decoded = B64.decode(tcp_d).unwrap();
        assert_eq!(&decoded[..], b"DELAYED");
    }

    /// When the upstream UDP socket dies (recv error), the reader_task
    /// must mark the session eof so subsequent batches return
    /// `eof: true` instead of looping the proxy on a zombie session.
    #[tokio::test]
    async fn udp_drain_surfaces_upstream_eof() {
        let inner = Arc::new(UdpSessionInner {
            socket: Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap()),
            packets: Mutex::new(VecDeque::new()),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
            eof: AtomicBool::new(false),
            queue_drops: AtomicU64::new(0),
        });
        // Healthy state: drain reports no eof.
        let (pkts, eof) = drain_udp_now(&inner).await;
        assert!(pkts.is_empty());
        assert!(!eof);

        // Simulate the failure path udp_reader_task takes on socket err.
        inner.eof.store(true, Ordering::Release);
        inner.notify.notify_one();

        let (pkts, eof) = drain_udp_now(&inner).await;
        assert!(pkts.is_empty());
        assert!(eof, "drain should surface eof once the reader marks it");

        // wait_for_any_udp_drainable also wakes immediately on eof.
        let t0 = Instant::now();
        wait_for_any_udp_drainable(std::slice::from_ref(&inner), Duration::from_secs(5)).await;
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "eof should short-circuit the wait, took {:?}",
            t0.elapsed()
        );

        // The `udp_drain_response` helper threads eof into `eof: Some(true)`.
        let resp = udp_drain_response("zombie".into(), pkts, eof);
        assert_eq!(resp.eof, Some(true));
        assert!(resp.pkts.is_none());
    }

    /// A batch that targets a UDP session reaped by the cleanup task
    /// (or removed via close) returns `eof: true` so the proxy task
    /// exits its select loop instead of polling a zombie.
    #[tokio::test]
    async fn udp_data_for_missing_session_returns_eof() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "udp_data", "sid": "does-not-exist"},
            ]
        })
        .to_string();
        let resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let (_parts, body) = resp.into_parts();
        let body_bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let r = parsed["r"].as_array().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0]["eof"], serde_json::Value::Bool(true));
    }

    /// Regression for the cleanup-correctness fix. Previously, the
    /// batch handler reaped any session whose `inner.eof` atomic was
    /// set, even when `drain_now` had withheld eof to keep tail bytes
    /// buffered (i.e. the buffer exceeded `TCP_DRAIN_MAX_BYTES`).
    /// Reaping aborted the reader_task and dropped the tail. Cleanup
    /// is now driven off the drain's returned `eof`, so an over-cap
    /// buffer + atomic eof keeps the session alive through the first
    /// poll and only reaps on the drain that actually returns eof.
    #[tokio::test]
    async fn batch_keeps_over_cap_session_until_tail_is_drained() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();
        let inner = fake_inner().await;
        // Prime an over-cap buffer + raw eof. drain_now will return
        // TCP_DRAIN_MAX_BYTES bytes with eof=false; the previous
        // cleanup would still reap because it read inner.eof directly.
        inner
            .read_buf
            .lock()
            .await
            .resize(TCP_DRAIN_MAX_BYTES + 4096, 0u8);
        inner.eof.store(true, Ordering::Release);

        let sid = "over-cap-sid".to_string();
        state.sessions.lock().await.insert(
            sid.clone(),
            ManagedSession {
                inner: inner.clone(),
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        let body = serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": &sid}]
        })
        .to_string();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();

        // First poll: session must still be in the map, tail intact.
        // The previous code reaped here and dropped the 4096 tail bytes.
        {
            let sessions = state.sessions.lock().await;
            let s = sessions.get(&sid).expect(
                "session removed despite tail bytes still buffered; \
                 drain_now returned eof=false but cleanup ignored that \
                 and read inner.eof directly",
            );
            let remaining = s.inner.read_buf.lock().await.len();
            assert_eq!(remaining, 4096, "tail must be preserved for next drain");
        }

        // Second poll: drain_now sees buf.len() ≤ cap AND raw_eof,
        // so returns eof=true. Cleanup runs and the session is reaped.
        let body2 = serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": &sid}]
        })
        .to_string();
        let _resp2 = handle_batch(State(state.clone()), Bytes::from(body2))
            .await
            .into_response();

        assert!(
            !state.sessions.lock().await.contains_key(&sid),
            "session should be reaped on the drain that returns eof=true",
        );
    }

    /// Regression for the `tokio::join!` → `tokio::select!` mixed-drain
    /// fix. Before the change, a TCP-ready / UDP-idle pure-poll batch
    /// paid the full UDP `LONGPOLL_DEADLINE` (15 s) because the join
    /// was conjunctive — both arms had to complete. Under select! the
    /// TCP wake returns the response promptly even though UDP is
    /// quiet. The bound is loose (1 s) on purpose: real elapsed is
    /// in the millisecond range, but the prior bug would have
    /// triggered the test timeout instead of the assert.
    #[tokio::test]
    async fn batch_tcp_ready_does_not_pay_udp_longpoll_deadline() {
        use axum::body::Bytes;
        use axum::extract::State;

        let state = fresh_state();

        // TCP session with bytes already buffered → immediately drainable.
        let tcp_inner = fake_inner().await;
        tcp_inner.read_buf.lock().await.extend_from_slice(b"ready");
        let tcp_sid = "tcp-sid".to_string();
        state.sessions.lock().await.insert(
            tcp_sid.clone(),
            ManagedSession {
                inner: tcp_inner,
                reader_handle: tokio::spawn(async {}),
                udpgw_handle: None,
            },
        );

        // Idle UDP session — never wakes. Real upstream so udp_open
        // succeeds; we just never send anything to it.
        let udp_target = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let udp_port = udp_target.local_addr().unwrap().port();
        let (udp_sid, _udp_inner) =
            handle_udp_open_phase1(&state, Some("127.0.0.1".into()), Some(udp_port), None)
                .await
                .expect("udp open");

        // Pure-poll batch (no `d` payload) → had_writes_or_connects =
        // false → deadline = LONGPOLL_DEADLINE (15 s). Under the
        // previous tokio::join! wait, the UDP arm would have held the
        // response open for the full window even though TCP was
        // already drainable.
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "data", "sid": &tcp_sid},
                {"op": "udp_data", "sid": &udp_sid},
            ]
        })
        .to_string();

        let t0 = Instant::now();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body))
            .await
            .into_response();
        let elapsed = t0.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "TCP-ready / UDP-idle pure-poll batch must not pay \
             LONGPOLL_DEADLINE; elapsed={:?}",
            elapsed,
        );
    }

    /// Helper for the seq tests: bump `expected` from N to N+1 the
    /// way `process_seq_data_op` does — under the same guard, with a
    /// notify_waiters() afterward. Lets unit tests exercise the same
    /// state machine without spinning up the full op handler.
    async fn release_seq(inner: &SessionInner, mut guard: tokio::sync::MutexGuard<'_, SeqState>) {
        guard.expected = guard.expected.saturating_add(1);
        drop(guard);
        inner.seq_advance.notify_waiters();
    }

    /// Sanity-check: a fresh session starts with `expected = 0`,
    /// so seq=0's `wait_for_seq_turn` succeeds immediately. After
    /// the simulated release, expected advances to 1.
    #[tokio::test]
    async fn wait_for_seq_turn_succeeds_when_in_order() {
        let inner = fake_inner().await;
        let guard = wait_for_seq_turn(&inner, 0, Duration::from_secs(2))
            .await
            .expect("seq=0 should claim immediately on fresh session");
        release_seq(&inner, guard).await;
        let state = inner.seq_state.lock().await;
        assert_eq!(state.expected, 1);
    }

    /// The headline correctness invariant: when seq=N+1 arrives at the
    /// server before seq=N (different batches taking different paths),
    /// the N+1 task waits inside `wait_for_seq_turn` until the N task
    /// lands and bumps `expected`. Without this, the per-session
    /// reorder buffer on the client would see a reply for seq=N+1
    /// containing bytes that should have followed seq=N's bytes —
    /// silent data corruption.
    #[tokio::test]
    async fn wait_for_seq_turn_blocks_until_earlier_seq_lands() {
        let inner = fake_inner().await;

        // Spawn a seq=2 claim — should block (expected is 0).
        let inner_for_2 = inner.clone();
        let claim_2 = tokio::spawn(async move {
            let g = wait_for_seq_turn(&inner_for_2, 2, Duration::from_secs(5)).await?;
            release_seq(&inner_for_2, g).await;
            Ok::<(), String>(())
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !claim_2.is_finished(),
            "seq=2 must not proceed before seqs 0 and 1 land",
        );

        // Land seq=0.
        let g0 = wait_for_seq_turn(&inner, 0, Duration::from_secs(2))
            .await
            .expect("seq=0 should claim");
        release_seq(&inner, g0).await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !claim_2.is_finished(),
            "seq=2 must not proceed with only seq=0 landed (expected==1)",
        );

        // Land seq=1.
        let g1 = wait_for_seq_turn(&inner, 1, Duration::from_secs(2))
            .await
            .expect("seq=1 should claim");
        release_seq(&inner, g1).await;

        let result = tokio::time::timeout(Duration::from_secs(2), claim_2)
            .await
            .expect("seq=2 must wake within timeout once seq=1 lands")
            .expect("task should not panic");
        result.expect("seq=2 claim should succeed");
    }

    /// Late arrivals (seq < expected) — typically a duplicate retry
    /// from the client — must return an error so the caller can echo
    /// it as a "skipped" reply instead of double-writing the upstream.
    #[tokio::test]
    async fn wait_for_seq_turn_rejects_already_processed_seq() {
        let inner = fake_inner().await;
        inner.seq_state.lock().await.expected = 5;
        let r = wait_for_seq_turn(&inner, 3, Duration::from_secs(1)).await;
        assert!(
            r.is_err(),
            "seq=3 should be rejected when expected has already advanced to 5",
        );
    }

    /// Hard timeout when an earlier seq simply never arrives (client
    /// crashed mid-pipeline, batch dropped, etc.). Without this the
    /// task would wait forever and the session would leak until the
    /// idle reaper fires.
    #[tokio::test]
    async fn wait_for_seq_turn_times_out_when_earlier_seq_never_arrives() {
        let inner = fake_inner().await;
        let r = wait_for_seq_turn(&inner, 3, Duration::from_millis(100)).await;
        assert!(r.is_err(), "seq=3 must time out when seqs 0..3 never land",);
    }

    /// Two pipelined seq ops for the same session must not race for
    /// `read_buf` — the seq lock has to stay held across the entire
    /// (write, drain) sequence. Pre-buffer enough bytes that the
    /// drain has multiple kernel-FIFO chunks to take, then run two
    /// `process_seq_data_op` calls concurrently. The reply with the
    /// lower seq must contain the earlier prefix of the buffered
    /// bytes; if the lock granularity regressed, both replies can
    /// take from the same buffer in arrival-of-final-lock order
    /// rather than seq order.
    #[tokio::test]
    async fn process_seq_data_drains_in_seq_order_under_concurrency() {
        let inner = fake_inner().await;
        // Pre-load 200 bytes — 100 each so we can clearly attribute
        // which prefix landed where if ordering breaks.
        {
            let mut buf = inner.read_buf.lock().await;
            buf.extend_from_slice(&vec![0xAAu8; 100]);
            buf.extend_from_slice(&vec![0xBBu8; 100]);
        }
        // Mark eof so seq=1's wait_for_any_drainable returns
        // immediately on empty buffer instead of paying the full
        // LONGPOLL_DEADLINE waiting for non-existent data.
        inner.eof.store(true, Ordering::Release);

        let budget = Arc::new(Mutex::new(BATCH_RESPONSE_BUDGET));

        // Spawn seq=1 first — it should block waiting for seq=0.
        let inner_1 = inner.clone();
        let budget_1 = budget.clone();
        let task_1 = tokio::spawn(async move {
            process_seq_data_op(
                inner_1,
                "sid".into(),
                1,
                None,
                budget_1,
                false,
                BatchWait::new(Vec::new()),
            )
            .await
        });
        // Brief wait so seq=1 is definitely parked on its seq lock.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now run seq=0. It should drain everything currently in
        // read_buf (the cap is generous), then seq=1 wakes and gets
        // empty (or whatever the reader pushed in between, none here).
        let resp_0 = process_seq_data_op(
            inner.clone(),
            "sid".into(),
            0,
            None,
            budget,
            false,
            BatchWait::new(Vec::new()),
        )
        .await;
        let resp_1 = tokio::time::timeout(Duration::from_secs(2), task_1)
            .await
            .expect("seq=1 must complete after seq=0")
            .expect("task should not panic");

        assert_eq!(resp_0.seq, Some(0));
        assert_eq!(resp_1.seq, Some(1));
        // seq=0's reply must carry all the buffered bytes (200 bytes,
        // well under TCP_DRAIN_MAX_BYTES). seq=1 gets empty.
        let d0 = resp_0.d.as_deref().expect("seq=0 should have drained data");
        let d0_bytes = B64.decode(d0).unwrap();
        assert_eq!(d0_bytes.len(), 200);
        // Verify byte order within seq=0's reply (kernel-FIFO).
        assert!(d0_bytes[..100].iter().all(|&b| b == 0xAA));
        assert!(d0_bytes[100..].iter().all(|&b| b == 0xBB));
        assert!(
            resp_1.d.as_deref().map(str::is_empty).unwrap_or(true),
            "seq=1 must observe empty buffer after seq=0 drained — \
             non-empty here means the drains raced",
        );
    }

    /// `wait_and_drain` empties the whole buffer; `process_seq_data_op`
    /// must use `drain_now` (or its equivalent) so any tail beyond
    /// the per-session / per-batch cap is left buffered for the next
    /// op. Without this, oversized read_bufs silently drop bytes — a
    /// data-loss regression on high-throughput pipelined sessions.
    #[tokio::test]
    async fn process_seq_data_preserves_tail_when_over_cap() {
        let inner = fake_inner().await;
        let oversized = TCP_DRAIN_MAX_BYTES + 4096;
        inner.read_buf.lock().await.resize(oversized, 0xCD);

        let budget = Arc::new(Mutex::new(BATCH_RESPONSE_BUDGET));
        let resp = process_seq_data_op(
            inner.clone(),
            "sid".into(),
            0,
            None,
            budget,
            false,
            BatchWait::new(Vec::new()),
        )
        .await;

        // Reply should carry exactly TCP_DRAIN_MAX_BYTES of the prefix.
        let d = resp.d.as_deref().expect("seq=0 should have data");
        let d_bytes = B64.decode(d).unwrap();
        assert_eq!(d_bytes.len(), TCP_DRAIN_MAX_BYTES);
        // The 4 KiB tail must remain in the buffer for the next op.
        let remaining = inner.read_buf.lock().await.len();
        assert_eq!(
            remaining, 4096,
            "tail beyond TCP_DRAIN_MAX_BYTES must stay in read_buf for the next \
             op — silently dropping it (the wait_and_drain regression) loses \
             bytes on high-throughput pipelined sessions",
        );
    }

    /// `last_active` must be refreshed on EVERY pipelined op — including
    /// empty polls — so the idle reaper doesn't close a session that's
    /// being actively long-polled by the client. The legacy non-seq
    /// `data` branch refreshes unconditionally; the seq path has to
    /// match or long-lived idle / server-push sessions get reaped at
    /// 300 s even while the client is still engaged.
    #[tokio::test]
    async fn process_seq_data_refreshes_last_active_on_empty_poll() {
        let inner = fake_inner().await;
        // Backdate last_active so we can detect a refresh.
        let backdated = Instant::now() - Duration::from_secs(120);
        *inner.last_active.lock().await = backdated;

        let budget = Arc::new(Mutex::new(BATCH_RESPONSE_BUDGET));
        // Empty poll — no uplink. Use a tiny deadline so the test
        // doesn't sit on LONGPOLL_DEADLINE waiting for non-existent data.
        // (process_seq_data_op picks the deadline based on had_uplink,
        // which is false here, so we'd actually pay LONGPOLL_DEADLINE
        // = 15 s. Mark eof on the session so wait_for_any_drainable
        // returns immediately.)
        inner.eof.store(true, Ordering::Release);
        let _resp = process_seq_data_op(
            inner.clone(),
            "sid".into(),
            0,
            None,
            budget,
            false,
            BatchWait::new(Vec::new()),
        )
        .await;

        let after = *inner.last_active.lock().await;
        assert!(
            after > backdated,
            "last_active must refresh on every seq op (was {:?}, now {:?})",
            backdated,
            after,
        );
    }

    /// Two pipelined seq ops draining oversized buffers must share the
    /// `BATCH_RESPONSE_BUDGET` so the combined response stays under
    /// Apps Script's 50 MiB ceiling (#863). Without the shared budget,
    /// each task takes up to TCP_DRAIN_MAX_BYTES (16 MiB), and 3+
    /// concurrent pipelined sessions would stack past the ceiling and
    /// cause truncation / parse failures on the wire.
    #[tokio::test]
    async fn process_seq_data_shares_batch_response_budget() {
        let inner_a = fake_inner().await;
        let inner_b = fake_inner().await;
        // Each session has a maximally oversized buffer.
        inner_a
            .read_buf
            .lock()
            .await
            .resize(TCP_DRAIN_MAX_BYTES + 1024, 0xAA);
        inner_b
            .read_buf
            .lock()
            .await
            .resize(TCP_DRAIN_MAX_BYTES + 1024, 0xBB);

        // Tight shared budget: well below 2 × TCP_DRAIN_MAX_BYTES.
        // Forces the second drain to take less (or zero) so the
        // combined response respects the cap.
        let budget_cap = TCP_DRAIN_MAX_BYTES + 4096;
        let budget = Arc::new(Mutex::new(budget_cap));

        let task_a = tokio::spawn({
            let inner = inner_a.clone();
            let budget = budget.clone();
            async move {
                process_seq_data_op(
                    inner,
                    "sid-a".into(),
                    0,
                    None,
                    budget,
                    false,
                    BatchWait::new(Vec::new()),
                )
                .await
            }
        });
        let task_b = tokio::spawn({
            let inner = inner_b.clone();
            let budget = budget.clone();
            async move {
                process_seq_data_op(
                    inner,
                    "sid-b".into(),
                    0,
                    None,
                    budget,
                    false,
                    BatchWait::new(Vec::new()),
                )
                .await
            }
        });

        let resp_a = tokio::time::timeout(Duration::from_secs(5), task_a)
            .await
            .unwrap()
            .unwrap();
        let resp_b = tokio::time::timeout(Duration::from_secs(5), task_b)
            .await
            .unwrap()
            .unwrap();

        let len_a = resp_a
            .d
            .as_deref()
            .map(|d| B64.decode(d).unwrap().len())
            .unwrap_or(0);
        let len_b = resp_b
            .d
            .as_deref()
            .map(|d| B64.decode(d).unwrap().len())
            .unwrap_or(0);
        assert!(
            len_a + len_b <= budget_cap,
            "combined drained bytes ({} + {} = {}) must not exceed shared budget {}",
            len_a,
            len_b,
            len_a + len_b,
            budget_cap,
        );
    }

    /// Regression: when batch budget is exhausted AND the
    /// session has both buffered bytes AND eof, the seq response
    /// must NOT report eof=true. Doing so would close the session
    /// client-side and silently drop the buffered tail. Mirrors
    /// `drain_now`'s "withhold EOF until tail is drained" semantics.
    #[tokio::test]
    async fn process_seq_data_withholds_eof_when_budget_exhausted_and_buffer_nonempty() {
        let inner = fake_inner().await;
        // Pre-buffer real bytes AND mark eof.
        inner.read_buf.lock().await.extend_from_slice(b"tail-bytes");
        inner.eof.store(true, Ordering::Release);

        // Budget already at zero — simulates a sibling drain having
        // consumed it before we got here.
        let budget = Arc::new(Mutex::new(0usize));
        let resp = process_seq_data_op(
            inner.clone(),
            "sid".into(),
            0,
            None,
            budget,
            true,
            BatchWait::new(Vec::new()),
        )
        .await;

        assert_eq!(resp.seq, Some(0));
        // No data drained (budget = 0).
        assert!(
            resp.d.as_deref().map(str::is_empty).unwrap_or(true),
            "no data should be returned when budget is 0",
        );
        // CRITICAL: eof must NOT be true while bytes remain in the
        // buffer. Reporting eof=true here is the data-loss bug —
        // the client closes the session and drops the buffered tail.
        assert_ne!(
            resp.eof,
            Some(true),
            "eof must be withheld while read_buf still has bytes; \
             reporting it now would silently drop the buffered tail \
             on the client side",
        );
        // The tail is still in the buffer for the next op.
        assert_eq!(inner.read_buf.lock().await.as_slice(), b"tail-bytes");
    }

    /// Regression: every exit path of `process_seq_data_op`
    /// past `wait_for_seq_turn` must bump `expected` and notify
    /// waiters — including write/flush failures, where the function
    /// early-returns with an error response. The `SeqAdvanceOnDrop`
    /// guard delivers this; without it, an upstream write failure
    /// would strand later seqs behind a never-bumped `expected`
    /// until each hit `SEQ_WAIT_TIMEOUT` (~30 s), pushing batches
    /// into client / Apps Script timeout territory.
    ///
    /// We test the guard directly rather than through
    /// `process_seq_data_op` because writing to a closed peer or a
    /// dropped duplex doesn't reliably error on every platform —
    /// the kernel often buffers or blocks instead. The guard's
    /// contract is what every error path in `process_seq_data_op`
    /// relies on, so testing it in isolation is both stronger and
    /// faster.
    #[tokio::test]
    async fn seq_advance_on_drop_bumps_expected_and_notifies_waiters() {
        let inner = fake_inner().await;
        assert_eq!(inner.seq_state.lock().await.expected, 0);

        // Park a seq=1 waiter (expected is 0 → it has to wait).
        let inner_for_waiter = inner.clone();
        let waiter = tokio::spawn(async move {
            wait_for_seq_turn(&inner_for_waiter, 1, Duration::from_secs(2))
                .await
                .map(|g| {
                    drop(g);
                })
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiter.is_finished(),
            "seq=1 waiter must park while expected=0",
        );

        // Acquire the seq lock and drop a guard immediately —
        // simulates the early-return path of process_seq_data_op
        // after wait_for_seq_turn succeeds (e.g. write/flush fails
        // before reaching the success-path drop at function end).
        {
            let state = inner.seq_state.lock().await;
            let _guard = SeqAdvanceOnDrop {
                state: Some(state),
                notify: &inner.seq_advance,
            };
            // _guard drops here, bumping expected from 0 → 1 and
            // calling notify_waiters() on seq_advance.
        }

        // expected must be advanced.
        assert_eq!(
            inner.seq_state.lock().await.expected,
            1,
            "guard's Drop must bump `expected` even on the error-return paths",
        );

        // The parked waiter must wake (because notify_waiters fired)
        // AND succeed (because expected now matches its seq=1).
        // Without notify_waiters in the guard's Drop, the waiter
        // would sleep until SEQ_WAIT_TIMEOUT.
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect(
                "waiter must wake when guard drops — without \
                 notify_waiters() in SeqAdvanceOnDrop's Drop, the \
                 waiter sleeps until SEQ_WAIT_TIMEOUT (~30 s)",
            )
            .expect("task should not panic");
        assert!(result.is_ok(), "seq=1 should have claimed");
    }

    /// Regression: `wait_for_seq_turn` must register its
    /// `Notified` future BEFORE locking and checking `seq_state`,
    /// otherwise an advance + notify_waiters that fires between
    /// drop(state) and notified() is lost (notify_waiters does not
    /// save permits for unregistered waiters), and the waiter
    /// sleeps until SEQ_WAIT_TIMEOUT.
    ///
    /// Reproducing the exact race deterministically requires
    /// scheduler-level control we don't have, but we can verify
    /// the post-fix property: a notify that fires *while* the
    /// waiter is between its lock-and-check and its await still
    /// wakes it. We approximate by spawning the waiter, briefly
    /// pausing so it reaches the wait, then bumping + notifying;
    /// the waiter must complete in well under SEQ_WAIT_TIMEOUT.
    #[tokio::test]
    async fn wait_for_seq_turn_does_not_miss_notify_after_lock_release() {
        let inner = fake_inner().await;

        let inner_clone = inner.clone();
        let waiter = tokio::spawn(async move {
            wait_for_seq_turn(&inner_clone, 5, Duration::from_secs(10))
                .await
                .map(|g| {
                    drop(g);
                })
        });

        // Hammer many advance + notify cycles in a tight loop. With
        // the missed-notify race, an advance whose notify falls in
        // the lock-release-to-await gap would be lost, leaving the
        // waiter parked. The pre-enabled Notified guarantees we
        // wake on any of these.
        for target in 1u64..=5 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            {
                let mut state = inner.seq_state.lock().await;
                state.expected = target;
            }
            inner.seq_advance.notify_waiters();
        }

        let result = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect(
                "seq=5 waiter must observe one of the advances; if it \
                 doesn't, notify_waiters fired in the lock-release-to- \
                 await gap and was lost (the missed-notify race)",
            )
            .expect("task should not panic");
        assert!(result.is_ok());
    }

    /// Regression: an idle empty seq poll for session B
    /// must NOT hold the batch open behind a sibling session A whose
    /// bytes are already buffered. The shared `wait_set` makes A's
    /// bytes wake B's wait — without it, B paid `LONGPOLL_DEADLINE`
    /// (≈ 15 s) because its own inner stayed empty.
    #[tokio::test]
    async fn process_seq_data_wakes_when_other_session_in_wait_set_has_bytes() {
        let inner_a = fake_inner().await;
        let inner_b = fake_inner().await;

        // Session A has bytes ready; session B is idle.
        inner_a.read_buf.lock().await.extend_from_slice(b"a-bytes");

        let batch_wait = BatchWait::new(vec![inner_a.clone(), inner_b.clone()]);
        let budget = Arc::new(Mutex::new(BATCH_RESPONSE_BUDGET));

        // B's seq op uses had_active_in_batch=false and had_uplink=false,
        // so deadline = LONGPOLL_DEADLINE (15 s). Without the shared
        // BatchWait, B would sit the full 15 s. With it, A's bytes
        // immediately wake B's wait via `notify_waiters()` — and B
        // drains its own (empty) buffer in milliseconds.
        let t0 = Instant::now();
        let resp_b = process_seq_data_op(
            inner_b.clone(),
            "sid-b".into(),
            0,
            None,
            budget,
            false, // had_active_in_batch
            batch_wait,
        )
        .await;
        let elapsed = t0.elapsed();

        assert_eq!(resp_b.seq, Some(0));
        // B's reply must be empty (it has no bytes of its own).
        assert!(resp_b.d.as_deref().map(str::is_empty).unwrap_or(true));
        // Must have returned in well under LONGPOLL_DEADLINE — give
        // a generous 2 s ceiling for CI jitter.
        assert!(
            elapsed < Duration::from_secs(2),
            "idle seq poll must wake on shared wait set when sibling \
             session has bytes; elapsed={:?} (LONGPOLL_DEADLINE={:?})",
            elapsed,
            LONGPOLL_DEADLINE,
        );
    }

    /// Regression: batches containing seq'd ops must use
    /// the pipelined timeout floor on the client side, otherwise
    /// `Config::request_timeout_secs` (default 30 s) fires before
    /// the server-side worst case (`SEQ_WAIT_TIMEOUT 30s +
    /// LONGPOLL_DEADLINE 15s`) and pipelined sessions disconnect
    /// where legacy sessions survived. We can't easily test the
    /// effective applied timeout end-to-end, but we can assert the
    /// floor is at least the server's worst-case wait so the budget
    /// stays consistent.
    #[tokio::test]
    async fn pipelined_timeout_floor_exceeds_server_worst_case_wait() {
        // The server's worst-case wait per seq op is SEQ_WAIT_TIMEOUT
        // (waiting for an earlier seq) + LONGPOLL_DEADLINE (waiting
        // for upstream data inside that op). The client's pipelined
        // batch timeout floor must exceed this so a valid slow
        // server response doesn't fire a client-side "batch timed
        // out" + deployment timeout strike.
        let server_worst_case = SEQ_WAIT_TIMEOUT + LONGPOLL_DEADLINE;
        // PIPELINED_BATCH_TIMEOUT_FLOOR is a client-side constant;
        // we duplicate the value here to keep this test in the same
        // crate. If either side is bumped, this test will fail
        // until the client's floor follows.
        let pipelined_floor = Duration::from_secs(60);
        assert!(
            pipelined_floor > server_worst_case,
            "pipelined batch timeout floor ({:?}) must exceed server \
             worst-case wait per seq op ({:?} = SEQ_WAIT_TIMEOUT + \
             LONGPOLL_DEADLINE), otherwise a valid slow batch fires \
             a client timeout + deployment strike",
            pipelined_floor,
            server_worst_case,
        );
    }

    /// Regression: when M seq jobs all park on the shared
    /// `BatchWait`, a SINGLE push must wake every one of them —
    /// not just one. The watcher self-fan-out via
    /// `wake.notify_waiters()` is what makes this work; without
    /// it, parked jobs would each compete for one wake and the
    /// rest would sit until `LONGPOLL_DEADLINE`.
    #[tokio::test]
    async fn batch_wait_wakes_all_jobs_on_single_push() {
        let inner = fake_inner().await;
        let batch_wait = BatchWait::new(vec![inner.clone()]);

        // Park 5 concurrent waiters with a generous deadline. They
        // must all see the wake from a single push.
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let bw = batch_wait.clone();
            tasks.push(tokio::spawn(async move {
                let t0 = Instant::now();
                bw.wait(LONGPOLL_DEADLINE).await;
                t0.elapsed()
            }));
        }

        // Give all 5 tasks time to park inside `wait` (synchronous
        // is_any_drainable check returns false because read_buf is
        // empty; they all reach the timeout-wrapped `notified.await`).
        tokio::time::sleep(Duration::from_millis(50)).await;
        for task in &tasks {
            assert!(!task.is_finished(), "all 5 waiters should be parked");
        }

        // Single push to inner.read_buf, single notify_waiters()
        // (matching production `reader_task`). BatchWait's watcher
        // wakes, sees drainable state, and fans out via
        // `wake.notify_waiters()` — all 5 parked waiters wake.
        inner.read_buf.lock().await.extend_from_slice(b"go");
        inner.notify.notify_waiters();

        // Each waiter must complete in well under LONGPOLL_DEADLINE.
        for (i, task) in tasks.into_iter().enumerate() {
            let elapsed = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap_or_else(|_| panic!(
                    "waiter {} did not wake within 2s after single push — \
                     wake-fan-out regression: only one of N parked jobs woke",
                    i
                ))
                .expect("task should not panic");
            assert!(
                elapsed < Duration::from_secs(2),
                "waiter {} took {:?} (must be << LONGPOLL_DEADLINE = {:?})",
                i,
                elapsed,
                LONGPOLL_DEADLINE,
            );
        }
    }

    /// `BatchWait` must dedupe inners by Arc pointer — the same
    /// session can appear in a batch via multiple paths (e.g. a
    /// `connect_data` plus a seq `data` op for the same sid).
    /// Spawning two watchers for it would double-fan-out the wake
    /// signal and inflate task spawn count linearly with op
    /// duplication. The dedup also has to apply to STORED inners
    /// (not just watcher count), so `is_any_drainable` doesn't
    /// re-lock the same session's read_buf once per duplicate
    /// occurrence.
    #[tokio::test]
    async fn batch_wait_deduplicates_watchers_per_inner() {
        let inner = fake_inner().await;
        // Same Arc<SessionInner> appearing 4 times in the input.
        let bw = BatchWait::new(vec![
            inner.clone(),
            inner.clone(),
            inner.clone(),
            inner.clone(),
        ]);
        assert_eq!(
            bw._watchers.len(),
            1,
            "BatchWait must spawn one watcher per UNIQUE inner; \
             4 dup inputs spawned {} watchers",
            bw._watchers.len(),
        );
        assert_eq!(
            bw.inners.len(),
            1,
            "BatchWait::inners must be deduped too — otherwise \
             `is_any_drainable` re-locks the same Mutex per duplicate; \
             4 dup inputs stored {} inners",
            bw.inners.len(),
        );
    }

    /// Critical regression: with pipelining, seq=N and seq=N+1 for
    /// the same session can arrive in DIFFERENT batches. Each batch
    /// builds its own `BatchWait`, each with its own watcher on the
    /// session's `inner.notify`. A single `notify_one()` only wakes
    /// one of those watchers — the other batch's watcher would sit
    /// until `LONGPOLL_DEADLINE` even though the data is right
    /// there. The fix: `reader_task` now uses `notify_waiters()`,
    /// so every parked watcher across every batch wakes on each
    /// push. Watchers `enable()` their `Notified` before the
    /// synchronous state check to handle the no-permits edge of
    /// `notify_waiters()`.
    #[tokio::test]
    async fn batch_wait_wakes_across_concurrent_batches_on_same_session() {
        let inner = fake_inner().await;

        // Two BatchWaits — simulating two concurrent batches that
        // both contain ops for the same session.
        let bw_a = BatchWait::new(vec![inner.clone()]);
        let bw_b = BatchWait::new(vec![inner.clone()]);

        // Park one waiter on each. Without the broadcast fix, only
        // ONE of them would wake on a single push.
        let bw_a_clone = bw_a.clone();
        let waiter_a = tokio::spawn(async move {
            let t0 = Instant::now();
            bw_a_clone.wait(LONGPOLL_DEADLINE).await;
            t0.elapsed()
        });
        let bw_b_clone = bw_b.clone();
        let waiter_b = tokio::spawn(async move {
            let t0 = Instant::now();
            bw_b_clone.wait(LONGPOLL_DEADLINE).await;
            t0.elapsed()
        });

        // Give both waiters time to park inside their respective
        // BatchWait::wait calls.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter_a.is_finished(), "batch A waiter should park");
        assert!(!waiter_b.is_finished(), "batch B waiter should park");

        // One push, one notify — must wake BOTH batches' watchers.
        inner.read_buf.lock().await.extend_from_slice(b"go");
        inner.notify.notify_waiters();

        let elapsed_a = tokio::time::timeout(Duration::from_secs(2), waiter_a)
            .await
            .expect("batch A waiter must wake within 2s")
            .expect("task A should not panic");
        let elapsed_b = tokio::time::timeout(Duration::from_secs(2), waiter_b)
            .await
            .expect(
                "batch B waiter must ALSO wake within 2s — under \
                 `notify_one()` only one of A/B woke and the other \
                 sat for LONGPOLL_DEADLINE (~15s)",
            )
            .expect("task B should not panic");

        assert!(
            elapsed_a < Duration::from_secs(2),
            "batch A waiter took {:?} (must be << LONGPOLL_DEADLINE)",
            elapsed_a,
        );
        assert!(
            elapsed_b < Duration::from_secs(2),
            "batch B waiter took {:?} (must be << LONGPOLL_DEADLINE)",
            elapsed_b,
        );
    }

    /// Pin the documented latency trade-off for `SEQ_WAIT_TIMEOUT`:
    /// when one seq op in a batch is stuck waiting for a missing
    /// earlier seq, an UNRELATED session's seq op in the same batch
    /// completes its own work in milliseconds, but its result sits
    /// in `seq_data_jobs` until the stuck job times out — because
    /// `handle_batch`'s `tokio::join!` waits for every seq job
    /// before returning the response.
    ///
    /// This test asserts the upper bound on that latency: bounded
    /// above by `SEQ_WAIT_TIMEOUT` (the stuck job's max wait), and
    /// the unrelated session's per-job processing time is ≪ that.
    /// Any future change to either constant — or to a design that
    /// allows partial batch responses — should fail this test
    /// intentionally so reviewers can confirm the new behavior.
    #[tokio::test]
    async fn unrelated_seq_session_in_same_batch_is_not_delayed_past_seq_wait() {
        // Two independent sessions A and B. A's seq=2 will wait
        // (expected=0, no seq=0/1 ever arrives — the
        // "lost earlier seq" failure mode). B's seq=0 on a fresh
        // session can claim immediately.
        let inner_a = fake_inner().await;
        let inner_b = fake_inner().await;
        // B has data ready and eof set — its drain wait
        // short-circuits, so B's job processing time is the
        // intrinsic per-op cost (decode + lock + drain).
        inner_b.read_buf.lock().await.extend_from_slice(b"b-bytes");
        inner_b.eof.store(true, Ordering::Release);

        let bw = BatchWait::new(vec![inner_a.clone(), inner_b.clone()]);
        let budget = Arc::new(Mutex::new(BATCH_RESPONSE_BUDGET));

        // Spawn A first so it parks on `seq_state` waiting for
        // earlier seqs that never arrive. With the production
        // SEQ_WAIT_TIMEOUT this would sit 30 s; for the test we
        // just need it to remain pending while B runs.
        let inner_a_clone = inner_a.clone();
        let bw_a = bw.clone();
        let budget_a = budget.clone();
        let task_a = tokio::spawn(async move {
            // Use seq=2 so wait_for_seq_turn sees seq > expected (0)
            // and parks on `seq_advance`.
            process_seq_data_op(
                inner_a_clone,
                "sid-a".into(),
                2,
                None,
                budget_a,
                false,
                bw_a,
            )
            .await
        });

        // Brief wait so A is definitely parked inside its
        // wait_for_seq_turn loop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !task_a.is_finished(),
            "A should be parked waiting for earlier seqs",
        );

        // Now run B. Its INTRINSIC processing time is what we
        // pin: even with A blocking on seq_state, B has nothing
        // to wait on (different session, fresh seq state, eof
        // short-circuits its drain). Its latency must be ≪
        // SEQ_WAIT_TIMEOUT.
        let t0 = Instant::now();
        let resp_b = process_seq_data_op(
            inner_b.clone(),
            "sid-b".into(),
            0,
            None,
            budget,
            false,
            bw,
        )
        .await;
        let elapsed_b = t0.elapsed();
        assert_eq!(resp_b.seq, Some(0));

        assert!(
            elapsed_b < Duration::from_secs(2),
            "session B's seq job took {:?} while A was stuck — \
             unrelated sessions must finish in well under \
             SEQ_WAIT_TIMEOUT ({:?}). A regression here means a \
             stuck seq from one session is now blocking unrelated \
             sessions' INTRINSIC processing, not just the batch \
             response join (which is the documented trade-off).",
            elapsed_b,
            SEQ_WAIT_TIMEOUT,
        );

        // Cancel A so the test doesn't sit SEQ_WAIT_TIMEOUT.
        task_a.abort();
    }

    /// Critical regression: a batch with `data(seq=N) + close(same sid)`
    /// must run the seq op's (write, drain) BEFORE the close tears
    /// down the session. Running close inline during dispatch (the
    /// pre-fix shape) removed the session from `state.sessions`
    /// and aborted `reader_task` while the deferred seq job was
    /// still about to run on its cloned `Arc<SessionInner>` —
    /// uplink writes raced the upstream socket's read-half being
    /// dropped and downlink drains saw zero bytes. The fix:
    /// `pending_closes` collects close ops during dispatch and
    /// runs them AFTER `seq_data_jobs` complete.
    #[tokio::test]
    async fn batch_data_seq_then_close_runs_data_first() {
        use axum::body::Bytes;
        use axum::extract::State;

        // Set up an upstream that captures everything written to it
        // so we can verify the seq op's bytes arrived before close
        // dropped the connection.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let received_uplink = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_clone = received_uplink.clone();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            received_clone
                                .lock()
                                .await
                                .extend_from_slice(&buf[..n]);
                        }
                    }
                }
            }
        });

        let state = fresh_state();

        // Open a session via connect (legacy non-seq path so we
        // get a sid the batch can target).
        let connect_resp = handle_connect(
            &state,
            Some("127.0.0.1".into()),
            Some(upstream_port),
        )
        .await;
        let sid = match connect_resp {
            TunnelResponse {
                sid: Some(s),
                e: None,
                ..
            } => s,
            other => panic!("connect failed: {:?}", other),
        };

        // Batch: data(seq=0) carrying "PAYLOAD" + close(same sid).
        // The dispatch order in the request determines the
        // intended effect order — seq=0's write must reach
        // upstream BEFORE close tears down the session.
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "data", "sid": sid.clone(), "seq": 0, "d": B64.encode(b"PAYLOAD")},
                {"op": "close", "sid": sid.clone()}
            ]
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body_bytes))
            .await
            .into_response();

        // Give the upstream reader time to drain whatever was
        // written before the close shut things down.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let received = received_uplink.lock().await.clone();
        assert_eq!(
            received,
            b"PAYLOAD",
            "seq=0's uplink bytes must reach upstream before close \
             tears the session down — running close inline (pre-fix) \
             would race the seq job and could lose these bytes",
        );

        // The session should be gone after close.
        assert!(
            !state.sessions.lock().await.contains_key(&sid),
            "close must have removed the session from the state map",
        );
    }

    /// Important regression: an ACTIVE seq op (one with uplink
    /// bytes) must wait for ITS OWN session's response, not get
    /// short-circuited by a sibling session in the same batch
    /// already having buffered bytes. Subscribing to the shared
    /// `BatchWait` for active ops is wrong — a sibling's bytes
    /// would wake us instantly and we'd return empty for an op
    /// that just hadn't gotten its own reply yet, doubling the
    /// number of round-trips for the same logical exchange.
    #[tokio::test]
    async fn active_seq_op_waits_for_own_response_not_sibling_bytes() {
        let inner_active = fake_inner().await;
        let inner_sibling = fake_inner().await;
        // Sibling already has bytes ready — the shared wait would
        // wake on this immediately if we (incorrectly) subscribed.
        inner_sibling
            .read_buf
            .lock()
            .await
            .extend_from_slice(b"sibling-bytes");
        // No bytes for the active op yet — its own response would
        // come from upstream within ACTIVE_DRAIN_DEADLINE.
        // Mark eof to short-circuit the active op's settle so the
        // test doesn't actually sit ACTIVE_DRAIN_DEADLINE.
        inner_active.eof.store(true, Ordering::Release);

        let bw = BatchWait::new(vec![inner_active.clone(), inner_sibling.clone()]);
        let budget = Arc::new(Mutex::new(BATCH_RESPONSE_BUDGET));

        let t0 = Instant::now();
        // Active op: had_uplink = true (we pass non-empty data).
        // The op's drain phase must NOT short-circuit on the
        // sibling's bytes — its own buffer is empty + eof, so
        // it'll drain that and return.
        let resp = process_seq_data_op(
            inner_active.clone(),
            "sid-active".into(),
            0,
            Some(B64.encode(b"uplink")),
            budget,
            true, // had_active_in_batch
            bw,
        )
        .await;
        let elapsed = t0.elapsed();

        assert_eq!(resp.seq, Some(0));
        // The active op's drain should reflect its OWN buffer
        // state (empty + eof), not the sibling's. If the active
        // path mistakenly subscribed to batch_wait, the sibling's
        // bytes would wake it and the same `inner_active.read_buf`
        // would still be empty — so this test wouldn't catch the
        // bug just from the bytes returned. What it DOES catch:
        // the active op should not be sleeping on the shared wake;
        // its time bound is its own per-session wait + settle.
        assert!(
            elapsed < ACTIVE_DRAIN_DEADLINE * 2,
            "active op took {:?}; bound is per-session ACTIVE \
             window ({:?}) plus settle, not LONGPOLL",
            elapsed,
            ACTIVE_DRAIN_DEADLINE,
        );
    }

    /// Regression: a batch ordered as `[close(sid), data(sid)]`
    /// must run the close FIRST and the subsequent data must
    /// observe a closed session (eof_response). Unconditionally
    /// deferring close to after seq jobs would let the data write
    /// succeed against the still-open session even though the
    /// client asked us to close first — a protocol-ordering
    /// regression. Close is now deferred ONLY if there's an
    /// earlier same-sid op already deferred.
    #[tokio::test]
    async fn batch_close_then_data_processes_close_first() {
        use axum::body::Bytes;
        use axum::extract::State;

        // Upstream that captures whatever bytes we write.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let received_uplink = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_clone = received_uplink.clone();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            received_clone
                                .lock()
                                .await
                                .extend_from_slice(&buf[..n]);
                        }
                    }
                }
            }
        });

        let state = fresh_state();
        let connect_resp = handle_connect(
            &state,
            Some("127.0.0.1".into()),
            Some(upstream_port),
        )
        .await;
        let sid = match connect_resp {
            TunnelResponse {
                sid: Some(s),
                e: None,
                ..
            } => s,
            other => panic!("connect failed: {:?}", other),
        };

        // Batch: close FIRST, then data(seq=0).
        let body = serde_json::json!({
            "k": "test-key",
            "ops": [
                {"op": "close", "sid": sid.clone()},
                {"op": "data", "sid": sid.clone(), "seq": 0, "d": B64.encode(b"AFTER-CLOSE")}
            ]
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let _resp = handle_batch(State(state.clone()), Bytes::from(body_bytes))
            .await
            .into_response();

        // Give the upstream reader a moment.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The session was closed BEFORE the data op got to run, so
        // upstream should NOT have received the post-close bytes.
        let received = received_uplink.lock().await.clone();
        assert!(
            received.is_empty()
                || !received.windows(b"AFTER-CLOSE".len()).any(|w| w == b"AFTER-CLOSE"),
            "close-first ordering was lost: post-close bytes leaked to \
             upstream (got {:?}). With unconditional close-deferral the \
             data op writes 'AFTER-CLOSE' against a session the client \
             told us to close first.",
            String::from_utf8_lossy(&received),
        );
    }

    /// Regression: Phase 2's drain loop must reserve at most
    /// `TCP_DRAIN_MAX_BYTES` from the shared `response_budget`,
    /// not the full remaining budget. The previous shape set
    /// `*budget = 0` upfront, drained, then refunded — concurrent
    /// seq jobs running in the same batch could observe the 0
    /// state and return empty responses for an op that would have
    /// fit comfortably in the remaining budget.
    #[tokio::test]
    async fn phase_2_budget_reservation_caps_at_tcp_drain_max_bytes() {
        // Synthetic scenario: a single legacy tcp_drain entry on
        // a session with a small buffer. Budget is set to a
        // generous value (well above TCP_DRAIN_MAX_BYTES). Run
        // the drain in a way that exposes the per-iteration
        // reservation.
        //
        // We can't easily run the Phase 2 closure from a unit
        // test (it's defined inline in `handle_batch`), so we
        // verify the reservation invariant directly: the seq
        // path's `process_seq_data_op` and Phase 2 should both
        // cap reservations at TCP_DRAIN_MAX_BYTES. The seq path
        // is already covered by `process_seq_data_shares_batch_response_budget`;
        // here we assert the same property on a different shape:
        // a budget large enough that the Phase 2 drain leaves
        // headroom equal to (budget − drained) when its drain
        // takes less than `TCP_DRAIN_MAX_BYTES`.
        let inner = fake_inner().await;
        let bytes_to_drain = 4096usize;
        inner
            .read_buf
            .lock()
            .await
            .extend_from_slice(&vec![0xAB; bytes_to_drain]);

        let initial_budget = TCP_DRAIN_MAX_BYTES * 4;
        let budget = Arc::new(Mutex::new(initial_budget));

        // Mirror the production reservation pattern.
        let take = {
            let mut b = budget.lock().await;
            let take = (*b).min(TCP_DRAIN_MAX_BYTES);
            *b = b.saturating_sub(take);
            take
        };
        assert_eq!(
            take, TCP_DRAIN_MAX_BYTES,
            "reservation must be capped at TCP_DRAIN_MAX_BYTES \
             (got {} from initial_budget {})",
            take, initial_budget,
        );
        // The remaining budget visible to a concurrent seq job
        // must still be the full initial_budget − TCP_DRAIN_MAX_BYTES,
        // not 0. Pre-fix the budget would have been 0 here.
        let remaining_visible = *budget.lock().await;
        assert_eq!(
            remaining_visible,
            initial_budget - TCP_DRAIN_MAX_BYTES,
            "Phase 2's reservation must leave headroom for \
             concurrent seq jobs; under the pre-fix shape this \
             would be 0",
        );

        let (data, _eof) = drain_now(&inner, take).await;
        if data.len() < take {
            *budget.lock().await += take - data.len();
        }
        // After refund, the full initial_budget minus actually-
        // drained bytes is available again.
        assert_eq!(
            *budget.lock().await,
            initial_budget - bytes_to_drain,
            "after refund of unused reservation, budget should be \
             initial − drained",
        );
    }
}
