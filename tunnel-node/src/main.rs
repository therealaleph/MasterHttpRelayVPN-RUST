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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinSet;

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

/// After the first session in an active batch wakes the wait, we sleep
/// briefly so neighboring sessions whose responses land just after the
/// first one don't get reported empty and pay an extra round-trip. Only
/// applies to active batches — for long-poll batches the wake event IS
/// the data we want, so we deliver it immediately.
///
/// 30 ms is much shorter than the legacy two-pass retry (150 + 200 ms)
/// but covers the typical case of co-located upstreams whose RTTs
/// cluster within a few tens of ms of each other.
const STRAGGLER_SETTLE: Duration = Duration::from_millis(30);

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
///   * Lower (e.g. 2 s) — interactive shells / typing-burst flows feel
///     snappier, but push-only sessions pay more empty round-trips.
///   * Higher (e.g. 20 s) — push delivery is near-RTT and round-trip
///     count is minimal, but a thinking pause between keystrokes can
///     tax the next keystroke by up to the chosen value.
///
/// 5 s is a middle ground: a typing user pausing mid-thought pays at
/// most a 5 s nudge before their next keystroke flows, while idle
/// sessions still get the bulk of the long-poll benefit. Must also
/// stay safely below the client's `BATCH_TIMEOUT` (30 s) and Apps
/// Script's UrlFetch ceiling (~60 s).
const LONGPOLL_DEADLINE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct SessionInner {
    writer: Mutex<OwnedWriteHalf>,
    read_buf: Mutex<Vec<u8>>,
    eof: AtomicBool,
    last_active: Mutex<Instant>,
    /// Fired by `reader_task` whenever new bytes land in `read_buf` or the
    /// upstream socket closes. `wait_for_any_drainable` listens on this
    /// to wake the drain phase as soon as any session has something to
    /// ship, replacing the old fixed-sleep heuristic.
    notify: Notify,
}

struct ManagedSession {
    inner: Arc<SessionInner>,
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
        writer: Mutex::new(writer),
        read_buf: Mutex::new(Vec::with_capacity(32768)),
        eof: AtomicBool::new(false),
        last_active: Mutex::new(Instant::now()),
        notify: Notify::new(),
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(reader_task(reader, inner_ref));

    Ok(ManagedSession { inner, reader_handle })
}

async fn reader_task(mut reader: OwnedReadHalf, session: Arc<SessionInner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                session.eof.store(true, Ordering::Release);
                session.notify.notify_one();
                break;
            }
            Ok(n) => {
                // Extend the buffer before notifying. The MutexGuard is
                // dropped at the end of the statement, *before* the
                // notify_one call below, so any waiter that wakes on the
                // notify and then locks read_buf can immediately observe
                // the new bytes — no torn read where the wake fires but
                // the buffer still looks empty. Notify::notify_one also
                // stores a permit if no waiter is currently registered,
                // so we never lose an edge across the spawn race in
                // wait_for_any_drainable.
                session.read_buf.lock().await.extend_from_slice(&buf[..n]);
                session.notify.notify_one();
            }
            Err(_) => {
                session.eof.store(true, Ordering::Release);
                session.notify.notify_one();
                break;
            }
        }
    }
}

/// Drain whatever is currently buffered — no waiting.
/// Used by batch mode where we poll frequently.
async fn drain_now(session: &SessionInner) -> (Vec<u8>, bool) {
    let mut buf = session.read_buf.lock().await;
    let data = std::mem::take(&mut *buf);
    let eof = session.eof.load(Ordering::Acquire);
    (data, eof)
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
async fn wait_for_any_drainable(inners: &[Arc<SessionInner>], deadline: Duration) {
    if inners.is_empty() {
        return;
    }

    // One watcher per session. Each loops until it observes real state
    // (eof set or buffer non-empty) before signaling — see the
    // race-safety note on `wait_for_any_drainable` for why. We abort the
    // watchers on return; the only state they hold is a notify
    // subscription, so abort is clean.
    let (tx, mut rx) = mpsc::channel::<()>(1);
    let mut watchers = Vec::with_capacity(inners.len());
    for inner in inners {
        let inner = inner.clone();
        let tx = tx.clone();
        watchers.push(tokio::spawn(async move {
            loop {
                inner.notify.notified().await;
                if inner.eof.load(Ordering::Acquire) {
                    break;
                }
                if !inner.read_buf.lock().await.is_empty() {
                    break;
                }
                // Stale permit (notify fired but state didn't change in
                // an observable way — e.g., bytes were already drained
                // by a prior batch). Loop back and wait for a real
                // notify, don't wake the caller.
            }
            let _ = tx.try_send(());
        }));
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

    for w in &watchers {
        w.abort();
    }
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
        if is_eof { break; }
        if Instant::now() >= deadline { break; }
        if ever_had_data && last_growth.elapsed() > Duration::from_millis(100) { break; }
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
    auth_key: String,
}

// ---------------------------------------------------------------------------
// Protocol types — single op (backward compat)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TunnelRequest {
    k: String,
    op: String,
    #[serde(default)] host: Option<String>,
    #[serde(default)] port: Option<u16>,
    #[serde(default)] sid: Option<String>,
    #[serde(default)] data: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct TunnelResponse {
    #[serde(skip_serializing_if = "Option::is_none")] sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] code: Option<String>,
}

impl TunnelResponse {
    fn error(msg: impl Into<String>) -> Self {
        Self { sid: None, d: None, eof: None, e: Some(msg.into()), code: None }
    }
    fn unsupported_op(op: &str) -> Self {
        Self {
            sid: None, d: None, eof: None,
            e: Some(format!("unknown op: {}", op)),
            code: Some(CODE_UNSUPPORTED_OP.into()),
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
    #[serde(default)] sid: Option<String>,
    #[serde(default)] host: Option<String>,
    #[serde(default)] port: Option<u16>,
    #[serde(default)] d: Option<String>, // base64 data
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
) -> Json<TunnelResponse> {
    if req.k != state.auth_key {
        return Json(TunnelResponse::error("unauthorized"));
    }
    match req.op.as_str() {
        "connect" => Json(handle_connect(&state, req.host, req.port).await),
        "connect_data" => {
            Json(handle_connect_data_single(&state, req.host, req.port, req.data).await)
        }
        "data" => Json(handle_data_single(&state, req.sid, req.data).await),
        "close" => Json(handle_close(&state, req.sid).await),
        other => Json(TunnelResponse::unsupported_op(other)),
    }
}

// ---------------------------------------------------------------------------
// Batch handler
// ---------------------------------------------------------------------------

async fn handle_batch(
    State(state): State<AppState>,
    body: Bytes,
) -> impl IntoResponse {
    // Decompress if gzipped
    let json_bytes = if body.starts_with(&[0x1f, 0x8b]) {
        match decompress_gzip(&body) {
            Ok(b) => b,
            Err(e) => {
                let resp = serde_json::to_vec(&BatchResponse {
                    r: vec![TunnelResponse::error(format!("gzip decode: {}", e))],
                }).unwrap_or_default();
                return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], resp);
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
            }).unwrap_or_default();
            return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], resp);
        }
    };

    if req.k != state.auth_key {
        let resp = serde_json::to_vec(&BatchResponse {
            r: vec![TunnelResponse::error("unauthorized")],
        }).unwrap_or_default();
        return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], resp);
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
    let mut data_ops: Vec<(usize, String)> = Vec::new(); // (index, sid) for data ops needing drain
    // True iff the batch contained any op that performed a real action
    // upstream — a new connection or a non-empty data write. A batch of
    // only empty "data" polls (and possibly closes) leaves this false and
    // qualifies for long-poll behavior in phase 2.
    let mut had_writes_or_connects = false;

    enum NewConn {
        Connect(TunnelResponse),
        ConnectData(Result<String, TunnelResponse>),
    }
    let mut new_conn_jobs: JoinSet<(usize, NewConn)> = JoinSet::new();

    for (i, op) in req.ops.iter().enumerate() {
        match op.op.as_str() {
            "connect" => {
                had_writes_or_connects = true;
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                new_conn_jobs.spawn(async move {
                    (i, NewConn::Connect(handle_connect(&state, host, port).await))
                });
            }
            "connect_data" => {
                had_writes_or_connects = true;
                let state = state.clone();
                let host = op.host.clone();
                let port = op.port;
                let d = op.d.clone();
                new_conn_jobs.spawn(async move {
                    // Drop the returned Arc<SessionInner>: phase 2 below
                    // re-looks up each sid under one sessions-map lock,
                    // which is cheap. The Arc return is a convenience for
                    // the single-op path only.
                    let r = handle_connect_data_phase1(&state, host, port, d)
                        .await
                        .map(|(sid, _inner)| sid);
                    (i, NewConn::ConnectData(r))
                });
            }
            "data" => {
                let sid = match &op.sid {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => { results.push((i, TunnelResponse::error("missing sid"))); continue; }
                };

                // Write outbound data
                let sessions = state.sessions.lock().await;
                if let Some(session) = sessions.get(&sid) {
                    *session.inner.last_active.lock().await = Instant::now();
                    if let Some(ref data_b64) = op.d {
                        if !data_b64.is_empty() {
                            had_writes_or_connects = true;
                            if let Ok(bytes) = B64.decode(data_b64) {
                                if !bytes.is_empty() {
                                    let mut w = session.inner.writer.lock().await;
                                    let _ = w.write_all(&bytes).await;
                                    let _ = w.flush().await;
                                }
                            }
                        }
                    }
                    drop(sessions);
                    data_ops.push((i, sid));
                } else {
                    drop(sessions);
                    results.push((i, TunnelResponse {
                        sid: Some(sid), d: None, eof: Some(true), e: None, code: None,
                    }));
                }
            }
            "close" => {
                let r = handle_close(&state, op.sid.clone()).await;
                results.push((i, r));
            }
            other => {
                results.push((i, TunnelResponse::unsupported_op(other)));
            }
        }
    }

    // Await all concurrent connect / connect_data jobs. For connect_data,
    // successful ones join the data-drain set in phase 2; plain connects
    // go straight to results because they have no initial data to drain.
    while let Some(join) = new_conn_jobs.join_next().await {
        match join {
            Ok((i, NewConn::Connect(r))) => results.push((i, r)),
            Ok((i, NewConn::ConnectData(Ok(sid)))) => data_ops.push((i, sid)),
            Ok((i, NewConn::ConnectData(Err(r)))) => results.push((i, r)),
            Err(e) => {
                tracing::error!("new-connection task panicked: {}", e);
            }
        }
    }

    // Phase 2: signal-driven wait for any session to have data (or hit
    // EOF), then drain everyone in a single pass. The deadline is
    // adaptive:
    //   * `ACTIVE_DRAIN_DEADLINE` (~350 ms) when the batch had real work
    //     — typical responses arrive in ms and `wait_for_any_drainable`
    //     returns on the first notify. After the first wake we settle
    //     for `STRAGGLER_SETTLE` so neighboring sessions whose replies
    //     land just behind the first one don't get reported empty.
    //   * `LONGPOLL_DEADLINE` when the batch is a pure poll — no writes,
    //     no new connections. The response is held open until upstream
    //     pushes data, turning idle sessions into a true long-poll
    //     without paying per-poll latency. No straggler settle here:
    //     the wake event IS the data the client wants, so deliver it
    //     immediately.
    if !data_ops.is_empty() {
        let deadline = if had_writes_or_connects {
            ACTIVE_DRAIN_DEADLINE
        } else {
            LONGPOLL_DEADLINE
        };

        // Snapshot SessionInner Arcs under a single lock so we don't
        // hold the sessions-map lock across the await.
        let inners: Vec<Arc<SessionInner>> = {
            let sessions = state.sessions.lock().await;
            data_ops
                .iter()
                .filter_map(|(_, sid)| sessions.get(sid).map(|s| s.inner.clone()))
                .collect()
        };

        let wait_start = Instant::now();
        wait_for_any_drainable(&inners, deadline).await;

        // Straggler settle: only for active batches, only if we woke
        // early (didn't hit the deadline). Capped by the remaining
        // deadline budget — `saturating_sub` so a future refactor that
        // ever lets `elapsed > deadline` slip through can't underflow.
        if had_writes_or_connects {
            let remaining = deadline.saturating_sub(wait_start.elapsed());
            if !remaining.is_zero() {
                tokio::time::sleep(STRAGGLER_SETTLE.min(remaining)).await;
            }
        }

        // Single drain pass for all sessions in this batch.
        {
            let sessions = state.sessions.lock().await;
            for (i, sid) in &data_ops {
                if let Some(session) = sessions.get(sid) {
                    let (data, eof) = drain_now(&session.inner).await;
                    results.push((*i, TunnelResponse {
                        sid: Some(sid.clone()),
                        d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
                        eof: Some(eof), e: None, code: None,
                    }));
                } else {
                    results.push((*i, TunnelResponse {
                        sid: Some(sid.clone()), d: None, eof: Some(true), e: None, code: None,
                    }));
                }
            }
        }

        // Clean up eof sessions
        let mut sessions = state.sessions.lock().await;
        for (_, sid) in &data_ops {
            if let Some(s) = sessions.get(sid) {
                if s.inner.eof.load(Ordering::Acquire) {
                    if let Some(s) = sessions.remove(sid) {
                        s.reader_handle.abort();
                        tracing::info!("session {} closed by remote (batch)", sid);
                    }
                }
            }
        }
    }

    // Sort results by original index and build response
    results.sort_by_key(|(i, _)| *i);
    let batch_resp = BatchResponse {
        r: results.into_iter().map(|(_, r)| r).collect(),
    };

    let json = serde_json::to_vec(&batch_resp).unwrap_or_default();
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json)
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

async fn handle_connect(state: &AppState, host: Option<String>, port: Option<u16>) -> TunnelResponse {
    let (host, port) = match validate_host_port(host, port) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let session = match create_session(&host, port).await {
        Ok(s) => s,
        Err(e) => return TunnelResponse::error(format!("connect failed: {}", e)),
    };
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{}", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    TunnelResponse { sid: Some(sid), d: None, eof: Some(false), e: None, code: None }
}

/// Open a session and write the client's first bytes in one round trip.
/// Returns the new sid plus an `Arc<SessionInner>` so unary callers
/// (`handle_connect_data_single`) can drain the first response without a
/// second sessions-map lookup. The batch caller drops the Arc — it takes
/// a single lock across all drain-bound sessions in phase 2, which is
/// cheaper than the Arc plumbing would be.
async fn handle_connect_data_phase1(
    state: &AppState,
    host: Option<String>,
    port: Option<u16>,
    data: Option<String>,
) -> Result<(String, Arc<SessionInner>), TunnelResponse> {
    let (host, port) = validate_host_port(host, port)?;

    let session = create_session(&host, port)
        .await
        .map_err(|e| TunnelResponse::error(format!("connect failed: {}", e)))?;

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
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
        eof: Some(eof),
        e: None,
        code: None,
    }
}

async fn handle_data_single(state: &AppState, sid: Option<String>, data: Option<String>) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    let sessions = state.sessions.lock().await;
    let session = match sessions.get(&sid) {
        Some(s) => s,
        None => return TunnelResponse::error("unknown session"),
    };
    *session.inner.last_active.lock().await = Instant::now();
    if let Some(ref data_b64) = data {
        if !data_b64.is_empty() {
            if let Ok(bytes) = B64.decode(data_b64) {
                if !bytes.is_empty() {
                    let mut w = session.inner.writer.lock().await;
                    if let Err(e) = w.write_all(&bytes).await {
                        drop(w); drop(sessions);
                        state.sessions.lock().await.remove(&sid);
                        return TunnelResponse::error(format!("write failed: {}", e));
                    }
                    let _ = w.flush().await;
                }
            }
        }
    }
    let (data, eof) = wait_and_drain(&session.inner, Duration::from_secs(5)).await;
    drop(sessions);
    if eof {
        if let Some(s) = state.sessions.lock().await.remove(&sid) {
            s.reader_handle.abort();
            tracing::info!("session {} closed by remote", sid);
        }
    }
    TunnelResponse {
        sid: Some(sid),
        d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
        eof: Some(eof), e: None, code: None,
    }
}

async fn handle_close(state: &AppState, sid: Option<String>) -> TunnelResponse {
    let sid = match sid {
        Some(s) if !s.is_empty() => s,
        _ => return TunnelResponse::error("missing sid"),
    };
    if let Some(s) = state.sessions.lock().await.remove(&sid) {
        s.reader_handle.abort();
        tracing::info!("session {} closed by client", sid);
    }
    TunnelResponse { sid: Some(sid), d: None, eof: Some(true), e: None, code: None }
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

async fn cleanup_task(sessions: Arc<Mutex<HashMap<String, ManagedSession>>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let mut map = sessions.lock().await;
        let now = Instant::now();
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
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let auth_key = std::env::var("TUNNEL_AUTH_KEY").unwrap_or_else(|_| {
        tracing::warn!("TUNNEL_AUTH_KEY not set — using default (INSECURE)");
        "changeme".into()
    });
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let sessions: Arc<Mutex<HashMap<String, ManagedSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(cleanup_task(sessions.clone()));

    let state = AppState { sessions, auth_key };

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
            auth_key: "test-key".into(),
        }
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
        let resp = handle_connect_data_single(
            &state, None, Some(443), Some(B64.encode(b"x")),
        ).await;
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
            writer: Mutex::new(writer),
            read_buf: Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
        })
    }

    #[tokio::test]
    async fn wait_for_any_drainable_returns_immediately_when_buffer_has_data() {
        let inner = fake_inner().await;
        inner.read_buf.lock().await.extend_from_slice(b"already here");

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
            writer: Mutex::new(writer),
            read_buf: Mutex::new(Vec::new()),
            eof: AtomicBool::new(false),
            last_active: Mutex::new(Instant::now()),
            notify: Notify::new(),
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
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body_bytes).unwrap()
    }

    /// Pure-poll batch (one `data` op with no `d`) holds open and wakes
    /// when upstream pushes data. Push arrives at ~150 ms — well past
    /// any active-batch ceiling. If long-poll didn't engage we'd return
    /// at ACTIVE_DRAIN_DEADLINE (350 ms) with no data.
    #[tokio::test]
    async fn batch_pure_poll_wakes_on_push() {
        let push_port = start_push_server(
            Duration::from_millis(150),
            b"PUSHED".to_vec(),
        ).await;
        let state = fresh_state();
        let connect_resp = handle_connect(&state, Some("127.0.0.1".into()), Some(push_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid}],
        })).unwrap();

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
        let d_b64 = r[0]["d"].as_str().expect("response should carry pushed bytes");
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
        let connect_resp = handle_connect(&state, Some("127.0.0.1".into()), Some(silent_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid, "d": B64.encode(b"PING")}],
        })).unwrap();

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
        let push_port = start_push_server(
            Duration::from_millis(600),
            b"DELAYED".to_vec(),
        ).await;
        let state = fresh_state();
        let connect_resp = handle_connect(&state, Some("127.0.0.1".into()), Some(push_port)).await;
        let sid = connect_resp.sid.expect("connect should succeed");

        let body = serde_json::to_vec(&serde_json::json!({
            "k": "test-key",
            "ops": [{"op": "data", "sid": sid, "d": ""}],
        })).unwrap();

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
        let d_b64 = r[0]["d"].as_str()
            .expect("Some(\"\") payload should have engaged long-poll and delivered DELAYED");
        let data = B64.decode(d_b64).unwrap();
        assert_eq!(&data[..], b"DELAYED");
    }
}
