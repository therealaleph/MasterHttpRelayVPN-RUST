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
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct SessionInner {
    writer: Mutex<OwnedWriteHalf>,
    read_buf: Mutex<Vec<u8>>,
    eof: AtomicBool,
    last_active: Mutex<Instant>,
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
    });

    let inner_ref = inner.clone();
    let reader_handle = tokio::spawn(reader_task(reader, inner_ref));

    Ok(ManagedSession { inner, reader_handle })
}

async fn reader_task(mut reader: OwnedReadHalf, session: Arc<SessionInner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => { session.eof.store(true, Ordering::Release); break; }
            Ok(n) => { session.read_buf.lock().await.extend_from_slice(&buf[..n]); }
            Err(_) => { session.eof.store(true, Ordering::Release); break; }
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

#[derive(Serialize, Clone)]
struct TunnelResponse {
    #[serde(skip_serializing_if = "Option::is_none")] sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] eof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] e: Option<String>,
}

impl TunnelResponse {
    fn error(msg: impl Into<String>) -> Self {
        Self { sid: None, d: None, eof: None, e: Some(msg.into()) }
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
        "data" => Json(handle_data_single(&state, req.sid, req.data).await),
        "close" => Json(handle_close(&state, req.sid).await),
        other => Json(TunnelResponse::error(format!("unknown op: {}", other))),
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

    // Process all ops. For "data" ops, first write all outbound data,
    // then do a short sleep to let servers respond, then drain all.
    // This batches the network round trips on the server side too.

    // Phase 1: process connects and writes
    let mut results: Vec<(usize, TunnelResponse)> = Vec::with_capacity(req.ops.len());
    let mut data_ops: Vec<(usize, String)> = Vec::new(); // (index, sid) for data ops needing drain

    for (i, op) in req.ops.iter().enumerate() {
        match op.op.as_str() {
            "connect" => {
                let r = handle_connect(&state, op.host.clone(), op.port).await;
                results.push((i, r));
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
                    results.push((i, TunnelResponse { sid: Some(sid), d: None, eof: Some(true), e: None }));
                }
            }
            "close" => {
                let r = handle_close(&state, op.sid.clone()).await;
                results.push((i, r));
            }
            other => {
                results.push((i, TunnelResponse::error(format!("unknown op: {}", other))));
            }
        }
    }

    // Phase 2: short wait for servers to respond, then drain all data sessions
    if !data_ops.is_empty() {
        // Give servers a moment to respond to the data we just wrote
        tokio::time::sleep(Duration::from_millis(150)).await;

        // First drain pass
        {
            let sessions = state.sessions.lock().await;
            let mut need_retry = Vec::new();
            for (i, sid) in &data_ops {
                if let Some(session) = sessions.get(sid) {
                    let (data, eof) = drain_now(&session.inner).await;
                    if data.is_empty() && !eof {
                        need_retry.push((*i, sid.clone()));
                    } else {
                        results.push((*i, TunnelResponse {
                            sid: Some(sid.clone()),
                            d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
                            eof: Some(eof), e: None,
                        }));
                    }
                } else {
                    results.push((*i, TunnelResponse {
                        sid: Some(sid.clone()), d: None, eof: Some(true), e: None,
                    }));
                }
            }
            drop(sessions);

            // Retry sessions that had no data yet
            if !need_retry.is_empty() {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let sessions = state.sessions.lock().await;
                for (i, sid) in &need_retry {
                    if let Some(s) = sessions.get(sid) {
                        let (data, eof) = drain_now(&s.inner).await;
                        results.push((*i, TunnelResponse {
                            sid: Some(sid.clone()),
                            d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
                            eof: Some(eof), e: None,
                        }));
                    } else {
                        results.push((*i, TunnelResponse {
                            sid: Some(sid.clone()), d: None, eof: Some(true), e: None,
                        }));
                    }
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

async fn handle_connect(state: &AppState, host: Option<String>, port: Option<u16>) -> TunnelResponse {
    let host = match host {
        Some(h) if !h.is_empty() => h,
        _ => return TunnelResponse::error("missing host"),
    };
    let port = match port {
        Some(p) if p > 0 => p,
        _ => return TunnelResponse::error("missing or invalid port"),
    };
    let session = match create_session(&host, port).await {
        Ok(s) => s,
        Err(e) => return TunnelResponse::error(format!("connect failed: {}", e)),
    };
    let sid = uuid::Uuid::new_v4().to_string();
    tracing::info!("session {} -> {}:{}", sid, host, port);
    state.sessions.lock().await.insert(sid.clone(), session);
    TunnelResponse { sid: Some(sid), d: None, eof: Some(false), e: None }
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
        eof: Some(eof), e: None,
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
    TunnelResponse { sid: Some(sid), d: None, eof: Some(true), e: None }
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
