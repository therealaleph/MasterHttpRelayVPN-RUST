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
use std::sync::Arc;
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

/// Structured error code the tunnel-node returns when it doesn't know the
/// op (version mismatch). Must match `tunnel-node/src/main.rs`.
const CODE_UNSUPPORTED_OP: &str = "UNSUPPORTED_OP";

/// Ports where the *server* speaks first (SMTP banner, SSH identification,
/// POP3/IMAP greeting, FTP banner). On these, waiting for client bytes
/// gains nothing and just adds handshake latency — skip the pre-read.
/// HTTP on 80 also qualifies because a naive HTTP client may not flush
/// the request line immediately after the CONNECT reply.
fn is_server_speaks_first(port: u16) -> bool {
    matches!(port, 21 | 22 | 25 | 80 | 110 | 143 | 587)
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
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
        })
    }

    async fn send(&self, msg: MuxMsg) {
        let _ = self.tx.send(msg).await;
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

    fn record_preread_win(&self, port: u16, elapsed: Duration) {
        self.preread_win.fetch_add(1, Ordering::Relaxed);
        self.preread_win_total_us
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        tracing::debug!("preread win: port={} took={:?}", port, elapsed);
        self.maybe_log_preread_summary();
    }

    fn record_preread_loss(&self, port: u16) {
        self.preread_loss.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("preread loss: port={} (empty within {:?})", port, CLIENT_FIRST_DATA_WAIT);
        self.maybe_log_preread_summary();
    }

    fn record_preread_skip_port(&self, port: u16) {
        self.preread_skip_port.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("preread skip: port={} (server-speaks-first)", port);
        self.maybe_log_preread_summary();
    }

    fn record_preread_skip_unsupported(&self, port: u16) {
        self.preread_skip_unsupported.fetch_add(1, Ordering::Relaxed);
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
            .map(|id| (id.clone(), Arc::new(Semaphore::new(CONCURRENCY_PER_DEPLOYMENT))))
            .collect(),
    );

    loop {
        let mut msgs = Vec::new();
        match tokio::time::timeout(Duration::from_millis(30), rx.recv()).await {
            Ok(Some(msg)) => msgs.push(msg),
            Ok(None) => break,
            Err(_) => continue,
        }
        while let Ok(msg) = rx.try_recv() {
            msgs.push(msg);
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
                        let result =
                            f.tunnel_request("connect", Some(&host), Some(port), None, None)
                                .await;
                        match result {
                            Ok(resp) => { let _ = reply.send(Ok(resp)); }
                            Err(e) => { let _ = reply.send(Err(format!("{}", e))); }
                        }
                    });
                }
                MuxMsg::ConnectData { host, port, data, reply } => {
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
                    tracing::error!("tunnel session {}: bad base64 in connect_data response", sid);
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

    Ok(ConnectDataOutcome::Opened { sid, response: resp })
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
        let client_data = if let Some(data) = pending_client_data.take() {
            Some(data)
        } else {
            let read_timeout = match consecutive_empty {
                0 => Duration::from_millis(20),
                1 => Duration::from_millis(80),
                2 => Duration::from_millis(200),
                _ => Duration::from_secs(30),
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

        if client_data.is_none() && consecutive_empty > 3 {
            continue;
        }

        let data = client_data.unwrap_or_default();

        let (reply_tx, reply_rx) = oneshot::channel();
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
            eof: None,
            e: e.map(str::to_string),
            code: code.map(str::to_string),
        }
    }

    #[test]
    fn unsupported_detection_via_structured_code() {
        assert!(is_connect_data_unsupported_response(&resp_with(Some("UNSUPPORTED_OP"), None)));
        assert!(is_connect_data_unsupported_response(&resp_with(
            Some("UNSUPPORTED_OP"),
            Some("unknown op: connect_data"),
        )));
    }

    #[test]
    fn unsupported_detection_via_legacy_tunnel_node_string() {
        // Pre-change tunnel-node: no code field, bare "unknown op: ...".
        assert!(is_connect_data_unsupported_response(&resp_with(
            None, Some("unknown op: connect_data"),
        )));
        assert!(is_connect_data_unsupported_response(&resp_with(
            None, Some("Unknown Op: CONNECT_DATA"),
        )));
    }

    #[test]
    fn unsupported_detection_via_legacy_apps_script_string() {
        // Pre-change apps_script: default branch emits "unknown tunnel op: ...".
        // This is the realistic skew case — user upgrades tunnel-node + client
        // binary but hasn't redeployed the Apps Script yet.
        assert!(is_connect_data_unsupported_response(&resp_with(
            None, Some("unknown tunnel op: connect_data"),
        )));
    }

    #[test]
    fn unsupported_detection_rejects_unrelated_errors() {
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None, Some("connect failed: refused"),
        )));
        assert!(!is_connect_data_unsupported_response(&resp_with(None, Some("bad base64"))));
        assert!(!is_connect_data_unsupported_response(&resp_with(None, None)));
        // "connect_data" alone (without "unknown op") shouldn't trigger.
        assert!(!is_connect_data_unsupported_response(&resp_with(
            None, Some("connect_data: bad port"),
        )));
    }

    #[test]
    fn server_speaks_first_covers_common_protocols() {
        for p in [21u16, 22, 25, 80, 110, 143, 587] {
            assert!(is_server_speaks_first(p), "port {} should be server-first", p);
        }
        for p in [443u16, 8443, 853, 993, 1234] {
            assert!(!is_server_speaks_first(p), "port {} should NOT be server-first", p);
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
            preread_win: AtomicU64::new(0),
            preread_loss: AtomicU64::new(0),
            preread_skip_port: AtomicU64::new(0),
            preread_skip_unsupported: AtomicU64::new(0),
            preread_win_total_us: AtomicU64::new(0),
            preread_total_events: AtomicU64::new(0),
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
            async move {
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
            MuxMsg::Data { sid, data, reply } => {
                assert_eq!(sid, "sid-under-test");
                assert_eq!(&data[..], b"CLIENTHELLO");
                // Reply with eof so tunnel_loop unwinds cleanly.
                let _ = reply.send(Ok(TunnelResponse {
                    sid: Some("sid-under-test".into()),
                    d: None,
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
