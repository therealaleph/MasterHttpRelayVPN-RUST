//! Full-mode tunnel client with pipelined batch multiplexer.
//!
//! A central multiplexer collects pending data from ALL active sessions
//! and fires batch requests without waiting for the previous one to return.
//! Pipeline depth equals the number of script deployments (minimum 2),
//! so users with more deployments get lower latency automatically.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::domain_fronter::{BatchOp, DomainFronter, TunnelResponse};

/// Minimum pipeline depth even with a single script.
const MIN_PIPELINE_DEPTH: usize = 2;

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

// ---------------------------------------------------------------------------
// Multiplexer
// ---------------------------------------------------------------------------

enum MuxMsg {
    Connect {
        host: String,
        port: u16,
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
}

impl TunnelMux {
    pub fn start(fronter: Arc<DomainFronter>) -> Arc<Self> {
        let pipeline_depth = fronter.num_scripts().max(MIN_PIPELINE_DEPTH);
        tracing::info!(
            "tunnel mux: pipeline_depth={} (from {} script deployments)",
            pipeline_depth,
            fronter.num_scripts()
        );
        let (tx, rx) = mpsc::channel(512);
        tokio::spawn(mux_loop(rx, fronter, pipeline_depth));
        Arc::new(Self { tx })
    }

    async fn send(&self, msg: MuxMsg) {
        let _ = self.tx.send(msg).await;
    }
}

async fn mux_loop(
    mut rx: mpsc::Receiver<MuxMsg>,
    fronter: Arc<DomainFronter>,
    pipeline_depth: usize,
) {
    let sem = Arc::new(Semaphore::new(pipeline_depth));

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

        // Split: connects go parallel, data/close get batched.
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
                            &sem,
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

        fire_batch(&sem, &fronter, data_ops, data_replies).await;
    }
}

/// Acquire a pipeline slot and spawn a batch request task.
///
/// The batch HTTP round-trip is bounded by `BATCH_TIMEOUT` so a slow or
/// dead tunnel-node target cannot hold a pipeline slot (and block waiting
/// sessions) forever.
async fn fire_batch(
    sem: &Arc<Semaphore>,
    fronter: &Arc<DomainFronter>,
    data_ops: Vec<BatchOp>,
    data_replies: Vec<(usize, oneshot::Sender<Result<TunnelResponse, String>>)>,
) {
    let permit = sem.clone().acquire_owned().await.unwrap();
    let f = fronter.clone();

    tokio::spawn(async move {
        let _permit = permit;
        let t0 = std::time::Instant::now();
        let n_ops = data_ops.len();

        // Bounded-wait: if the batch takes longer than BATCH_TIMEOUT,
        // all sessions in this batch get an error and can retry.
        let result = tokio::time::timeout(BATCH_TIMEOUT, f.tunnel_batch_request(&data_ops)).await;
        tracing::info!("batch: {} ops, rtt={:?}", n_ops, t0.elapsed());

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
    let (reply_tx, reply_rx) = oneshot::channel();
    mux.send(MuxMsg::Connect {
        host: host.to_string(),
        port,
        reply: reply_tx,
    })
    .await;

    let sid = match reply_rx.await {
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
            })?
        }
        Ok(Err(e)) => {
            tracing::error!("tunnel connect error for {}:{}: {}", host, port, e);
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

    tracing::info!("tunnel session {} opened for {}:{}", sid, host, port);
    let result = tunnel_loop(&mut sock, &sid, mux).await;
    mux.send(MuxMsg::Close { sid: sid.clone() }).await;
    tracing::info!("tunnel session {} closed for {}:{}", sid, host, port);
    result
}

async fn tunnel_loop(
    sock: &mut TcpStream,
    sid: &str,
    mux: &Arc<TunnelMux>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = sock.split();
    let mut buf = vec![0u8; 65536];
    let mut consecutive_empty = 0u32;

    loop {
        let read_timeout = match consecutive_empty {
            0 => Duration::from_millis(20),
            1 => Duration::from_millis(80),
            2 => Duration::from_millis(200),
            _ => Duration::from_secs(30),
        };

        let client_data = match tokio::time::timeout(read_timeout, reader.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                consecutive_empty = 0;
                Some(buf[..n].to_vec())
            }
            Ok(Err(_)) => break,
            Err(_) => None,
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

        let got_data = if let Some(ref d) = resp.d {
            if !d.is_empty() {
                match B64.decode(d) {
                    Ok(bytes) if !bytes.is_empty() => {
                        writer.write_all(&bytes).await?;
                        writer.flush().await?;
                        true
                    }
                    Err(e) => {
                        tracing::error!("tunnel bad base64: {}", e);
                        break;
                    }
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
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
