//! Full-mode tunnel client with batch multiplexer.
//!
//! A central multiplexer collects pending data from ALL active sessions
//! and sends ONE batch request per tick. Connects are handled individually
//! (they're slow and can't be serialized). Data/close ops are batched.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::domain_fronter::{BatchOp, DomainFronter, TunnelResponse};

// ---------------------------------------------------------------------------
// Multiplexer
// ---------------------------------------------------------------------------

enum MuxMsg {
    /// Connect handled individually (not batched — too slow for serial).
    Connect {
        host: String,
        port: u16,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    /// Data batched with other sessions per tick.
    Data {
        sid: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<TunnelResponse, String>>,
    },
    /// Close is fire-and-forget, batched.
    Close {
        sid: String,
    },
}

pub struct TunnelMux {
    tx: mpsc::Sender<MuxMsg>,
}

impl TunnelMux {
    pub fn start(fronter: Arc<DomainFronter>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(512);
        tokio::spawn(mux_loop(rx, fronter));
        Arc::new(Self { tx })
    }

    async fn send(&self, msg: MuxMsg) {
        let _ = self.tx.send(msg).await;
    }
}

async fn mux_loop(
    mut rx: mpsc::Receiver<MuxMsg>,
    fronter: Arc<DomainFronter>,
) {
    loop {
        // Wait for first message
        let mut msgs = Vec::new();
        match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            Ok(Some(msg)) => msgs.push(msg),
            Ok(None) => break,
            Err(_) => continue,
        }
        // Drain any queued messages
        while let Ok(msg) = rx.try_recv() {
            msgs.push(msg);
        }

        // Split: connects go parallel+individual, data/close go batched
        let mut data_ops: Vec<BatchOp> = Vec::new();
        let mut data_replies: Vec<(usize, oneshot::Sender<Result<TunnelResponse, String>>)> = Vec::new();
        let mut close_sids: Vec<String> = Vec::new();

        for msg in msgs {
            match msg {
                MuxMsg::Connect { host, port, reply } => {
                    // Spawn individual connect — don't block the batch loop
                    let f = fronter.clone();
                    tokio::spawn(async move {
                        let result = f.tunnel_request(
                            "connect", Some(&host), Some(port), None, None,
                        ).await;
                        match result {
                            Ok(resp) => { let _ = reply.send(Ok(resp)); }
                            Err(e) => { let _ = reply.send(Err(format!("{}", e))); }
                        }
                    });
                }
                MuxMsg::Data { sid, data, reply } => {
                    let idx = data_ops.len();
                    data_ops.push(BatchOp {
                        op: "data".into(),
                        sid: Some(sid),
                        host: None,
                        port: None,
                        d: if data.is_empty() { None } else { Some(B64.encode(&data)) },
                    });
                    data_replies.push((idx, reply));
                }
                MuxMsg::Close { sid } => {
                    close_sids.push(sid);
                }
            }
        }

        // Add close ops (no reply needed)
        for sid in close_sids {
            data_ops.push(BatchOp {
                op: "close".into(),
                sid: Some(sid),
                host: None,
                port: None,
                d: None,
            });
        }

        // Send batch if there are data/close ops
        if !data_ops.is_empty() {
            let t0 = std::time::Instant::now();
            let n_ops = data_ops.len();
            let result = fronter.tunnel_batch_request(&data_ops).await;
            tracing::info!("batch tick: {} ops, rtt={:?}", n_ops, t0.elapsed());
            match result {
                Ok(batch_resp) => {
                    for (idx, reply) in data_replies {
                        if let Some(resp) = batch_resp.r.get(idx) {
                            let _ = reply.send(Ok(resp.clone()));
                        } else {
                            let _ = reply.send(Err("missing response in batch".into()));
                        }
                    }
                }
                Err(e) => {
                    let err_msg = format!("{}", e);
                    for (_, reply) in data_replies {
                        let _ = reply.send(Err(err_msg.clone()));
                    }
                }
            }
        }
    }
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
    // 1. Connect (individual, not batched)
    let (reply_tx, reply_rx) = oneshot::channel();
    mux.send(MuxMsg::Connect {
        host: host.to_string(),
        port,
        reply: reply_tx,
    }).await;

    let sid = match reply_rx.await {
        Ok(Ok(resp)) => {
            if let Some(ref e) = resp.e {
                tracing::error!("tunnel connect error for {}:{}: {}", host, port, e);
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.clone()));
            }
            resp.sid.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "tunnel connect: no session id")
            })?
        }
        Ok(Err(e)) => {
            tracing::error!("tunnel connect error for {}:{}: {}", host, port, e);
            return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e));
        }
        Err(_) => {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "mux channel closed"));
        }
    };

    tracing::info!("tunnel session {} opened for {}:{}", sid, host, port);

    // 2. Data loop (batched with other sessions)
    let result = tunnel_loop(&mut sock, &sid, mux).await;

    // 3. Close
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
            0 => Duration::from_millis(30),
            1 => Duration::from_millis(100),
            2 => Duration::from_millis(300),
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
        let sent = data.len();

        let (reply_tx, reply_rx) = oneshot::channel();
        mux.send(MuxMsg::Data {
            sid: sid.to_string(),
            data,
            reply: reply_tx,
        }).await;

        let resp = match reply_rx.await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::debug!("tunnel data error: {}", e);
                break;
            }
            Err(_) => break,
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
            } else { false }
        } else { false };

        if resp.eof.unwrap_or(false) {
            break;
        }

        let recv = if got_data { resp.d.as_ref().map(|d| d.len()).unwrap_or(0) } else { 0 };
        if sent > 0 || recv > 0 {
            tracing::info!("sess {}: sent={}B recv={}B empty={}", &sid[..8], sent, recv, consecutive_empty);
        }

        if got_data {
            consecutive_empty = 0;
        } else {
            consecutive_empty = consecutive_empty.saturating_add(1);
        }
    }

    Ok(())
}
