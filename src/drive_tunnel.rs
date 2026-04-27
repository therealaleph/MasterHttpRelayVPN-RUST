//! FlowDriver-style Google Drive tunnel mode.
//!
//! The Drive folder acts as a lossy, short-lived message queue. Client-side
//! SOCKS5 CONNECT streams become sessions. Both sides periodically flush
//! buffered bytes into multiplexed `req-...-mux-...bin` / `res-...` files,
//! poll for peer files, process envelopes in sequence, then delete them.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::stream::{self, StreamExt};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::config::Config;
use crate::google_drive::{DriveError, GoogleDriveBackend};

/// Maximum number of concurrent uploads/downloads in flight against
/// Drive. Matches FlowDriver's `e.sem = make(chan struct{}, 8)`. Uses
/// HTTP/2 multiplexing on a single TLS connection, so the cost of bumping
/// this is just a few more in-flight streams — no extra handshakes.
const STORAGE_CONCURRENCY: usize = 8;

const MAGIC_BYTE: u8 = 0x1f;
/// Bumped whenever the wire format changes. v1 added a flags byte
/// (replacing the old `close` bool) and gained the FLAG_OPEN_OK bit
/// so the server can confirm a successful upstream connect to the
/// SOCKS5 client before it returns success to its caller.
const ENVELOPE_VERSION: u8 = 0x01;

const FLAG_CLOSE: u8 = 0x01;
const FLAG_OPEN_OK: u8 = 0x02;

const MAX_ENVELOPE_PAYLOAD: usize = 10 * 1024 * 1024;
const MAX_TX_BUFFER: usize = 2 * 1024 * 1024;
/// Garbage-collect own files whose Drive `createdTime` is older than
/// this. The peer should normally consume + delete within seconds; if
/// it doesn't (peer down, network outage), this is the failsafe so the
/// shared folder doesn't fill up. Compared against Drive's clock, not
/// the local clock, so multi-machine setups don't false-positive on
/// clock skew.
const OLD_FILE_TTL: Duration = Duration::from_secs(60);
/// Drop files we find on first poll that look ancient — most likely
/// leftovers from a previous run on the other side. Same Drive-clock
/// comparison as OLD_FILE_TTL.
const STARTUP_STALE_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a SOCKS5 client waits for the server's connect result
/// before giving up and returning a SOCKS5 reply error.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Recently-closed session IDs are remembered for this long; envelopes
/// that arrive for a closed ID are dropped instead of resurrecting it.
const CLOSED_SESSION_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Req,
    Res,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Req => "req",
            Direction::Res => "res",
        }
    }
}

#[derive(Debug)]
struct Envelope {
    session_id: String,
    seq: u64,
    target_addr: String,
    payload: Vec<u8>,
    flags: u8,
}

impl Envelope {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), DriveError> {
        if self.session_id.len() > u8::MAX as usize {
            return Err(DriveError::BadResponse("session id too long".into()));
        }
        if self.target_addr.len() > u8::MAX as usize {
            return Err(DriveError::BadResponse("target address too long".into()));
        }
        if self.payload.len() > u32::MAX as usize {
            return Err(DriveError::BadResponse("payload too large".into()));
        }
        out.push(MAGIC_BYTE);
        out.push(ENVELOPE_VERSION);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(self.session_id.as_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.target_addr.len() as u8);
        out.extend_from_slice(self.target_addr.as_bytes());
        out.push(self.flags);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    fn decode_one(buf: &[u8], pos: &mut usize) -> Result<Option<Self>, DriveError> {
        if *pos >= buf.len() {
            return Ok(None);
        }
        if read_u8(buf, pos)? != MAGIC_BYTE {
            return Err(DriveError::BadResponse("bad Drive envelope magic".into()));
        }
        let version = read_u8(buf, pos)?;
        if version != ENVELOPE_VERSION {
            return Err(DriveError::BadResponse(format!(
                "unsupported Drive envelope version {}",
                version
            )));
        }
        let sid_len = read_u8(buf, pos)? as usize;
        let session_id = read_string(buf, pos, sid_len)?;
        let seq = read_u64(buf, pos)?;
        let target_len = read_u8(buf, pos)? as usize;
        let target_addr = read_string(buf, pos, target_len)?;
        let flags = read_u8(buf, pos)?;
        let payload_len = read_u32(buf, pos)? as usize;
        if payload_len > MAX_ENVELOPE_PAYLOAD {
            return Err(DriveError::BadResponse(format!(
                "Drive envelope payload too large: {}",
                payload_len
            )));
        }
        if buf.len().saturating_sub(*pos) < payload_len {
            return Err(DriveError::BadResponse(
                "truncated Drive envelope payload".into(),
            ));
        }
        let payload = buf[*pos..*pos + payload_len].to_vec();
        *pos += payload_len;
        Ok(Some(Self {
            session_id,
            seq,
            target_addr,
            payload,
            flags,
        }))
    }
}

enum DriveRx {
    /// Server confirmed a successful upstream TCP connect. The client
    /// SOCKS5 handshake waits for this before replying success so a
    /// failed dial surfaces as a SOCKS5 error rather than a half-open
    /// socket that silently closes.
    Open,
    Data(Vec<u8>),
    Close,
}

struct DriveSession {
    id: String,
    target_addr: String,
    client_id: String,
    tx_buf: Vec<u8>,
    tx_seq: u64,
    rx_seq: u64,
    rx_queue: BTreeMap<u64, Envelope>,
    last_activity: Instant,
    closed: bool,
    rx_closed: bool,
    /// Server-side: set once the upstream TCP connect succeeds; cleared
    /// after the next flush emits an open-ack envelope. Always false on
    /// the client side.
    pending_open_ok: bool,
    rx_tx: mpsc::Sender<DriveRx>,
}

impl DriveSession {
    fn new(
        id: String,
        target_addr: String,
        client_id: String,
    ) -> (Arc<Mutex<Self>>, mpsc::Receiver<DriveRx>) {
        let (rx_tx, rx_rx) = mpsc::channel(1024);
        let session = Self {
            id,
            target_addr,
            client_id,
            tx_buf: Vec::new(),
            tx_seq: 0,
            rx_seq: 0,
            rx_queue: BTreeMap::new(),
            last_activity: Instant::now(),
            closed: false,
            rx_closed: false,
            pending_open_ok: false,
            rx_tx,
        };
        (Arc::new(Mutex::new(session)), rx_rx)
    }
}

pub struct DriveNewSession {
    id: String,
    target_addr: String,
    rx: mpsc::Receiver<DriveRx>,
}

pub struct DriveEngine {
    backend: Arc<GoogleDriveBackend>,
    my_dir: Direction,
    peer_dir: Direction,
    client_id: String,
    sessions: Mutex<HashMap<String, Arc<Mutex<DriveSession>>>>,
    processed: Mutex<HashMap<String, Instant>>,
    /// Recently-closed session IDs. process_envelope refuses to
    /// re-create a session for any ID in here, so a stale envelope
    /// arriving after teardown can't resurrect it (which would
    /// otherwise re-dial the target on the server).
    closed_sessions: Mutex<HashMap<String, Instant>>,
    poll_interval: Duration,
    flush_interval: Duration,
    idle_timeout: Duration,
    new_session_tx: Option<mpsc::Sender<DriveNewSession>>,
}

impl DriveEngine {
    fn new(
        backend: Arc<GoogleDriveBackend>,
        is_client: bool,
        client_id: String,
        config: &Config,
        new_session_tx: Option<mpsc::Sender<DriveNewSession>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            backend,
            my_dir: if is_client {
                Direction::Req
            } else {
                Direction::Res
            },
            peer_dir: if is_client {
                Direction::Res
            } else {
                Direction::Req
            },
            client_id,
            sessions: Mutex::new(HashMap::new()),
            processed: Mutex::new(HashMap::new()),
            closed_sessions: Mutex::new(HashMap::new()),
            poll_interval: Duration::from_millis(config.drive_poll_ms),
            flush_interval: Duration::from_millis(config.drive_flush_ms),
            idle_timeout: Duration::from_secs(config.drive_idle_timeout_secs),
            new_session_tx,
        })
    }

    fn start(self: &Arc<Self>) {
        let flush = self.clone();
        tokio::spawn(async move { flush.flush_loop().await });
        let poll = self.clone();
        tokio::spawn(async move { poll.poll_loop().await });
        let cleanup = self.clone();
        tokio::spawn(async move { cleanup.cleanup_loop().await });
    }

    async fn add_client_session(&self, target_addr: String) -> (String, mpsc::Receiver<DriveRx>) {
        let id = random_hex(16);
        let (session, rx) = DriveSession::new(id.clone(), target_addr, self.client_id.clone());
        self.sessions.lock().await.insert(id.clone(), session);
        (id, rx)
    }

    /// Returns `Err` when the session has been closed (either previously
    /// or because the TX buffer would overflow). Callers must propagate
    /// the error so the upstream socket reader stops pumping bytes that
    /// would otherwise be silently dropped — silent drops corrupt the
    /// underlying byte stream and break TLS / HTTP / SSH on top.
    async fn enqueue_tx(&self, session_id: &str, data: &[u8]) -> Result<(), &'static str> {
        let session = self.sessions.lock().await.get(session_id).cloned();
        let Some(session) = session else {
            return Err("session gone");
        };
        let mut s = session.lock().await;
        if s.closed {
            return Err("session closed");
        }
        if s.tx_buf.len().saturating_add(data.len()) > MAX_TX_BUFFER {
            // Force-close instead of silently truncating. The flush
            // will emit a FLAG_CLOSE envelope; the peer will tear its
            // end down. Better a clean RST than a hole in the stream.
            s.closed = true;
            s.last_activity = Instant::now();
            tracing::warn!(
                "Drive session {} TX buffer would overflow ({} + {} > {}); closing session",
                session_id,
                s.tx_buf.len(),
                data.len(),
                MAX_TX_BUFFER
            );
            return Err("tx buffer overflow");
        }
        s.tx_buf.extend_from_slice(data);
        s.last_activity = Instant::now();
        Ok(())
    }

    async fn mark_closed(&self, session_id: &str) {
        let session = self.sessions.lock().await.get(session_id).cloned();
        if let Some(session) = session {
            let mut s = session.lock().await;
            s.closed = true;
            s.last_activity = Instant::now();
        }
    }

    /// Server-side: flag a session so the next flush carries a
    /// FLAG_OPEN_OK envelope back to the client. No-op if the session
    /// is already gone (e.g. timed out before connect returned).
    async fn mark_open_ok(&self, session_id: &str) {
        let session = self.sessions.lock().await.get(session_id).cloned();
        if let Some(session) = session {
            let mut s = session.lock().await;
            s.pending_open_ok = true;
            s.last_activity = Instant::now();
        }
    }

    async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    async fn flush_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(self.flush_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(e) = self.flush_all().await {
                tracing::debug!("Drive flush error: {}", e);
            }
        }
    }

    async fn flush_all(&self) -> Result<(), DriveError> {
        let sessions: Vec<Arc<Mutex<DriveSession>>> =
            self.sessions.lock().await.values().cloned().collect();
        let mut muxes: HashMap<String, Vec<Envelope>> = HashMap::new();
        let mut closed_ids = Vec::new();

        for session in sessions {
            let mut s = session.lock().await;
            if s.last_activity.elapsed() > self.idle_timeout {
                s.closed = true;
            }
            let first_client_open = self.my_dir == Direction::Req && s.tx_seq == 0;
            let open_ok = self.my_dir == Direction::Res && s.pending_open_ok;
            let should_send = !s.tx_buf.is_empty() || first_client_open || s.closed || open_ok;
            if !should_send {
                continue;
            }

            let payload = std::mem::take(&mut s.tx_buf);
            let mut flags = 0u8;
            if s.closed {
                flags |= FLAG_CLOSE;
            }
            if open_ok {
                flags |= FLAG_OPEN_OK;
                s.pending_open_ok = false;
            }
            let env = Envelope {
                session_id: s.id.clone(),
                seq: s.tx_seq,
                target_addr: s.target_addr.clone(),
                payload,
                flags,
            };
            s.tx_seq += 1;
            if s.closed {
                closed_ids.push(s.id.clone());
            }
            let cid = if self.my_dir == Direction::Req {
                self.client_id.clone()
            } else if s.client_id.is_empty() {
                "unknown".into()
            } else {
                s.client_id.clone()
            };
            muxes.entry(cid).or_default().push(env);
        }

        // Encode all mux files up front (CPU only, fast), then ship them
        // in parallel. With one client this is one upload — no win — but
        // the server side typically has several active clients and the
        // parallelism plus HTTP/2 multiplexing folds them into a single
        // round-trip's worth of latency.
        let mut uploads: Vec<(String, Vec<u8>)> = Vec::with_capacity(muxes.len());
        for (cid, envelopes) in muxes {
            let filename = format!("{}-{}-mux-{}.bin", self.my_dir.as_str(), cid, now_nanos());
            let mut body = Vec::new();
            for env in &envelopes {
                env.encode(&mut body)?;
            }
            uploads.push((filename, body));
        }
        if !uploads.is_empty() {
            let backend = self.backend.clone();
            let results: Vec<Result<(), DriveError>> = stream::iter(uploads.into_iter().map(
                |(name, body)| {
                    let backend = backend.clone();
                    async move { backend.upload(&name, body).await }
                },
            ))
            .buffer_unordered(STORAGE_CONCURRENCY)
            .collect()
            .await;
            for r in results {
                if let Err(e) = r {
                    tracing::debug!("Drive upload error: {}", e);
                }
            }
        }

        if !closed_ids.is_empty() {
            let mut sessions = self.sessions.lock().await;
            let mut closed_set = self.closed_sessions.lock().await;
            for id in closed_ids {
                sessions.remove(&id);
                closed_set.insert(id, Instant::now());
            }
        }
        Ok(())
    }

    async fn poll_loop(self: Arc<Self>) {
        loop {
            if self.my_dir == Direction::Req && self.session_count().await == 0 {
                tokio::time::sleep(self.poll_interval).await;
                continue;
            }
            let got_files = match self.poll_once().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("Drive poll error: {}", e);
                    false
                }
            };
            let delay = if got_files {
                Duration::from_millis(100)
            } else {
                self.poll_interval
            };
            tokio::time::sleep(delay).await;
        }
    }

    async fn poll_once(&self) -> Result<bool, DriveError> {
        let mut prefix = self.peer_dir.as_str().to_string();
        prefix.push('-');
        if self.my_dir == Direction::Req {
            prefix.push_str(&self.client_id);
            prefix.push_str("-mux-");
        }

        let files = self.backend.list_query(&prefix).await?;
        if files.is_empty() {
            return Ok(false);
        }

        let stale_cutoff = SystemTime::now().checked_sub(STARTUP_STALE_TTL);

        // Pre-filter: drop stale files (created > 5 min ago is most
        // likely a leftover from a previous run on the peer; nuking it
        // is safer than re-processing) and skip files we already
        // downloaded but haven't garbage-collected from `processed`
        // yet. Mark the survivors as processed up front so a slow
        // download doesn't get re-fetched on the next poll cycle.
        let mut to_download: Vec<String> = Vec::with_capacity(files.len());
        let mut to_delete_stale: Vec<String> = Vec::new();
        {
            let mut processed = self.processed.lock().await;
            for file in files {
                if let (Some(cutoff), Some(created)) = (stale_cutoff, file.created_time) {
                    if created < cutoff {
                        to_delete_stale.push(file.name);
                        continue;
                    }
                }
                if processed.contains_key(&file.name) {
                    continue;
                }
                processed.insert(file.name.clone(), Instant::now());
                to_download.push(file.name);
            }
        }

        // Fire stale deletes in the background — don't block this poll
        // cycle on cleanup.
        for name in to_delete_stale {
            let backend = self.backend.clone();
            tokio::spawn(async move {
                let _ = backend.delete(&name).await;
            });
        }

        if to_download.is_empty() {
            return Ok(true);
        }

        // Concurrent downloads, bounded by STORAGE_CONCURRENCY. With
        // HTTP/2 these all multiplex onto the same TLS connection — no
        // extra handshakes, just more in-flight streams. This is the
        // single biggest win over the v1 sequential implementation.
        let backend = self.backend.clone();
        let downloads = stream::iter(to_download.into_iter().map(|name| {
            let backend = backend.clone();
            async move {
                let res = backend.download(&name).await;
                (name, res)
            }
        }))
        .buffer_unordered(STORAGE_CONCURRENCY);
        tokio::pin!(downloads);

        while let Some((name, result)) = downloads.next().await {
            match result {
                Ok(data) => {
                    let file_client_id = client_id_from_filename(&name).unwrap_or_default();
                    if let Err(e) = self.process_mux_file(&data, &file_client_id).await {
                        // A bad envelope inside a mux file aborts the
                        // rest of that file's envelopes. Bumping past
                        // `debug` so the data loss is visible.
                        tracing::warn!(
                            "Drive mux decode {} failed: {} (remaining envelopes in this file are lost)",
                            name,
                            e
                        );
                    }
                    // Fire-and-forget delete — the next poll won't see
                    // it because we marked it processed; if delete
                    // races we get a 404 which the backend ignores.
                    let backend = self.backend.clone();
                    let name_for_delete = name;
                    tokio::spawn(async move {
                        let _ = backend.delete(&name_for_delete).await;
                    });
                }
                Err(e) => {
                    self.processed.lock().await.remove(&name);
                    tracing::debug!("Drive download {} failed: {}", name, e);
                }
            }
        }

        Ok(true)
    }

    async fn process_mux_file(&self, data: &[u8], file_client_id: &str) -> Result<(), DriveError> {
        let mut pos = 0usize;
        while let Some(env) = Envelope::decode_one(data, &mut pos)? {
            self.process_envelope(env, file_client_id).await?;
        }
        Ok(())
    }

    async fn process_envelope(
        &self,
        env: Envelope,
        file_client_id: &str,
    ) -> Result<(), DriveError> {
        let session = self.sessions.lock().await.get(&env.session_id).cloned();
        let session = if let Some(session) = session {
            session
        } else if self.my_dir == Direction::Res && !env.target_addr.is_empty() {
            // Refuse to resurrect a session we've already torn down.
            // Without this, a late envelope (peer retried, our delete
            // raced the upload, etc.) would re-dial the target.
            if self
                .closed_sessions
                .lock()
                .await
                .contains_key(&env.session_id)
            {
                return Ok(());
            }
            let (session, rx) = DriveSession::new(
                env.session_id.clone(),
                env.target_addr.clone(),
                file_client_id.to_string(),
            );
            self.sessions
                .lock()
                .await
                .insert(env.session_id.clone(), session.clone());
            if let Some(tx) = &self.new_session_tx {
                let _ = tx
                    .send(DriveNewSession {
                        id: env.session_id.clone(),
                        target_addr: env.target_addr.clone(),
                        rx,
                    })
                    .await;
            }
            session
        } else {
            return Ok(());
        };

        process_rx(session, env).await;
        Ok(())
    }

    async fn cleanup_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            self.processed
                .lock()
                .await
                .retain(|_, seen| seen.elapsed() < Duration::from_secs(600));
            self.closed_sessions
                .lock()
                .await
                .retain(|_, seen| seen.elapsed() < CLOSED_SESSION_TTL);

            // Cleanup is scoped to files we actually own. Without the
            // client_id prefix, two clients sharing a Drive folder
            // would each delete each other's in-flight req-* files.
            let prefix = if self.my_dir == Direction::Req {
                format!("req-{}-mux-", self.client_id)
            } else {
                "res-".to_string()
            };
            let files = match self.backend.list_query(&prefix).await {
                Ok(files) => files,
                Err(_) => continue,
            };
            let cutoff = match SystemTime::now().checked_sub(OLD_FILE_TTL) {
                Some(t) => t,
                None => continue,
            };
            for file in files {
                if let Some(created) = file.created_time {
                    if created < cutoff {
                        let _ = self.backend.delete(&file.name).await;
                    }
                }
            }

            // Reap orphan peer files. Normal flow has each side
            // deleting its own files via `cleanup_loop` above plus the
            // `processed`-then-delete path in `poll_once`. The edge
            // case is the peer dying mid-batch: a `res-*` file it
            // wrote remains in the folder, the dead node can't run
            // its own cleanup, and our own cleanup above only
            // touches files matching our `my_dir` prefix. Without
            // the block below, those orphans accumulate forever.
            //
            // Scoped to `<peer_dir>-<my_client_id>-mux-` so a single
            // client sharing a folder with several others doesn't
            // touch their in-flight files. Uses STARTUP_STALE_TTL
            // (5 min) — much longer than the per-file lifetime in
            // normal operation, so this only fires on the orphan
            // case; a slow round-trip won't trip it.
            let orphan_prefix = format!(
                "{}-{}-mux-",
                self.peer_dir.as_str(),
                self.client_id,
            );
            if !self.client_id.is_empty() {
                if let Ok(orphans) = self.backend.list_query(&orphan_prefix).await {
                    if let Some(orphan_cutoff) =
                        SystemTime::now().checked_sub(STARTUP_STALE_TTL)
                    {
                        for file in orphans {
                            if let Some(created) = file.created_time {
                                if created < orphan_cutoff {
                                    let _ = self.backend.delete(&file.name).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn process_rx(session: Arc<Mutex<DriveSession>>, env: Envelope) {
    let (tx, out) = {
        let mut s = session.lock().await;
        s.last_activity = Instant::now();
        let tx = s.rx_tx.clone();
        let mut out = Vec::new();
        if s.rx_closed {
            return;
        }
        if env.seq == s.rx_seq {
            apply_rx_env(&mut s, env, &mut out);
            loop {
                let next_seq = s.rx_seq;
                let Some(next) = s.rx_queue.remove(&next_seq) else {
                    break;
                };
                apply_rx_env(&mut s, next, &mut out);
                if s.rx_closed {
                    break;
                }
            }
        } else if env.seq > s.rx_seq {
            s.rx_queue.insert(env.seq, env);
        }
        (tx, out)
    };

    for msg in out {
        let _ = tx.send(msg).await;
    }
}

fn apply_rx_env(session: &mut DriveSession, env: Envelope, out: &mut Vec<DriveRx>) {
    if env.flags & FLAG_OPEN_OK != 0 {
        out.push(DriveRx::Open);
    }
    if !env.payload.is_empty() {
        out.push(DriveRx::Data(env.payload));
    }
    session.rx_seq += 1;
    if env.flags & FLAG_CLOSE != 0 {
        session.rx_closed = true;
        session.closed = true;
        out.push(DriveRx::Close);
    }
}

pub async fn run_client(config: &Config) -> Result<(), DriveError> {
    // Backward compatibility shim — never returns. Newer entry points
    // ([`run_client_with_shutdown`]) accept a oneshot so UIs can stop
    // the SOCKS5 listener cleanly.
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    run_client_with_shutdown(config, rx).await
}

/// Same as [`run_client`] but returns when `shutdown` resolves. UIs and
/// services use this so the listener can be released on stop without
/// killing the whole tokio runtime. Backend OAuth + folder discovery
/// happen up front (before the listen socket binds), so a Ctrl+C that
/// arrives during login still bubbles back to the caller.
pub async fn run_client_with_shutdown(
    config: &Config,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), DriveError> {
    let backend = init_backend(config).await?;
    run_client_with_backend(config, backend, shutdown).await
}

/// Run the SOCKS5 client side with a pre-built (and pre-validated) Drive
/// backend. JNI / UI entry points use this so OAuth refresh + folder
/// discovery can happen synchronously up front and surface any failure
/// before they commit to spawning the listener task. The runtime that
/// drives this future must be the same one the `backend` was built
/// against — its HTTP/2 connection task is already attached to it.
pub async fn run_client_with_backend(
    config: &Config,
    backend: Arc<GoogleDriveBackend>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), DriveError> {
    let client_id = if config.drive_client_id.trim().is_empty() {
        random_hex(4)
    } else {
        config.drive_client_id.trim().to_string()
    };
    let engine = DriveEngine::new(backend, true, client_id.clone(), config, None);
    engine.start();

    let port = config.socks5_port.unwrap_or(config.listen_port + 1);
    let addr = format!("{}:{}", config.listen_host, port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::warn!(
        "Google Drive mode listening SOCKS5 on {} (client_id={})",
        addr,
        client_id
    );
    tracing::warn!("HTTP proxy and UDP ASSOCIATE are not available in google_drive mode.");

    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!("google_drive client: shutdown signal received, releasing {}", addr);
                return Ok(());
            }
            accepted = listener.accept() => {
                let (sock, peer) = accepted?;
                let engine = engine.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_client(sock, engine).await {
                        tracing::debug!("Drive SOCKS5 client {} closed: {}", peer, e);
                    }
                });
            }
        }
    }
}

/// Build and validate a Drive backend (loads credentials JSON, refreshes
/// the OAuth access token, ensures the target folder exists). Surfaces
/// any failure synchronously so JNI / UI callers can early-return
/// before spawning long-lived state. Public so it can be shared by the
/// CLI and the JNI entry points.
pub async fn build_backend(config: &Config) -> Result<Arc<GoogleDriveBackend>, DriveError> {
    init_backend(config).await
}

pub async fn run_server(config: &Config) -> Result<(), DriveError> {
    let backend = init_backend(config).await?;
    let (new_tx, mut new_rx) = mpsc::channel(1024);
    let engine = DriveEngine::new(backend, false, String::new(), config, Some(new_tx));
    engine.start();
    tracing::warn!("mhrv-drive-node polling Google Drive folder for request sessions");

    while let Some(new_session) = new_rx.recv().await {
        let engine = engine.clone();
        tokio::spawn(async move {
            handle_server_session(engine, new_session).await;
        });
    }
    Ok(())
}

async fn init_backend(config: &Config) -> Result<Arc<GoogleDriveBackend>, DriveError> {
    let backend = Arc::new(GoogleDriveBackend::from_config(config)?);
    backend.login().await?;
    backend.ensure_folder(&config.drive_folder_name).await?;
    tracing::info!(
        "Google Drive backend ready using credentials {}",
        backend.credentials_path().display()
    );
    Ok(backend)
}

async fn handle_socks5_client(
    mut sock: TcpStream,
    engine: Arc<DriveEngine>,
) -> std::io::Result<()> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    sock.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    if req[1] != 0x01 {
        write_socks5_reply(&mut sock, 0x07).await?;
        return Ok(());
    }
    let host = read_socks5_addr(&mut sock, req[3]).await?;
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    let target = format!("{}:{}", host, port);

    let (session_id, mut rx) = engine.add_client_session(target.clone()).await;
    tracing::info!("Drive SOCKS5 CONNECT {} -> session {}", target, session_id);

    // Wait for the server to confirm the upstream connect (FLAG_OPEN_OK)
    // or report a failure (FLAG_CLOSE arriving without ever seeing Open)
    // before replying to the SOCKS5 client. Without this we'd return
    // success for unreachable hosts and the caller would see a half-open
    // socket that immediately closes.
    let mut early_data: Vec<Vec<u8>> = Vec::new();
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    tokio::select! {
        msg = rx.recv() => match msg {
            Some(DriveRx::Open) => {}
            Some(DriveRx::Data(data)) => {
                // Server *should* always send Open before Data, but if
                // the encoder bundles them together in one envelope,
                // treat the first Data as implicit success and forward
                // the bytes after we've replied to the SOCKS5 client.
                early_data.push(data);
            }
            Some(DriveRx::Close) | None => {
                // Connect failed (or session vanished). Use SOCKS5
                // REP=5 (connection refused) since we can't tell
                // refused vs unreachable from here.
                write_socks5_reply(&mut sock, 0x05).await?;
                engine.mark_closed(&session_id).await;
                return Ok(());
            }
        },
        _ = tokio::time::sleep_until(deadline) => {
            // SOCKS5 REP=4 (host unreachable) is the closest match for
            // a connect that didn't even ack within the window.
            write_socks5_reply(&mut sock, 0x04).await?;
            engine.mark_closed(&session_id).await;
            return Ok(());
        }
    }

    write_socks5_reply(&mut sock, 0x00).await?;
    if !early_data.is_empty() {
        for data in &early_data {
            sock.write_all(data).await?;
        }
        sock.flush().await?;
    }
    pump_client_socket(sock, engine, session_id, rx).await
}

async fn read_socks5_addr(sock: &mut TcpStream, atyp: u8) -> std::io::Result<String> {
    match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            Ok(std::net::Ipv4Addr::from(ip).to_string())
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8(name)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad domain"))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            sock.read_exact(&mut ip).await?;
            Ok(std::net::Ipv6Addr::from(ip).to_string())
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad SOCKS5 ATYP",
        )),
    }
}

async fn write_socks5_reply(sock: &mut TcpStream, rep: u8) -> std::io::Result<()> {
    sock.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    sock.flush().await
}

async fn pump_client_socket(
    sock: TcpStream,
    engine: Arc<DriveEngine>,
    session_id: String,
    mut rx: mpsc::Receiver<DriveRx>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = sock.into_split();
    let up_engine = engine.clone();
    let up_sid = session_id.clone();
    let mut upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // If enqueue_tx returns Err the session has been closed
            // (peer hung up, TX buffer overflow, ...). Stop reading
            // from the local socket so we don't drop bytes on the
            // floor — flush_all will already emit a FLAG_CLOSE for us.
            if up_engine.enqueue_tx(&up_sid, &buf[..n]).await.is_err() {
                break;
            }
        }
        up_engine.mark_closed(&up_sid).await;
        Ok::<_, std::io::Error>(())
    });

    let down_engine = engine.clone();
    let down_sid = session_id.clone();
    let mut downstream = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                DriveRx::Open => {} // late open-ack after handshake; harmless
                DriveRx::Data(data) => {
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                }
                DriveRx::Close => break,
            }
        }
        down_engine.mark_closed(&down_sid).await;
        Ok::<_, std::io::Error>(())
    });

    tokio::select! {
        _ = &mut upstream => {}
        _ = &mut downstream => {}
    }
    upstream.abort();
    downstream.abort();
    engine.mark_closed(&session_id).await;
    Ok(())
}

async fn handle_server_session(engine: Arc<DriveEngine>, new_session: DriveNewSession) {
    tracing::info!(
        "Drive server session {} -> {}",
        new_session.id,
        new_session.target_addr
    );
    let stream = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&new_session.target_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::debug!(
                "Drive server connect {} failed: {}",
                new_session.target_addr,
                e
            );
            // mark_closed → next flush emits FLAG_CLOSE without ever
            // having sent FLAG_OPEN_OK, so the client SOCKS5 handshake
            // resolves to a connection-refused reply.
            engine.mark_closed(&new_session.id).await;
            return;
        }
        Err(_) => {
            tracing::debug!("Drive server connect {} timed out", new_session.target_addr);
            engine.mark_closed(&new_session.id).await;
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    // Connect succeeded — flag the session so the next flush carries a
    // FLAG_OPEN_OK envelope back to the SOCKS5 client.
    engine.mark_open_ok(&new_session.id).await;
    let _ = pump_server_socket(stream, engine, new_session.id, new_session.rx).await;
}

async fn pump_server_socket(
    stream: TcpStream,
    engine: Arc<DriveEngine>,
    session_id: String,
    mut rx: mpsc::Receiver<DriveRx>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let up_engine = engine.clone();
    let up_sid = session_id.clone();
    let mut upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if up_engine.enqueue_tx(&up_sid, &buf[..n]).await.is_err() {
                break;
            }
        }
        up_engine.mark_closed(&up_sid).await;
        Ok::<_, std::io::Error>(())
    });

    let down_engine = engine.clone();
    let down_sid = session_id.clone();
    let mut downstream = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                DriveRx::Open => {} // server side never expects Open; ignore defensively
                DriveRx::Data(data) => {
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                }
                DriveRx::Close => break,
            }
        }
        down_engine.mark_closed(&down_sid).await;
        Ok::<_, std::io::Error>(())
    });

    tokio::select! {
        _ = &mut upstream => {}
        _ = &mut downstream => {}
    }
    upstream.abort();
    downstream.abort();
    engine.mark_closed(&session_id).await;
    Ok(())
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8, DriveError> {
    if *pos >= buf.len() {
        return Err(DriveError::BadResponse("truncated Drive envelope".into()));
    }
    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, DriveError> {
    if buf.len().saturating_sub(*pos) < 4 {
        return Err(DriveError::BadResponse(
            "truncated Drive envelope u32".into(),
        ));
    }
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&buf[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_be_bytes(tmp))
}

fn read_u64(buf: &[u8], pos: &mut usize) -> Result<u64, DriveError> {
    if buf.len().saturating_sub(*pos) < 8 {
        return Err(DriveError::BadResponse(
            "truncated Drive envelope u64".into(),
        ));
    }
    let mut tmp = [0u8; 8];
    tmp.copy_from_slice(&buf[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_be_bytes(tmp))
}

fn read_string(buf: &[u8], pos: &mut usize, len: usize) -> Result<String, DriveError> {
    if buf.len().saturating_sub(*pos) < len {
        return Err(DriveError::BadResponse(
            "truncated Drive envelope string".into(),
        ));
    }
    let s = std::str::from_utf8(&buf[*pos..*pos + len])
        .map_err(|_| DriveError::BadResponse("non-utf8 Drive envelope string".into()))?
        .to_string();
    *pos += len;
    Ok(s)
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn timestamp_from_filename(filename: &str) -> Option<u128> {
    let tail = filename.rsplit_once("-mux-")?.1;
    tail.strip_suffix(".bin")?.parse::<u128>().ok()
}

/// Extract the embedded client_id from either a `req-<cid>-mux-…` or
/// `res-<cid>-mux-…` filename. Used on the server side (for `req-`) to
/// learn which client a session belongs to so the response is
/// addressed back to the same client; clients only ever read files
/// already filtered to their own id by the listing prefix.
fn client_id_from_filename(filename: &str) -> Option<String> {
    let rest = filename
        .strip_prefix("req-")
        .or_else(|| filename.strip_prefix("res-"))?;
    let (client_id, _) = rest.split_once("-mux-")?;
    Some(client_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_close_and_open() {
        let env = Envelope {
            session_id: "abc".into(),
            seq: 42,
            target_addr: "example.com:443".into(),
            payload: b"hello".to_vec(),
            flags: FLAG_CLOSE | FLAG_OPEN_OK,
        };
        let mut buf = Vec::new();
        env.encode(&mut buf).unwrap();
        // Magic + version are on the wire so a future format change
        // can be detected at decode time instead of corrupting state.
        assert_eq!(buf[0], MAGIC_BYTE);
        assert_eq!(buf[1], ENVELOPE_VERSION);
        let mut pos = 0;
        let got = Envelope::decode_one(&buf, &mut pos).unwrap().unwrap();
        assert_eq!(got.session_id, "abc");
        assert_eq!(got.seq, 42);
        assert_eq!(got.target_addr, "example.com:443");
        assert_eq!(&got.payload, b"hello");
        assert_eq!(got.flags, FLAG_CLOSE | FLAG_OPEN_OK);
        assert!(Envelope::decode_one(&buf, &mut pos).unwrap().is_none());
    }

    #[test]
    fn envelope_decode_rejects_wrong_version() {
        let env = Envelope {
            session_id: "x".into(),
            seq: 0,
            target_addr: String::new(),
            payload: Vec::new(),
            flags: 0,
        };
        let mut buf = Vec::new();
        env.encode(&mut buf).unwrap();
        buf[1] = 0xff;
        let mut pos = 0;
        assert!(Envelope::decode_one(&buf, &mut pos).is_err());
    }

    #[tokio::test]
    async fn rx_queue_reorders_out_of_order_envelopes() {
        let (session, mut rx) =
            DriveSession::new("sid".into(), "target:443".into(), "cid".into());
        let make_env = |seq: u64, payload: &[u8], flags: u8| Envelope {
            session_id: "sid".into(),
            seq,
            target_addr: String::new(),
            payload: payload.to_vec(),
            flags,
        };
        // Apply seq=2 first, then seq=0, then seq=1; expect everything
        // to surface in seq order with a final Close.
        process_rx(session.clone(), make_env(2, b"world", FLAG_CLOSE)).await;
        process_rx(session.clone(), make_env(0, b"hel", 0)).await;
        process_rx(session.clone(), make_env(1, b"lo ", 0)).await;

        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut saw_close = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            match msg {
                Some(DriveRx::Data(d)) => payloads.push(d),
                Some(DriveRx::Close) => {
                    saw_close = true;
                    break;
                }
                Some(DriveRx::Open) => {}
                None => break,
            }
        }
        assert_eq!(
            payloads,
            vec![b"hel".to_vec(), b"lo ".to_vec(), b"world".to_vec()]
        );
        assert!(saw_close, "expected DriveRx::Close to surface after seq=2");
    }


    #[test]
    fn filename_helpers_parse_client_and_timestamp() {
        let req = "req-client-a-mux-12345.bin";
        assert_eq!(client_id_from_filename(req).as_deref(), Some("client-a"));
        assert_eq!(timestamp_from_filename(req), Some(12345));

        let res = "res-client-b-mux-67890.bin";
        assert_eq!(client_id_from_filename(res).as_deref(), Some("client-b"));
        assert_eq!(timestamp_from_filename(res), Some(67890));

        assert!(client_id_from_filename("garbage.txt").is_none());
    }
}
