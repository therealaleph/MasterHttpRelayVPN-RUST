//! Apps Script relay client.
//!
//! Opens a TLS connection to the configured Google IP while the TLS SNI is set
//! to `front_domain` (e.g. "www.google.com"). Inside the encrypted stream, HTTP
//! `Host` points to `script.google.com`, and we POST a JSON payload to
//! `/macros/s/{script_id}/exec`. Apps Script performs the actual upstream
//! HTTP fetch server-side and returns a JSON envelope.
//!
//! TODO: add HTTP/2 multiplexing (`h2` crate) for lower latency.
//! TODO: add parallel range-based downloads.

use std::collections::HashMap;
// AtomicU64 via portable-atomic: native on 64-bit / armv7, spinlock-
// backed on mipsel (MIPS32 has no 64-bit atomic instructions). API
// is identical to std::sync::atomic::AtomicU64 so call sites need
// no other changes.
use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use crate::cache::{cache_key, is_cacheable_method, parse_ttl, ResponseCache};
use crate::config::Config;

#[derive(Debug, thiserror::Error)]
pub enum FronterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid dns name: {0}")]
    Dns(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("relay error: {0}")]
    Relay(String),
    #[error("timeout")]
    Timeout,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

type PooledStream = TlsStream<TcpStream>;
const POOL_TTL_SECS: u64 = 45;
const POOL_MAX: usize = 80;
const REQUEST_TIMEOUT_SECS: u64 = 25;

struct PoolEntry {
    stream: PooledStream,
    created: Instant,
}

pub struct DomainFronter {
    connect_host: String,
    /// Pool of SNI domains to rotate through per outbound connection. All of
    /// them must be hosted on the same Google edge as `connect_host` (that's
    /// the whole point of domain fronting). Rotating across several of them
    /// defeats naive DPI that would count "too many connections to a single
    /// SNI". Populated from config's front_domain: if that's a single name we
    /// add a small pool of known-safe Google subdomains automatically.
    sni_hosts: Vec<String>,
    sni_idx: AtomicUsize,
    http_host: &'static str,
    auth_key: String,
    script_ids: Vec<String>,
    script_idx: AtomicUsize,
    /// Fan-out factor: fire this many Apps Script instances in parallel
    /// per request and return first success. `<= 1` = off.
    parallel_relay: usize,
    /// Enable the `normalize_x_graphql` URL rewrite (issue #16, credit
    /// seramo_ir). When true, GETs to `x.com/i/api/graphql/<hash>/<op>`
    /// have their query trimmed to the first `variables=` block so the
    /// response cache isn't busted by the constantly-changing `features`
    /// / `fieldToggles` params.
    normalize_x_graphql: bool,
    /// Set once we've emitted the "UnknownIssuer means ISP MITM" hint,
    /// so we don't spam it every time a cert-validation error repeats.
    cert_hint_shown: std::sync::atomic::AtomicBool,
    tls_connector: TlsConnector,
    pool: Arc<Mutex<Vec<PoolEntry>>>,
    cache: Arc<ResponseCache>,
    inflight: Arc<Mutex<HashMap<String, broadcast::Sender<Vec<u8>>>>>,
    coalesced: AtomicU64,
    blacklist: Arc<std::sync::Mutex<HashMap<String, Instant>>>,
    relay_calls: AtomicU64,
    relay_failures: AtomicU64,
    bytes_relayed: AtomicU64,
    /// Per-host breakdown of traffic going through this fronter. Keyed by
    /// the host of the URL (e.g. "api.x.com"). Read-mostly; only touched
    /// on the slow path (once per relayed request), so a plain Mutex is
    /// fine.
    per_site: Arc<std::sync::Mutex<HashMap<String, HostStat>>>,
}

/// Aggregated stats for one remote host.
#[derive(Default, Clone, Debug)]
pub struct HostStat {
    pub requests: u64,
    pub cache_hits: u64,
    pub bytes: u64,
    pub total_latency_ns: u64,
}

impl HostStat {
    pub fn avg_latency_ms(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            (self.total_latency_ns as f64) / (self.requests as f64) / 1_000_000.0
        }
    }
}

const BLACKLIST_COOLDOWN_SECS: u64 = 600;

/// Request payload sent to Apps Script (single, non-batch).
#[derive(Serialize)]
struct RelayRequest<'a> {
    k: &'a str,
    m: &'a str,
    u: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    h: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ct: Option<&'a str>,
    r: bool,
}

/// Parsed Apps Script response JSON (single mode).
#[derive(Deserialize, Default)]
struct RelayResponse {
    #[serde(default)]
    s: Option<u16>,
    #[serde(default)]
    h: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    b: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// Parsed tunnel response JSON (full mode).
#[derive(Deserialize, Debug, Clone)]
pub struct TunnelResponse {
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub d: Option<String>,
    #[serde(default)]
    pub eof: Option<bool>,
    #[serde(default)]
    pub e: Option<String>,
}

/// A single op in a batch tunnel request.
#[derive(Serialize, Clone, Debug)]
pub struct BatchOp {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

/// Batch tunnel response from Apps Script / tunnel node.
#[derive(Deserialize, Debug)]
pub struct BatchTunnelResponse {
    #[serde(default)]
    pub r: Vec<TunnelResponse>,
    #[serde(default)]
    pub e: Option<String>,
}

impl DomainFronter {
    pub fn new(config: &Config) -> Result<Self, FronterError> {
        let script_ids = config.script_ids_resolved();
        if script_ids.is_empty() {
            return Err(FronterError::Relay("no script_id configured".into()));
        }
        let tls_config = if config.verify_ssl {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth()
        };
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            connect_host: config.google_ip.clone(),
            sni_hosts: build_sni_pool_for(
                &config.front_domain,
                config.sni_hosts.as_deref().unwrap_or(&[]),
            ),
            sni_idx: AtomicUsize::new(0),
            http_host: "script.google.com",
            auth_key: config.auth_key.clone(),
            parallel_relay: config.parallel_relay as usize,
            normalize_x_graphql: config.normalize_x_graphql,
            cert_hint_shown: std::sync::atomic::AtomicBool::new(false),
            script_ids,
            script_idx: AtomicUsize::new(0),
            tls_connector,
            pool: Arc::new(Mutex::new(Vec::new())),
            cache: Arc::new(ResponseCache::with_default()),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            coalesced: AtomicU64::new(0),
            blacklist: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_calls: AtomicU64::new(0),
            relay_failures: AtomicU64::new(0),
            bytes_relayed: AtomicU64::new(0),
            per_site: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Increment the per-site counters. Called on every logical request
    /// (both cache hits and relay roundtrips).
    fn record_site(&self, url: &str, cache_hit: bool, bytes: u64, latency_ns: u64) {
        let host = match extract_host(url) {
            Some(h) => h,
            None => return,
        };
        let mut m = self.per_site.lock().unwrap();
        let e = m.entry(host).or_default();
        e.requests += 1;
        if cache_hit {
            e.cache_hits += 1;
        }
        e.bytes += bytes;
        e.total_latency_ns += latency_ns;
    }

    /// Snapshot per-site stats, sorted by request count descending.
    pub fn snapshot_per_site(&self) -> Vec<(String, HostStat)> {
        let m = self.per_site.lock().unwrap();
        let mut v: Vec<(String, HostStat)> =
            m.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort_by(|a, b| b.1.requests.cmp(&a.1.requests));
        v
    }

    pub fn snapshot_stats(&self) -> StatsSnapshot {
        let bl = self.blacklist.lock().unwrap();
        StatsSnapshot {
            relay_calls: self.relay_calls.load(Ordering::Relaxed),
            relay_failures: self.relay_failures.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            bytes_relayed: self.bytes_relayed.load(Ordering::Relaxed),
            cache_hits: self.cache.hits(),
            cache_misses: self.cache.misses(),
            cache_bytes: self.cache.size(),
            blacklisted_scripts: bl.len(),
            total_scripts: self.script_ids.len(),
        }
    }

    pub fn num_scripts(&self) -> usize {
        self.script_ids.len()
    }

    pub fn cache(&self) -> &ResponseCache {
        &self.cache
    }

    pub fn coalesced_count(&self) -> u64 {
        self.coalesced.load(Ordering::Relaxed)
    }

    fn next_script_id(&self) -> String {
        let n = self.script_ids.len();
        let mut bl = self.blacklist.lock().unwrap();
        let now = Instant::now();
        bl.retain(|_, until| *until > now);

        for _ in 0..n {
            let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
            let sid = &self.script_ids[idx % n];
            if !bl.contains_key(sid) {
                return sid.clone();
            }
        }
        // All blacklisted: pick whichever comes off cooldown soonest.
        if let Some((sid, _)) = bl.iter().min_by_key(|(_, t)| **t) {
            let sid = sid.clone();
            bl.remove(&sid);
            return sid;
        }
        self.script_ids[0].clone()
    }

    /// Pick `want` distinct non-blacklisted script IDs for a parallel fan-out
    /// dispatch. Returns fewer than `want` if there aren't enough non-blacklisted
    /// IDs available. Advances the round-robin index by `want` to spread load
    /// across subsequent calls.
    fn next_script_ids(&self, want: usize) -> Vec<String> {
        let n = self.script_ids.len();
        if n == 0 {
            return vec![];
        }
        let mut bl = self.blacklist.lock().unwrap();
        let now = Instant::now();
        bl.retain(|_, until| *until > now);

        let mut picked: Vec<String> = Vec::with_capacity(want);
        for _ in 0..n {
            if picked.len() >= want {
                break;
            }
            let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
            let sid = &self.script_ids[idx % n];
            if !bl.contains_key(sid) && !picked.iter().any(|p| p == sid) {
                picked.push(sid.clone());
            }
        }
        if picked.is_empty() {
            picked.push(self.script_ids[0].clone());
        }
        picked
    }

    fn blacklist_script(&self, script_id: &str, reason: &str) {
        let until = Instant::now() + Duration::from_secs(BLACKLIST_COOLDOWN_SECS);
        let mut bl = self.blacklist.lock().unwrap();
        bl.insert(script_id.to_string(), until);
        tracing::warn!(
            "blacklisted script {} for {}s: {}",
            mask_script_id(script_id),
            BLACKLIST_COOLDOWN_SECS,
            reason
        );
    }

    /// Log a relay failure with extra guidance on cert-validation cases.
    /// Rate-limited so a flood of identical "UnknownIssuer" errors doesn't
    /// fill the log.
    fn log_relay_failure(&self, e: &FronterError) {
        let msg = e.to_string();
        let is_cert_issue = msg.contains("UnknownIssuer")
            || msg.contains("invalid peer certificate")
            || msg.contains("CertificateExpired")
            || msg.contains("CertNotValidYet")
            || msg.contains("NotValidForName");
        if is_cert_issue
            && !self
                .cert_hint_shown
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            // First time — print the full diagnostic. Subsequent hits
            // drop to debug so the log stays readable.
            tracing::error!(
                "Relay failed: {} — this almost always means one of:\n  \
                 (1) your ISP or a middlebox is intercepting TLS to the Google edge \
                 (common in Iran / IR);\n  \
                 (2) the `google_ip` in your config is pointing at a non-Google host;\n  \
                 (3) your system clock is way off (NTP not synced).\n\
                 Fixes (try in order): run `mhrv-rs scan-ips` to find a different Google \
                 frontend IP that isn't being MITM'd; check `date` on your host; as a \
                 LAST RESORT set `\"verify_ssl\": false` in config.json — this lets the \
                 relay work even through a middlebox, but your traffic is then only \
                 protected by the Apps Script relay's secret `auth_key`, not by outer TLS.",
                e
            );
        } else if is_cert_issue {
            tracing::debug!("Relay failed (cert): {}", e);
        } else {
            tracing::error!("Relay failed: {}", e);
        }
    }

    fn next_sni(&self) -> String {
        let n = self.sni_hosts.len();
        let i = self.sni_idx.fetch_add(1, Ordering::Relaxed) % n;
        self.sni_hosts[i].clone()
    }

    async fn open(&self) -> Result<PooledStream, FronterError> {
        let tcp = TcpStream::connect((self.connect_host.as_str(), 443u16)).await?;
        let _ = tcp.set_nodelay(true);
        let sni = self.next_sni();
        let name = ServerName::try_from(sni)?;
        let tls = self.tls_connector.connect(name, tcp).await?;
        Ok(tls)
    }

    /// Open `n` outbound TLS connections in parallel and park them in the
    /// pool so the first few user requests don't pay the handshake cost.
    /// Errors are logged but not returned — best-effort.
    pub async fn warm(self: &Arc<Self>, n: usize) {
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..n {
            let me = self.clone();
            set.spawn(async move {
                match me.open().await {
                    Ok(s) => Some(PoolEntry {
                        stream: s,
                        created: Instant::now(),
                    }),
                    Err(e) => {
                        tracing::debug!("pool warm: open failed: {}", e);
                        None
                    }
                }
            });
        }
        let mut warmed = 0;
        while let Some(res) = set.join_next().await {
            if let Ok(Some(entry)) = res {
                let mut pool = self.pool.lock().await;
                if pool.len() < POOL_MAX {
                    pool.push(entry);
                    warmed += 1;
                }
            }
        }
        if warmed > 0 {
            tracing::info!("pool pre-warmed with {} connection(s)", warmed);
        }
    }

    async fn acquire(&self) -> Result<PoolEntry, FronterError> {
        {
            let mut pool = self.pool.lock().await;
            while let Some(entry) = pool.pop() {
                if entry.created.elapsed().as_secs() < POOL_TTL_SECS {
                    return Ok(entry);
                }
                // expired — drop it
                drop(entry);
            }
        }
        let stream = self.open().await?;
        Ok(PoolEntry {
            stream,
            created: Instant::now(),
        })
    }

    async fn release(&self, entry: PoolEntry) {
        if entry.created.elapsed().as_secs() >= POOL_TTL_SECS {
            return;
        }
        let mut pool = self.pool.lock().await;
        if pool.len() < POOL_MAX {
            pool.push(entry);
        }
    }

    /// Relay an HTTP request through Apps Script.
    /// Returns a raw HTTP/1.1 response (status line + headers + body) suitable
    /// for writing back to the browser over an MITM'd TLS stream.
    pub async fn relay(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        // Optional URL rewrite for X/Twitter GraphQL (issue #16). Applied
        // here, at the top of relay(), so it affects BOTH the cache key
        // (so matching requests collapse into one entry) AND the URL that
        // gets sent upstream to Apps Script (so Apps Script only has to
        // fetch the trimmed variant, cutting quota usage).
        let normalized;
        let url: &str = if self.normalize_x_graphql {
            normalized = normalize_x_graphql_url(url);
            normalized.as_str()
        } else {
            url
        };

        // Range requests are partial-content responses; caching or
        // coalescing them against a non-range key would be catastrophic
        // (wrong bytes for the wrong consumer). The range-parallel
        // downloader calls `relay()` concurrently with N different Range
        // headers for the same URL, and absolutely needs each call to go
        // to the relay independently. Simplest correct answer: if any
        // Range header is present, skip cache and coalesce entirely.
        let has_range = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range"));
        let coalescible = is_cacheable_method(method) && body.is_empty() && !has_range;
        let key = if coalescible { Some(cache_key(method, url)) } else { None };
        let t_start = Instant::now();

        if let Some(ref k) = key {
            if let Some(hit) = self.cache.get(k) {
                tracing::debug!("cache hit: {}", url);
                self.record_site(url, true, hit.len() as u64, t_start.elapsed().as_nanos() as u64);
                return hit;
            }
        }

        // Coalesce concurrent identical requests: only the first caller actually
        // hits the relay; waiters subscribe to the same broadcast channel.
        let waiter = if let Some(ref k) = key {
            let mut inflight = self.inflight.lock().await;
            match inflight.get(k) {
                Some(tx) => {
                    let rx = tx.subscribe();
                    self.coalesced.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("coalesced: {}", url);
                    Some(rx)
                }
                None => {
                    let (tx, _) = broadcast::channel(1);
                    inflight.insert(k.clone(), tx);
                    None
                }
            }
        } else {
            None
        };

        if let Some(mut rx) = waiter {
            match rx.recv().await {
                Ok(bytes) => return bytes,
                Err(_) => return error_response(502, "coalesced request dropped"),
            }
        }

        let bytes = self.relay_uncoalesced(method, url, headers, body, key.as_deref()).await;

        if let Some(ref k) = key {
            let mut inflight = self.inflight.lock().await;
            if let Some(tx) = inflight.remove(k) {
                let _ = tx.send(bytes.clone());
            }
        }

        self.record_site(url, false, bytes.len() as u64, t_start.elapsed().as_nanos() as u64);
        bytes
    }

    /// Range-parallel relay — the big difference between this port and
    /// the upstream Python version. Apps Script's per-call cost is
    /// ~flat (1-2s regardless of payload), so a 10MB single GET is
    /// ~10s round-trip; the same 10MB sliced into 40 x 256KB chunks
    /// and fetched 16-at-a-time is 3-4 round-trips, total ~6-8s, and
    /// the client sees the first byte in 1-2s instead of 10. This is
    /// what actually makes YouTube video playback viable through the
    /// relay — without it, googlevideo.com chunks timeout or stall
    /// while the player waits for the next 10s-away Apps Script call
    /// to finish.
    ///
    /// Flow (mirrors upstream `relay_parallel`):
    ///   1. For anything other than GET-without-body, defer to
    ///      `relay()` — range requests on POSTs / PUTs aren't well
    ///      defined, and the user-sent-Range-header case is handled
    ///      by relay() already (we skip cache for it).
    ///   2. Probe with `Range: bytes=0-<chunk-1>`.
    ///   3. 200 back (origin doesn't support ranges) → return as-is.
    ///   4. 206 back → parse Content-Range total. If the body fits in
    ///      the first probe (total <= chunk or body >= total), rewrite
    ///      the 206 to a 200 so the client — which never asked for a
    ///      range — doesn't choke on a stray Partial Content. (x.com
    ///      and Cloudflare turnstile in particular reject unsolicited
    ///      206 on XHR/fetch.)
    ///   5. Else: compute the remaining ranges, fetch them with
    ///      bounded concurrency, stitch, return as 200.
    ///
    /// If any later chunk fails validation or fetch, we fall back to the
    /// probe's single-chunk response as a graceful-degradation, but we do
    /// not stitch unchecked bytes into a fake full-success response.
    pub async fn relay_parallel_range(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        const CHUNK: u64 = 256 * 1024;
        const MAX_PARALLEL: usize = 16;

        if method != "GET" || !body.is_empty() {
            return self.relay(method, url, headers, body).await;
        }
        // If the client already sent a Range header, honour it as-is —
        // don't second-guess a caller that knows what bytes they want.
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("range")) {
            return self.relay(method, url, headers, body).await;
        }

        // Probe with the first chunk.
        let mut probe_headers: Vec<(String, String)> = headers.to_vec();
        probe_headers.push(("Range".into(), format!("bytes=0-{}", CHUNK - 1)));
        let first = self.relay(method, url, &probe_headers, body).await;

        let (status, resp_headers, resp_body) = match split_response(&first) {
            Some(v) => v,
            None => return first,
        };

        if status != 206 {
            // Origin returned the whole thing (or an error). Either way,
            // pass through.
            return first;
        }

        let probe_range = match validate_probe_range(status, &resp_headers, resp_body, CHUNK - 1)
        {
            Some(r) => r,
            None => {
                tracing::warn!(
                    "range-parallel: probe returned invalid 206 for {}; falling back to single GET",
                    url,
                );
                return self.relay(method, url, headers, body).await;
            }
        };
        let total = probe_range.total;

        if total <= CHUNK || (probe_range.end + 1) >= total {
            return rewrite_206_to_200(&first);
        }

        // Plan remaining ranges after what the probe already returned.
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut start = probe_range.end + 1;
        while start < total {
            let end = (start + CHUNK - 1).min(total - 1);
            ranges.push((start, end));
            start = end + 1;
        }

        tracing::info!(
            "range-parallel: {} bytes total, {} chunks remaining after probe, up to {} in flight",
            total, ranges.len(), MAX_PARALLEL,
        );

        // Concurrent fetch with `buffered` — preserves input order
        // (important for stitching) and caps in-flight count. Each task
        // calls back into `relay()`, which already has retry + fan-out
        // wiring on single-request granularity; we don't duplicate
        // those here.
        use futures_util::stream::{self, StreamExt};
        let url_owned = url.to_string();
        let base_headers = headers.to_vec();
        let fetches = stream::iter(ranges.into_iter())
            .map(|(s, e)| {
                let url = url_owned.clone();
                let mut h = base_headers.clone();
                // Force a single Range header — if the caller's headers
                // somehow already had one we wouldn't be here, but be
                // defensive anyway.
                h.retain(|(k, _)| !k.eq_ignore_ascii_case("range"));
                h.push(("Range".into(), format!("bytes={}-{}", s, e)));
                async move {
                    let raw = self.relay("GET", &url, &h, &[]).await;
                    (s, e, extract_exact_range_body(&raw, s, e, total))
                }
            })
            .buffered(MAX_PARALLEL)
            .collect::<Vec<_>>()
            .await;

        // Stitch: probe body first, then the chunks in order.
        let mut full = Vec::with_capacity(total as usize);
        full.extend_from_slice(resp_body);
        for (start, end, chunk) in fetches {
            match chunk {
                Ok(chunk) => full.extend_from_slice(&chunk),
                Err(reason) => {
                    tracing::warn!(
                        "range-parallel: invalid chunk {}-{} for {} ({}); falling back to probe response",
                        start,
                        end,
                        url,
                        reason,
                    );
                    return rewrite_206_to_200(&first);
                }
            }
        }

        if (full.len() as u64) != total {
            tracing::warn!(
                "range-parallel: stitched {}/{} bytes for {}; falling back to probe response",
                full.len(), total, url,
            );
            return rewrite_206_to_200(&first);
        }

        // Build a 200 OK with Content-Length = full body length. Drop
        // the Content-Range header (no longer applicable) and
        // Transfer-Encoding/Content-Encoding (origin already decoded
        // what we got; we ship plain bytes).
        assemble_full_200(&resp_headers, &full)
    }

    async fn relay_uncoalesced(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        cache_key_opt: Option<&str>,
    ) -> Vec<u8> {
        self.relay_calls.fetch_add(1, Ordering::Relaxed);
        let bytes = match timeout(
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
            self.do_relay_with_retry(method, url, headers, body),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                self.relay_failures.fetch_add(1, Ordering::Relaxed);
                self.log_relay_failure(&e);
                return error_response(502, &format!("Relay error: {}", e));
            }
            Err(_) => {
                self.relay_failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!("Relay timeout");
                return error_response(504, "Relay timeout");
            }
        };
        self.bytes_relayed.fetch_add(bytes.len() as u64, Ordering::Relaxed);

        if let Some(k) = cache_key_opt {
            if let Some(ttl) = parse_ttl(&bytes, url) {
                tracing::debug!("cache store: {} ttl={}s", url, ttl.as_secs());
                self.cache.put(k.to_string(), bytes.clone(), ttl);
            }
        }
        bytes
    }

    async fn do_relay_with_retry(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        // Fan-out path: fire N instances in parallel, return first Ok, cancel
        // the rest. Clamps to number of available script IDs so the single-ID
        // case is a no-op even if parallel_relay>1 was configured.
        let fan = self.parallel_relay.min(self.script_ids.len()).max(1);
        if fan >= 2 {
            return self.do_relay_parallel(method, url, headers, body, fan).await;
        }

        // Sequential path: one retry on connection failure.
        match self.do_relay_once(method, url, headers, body).await {
            Ok(v) => Ok(v),
            Err(e) => {
                tracing::debug!("relay attempt 1 failed: {}; retrying", e);
                self.do_relay_once(method, url, headers, body).await
            }
        }
    }

    async fn do_relay_parallel(
        self: &Self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        fan: usize,
    ) -> Result<Vec<u8>, FronterError> {
        use futures_util::future::FutureExt;
        let ids = self.next_script_ids(fan);
        if ids.is_empty() {
            return Err(FronterError::Relay("no script_ids available".into()));
        }

        // Build one future per script, each a pinned boxed future so we can
        // `select_ok` over them.
        let mut futs = Vec::with_capacity(ids.len());
        for sid in ids {
            let fut = self.do_relay_once_with(sid.clone(), method, url, headers, body).boxed();
            futs.push(fut);
        }

        // `select_ok`: drive all futures concurrently, return the first Ok
        // (cancelling the rest when the returned future is dropped). If all
        // error out, returns the last error.
        match futures_util::future::select_ok(futs).await {
            Ok((bytes, _remaining)) => Ok(bytes),
            Err(e) => Err(e),
        }
    }

    async fn do_relay_once(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let script_id = self.next_script_id();
        self.do_relay_once_with(script_id, method, url, headers, body).await
    }

    async fn do_relay_once_with(
        &self,
        script_id: String,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let payload = self.build_payload_json(method, url, headers, body)?;
        let path = format!("/macros/s/{}/exec", script_id);

        let mut entry = self.acquire().await?;
        let reuse_ok = {
            let write_res = async {
                let req_head = format!(
                    "POST {path} HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {len}\r\n\
                     Accept-Encoding: gzip\r\n\
                     Connection: keep-alive\r\n\
                     \r\n",
                    path = path,
                    host = self.http_host,
                    len = payload.len(),
                );
                entry.stream.write_all(req_head.as_bytes()).await?;
                entry.stream.write_all(&payload).await?;
                entry.stream.flush().await?;

                let (status, resp_headers, resp_body) =
                    read_http_response(&mut entry.stream).await?;
                Ok::<_, FronterError>((status, resp_headers, resp_body))
            }
            .await;

            match write_res {
                Err(e) => {
                    // Connection may be dead — don't return to pool.
                    return Err(e);
                }
                Ok((mut status, mut resp_headers, mut resp_body)) => {
                    // Follow redirect chain (Apps Script usually redirects
                    // /exec to googleusercontent.com). Up to 5 hops, same
                    // connection.
                    for _ in 0..5 {
                        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                            break;
                        }
                        let Some(loc) = header_get(&resp_headers, "location") else {
                            break;
                        };
                        let (rpath, rhost) = parse_redirect(&loc);
                        let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
                        let req = format!(
                            "GET {rpath} HTTP/1.1\r\n\
                             Host: {rhost}\r\n\
                             Accept-Encoding: gzip\r\n\
                             Connection: keep-alive\r\n\
                             \r\n",
                        );
                        entry.stream.write_all(req.as_bytes()).await?;
                        entry.stream.flush().await?;
                        let (s, h, b) = read_http_response(&mut entry.stream).await?;
                        status = s;
                        resp_headers = h;
                        resp_body = b;
                    }

                    if status != 200 {
                        let body_txt = String::from_utf8_lossy(&resp_body)
                            .chars()
                            .take(200)
                            .collect::<String>();
                        if should_blacklist(status, &body_txt) {
                            self.blacklist_script(&script_id, &format!("HTTP {}", status));
                        }
                        return Err(FronterError::Relay(format!(
                            "Apps Script HTTP {}: {}",
                            status, body_txt
                        )));
                    }
                    match parse_relay_json(&resp_body) {
                        Ok(bytes) => Ok::<_, FronterError>((bytes, true)),
                        Err(e) => {
                            if let FronterError::Relay(ref msg) = e {
                                if looks_like_quota_error(msg) {
                                    self.blacklist_script(&script_id, msg);
                                }
                            }
                            Err(e)
                        }
                    }
                }
            }
        };

        match reuse_ok {
            Ok((bytes, reuse)) => {
                if reuse {
                    self.release(entry).await;
                }
                Ok(bytes)
            }
            Err(e) => Err(e),
        }
    }

    fn build_payload_json(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let filtered = filter_forwarded_headers(headers);
        let hmap = if filtered.is_empty() {
            None
        } else {
            let mut m = serde_json::Map::with_capacity(filtered.len());
            for (k, v) in &filtered {
                m.insert(k.clone(), Value::String(v.clone()));
            }
            Some(m)
        };
        let b_encoded = if body.is_empty() {
            None
        } else {
            Some(B64.encode(body))
        };
        let ct = if body.is_empty() {
            None
        } else {
            find_header(headers, "content-type")
        };
        let req = RelayRequest {
            k: &self.auth_key,
            m: method,
            u: url,
            h: hmap,
            b: b_encoded,
            ct,
            r: true,
        };
        Ok(serde_json::to_vec(&req)?)
    }

    // ────── Full-mode tunnel protocol ──────────────────────────────────

    /// Send a tunnel-protocol request through the domain-fronted connection
    /// to Apps Script. Reuses the same TLS pool as `relay()` but builds a
    /// tunnel JSON payload (the `t` field triggers `_doTunnel` in CodeFull.gs).
    pub async fn tunnel_request(
        &self,
        op: &str,
        host: Option<&str>,
        port: Option<u16>,
        sid: Option<&str>,
        data: Option<String>,
    ) -> Result<TunnelResponse, FronterError> {
        let payload = self.build_tunnel_payload(op, host, port, sid, data)?;
        let script_id = self.next_script_id();
        let path = format!("/macros/s/{}/exec", script_id);

        let mut entry = self.acquire().await?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response(&mut entry.stream).await?;

        // Follow redirect chain (Apps Script usually redirects /exec to
        // googleusercontent.com). Same logic as do_relay_once_with.
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                break;
            }
            let Some(loc) = header_get(&resp_headers, "location") else {
                break;
            };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\n\
                 Host: {rhost}\r\n\
                 Accept-Encoding: gzip\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) = read_http_response(&mut entry.stream).await?;
            status = s;
            resp_headers = h;
            resp_body = b;
        }

        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body)
                .chars()
                .take(200)
                .collect::<String>();
            if should_blacklist(status, &body_txt) {
                self.blacklist_script(&script_id, &format!("HTTP {}", status));
            }
            return Err(FronterError::Relay(format!(
                "tunnel HTTP {}: {}",
                status, body_txt
            )));
        }

        // Parse tunnel response JSON
        let text = std::str::from_utf8(&resp_body)
            .map_err(|_| FronterError::BadResponse("non-utf8 tunnel response".into()))?
            .trim();

        // Apps Script may prepend HTML; extract first {...}
        let json_str = if text.starts_with('{') {
            text
        } else {
            let start = text.find('{').ok_or_else(|| {
                FronterError::BadResponse(format!("no json in tunnel response: {}", &text[..text.len().min(200)]))
            })?;
            let end = text.rfind('}').ok_or_else(|| {
                FronterError::BadResponse("no json end in tunnel response".into())
            })?;
            &text[start..=end]
        };

        let resp: TunnelResponse = serde_json::from_str(json_str)?;

        self.release(entry).await;
        Ok(resp)
    }

    fn build_tunnel_payload(
        &self,
        op: &str,
        host: Option<&str>,
        port: Option<u16>,
        sid: Option<&str>,
        data: Option<String>,
    ) -> Result<Vec<u8>, FronterError> {
        let mut map = serde_json::Map::new();
        map.insert("k".into(), Value::String(self.auth_key.clone()));
        map.insert("t".into(), Value::String(op.to_string()));
        if let Some(h) = host {
            map.insert("h".into(), Value::String(h.to_string()));
        }
        if let Some(p) = port {
            map.insert("p".into(), Value::Number(serde_json::Number::from(p)));
        }
        if let Some(s) = sid {
            map.insert("sid".into(), Value::String(s.to_string()));
        }
        if let Some(d) = data {
            map.insert("d".into(), Value::String(d));
        }
        Ok(serde_json::to_vec(&Value::Object(map))?)
    }

    /// Send a batch of tunnel operations in one Apps Script round trip.
    /// All active sessions' data is collected and sent together, and all
    /// responses come back in one response. This reduces N Apps Script
    /// calls to 1 per tick.
    pub async fn tunnel_batch_request(
        &self,
        ops: &[BatchOp],
    ) -> Result<BatchTunnelResponse, FronterError> {
        let mut map = serde_json::Map::new();
        map.insert("k".into(), Value::String(self.auth_key.clone()));
        map.insert("t".into(), Value::String("batch".into()));
        map.insert("ops".into(), serde_json::to_value(ops)?);
        let payload = serde_json::to_vec(&Value::Object(map))?;

        let script_id = self.next_script_id();
        let path = format!("/macros/s/{}/exec", script_id);

        let mut entry = self.acquire().await?;

        let req_head = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Accept-Encoding: gzip\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path = path,
            host = self.http_host,
            len = payload.len(),
        );
        entry.stream.write_all(req_head.as_bytes()).await?;
        entry.stream.write_all(&payload).await?;
        entry.stream.flush().await?;

        let (mut status, mut resp_headers, mut resp_body) =
            read_http_response(&mut entry.stream).await?;

        // Follow redirect chain
        for _ in 0..5 {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) { break; }
            let Some(loc) = header_get(&resp_headers, "location") else { break; };
            let (rpath, rhost) = parse_redirect(&loc);
            let rhost = rhost.unwrap_or_else(|| self.http_host.to_string());
            let req = format!(
                "GET {rpath} HTTP/1.1\r\nHost: {rhost}\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n",
            );
            entry.stream.write_all(req.as_bytes()).await?;
            entry.stream.flush().await?;
            let (s, h, b) = read_http_response(&mut entry.stream).await?;
            status = s; resp_headers = h; resp_body = b;
        }

        if status != 200 {
            let body_txt = String::from_utf8_lossy(&resp_body).chars().take(200).collect::<String>();
            if should_blacklist(status, &body_txt) {
                self.blacklist_script(&script_id, &format!("HTTP {}", status));
            }
            return Err(FronterError::Relay(format!("batch tunnel HTTP {}: {}", status, body_txt)));
        }

        let text = std::str::from_utf8(&resp_body)
            .map_err(|_| FronterError::BadResponse("non-utf8 batch response".into()))?
            .trim();

        let json_str = if text.starts_with('{') {
            text
        } else {
            let start = text.find('{').ok_or_else(|| {
                FronterError::BadResponse(format!("no json in batch response: {}", &text[..text.len().min(200)]))
            })?;
            let end = text.rfind('}').ok_or_else(|| {
                FronterError::BadResponse("no json end in batch response".into())
            })?;
            &text[start..=end]
        };

        tracing::debug!("batch response body: {}", &json_str[..json_str.len().min(500)]);

        let resp: BatchTunnelResponse = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("batch JSON parse error: {} — body: {}", e, &json_str[..json_str.len().min(300)]);
                return Err(FronterError::Json(e));
            }
        };
        self.release(entry).await;
        Ok(resp)
    }
}

/// Strip connection-specific headers (matches Code.gs SKIP_HEADERS) and
/// strip Accept-Encoding: br (Apps Script can't decompress brotli).
/// Extract the host (no scheme, no port, no path) from a URL string.
/// Returns None for malformed / scheme-less inputs.
/// Trim X/Twitter GraphQL URLs down to just the `variables=` query param,
/// stripping everything from the first `&` in the query onward. See the
/// `normalize_x_graphql` config field for the why.
///
/// Exact pattern mirrored from the Python community patch (issue #16):
///
///   host == "x.com"
///   && path starts with "/i/api/graphql/"
///   && query starts with "variables="
///   → truncate at first `&` past the `?`.
///
/// Returns the possibly-rewritten URL. If the URL doesn't match the
/// pattern the input is returned unchanged (as an owned String — the
/// allocation is cheap on the slow path and keeps the caller's
/// type-signature-juggling simple).
// ─── HTTP response helpers used by relay_parallel_range ──────────────────

/// Split an HTTP/1.x response blob into `(status, headers, body)`.
/// Returns `None` if the buffer doesn't even have a status line + CRLFCRLF
/// separator — the caller should then pass the bytes through unchanged.
fn split_response(raw: &[u8]) -> Option<(u16, Vec<(String, String)>, &[u8])> {
    // Locate end-of-headers.
    let sep = b"\r\n\r\n";
    let sep_pos = raw.windows(sep.len()).position(|w| w == sep)?;
    let head = &raw[..sep_pos];
    let body = &raw[sep_pos + sep.len()..];

    let mut lines = head.split(|&b| b == b'\n');
    let status_line = lines.next()?;
    // Status line: "HTTP/1.1 206 Partial Content"
    let status_line = std::str::from_utf8(status_line).ok()?.trim_end_matches('\r');
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next()?;
    let code = parts.next()?.parse::<u16>().ok()?;

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Some((code, headers, body))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentRange {
    start: u64,
    end: u64,
    total: u64,
}

/// Parse `Content-Range: bytes START-END/TOTAL`.
fn parse_content_range(headers: &[(String, String)]) -> Option<ContentRange> {
    let cr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-range"))?;
    let value = cr.1.trim();
    let (unit, rest) = value.split_once(' ')?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (range, total) = rest.trim_start().split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = end.trim().parse::<u64>().ok()?;
    let total = total.trim().parse::<u64>().ok()?;
    if start > end || total == 0 || end >= total {
        return None;
    }
    Some(ContentRange { start, end, total })
}

/// Pull the total size out of a valid `Content-Range: bytes START-END/TOTAL` header.
fn parse_content_range_total(headers: &[(String, String)]) -> Option<u64> {
    parse_content_range(headers).map(|r| r.total)
}

fn content_range_matches_body(range: ContentRange, body_len: usize) -> bool {
    body_len > 0 && (range.end - range.start + 1) == body_len as u64
}

fn validate_probe_range(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    requested_end: u64,
) -> Option<ContentRange> {
    if status != 206 {
        return None;
    }
    let range = parse_content_range(headers)?;
    if range.start != 0 || range.end > requested_end || !content_range_matches_body(range, body.len()) {
        return None;
    }
    Some(range)
}

fn extract_exact_range_body(
    raw: &[u8],
    start: u64,
    end: u64,
    total: u64,
) -> Result<Vec<u8>, &'static str> {
    let (status, headers, body) = split_response(raw).ok_or("malformed HTTP response")?;
    if status != 206 {
        return Err("expected 206 Partial Content");
    }
    let range = parse_content_range(&headers).ok_or("missing or invalid Content-Range")?;
    if range.start != start || range.end != end || range.total != total {
        return Err("unexpected Content-Range");
    }
    if !content_range_matches_body(range, body.len()) {
        return Err("Content-Range/body length mismatch");
    }
    Ok(body.to_vec())
}

/// Rewrite a 206 response to a 200 OK, dropping Content-Range and
/// recomputing Content-Length. Used when we probed with a synthetic
/// Range header but the client sent a plain GET — handing a 206 back to
/// XHR/fetch code on some sites (x.com, Cloudflare Turnstile) makes them
/// treat the response as aborted. Same rationale as the upstream Python
/// `_rewrite_206_to_200`.
fn rewrite_206_to_200(raw: &[u8]) -> Vec<u8> {
    let (_status, headers, body) = match split_response(raw) {
        Some(v) => v,
        None => return raw.to_vec(),
    };
    assemble_full_200(&headers, body)
}

/// Build a complete `HTTP/1.1 200 OK` response with the given header
/// set + body. Skips headers the caller shouldn't be forwarding
/// verbatim (content-length/range/encoding, transfer-encoding, hop-by-hop
/// wire-level stuff) — we set Content-Length from the body we're
/// actually shipping.
fn assemble_full_200(src_headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let skip = |k: &str| {
        matches!(
            k.to_ascii_lowercase().as_str(),
            "content-length"
                | "content-range"
                | "content-encoding"
                | "transfer-encoding"
                | "connection"
                | "keep-alive",
        )
    };
    let mut out: Vec<u8> = b"HTTP/1.1 200 OK\r\n".to_vec();
    for (k, v) in src_headers {
        if skip(k) {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

fn normalize_x_graphql_url(url: &str) -> String {
    // Split host from the rest. We accept both "x.com" and common legacy
    // forms; the Python patch only checks x.com so we do the same to be
    // safe about the endpoint actually accepting truncated requests.
    let Some(rest) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) else {
        return url.to_string();
    };
    let Some(slash) = rest.find('/') else {
        return url.to_string();
    };
    let host = &rest[..slash];
    let path_and_query = &rest[slash..];

    // Strip port if present in host.
    let host_no_port = host.split(':').next().unwrap_or(host);
    if host_no_port != "x.com" {
        return url.to_string();
    }

    let Some(q_idx) = path_and_query.find('?') else {
        return url.to_string();
    };
    let path = &path_and_query[..q_idx];
    let query = &path_and_query[q_idx + 1..];

    if !path.starts_with("/i/api/graphql/") || !query.starts_with("variables=") {
        return url.to_string();
    }

    let new_query = match query.find('&') {
        Some(amp) => &query[..amp],
        None => query,
    };
    let scheme = if url.starts_with("https://") { "https://" } else { "http://" };
    format!("{}{}{}?{}", scheme, host, path, new_query)
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or("");
    // Strip userinfo if present.
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority);
    // Strip port. Handle IPv6 literals in brackets.
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // [::1]:443 -> ::1
        stripped.split_once(']').map(|(h, _)| h).unwrap_or(stripped)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// The default pool of SNI names that share the Google Front End with
/// `www.google.com`. Used both when auto-expanding from `front_domain` and
/// when the UI wants to show the starting candidates for the SNI editor.
pub const DEFAULT_GOOGLE_SNI_POOL: &[&str] = &[
    "www.google.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "calendar.google.com",
    // accounts.google.com — standard Google account service, covered by
    // the *.google.com wildcard cert. Previously listed as
    // accounts.googl.com (issue #42), but googl.com is NOT in the SAN
    // list of Google's GFE certificate — connections with verify_ssl=true
    // fail with "certificate not valid for name" when the round-robin
    // lands on it.
    "accounts.google.com",
    // scholar.google.com — reported
    // in #47 as a DPI-passing SNI on MCI / Samantel. Covered by the
    // core *.google.com cert so it handshakes normally against
    // google_ip:443.
    "scholar.google.com",
    // Additional Google properties for rotation. Ported from upstream
    // Python `FRONT_SNI_POOL_GOOGLE` (masterking32/MasterHttpRelayVPN
    // commit 57738ec, "Add additional Google services to exclusion
    // lists"). All served off the same GFE IP range, all covered by the
    // wildcard cert, all give the DPI-fingerprint spread without extra
    // config. A few of these (maps.google.com, play.google.com) reliably
    // pass DPI on carriers where the shorter `*.google.com` names don't.
    "maps.google.com",
    "chat.google.com",
    "translate.google.com",
    "play.google.com",
    "lens.google.com",
    // chromewebstore.google.com — reported in issue #75 as a working
    // SNI. Same family as the rest: wildcard cert, GFE-hosted,
    // handshake against google_ip:443 with no content negotiation.
    "chromewebstore.google.com",
];

/// Build the pool of SNI hosts used for outbound connections to the Google
/// edge.
///
/// Precedence:
/// 1. If `user_pool` is non-empty, use it verbatim (user is in charge).
/// 2. If `primary` is one of the DEFAULT_GOOGLE_SNI_POOL entries, auto-expand
///    to the full default list with `primary` first. This gives the per-SNI
///    connection-count fingerprint spread without the user configuring
///    anything.
/// 3. Otherwise — custom / non-Google `primary` — use just `[primary]`, since
///    we have no way to verify which sibling names share a non-Google edge.
///
/// All entries MUST be hosted on the same edge as `connect_host`, otherwise
/// the TLS handshake will land on the wrong server.
pub fn build_sni_pool_for(primary: &str, user_pool: &[String]) -> Vec<String> {
    let primary = primary.trim().to_string();
    let user_filtered: Vec<String> = user_pool
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !user_filtered.is_empty() {
        return user_filtered;
    }

    let looks_like_google_edge = DEFAULT_GOOGLE_SNI_POOL.iter().any(|s| *s == primary);
    let mut pool = vec![primary.clone()];
    if looks_like_google_edge {
        for s in DEFAULT_GOOGLE_SNI_POOL {
            if *s != primary {
                pool.push((*s).to_string());
            }
        }
    }
    pool
}

/// Back-compat thin wrapper for the old callers / tests.
fn build_sni_pool(primary: &str) -> Vec<String> {
    build_sni_pool_for(primary, &[])
}

pub fn filter_forwarded_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    const SKIP: &[&str] = &[
        // Hop-by-hop / framing — must not be forwarded across the proxy.
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "proxy-authorization",
        // Identity-revealing forwarding headers (issue #104).
        // If the user sits behind another proxy or uses a browser
        // extension that inserts any of these, they'd normally carry
        // the client's real IP. We strip every known variant so the
        // origin server only ever sees whatever source IP the Apps
        // Script or GFE path terminates on — never the user's home IP.
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-forwarded-server",
        "x-forwarded-ssl",
        "forwarded",
        "via",
        "x-real-ip",
        "x-client-ip",
        "x-originating-ip",
        "true-client-ip",
        "cf-connecting-ip",
        "fastly-client-ip",
        "x-cluster-client-ip",
        "client-ip",
    ];
    headers
        .iter()
        .filter_map(|(k, v)| {
            let lk = k.to_ascii_lowercase();
            if SKIP.contains(&lk.as_str()) {
                return None;
            }
            if lk == "accept-encoding" {
                let cleaned = strip_brotli_from_accept_encoding(v);
                if cleaned.is_empty() {
                    return None;
                }
                return Some((k.clone(), cleaned));
            }
            Some((k.clone(), v.clone()))
        })
        .collect()
}

fn strip_brotli_from_accept_encoding(value: &str) -> String {
    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
    let kept: Vec<&str> = parts
        .into_iter()
        .filter(|p| {
            let tok = p.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            tok != "br" && tok != "zstd"
        })
        .collect();
    kept.join(", ")
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn header_get(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn parse_redirect(location: &str) -> (String, Option<String>) {
    // Absolute URL: http(s)://host/path?query
    if let Some(rest) = location.strip_prefix("https://").or_else(|| location.strip_prefix("http://")) {
        let slash = rest.find('/').unwrap_or(rest.len());
        let host = rest[..slash].to_string();
        let path = if slash < rest.len() { rest[slash..].to_string() } else { "/".into() };
        return (path, Some(host));
    }
    // Relative path.
    (location.to_string(), None)
}

/// Read a single HTTP/1.1 response from the stream. Keep-alive safe: respects
/// Content-Length or chunked transfer-encoding.
async fn read_http_response<S>(stream: &mut S) -> Result<(u16, Vec<(String, String)>, Vec<u8>), FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = timeout(Duration::from_secs(10), stream.read(&mut tmp)).await
            .map_err(|_| FronterError::Timeout)??;
        if n == 0 {
            return Err(FronterError::BadResponse("connection closed before headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 1024 * 1024 {
            return Err(FronterError::BadResponse("headers too large".into()));
        }
    };

    let header_section = &buf[..header_end];
    let header_str = std::str::from_utf8(header_section)
        .map_err(|_| FronterError::BadResponse("non-utf8 headers".into()))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = parse_status_line(status_line)?;

    let mut headers_out: Vec<(String, String)> = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers_out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    let content_length: Option<usize> = header_get(&headers_out, "content-length")
        .and_then(|v| v.parse().ok());
    let te = header_get(&headers_out, "transfer-encoding").unwrap_or_default();
    let is_chunked = te.to_ascii_lowercase().contains("chunked");

    if is_chunked {
        body = read_chunked(stream, body).await?;
    } else if let Some(cl) = content_length {
        while body.len() < cl {
            let need = cl - body.len();
            let want = need.min(tmp.len());
            let n = timeout(Duration::from_secs(20), stream.read(&mut tmp[..want])).await
                .map_err(|_| FronterError::Timeout)??;
            if n == 0 {
                return Err(FronterError::BadResponse(
                    "connection closed before full response body".into(),
                ));
            }
            body.extend_from_slice(&tmp[..n]);
        }
    } else {
        // No framing — read until short timeout.
        loop {
            match timeout(Duration::from_secs(2), stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => body.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }
        }
    }

    // gzip decompress if content-encoding says so.
    if let Some(enc) = header_get(&headers_out, "content-encoding") {
        if enc.eq_ignore_ascii_case("gzip") {
            if let Ok(decoded) = decode_gzip(&body) {
                body = decoded;
            }
        }
    }

    Ok((status, headers_out, body))
}

async fn read_chunked<S>(stream: &mut S, mut buf: Vec<u8>) -> Result<Vec<u8>, FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 16384];
    loop {
        let size_line_owned = std::str::from_utf8(&read_crlf_line(stream, &mut buf, &mut tmp).await?)
            .map_err(|_| FronterError::BadResponse("bad chunk size".into()))?
            .trim()
            .to_string();
        if size_line_owned.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(
            size_line_owned.split(';').next().unwrap_or(""),
            16,
        )
        .map_err(|_| FronterError::BadResponse(format!("bad chunk size '{}'", size_line_owned)))?;
        if size == 0 {
            loop {
                if read_crlf_line(stream, &mut buf, &mut tmp).await?.is_empty() {
                    return Ok(out);
                }
            }
        }
        while buf.len() < size + 2 {
            let n = timeout(Duration::from_secs(20), stream.read(&mut tmp)).await
                .map_err(|_| FronterError::Timeout)??;
            if n == 0 {
                return Err(FronterError::BadResponse(
                    "connection closed mid-chunked response".into(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        if &buf[size..size + 2] != b"\r\n" {
            return Err(FronterError::BadResponse(
                "chunk missing trailing CRLF".into(),
            ));
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<Vec<u8>, FronterError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(idx) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..idx].to_vec();
            buf.drain(..idx + 2);
            return Ok(line);
        }
        let n = timeout(Duration::from_secs(20), stream.read(tmp)).await
            .map_err(|_| FronterError::Timeout)??;
        if n == 0 {
            return Err(FronterError::BadResponse(
                "connection closed mid-chunked response".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn decode_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut out = Vec::with_capacity(data.len() * 2);
    flate2::read::GzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<u16, FronterError> {
    // "HTTP/1.1 200 OK"
    let mut parts = line.split_whitespace();
    let _version = parts.next();
    let code = parts.next().ok_or_else(|| {
        FronterError::BadResponse(format!("bad status line: {}", line))
    })?;
    code.parse::<u16>().map_err(|_| FronterError::BadResponse(format!("bad status code: {}", code)))
}

/// Parse the JSON envelope from Apps Script and build a raw HTTP response.
fn parse_relay_json(body: &[u8]) -> Result<Vec<u8>, FronterError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| FronterError::BadResponse("non-utf8 json".into()))?
        .trim();
    if text.is_empty() {
        return Err(FronterError::BadResponse("empty relay body".into()));
    }

    let data: RelayResponse = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            // Apps Script may prepend HTML fallback; try to extract first {...}
            let start = text.find('{').ok_or_else(|| {
                FronterError::BadResponse(format!("no json in: {}", &text[..text.len().min(200)]))
            })?;
            let end = text.rfind('}').ok_or_else(|| {
                FronterError::BadResponse(format!("no json end in: {}", &text[..text.len().min(200)]))
            })?;
            serde_json::from_str(&text[start..=end])?
        }
    };

    if let Some(e) = data.e {
        return Err(FronterError::Relay(e));
    }

    let status = data.s.unwrap_or(200);
    let status_text = status_text(status);
    let resp_body = match data.b {
        Some(b) => B64
            .decode(b)
            .map_err(|e| FronterError::BadResponse(format!("bad relay body base64: {}", e)))?,
        None => Vec::new(),
    };

    let mut out = Vec::with_capacity(resp_body.len() + 256);
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status, status_text).as_bytes());

    const SKIP: &[&str] = &[
        "transfer-encoding",
        "connection",
        "keep-alive",
        "content-length",
        "content-encoding",
    ];

    if let Some(hmap) = data.h {
        for (k, v) in hmap {
            let lk = k.to_ascii_lowercase();
            if SKIP.contains(&lk.as_str()) {
                continue;
            }
            match v {
                Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = value_to_header_str(&item) {
                            out.extend_from_slice(format!("{}: {}\r\n", k, s).as_bytes());
                        }
                    }
                }
                other => {
                    if let Some(s) = value_to_header_str(&other) {
                        out.extend_from_slice(format!("{}: {}\r\n", k, s).as_bytes());
                    }
                }
            }
        }
    }

    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", resp_body.len()).as_bytes());
    out.extend_from_slice(&resp_body);
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub relay_calls: u64,
    pub relay_failures: u64,
    pub coalesced: u64,
    pub bytes_relayed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_bytes: usize,
    pub blacklisted_scripts: usize,
    pub total_scripts: usize,
}

impl StatsSnapshot {
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total as f64) * 100.0
        }
    }

    pub fn fmt_line(&self) -> String {
        format!(
            "stats: relay={} ({}KB) failures={} coalesced={} cache={}/{} ({:.0}% hit, {}KB) scripts={}/{} active",
            self.relay_calls,
            self.bytes_relayed / 1024,
            self.relay_failures,
            self.coalesced,
            self.cache_hits,
            self.cache_hits + self.cache_misses,
            self.hit_rate(),
            self.cache_bytes / 1024,
            self.total_scripts - self.blacklisted_scripts,
            self.total_scripts,
        )
    }
}

fn should_blacklist(status: u16, body: &str) -> bool {
    if status == 429 || status == 403 {
        return true;
    }
    looks_like_quota_error(body)
}

fn looks_like_quota_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("quota")
        || lower.contains("daily limit")
        || lower.contains("rate limit")
        || lower.contains("too many times")
        || lower.contains("service invoked")
}

fn mask_script_id(id: &str) -> String {
    let n = id.chars().count();
    if n <= 8 {
        return "***".into();
    }
    let head: String = id.chars().take(4).collect();
    let tail: String = id.chars().skip(n - 4).collect();
    format!("{}...{}", head, tail)
}

fn value_to_header_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        _ => None,
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

pub fn error_response(status: u16, message: &str) -> Vec<u8> {
    let body = format!(
        "<html><body><h1>{}</h1><p>{}</p></body></html>",
        status,
        html_escape(message)
    );
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
        status,
        status_text(status),
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

// Dangerous "accept anything" TLS verifier, used only when config.verify_ssl=false.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    #[test]
    fn filter_forwarded_headers_strips_identity_revealing_headers() {
        // Issue #104: any proxy/extension that inserts these must not
        // leak the client's real IP to origin via the Apps Script relay.
        let input: Vec<(String, String)> = vec![
            ("X-Forwarded-For".into(), "203.0.113.42".into()),
            ("X-Real-IP".into(), "203.0.113.42".into()),
            ("Forwarded".into(), "for=203.0.113.42".into()),
            ("Via".into(), "1.1 squid".into()),
            ("CF-Connecting-IP".into(), "203.0.113.42".into()),
            ("True-Client-IP".into(), "203.0.113.42".into()),
            ("X-Client-IP".into(), "203.0.113.42".into()),
            ("Fastly-Client-IP".into(), "203.0.113.42".into()),
            ("X-Cluster-Client-IP".into(), "203.0.113.42".into()),
            ("Client-IP".into(), "203.0.113.42".into()),
            ("X-Originating-IP".into(), "203.0.113.42".into()),
            ("X-Forwarded-Host".into(), "internal.example".into()),
            ("X-Forwarded-Proto".into(), "https".into()),
            ("X-Forwarded-Port".into(), "8080".into()),
            ("X-Forwarded-Server".into(), "lb-01.example".into()),
            ("X-Forwarded-Ssl".into(), "on".into()),
            // Mix in a legitimate header that MUST pass through.
            ("User-Agent".into(), "Mozilla/5.0".into()),
            ("Accept".into(), "text/html".into()),
        ];
        let out = filter_forwarded_headers(&input);
        let keys: Vec<String> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        // All identity-revealing headers must be dropped.
        for h in [
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "via",
            "cf-connecting-ip",
            "true-client-ip",
            "x-client-ip",
            "fastly-client-ip",
            "x-cluster-client-ip",
            "client-ip",
            "x-originating-ip",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-forwarded-ssl",
        ] {
            assert!(!keys.iter().any(|k| k == h), "{} must be stripped", h);
        }
        // And legitimate headers must survive.
        assert!(keys.iter().any(|k| k == "user-agent"));
        assert!(keys.iter().any(|k| k == "accept"));
    }

    #[test]
    fn normalize_x_graphql_trims_after_variables() {
        // Real-looking x.com GraphQL URL with variables + features +
        // fieldToggles. Only the variables= prefix should survive.
        let in_url = "https://x.com/i/api/graphql/abcd1234/TweetDetail?variables=%7B%22focalTweetId%22%3A%221234%22%7D&features=%7B%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D&fieldToggles=%7B%22withArticleRichContentState%22%3Atrue%7D";
        let out = normalize_x_graphql_url(in_url);
        assert!(out.starts_with("https://x.com/i/api/graphql/abcd1234/TweetDetail?variables="));
        assert!(!out.contains("features="));
        assert!(!out.contains("fieldToggles="));
        assert!(!out.contains('&'));
    }

    #[test]
    fn normalize_x_graphql_leaves_non_x_hosts_alone() {
        let cases = [
            "https://twitter.com/i/api/graphql/x/y?variables=z&features=q",
            "https://x.co/i/api/graphql/x/y?variables=z&features=q",
            "https://api.x.com/i/api/graphql/x/y?variables=z&features=q",
            "https://example.com/?variables=1&other=2",
        ];
        for u in cases {
            assert_eq!(normalize_x_graphql_url(u), u, "should pass through: {}", u);
        }
    }

    #[test]
    fn normalize_x_graphql_leaves_non_graphql_paths_alone() {
        let cases = [
            "https://x.com/home",
            "https://x.com/i/api/2/notifications/view/generic.json",
            "https://x.com/i/api/graphql/x/y",       // no query
            "https://x.com/i/api/graphql/x/y?features=1&variables=2", // variables not first
        ];
        for u in cases {
            assert_eq!(normalize_x_graphql_url(u), u, "should pass through: {}", u);
        }
    }

    #[test]
    fn normalize_x_graphql_is_idempotent() {
        let once = normalize_x_graphql_url(
            "https://x.com/i/api/graphql/H/Op?variables=%7B%7D&features=%7B%7D",
        );
        let twice = normalize_x_graphql_url(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn extract_host_strips_scheme_port_path() {
        assert_eq!(extract_host("https://example.com/foo"), Some("example.com".into()));
        assert_eq!(extract_host("http://foo.bar:8080/x"), Some("foo.bar".into()));
        assert_eq!(extract_host("https://user:pw@host.test/x"), Some("host.test".into()));
        assert_eq!(extract_host("https://[2001:db8::1]:443/"), Some("2001:db8::1".into()));
        assert_eq!(extract_host("API.X.com/foo"), Some("api.x.com".into()));
        assert_eq!(extract_host(""), None);
    }

    #[test]
    fn build_sni_pool_extends_for_google() {
        let p = build_sni_pool("www.google.com");
        assert!(p.len() >= 2);
        assert_eq!(p[0], "www.google.com");
        assert!(p.iter().any(|s| s == "mail.google.com"));
    }

    #[test]
    fn build_sni_pool_preserves_custom_primary() {
        let p = build_sni_pool("mycustom.edge.example.com");
        assert_eq!(p, vec!["mycustom.edge.example.com".to_string()]);
    }

    #[test]
    fn filter_drops_connection_specific() {
        let h = vec![
            ("Host".into(), "example.com".into()),
            ("Connection".into(), "keep-alive".into()),
            ("Content-Length".into(), "5".into()),
            ("Cookie".into(), "a=b".into()),
            ("Proxy-Connection".into(), "close".into()),
        ];
        let out = filter_forwarded_headers(&h);
        let names: Vec<_> = out.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        assert!(names.contains(&"cookie".to_string()));
        assert!(!names.contains(&"host".to_string()));
        assert!(!names.contains(&"connection".to_string()));
        assert!(!names.contains(&"content-length".to_string()));
        assert!(!names.contains(&"proxy-connection".to_string()));
    }

    #[test]
    fn strip_brotli_keeps_gzip() {
        let r = strip_brotli_from_accept_encoding("gzip, deflate, br");
        assert_eq!(r, "gzip, deflate");
        let r = strip_brotli_from_accept_encoding("br");
        assert_eq!(r, "");
        let r = strip_brotli_from_accept_encoding("gzip;q=1.0, br;q=0.5");
        assert_eq!(r, "gzip;q=1.0");
    }

    #[test]
    fn redirect_absolute_url() {
        let (p, h) = parse_redirect("https://script.googleusercontent.com/abc?x=1");
        assert_eq!(p, "/abc?x=1");
        assert_eq!(h.as_deref(), Some("script.googleusercontent.com"));
    }

    #[test]
    fn redirect_relative() {
        let (p, h) = parse_redirect("/somewhere");
        assert_eq!(p, "/somewhere");
        assert!(h.is_none());
    }

    #[test]
    fn parse_relay_basic_json() {
        let body = r#"{"s":200,"h":{"Content-Type":"text/plain"},"b":"SGVsbG8="}"#;
        let raw = parse_relay_json(body.as_bytes()).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("Hello"));
    }

    #[test]
    fn parse_content_range_total_accepts_mixed_case_unit() {
        let headers = vec![("Content-Range".to_string(), "Bytes 0-4/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), Some(20));
    }

    #[test]
    fn parse_content_range_total_rejects_descending_range() {
        let headers = vec![("Content-Range".to_string(), "bytes 10-4/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), None);
    }

    #[test]
    fn parse_content_range_total_rejects_end_past_total() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-20/20".to_string())];
        assert_eq!(parse_content_range_total(&headers), None);
    }

    #[test]
    fn validate_probe_range_rejects_body_length_mismatch() {
        let headers = vec![("Content-Range".to_string(), "bytes 0-4/20".to_string())];
        assert!(validate_probe_range(206, &headers, b"hey", 4).is_none());
    }

    #[test]
    fn extract_exact_range_body_rejects_mismatched_content_range() {
        let raw = b"HTTP/1.1 206 Partial Content\r\n\
Content-Range: bytes 5-9/20\r\n\
Content-Length: 5\r\n\r\n\
hello";
        let err = extract_exact_range_body(raw, 10, 14, 20).unwrap_err();
        assert_eq!(err, "unexpected Content-Range");
    }

    #[test]
    fn parse_relay_error_field() {
        let body = r#"{"e":"unauthorized"}"#;
        let err = parse_relay_json(body.as_bytes()).unwrap_err();
        assert!(matches!(err, FronterError::Relay(_)));
    }

    #[test]
    fn parse_relay_rejects_invalid_body_base64() {
        let body = r#"{"s":200,"b":"***not-base64***"}"#;
        let err = parse_relay_json(body.as_bytes()).unwrap_err();
        assert!(matches!(err, FronterError::BadResponse(_)));
    }

    #[test]
    fn blacklist_heuristics() {
        assert!(should_blacklist(429, ""));
        assert!(should_blacklist(403, "quota"));
        assert!(should_blacklist(500, "Service invoked too many times per day: urlfetch"));
        assert!(!should_blacklist(200, ""));
        assert!(!should_blacklist(502, "bad gateway"));
        assert!(looks_like_quota_error("Exception: Service invoked too many times per day"));
        assert!(!looks_like_quota_error("bad url"));
    }

    #[test]
    fn mask_script_id_hides_middle() {
        assert_eq!(mask_script_id("short"), "***");
        assert_eq!(mask_script_id("AKfycbx1234567890abcdef"), "AKfy...cdef");
    }

    #[test]
    fn parse_relay_array_set_cookie() {
        let body = r#"{"s":200,"h":{"Set-Cookie":["a=1","b=2"]},"b":""}"#;
        let raw = parse_relay_json(body.as_bytes()).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("Set-Cookie: a=1\r\n"));
        assert!(s.contains("Set-Cookie: b=2\r\n"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_consumes_final_crlf_and_trailers() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\nX-Test: 1\r\n\r\n",
            )
            .await
            .unwrap();

        let (status, _headers, body) = read_http_response(&mut server).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"Hello");

        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();

        let (status2, _headers2, body2) = read_http_response(&mut server).await.unwrap();
        assert_eq!(status2, 200);
        assert_eq!(body2, b"OK");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn content_length_reader_rejects_truncated_body() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHel")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("full response body"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_rejects_truncated_chunk_body() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHel")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("mid-chunked"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_reader_rejects_missing_chunk_crlf() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHelloXX")
            .await
            .unwrap();
        drop(client);

        let err = read_http_response(&mut server).await.unwrap_err();
        match err {
            FronterError::BadResponse(msg) => {
                assert!(msg.contains("trailing CRLF"), "unexpected error: {}", msg);
            }
            other => panic!("unexpected error: {}", other),
        }
    }
}
