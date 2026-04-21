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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
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
const POOL_MAX: usize = 20;
const REQUEST_TIMEOUT_SECS: u64 = 25;

struct PoolEntry {
    stream: PooledStream,
    created: Instant,
}

pub struct DomainFronter {
    connect_host: String,
    sni_host: String,
    http_host: &'static str,
    auth_key: String,
    script_ids: Vec<String>,
    script_idx: AtomicUsize,
    tls_connector: TlsConnector,
    pool: Arc<Mutex<Vec<PoolEntry>>>,
    cache: Arc<ResponseCache>,
}

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
            sni_host: config.front_domain.clone(),
            http_host: "script.google.com",
            auth_key: config.auth_key.clone(),
            script_ids,
            script_idx: AtomicUsize::new(0),
            tls_connector,
            pool: Arc::new(Mutex::new(Vec::new())),
            cache: Arc::new(ResponseCache::with_default()),
        })
    }

    pub fn cache(&self) -> &ResponseCache {
        &self.cache
    }

    fn next_script_id(&self) -> &str {
        let idx = self.script_idx.fetch_add(1, Ordering::Relaxed);
        &self.script_ids[idx % self.script_ids.len()]
    }

    async fn open(&self) -> Result<PooledStream, FronterError> {
        let tcp = TcpStream::connect((self.connect_host.as_str(), 443u16)).await?;
        let _ = tcp.set_nodelay(true);
        let name = ServerName::try_from(self.sni_host.clone())?;
        let tls = self.tls_connector.connect(name, tcp).await?;
        Ok(tls)
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
        let cacheable = is_cacheable_method(method) && body.is_empty();
        let key = if cacheable { Some(cache_key(method, url)) } else { None };
        if let Some(ref k) = key {
            if let Some(hit) = self.cache.get(k) {
                tracing::debug!("cache hit: {}", url);
                return hit;
            }
        }

        let bytes = match timeout(
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
            self.do_relay_with_retry(method, url, headers, body),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                tracing::error!("Relay failed: {}", e);
                return error_response(502, &format!("Relay error: {}", e));
            }
            Err(_) => {
                tracing::error!("Relay timeout");
                return error_response(504, "Relay timeout");
            }
        };

        if let Some(k) = key {
            if let Some(ttl) = parse_ttl(&bytes, url) {
                tracing::debug!("cache store: {} ttl={}s", url, ttl.as_secs());
                self.cache.put(k, bytes.clone(), ttl);
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
        // One retry on connection failure.
        match self.do_relay_once(method, url, headers, body).await {
            Ok(v) => Ok(v),
            Err(e) => {
                tracing::debug!("relay attempt 1 failed: {}; retrying", e);
                self.do_relay_once(method, url, headers, body).await
            }
        }
    }

    async fn do_relay_once(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, FronterError> {
        let payload = self.build_payload_json(method, url, headers, body)?;
        let script_id = self.next_script_id().to_string();
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
                        return Err(FronterError::Relay(format!(
                            "Apps Script HTTP {}: {}",
                            status,
                            String::from_utf8_lossy(&resp_body)
                                .chars()
                                .take(200)
                                .collect::<String>()
                        )));
                    }
                    let bytes = parse_relay_json(&resp_body)?;
                    Ok::<_, FronterError>((bytes, true))
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
}

/// Strip connection-specific headers (matches Code.gs SKIP_HEADERS) and
/// strip Accept-Encoding: br (Apps Script can't decompress brotli).
pub fn filter_forwarded_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    const SKIP: &[&str] = &[
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "proxy-authorization",
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
                break;
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
        while !buf.windows(2).any(|w| w == b"\r\n") {
            let n = timeout(Duration::from_secs(20), stream.read(&mut tmp)).await
                .map_err(|_| FronterError::Timeout)??;
            if n == 0 {
                return Ok(out);
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let idx = buf.windows(2).position(|w| w == b"\r\n").unwrap();
        let size_line_owned = std::str::from_utf8(&buf[..idx])
            .map_err(|_| FronterError::BadResponse("bad chunk size".into()))?
            .trim()
            .to_string();
        buf.drain(..idx + 2);
        if size_line_owned.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(
            size_line_owned.split(';').next().unwrap_or(""),
            16,
        )
        .map_err(|_| FronterError::BadResponse(format!("bad chunk size '{}'", size_line_owned)))?;
        if size == 0 {
            break;
        }
        while buf.len() < size + 2 {
            let n = timeout(Duration::from_secs(20), stream.read(&mut tmp)).await
                .map_err(|_| FronterError::Timeout)??;
            if n == 0 {
                out.extend_from_slice(&buf[..buf.len().min(size)]);
                return Ok(out);
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
    Ok(out)
}

fn decode_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    // Minimal gzip decode — we don't pull in flate2 to keep deps small.
    // Apps Script typically doesn't emit gzip to us (we disable brotli, but
    // Google's frontend may still use gzip). On decode failure we just pass
    // the raw bytes through; the caller ignores errors.
    let _ = data;
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "gzip decode not implemented",
    ))
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
        Some(b) => B64.decode(b).unwrap_or_default(),
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
    fn parse_relay_error_field() {
        let body = r#"{"e":"unauthorized"}"#;
        let err = parse_relay_json(body.as_bytes()).unwrap_err();
        assert!(matches!(err, FronterError::Relay(_)));
    }

    #[test]
    fn parse_relay_array_set_cookie() {
        let body = r#"{"s":200,"h":{"Set-Cookie":["a=1","b=2"]},"b":""}"#;
        let raw = parse_relay_json(body.as_bytes()).unwrap();
        let s = String::from_utf8_lossy(&raw);
        assert!(s.contains("Set-Cookie: a=1\r\n"));
        assert!(s.contains("Set-Cookie: b=2\r\n"));
    }
}
