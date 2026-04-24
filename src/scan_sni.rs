//! SNI reachability probes.
//!
//! Given a fixed `google_ip`, test which SNI strings the path between here and
//! Google's edge actually lets through. Iran's DPI blocks specific SNI strings
//! (`mail.google.com` has been targeted at various times; `translate.google.com`
//! has been on/off; etc.) while others co-hosted on the exact same IP pass
//! through. This module exposes the probe logic used by both the `test-sni`
//! CLI subcommand and the UI's per-row **Test** / **Test all** buttons.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::RootCertStore;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::config::Config;
use crate::scan_ips::{fetch_google_ips, FAMOUS_GOOGLE_DOMAINS};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const CONCURRENCY: usize = 8;

/// Outcome of a single SNI probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

impl ProbeResult {
    pub fn is_ok(&self) -> bool {
        self.latency_ms.is_some()
    }
}

/// Probe one (google_ip, sni) pair. Succeeds if we can complete a TLS
/// handshake with the given SNI against `google_ip:443`. Does not do an HTTP
/// request on top — handshake completion alone proves the SNI isn't blocked
/// by DPI and the IP accepts the fronting.
pub async fn probe_one(google_ip: &str, sni: &str) -> ProbeResult {
    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    probe_with(google_ip, sni, connector).await
}

/// Probe every SNI in `snis` in parallel (bounded to CONCURRENCY).
/// Results come back in the same order as the input.
pub async fn probe_all(google_ip: &str, snis: Vec<String>) -> Vec<(String, ProbeResult)> {
    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = Vec::with_capacity(snis.len());
    for sni in snis.iter() {
        let connector = connector.clone();
        let sem = sem.clone();
        let sni_clone = sni.clone();
        let ip = google_ip.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            (
                sni_clone.clone(),
                probe_with(&ip, &sni_clone, connector).await,
            )
        }));
    }
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(r) = t.await {
            out.push(r);
        }
    }
    // Re-sort into input order (task scheduling may shuffle).
    let mut indexed: Vec<(String, ProbeResult)> = Vec::with_capacity(out.len());
    for sni in snis {
        if let Some(pos) = out.iter().position(|(s, _)| s == &sni) {
            indexed.push(out.remove(pos));
        }
    }
    indexed
}

async fn probe_with(google_ip: &str, sni: &str, connector: TlsConnector) -> ProbeResult {
    let start = Instant::now();

    // DNS sanity check first. Google's GFE returns a valid wildcard cert for
    // ANY *.google.com SNI (including typos and gibberish), so a successful
    // TLS handshake alone doesn't prove the name actually exists. Resolving
    // catches typos and random strings before they show a misleading "ok".
    // We still only connect to the configured google_ip — the resolve is
    // purely an existence check.
    let resolve_target = format!("{}:443", sni);
    let resolved = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host(resolve_target),
    )
    .await;
    match resolved {
        Ok(Ok(mut iter)) => {
            if iter.next().is_none() {
                return ProbeResult {
                    latency_ms: None,
                    error: Some("dns: no addresses".into()),
                };
            }
        }
        Ok(Err(e)) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("dns: {}", truncate_reason(&e.to_string(), 32))),
            };
        }
        Err(_) => {
            return ProbeResult {
                latency_ms: None,
                error: Some("dns timeout".into()),
            };
        }
    }

    let addr: SocketAddr = match format!("{}:443", google_ip).parse() {
        Ok(a) => a,
        Err(e) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("bad ip: {}", e)),
            };
        }
    };

    let tcp = match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("connect: {}", e)),
            };
        }
        Err(_) => {
            return ProbeResult {
                latency_ms: None,
                error: Some("connect timeout".into()),
            };
        }
    };
    let _ = tcp.set_nodelay(true);

    let server_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(e) => {
            return ProbeResult {
                latency_ms: None,
                error: Some(format!("bad sni: {}", e)),
            };
        }
    };

    let mut tls =
        match tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                // DPI that blocks the SNI typically kills the handshake here.
                let emsg = e.to_string();
                let reason = if emsg.contains("reset") || emsg.contains("peer") {
                    "handshake RST (SNI may be blocked)".into()
                } else {
                    format!("tls: {}", emsg)
                };
                return ProbeResult {
                    latency_ms: None,
                    error: Some(reason),
                };
            }
            Err(_) => {
                return ProbeResult {
                    latency_ms: None,
                    error: Some("tls handshake timeout".into()),
                };
            }
        };

    // Handshake completed — SNI passed. Do a tiny HEAD to confirm the other
    // side actually speaks HTTP (catches weird misroutes).
    let req = b"HEAD / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    if tls.write_all(req).await.is_err() {
        return ProbeResult {
            latency_ms: None,
            error: Some("write failed".into()),
        };
    }
    let _ = tls.flush().await;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(PROBE_TIMEOUT, tls.read(&mut buf)).await {
        Ok(Ok(n)) if n >= 5 && buf.starts_with(b"HTTP/") => {
            let elapsed = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
            ProbeResult {
                latency_ms: Some(elapsed),
                error: None,
            }
        }
        Ok(Ok(_)) => ProbeResult {
            latency_ms: None,
            error: Some("non-HTTP reply".into()),
        },
        Ok(Err(e)) => ProbeResult {
            latency_ms: None,
            error: Some(format!("read: {}", e)),
        },
        Err(_) => ProbeResult {
            latency_ms: None,
            error: Some("read timeout".into()),
        },
    }
}

/// `mhrv-rs test-sni` CLI entry point. Probes every SNI in the active pool
/// (either the user's `sni_hosts` list or the auto-expanded default from
/// `front_domain`) against `google_ip` and prints a sorted table.
pub async fn run(config: &Config) -> bool {
    use crate::domain_fronter::build_sni_pool_for;
    let pool = build_sni_pool_for(
        &config.front_domain,
        config.sni_hosts.as_deref().unwrap_or(&[]),
    );
    println!(
        "Probing {} SNI candidate(s) against google_ip={} (TCP+TLS, timeout={}s)...",
        pool.len(),
        config.google_ip,
        PROBE_TIMEOUT.as_secs()
    );
    println!();

    let mut results = probe_all(&config.google_ip, pool).await;
    results.sort_by_key(|(_, r)| r.latency_ms.unwrap_or(u32::MAX));

    println!("{:<36} {:>10}  {}", "SNI", "LATENCY", "STATUS");
    println!("{:-<36} {:->10}  {}", "", "", "------");
    let mut ok_count = 0usize;
    for (sni, r) in &results {
        match r.latency_ms {
            Some(ms) => {
                println!("{:<36} {:>8}ms  ok", sni, ms);
                ok_count += 1;
            }
            None => {
                let err = r.error.as_deref().unwrap_or("failed");
                println!("{:<36} {:>10}  {}", sni, "-", err);
            }
        }
    }
    println!();
    println!("Working: {} / {}", ok_count, results.len());
    ok_count > 0
}

fn truncate_reason(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Strip newlines / extra junk for clean UI display.
        let cleaned: String = s.chars().take(max).filter(|c| !c.is_control()).collect();
        cleaned
    }
}

fn parse_http_response_body(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("No HTTP header/body separator found")?;
    let header_block = std::str::from_utf8(&raw[..header_end]).map_err(|_| "Bad HTTP headers")?;
    let body = &raw[header_end + 4..];

    let mut transfer_encoding = None;
    let mut content_length = None;
    for line in header_block.lines().skip(1) {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = Some(v.trim().to_string());
        } else if k.eq_ignore_ascii_case("content-length") {
            content_length = v.trim().parse::<usize>().ok();
        }
    }

    if transfer_encoding
        .as_deref()
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
    {
        return decode_chunked_http_body(body);
    }

    if let Some(len) = content_length {
        if body.len() < len {
            return Err("HTTP body shorter than Content-Length");
        }
        return Ok(body[..len].to_vec());
    }

    Ok(body.to_vec())
}

fn decode_chunked_http_body(mut body: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("truncated chunk size line")?;
        let size_line = std::str::from_utf8(&body[..line_end]).map_err(|_| "bad chunk size line")?;
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| "bad chunk size")?;
        body = &body[line_end + 2..];

        if size == 0 {
            loop {
                let trailer_end = body
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .ok_or("truncated chunk trailer")?;
                if trailer_end == 0 {
                    return Ok(out);
                }
                body = &body[trailer_end + 2..];
            }
        }

        if body.len() < size + 2 {
            return Err("truncated chunk body");
        }
        if &body[size..size + 2] != b"\r\n" {
            return Err("chunk missing trailing CRLF");
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

#[derive(Deserialize)]
struct DnsResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsAnswer>>,
}

#[derive(Deserialize)]
struct DnsAnswer {
    data: String,
}

fn is_public_google_sni_candidate(domain: &str) -> bool {
    let public_suffixes = [
        "google.com",
        "youtube.com",
        "googleapis.com",
        "gstatic.com",
        "ggpht.com",
        "withgoogle.com",
    ];
    public_suffixes.iter().any(|suffix| {
        domain == *suffix || domain.strip_suffix(suffix).is_some_and(|prefix| prefix.ends_with('.'))
    })
}

pub async fn discover_snis_from_google_ips(config: &Config) -> bool {
    let ips = fetch_google_ips(config).await;
    println!(
        "Discovering SNIs for {} Google IPs via dns.google...",
        ips.len()
    );
    println!();

    let sem = Arc::new(tokio::sync::Semaphore::new(20));
    let mut tasks = Vec::new();

    for ip in ips {
        let sem = sem.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();

            let octets: Vec<&str> = ip.split('.').collect();
            if octets.len() != 4 {
                return Vec::new();
            }

            let ptr_name = format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            );

            let url = format!("https://dns.google/resolve?name={}&type=PTR", ptr_name);

            match fetch_dns_info(&url).await {
                Ok(body) => {
                    if let Ok(dns_resp) = serde_json::from_str::<DnsResponse>(&body) {
                        if let Some(answers) = dns_resp.answer {
                            return answers
                                .into_iter()
                                .map(|a| a.data.trim_end_matches('.').to_lowercase())
                                .filter(|d| {
                                    d.contains("1e100.net")
                                        || d.contains("google")
                                        || d.contains("goog")
                                        || d.contains("youtube")
                                        || FAMOUS_GOOGLE_DOMAINS.iter().any(|famous| {
                                            let base = famous
                                                .trim_start_matches("www.")
                                                .trim_end_matches(".com");
                                            d.contains(base)
                                        })
                                })
                                .collect::<Vec<_>>();
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("PTR lookup failed for {}: {}", ip, e);
                }
            }
            Vec::new()
        }));
    }

    let mut all_domains = std::collections::HashSet::new();
    for task in tasks {
        if let Ok(domains) = task.await {
            all_domains.extend(domains);
        }
    }

    let mut discovered: Vec<String> = all_domains
        .into_iter()
        .filter(|d| is_public_google_sni_candidate(d))
        .collect();

    // PTRs on Google frontend IPs usually resolve to infrastructure names
    // like `*.1e100.net`, which are useful as edge hints but not usable as
    // fronting SNIs with normal certificate validation. Always validate the
    // public Google domain pool too, then add any public PTR-derived names on
    // top.
    discovered.extend(FAMOUS_GOOGLE_DOMAINS.iter().map(|d| d.to_string()));
    discovered.sort();
    discovered.dedup();

    if discovered.is_empty() {
        println!("No public SNI candidates discovered.");
        println!();
        return false;
    }

    println!(
        "Validating {} public SNI candidates against DPI (IP: {})...",
        discovered.len(),
        config.google_ip
    );
    println!();

    let sem = Arc::new(tokio::sync::Semaphore::new(config.scan_batch_size));
    let mut validation_tasks = Vec::new();

    for sni in discovered {
        let test_ip_owned = config.google_ip.to_string();
        let sem = sem.clone();

        validation_tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            if validate_sni_against_dpi(&sni, &test_ip_owned).await {
                Some(sni)
            } else {
                None
            }
        }));
    }

    let mut validation_ok: Vec<String> = Vec::new();

    for task in validation_tasks {
        if let Ok(Some(sni)) = task.await {
            validation_ok.push(sni);
        }
    }

    if validation_ok.is_empty() {
        println!("No SNI domains passed DPI validation.");
        println!();
        false
    } else {
        validation_ok.sort();
        println!("SNIs that passed DPI validation:");
        println!();
        for sni in validation_ok {
            println!("  {}", sni);
        }
        println!();
        true
    }
}

async fn validate_sni_against_dpi(sni: &str, test_ip: &str) -> bool {
    let addr = format!("{}:443", test_ip);

    let tcp_stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let sni_owned = sni.to_string();
    let domain = match ServerName::try_from(sni_owned.as_str()) {
        Ok(d) => d.to_owned(),
        Err(_) => return false,
    };

    match timeout(
        Duration::from_secs(5),
        connector.connect(domain, tcp_stream),
    )
    .await
    {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

pub async fn fetch_dns_info(url_addr: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(url_addr)?;
    let host = parsed.host_str().ok_or("No host in URL")?;
    let port = parsed.port().unwrap_or(443);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let query = parsed
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await??;

    // DoH is a normal public HTTPS request, not a fronted probe. Keep
    // certificate validation on so an on-path MITM can't forge PTR data and
    // poison the discovered SNI pool.
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let server_name = ServerName::try_from(host.to_string())?;

    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await??;

    let request = format!(
        "GET {}{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        path, query, host
    );
    tls_stream.write_all(request.as_bytes()).await?;
    tls_stream.flush().await?;

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut buf = [0u8; 4096];
        loop {
            match tls_stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
    })
    .await?;

    let body = parse_http_response_body(&response)?;
    Ok(String::from_utf8_lossy(&body).to_string())
}

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
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
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
    use super::{is_public_google_sni_candidate, parse_http_response_body};

    #[test]
    fn parses_chunked_http_body_for_dns_json() {
        let raw = b"HTTP/1.1 200 OK\r\n\
Transfer-Encoding: chunked\r\n\
Content-Type: application/json\r\n\
\r\n\
5\r\n\
{\"Sta\r\n\
7\r\n\
tus\":0}\r\n\
0\r\n\
\r\n";
        let body = parse_http_response_body(raw).unwrap();
        assert_eq!(body, br#"{"Status":0}"#);
    }

    #[test]
    fn parses_content_length_http_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{\"Status\":0}";
        let body = parse_http_response_body(raw).unwrap();
        assert_eq!(body, br#"{"Status":0}"#);
    }

    #[test]
    fn only_public_google_hostnames_are_scan_sni_candidates() {
        assert!(is_public_google_sni_candidate("www.google.com"));
        assert!(is_public_google_sni_candidate("fonts.googleapis.com"));
        assert!(!is_public_google_sni_candidate("ams15s21-in-f14.1e100.net"));
        assert!(!is_public_google_sni_candidate("82.221.107.34.bc.googleusercontent.com"));
    }
}
