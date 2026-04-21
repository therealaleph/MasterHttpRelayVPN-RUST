use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::config::Config;

const CANDIDATE_IPS: &[&str] = &[
    "216.239.32.120",
    "216.239.34.120",
    "216.239.36.120",
    "216.239.38.120",
    "216.58.212.142",
    "142.250.80.142",
    "142.250.80.138",
    "142.250.179.110",
    "142.250.185.110",
    "142.250.184.206",
    "142.250.190.238",
    "142.250.191.78",
    "172.217.1.206",
    "172.217.14.206",
    "172.217.16.142",
    "172.217.22.174",
    "172.217.164.110",
    "172.217.168.206",
    "172.217.169.206",
    "34.107.221.82",
    "142.251.32.110",
    "142.251.33.110",
    "142.251.46.206",
    "142.251.46.238",
    "142.250.80.170",
    "142.250.72.206",
    "142.250.64.206",
    "142.250.72.110",
];

const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const CONCURRENCY: usize = 8;

struct Result_ {
    ip: String,
    latency_ms: Option<u128>,
    error: Option<String>,
}

pub async fn run(config: &Config) -> bool {
    let sni = config.front_domain.clone();
    println!("Scanning {} Google frontend IPs (SNI={}, timeout={}s)...", CANDIDATE_IPS.len(), sni, PROBE_TIMEOUT.as_secs());
    println!();

    let tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let mut tasks = Vec::with_capacity(CANDIDATE_IPS.len());
    for ip in CANDIDATE_IPS {
        let sni = sni.clone();
        let connector = connector.clone();
        let sem = sem.clone();
        let ip = ip.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            probe(&ip, &sni, connector).await
        }));
    }

    let mut results: Vec<Result_> = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(r) = t.await {
            results.push(r);
        }
    }
    results.sort_by_key(|r| r.latency_ms.unwrap_or(u128::MAX));

    println!("{:<20} {:>12}   {}", "IP", "LATENCY", "STATUS");
    println!("{:-<20} {:->12}   {}", "", "", "-------");
    let mut ok_count = 0usize;
    for r in &results {
        match r.latency_ms {
            Some(ms) => {
                println!("{:<20} {:>10}ms   OK", r.ip, ms);
                ok_count += 1;
            }
            None => {
                let err = r.error.as_deref().unwrap_or("failed");
                println!("{:<20} {:>12}   {}", r.ip, "-", err);
            }
        }
    }
    println!();
    println!("{} / {} reachable. Fastest:", ok_count, results.len());
    for r in results.iter().filter(|r| r.latency_ms.is_some()).take(3) {
        println!("  {} ({} ms)", r.ip, r.latency_ms.unwrap());
    }
    println!();
    if ok_count == 0 {
        println!("No Google IPs reachable from this network.");
        false
    } else {
        println!("To use the fastest, set \"google_ip\" in config.json to the top result above.");
        true
    }
}

async fn probe(ip: &str, sni: &str, connector: TlsConnector) -> Result_ {
    let start = Instant::now();
    let addr: SocketAddr = match format!("{}:443", ip).parse() {
        Ok(a) => a,
        Err(e) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some(e.to_string()),
            }
        }
    };

    let tcp = match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some(format!("connect: {}", e)),
            }
        }
        Err(_) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some("timeout".into()),
            }
        }
    };
    let _ = tcp.set_nodelay(true);

    let server_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(e) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some(format!("bad sni: {}", e)),
            }
        }
    };

    let mut tls = match tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some(format!("tls: {}", e)),
            }
        }
        Err(_) => {
            return Result_ {
                ip: ip.into(),
                latency_ms: None,
                error: Some("tls timeout".into()),
            }
        }
    };

    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        sni
    );
    if tls.write_all(req.as_bytes()).await.is_err() {
        return Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some("write failed".into()),
        };
    }
    let _ = tls.flush().await;

    let mut buf = [0u8; 256];
    match tokio::time::timeout(PROBE_TIMEOUT, tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let elapsed = start.elapsed().as_millis();
            let head = String::from_utf8_lossy(&buf[..n.min(32)]);
            if head.starts_with("HTTP/") {
                Result_ {
                    ip: ip.into(),
                    latency_ms: Some(elapsed),
                    error: None,
                }
            } else {
                Result_ {
                    ip: ip.into(),
                    latency_ms: None,
                    error: Some(format!("bad reply: {:?}", head)),
                }
            }
        }
        Ok(Ok(_)) => Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some("empty reply".into()),
        },
        Ok(Err(e)) => Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some(format!("read: {}", e)),
        },
        Err(_) => Result_ {
            ip: ip.into(),
            latency_ms: None,
            error: Some("read timeout".into()),
        },
    }
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
