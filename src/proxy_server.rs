use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};

use crate::config::{Config, Mode};
use crate::domain_fronter::DomainFronter;
use crate::mitm::MitmCertManager;

// Domains that are served from Google's core frontend IP pool and therefore
// respond correctly when we connect to `google_ip` with SNI=`front_domain`
// and Host=<the real domain>. Routing these via the tunnel instead of the
// Apps Script relay also avoids Apps Script's fixed "Google-Apps-Script"
// User-Agent, which makes Google serve the bot/no-JS fallback for search.
// Kept conservative: anything on a separate CDN (googlevideo, ytimg,
// doubleclick, etc.) is DROPPED because routing to the wrong backend breaks
// rather than helps. Those fall through to MITM+relay (slower but works).
// Domains that are hosted on the Google Front End and therefore reachable via
// the same SNI-rewrite tunnel used for www.google.com itself. Adding a suffix
// here means "TLS CONNECT to google_ip, SNI = front_domain, Host = real name"
// for requests to it — bypassing the Apps Script relay entirely, so there's no
// User-Agent locking and no Apps Script quota.
// When in doubt leave it out: sites that aren't actually on GFE will 404 or
// return a wrong-cert error instead of loading.
const SNI_REWRITE_SUFFIXES: &[&str] = &[
    // Core Google
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "googleapis.com",
    "ggpht.com",
    // YouTube family
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "ytimg.com",
    // Google Video Transport CDN — YouTube video chunks, Chrome
    // auto-updates, Google Play Store downloads. The single biggest
    // gap vs the upstream Python port: without these in the list
    // YouTube video playback stalls because every chunk tries to
    // traverse Apps Script instead of the direct GFE tunnel.
    "gvt1.com",
    "gvt2.com",
    // Ad + analytics infra. All on GFE, all previously broken the
    // same way YouTube was: SNI-blocked on Iranian DPI, but reachable
    // via `google_ip` with SNI rewritten.
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    // fonts.googleapis.com is technically covered by the googleapis.com
    // suffix above, but mirroring Python's explicit listing makes the
    // intent obvious at a glance.
    "fonts.googleapis.com",
    // Blogger / Blog.google
    "blogspot.com",
    "blogger.com",
];

/// YouTube-family suffixes. Extracted so `youtube_via_relay` config can
/// pull them out of the SNI-rewrite dispatch at runtime.
const YOUTUBE_SNI_SUFFIXES: &[&str] = &[
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "ytimg.com",
];

fn matches_sni_rewrite(host: &str, youtube_via_relay: bool) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    SNI_REWRITE_SUFFIXES
        .iter()
        .filter(|s| {
            // If the user opted into youtube_via_relay, skip YouTube
            // suffixes so they fall through to the Apps Script relay
            // path. See config.rs `youtube_via_relay` docs for the
            // trade-off. Issue #102.
            !(youtube_via_relay && YOUTUBE_SNI_SUFFIXES.contains(s))
        })
        .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
}

fn hosts_override<'a>(
    hosts: &'a std::collections::HashMap<String, String>,
    host: &str,
) -> Option<&'a str> {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if let Some(ip) = hosts.get(h) {
        return Some(ip.as_str());
    }
    let parts: Vec<&str> = h.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if let Some(ip) = hosts.get(&parent) {
            return Some(ip.as_str());
        }
    }
    None
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ProxyServer {
    host: String,
    port: u16,
    socks5_port: u16,
    /// `None` in `google_only` (bootstrap) mode: no Apps Script relay is
    /// wired up, only the SNI-rewrite tunnel path is live.
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
}

pub struct RewriteCtx {
    pub google_ip: String,
    pub front_domain: String,
    pub hosts: std::collections::HashMap<String, String>,
    pub tls_connector: TlsConnector,
    pub upstream_socks5: Option<String>,
    pub mode: Mode,
    /// If true, YouTube traffic bypasses the SNI-rewrite tunnel and
    /// goes through the Apps Script relay instead. See config.rs for
    /// the trade-off. Issue #102.
    pub youtube_via_relay: bool,
}

impl ProxyServer {
    pub fn new(config: &Config, mitm: Arc<Mutex<MitmCertManager>>) -> Result<Self, ProxyError> {
        let mode = config
            .mode_kind()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{e}")))?;

        // `google_only` mode skips the Apps Script relay entirely, so we must
        // not try to construct the DomainFronter — it errors on a missing
        // `script_id`, which is exactly the state a bootstrapping user is in.
        let fronter = match mode {
            Mode::AppsScript => {
                let f = DomainFronter::new(config).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("{e}"))
                })?;
                Some(Arc::new(f))
            }
            Mode::GoogleOnly => None,
        };

        let tls_config = if config.verify_ssl {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
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

        let rewrite_ctx = Arc::new(RewriteCtx {
            google_ip: config.google_ip.clone(),
            front_domain: config.front_domain.clone(),
            hosts: config.hosts.clone(),
            tls_connector,
            upstream_socks5: config.upstream_socks5.clone(),
            mode,
            youtube_via_relay: config.youtube_via_relay,
        });

        let socks5_port = config.socks5_port.unwrap_or(config.listen_port + 1);

        Ok(Self {
            host: config.listen_host.clone(),
            port: config.listen_port,
            socks5_port,
            fronter,
            mitm,
            rewrite_ctx,
        })
    }

    pub fn fronter(&self) -> Option<Arc<DomainFronter>> {
        self.fronter.clone()
    }
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        let http_addr = format!("{}:{}", self.host, self.port);
        let socks_addr = format!("{}:{}", self.host, self.socks5_port);
        let http_listener = TcpListener::bind(&http_addr).await?;
        let socks_listener = TcpListener::bind(&socks_addr).await?;
        tracing::warn!(
            "Listening HTTP   on {} — set your browser HTTP proxy to this address.",
            http_addr
        );
        tracing::warn!(
            "Listening SOCKS5 on {} — xray / Telegram / app-level SOCKS5 clients use this.",
            socks_addr
        );
        // Pre-warm the outbound connection pool so the user's first request
        // doesn't pay a fresh TLS handshake to Google edge. Best-effort;
        // failures are logged and ignored. Skipped in `google_only` — there
        // is no fronter to warm.
        if let Some(warm_fronter) = self.fronter.clone() {
            tokio::spawn(async move {
                warm_fronter.warm(3).await;
            });
        }

        let stats_task = if let Some(stats_fronter) = self.fronter.clone() {
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let s = stats_fronter.snapshot_stats();
                    if s.relay_calls > 0 || s.cache_hits > 0 {
                        tracing::info!("{}", s.fmt_line());
                    }
                }
            })
        } else {
            tokio::spawn(async move { std::future::pending::<()>().await })
        };

        let http_fronter = self.fronter.clone();
        let http_mitm = self.mitm.clone();
        let http_ctx = self.rewrite_ctx.clone();
        let mut http_task = tokio::spawn(async move {
            let mut fd_exhaust_count: u64 = 0;
            // Track every per-client child task in a JoinSet so that when
            // this accept task is aborted on shutdown, dropping the JoinSet
            // aborts the children too. Previously children were bare
            // `tokio::spawn(...)` handles with no ownership — aborting the
            // parent accept loop stopped taking new connections but left
            // in-flight ones running with the OLD config. That manifested
            // as "hitting Stop in the UI doesn't actually stop anything
            // already running" (issue #99) and as "changing auth_key and
            // Start doesn't take effect for domains with a live
            // keep-alive" because the old DomainFronter stayed alive
            // inside those child tasks.
            let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            loop {
                // Opportunistic reap so completed children don't pile up
                // memory on long-running proxies.
                while children.try_join_next().is_some() {}

                let (sock, peer) = match http_listener.accept().await {
                    Ok(x) => {
                        fd_exhaust_count = 0;
                        x
                    }
                    Err(e) => {
                        accept_backoff("http", &e, &mut fd_exhaust_count).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let fronter = http_fronter.clone();
                let mitm = http_mitm.clone();
                let rewrite_ctx = http_ctx.clone();
                children.spawn(async move {
                    if let Err(e) = handle_http_client(sock, fronter, mitm, rewrite_ctx).await {
                        tracing::debug!("http client {} closed: {}", peer, e);
                    }
                });
            }
        });

        let socks_fronter = self.fronter.clone();
        let socks_mitm = self.mitm.clone();
        let socks_ctx = self.rewrite_ctx.clone();
        let mut socks_task = tokio::spawn(async move {
            let mut fd_exhaust_count: u64 = 0;
            // Same pattern as http_task above — JoinSet so shutdown
            // drops in-flight SOCKS5 clients instead of leaving them to
            // keep running on the stale config.
            let mut children: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            loop {
                while children.try_join_next().is_some() {}

                let (sock, peer) = match socks_listener.accept().await {
                    Ok(x) => {
                        fd_exhaust_count = 0;
                        x
                    }
                    Err(e) => {
                        accept_backoff("socks", &e, &mut fd_exhaust_count).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let fronter = socks_fronter.clone();
                let mitm = socks_mitm.clone();
                let rewrite_ctx = socks_ctx.clone();
                children.spawn(async move {
                    if let Err(e) = handle_socks5_client(sock, fronter, mitm, rewrite_ctx).await {
                        tracing::debug!("socks client {} closed: {}", peer, e);
                    }
                });
            }
        });

        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                tracing::info!("Shutdown signal received, stopping listeners");
                stats_task.abort();
                http_task.abort();
                socks_task.abort();
            }
            _ = &mut http_task => {}
            _ = &mut socks_task => {}
        }

        Ok(())
    }
}

/// Back-off helper for the accept() loop.
///
/// Motivated by issue #18: when the process hits its file-descriptor limit
/// (EMFILE — `No file descriptors available`), `accept()` returns that
/// error synchronously and is immediately ready to fire again. The old
/// loop just `continue`'d, producing a wall of identical ERROR lines
/// thousands per second and starving the tokio runtime of CPU that
/// existing connections would have used to drain and close.
///
/// Two things this does right:
///   1. Sleeps when `EMFILE` / `ENFILE` are seen, proportional to how long
///      the problem has been going on (exponential-ish, capped at 2s).
///      Gives existing connections a chance to finish and free fds.
///   2. Rate-limits the log line: first occurrence logs a full warning
///      with fix instructions, subsequent ones log once per 100 errors
///      so the log doesn't fill up.
async fn accept_backoff(kind: &str, err: &std::io::Error, count: &mut u64) {
    let is_fd_limit = matches!(
        err.raw_os_error(),
        Some(libc_emfile) if libc_emfile == 24 || libc_emfile == 23
    );

    *count = count.saturating_add(1);

    if is_fd_limit {
        if *count == 1 {
            tracing::warn!(
                "accept ({}) hit RLIMIT_NOFILE: {}. Backing off. Raise the fd limit: \
                 `ulimit -n 65536` before starting, or (OpenWRT) use the shipped procd \
                 init which sets nofile=16384. The listener will keep retrying.",
                kind,
                err
            );
        } else if *count % 100 == 0 {
            tracing::warn!(
                "accept ({}) still fd-limited after {} retries. Current connections \
                 need to finish before we can accept new ones.",
                kind,
                *count
            );
        }
        // Back off exponentially-ish up to 2s. First hit: 50ms, 10th hit:
        // ~500ms, 50th+: 2s cap.
        let backoff_ms = (50u64 * (*count).min(40)).min(2000);
        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
    } else {
        // Transient non-EMFILE error (e.g. ECONNABORTED from a client that
        // went away during the handshake). One-line log, short sleep to
        // avoid a tight loop in case it repeats.
        tracing::error!("accept ({}): {}", kind, err);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

async fn handle_http_client(
    mut sock: TcpStream,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    let (head, leftover) = match read_http_head(&mut sock).await? {
        Some(v) => v,
        None => return Ok(()),
    };

    let (method, target, _version, _headers) = parse_request_head(&head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target);
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        sock.flush().await?;
        dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx).await
    } else {
        // Plain HTTP proxy request (e.g. `GET http://…`). The Apps Script
        // relay is the only code path that can fulfil this, so in google_only
        // bootstrap mode we return a clear 502 instead.
        match fronter {
            Some(f) => do_plain_http(sock, &head, &leftover, f).await,
            None => {
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\n\
                          Content-Type: text/plain; charset=utf-8\r\n\
                          Content-Length: 120\r\n\
                          Connection: close\r\n\r\n\
                          google_only mode: plain HTTP proxy requests are not supported. \
                          Browse https over CONNECT, or switch to apps_script mode.",
                    )
                    .await;
                let _ = sock.flush().await;
                Ok(())
            }
        }
    }
}

// ---------- SOCKS5 ----------

async fn handle_socks5_client(
    mut sock: TcpStream,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    // RFC 1928 handshake: VER=5, NMETHODS, METHODS...
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Ok(());
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    // Only "no auth" (0x00) is supported.
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    sock.write_all(&[0x05, 0x00]).await?;

    // Request: VER=5, CMD, RSV=0, ATYP, DST.ADDR, DST.PORT
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    let cmd = req[1];
    if cmd != 0x01 {
        // CONNECT only.
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let atyp = req[3];
    let host: String = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            sock.read_exact(&mut ip).await?;
            let addr = std::net::Ipv6Addr::from(ip);
            addr.to_string()
        }
        _ => {
            sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    tracing::info!("SOCKS5 CONNECT -> {}:{}", host, port);

    // Success reply with zeroed BND.
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    sock.flush().await?;

    dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx).await
}

// ---------- Smart dispatch (used by both HTTP CONNECT and SOCKS5) ----------

fn should_use_sni_rewrite(
    hosts: &std::collections::HashMap<String, String>,
    host: &str,
    port: u16,
    youtube_via_relay: bool,
) -> bool {
    // The SNI-rewrite path expects TLS from the client: it accepts inbound
    // TLS, then opens a second TLS connection to the Google edge with a front
    // SNI. Auto-forcing that path for non-TLS ports (for example a SOCKS5
    // CONNECT to google.com:80) makes the proxy wait for a ClientHello that
    // will never arrive.
    //
    // youtube_via_relay=true removes YouTube suffixes from the match so
    // YouTube traffic falls through to the Apps Script relay path instead
    // of the SNI-rewrite tunnel. An explicit hosts override still wins
    // over the config toggle.
    port == 443
        && (matches_sni_rewrite(host, youtube_via_relay) || hosts_override(hosts, host).is_some())
}

async fn dispatch_tunnel(
    sock: TcpStream,
    host: String,
    port: u16,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    // 1. Explicit hosts override or SNI-rewrite suffix: for HTTPS targets,
    //    always use the TLS SNI-rewrite tunnel.
    if should_use_sni_rewrite(
        &rewrite_ctx.hosts,
        &host,
        port,
        rewrite_ctx.youtube_via_relay,
    ) {
        tracing::info!("dispatch {}:{} -> sni-rewrite tunnel (Google edge direct)", host, port);
        return do_sni_rewrite_tunnel_from_tcp(sock, &host, port, mitm, rewrite_ctx).await;
    }

    // 2. google_only bootstrap: no Apps Script relay exists. Anything that
    //    isn't SNI-rewrite-matched gets direct TCP passthrough so the user's
    //    browser still works while they're deploying Code.gs. They'd switch
    //    to apps_script mode for the real DPI bypass.
    if rewrite_ctx.mode == Mode::GoogleOnly {
        let via = rewrite_ctx.upstream_socks5.as_deref();
        tracing::info!(
            "dispatch {}:{} -> raw-tcp ({}) (google_only: no relay)",
            host,
            port,
            via.unwrap_or("direct")
        );
        plain_tcp_passthrough(sock, &host, port, via).await;
        return Ok(());
    }

    // From here on we know mode == AppsScript, so `fronter` is Some.
    let fronter = match fronter {
        Some(f) => f,
        None => {
            // Defensive: mode says apps_script but the fronter is missing.
            // Fall back to raw TCP rather than panicking.
            tracing::error!(
                "dispatch {}:{} -> raw-tcp (unexpected: apps_script mode with no fronter)",
                host,
                port
            );
            plain_tcp_passthrough(sock, &host, port, rewrite_ctx.upstream_socks5.as_deref()).await;
            return Ok(());
        }
    };

    // 3. Peek at the first byte to detect TLS vs plain. Time-bounded — if the
    //    client doesn't send anything within 300ms, assume server-first
    //    protocol (SMTP, POP3, FTP banner) and jump straight to plain TCP.
    let mut peek_buf = [0u8; 8];
    let peek_n = match tokio::time::timeout(
        std::time::Duration::from_millis(300),
        sock.peek(&mut peek_buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return Ok(()),
        Err(_) => {
            // Client silent: likely a server-first protocol.
            let via = rewrite_ctx.upstream_socks5.as_deref();
            tracing::info!(
                "dispatch {}:{} -> raw-tcp ({}) (client silent, likely server-first)",
                host,
                port,
                via.unwrap_or("direct")
            );
            plain_tcp_passthrough(sock, &host, port, via).await;
            return Ok(());
        }
    };

    if peek_n >= 1 && peek_buf[0] == 0x16 {
        // Looks like TLS: MITM + relay via Apps Script. Note: upstream_socks5
        // is NOT consulted here by design — HTTPS goes through the Apps Script
        // relay, which is the whole reason mhrv-rs exists. If you want HTTPS
        // to flow through xray, disable mhrv-rs and point your browser at
        // xray directly.
        tracing::info!(
            "dispatch {}:{} -> MITM + Apps Script relay (TLS detected)",
            host,
            port
        );
        run_mitm_then_relay(sock, &host, port, mitm, &fronter).await;
        return Ok(());
    }

    // 4. Not TLS. If bytes look like HTTP, relay on scheme=http. Otherwise
    //    fall back to plain TCP passthrough.
    if peek_n > 0 && looks_like_http(&peek_buf[..peek_n]) {
        let scheme = if port == 443 { "https" } else { "http" };
        tracing::info!(
            "dispatch {}:{} -> Apps Script relay (plain HTTP, scheme={})",
            host,
            port,
            scheme
        );
        relay_http_stream_raw(sock, &host, port, scheme, &fronter).await;
        return Ok(());
    }

    let via = rewrite_ctx.upstream_socks5.as_deref();
    tracing::info!(
        "dispatch {}:{} -> raw-tcp ({}) (non-HTTP, non-TLS client payload)",
        host,
        port,
        via.unwrap_or("direct")
    );
    plain_tcp_passthrough(sock, &host, port, via).await;
    Ok(())
}

// ---------- Plain TCP passthrough ----------

async fn plain_tcp_passthrough(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    upstream_socks5: Option<&str>,
) {
    let target_host = host.trim_start_matches('[').trim_end_matches(']');
    // Shorter connect timeout for IP literals (4s vs 10s for hostnames).
    // Ported from upstream Python 7b1812c: when the target is an IP (i.e.
    // a raw Telegram DC, or an IP someone hardcoded), and that route is
    // DPI-dropped, the client speeds up its own DC-rotation / fallback if
    // we fail fast. Ten seconds of "waiting for a dead IP" translates
    // directly into Telegram's 10s-per-DC rotation delay — users see the
    // app sit on "connecting..." for nearly a minute as it walks through
    // DC1, DC2, DC3. At 4s we cut that in roughly half.
    // Hostnames still get 10s because DNS + first-hop TCP genuinely can
    // take that long on flaky links, and the resolver fallbacks already
    // trim the worst case.
    let connect_timeout = if looks_like_ip(target_host) {
        std::time::Duration::from_secs(4)
    } else {
        std::time::Duration::from_secs(10)
    };
    let upstream = if let Some(proxy) = upstream_socks5 {
        match socks5_connect_via(proxy, target_host, port).await {
            Ok(s) => {
                tracing::info!("tcp via upstream-socks5 {} -> {}:{}", proxy, host, port);
                s
            }
            Err(e) => {
                tracing::warn!(
                    "upstream-socks5 {} -> {}:{} failed: {} (falling back to direct)",
                    proxy,
                    host,
                    port,
                    e
                );
                match tokio::time::timeout(
                    connect_timeout,
                    TcpStream::connect((target_host, port)),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    _ => return,
                }
            }
        }
    } else {
        match tokio::time::timeout(
            connect_timeout,
            TcpStream::connect((target_host, port)),
        )
        .await
        {
            Ok(Ok(s)) => {
                tracing::info!("plain-tcp passthrough -> {}:{}", host, port);
                s
            }
            Ok(Err(e)) => {
                tracing::debug!("plain-tcp connect {}:{} failed: {}", host, port, e);
                return;
            }
            Err(_) => {
                tracing::debug!(
                    "plain-tcp connect {}:{} timeout (likely blocked; client should rotate)",
                    host, port
                );
                return;
            }
        }
    };
    let _ = upstream.set_nodelay(true);
    let (mut ar, mut aw) = sock.split();
    let (mut br, mut bw) = {
        let (r, w) = upstream.into_split();
        (r, w)
    };
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
}

/// Open a TCP stream to `(host, port)` through an upstream SOCKS5 proxy
/// (no-auth only). Returns the connected stream after SOCKS5 negotiation.
async fn socks5_connect_via(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(proxy))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = s.set_nodelay(true);

    // Greeting: VER=5, NMETHODS=1, METHOD=no-auth
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("socks5 greet rejected: {:?}", reply),
        ));
    }

    // CONNECT request: VER=5, CMD=1, RSV=0, ATYP=3 (domain) | 1 (IPv4) | 4 (IPv6)
    let mut req: Vec<u8> = Vec::with_capacity(8 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hostname > 255",
            ));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply header: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("socks5 connect rejected rep=0x{:02x}", head[1]),
        ));
    }
    // Skip BND.ADDR + BND.PORT.
    match head[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut name).await?;
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("socks5 bad ATYP in reply: {}", other),
            ));
        }
    }
    Ok(s)
}

fn looks_like_http(first_bytes: &[u8]) -> bool {
    // Cheap sniff: must start with an ASCII HTTP method token followed by a space.
    for m in [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT ", "TRACE ",
    ] {
        if first_bytes.starts_with(m.as_bytes()) {
            return true;
        }
    }
    false
}

/// Read an HTTP head (request line + headers) up to the first \r\n\r\n.
/// Returns (head_bytes, leftover_after_head). The leftover may contain part
/// of the request body already received.
async fn read_http_head(sock: &mut TcpStream) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(Some((head, leftover)));
        }
        if buf.len() > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_request_head(head: &[u8]) -> Option<(String, String, String, Vec<(String, String)>)> {
    let s = std::str::from_utf8(head).ok()?;
    let mut lines = s.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if !is_valid_http_method(&method) {
        return None;
    }

    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((method, target, version, headers))
}

fn is_valid_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

// ---------- CONNECT handling ----------

async fn run_mitm_then_relay(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    fronter: &DomainFronter,
) {
    // Peek the TLS ClientHello BEFORE minting the MITM cert. When the client
    // resolves the hostname itself (DoH in Chrome/Firefox) and hands us a raw
    // IP via SOCKS5, the only place the real hostname lives is the SNI. If we
    // mint a cert for the IP, Chrome rejects with ERR_CERT_COMMON_NAME_INVALID
    // — the IP isn't in the cert's SAN. Reading SNI up front and using it as
    // both the cert subject and the upstream Host for the Apps Script relay
    // is what unblocks Cloudflare-fronted sites and any browser on Android
    // where DoH is the default.
    let start = match LazyConfigAcceptor::new(Acceptor::default(), sock).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("TLS ClientHello peek failed for {}: {}", host, e);
            return;
        }
    };

    let sni_hostname = start.client_hello().server_name().map(String::from);

    // Effective host: SNI when present and looks like a hostname (anything
    // other than a bare IPv4 literal — IP SNIs exist for weird setups but
    // minting a cert for them still triggers ERR_CERT_COMMON_NAME_INVALID,
    // so we fall through to the raw host in that case).
    let effective_host: String = match sni_hostname.as_deref() {
        Some(s) if !looks_like_ip(s) && !s.is_empty() => s.to_string(),
        _ => host.to_string(),
    };

    tracing::info!(
        "MITM TLS -> {}:{} (socks_host={}, sni={})",
        effective_host,
        port,
        host,
        sni_hostname.as_deref().unwrap_or("<none>"),
    );

    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(&effective_host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", effective_host, e);
                return;
            }
        }
    };

    let mut tls = match start.into_stream(server_config).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("TLS accept failed for {}: {}", effective_host, e);
            return;
        }
    };

    // Keep-alive loop: read HTTP requests from the decrypted stream. Pass the
    // SNI-derived hostname so the Apps Script relay fetches
    // `https://<real hostname>/path` instead of `https://<raw IP>/path` — the
    // latter would produce an IP-in-Host request that Cloudflare/etc. reject
    // outright.
    loop {
        match handle_mitm_request(&mut tls, &effective_host, port, fronter, "https").await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("MITM handler error for {}: {}", effective_host, e);
                break;
            }
        }
    }
}

/// True if `s` parses as an IPv4 or IPv6 literal. Used to decide whether
/// a string is a hostname we should mint a MITM leaf cert for — IP SANs
/// need their own cert extension and we don't bother emitting those,
/// so fall back to the SOCKS5-provided target in that case.
fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

// ---------- Plain HTTP relay on a raw TCP stream (port 80 targets) ----------

async fn relay_http_stream_raw(
    mut sock: TcpStream,
    host: &str,
    port: u16,
    scheme: &str,
    fronter: &DomainFronter,
) {
    loop {
        match handle_mitm_request(&mut sock, host, port, fronter, scheme).await {
            Ok(true) => continue,
            Ok(false) => break,
            Err(e) => {
                tracing::debug!("http relay error for {}: {}", host, e);
                break;
            }
        }
    }
}

async fn do_sni_rewrite_tunnel_from_tcp(
    sock: TcpStream,
    host: &str,
    port: u16,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
) -> std::io::Result<()> {
    let target_ip = hosts_override(&rewrite_ctx.hosts, host)
        .map(|s| s.to_string())
        .unwrap_or_else(|| rewrite_ctx.google_ip.clone());

    tracing::info!(
        "SNI-rewrite tunnel -> {}:{} via {} (outbound SNI={})",
        host,
        port,
        target_ip,
        rewrite_ctx.front_domain
    );

    // Accept browser TLS with a cert we sign for `host`.
    let server_config = {
        let mut m = mitm.lock().await;
        match m.get_server_config(host) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("cert gen failed for {}: {}", host, e);
                return Ok(());
            }
        }
    };
    let inbound = match TlsAcceptor::from(server_config).accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("inbound TLS accept failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Open outbound TLS to google_ip with SNI=front_domain.
    let upstream_tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target_ip.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            s
        }
        Ok(Err(e)) => {
            tracing::debug!("upstream connect failed for {}: {}", host, e);
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("upstream connect timeout for {}", host);
            return Ok(());
        }
    };
    let _ = upstream_tcp.set_nodelay(true);

    let server_name = match ServerName::try_from(rewrite_ctx.front_domain.clone()) {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("invalid front_domain '{}': {}", rewrite_ctx.front_domain, e);
            return Ok(());
        }
    };
    let outbound = match rewrite_ctx
        .tls_connector
        .connect(server_name, upstream_tcp)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("outbound TLS connect failed for {}: {}", host, e);
            return Ok(());
        }
    };

    // Bridge decrypted bytes between the two TLS streams.
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let (mut or, mut ow) = tokio::io::split(outbound);
    let client_to_server = async { tokio::io::copy(&mut ir, &mut ow).await };
    let server_to_client = async { tokio::io::copy(&mut or, &mut iw).await };
    tokio::select! {
        _ = client_to_server => {}
        _ = server_to_client => {}
    }
    Ok(())
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
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

fn parse_host_port(target: &str) -> (String, u16) {
    if let Some((h, p)) = target.rsplit_once(':') {
        let port: u16 = p.parse().unwrap_or(443);
        (h.to_string(), port)
    } else {
        (target.to_string(), 443)
    }
}

async fn handle_mitm_request<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    fronter: &DomainFronter,
    scheme: &str,
) -> std::io::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (head, leftover) = match read_http_head_io(stream).await? {
        Some(v) => v,
        None => return Ok(false),
    };

    let (method, path, _version, headers) = match parse_request_head(&head) {
        Some(v) => v,
        None => return Ok(false),
    };

    let body = read_body(stream, &leftover, &headers).await?;

    // ── Per-host URL fix-ups ──────────────────────────────────────────
    // x.com's GraphQL endpoints concatenate three huge JSON blobs into
    // the query string: `?variables=<json>&features=<json>&fieldToggles=<json>`.
    // The combined URL regularly exceeds Apps Script's URL length limit
    // (Apps Script returns "بیش از حد مجاز: طول نشانی وب URLFetch" /
    // "URLFetch URL length exceeded"). The `variables=` portion alone
    // is enough for x.com to serve the timeline — `features` /
    // `fieldToggles` are client-capability hints it tolerates being
    // absent. Truncating at the first `&` after `?variables=` ships a
    // working request that fits under the limit. Ported from upstream
    // Python 2d959d4 (p0u1ya's fix). Issue #64.
    //
    // Host matcher: browsers actually hit `www.x.com` (and sometimes
    // `api.x.com`), not bare `x.com`. The original check only matched
    // `x.com` exactly, so real traffic flew past the rewrite until
    // pourya-p's log in #64 showed the real Host header. Match every
    // subdomain of x.com here.
    let host_lower = host.to_ascii_lowercase();
    let is_x_com = host_lower == "x.com" || host_lower.ends_with(".x.com");
    let path = if is_x_com
        && path.starts_with("/i/api/graphql/")
        && path.contains("?variables=")
    {
        match path.split_once('&') {
            Some((short, _)) => {
                tracing::debug!("x.com graphql URL truncated: {} chars -> {}", path.len(), short.len());
                short.to_string()
            }
            None => path,
        }
    } else {
        path
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let url = if port == default_port {
        format!("{}://{}{}", scheme, host, path)
    } else {
        format!("{}://{}:{}{}", scheme, host, port, path)
    };

    // Short-circuit CORS preflight at the MITM boundary.
    //
    // Apps Script's UrlFetchApp.fetch() only accepts methods {get, delete,
    // patch, post, put} — OPTIONS triggers the Swedish-localized
    // "Ett attribut med ogiltigt värde har angetts: method" error, which
    // kills every XHR/fetch preflight and is the root cause of "JS doesn't
    // load" on sites like Discord, Yahoo finance widgets, etc.
    //
    // Answering the preflight ourselves is safe: we already terminate the
    // TLS for the browser (we minted the cert), so it's legitimate for us
    // to own the wire-level conversation. CORS is a browser-side
    // protection, not a network security one — responding 204 with
    // permissive ACL headers just tells the browser the *subsequent* real
    // request is allowed, and that real request still goes through the
    // Apps Script relay where the origin server gets final say on content.
    // The origin header is echoed (not "*") so Credentials-true responses
    // stay spec-valid.
    if method.eq_ignore_ascii_case("OPTIONS") {
        tracing::info!("preflight 204 {} (short-circuit, no relay)", url);
        let origin = header_value(&headers, "origin").unwrap_or("*");
        let acrm = header_value(&headers, "access-control-request-method")
            .unwrap_or("GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD");
        let acrh = header_value(&headers, "access-control-request-headers").unwrap_or("*");
        let resp = format!(
            "HTTP/1.1 204 No Content\r\n\
             Access-Control-Allow-Origin: {origin}\r\n\
             Access-Control-Allow-Methods: {acrm}\r\n\
             Access-Control-Allow-Headers: {acrh}\r\n\
             Access-Control-Allow-Credentials: true\r\n\
             Access-Control-Max-Age: 86400\r\n\
             Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n\
             Content-Length: 0\r\n\
             \r\n",
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        let connection_close = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
        return Ok(!connection_close);
    }

    tracing::info!("relay {} {}", method, url);

    // For GETs without a body, take the range-parallel path — probes
    // with `Range: bytes=0-<chunk>`, and if the origin supports ranges,
    // fetches the rest in parallel 256 KB chunks. This is what lets
    // YouTube video streaming / gvt1.com Chrome-updates / big static
    // files not stall waiting on one ~2s Apps Script call per MB.
    // Anything with a body (POST/PUT/PATCH) goes through the normal
    // relay path — range semantics on mutating requests are undefined
    // and would break form submissions.
    let response = if method.eq_ignore_ascii_case("GET") && body.is_empty() {
        fronter.relay_parallel_range(&method, &url, &headers, &body).await
    } else {
        fronter.relay(&method, &url, &headers, &body).await
    };
    stream.write_all(&response).await?;
    stream.flush().await?;

    // Keep-alive unless the client asked to close.
    let connection_close = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
    Ok(!connection_close)
}

async fn read_http_head_io<S>(stream: &mut S) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF mid-header",
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let head = buf[..pos].to_vec();
            let leftover = buf[pos..].to_vec();
            return Ok(Some((head, leftover)));
        }
        if buf.len() > 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn expects_100_continue(headers: &[(String, String)]) -> bool {
    header_value(headers, "expect")
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("100-continue"))
        })
        .unwrap_or(false)
}

fn invalid_body(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

async fn read_body<S>(
    stream: &mut S,
    leftover: &[u8],
    headers: &[(String, String)],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let transfer_encoding = header_value(headers, "transfer-encoding");
    let is_chunked = transfer_encoding
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false);

    let content_length = match header_value(headers, "content-length") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| invalid_body(format!("invalid Content-Length: {}", v)))?,
        ),
        None => None,
    };

    if transfer_encoding.is_some() && !is_chunked {
        return Err(invalid_body(format!(
            "unsupported Transfer-Encoding: {}",
            transfer_encoding.unwrap_or_default()
        )));
    }

    if is_chunked && content_length.is_some() {
        return Err(invalid_body(
            "both Transfer-Encoding: chunked and Content-Length are present",
        ));
    }

    if expects_100_continue(headers) && (is_chunked || content_length.is_some()) {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        stream.flush().await?;
    }

    if is_chunked {
        return read_chunked_request_body(stream, leftover.to_vec()).await;
    }

    let Some(content_length) = content_length else {
        return Ok(Vec::new());
    };

    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&leftover[..leftover.len().min(content_length)]);
    let mut tmp = [0u8; 8192];
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF mid-body",
            ));
        }
        let need = content_length - body.len();
        body.extend_from_slice(&tmp[..n.min(need)]);
    }
    Ok(body)
}

async fn read_chunked_request_body<S>(stream: &mut S, mut buf: Vec<u8>) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];

    loop {
        let line = read_crlf_line(stream, &mut buf, &mut tmp).await?;
        if line.is_empty() {
            continue;
        }

        let line_str = std::str::from_utf8(&line)
            .map_err(|_| invalid_body("non-utf8 chunk size line"))?
            .trim();
        let size_hex = line_str.split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| invalid_body(format!("bad chunk size '{}'", line_str)))?;

        if size == 0 {
            loop {
                let trailer = read_crlf_line(stream, &mut buf, &mut tmp).await?;
                if trailer.is_empty() {
                    return Ok(out);
                }
            }
        }

        fill_buffer(stream, &mut buf, &mut tmp, size + 2).await?;
        if &buf[size..size + 2] != b"\r\n" {
            return Err(invalid_body("chunk missing trailing CRLF"));
        }
        out.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        if let Some(idx) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = buf[..idx].to_vec();
            buf.drain(..idx + 2);
            return Ok(line);
        }
        let n = stream.read(tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn fill_buffer<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
    want: usize,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    while buf.len() < want {
        let n = stream.read(tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF in chunked body",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

// ---------- Plain HTTP proxy ----------

async fn do_plain_http(
    mut sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    fronter: Arc<DomainFronter>,
) -> std::io::Result<()> {
    let (method, target, _version, headers) = parse_request_head(head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    let body = read_body(&mut sock, leftover, &headers).await?;

    // Browser sends `GET http://example.com/path HTTP/1.1` on plain proxy.
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target.clone()
    } else {
        // Fallback: stitch Host header with path.
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        format!("http://{}{}", host, target)
    };

    tracing::info!("HTTP {} {}", method, url);
    // Plain HTTP proxy path — same range-parallel strategy as the
    // MITM-HTTPS path above. Large downloads on port 80 (package
    // mirrors, video poster streams, etc.) need the same acceleration
    // or the relay stalls per-chunk.
    let response = if method.eq_ignore_ascii_case("GET") && body.is_empty() {
        fronter.relay_parallel_range(&method, &url, &headers, &body).await
    } else {
        fronter.relay(&method, &url, &headers, &body).await
    };
    sock.write_all(&response).await?;
    sock.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_decodes_chunked_request() {
        let (mut client, mut server) = duplex(1024);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"llo\r\n6\r\n world\r\n0\r\nFoo: bar\r\n\r\n")
                .await
                .unwrap();
        });

        let body = read_body(
            &mut server,
            b"5\r\nhe",
            &headers(&[("Transfer-Encoding", "chunked")]),
        )
        .await
        .unwrap();

        writer.await.unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_body_sends_100_continue_before_waiting_for_body() {
        let (mut client, mut server) = duplex(1024);
        let client_task = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut tmp = [0u8; 64];
            loop {
                let n = client.read(&mut tmp).await.unwrap();
                assert!(n > 0, "proxy closed before sending 100 Continue");
                got.extend_from_slice(&tmp[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert_eq!(got, b"HTTP/1.1 100 Continue\r\n\r\n");
            client.write_all(b"hello").await.unwrap();
        });

        let body = read_body(
            &mut server,
            &[],
            &headers(&[("Content-Length", "5"), ("Expect", "100-continue")]),
        )
        .await
        .unwrap();

        client_task.await.unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn sni_rewrite_is_only_for_port_443() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("example.com".to_string(), "1.2.3.4".to_string());

        assert!(should_use_sni_rewrite(&hosts, "google.com", 443, false));
        assert!(!should_use_sni_rewrite(&hosts, "google.com", 80, false));
        assert!(should_use_sni_rewrite(&hosts, "www.example.com", 443, false));
        assert!(!should_use_sni_rewrite(&hosts, "www.example.com", 80, false));
    }

    #[test]
    fn youtube_via_relay_routes_youtube_through_relay_path() {
        // Issue #102. When youtube_via_relay=true, YouTube suffixes
        // must NOT match the SNI-rewrite path, so traffic falls
        // through to Apps Script relay. Other Google suffixes are
        // unaffected.
        let hosts = std::collections::HashMap::new();

        // Default behaviour: everything in the pool rewrites.
        assert!(should_use_sni_rewrite(&hosts, "www.youtube.com", 443, false));
        assert!(should_use_sni_rewrite(&hosts, "i.ytimg.com", 443, false));
        assert!(should_use_sni_rewrite(&hosts, "youtu.be", 443, false));
        assert!(should_use_sni_rewrite(&hosts, "www.google.com", 443, false));

        // With the toggle on: YouTube opts out, Google stays.
        assert!(!should_use_sni_rewrite(&hosts, "www.youtube.com", 443, true));
        assert!(!should_use_sni_rewrite(&hosts, "i.ytimg.com", 443, true));
        assert!(!should_use_sni_rewrite(&hosts, "youtu.be", 443, true));
        assert!(should_use_sni_rewrite(&hosts, "www.google.com", 443, true));
        assert!(should_use_sni_rewrite(&hosts, "fonts.gstatic.com", 443, true));
    }

    #[test]
    fn hosts_override_beats_youtube_via_relay() {
        // If the user added an explicit hosts override for a YouTube
        // subdomain, it should win — the override is a deliberate
        // user choice, the toggle is a default policy.
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("rr4.googlevideo.com".to_string(), "1.2.3.4".to_string());

        assert!(should_use_sni_rewrite(&hosts, "rr4.googlevideo.com", 443, true));
    }
}
