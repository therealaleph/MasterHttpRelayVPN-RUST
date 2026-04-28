use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};

use crate::config::{Config, Mode};
use crate::domain_fronter::DomainFronter;
use crate::mitm::MitmCertManager;
use crate::tunnel_client::{decode_udp_packets, TunnelMux};

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
    // NOTE on `googlevideo.com`: v1.7.4 (#275) added this here on the
    // theory that video chunks should bypass the Apps Script relay.
    // **Reverted in v1.7.6** — multiple users (#275 amirabbas117, #281
    // mrerf) reported total YouTube breakage after v1.7.4. Root cause
    // is that googlevideo.com is served by Google's separate "EVA"
    // edge IPs, not the regular GFE IPs that the user's `google_ip`
    // typically points at. SNI-rewriting `googlevideo.com:443` to a
    // GFE IP got TLS handshake / wrong-cert errors for those users.
    // Pre-v1.7.4 behaviour (chunks via the Apps Script relay path —
    // slow but reliable on every GFE IP) is restored. If we ever want
    // direct googlevideo.com routing, it needs a separate config knob
    // that lets users specify their EVA edge IP independently.
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

/// YouTube hosts that should be routed through the Apps Script relay
/// when `youtube_via_relay` is enabled — the API + HTML surfaces where
/// Restricted Mode is actually enforced (via the SNI=www.google.com
/// edge looking at the request). Issue #102 / #275.
///
/// Deliberately narrower than the YouTube section of
/// `SNI_REWRITE_SUFFIXES`:
///   - `youtube.com` / `youtu.be` / `youtube-nocookie.com`: HTML pages
///     and player frames. These trigger Restricted Mode if served via
///     the SNI rewrite, so when the flag is on we relay them.
///   - `youtubei.googleapis.com`: the YouTube data API the player
///     queries for video metadata + manifest. Restricted Mode also
///     gates video availability here. Without this entry, the JSON
///     RPC layer would still hit the SNI-rewrite tunnel via the
///     broader `googleapis.com` suffix — the user-visible symptom of
///     that miss is "youtube_via_relay flips on but Restricted Mode
///     stays sticky on some videos."
///
/// **NOT** in this list (intentional, was a regression in #275):
///   - `ytimg.com`: thumbnails. No Restricted Mode logic on a static
///     image CDN; routing through Apps Script makes thumbnails slow
///     for zero gain.
///   - `googlevideo.com`: video chunk CDN. Routing through Apps Script
///     means every chunk eats Apps Script quota *and* risks the 6-min
///     execution cap aborting long videos mid-playback.
///   - `ggpht.com`: channel/profile images, same reasoning as ytimg.
const YOUTUBE_RELAY_HOSTS: &[&str] = &[
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
];

/// Built-in list of DNS-over-HTTPS endpoints. CONNECTs to these (when
/// `tunnel_doh` is left at the default of `false`, i.e. bypass enabled)
/// skip the Apps Script tunnel and exit via plain TCP. Mix of the
/// browser-pinned variants Chrome/Brave/Edge/Firefox/Safari use and the
/// well-known public DoH providers users wire up by hand. Suffix
/// matching means we don't need to enumerate every tenant subdomain
/// (e.g. `*.cloudflare-dns.com` covers Workers-hosted DoH too).
///
/// Entries are matched case-insensitively. Both exact-match (`dns.google`)
/// and dot-anchored suffix-match (a host whose suffix is `.cloudflare-dns.com`
/// or which equals `cloudflare-dns.com`) are accepted — same shape as
/// `passthrough_hosts`'s `.foo` rule.
const DEFAULT_DOH_HOSTS: &[&str] = &[
    // The base SLD covers every tenant subdomain via suffix matching;
    // the browser-pinned variants below are listed for grep/discovery
    // (so a user searching "chrome.cloudflare-dns.com" finds this list)
    // and are technically redundant under cloudflare-dns.com.
    "cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "dns11.quad9.net",
    "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    "family.adguard-dns.com",
    "dns.nextdns.io",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "doh.dns.sb",
    "dns0.eu",
    "dns.alidns.com",
    "doh.pub",
    "dns.mullvad.net",
];

fn matches_sni_rewrite(host: &str, youtube_via_relay: bool) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');

    // YouTube relay carve-out runs FIRST so it wins over the broad
    // `googleapis.com` suffix that would otherwise pull
    // `youtubei.googleapis.com` into the SNI-rewrite path. The earlier
    // implementation iterated SNI_REWRITE_SUFFIXES with a filter, which
    // works for sibling entries (e.g. `youtube.com` in both lists) but
    // not for nested ones (`youtubei.googleapis.com` matches the broad
    // `googleapis.com` even when its specific entry is filtered out).
    // The short-circuit here is unconditional — we don't need to check
    // SNI rewrite once we've decided this host goes to the relay.
    if youtube_via_relay {
        for s in YOUTUBE_RELAY_HOSTS {
            if h == *s || h.ends_with(&format!(".{}", s)) {
                return false;
            }
        }
    }

    SNI_REWRITE_SUFFIXES
        .iter()
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
    tunnel_mux: Option<Arc<TunnelMux>>,
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
    /// User-configured hostnames that should skip the relay entirely
    /// and pass through as plain TCP (optionally via upstream_socks5).
    /// See config.rs `passthrough_hosts` for matching rules. Issues #39, #127.
    pub passthrough_hosts: Vec<String>,
    /// If true, drop SOCKS5 UDP datagrams destined for port 443 so
    /// callers fall back to TCP/HTTPS. See config.rs `block_quic` for
    /// the trade-off. Issue #213.
    pub block_quic: bool,
    /// If true, route DoH CONNECTs around the Apps Script tunnel via
    /// plain TCP. Default true via `Config::tunnel_doh = false`. See
    /// `DEFAULT_DOH_HOSTS` and `matches_doh_host` for matching, and
    /// config.rs `tunnel_doh` for the trade-off.
    pub bypass_doh: bool,
    /// User-supplied DoH hostnames added to the built-in default list.
    /// Same matching semantics as `passthrough_hosts`.
    pub bypass_doh_hosts: Vec<String>,
}

/// True if `host` matches a known DoH endpoint — either the built-in
/// `DEFAULT_DOH_HOSTS` list or a user-supplied entry in `extra`. Match
/// is case-insensitive, and entries match either exactly OR as a
/// dot-anchored suffix unconditionally (no leading-dot requirement,
/// unlike `passthrough_hosts`). The DoH list is *always* about a
/// service — every legitimate tenant subdomain of `cloudflare-dns.com`
/// or a user's private `doh.acme.test` is a DoH endpoint, so requiring
/// users to remember to write `.doh.acme.test` would be a footgun
/// without an obvious benefit.
fn host_matches_doh_entry(h: &str, entry: &str) -> bool {
    let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
    let e = e.strip_prefix('.').unwrap_or(&e);
    if e.is_empty() {
        return false;
    }
    h == e || h.ends_with(&format!(".{}", e))
}

pub fn matches_doh_host(host: &str, extra: &[String]) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if h.is_empty() {
        return false;
    }
    if DEFAULT_DOH_HOSTS
        .iter()
        .any(|s| host_matches_doh_entry(h, s))
    {
        return true;
    }
    extra.iter().any(|s| host_matches_doh_entry(h, s))
}

/// True if `host` matches any entry in the user's passthrough list.
/// Match is case-insensitive. Entries match either exactly, or as a
/// suffix if they start with "." (e.g. ".internal.example" matches
/// "a.b.internal.example" and the bare "internal.example"). Bare
/// entries like "example.com" only match the exact hostname — users
/// who want subdomains included should use ".example.com".
pub fn matches_passthrough(host: &str, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    let h = host.to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    list.iter().any(|entry| {
        let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        if e.is_empty() {
            return false;
        }
        if let Some(suffix) = e.strip_prefix('.') {
            h == suffix || h.ends_with(&format!(".{}", suffix))
        } else {
            h == e
        }
    })
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
            Mode::AppsScript | Mode::Full => {
                let f = DomainFronter::new(config)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
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

        // Surface a config combo that is otherwise silently inert: extras
        // listed under `bypass_doh_hosts` only take effect when the bypass
        // itself is on. A user who set `tunnel_doh: true` *and* populated
        // the extras list almost certainly didn't mean to disable the
        // feature their custom hosts feed into.
        if config.tunnel_doh && !config.bypass_doh_hosts.is_empty() {
            tracing::warn!(
                "config: bypass_doh_hosts has {} entries but tunnel_doh=true — \
                 the bypass is off, so the extras have no effect. Set \
                 tunnel_doh=false (or omit it) to use them.",
                config.bypass_doh_hosts.len()
            );
        }

        let rewrite_ctx = Arc::new(RewriteCtx {
            google_ip: config.google_ip.clone(),
            front_domain: config.front_domain.clone(),
            hosts: config.hosts.clone(),
            tls_connector,
            upstream_socks5: config.upstream_socks5.clone(),
            mode,
            youtube_via_relay: config.youtube_via_relay,
            passthrough_hosts: config.passthrough_hosts.clone(),
            block_quic: config.block_quic,
            bypass_doh: !config.tunnel_doh,
            bypass_doh_hosts: config.bypass_doh_hosts.clone(),
        });

        let socks5_port = config.socks5_port.unwrap_or(config.listen_port + 1);

        Ok(Self {
            host: config.listen_host.clone(),
            port: config.listen_port,
            socks5_port,
            fronter,
            mitm,
            rewrite_ctx,
            tunnel_mux: None, // initialized in run() inside the tokio runtime
        })
    }

    pub fn fronter(&self) -> Option<Arc<DomainFronter>> {
        self.fronter.clone()
    }
    pub async fn run(
        mut self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ProxyError> {
        // Initialize TunnelMux inside the runtime (tokio::spawn requires it).
        if self.rewrite_ctx.mode == Mode::Full {
            if let Some(f) = self.fronter.as_ref() {
                self.tunnel_mux = Some(TunnelMux::start(f.clone()));
            }
        }

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
        //
        // Sized to roughly match a browser's parallel-connection burst at
        // startup. The previous fixed `3` was fine for a single deployment
        // but left requests 4-10 of the opening burst paying a cold TLS
        // handshake each (~300ms). Scaling with deployment count gives
        // multi-account configs a proportionally warmer pool, capped so
        // single-deployment users don't hammer Google edge unnecessarily.
        if let Some(warm_fronter) = self.fronter.clone() {
            let n = warm_fronter.num_scripts().clamp(6, 16);
            tokio::spawn(async move {
                warm_fronter.warm(n).await;
            });
        }

        // Apps Script container keepalive. `warm()` above keeps the TCP
        // pool warm at startup, but the V8 container behind UrlFetchApp
        // goes cold after ~5min idle and costs 1-3s to wake. A periodic
        // HEAD ping prevents the cold-start lag on the first request
        // after a quiet pause (most visible as YouTube player stalls).
        // Skipped in google_only mode for the same reason as warm —
        // there's no fronter to ping.
        //
        // The handle is captured (not fire-and-forget) so the shutdown
        // arm of the select! below can abort it. Without that, hitting
        // Stop in the UI would leave the keepalive holding an
        // Arc<DomainFronter> on stale config and pinging Apps Script
        // every 240s — same class of bug that issue #99 hit for the
        // accept loops.
        let keepalive_task = if let Some(keepalive_fronter) = self.fronter.clone() {
            tokio::spawn(async move {
                keepalive_fronter.run_h1_keepalive().await;
            })
        } else {
            tokio::spawn(async move { std::future::pending::<()>().await })
        };

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
        let http_mux = self.tunnel_mux.clone();
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
                let mux = http_mux.clone();
                children.spawn(async move {
                    if let Err(e) = handle_http_client(sock, fronter, mitm, rewrite_ctx, mux).await
                    {
                        tracing::debug!("http client {} closed: {}", peer, e);
                    }
                });
            }
        });

        let socks_fronter = self.fronter.clone();
        let socks_mitm = self.mitm.clone();
        let socks_ctx = self.rewrite_ctx.clone();
        let socks_mux = self.tunnel_mux.clone();
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
                let mux = socks_mux.clone();
                children.spawn(async move {
                    if let Err(e) =
                        handle_socks5_client(sock, fronter, mitm, rewrite_ctx, mux).await
                    {
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
                keepalive_task.abort();
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
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    let (head, leftover) = match read_http_head(&mut sock).await? {
        HeadReadResult::Got { head, leftover } => (head, leftover),
        HeadReadResult::Closed => return Ok(()),
        HeadReadResult::Oversized => {
            // Reply with 431 instead of just dropping the socket so the
            // browser shows a real error rather than retrying the same
            // oversized request in a loop.
            tracing::warn!(
                "request head exceeds {} bytes — refusing with 431",
                MAX_HEADER_BYTES
            );
            let _ = sock
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
                      Connection: close\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
            let _ = sock.flush().await;
            return Ok(());
        }
    };

    let (method, target, _version, _headers) = parse_request_head(&head)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target);
        // Mirror the SOCKS5 short-circuit: if the tunnel-node just failed
        // this (host, port) with unreachable, return 502 immediately rather
        // than acknowledging the CONNECT and blowing tunnel quota on a
        // guaranteed retry. See `TunnelMux::is_unreachable` for context.
        if let Some(ref mux) = tunnel_mux {
            if mux.is_unreachable(&host, port) {
                tracing::info!("CONNECT {}:{} (negative-cached, refusing)", host, port);
                let _ = sock
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = sock.flush().await;
                return Ok(());
            }
        }
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        sock.flush().await?;
        dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx, tunnel_mux).await
    } else {
        // Plain HTTP proxy request (e.g. `GET http://…`).
        //
        // apps_script mode: relay through the Apps Script fronter (which
        // is the whole point of the relay).
        //
        // google_only bootstrap mode: no fronter exists, so passthrough as
        // direct TCP. Same contract as `dispatch_tunnel` honors for CONNECT
        // in google_only — anything not on the Google edge is forwarded
        // direct (or via `upstream_socks5`) so the user's browser still
        // works while they finish setting up Apps Script. Issue: typing a
        // bare `http://example.com` URL used to return a 502 here even
        // though `https://example.com` (CONNECT) worked fine.
        match fronter {
            Some(f) => do_plain_http(sock, &head, &leftover, f).await,
            None => do_plain_http_passthrough(sock, &head, &leftover, &rewrite_ctx).await,
        }
    }
}

// ---------- SOCKS5 ----------

async fn handle_socks5_client(
    mut sock: TcpStream,
    fronter: Option<Arc<DomainFronter>>,
    mitm: Arc<Mutex<MitmCertManager>>,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
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
    if cmd != 0x01 && cmd != 0x03 {
        // CONNECT and UDP ASSOCIATE only.
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

    if cmd == 0x03 {
        tracing::info!("SOCKS5 UDP ASSOCIATE requested for {}:{}", host, port);
        return handle_socks5_udp_associate(sock, rewrite_ctx, tunnel_mux).await;
    }

    // Negative-cache short-circuit: if the tunnel-node just failed to reach
    // this exact (host, port) with `Network is unreachable` / `No route to
    // host`, reply 0x04 (Host unreachable) immediately. Saves a 1.5–2s tunnel
    // round-trip on guaranteed-failing targets — the IPv6 probe retry loop
    // is the main offender on devices without IPv6.
    if let Some(ref mux) = tunnel_mux {
        if mux.is_unreachable(&host, port) {
            tracing::info!("SOCKS5 CONNECT -> {}:{} (negative-cached, refusing)", host, port);
            sock.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            sock.flush().await?;
            return Ok(());
        }
    }

    tracing::info!("SOCKS5 CONNECT -> {}:{}", host, port);

    // Success reply with zeroed BND.
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    sock.flush().await?;

    dispatch_tunnel(sock, host, port, fronter, mitm, rewrite_ctx, tunnel_mux).await
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SocksUdpTarget {
    host: String,
    port: u16,
    atyp: u8,
    addr: Vec<u8>,
}

/// Per-target relay session state shared between the dispatch loop and
/// the per-session task. The dispatch loop pushes uplink datagrams via
/// `uplink`; the task drains the upstream and serializes both directions
/// onto a single tunnel-mux call at a time. `sid` is held here so the
/// dispatch teardown path can issue close_session for any task it has
/// to abort mid-await.
struct UdpRelaySession {
    sid: String,
    uplink: mpsc::Sender<Vec<u8>>,
}

/// All per-ASSOCIATE UDP relay state behind a single mutex so insertion
/// order, the live-session map, and per-task self-removal can all stay
/// consistent. Wrapping each separately invited a slow leak: the
/// previous design's `insertion_order` deque was only pruned on
/// overflow eviction, so a long-lived ASSOCIATE that opened many
/// short-lived sessions accumulated dead `SocksUdpTarget` entries.
struct UdpRelayState {
    sessions: HashMap<SocksUdpTarget, UdpRelaySession>,
    /// Insertion-order log for FIFO eviction. NOT a real LRU — repeated
    /// uplinks to a hot session do not move it to the back. We keep it
    /// in lockstep with `sessions` (insert appends; remove scans and
    /// erases the matching entry — O(N) but N ≤ 256).
    order: VecDeque<SocksUdpTarget>,
}

impl UdpRelayState {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get_uplink(&self, target: &SocksUdpTarget) -> Option<mpsc::Sender<Vec<u8>>> {
        self.sessions.get(target).map(|s| s.uplink.clone())
    }

    fn insert(&mut self, target: SocksUdpTarget, session: UdpRelaySession) {
        self.order.push_back(target.clone());
        self.sessions.insert(target, session);
    }

    fn remove(&mut self, target: &SocksUdpTarget) {
        if let Some(pos) = self.order.iter().position(|t| t == target) {
            self.order.remove(pos);
        }
        self.sessions.remove(target);
    }

    /// Pop the oldest session entries until `sessions.len() < cap`.
    /// Stale `order` entries (already removed by self-cleanup on a
    /// task's natural exit) are quietly skipped.
    fn evict_until_under(&mut self, cap: usize) -> Vec<SocksUdpTarget> {
        let mut evicted = Vec::new();
        while self.sessions.len() >= cap {
            let Some(victim) = self.order.pop_front() else {
                break;
            };
            if self.sessions.remove(&victim).is_some() {
                evicted.push(victim);
            }
        }
        evicted
    }

    /// Snapshot live sids for the teardown close_session sweep. We
    /// take a copy (not a drain) so the caller can decide whether to
    /// also clear the map.
    fn live_sids(&self) -> Vec<String> {
        self.sessions.values().map(|s| s.sid.clone()).collect()
    }

    fn clear(&mut self) {
        self.sessions.clear();
        self.order.clear();
    }
}

/// SOCKS5 UDP request frame: 4-byte header + atyp-specific address + 2-byte
/// port + payload. DOMAIN atyp uses a 1-byte length prefix + up to 255
/// bytes, so the largest header is `4 + 1 + 255 + 2 = 262`. Round to 300
/// for safety; payload itself can be a full 64 KB datagram.
const SOCKS5_UDP_RECV_BUF_BYTES: usize = 65535 + 300;

/// Bound on per-session uplink queue depth. UDP is lossy by design — if
/// the per-session task can't keep up, drop the newest datagram (caller
/// uses `try_send`) instead of stalling the whole UDP relay loop.
const UDP_UPLINK_QUEUE: usize = 64;

/// Initial poll spacing when a session is idle. Tunnel-node already
/// long-polls each empty `udp_data` for up to 5 s, so this is a
/// client-side floor — bursts of upstream packets reset back to this.
const UDP_INITIAL_POLL_DELAY: Duration = Duration::from_millis(500);

/// Cap on the exponential backoff for an idle session. After this many
/// seconds of zero traffic in either direction, polls happen at most
/// once per `UDP_MAX_POLL_DELAY` plus the tunnel-node long-poll window —
/// so an idle UDP destination costs roughly one batch slot every 35 s.
const UDP_MAX_POLL_DELAY: Duration = Duration::from_secs(30);

/// Cap on simultaneous UDP relay sessions per SOCKS5 ASSOCIATE. STUN
/// candidate gathering and DNS fanout produce dozens of distinct
/// targets; an abusive or runaway client could produce thousands.
/// 256 is generous for legitimate use and bounds tunnel-node UDP
/// sessions a single ASSOCIATE can hold open.
///
/// Eviction policy is FIFO by insertion time, not true LRU — repeated
/// uplinks to a hot session do not move it to the back. Real LRU
/// would need a touch on every uplink (extra lock acquisition per
/// datagram); the long-tail of dead targets gets cleaned up here just
/// fine without that cost, and live targets are typically also recently
/// inserted.
const MAX_UDP_SESSIONS_PER_ASSOCIATE: usize = 256;

/// Drop UDP datagrams larger than this (pre-base64). Standard MTU is
/// 1500B, jumbo frames are ~9000B; anything above that is either a
/// pathologically fragmented IP datagram or abusive traffic. Each
/// datagram carries ~33% base64 + JSON envelope overhead and consumes
/// Apps Script per-account quota, so a permissive ceiling here matters.
const MAX_UDP_PAYLOAD_BYTES: usize = 9 * 1024;

async fn handle_socks5_udp_associate(
    mut control: TcpStream,
    rewrite_ctx: Arc<RewriteCtx>,
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    if rewrite_ctx.mode != Mode::Full {
        tracing::debug!("UDP ASSOCIATE rejected: only full mode supports UDP tunneling");
        write_socks5_reply(&mut control, 0x07, None).await?;
        return Ok(());
    }
    let Some(mux) = tunnel_mux else {
        tracing::debug!("UDP ASSOCIATE rejected: full mode has no tunnel mux");
        write_socks5_reply(&mut control, 0x01, None).await?;
        return Ok(());
    };

    // Per RFC 1928 §6 the UDP relay only accepts datagrams from the
    // SOCKS5 client. We pin the source IP to the control TCP peer up
    // front so a third party on the bind interface can't hijack the
    // session by sending the first datagram. THIS — not the bind IP
    // below — is what actually keeps unauthenticated traffic out.
    let client_peer_ip = control.peer_addr()?.ip();

    // Bind the UDP relay to the same local IP the SOCKS5 client used
    // to reach the control TCP socket. `TcpStream::local_addr()` on an
    // accepted socket returns the concrete terminating address (e.g.
    // 127.0.0.1 for a loopback client, 192.168.1.5 for a LAN client),
    // not the listener's bind specifier — so this naturally tracks the
    // path the client took. Source-IP filtering above is the security
    // boundary; the bind choice is just about reachability.
    let bind_ip = control.local_addr()?.ip();
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
    write_socks5_reply(&mut control, 0x00, Some(udp.local_addr()?)).await?;
    tracing::info!(
        "SOCKS5 UDP relay bound on {} for client {}",
        udp.local_addr()?,
        client_peer_ip
    );

    let mut buf = vec![0u8; SOCKS5_UDP_RECV_BUF_BYTES];
    let mut control_buf = [0u8; 1];
    let mut client_addr: Option<SocketAddr> = None;
    let state: Arc<Mutex<UdpRelayState>> = Arc::new(Mutex::new(UdpRelayState::new()));
    // Tracking per-target tasks here — instead of bare `tokio::spawn`
    // — lets the teardown path call `abort_all()`, cancelling any
    // in-flight `mux.udp_data` await. Without it, a task mid-poll
    // could keep paying tunnel-node round trips for up to 5 s after
    // the SOCKS5 client went away.
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut oversized_dropped: u64 = 0;
    let mut sessions_evicted: u64 = 0;
    let mut foreign_ip_drops: u64 = 0;

    loop {
        tokio::select! {
            recv = udp.recv_from(&mut buf) => {
                let (n, peer) = match recv {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("udp associate recv failed: {}", e);
                        break;
                    }
                };
                // Source-IP check: anything not from the SOCKS5 client's
                // host is dropped silently.
                if peer.ip() != client_peer_ip {
                    foreign_ip_drops += 1;
                    if foreign_ip_drops == 1 || foreign_ip_drops.is_multiple_of(100) {
                        tracing::debug!(
                            "udp dropped from unauthorized source {}: count={}",
                            peer.ip(),
                            foreign_ip_drops,
                        );
                    }
                    continue;
                }

                // Parse BEFORE port-locking. A malformed datagram from
                // the right IP must not pin client_addr to its source
                // port — otherwise a co-tenant on the bind interface
                // can race one bad packet to DoS the legitimate client
                // (whose real datagram, sent from a different ephemeral
                // port, would then be silently rejected).
                let Some((target, payload)) = parse_socks5_udp_packet(&buf[..n]) else {
                    continue;
                };

                // Issue #213: client-side QUIC block. UDP/443 is
                // HTTP/3 — drop the datagram silently so the client
                // stack retries a couple of times and then falls back
                // to TCP/HTTPS, which goes through the regular CONNECT
                // path. Skipping this at the SOCKS5 layer (rather than
                // letting it hit the tunnel-node) avoids paying the
                // 200–500 ms tunnel-node round-trip per dropped QUIC
                // datagram, which would otherwise compound during the
                // 1–3 retries before the browser falls back.
                //
                // Silent drop instead of an explicit error reply: the
                // SOCKS5 UDP wire has no "destination unreachable"
                // datagram — `0x04` only exists in TCP CONNECT replies
                // (RFC 1928 §6). The browser's QUIC stack already has
                // a "no response → fall back" timeout, so silent drop
                // is the contractually correct shape.
                if rewrite_ctx.block_quic && target.port == 443 {
                    tracing::debug!(
                        "udp dropped: block_quic=true, target {}:443",
                        target.host
                    );
                    continue;
                }

                // RFC 1928 §6: lock to the first VALID datagram's source
                // port. Subsequent datagrams must come from the same
                // (ip, port) pair.
                if let Some(existing) = client_addr {
                    if existing != peer {
                        continue;
                    }
                } else {
                    tracing::info!("UDP relay locked to client {}", peer);
                    client_addr = Some(peer);
                }

                // Size guard: drop oversize datagrams before they reach
                // the mux. Each datagram costs ~payload * 1.33 in the
                // batched JSON envelope plus tunnel-node CPU; uncapped,
                // a runaway client can exhaust Apps Script quota.
                if payload.len() > MAX_UDP_PAYLOAD_BYTES {
                    oversized_dropped += 1;
                    if oversized_dropped == 1 || oversized_dropped.is_multiple_of(100) {
                        tracing::debug!(
                            "udp datagram dropped: {} B > {} B (count={})",
                            payload.len(),
                            MAX_UDP_PAYLOAD_BYTES,
                            oversized_dropped,
                        );
                    }
                    continue;
                }
                let payload = payload.to_vec();

                // Fast path: existing session — push payload onto its
                // bounded uplink queue, drop on overflow (UDP semantics).
                {
                    let st = state.lock().await;
                    if let Some(uplink) = st.get_uplink(&target) {
                        let _ = uplink.try_send(payload);
                        continue;
                    }
                }

                // Cap reached → evict oldest sessions before opening a
                // new one. Each evicted entry drops its uplink Sender,
                // which causes the per-session task to exit its select
                // and tell tunnel-node to close. Any uplink already in
                // that channel is delivered before the task exits.
                {
                    let mut st = state.lock().await;
                    let evicted = st.evict_until_under(MAX_UDP_SESSIONS_PER_ASSOCIATE);
                    for victim in evicted {
                        sessions_evicted += 1;
                        if sessions_evicted == 1 || sessions_evicted.is_multiple_of(50) {
                            tracing::debug!(
                                "udp session cap {} reached; evicted {}:{} (total evicted={})",
                                MAX_UDP_SESSIONS_PER_ASSOCIATE,
                                victim.host,
                                victim.port,
                                sessions_evicted,
                            );
                        }
                    }
                }

                // New target: open via tunnel-node and spawn the per-session
                // task. The first datagram rides the udp_open op so we
                // save one round trip on session establishment.
                let resp = match mux.udp_open(&target.host, target.port, payload).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(
                            "udp open {}:{} failed: {}",
                            target.host, target.port, e
                        );
                        continue;
                    }
                };
                if let Some(ref e) = resp.e {
                    tracing::debug!("udp open {}:{} failed: {}", target.host, target.port, e);
                    continue;
                }
                let Some(sid) = resp.sid.clone() else {
                    tracing::debug!(
                        "udp open {}:{} returned no sid",
                        target.host, target.port
                    );
                    continue;
                };
                send_udp_response_packets(&udp, peer, &target, &resp).await;

                // Tunnel-node may report eof on the open response if the
                // upstream socket died between bind and the first drain
                // (e.g., immediate ICMP unreachable). The session has
                // already been reaped on that side — skip insert/spawn
                // and let the next datagram from the client retry.
                if resp.eof.unwrap_or(false) {
                    tracing::debug!(
                        "udp open {}:{} returned eof; not tracking session",
                        target.host,
                        target.port,
                    );
                    continue;
                }

                let (uplink_tx, uplink_rx) = mpsc::channel::<Vec<u8>>(UDP_UPLINK_QUEUE);
                let task_mux = mux.clone();
                let task_udp = udp.clone();
                let task_target = target.clone();
                let task_state = state.clone();
                let task_sid = sid.clone();
                tasks.spawn(async move {
                    udp_session_task(
                        task_mux,
                        task_udp,
                        task_sid,
                        task_target.clone(),
                        peer,
                        uplink_rx,
                    )
                    .await;
                    // Natural-exit cleanup (eof / mux error / channel
                    // close): remove from shared state so a future
                    // packet to the same target opens a fresh session,
                    // and so insertion_order doesn't leak. Skipped on
                    // teardown since abort_all cancels this await point.
                    task_state.lock().await.remove(&task_target);
                });

                state.lock().await.insert(
                    target,
                    UdpRelaySession {
                        sid,
                        uplink: uplink_tx,
                    },
                );
            }
            read = control.read(&mut control_buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }

    // Teardown. Snapshot live sids first; they're authoritative for
    // which tunnel-node sessions still exist. Then clear state — that
    // drops every uplink Sender, so any task waiting on `recv()` wakes
    // and exits naturally. Finally `abort_all` cancels tasks that were
    // mid-`mux.udp_data` await; for those the natural-exit close won't
    // run, so we send close_session here on their behalf.
    let live_sids: Vec<String>;
    {
        let mut st = state.lock().await;
        live_sids = st.live_sids();
        st.clear();
    }
    tasks.abort_all();
    for sid in live_sids {
        mux.close_session(&sid).await;
    }
    Ok(())
}

/// Per-target relay task. Owns one tunnel-node UDP session and shuttles
/// datagrams in both directions through a single in-flight tunnel call
/// at a time. Two cancellation points:
///   * `uplink_rx.recv()` returns `None` when the dispatch loop drops
///     the matching `Sender` (SOCKS5 client gone, or session evicted).
///   * `mux.udp_data` returns eof / error when the tunnel-node session
///     is reaped or the target is unreachable.
async fn udp_session_task(
    mux: Arc<TunnelMux>,
    udp: Arc<UdpSocket>,
    sid: String,
    target: SocksUdpTarget,
    client_addr: SocketAddr,
    mut uplink_rx: mpsc::Receiver<Vec<u8>>,
) {
    let mut backoff = UDP_INITIAL_POLL_DELAY;
    loop {
        // `biased;` prefers uplink so an active client doesn't get
        // shadowed by a long sleep. Both branches are cancel-safe.
        let resp = tokio::select! {
            biased;
            uplink = uplink_rx.recv() => {
                let Some(payload) = uplink else { break; };
                // Active uplink — reset the empty-poll backoff so the
                // next inbound poll happens promptly.
                backoff = UDP_INITIAL_POLL_DELAY;
                match mux.udp_data(&sid, payload).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("udp data {} failed: {}", sid, e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(backoff) => {
                match mux.udp_data(&sid, Vec::new()).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("udp poll {} failed: {}", sid, e);
                        break;
                    }
                }
            }
        };
        if resp.e.is_some() || resp.eof.unwrap_or(false) {
            break;
        }
        let got_pkts = resp.pkts.as_ref().map(|p| !p.is_empty()).unwrap_or(false);
        if got_pkts {
            send_udp_response_packets(&udp, client_addr, &target, &resp).await;
            backoff = UDP_INITIAL_POLL_DELAY;
        } else {
            // Empty poll — back off so an idle destination doesn't
            // monopolize batch slots.
            backoff = (backoff * 2).min(UDP_MAX_POLL_DELAY);
        }
    }
    // Be polite even if the session is already gone server-side; the
    // tunnel-node tolerates close on an unknown sid.
    mux.close_session(&sid).await;
}

async fn send_udp_response_packets(
    udp: &UdpSocket,
    client_addr: SocketAddr,
    target: &SocksUdpTarget,
    resp: &crate::domain_fronter::TunnelResponse,
) {
    let packets = match decode_udp_packets(resp) {
        Ok(packets) => packets,
        Err(e) => {
            tracing::debug!("{}", e);
            return;
        }
    };
    for packet in packets {
        let framed = build_socks5_udp_packet(target, &packet);
        if let Err(e) = udp.send_to(&framed, client_addr).await {
            // Errors here mean the local socket can't reach the SOCKS5
            // client (ENETUNREACH, EHOSTDOWN, etc.). Surface at debug
            // so a "my UDP traffic isn't coming back" report has
            // something to grep for; volume is bounded by what we'd
            // have delivered anyway.
            tracing::debug!(
                "udp send to client {} failed for {}:{}: {}",
                client_addr,
                target.host,
                target.port,
                e,
            );
        }
    }
}

async fn write_socks5_reply(
    sock: &mut TcpStream,
    rep: u8,
    addr: Option<SocketAddr>,
) -> std::io::Result<()> {
    let mut out = vec![0x05, rep, 0x00];
    match addr {
        Some(SocketAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            out.push(0x01);
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    sock.write_all(&out).await?;
    sock.flush().await
}

fn parse_socks5_udp_packet(buf: &[u8]) -> Option<(SocksUdpTarget, &[u8])> {
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return None;
    }
    let atyp = buf[3];
    let mut pos = 4usize;
    let (host, addr) = match atyp {
        0x01 => {
            if buf.len() < pos + 4 + 2 {
                return None;
            }
            let addr = buf[pos..pos + 4].to_vec();
            pos += 4;
            let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            (ip.to_string(), addr)
        }
        0x03 => {
            if buf.len() < pos + 1 {
                return None;
            }
            let len = buf[pos] as usize;
            pos += 1;
            if len == 0 || buf.len() < pos + len + 2 {
                return None;
            }
            let addr = buf[pos..pos + len].to_vec();
            pos += len;
            // Reject non-UTF-8 hostnames at the parser. Lossy decoding
            // would forward U+FFFD into DNS and trigger an opaque
            // NXDOMAIN — failing fast here gives us a clean parse-level
            // drop that the test suite can assert on.
            let host = std::str::from_utf8(&addr).ok()?.to_owned();
            (host, addr)
        }
        0x04 => {
            if buf.len() < pos + 16 + 2 {
                return None;
            }
            let addr = buf[pos..pos + 16].to_vec();
            pos += 16;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr);
            (std::net::Ipv6Addr::from(octets).to_string(), addr)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Some((
        SocksUdpTarget {
            host,
            port,
            atyp,
            addr,
        },
        &buf[pos..],
    ))
}

fn build_socks5_udp_packet(target: &SocksUdpTarget, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + target.addr.len() + 2 + payload.len() + 1);
    out.extend_from_slice(&[0, 0, 0, target.atyp]);
    match target.atyp {
        0x03 => {
            out.push(target.addr.len() as u8);
            out.extend_from_slice(&target.addr);
        }
        _ => out.extend_from_slice(&target.addr),
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    out.extend_from_slice(payload);
    out
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
    tunnel_mux: Option<Arc<TunnelMux>>,
) -> std::io::Result<()> {
    // 0. User-configured passthrough list wins over every other path.
    //    If the host matches `passthrough_hosts`, we raw-TCP it (through
    //    upstream_socks5 if set) and never touch Apps Script, SNI-rewrite,
    //    or MITM. Point: saves Apps Script quota on hosts the user already
    //    has reachability to, and avoids MITM-breaking cert pinning on
    //    hosts the user knows are cert-pinned. Issues #39, #127.
    if matches_passthrough(&host, &rewrite_ctx.passthrough_hosts) {
        let via = rewrite_ctx.upstream_socks5.as_deref();
        tracing::info!(
            "dispatch {}:{} -> raw-tcp ({}) (passthrough_hosts match)",
            host,
            port,
            via.unwrap_or("direct")
        );
        plain_tcp_passthrough(sock, &host, port, via).await;
        return Ok(());
    }

    // 0.5. DoH bypass. DNS-over-HTTPS is the dominant per-flow DNS cost
    //      in Full mode (every browser name lookup costs a ~2 s Apps
    //      Script round-trip), and the tunnel adds no privacy beyond
    //      what DoH already provides. Route known DoH hosts directly.
    //      Port-gated to 443 so a non-TLS CONNECT to e.g. `dns.google:80`
    //      doesn't get diverted off-tunnel by accident.
    //      See `DEFAULT_DOH_HOSTS` and config.rs `tunnel_doh`.
    if rewrite_ctx.bypass_doh
        && port == 443
        && matches_doh_host(&host, &rewrite_ctx.bypass_doh_hosts)
    {
        let via = rewrite_ctx.upstream_socks5.as_deref();
        tracing::info!(
            "dispatch {}:{} -> raw-tcp ({}) (doh bypass)",
            host,
            port,
            via.unwrap_or("direct")
        );
        plain_tcp_passthrough(sock, &host, port, via).await;
        return Ok(());
    }

    // 1. Full tunnel mode: ALL traffic goes through the batch multiplexer
    //    (Apps Script → tunnel node → real TCP). No MITM, no cert.
    if rewrite_ctx.mode == Mode::Full {
        let mux = match tunnel_mux {
            Some(m) => m,
            None => {
                tracing::error!(
                    "dispatch {}:{} -> full mode but no tunnel mux (should not happen)",
                    host,
                    port
                );
                return Ok(());
            }
        };
        tracing::info!("dispatch {}:{} -> full tunnel (via batch mux)", host, port);
        crate::tunnel_client::tunnel_connection(sock, &host, port, &mux).await?;
        return Ok(());
    }

    // 2. Explicit hosts override or SNI-rewrite suffix: for HTTPS targets,
    //    use the TLS SNI-rewrite tunnel (skipped in full mode above).
    if should_use_sni_rewrite(
        &rewrite_ctx.hosts,
        &host,
        port,
        rewrite_ctx.youtube_via_relay,
    ) {
        tracing::info!(
            "dispatch {}:{} -> sni-rewrite tunnel (Google edge direct)",
            host,
            port
        );
        return do_sni_rewrite_tunnel_from_tcp(sock, &host, port, mitm, rewrite_ctx).await;
    }

    // 3. google_only bootstrap: no Apps Script relay exists. Anything that
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
                match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port)))
                    .await
                {
                    Ok(Ok(s)) => s,
                    _ => return,
                }
            }
        }
    } else {
        match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port))).await {
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
                    host,
                    port
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
/// Maximum size of an HTTP request head (request line + all headers).
///
/// Set to match upstream Python's `MAX_HEADER_BYTES` (64 KB,
/// masterking32/MasterHttpRelayVPN constants.py). Real browsers
/// virtually never exceed ~16 KB; anything past 64 KB is either a
/// buggy client or a deliberate slowloris-style header bomb.
/// Previously 1 MB, which let a misbehaving client allocate a lot
/// of memory before failing.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Result of `read_http_head` / `read_http_head_io`.
/// `Oversized` is distinct from other I/O errors so the caller can
/// reply with `431 Request Header Fields Too Large` instead of just
/// dropping the connection (which a browser would silently retry,
/// reproducing the same problem).
enum HeadReadResult {
    Got { head: Vec<u8>, leftover: Vec<u8> },
    Closed,
    Oversized,
}

async fn read_http_head(sock: &mut TcpStream) -> std::io::Result<HeadReadResult> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(HeadReadResult::Closed)
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
            return Ok(HeadReadResult::Got { head, leftover });
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(HeadReadResult::Oversized);
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
        HeadReadResult::Got { head, leftover } => (head, leftover),
        HeadReadResult::Closed => return Ok(false),
        HeadReadResult::Oversized => {
            // Inside MITM: same reasoning as the plaintext path. Return
            // 431 over the decrypted stream so the browser surfaces a
            // real error to the user instead of looping a connection
            // reset, which was the symptom upstream caught (Apps Script
            // ate malformed JSON when truncated header blocks were
            // forwarded blindly).
            tracing::warn!(
                "MITM header block exceeds {} bytes — closing ({}:{})",
                MAX_HEADER_BYTES,
                host,
                port
            );
            let _ = stream
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
                      Connection: close\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
            let _ = stream.flush().await;
            return Ok(false);
        }
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
    let is_x_com = host_lower == "x.com" || host_lower.ends_with(".x.com") || host_lower == "twitter.com" || host_lower.ends_with(".twitter.com");
    let path = if is_x_com && path.starts_with("/i/api/graphql/") && path.contains("?variables=") {
        match path.split_once('&') {
            Some((short, _)) => {
                tracing::debug!(
                    "x.com graphql URL truncated: {} chars -> {}",
                    path.len(),
                    short.len()
                );
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
        fronter
            .relay_parallel_range(&method, &url, &headers, &body)
            .await
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

async fn read_http_head_io<S>(stream: &mut S) -> std::io::Result<HeadReadResult>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(HeadReadResult::Closed)
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
            return Ok(HeadReadResult::Got { head, leftover });
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(HeadReadResult::Oversized);
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
        fronter
            .relay_parallel_range(&method, &url, &headers, &body)
            .await
    } else {
        fronter.relay(&method, &url, &headers, &body).await
    };
    sock.write_all(&response).await?;
    sock.flush().await?;
    Ok(())
}

/// google_only mode plain-HTTP passthrough. The CONNECT path already
/// falls through to direct TCP for non-Google-edge hosts in google_only;
/// this is the same idea for the `GET http://…` proxy form so a bare
/// `http://example.com` typed in the address bar doesn't 502.
///
/// We rewrite the absolute-form request URI (`GET http://host/path`) to
/// origin form (`GET /path`), strip hop-by-hop headers, force
/// `Connection: close` so a keep-alive client can't pipeline a request
/// to a different host onto our spliced socket, then dial the origin
/// (honoring `upstream_socks5` if set) and splice both directions.
async fn do_plain_http_passthrough(
    mut sock: TcpStream,
    head: &[u8],
    leftover: &[u8],
    rewrite_ctx: &RewriteCtx,
) -> std::io::Result<()> {
    let (method, target, version, headers) = match parse_request_head(head) {
        Some(v) => v,
        None => return Ok(()),
    };

    let (host, port, path) = match resolve_plain_http_target(&target, &headers) {
        Some(v) => v,
        None => {
            tracing::debug!("plain-http passthrough: cannot parse target {}", target);
            return Ok(());
        }
    };

    tracing::info!(
        "dispatch http {}:{} -> raw-tcp ({}) (google_only: no relay)",
        host,
        port,
        rewrite_ctx.upstream_socks5.as_deref().unwrap_or("direct"),
    );

    // Rewrite request line to origin form and drop hop-by-hop headers.
    let mut rewritten = Vec::with_capacity(head.len());
    rewritten.extend_from_slice(method.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(version.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    for (k, v) in &headers {
        let kl = k.to_ascii_lowercase();
        if kl == "proxy-connection" || kl == "connection" || kl == "keep-alive" {
            continue;
        }
        rewritten.extend_from_slice(k.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(v.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");

    let target_host = host.trim_start_matches('[').trim_end_matches(']');
    let connect_timeout = if looks_like_ip(target_host) {
        std::time::Duration::from_secs(4)
    } else {
        std::time::Duration::from_secs(10)
    };
    let upstream = if let Some(proxy) = rewrite_ctx.upstream_socks5.as_deref() {
        match socks5_connect_via(proxy, target_host, port).await {
            Ok(s) => s,
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
                    _ => return Ok(()),
                }
            }
        }
    } else {
        match tokio::time::timeout(connect_timeout, TcpStream::connect((target_host, port))).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!("plain-http connect {}:{} failed: {}", host, port, e);
                return Ok(());
            }
            Err(_) => {
                tracing::debug!("plain-http connect {}:{} timeout", host, port);
                return Ok(());
            }
        }
    };
    let _ = upstream.set_nodelay(true);

    let (mut ar, mut aw) = sock.split();
    let (mut br, mut bw) = upstream.into_split();
    bw.write_all(&rewritten).await?;
    if !leftover.is_empty() {
        bw.write_all(leftover).await?;
    }
    let t1 = tokio::io::copy(&mut ar, &mut bw);
    let t2 = tokio::io::copy(&mut br, &mut aw);
    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
    Ok(())
}

/// Parse the target of a plain-HTTP proxy request line into
/// `(host, port, origin-form-path)`. Browsers send absolute form
/// (`http://host[:port]/path`); we also accept the origin-form
/// fallback (`/path` with a `Host:` header) for transparent-proxy
/// clients. `https://` is accepted defensively, though browsers route
/// HTTPS through CONNECT and shouldn't hit this path.
fn resolve_plain_http_target(
    target: &str,
    headers: &[(String, String)],
) -> Option<(String, u16, String)> {
    let (rest, default_port) = if let Some(r) = target.strip_prefix("http://") {
        (r, 80u16)
    } else if let Some(r) = target.strip_prefix("https://") {
        (r, 443u16)
    } else if target.starts_with('/') {
        let host_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())?;
        let (host, port) = split_authority(host_header, 80);
        return Some((host, port, target.to_string()));
    } else {
        return None;
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = split_authority(authority, default_port);
    Some((host, port, path.to_string()))
}

/// Split an `authority` (`host[:port]`, with optional IPv6 brackets)
/// into a `(host, port)` pair, defaulting the port when absent.
fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    // Bare IPv6 (multiple colons, no brackets) — `rsplit_once(':')`
    // would otherwise mangle `::1` into `(":", 1)`. Take the whole
    // string as the host and use the default port.
    let colons = authority.bytes().filter(|&b| b == b':').count();
    if colons > 1 && !authority.starts_with('[') {
        return (authority.to_string(), default_port);
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (authority.to_string(), default_port)
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

    #[test]
    fn resolve_plain_http_target_parses_absolute_form() {
        let h = headers(&[]);
        let (host, port, path) =
            resolve_plain_http_target("http://example.com/", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");

        let (host, port, path) =
            resolve_plain_http_target("http://example.com:8080/foo?x=1", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo?x=1");

        let (host, port, path) =
            resolve_plain_http_target("http://example.com", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn resolve_plain_http_target_falls_back_to_host_header() {
        let h = headers(&[("Host", "example.com:8080")]);
        let (host, port, path) = resolve_plain_http_target("/foo", &h).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/foo");
    }

    #[test]
    fn resolve_plain_http_target_rejects_bare_authority() {
        // No scheme, doesn't start with `/` — not something we can route.
        assert!(resolve_plain_http_target("example.com", &headers(&[])).is_none());
        assert!(resolve_plain_http_target("http://", &headers(&[])).is_none());
    }

    #[test]
    fn split_authority_handles_ports_and_ipv6() {
        assert_eq!(
            split_authority("example.com", 80),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            split_authority("example.com:8080", 80),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            split_authority("[::1]:8080", 80),
            ("[::1]".to_string(), 8080)
        );
        // Bare IPv6 without brackets — keep the whole string as the host
        // and use the default port instead of mis-splitting on a colon.
        assert_eq!(split_authority("::1", 80), ("::1".to_string(), 80));
    }

    #[test]
    fn socks5_udp_domain_packet_round_trips() {
        let mut raw = vec![0, 0, 0, 0x03, 11];
        raw.extend_from_slice(b"example.com");
        raw.extend_from_slice(&3478u16.to_be_bytes());
        raw.extend_from_slice(b"hello");

        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 3478);
        assert_eq!(payload, b"hello");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[test]
    fn socks5_udp_rejects_fragmented_packets() {
        let raw = [0, 0, 1, 0x01, 127, 0, 0, 1, 0x13, 0x8a, b'x'];
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_rejects_non_utf8_domain() {
        // Lone continuation byte (0x80) — not valid UTF-8. Lossy decode
        // would forward U+FFFD into DNS; strict parse should reject so
        // we fail fast instead of issuing a doomed lookup.
        let raw = [0, 0, 0, 0x03, 1, 0x80, 0, 80];
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_rejects_truncated_inputs() {
        // Header alone is not enough.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01]).is_none());
        // IPv4 with truncated address bytes (need 4 octets).
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01, 127, 0, 0]).is_none());
        // IPv4 with no port.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x01, 127, 0, 0, 1]).is_none());
        // DOMAIN with zero-length.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x03, 0, 0, 80]).is_none());
        // DOMAIN with length exceeding remaining buffer.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x03, 5, b'a', b'b']).is_none());
        // Unknown atyp.
        assert!(parse_socks5_udp_packet(&[0, 0, 0, 0x09, 1, 2, 3, 4]).is_none());
        // IPv6 with truncated address.
        let raw = [0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 11 bytes < 16
        assert!(parse_socks5_udp_packet(&raw).is_none());
    }

    #[test]
    fn socks5_udp_ipv4_round_trips() {
        let mut raw = vec![0, 0, 0, 0x01, 1, 2, 3, 4];
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.extend_from_slice(b"\x00\x01");

        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "1.2.3.4");
        assert_eq!(target.port, 53);
        assert_eq!(payload, b"\x00\x01");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
    }

    #[test]
    fn socks5_udp_ipv6_round_trips() {
        let mut raw = vec![0, 0, 0, 0x04];
        raw.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        raw.extend_from_slice(&443u16.to_be_bytes());
        raw.extend_from_slice(b"q");
        let (target, payload) = parse_socks5_udp_packet(&raw).unwrap();
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, 443);
        assert_eq!(payload, b"q");
        assert_eq!(build_socks5_udp_packet(&target, payload), raw);
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
        assert!(should_use_sni_rewrite(
            &hosts,
            "www.example.com",
            443,
            false
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.example.com",
            80,
            false
        ));
    }

    #[test]
    fn youtube_via_relay_routes_youtube_through_relay_path() {
        // Issue #102 + #275. When youtube_via_relay=true:
        //   - YouTube API + HTML hosts (where Restricted Mode lives)
        //     opt out of SNI rewrite so they go through the relay.
        //   - YouTube image / video / channel-asset CDNs STAY on SNI
        //     rewrite — Restricted Mode isn't enforced on those, and
        //     routing video chunks through Apps Script burns quota
        //     and risks the 6-min execution cap. Pre-#275 ytimg.com
        //     was incorrectly carved out alongside the API surfaces.
        //   - Non-YouTube Google suffixes are unaffected by the flag.
        let hosts = std::collections::HashMap::new();

        // Default behaviour (flag off): everything in the SNI pool
        // rewrites including all YouTube assets.
        assert!(should_use_sni_rewrite(&hosts, "www.youtube.com", 443, false));
        assert!(should_use_sni_rewrite(&hosts, "i.ytimg.com", 443, false));
        assert!(should_use_sni_rewrite(&hosts, "youtu.be", 443, false));
        assert!(should_use_sni_rewrite(&hosts, "www.google.com", 443, false));
        assert!(should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            false
        ));

        // googlevideo.com is INTENTIONALLY NOT in SNI_REWRITE_SUFFIXES
        // — see the long note at the top of the SNI list. v1.7.4 tried
        // adding it; reverted in v1.7.6 after user reports of total
        // YouTube breakage. If the project ever ships an EVA-edge-IP
        // config knob, this assertion can flip. Until then, video
        // chunks correctly fall through to the Apps Script relay path
        // and this assertion guards against a regression.
        assert!(!should_use_sni_rewrite(
            &hosts,
            "rr1---sn-abc.googlevideo.com",
            443,
            false
        ));

        // Flag on: only the API + HTML hosts opt out.
        assert!(!should_use_sni_rewrite(&hosts, "www.youtube.com", 443, true));
        assert!(!should_use_sni_rewrite(&hosts, "youtu.be", 443, true));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "www.youtube-nocookie.com",
            443,
            true
        ));
        assert!(!should_use_sni_rewrite(
            &hosts,
            "youtubei.googleapis.com",
            443,
            true
        ));

        // Flag on: image / channel-asset CDNs STAY on SNI rewrite. Pre-#275
        // ytimg.com was incorrectly carved out alongside the API surfaces.
        // googlevideo.com still goes through the relay path (not in the
        // SNI list at all — see note above the SNI_REWRITE_SUFFIXES
        // entries) so the same flag-on assertion isn't applicable to it.
        assert!(should_use_sni_rewrite(&hosts, "i.ytimg.com", 443, true));
        assert!(should_use_sni_rewrite(&hosts, "yt3.ggpht.com", 443, true));

        // Flag on: non-YouTube Google suffixes are unaffected. Note
        // youtubei.googleapis.com (above) is the *carve-out* — the
        // broader googleapis.com suffix is NOT carved out, so e.g.
        // Drive / Calendar / etc. continue to SNI-rewrite.
        assert!(should_use_sni_rewrite(&hosts, "www.google.com", 443, true));
        assert!(should_use_sni_rewrite(&hosts, "fonts.gstatic.com", 443, true));
        assert!(should_use_sni_rewrite(
            &hosts,
            "drive.googleapis.com",
            443,
            true
        ));
    }

    #[test]
    fn hosts_override_beats_youtube_via_relay() {
        // If the user added an explicit hosts override for a YouTube
        // subdomain, it should win — the override is a deliberate
        // user choice, the toggle is a default policy.
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("rr4.googlevideo.com".to_string(), "1.2.3.4".to_string());

        assert!(should_use_sni_rewrite(
            &hosts,
            "rr4.googlevideo.com",
            443,
            true
        ));
    }

    #[test]
    fn passthrough_hosts_exact_match() {
        let list = vec!["example.com".to_string(), "banking.local".to_string()];
        assert!(matches_passthrough("example.com", &list));
        assert!(matches_passthrough("banking.local", &list));
        assert!(matches_passthrough("EXAMPLE.COM", &list)); // case-insensitive
        assert!(!matches_passthrough("notexample.com", &list));
        assert!(!matches_passthrough("sub.example.com", &list)); // exact only, not suffix
    }

    #[test]
    fn passthrough_hosts_dot_prefix_is_suffix_match() {
        let list = vec![".internal.example".to_string()];
        assert!(matches_passthrough("internal.example", &list)); // bare parent matches
        assert!(matches_passthrough("a.internal.example", &list));
        assert!(matches_passthrough("a.b.c.internal.example", &list));
        assert!(!matches_passthrough("internal.exampleX", &list));
        assert!(!matches_passthrough("fakeinternal.example", &list));
    }

    #[test]
    fn passthrough_hosts_empty_list_never_matches() {
        let list: Vec<String> = vec![];
        assert!(!matches_passthrough("anything.com", &list));
        assert!(!matches_passthrough("", &list));
    }

    #[test]
    fn passthrough_hosts_ignores_empty_and_whitespace_entries() {
        let list = vec!["".to_string(), "   ".to_string(), "real.com".to_string()];
        assert!(!matches_passthrough("", &list));
        assert!(matches_passthrough("real.com", &list));
    }

    #[test]
    fn passthrough_hosts_trailing_dot_normalized() {
        // FQDNs sometimes have a trailing dot; both entry-side and host-side
        // trailing dots should be treated as equivalent to the un-dotted form.
        let list = vec!["example.com.".to_string()];
        assert!(matches_passthrough("example.com", &list));
        assert!(matches_passthrough("example.com.", &list));
    }

    #[test]
    fn doh_default_list_exact_matches() {
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("chrome.cloudflare-dns.com", &extra));
        assert!(matches_doh_host("dns.google", &extra));
        assert!(matches_doh_host("dns.quad9.net", &extra));
        assert!(matches_doh_host("doh.opendns.com", &extra));
    }

    #[test]
    fn doh_default_list_case_insensitive_and_trailing_dot() {
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("DNS.GOOGLE", &extra));
        assert!(matches_doh_host("dns.google.", &extra));
    }

    #[test]
    fn doh_default_list_suffix_match_for_tenant_subdomains() {
        // `cloudflare-dns.com` is in the default list — Workers-hosted
        // tenant DoH endpoints sit under it and should match too.
        let extra: Vec<String> = vec![];
        assert!(matches_doh_host("tenant.cloudflare-dns.com", &extra));
        // But a substring match must NOT pass: `xcloudflare-dns.com` is
        // a different domain.
        assert!(!matches_doh_host("xcloudflare-dns.com", &extra));
    }

    #[test]
    fn doh_default_list_unrelated_hosts_do_not_match() {
        let extra: Vec<String> = vec![];
        assert!(!matches_doh_host("example.com", &extra));
        assert!(!matches_doh_host("googlevideo.com", &extra));
        assert!(!matches_doh_host("", &extra));
    }

    #[test]
    fn doh_extra_list_extends_default() {
        let extra = vec![".internal-doh.example".to_string(), "doh.acme.test".to_string()];
        // Defaults still match.
        assert!(matches_doh_host("dns.google", &extra));
        // User additions match.
        assert!(matches_doh_host("doh.acme.test", &extra));
        assert!(matches_doh_host("a.b.internal-doh.example", &extra));
        // Unrelated still doesn't match.
        assert!(!matches_doh_host("example.com", &extra));
    }

    #[test]
    fn doh_extra_entries_match_subdomains_without_leading_dot() {
        // Asymmetry footgun guard: user adds `doh.acme.test` and expects
        // `tenant.doh.acme.test` to match too — same as `dns.google`
        // matching `tenant.dns.google` from the default list. Unlike
        // `passthrough_hosts`, DoH extras don't require a leading dot.
        let extra = vec!["doh.acme.test".to_string()];
        assert!(matches_doh_host("doh.acme.test", &extra));
        assert!(matches_doh_host("tenant.doh.acme.test", &extra));
        // But substring overlap must still be rejected.
        assert!(!matches_doh_host("xdoh.acme.test", &extra));
    }
}
