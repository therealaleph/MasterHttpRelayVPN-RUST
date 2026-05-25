//! C FFI entry points for the iOS Network Extension.
//!
//! Swift (NEPacketTunnelProvider) calls:
//!   mhrv_set_data_dir  — once, before start, with the App Group container path
//!   mhrv_start         — starts mhrv-rs SOCKS5 proxy + leaf TUN/FakeIP bridge
//!   mhrv_stop          — gracefully shuts both down
//!   mhrv_drain_logs    — drains the in-memory log ring (caller must free)
//!   mhrv_free_string   — frees a string returned by drain_logs
//!   mhrv_version       — static version string (no free needed)
//!
//! SAFETY: every entry point catches panics so they never unwind across the
//! C boundary. All pointer arguments are null-checked before use.

#![cfg(target_os = "ios")]

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{oneshot, Mutex as AsyncMutex};

use crate::config::{Config, TomlConfig};
use crate::mitm::{MitmCertManager, CA_CERT_FILE};
use crate::proxy_server::ProxyServer;

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

struct IosSession {
    proxy_shutdown: Option<oneshot::Sender<()>>,
    proxy_rt: Option<tokio::runtime::Runtime>,
    leaf_rt_id: u16,
    fronter: Option<Arc<crate::domain_fronter::DomainFronter>>,
}

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);
static LEAF_RT_COUNTER: AtomicU16 = AtomicU16::new(1);

fn session_map() -> &'static Mutex<std::collections::HashMap<u64, IosSession>> {
    static MAP: OnceLock<Mutex<std::collections::HashMap<u64, IosSession>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

// ---------------------------------------------------------------------------
// Logging — stderr (shows in Xcode console / idevicesyslog) + ring buffer
// ---------------------------------------------------------------------------

const LOG_RING_CAP: usize = 500;

fn log_ring() -> &'static Mutex<VecDeque<String>> {
    static RING: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(LOG_RING_CAP)))
}

struct StderrRingWriter;

impl std::io::Write for StderrRingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let trimmed = if buf.ends_with(b"\n") { &buf[..buf.len() - 1] } else { buf };
        let _ = std::io::stderr().write_all(trimmed);
        let _ = std::io::stderr().write_all(b"\n");
        if let Ok(mut g) = log_ring().lock() {
            if g.len() >= LOG_RING_CAP {
                g.pop_front();
            }
            g.push_back(String::from_utf8_lossy(trimmed).into_owned());
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for StderrRingWriter {
    type Writer = StderrRingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        StderrRingWriter
    }
}

fn install_logging_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(StderrRingWriter)
            .try_init();
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Log panic message + source location into the ring buffer. catch_unwind
        // swallows the payload, so without this hook a leaf panic is invisible.
        std::panic::set_hook(Box::new(|info| {
            let loc = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "?".into());
            let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            tracing::error!("PANIC at {}: {}", loc, msg);
        }));
    });
}

fn safe<F: FnOnce() -> R + std::panic::UnwindSafe, R>(default: R, f: F) -> R {
    std::panic::catch_unwind(f).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

/// Set the data directory for cert storage. Must be called before mhrv_start.
/// Pass the App Group container path so the extension and host app share certs.
#[no_mangle]
pub extern "C" fn mhrv_set_data_dir(path: *const c_char) {
    let _ = safe((), AssertUnwindSafe(|| {
        install_logging_once();
        if path.is_null() {
            return;
        }
        let s = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
        if !s.is_empty() {
            crate::data_dir::set_data_dir(std::path::PathBuf::from(s));
        }
    }));
}

/// Start the VPN: mhrv-rs SOCKS5 proxy + leaf TUN/FakeIP bridge.
///
/// config_json: mhrv-rs config (JSON or TOML). listen_host MUST be "127.0.0.1"
///              so the SOCKS5 listener is loopback-only on the device.
/// tun_fd:      file descriptor of the utun device, obtained by the Swift side
///              via `packetFlow.value(forKeyPath: "socket.fileDescriptor")`.
///
/// Returns a nonzero session handle on success, 0 on failure.
/// The handle is passed to mhrv_stop later.
#[no_mangle]
pub extern "C" fn mhrv_start(config_json: *const c_char, tun_fd: i32) -> u64 {
    safe(0u64, AssertUnwindSafe(|| {
        install_logging_once();

        if config_json.is_null() || tun_fd < 0 {
            tracing::error!("ios: mhrv_start called with null config or invalid fd");
            return 0;
        }

        // dup() so leaf owns an independent fd; original stays valid for packetFlow.
        let tun_fd = unsafe { libc::dup(tun_fd) };
        if tun_fd < 0 {
            tracing::error!("ios: dup(tun_fd) failed: {}", std::io::Error::last_os_error());
            return 0;
        }
        tracing::info!("ios: tun_fd duped to {}", tun_fd);

        let raw = unsafe { CStr::from_ptr(config_json) }.to_string_lossy().into_owned();

        // Parse the mhrv-rs config, forcing loopback listen for security.
        let mut config: Config = match serde_json::from_str::<Config>(&raw) {
            Ok(c) => c,
            Err(_) => match toml::from_str::<TomlConfig>(&raw) {
                Ok(tc) => Config::from(tc),
                Err(e) => {
                    tracing::error!("ios: invalid config: {}", e);
                    return 0;
                }
            },
        };

        // Force loopback — the extension must not expose SOCKS5 to the LAN.
        config.listen_host = "127.0.0.1".into();

        let socks_port = config.socks5_port.unwrap_or(config.listen_port + 1);

        // Build the tokio runtime for mhrv-rs. 2 workers — the extension has
        // a tight memory budget; more threads don't help on a loopback-only proxy.
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("mhrv-ios")
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("ios: tokio build failed: {}", e);
                return 0;
            }
        };

        let base = crate::data_dir::data_dir();
        let mitm = match MitmCertManager::new_in(&base) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("ios: MITM CA init: {}", e);
                return 0;
            }
        };
        let mitm = Arc::new(AsyncMutex::new(mitm));

        let server = match ProxyServer::new(&config, mitm) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("ios: ProxyServer::new: {}", e);
                return 0;
            }
        };
        let fronter = server.fronter();
        let (tx, rx) = oneshot::channel::<()>();

        rt.spawn(async move {
            if let Err(e) = server.run(rx).await {
                tracing::error!("ios: proxy server exited: {}", e);
            }
        });

        // Give the proxy a moment to bind before leaf starts sending traffic.
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Start leaf on its own thread (leaf::start blocks until shutdown).
        let leaf_rt_id = LEAF_RT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let leaf_config = build_leaf_config(tun_fd, socks_port);

        // Flush current log ring to a file so they survive if the extension crashes.
        let crash_log_path = crate::data_dir::data_dir().join("mhrv_pre_leaf.log");
        if let Ok(mut g) = log_ring().lock() {
            let content = g.iter().cloned().collect::<Vec<_>>().join("\n");
            let _ = std::fs::write(&crash_log_path, &content);
        }

        std::thread::Builder::new()
            .name("leaf-tun".to_string())
            .spawn(move || {
                tracing::info!("ios: leaf starting rt_id={} tun_fd={} socks={}", leaf_rt_id, tun_fd, socks_port);

                // catch_unwind requires panic=unwind (release-ios profile).
                // Without it, a leaf panic would abort the entire extension process.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let opts = leaf::StartOptions {
                        config: leaf::Config::Str(leaf_config),
                        runtime_opt: leaf::RuntimeOption::SingleThread,
                    };
                    leaf::start(leaf_rt_id, opts)
                }));
                match result {
                    Ok(Ok(())) => tracing::info!("ios: leaf rt_id={} stopped cleanly", leaf_rt_id),
                    Ok(Err(e)) => tracing::error!("ios: leaf rt_id={} error: {:?}", leaf_rt_id, e),
                    Err(_)     => tracing::error!("ios: leaf rt_id={} PANICKED — caught by catch_unwind", leaf_rt_id),
                }
                // After leaf exits for any reason, close the duped fd.
                unsafe { libc::close(tun_fd); }
            })
            .ok();

        let session_id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        session_map().lock().unwrap().insert(session_id, IosSession {
            proxy_shutdown: Some(tx),
            proxy_rt: Some(rt),
            leaf_rt_id,
            fronter,
        });

        tracing::info!("ios: session {} started (leaf rt_id={})", session_id, leaf_rt_id);
        session_id
    }))
}

/// Stop a session previously returned by mhrv_start.
/// Idempotent: calling with an unknown handle returns false silently.
#[no_mangle]
pub extern "C" fn mhrv_stop(session_id: u64) -> bool {
    safe(false, AssertUnwindSafe(|| {
        let mut map = session_map().lock().unwrap();
        let Some(mut sess) = map.remove(&session_id) else {
            return false;
        };

        // Signal leaf to stop first — it drains in-flight connections before exit.
        let leaf_rt_id = sess.leaf_rt_id;
        leaf::shutdown(leaf_rt_id);
        tracing::info!("ios: leaf rt_id={} shutdown signalled", leaf_rt_id);

        // Signal mhrv-rs proxy.
        if let Some(tx) = sess.proxy_shutdown.take() {
            let _ = tx.send(());
        }

        drop(map); // release lock before blocking shutdown

        if let Some(rt) = sess.proxy_rt.take() {
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
        }

        tracing::info!("ios: session {} stopped", session_id);
        true
    }))
}

/// Drain the in-memory log ring as a single '\n'-joined string.
/// CALLER MUST FREE the returned pointer with mhrv_free_string.
/// Returns a valid (possibly empty) C string — never null.
#[no_mangle]
pub extern "C" fn mhrv_drain_logs() -> *mut c_char {
    let out = safe(String::new(), AssertUnwindSafe(|| {
        let mut g = log_ring().lock().unwrap_or_else(|e| e.into_inner());
        let lines: Vec<String> = g.drain(..).collect();
        lines.join("\n")
    }));
    CString::new(out).unwrap_or_default().into_raw()
}

/// Free a string returned by mhrv_drain_logs.
#[no_mangle]
pub extern "C" fn mhrv_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}

/// Return the crate version string. Pointer is static — do NOT free.
#[no_mangle]
pub extern "C" fn mhrv_version() -> *const c_char {
    static V: OnceLock<CString> = OnceLock::new();
    V.get_or_init(|| CString::new(env!("CARGO_PKG_VERSION")).unwrap()).as_ptr()
}

/// Export the MITM CA certificate to dest_path so the user can install it.
/// Returns true on success.
#[no_mangle]
pub extern "C" fn mhrv_export_ca(dest_path: *const c_char) -> bool {
    safe(false, AssertUnwindSafe(|| {
        if dest_path.is_null() { return false; }
        let dest = unsafe { CStr::from_ptr(dest_path) }.to_string_lossy().into_owned();
        if dest.is_empty() { return false; }
        let base = crate::data_dir::data_dir();
        if MitmCertManager::new_in(&base).is_err() { return false; }
        let src = base.join(CA_CERT_FILE);
        std::fs::copy(&src, &dest).is_ok()
    }))
}

// ---------------------------------------------------------------------------
// Leaf config builder
// ---------------------------------------------------------------------------

/// Build the leaf JSON config for full-tunnel mode:
///   - TUN inbound on tun_fd with FakeIP DNS (198.18.0.0/15 range)
///   - SOCKS5 outbound → mhrv-rs proxy on 127.0.0.1:socks_port
///   - Loopback and private ranges bypass SOCKS5 (direct)
///   - Everything else → proxy
fn build_leaf_config(tun_fd: i32, socks_port: u16) -> String {
    // leaf's own logger does `tracing_subscriber::registry()...init()`, which
    // PANICS if a global default subscriber already exists — and we install one
    // in install_logging_once. Level "none" makes leaf's setup_logger return
    // early before that .init() call, avoiding the panic. As a bonus, leaf then
    // never installs its own subscriber, so leaf's tracing events fall through
    // to our global subscriber and show up in the log ring / app panel.
    let leaf_level = "none";
    // 198.18.0.0/15 is IANA-reserved for benchmarking — safe as FakeIP range.
    // Leaf assigns IPs from this pool for intercepted DNS queries and maps them
    // back to hostnames when the TUN connection arrives, giving mhrv-rs the
    // original domain name for domain-fronting decisions.
    format!(
        r#"{{
  "log": {{ "level": "{leaf_level}" }},
  "dns": {{
    "servers": ["1.1.1.1", "8.8.8.8"],
    "hosts": {{ "localhost": ["127.0.0.1"] }}
  }},
  "inbounds": [{{
    "tag": "tun",
    "protocol": "tun",
    "settings": {{
      "fd": {tun_fd},
      "mtu": 1500,
      "fakeDnsExclude": [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fe80::/10"
      ]
    }}
  }}],
  "outbounds": [
    {{
      "tag": "proxy",
      "protocol": "socks",
      "settings": {{
        "address": "127.0.0.1",
        "port": {socks_port}
      }}
    }},
    {{
      "tag": "direct",
      "protocol": "direct"
    }}
  ],
  "router": {{
    "rules": [
      {{
        "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"],
        "target": "direct"
      }},
      {{ "target": "proxy" }}
    ]
  }}
}}"#
    )
}
