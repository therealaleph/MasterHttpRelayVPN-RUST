//! JNI entry points for the Android app.
//!
//! The app (Kotlin) calls `Native.setDataDir()` once, then `Native.startProxy()`
//! with the full config.json payload and gets back a handle (u64). Later the
//! app calls `stopProxy(handle)` to stop, `statsJson(handle)` to poll, or
//! `exportCa(dest)` to copy the MITM CA cert to a path the app can hand to
//! Android's system "install certificate" dialog.
//!
//! The proxy runs on an internal tokio runtime that we own (1 worker thread
//! minimum) — we don't piggyback on the JVM thread that calls in.
//!
//! SAFETY: every `extern "system"` entry point catches panics so they never
//! unwind across the JNI boundary (UB otherwise).

#![cfg(target_os = "android")]

use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use tokio::runtime::Runtime;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use crate::config::Config;
use crate::mitm::{MitmCertManager, CA_CERT_FILE};
use crate::proxy_server::ProxyServer;

/// Running-proxy record. The JNI handle is the index into a slot map we
/// keep in a lazy-initialized global — we can't round-trip a Rust pointer
/// through `jlong` safely if the JVM compacts, but we can hand out an
/// integer key.
struct Running {
    /// Dropping this sends the shutdown signal. Optional so we can `take()`
    /// it in stop().
    shutdown: Option<oneshot::Sender<()>>,
    /// Own the runtime so it outlives the server. Dropped last.
    rt: Option<Runtime>,
}

static HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn slot_map() -> &'static Mutex<std::collections::HashMap<u64, Running>> {
    static SLOTS: OnceLock<Mutex<std::collections::HashMap<u64, Running>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

// ---------------------------------------------------------------------------
// Logging bridge.
//
// We fan each tracing event out two ways:
//   1. `__android_log_write` — lands in `adb logcat` under tag `mhrv_rs`.
//   2. An in-memory ring buffer the Kotlin UI drains via `Native.drainLogs()`.
// The first path was enough to get past "startProxy returned 0 — silent
// failure"; the second path gives the user a live log panel without making
// them attach a debugger.
// ---------------------------------------------------------------------------

extern "C" {
    fn __android_log_write(prio: i32, tag: *const std::os::raw::c_char, text: *const std::os::raw::c_char) -> i32;
}

const ANDROID_LOG_INFO: i32 = 4;
const LOG_RING_CAP: usize = 500;

fn log_ring() -> &'static Mutex<VecDeque<String>> {
    static RING: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(LOG_RING_CAP)))
}

/// MakeWriter that forwards each write to `__android_log_write` AND to the
/// in-memory ring buffer. One line per write call; we trim the trailing
/// newline that tracing-subscriber appends so logcat doesn't show blank
/// rows between every event.
struct LogcatWriter;

impl std::io::Write for LogcatWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Skip empty writes — tracing occasionally flushes a bare "\n".
        if buf.is_empty() { return Ok(0); }
        let trimmed = if buf.ends_with(b"\n") { &buf[..buf.len() - 1] } else { buf };

        // logcat side.
        let mut cstr = Vec::with_capacity(trimmed.len() + 1);
        cstr.extend_from_slice(trimmed);
        cstr.push(0);
        static TAG: &[u8] = b"mhrv_rs\0";
        unsafe {
            __android_log_write(
                ANDROID_LOG_INFO,
                TAG.as_ptr() as *const std::os::raw::c_char,
                cstr.as_ptr() as *const std::os::raw::c_char,
            );
        }

        // ring-buffer side. Best-effort UTF-8; if there are invalid bytes
        // we'd rather show replacement chars than drop the line entirely.
        if let Ok(mut g) = log_ring().lock() {
            if g.len() >= LOG_RING_CAP {
                g.pop_front();
            }
            let line = String::from_utf8_lossy(trimmed).into_owned();
            g.push_back(line);
        }

        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogcatWriter {
    type Writer = LogcatWriter;
    fn make_writer(&'a self) -> Self::Writer { LogcatWriter }
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
            .with_writer(LogcatWriter)
            .try_init();

        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Helper: JString -> String, defaulting to "" on any failure.
fn jstring_to_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s)
        .map(|j| j.into())
        .unwrap_or_else(|_| String::new())
}

fn safe<F: FnOnce() -> R + std::panic::UnwindSafe, R>(default: R, f: F) -> R {
    std::panic::catch_unwind(f).unwrap_or(default)
}

/// Build a throwaway tokio runtime for one-shot blocking calls from JNI.
/// Small, single-worker — sufficient for probes and cert ops.
fn one_shot_runtime() -> Option<Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
}

/// `Native.setDataDir(String)` — must be called once, before `startProxy`.
/// The Kotlin side passes `context.filesDir.absolutePath`.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_setDataDir(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) {
    let _ = safe((), AssertUnwindSafe(|| {
        install_logging_once();
        let p = jstring_to_string(&mut env, &path);
        if !p.is_empty() {
            crate::data_dir::set_data_dir(PathBuf::from(p));
        }
    }));
}

/// `Native.startProxy(String configJson)` -> `long` handle (0 on failure).
/// The config is parsed and validated; on success the proxy server is
/// spawned on its own tokio runtime and a non-zero handle returned.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_startProxy(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jlong {
    safe(0i64, AssertUnwindSafe(|| {
        install_logging_once();

        let json = jstring_to_string(&mut env, &config_json);
        let config: Config = match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("android: invalid config json: {}", e);
                return 0i64;
            }
        };

        // Try to build the runtime first — if allocation fails we want to
        // know before spinning up anything stateful.
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("mhrv-worker")
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("android: tokio runtime build failed: {}", e);
                return 0i64;
            }
        };

        let base = crate::data_dir::data_dir();
        let mitm = match MitmCertManager::new_in(&base) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("android: MITM CA init failed: {}", e);
                return 0i64;
            }
        };
        let mitm = Arc::new(AsyncMutex::new(mitm));

        let server = match ProxyServer::new(&config, mitm) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("android: ProxyServer::new failed: {}", e);
                return 0i64;
            }
        };

        let (tx, rx) = oneshot::channel::<()>();

        rt.spawn(async move {
            if let Err(e) = server.run(rx).await {
                tracing::error!("android: proxy server exited: {}", e);
            }
        });

        let handle = HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed);
        slot_map().lock().unwrap().insert(
            handle,
            Running {
                shutdown: Some(tx),
                rt: Some(rt),
            },
        );
        handle as jlong
    }))
}

/// `Native.stopProxy(long handle)` -> boolean. Idempotent: calling on an
/// unknown handle returns false quietly.
///
/// Uses `Runtime::shutdown_timeout` instead of letting `drop(rt)` block
/// synchronously. `drop(rt)` waits forever for tokio tasks to finish, and
/// if ANY task is stuck (in-flight TLS handshake, retrying HTTP request,
/// blocked read) the whole thing deadlocks — which is exactly what caused
/// the reported "Stop doesn't disconnect; subsequent Start fails with
/// Address already in use" bug. 3s is enough for a cooperative server to
/// unwind; anything slower, we force-kill (the listener socket is released
/// as part of the forced shutdown).
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_stopProxy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    safe(JNI_FALSE, AssertUnwindSafe(|| {
        let mut map = slot_map().lock().unwrap();
        let Some(mut running) = map.remove(&(handle as u64)) else {
            return JNI_FALSE;
        };
        if let Some(tx) = running.shutdown.take() {
            let _ = tx.send(());
        }
        // Release the map lock BEFORE shutting the runtime down so concurrent
        // JNI callers (stats queries, etc.) don't stall behind us.
        drop(map);
        if let Some(rt) = running.rt.take() {
            tracing::info!("android: stopProxy handle={} — shutting runtime down", handle);
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
            tracing::info!("android: stopProxy handle={} — runtime shutdown complete", handle);
        }
        JNI_TRUE
    }))
}

/// `Native.exportCa(String destPath)` -> boolean. Writes the MITM CA's
/// public cert to the given path. Init-safe: creates the CA on first call
/// if it doesn't exist yet.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_exportCa(
    mut env: JNIEnv,
    _class: JClass,
    dest: JString,
) -> jboolean {
    safe(JNI_FALSE, AssertUnwindSafe(|| {
        install_logging_once();
        let dest_path = jstring_to_string(&mut env, &dest);
        if dest_path.is_empty() {
            return JNI_FALSE;
        }
        let base = crate::data_dir::data_dir();
        if MitmCertManager::new_in(&base).is_err() {
            return JNI_FALSE;
        }
        let src = base.join(CA_CERT_FILE);
        match std::fs::copy(&src, &dest_path) {
            Ok(_) => JNI_TRUE,
            Err(e) => {
                tracing::error!("android: CA export to {} failed: {}", dest_path, e);
                JNI_FALSE
            }
        }
    }))
}

/// `Native.version()` -> String. Trivial smoke test for the JNI linkage.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_version<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
) -> jstring {
    let v = env!("CARGO_PKG_VERSION");
    env.new_string(v).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// `Native.drainLogs()` -> String. Returns the full ring buffer as a single
/// `\n`-joined blob, then clears it. We return one String rather than an
/// array because it's one JNI call vs. N — the Kotlin side splits on `\n`
/// for display. Empty string when there's nothing to read.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_drainLogs<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
) -> jstring {
    let out = safe(String::new(), AssertUnwindSafe(|| {
        let mut g = match log_ring().lock() {
            Ok(g) => g,
            Err(_) => return String::new(),
        };
        let lines: Vec<String> = g.drain(..).collect();
        lines.join("\n")
    }));
    env.new_string(out).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// `Native.checkUpdate()` -> String. Runs the same `update_check::check`
/// the desktop UI uses, serializes the outcome as JSON so Kotlin can
/// pattern-match without needing its own GitHub client.
///
/// Returned shape, one of:
///   {"kind":"upToDate","current":"1.0.0","latest":"1.0.0"}
///   {"kind":"updateAvailable","current":"1.0.0","latest":"1.1.0","url":"https://..."}
///   {"kind":"offline","reason":"..."}
///   {"kind":"error","reason":"..."}
///
/// Blocking — hit from a background dispatcher.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_checkUpdate<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
) -> jstring {
    let result_json = safe(
        r#"{"kind":"error","reason":"panic"}"#.to_string(),
        AssertUnwindSafe(|| {
            install_logging_once();
            let Some(rt) = one_shot_runtime() else {
                return r#"{"kind":"error","reason":"tokio init failed"}"#.to_string();
            };
            let outcome = rt.block_on(crate::update_check::check(
                crate::update_check::Route::Direct,
            ));
            update_check_to_json(&outcome)
        }),
    );
    env.new_string(result_json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn update_check_to_json(u: &crate::update_check::UpdateCheck) -> String {
    // Hand-serialized to keep the JNI side free of serde derive noise on
    // the inner enum (which would need `#[derive(Serialize)]`). Short
    // enough that the hand-rolled version is simpler than pulling
    // serde_json in here for one call.
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    match u {
        crate::update_check::UpdateCheck::UpToDate { current, latest } => format!(
            r#"{{"kind":"upToDate","current":"{}","latest":"{}"}}"#,
            esc(current), esc(latest),
        ),
        crate::update_check::UpdateCheck::UpdateAvailable { current, latest, release_url, .. } => format!(
            r#"{{"kind":"updateAvailable","current":"{}","latest":"{}","url":"{}"}}"#,
            esc(current), esc(latest), esc(release_url),
        ),
        crate::update_check::UpdateCheck::Offline(reason) => format!(
            r#"{{"kind":"offline","reason":"{}"}}"#,
            esc(reason),
        ),
        crate::update_check::UpdateCheck::Error(reason) => format!(
            r#"{{"kind":"error","reason":"{}"}}"#,
            esc(reason),
        ),
    }
}

/// `Native.testSni(googleIp, sni)` -> String. Returns a small JSON blob
/// like `{"ok":true,"latencyMs":123}` or `{"ok":false,"error":"..."}`.
/// Blocking call — Kotlin side should invoke on a background coroutine.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_testSni<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    google_ip: JString,
    sni: JString,
) -> jstring {
    let result_json = safe(r#"{"ok":false,"error":"panic"}"#.to_string(), AssertUnwindSafe(|| {
        install_logging_once();
        let ip = jstring_to_string(&mut env, &google_ip);
        let s = jstring_to_string(&mut env, &sni);
        if ip.is_empty() || s.is_empty() {
            return r#"{"ok":false,"error":"empty google_ip or sni"}"#.to_string();
        }
        let Some(rt) = one_shot_runtime() else {
            return r#"{"ok":false,"error":"tokio init failed"}"#.to_string();
        };
        let probe = rt.block_on(crate::scan_sni::probe_one(&ip, &s));
        match (probe.latency_ms, probe.error) {
            (Some(ms), _) => {
                tracing::info!("sni_probe: {} via {} ok in {}ms", s, ip, ms);
                format!(r#"{{"ok":true,"latencyMs":{}}}"#, ms)
            }
            (None, Some(e)) => {
                // Surface the reason in logcat too — otherwise users see a
                // red dot in the UI with no path to diagnose. Common causes:
                //   - "dns: ..."   -> system resolver can't reach DNS
                //   - "connect: ..." -> TCP to google_ip:443 blocked
                //   - "handshake: ..." -> TLS fail (cert, ALPN, etc.)
                tracing::warn!("sni_probe: {} via {} FAIL: {}", s, ip, e);
                let cleaned = e.replace('\\', "\\\\").replace('"', "\\\"");
                format!(r#"{{"ok":false,"error":"{}"}}"#, cleaned)
            }
            _ => r#"{"ok":false,"error":"unknown"}"#.to_string(),
        }
    }));
    env.new_string(result_json).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}
