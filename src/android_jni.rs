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
    /// Keep an Arc to the DomainFronter so `statsJson(handle)` can read the
    /// live stats without going through the async server. `None` for
    /// direct / full-only configs where the fronter isn't used.
    fronter: Option<Arc<crate::domain_fronter::DomainFronter>>,
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

        // Grab the fronter Arc BEFORE we move `server` into the async task —
        // so `statsJson(handle)` can read counters without cross-task plumbing.
        let fronter = server.fronter();

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
                fronter,
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
///   {"kind":"updateAvailable","current":"1.0.0","latest":"1.1.0","url":"https://...",
///    "assetName":"mhrv-rs-android-arm64-v8a-v1.1.0.apk",
///    "assetUrl":"https://...","assetSize":12345678}
///   {"kind":"offline","reason":"..."}
///   {"kind":"error","reason":"..."}
///
/// `assetName/Url/Size` are only present on `updateAvailable` and only when
/// the picker matched a per-ABI APK in the release. The Kotlin updater
/// uses these fields to fetch the right APK and hand it to PackageInstaller.
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
        crate::update_check::UpdateCheck::UpdateAvailable { current, latest, release_url, asset } => {
            let asset_fields = match asset {
                Some(a) => format!(
                    r#","assetName":"{}","assetUrl":"{}","assetSize":{}"#,
                    esc(&a.name), esc(&a.download_url), a.size_bytes,
                ),
                None => String::new(),
            };
            format!(
                r#"{{"kind":"updateAvailable","current":"{}","latest":"{}","url":"{}"{}}}"#,
                esc(current), esc(latest), esc(release_url), asset_fields,
            )
        }
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

/// `Native.downloadAsset(url, destPath)` -> String. Downloads a release
/// asset to `destPath` using the same rustls + redirect-following client
/// the desktop UI uses (so we go through CA-pinned TLS, no Java/OkHttp
/// dependency on the Kotlin side). When this build embeds
/// `MHRV_UPDATE_PUBKEY`, also downloads `<url>.minisig` and verifies the
/// asset before returning success. BLOCKS — call from IO dispatcher.
///
/// Returns a JSON blob:
///   {"ok":true,"bytes":12345678}
///   {"ok":false,"error":"..."}
///
/// Always uses Route::Direct on Android — the proxy-route trick that
/// helps shared-NAT desktop users isn't needed here (Android users
/// generally have working clear-net to GitHub for the asset CDN, which
/// `objects.githubusercontent.com` redirects to). Can be revisited if
/// users on Iranian networks report the asset host blocked.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_downloadAsset<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    url: JString,
    dest: JString,
) -> jstring {
    let result_json = safe(
        r#"{"ok":false,"error":"panic"}"#.to_string(),
        AssertUnwindSafe(|| {
            install_logging_once();
            let url_s = jstring_to_string(&mut env, &url);
            let dest_s = jstring_to_string(&mut env, &dest);
            if url_s.is_empty() || dest_s.is_empty() {
                return r#"{"ok":false,"error":"empty url or dest"}"#.to_string();
            }
            let Some(rt) = one_shot_runtime() else {
                return r#"{"ok":false,"error":"tokio init failed"}"#.to_string();
            };
            let dest_path = std::path::PathBuf::from(&dest_s);
            let res = rt.block_on(async {
                let bytes = crate::update_check::download_asset(
                    crate::update_check::Route::Direct,
                    &url_s,
                    &dest_path,
                )
                .await?;

                if let Some(pubkey) = crate::update_apply::embedded_update_pubkey() {
                    let sig_url = crate::update_apply::signature_url_for_asset(&url_s);
                    let sig_path = {
                        let Some(file_name) = dest_path.file_name() else {
                            return Err("dest path has no filename".to_string());
                        };
                        let mut sig_name = file_name.to_os_string();
                        sig_name.push(".minisig");
                        dest_path.with_file_name(sig_name)
                    };
                    crate::update_check::download_asset(
                        crate::update_check::Route::Direct,
                        &sig_url,
                        &sig_path,
                    )
                    .await
                    .map_err(|e| format!("signature missing: {}", e))?;
                    let sig_text = tokio::fs::read_to_string(&sig_path)
                        .await
                        .map_err(|e| format!("read signature: {}", e))?;
                    crate::update_apply::verify_minisign_signature(
                        pubkey,
                        &dest_path,
                        &sig_text,
                    )
                    .map_err(|e| format!("signature invalid: {}", e))?;
                    let _ = tokio::fs::remove_file(&sig_path).await;
                    tracing::info!("android: minisign signature verified for {}", dest_s);
                } else {
                    tracing::warn!(
                        "android: MHRV_UPDATE_PUBKEY was not set at build time — \
                         installing update without minisign check (rollout mode)."
                    );
                }

                Ok::<u64, String>(bytes)
            });
            match res {
                Ok(bytes) => {
                    tracing::info!("android: downloadAsset {} -> {} ({} bytes)", url_s, dest_s, bytes);
                    format!(r#"{{"ok":true,"bytes":{}}}"#, bytes)
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&dest_path);
                    tracing::warn!("android: downloadAsset failed: {}", e);
                    let cleaned = e.replace('\\', "\\\\").replace('"', "\\\"");
                    format!(r#"{{"ok":false,"error":"{}"}}"#, cleaned)
                }
            }
        }),
    );
    env.new_string(result_json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
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

/// `Native.statsJson(long handle)` -> String. Returns a JSON blob with the
/// live `StatsSnapshot` for a running proxy, or an empty string if the
/// handle is unknown or the proxy has no fronter (direct / full modes).
///
/// Cheap — just reads a handful of atomics. The Kotlin UI polls this on a
/// timer to render the "Usage today (estimated)" card.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_statsJson<'a>(
    env: JNIEnv<'a>,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let out = safe(String::new(), AssertUnwindSafe(|| {
        let map = match slot_map().lock() {
            Ok(g) => g,
            Err(_) => return String::new(),
        };
        let Some(running) = map.get(&(handle as u64)) else {
            return String::new();
        };
        let Some(f) = running.fronter.as_ref() else {
            return String::new();
        };
        f.snapshot_stats().to_json()
    }));
    env.new_string(out).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

// ---------------------------------------------------------------------------
// tun2proxy CLI API wrapper (dlsym — no fork or patch needed)
// ---------------------------------------------------------------------------

/// `Native.runTun2proxy(cliArgs, tunMtu)` -> int
///
/// Calls `tun2proxy_run_with_cli_args` from libtun2proxy.so via dlsym.
/// This is the C API the tun2proxy maintainer recommends for callers that
/// need full CLI flexibility (e.g. --udpgw-server). BLOCKS until shutdown.
#[no_mangle]
pub extern "system" fn Java_com_therealaleph_mhrv_Native_runTun2proxy<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass,
    cli_args: JString,
    tun_mtu: jni::sys::jint,
) -> jni::sys::jint {
    safe(-1, AssertUnwindSafe(|| {
        let args_str = jstring_to_string(&mut env, &cli_args);
        tracing::info!("runTun2proxy: cli={}", args_str);

        unsafe {
            use std::ffi::{CStr, CString};

            let lib = CString::new("libtun2proxy.so").unwrap();
            let handle = libc::dlopen(lib.as_ptr(), libc::RTLD_NOW);
            if handle.is_null() {
                let err = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlopen libtun2proxy.so failed: {:?}", err);
                return -10;
            }

            let sym = CString::new("tun2proxy_run_with_cli_args").unwrap();
            let func = libc::dlsym(handle, sym.as_ptr());
            if func.is_null() {
                let err = CStr::from_ptr(libc::dlerror());
                tracing::error!("dlsym tun2proxy_run_with_cli_args: {:?}", err);
                libc::dlclose(handle);
                return -11;
            }

            type RunFn = unsafe extern "C" fn(*const std::ffi::c_char, u16, bool) -> i32;
            let run: RunFn = std::mem::transmute(func);
            let c_args = CString::new(args_str).unwrap();
            let rc = run(c_args.as_ptr(), tun_mtu as u16, false);
            libc::dlclose(handle);
            rc
        }
    }))
}
