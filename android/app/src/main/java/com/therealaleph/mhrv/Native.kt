package com.therealaleph.mhrv

/**
 * JNI bindings for the mhrv_rs Rust crate. The crate is compiled to
 * libmhrv_rs.so and loaded at app start.
 *
 * All methods are blocking on a short-lived native call — the proxy itself
 * runs on a Rust-side tokio runtime, not on the JVM thread that calls in.
 * The returned handles are opaque to Kotlin; pass them back to stop() /
 * statsJson() / etc.
 *
 * Thread-safe: the underlying Rust side guards its state with a mutex.
 */
object Native {

    init {
        System.loadLibrary("mhrv_rs")
    }

    /**
     * Tell the Rust side where to put config + CA + cache. Must be called
     * once before any other call. The path we hand over is our app's
     * private filesDir — guaranteed writable, auto-cleaned on uninstall.
     */
    external fun setDataDir(path: String)

    /**
     * Spin up the proxy. `configJson` is the full config.json contents as
     * a String. Returns the handle (positive) on success, or 0 on failure
     * (inspect logcat for the failure reason).
     */
    external fun startProxy(configJson: String): Long

    /**
     * Stop a running proxy. Idempotent: returns false if the handle is
     * unknown (e.g. already stopped).
     */
    external fun stopProxy(handle: Long): Boolean

    /**
     * Copy the MITM CA cert to a destination path. Used by the UI to
     * surface ca.crt in Downloads so the user can feed it to Android's
     * system "Install certificate" picker.
     */
    external fun exportCa(destPath: String): Boolean

    /** mhrv_rs crate version. Smoke test for JNI linkage. */
    external fun version(): String

    /**
     * Drain the in-memory log ring buffer (populated by the same tracing
     * subscriber that feeds logcat). Returns a `\n`-joined blob of any
     * events the UI hasn't seen yet, or an empty string.
     *
     * Cheap to call — the Kotlin side polls this on a timer. Single blob
     * instead of `String[]` because one JNI crossing is much faster than N.
     */
    external fun drainLogs(): String

    /**
     * Probe a single SNI against `googleIp`. Returns a JSON string of the
     * form `{"ok":true,"latencyMs":123}` on success or
     * `{"ok":false,"error":"..."}` on failure.
     *
     * BLOCKS (does a TLS handshake); call from a background dispatcher.
     */
    external fun testSni(googleIp: String, sni: String): String

    /**
     * Ask GitHub's Releases API whether a newer version of mhrv-rs is
     * out. Returns a JSON blob, one of:
     *   - `{"kind":"upToDate","current":"1.0.0","latest":"1.0.0"}`
     *   - `{"kind":"updateAvailable","current":"1.0.0","latest":"1.1.0","url":"https://...",`
     *     `"assetName":"...apk","assetUrl":"https://...","assetSize":12345}`
     *   - `{"kind":"offline","reason":"..."}`
     *   - `{"kind":"error","reason":"..."}`
     *
     * The `assetName/Url/Size` fields appear on `updateAvailable` when the
     * Rust-side picker matched a per-ABI APK in the release. The auto-
     * updater (UpdateInstaller.kt) uses these to fetch the right APK.
     *
     * BLOCKS (HTTPS round-trip); call from a background dispatcher.
     * Same check the desktop UI runs — same result format.
     */
    external fun checkUpdate(): String

    /**
     * Download a release asset (typically an APK) to `destPath` using the
     * Rust-side rustls client. Signed release builds also fetch and verify
     * the sibling `.minisig` before returning success. Returns a JSON blob:
     *   - `{"ok":true,"bytes":12345678}`
     *   - `{"ok":false,"error":"..."}`
     *
     * BLOCKS (large download); call from `Dispatchers.IO`.
     */
    external fun downloadAsset(url: String, destPath: String): String

    /**
     * Live traffic/usage counters for a running proxy handle. Returns a
     * JSON blob with the StatsSnapshot fields — or an empty string if the
     * handle is unknown or the proxy isn't using the Apps Script relay
     * (direct / full-only modes).
     *
     * Schema (all integer fields unless noted):
     *   relay_calls, relay_failures, coalesced, bytes_relayed,
     *   cache_hits, cache_misses, cache_bytes,
     *   blacklisted_scripts, total_scripts,
     *   today_calls, today_bytes, today_key (string "YYYY-MM-DD"),
     *   today_reset_secs (seconds until 00:00 UTC rollover)
     *
     * Cheap — just reads atomics. Safe to poll on a second-scale timer.
     */
    external fun statsJson(handle: Long): String

    /**
     * Start tun2proxy via its CLI args C API (`tun2proxy_run_with_cli_args`).
     * Resolved at runtime via dlsym from libtun2proxy.so — no fork needed.
     *
     * @param cliArgs full CLI string, e.g. "tun2proxy --proxy socks5://... --tun-fd 42 --udpgw-server 198.18.0.1:7300"
     * @param tunMtu TUN MTU (typically 1500)
     * @return 0 on normal shutdown, negative on error. BLOCKS.
     */
    external fun runTun2proxy(cliArgs: String, tunMtu: Int): Int
}
