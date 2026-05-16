package com.therealaleph.mhrv

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.github.shadowsocks.bg.Tun2proxy
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground VpnService that:
 *   1. Runs the mhrv-rs Rust proxy (HTTP + SOCKS5 on 127.0.0.1).
 *   2. Establishes a VPN TUN interface capturing all device traffic.
 *   3. Spawns tun2proxy in a background thread — it reads IP packets from
 *      the TUN fd, runs a userspace TCP/IP stack, and funnels every TCP/UDP
 *      flow through our local SOCKS5. Without step 3 the TUN captures
 *      traffic but nothing reads it → DNS_PROBE_STARTED in Chrome (the
 *      symptom that bit us on the first run).
 *
 * Loop-avoidance note: our own proxy's OUTBOUND connections to
 * google_ip:443 would normally be re-captured by the TUN ("traffic goes in
 * circles"). We break the loop by excluding this app's UID from the VPN
 * via `addDisallowedApplication(packageName)`. Everything else on the
 * device still gets routed through us.
 */
class MhrvVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var proxyHandle: Long = 0L
    private var tun2proxyThread: Thread? = null
    private val tun2proxyRunning = AtomicBoolean(false)
    private var debugOverlay: PipelineDebugOverlay? = null

    // Idempotency guard. teardown() is reachable from three paths:
    //   1. ACTION_STOP onStartCommand branch (background thread)
    //   2. onDestroy() (main thread, fires whenever stopSelf resolves
    //      OR Android decides to kill the service)
    //   3. Android revoking the VPN profile out-of-band (also onDestroy)
    // Running the full native cleanup sequence twice races two threads
    // through Tun2proxy.stop(), fd.close(), Native.stopProxy() on state
    // that's already been nullified — the second pass was the
    // SIGSEGV-or-zombie source. This flag makes the second call a
    // no-op.
    private val tornDown = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action ?: "<null>"} startId=$startId")
        return when (intent?.action) {
            ACTION_STOP -> {
                // Drop foreground FIRST — that's what makes the status-bar
                // key icon disappear and lets the user see "Stop worked"
                // even if the native teardown below takes a few seconds
                // (e.g. a dozen in-flight Apps Script requests stuck in
                // their 30s timeout). The service itself stays alive until
                // stopSelf + the background thread below finish.
                try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (t: Throwable) {
                    Log.w(TAG, "stopForeground: ${t.message}")
                }
                // Teardown can block on native shutdown (rt.shutdown_timeout
                // is 5s max, plus 2s for the tun2proxy join). Do it off the
                // main thread so we don't ANR.
                Thread({
                    teardown()
                    stopSelf()
                    Log.i(TAG, "teardown done, service stopping")
                }, "mhrv-teardown").start()
                START_NOT_STICKY
            }
            else -> {
                startEverything()
                START_STICKY
            }
        }
    }

    private fun startEverything() {
        // 1) Seed native with our app's private dir and boot the proxy.
        Native.setDataDir(filesDir.absolutePath)

        val cfg = ConfigStore.load(this)

        // Android 8+ requires every service started via
        // `startForegroundService()` to call `startForeground()` within a
        // short window or the system crashes the app with
        // `ForegroundServiceDidNotStartInTimeException`. Every `stopSelf()`
        // path below MUST therefore happen after a `startForeground()`
        // call — otherwise the user-visible symptom is "the app crashes
        // the instant I tap Start". See issue #73.
        // Issue #211: notification used to display
        // `127.0.0.1:${listenPort + 1}` for the SOCKS5 port, which is
        // wrong whenever socks5Port doesn't equal listenPort+1. With the
        // default Android config (listenPort=8080, socks5Port=1081)
        // users saw "Routing via SOCKS5 127.0.0.1:8081" but the real
        // listener was on 1081 — so per-app SOCKS5 setup against the
        // notification value silently failed. Pass the actual socks5Port
        // (after the same elvis fallback used elsewhere) so the
        // notification matches reality.
        val notifSocks5Port = cfg.socks5Port ?: (cfg.listenPort + 1)
        startForeground(NOTIF_ID, buildNotif(cfg.listenPort, notifSocks5Port))

        // Deployment ID + auth key are required for apps_script and full
        // modes — both talk to Apps Script. Only `direct` mode runs
        // without them. Closes #73 regression where direct-mode users
        // hit this branch and crashed on startForeground timeout.
        val needsCreds = cfg.mode != Mode.DIRECT
        if (needsCreds && (!cfg.hasDeploymentId || cfg.authKey.isBlank())) {
            Log.e(TAG, "Config is incomplete — deployment ID + auth key required for ${cfg.mode}")
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
            return
        }

        // Defensive stop: if a previous startEverything left a handle behind
        // (e.g. the user tapped Start twice, or a Stop path errored out
        // mid-teardown), release it first. Without this, Native.startProxy
        // below binds a brand-new listener while the old one still holds
        // :listenPort → "Address already in use" from the Rust side and the
        // app looks stuck in a half-configured state.
        if (proxyHandle != 0L) {
            Log.w(TAG, "startEverything: stale proxyHandle=$proxyHandle; stopping old proxy first")
            try { Native.stopProxy(proxyHandle) } catch (_: Throwable) {}
            proxyHandle = 0L
        }

        proxyHandle = Native.startProxy(cfg.toJson())
        if (proxyHandle == 0L) {
            Log.e(TAG, "Native.startProxy returned 0 — see logcat tag mhrv_rs")
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
            return
        }

        val socks5Port = cfg.socks5Port ?: (cfg.listenPort + 1)

        // PROXY_ONLY mode: the user wants just the 127.0.0.1 HTTP + SOCKS5
        // listeners up, with no VpnService / no TUN. Typical reasons:
        // another VPN app already owns the system VPN slot, the user
        // wants per-app opt-in via Wi-Fi proxy settings, or the device
        // is a sandboxed/rooted setup where VpnService is unwelcome.
        // We already called startForeground() at the top of this method,
        // which is all PROXY_ONLY needs for the listener thread to survive
        // backgrounding. Issue #37.
        if (cfg.connectionMode == ConnectionMode.PROXY_ONLY) {
            Log.i(TAG, "PROXY_ONLY mode: listeners up, skipping VpnService/TUN")
            VpnState.setProxyHandle(proxyHandle)
            VpnState.setRunning(true)
            showDebugOverlay()
            return
        }

        // 2) Establish the TUN. Key Builder calls:
        //    - addAddress(10.0.0.2/32): our local IP inside the tunnel.
        //    - addRoute(0.0.0.0/0): capture ALL IPv4 traffic. IPv6 isn't added,
        //      so v6 leaks stay up the normal route — fine for this app.
        //    - addDnsServer(1.1.1.1): DNS queries go to this IP, which ALSO
        //      hits our TUN — tun2proxy intercepts in Virtual DNS mode.
        //    - addDisallowedApplication(packageName): our OWN outbound
        //      connections bypass the TUN. Without this, the proxy's
        //      outbound to google_ip loops back through the TUN forever.
        //    - setBlocking(false): we're going to hand the fd to tun2proxy,
        //      which does its own async I/O.
        val builder = Builder()
            .setSession("mhrv-rs")
            .setMtu(MTU)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setBlocking(false)

        // Apply user-chosen app splitting. The VpnService API treats
        // addAllowedApplication and addDisallowedApplication as mutually
        // exclusive — calling both on one Builder throws
        // IllegalArgumentException at establish() time, which is the bug
        // that manifested as "ONLY mode tunnels everything" (establish()
        // failed silently and the fallback never routed correctly).
        //
        // ALL / EXCEPT: add the mandatory self-exclude (packageName) via
        // addDisallowedApplication so our own proxy's outbound to
        // google_ip doesn't loop through the TUN.
        // ONLY: self-exclusion is implicit — we're not in the allow-list.
        //
        // Packages that are not installed (leftover selections from a
        // previous device) throw PackageManager.NameNotFoundException —
        // we log and skip rather than aborting the whole VPN start.
        when (cfg.splitMode) {
            SplitMode.ALL -> {
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (e: Throwable) {
                    Log.w(TAG, "addDisallowedApplication(self) failed: ${e.message}")
                }
            }
            SplitMode.ONLY -> {
                if (cfg.splitApps.isEmpty()) {
                    Log.w(TAG, "ONLY mode with empty splitApps list — no app would get the VPN; falling back to ALL")
                    try {
                        builder.addDisallowedApplication(packageName)
                    } catch (_: Throwable) {}
                } else {
                    var allowed = 0
                    for (pkg in cfg.splitApps) {
                        if (pkg == packageName) continue  // can't tunnel ourselves
                        try {
                            builder.addAllowedApplication(pkg)
                            allowed++
                        } catch (e: Throwable) {
                            Log.w(TAG, "addAllowedApplication($pkg) failed: ${e.message}")
                        }
                    }
                    if (allowed == 0) {
                        Log.w(TAG, "ONLY mode had no usable apps — falling back to ALL")
                        try {
                            builder.addDisallowedApplication(packageName)
                        } catch (_: Throwable) {}
                    }
                }
            }
            SplitMode.EXCEPT -> {
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (e: Throwable) {
                    Log.w(TAG, "addDisallowedApplication(self) failed: ${e.message}")
                }
                for (pkg in cfg.splitApps) {
                    if (pkg == packageName) continue  // already self-excluded above
                    try { builder.addDisallowedApplication(pkg) } catch (e: Throwable) {
                        Log.w(TAG, "addDisallowedApplication($pkg) failed: ${e.message}")
                    }
                }
            }
        }

        val parcelFd = try {
            builder.establish()
        } catch (t: Throwable) {
            Log.e(TAG, "VpnService.establish() failed: ${t.message}")
            null
        }

        if (parcelFd == null) {
            Log.e(TAG, "establish() returned null — is VPN permission granted?")
            Native.stopProxy(proxyHandle)
            proxyHandle = 0L
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
            return
        }
        tun = parcelFd

        // 3) Start tun2proxy on a worker thread. It blocks until stop() or
        //    shutdown. We detach the fd so ownership transfers cleanly to
        //    tun2proxy (closeFdOnDrop = true closes it on return from run()).
        //    The ParcelFileDescriptor (`tun`) we keep is post-detach — its
        //    own close() is a no-op for the underlying fd, so the worker is
        //    the sole owner once it's running.
        val detachedFd = parcelFd.detachFd()
        tun2proxyRunning.set(true)
        // Use tun2proxy_run_with_cli_args C API via dlsym — gives full
        // CLI flexibility including --udpgw-server, no fork needed.
        val cliArgs = buildString {
            append("tun2proxy")
            append(" --proxy socks5://127.0.0.1:$socks5Port")
            append(" --tun-fd $detachedFd")
            append(" --dns virtual")
            append(" --verbosity info")
            append(" --close-fd-on-drop true")
            if (cfg.mode == Mode.FULL) append(" --udpgw-server $UDPGW_MAGIC_DEST")
        }
        val worker = Thread({
            try {
                val rc = Native.runTun2proxy(cliArgs, MTU)
                Log.i(TAG, "tun2proxy exited rc=$rc")
            } catch (t: Throwable) {
                Log.e(TAG, "tun2proxy crashed: ${t.message}", t)
            } finally {
                tun2proxyRunning.set(false)
            }
        }, "tun2proxy")
        try {
            worker.start()
            tun2proxyThread = worker
        } catch (t: Throwable) {
            // Thread.start can throw OutOfMemoryError under extreme memory
            // pressure. The fd we just detached has no owner — without an
            // explicit close it leaks for the life of the process. Adopt
            // it into a fresh ParcelFileDescriptor purely so we can call
            // close() on it.
            Log.e(TAG, "tun2proxy thread start failed: ${t.message}", t)
            tun2proxyRunning.set(false)
            try {
                ParcelFileDescriptor.adoptFd(detachedFd).close()
            } catch (closeErr: Throwable) {
                Log.w(TAG, "adoptFd($detachedFd).close failed: ${closeErr.message}")
            }
            Native.stopProxy(proxyHandle)
            proxyHandle = 0L
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
            stopSelf()
            return
        }

        // (startForeground was already called at the top of this method
        // to satisfy Android 8+'s foreground-service contract — see the
        // comment at the start of startEverything. Calling it here again
        // would be a no-op but wasteful.)

        // Publish "running" state for the UI's Connect/Disconnect button
        // to observe. Only flipped true once everything above succeeded —
        // if we'd flipped it earlier the button would light up green for
        // a failed-to-establish run.
        VpnState.setProxyHandle(proxyHandle)
        VpnState.setRunning(true)
        showDebugOverlay()
    }

    private fun showDebugOverlay() {
        if (debugOverlay != null) return
        if (!android.provider.Settings.canDrawOverlays(this)) {
            Log.w(TAG, "overlay permission not granted — skipping debug overlay")
            return
        }
        debugOverlay = PipelineDebugOverlay(this).also { it.show() }
    }

    /**
     * Tear down everything this service owns. Safe to call more than once:
     *   - `Tun2proxy.stop()` is idempotent on its side.
     *   - tun2proxyRunning gating means we skip the stop call when the
     *     worker thread has already exited.
     *   - `tun` and `proxyHandle` are nulled/zeroed after one pass, so a
     *     second call is a no-op.
     *
     * Shutdown order matters. Doing it wrong (we did originally) leaves
     * tun2proxy still forwarding packets into a half-dead Rust runtime
     * while the runtime is force-aborting its tasks — that's the scenario
     * that manifested as "Stop crashes the app" when there were in-flight
     * relay requests piled up against a dead Apps Script deployment.
     *
     * Steps, with the bound on each one called out so a hung native call
     * cannot stall the whole teardown thread:
     *   1. Shut down the Rust proxy FIRST. This closes the listening
     *      SOCKS5 socket that tun2proxy's worker thread is blocked on
     *      a read() from. Killing the upstream socket is what makes the
     *      worker's blocking native call return — we have no other lever
     *      to wake it. Bounded by `rt.shutdown_timeout(3s)` Rust-side.
     *   2. Signal tun2proxy to stop (cooperative). Mostly redundant after
     *      step 1, but cheap and covers the rare path where the worker is
     *      blocked on something other than its socket read (e.g. a
     *      smoltcp internal queue waiting on a wake). Bounded by a 2s
     *      side-thread join.
     *   3. Drop our `ParcelFileDescriptor` reference. Because we already
     *      called detachFd() at startup, this is a no-op for the
     *      underlying fd — the worker (closeFdOnDrop=true) owns it.
     *      We keep the call only so the PROXY_ONLY / failed-establish
     *      paths still null out the field cleanly.
     *   4. Join the tun2proxy thread, bounded at 4s. With step 1 having
     *      already closed the socket the worker was reading from, this
     *      join almost always completes well under the deadline.
     *
     * History (#700 from @ilok67): the original order was
     * tun2proxy → tun.close → join → stopProxy. That ordering crashed
     * SIGSEGV ~2s after Disconnect because Native.stopProxy() freed the
     * Rust runtime (including the SOCKS5 listener) while tun2proxy's
     * worker was still in a blocking native read against it — classic
     * use-after-free. The previous comment claimed "the runtime shutdown
     * below will knock the rest of the world over," but Native.stopProxy
     * cannot forcibly terminate a separate native thread; it just frees
     * memory the other thread is still using. Reversing the order means
     * the worker's blocking read returns with an EOF / socket-closed
     * error, the worker exits through its own error path, and the join
     * is effectively just confirming a clean shutdown.
     */
    private fun teardown() {
        // Idempotency guard. Without this, onDestroy racing the
        // ACTION_STOP background thread has been observed to crash the
        // process — two threads into Tun2proxy.stop() and
        // Native.stopProxy(handle) where handle has already been zeroed
        // is a SIGSEGV waiting to happen. First caller wins, subsequent
        // callers return immediately.
        if (!tornDown.compareAndSet(false, true)) {
            Log.i(TAG, "teardown: already done, skipping (caller=${Thread.currentThread().name})")
            return
        }
        Log.i(
            TAG,
            "teardown: begin caller=${Thread.currentThread().name} " +
            "(tun2proxy running=${tun2proxyRunning.get()}, proxyHandle=$proxyHandle)",
        )

        // 1. Stop the Rust proxy FIRST. Closing the SOCKS5 listener is
        //    what makes tun2proxy's worker thread's blocking read return
        //    — without this the worker stays in native code and a later
        //    Native.stopProxy would race it into use-after-free (#700).
        val handle = proxyHandle
        proxyHandle = 0L
        if (handle != 0L) {
            Log.i(TAG, "teardown: stopping proxy handle=$handle")
            try { Native.stopProxy(handle) } catch (t: Throwable) {
                Log.e(TAG, "Native.stopProxy threw: ${t.message}", t)
            }
        }

        // 2. Cooperative stop signal — mostly redundant now that step 1
        //    has yanked the socket out from under the worker, but cheap
        //    and covers any future code path where the worker might be
        //    blocked on something other than its upstream socket read.
        //    Bounded so a hung JNI call can't stall teardown.
        if (tun2proxyRunning.get()) {
            val stopper = Thread({
                try { Tun2proxy.stop() } catch (t: Throwable) {
                    Log.w(TAG, "Tun2proxy.stop: ${t.message}")
                }
            }, "mhrv-tun2proxy-stop").apply { start() }
            try { stopper.join(2_000) } catch (_: InterruptedException) {}
            if (stopper.isAlive) {
                Log.w(TAG, "Tun2proxy.stop did not return within 2s — proceeding")
            }
        }

        // 3. Drop our PFD reference. detachFd at startup means this
        //    close() is a no-op for the underlying fd — tun2proxy owns
        //    it (closeFdOnDrop = true) and closes it on return from
        //    run(). The call is kept only to null the field cleanly on
        //    paths that never reached detachFd (PROXY_ONLY, or an
        //    establish() that failed mid-builder).
        try { tun?.close() } catch (t: Throwable) {
            Log.w(TAG, "tun.close: ${t.message}")
        }
        tun = null

        // 4. Join the worker. With step 1 having killed its upstream this
        //    almost always completes immediately; the 4s budget is just
        //    headroom for tun2proxy's internal close path to drain.
        try {
            tun2proxyThread?.join(4_000)
        } catch (_: InterruptedException) {}
        val stillAlive = tun2proxyThread?.isAlive == true
        tun2proxyThread = null
        if (stillAlive) {
            Log.w(TAG, "tun2proxy thread still alive after join timeout — proceeding anyway")
        }

        // Hide debug overlay before flipping UI state.
        debugOverlay?.hide()
        debugOverlay = null

        // Flip UI state last — the button reverts to Connect only after
        // the native-side cleanup actually happened, not optimistically.
        VpnState.setProxyHandle(0L)
        VpnState.setRunning(false)
        Log.i(TAG, "teardown: done")
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy entered")
        try {
            teardown()
        } catch (t: Throwable) {
            // Belt-and-suspenders. Crashing out of onDestroy takes the
            // whole process with it — user-visible as the app closing
            // right when they tap Stop, which is exactly the symptom we
            // are trying to fix. Anything that gets here is logged and
            // swallowed.
            Log.e(TAG, "onDestroy teardown threw: ${t.message}", t)
        }
        super.onDestroy()
        Log.i(TAG, "onDestroy done")
    }

    private fun buildNotif(httpPort: Int, socks5Port: Int): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "mhrv-rs",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Status of the mhrv-rs VPN"
                setShowBadge(false)
            }
            mgr.createNotificationChannel(ch)
        }
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, MhrvVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("mhrv-rs VPN is active")
            .setContentText("HTTP 127.0.0.1:$httpPort  ·  SOCKS5 127.0.0.1:$socks5Port")
            .setSmallIcon(android.R.drawable.presence_online)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    companion object {
        private const val TAG = "MhrvVpnService"
        private const val CHANNEL_ID = "mhrv.vpn.status"
        private const val NOTIF_ID = 0x1001
        private const val MTU = 1500
        const val ACTION_STOP = "com.therealaleph.mhrv.STOP"

        // Magic udpgw destination passed to tun2proxy in Full mode. MUST stay
        // outside tun2proxy's --dns virtual range (198.18.0.0/15) — otherwise
        // virtual DNS can synthesise the magic IP for a real hostname and
        // silently mis-route its traffic into the udpgw path. See issue #251
        // and `UDPGW_MAGIC_IP` / `UDPGW_MAGIC_PORT` in tunnel-node/src/udpgw.rs.
        // Wire-protocol convention: both sides must agree. v1.9.25+ tunnel-nodes
        // also accept the legacy 198.18.0.1:7300 for one deprecation cycle.
        private const val UDPGW_MAGIC_DEST = "192.0.2.1:7300"
    }
}
