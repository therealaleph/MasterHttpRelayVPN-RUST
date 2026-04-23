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
        if (!cfg.hasDeploymentId || cfg.authKey.isBlank()) {
            Log.e(TAG, "Config is incomplete — can't start proxy")
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
            stopSelf()
            return
        }

        val socks5Port = cfg.socks5Port ?: (cfg.listenPort + 1)

        // PROXY_ONLY mode: the user wants just the 127.0.0.1 HTTP + SOCKS5
        // listeners up, with no VpnService / no TUN. Typical reasons:
        // another VPN app already owns the system VPN slot, the user
        // wants per-app opt-in via Wi-Fi proxy settings, or the device
        // is a sandboxed/rooted setup where VpnService is unwelcome.
        // We still run as a foreground service (required for the native
        // listener thread to survive backgrounding), we just skip every
        // VPN-specific step below. Issue #37.
        if (cfg.connectionMode == ConnectionMode.PROXY_ONLY) {
            Log.i(TAG, "PROXY_ONLY mode: listeners up, skipping VpnService/TUN")
            startForeground(NOTIF_ID, buildNotif(cfg.listenPort))
            VpnState.setRunning(true)
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
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Throwable) {
            // Shouldn't happen for our own package, but don't hard-fail.
            Log.w(TAG, "addDisallowedApplication failed: ${e.message}")
        }

        // Apply user-chosen app splitting on top of the mandatory
        // self-exclusion above.
        //
        //   ALL    — no extra restriction; every other app routes through
        //            us. Matches pre-splitting behaviour.
        //   ONLY   — allow-list. addAllowedApplication() for each chosen
        //            package; anything missing from the list bypasses the
        //            VPN on the OS-native route. Note that ONLY and the
        //            mandatory self-exclude are mutually exclusive in the
        //            VpnService API, so if the user also put us in the
        //            allow-list we skip the self-exclude (it's already
        //            implicit via "we're not in the list").
        //   EXCEPT — deny-list. addDisallowedApplication() for each chosen
        //            package, additive with our self-exclude.
        //
        // Packages that are not installed (leftover selections from a
        // previous device) throw PackageManager.NameNotFoundException —
        // we log and skip rather than aborting the whole VPN start.
        when (cfg.splitMode) {
            SplitMode.ALL -> { /* no-op */ }
            SplitMode.ONLY -> {
                if (cfg.splitApps.isEmpty()) {
                    Log.w(TAG, "ONLY mode with empty splitApps list — no app would get the VPN; falling back to ALL")
                } else {
                    for (pkg in cfg.splitApps) {
                        try { builder.addAllowedApplication(pkg) } catch (e: Throwable) {
                            Log.w(TAG, "addAllowedApplication($pkg) failed: ${e.message}")
                        }
                    }
                }
            }
            SplitMode.EXCEPT -> {
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
            stopSelf()
            return
        }
        tun = parcelFd

        // 3) Start tun2proxy on a worker thread. It blocks until stop() or
        //    shutdown. We detach the fd so ownership transfers cleanly; the
        //    ParcelFileDescriptor (`tun`) still holds a reference, so closing
        //    it at teardown reliably tears down the TUN even if tun2proxy
        //    doesn't cleanly exit.
        val detachedFd = parcelFd.detachFd()
        tun2proxyRunning.set(true)
        tun2proxyThread = Thread({
            try {
                val rc = Tun2proxy.run(
                    "socks5://127.0.0.1:$socks5Port",
                    detachedFd,
                    /* closeFdOnDrop = */ true,
                    MTU.toChar(),
                    /* verbosity = info */ 3,
                    /* dnsStrategy = virtual */ 0,
                )
                Log.i(TAG, "tun2proxy exited rc=$rc")
            } catch (t: Throwable) {
                Log.e(TAG, "tun2proxy crashed: ${t.message}", t)
            } finally {
                tun2proxyRunning.set(false)
            }
        }, "tun2proxy").apply { start() }

        startForeground(NOTIF_ID, buildNotif(cfg.listenPort))

        // Publish "running" state for the UI's Connect/Disconnect button
        // to observe. Only flipped true once everything above succeeded —
        // if we'd flipped it earlier the button would light up green for
        // a failed-to-establish run.
        VpnState.setRunning(true)
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
     * relay requests piled up against a dead Apps Script deployment. The
     * correct order is:
     *   1. Signal tun2proxy to stop (cooperative).
     *   2. Close the TUN fd — forces tun2proxy's read() to return EBADF.
     *   3. Join the tun2proxy thread (now it really will exit).
     *   4. Shut down the Rust proxy runtime (nothing left to forward to).
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

        // 1. Cooperative stop signal.
        if (tun2proxyRunning.get()) {
            try { Tun2proxy.stop() } catch (t: Throwable) {
                Log.w(TAG, "Tun2proxy.stop: ${t.message}")
            }
        }

        // 2. Close the TUN fd. Since we called detachFd earlier the
        //    ParcelFileDescriptor no longer owns the fd and close() here
        //    is a no-op; the real fd is owned by tun2proxy (closeFdOnDrop
        //    = true), which closes it on return from run().
        try { tun?.close() } catch (t: Throwable) {
            Log.w(TAG, "tun.close: ${t.message}")
        }
        tun = null

        // 3. Join the worker. 4s is enough in the happy case; if tun2proxy
        //    is stuck on something untoward we'd rather move on and force
        //    the runtime shutdown than hang forever.
        try {
            tun2proxyThread?.join(4_000)
        } catch (_: InterruptedException) {}
        val stillAlive = tun2proxyThread?.isAlive == true
        tun2proxyThread = null
        if (stillAlive) {
            Log.w(TAG, "tun2proxy thread still alive after join timeout — proceeding anyway")
        }

        // 4. Shut down the Rust proxy. Backed by `rt.shutdown_timeout(3s)`
        //    on the Rust side, so this is bounded even if the runtime
        //    has in-flight tasks (common when the Apps Script relay has
        //    piled up pending 30s timeouts).
        val handle = proxyHandle
        proxyHandle = 0L
        if (handle != 0L) {
            Log.i(TAG, "teardown: stopping proxy handle=$handle")
            try { Native.stopProxy(handle) } catch (t: Throwable) {
                Log.e(TAG, "Native.stopProxy threw: ${t.message}", t)
            }
        }
        // Flip UI state last — the button reverts to Connect only after
        // the native-side cleanup actually happened, not optimistically.
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

    private fun buildNotif(proxyPort: Int): Notification {
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
            .setContentText("Routing via SOCKS5 127.0.0.1:${proxyPort + 1}")
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
    }
}
