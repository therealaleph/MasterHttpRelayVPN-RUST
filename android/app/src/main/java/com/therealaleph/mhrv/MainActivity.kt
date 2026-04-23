package com.therealaleph.mhrv

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.therealaleph.mhrv.ui.CaInstallOutcome
import com.therealaleph.mhrv.ui.HomeScreen
import com.therealaleph.mhrv.ui.theme.MhrvTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Native.setDataDir(filesDir.absolutePath)

        // Android 13+ needs runtime permission for foreground service
        // notifications. Ask once at launch — if the user declines the
        // service still runs, it just won't surface a notification.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this, Manifest.permission.POST_NOTIFICATIONS,
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    REQ_NOTIF,
                )
            }
        }

        setContent {
            MhrvTheme {
                AppRoot()
            }
        }
    }

    @Composable
    private fun AppRoot() {
        // The system VpnService.prepare() returns an Intent if the user
        // hasn't approved VPN access yet; if null, we're already approved
        // and can start directly.
        val vpnPrepareLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startVpnService()
            }
        }

        // CA install flow. We hold the fingerprint of the cert we fired the
        // intent with so we can look it up in AndroidCAStore after the
        // picker returns — the resultCode itself is unreliable on Android
        // 11+ (the system always returns RESULT_CANCELED from the Settings
        // shim), so fingerprint verification is our ground truth.
        var pendingFingerprint by remember { mutableStateOf<ByteArray?>(null) }
        // Human-readable path where we saved the cert copy (e.g.
        // "Downloads/mhrv-ca.crt"). Shown in the outcome snackbar so the
        // user knows where to find it if they need to install manually
        // or share it.
        var pendingDownloadPath by remember { mutableStateOf<String?>(null) }
        var caOutcome by remember { mutableStateOf<CaInstallOutcome?>(null) }

        val installCaLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { _ ->
            val fp = pendingFingerprint
            caOutcome = when {
                fp == null -> CaInstallOutcome.Failed("Internal error: no fingerprint")
                CaInstall.isInstalled(fp) -> CaInstallOutcome.Installed
                else -> CaInstallOutcome.NotInstalled(pendingDownloadPath)
            }
            pendingFingerprint = null
            pendingDownloadPath = null
        }

        HomeScreen(
            // MainActivity's onStart is intentionally dumb: it only
            // launches the VpnService. The auto-resolve that used to
            // live here ran load-modify-save directly on disk, which
            // left HomeScreen's in-memory Compose `cfg` stale — a
            // subsequent UI edit would then persist the stale cfg back
            // over the fresh IP we just wrote. HomeScreen now owns the
            // auto-resolve (it uses the same persist() flow the UI uses
            // for text-field edits, so there's one source of truth).
            onStart = {
                val prepareIntent = VpnService.prepare(this)
                if (prepareIntent == null) {
                    startVpnService()
                } else {
                    vpnPrepareLauncher.launch(prepareIntent)
                }
            },
            onStop = {
                // Three-step teardown. Each step is defensive against a
                // different failure mode we've actually hit in testing:
                //
                //   1. ACTION_STOP — graceful path. The service receives it,
                //      runs its teardown (stops tun2proxy, closes the TUN
                //      fd, shuts down the Rust runtime) and stopSelf()'s.
                //      This is what we want 99% of the time.
                //
                //   2. stopService() — covers the "force-closed then
                //      reopened" zombie case. Android may auto-restart our
                //      START_STICKY service in a fresh process after the
                //      user swipes us away from Recents, and the user's
                //      next Stop tap needs to actually unbind even if our
                //      in-memory TUN fd reference is gone. stopService is
                //      idempotent so it's safe to follow the graceful path.
                //
                //   3. We do NOT touch the VpnService permission — that's
                //      the OS-wide VPN grant and the user approved it
                //      deliberately. Revoking it would force a re-prompt
                //      on next Start, which is worse UX.
                val stopAction = Intent(this, MhrvVpnService::class.java)
                    .setAction(MhrvVpnService.ACTION_STOP)
                startService(stopAction)
                stopService(Intent(this, MhrvVpnService::class.java))
            },
            onInstallCaConfirmed = {
                // The flow is (1) export cert, (2) copy it to Downloads so
                // the user can find it in the Files app, (3) deep-link to
                // Security Settings where they can tap "Install a
                // certificate". On return we verify via AndroidCAStore.
                //
                // We explicitly DO NOT use KeyChain.createInstallIntent —
                // on Android 11+ that intent just opens a dead-end
                // "Install in Settings" dialog with no path forward, which
                // is confusing for users.
                val fp = CaInstall.fingerprint(this)
                val downloadPath = CaInstall.saveToDownloads(this)
                if (fp != null) {
                    pendingFingerprint = fp
                    pendingDownloadPath = downloadPath
                    installCaLauncher.launch(CaInstall.buildSettingsIntent())
                } else {
                    caOutcome = CaInstallOutcome.Failed(
                        "Couldn't read the CA cert. Tap Start once so the proxy creates it, then try again.",
                    )
                }
            },
            caOutcome = caOutcome,
            onCaOutcomeConsumed = { caOutcome = null },
        )
    }

    private fun startVpnService() {
        val i = Intent(this, MhrvVpnService::class.java)
        startService(i)
    }

    companion object {
        private const val REQ_NOTIF = 42
    }
}
