package com.therealaleph.mhrv

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.content.Context
import android.content.res.Configuration
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import java.util.Locale
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

// UiLang is in the outer package namespace already.


// AppCompatActivity (not plain ComponentActivity) because it's what picks
// up AppCompatDelegate.setApplicationLocales() and swaps per-activity
// Configuration + LayoutDirection on recreate(). Compose works fine on
// top — setContent / rememberLauncherForActivityResult live on
// ComponentActivity and AppCompatActivity inherits from it.
class MainActivity : AppCompatActivity() {

    override fun attachBaseContext(newBase: Context) {
        // Force the persisted ui_lang into the Activity's Configuration
        // before it's constructed. AppCompatDelegate.setApplicationLocales
        // schedules a locale change but only takes effect on the NEXT
        // process, so on cold start with a saved preference the activity
        // would render in the device-default locale until recreate().
        // Overriding attachBaseContext wraps `newBase` with the correct
        // locale at the earliest possible moment — what AppCompat did
        // internally before the setApplicationLocales API existed. This
        // path is reliable across all Android versions we support.
        val cfg = ConfigStore.load(newBase)
        val tag = when (cfg.uiLang) {
            UiLang.FA -> "fa"
            UiLang.EN -> "en"
            UiLang.AUTO -> null
        }
        val wrapped = if (tag != null) {
            val config = Configuration(newBase.resources.configuration)
            val locale = Locale.forLanguageTag(tag)
            Locale.setDefault(locale)
            config.setLocale(locale)
            newBase.createConfigurationContext(config)
        } else newBase
        super.attachBaseContext(wrapped)
    }

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

        // Handle mhrv:// deep link — auto-import config.
        handleDeepLink(intent)

        setContent {
            MhrvTheme {
                AppRoot()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme != "mhrv") return
        val encoded = data.toString()
        val cfg = ConfigStore.decode(encoded) ?: return
        ConfigStore.save(this, cfg)
        android.widget.Toast.makeText(this, "Config imported", android.widget.Toast.LENGTH_SHORT).show()
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
                // Only ask for the VPN-consent grant when the user has
                // opted into VPN_TUN mode. In PROXY_ONLY we don't touch
                // VpnService.prepare — firing the consent dialog there
                // would be wrong (user said "no VPN") and MhrvVpnService
                // wouldn't call establish() anyway.
                val cfg = ConfigStore.load(this)
                if (cfg.connectionMode == ConnectionMode.VPN_TUN) {
                    val prepareIntent = VpnService.prepare(this)
                    if (prepareIntent == null) {
                        startVpnService()
                    } else {
                        vpnPrepareLauncher.launch(prepareIntent)
                    }
                } else {
                    startVpnService()
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
            onLangChange = { lang ->
                // Re-apply the new locale to the running process. AppCompatDelegate
                // picks it up from MhrvApp.onCreate on process restart, so we
                // recreate() the activity to take effect immediately — otherwise
                // the user would have to swipe the app away and reopen it for
                // RTL/LTR to swap.
                val tag = when (lang) {
                    UiLang.FA -> "fa"
                    UiLang.EN -> "en"
                    UiLang.AUTO -> ""
                }
                androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(
                    if (tag.isEmpty())
                        androidx.core.os.LocaleListCompat.getEmptyLocaleList()
                    else
                        androidx.core.os.LocaleListCompat.forLanguageTags(tag),
                )
                // AppCompatDelegate triggers recreate internally on API 33+
                // via the per-app language OS setting, but on older API
                // levels it doesn't — call it explicitly for consistent
                // behaviour across the minSdk=24 range.
                recreate()
            },
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
