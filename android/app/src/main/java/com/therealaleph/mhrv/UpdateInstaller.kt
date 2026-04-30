package com.therealaleph.mhrv

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

/**
 * Sideload-update flow. We can't push a silent install without root or a
 * system signature, but we can:
 *   1. Pick the per-ABI APK from a `Native.checkUpdate()` result.
 *   2. Stream it down via `Native.downloadAsset` (same rustls client the
 *      desktop UI uses — no OkHttp / Java HTTP needed). When the release
 *      build embeds MHRV_UPDATE_PUBKEY, native code also verifies the
 *      sibling `.minisig` before reporting success.
 *   3. Hand the file to the OS installer via a FileProvider URI + the
 *      `application/vnd.android.package-archive` MIME type.
 *
 * The OS shows its standard "Update existing app?" dialog and, on API 26+,
 * gates that on the user having flipped "Install unknown apps" for us in
 * system settings — `ensureCanInstallUnknownApps` routes the user to that
 * settings page if the permission isn't yet granted.
 *
 * Same-key requirement: APKs are signed by `release.jks` checked into the
 * repo, so Android will only install an update over the existing package
 * when the APK signature matches the installed app. Provenance still comes
 * from minisign verification in `Native.downloadAsset` for signed builds.
 */
object UpdateInstaller {

    sealed class State {
        object Idle : State()
        object Checking : State()
        data class Available(
            val current: String,
            val latest: String,
            val releaseUrl: String,
            val asset: ApkAsset?,
        ) : State()
        object UpToDate : State()
        data class Downloading(val pct: Int?) : State()
        data class ReadyToInstall(val apk: File) : State()
        data class Failed(val reason: String) : State()
    }

    data class ApkAsset(
        val name: String,
        val url: String,
        val sizeBytes: Long,
    )

    private fun safeUpdateAssetName(name: String): String =
        name.substringAfterLast('/')
            .substringAfterLast('\\')
            .replace("..", "_")
            .replace(Regex("""[\p{Cntrl}]"""), "_")
            .ifBlank { "mhrv-update.apk" }

    /**
     * Parse the JSON `Native.checkUpdate()` returns into a `State`. Pure
     * function — call from any dispatcher.
     */
    fun parseCheckResult(json: String?): State {
        if (json.isNullOrBlank()) return State.Failed("no response from native check")
        return try {
            val obj = JSONObject(json)
            when (obj.optString("kind")) {
                "upToDate" -> State.UpToDate
                "updateAvailable" -> {
                    val asset = if (obj.has("assetUrl")) {
                        ApkAsset(
                            name = obj.optString("assetName"),
                            url = obj.optString("assetUrl"),
                            sizeBytes = obj.optLong("assetSize", 0L),
                        )
                    } else null
                    State.Available(
                        current = obj.optString("current"),
                        latest = obj.optString("latest"),
                        releaseUrl = obj.optString("url"),
                        asset = asset,
                    )
                }
                "offline" -> State.Failed("Offline: ${obj.optString("reason", "")}")
                "error" -> State.Failed("Update check failed: ${obj.optString("reason", "")}")
                else -> State.Failed("Unrecognized check result")
            }
        } catch (t: Throwable) {
            State.Failed("Bad check JSON: ${t.message}")
        }
    }

    /**
     * Download and verify the APK to the app's cache dir via the Rust
     * client. Returns the on-disk file on success, or a Failed state with
     * the reason. The cache dir is exposed by our FileProvider (see
     * `xml/file_paths.xml`), so the resulting File can be turned into a
     * content:// URI without further setup.
     */
    suspend fun downloadApk(ctx: Context, asset: ApkAsset): State =
        withContext(Dispatchers.IO) {
            try {
                val updatesDir = File(ctx.cacheDir, "updates").apply { mkdirs() }
                // Wipe any previously downloaded APK so we don't fill up
                // cache across multiple update attempts. Safe — we never
                // read these files except through this flow.
                updatesDir.listFiles()?.forEach { it.delete() }
                val target = File(updatesDir, safeUpdateAssetName(asset.name))
                val resultJson = Native.downloadAsset(asset.url, target.absolutePath)
                val obj = JSONObject(resultJson)
                if (obj.optBoolean("ok", false)) {
                    val actualBytes = target.length()
                    if (actualBytes <= 0L) {
                        return@withContext State.Failed(
                            ctx.getString(R.string.snack_update_apk_empty),
                        )
                    }
                    if (asset.sizeBytes > 0L && actualBytes != asset.sizeBytes) {
                        return@withContext State.Failed(
                            ctx.getString(
                                R.string.snack_update_apk_size_mismatch,
                                actualBytes,
                                asset.sizeBytes,
                            ),
                        )
                    }
                    State.ReadyToInstall(target)
                } else {
                    State.Failed(
                        ctx.getString(
                            R.string.snack_update_download_failed,
                            obj.optString("error", "unknown"),
                        ),
                    )
                }
            } catch (t: Throwable) {
                State.Failed(
                    ctx.getString(
                        R.string.snack_update_download_crashed,
                        t.message ?: "unknown",
                    ),
                )
            }
        }

    /**
     * Hand the APK to the OS installer. On API 26+ this requires that
     * the user has previously enabled "Install unknown apps" for our
     * package in system settings; call `ensureCanInstallUnknownApps`
     * first and only proceed if it returns `true`.
     *
     * Always uses ACTION_VIEW with `application/vnd.android.package-archive`
     * — the simpler path that works back to API 24 (our minSdk). The
     * dialog the user sees is the OS's "Update existing app?" prompt;
     * we have no programmatic callback, but if the install succeeds the
     * OS replaces our process and the user lands back in the new build.
     */
    fun launchInstaller(ctx: Context, apk: File) {
        val authority = "${ctx.packageName}.fileprovider"
        val uri: Uri = FileProvider.getUriForFile(ctx, authority, apk)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            // FLAG_ACTIVITY_NEW_TASK is required when starting from a
            // non-Activity context (we may be invoked from a coroutine
            // launched out of a Composable's scope, where the caller is
            // already an Activity, but the flag is harmless either way
            // and required if the OS routes through any non-Activity
            // intermediary).
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            // Without this the receiving installer can't read the APK
            // through the FileProvider URI.
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        ctx.startActivity(intent)
    }

    /**
     * `true` if the OS will accept our package-archive install intent.
     * Pre-26: always true (no per-app gate existed). 26+: the user must
     * have flipped "Install unknown apps" for us. If false, callers
     * should route the user to that settings page via
     * `openUnknownSourcesSettings` before retrying.
     */
    fun canInstallUnknownApps(ctx: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ctx.packageManager.canRequestPackageInstalls()
        } else {
            true
        }
    }

    /**
     * Open the system "Install unknown apps" page for our package, so
     * the user can flip the toggle. Only meaningful on API 26+; no-op
     * on older devices.
     */
    fun openUnknownSourcesSettings(ctx: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val intent = Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${ctx.packageName}"),
            ).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            ctx.startActivity(intent)
        }
    }
}
