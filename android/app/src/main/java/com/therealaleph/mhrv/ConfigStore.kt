package com.therealaleph.mhrv

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Config I/O. The source of truth is a JSON file in the app's files dir —
 * the Rust side parses the same file, so we don't maintain two schemas.
 *
 * What the Android UI exposes is a pragmatic subset of the full mhrv-rs
 * config, but we now track parity with the desktop UI on the dimensions
 * that actually matter on a phone:
 *   - multiple deployment IDs (round-robin)
 *   - an SNI rotation pool
 *   - log level / verify_ssl / parallel_relay knobs
 * Anything else gets phone-appropriate defaults.
 */
/**
 * How the foreground service exposes the proxy to the rest of the device.
 *
 * - [VPN_TUN] — the default; `VpnService` claims a TUN interface and every
 *   app's traffic goes through `tun2proxy` → our SOCKS5 → Apps Script.
 *   Requires the user to accept the system "VPN connection request"
 *   dialog on first Start.
 *
 * - [PROXY_ONLY] — just runs the HTTP (`127.0.0.1:8080`) and SOCKS5
 *   (`127.0.0.1:1081`) listeners; no VpnService, no TUN. The user sets
 *   their Wi-Fi proxy (or a per-app proxy setting) to those addresses.
 *   Useful when the device already has another VPN up, or the user
 *   specifically wants per-app opt-in, or on rooted/specialized devices
 *   where VpnService is unwelcome. Closes issue #37.
 */
enum class ConnectionMode { VPN_TUN, PROXY_ONLY }

/**
 * App-splitting policy when in VPN_TUN mode.
 *
 * - [ALL]  — tunnel every app (default; the package list is ignored).
 * - [ONLY] — allow-list: tunnel ONLY the apps in `splitApps`. Everything
 *   else bypasses the VPN. Useful when you want mhrv-rs for a specific
 *   browser / messenger and nothing else.
 * - [EXCEPT] — deny-list: tunnel everything EXCEPT the apps in
 *   `splitApps`. Useful for excluding a banking app that would break
 *   under MITM anyway, or a self-updater you don't want going through
 *   the quota-limited relay.
 *
 * Our own package (`packageName`) is always excluded regardless of mode
 * — that's the loop-avoidance rule from day one, not a user toggle.
 */
enum class SplitMode { ALL, ONLY, EXCEPT }

/**
 * UI language preference. AUTO respects the device locale; FA / EN
 * force the app into Persian / English with proper RTL / LTR layout
 * on next app launch (AppCompatDelegate.setApplicationLocales is
 * applied at Application.onCreate).
 */
enum class UiLang { AUTO, FA, EN }

/**
 * Operating mode. Mirrors the Rust-side `Mode` enum.
 *
 * - [APPS_SCRIPT] (default) — full DPI bypass through the user's deployed
 *   Apps Script relay. Requires a Deployment ID + Auth key.
 * - [GOOGLE_ONLY] — bootstrap mode. Only the SNI-rewrite tunnel to the
 *   Google edge is active, so the user can reach `script.google.com` to
 *   deploy Code.gs in the first place. No Deployment ID / Auth key needed.
 *   Non-Google traffic goes direct (no relay).
 * - [FULL] — full tunnel mode. ALL traffic is tunneled end-to-end through
 *   Apps Script + a remote tunnel node. No certificate installation needed.
 * - [GOOGLE_DRIVE] — FlowDriver-style queue. SOCKS5 multiplexed through
 *   a shared Google Drive folder; needs `mhrv-drive-node` running on a
 *   remote host pointed at the same folder. No Apps Script involved.
 */
enum class Mode { APPS_SCRIPT, GOOGLE_ONLY, FULL, GOOGLE_DRIVE }

data class MhrvConfig(
    val mode: Mode = Mode.APPS_SCRIPT,

    val listenHost: String = "127.0.0.1",
    val listenPort: Int = 8080,
    val socks5Port: Int? = 1081,

    /** One Apps Script ID or deployment URL per entry. */
    val appsScriptUrls: List<String> = emptyList(),
    val authKey: String = "",

    val frontDomain: String = "www.google.com",
    /** Rotation pool of SNI hostnames; empty means "let Rust auto-expand". */
    val sniHosts: List<String> = emptyList(),
    val googleIp: String = "142.251.36.68",

    val verifySsl: Boolean = true,
    val logLevel: String = "info",
    val parallelRelay: Int = 1,
    val upstreamSocks5: String = "",

    /**
     * User-configured hostnames that bypass Apps Script relay entirely
     * and plain-TCP passthrough (via upstreamSocks5 if set). Each entry
     * is either an exact hostname ("example.com") or a leading-dot
     * suffix (".example.com" → matches example.com + any subdomain).
     * See `src/config.rs` `passthrough_hosts` for semantics.
     * Issues #39, #127.
     */
    val passthroughHosts: List<String> = emptyList(),

    /** VPN_TUN (everything routed) vs PROXY_ONLY (user configures per-app). */
    val connectionMode: ConnectionMode = ConnectionMode.VPN_TUN,

    /** ALL / ONLY / EXCEPT — scope of app splitting inside VPN_TUN mode. */
    val splitMode: SplitMode = SplitMode.ALL,
    /** Package names used by ONLY and EXCEPT. Empty under ALL. */
    val splitApps: List<String> = emptyList(),

    /** UI language toggle. Non-Rust; honoured only by the Android wrapper. */
    val uiLang: UiLang = UiLang.AUTO,

    // ── google_drive mode ──────────────────────────────────────────────
    /**
     * Path to the Google Cloud OAuth desktop credentials JSON. On Android
     * this is the absolute path inside the app's filesDir where the user
     * imported their downloaded `credentials.json`. Empty on a fresh install.
     */
    val driveCredentialsPath: String = "",
    /** Pinned Drive folder ID, or empty to look up by [driveFolderName]. */
    val driveFolderId: String = "",
    val driveFolderName: String = "MHRV-Drive",
    /**
     * Stable per-device client_id embedded in Drive filenames. Empty =
     * Rust generates a random short id at start. Validated server-side
     * (<=32 chars, ASCII alphanumeric / dash / underscore).
     */
    val driveClientId: String = "",
    val drivePollMs: Int = 500,
    val driveFlushMs: Int = 300,
    val driveIdleTimeoutSecs: Int = 300,
) {
    /**
     * Extract just the deployment ID from either a full
     * `https://script.google.com/macros/s/<ID>/exec` URL or a bare ID.
     *
     * Implementation note (this used to be buggy): never use the chained
     * `substringBefore(delim, missingDelimiterValue)` form passing the
     * original input as the fallback. Example of what that caused:
     *   "https://.../macros/s/X/exec"
     *     .substringAfter("/macros/s/", s)  -> "X/exec"
     *     .substringBefore("/", s)          -> "X"
     *     .substringBefore("?", s)          -> FALLBACK fires because
     *                                           "?" isn't in "X",
     *                                           returning the ORIGINAL URL
     * → we'd then save the full URL as the "ID", and on reload the UI
     * would build `https://.../macros/s/<full-URL>/exec`, producing the
     * "extra https:// and extra /exec" symptom users reported. Keep the
     * extraction linear and don't reach for a fallback.
     */
    private fun extractId(input: String): String {
        var s = input.trim()
        if (s.isEmpty()) return s
        val marker = "/macros/s/"
        val i = s.indexOf(marker)
        if (i >= 0) s = s.substring(i + marker.length)
        // Strip /exec or /dev suffix (or any path after the ID).
        val slash = s.indexOf('/')
        if (slash >= 0) s = s.substring(0, slash)
        // Strip query string.
        val q = s.indexOf('?')
        if (q >= 0) s = s.substring(0, q)
        return s.trim()
    }

    fun toJson(): String {
        val ids = appsScriptUrls
            .map { extractId(it) }
            .filter { it.isNotEmpty() }

        val obj = JSONObject().apply {
            // `mode` is required — without it serde errors with
            // "missing field `mode`" and startProxy silently returns 0.
            put("mode", when (mode) {
                Mode.APPS_SCRIPT -> "apps_script"
                Mode.GOOGLE_ONLY -> "google_only"
                Mode.FULL -> "full"
                Mode.GOOGLE_DRIVE -> "google_drive"
            })
            put("listen_host", listenHost)
            put("listen_port", listenPort)
            socks5Port?.let { put("socks5_port", it) }

            // In google_only mode these are unused by the Rust side, but we
            // still persist whatever the user typed so flipping back to
            // apps_script mode doesn't wipe their settings.
            put("script_ids", JSONArray().apply { ids.forEach { put(it) } })
            put("auth_key", authKey)

            put("front_domain", frontDomain)
            if (sniHosts.isNotEmpty()) {
                put("sni_hosts", JSONArray().apply { sniHosts.forEach { put(it) } })
            }
            put("google_ip", googleIp)

            put("verify_ssl", verifySsl)
            put("log_level", logLevel)
            put("parallel_relay", parallelRelay)
            if (upstreamSocks5.isNotBlank()) {
                put("upstream_socks5", upstreamSocks5.trim())
            }
            if (passthroughHosts.isNotEmpty()) {
                put("passthrough_hosts", JSONArray().apply { passthroughHosts.forEach { put(it) } })
            }

            // Phone-scoped scan defaults. We don't expose these in the UI
            // because a phone isn't where you'd run a full /16 scan; users
            // who need it can do that on the desktop UI and paste the IP.
            put("fetch_ips_from_api", false)
            put("max_ips_to_scan", 20)

            // Android-only: surfaced in the UI dropdown. The Rust side
            // doesn't read this key (serde ignores unknown fields), which
            // is intentional — proxy-vs-TUN is a service-layer decision
            // that belongs to the Android wrapper, not the crate.
            put("connection_mode", when (connectionMode) {
                ConnectionMode.VPN_TUN -> "vpn_tun"
                ConnectionMode.PROXY_ONLY -> "proxy_only"
            })
            put("split_mode", when (splitMode) {
                SplitMode.ALL -> "all"
                SplitMode.ONLY -> "only"
                SplitMode.EXCEPT -> "except"
            })
            if (splitApps.isNotEmpty()) {
                put("split_apps", JSONArray().apply { splitApps.forEach { put(it) } })
            }
            put("ui_lang", when (uiLang) {
                UiLang.AUTO -> "auto"
                UiLang.FA -> "fa"
                UiLang.EN -> "en"
            })

            // google_drive: only emit when the user has actually set a
            // credentials path. Otherwise the file would gain stub keys
            // (poll/flush/idle defaults) for users who don't run drive
            // mode, which makes diffs noisier.
            if (mode == Mode.GOOGLE_DRIVE || driveCredentialsPath.isNotBlank()) {
                if (driveCredentialsPath.isNotBlank()) {
                    put("drive_credentials_path", driveCredentialsPath)
                }
                if (driveFolderId.isNotBlank()) put("drive_folder_id", driveFolderId)
                if (driveFolderName.isNotBlank()) put("drive_folder_name", driveFolderName)
                if (driveClientId.isNotBlank()) put("drive_client_id", driveClientId)
                put("drive_poll_ms", drivePollMs)
                put("drive_flush_ms", driveFlushMs)
                put("drive_idle_timeout_secs", driveIdleTimeoutSecs)
            }
        }
        return obj.toString(2)
    }

    /**
     * Whether the Drive mode has enough configured to attempt a Start.
     * Mirrors the Rust-side validate() rules: needs a credentials path
     * and an OAuth refresh token cached for those credentials. The
     * token check is best-effort — `Native.driveTokenPresent` reads the
     * file on disk, so a true here doesn't guarantee Google will accept
     * the refresh on next call.
     */
    val driveConfigured: Boolean get() = driveCredentialsPath.isNotBlank()

    /** Convenience: is there at least one usable deployment ID? */
    val hasDeploymentId: Boolean get() =
        appsScriptUrls.any { extractId(it).isNotEmpty() }
}

object ConfigStore {
    private const val FILE = "config.json"

    fun load(ctx: Context): MhrvConfig {
        val f = File(ctx.filesDir, FILE)
        if (!f.exists()) return MhrvConfig()
        return try {
            loadFromJson(JSONObject(f.readText()))
        } catch (_: Throwable) {
            MhrvConfig()
        }
    }

    fun save(ctx: Context, cfg: MhrvConfig) {
        val f = File(ctx.filesDir, FILE)
        f.writeText(cfg.toJson())
    }

    /** Prefix for encoded config strings so we can detect them in clipboard. */
    private const val HASH_PREFIX = "mhrv-rs://"

    /** Distinct prefix for the "Drive setup" share — bundles credentials
     *  + refresh token so a recipient can connect with no manual OAuth.
     *  Different from [HASH_PREFIX] because the payload includes secrets,
     *  the recipient flow needs to write extra files, and we don't want
     *  to silently fall through to the regular config import path. */
    private const val DRIVE_SETUP_PREFIX = "mhrv-rs-setup://"

    /** Filename inside the app's filesDir where imported credentials are
     *  written. Must match what the regular Drive import flow uses, so
     *  a setup-import is indistinguishable from a manual import +
     *  authorize after the fact. */
    private const val DRIVE_CREDENTIALS_FILE = "drive-credentials.json"

    /** Token cache filename — `<credentials>.token` — same shape the
     *  Rust side writes when a fresh OAuth dance completes. */
    private const val DRIVE_TOKEN_FILE = "drive-credentials.json.token"

    /** Encode config as a shareable base64 string with prefix.
     *  Only includes non-default fields to keep the hash short. */
    fun encode(cfg: MhrvConfig): String {
        val defaults = MhrvConfig()
        val obj = JSONObject()

        // Always include essential fields.
        obj.put("mode", when (cfg.mode) {
            Mode.APPS_SCRIPT -> "apps_script"
            Mode.GOOGLE_ONLY -> "google_only"
            Mode.FULL -> "full"
            Mode.GOOGLE_DRIVE -> "google_drive"
        })
        val ids = cfg.appsScriptUrls.mapNotNull { url ->
            val marker = "/macros/s/"
            val i = url.indexOf(marker)
            if (i >= 0) {
                var s = url.substring(i + marker.length)
                val slash = s.indexOf('/'); if (slash >= 0) s = s.substring(0, slash)
                s.trim().ifEmpty { null }
            } else url.trim().ifEmpty { null }
        }
        if (ids.isNotEmpty()) obj.put("script_ids", JSONArray().apply { ids.forEach { put(it) } })
        if (cfg.authKey.isNotBlank()) obj.put("auth_key", cfg.authKey)

        // Only include non-default values.
        if (cfg.googleIp != defaults.googleIp) obj.put("google_ip", cfg.googleIp)
        if (cfg.frontDomain != defaults.frontDomain) obj.put("front_domain", cfg.frontDomain)
        if (cfg.sniHosts.isNotEmpty()) obj.put("sni_hosts", JSONArray().apply { cfg.sniHosts.forEach { put(it) } })
        if (cfg.verifySsl != defaults.verifySsl) obj.put("verify_ssl", cfg.verifySsl)
        if (cfg.logLevel != defaults.logLevel) obj.put("log_level", cfg.logLevel)
        if (cfg.parallelRelay != defaults.parallelRelay) obj.put("parallel_relay", cfg.parallelRelay)
        if (cfg.upstreamSocks5.isNotBlank()) obj.put("upstream_socks5", cfg.upstreamSocks5)
        if (cfg.passthroughHosts.isNotEmpty()) obj.put("passthrough_hosts", JSONArray().apply { cfg.passthroughHosts.forEach { put(it) } })
        // google_drive — share the knobs but never the credentials path
        // or refresh token; those are device-local.
        if (cfg.mode == Mode.GOOGLE_DRIVE) {
            if (cfg.driveFolderId.isNotBlank()) obj.put("drive_folder_id", cfg.driveFolderId)
            if (cfg.driveFolderName != defaults.driveFolderName) obj.put("drive_folder_name", cfg.driveFolderName)
            if (cfg.drivePollMs != defaults.drivePollMs) obj.put("drive_poll_ms", cfg.drivePollMs)
            if (cfg.driveFlushMs != defaults.driveFlushMs) obj.put("drive_flush_ms", cfg.driveFlushMs)
            if (cfg.driveIdleTimeoutSecs != defaults.driveIdleTimeoutSecs) obj.put("drive_idle_timeout_secs", cfg.driveIdleTimeoutSecs)
        }

        // Compress with DEFLATE then base64.
        val jsonBytes = obj.toString().toByteArray(Charsets.UTF_8)
        val compressed = java.io.ByteArrayOutputStream().also { bos ->
            java.util.zip.DeflaterOutputStream(bos).use { it.write(jsonBytes) }
        }.toByteArray()

        val b64 = android.util.Base64.encodeToString(
            compressed,
            android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE,
        )
        return "$HASH_PREFIX$b64"
    }

    /** Try DEFLATE inflate; fall back to treating bytes as raw UTF-8
     *  (for backward compat with uncompressed exports). */
    private fun inflateOrRaw(raw: ByteArray): String {
        return try {
            java.util.zip.InflaterInputStream(raw.inputStream()).bufferedReader().readText()
        } catch (_: Throwable) {
            String(raw, Charsets.UTF_8)
        }
    }

    /** Try to decode an encoded config string or raw JSON. Returns null on failure. */
    fun decode(encoded: String): MhrvConfig? {
        val trimmed = encoded.trim()
        // Try raw JSON first.
        if (trimmed.startsWith("{")) {
            return try {
                val obj = JSONObject(trimmed)
                if (!obj.has("mode") && !obj.has("script_ids") && !obj.has("auth_key")) null
                else loadFromJson(obj)
            } catch (_: Throwable) { null }
        }
        // Try mhrv:// base64 encoded (possibly DEFLATE-compressed).
        val payload = if (trimmed.startsWith(HASH_PREFIX)) trimmed.removePrefix(HASH_PREFIX) else trimmed
        return try {
            val raw = android.util.Base64.decode(payload, android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE)
            val text = inflateOrRaw(raw)
            val obj = JSONObject(text)
            if (!obj.has("mode") && !obj.has("script_ids") && !obj.has("auth_key")) return null
            loadFromJson(obj)
        } catch (_: Throwable) {
            null
        }
    }

    // -----------------------------------------------------------------
    //  Drive setup share — bundle credentials + refresh token + folder
    //  ID so a fresh device can be onboarded with one QR scan and zero
    //  technical steps. Distinct from [encode]/[decode] because that
    //  flow deliberately omits secrets; this one deliberately includes
    //  them and warns the sharer accordingly.
    // -----------------------------------------------------------------

    /**
     * Drive-setup payload as it travels in the QR. Versioned in case we
     * later rotate the bundle shape.
     *
     * - [credentials]: full content of credentials.json (the OAuth
     *   desktop client config — client_id + client_secret).
     * - [refreshToken]: the cached OAuth refresh token. The recipient
     *   uses it directly without any browser dance.
     * - [folderId] / [folderName] / [pollMs] / [flushMs] / [idleSecs] /
     *   [googleIp] / [frontDomain]: the same Drive-mode knobs that
     *   apply on the recipient.
     */
    data class DriveSetup(
        val credentials: String,
        val refreshToken: String,
        val folderId: String,
        val folderName: String,
        val pollMs: Int,
        val flushMs: Int,
        val idleSecs: Int,
        val googleIp: String,
        val frontDomain: String,
    )

    /** Read the on-disk credentials + token files and bundle them with
     *  the user's Drive config knobs into a shareable string. Returns
     *  null when there's nothing to share (no credentials imported, or
     *  no token cached yet — the sharer has to complete OAuth first). */
    fun encodeDriveSetup(ctx: Context, cfg: MhrvConfig): String? {
        if (cfg.driveCredentialsPath.isBlank()) return null
        val credsFile = File(cfg.driveCredentialsPath)
        if (!credsFile.exists()) return null
        val tokenFile = File(credsFile.absolutePath + ".token")
        if (!tokenFile.exists()) return null

        val credentials = runCatching { credsFile.readText() }.getOrNull() ?: return null
        val refreshToken = runCatching {
            JSONObject(tokenFile.readText()).optString("refresh_token", "")
        }.getOrNull().orEmpty()
        if (refreshToken.isBlank()) return null

        val defaults = MhrvConfig()
        val obj = JSONObject().apply {
            put("v", 1)
            put("credentials", credentials)
            put("refresh_token", refreshToken)
            if (cfg.driveFolderId.isNotBlank()) put("folder_id", cfg.driveFolderId)
            if (cfg.driveFolderName != defaults.driveFolderName) put("folder_name", cfg.driveFolderName)
            if (cfg.drivePollMs != defaults.drivePollMs) put("poll_ms", cfg.drivePollMs)
            if (cfg.driveFlushMs != defaults.driveFlushMs) put("flush_ms", cfg.driveFlushMs)
            if (cfg.driveIdleTimeoutSecs != defaults.driveIdleTimeoutSecs) put("idle_secs", cfg.driveIdleTimeoutSecs)
            if (cfg.googleIp != defaults.googleIp) put("google_ip", cfg.googleIp)
            if (cfg.frontDomain != defaults.frontDomain) put("front_domain", cfg.frontDomain)
        }

        val raw = obj.toString().toByteArray(Charsets.UTF_8)
        val compressed = java.io.ByteArrayOutputStream().also { bos ->
            java.util.zip.DeflaterOutputStream(bos).use { it.write(raw) }
        }.toByteArray()
        val b64 = android.util.Base64.encodeToString(
            compressed,
            android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE,
        )
        return "$DRIVE_SETUP_PREFIX$b64"
    }

    /** Cheap check used to dispatch a scanned / pasted blob to the
     *  Drive-setup import path instead of the regular config-import
     *  path (the two formats look different but both base64; the prefix
     *  is what disambiguates). */
    fun looksLikeDriveSetup(text: String): Boolean =
        text.trim().startsWith(DRIVE_SETUP_PREFIX)

    /** Decode a [DRIVE_SETUP_PREFIX] payload. Returns null if the blob
     *  doesn't parse, lacks required fields, or has an unsupported
     *  version. Does NOT touch disk — call [applyDriveSetup] to actually
     *  import. */
    fun decodeDriveSetup(encoded: String): DriveSetup? {
        val trimmed = encoded.trim()
        val payload = trimmed.removePrefix(DRIVE_SETUP_PREFIX).trim()
        if (payload.isEmpty()) return null
        val raw = runCatching {
            android.util.Base64.decode(
                payload,
                android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE,
            )
        }.getOrNull() ?: return null
        val text = inflateOrRaw(raw)
        return try {
            val obj = JSONObject(text)
            if (obj.optInt("v", 0) != 1) return null
            val credentials = obj.optString("credentials", "")
            val refreshToken = obj.optString("refresh_token", "")
            if (credentials.isBlank() || refreshToken.isBlank()) return null
            val defaults = MhrvConfig()
            DriveSetup(
                credentials = credentials,
                refreshToken = refreshToken,
                folderId = obj.optString("folder_id", ""),
                folderName = obj.optString("folder_name", defaults.driveFolderName),
                pollMs = obj.optInt("poll_ms", defaults.drivePollMs),
                flushMs = obj.optInt("flush_ms", defaults.driveFlushMs),
                idleSecs = obj.optInt("idle_secs", defaults.driveIdleTimeoutSecs),
                googleIp = obj.optString("google_ip", defaults.googleIp),
                frontDomain = obj.optString("front_domain", defaults.frontDomain),
            )
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * Write the credentials + token files into the app's filesDir and
     * return an [MhrvConfig] reflecting the imported setup. The caller
     * is responsible for [save]'ing it (we keep this side-effect-free
     * apart from disk writes so callers can compose it into their own
     * "import + persist + snackbar" flow).
     *
     * On success returns the new config. On any I/O failure returns
     * null and tries to clean up partial writes — better to leave the
     * recipient in the original (empty) state than half-imported.
     */
    fun applyDriveSetup(ctx: Context, base: MhrvConfig, setup: DriveSetup): MhrvConfig? {
        val credsFile = File(ctx.filesDir, DRIVE_CREDENTIALS_FILE)
        val tokenFile = File(ctx.filesDir, DRIVE_TOKEN_FILE)
        return try {
            credsFile.writeText(setup.credentials)
            tokenFile.writeText(JSONObject().apply {
                put("refresh_token", setup.refreshToken)
            }.toString())
            // Best-effort 0600. Android's FileProvider sandbox already
            // walls /data/user/0/<pkg>/files/ off from other apps, so
            // this is belt-and-braces.
            runCatching {
                credsFile.setReadable(false, false)
                credsFile.setReadable(true, true)
                credsFile.setWritable(false, false)
                credsFile.setWritable(true, true)
                tokenFile.setReadable(false, false)
                tokenFile.setReadable(true, true)
                tokenFile.setWritable(false, false)
                tokenFile.setWritable(true, true)
            }
            base.copy(
                mode = Mode.GOOGLE_DRIVE,
                driveCredentialsPath = credsFile.absolutePath,
                driveFolderId = setup.folderId,
                driveFolderName = setup.folderName,
                drivePollMs = setup.pollMs,
                driveFlushMs = setup.flushMs,
                driveIdleTimeoutSecs = setup.idleSecs,
                googleIp = setup.googleIp,
                frontDomain = setup.frontDomain,
            )
        } catch (_: Throwable) {
            runCatching { credsFile.delete() }
            runCatching { tokenFile.delete() }
            null
        }
    }

    /** Check if a string looks like an encoded mhrv config. */
    fun looksLikeConfig(text: String): Boolean {
        val t = text.trim()
        if (t.startsWith(HASH_PREFIX)) return true
        // Also accept raw JSON with a "mode" field.
        if (t.startsWith("{")) {
            return try { JSONObject(t).has("mode") } catch (_: Throwable) { false }
        }
        return false
    }

    /** Parse config from a JSON object — shared by load() and decode(). */
    private fun loadFromJson(obj: JSONObject): MhrvConfig {
        val ids = obj.optJSONArray("script_ids")?.let { arr ->
            buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
        }?.filter { it.isNotBlank() }.orEmpty()
        val urls = ids.map { "https://script.google.com/macros/s/$it/exec" }
        val sni = obj.optJSONArray("sni_hosts")?.let { arr ->
            buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
        }?.filter { it.isNotBlank() }.orEmpty()

        return MhrvConfig(
            mode = when (obj.optString("mode", "apps_script")) {
                "google_only" -> Mode.GOOGLE_ONLY
                "full" -> Mode.FULL
                "google_drive" -> Mode.GOOGLE_DRIVE
                else -> Mode.APPS_SCRIPT
            },
            listenHost = obj.optString("listen_host", "127.0.0.1"),
            listenPort = obj.optInt("listen_port", 8080),
            socks5Port = obj.optInt("socks5_port", 1081).takeIf { it > 0 },
            appsScriptUrls = urls,
            authKey = obj.optString("auth_key", ""),
            frontDomain = obj.optString("front_domain", "www.google.com"),
            sniHosts = sni,
            googleIp = obj.optString("google_ip", "142.251.36.68"),
            verifySsl = obj.optBoolean("verify_ssl", true),
            logLevel = obj.optString("log_level", "info"),
            parallelRelay = obj.optInt("parallel_relay", 1),
            upstreamSocks5 = obj.optString("upstream_socks5", ""),
            passthroughHosts = obj.optJSONArray("passthrough_hosts")?.let { arr ->
                buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
            }?.filter { it.isNotBlank() }.orEmpty(),
            connectionMode = when (obj.optString("connection_mode", "vpn_tun")) {
                "proxy_only" -> ConnectionMode.PROXY_ONLY
                else -> ConnectionMode.VPN_TUN
            },
            splitMode = when (obj.optString("split_mode", "all")) {
                "only" -> SplitMode.ONLY
                "except" -> SplitMode.EXCEPT
                else -> SplitMode.ALL
            },
            splitApps = obj.optJSONArray("split_apps")?.let { arr ->
                buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
            }?.filter { it.isNotBlank() }.orEmpty(),
            uiLang = when (obj.optString("ui_lang", "auto")) {
                "fa" -> UiLang.FA
                "en" -> UiLang.EN
                else -> UiLang.AUTO
            },
            driveCredentialsPath = obj.optString("drive_credentials_path", ""),
            driveFolderId = obj.optString("drive_folder_id", ""),
            driveFolderName = obj.optString("drive_folder_name", "MHRV-Drive"),
            driveClientId = obj.optString("drive_client_id", ""),
            drivePollMs = obj.optInt("drive_poll_ms", 500),
            driveFlushMs = obj.optInt("drive_flush_ms", 300),
            driveIdleTimeoutSecs = obj.optInt("drive_idle_timeout_secs", 300),
        )
    }
}

/**
 * Default SNI rotation pool. Mirrors `DEFAULT_GOOGLE_SNI_POOL` from the
 * Rust `domain_fronter` module — keep the lists in sync, or leave the
 * user's sniHosts empty and let Rust auto-expand.
 */
val DEFAULT_SNI_POOL: List<String> = listOf(
    "www.google.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "calendar.google.com",
    // accounts.google.com — originally listed as accounts.googl.com per
    // issue #42, but googl.com is NOT in Google's GFE cert SAN so TLS
    // validation fails with verify_ssl=true (PR #92). Replaced with
    // accounts.google.com which is covered by the *.google.com wildcard.
    "accounts.google.com",
    // Issue #47: same DPI-passing behaviour on MCI / Samantel.
    "scholar.google.com",
    // Ported from upstream Python FRONT_SNI_POOL_GOOGLE (commit 57738ec);
    // more rotation material for DPI-fingerprint spread and a couple of
    // SNIs (maps/play) that pass DPI where shorter *.google.com names don't.
    "maps.google.com",
    "chat.google.com",
    "translate.google.com",
    "play.google.com",
    "lens.google.com",
    // Issue #75.
    "chromewebstore.google.com",
)
