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

data class MhrvConfig(
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

    /** VPN_TUN (everything routed) vs PROXY_ONLY (user configures per-app). */
    val connectionMode: ConnectionMode = ConnectionMode.VPN_TUN,

    /** ALL / ONLY / EXCEPT — scope of app splitting inside VPN_TUN mode. */
    val splitMode: SplitMode = SplitMode.ALL,
    /** Package names used by ONLY and EXCEPT. Empty under ALL. */
    val splitApps: List<String> = emptyList(),

    /** UI language toggle. Non-Rust; honoured only by the Android wrapper. */
    val uiLang: UiLang = UiLang.AUTO,
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
            put("mode", "apps_script")
            put("listen_host", listenHost)
            put("listen_port", listenPort)
            socks5Port?.let { put("socks5_port", it) }

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
        }
        return obj.toString(2)
    }

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
            val obj = JSONObject(f.readText())

            val ids = obj.optJSONArray("script_ids")?.let { arr ->
                buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
            }?.filter { it.isNotBlank() }.orEmpty()
            // For display we turn each ID back into the full URL form —
            // easier to paste-verify, and the Kotlin side doesn't depend
            // on it (extractId re-parses on save).
            val urls = ids.map { "https://script.google.com/macros/s/$it/exec" }

            val sni = obj.optJSONArray("sni_hosts")?.let { arr ->
                buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
            }?.filter { it.isNotBlank() }.orEmpty()

            MhrvConfig(
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
                connectionMode = when (obj.optString("connection_mode", "vpn_tun")) {
                    "proxy_only" -> ConnectionMode.PROXY_ONLY
                    else -> ConnectionMode.VPN_TUN  // default for unknown/missing
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
            )
        } catch (_: Throwable) {
            MhrvConfig()
        }
    }

    fun save(ctx: Context, cfg: MhrvConfig) {
        val f = File(ctx.filesDir, FILE)
        f.writeText(cfg.toJson())
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
    // Issue #42: passes DPI on Samantel / MCI where the longer google.com
    // subdomains are selectively SNI-blocked. Must mirror the Rust list
    // in src/domain_fronter.rs exactly.
    "accounts.googl.com",
)
