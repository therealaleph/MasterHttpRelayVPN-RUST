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
)
