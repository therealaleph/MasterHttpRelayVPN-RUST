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
 * - [DIRECT] — no Apps Script relay. Only the SNI-rewrite tunnel is
 *   active: Google edge by default, plus any user-configured
 *   `fronting_groups` (Vercel, Fastly, …). Useful as a bootstrap to
 *   reach `script.google.com` and deploy Code.gs, or as a standalone
 *   mode for users who only need fronting-group targets. No Deployment
 *   ID / Auth key needed. Non-matching traffic goes raw (no relay).
 *   Was named `GOOGLE_ONLY` before fronting_groups was added — the
 *   string `"google_only"` is still accepted on parse for back-compat.
 * - [FULL] — full tunnel mode. ALL traffic is tunneled end-to-end through
 *   Apps Script + a remote tunnel node. No certificate installation needed.
 */
enum class Mode { APPS_SCRIPT, DIRECT, FULL }

data class MhrvConfig(
    val mode: Mode = Mode.APPS_SCRIPT,

    val listenHost: String = "0.0.0.0",
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
    /**
     * Disable the HTTP/2 multiplexing on the Apps Script relay leg.
     * Default false (h2 active); flip to true to force the legacy
     * HTTP/1.1 keep-alive pool. Round-tripped from config.json so a
     * hand-edited kill switch survives a save round trip from the
     * Android UI. See `src/config.rs` `force_http1`.
     */
    val forceHttp1: Boolean = false,
    val coalesceStepMs: Int = 10,
    val coalesceMaxMs: Int = 1000,
    /** Block QUIC (UDP/443). QUIC over TCP tunnel causes meltdown. */
    val blockQuic: Boolean = true,
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

    /**
     * Opt-out for the DoH bypass. The Rust default is to bypass DoH
     * traffic (chrome.cloudflare-dns.com, dns.google, etc.) directly
     * instead of routing it through the Apps Script tunnel — DoH
     * already encrypts queries, so the tunnel was just adding ~2 s
     * per name lookup with no real privacy gain. Set this to true to
     * keep DoH inside the tunnel. See `src/config.rs` `tunnel_doh`.
     */
    val tunnelDoh: Boolean = true,

    /**
     * Extra hostnames added to the built-in DoH default list. Same
     * matching shape as `passthroughHosts` (exact or leading-dot
     * suffix). Use to cover private / enterprise DoH endpoints.
     */
    val bypassDohHosts: List<String> = emptyList(),

    /**
     * When true, reject all connections to known DoH endpoints.
     * Browsers fall back to system DNS (tun2proxy virtual DNS — instant).
     * Takes priority over tunnel_doh / bypass_doh.
     */
    val blockDoh: Boolean = true,

    /** VPN_TUN (everything routed) vs PROXY_ONLY (user configures per-app). */
    val connectionMode: ConnectionMode = ConnectionMode.VPN_TUN,

    /** ALL / ONLY / EXCEPT — scope of app splitting inside VPN_TUN mode. */
    val splitMode: SplitMode = SplitMode.ALL,
    /** Package names used by ONLY and EXCEPT. Empty under ALL. */
    val splitApps: List<String> = emptyList(),

    /**
     * Route YouTube traffic through Apps Script relay instead of the
     * SNI-rewrite tunnel. Avoids Google SafeSearch-on-SNI / restricted
     * mode, but slower for video. Maps to Rust `youtube_via_relay`.
     */
    val youtubeViaRelay: Boolean = false,

    /** UI language toggle. Non-Rust; honoured only by the Android wrapper. */
    val uiLang: UiLang = UiLang.AUTO,

    /**
     * Verbatim JSON for any config.json key this build doesn't model
     * (e.g. desktop-only `fronting_groups`, `exit_node`,
     * `request_timeout_secs`, `disable_padding`, `auto_blacklist_*`,
     * `hosts`, `normalize_x_graphql`, and any future Rust-side field
     * added before Android catches up).
     *
     * Captured by [ConfigStore.loadFromJson] and re-emitted by
     * [toJson] so a Rust-shaped or future-shaped config survives a
     * round-trip through the Android UI **without losing fields the
     * native runtime still needs**. The whole point of the Profile
     * "raw snapshot preservation" invariant is that the Rust side
     * sees those fields — and the Rust side reads `config.json`,
     * which is what we write here.
     *
     * Stored as a JSON object string (not Map) so we can splice it
     * back in via [JSONObject.put] without retyping every key.
     * Default empty = no passthrough fields.
     *
     * Excluded from [toJson]'s output when blank.
     */
    val extrasJson: String = "",
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
                Mode.DIRECT -> "direct"
                Mode.FULL -> "full"
            })
            put("listen_host", listenHost)
            put("listen_port", listenPort)
            socks5Port?.let { put("socks5_port", it) }

            // In direct mode these are unused by the Rust side, but we
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
            if (forceHttp1) put("force_http1", true)
            if (coalesceStepMs != 10) put("coalesce_step_ms", coalesceStepMs)
            if (coalesceMaxMs != 1000) put("coalesce_max_ms", coalesceMaxMs)
            put("block_quic", blockQuic)
            if (upstreamSocks5.isNotBlank()) {
                put("upstream_socks5", upstreamSocks5.trim())
            }
            if (passthroughHosts.isNotEmpty()) {
                put("passthrough_hosts", JSONArray().apply { passthroughHosts.forEach { put(it) } })
            }
            put("tunnel_doh", tunnelDoh)
            put("block_doh", blockDoh)
            if (youtubeViaRelay) put("youtube_via_relay", true)
            // Trim/drop-empty/dedupe before serializing — symmetric with the
            // read-side normalization in loadFromJson(), so a user typing
            // " doh.foo " or accidentally adding a duplicate doesn't end up
            // in the saved JSON.
            val cleanBypassDohHosts = bypassDohHosts
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
            if (cleanBypassDohHosts.isNotEmpty()) {
                put("bypass_doh_hosts", JSONArray().apply { cleanBypassDohHosts.forEach { put(it) } })
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

            // Splice back any keys this build doesn't model (so they
            // survive a load → edit → save round-trip and reach the
            // native runtime, which IS the source of truth for them).
            // We deliberately don't overwrite our modelled keys — if a
            // future build models a field that's currently in extras,
            // the new modelled value wins on the next save.
            if (extrasJson.isNotBlank()) {
                try {
                    val ex = JSONObject(extrasJson)
                    val it = ex.keys()
                    while (it.hasNext()) {
                        val k = it.next()
                        if (!has(k)) put(k, ex.get(k))
                    }
                } catch (_: Throwable) {
                    // Malformed extras — drop. Captured-at-parse-time
                    // extras should never be malformed; this guard is
                    // for the synthetic-cfg path (decode()).
                }
            }
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
            loadFromJson(JSONObject(f.readText()))
        } catch (_: Throwable) {
            MhrvConfig()
        }
    }

    /**
     * Persist [cfg] to `config.json`. Returns true on success.
     *
     * Atomicity: writes to `config.json.tmp` and replaces via the same
     * NIO/backup pattern as [ProfileStore.save] — never deletes the
     * existing file without a backup. On failure the previous
     * `config.json` is preserved untouched (or restored from `.bak`).
     */
    fun save(ctx: Context, cfg: MhrvConfig): Boolean {
        val f = File(ctx.filesDir, FILE)
        val tmp = File(ctx.filesDir, "$FILE.tmp")
        return try {
            tmp.writeText(cfg.toJson())
            ProfileStore.atomicReplacePublic(tmp, f)
        } catch (_: Throwable) {
            tmp.delete()
            false
        }
    }

    /** Prefix for encoded config strings so we can detect them in clipboard. */
    private const val HASH_PREFIX = "mhrv-rs://"

    /** Encode config as a shareable base64 string with prefix.
     *  Only includes non-default fields to keep the hash short. */
    fun encode(cfg: MhrvConfig): String {
        val defaults = MhrvConfig()
        val obj = JSONObject()

        // Always include essential fields.
        obj.put("mode", when (cfg.mode) {
            Mode.APPS_SCRIPT -> "apps_script"
            Mode.DIRECT -> "direct"
            Mode.FULL -> "full"
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
        if (cfg.forceHttp1 != defaults.forceHttp1) obj.put("force_http1", cfg.forceHttp1)
        if (cfg.coalesceStepMs != defaults.coalesceStepMs) obj.put("coalesce_step_ms", cfg.coalesceStepMs)
        if (cfg.coalesceMaxMs != defaults.coalesceMaxMs) obj.put("coalesce_max_ms", cfg.coalesceMaxMs)
        if (cfg.blockQuic != defaults.blockQuic) obj.put("block_quic", cfg.blockQuic)
        if (cfg.upstreamSocks5.isNotBlank()) obj.put("upstream_socks5", cfg.upstreamSocks5)
        if (cfg.passthroughHosts.isNotEmpty()) obj.put("passthrough_hosts", JSONArray().apply { cfg.passthroughHosts.forEach { put(it) } })
        if (cfg.tunnelDoh != defaults.tunnelDoh) obj.put("tunnel_doh", cfg.tunnelDoh)
        if (cfg.blockDoh != defaults.blockDoh) obj.put("block_doh", cfg.blockDoh)
        if (cfg.youtubeViaRelay != defaults.youtubeViaRelay) obj.put("youtube_via_relay", cfg.youtubeViaRelay)
        val cleanBypassDohHosts = cfg.bypassDohHosts
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        if (cleanBypassDohHosts.isNotEmpty()) {
            obj.put("bypass_doh_hosts", JSONArray().apply { cleanBypassDohHosts.forEach { put(it) } })
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
                if (!hasConfigShape(obj)) null else loadFromJson(obj)
            } catch (_: Throwable) { null }
        }
        // Try mhrv:// base64 encoded (possibly DEFLATE-compressed).
        val payload = if (trimmed.startsWith(HASH_PREFIX)) trimmed.removePrefix(HASH_PREFIX) else trimmed
        return try {
            val raw = android.util.Base64.decode(payload, android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE)
            val text = inflateOrRaw(raw)
            val obj = JSONObject(text)
            if (!hasConfigShape(obj)) return null
            loadFromJson(obj)
        } catch (_: Throwable) {
            null
        }
    }

    /** Check if a string looks like an encoded mhrv config. */
    fun looksLikeConfig(text: String): Boolean {
        val t = text.trim()
        if (t.startsWith(HASH_PREFIX)) return true
        if (t.startsWith("{")) {
            return try { hasConfigShape(JSONObject(t)) } catch (_: Throwable) { false }
        }
        return false
    }

    /**
     * Acceptance gate for "is this JSON shaped like an mhrv config?".
     * Accepts any of `mode`, `auth_key`, `script_id` (Rust output),
     * or `script_ids` (legacy Android output). `script_id` was added
     * after the parser was taught to read both shapes — without it,
     * a Rust-shaped config with only `script_id` would be rejected
     * here even though [loadFromJson] could read it fine.
     */
    private fun hasConfigShape(obj: JSONObject): Boolean =
        obj.has("mode") ||
            obj.has("auth_key") ||
            obj.has("script_id") ||
            obj.has("script_ids")

    /**
     * Keys this build models. Anything outside this set is captured
     * into [MhrvConfig.extrasJson] at parse time and re-emitted by
     * [MhrvConfig.toJson] so the native runtime keeps seeing
     * desktop-only / future Rust-side fields (`fronting_groups`,
     * `exit_node`, `request_timeout_secs`, `disable_padding`,
     * `auto_blacklist_*`, `hosts`, `normalize_x_graphql`,
     * `google_ip_validation`, `scan_batch_size`, etc.).
     *
     * Updating this set is a deliberate act — add a key here only
     * when [MhrvConfig] gains a real field for it.
     */
    private val MODELLED_KEYS: Set<String> = setOf(
        "mode",
        "listen_host", "listen_port", "socks5_port",
        // Both script_id (Rust output) and script_ids (legacy Android
        // output) are read by us, so both belong in the "modelled" set
        // — otherwise a Rust-shaped config would have its IDs end up
        // in extras AND in the parsed appsScriptUrls, getting written
        // out twice (once as the unmodelled passthrough, once as
        // script_ids).
        "script_id", "script_ids",
        "auth_key",
        "front_domain", "sni_hosts", "google_ip",
        "verify_ssl", "log_level", "parallel_relay",
        "force_http1",
        "coalesce_step_ms", "coalesce_max_ms",
        "block_quic", "upstream_socks5",
        "passthrough_hosts",
        "tunnel_doh", "bypass_doh_hosts", "block_doh",
        "youtube_via_relay",
        "connection_mode", "split_mode", "split_apps", "ui_lang",
        // Phone-scoped scan defaults toJson() emits. Modelled so they
        // don't round-trip into extras then collide with toJson's
        // explicit puts.
        "fetch_ips_from_api", "max_ips_to_scan",
    )

    /** Parse config from a JSON object — shared by load() and decode(). */
    private fun loadFromJson(obj: JSONObject): MhrvConfig {
        // Read deployment IDs from both `script_id` (Rust output) and
        // `script_ids` (legacy Android output). Each can be a scalar
        // string OR an array of strings.
        val ids = buildList<String> {
            addAll(readScriptIdList(obj, "script_id"))
            addAll(readScriptIdList(obj, "script_ids"))
        }.filter { it.isNotBlank() }.distinct()
        val urls = ids.map { "https://script.google.com/macros/s/$it/exec" }
        val sni = obj.optJSONArray("sni_hosts")?.let { arr ->
            buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
        }?.filter { it.isNotBlank() }.orEmpty()

        // Capture anything we don't model into extras for passthrough
        // (raw-snapshot preservation invariant — the native runtime
        // reads config.json directly and needs every field).
        val extras = JSONObject()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            if (k !in MODELLED_KEYS) extras.put(k, obj.get(k))
        }
        val extrasStr = if (extras.length() > 0) extras.toString() else ""

        return MhrvConfig(
            mode = when (obj.optString("mode", "apps_script")) {
                "direct" -> Mode.DIRECT
                // Deprecated alias kept forever for back-compat with
                // configs written before the rename.
                "google_only" -> Mode.DIRECT
                "full" -> Mode.FULL
                else -> Mode.APPS_SCRIPT
            },
            listenHost = obj.optString("listen_host", "0.0.0.0"),
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
            forceHttp1 = obj.optBoolean("force_http1", false),
            coalesceStepMs = obj.optInt("coalesce_step_ms", 10),
            coalesceMaxMs = obj.optInt("coalesce_max_ms", 1000),
            blockQuic = obj.optBoolean("block_quic", true),
            upstreamSocks5 = obj.optString("upstream_socks5", ""),
            passthroughHosts = obj.optJSONArray("passthrough_hosts")?.let { arr ->
                buildList { for (i in 0 until arr.length()) add(arr.optString(i)) }
            }?.filter { it.isNotBlank() }.orEmpty(),
            tunnelDoh = obj.optBoolean("tunnel_doh", true),
            blockDoh = obj.optBoolean("block_doh", true),
            youtubeViaRelay = obj.optBoolean("youtube_via_relay", false),
            bypassDohHosts = obj.optJSONArray("bypass_doh_hosts")?.let { arr ->
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
            extrasJson = extrasStr,
        )
    }

    /**
     * Read a list of deployment IDs from `key`. Accepts:
     *   - a JSON string scalar ("abc")
     *   - a JSON array of strings (["abc","def"])
     *
     * Mirrors the Rust [ScriptId] enum's `untagged` deserialize so both
     * shapes interop with desktop. Returns an empty list if the key
     * is absent or shaped wrong.
     */
    private fun readScriptIdList(obj: JSONObject, key: String): List<String> {
        if (!obj.has(key)) return emptyList()
        // Array form first.
        obj.optJSONArray(key)?.let { arr ->
            return buildList {
                for (i in 0 until arr.length()) {
                    val s = arr.optString(i, "")
                    if (s.isNotBlank()) add(s)
                }
            }
        }
        // Scalar form.
        val s = obj.optString(key, "")
        return if (s.isNotBlank()) listOf(s) else emptyList()
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
