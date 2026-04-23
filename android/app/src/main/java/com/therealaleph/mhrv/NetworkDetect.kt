package com.therealaleph.mhrv

import java.net.Inet4Address
import java.net.InetAddress

/**
 * Helpers for figuring out which IP to actually connect to when the user
 * left the config on a stale `google_ip`.
 *
 * Google rotates the A record for `www.google.com` across their global
 * anycast pool; an IP that answered a year ago often 100% packet-drops
 * today from networks that are geo-homed somewhere else. Hardcoding any
 * single value in the config breaks new installs on all but one region.
 *
 * At Start time we ask Android's resolver for the current A record and
 * use that, falling back to whatever the user had configured only if the
 * resolver itself fails (no connectivity, DNS blocked, etc.). We
 * deliberately do this on the Kotlin side rather than inside the proxy:
 *   - It happens before we open the VPN TUN — so the resolver uses the
 *     underlying network, not our own VPN's Virtual DNS (which would
 *     loop).
 *   - The resolved IP gets persisted into `config.json`, so the next
 *     launch has a warm value even before auto-detection re-runs.
 */
object NetworkDetect {

    /**
     * Resolve `www.google.com` and return the first IPv4 A record as a
     * dotted-quad string, or null if resolution failed. IPv6 is skipped —
     * the outbound leg of our proxy is IPv4-only for now.
     *
     * BLOCKING — call from a background coroutine (Dispatchers.IO).
     */
    fun resolveGoogleIp(hostname: String = "www.google.com"): String? {
        return try {
            InetAddress.getAllByName(hostname)
                .filterIsInstance<Inet4Address>()
                .firstOrNull()
                ?.hostAddress
        } catch (_: Throwable) {
            null
        }
    }
}
