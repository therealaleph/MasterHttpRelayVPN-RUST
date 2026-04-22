package com.github.shadowsocks.bg

/**
 * JNI bridge to the tun2proxy crate's Android entry points.
 *
 * The tun2proxy Rust crate (already pulled in as an Android-only dep of
 * libmhrv_rs) defines its C entry points under this exact package path:
 *   Java_com_github_shadowsocks_bg_Tun2proxy_run
 *   Java_com_github_shadowsocks_bg_Tun2proxy_stop
 *
 * That's why this file lives at `com.github.shadowsocks.bg` — we did NOT
 * pick this package. Renaming it would break the JNI name mangling and
 * the native functions would fail to resolve at runtime.
 *
 * The crate is reusing Shadowsocks-Android's original JNI convention.
 *
 * NOTE: the tun2proxy JNI symbols live in libtun2proxy.so (not libmhrv_rs.so).
 * tun2proxy is pulled in as a Rust dep of mhrv-rs, but because nothing in
 * mhrv-rs calls these symbols directly, Rust's rlib-level dead-code
 * elimination drops them from libmhrv_rs.so. The cdylib variant of tun2proxy
 * (which rustc builds alongside the rlib) retains them, so we ship that .so
 * separately and load it explicitly here.
 */
object Tun2proxy {

    init {
        System.loadLibrary("tun2proxy")
    }

    /**
     * Start the TUN <-> proxy bridge.
     *
     * @param proxyUrl e.g. "socks5://127.0.0.1:1081"
     * @param tunFd raw fd from VpnService.Builder#establish().detachFd()
     * @param closeFdOnDrop whether tun2proxy should close the fd on shutdown.
     *                     We detach and hand over ownership, so this is true.
     * @param tunMtu MTU to match the VpnService setMtu() call.
     * @param verbosity 0=off, 1=error, 2=warn, 3=info, 4=debug, 5=trace.
     *                  Logs land in logcat under tag "tun2proxy".
     * @param dnsStrategy 0=Virtual (fake-IP DNS, tun2proxy resolves via proxy),
     *                    1=OverTcp (UDP DNS tunneled as TCP via proxy),
     *                    2=Direct (DNS goes straight through VpnService.protect).
     *                    Virtual is the right default here: app asks DNS for
     *                    example.com, gets a fake 198.18.x.y, tries to connect,
     *                    tun2proxy intercepts, knows the real hostname, opens
     *                    SOCKS5 to our proxy with "example.com:443" as target.
     *                    Our proxy does its own resolution via the Apps Script
     *                    relay, so this gives us end-to-end name resolution
     *                    without leaking plaintext DNS to the ISP.
     *
     * Returns 0 on normal shutdown, non-zero on error. BLOCKS until the TUN
     * is torn down or `stop()` is called — call this from a background thread.
     */
    @JvmStatic
    external fun run(
        proxyUrl: String,
        tunFd: Int,
        closeFdOnDrop: Boolean,
        tunMtu: Char,
        verbosity: Int,
        dnsStrategy: Int,
    ): Int

    /** Signals the running `run()` to shut down. Idempotent. */
    @JvmStatic
    external fun stop(): Int
}
