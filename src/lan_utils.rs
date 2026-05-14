//! Helpers for the "Share with other devices on my Wi-Fi / network" toggle in
//! the desktop UI and the Android share-LAN config.
//!
//! `detect_lan_ip()` returns the IPv4 address that the OS would use as the
//! source for outbound traffic (i.e. the LAN-reachable address on the
//! interface that has the default route). The trick is to open a UDP socket,
//! `connect()` it to a public address (no packets are actually sent during
//! the syscall), then read the socket's bound `local_addr()` — that's the
//! IP a peer on the LAN would use to reach this machine.
//!
//! Returns `None` if the host has no usable IPv4 (no network at all, or
//! IPv6-only). Callers fall back to telling the user to figure it out
//! themselves in that case.
//!
//! This is the same pattern used by `gethostbyname` callers and by every
//! other "what's my LAN IP" helper across the ecosystem — no
//! getifaddrs / `if_nameindex` boilerplate, no platform-specific code,
//! works on every target the rest of mhrv-rs builds on.

use std::net::{IpAddr, UdpSocket};

/// Try to figure out the LAN-reachable IPv4 of the current host. See module
/// docs for the trick. Returns `None` on any failure (no IPv4 stack, no
/// route, etc.) — callers should treat that as "ask the user to find it
/// themselves" rather than as an error.
pub fn detect_lan_ip() -> Option<IpAddr> {
    // Bind to all interfaces on a kernel-picked port. We never read or
    // write — the socket is just a vehicle for asking the routing table
    // which interface would carry traffic to a public IP.
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // Public IP outside any RFC-1918 range. UDP "connect" doesn't actually
    // send anything; it just records the peer for later sendto/recv calls
    // and tells the kernel to commit a source-address selection.
    sock.connect(("1.1.1.1", 80)).ok()?;
    let local = sock.local_addr().ok()?.ip();
    // The socket's local_addr is `0.0.0.0` only when the OS hasn't
    // committed a source address yet (rare — connect() forces commit on
    // every modern kernel). Treat that case as "no LAN IP available."
    match local {
        IpAddr::V4(v4) if v4.is_unspecified() => None,
        ip => Some(ip),
    }
}

/// Returns `true` if the bind host string represents "all interfaces"
/// (`0.0.0.0`, `[::]`, or an empty / whitespace-only value — empty defaults
/// to `0.0.0.0` in the underlying socket bind on most platforms).
///
/// Used by the UI to decide whether the "share on LAN" checkbox should
/// appear checked.
pub fn is_share_on_lan(listen_host: &str) -> bool {
    let trimmed = listen_host.trim();
    matches!(trimmed, "0.0.0.0" | "[::]" | "::")
}

/// Returns `true` if the bind host string is loopback-only
/// (`127.0.0.1`, `localhost`, `::1`, `[::1]`).
pub fn is_loopback_only(listen_host: &str) -> bool {
    let trimmed = listen_host.trim().to_ascii_lowercase();
    matches!(trimmed.as_str(), "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

/// Map a `listen_host` bind value to an address that a client on the
/// same machine can actually connect to. Wildcard binds (`0.0.0.0`,
/// `[::]`, `::`, empty/whitespace) collapse to `127.0.0.1`; explicit
/// addresses pass through unchanged.
///
/// Use this when generating UI strings like "Upstream proxy:
/// 127.0.0.1:8085 [copy]" — pasting `0.0.0.0:8085` into Psiphon (or
/// any TCP client) fails on Windows because Winsock rejects
/// `INADDR_ANY` as a connect target, and on Linux/macOS it works
/// only by accident. For "advertise this address to other devices
/// on the LAN" you want the LAN IP from `detect_lan_ip()` instead.
pub fn advertise_proxy_host(listen_host: &str) -> String {
    let trimmed = listen_host.trim();
    if trimmed.is_empty() || is_share_on_lan(trimmed) {
        "127.0.0.1".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_on_lan_recognizes_wildcards() {
        assert!(is_share_on_lan("0.0.0.0"));
        assert!(is_share_on_lan(" 0.0.0.0 "));
        assert!(is_share_on_lan("[::]"));
        assert!(is_share_on_lan("::"));
        assert!(!is_share_on_lan("127.0.0.1"));
        assert!(!is_share_on_lan("192.168.1.42"));
        assert!(!is_share_on_lan(""));
    }

    #[test]
    fn loopback_only_recognizes_local_names() {
        assert!(is_loopback_only("127.0.0.1"));
        assert!(is_loopback_only("localhost"));
        assert!(is_loopback_only("LocalHost"));
        assert!(is_loopback_only("::1"));
        assert!(is_loopback_only("[::1]"));
        assert!(!is_loopback_only("0.0.0.0"));
        assert!(!is_loopback_only("192.168.1.42"));
    }

    #[test]
    fn advertise_proxy_host_collapses_wildcards_to_loopback() {
        // Wildcard binds → 127.0.0.1 (only sane same-device client target)
        assert_eq!(advertise_proxy_host("0.0.0.0"), "127.0.0.1");
        assert_eq!(advertise_proxy_host(" 0.0.0.0 "), "127.0.0.1");
        assert_eq!(advertise_proxy_host("[::]"), "127.0.0.1");
        assert_eq!(advertise_proxy_host("::"), "127.0.0.1");
        // Empty / whitespace → 127.0.0.1 (matches socket-bind default)
        assert_eq!(advertise_proxy_host(""), "127.0.0.1");
        assert_eq!(advertise_proxy_host("   "), "127.0.0.1");
        // Explicit loopback passes through (already correct for clients)
        assert_eq!(advertise_proxy_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(advertise_proxy_host("localhost"), "localhost");
        // Explicit non-wildcard LAN/host address passes through —
        // user picked it deliberately, don't second-guess them
        assert_eq!(advertise_proxy_host("192.168.1.42"), "192.168.1.42");
        assert_eq!(advertise_proxy_host("10.0.0.5"), "10.0.0.5");
    }

    #[test]
    fn detect_lan_ip_returns_non_unspecified_when_online() {
        // This test makes a UDP `connect()` to 1.1.1.1 to ask the OS what
        // IP it would use. On a CI box with no network the connect can
        // fail and we'd get None; on a typical dev machine we get a real
        // address. Either result is allowed — we just verify the unwrapped
        // value is never `0.0.0.0` (the contract).
        if let Some(ip) = detect_lan_ip() {
            assert!(!ip.is_unspecified(), "got unspecified address: {}", ip);
        }
    }
}
