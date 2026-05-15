//! Auto-discover edge IPs for a CDN fronting target.
//!
//! Given a hostname known to live on a multi-tenant CDN edge (e.g.
//! `python.org` on Fastly, `react.dev` on Vercel, `www.bbc.com` on
//! Akamai), this module resolves the hostname to its current A/AAAA
//! records and runs a TLS+SNI probe against each one. The successful
//! IPs can be dropped into a `FrontingGroup` so the user doesn't have
//! to dig around in `dig`/`nslookup` output or copy-paste an IP list
//! off a Telegram channel that may already be stale.
//!
//! The technique is self-healing: when the CDN rotates IPs (Akamai
//! does this constantly), re-running discovery picks up fresh ones.
//! And because GeoDNS returns the IP for the user's *own* region,
//! the IP is automatically the closest healthy PoP — typically a
//! better choice than a hardcoded global list.
//!
//! See [`crate::scan_sni`] for the same TLS-probe primitive used for
//! SNI-blocking checks against a fixed Google IP. This module uses
//! the inverse: a known SNI, probing every IP that resolves for it.
//!
//! Issues a strict cert verification so a misrouted edge that
//! happens to accept the TLS handshake but serves the wrong cert
//! (rare on production CDNs, common on transparent proxies / captive
//! portals) is reported as a failure rather than a false positive.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Per-step probe timeout. Both the TCP connect AND the TLS
/// handshake are bounded by this — they run sequentially per
/// IP, so the per-IP worst case is `2 * PROBE_TIMEOUT`. Healthy
/// CDN edges respond well under 500ms; anything taking 2s is
/// effectively dead from a user-perceptible-latency standpoint.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_CONCURRENCY: usize = 8;
/// Hard cap on how many resolved IPs we probe. DNS can return dozens
/// of addresses for large CDNs (Akamai routinely returns 8-16); on
/// some resolvers it can balloon. 24 is comfortably more than any
/// real-world response while bounding worst-case probe time.
///
/// Worst-case wall time, all timeouts paid: DNS (3s) plus
/// `ceil(24 / 8) = 3` probe waves of `2 * 2s = 4s` each = **15s
/// total**. JNI / UI surfaces document "blocks for up to ~15s"
/// rather than the more optimistic "a few seconds" the earlier
/// docstring claimed.
const MAX_IPS_PROBED: usize = 24;

/// Outcome of a single (IP, SNI) probe. `latency_ms` is set on success
/// (handshake completed AND cert was valid for the SNI); `error` is set
/// on any failure with a short human-readable reason.
#[derive(Debug, Clone)]
pub struct DiscoveredIp {
    pub ip: String,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

impl DiscoveredIp {
    pub fn is_ok(&self) -> bool {
        self.latency_ms.is_some()
    }
}

/// Result of one discovery run. `hostname` echoes the input (so the
/// caller can drop it straight into `FrontingGroup.sni` without
/// re-passing); `ips` is the list of probed IPs in latency order
/// (successful first, sorted ascending), with failed probes at the
/// end so the UI can still show *why* they failed.
#[derive(Debug, Clone)]
pub struct DiscoveredFront {
    pub hostname: String,
    pub ips: Vec<DiscoveredIp>,
}

impl DiscoveredFront {
    /// Returns the first reachable IP, if any. Convenience for the
    /// UI's common "single-IP per FrontingGroup" case.
    pub fn best_ip(&self) -> Option<&str> {
        self.ips.iter().find(|r| r.is_ok()).map(|r| r.ip.as_str())
    }

    /// Returns every reachable IP. Useful once `FrontingGroup` grows
    /// a rotation pool field.
    pub fn ok_ips(&self) -> Vec<&str> {
        self.ips
            .iter()
            .filter(|r| r.is_ok())
            .map(|r| r.ip.as_str())
            .collect()
    }
}

/// Resolve `hostname` to all A/AAAA records and TLS-probe each one
/// with `SNI=hostname`. Cert validation is strict — a probe is OK
/// only if the cert presented at the resolved IP is valid for the
/// hostname being probed.
pub async fn discover_front(hostname: &str) -> Result<DiscoveredFront, String> {
    let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() {
        return Err("hostname is empty".into());
    }
    // Reject anything that already parses as an IP — the whole point
    // of this module is to *discover* IPs. If the user already has
    // one they can put it straight in `FrontingGroup.ip`.
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return Err("expected a hostname, not an IP literal".into());
    }

    let resolve_target = format!("{}:443", hostname);
    let resolved = match tokio::time::timeout(
        DNS_TIMEOUT,
        tokio::net::lookup_host(resolve_target),
    )
    .await
    {
        Ok(Ok(iter)) => iter.collect::<Vec<_>>(),
        Ok(Err(e)) => return Err(format!("dns: {}", e)),
        Err(_) => return Err("dns timeout".into()),
    };

    // Dedup IPs while preserving the resolver's order — some CDNs
    // return A records in a deliberate per-client-rotated order, and
    // collapsing into a HashSet would lose that signal. Carry the
    // `IpAddr` instead of the bare string so IPv6 keeps its native
    // form: bracketed literals (`[::1]:443`) need explicit bracketing
    // when built from text, but `SocketAddr::new(IpAddr::V6, 443)`
    // displays correctly and parses correctly downstream.
    //
    // Filter to globally-routable public addresses BEFORE probing.
    // Otherwise a malicious DNS name pointed at `127.0.0.1` /
    // `169.254.169.254` (cloud-metadata!) / `192.168.0.0` would
    // turn this app into a local-network TLS probe. CDN edges
    // live on public space only; legitimate discovery never trips
    // the filter. See `is_public_routable_ip`.
    let mut seen = std::collections::HashSet::new();
    let mut filtered_count = 0u32;
    let ips: Vec<IpAddr> = resolved
        .into_iter()
        .map(|sa| sa.ip())
        .filter(|ip| {
            if !is_public_routable_ip(*ip) {
                filtered_count += 1;
                tracing::warn!(
                    "discover_front({}): dropped non-public IP {}",
                    hostname,
                    ip,
                );
                return false;
            }
            seen.insert(*ip)
        })
        .take(MAX_IPS_PROBED)
        .collect();

    if ips.is_empty() {
        // Distinguish "nothing resolved" from "everything resolved
        // was on a non-public range" so the UI's error can tell the
        // user *why* an answer with valid DNS records still came
        // back empty.
        if filtered_count > 0 {
            return Err(format!(
                "all {} resolved addresses were non-public (reserved / private / loopback). \
                 mhrv-rs only probes globally-routable IPs for CDN edges.",
                filtered_count,
            ));
        }
        return Err("dns: no addresses".into());
    }

    // One TLS config for the whole batch; per-probe cost is just the
    // TCP+TLS round-trip, no per-probe allocation in the hot path.
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let sem = Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
    let mut tasks = Vec::with_capacity(ips.len());
    for ip in ips.into_iter() {
        let connector = connector.clone();
        let sem = sem.clone();
        let hostname = hostname.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            probe_one(ip, &hostname, connector).await
        }));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(r) = t.await {
            results.push(r);
        }
    }

    // Sort: successes first (ascending latency), then failures.
    results.sort_by_key(|r| match r.latency_ms {
        Some(ms) => (0u8, ms),
        None => (1u8, u32::MAX),
    });

    Ok(DiscoveredFront {
        hostname,
        ips: results,
    })
}

/// True if `ip` is a globally-routable public address — safe to
/// probe for CDN-discovery. Returns false for any reserved /
/// special-use range, so a malicious or misconfigured DNS name
/// that resolves to `127.0.0.1`, `192.168.1.1`, `169.254.169.254`
/// (cloud metadata service!), `::1`, `fe80::…`, or an RFC-1918
/// peer can't turn this app into a local-network TLS probe.
///
/// Conservative on purpose: anything we can't positively identify
/// as "public unicast" is excluded. Real CDN edges only sit on
/// public space, so legitimate discovery never trips this.
///
/// IPv4 ranges rejected:
///   - 0.0.0.0/8       unspecified / "this network"
///   - 10.0.0.0/8      RFC1918 private
///   - 100.64.0.0/10   RFC6598 CGNAT shared
///   - 127.0.0.0/8     loopback
///   - 169.254.0.0/16  link-local (incl. cloud-metadata 169.254.169.254)
///   - 172.16.0.0/12   RFC1918 private
///   - 192.0.0.0/24    IETF protocol assignments
///   - 192.0.2.0/24    TEST-NET-1 documentation
///   - 192.168.0.0/16  RFC1918 private
///   - 198.18.0.0/15   network benchmark testing (RFC2544)
///   - 198.51.100.0/24 TEST-NET-2 documentation
///   - 203.0.113.0/24  TEST-NET-3 documentation
///   - 224.0.0.0/4     multicast (Class D)
///   - 240.0.0.0/4     reserved (Class E) incl. broadcast 255.255.255.255
///
/// IPv6 strategy is the inverse — *allowlist* global unicast
/// (`2000::/3`) only, then carve out the documented special-use
/// subranges. This catches the entire `0::/3`, `4000::/3`,
/// `6000::/3`, `8000::/3`, `a000::/3`, `c000::/3`, `e000::/3`
/// reserved blocks in one check, including:
///   - ::, ::1, IPv4-compat (`::a.b.c.d`), IPv4-mapped (`::ffff:0:0/96`)
///   - NAT64 well-known `64:ff9b::/96` (RFC 6052) and local-use
///     `64:ff9b:1::/48` (RFC 8215). A malicious DNS answer like
///     `64:ff9b::a9fe:a9fe` would otherwise route to
///     `169.254.169.254` (cloud metadata) via the operator's NAT64.
///   - fc00::/7 ULA, fe80::/10 link-local, ff00::/8 multicast,
///     fec0::/10 (deprecated site-local), 100::/64 discard
///
/// Then within `2000::/3`, reject:
///   - 2001:0000::/32  Teredo (RFC 4380)
///   - 2001:0020::/28  ORCHIDv2 (RFC 7343)
///   - 2001:db8::/32   documentation (RFC 3849)
///   - 2002::/16       6to4 (RFC 3056, deprecated by RFC 7526)
///
/// IPv4-mapped (`::ffff:0:0/96`) is the one IPv6 form we let
/// reach the v4 branch — `to_ipv4_mapped` extracts the inner
/// address and `is_public_v4` decides — because some socket
/// APIs hand back v4 destinations in that form.
fn is_public_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return false;
    }
    let [a, b, _c, _d] = ip.octets();
    // 0.0.0.0/8 — "this network" (RFC 1122). is_unspecified() only
    // matches the exact 0.0.0.0 address, but the whole /8 is reserved.
    if a == 0 {
        return false;
    }
    // 100.64.0.0/10 — CGNAT (RFC 6598). Not covered by is_private.
    if a == 100 && (b & 0xC0) == 64 {
        return false;
    }
    // 192.0.0.0/24 — IETF protocol assignments.
    if a == 192 && b == 0 && _c == 0 {
        return false;
    }
    // 198.18.0.0/15 — RFC 2544 benchmarking.
    if a == 198 && (b & 0xFE) == 18 {
        return false;
    }
    // 240.0.0.0/4 — Class E reserved. is_broadcast covers only
    // the exact 255.255.255.255 address; the rest of /4 is also
    // unrouted and worth excluding for a probe target.
    if (a & 0xF0) == 0xF0 {
        return false;
    }
    true
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let segs = ip.segments();

    // Allowlist global unicast (2000::/3) only. IANA reserves
    // `2000::/3` for global unicast (RFC 4291 §2.4); every other
    // /3 block is special-use. This single check eliminates a
    // class of bypasses that a per-range denylist keeps missing:
    //
    //   - 0::/3 includes ::, ::1, IPv4-compat (`::a.b.c.d`),
    //     IPv4-mapped (`::ffff:0:0/96`), and critically the
    //     NAT64 well-known prefixes `64:ff9b::/96` and
    //     `64:ff9b:1::/48` (RFC 6052 / RFC 8215). A NAT64
    //     gateway translates `64:ff9b::a9fe:a9fe` outward to
    //     `169.254.169.254` (cloud-metadata!), and
    //     `64:ff9b::c0a8:0101` to `192.168.1.1`. Letting
    //     these through means a malicious DNS response can
    //     steer probes at private/translatable destinations
    //     via the operator's NAT64.
    //   - c000::/3 holds fc00::/7 (ULA), fe80::/10 (link-local).
    //   - e000::/3 holds ff00::/8 (multicast), fec0::/10
    //     (deprecated site-local).
    //
    // IPv4-mapped addresses (`::ffff:0:0/96`) ARE legitimate but
    // are handled in `is_public_routable_ip` via
    // `to_ipv4_mapped` *before* we reach here, so by this point
    // an address in 0::/3 is either NAT64, IPv4-compat, or
    // similar — all unsafe to probe blindly.
    if (segs[0] & 0xE000) != 0x2000 {
        return false;
    }

    // Within 2000::/3, reject the documented special-use
    // subranges that route somewhere unexpected:

    // 2001:0000::/32 — Teredo (RFC 4380). NAT-traversal tunnel
    // carrying inner IPv4; no production CDN edge uses Teredo.
    if segs[0] == 0x2001 && segs[1] == 0x0000 {
        return false;
    }
    // 2001:0020::/28 — ORCHIDv2 (RFC 7343). Cryptographic
    // identifiers, not routable destinations.
    if segs[0] == 0x2001 && (segs[1] & 0xFFF0) == 0x0020 {
        return false;
    }
    // 2001:db8::/32 — documentation (RFC 3849).
    if segs[0] == 0x2001 && segs[1] == 0x0DB8 {
        return false;
    }
    // 2002::/16 — 6to4 (RFC 3056). Encodes an arbitrary IPv4 in
    // bits 16-47, including reserved/private ranges. Even if
    // the kernel routes it correctly, we don't want to probe a
    // 6to4 anycast relay. Deprecated since 2015 (RFC 7526);
    // any modern CDN edge has a real 2000::/3 address.
    if segs[0] == 0x2002 {
        return false;
    }

    true
}

async fn probe_one(ip: IpAddr, sni: &str, connector: TlsConnector) -> DiscoveredIp {
    let ip_str = ip.to_string();
    let mk_err = |msg: String| DiscoveredIp {
        ip: ip_str.clone(),
        latency_ms: None,
        error: Some(msg),
    };

    // `SocketAddr::new` handles v4 and v6 uniformly — the textual form
    // `IpAddr::V6 + ":443"` would need explicit brackets, which we
    // dodge entirely by building the SocketAddr directly.
    let addr = SocketAddr::new(ip, 443);

    let server_name = match ServerName::try_from(sni.to_string()) {
        Ok(n) => n,
        Err(e) => return mk_err(format!("bad sni: {}", e)),
    };

    let started = Instant::now();
    let tcp = match tokio::time::timeout(
        PROBE_TIMEOUT,
        tokio::net::TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return mk_err(format!("connect: {}", e)),
        Err(_) => return mk_err("connect timeout".into()),
    };
    let _ = tcp.set_nodelay(true);

    match tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp)).await {
        Ok(Ok(_)) => {
            let ms = started.elapsed().as_millis() as u32;
            DiscoveredIp {
                ip: ip.to_string(),
                latency_ms: Some(ms),
                error: None,
            }
        }
        Ok(Err(e)) => {
            // Cert mismatch lives here too — rustls returns it as a
            // connect-time error with a descriptive InvalidCertificate
            // payload. The whole point of strict validation is that we
            // *reject* misrouting (an IP that answers but isn't the
            // CDN edge for this hostname).
            //
            // Truncate on char boundaries (not bytes) — rustls error
            // strings can contain non-ASCII in some locale-aware
            // configurations; slicing by bytes panics mid-codepoint.
            let emsg = e.to_string();
            let mut iter = emsg.chars();
            let head: String = iter.by_ref().take(80).collect();
            let short = if iter.next().is_some() {
                format!("{}…", head)
            } else {
                head
            };
            mk_err(format!("tls: {}", short))
        }
        Err(_) => mk_err("tls handshake timeout".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_empty_hostname() {
        let err = discover_front("").await.unwrap_err();
        assert!(err.contains("empty"), "got: {}", err);
        let err = discover_front("   ").await.unwrap_err();
        assert!(err.contains("empty"), "got: {}", err);
    }

    #[tokio::test]
    async fn rejects_ip_literal() {
        // Whole point of discovery is finding IPs from a hostname —
        // an IP-literal input is a user error, not a hostname to
        // resolve. Surface that rather than silently "discovering"
        // the same IP back. Tests both v4 and v6 literal forms.
        let err = discover_front("1.1.1.1").await.unwrap_err();
        assert!(err.to_lowercase().contains("ip literal"), "got: {}", err);
        let err = discover_front("::1").await.unwrap_err();
        assert!(err.to_lowercase().contains("ip literal"), "got: {}", err);
    }

    #[tokio::test]
    async fn discovered_front_best_ip_picks_first_ok() {
        let df = DiscoveredFront {
            hostname: "example.test".into(),
            ips: vec![
                DiscoveredIp { ip: "10.0.0.1".into(), latency_ms: None, error: Some("connect timeout".into()) },
                DiscoveredIp { ip: "10.0.0.2".into(), latency_ms: Some(50), error: None },
                DiscoveredIp { ip: "10.0.0.3".into(), latency_ms: Some(80), error: None },
            ],
        };
        assert_eq!(df.best_ip(), Some("10.0.0.2"));
        assert_eq!(df.ok_ips(), vec!["10.0.0.2", "10.0.0.3"]);
    }

    #[test]
    fn is_public_routable_ip_rejects_reserved_ranges() {
        // IPv4 — every reserved range we filter, plus a sample
        // of cloud-provider IPs that MUST pass (regression guard
        // for "we got too aggressive and dropped real CDN edges").
        let bad_v4 = [
            "0.0.0.0",          // unspecified
            "0.1.2.3",          // 0.0.0.0/8
            "10.0.0.1",         // RFC1918
            "10.255.255.255",
            "100.64.0.1",       // CGNAT
            "100.127.255.254",
            "127.0.0.1",        // loopback
            "127.10.20.30",
            "169.254.169.254",  // cloud metadata!
            "172.16.0.1",       // RFC1918
            "172.31.255.254",
            "192.0.0.1",        // IETF protocol
            "192.0.2.99",       // TEST-NET-1
            "192.168.1.1",      // RFC1918
            "198.18.0.1",       // benchmarking
            "198.19.255.254",
            "198.51.100.1",     // TEST-NET-2
            "203.0.113.1",      // TEST-NET-3
            "224.0.0.1",        // multicast
            "239.255.255.255",
            "240.0.0.1",        // Class E
            "255.255.255.255",  // broadcast
        ];
        for s in bad_v4 {
            let ip: IpAddr = s.parse().unwrap();
            assert!(
                !is_public_routable_ip(ip),
                "{} should be rejected as non-public",
                s,
            );
        }

        // Real CDN edges (Akamai, Fastly, Cloudflare, Google) and
        // assorted public unicast — must pass.
        let good_v4 = [
            "1.1.1.1",          // Cloudflare DNS
            "8.8.8.8",          // Google DNS
            "151.101.0.223",    // Fastly
            "2.22.151.143",     // Akamai (the IPs from the user's Twitter list)
            "76.76.21.21",      // Vercel
            "172.15.0.1",       // just outside RFC1918 172.16/12
            "172.32.0.1",       // also outside
            "100.63.255.254",   // just outside CGNAT 100.64/10
            "100.128.0.1",      // also outside
        ];
        for s in good_v4 {
            let ip: IpAddr = s.parse().unwrap();
            assert!(
                is_public_routable_ip(ip),
                "{} should be accepted as public",
                s,
            );
        }
    }

    #[test]
    fn is_public_routable_ip_rejects_reserved_v6_ranges() {
        let bad_v6 = [
            "::",                       // unspecified
            "::1",                       // loopback
            "::ffff:127.0.0.1",          // v4-mapped loopback — must re-check
            "::ffff:192.168.1.1",        // v4-mapped private
            "::1.2.3.4",                 // IPv4-compatible (0::/96, deprecated)
            "fe80::1",                   // link-local
            "febf:ffff:ffff::1",         // still link-local fe80::/10
            "fc00::1",                   // ULA
            "fd00::1",                   // ULA
            "ff02::1",                   // multicast
            "ff00::abc",
            "fec0::1",                   // deprecated site-local
            "2001:db8::1",               // documentation
            "2001:db8:ffff::1",
            "100::1",                    // discard
        ];
        for s in bad_v6 {
            let ip: IpAddr = s.parse().unwrap();
            assert!(
                !is_public_routable_ip(ip),
                "{} should be rejected as non-public",
                s,
            );
        }

        let good_v6 = [
            "2606:4700:4700::1111", // Cloudflare
            "2001:4860:4860::8888", // Google
            "2620:fe::fe",          // Quad9
            "::ffff:1.1.1.1",       // v4-mapped public
        ];
        for s in good_v6 {
            let ip: IpAddr = s.parse().unwrap();
            assert!(
                is_public_routable_ip(ip),
                "{} should be accepted as public",
                s,
            );
        }
    }

    #[test]
    fn is_public_routable_ip_rejects_v6_transition_and_special_use() {
        // Specific attack vectors that earlier versions of the
        // filter missed. NAT64 / 6to4 / Teredo can carry an
        // arbitrary v4 destination as a sub-payload of the v6
        // address; a malicious DNS reply pointing at one of
        // these routes our probe to the embedded v4 target
        // (potentially a private / loopback / cloud-metadata
        // address) without ever going through the v4 filter.
        let must_reject = [
            // NAT64 well-known prefix (RFC 6052), embedded v4 = cloud
            // metadata 169.254.169.254. Without this rule the kernel
            // would route via the operator's NAT64 gateway, which
            // translates outward to the embedded v4 — directly hitting
            // the cloud instance metadata service.
            "64:ff9b::a9fe:a9fe",
            // NAT64 well-known, embedded v4 = 192.168.1.1 (RFC 1918).
            "64:ff9b::c0a8:101",
            // NAT64 well-known, embedded v4 = 127.0.0.1 (loopback).
            "64:ff9b::7f00:1",
            // NAT64 local-use prefix (RFC 8215), embedded v4 = same.
            "64:ff9b:1::a9fe:a9fe",
            "64:ff9b:1:abcd::a9fe:a9fe",
            // 6to4 (RFC 3056) — first 32 bits AFTER 2002 are the
            // embedded IPv4. 2002:c0a8:0101:: encodes 192.168.1.1.
            "2002:c0a8:101::1",
            // Any 2002::/16 — deprecated entirely.
            "2002::1",
            // Teredo (RFC 4380) — 2001:0000::/32. Inner IPv4 server
            // and client encoded in later bits; not a real CDN.
            "2001:0:0:0:0:0:0:1",
            "2001::abc",
            // ORCHIDv2 (RFC 7343) — 2001:20::/28. Cryptographic
            // identifiers, not routable destinations.
            "2001:20::1",
            "2001:2f::1",
        ];
        for s in must_reject {
            let ip: IpAddr = s.parse().unwrap();
            assert!(
                !is_public_routable_ip(ip),
                "{} should be rejected: maps/translates to a non-public destination",
                s,
            );
        }
    }

    #[test]
    fn ipv6_socket_addr_construction_brackets_correctly() {
        // Regression guard for the IPv6 probe bug.
        //
        // An earlier version of `probe_one` built its SocketAddr
        // from `format!("{}:443", ip).parse()`. For IPv4 (`1.2.3.4`)
        // that produced `1.2.3.4:443` which parses fine. For IPv6
        // (`::1`) it produced `::1:443` — invalid syntax, since
        // IPv6 needs bracketing (`[::1]:443`), so every AAAA result
        // came back as `bad ip: invalid socket address syntax`.
        //
        // The fix uses `SocketAddr::new(IpAddr, 443)` directly,
        // which handles both families with no string roundtrip.
        // This test pins that — no real network is touched; the
        // assertion is purely on the textual form so it's
        // deterministic in any environment.
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(SocketAddr::new(v4, 443).to_string(), "1.2.3.4:443");

        let v6_loop: IpAddr = "::1".parse().unwrap();
        assert_eq!(SocketAddr::new(v6_loop, 443).to_string(), "[::1]:443");

        let v6_full: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            SocketAddr::new(v6_full, 443).to_string(),
            "[2001:db8::1]:443",
        );
    }

    #[tokio::test]
    async fn discovered_front_best_ip_none_when_all_fail() {
        let df = DiscoveredFront {
            hostname: "example.test".into(),
            ips: vec![
                DiscoveredIp { ip: "10.0.0.1".into(), latency_ms: None, error: Some("x".into()) },
            ],
        };
        assert_eq!(df.best_ip(), None);
        assert!(df.ok_ips().is_empty());
    }
}
