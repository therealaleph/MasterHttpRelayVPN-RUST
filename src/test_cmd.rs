//! `mhrv-rs test` — end-to-end probe of the Apps Script relay.
//!
//! Sends one GET through the relay to api.ipify.org and verifies the
//! response is a real IP-lookup response, not just any HTTP 200. Emits
//! both `println!` (visible on the CLI terminal) and `tracing::info!` /
//! `warn!` / `error!` (visible in the UI's Recent log panel) — so the UI
//! user gets actionable feedback when a test fails.
//!
//! The stricter PASS criteria (body-shape verification, not just status
//! line) exists because Apps Script keeps deleted deployments serving for
//! a grace period (observed up to ~15 min) and because some upstream
//! failure modes come back 200 OK with an HTML error page inside. Without
//! checking the body we'd report PASS on a dead deployment.

use std::time::Instant;

use crate::config::{Config, Mode};
use crate::domain_fronter::DomainFronter;

const TEST_URL: &str = "https://api.ipify.org/?format=json";

pub async fn run(config: &Config) -> bool {
    if matches!(config.mode_kind(), Ok(Mode::Direct)) {
        let msg = "`mhrv-rs test` probes the Apps Script relay, which isn't \
                   wired up in direct mode. Run `mhrv-rs test-sni` to check \
                   the SNI-rewrite tunnel instead.";
        println!("{}", msg);
        tracing::error!("{}", msg);
        return false;
    }
    if matches!(config.mode_kind(), Ok(Mode::Full)) {
        // Issue #160: Test Relay used to silently fall through to the
        // apps_script path here, which made it look like the user's
        // tunnel-node was being used when it wasn't. The probed IP came
        // back as the Apps Script datacenter — confusing because it
        // disagreed with what whatismyipaddress.com showed in the
        // browser (which DOES go through the tunnel). Rather than fake
        // a passing test, refuse the same way we do for direct mode and
        // tell the user how to actually verify Full mode.
        let msg = "`mhrv-rs test` is wired only for the apps_script relay \
                   path. In full mode the data plane is the pipelined \
                   tunnel mux talking to your tunnel-node — Test Relay \
                   would bypass that and probe Apps Script directly, \
                   which is misleading. To verify full mode end-to-end, \
                   start the proxy and load https://whatismyipaddress.com \
                   in your browser via 127.0.0.1:8085 (HTTP) or :8086 \
                   (SOCKS5) — the IP shown should be your tunnel-node's \
                   VPS IP. Tracking a real Full-mode test in #160.";
        println!("{}", msg);
        tracing::error!("{}", msg);
        return false;
    }
    let fronter = match DomainFronter::new(config) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("FAIL: could not create fronter: {}", e);
            println!("{}", msg);
            tracing::error!("{}", msg);
            return false;
        }
    };

    println!("Probing relay end-to-end...");
    println!("  front_domain : {}", config.front_domain);
    println!("  google_ip    : {}", config.google_ip);
    println!("  test URL     : {}", TEST_URL);
    println!();
    tracing::info!(
        "test: probing {} via SNI={} @ {}",
        TEST_URL,
        config.front_domain,
        config.google_ip
    );

    let t0 = Instant::now();
    let resp = fronter.relay("GET", TEST_URL, &[], &[]).await;
    let elapsed = t0.elapsed();

    let resp_str = String::from_utf8_lossy(&resp);
    let status_line = resp_str.lines().next().unwrap_or("").to_string();
    let body_start = resp_str.find("\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let body = &resp_str[body_start..];

    println!("Response in {}ms:", elapsed.as_millis());
    println!("  status  : {}", status_line);
    let body_trunc: String = body.chars().take(500).collect();
    println!("  body    : {}", body_trunc);
    println!();

    // Classify the outcome. We want PASS to really mean "the relay is
    // doing what it's supposed to" — not just "some HTTP response came
    // back". Criteria, in order:
    //
    //   1. Status must be 200 OK.
    //   2. Body must be valid JSON.
    //   3. JSON must have an "ip" field with a plausible IPv4/IPv6 value.
    //
    // If 2 or 3 fail, classify as SUSPECT — the relay is answering, but
    // the answer isn't what ipify.org serves. Common root causes: a
    // deleted Apps Script deployment still in Google's grace period, an
    // Apps Script auth redirect, or a mismatched AUTH_KEY.

    if !status_line.contains("200 OK") {
        let verdict = if status_line.contains("502") || status_line.contains("504") {
            "FAIL (gateway error). Likely: wrong Apps Script ID, bad AUTH_KEY, quota hit, or Google edge unreachable."
        } else {
            "FAIL (unexpected status)."
        };
        println!("{}", verdict);
        tracing::error!("test: {}  status={}", verdict, status_line);
        return false;
    }

    match serde_json::from_str::<serde_json::Value>(body.trim()) {
        Ok(v) => {
            let ip = v.get("ip").and_then(|x| x.as_str()).unwrap_or("");
            if looks_like_ip(ip) {
                let msg = format!("PASS: end-to-end verified (response IP = {}).", ip);
                println!("{}", msg);
                tracing::info!("test: {}", msg);
                true
            } else {
                // 200 + parseable JSON but no ip field. Apps Script might
                // be answering with its own envelope because the upstream
                // call itself errored.
                println!(
                    "SUSPECT: 200 OK with JSON, but no recognisable 'ip' field. \
                     Likely the Apps Script ran but the upstream fetch failed. \
                     Body preview: {}",
                    body_trunc
                );
                tracing::warn!(
                    "test: 200 OK without ipify 'ip' field — upstream may be broken. body: {}",
                    body_trunc.chars().take(200).collect::<String>()
                );
                false
            }
        }
        Err(_) => {
            // 200 with non-JSON body. Classic signature of an Apps Script
            // auth page, a deleted-deployment HTML page, or Google's
            // "you need to sign in" redirect reaching us unproxied.
            let html_signature = body_trunc.contains("<!DOCTYPE")
                || body_trunc.contains("<html")
                || body_trunc.to_ascii_lowercase().contains("sign in")
                || body_trunc.to_ascii_lowercase().contains("moved");
            let reason = if html_signature {
                "HTML returned instead of JSON. The Apps Script deployment may be deleted, \
                 not published to 'Anyone', or requires sign-in."
            } else {
                "Non-JSON body returned."
            };
            println!("SUSPECT: {}\nbody preview: {}", reason, body_trunc);
            tracing::warn!(
                "test: {} body preview: {}",
                reason,
                body_trunc.chars().take(200).collect::<String>()
            );
            false
        }
    }
}

fn looks_like_ip(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_shape_accepts_v4_and_v6() {
        assert!(looks_like_ip("8.8.8.8"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(!looks_like_ip(""));
        assert!(!looks_like_ip("not-an-ip"));
        assert!(!looks_like_ip("999.999.999.999"));
    }
}
