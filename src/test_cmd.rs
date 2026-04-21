use std::time::Instant;

use crate::config::Config;
use crate::domain_fronter::DomainFronter;

const TEST_URL: &str = "https://api.ipify.org/?format=json";

pub async fn run(config: &Config) -> bool {
    let fronter = match DomainFronter::new(config) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("FAIL: could not create fronter: {}", e);
            return false;
        }
    };

    println!("Probing relay end-to-end...");
    println!("  front_domain : {}", config.front_domain);
    println!("  google_ip    : {}", config.google_ip);
    println!("  test URL     : {}", TEST_URL);
    println!();

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

    let ok = status_line.contains("200 OK");
    if ok {
        println!("PASS: relay round-trip successful.");
        if body.contains("\"ip\"") {
            println!("      returned an IP address — end-to-end verified.");
        }
        true
    } else if status_line.contains("502") || status_line.contains("504") {
        println!("FAIL: gateway error. Likely causes:");
        println!("  - Apps Script deployment ID is wrong");
        println!("  - auth_key doesn't match Code.gs AUTH_KEY");
        println!("  - Google IP / front_domain unreachable from this network");
        println!("  - Apps Script has hit its daily quota (try a different script_id)");
        false
    } else {
        println!("FAIL: unexpected status");
        false
    }
}
