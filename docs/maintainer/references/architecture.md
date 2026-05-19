# Architecture

## What mhrv-rs is

mhrv-rs is the Rust port of [`masterking32/MasterHttpRelayVPN`](https://github.com/masterking32/MasterHttpRelayVPN) (Python). It's an HTTP proxy that runs locally on the user's machine (Windows / macOS / Linux / Android, with OpenWRT and Raspbian builds for sidecars) and bridges browser/app traffic out through Google Apps Script.

The architectural unlock: from the user's ISP perspective, all traffic looks like normal HTTPS to a Google IP. ISPs that censor by SNI / domain / TLS-fingerprint can't block the relay without breaking Google access for their entire customer base. ISPs that censor by destination IP can't block it either, because the destinations are Google data centers.

Apps Script's `UrlFetchApp.fetch()` is the workhorse — it's a Google-blessed API for outbound HTTPS, and Google effectively runs an open proxy to the rest of the internet on every Apps Script user's behalf.

## Two operating modes

### apps_script mode (default)

```
client app → mhrv-rs HTTP/SOCKS5 listener →
  MITM (intercepts HTTPS, signs with local CA) →
  POST batch to Apps Script Web App →
  Apps Script's UrlFetchApp.fetch() → upstream destination →
  Apps Script returns body → mhrv-rs returns to client
```

- **Code.gs** (in `assets/apps_script/Code.gs`) is the script the user deploys to their own Google account at `script.google.com`. Each deployment gets a `script_id` like `AKfycbz1abc...`.
- The MITM layer signs HTTPS leaf certs on the fly using a CA installed in the user's trust store. This lets mhrv-rs read the plaintext request, batch it through Apps Script, and return the response to the client.
- All upstream protocols are HTTP/HTTPS. **No UDP, no MTProto, no QUIC, no WebRTC.** Apps Script can't carry them.
- Per-Apps-Script-account quota: ~20,000 UrlFetchApp calls/day, 30 concurrent, 6-min per-invocation cap, 30s soft response cliff.

### Full mode

```
client app → mhrv-rs SOCKS5 →
  signal/control via Apps Script (small JSON RPC) →
  Apps Script calls into tunnel-node container on user's VPS →
  tunnel-node opens TCP socket to upstream →
  bytes flow through tunnel-node ↔ Apps Script ↔ mhrv-rs ↔ client
```

- **CodeFull.gs** (in `assets/apps_script/CodeFull.gs`) is a different Apps Script — replaces Code.gs's local-fetch with calls to a tunnel-node container.
- **tunnel-node** is a small axum-based Rust HTTP server (in `tunnel-node/`) that the user runs on their own VPS via Docker. Image: `ghcr.io/therealaleph/mhrv-tunnel-node:latest`.
- The bytes flow through the actual TCP tunnel between tunnel-node and the upstream server — Apps Script only handles the **signaling** for tunnel session lifecycle. This means Apps Script's 30s response cap doesn't apply to long-running connections (no SABR cliff). Bigger uploads/downloads work.
- Trade-off: requires a VPS ($3-5/month from Hetzner/Contabo/OVH/Parspack), more setup steps, three places to keep AUTH_KEYs in sync.
- The VPS does NOT need to be reachable from Iran directly. Apps Script (running in Google's data center) is the one that talks to the VPS, so the user's ISP only sees the user-to-Apps-Script leg, which is Google IPs.

## The three secrets

These are the constant source of user confusion. Get the names right:

| Secret | Lives where | Must match | Notes |
|--------|-------------|------------|-------|
| `AUTH_KEY` (or `auth_key` in mhrv-rs config.toml) | mhrv-rs `config.toml` ↔ `Code.gs`/`CodeFull.gs` | Both ends | Per-deployment user secret; protects against random people hitting the user's deployment URL. Editing it in Code.gs without **redeploying as a new version** in Apps Script is the single most common user mistake. |
| `TUNNEL_AUTH_KEY` | `CodeFull.gs` ↔ tunnel-node container env var | Both ends | Full mode only. Env var name is **literally `TUNNEL_AUTH_KEY`** — uppercase, with underscores, exact string. Several users have written `MHRV_AUTH_KEY` (wrong) or `Tunnel` (wrong); the env var is case-sensitive in Linux/Docker and any deviation falls back to the default `changeme`. |
| `DIAGNOSTIC_MODE` | `Code.gs` and `CodeFull.gs` (constant at top) | n/a — local toggle | When `false` (default), the script returns a benign HTML decoy (`"The script completed but did not return anything"`) for bad-auth requests, mimicking Apps Script's own placeholder. When `true`, returns explicit JSON `{"e":"unauthorized"}`. The decoy mode is anti-active-probing defense (#357 pattern); diagnostic mode is for setup. |

## Apps Script's hidden constraints

These are constraints Google enforces on Apps Script's `UrlFetchApp.fetch()` that shape what mhrv-rs can and can't do:

1. **Self-loop restriction** — `UrlFetchApp.fetch()` blocks calls to `*.google.com`, `*.googleapis.com`, `*.gstatic.com`, `*.googleusercontent.com`. **Google services are unreachable through apps_script mode by design.** Includes `gmail.com`, `meet.google.com`, `colab.research.google.com`, `drive.google.com`, `script.google.com` itself (ironic — you can't proxy your way to manage your own deployment). Workaround for users with VPS: dual-routing in xray (route Google direct from VPS, everything else through mhrv-rs). Without VPS, no workaround — point users at #420.
2. **30-second response cliff** — Apps Script Web Apps have a soft cap of 30s on the response. Long downloads or video streams (YouTube SABR, large file downloads >50 MB through MITM) get truncated. Tracked as #300 (SABR cliff). v1.9.0 xmux roadmap aims to mitigate by splitting across deployments.
3. **6-minute per-invocation cap** — hard limit. After this, `UrlFetchApp.fetch()` throws and Apps Script kills the request.
4. **30 concurrent executions per Apps Script account** — affects users who put the same `script_id` under heavy load. Lower `parallel_concurrency` in mhrv-rs config to avoid hitting this.
5. **Daily quota: 20,000 UrlFetchApp calls per Google account** — resets at 00:00 UTC. Multi-deployment rotation across multiple Google accounts is the workaround.
6. **Per-100s rolling soft quota** — undocumented but consistently observed. When tripped, returns the placeholder body (one of the 6 candidate causes for the placeholder; see `diagnostic-taxonomy.md`).
7. **Localized error pages** — Apps Script returns its placeholder body in the locale of the deploying account or origin IP. For Iranian users, this means a Persian HTML page. v1.8.3 detection now distinguishes this case.

## The MITM CA

To intercept HTTPS in apps_script mode, mhrv-rs runs a per-machine CA:

- Generated on first run, stored at `<data_dir>/ca/ca.crt` and `ca.key`.
- Installed into the user's OS trust store via the `cert_installer` module.
- On Windows: user-trust store via `certutil -addstore`.
- On macOS: login keychain via `security`.
- On Linux: distro-specific (NSS for Firefox, system bundle for Chrome/curl).
- **On Android**: only the **user trust store**, not system. Most apps (YouTube, Gmail, Telegram, Instagram, banking) only trust the system store, so they don't see mhrv-rs. Chrome/Firefox/Edge browsers explicitly opt in to user trust and DO use mhrv-rs. This is the Android user-trust-store gotcha that drives much of the Android UX confusion. Workaround for power users: root + Magisk + MagiskTrustUserCerts module migrates user CA to system.

The `--remove-cert` CLI flag tears down the CA cleanly (uninstall from trust store + delete files). PR #121 from `dazzling-no-more` added this; lives in `src/main.rs` `remove_cert` flow.

## SNI rewriting + google_ip rotation

The TLS handshake between mhrv-rs and Apps Script does:

- **TCP connect** to `google_ip` (default `216.239.38.120` — a Google edge IP)
- **TLS SNI** = `www.google.com` (rewritten — this is what the ISP sees in cleartext)
- **HTTP Host header** = `script.google.com` (the real destination, hidden inside the encrypted tunnel)

Iran ISPs occasionally filter specific Google IPs (#313 pattern). When this happens, the user can rotate `google_ip` to another IP from `DEFAULT_GOOGLE_SNI_POOL` (the 12-entry list in `src/domain_fronter.rs`). `mhrv-rs scan-ips` is a diagnostic command that probes Google IPs from the user's network and reports which ones complete TLS handshakes.

`scan_config.toml` (separate from main `config.toml`) is the input for `mhrv-rs scan-ips` — users sometimes confuse the two and put the scan config where the main config should be. See `issue-patterns.md`.

## v1.8.0 anti-fingerprinting features

- **Random padding** (`_pad` field, 0-1024 bytes uniform random, base64) — defeats DPI length-distribution fingerprinting. Users on heavily-throttled ISPs can disable with `disable_padding: true` (~25% bandwidth savings) — landed in v1.8.1.
- **Auto-blacklist deployments** that timeout repeatedly (#319) — round-robin pool actively excludes failing deployments for a cooldown period. Tunable strike threshold queued for v1.8.x.
- **Decoy responses** for bad-auth requests — see `DIAGNOSTIC_MODE` above.
- **Active-probing defense** — random benign body on `doGet` requests so a probe to the deployment URL doesn't reveal that it's a relay.

## v1.8.3 features (just shipped)

- **DoH bypass** — DNS-over-HTTPS to Cloudflare/Google/Quad9/AdGuard/etc. routes around the Apps Script tunnel via plain TCP/443. Saves ~2s per DNS lookup. Default on; opt out with `tunnel_doh: true`.
- **H1 container keepalive** — 240s ping to prevent Apps Script V8 cold-start stalls. Visible win for YouTube playback after pause.
- **64 KB header cap with HTTP 431** — replaces silent socket drops that caused browser retry loops on oversized headers.
- **Spreadsheet-backed response cache** in Code.gs (opt-in via `CACHE_SPREADSHEET_ID`) — TTL-aware, Vary-aware, circular-buffer for O(1) writes. Reduces UrlFetchApp quota consumption.

## Key files in the repo

- `src/main.rs` — CLI binary entry point. `init_logging()` reads `config.log_level`. `Cmd::Test`, `Cmd::ScanIps`, etc. as subcommands.
- `src/bin/ui.rs` — UI binary entry (Windows + Android via JNI). Shares lib code via `mhrv_rs::*`. The `install_ui_tracing` function (post-v1.8.2) reads `RUST_LOG > config.log_level > info,hyper=warn`.
- `src/lib.rs` — re-exports for the lib + Android JNI shim.
- `src/domain_fronter.rs` — the SNI-rewrite TLS dialer + the `DomainFronter` orchestrator. `DEFAULT_GOOGLE_SNI_POOL` lives here.
- `src/proxy_server.rs` — HTTP/SOCKS5 listeners, dispatch logic, DoH bypass, MITM mode entry.
- `src/tunnel_client.rs` — Full mode batch client. Decoy detection + script_id-in-logs added v1.8.1; softer 6-cause message v1.8.3.
- `src/mitm/` — MITM cert manager.
- `src/cert_installer/` — per-OS trust store installation logic.
- `src/config.rs` — `Config` struct + TOML/JSON serde. Default values, validation.
- `assets/apps_script/Code.gs` and `CodeFull.gs` — server-side scripts. Edit these and tell users to redeploy as new version in Apps Script.
- `tunnel-node/` — separate Rust crate for the Full-mode VPS container. README + README.fa.md (Persian translation).
- `android/app/src/main/java/com/therealaleph/mhrv/` — Android Kotlin glue. `MhrvVpnService.kt` is the VPNService that calls into Rust via JNI. `ConfigStore.kt` is the form/preferences round-trip.
- `docs/changelog/` — versioned changelog files. Format: Persian, then `---`, then English.
- `.github/workflows/release.yml` — release CI: builds for all platforms, attaches to GitHub release.
- `.github/workflows/telegram-publish-files.yml` — fires on `workflow_run` of release.yml; posts each file individually to the Telegram channel `-1003966234444` with Persian captions, SHA-256 in caption, and a cross-link from the main channel.
- `.github/scripts/telegram_publish_files.py` — stdlib-only Python script that does the actual Telegram posting (no `requests` dep so it works in minimal CI runners).
