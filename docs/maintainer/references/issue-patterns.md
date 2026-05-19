# Issue patterns

The repo gets the same ~15 issues over and over with different wrappers. Recognizing the pattern fast is most of the maintenance job. Each section below covers: the symptoms users describe, what's actually happening, how to diagnose, and the canonical reply structure.

## Pattern 1: AUTH_KEY mismatch (the v1.8.0 decoy body)

**Symptoms**:
- `502 Relay error: bad response: no json in: <!DOCTYPE html>...The script completed but did not return anything`
- v1.8.1+ logs say `got the v1.8.0 bad-auth decoy` (now soft-language in v1.8.3)
- Issue title often "502 error", "خطای 502", "ارور relay", or "no json in batch response"
- Often combined with: "MITM mode works but Full mode doesn't" (CodeFull.gs has different AUTH_KEY than Code.gs)

**Root cause**: The `AUTH_KEY` constant in `Code.gs` (or `CodeFull.gs`) on Apps Script doesn't match the `auth_key` field in mhrv-rs `config.toml`. Apps Script returns the v1.8.0 decoy HTML.

**The hidden killer**: Apps Script does NOT auto-pickup edits to deployed scripts. Editing `const AUTH_KEY = "..."` in the Apps Script editor and clicking Save does nothing for the deployed version. The user must:

1. Apps Script web editor → **Deploy → Manage Deployments**
2. Click the deployment → pencil/Edit
3. Version dropdown → **New version**
4. Click Deploy

This redeploys with the new AUTH_KEY. Most users skip this and stay on the old version.

**Diagnostic procedure**:

Tell the user to flip `DIAGNOSTIC_MODE = true` at the top of `Code.gs` / `CodeFull.gs`, redeploy as new version, and re-test:

- If they still see the same decoy body → it's NOT AUTH_KEY mismatch (one of the other 5 candidate causes — see `diagnostic-taxonomy.md`)
- If they see explicit JSON `{"e":"unauthorized"}` → confirmed AUTH_KEY mismatch; align values + redeploy as new version

**Canonical reply structure** (from #414 thread):

1. Confirm the symptom matches the v1.8.x decoy detection
2. Walk through the 6 candidate causes and explain why AUTH_KEY mismatch is most likely for their case
3. Detail the redeploy-as-new-version steps with exact UI clicks
4. Suggest the DIAGNOSTIC_MODE flip as the disambiguator
5. Close with link to `diagnostic-taxonomy.md`-equivalent context

## Pattern 2: TUNNEL_AUTH_KEY env var name confusion (Full mode)

**Symptoms**:
- User on Full mode, Docker container set up
- `docker logs mhrv-tunnel` shows `tunnel_auth_key not set, using defaults`
- Or: AUTH_KEY mismatch errors in mhrv-rs that the user "definitely" set correctly
- Often Persian-language issue (matches Iranian VPS user demographic)

**Root cause**: User typed `MHRV_AUTH_KEY` (wrong, this is what some old docs said), `Tunnel` (wrong, partial match), `tunnel_auth_key` (wrong, lowercase), `TUNNEL-AUTH-KEY` (wrong, dash instead of underscore), or skipped the env var entirely.

The literal env var name is **`TUNNEL_AUTH_KEY`** — uppercase, three underscored words.

**Diagnostic command**:
```bash
docker exec mhrv-tunnel env | grep TUNNEL_AUTH_KEY
```

Should print: `TUNNEL_AUTH_KEY=<their-secret>`. If empty, the env var wasn't set during `docker run`.

**Canonical fix**:
```bash
docker stop mhrv-tunnel
docker rm mhrv-tunnel

docker run -d --name mhrv-tunnel \
  --restart unless-stopped \
  -p 8443:8443 \
  -e TUNNEL_AUTH_KEY="<their-real-secret>" \
  ghcr.io/therealaleph/mhrv-tunnel-node:latest
```

Then in `CodeFull.gs`, `const TUNNEL_AUTH_KEY = "<their-real-secret>"` must match. Redeploy as new version.

**Related: port mismatch**. If `docker run` used `-p 8443:8080` or similar mapping, the curl test must use the external port. Check with `docker port mhrv-tunnel`.

## Pattern 3: Iran ISP throttle (#313)

**Symptoms**:
- 504 timeouts, intermittent connection drops
- "Worked yesterday, broken today"
- "Mobile data works but home Wi-Fi doesn't" (or vice versa)
- TLS handshake timeouts during SNI rotation pool tests
- All sites slow, not specific to one destination

**Root cause**: Iran's ISP infrastructure (especially TCI/مخابرات, less so MCI/همراه) actively RST-injects mid-stream into TLS connections destined for specific Google IPs. This is targeted at Apps Script outbound, not generic Google access. The throttle has plus-and-minus periods — sometimes off for hours, sometimes on for days. Was particularly aggressive starting late April 2026.

**Direct curl test** (the gold-standard diagnostic):
```bash
curl -L -X POST 'https://script.google.com/macros/s/<deployment_id>/exec' \
  -H 'Content-Type: application/json' \
  -d '{"k":"<auth_key>","u":"https://httpbin.org/get","m":"GET"}' \
  --max-time 30 -w "\ntime: %{time_total}s\n"
```

Run 5-10 times. If majority timeout/RST → ISP throttle confirmed. If majority succeed → it's mhrv-rs path or config.

**Workarounds** (in roughly the order to try):
1. Upgrade to latest version (each release tends to add diagnostics + small mitigations)
2. `disable_padding: true` in config (~25% bandwidth savings, helps under throttle)
3. Rotate `google_ip` to a different IP from the SNI pool (some IPs filtered, others not, varies by ISP and week)
4. Switch network (mobile data often less throttled than home Wi-Fi)
5. Multiple `script_ids` in config — rotation helps when individual deployments are mid-throttle
6. Full mode + non-Iranian VPS (Hetzner/Contabo/OVH or Iranian-VPS-broker like Parspack selling German VPS)

**Don't promise a fix**. The ISP throttle is upstream of anything we can ship. Acknowledge it, list workarounds, point at #313 as the canonical thread.

## Pattern 4: Apps Script self-loop restriction (Google services blocked)

**Symptoms**:
- "cloud.google.com gives 403"
- "Can't access Gmail / Meet / Drive / Colab / Gemini"
- "google.com loads but mail.google.com doesn't"
- "YouTube video player shows error" (different — this is SABR cliff #300)

**Root cause**: Google explicitly blocks `UrlFetchApp.fetch()` calls to `*.google.com`, `*.googleapis.com`, `*.gstatic.com`, `*.googleusercontent.com`. This is hardcoded into Google's API to prevent Apps Script from being abused as an internal Google proxy. **No HTTP-relay-on-Apps-Script architecture can fix this.**

**No workaround in apps_script mode**. This is permanent.

**Workaround for users with VPS in Full mode**: dual-routing in xray. Their xray client (or v2ray, etc.) routes Google domains direct from their VPS, everything else through mhrv-rs. See #420 for the canonical thread with config snippets.

**Canonical reply**: explain the architectural limit, list the affected sites, point at #420 for the dual-VPS workaround. Close as duplicate of #420 if it's a clean duplicate.

## Pattern 5: SABR cliff (#300) — YouTube video doesn't play

**Symptoms**:
- "YouTube loads but video doesn't play"
- "This content isn't available"
- "Playback error" / "An error occurred"
- "Short videos work, long ones don't"

**Root cause**: Apps Script's 30-second response cap. YouTube's SABR streaming protocol expects long-lived response streams. After ~30s the stream gets cut by Apps Script and the video player errors out. Page HTML/JS loads fine (small, fits in window). Video stream doesn't.

**Workarounds**:
- Short videos (<1 min) often work
- Lowest quality (144p/240p) sometimes squeaks past
- YouTube web in Chrome/Firefox (browsers use user trust store on Android, YouTube app doesn't) > YouTube app
- NewPipe (Android, F-Droid) sometimes works better than official app
- Full mode + VPS (definitive — bytes flow through TCP tunnel, not Apps Script's response window)

v1.9.0 xmux roadmap aims to mitigate by splitting streams across multiple deployments. Won't fully resolve.

**Canonical reply**: explain SABR cliff, list workarounds, close as duplicate of #300 if pure duplicate.

## Pattern 6: Android user trust store

**Symptoms**:
- "Browser works but YouTube/Telegram/Instagram apps don't"
- "VPN is on but apps don't go through mhrv-rs"
- "How do I make Gmail app work?"

**Root cause**: Android has two CA trust stores — system (factory-installed CAs) and user (user-installed CAs via Settings → Security → Install certificate). Since Android 7.0 (2016), most apps default to system-only. The mhrv-rs MITM CA installs to user trust store; system trust requires root.

**Apps that work via mhrv-rs on Android**: Chrome, Firefox, Edge, Brave (browsers explicitly opt in to user trust). Most desktop-class apps that delegate to system browser.

**Apps that don't work**: YouTube app, Gmail app, Maps, Instagram, Twitter/X, banking apps, any app shipped with strict TLS pinning. They use system trust + don't see mhrv-rs.

**Workarounds**:
- Use web versions (`youtube.com` in Chrome instead of YouTube app)
- Root + Magisk + MagiskTrustUserCerts module migrates user CA to system
- Full mode + VPS (bytes don't flow through MITM, so trust isn't needed for arbitrary apps; v2ray/xray on VPS handles routing)

**Canonical reply**: explain user/system trust store distinction, list which apps work, give the three workarounds. This is FAQ-tier — should eventually be in `docs/faq/android.md`.

## Pattern 7: Cloudflare CAPTCHA / 403

**Symptoms**:
- "Most CF-protected sites block me"
- "ChatGPT shows captcha I can't solve"
- "Cloudflare checking your browser..." stuck

**Root cause**: All mhrv-rs traffic exits via Google data center IPs (Apps Script's outbound). Cloudflare's bot detection flags traffic from Google IPs to consumer-facing sites as suspicious — looks like a scraper/bot, not a person. Result: aggressive CAPTCHA, sometimes outright 403.

**Workarounds** (limited):
- Solve interactive CAPTCHA when shown — the resulting token works for hours
- Different browser fingerprints sometimes pass (Brave, Tor)
- Full mode + VPS — VPS exits with its own (residential-adjacent) IP, often not flagged
- Cloudflare WARP integration is on the v1.9.x roadmap (#309) but feasibility uncertain

**Canonical reply**: explain why (Google IP exit), list workarounds, point at #382 (canonical Cloudflare thread) and #309 (WARP roadmap).

## Pattern 8: Apps Script account suspension / phone-required

**Symptoms**:
- "Action required" notifications on Google account
- "Phone number must be added"
- Deployment intermittently returns Persian Workspace landing HTML (`<html lang="fa" dir="rtl">پردازش کلمه وب...`)
- Sometimes resolves on its own; sometimes escalates to suspension

**Root cause**: Google's anti-abuse system flags new Google accounts (especially phone-less ones) within hours of deploying automation-pattern code. The progression is: warning → soft restriction (Workspace landing HTML on UrlFetchApp calls) → full suspension.

**Workarounds**:
1. Add a phone number to the account (most reliable). Iranian phones often filtered by Google's verification; user might need a friend's foreign number, TextNow, paid SMS-receive service, or shared phone
2. Use established phone-verified accounts (own main Gmail, family/friends' main accounts) — multi-year-old accounts with normal usage history are very rarely flagged
3. Workflow #325 — community shared deployments (one user with stable account hosts the deployment, others use the deployment ID + shared AUTH_KEY)

**Risk levels** (approximate, from observed reports):
- Phone-verified personal Gmail, single deployment, light use → low risk
- Phone-verified, multiple deployments under same account → medium risk
- New no-phone account, any usage → high risk
- Old established account, single deployment → very low risk

No confirmed cases of full Google account ban (Gmail deletion, Drive loss). Suspensions are scoped to Apps Script + UrlFetchApp.

## Pattern 9: Telegram / VoIP / "app doesn't work in Full mode"

**Symptoms**:
- "Can I add Telegram support?"
- "WhatsApp/Skype voice calls don't work"
- "Need a port for Telegram"

**Root cause**: Telegram uses MTProto (custom UDP-ish protocol). WhatsApp/Skype/FaceTime voice/video use WebRTC (UDP STUN/TURN). Apps Script's `UrlFetchApp` is HTTP/HTTPS only — **cannot carry UDP or non-HTTP protocols by design.**

**Workarounds**:
- **Telegram messaging**: web.telegram.org through mhrv-rs Chrome (HTTPS, works)
- **Telegram MTProto proxy**: use a public MTProto proxy from Telegram channels (free, unreliable) or self-host on VPS
- **Voice/video calls**: only via Full mode + VPS + xray UDP-enabled routing — bytes route direct from VPS to upstream, not through Apps Script

Architectural ceiling — can't be fixed in mhrv-rs core.

## Pattern 10: Config file confusion (config.toml vs scan_config.json)

**Symptoms**:
- "I followed instructions but it doesn't import the config"
- User pastes a config that has `google_ips`, `max_ips_to_scan`, `scan_batch_size`, `google_ip_validation` fields
- Says "the program doesn't pick up my config"

**Root cause**: User confused `config.toml` (main runtime config — `script_ids`, `auth_key`, `google_ip`, `mode`, etc.) with `scan_config.json` (input for `mhrv-rs scan-ips` diagnostic command — Google IP discovery).

**Fix**: explain the two files, point at `config.example.toml` in repo root for the right template.

Common related typos:
- `script_id` (singular) instead of `script_ids` (plural array) — mhrv-rs parses as 0 deployments and falls back
- `mode: "fullmode"` or `"full_mode"` instead of `"full"` (or `"apps_script"`)

## Pattern 11: Windows OpenGL renderer fail

**Symptoms**:
- `Error: Glutin(Error { ... NotSupported("extension to create ES context with wgl is not present") })`
- `Error: Wgpu(NoSuitableAdapterFound)`
- run.bat fails twice (Glow then wgpu fallback) and exits

**Root cause**: User's Windows lacks OpenGL 2.0+ AND lacks DX12/Vulkan-compatible GPU. Causes: old GPU (Intel HD 2500/3000-era), running in VM without GPU acceleration, RDP session, missing/corrupt graphics drivers.

**Workaround**: use the CLI binary `mhrv-rs.exe` directly. Put `config.toml` in the same folder, double-click `mhrv-rs.exe`, set browser proxy to `127.0.0.1:8086`. Same functionality, no UI.

v1.8.x roadmap: improve `run.bat` to auto-fallback to CLI when both UI renderers fail.

## Pattern 12: VPS / Full mode setup questions

**Symptoms**:
- "How do I set up VPS?"
- "Does the VPS need to be reachable from Iran?"
- "Which provider should I buy?"
- "Step-by-step please"

**Canonical answer**: VPS does NOT need to be reachable from Iran (Apps Script proxies the path). Recommended providers:

- **Direct purchase from Iran**: difficult — Hetzner needs VAT ID
- **Iranian reseller**: Parspack ([parspack.com/vps](https://parspack.com/vps)), Iranserver, Hostiran sell German VPS via Iranian payment with mark-up (~20-40% over direct)
- **Outside Iran**: Hetzner Falkenstein DE, Contabo DE, OVH SYS — direct euro/dollar payment

Specs: 1 vCPU, 1 GB RAM, 25 GB SSD, 50+ Mbps unmetered → ~$3-5/month direct or ~250-500k toman/month via reseller for personal use. For 5+ devices + Instagram smooth: 2-4 GB RAM, 100 Mbps unmetered.

Setup walkthrough: see `tunnel-node/README.md` and `tunnel-node/README.fa.md` (Persian).

## Pattern 13: Iranian VPS provider bandwidth-cap appliance

**Symptoms** (rare but observed):
- Persian "exceeded bandwidth quota" HTML response from user's own tunnel-node URL
- Mixed success/failure on same `script_id`

**Root cause** (provisional — confirmed only when VPS is on Iranian provider): Iranian VPS providers enforce monthly bandwidth quotas at the upstream router/load-balancer layer. When tripped, they intercept traffic and serve a Persian quota landing page **upstream** of the user's Docker container. Container itself never sees the request during quota events.

**Note**: Several users have reported this where the VPS turned out to be at Hetzner DE (not Iranian) — in which case the Persian body is actually Apps Script's own localized soft-quota response (cause #5 in the diagnostic taxonomy). Always confirm the VPS provider before assuming.

**Workarounds**:
1. Upgrade plan if provider has a higher tier
2. Move to non-Iranian VPS (Hetzner/Contabo/OVH unmetered)
3. Client-side bandwidth optimizations: `disable_padding`, lower `parallel_concurrency`, DNS bypass (v1.8.3+)

## Pattern 14: Account locale → Persian Apps Script error pages

**Symptoms**:
- Apps Script's response body comes back as Persian HTML (Workspace landing page or quota page)
- User on Hetzner/non-Iranian VPS
- Their Google account is set to fa-IR locale OR request originates from Iranian IP through some leg

**Root cause**: Apps Script localizes its system error/placeholder pages based on the deploying account's locale and (sometimes) request-origin IP. Persian-locale account → Persian error pages. This is independent of the user's geographic location running mhrv-rs.

**Disambiguator**: `DIAGNOSTIC_MODE = true` in Code.gs. If still see Persian body → it's NOT AUTH_KEY mismatch (which gets replaced with explicit JSON in diagnostic mode). It's Apps Script's own quota/state response.

This is the "5th candidate cause" in the diagnostic taxonomy and the "6th candidate cause" if you separate "Workspace landing HTML for account-flagged deployments" from "Persian quota body for healthy deployments under quota tear".

## Pattern 15: Download large files / IDM workaround

**Symptoms**:
- "Downloads stick at 1-10 MB"
- "Need to download a 1 GB file, IDM gets partial only"

**Root cause**: 30s response cliff again. For 10 MB files at typical Apps Script throughput, 30s is enough. For 1 GB, would need 200+ seconds — hopeless.

**Workarounds**:
- IDM's multi-segment download with 5 MB segments — each segment fits inside 30s window
- Full mode + VPS — bytes flow through TCP tunnel, not constrained
- v1.8.x roadmap: range-aware splicing in Code.gs to natively support `Range:` requests

## Quick triage table

When a new issue lands, scan for these keywords to map fast:

| Keywords | Pattern |
|----------|---------|
| `502`, `decoy`, `no json in batch`, `script completed but did not return` | 1 (AUTH_KEY mismatch) |
| `tunnel_auth_key not set`, `MHRV_AUTH_KEY`, `Tunnel_Auth_Key`, `docker logs mhrv-tunnel` | 2 (TUNNEL_AUTH_KEY confusion) |
| `504`, `timeout`, `Apps Script unresponsive`, `Connection reset`, `RST`, "yesterday worked" | 3 (Iran ISP throttle #313) |
| `cloud.google.com`, `colab`, `gmail`, `meet`, `gemini`, `drive` not loading | 4 (self-loop restriction → #420) |
| `YouTube video doesn't play`, `This content isn't available`, `playback error` | 5 (SABR cliff → #300) |
| Android, `Gmail app`, `YouTube app`, `Telegram`, "browser works but apps don't" | 6 (user trust store) |
| `Cloudflare`, `captcha`, `403 Forbidden`, "checking your browser" | 7 (CF bot detection → #382) |
| `Google account`, `phone required`, `action required`, `suspension`, `Workspace landing` | 8 (account flag) |
| `Telegram support`, `WhatsApp call`, `Skype`, `voice call`, `video call` | 9 (UDP/MTProto architectural) |
| Config has `google_ips`, `scan_batch_size`, `max_ips_to_scan` | 10 (scan_config confusion) |
| `egui_glow`, `OpenGL`, `wgl`, `Wgpu(NoSuitableAdapterFound)`, `run.bat` | 11 (Windows OpenGL → CLI) |
| `VPS`, `Hetzner`, `Parspack`, `setup help`, "step by step VPS" | 12 (Full mode setup) |
| `سهمیه پهنای باند`, `bandwidth quota`, Iranian VPS provider | 13 (provider appliance) |
| Persian HTML body in error log + non-Iranian VPS | 14 (account locale) |
| `IDM`, `download stuck`, `large file`, `1 GB download` | 15 (range/cliff) |

If the issue doesn't fit any pattern, it's worth reading carefully — these are the genuine new bugs.
