# Android app

Full guide for the mhrv-rs Android app: install, first-run setup, troubleshooting, known limits.

- [Overview](#overview)
- [Requirements](#requirements)
- [1. Install the APK](#1-install-the-apk)
- [2. Deploy the Apps Script](#2-deploy-the-apps-script)
- [3. Enter your config in the app](#3-enter-your-config-in-the-app)
- [4. Run the SNI tester](#4-run-the-sni-tester)
- [5. Install the MITM certificate](#5-install-the-mitm-certificate)
- [6. Start the tunnel](#6-start-the-tunnel)
- [UI quick reference](#ui-quick-reference)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)

---

## Overview

The Android app is the exact same `mhrv-rs` Rust crate that powers the desktop build, wrapped in a Compose UI and fed a TUN file descriptor via `VpnService` + [`tun2proxy`](https://crates.io/crates/tun2proxy). Every app on the device is routed through the proxy — no per-app setup.

```
Any app on the device
        │
        ▼
VpnService TUN  ──► tun2proxy (in-process)
                        │
                        ▼
                Local SOCKS5 listener  ──► mhrv-rs dispatcher
                                                 │
                         ┌───────────────────────┤
                         ▼                       ▼
               sni-rewrite tunnel        Apps Script relay
               (Google-owned hosts       (everything else,
                direct to google_ip)     via your /exec URL)
```

Setup time: **~10 minutes** if your Apps Script deployment already exists, ~15 min if you're deploying fresh.

---

## Requirements

| | |
|---|---|
| **Android version** | 7.0 (API 24) or later |
| **Device architecture** | Any. The APK is universal: arm64-v8a, armeabi-v7a, x86_64, x86 |
| **Google account** | Yes — you'll deploy the Apps Script under it. A throwaway Gmail works |
| **Screen lock** | PIN, pattern, password, or biometric + fallback. **Required by Android for user-CA install.** Can be removed after install; the cert stays trusted |
| **Data usage** | ~5 MB for the APK, then ~2 MB overhead per GB of browsing (base64 + JSON wrapping) |

> **Scope note.** mhrv-rs relays through Apps Script. That's what makes it cheap and DPI-resilient, but it's also what imposes the [known limitations](#known-limitations) below. If you're evaluating against a real VPN (WireGuard/Tailscale/OpenVPN), skim that section first.

---

## 1. Install the APK

1. On your phone, open the browser and go to <https://github.com/therealaleph/MasterHttpRelayVPN-RUST/releases/latest>.
2. Download `mhrv-rs-android-universal-v*.apk`.
3. Tap the download to open the installer.
4. When Android asks **"Allow this source to install apps?"**:
   - Tap **Settings**
   - Toggle **Allow from this source**
   - Tap **← Back** → **Install**
5. Tap **Open** once install finishes.

> If Android refuses with "App not installed": an old build signed with a different key is still present. `Settings → Apps → mhrv-rs → Uninstall`, then try again. (From v1.0.2 onward this is a one-time thing — updates are signed with a stable key.)

---

## 2. Deploy the Apps Script

Skip this step if you already have a working `/exec` URL.

Do this on a laptop — it's a browser-heavy flow that's painful on a phone.

1. Go to <https://script.google.com> → **New project**.
2. Copy the full contents of [`assets/apps_script/Code.gs`](../assets/apps_script/Code.gs) from this repo.
3. In the script editor, select the default `function myFunction() {}` and paste over it.
4. Find the line near the top:
   ```js
   const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
   ```
   Replace the placeholder with a strong random secret (20+ chars, letters + digits). Save this value — you'll paste it into the app too.
5. **File → Save** (⌘S / Ctrl+S). Name the project something like `mhrv-relay`.
6. **Deploy → New deployment**.
7. Click the gear icon → **Web app**. Fill in:

   | Field | Value |
   |---|---|
   | Description | `mhrv-relay v1` (or whatever) |
   | Execute as | **Me** |
   | Who has access | **Anyone** |

8. Click **Deploy**. First time only: Google asks for permissions.
   - Click **Authorize access** → pick your account
   - On "Google hasn't verified this app" → **Advanced** → **Go to &lt;project name&gt; (unsafe)** → **Allow**
9. Copy the **Web app URL**. It looks like `https://script.google.com/macros/s/AKfyc.../exec`.

<details>
<summary>What the script does</summary>

It receives `POST { method, url, headers, body_base64 }` from our proxy, calls `UrlFetchApp.fetch(url, ...)` inside Google's datacenter, and returns `{ status, headers, body_base64 }`. DPI bypass comes from us connecting to `script.google.com` using a different TLS SNI than the HTTP `Host` header — the ISP sees `www.google.com`, Google's edge routes by the Host header inside the encrypted stream.
</details>

---

## 3. Enter your config in the app

Back on the phone:

| Field | What to enter |
|---|---|
| **Deployment URL(s) or script ID(s)** | The `/exec` URL you copied. You can paste multiple — one per line — and the proxy will round-robin between them (useful when you hit the 20k/day per-script quota) |
| **auth_key** | The exact string you put in `AUTH_KEY` inside `Code.gs` |
| **google_ip** | Leave the default. The next step will auto-populate it |
| **front_domain** | Leave at `www.google.com` |

Tap anywhere outside the text fields to dismiss the keyboard.

---

## 4. Run the SNI tester

Before starting the tunnel, verify the outbound leg works. Expand **SNI pool + tester** and tap **Test all**.

| Result | Meaning | Action |
|---|---|---|
| ✅ Green check + `NNN ms` | `google_ip` is reachable + accepts the SNI | Proceed |
| ❌ `connect timeout` on every row | Configured `google_ip` is unreachable | Tap **Auto-detect google_ip** under the Network card, then Test all again |
| ❌ `connect timeout` on some rows | Those specific SNIs are DPI-filtered on your network | Leave them unchecked; rotation pool uses only ticked boxes |
| ❌ `dns: ...` | Device can't resolve `www.google.com` at all | Fix Wi-Fi / airplane mode |

If you tap Auto-detect and it still fails on every row, your network is blocking Google's edge entirely — mhrv-rs can't help there.

---

## 5. Install the MITM certificate

The proxy terminates TLS locally (re-encrypts before routing through Apps Script), so your phone needs to trust a cert we minted on first run.

1. In the app, tap **Install MITM certificate**.
2. The confirmation dialog shows the certificate fingerprint. Tap **Install**.
3. The app:
   - saves a PEM copy to `Downloads/mhrv-ca.crt`
   - opens the Android **Settings** app
4. **If you don't have a screen lock** — Android will prompt you to set one now. You have to. User CAs require it. You can remove it after install; the cert stays trusted.
5. In Settings, tap the **search bar** at the top and type `CA certificate`. Open the result labelled **"CA certificate"** (or "Install CA certificate" on some OEMs).

   > **Don't** pick "VPN & app user certificate" or "Wi-Fi certificate" — wrong category, won't work.

   Searching is more reliable than navigating menus: Pixel/Samsung/Xiaomi all bury CA install under different paths, but all of them index it under "CA certificate" in search.

6. Android warns **"Your network may be monitored by an unknown third party"**. That's us. Tap **Install anyway**.
7. Pick **Downloads** → tap **mhrv-ca.crt**. Give it a friendly name (or accept the default). Tap **OK**.
8. Switch back to the mhrv-rs app. A snackbar confirms **Certificate installed ✓** — the app verifies by fingerprint against `AndroidCAStore`.

   If it says "not yet installed", repeat step 5.

<details>
<summary>Why can't the app install the cert directly?</summary>

Android 11 removed the inline `KeyChain.createInstallIntent` flow. That intent used to open a category picker directly inside the app. On current Android it opens a dead-end dialog with just a Close button — Google wants CA installs to be deliberate. We do the grunt work (save file, open Settings, verify afterwards), but the manual navigation step is unavoidable.
</details>

---

## 6. Start the tunnel

1. Tap **Start**.
2. Android shows the VPN-permission dialog: *"mhrv-rs wants to set up a VPN connection..."*. Tap **OK**.
3. A key icon appears in the status bar. That's your VPN indicator.
4. Open Chrome. Try `https://www.cloudflare.com`, `https://yahoo.com`, `https://discord.com` as stress tests — all should render normally.

Expand **Live logs** to watch the traffic flow:

| Log line | What it means |
|---|---|
| `SOCKS5 CONNECT -> <host>:443` | Browser opened a TCP flow; TUN captured it |
| `dispatch <host>:443 -> MITM + Apps Script relay` | Routing decision |
| `MITM TLS -> <host>:443 (sni=<host>)` | Our leaf cert was accepted by the browser |
| `relay GET https://<host>/...` | Forwarded to Apps Script |
| `preflight 204 <url>` | CORS preflight we answered ourselves (normal, don't worry about these) |

---

## UI quick reference

| Control | Location | Notes |
|---|---|---|
| **Deployment URL(s) or script ID(s)** | Apps Script relay section | One per line; round-robin dispatch |
| **auth_key** | Apps Script relay section | Must match `AUTH_KEY` in `Code.gs` |
| **google_ip** / **front_domain** | Network section | Auto-detect button fills google_ip via DNS |
| **Auto-detect google_ip** | Under the Network row | Re-resolves `www.google.com` + repairs `front_domain` if corrupted to an IP |
| **SNI pool + tester** | Collapsible | Checkboxes for rotation; per-row Test + Test all |
| **Advanced** | Collapsible | verify_ssl, log_level, parallel_relay, upstream_socks5 |
| **Start / Stop** | Bottom row | 2-second debounce between taps |
| **Install MITM certificate** | Below Start/Stop | Save PEM → open Settings → search "CA certificate" |
| **Live logs** | Collapsible (below the Install button) | 500ms poll of the proxy's log ring buffer |
| **v1.0.x (version badge)** | Top bar, right | Tap to check GitHub for a newer release |

---

## Known limitations

Read this before reporting a bug — most "it doesn't work" reports fall into one of these.

### Cloudflare Turnstile ("Verify you are human") loops

On Cloudflare-protected sites that challenge **every** request, you'll solve the Turnstile, reach the page, then get challenged again on the next click. This is inherent to the Apps Script relay model:

| Factor | Normal browser | Apps Script relay |
|---|---|---|
| Egress IP | Stable (your ISP) | Rotates across Google's datacenter pool per request |
| User-Agent | Chrome's | Fixed `Google-Apps-Script` (locked by Google; we can't override) |
| TLS JA3/JA4 | Chrome's | Google-datacenter's |

Cloudflare's `cf_clearance` cookie is bound to the `(IP, UA, JA3)` tuple the challenge was solved against. Different IP next request → re-challenge.

**Sites that only gate the first page load** (most of CF's Bot Fight Mode customers) work fine after one solve. Sites that challenge every request (crypto exchanges, adult, some forums) fundamentally can't hold a session through this architecture — use a different tunnel for those.

### UDP / QUIC (HTTP/3) doesn't go through

The SOCKS5 listener only handles `CONNECT`, not `UDP ASSOCIATE`. Chrome tries HTTP/3 first and falls back to HTTP/2 over TCP, which works fine. Effect: slightly slower first connect, everything else normal.

### IPv6 leaks

The TUN only routes IPv4 (`addRoute 0.0.0.0/0`). IPv6 goes out your normal interface, including WebRTC. If you're using mhrv-rs for privacy rather than DPI bypass, disable IPv6 on your Wi-Fi network entirely.

### Apps Script daily quota

Each `/exec` has a daily execution limit (20k/day for consumer Google accounts, higher for Workspace). Heavy streaming or infinite-scroll sites burn through it. Mitigation: deploy 2–3 scripts, paste all their `/exec` URLs into the app, one per line — the proxy round-robins.

### Most non-browser apps ignore user CAs

By default, Android apps opt out of trusting user-installed CAs (Android 7+ `Network Security Config` default). Banking apps, Netflix, Spotify, most messengers — they'll fail with cert errors through mhrv-rs. The TUN routes their traffic to us; they just refuse our leaf. Only apps that explicitly opt in (browsers, curl, some developer tools) will work. This is a general MITM-proxy limitation.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `504 Relay timeout` in Chrome | Apps Script deployment not responding | Re-check the `/exec` URL (must end in `/exec`, not `/dev`). Watch Live logs for `Relay timeout` vs `connect:` errors |
| `NET::ERR_CERT_AUTHORITY_INVALID` | MITM CA not installed / not found | Redo [step 5](#5-install-the-mitm-certificate). Make sure you picked "CA certificate" in Settings, not VPN or Wi-Fi |
| `NET::ERR_CERT_COMMON_NAME_INVALID` on Cloudflare sites | Pre-v1.0 bug | Upgrade to v1.0.0 or later |
| JS parts of a site don't load | Pre-v1.0 OPTIONS rejection | Upgrade to v1.0.0+. If still present: Live logs → grep for `Relay failed`, report |
| All SNIs time out in the tester | `google_ip` is stale (Google rotated the A record) | Tap **Auto-detect google_ip** |
| SNI tester red on some rows only | Those SNIs are DPI-filtered on your network | Uncheck the failing ones in the rotation pool |
| App closes when tapping Stop | Was a v1.0.0/1.0.1 race bug | Upgrade to v1.0.2. If still present on v1.0.2+: `adb logcat -s MhrvVpnService mhrv-crash mhrv_rs` and report |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` when upgrading | Old APK signed with a different key (pre-v1.0.2) | Uninstall first, then install the new APK. Only a one-time thing — v1.0.2 onward has a stable signature |
| Chrome white-pages with no error | Often a rendering bug on the emulator with software GPU | Test on real hardware. Check `Live logs` to verify the relay is actually making requests |
| Cloudflare Turnstile loop | [Known limitation](#cloudflare-turnstile-verify-you-are-human-loops) | No fix inside this architecture |
| Banking/streaming apps show cert errors | [Known limitation](#most-non-browser-apps-ignore-user-cas) | No fix — app chose not to trust user CAs |

### Collecting a useful log

If you need to report a bug:

```sh
adb logcat -c                              # clear
# reproduce the issue in the app
adb logcat -d | grep -E "MhrvVpnService|mhrv_rs|mhrv-crash|tun2proxy" > mhrv.log
```

Attach `mhrv.log` to your issue. Also include:
- Android version (Settings → About phone → Android version)
- OEM (Pixel / Samsung / Xiaomi / …)
- App version (tap the version badge in the top bar)
- What you did, what you expected, what happened

---

## Uninstall

1. `Settings → Apps → mhrv-rs → Uninstall`.
2. Optional: remove the MITM CA — `Settings → Security → Encryption & credentials → User credentials → mhrv-rs MITM CA → Remove`. (On OEMs where that path is buried, search Settings for `user credentials`.)
3. The VPN profile is auto-revoked on uninstall — nothing to clean up there.
