# Android app — installation & first-run guide

This is the one-stop guide for running **mhrv-rs on your Android phone**. It covers the APK install, the MITM certificate dance (which changed a lot on Android 11+), the VPN permission, the first-time Apps Script deployment, and the common "why doesn't this site load" failure modes.

Estimated time: ~10 minutes if the Apps Script deployment already exists, ~15 if you're deploying it fresh.

> **Scope note.** mhrv-rs relays through Google Apps Script. That's what makes it cheap and firewall-resilient, but it's also what imposes the limits documented under [Known limitations](#known-limitations). If you're evaluating this against "a real VPN" — WireGuard, Tailscale, OpenVPN — read that section first.

---

## What you'll need

- An Android phone running **Android 7.0 (API 24)** or later. Arm64, armv7, x86_64, and x86 all ship in one APK.
- A **Google account** (you'll deploy the Apps Script under it). Any account works; a throwaway Gmail is fine.
- About **5 MB of mobile data** for the APK download, **2 MB/day** of relay traffic per GB of browsing (overhead from base64 + JSON wrapping).
- A way to set a **screen lock** (PIN, pattern, password, or biometric + fallback) — this is an Android OS requirement for installing any user CA certificate. You can remove the lock later if you want.

---

## Step 1 — Install the APK

1. On your phone, open the browser and go to: `https://github.com/therealaleph/MasterHttpRelayVPN-RUST/tree/main/releases`
2. Tap `mhrv-rs-android-universal-v1.0.0.apk` → **View raw** (or **Download**).
3. When the browser finishes the download, tap the notification to open the APK.
4. Android will ask: **"Allow this source to install apps?"** — tap **Settings**, toggle **Allow from this source**, then tap **← Back**. Tap **Install**.
5. Tap **Open** once install finishes. You should see the **mhrv-rs** main screen.

> **Why "unknown source" is necessary.** The app isn't on Play Store (it's not the kind of app Google will accept — explicit VPN with MITM). Every Android phone ships with sideload capability for exactly this situation; you're just toggling the permission for the one app that's delivering the APK (Chrome, Files, etc.).

If Android refuses to install with "App not installed" or similar, 99% of the time it's because a different mhrv-rs build is already installed signed with a different key. Uninstall the old one first: `Settings → Apps → mhrv-rs → Uninstall`.

---

## Step 2 — Deploy the Apps Script

Skip this step if you already have a working `/exec` URL from a previous install.

1. On your laptop (easier than on phone), go to <https://script.google.com> and sign in.
2. Click **New project**. You'll land in the script editor.
3. Open [`assets/apps_script/Code.gs`](../assets/apps_script/Code.gs) in this repo, copy the **entire** contents.
4. Back in the script editor, select ALL of the default code (`function myFunction() {}`) and paste over it.
5. Find this line near the top:
   ```js
   const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
   ```
   Replace the placeholder with a **strong random secret** (20+ characters, letters + digits). Save a copy somewhere — you'll paste the exact same string into the app.
6. Save the file (⌘S or Ctrl+S). Name the project something like `mhrv-relay`.
7. Top-right, click **Deploy → New deployment**.
8. Click the gear icon → **Web app**.
9. Fill in:
   - **Description**: `mhrv-relay v1` (or whatever)
   - **Execute as**: **Me**
   - **Who has access**: **Anyone**
   - Click **Deploy**.
10. First time only: Google asks for permissions. Click **Authorize access** → pick your account → on the "Google hasn't verified this app" screen click **Advanced → Go to <project name> (unsafe)** → **Allow**. This is the standard Apps Script deployment flow — the script runs under your account only, Google just hasn't manually audited it.
11. Copy the **Web app URL**. It looks like `https://script.google.com/macros/s/AKfyc.../exec`.

> **What the script actually does.** It receives POST requests from our proxy containing `{ method, url, headers, body_base64 }`, calls `UrlFetchApp.fetch(url, ...)` inside Google's datacenter, and returns `{ status, headers, body_base64 }` back. The "DPI bypass" comes from our proxy connecting to `script.google.com` using a different SNI than the Host header — we hit Google's edge under one name and then funnel traffic to Apps Script under another. Your ISP sees a plain TLS handshake to `www.google.com`.

---

## Step 3 — Fill in the app's config

Back on the phone in the mhrv-rs app:

1. Paste the `/exec` URL (or just the `AKfyc...` ID) into **Deployment URL(s) or script ID(s)**. You can paste multiple — one per line — and the proxy will round-robin between them. Useful later when you hit the 20k/day per-script quota.
2. Paste your **auth_key** — the exact same string you put in `AUTH_KEY` inside `Code.gs`.
3. Leave **google_ip** at the default for now. You'll verify it in step 4.
4. Leave **front_domain** at `www.google.com` — that's the SNI we present on the outbound leg.

---

## Step 4 — Test SNI reachability (strongly recommended)

Before you tap Start, expand the **SNI pool + tester** card and tap **Test all**.

- ✅ **Green check + latency** — your `google_ip` is reachable and accepts the SNI. Proceed.
- ❌ **connect timeout** on every row — your configured `google_ip` is unreachable from your network. Fix by running `nslookup www.google.com` on any working device and pasting the resulting IP into **google_ip**. Then Test all again.
- ❌ **connect timeout** only on some rows — the blocked SNIs are DPI-filtered on your network. Leave them unchecked; the rotation pool only uses the ticked boxes.
- ❌ **dns: …** — your device can't resolve `www.google.com` at all. Switch WiFi or check airplane mode.

Why this matters: if `google_ip` is wrong, the proxy will boot fine but every request will silently time out and you'll chase red herrings.

---

## Step 5 — Install the MITM certificate

This step is annoying but unavoidable: the proxy terminates TLS on your behalf so it can re-encrypt to the Apps Script relay, which means your phone needs to trust a cert we minted locally.

1. In the app, tap **Install MITM certificate**.
2. Read the confirmation dialog — it shows the certificate fingerprint (handy to verify later). Tap **Install**.
3. The app saves `Downloads/mhrv-ca.crt` and deep-links Android into **Settings → Security & privacy** (or similar; wording varies by OEM).
4. If you don't have a screen lock: Android will prompt you to set one. **You have to.** User CAs require a screen lock, period. Set PIN/pattern/password. You can remove it after install if you really want; the cert stays installed.
5. In Settings, navigate: **Encryption & credentials → Install a certificate → "CA certificate"**.
   - On Pixel / stock Android: `Security → More security settings → Encryption & credentials → Install a certificate → CA certificate`.
   - On Samsung: `Biometrics and security → Other security settings → Install from device storage → CA certificate`.
   - On Xiaomi/MIUI: `Passwords & Security → Privacy → Encryption & credentials → Install a certificate → CA certificate`.
   - **Do NOT** pick "VPN & app user certificate" or "Wi-Fi certificate" — wrong category, won't work.
6. Android warns you: **"Your network may be monitored by an unknown third party"**. That's us. Tap **Install anyway**.
7. Pick **Downloads** → tap **mhrv-ca.crt**. Give it a friendly name (or accept the default). Tap **OK**.
8. Return to the mhrv-rs app. A snackbar at the bottom will say **Certificate installed ✓** (the app verifies by fingerprint against AndroidCAStore). If it says "not yet installed", go back to step 5 and try again.

> **Why the dance and not an inline KeyChain flow?** Android 11 removed the inline `KeyChain.createInstallIntent` path — tapping Install MITM used to open a category picker directly, but it now opens a dead-end dialog with just a Close button. Google wants CA installs to be intentional, so they funnel you through Settings. We do the grunt work (save the file, deep-link Settings, verify afterwards) but the manual nav is unavoidable on current Android.

---

## Step 6 — Start the proxy

1. Tap **Start**.
2. Android shows the **VPN connection request** dialog: *"mhrv-rs wants to set up a VPN connection..."*. Tap **OK**.
3. A key icon appears in the status bar. That's your VPN indicator.
4. Open Chrome and visit any site. It should load normally — JavaScript, images, everything. Try `https://www.cloudflare.com`, `https://yahoo.com`, `https://discord.com` as stress tests.
5. If you expand **Live logs** in the mhrv-rs app you'll see:
   - `SOCKS5 CONNECT -> <hostname>:443` — browser asking the TUN layer to open a flow
   - `dispatch <hostname>:443 -> MITM + Apps Script relay (TLS detected)` — routing decision
   - `MITM TLS -> <hostname>:443 (sni=<hostname>)` — we minted the leaf cert and the browser accepted it
   - `relay GET https://<hostname>/...` — forwarded to Apps Script
   - `preflight 204 https://...` — a CORS preflight we answered ourselves (don't worry about these)

---

## Known limitations

Read this before reporting a bug — most "it doesn't work" reports land in one of these buckets.

### Cloudflare Turnstile (the "Verify you are human" checkbox) loops

On Cloudflare-protected sites that challenge every request (not just the first), **you'll solve the challenge, reach the page, then get challenged again on the next click**. This is fundamental to the Apps Script relay model and cannot be fixed in the app:

| Factor | Normal browser | Apps Script relay |
|---|---|---|
| Egress IP | Stable (your ISP) | Rotates across Google's datacenter pool per request |
| User-Agent | Chrome's | Fixed `Google-Apps-Script` (Google overrides it) |
| TLS JA3/JA4 | Chrome's | Google-datacenter's |

CF's `cf_clearance` cookie is bound to the `(IP, UA, JA3)` tuple the challenge was solved against. Different IP next request → re-challenge. No amount of cookie forwarding fixes this.

**Sites that only gate the first page load** (most of CF's Bot Fight Mode customers) work fine after one solve. Sites that challenge every request (cryptocurrency, adult, some forums) won't work through this architecture. Use a different tunnel for those.

### UDP / QUIC (HTTP/3) doesn't go through

Our SOCKS5 listener only handles `CONNECT`, not `UDP ASSOCIATE`. Chrome tries HTTP/3 first and falls back to HTTP/2 over TCP, which works through the proxy. Effect: slightly slower connects on first visit, everything else fine.

### IPv6 leaks

The TUN only routes IPv4 (`0.0.0.0/0`). IPv6 traffic goes out your normal interface, including WebRTC. If you're using mhrv-rs for privacy rather than DPI bypass, disable IPv6 on your WiFi network entirely.

### Apps Script daily quota

Each deployment URL has a daily execution limit (20k/day for consumer Google accounts, higher for Workspace). Heavy streaming or infinite-scroll sites will burn through it. Mitigation: deploy 2–3 scripts and paste all their `/exec` URLs (one per line) into the app — the proxy round-robins across them.

### The MITM cert has no Play Store signature

We ship the APK signed with the standard Gradle debug keystore. Android installs it fine, but you'll see "app is from an unknown developer" warnings, and `Play Protect` may flag it on some devices. That's accurate — the tradeoff is that the build is reproducible from source without us holding a secret key.

---

## Troubleshooting

### "504 Relay timeout" in Chrome

- Your Apps Script deployment isn't responding. Re-check the `/exec` URL (must end in `/exec`, not `/dev`). Watch Live logs for `Relay timeout` vs `connect:` — the former is the Apps Script leg, the latter is the outbound leg from Google to the origin.

### "Your connection is not private — NET::ERR_CERT_AUTHORITY_INVALID"

- The MITM CA isn't installed, or Chrome doesn't see it. Go back to Step 5. If the snackbar confirmed install but Chrome still complains: clear Chrome's data for the site, or tap Advanced → Proceed anyway for testing, then install the cert properly.

### "NET::ERR_CERT_COMMON_NAME_INVALID" on Cloudflare sites

- You're on a version before v1.0. Upgrade — this was fixed by peeking the TLS ClientHello.

### JavaScript parts of a site don't load

- Pre-v1.0 Apps Script rejected `OPTIONS` CORS preflights, which silently broke `fetch()`. Fixed in v1.0 by short-circuiting preflights at the MITM boundary. If you're on v1.0 and still seeing this: open Live logs, look for `Relay failed` errors, report them.

### The app closes after tapping Stop then Start quickly

- Emulator-specific EGL renderer crash on rapid UI transitions. The VPN service itself survives; only the Compose UI process died. Debounced in v1.0 — buttons disable for 2 seconds after tap. On real hardware this rarely happens.

### Chrome shows a white page with no error

- Very common on emulator with software rendering. Check `adb logcat | grep mhrv_rs` to see if the relay is actually making requests. If yes → Chrome's renderer has issues on the emulator, try a real device. If no → the proxy isn't running; check that the VPN key icon is in the status bar.

### Apps that ignore user CAs

Most non-browser Android apps opt out of trusting user CAs by default (Google's Network Security Config default as of API 24). Banking apps, Netflix, Spotify, most messengers — they'll fail through mhrv-rs with cert errors. The full TUN bridge routes their traffic to us, but their TLS stack refuses our cert. Only Chrome, Firefox, and apps that explicitly opt in will work. This is a general MITM limitation, not an mhrv-rs bug.

---

## Uninstall

1. `Settings → Apps → mhrv-rs → Uninstall`.
2. Optionally remove the MITM CA: `Settings → Security → Encryption & credentials → User credentials → mhrv-rs MITM CA → Remove`.
3. The VPN profile is automatically revoked on uninstall.

---

## راهنمای فارسی

این فایل به انگلیسی نوشته شده تا با باقی مستندات پروژه هماهنگ باشد. اگر راهنمای فارسی می‌خواهید، لطفاً [issue بسازید](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues) تا ترجمه کنیم.
