# Diagnostic taxonomy: the placeholder body

## What this is

Multiple distinct conditions cause Apps Script (or our own scripts on Apps Script) to return an HTML body that mhrv-rs's batch parser sees as `bad response: no json in batch response: <body prefix>`. Through user reports and iteration we've narrowed the body strings to **6 candidate causes**. Distinguishing them requires both client-side detection (string-match on body content) and server-side disambiguation (`DIAGNOSTIC_MODE` flag in Code.gs).

This taxonomy is the post-mortem evolution of v1.8.0 → v1.8.1 → v1.8.2 → v1.8.3 detection. v1.8.1 falsely asserted "AUTH_KEY mismatch" on body match; v1.8.2 softened to enumerate 4 candidates; v1.8.3 added the Persian-localized cause and the Workspace landing HTML cause for account-flagged deployments — bringing the count to 6.

## The 6 candidate causes

### 1. AUTH_KEY mismatch (intentional decoy)

**Body**:
```html
<!DOCTYPE html>
<html>
<head><title>Web App</title></head>
<body><p>The script completed but did not return anything.</p></body>
</html>
```

**Source**: Our `Code.gs` / `CodeFull.gs` returns this when `request.k !== AUTH_KEY` and `DIAGNOSTIC_MODE = false`. It mimics Apps Script's stock placeholder for empty-return scripts.

**Trigger**: User edited AUTH_KEY in Apps Script editor but didn't redeploy as new version, OR user has different AUTH_KEY in `config.toml` than in `Code.gs`, OR user is using Code.gs deployment ID with `mode: full` (which expects CodeFull.gs).

**Disambiguator**: Set `DIAGNOSTIC_MODE = true` in Code.gs / CodeFull.gs + redeploy as new version. Then this case returns `{"e":"unauthorized"}` (explicit JSON) instead of the HTML. The other 5 cases are independent of DIAGNOSTIC_MODE and still return their natural body.

**Fix**: Align AUTH_KEY values + redeploy as new version.

### 2. Apps Script execution timeout

**Body**: same `"The script completed but did not return anything"` HTML, but emitted by Apps Script itself (not our script) when the execution exceeded the per-invocation cap.

**Source**: Apps Script's runtime kills the script after 6-min hard cap or 30s soft cap on Web App responses, then serves the placeholder body.

**Trigger**: Slow upstream destination, large response payload, network stall mid-fetch.

**Disambiguator**: With `DIAGNOSTIC_MODE = true`, AUTH_KEY mismatch (cause 1) goes away; if the placeholder body still appears for some batches, it's likely cause 2/3/4/5/6.

**Fix**: Lower `parallel_concurrency` in `config.toml`, retry, accept some intermittent failures.

### 3. Apps Script soft-quota tear

**Body**: same placeholder HTML. Sometimes a different short HTML page mentioning Apps Script's quota system.

**Source**: Apps Script's per-100s rolling soft quota or per-account daily quota hit. Apps Script kills the request mid-execution.

**Trigger**: Account-aggregate UrlFetchApp throughput exceeded per-100s threshold (~30 concurrent or so). Common with multi-device single-deployment users during page load events (browsers fire 50+ requests in a burst).

**Disambiguator**: Same as 2 — DIAGNOSTIC_MODE rules out AUTH_KEY but doesn't distinguish 2 from 3 from 4. Check the per-script_id error rate over a few minutes — if a deployment has 30%+ failure rate during peak browser activity but works fine when idle, it's quota-related (3 or possibly 5).

**Fix**: Lower `parallel_concurrency`, add more deployments to `script_ids` rotation, distribute deployments across multiple Google accounts.

### 4. Iran ISP-side response truncation

**Body**: typically truncated mid-stream — the body that arrives at mhrv-rs is missing the trailing JSON envelope. The early bytes look like a valid Apps Script response prefix but the request was cut by an ISP-side TCP RST mid-flight.

**Source**: Iran's ISP infrastructure (especially TCI/مخابرات) actively RST-injects on TLS connections to specific Google IPs (the #313 pattern).

**Trigger**: Network-conditional. Active throttle periods (sometimes hours, sometimes days). Worse on certain Google IPs. Worse on certain Iranian ISPs.

**Disambiguator**: Direct curl test from the user's network (see `issue-patterns.md` Pattern 3). If curl-to-Apps-Script also gets timeouts/RST, confirmed ISP-side. The HTML body in this case is partial/truncated — sometimes just `<!DOCT...` rather than the full placeholder.

**Fix**: Workarounds in Pattern 3 — `disable_padding`, rotate `google_ip`, switch network, multi-deployment, Full mode + VPS.

### 5. Apps Script Persian-localized soft-quota body

**Body**:
```html
<html lang="fa" dir="rtl">
<head>
  <meta name="description" content="پردازش کلمه وب، ارائه‌ها و صفحات گسترده">
  ...
```

May also include phrases like `از سهمیه پهنای باند مجاز فراتر رفته‌اید` ("you exceeded the allowed bandwidth quota") and `مقدار انتقال داده را کمتر کنید` ("reduce data transfer volume").

**Source**: Apps Script itself. Apps Script localizes its system error pages based on the deploying Google account's locale (fa-IR for Persian) and/or the request-origin IP.

**Trigger**: Account is Persian-locale (common for Iranian users) AND hit a quota threshold (cause 3) OR an internal Google-side hiccup.

**Disambiguator**: With `DIAGNOSTIC_MODE = true`, cause 1 returns explicit JSON; if Persian HTML still appears, it's not our script — it's Apps Script's own response.

**Important**: w0l4i's case in #404 traced through several wrong hypotheses before landing here:
- Initially diagnosed as AUTH_KEY mismatch → no, mixed success/failure on same `script_id`
- Then diagnosed as third-party relay (`g.workstream.ir` looks Iranian) → no, w0l4i clarified it's his own tunnel
- Then diagnosed as Iranian VPS provider appliance → no, Hetzner Nuremberg
- Final landing: Apps Script's own Persian-localized quota response based on Google account locale

This iteration is documented because the false starts are instructive — don't lock in on the first hypothesis.

**Fix**: Same as cause 3 (it's a quota issue presenting as Persian HTML).

### 6. Workspace landing HTML for account-flagged deployments

**Body**:
```html
<html lang="fa" dir="rtl">
<head>
  <meta name="description" content="پردازش کلمه وب، ارائه‌ها و صفحات گسترده"...
  <title>...</title>
```

The body is Google Workspace's landing page (the description "Word web processing, presentations, and spreadsheets" is the standard tagline for Google Docs/Sheets/Slides). It's served by Apps Script when the deployment owner's Google account is in a flagged state (post-warning, pre-suspension).

**Source**: Apps Script refuses to execute the deployed script when the owning account is restricted, and serves the Workspace landing page as a "log in" prompt instead.

**Trigger**: Account is in stage 1b or stage 2 of the suspension progression (see `issue-patterns.md` Pattern 8). Often correlates with phone-less new accounts that ignored the "action required" prompt.

**Disambiguator**: Owner of the deployment can log in to Google → see if there are pending warnings or restrictions. If yes → fix the account (add phone) or rotate the deployment to a healthier account.

**Fix**: Account-side, not config-side. Add phone verification, OR move to a different deployment owner via #325 workflow.

## v1.8.3 detection logic

```rust
// In src/tunnel_client.rs around line 893+
if err_msg.contains("The script completed but did not return anything") {
    tracing::error!(
        "batch failed (script {}): got the v1.8.0 decoy/placeholder body — \
         could be (1) AUTH_KEY mismatch (run a direct curl probe against \
         the deployment to verify), (2) Apps Script execution timeout or \
         per-100s quota tear (try lowering parallel_concurrency), \
         (3) Apps Script internal hiccup (transient, retry next batch), \
         or (4) ISP-side response truncation (#313 pattern, try a \
         different google_ip). To distinguish (1) from the rest: set \
         DIAGNOSTIC_MODE=true at the top of Code.gs + redeploy as new \
         version — only AUTH_KEY mismatch returns this body in diagnostic \
         mode.",
        sid_short
    );
}
```

This is the v1.8.2 string. v1.8.3 adds detection for the Persian quota body and the Workspace landing HTML as separate paths.

## When responding to users showing this log

The right response shape is:

1. **Acknowledge** the log line they pasted
2. **Enumerate** the 6 (or 4-5 in older versions) candidate causes briefly
3. **Identify the most likely** for their specific case using context clues:
   - Single-deployment user, fresh setup → likely cause 1 (AUTH_KEY)
   - Mixed success/failure on same script_id → NOT cause 1 (AUTH_KEY would fail 100%)
   - "Worked yesterday, broken today" → likely cause 4 (ISP throttle) or cause 8 (account flag in progression)
   - High concurrency / many devices on one deployment → likely cause 3 (quota) or cause 5 (Persian quota variant)
   - Persian HTML body → cause 5 or 6
   - Hetzner/Iranian VPS Full-mode user → check if VPS is actually Iranian (provider appliance is real for Iranian VPS only)
4. **Give the disambiguator**: DIAGNOSTIC_MODE flip + redeploy
5. **Give the immediate workaround** appropriate to the most-likely cause

Don't claim certainty before disambiguator data. v1.8.1 over-asserted; v1.8.3 explicitly enumerates because we learned to.

## What v1.8.x roadmap is doing about this

- **Per-script_id error-category counter** — surface in CLI/UI: "deployment AKfycbz1: 95% success, 4% timeout, 1% quota, 0% auth_mismatch over last 5 min". Lets users diagnose without flipping DIAGNOSTIC_MODE.
- **Distinct error categories in client logs** — separate AUTH_KEY mismatch / timeout / quota / ISP truncation / Persian quota / Workspace landing into 6 distinct error log lines. Currently merged.
- **AIMD per-deployment auto-throttle** — automatically lower `parallel_concurrency` for deployments that hit quota too often. Find the sustainable rate per deployment without manual tuning.

These are queued for v1.8.x batch (~2-4 weeks).
