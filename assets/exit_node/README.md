# Exit node — bypassing CF anti-bot for ChatGPT / Claude / Grok / X

Many Cloudflare-fronted services flag traffic from Google datacenter
IPs as bots and serve a Turnstile / CAPTCHA / 502 challenge instead of
the real page. `UrlFetchApp.fetch()` in Apps Script always exits from
Google's datacenter IP space, so for sites like:

- **chatgpt.com / openai.com**
- **claude.ai**
- **grok.com / x.com**

…mhrv-rs's normal apps_script-mode path returns errors like `Relay
error: json: key must be a string at line 2 column 1` or `502 Relay
error` because Code.gs is wrapping a CF challenge HTML page that the
client can't parse as relay JSON.

The **exit node** is a small TypeScript HTTP handler you deploy on a
serverless TypeScript host you control. It sits between Apps Script
and the destination, so the request chain becomes:

```
Browser ─┐                                                ┌─→ Destination
         │                                                │   (chatgpt.com)
         ▼                                                │
    mhrv-rs                                               │
       │                                                  │
       │  TLS to Google IP, SNI=www.google.com (DPI cover)│
       ▼                                                  │
   Apps Script (Google datacenter)                        │
       │                                                  │
       │  UrlFetchApp.fetch(EXIT_NODE_URL)                │
       ▼                                                  │
    your exit node (non-Google IP)                        │
       │                                                  │
       │  fetch(real_url)                                 │
       └──────────────────────────────────────────────────┘
```

The destination sees the exit node's outbound IP, not a Google
datacenter IP. CF's anti-bot heuristic doesn't fire and the real page
comes back.

**Important property preserved:** the user-side leg (Iran ISP →
Apps Script) is unchanged. The ISP only sees TLS to a Google IP — the
second hop happens entirely inside Apps Script's outbound, invisible
from the user's network. The DPI evasion property mhrv-rs is built
around stays intact.

## Setup

The handler in [`exit_node.ts`](exit_node.ts) is plain TypeScript that
uses only web-standard APIs (`Request`, `Response`, `fetch`). It runs
on any platform with a serverless-fetch runtime.

### Generic steps (apply to every host)

1. **Open `exit_node.ts`** and replace the placeholder PSK at the top:
   ```ts
   const PSK = "<your-strong-secret>";
   ```
   Generate a strong secret with `openssl rand -hex 32`. **Do not leave
   the placeholder** — the script is deliberately fail-closed (returns
   503 on every request until the placeholder is replaced) so a fresh
   deploy without configuration can't accidentally serve as an open
   relay.
2. **Deploy** to your chosen host (see options below).
3. **Copy the public URL** of the deployed handler.
4. **In `mhrv-rs` config.json**, add an `exit_node` block:
   ```json
   "exit_node": {
     "enabled": true,
     "relay_url": "https://your-deployed-exit-node.example.com",
     "psk": "<the same PSK you set in step 1>",
     "mode": "selective",
     "hosts": ["chatgpt.com", "claude.ai", "x.com", "grok.com", "openai.com"]
   }
   ```
5. **Restart mhrv-rs** (Disconnect + Connect, or kill + restart the
   binary).
6. **Test** — open `chatgpt.com` or `grok.com` from a browser pointed
   at mhrv-rs's proxy. You should see the real login page, not a CF
   challenge.

A complete example config is at
[`config.exit-node.example.json`](../../config.exit-node.example.json)
in the repo root.

### Hosting options

The script is one self-contained file. Pick whichever host you can
sign up for and trust:

| Host | Notes |
|---|---|
| **Deno Deploy** ([deno.com/deploy](https://deno.com/deploy)) | Free tier covers personal use. Deploy via `deployctl deploy --prod exit_node.ts` or via GitHub Actions. Same web-standard API as the script expects. |
| **fly.io** | Free tier with limits. Wrap the handler in a thin server (`Deno.serve(handler)` for Deno or an Express wrapper for Node) + add a Dockerfile. Persistent IPs, picks geographic region. |
| **Your own VPS** | Run `deno run --allow-net wrapper.ts` where `wrapper.ts` does `Deno.serve({ port: 8443 }, handler)`. Most control, ~$3-5/mo. |
| **Cloudflare Workers** | **Doesn't help.** CF Workers exit through CF's own IP space, which CF anti-bot still flags as worker-internal traffic. |

For most users running locally, Deno Deploy is the fastest setup. For
a long-term deployment you control end-to-end, your own small VPS is
ideal.

## `selective` vs `full`

| Mode | What it does | When to use |
|---|---|---|
| `selective` (default) | Only hosts in `hosts` route via the exit node; everything else takes the normal Apps Script path | Recommended. The exit-node hop adds ~200-500ms per request, so reserve it for sites that actually need a non-Google IP. |
| `full` | Every request routes via the exit node | Only when your entire workload is CF-anti-bot affected, or when your exit node is faster than Apps Script on your network path (rare). Burns the exit node's runtime budget on sites that don't need it. |

## Behaviour on failure

If the exit node is unreachable, returns 5xx, or returns a malformed
response, mhrv-rs **automatically falls back to the regular Apps
Script relay**. The log shows a `warn: exit node failed for ... —
falling back to direct Apps Script` line. The CF-affected sites then
fail (CF challenge), but every other site keeps working — a downed
exit node doesn't take you fully offline.

## Security model

The PSK is the only thing keeping the deployed endpoint from being a
public open proxy. Treat it like a password:

- **Don't commit** the PSK to source control. Most TypeScript hosts
  default deployed code to private; keep it that way.
- **Don't share publicly.** Anyone with both the URL and the PSK can
  use the deployment as their own proxy and burn your runtime quota.
- **Rotate** if you suspect a leak. Change the PSK in the deployed
  source, redeploy, then update `psk` in `mhrv-rs` config.json and
  restart.

The script also includes a **loop guard** (refuses to fetch its own
host) and a **placeholder check** (returns 503 if `PSK ===
"CHANGE_ME_TO_A_STRONG_SECRET"`) so a fresh deploy without
configuration can't be accidentally served as an open relay.

## Why isn't this on by default?

- Adds ~200-500ms per request through the exit-node hop
- Burns the host's free-tier runtime quota
- No benefit for sites that don't have CF anti-bot
- Requires signing up for a separate third-party platform

So `enabled: false` is the default. Users who specifically need
ChatGPT / Claude / Grok opt in; everyone else runs lighter.

## Troubleshooting

**`exit node refused or errored: unauthorized`** — PSK mismatch.
Double-check `psk` in `config.json` matches the `PSK` constant in your
deployed source character-for-character. Whitespace and quoting
matter.

**`exit_node misconfigured: PSK is still the placeholder`** — you
forgot to replace `CHANGE_ME_TO_A_STRONG_SECRET` in the source. Edit
the deployed file, save, redeploy.

**`exit node failed for ...: connection refused`** — the URL is wrong
or the deployment isn't live. Verify by hitting the URL in a browser
— it should respond with `{"e":"method_not_allowed"}` (the script
expects POST).

**`exit node failed for ...: timeout`** — the host's outbound or the
destination is slow. Try a different region, or accept the latency
trade-off.

**Site still shows a CF challenge after enabling the exit node** —
CF has flagged your host's IP too. Some hosting providers' outbound
IP space is on CF's bot blocklist. Workarounds: try a different host
(your own VPS gives you a clean IP), or add the affected site to
`passthrough_hosts` to bypass the MITM and use your real ISP IP.

## See also

- [Persian (راهنمای فارسی)](README.fa.md) version of this doc
- [`exit_node.ts`](exit_node.ts) — the handler source (with hardening)
- [`config.exit-node.example.json`](../../config.exit-node.example.json)
  — complete example mhrv-rs config
- Issue [#382](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/382)
  — canonical thread tracking Cloudflare anti-bot
- Issue [#309](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/309)
  — roadmap for CF WARP integration (alternative approach, longer-horizon)
