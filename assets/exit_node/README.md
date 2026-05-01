# Exit node — bypass Cloudflare anti-bot for ChatGPT / Claude / Grok / X

Many Cloudflare-protected services flag traffic from Google datacenter
IP ranges as bots and serve a Turnstile / interactive CAPTCHA / 502
challenge instead of the actual page. Apps Script's `UrlFetchApp.fetch()`
exits from those Google datacenter IPs, so for sites like:

- **chatgpt.com / openai.com** (Cloudflare anti-bot, often blocks GCP IPs)
- **claude.ai** (same)
- **grok.com / x.com** (CF-fronted, returns 502 on Google IPs)

…the regular mhrv-rs apps_script-mode path returns errors like
`Relay error: json: key must be a string at line 2 column 1` or
`502 Relay error` because Code.gs is wrapping a CF challenge HTML
page that the client can't make sense of.

The **exit node** is a small TypeScript HTTP endpoint deployed on a
serverless platform (val.town, Deno Deploy, fly.io, etc.) that sits
between Apps Script and the destination. The traffic chain becomes:

```
Browser ─┐                                                    ┌─→ Destination
         │                                                    │   (chatgpt.com)
         ▼                                                    │
    mhrv-rs                                                   │
       │                                                      │
       │  TLS to Google IP, SNI=www.google.com (DPI cover)    │
       ▼                                                      │
   Apps Script (Google datacenter)                            │
       │                                                      │
       │  UrlFetchApp.fetch(EXIT_NODE_URL)                    │
       ▼                                                      │
    val.town (non-Google IP)                                  │
       │                                                      │
       │  fetch(real_url)                                     │
       └──────────────────────────────────────────────────────┘
```

The destination sees the val.town IP, not Google datacenter. CF's
anti-bot heuristic doesn't fire, and you get the actual page.

Crucially: **the user-side leg (Iran ISP → Apps Script) is unchanged.**
The ISP still only sees TLS to a Google IP — the second hop happens
entirely inside Apps Script's outbound, invisible from the user's
network. So the DPI evasion property mhrv-rs is built around stays
intact.

## Setup

1. **Sign up at [val.town](https://val.town)** (free tier is fine —
   the free tier's outbound bandwidth is enough for personal use).
2. **Create a new HTTP val** (TypeScript). On val.town: New → HTTP.
3. **Paste the contents of `valtown.ts`** from this directory.
4. **Set the PSK** at the top of the file:
   ```ts
   const PSK = "<your-strong-secret>";
   ```
   Generate a strong secret with `openssl rand -hex 32` from a terminal.
   **Don't leave the placeholder in production** — the val.town code
   intentionally fails closed (returns 503 on every request) until
   you replace the placeholder, so you can't accidentally serve as
   an open relay.
5. **Save** the val. Copy the val's public URL — it looks like
   `https://your-handle-mhrv.web.val.run`.
6. **In your mhrv-rs `config.json`**, add an `exit_node` block:
   ```json
   "exit_node": {
     "enabled": true,
     "relay_url": "https://your-handle-mhrv.web.val.run",
     "psk": "<the same PSK you set in step 4>",
     "mode": "selective",
     "hosts": ["chatgpt.com", "claude.ai", "x.com", "grok.com", "openai.com"]
   }
   ```
7. **Restart mhrv-rs** (Disconnect + Connect, or `kill` + restart the
   binary).
8. **Test** — visit `chatgpt.com` or `grok.com` from a browser pointed
   at the mhrv-rs proxy. You should see the actual login page now,
   not a CF challenge.

A complete example config is at
[`config.exit-node.example.json`](../../config.exit-node.example.json)
in the repo root.

## How `selective` vs `full` mode pick

| Mode | What it does | When to use |
|---|---|---|
| `selective` (default) | Only hosts in `hosts` route via exit node; everything else takes the regular Apps Script path | Recommended. The exit-node hop adds ~200-500ms per request, so reserve it for sites that need a non-Google IP. |
| `full` | Every request routes via exit node | Only useful when your entire workload is CF-anti-bot affected, or when the exit node happens to be faster than Apps Script alone for your network path (rare). Burns val.town runtime budget for sites that don't need it. |

## Failure mode

If the exit node is unreachable, returns a 5xx, or returns a malformed
response, mhrv-rs **falls back to the regular Apps Script relay
automatically**. You'll see a `warn: exit node failed for ... — falling
back to direct Apps Script` line in the log. Sites that need the exit
node will fail in that case (CF challenge), but other sites work
normally — a down exit node doesn't take you fully offline.

## Security model

The PSK is the only thing keeping the val.town endpoint from being a
public open proxy. Treat it like a password:

- **Don't commit** the PSK to source control. The val.town source
  is private to your account by default; keep it that way.
- **Don't share** the PSK publicly. Anyone who has both the URL and
  the PSK can use your val.town quota as their own proxy.
- **Rotate** if you suspect leak. Change the PSK in val.town source,
  save, then update `psk` in mhrv-rs `config.json` and restart.

The val.town script also includes a **loop guard** (refuses to fetch
its own host) and **placeholder check** (returns 503 if `PSK ===
"CHANGE_ME_TO_A_STRONG_SECRET"`) so a fresh deploy without setup can't
accidentally serve as an open relay.

## Alternative platforms

The `valtown.ts` script is plain TypeScript using web-standard APIs
(`Request`, `Response`, `fetch`). It runs on:

- **val.town** — easiest, free tier sufficient for personal use
- **Deno Deploy** — similar API; deploy with `deployctl`
- **fly.io** — needs a `Dockerfile` wrapper; gives you a fixed
  geographic region
- **Cloudflare Workers** — won't help (CF Workers exit from CF's own
  IP space, which CF anti-bot still flags as worker-internal)

For most users, val.town's the right choice. Deno Deploy if you want
a non-val.town option for redundancy.

## Why not always-on by default

- Adds 200-500ms per request (extra hop)
- Burns val.town's free-tier bandwidth budget
- Offers no benefit for sites that don't have CF anti-bot
- Setup requires a separate account on a third-party platform

So `enabled: false` is the default. Users who care about ChatGPT /
Claude / Grok specifically opt in; everyone else runs lighter.

## Troubleshooting

**`exit node refused or errored: unauthorized`** — PSK mismatch.
Check that the `psk` in `config.json` exactly matches the `PSK`
constant in val.town. Whitespace and quoting matter.

**`exit node refused or errored: exit_node misconfigured: PSK is still
the placeholder`** — you forgot to replace `CHANGE_ME_TO_A_STRONG_SECRET`
in val.town. Edit + save the val.

**`exit node failed for ...: connection refused`** — the val.town URL
is wrong or the val isn't deployed. Verify by hitting the URL directly
from a browser — it should return `{"e":"method_not_allowed"}` (val
expects POST).

**`exit node failed for ...: timeout`** — val.town outbound is slow
or the destination is slow. Try a different val.town deployment region,
or accept the latency trade-off.

**Site still shows CF challenge after enabling exit node** — CF is
flagging val.town's IP too. Some CF customers explicitly blocklist
val.town. Workarounds: try Deno Deploy instead, or add the site to
`passthrough_hosts` (bypasses MITM entirely; uses your real ISP IP).

## See also

- [Persian translation](README.fa.md) of this doc
- [`valtown.ts`](valtown.ts) — the val.town source (with hardening)
- [`config.exit-node.example.json`](../../config.exit-node.example.json)
  — complete example config
- Issue [#382](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/382)
  — canonical Cloudflare anti-bot tracking thread
- Issue [#309](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/309)
  — CF WARP integration roadmap (alternative approach, longer-horizon)
