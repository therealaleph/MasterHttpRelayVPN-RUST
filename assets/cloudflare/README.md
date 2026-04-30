# Cloudflare Worker exit (alternative Apps Script backend)

> *فارسی: [README.fa.md](README.fa.md)*

This directory ships a **Cloudflare Worker** that pairs with [`assets/apps_script/Code.cfw.gs`](../apps_script/Code.cfw.gs) to give you a different shape of `apps_script` mode:

```
mhrv-rs ──► Apps Script (Code.cfw.gs) ──► Cloudflare Worker ──► target
            ▲ thin auth + forward          ▲ outbound fetch + base64
```

The standard backend (`assets/apps_script/Code.gs`) does the outbound fetch from inside Apps Script directly. This variant makes Apps Script a thin relay and pushes the actual fetch to Cloudflare's edge. **mhrv-rs itself is unchanged** — same JSON envelope on the wire, same `mode: "apps_script"` in `config.json`, same `script_id`. The only thing that's different is what your deployed Apps Script does after it authenticates the request.

Original idea: <https://github.com/denuitt1/mhr-cfw>. This copy adds an `AUTH_KEY` check on the Worker, the decoy-on-bad-auth treatment from `Code.gs`, and a hop-loop guard.

## When this is worth it

✅ Browsing, page navigation, chat-style traffic — visibly snappier. Per-call latency drops from the ~250-500 ms Apps Script floor to ~10-50 ms at the CF edge.
✅ Telegram realtime — small frequent messages benefit most.
✅ Networks where the Apps Script *runtime* quota (90 min/day on consumer Google accounts) is what you hit before the URL-fetch count cap. GAS spends almost no time per call here.

❌ **No `UrlFetchApp` daily-count relief today.** mhrv-rs's HTTP relay path emits a single-URL envelope per request, never the `q: [...]` batch shape, so each user request still consumes one GAS UrlFetchApp call regardless of which `Code.gs` variant is deployed. The `Code.cfw.gs` ↔ Worker path *is* batch-aware (chunks at 40, Worker fans out via `Promise.all`, costs `ceil(N / 40)` per batch instead of N), but that branch is unreachable from any shipping client. **Until/unless mhrv-rs grows HTTP-relay batching, the daily 20k-fetch ceiling is unchanged from `Code.gs`.** The ready batching support is left in place for forward compatibility — it costs nothing and goes live the day a batching client lands.
❌ YouTube long-form video — gets **worse**, not better. Apps Script allows ~6 min wall per execution; CF Workers cap at 30 s. The SABR cliff arrives sooner. Stay on `Code.gs` for YouTube-heavy use.
❌ Sites behind Cloudflare anti-bot (Twitter/X, OpenAI, etc.) — exit IP becomes a Workers IP, which CF's own anti-bot fingerprints as a worker-internal request. Often *stricter* than a Google IP. This is a separate problem from DPI bypass and neither variant fixes it.
❌ When/if HTTP-relay batching ships, the 30 s wall would apply to **the slowest URL in each chunk**, not per-URL — a single hung target could drag a 40-URL chunk to timeout. mhrv-rs's existing per-item retry would absorb this, but it's a behavioral change vs the per-URL `fetchAll` wall under `Code.gs`. (Inert today since no batching client exists.)

## Setup

You need three matching strings: an `AUTH_KEY` shared between `worker.js`, `Code.cfw.gs`, and your `mhrv-rs` `config.json`. Pick a strong random secret once and paste it into all three.

### 1. Deploy the Worker

1. Open <https://dash.cloudflare.com/> → **Workers & Pages** → **Create** → **Hello World** → **Deploy**.
2. Click **Edit code**, delete the template, and paste the contents of [`worker.js`](worker.js).
3. Change the `AUTH_KEY` constant near the top of the file to your strong secret.
4. **Deploy**. Copy the `*.workers.dev` URL — you'll need it next.

### 2. Deploy the Apps Script

1. Open <https://script.google.com> while signed into your Google account → **New project** → delete the default code.
2. Paste the contents of [`../apps_script/Code.cfw.gs`](../apps_script/Code.cfw.gs).
3. Set both constants at the top:
   - `AUTH_KEY` — the same secret you set in `worker.js`.
   - `WORKER_URL` — the full `https://…workers.dev` URL of the Worker you just deployed (must include the scheme).
4. **Deploy → New deployment → Web app**: *Execute as* = **Me**, *Who has access* = **Anyone**.
5. Copy the **Deployment ID**.

### 3. Point mhrv-rs at the Apps Script

In `config.json` (or via the UI's config form):

```json
{
  "mode": "apps_script",
  "script_id": "PASTE_DEPLOYMENT_ID_HERE",
  "auth_key": "SAME_SECRET_AS_BOTH_FILES_ABOVE"
}
```

That's it. mhrv-rs doesn't need to know Cloudflare exists; from its perspective, the `script_id` deployment behaves like any other. If you have multiple deployments (some plain, some CFW), `script_ids: [...]` round-robins across all of them and the parallel-relay fan-out still works.

## Why three matching `AUTH_KEY`s

- **mhrv-rs ↔ Apps Script**: prevents random POSTs to your `*.googleusercontent.com` deployment from being relayed. Probes that don't carry the key get the decoy HTML page (`DIAGNOSTIC_MODE = false` in `Code.cfw.gs`), so the deployment looks like a forgotten placeholder rather than a tunnel.
- **Apps Script ↔ Worker**: prevents random POSTs to your `*.workers.dev` Worker from being relayed if the Worker URL ever leaks. Without this check the Worker becomes an open HTTP-relay for arbitrary attackers. The upstream `mhr-cfw` Worker omits it; this copy adds it back.

If you want compartmentalization (different secret on each leg), edit `Code.cfw.gs` to send a different `k` to the Worker than the one it accepts from mhrv-rs. The single-secret setup is the simplest correct configuration.

## Verifying it works

Same procedure as the standard backend: open <https://ipleak.net> through the proxy. You should see a Cloudflare-owned IP (since the actual fetch now exits Cloudflare's network), not a Google-owned one as you would with `Code.gs`. If you see your real IP, the proxy isn't being used; if you see a Google IP, you deployed `Code.gs` instead of `Code.cfw.gs`.

The `Test` button in the desktop UI still works — it does a HEAD relay through whichever Apps Script deployment you configured.

## Trade-off table at a glance

| Axis | `Code.gs` (standard) | `Code.cfw.gs` (this variant) |
|---|---|---|
| Per-call latency floor | ~250-500 ms (GAS internal hop) | ~10-50 ms (CF edge) |
| Apps Script `UrlFetchApp`/day, **what mhrv-rs sends today** | 1 quota / request | 1 quota / request — same (mhrv-rs only emits single-URL envelopes) |
| Apps Script `UrlFetchApp`/day, **if a future client batches** | N quota (one per URL via `fetchAll`) | `ceil(N / 40)` quota (chunks at 40, Worker fans out via `Promise.all`) |
| CF Workers requests/day (free tier) | n/a | 100 000 — far above what GAS can feed it; not the binding ceiling |
| Apps Script runtime/day | 90 min, often binding | 90 min, rarely binding |
| Per-execution wall budget | ~6 min, per-URL | 30 s, per-call (would become per-chunk if batching ships) |
| Per-response size cap | ~50 MB (Apps Script doc'd) | bounded by Worker memory (128 MB free tier); ~tens of MB in practice with the base64 conversion |
| Response header casing | preserved as origin sent it | lowercased (Workers' `Headers.forEach` normalises). Matters only for downstream tools that compare header names case-sensitively; mhrv-rs is case-insensitive. |
| YouTube long-form playback | OK (6-min cliff) | WORSE (30-s cliff) |
| Telegram / chat snappiness | baseline | noticeably better |
| Cloudflare anti-bot on target | datacenter IP | worker-internal IP (often stricter) |
| Spreadsheet response cache | available (opt-in) | not in this variant |
| Deployment complexity | 1 thing to maintain | 2 things to keep in sync |

If those trade-offs land on the right side for you, deploy this variant. If not — or if you don't have a Cloudflare account — stay on `Code.gs`.

## Important limitation: not compatible with `mode: "full"`

`Code.cfw.gs` only ports the HTTP-relay path (modes 1 + 2 in `CodeFull.gs`). The raw-TCP/UDP tunnel ops that `mode: "full"` depends on (modes 3 + 4 in `CodeFull.gs` — required for Android full-mode coverage of WhatsApp / Telegram / messengers / any non-HTTPS-MITM-able app) are **not** ported. If you're on full mode and looking for messenger speed-ups, this variant won't help — that's a different design that would need to ride on top of Cloudflare's TCP Sockets API + Durable Objects, with no equivalent for UDP. See the discussion in [issue #380](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/issues/380) for context.
