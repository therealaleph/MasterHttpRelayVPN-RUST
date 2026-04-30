# Apps Script source

Three deploy-ready Apps Script files live here. They all speak the same `{k, m, u, h, b, ct, r}` wire protocol with `mhrv-rs`, so the client just points its `script_id` at whichever deployment you want — no mode change required.

## Variants and origins

- **`Code.gs`** — standard relay. **Verbatim mirror of upstream.** Apps Script does the outbound fetch itself. This is the default choice for most users.
  - Upstream: <https://github.com/masterking32/MasterHttpRelayVPN/blob/python_testing/apps_script/Code.gs>
  - Credit: [@masterking32](https://github.com/masterking32). We do not modify this file.
  - The mirror lives here so that (a) users on networks where `raw.githubusercontent.com` is unreachable can still deploy from a `git clone` / ZIP, and (b) we have a snapshot to diff against if upstream changes silently break the informal relay protocol.

- **`CodeFull.gs`** — superset of `Code.gs` that additionally proxies raw-TCP / UDP via `tunnel-node` (used by `mode: "full"`). **Maintained in this repo** — written for this Rust port and not present upstream. Deploy this if you want full-tunnel mode; details in the file's header comment.

- **`Code.cfw.gs`** — Apps Script becomes a thin auth+forward layer; the actual outbound fetch happens on a Cloudflare Worker you also deploy ([`assets/cloudflare/`](../cloudflare/)). **Derivative work — not unmodified upstream.** The pattern of forwarding through a Cloudflare Worker came from [denuitt1/mhr-cfw](https://github.com/denuitt1/mhr-cfw); this file inherits hardening from `Code.gs` (decoy-on-bad-auth, fail-closed sentinels) and adds chunked batch forwarding (`Promise.all` on the Worker side, `ceil(N/40)` GAS calls per batch) that the upstream `mhr-cfw` does not have. Faster per-call latency, worse YouTube long-form, no fix for Cloudflare anti-bot. Read [`assets/cloudflare/README.md`](../cloudflare/README.md) before choosing this one.

## What you must edit before deploying

For every variant: change `AUTH_KEY` from its placeholder to a strong secret, and use that same string in your `mhrv-rs` config's `auth_key`. `Code.cfw.gs` additionally requires setting `WORKER_URL` to your deployed Cloudflare Worker URL; `CodeFull.gs` additionally requires `TUNNEL_SERVER_URL` and `TUNNEL_AUTH_KEY` for the tunnel-node leg.
