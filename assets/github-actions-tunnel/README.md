# GitHub Actions Full Tunnel

A temporary, repeatable Full tunnel mode for users who cannot or prefer not to
purchase a VPS. Uses GitHub Actions free hosted runners to run the official
`mhrv-tunnel-node` container for 6-hour sessions at no cost.

## Who This Is For

- Users who cannot access international payment methods to purchase a VPS
- Users who need Full tunnel mode occasionally — CAPTCHA-protected sites,
  streaming, or services that require a real browser
- Users who want to test Full tunnel mode before committing to a permanent VPS
- Users in networks where the standard `apps_script` mode is sufficient for
  daily browsing, but Full mode is needed for specific use cases

## How It Works

1. A GitHub Actions workflow starts the official `mhrv-tunnel-node` Docker
   container on a free hosted runner
2. A tunneling service (cloudflared or ngrok) exposes the container to the
   internet on a public URL
3. `CodeFull.gs` is configured to forward tunnel traffic to this URL
4. The runner stays alive for 6 hours, then shuts down automatically
5. The workflow can be re-triggered at any time for another 6-hour session

## Available Methods

Three methods are provided, ordered by setup complexity. Each is documented in
its own guide with step-by-step instructions.

| # | Method | Guide | Account Required | URL Behavior | Iran ISP friendly? |
|---|---|---|---|---|---|
| 1 | cloudflared Quick Tunnel | [cloudflared-quick.md][quick] | None | New URL each session | ⚠️ See note below |
| 2 | ngrok Tunnel | [ngrok.md][ngrok] | ngrok (free) | **Permanent URL** | ⚠️ `.dev` TLD blocked on some ISPs |
| 3 | cloudflared Named Tunnel | [cloudflared-named.md][named] | Cloudflare + domain | **Permanent URL** | ⚠️ See note below |

> **⚠️ ngrok `*.ngrok-free.dev` block (early 2026).** Free-tier ngrok now
> auto-assigns `*.ngrok-free.dev` domains exclusively for new accounts (the
> older `*.ngrok-free.app` is grandfathered for existing accounts only and
> cannot be claimed). Some Iran ISPs (TCI, Irancell, IRMCI confirmed via
> #924) block `*.ngrok-free.dev` at DNS or TCP. Symptom: `curl` from your
> network to your ngrok URL times out, but works from a non-Iran machine.
> Workarounds: try **Method 1 (cloudflared Quick)** as a different TLD, or
> pay $10/mo for ngrok Personal plan to get `*.ngrok.app` instead.
>
> **⚠️ cloudflared methods may not work from Iran ISP.** Apps Script
> outbound runs from Google datacenter IPs, which Cloudflare's anti-bot
> system sometimes flags as bots and serves a 403 / Persian Google Docs
> error page (#849). cloudflared Methods 1 and 3 may still work for users
> on networks where Cloudflare's anti-bot heuristics aren't firing against
> Apps Script's outbound — try them and check.

**New to Full tunnel mode?** Try [Method 2 (ngrok)][ngrok] first — it's the
fastest setup and gives a permanent URL on the free tier. If `*.ngrok-free.dev`
is blocked on your ISP (curl times out), switch to [Method 1 (cloudflared
Quick)][quick] — different TLD, sometimes passes where ngrok's `.dev`
doesn't. If both fail, see the **Alternative hosts** section below.

**Need a stable URL on a CF-friendly domain?** Use [Method 3][named] — requires
a one-time Cloudflare CLI setup with your own domain.

## Alternative hosts (when GitHub Actions tunnels don't work)

If both ngrok and cloudflared paths are blocked on your network, run
`mhrv-tunnel-node` somewhere that doesn't rely on a third-party tunnel:

- **HuggingFace Spaces (Docker SDK)**: free, permanent `*.hf.space` URL,
  no tunnel layer needed. Create a Space → pick Docker SDK → small
  Dockerfile that runs `ghcr.io/therealaleph/mhrv-tunnel-node:latest`.
  16 GB storage, 2 vCPU. Most Iran-friendly option in 2026.
- **Replit (Deno repl)**: signup with email, free tier. Run
  `mhrv-tunnel-node` and the Repl exposes a public URL.
- **Your own VPS**: Hetzner / Vultr / DigitalOcean / ArvanCloud. ~$3-5/mo.
  See [tunnel-node README](../../tunnel-node/README.md) for Docker setup.

## Shared Requirements

All methods share these requirements:

| Requirement | Details |
|---|---|
| GitHub account | Free. Repository must be private to keep secrets secure. |
| Google account | Free. Used to deploy `CodeFull.gs`. |
| `CodeFull.gs` deployed | See the main project documentation for deployment instructions. |
| `TUNNEL_AUTH_KEY` secret | A strong password shared between the workflow and `CodeFull.gs`. |

## After Starting the Tunnel

1. Run the workflow from your repository's **Actions** tab
2. Copy the `TUNNEL_SERVER_URL` from the workflow log output
3. Update the `TUNNEL_SERVER_URL` constant in `CodeFull.gs`
4. Deploy `CodeFull.gs` (Deploy → New Deployment → Web App)
5. Configure your `mhrv-rs` client to use the new deployment in Full mode

For Method 1 (cloudflared Quick) the URL is fresh every session, so steps 2–4
must be repeated each time. For Method 2 (ngrok), free-tier accounts now get a
**static domain** by default — once assigned, the URL is the same across runs
and `CodeFull.gs` only needs to be updated once. Method 3 uses a permanent
URL — configure `CodeFull.gs` once and only re-trigger the workflow when
needed.

## Limitations

- **6-hour maximum per session.** GitHub Actions enforces a 360-minute timeout
  on hosted runners. Re-trigger the workflow for another session.
- **URL changes on restart (Method 1).** cloudflared Quick assigns a fresh
  `*.trycloudflare.com` URL at runtime. `CodeFull.gs` must be updated and
  redeployed each session. Method 2 (ngrok) keeps the same URL across runs
  on accounts with a static domain assigned (the free-tier default).
- **Shared IP ranges.** GitHub-hosted runners share IP ranges with other users.
  Some websites may already have these IPs flagged.(sometimes need re-run)
- **GitHub Actions terms.** This workflow is intended for occasional personal
  use. Review [GitHub's Terms for Additional Products and Features][gh-terms]
  and ensure your usage complies.

## Compliance Note

This workflow uses GitHub-hosted runners for a purpose adjacent to, but not
directly part of, software development on the repository. Usage is low-burden
(a single Docker container, moderate outbound traffic for one user) and aligns
with GitHub's acceptable use guidelines for development and testing
infrastructure. Continuous, high-bandwidth, or commercial use is not
recommended. For persistent Full mode operation, a dedicated VPS remains the
recommended solution.

[quick]: cloudflared-quick.md
[ngrok]: ngrok.md
[named]: cloudflared-named.md
[gh-terms]: https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features#actions
