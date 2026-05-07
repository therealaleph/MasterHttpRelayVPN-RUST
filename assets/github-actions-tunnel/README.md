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
| 2 | ngrok Tunnel | [ngrok.md][ngrok] | ngrok (free) | New URL each session | ✅ Works |
| 3 | cloudflared Named Tunnel | [cloudflared-named.md][named] | Cloudflare + domain | **Permanent URL** | ⚠️ See note below |

> **⚠️ Important — cloudflared methods may not work from Iran ISP.** Apps Script
> outbound runs from Google datacenter IPs, which Cloudflare's anti-bot system
> flags as bots and serves a 403 / Persian Google Docs error page (#849). This
> blocks the Apps Script → trycloudflare.com / your-domain step. **If you're on
> Iran ISP, start with Method 2 (ngrok) instead** — ngrok's edge IPs are not
> on Cloudflare's flagged list. cloudflared Methods 1 and 3 may still work for
> users on networks where Cloudflare's anti-bot heuristics aren't firing
> against Apps Script's outbound, so they're documented for completeness.

**New to Full tunnel mode?** If you're on Iran ISP, start with [Method 2 (ngrok)][ngrok]
— it's the most reliable. If you're on a network where CF anti-bot doesn't
fire against Google datacenter IPs, [Method 1 (cloudflared Quick)][quick] is
the simplest (no third-party signup).

**Need a stable URL that survives restarts?** Use [Method 3][named] — requires
a one-time Cloudflare CLI setup but the URL never changes.

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

For methods where the URL changes each session (1 and 2), steps 2–4 must be
repeated each time the workflow runs. Method 3 uses a permanent URL — configure
`CodeFull.gs` once and only re-trigger the workflow when needed.

## Limitations

- **6-hour maximum per session.** GitHub Actions enforces a 360-minute timeout
  on hosted runners. Re-trigger the workflow for another session.
- **URL changes on restart (Methods 1 & 2).** The tunnel URL is assigned at
  runtime. `CodeFull.gs` must be updated and redeployed each time.
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
