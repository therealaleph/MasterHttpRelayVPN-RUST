# Multi-edge fronting groups

The default mhrv-rs SNI-rewrite path targets Google's edge: TLS goes out
with `SNI=www.google.com` to a Google IP, the inner `Host` header (after
the local MITM CA terminates the browser's TLS) names the real
destination, and Google's frontend routes by `Host`. That's how
`www.youtube.com`, `script.google.com`, and friends reach you despite a
DPI box that drops anything not SNI'd as `www.google.com`.

The same trick works on any multi-tenant CDN edge that:

1. serves multiple tenant domains on the same IP pool, and
2. dispatches to the right backend by inner HTTP `Host`, and
3. presents a TLS cert whose name matches the SNI you choose.

Vercel, Fastly, and AWS CloudFront (which is what Netlify-hosted sites
sit behind) all fit the bill. Pick a benign-looking domain hosted on
the same edge, use it as the SNI, and you can route many other domains
on that edge through the same tunnel without burning Apps Script quota.

## Config shape

```jsonc
{
  "mode": "direct",                         // or apps_script / full
  "fronting_groups": [
    {
      "name":    "vercel",                  // free-form, used in logs
      "ip":      "76.76.21.21",             // a Vercel edge IP
      "sni":     "react.dev",               // a Vercel-hosted domain
      "domains": [                          // hosts to route via this group
        "vercel.com", "vercel.app",
        "nextjs.org", "now.sh"
      ]
    }
  ]
}
```

`domains` matches case-insensitively, exact OR dot-anchored suffix —
`vercel.com` covers both `vercel.com` and `*.vercel.com`. First group
in the list whose member matches wins.

A working example is shipped at `config.fronting-groups.example.json`.

## Picking the (ip, sni) pair

The SNI must be a real, currently-live domain on the same edge. rustls
validates the upstream cert against the SNI you send; if the edge
returns a cert that doesn't cover that name, the handshake fails. So
the recipe is:

1. Pick the target edge (Vercel, Fastly, …).
2. Find a neutral, never-blocked domain hosted there. Vercel: `react.dev`,
   `nextjs.org`. Fastly: `www.python.org`, `pypi.org`. AWS CloudFront
   (where Netlify lives): `letsencrypt.org`, `aws.amazon.com`.
3. Resolve that domain (`dig +short react.dev A`) — pick one IP, drop
   it in `ip`.
4. List the domains you actually want to reach via this edge in
   `domains` — **only domains you've verified are hosted on the same
   edge as `sni`** (see warning below).

Edge IPs rotate. If a group's `ip` stops working, re-resolve the SNI
domain and update the config — IP rotation per-group is on the
roadmap but not implemented yet.

## ⚠️ Cross-tenant leak: don't list domains that aren't on the edge

If you put a domain in `domains` that is **not** actually hosted on the
edge you've configured, two things happen, both bad:

1. **Privacy leak.** The proxy completes a TLS handshake with the edge
   (validated against `sni`, which IS on the edge), then sends `Host:
   <your-domain>` inside that encrypted stream. The edge — which is
   not your-domain's host — now sees a request labelled with
   your-domain's name. From the edge's perspective, *you* deliberately
   sent that request to them. Vercel/Fastly logs will show your-domain
   in their access logs, attributable to your IP and timestamps.

2. **UX failure.** The edge has no backend for your-domain, so it
   returns its default 404 / wrong-tenant page. The site appears
   "broken via mhrv-rs" but works fine over a normal connection,
   which is confusing to debug.

**Verify before listing.** A simple check: if `dig +short your-domain
A` returns an IP that's *also* one of the edge's IPs, you're fine. If
the IPs differ, your-domain is hosted somewhere else and listing it
will leak. This is also why the upstream MITM-DomainFronting Xray
config uses `verifyPeerCertByName` with an explicit SAN allowlist —
it's a second guard against accidentally fronting unrelated domains
through the same edge. mhrv-rs leaves verification to rustls + the
SNI you send; the leak guard is "you, the operator, listing only
domains you've verified."

Only listed domains are routed to the group. Anything else falls
through to the next dispatch step (Google SNI-rewrite or Apps Script
relay), so unrelated traffic does NOT accidentally hit a group's edge.

## Routing precedence

Within a single CONNECT, the dispatch order is:

1. `passthrough_hosts` — explicit user opt-out.
2. DoH bypass (port 443, known DoH host).
3. `mode = full` — everything via the batch tunnel mux.
4. **`fronting_groups` match (port 443).** — this feature.
5. Built-in Google SNI-rewrite suffix list (port 443).
6. `mode = direct` fallback → raw TCP.
7. `mode = apps_script` peek + relay.

So fronting groups beat the Google-edge default for hosts they list,
but lose to user-explicit passthrough/DoH choices. Putting `vercel.com`
in a Vercel fronting group will route Vercel traffic through Vercel's
edge directly, not through the Apps Script relay or the Google edge.

## Limitations / what's not here yet

- **Single IP per group.** Real edges have many; we'll add a pool with
  health-checking when there's a clear need. Workaround: when the
  configured IP starts failing, swap it.
- **No bundled domain catalog.** The upstream Xray config uses
  `geosite:vercel` / `geosite:fastly` lists from a binary geosite
  database — we don't ship that, you list domains explicitly.
- **No UI editor.** Edit `config.json` directly. The UI's Save path
  preserves your `fronting_groups` block (round-tripped) — it just
  doesn't render an editor for it.
- **Browsers only for Android non-root**, same as the Google path —
  third-party apps that don't trust user CAs (Telegram, Instagram, …)
  can't be MITM'd, so this trick doesn't help them.
- **Cert verification matches the SNI.** No per-group SAN allowlist
  (their `verifyPeerCertByName`); the SNI you send IS what rustls
  validates against. If you want stricter pinning, set `verify_ssl:
  false` is the wrong answer — instead, pick an SNI whose cert
  genuinely covers your targets.

## Credit

The technique is the same one [@masterking32]'s original
MasterHttpRelayVPN demonstrated for Google's edge. The Vercel +
Fastly extension and the matching Xray config came from
[@patterniha]'s [MITM-DomainFronting](https://github.com/patterniha/MITM-DomainFronting)
project — this `fronting_groups` field is a Rust port of that idea
into mhrv-rs's existing dispatcher.
