/**
 * MHR-CFW Exit Worker — Cloudflare Workers companion to Code.cfw.gs.
 *
 * Architecture (alternative backend, opt-in):
 *   mhrv-rs → Apps Script (Code.cfw.gs) → THIS Worker → target site
 *
 * Apps Script in this configuration is a thin relay: it authenticates
 * the inbound request from mhrv-rs, then forwards to this Worker. The
 * Worker does the actual outbound fetch(es), base64-encodes the body,
 * and returns the same JSON envelope shape the standard Code.gs would
 * have returned. The mhrv-rs client is unaware that the work happened
 * on Cloudflare — same `{u, m, h, b, ct, r}` request, same `{s, h, b}`
 * response.
 *
 * Two request shapes are accepted:
 *   1. Single:  { k, u, m, h, b, ct, r }            → { s, h, b }
 *   2. Batch:   { k, q: [{u,m,h,b,ct,r}, ...] }     → { q: [{s,h,b} | {e}, ...] }
 *
 * The batch shape is what makes this design actually save Apps Script
 * UrlFetchApp quota. Without it, Code.cfw.gs would have to do
 * `UrlFetchApp.fetchAll(N worker calls)` to fan out an N-URL batch,
 * which costs N quota — same as the standard Code.gs. With it,
 * Code.cfw.gs does ONE fetch to this Worker (1 quota) and we fan out
 * inside the Worker via Promise.all. For a typical mhrv-rs batch of
 * 5-30 URLs that's a 5-30x reduction in GAS daily quota.
 *
 * Why bother:
 *   - Faster per-call latency (~10-50 ms at CF edge vs ~250-500 ms in
 *     Apps Script), which matters most for many small requests
 *     (Telegram realtime, page navigation chatter).
 *   - Apps Script *runtime* quota (90 min/day on consumer accounts)
 *     stretches further because GAS spends each call almost entirely
 *     on its single forward to the Worker rather than on body fetch
 *     + base64 + header munging.
 *   - With the batch shape (above), Apps Script *UrlFetchApp count*
 *     quota also stretches roughly Nx for an N-URL batch — typically
 *     5-30x for mhrv-rs.
 *
 * What this does NOT change:
 *   - Cloudflare anti-bot challenges on the destination. The exit IP
 *     becomes a Workers IP (inside Cloudflare's network), which CF's
 *     own anti-bot can fingerprint as a worker-internal request —
 *     often *stricter* than a Google IP. This is a different problem
 *     than DPI bypass; see docs.
 *   - YouTube long-form streaming gets WORSE, not better. Apps Script
 *     allows ~6 min wall per execution; CF Workers cap at 30s wall.
 *     The SABR cliff arrives sooner. Keep the standard `apps_script`
 *     mode (Code.gs) for YouTube-heavy use.
 *   - The 30s wall now applies to the *slowest URL in the batch*
 *     because Promise.all only resolves once every fetch finishes.
 *     mhrv-rs already retries failed batch items individually, so a
 *     single slow target degrades to a per-item timeout rather than
 *     a hard failure — but it's a real behavioural difference vs the
 *     per-URL wall under the standard Code.gs path.
 *
 * Deployment:
 *   1. Cloudflare dashboard → Workers & Pages → Create → Hello World
 *   2. Edit code → delete the template, paste this entire file
 *   3. Change AUTH_KEY below to the same value you set in Code.cfw.gs
 *      AND in your mhrv-rs config.json (auth_key). All three must match.
 *   4. Deploy. Note the *.workers.dev URL; paste it into Code.cfw.gs as
 *      WORKER_URL.
 *
 * SECURITY NOTE: this Worker accepts unauthenticated POSTs from anyone
 * who knows the URL unless AUTH_KEY is changed. The check below is
 * cheap; do not skip it. The point of the AUTH_KEY is to keep the
 * Worker from becoming an open HTTP-relay for arbitrary attackers if
 * its URL leaks. Same secret as Code.cfw.gs by convention — if you
 * want compartmentalisation, use a different one and have Code.cfw.gs
 * forward both keys.
 *
 * Hardened over the upstream mhr-cfw worker.js by adding the AUTH_KEY
 * check and batch handling. Upstream credit: github.com/denuitt1/mhr-cfw.
 */

const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
const DEFAULT_AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";

// Loop-prevention tag. The Worker tags its OUTBOUND request to the
// target with `x-relay-hop: 1` (see processOne). If a subsequent
// request comes back into the Worker with that header set, the Worker
// has been chained back to itself somehow — most likely the user's
// `item.u` resolved to this Worker's own URL. Bail out instead of
// fetching to avoid a stack-overflow loop.
//
// Note: Code.cfw.gs does NOT set this header on its GAS→Worker call
// (and could not check for it on inbound anyway — Apps Script's
// doPost event doesn't expose request headers). So this guard
// catches Worker-↔-Worker cycles, not GAS-↔-Worker cycles. The
// `targetUrl.hostname === selfHost` check in processOne is the
// primary defence for the common misconfiguration.
const RELAY_HOP_HEADER = "x-relay-hop";

// Soft cap on batch size. Cloudflare Workers allow up to 50
// subrequests per invocation on the free tier (1000 on paid). We
// keep a margin for retries and internal CF traffic. mhrv-rs's
// typical batches are 5-30 URLs so this is rarely the binding limit.
//
// **Must match `WORKER_BATCH_CHUNK` in Code.cfw.gs.** If the GAS side
// chunks at a different size, oversized chunks here return a top-level
// error and the entire chunk's slots fail. Tune both together.
const MAX_BATCH_SIZE = 40;

// Hop-by-hop headers and headers Cloudflare manages itself. Stripped
// before forwarding so the inbound request doesn't poison the outbound.
// Kept in sync with Code.cfw.gs / Code.gs SKIP_HEADERS so the Worker
// is correct as a defence-in-depth even when called directly (the
// AUTH_KEY check is the primary gate, but GAS scrubs first in the
// normal flow).
const SKIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "priority",
  "te",
]);

export default {
  async fetch(request) {
    // Fail-closed if the deployer forgot to change AUTH_KEY from the
    // template default. Without this guard a forgotten edit would
    // accept any client that also happens to send the placeholder —
    // effectively running as an open relay. Prefer a loud 500 over
    // a silent open door.
    if (AUTH_KEY === DEFAULT_AUTH_KEY) {
      return json({ e: "configure AUTH_KEY in worker.js" }, 500);
    }

    if (request.method !== "POST") {
      return json({ e: "method not allowed" }, 405);
    }

    if (request.headers.get(RELAY_HOP_HEADER) === "1") {
      return json({ e: "loop detected" }, 508);
    }

    let req;
    try {
      req = await request.json();
    } catch (_err) {
      return json({ e: "bad json" }, 400);
    }

    if (!req || req.k !== AUTH_KEY) {
      // Same shape as Code.cfw.gs unauthorized so downstream errors are
      // uniform. The Worker URL is generally not user-discoverable; the
      // GAS in front of it is the public surface, and probes hit GAS
      // first. We don't bother with the decoy-HTML treatment here.
      return json({ e: "unauthorized" }, 401);
    }

    const selfHost = new URL(request.url).hostname;

    // Batch mode: { k, q: [{u,m,h,b,ct,r}, ...] }. Process all items in
    // parallel via Promise.all. Per-item failures are per-item `{e}`s in
    // the response array; the envelope itself stays 200 unless the batch
    // is malformed at the top level.
    if (Array.isArray(req.q)) {
      if (req.q.length === 0) return json({ q: [] });
      if (req.q.length > MAX_BATCH_SIZE) {
        return json({
          e: "batch too large (" + req.q.length + " > " + MAX_BATCH_SIZE + ")",
        }, 400);
      }
      const results = await Promise.all(
        req.q.map((item) => processOne(item, selfHost).catch((err) => ({
          e: "fetch failed: " + String(err),
        })))
      );
      return json({ q: results });
    }

    // Single mode: { k, u, m, h, b, ct, r }
    let result;
    try {
      result = await processOne(req, selfHost);
    } catch (err) {
      return json({ e: "fetch failed: " + String(err) }, 502);
    }
    if (result.e) {
      // Per-item validation errors get HTTP 400 in single mode so
      // mhrv-rs sees the same shape as in standard Code.gs ("bad url"
      // etc are already client-error-coded there).
      return json(result, 400);
    }
    return json(result);
  },
};

/**
 * Process one item, whether it came in as the top-level single
 * request or as one slot of a batch. Returns a plain object — never
 * throws to the caller; Promise.all's .catch above only triggers on
 * exceptions from this function's own internals (programmer error).
 *
 * Result shape mirrors what Code.gs would return for the same item:
 *   - Success: { s: status, h: {...}, b: base64Body }
 *   - Validation / fetch failure: { e: "..." }
 */
async function processOne(item, selfHost) {
  if (!item || typeof item !== "object") {
    return { e: "bad item" };
  }
  if (!item.u || typeof item.u !== "string" || !/^https?:\/\//i.test(item.u)) {
    return { e: "bad url" };
  }

  let targetUrl;
  try {
    targetUrl = new URL(item.u);
  } catch (_err) {
    return { e: "bad url" };
  }
  if (targetUrl.hostname === selfHost) {
    return { e: "self-fetch blocked" };
  }

  const headers = new Headers();
  if (item.h && typeof item.h === "object") {
    for (const [k, v] of Object.entries(item.h)) {
      if (SKIP_HEADERS.has(k.toLowerCase())) continue;
      try {
        headers.set(k, v);
      } catch (_err) {
        // Worker rejects some headers (e.g. forbidden ones); skip
        // rather than fail the whole item.
      }
    }
  }
  headers.set(RELAY_HOP_HEADER, "1");

  const method = (item.m || "GET").toUpperCase();
  const fetchOptions = {
    method,
    headers,
    redirect: item.r === false ? "manual" : "follow",
  };

  // Code.gs/UrlFetchApp tolerates a body on GET/HEAD (browsers don't
  // do this, but custom clients sometimes do); Workers' native fetch
  // throws TypeError if you set a body on a body-prohibited method.
  // To match Code.gs's permissiveness, silently drop the body for
  // those methods rather than failing the whole item.
  const bodyAllowed = method !== "GET" && method !== "HEAD";
  if (item.b && bodyAllowed) {
    try {
      const binary = Uint8Array.from(atob(item.b), (c) => c.charCodeAt(0));
      fetchOptions.body = binary;
      if (item.ct && !headers.has("content-type")) {
        headers.set("content-type", item.ct);
      }
    } catch (_err) {
      return { e: "bad body base64" };
    }
  }

  let resp;
  try {
    resp = await fetch(targetUrl.toString(), fetchOptions);
  } catch (err) {
    return { e: "fetch failed: " + String(err) };
  }

  const buffer = await resp.arrayBuffer();
  const uint8 = new Uint8Array(buffer);

  // Avoid call-stack overflow from String.fromCharCode.apply on big
  // bodies — chunk the conversion.
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < uint8.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, uint8.subarray(i, i + chunkSize));
  }
  const base64 = btoa(binary);

  // Note: Headers.forEach delivers keys lowercased per the Fetch
  // spec, whereas Code.gs's getAllHeaders preserves the origin's
  // casing. mhrv-rs treats headers case-insensitively, but anything
  // downstream that does a case-sensitive string compare will see
  // a backend-dependent difference. There is no Workers API to
  // recover the origin casing, so we accept the divergence.
  const responseHeaders = {};
  resp.headers.forEach((v, k) => {
    responseHeaders[k] = v;
  });

  return {
    s: resp.status,
    h: responseHeaders,
    b: base64,
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}
