/**
 * DomainFront Relay — Apps Script with Cloudflare Worker exit.
 *
 * Variant of Code.gs that off-loads the actual outbound HTTP fetch to
 * a Cloudflare Worker. Apps Script becomes a thin auth-and-forward
 * relay; Cloudflare does the work and pays the latency.
 *
 *   mhrv-rs ──► Apps Script (this file) ──► Cloudflare Worker ──► target
 *               ▲ inbound auth & batch     ▲ outbound fetch + base64
 *
 * Wire protocol with mhrv-rs is identical to Code.gs:
 *   1. Single:  POST { k, m, u, h, b, ct, r }       → { s, h, b }
 *   2. Batch:   POST { k, q: [{m,u,h,b,ct,r}, ...] } → { q: [{s,h,b}, ...] }
 *      Both shapes are forwarded to the Worker as one POST per call
 *      from Apps Script: single mode posts {k, u, m, ...} once, batch
 *      mode posts {k, q: [...]} once. The Worker fans out batches
 *      internally via Promise.all. This is the design choice that
 *      makes Code.cfw.gs actually save GAS UrlFetchApp quota — without
 *      it we'd have to fetchAll(N worker calls) and end up at parity
 *      with the standard Code.gs.
 *
 * Trade-off summary (read before deploying):
 *   + Per-call latency drops from ~250-500 ms (Apps Script internal
 *     hop) to ~10-50 ms (CF edge). Visibly snappier for chat-style
 *     workloads (Telegram, page navigation).
 *   + Apps Script *runtime* quota (90 min/day on consumer accounts)
 *     stretches significantly because each call now spends almost all
 *     its time in the network leg to the Worker, not in the body
 *     fetch + base64 + header processing.
 *   + Apps Script *UrlFetchApp count* quota stretches roughly Nx for
 *     an N-URL batch because the batch is sent as a small number of
 *     POSTs to the Worker (one per chunk of WORKER_BATCH_CHUNK URLs),
 *     not fanned out per-URL via fetchAll. For mhrv-rs's typical
 *     5-30 URL batches that's 1 GAS call (vs N under standard
 *     Code.gs). Single non-batched requests still count 1:1.
 *   - YouTube long-form streaming gets WORSE. Apps Script allows
 *     ~6 min wall per execution; CF Workers cap at 30 s wall. The
 *     SABR cliff hits sooner. For YouTube-heavy use, keep the
 *     standard Code.gs (apps_script mode).
 *   - Batch mode now has a per-batch wall, not per-URL: Promise.all
 *     resolves only when every fetch finishes, so the slowest URL
 *     dominates. mhrv-rs already retries failed batch items
 *     individually, so failure modes are graceful, but it's a real
 *     behavioural change vs Code.gs's per-URL fetchAll wall.
 *   - Cloudflare anti-bot challenges on destination sites can be
 *     stricter — exit IP is now in CF's own range, which CF's
 *     anti-bot fingerprints as a worker-internal request. This is
 *     a different problem than DPI bypass; not solved by either
 *     variant.
 *
 * Deployment:
 *   1. Deploy assets/cloudflare/worker.js to Cloudflare Workers first
 *      (set its AUTH_KEY to a strong secret).
 *   2. Note the *.workers.dev URL of that Worker.
 *   3. Open https://script.google.com → New project, delete default code.
 *   4. Paste THIS entire file.
 *   5. Set AUTH_KEY (must match the Worker's AUTH_KEY and your mhrv-rs
 *      config's auth_key — all three identical).
 *   6. Set WORKER_URL to your *.workers.dev URL (must include https://).
 *   7. Deploy → New deployment → Web app
 *      Execute as: Me   |   Who has access: Anyone
 *   8. Copy the Deployment ID into mhrv-rs config.json as "script_id".
 *      mhrv-rs does not need to know about Cloudflare; it talks to
 *      Apps Script the same way it always has.
 *
 * CHANGE THESE TWO CONSTANTS BELOW.
 *
 * Upstream credit for the GAS-→-Worker pattern: github.com/denuitt1/mhr-cfw.
 * This file inherits the hardening (decoy-on-bad-auth, hop-loop guard)
 * from the standard Code.gs.
 */

const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";

// Full https://… URL of the Cloudflare Worker you deployed using
// assets/cloudflare/worker.js. Must include the scheme.
const WORKER_URL = "https://CHANGE_ME.workers.dev";

// ── Sentinels — DO NOT EDIT ─────────────────────────────────
// These two constants are NOT configuration. They are the literal
// template-default values used by the fail-closed check in doPost so
// that a forgotten edit (AUTH_KEY or WORKER_URL still set to the
// placeholder) returns a loud error instead of silently accepting the
// placeholder secret or POSTing to a bogus URL. Configure AUTH_KEY
// and WORKER_URL above; leave these alone.
const DEFAULT_AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
const DEFAULT_WORKER_URL = "https://CHANGE_ME.workers.dev";

// Must match the Worker's MAX_BATCH_SIZE. Batches larger than this
// are split into chunks of this size and dispatched via fetchAll —
// each chunk costs 1 GAS UrlFetchApp call, so an N-URL batch costs
// ceil(N/CHUNK) calls (still much cheaper than the per-URL cost
// under standard Code.gs's fetchAll).
const WORKER_BATCH_CHUNK = 40;

// Active-probing defense — same semantics as Code.gs. Bad-auth and
// malformed POST bodies receive a decoy HTML page that looks like a
// placeholder Apps Script web app instead of the JSON `{e}` error,
// so probes can't fingerprint the deployment as a relay endpoint.
// Flip to `true` only during initial setup if you need to debug an
// "unauthorized" loop, then flip back before sharing the deployment.
const DIAGNOSTIC_MODE = false;

const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  "priority": 1, te: 1,
};

const DECOY_HTML =
  '<!DOCTYPE html><html><head><title>Web App</title></head>' +
  '<body><p>The script completed but did not return anything.</p>' +
  '</body></html>';

// ── Request Handlers ────────────────────────────────────────

function _decoyOrError(jsonBody) {
  if (DIAGNOSTIC_MODE) return _json(jsonBody);
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.HTML);
}

function doPost(e) {
  try {
    // Fail-closed if either constant is still the template default.
    // Without this, a forgotten edit would either accept the placeholder
    // secret as valid auth or POST to a literal "CHANGE_ME" URL — both
    // are silent failure modes a deploy might miss. Surface them loud.
    if (AUTH_KEY === DEFAULT_AUTH_KEY) {
      return _json({ e: "configure AUTH_KEY in Code.cfw.gs" });
    }
    if (WORKER_URL === DEFAULT_WORKER_URL) {
      return _json({ e: "configure WORKER_URL in Code.cfw.gs" });
    }

    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _decoyOrError({ e: "unauthorized" });

    if (Array.isArray(req.q)) return _doBatch(req.q);
    return _doSingle(req);
  } catch (err) {
    return _decoyOrError({ e: String(err) });
  }
}

function doGet(e) {
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.HTML);
}

// ── Worker Forwarding ──────────────────────────────────────

/**
 * Strip headers that must not be forwarded (hop-by-hop / Apps-Script-
 * managed). Returns a fresh header map; the input is never mutated.
 */
function _scrubHeaders(rawHeaders) {
  var out = {};
  if (rawHeaders && typeof rawHeaders === "object") {
    for (var k in rawHeaders) {
      if (rawHeaders.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
        out[k] = rawHeaders[k];
      }
    }
  }
  return out;
}

/**
 * Normalize one request item into the shape the Worker expects.
 * Used for both single and batch paths — single mode wraps this in
 * `{k, ...item}`; batch mode wraps it in `{k, q: [item, ...]}`.
 * Auth key is added at envelope level by callers, not per-item.
 */
function _normalizeItem(item) {
  return {
    u: item.u,
    m: (item.m || "GET").toUpperCase(),
    h: _scrubHeaders(item.h),
    b: item.b || null,
    ct: item.ct || null,
    r: item.r !== false,
  };
}

function _workerFetchOptions(payload) {
  return {
    url: WORKER_URL,
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    followRedirects: true,
    validateHttpsCertificates: true,
  };
}

// ── Single Request ─────────────────────────────────────────

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }

  var item = _normalizeItem(req);
  var envelope = {
    k: AUTH_KEY,
    u: item.u,
    m: item.m,
    h: item.h,
    b: item.b,
    ct: item.ct,
    r: item.r,
  };
  var opts = _workerFetchOptions(envelope);
  // muteHttpExceptions covers HTTP-level errors (4xx/5xx come back as
  // a normal HTTPResponse). It does NOT cover network-level failures
  // — DNS resolution failure, TLS handshake failure, connection
  // timeout to *.workers.dev, etc. — those throw. Catch and surface
  // them as `{e}` so the operator debugging "why isn't my deployment
  // responding?" gets a useful signal instead of the doPost outer
  // catch returning the decoy HTML page (which makes the deployment
  // look like a bad-auth probe to the client). Auth has already
  // passed at this point so the probe-defence argument doesn't apply.
  var resp;
  try {
    resp = UrlFetchApp.fetch(opts.url, opts);
  } catch (err) {
    return _json({ e: "worker unreachable: " + String(err) });
  }
  return _json(_parseWorkerJson(resp));
}

// ── Batch Request ──────────────────────────────────────────

/**
 * Forward a batch to the Worker, chunking when needed. Each chunk
 * becomes ONE POST to the Worker; the Worker fans out across the URLs
 * in the chunk via Promise.all and returns `{q: [...]}` in the same
 * order. Multiple chunks fire in parallel via UrlFetchApp.fetchAll.
 *
 * Quota cost: ceil(N / WORKER_BATCH_CHUNK) GAS UrlFetchApp calls for
 * an N-URL batch. For typical mhrv-rs batches of 5-30 URLs this is
 * exactly 1 call (vs N under standard Code.gs's fetchAll). Larger
 * batches gracefully degrade to a few calls instead of failing under
 * the Worker's own MAX_BATCH_SIZE soft cap.
 *
 * Bad-URL items are filtered locally so the Worker only sees valid
 * inputs, then re-interleaved into the result array in original order
 * so mhrv-rs's batch-index assumptions hold.
 */
function _doBatch(items) {
  var validItems = [];
  var errorMap = {};

  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[i] = "bad url";
      continue;
    }
    validItems.push(_normalizeItem(item));
  }

  var workerResults = [];
  if (validItems.length > 0) {
    // Split into chunks ≤ WORKER_BATCH_CHUNK so each Worker call stays
    // under the Worker's MAX_BATCH_SIZE cap. Single-chunk fast path
    // avoids the fetchAll overhead for the common case.
    var chunks = [];
    for (var c = 0; c < validItems.length; c += WORKER_BATCH_CHUNK) {
      chunks.push(validItems.slice(c, c + WORKER_BATCH_CHUNK));
    }

    var fetchOpts = chunks.map(function(chunk) {
      return _workerFetchOptions({ k: AUTH_KEY, q: chunk });
    });

    // muteHttpExceptions covers HTTP-level errors. Network-level
    // failures (DNS, TLS, connection timeout to *.workers.dev) still
    // throw — catch and convert to per-chunk `{e}` errors that get
    // spread across each chunk's slots. mhrv-rs's per-item retry
    // then handles them individually instead of getting the decoy
    // HTML page from the doPost outer catch. See _doSingle for why
    // the probe-defence argument doesn't apply post-auth.
    var responses;
    try {
      if (fetchOpts.length === 1) {
        responses = [UrlFetchApp.fetch(fetchOpts[0].url, fetchOpts[0])];
      } else {
        responses = UrlFetchApp.fetchAll(fetchOpts);
      }
    } catch (err) {
      var unreachable = { e: "worker unreachable: " + String(err) };
      for (var u = 0; u < validItems.length; u++) workerResults.push(unreachable);
      // Skip the per-response loop below by returning early through the
      // reassembly code path.
      responses = null;
    }

    for (var r = 0; responses && r < responses.length; r++) {
      var parsed = _parseWorkerJson(responses[r]);
      if (parsed && Array.isArray(parsed.q)) {
        for (var k = 0; k < parsed.q.length; k++) {
          workerResults.push(parsed.q[k]);
        }
      } else {
        // Per-chunk failure (worker error, parse failure, auth, etc).
        // Spread the same error to every slot in this chunk so mhrv-rs
        // retries each item individually rather than masking the
        // failure. Other chunks are unaffected.
        var slotErr = (parsed && parsed.e)
          ? { e: parsed.e }
          : { e: "worker batch failure" };
        for (var s = 0; s < chunks[r].length; s++) workerResults.push(slotErr);
      }
    }
  }

  // Reassemble into the original order: validated slots get their
  // worker result; invalid slots get their pre-flight error.
  var results = [];
  var wi = 0;
  for (var j = 0; j < items.length; j++) {
    if (errorMap.hasOwnProperty(j)) {
      results.push({ e: errorMap[j] });
    } else {
      results.push(workerResults[wi++] || { e: "missing worker response" });
    }
  }
  return _json({ q: results });
}

// ── Worker response handling ───────────────────────────────

/**
 * Parse the Worker's JSON envelope. Worker errors come back as
 * `{e: "..."}` — pass them through to the client unchanged so mhrv-rs
 * sees the same error-shape it would for a direct-fetch failure in
 * Code.gs. On HTTP errors from the Worker itself (auth failure, 5xx,
 * etc.), wrap into `{e}` so the client gets a useful message instead
 * of a parse-failure.
 */
function _parseWorkerJson(resp) {
  var code = resp.getResponseCode();
  var text = resp.getContentText();
  try {
    return JSON.parse(text);
  } catch (err) {
    return { e: "worker " + code + ": " + (text.length > 200 ? text.substring(0, 200) + "…" : text) };
  }
}

function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  );
}
