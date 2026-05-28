/**
 * DomainFront Relay — Google Apps Script
 *
 * TWO modes:
 *  1. Single: POST { k, m, u, h, b, ct, r } → { s, h, b }
 *  2. Batch: POST { k, q: [{m,u,h,b,ct,r}, ...] } → { q: [{s,h,b}, ...] }
 *  Uses UrlFetchApp.fetchAll() — all URLs fetched IN PARALLEL.
 *
 * DEPLOYMENT:
 *  1. Go to script.google.com → New project
 *  2. Delete the default code, paste THIS entire file
 *  3. Open Project Settings (⚙️ icon) > Script Properties
 *  4. Add key-value pair: AUTH_KEY = <your_key_value>
 *  5. Click Deploy → New deployment
 *  6. Type: Web app | Execute as: Me | Who has access: Anyone
 *  7. Copy the Deployment ID into config.toml (previous config.json) as "script_id"
 *
 */
const PROPERTIES = PropertiesService.getScriptProperties();

const AUTH_KEY = PROPERTIES.getProperty("AUTH_KEY");

// Active-probing defense. When false (production default), bad AUTH_KEY
// requests get a decoy HTML page that looks like a placeholder Apps
// Script web app instead of the JSON `{"e":"unauthorized"}` body. This
// makes the deployment indistinguishable from a forgotten-but-public
// Apps Script project to active scanners that POST malformed payloads
// looking for proxy endpoints.
//
// Set to `true` during initial setup if a misconfigured client is
// hitting "unauthorized" and you want the explicit JSON error to debug
// — then flip back to false before the deployment is widely shared.
// (Inspired by #365 Section 3, mhrv-rs v1.8.0+.)
const DIAGNOSTIC_MODE = false;

// Connection-level + IP-leak request headers we strip before forwarding
// to the destination. Browser capability headers (sec-ch-ua*, sec-fetch-*)
// stay intact — modern apps like Google Meet use them for browser gating.
// We also drop the `X-Forwarded-*` / `Forwarded` / `Via` family so a
// misconfigured upstream proxy on the user side can't leak the user's
// real IP through the relay path. Mirrors upstream
// `masterking32/MasterHttpRelayVPN@3094288`.
const SKIP_HEADERS = new Set([
  "host", "connection", "content-length",
  "transfer-encoding", "proxy-connection", "proxy-authorization",
  "priority", "te",
  "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
  "x-forwarded-port", "x-real-ip", "forwarded", "via",
]);
const VALID_METHODS = new Set([ "get", "post", "put", "delete", "patch", "head", "options" ]);
// Methods we consider safe to replay if `UrlFetchApp.fetchAll()` raises.
// GET/HEAD/OPTIONS are idempotent per RFC 9110; POST/PUT/PATCH/DELETE
// can have side-effects so we surface the error instead of silently
// re-firing them.
const SAFE_REPLAY_METHODS = new Set([ "get", "head", "options" ]);

// HTML body for the bad-auth decoy. Mimics a minimal Apps Script-style
// placeholder page — no proxy-shaped JSON, nothing distinctive enough
// for a probe to fingerprint as a tunnel endpoint.
const DECOY_HTML =
  '<!DOCTYPE html><html><head><title>Web App</title></head>' +
  '<body><p>The script completed but did not return anything.</p>' +
  '</body></html>';

const URL_PATTERN = /^https?:\/\//i;

/**
 * @typedef {Object} ClientRequest
 * @property {GoogleAppsScript.URL_Fetch.HttpMethod} m
 * @property {string} u - URL to relay
 * @property {GoogleAppsScript.URL_Fetch.HttpHeaders} h
 * @property {string} b  - Request body
 * @property {string} ct - Request contentType
 * @property {boolean} r - Request goes through exit node
 */

/**
 * @typedef {Object} ClientRequestSingle
 * @property {string} k - Auth token
 * @property {GoogleAppsScript.URL_Fetch.HttpMethod} m
 * @property {string} u - URL to relay
 * @property {GoogleAppsScript.URL_Fetch.HttpHeaders} h
 * @property {string} b  - Request body
 * @property {string} ct - Request contentType
 * @property {boolean} r - Request goes through exit node
 */

/**
 * @typedef {Object} ClientRequestBatch
 * @property {string} k
 * @property {Array<ClientRequest>} q
 */

/**
 * @typedef RelayErrorResponse
 * @property {string} e
 */

/**
 * @typedef RelaySingleResponse
 * @property {number} s
 * @property {GoogleAppsScript.URL_Fetch.HttpHeaders} h
 * @property {string} b
*/

/**
 * @typedef RelayBatchResponse
 * @property {Array<RelaySingleResponse | RelayErrorResponse>} q
 */

/**
 * `doGet` is what active scanners hit first (HTTP GET probes are cheaper
 * than POSTs). Apps Script defaults to a "Script function not found" page
 * here which is a fine-enough decoy on its own, but explicitly returning
 * the same harmless placeholder makes the response identical to the
 * bad-auth POST decoy — one less fingerprint vector.
 * @param {GoogleAppsScript.Events.DoGet} e
*/
function doGet (e) {
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.XML);
}

/** @param {RelayErrorResponse | RelaySingleResponse | RelayBatchResponse} obj  */
function _relayResponse (obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  );
}

/** @param {RelayErrorResponse} err  */
function _decoyOrError (err) {
  if (DIAGNOSTIC_MODE) return _relayResponse(err);
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.XML);
}

/** @param {GoogleAppsScript.URL_Fetch.HTTPResponse} resp  */
function _respHeaders (resp) {
  return resp.getAllHeaders?.() ?? resp.getHeaders();
}

/** @param {ClientRequest} req  */
function _buildOpts (req) {
  const method = (req.m?.toLowerCase?.() ?? "get");

  if (!VALID_METHODS.has(method)) {
    throw new Error(`Invalid HTTP method: ${ method }`);
  }

  /** @type {GoogleAppsScript.URL_Fetch.URLFetchRequestOptions} */
  let opts = {
    /** @type {GoogleAppsScript.URL_Fetch.HttpMethod} */
    method: method,
    muteHttpExceptions: true,
    followRedirects: true,          // ← always true; r flag now has different meaning
    validateHttpsCertificates: true,
    escaping: false,
  };

  if (req.h && typeof req.h === "object") {
    opts.headers = Object.fromEntries(
      Object.entries(req.h).filter(([ k ]) => !SKIP_HEADERS.has(k.toLowerCase())));
  }
  if (req.b) {
    if (typeof req.b !== "string") {
      throw new Error("Payload must be string (base64)");
    }
    try {
      const decoded = Utilities.base64Decode(req.b);
      if (decoded.length > 50000000) {
        throw new Error("Payload exceeds 50MB limit");
      }
      opts.payload = decoded;
    } catch (decodeErr) {
      throw new Error(`Base64 decode failed: ${ String(decodeErr) }`);
    }
    if (req.ct) opts.contentType = req.ct;
  }
  return opts;
}

/**
 * @param {GoogleAppsScript.URL_Fetch.HTTPResponse} resp
 * @return {RelaySingleResponse}
*/
function _buildResponse (resp) {
  try {
    let respContentB64 = Utilities.base64Encode(resp.getContent());
    if (respContentB64.length > 50000000) {
      throw new Error("Payload exceeds 50MB limit");
    }
    return {
      s: resp.getResponseCode(),
      h: _respHeaders(resp),
      b: respContentB64,
    };
  } catch (encodeErr) {
    throw new Error(`Base64 encode failed: ${ String(encodeErr) }`);
  }
}

/**
 * @param {ClientRequestSingle} req
 * @return {GoogleAppsScript.Content.TextOutput}
*/
function _doSingle (req) {
  if (!req.u || typeof req.u !== "string" || !URL_PATTERN.test(req.u)) {
    const errMsg = "invalid url: " + String(req.u);
    Logger.log(`[ERROR] _doSingle: ${ errMsg }`);
    return _relayResponse({ e: errMsg });
  }


  // ── Normal relay ────────
  // Wrap the fetch + body encode in try/catch so any failure surfaces as
  // a JSON error envelope the Rust client can parse. Without this, throws
  // from UrlFetchApp.fetch (URL too long, payload too large, quota
  // exhausted, 6-minute execution timeout) or from base64Encode (response
  // body near Apps Script's ~50 MB ceiling can blow the V8 heap during
  // encode) propagate unhandled, and Apps Script serves its default
  // `<title>Web App</title>` HTML error page — which the client then
  // reports as "Relay failed: bad response: no json in: <title>Web App>..."
  // and the user has no signal as to the actual cause. Mirrors the
  // per-item try/catch in _doBatch below.
  try {
    let opts = _buildOpts(req);
    let resp = UrlFetchApp.fetch(req.u, opts);

    // Raw-return mode for exit-node path.
    // r:true = return destination body verbatim so Rust gets {s,h,b} unwrapped.
    if (req.r === true) {
      try {
        let respContent = resp.getContentText();
        /** @type {Object} */
        let respObj = JSON.parse(respContent);
        if ([ "s", "h", "b" ].every(prop => respObj.hasOwnProperty(prop)))
          return ContentService
            .createTextOutput(respContent)
            .setMimeType(ContentService.MimeType.JSON);
      } catch {
        // exit-node format not matched, continuing normal relay
      }
    }

    return _relayResponse(_buildResponse(resp));
  } catch (err) {
    const errMsg = `fetch failed: ${ String(err) }`;
    Logger.log(`[ERROR] _doSingle(${ req.u }): ${ errMsg }`);
    return _relayResponse({ e: errMsg });
  }
}

/**
 * Helper to process a batch of 50 requests
 * @param { Array<GoogleAppsScript.URL_Fetch.URLFetchRequest>} fetchBatch
 * @param { Array<number>} batchIndices
 * @param { Map<number, RequestMapData>} requestMap
 * @param { Map<number, Object> } errorMap
 */
function _processBatch (fetchBatch, batchIndices, requestMap, errorMap) {
  try {
    const responses = UrlFetchApp.fetchAll(fetchBatch);
    for (let j = 0; j < responses.length; j++) {
      const originalIndex = batchIndices[ j ];
      requestMap.get(originalIndex).response = responses[ j ];
    }
  } catch (fetchAllErr) {
    const fetchAllErrMsg = String(fetchAllErr);
    Logger.log(`[WARN] fetchAll failed, retrying: ${ fetchAllErrMsg }`);

    // Fallback: retry safe methods individually
    for (let j = 0; j < fetchBatch.length; j++) {
      const originalIndex = batchIndices[ j ];
      const reqObj = requestMap.get(originalIndex);

      if (!SAFE_REPLAY_METHODS.has(reqObj.method)) {
        errorMap.set(originalIndex, "batch fetchAll failed; unsafe method not replayed");
        continue;
      }

      try {
        const resp = UrlFetchApp.fetch(reqObj.request.url, reqObj.request);
        reqObj.response = resp;
      } catch (singleErr) {
        const singleErrMsg = String(singleErr);
        Logger.log(`[ERROR] _doBatch fallback[${ originalIndex }]: ${ singleErrMsg }`);
        errorMap.set(originalIndex, singleErrMsg);
      }
    }
  }
}

/**
 * @param {Array<ClientRequest>} items
 * @returns {GoogleAppsScript.Content.TextOutput}
*/
function _doBatch (items) {
  /** @type {Map<number, {request: Object, method: string, response: GoogleAppsScript.URL_Fetch.HTTPResponse | null}>} */
  let requestMap = new Map();
  /** @type {Map<number, string>} */
  let errorMap = new Map();

  // Build request map
  for (let i = 0; i < items.length; i++) {
    let item = items[ i ];
    if (!item || typeof item !== "object") {
      errorMap.set(i, "bad item");
      continue;
    }
    if (!item.u || typeof item.u !== "string" || !URL_PATTERN.test(item.u)) {
      const errMsg = `bad url: ${ String(item.u) }`;
      Logger.log(`[ERROR] _doBatch[${ i }]: ${ errMsg }`);
      errorMap.set(i, errMsg);
      continue;
    }
    try {
      const method = (item.m?.toLowerCase?.() ?? "get");
      const request = { url: item.u, ..._buildOpts(item) };
      requestMap.set(i, { request, method, response: null });
    } catch (buildErr) {
      const errMsg = String(buildErr);
      Logger.log(`[ERROR] _doBatch[${ i }] _buildOpts: ${ errMsg }`);
      errorMap.set(i, errMsg);
    }
  }

  if (requestMap.size === 0) {
    // All items failed validation
    let results = [];
    for (let i = 0; i < items.length; i++) {
      results.push({ e: String(errorMap.get(i)) });
    }
    return _relayResponse({ q: results });
  }

  // Single-item fast path
  if (requestMap.size === 1) {
    const [ originalIndex, data ] = requestMap.entries().next().value;
    try {
      const resp = UrlFetchApp.fetch(data.request.url, data.request);
      data.response = resp;
    } catch (singleErr) {
      const singleErrMsg = String(singleErr);
      Logger.log(`[ERROR] _doBatch (fetching single item): ${ singleErrMsg }`);
      errorMap.set(originalIndex, singleErrMsg);
    }

  } else {
    // Batch mode
    let requestCount = 0;
    let fetchBatch = [];
    let batchIndices = [];

    for (const [ originalIndex, data ] of requestMap) {
      fetchBatch.push(data.request);
      batchIndices.push(originalIndex);
      requestCount++;

      // Process batch when it reaches 50 or we're at the end
      if (fetchBatch.length === 50 || requestCount === requestMap.size) {
        _processBatch(fetchBatch, batchIndices, requestMap, errorMap);
        fetchBatch = [];
        batchIndices = [];
      }
    }
  }

  // Build results
  /** @type {Array<RelaySingleResponse | RelayErrorResponse>} */
  let results = [];
  for (let i = 0; i < items.length; i++) {
    if (errorMap.has(i)) {
      results.push({ e: String(errorMap.get(i)) });
    } else if (requestMap.has(i) && requestMap.get(i).response) {
      try {
        results.push(_buildResponse(requestMap.get(i).response));
      } catch (err) {
        results.push({ e: `fetch failed: ${ String(err) }` });
      }
    } else {
      results.push({ e: "fetch failed" });
    }
  }

  return _relayResponse({ q: results });
}

/** @param {GoogleAppsScript.Events.DoPost} e */
function doPost (e) {
  if (!AUTH_KEY) {
    Logger.log("[ERROR] doPost: AUTH_KEY not configured");
    return _decoyOrError({ e: "AUTH_KEY not configured" });
  }
  try {
    /** @type {ClientRequestSingle | ClientRequestBatch} **/
    let req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) {
      Logger.log("[WARN] doPost: unauthorized attempt");
      return _decoyOrError({ e: "unauthorized" });
    }

    // Batch mode: { k, q: [...] }
    if ("q" in req) {
      if (req.q.length === 0) return _relayResponse({ q: [] });
      return _doBatch(req.q);
    }
    // Single mode: { k, m, u, h, b, ct, r }
    return _doSingle(req);
  } catch (err) {
    // Parse failures of the request body are also probe-shaped — a real
    // mhrv-rs client never sends invalid JSON. Decoy for the same reason.

    const errMsg = String(err);
    Logger.log(`[ERROR] doPost parse: ${ errMsg }`);
    return _decoyOrError({ e: errMsg });
  }
}
