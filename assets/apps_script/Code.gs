/**
 * DomainFront Relay — Google Apps Script
 *
 * TWO modes:
 *   1. Single:  POST { k, m, u, h, b, ct, r }       → { s, h, b }
 *   2. Batch:   POST { k, q: [{m,u,h,b,ct,r}, ...] } → { q: [{s,h,b}, ...] }
 *      Uses UrlFetchApp.fetchAll() — all URLs fetched IN PARALLEL.
 *
 * OPTIONAL SPREADSHEET-BACKED RESPONSE CACHE:
 *   Set CACHE_SPREADSHEET_ID to a valid Google Sheet ID (must be owned by
 *   the same account). When enabled, public GET requests are stored in the
 *   sheet and served from there on repeat visits, reducing UrlFetchApp
 *   quota consumption. The cache is Vary-aware (Accept-Encoding and
 *   Accept-Language are hashed into the compound cache key). Leave
 *   CACHE_SPREADSHEET_ID as-is to disable caching entirely — zero overhead.
 *
 * DEPLOYMENT:
 *   1. Go to https://script.google.com → New project
 *   2. Delete the default code, paste THIS entire file
 *   3. Change AUTH_KEY below to your own secret
 *   4. (Optional) Set CACHE_SPREADSHEET_ID to enable caching
 *   5. Click Deploy → New deployment
 *   6. Type: Web app  |  Execute as: Me  |  Who has access: Anyone
 *   7. Copy the Deployment ID into config.json as "script_id"
 *
 * CHANGE THE AUTH KEY BELOW TO YOUR OWN SECRET!
 */

const AUTH_KEY = "aaaaaaaa";

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

// ── Optional Spreadsheet Cache ──────────────────────────────
// Set to a valid Spreadsheet ID to enable response caching.
// Leave as-is to disable caching entirely (zero overhead).
const CACHE_SPREADSHEET_ID = "CHANGE_ME_TO_CACHE_SPREADSHEET_ID";
const CACHE_SHEET_NAME = "RelayCache";
const CACHE_META_SHEET_NAME = "RelayMeta";
const CACHE_META_CURSOR_CELL = "A1";

// ── Cache Tuning ────────────────────────────────────────────
const CACHE_MAX_ROWS = 5000;             // circular buffer capacity
const CACHE_MAX_BODY_BYTES = 35000;      // skip responses larger than ~35 KB
const CACHE_DEFAULT_TTL_SECONDS = 86400; // 24-hour fallback when no Cache-Control

// ── Vary-Aware Cache Key ────────────────────────────────────
// These request headers are hashed into the compound cache key
// alongside the URL so that responses with different encodings
// or languages never collide in the cache. Covers ~95 % of
// real-world Vary usage without inspecting the response.
const VARY_KEY_HEADERS = ["accept-encoding", "accept-language"];

// Connection-level + IP-leak request headers we strip before forwarding
// to the destination. Browser capability headers (sec-ch-ua*, sec-fetch-*)
// stay intact — modern apps like Google Meet use them for browser gating.
// We also drop the `X-Forwarded-*` / `Forwarded` / `Via` family so a
// misconfigured upstream proxy on the user side can't leak the user's
// real IP through the relay path. Mirrors upstream
// `masterking32/MasterHttpRelayVPN@3094288`.
const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
  "priority": 1, te: 1,
  "x-forwarded-for": 1, "x-forwarded-host": 1, "x-forwarded-proto": 1,
  "x-forwarded-port": 1, "x-real-ip": 1, "forwarded": 1, "via": 1,
};

// Methods we consider safe to replay if `UrlFetchApp.fetchAll()` raises.
// GET/HEAD/OPTIONS are idempotent per RFC 9110; POST/PUT/PATCH/DELETE
// can have side-effects so we surface the error instead of silently
// re-firing them.
const SAFE_REPLAY_METHODS = { GET: 1, HEAD: 1, OPTIONS: 1 };

// Headers that disqualify a request from the cache path.
const CACHE_BUSTING_HEADERS = {
  authorization: 1, cookie: 1, "x-api-key": 1,
  "proxy-authorization": 1, "set-cookie": 1,
};

// HTML body for the bad-auth decoy. Mimics a minimal Apps Script-style
// placeholder page — no proxy-shaped JSON, nothing distinctive enough
// for a probe to fingerprint as a tunnel endpoint.
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
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _decoyOrError({ e: "unauthorized" });

    // Batch mode: { k, q: [...] }
    if (Array.isArray(req.q)) return _doBatch(req.q);

    // Single mode
    return _doSingle(req);
  } catch (err) {
    // Parse failures of the request body are also probe-shaped — a real
    // mhrv-rs client never sends invalid JSON. Decoy for the same reason.
    return _decoyOrError({ e: String(err) });
  }
}

// `doGet` is what active scanners hit first (HTTP GET probes are cheaper
// than POSTs). Apps Script defaults to a "Script function not found" page
// here which is a fine-enough decoy on its own, but explicitly returning
// the same harmless placeholder makes the response identical to the
// bad-auth POST decoy — one less fingerprint vector.
function doGet(e) {
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.HTML);
}

// ── Single Request ─────────────────────────────────────────

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }

  // ── Optional cache path ────────────────────────────────
  // Only entered when CACHE_SPREADSHEET_ID is configured and
  // the request qualifies as a public, cachable GET.
  if (_canUseCache(req)) {
    var cached = _getFromCache(req.u, req.h);
    if (cached) {
      return _json({
        s: cached.status,
        h: JSON.parse(cached.headers),
        b: cached.body,
        cached: true,
      });
    }

    var fetchResult = _fetchAndCache(req.u, req.h);
    if (fetchResult) {
      return _json({
        s: fetchResult.status,
        h: JSON.parse(fetchResult.headers),
        b: fetchResult.body,
        cached: false,
      });
    }
    // If _fetchAndCache returns null (spreadsheet unavailable),
    // fall through to the normal relay path below.
  }

  // ── Normal relay (cache disabled or unavailable) ────────
  var opts = _buildOpts(req);
  var resp = UrlFetchApp.fetch(req.u, opts);
  return _json({
    s: resp.getResponseCode(),
    h: _respHeaders(resp),
    b: Utilities.base64Encode(resp.getContent()),
  });
}

// ── Batch Request ──────────────────────────────────────────

function _doBatch(items) {
  var fetchArgs = [];
  var fetchIndex = [];
  var fetchMethods = [];
  var errorMap = {};

  for (var i = 0; i < items.length; i++) {
    var item = items[i];
    if (!item || typeof item !== "object") {
      errorMap[i] = "bad item";
      continue;
    }
    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[i] = "bad url";
      continue;
    }
    try {
      var opts = _buildOpts(item);
      opts.url = item.u;
      fetchArgs.push(opts);
      fetchIndex.push(i);
      fetchMethods.push(String(item.m || "GET").toUpperCase());
    } catch (buildErr) {
      errorMap[i] = String(buildErr);
    }
  }

  // fetchAll() processes all requests in parallel inside Google. If it
  // throws as a whole (e.g. one URL violates UrlFetchApp limits and
  // poisons the whole batch), degrade to per-item fetch on safe methods
  // so a single bad request does not zero out every response in the
  // batch. Mirrors upstream `masterking32/MasterHttpRelayVPN@3094288`.
  var responses = [];
  if (fetchArgs.length > 0) {
    try {
      responses = UrlFetchApp.fetchAll(fetchArgs);
    } catch (fetchAllErr) {
      responses = [];
      for (var j = 0; j < fetchArgs.length; j++) {
        try {
          if (!SAFE_REPLAY_METHODS[fetchMethods[j]]) {
            errorMap[fetchIndex[j]] =
              "batch fetchAll failed; unsafe method not replayed";
            responses[j] = null;
            continue;
          }
          var fallbackReq = fetchArgs[j];
          var fallbackUrl = fallbackReq.url;
          var fallbackOpts = {};
          for (var key in fallbackReq) {
            if (
              Object.prototype.hasOwnProperty.call(fallbackReq, key) &&
              key !== "url"
            ) {
              fallbackOpts[key] = fallbackReq[key];
            }
          }
          responses[j] = UrlFetchApp.fetch(fallbackUrl, fallbackOpts);
        } catch (singleErr) {
          errorMap[fetchIndex[j]] = String(singleErr);
          responses[j] = null;
        }
      }
    }
  }

  var results = [];
  var rIdx = 0;
  for (var i = 0; i < items.length; i++) {
    if (Object.prototype.hasOwnProperty.call(errorMap, i)) {
      results.push({ e: errorMap[i] });
    } else {
      var resp = responses[rIdx++];
      if (!resp) {
        results.push({ e: "fetch failed" });
      } else {
        results.push({
          s: resp.getResponseCode(),
          h: _respHeaders(resp),
          b: Utilities.base64Encode(resp.getContent()),
        });
      }
    }
  }
  return _json({ q: results });
}

// ── Request Building ───────────────────────────────────────

function _buildOpts(req) {
  var opts = {
    method: (req.m || "GET").toLowerCase(),
    muteHttpExceptions: true,
    followRedirects: req.r !== false,
    validateHttpsCertificates: true,
    escaping: false,
  };
  if (req.h && typeof req.h === "object") {
    var headers = {};
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
        headers[k] = req.h[k];
      }
    }
    opts.headers = headers;
  }
  if (req.b) {
    opts.payload = Utilities.base64Decode(req.b);
    if (req.ct) opts.contentType = req.ct;
  }
  return opts;
}

function _respHeaders(resp) {
  try {
    if (typeof resp.getAllHeaders === "function") {
      return resp.getAllHeaders();
    }
  } catch (err) {}
  return resp.getHeaders();
}

function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  );
}

// ═══════════════════════════════════════════════════════════
//  SPREADSHEET CACHE — SHEET MANAGEMENT
// ═══════════════════════════════════════════════════════════

function _initCacheSheet() {
  if (CACHE_SPREADSHEET_ID === "CHANGE_ME_TO_CACHE_SPREADSHEET_ID") {
    return null;
  }
  try {
    var ss = SpreadsheetApp.openById(CACHE_SPREADSHEET_ID);
    var sheet = ss.getSheetByName(CACHE_SHEET_NAME);
    if (!sheet) {
      sheet = ss.insertSheet(CACHE_SHEET_NAME);
      // Schema: URL_Hash | URL | Status | Headers | Body | Timestamp | Expires_At
      sheet.getRange(1, 1, 1, 7).setValues([[
        "URL_Hash", "URL", "Status", "Headers", "Body", "Timestamp", "Expires_At"
      ]]);
    }
    return sheet;
  } catch (e) {
    return null;
  }
}

function _getMetaSheet() {
  if (CACHE_SPREADSHEET_ID === "CHANGE_ME_TO_CACHE_SPREADSHEET_ID") {
    return null;
  }
  try {
    var ss = SpreadsheetApp.openById(CACHE_SPREADSHEET_ID);
    var sheet = ss.getSheetByName(CACHE_META_SHEET_NAME);
    if (!sheet) {
      sheet = ss.insertSheet(CACHE_META_SHEET_NAME);
      sheet.getRange(CACHE_META_CURSOR_CELL).setValue(2);
      sheet.hideSheet();
    }
    return sheet;
  } catch (e) {
    return null;
  }
}

function _getNextCursor(sheet, metaSheet) {
  var cursorRange = metaSheet.getRange(CACHE_META_CURSOR_CELL);
  var cursor = cursorRange.getValue();
  if (typeof cursor !== "number" || cursor < 2) cursor = 2;

  var totalRows = sheet.getDataRange().getNumRows();

  if (totalRows < CACHE_MAX_ROWS + 1) {
    return totalRows + 1;
  }

  return cursor;
}

function _advanceCursor(metaSheet, currentRow) {
  var nextRow = currentRow + 1;
  if (nextRow > CACHE_MAX_ROWS + 1) nextRow = 2;
  metaSheet.getRange(CACHE_META_CURSOR_CELL).setValue(nextRow);
}

function _ensureRowsAllocated(sheet) {
  var totalRows = sheet.getDataRange().getNumRows();
  if (totalRows < CACHE_MAX_ROWS + 1) {
    var needed = CACHE_MAX_ROWS + 1 - totalRows;
    sheet.insertRowsAfter(totalRows, needed);
  }
}

// ═══════════════════════════════════════════════════════════
//  SPREADSHEET CACHE — VARY-AWARE COMPOUND KEY
// ═══════════════════════════════════════════════════════════

/**
 * Case-insensitive header lookup.
 * HTTP header names are case-insensitive per RFC 7230 § 3.2.
 */
function _getHeaderCaseInsensitive(headers, targetKey) {
  var target = targetKey.toLowerCase();
  for (var k in headers) {
    if (headers.hasOwnProperty(k) && k.toLowerCase() === target) {
      return headers[k];
    }
  }
  return null;
}

/**
 * Compute a compound cache key:
 *   MD5(URL | header1:value1 | header2:value2 | ...)
 *
 * Instead of reading the response Vary header (which would require
 * fetching first — circular), we preemptively include the request
 * headers that are known to cause response variation. This handles
 * Vary: Accept-Encoding and Vary: Accept-Language without ever
 * inspecting the response.
 *
 * Values are lowercased and whitespace-stripped so semantically
 * identical requests from different clients produce the same hash.
 * Missing and empty headers both map to "<none>" (same semantic).
 */
function _getCacheKey(url, reqHeaders) {
  var parts = [url];

  if (reqHeaders && typeof reqHeaders === "object") {
    for (var i = 0; i < VARY_KEY_HEADERS.length; i++) {
      var headerName = VARY_KEY_HEADERS[i];
      var rawValue = _getHeaderCaseInsensitive(reqHeaders, headerName);

      if (rawValue && String(rawValue).trim() !== "") {
        parts.push(headerName + ":" + rawValue.toLowerCase().replace(/\s/g, ""));
      } else {
        parts.push(headerName + ":<none>");
      }
    }
  } else {
    for (var j = 0; j < VARY_KEY_HEADERS.length; j++) {
      parts.push(VARY_KEY_HEADERS[j] + ":<none>");
    }
  }

  var compoundKey = parts.join("|");
  return _md5Hex(compoundKey);
}

function _md5Hex(input) {
  var rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, input);
  return rawHash
    .map(function (byte) {
      var v = (byte < 0) ? 256 + byte : byte;
      return ("0" + v.toString(16)).slice(-2);
    })
    .join("");
}

// ═══════════════════════════════════════════════════════════
//  SPREADSHEET CACHE — CORE LOGIC
// ═══════════════════════════════════════════════════════════

/**
 * Returns true if the request is eligible for the cache path:
 * public GET, no body, no auth/cookie headers, cache configured.
 */
function _canUseCache(req) {
  if ((req.m || "GET") !== "GET") return false;
  if (req.b) return false;
  if (!req.u || !req.u.match(/^https?:\/\//i)) return false;
  if (CACHE_SPREADSHEET_ID === "CHANGE_ME_TO_CACHE_SPREADSHEET_ID") return false;

  if (req.h && typeof req.h === "object") {
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k) && CACHE_BUSTING_HEADERS[k.toLowerCase()]) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Extract max-age (seconds) from a Cache-Control header value.
 * Returns 0 if the directive forbids caching (no-cache / no-store /
 * private). Falls back to CACHE_DEFAULT_TTL_SECONDS when no header
 * is present. Clamped to [60, 2592000] (1 min – 30 days).
 */
function _parseMaxAge(cacheControlHeader) {
  if (!cacheControlHeader) return CACHE_DEFAULT_TTL_SECONDS;

  var lower = cacheControlHeader.toLowerCase();

  if (
    lower.indexOf("no-cache") !== -1 ||
    lower.indexOf("no-store") !== -1 ||
    lower.indexOf("private") !== -1
  ) {
    return 0;
  }

  var match = lower.match(/max-age=(\d+)/);
  if (match) {
    var ttl = parseInt(match[1], 10);
    return Math.max(60, Math.min(ttl, 2592000));
  }

  return CACHE_DEFAULT_TTL_SECONDS;
}

/**
 * Rewrite time-sensitive headers so the client sees accurate
 * Date, Age, and Cache-Control values reflecting cache age.
 */
function _refreshCachedHeaders(headersJson, timestamp) {
  var headers = JSON.parse(headersJson);
  var cachedAt = new Date(timestamp);
  var now = new Date();
  var ageSeconds = Math.floor((now.getTime() - cachedAt.getTime()) / 1000);

  if (ageSeconds < 0) ageSeconds = 0;

  headers["Date"] = now.toUTCString();
  headers["Age"] = String(ageSeconds);

  var originalCc = headers["Cache-Control"] || headers["cache-control"];
  if (originalCc) {
    headers["X-Original-Cache-Control"] = originalCc;
  }

  var remainingMaxAge = Math.max(0, _parseMaxAge(originalCc) - ageSeconds);
  headers["Cache-Control"] = "public, max-age=" + remainingMaxAge;

  headers["X-Cache"] = "HIT from relay-spreadsheet";
  headers["X-Cached-At"] = cachedAt.toUTCString();

  return JSON.stringify(headers);
}

/**
 * Retrieve a cached response by compound cache key.
 * Uses TextFinder for O(log n) lookup. Skips expired entries.
 * Returns null on miss, expired entry, or unavailable sheet.
 */
function _getFromCache(url, reqHeaders) {
  var sheet = _initCacheSheet();
  if (!sheet) return null;

  var hash = _getCacheKey(url, reqHeaders);
  var finder = sheet.createTextFinder(hash).matchEntireCell(true);
  var found = finder.findNext();

  if (found) {
    var row = sheet.getRange(found.getRow(), 1, 1, 7).getValues()[0];

    var expiresAt = row[6];
    if (expiresAt && expiresAt instanceof Date && expiresAt < new Date()) {
      return null;
    }

    return {
      status: row[2],
      headers: _refreshCachedHeaders(row[3], row[5]),
      body: row[4],
    };
  }
  return null;
}

/**
 * Fetch a URL and store the response in the spreadsheet cache
 * using a circular buffer (O(1) writes). Skips storage when the
 * encoded body exceeds CACHE_MAX_BODY_BYTES or when Cache-Control
 * forbids caching. Returns the fetch result regardless.
 */
function _fetchAndCache(url, reqHeaders) {
  var sheet = _initCacheSheet();
  if (!sheet) return null;

  try {
    var response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
    var status = response.getResponseCode();
    var headers = _respHeaders(response);
    var body = Utilities.base64Encode(response.getContent());

    // Cell-size safety gate
    if (body.length > CACHE_MAX_BODY_BYTES) {
      return { status: status, headers: JSON.stringify(headers), body: body };
    }

    // TTL extraction
    var cacheControl =
      headers["Cache-Control"] || headers["cache-control"] || null;
    var ttlSeconds = _parseMaxAge(cacheControl);

    if (ttlSeconds === 0) {
      return { status: status, headers: JSON.stringify(headers), body: body };
    }

    var hash = _getCacheKey(url, reqHeaders);
    var timestamp = new Date();
    var expiresAt = new Date(timestamp.getTime() + ttlSeconds * 1000);

    // Safety: fallback if Date math produces invalid result
    if (isNaN(expiresAt.getTime())) {
      expiresAt = new Date(timestamp.getTime() + CACHE_DEFAULT_TTL_SECONDS * 1000);
    }

    var rowData = [
      hash,
      url,
      status,
      JSON.stringify(headers),
      body,
      timestamp.toISOString(),
      expiresAt,
    ];

    // Circular buffer write (O(1))
    var metaSheet = _getMetaSheet();
    if (metaSheet) {
      _ensureRowsAllocated(sheet);
      var writeRow = _getNextCursor(sheet, metaSheet);
      sheet.getRange(writeRow, 1, 1, 7).setValues([rowData]);
      _advanceCursor(metaSheet, writeRow);
    } else {
      // Fallback: simple append if meta sheet is unavailable
      sheet.appendRow(rowData);
    }

    return { status: status, headers: JSON.stringify(headers), body: body };
  } catch (e) {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════
//  SPREADSHEET CACHE — DIAGNOSTICS
// ═══════════════════════════════════════════════════════════

function getCacheStats() {
  var sheet = _initCacheSheet();
  if (!sheet) {
    console.log("Cache is not enabled or spreadsheet unavailable.");
    return;
  }

  var data = sheet.getDataRange().getValues();
  var totalEntries = data.length - 1;
  var now = new Date();
  var expiredCount = 0;

  for (var i = 1; i < data.length; i++) {
    var expiresAt = data[i][6];
    if (expiresAt && expiresAt instanceof Date && expiresAt < now) {
      expiredCount++;
    }
  }

  var metaSheet = _getMetaSheet();
  var cursorInfo = "N/A";
  if (metaSheet) {
    cursorInfo = String(metaSheet.getRange(CACHE_META_CURSOR_CELL).getValue());
  }

  console.log("=== CACHE STATS ===");
  console.log("Total rows used: " + totalEntries + " / " + CACHE_MAX_ROWS);
  console.log("Active entries: " + (totalEntries - expiredCount));
  console.log("Expired entries: " + expiredCount);
  console.log("Cursor position: " + cursorInfo);
  console.log("Max body size: " + CACHE_MAX_BODY_BYTES + " chars");
  console.log("Default TTL: " + CACHE_DEFAULT_TTL_SECONDS + " sec");
  console.log("Vary key headers: " + VARY_KEY_HEADERS.join(", "));
  if (totalEntries > 0) {
    console.log("Oldest entry: " + data[1][5]);
    console.log("Newest entry: " + data[data.length - 1][5]);
  }
}

function clearExpiredCache() {
  var sheet = _initCacheSheet();
  if (!sheet) {
    console.log("Cache is not enabled.");
    return;
  }

  var data = sheet.getDataRange().getValues();
  var now = new Date();
  var rowsToClear = [];

  for (var i = 1; i < data.length; i++) {
    var expiresAt = data[i][6];
    if (expiresAt && expiresAt instanceof Date && expiresAt < now) {
      rowsToClear.push(i + 1);
    }
  }

  for (var j = 0; j < rowsToClear.length; j++) {
    sheet.getRange(rowsToClear[j], 1, 1, 7).clearContent();
  }

  console.log("Cleared " + rowsToClear.length + " expired entries (" +
    (data.length - 1 - rowsToClear.length) + " remaining).");
}

function clearEntireCache() {
  var sheet = _initCacheSheet();
  if (sheet) {
    var totalRows = sheet.getDataRange().getNumRows();
    if (totalRows > 1) {
      sheet.getRange(2, 1, totalRows - 1, 7).clearContent();
    }
  }

  var metaSheet = _getMetaSheet();
  if (metaSheet) {
    metaSheet.getRange(CACHE_META_CURSOR_CELL).setValue(2);
  }

  console.log("Cache wiped. Cursor reset to row 2.");
}
