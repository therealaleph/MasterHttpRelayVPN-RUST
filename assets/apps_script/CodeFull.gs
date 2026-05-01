/**
 * DomainFront Relay + Full Tunnel — Google Apps Script
 *
 * FOUR modes:
 *   1. Single relay:  POST { k, m, u, h, b, ct, r }           → { s, h, b }
 *   2. Batch relay:   POST { k, q: [{m,u,h,b,ct,r}, ...] }    → { q: [{s,h,b}, ...] }
 *   3. Tunnel:        POST { k, t, h, p, sid, d }              → { sid, d, eof }
 *   4. Tunnel batch:  POST { k, t:"batch", ops:[...] }         → { r: [...] }
 *      Batch ops include TCP (`connect`, `data`) and UDP (`udp_open`,
 *      `udp_data`) tunnel-node operations.
 *
 * CHANGE THESE TO YOUR OWN VALUES!
 */

const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
const TUNNEL_SERVER_URL = "https://YOUR_TUNNEL_NODE_URL";
const TUNNEL_AUTH_KEY = "YOUR_TUNNEL_AUTH_KEY";

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
// to the destination. UrlFetchApp rejects most of the connection-level
// names anyway, but we also drop the `X-Forwarded-*` / `Forwarded` /
// `Via` family so that a misconfigured upstream proxy on the user side
// can't leak the user's real IP through the relay path. Mirrors
// upstream `masterking32/MasterHttpRelayVPN@3094288`.
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

// HTML body for the bad-auth decoy. Mimics a minimal Apps Script-style
// placeholder page — no proxy-shaped JSON, nothing distinctive enough
// for a probe to fingerprint as a tunnel endpoint.
const DECOY_HTML =
  '<!DOCTYPE html><html><head><title>Web App</title></head>' +
  '<body><p>The script completed but did not return anything.</p>' +
  '</body></html>';

function _decoyOrError(jsonBody) {
  if (DIAGNOSTIC_MODE) return _json(jsonBody);
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.HTML);
}

// Edge DNS cache. Plain UDP/53 queries normally traverse the full
// client → GAS → tunnel-node → public resolver path, and the
// trans-Atlantic round-trip dominates first-hop latency. When
// ENABLE_EDGE_DNS_CACHE is true, _doTunnelBatch intercepts udp_open
// ops with port=53, serves the reply from CacheService on a hit, or
// does its own DoH lookup on a miss from inside Google's network.
// Cache hits never reach the tunnel-node.
//
// Safety property: any failure (parse error, DoH unreachable,
// CacheService error, refused qtype) returns null from _edgeDnsTry,
// and the op falls through to the existing tunnel-node forward path.
// Set false to disable and forward all DNS through the tunnel as
// before.
const ENABLE_EDGE_DNS_CACHE = true;

// DoH endpoints tried in order on cache miss. All speak RFC 8484
// over GET. Apps Script's outbound network peers well to all three.
const EDGE_DNS_RESOLVERS = [
  "https://1.1.1.1/dns-query",
  "https://dns.google/dns-query",
  "https://dns.quad9.net/dns-query",
];

// CacheService bounds: 6h max TTL, 100KB per value, ~1000 keys, 250-char keys.
const EDGE_DNS_MIN_TTL_S = 30;
const EDGE_DNS_MAX_TTL_S = 21600;   // 6h CacheService ceiling
// Used for NXDOMAIN/SERVFAIL and the rare "no answer + no SOA in authority"
// case. NOERROR/NODATA replies normally carry an SOA, and per RFC 2308 §5
// we honor that SOA's TTL via _dnsMinTtl (the positive path).
const EDGE_DNS_NEG_TTL_S = 45;
const EDGE_DNS_CACHE_PREFIX = "edns:";
// CacheService rejects keys longer than 250 chars. Names approaching the
// 253-char DNS limit + prefix + qtype digits can exceed that, so we bail
// before issuing the get/put. The op falls through to the tunnel-node.
const EDGE_DNS_MAX_KEY_LEN = 240;

// qtypes we refuse to cache and pass through to the tunnel-node:
//   255 = ANY (resolvers handle it more correctly than we would)
const EDGE_DNS_REFUSE_QTYPES = { 255: 1 };

// ========================== Entry point ==========================

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _decoyOrError({ e: "unauthorized" });

    // Tunnel mode
    if (req.t) return _doTunnel(req);

    // Batch relay mode
    if (Array.isArray(req.q)) return _doBatch(req.q);

    // Single relay mode
    return _doSingle(req);
  } catch (err) {
    // Parse failures of the request body are also probe-shaped — a real
    // mhrv-rs client never sends invalid JSON. Decoy for the same reason.
    return _decoyOrError({ e: String(err) });
  }
}

// ========================== Tunnel mode ==========================

function _doTunnel(req) {
  // Batch tunnel: { k, t:"batch", ops:[...] }
  if (req.t === "batch") {
    return _doTunnelBatch(req);
  }

  // Single tunnel op
  var payload = { k: TUNNEL_AUTH_KEY };
  switch (req.t) {
    case "connect":
      payload.op = "connect";
      payload.host = req.h;
      payload.port = req.p;
      break;
    case "connect_data":
      payload.op = "connect_data";
      payload.host = req.h;
      payload.port = req.p;
      if (req.d) payload.data = req.d;
      break;
    case "data":
      payload.op = "data";
      payload.sid = req.sid;
      if (req.d) payload.data = req.d;
      break;
    case "close":
      payload.op = "close";
      payload.sid = req.sid;
      break;
    default:
      // Structured `code` lets the Rust client detect version skew
      // without substring-matching the error text. Must match
      // CODE_UNSUPPORTED_OP in tunnel_client.rs and tunnel-node/src/main.rs.
      return _json({ e: "unknown tunnel op: " + req.t, code: "UNSUPPORTED_OP" });
  }

  var resp = UrlFetchApp.fetch(TUNNEL_SERVER_URL + "/tunnel", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    followRedirects: true,
  });

  if (resp.getResponseCode() !== 200) {
    return _json({ e: "tunnel node HTTP " + resp.getResponseCode() });
  }

  return ContentService.createTextOutput(resp.getContentText())
    .setMimeType(ContentService.MimeType.JSON);
}

// Batch tunnel: forward all ops in one request to /tunnel/batch.
// When ENABLE_EDGE_DNS_CACHE is true, udp_open/port=53 ops are served
// locally where possible and only the remainder is forwarded.
function _doTunnelBatch(req) {
  var ops = (req && req.ops) || [];

  // Feature off: byte-identical to the pre-feature behavior.
  if (!ENABLE_EDGE_DNS_CACHE) {
    return _doTunnelBatchForward(ops);
  }

  var results = new Array(ops.length);   // sparse: filled by edge-DNS hits
  var forwardOps = [];
  var forwardIdx = [];

  for (var i = 0; i < ops.length; i++) {
    var op = ops[i];
    if (op && op.op === "udp_open" && op.port === 53 && op.d) {
      var synth = _edgeDnsTry(op);
      if (synth) {
        results[i] = synth;
        continue;
      }
    }
    forwardOps.push(op);
    forwardIdx.push(i);
  }

  // All ops served locally — no tunnel-node round-trip.
  if (forwardOps.length === 0) {
    return _json({ r: results });
  }

  // Nothing was served locally — forward verbatim, no splice needed.
  if (forwardOps.length === ops.length) {
    return _doTunnelBatchForward(ops);
  }

  // Partial: forward the un-served ops and splice results back in place.
  var resp = _doTunnelBatchFetch(forwardOps);
  if (resp.error) return _json({ e: resp.error });
  if (resp.r.length !== forwardOps.length) {
    // Tunnel-node version skew — bail explicitly rather than silently
    // route TCP responses to UDP sids.
    return _json({ e: "tunnel batch length mismatch" });
  }
  return _json({ r: _spliceTunnelResults(forwardIdx, resp.r, results) });
}

// Verbatim forward: no splice, response passed through unchanged.
function _doTunnelBatchForward(ops) {
  var resp = UrlFetchApp.fetch(TUNNEL_SERVER_URL + "/tunnel/batch", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({ k: TUNNEL_AUTH_KEY, ops: ops }),
    muteHttpExceptions: true,
    followRedirects: true,
  });
  if (resp.getResponseCode() !== 200) {
    return _json({ e: "tunnel batch HTTP " + resp.getResponseCode() });
  }
  return ContentService.createTextOutput(resp.getContentText())
    .setMimeType(ContentService.MimeType.JSON);
}

// Forward + parse for the splice path. Returns { r:[...] } on success or
// { error: "..." } on any failure.
function _doTunnelBatchFetch(ops) {
  var resp = UrlFetchApp.fetch(TUNNEL_SERVER_URL + "/tunnel/batch", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({ k: TUNNEL_AUTH_KEY, ops: ops }),
    muteHttpExceptions: true,
    followRedirects: true,
  });
  if (resp.getResponseCode() !== 200) {
    return { error: "tunnel batch HTTP " + resp.getResponseCode() };
  }
  try {
    var parsed = JSON.parse(resp.getContentText());
    return { r: (parsed && parsed.r) || [] };
  } catch (err) {
    return { error: "tunnel batch parse error" };
  }
}

// Pure helper: writes forwardedResults[j] into allResults[forwardIdx[j]]
// for each j. Returns the mutated allResults so callers can chain. Pure
// function — testable without the GAS runtime.
function _spliceTunnelResults(forwardIdx, forwardedResults, allResults) {
  for (var j = 0; j < forwardIdx.length; j++) {
    allResults[forwardIdx[j]] = forwardedResults[j];
  }
  return allResults;
}

// ========================== HTTP relay mode ==========================

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }
  var opts = _buildOpts(req);
  var resp = UrlFetchApp.fetch(req.u, opts);
  return _json({
    s: resp.getResponseCode(),
    h: _respHeaders(resp),
    b: Utilities.base64Encode(resp.getContent()),
  });
}

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

  // fetchAll() runs all requests in parallel inside Google. If it
  // throws as a whole (e.g. one URL violates UrlFetchApp limits and
  // poisons the whole batch), degrade to per-item fetch so a single
  // bad request does not zero out the entire batch's responses.
  // Mirrors upstream `masterking32/MasterHttpRelayVPN@3094288`.
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

// ========================== Helpers ==========================

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

// `doGet` is what active scanners hit first (HTTP GET probes are cheaper
// than POSTs). We use ContentService here so the response body is the
// raw HTML we wrote — `HtmlService.createHtmlOutput` would wrap it in
// a `goog.script.init` sandbox iframe, which the Rust client would then
// see if it ever GET-followed a redirect back onto /macros/.../exec
// (decoy/no-json error path). ContentService keeps the doGet response
// indistinguishable from a forgotten static-HTML web app.
function doGet(e) {
  return ContentService
    .createTextOutput(DECOY_HTML)
    .setMimeType(ContentService.MimeType.HTML);
}

function _json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(
    ContentService.MimeType.JSON
  );
}

// ========================== Edge DNS helpers ==========================

// Tries to serve a single udp_open DNS op from CacheService or DoH.
// Returns a synthesized batch-result {sid, pkts, eof} on success, or null
// on any failure / unsupported case so the caller can forward to the
// tunnel-node. Null is the safe default — every error path returns null.
function _edgeDnsTry(op) {
  try {
    var bytes = Utilities.base64Decode(op.d);
    if (!bytes || bytes.length < 12) return null;

    var q = _dnsParseQuestion(bytes);
    if (!q) return null;
    if (EDGE_DNS_REFUSE_QTYPES[q.qtype]) return null;

    var key = EDGE_DNS_CACHE_PREFIX + q.qtype + ":" + q.qname;
    if (key.length > EDGE_DNS_MAX_KEY_LEN) return null;
    var cache = CacheService.getScriptCache();

    var stored = null;
    try { stored = cache.get(key); } catch (_) {}
    if (stored) {
      try {
        var hit = Utilities.base64Decode(stored);
        if (hit && hit.length >= 12) {
          // Rewrite txid to match this query (RFC 1035 §4.1.1).
          var rewritten = _dnsRewriteTxid(hit, q.txid);
          return {
            sid: "edns-cache",
            pkts: [Utilities.base64Encode(rewritten)],
            eof: true,
          };
        }
      } catch (_) { /* corrupt cache entry — fall through to DoH */ }
    }

    for (var i = 0; i < EDGE_DNS_RESOLVERS.length; i++) {
      var reply = _edgeDnsDoh(EDGE_DNS_RESOLVERS[i], bytes);
      if (!reply) continue;

      var rcode = reply[3] & 0x0F;
      var ttl;
      if (rcode === 2 || rcode === 3) {
        ttl = EDGE_DNS_NEG_TTL_S;
      } else {
        var minTtl = _dnsMinTtl(reply);
        ttl = (minTtl === null) ? EDGE_DNS_NEG_TTL_S : minTtl;
        if (ttl < EDGE_DNS_MIN_TTL_S) ttl = EDGE_DNS_MIN_TTL_S;
        if (ttl > EDGE_DNS_MAX_TTL_S) ttl = EDGE_DNS_MAX_TTL_S;
      }

      try {
        cache.put(key, Utilities.base64Encode(reply), ttl);
      } catch (_) {
        // >100KB value or transient quota — still return the live answer.
      }

      // The DoH reply already echoes our query's txid; rewrite defensively
      // in case a resolver mangles it.
      var fixed = _dnsRewriteTxid(reply, q.txid);
      return {
        sid: "edns-doh",
        pkts: [Utilities.base64Encode(fixed)],
        eof: true,
      };
    }
    return null;
  } catch (err) {
    return null;
  }
}

// Single DoH GET against `url`. Returns the reply as a byte array, or null
// on any failure (HTTP non-200, network error, malformed body).
function _edgeDnsDoh(url, queryBytes) {
  try {
    var dns = Utilities.base64EncodeWebSafe(queryBytes).replace(/=+$/, "");
    var resp = UrlFetchApp.fetch(url + "?dns=" + dns, {
      method: "get",
      muteHttpExceptions: true,
      followRedirects: true,
      headers: { accept: "application/dns-message" },
    });
    if (resp.getResponseCode() !== 200) return null;
    var body = resp.getContent();
    if (!body || body.length < 12) return null;
    return body;
  } catch (err) {
    return null;
  }
}

// Returns { txid, qname, qtype } from a DNS wire-format query.
// qname is lowercased and dot-joined (no trailing dot). Null on malformed.
function _dnsParseQuestion(bytes) {
  if (bytes.length < 12) return null;
  var qdcount = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
  // RFC ambiguity: multi-question queries are essentially unused in
  // practice and would mis-key the cache (we'd cache a multi-answer reply
  // under only the first question). Bail and let the tunnel-node handle it.
  if (qdcount !== 1) return null;

  var off = 12;
  var labels = [];
  var nameLen = 0;
  while (off < bytes.length) {
    var len = bytes[off] & 0xFF;
    if (len === 0) { off++; break; }
    if ((len & 0xC0) !== 0) return null;   // questions don't use compression
    if (len > 63) return null;
    off++;
    if (off + len > bytes.length) return null;
    var label = "";
    for (var i = 0; i < len; i++) {
      var c = bytes[off + i] & 0xFF;
      if (c >= 0x41 && c <= 0x5A) c += 0x20;   // ASCII lowercase
      label += String.fromCharCode(c);
    }
    labels.push(label);
    off += len;
    nameLen += len + 1;
    if (nameLen > 255) return null;
  }
  if (off + 4 > bytes.length) return null;
  var qtype = ((bytes[off] & 0xFF) << 8) | (bytes[off + 1] & 0xFF);

  return {
    txid: ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF),
    qname: labels.join("."),
    qtype: qtype,
  };
}

// Walks the DNS reply's answer + authority sections and returns the min RR
// TTL, or null if there are no RRs (caller treats null as "use neg TTL").
// Returns null on any malformed input.
function _dnsMinTtl(bytes) {
  if (bytes.length < 12) return null;
  var qdcount = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
  var ancount = ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
  var nscount = ((bytes[8] & 0xFF) << 8) | (bytes[9] & 0xFF);

  var off = 12;
  for (var q = 0; q < qdcount; q++) {
    off = _dnsSkipName(bytes, off);
    if (off < 0 || off + 4 > bytes.length) return null;
    off += 4;
  }

  var min = null;
  var rrTotal = ancount + nscount;
  for (var r = 0; r < rrTotal; r++) {
    off = _dnsSkipName(bytes, off);
    if (off < 0 || off + 10 > bytes.length) return null;
    // 2B type, 2B class, 4B TTL, 2B rdlength
    var ttl = ((bytes[off + 4] & 0xFF) * 0x1000000)
            + (((bytes[off + 5] & 0xFF) << 16)
            |  ((bytes[off + 6] & 0xFF) << 8)
            |   (bytes[off + 7] & 0xFF));
    // RFC 2181: TTLs are 32-bit unsigned; values with the top bit set are
    // treated as 0. Multiplying the high byte (instead of <<24) avoids V8
    // sign-extension and keeps `ttl` in [0, 2^32).
    if (ttl < 0 || ttl > 0x7FFFFFFF) ttl = 0;
    if (min === null || ttl < min) min = ttl;
    var rdlen = ((bytes[off + 8] & 0xFF) << 8) | (bytes[off + 9] & 0xFF);
    off += 10 + rdlen;
    if (off > bytes.length) return null;
  }
  return min;
}

// Advances past a DNS name (sequence of labels or 16-bit pointer).
// Returns the new offset, or -1 on malformed input.
function _dnsSkipName(bytes, off) {
  while (off < bytes.length) {
    var len = bytes[off] & 0xFF;
    if (len === 0) return off + 1;
    if ((len & 0xC0) === 0xC0) {
      if (off + 2 > bytes.length) return -1;
      return off + 2;   // pointer terminates the name in-place
    }
    if ((len & 0xC0) !== 0) return -1;   // reserved label type
    if (len > 63) return -1;
    off += 1 + len;
  }
  return -1;
}

// Returns a copy of `bytes` with the first 2 bytes overwritten by the
// big-endian 16-bit transaction id. Coerces to signed-byte range so the
// result round-trips through Utilities.base64Encode regardless of whether
// the runtime exposes bytes as signed Java int8 or unsigned JS numbers.
function _dnsRewriteTxid(bytes, txid) {
  var out = [];
  for (var i = 0; i < bytes.length; i++) out.push(bytes[i]);
  var hi = (txid >> 8) & 0xFF;
  var lo = txid & 0xFF;
  out[0] = hi > 127 ? hi - 256 : hi;
  out[1] = lo > 127 ? lo - 256 : lo;
  return out;
}
