// Mocked-runtime tests for the batch DNS path in CodeFull.gs.
//
// Run from repo root:  node assets/apps_script/tests/edge_dns_batch_test.js
//
// Complements edge_dns_test.js (pure helpers) by exercising the parts of
// the file that depend on the GAS runtime: _edgeDnsPrepare, _edgeDnsResolve,
// _doTunnelBatch, and the long-qname hash path. Mocks Utilities,
// CacheService, UrlFetchApp, and ContentService just enough that the
// extracted code runs unmodified.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SRC = path.join(__dirname, '..', 'CodeFull.gs');
const src = fs.readFileSync(SRC, 'utf8');

// =============== Source extraction ===============

const FUNC_NAMES = [
  '_dnsSkipName', '_dnsParseQuestion', '_dnsMinTtl', '_dnsRewriteTxid',
  '_sha256Hex', '_edgeDnsPrepare', '_edgeDnsResolve', '_edgeDnsDoh',
  '_doTunnelBatch', '_doTunnelBatchForward', '_doTunnelBatchFetch',
  '_spliceTunnelResults', '_json',
];
const CONST_NAMES = [
  'ENABLE_EDGE_DNS_CACHE', 'EDGE_DNS_RESOLVERS', 'EDGE_DNS_MIN_TTL_S',
  'EDGE_DNS_MAX_TTL_S', 'EDGE_DNS_NEG_TTL_S', 'EDGE_DNS_CACHE_PREFIX',
  'EDGE_DNS_MAX_KEY_LEN', 'EDGE_DNS_REFUSE_QTYPES',
  'TUNNEL_SERVER_URL', 'TUNNEL_AUTH_KEY',
];

let bundle = '';
for (const name of CONST_NAMES) {
  // Match through the first ";" that ends the declaration. Allow an
  // optional trailing same-line comment ("const X = Y;   // note") before
  // the newline; otherwise the lazy quantifier would skip past and swallow
  // the next const, double-declaring it.
  const re = new RegExp(`const ${name}\\s*=[\\s\\S]*?;[^\\n]*\\n`);
  const m = src.match(re);
  if (!m) throw new Error('const not found in CodeFull.gs: ' + name);
  bundle += m[0] + '\n';
}
for (const name of FUNC_NAMES) {
  const re = new RegExp(`function ${name}\\b[\\s\\S]*?\\n\\}\\n`);
  const m = src.match(re);
  if (!m) throw new Error('helper not found in CodeFull.gs: ' + name);
  bundle += m[0] + '\n';
}
bundle += `return { ${FUNC_NAMES.concat(CONST_NAMES).join(', ')} };`;

function buildContext(deps) {
  // eslint-disable-next-line no-new-func
  const fn = new Function(
    'Utilities', 'CacheService', 'UrlFetchApp', 'ContentService', bundle);
  return fn(deps.Utilities, deps.CacheService, deps.UrlFetchApp, deps.ContentService);
}

// =============== Mocks ===============

function bytesArr(buf) {
  const arr = [];
  for (let i = 0; i < buf.length; i++) arr.push(buf[i]);
  return arr;
}

function makeUtilities() {
  return {
    base64Decode: (s) => bytesArr(Buffer.from(s, 'base64')),
    base64Encode: (b) => Buffer.from(b).toString('base64'),
    base64EncodeWebSafe: (b) =>
      Buffer.from(b).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_'),
    computeDigest: (algo, s) => {
      const h = crypto.createHash(algo);
      h.update(s, 'utf8');
      return bytesArr(h.digest());
    },
    DigestAlgorithm: { MD5: 'md5', SHA_256: 'sha256' },
    Charset: { UTF_8: 'utf8' },
  };
}

function makeCache(opts) {
  opts = opts || {};
  const store = Object.assign({}, opts.seed || {});
  let getAllCalls = 0;
  const putHistory = [];
  return {
    handle: {
      getAll: function (keys) {
        getAllCalls++;
        if (opts.throwOnGetAll) throw new Error('cache backend hiccup');
        const out = {};
        for (let i = 0; i < keys.length; i++) {
          if (keys[i] in store) out[keys[i]] = store[keys[i]];
        }
        return out;
      },
      put: function (k, v, ttl) {
        putHistory.push({ k: k, v: v, ttl: ttl });
        store[k] = v;
      },
    },
    getAllCalls: () => getAllCalls,
    putHistory: () => putHistory,
  };
}

function makeCacheService(cacheStub) {
  return { getScriptCache: () => cacheStub.handle };
}

function makeContentService() {
  return {
    createTextOutput: (s) => ({
      _text: s,
      _mime: null,
      setMimeType: function (m) { this._mime = m; return this; },
    }),
    MimeType: { JSON: 'json', HTML: 'html' },
  };
}

function makeUrlFetchApp(handler) {
  const calls = [];
  return {
    handle: {
      fetch: (url, opts) => {
        calls.push({ url: url, opts: opts });
        return handler(url, opts);
      },
    },
    calls: () => calls,
  };
}

// =============== DNS wire builders ===============

function buildQuery(txid, qname, qtype) {
  const labels = qname.split('.').filter((s) => s.length > 0);
  const parts = [Buffer.from([
    (txid >> 8) & 0xFF, txid & 0xFF,
    0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ])];
  for (const label of labels) {
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label, 'utf8'));
  }
  parts.push(Buffer.from([
    0x00,
    (qtype >> 8) & 0xFF, qtype & 0xFF,
    0x00, 0x01,
  ]));
  return Buffer.concat(parts);
}

function buildAReply(txid, qname, ttlSec, ip) {
  const labels = qname.split('.').filter((s) => s.length > 0);
  const parts = [Buffer.from([
    (txid >> 8) & 0xFF, txid & 0xFF,
    0x81, 0x80,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  ])];
  for (const label of labels) {
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label, 'utf8'));
  }
  parts.push(Buffer.from([
    0x00,
    0x00, 0x01, 0x00, 0x01,
    0xC0, 0x0C,
    0x00, 0x01, 0x00, 0x01,
    (ttlSec >>> 24) & 0xFF, (ttlSec >>> 16) & 0xFF,
    (ttlSec >>> 8) & 0xFF, ttlSec & 0xFF,
    0x00, 0x04,
    ip[0], ip[1], ip[2], ip[3],
  ]));
  return Buffer.concat(parts);
}

// =============== Runner ===============

let passed = 0;
function check(label, cond, detail) {
  if (!cond) {
    console.error('FAIL: ' + label + (detail ? ' — ' + detail : ''));
    process.exit(1);
  }
}
function ok() { console.log('  ok'); passed++; }

// =============== Tests ===============

console.log('TEST B1 _sha256Hex returns 64 hex chars, deterministic');
{
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(makeCache()),
    UrlFetchApp: makeUrlFetchApp(() => null).handle,
    ContentService: makeContentService(),
  });
  const h = ctx._sha256Hex('example.com');
  check('length 64', h.length === 64, 'len ' + h.length);
  check('hex only', /^[0-9a-f]+$/.test(h), h);
  check('deterministic', ctx._sha256Hex('example.com') === h);
  ok();
}

console.log('TEST B2 _edgeDnsPrepare short qname → readable key');
{
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(makeCache()),
    UrlFetchApp: makeUrlFetchApp(() => null).handle,
    ContentService: makeContentService(),
  });
  const prep = ctx._edgeDnsPrepare({
    d: buildQuery(0x1234, 'example.com', 1).toString('base64'),
  });
  check('not null', prep !== null);
  check('readable key', prep.key === 'edns:1:example.com', prep.key);
  check('parsed qtype', prep.q.qtype === 1);
  check('parsed txid', prep.q.txid === 0x1234);
  ok();
}

console.log('TEST B3 _edgeDnsPrepare long qname → SHA-256 hashed key');
{
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(makeCache()),
    UrlFetchApp: makeUrlFetchApp(() => null).handle,
    ContentService: makeContentService(),
  });
  const longName = 'a'.repeat(60) + '.' + 'b'.repeat(60) + '.'
                 + 'c'.repeat(60) + '.' + 'd'.repeat(60);
  const prep = ctx._edgeDnsPrepare({
    d: buildQuery(0x1234, longName, 1).toString('base64'),
  });
  check('not null (no longer bails on long qname)', prep !== null);
  check('hashed namespace', prep.key.indexOf('edns:h:1:') === 0, prep.key);
  // edns:h:1: (9) + 64 hex = 73 chars; well under the 250-char CacheService cap.
  check('hashed length 73', prep.key.length === 73, 'len ' + prep.key.length);
  ok();
}

console.log('TEST B4 _edgeDnsPrepare rejects qtype ANY (255)');
{
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(makeCache()),
    UrlFetchApp: makeUrlFetchApp(() => null).handle,
    ContentService: makeContentService(),
  });
  const prep = ctx._edgeDnsPrepare({
    d: buildQuery(0x1234, 'example.com', 255).toString('base64'),
  });
  check('null', prep === null);
  ok();
}

console.log('TEST B5 _doTunnelBatch all-served-from-cache: zero outbound fetch');
{
  const cache = makeCache();
  cache.handle.put(
    'edns:1:example.com',
    buildAReply(0xCAFE, 'example.com', 300, [1, 2, 3, 4]).toString('base64'),
    300);
  const utf = makeUrlFetchApp(() => {
    throw new Error('UrlFetchApp must not be invoked when batch is all-cached');
  });
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(cache),
    UrlFetchApp: utf.handle,
    ContentService: makeContentService(),
  });
  const out = ctx._doTunnelBatch({
    ops: [{
      op: 'udp_open', port: 53,
      d: buildQuery(0xBEEF, 'example.com', 1).toString('base64'),
    }],
  });
  check('no UrlFetchApp call', utf.calls().length === 0);
  check('exactly one getAll', cache.getAllCalls() === 1);
  const parsed = JSON.parse(out._text);
  check('one result', parsed.r && parsed.r.length === 1);
  check('cache sid', parsed.r[0].sid === 'edns-cache');
  // Verify the returned packet carries the requestor's txid (0xBEEF), not
  // the txid that was stored in the cache (0xCAFE).
  const pkt = bytesArr(Buffer.from(parsed.r[0].pkts[0], 'base64'));
  check('txid hi rewritten', pkt[0] === 0xBE, 'got ' + pkt[0]);
  check('txid lo rewritten', pkt[1] === 0xEF, 'got ' + pkt[1]);
  ok();
}

console.log('TEST B6 _doTunnelBatch all-non-DNS: forwarded verbatim');
{
  const cache = makeCache();
  const utf = makeUrlFetchApp(() => ({
    getResponseCode: () => 200,
    getContent: () => Buffer.alloc(0),
    getContentText: () => '{"r":[{"sid":"tcp-1"}]}',
  }));
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(cache),
    UrlFetchApp: utf.handle,
    ContentService: makeContentService(),
  });
  const out = ctx._doTunnelBatch({
    ops: [{ op: 'connect', host: 'a.com', port: 80 }],
  });
  check('one fetch', utf.calls().length === 1);
  check('went to /tunnel/batch',
        utf.calls()[0].url.indexOf('/tunnel/batch') >= 0);
  check('getAll skipped (no candidates)', cache.getAllCalls() === 0);
  check('verbatim body', out._text === '{"r":[{"sid":"tcp-1"}]}');
  ok();
}

console.log('TEST B7 _doTunnelBatch mixed: forwarded subset + spliced ordering');
{
  const cache = makeCache();
  cache.handle.put(
    'edns:1:example.com',
    buildAReply(0xAAAA, 'example.com', 300, [1, 2, 3, 4]).toString('base64'),
    300);
  const utf = makeUrlFetchApp((url, opts) => {
    const body = JSON.parse(opts.payload);
    check('forward carries non-DNS only', body.ops.length === 2);
    check('forward op[0] is connect', body.ops[0].op === 'connect');
    check('forward op[1] is udp_data', body.ops[1].op === 'udp_data');
    return {
      getResponseCode: () => 200,
      getContent: () => Buffer.alloc(0),
      getContentText: () =>
        JSON.stringify({ r: [{ sid: 'tcp-A' }, { sid: 'udp-Z' }] }),
    };
  });
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(cache),
    UrlFetchApp: utf.handle,
    ContentService: makeContentService(),
  });
  const out = ctx._doTunnelBatch({
    ops: [
      { op: 'connect', host: 'a.com', port: 80 },
      { op: 'udp_open', port: 53,
        d: buildQuery(0xBEEF, 'example.com', 1).toString('base64') },
      { op: 'udp_data', sid: 'u1', d: 'AAAA' },
    ],
  });
  const parsed = JSON.parse(out._text);
  check('three results', parsed.r.length === 3);
  check('idx 0 = tcp-A',  parsed.r[0].sid === 'tcp-A');
  check('idx 1 = edns',   parsed.r[1].sid === 'edns-cache');
  check('idx 2 = udp-Z',  parsed.r[2].sid === 'udp-Z');
  ok();
}

console.log('TEST B8 _doTunnelBatch getAll throws: DoH still runs, no put');
{
  const cache = makeCache({ throwOnGetAll: true });
  const replyBytes = buildAReply(0xAAAA, 'example.com', 300, [1, 2, 3, 4]);
  let dohCalls = 0;
  const utf = makeUrlFetchApp((url) => {
    if (url.indexOf('dns-query') >= 0) {
      dohCalls++;
      return {
        getResponseCode: () => 200,
        getContent: () => bytesArr(replyBytes),
      };
    }
    throw new Error('unexpected fetch ' + url);
  });
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(cache),
    UrlFetchApp: utf.handle,
    ContentService: makeContentService(),
  });
  const out = ctx._doTunnelBatch({
    ops: [{
      op: 'udp_open', port: 53,
      d: buildQuery(0xBEEF, 'example.com', 1).toString('base64'),
    }],
  });
  check('getAll attempted', cache.getAllCalls() === 1);
  check('one DoH call', dohCalls === 1);
  // cache==null was assigned in the catch path, so no put should fire.
  check('no cache.put', cache.putHistory().length === 0);
  const parsed = JSON.parse(out._text);
  check('result is doh (not forwarded)', parsed.r[0].sid === 'edns-doh');
  ok();
}

console.log('TEST B9 _doTunnelBatch intra-batch dedup: one DoH for two same-key ops');
{
  const cache = makeCache();
  const replyBytes = buildAReply(0xAAAA, 'example.com', 300, [1, 2, 3, 4]);
  let dohCalls = 0;
  const utf = makeUrlFetchApp((url) => {
    if (url.indexOf('dns-query') >= 0) {
      dohCalls++;
      return {
        getResponseCode: () => 200,
        getContent: () => bytesArr(replyBytes),
      };
    }
    throw new Error('unexpected fetch ' + url);
  });
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(cache),
    UrlFetchApp: utf.handle,
    ContentService: makeContentService(),
  });
  const out = ctx._doTunnelBatch({
    ops: [
      { op: 'udp_open', port: 53,
        d: buildQuery(0x1111, 'example.com', 1).toString('base64') },
      { op: 'udp_open', port: 53,
        d: buildQuery(0x2222, 'example.com', 1).toString('base64') },
    ],
  });
  const parsed = JSON.parse(out._text);
  check('only one DoH call', dohCalls === 1, 'got ' + dohCalls);
  check('two results', parsed.r.length === 2);
  check('first is doh', parsed.r[0].sid === 'edns-doh');
  // Second hits the in-batch dedup map (same code path as a real cache hit).
  check('second is cache (intra-batch hit)',
        parsed.r[1].sid === 'edns-cache');
  // Each result still carries its own request txid.
  const pkt1 = bytesArr(Buffer.from(parsed.r[0].pkts[0], 'base64'));
  const pkt2 = bytesArr(Buffer.from(parsed.r[1].pkts[0], 'base64'));
  check('pkt1 txid', pkt1[0] === 0x11 && pkt1[1] === 0x11);
  check('pkt2 txid', pkt2[0] === 0x22 && pkt2[1] === 0x22);
  ok();
}

console.log('TEST B10 _edgeDnsResolve: corrupt cache value falls through to DoH');
{
  const replyBytes = buildAReply(0xAAAA, 'example.com', 300, [1, 2, 3, 4]);
  let dohCalls = 0;
  const utf = makeUrlFetchApp(() => {
    dohCalls++;
    return {
      getResponseCode: () => 200,
      getContent: () => bytesArr(replyBytes),
    };
  });
  const ctx = buildContext({
    Utilities: makeUtilities(),
    CacheService: makeCacheService(makeCache()),
    UrlFetchApp: utf.handle,
    ContentService: makeContentService(),
  });
  const prep = ctx._edgeDnsPrepare({
    d: buildQuery(0xBEEF, 'example.com', 1).toString('base64'),
  });
  // <12-byte payload — the function bails on length and falls to DoH.
  const corruptB64 = Buffer.from([0x01, 0x02, 0x03]).toString('base64');
  const synth = ctx._edgeDnsResolve(prep, corruptB64, null, null);
  check('synth not null', synth !== null);
  check('fell through to DoH', synth.sid === 'edns-doh');
  check('one DoH call', dohCalls === 1);
  ok();
}

console.log('\n' + passed + ' tests passed');
