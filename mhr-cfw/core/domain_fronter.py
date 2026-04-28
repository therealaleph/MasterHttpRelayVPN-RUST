"""
CDN Relay engine.

Modes:
  1. custom_domain   — SNI and Host both point to your custom domain on CF.
  2. domain_fronting  — SNI = front_domain (allowed), Host = worker_host.
  3. google_fronting  — Connect to Google IP, SNI=google, Host=Cloud Run.
  4. apps_script     — Domain fronting via Google Apps Script relay.
     POST JSON to script.google.com (fronted through www.google.com).
     Apps Script fetches the target URL and returns the response.

Modes 1-3:
  tunnel()  — WebSocket-based TCP tunnel (HTTPS / any TCP)
  forward() — HTTP request forwarding    (plain HTTP)

Mode 4 (apps_script):
  relay()   — JSON-based HTTP relay through Apps Script
"""

import asyncio
import base64
import gzip
import json
import logging
import os
import re
import ssl
import time
from urllib.parse import urlparse

from core.ws import ws_encode, ws_decode

log = logging.getLogger("Fronter")


class DomainFronter:
    def __init__(self, config: dict):
        mode = config.get("mode", "domain_fronting")

        if mode == "custom_domain":
            domain = config["custom_domain"]
            self.connect_host = domain
            self.sni_host = domain
            self.http_host = domain
        elif mode == "google_fronting":
            self.connect_host = config.get("google_ip", "216.239.38.120")
            self.sni_host = config.get("front_domain", "www.google.com")
            self.http_host = config["worker_host"]
        elif mode == "apps_script":
            self.connect_host = config.get("google_ip", "216.239.38.120")
            self.sni_host = config.get("front_domain", "www.google.com")
            self.http_host = "script.google.com"
            # Multi-script round-robin for higher throughput
            script = config.get("script_ids") or config.get("script_id")
            self._script_ids = script if isinstance(script, list) else [script]
            self._script_idx = 0
            self.script_id = self._script_ids[0]  # backward compat / logging
            self._dev_available = False  # True if /dev endpoint works (no redirect, ~400ms faster)
        else:
            self.connect_host = config["front_domain"]
            self.sni_host = config["front_domain"]
            self.http_host = config["worker_host"]

        self.mode = mode
        self.worker_path = config.get("worker_path", "")
        self.auth_key = config.get("auth_key", "")
        self.verify_ssl = config.get("verify_ssl", True)

        # Connection pool — TTL-based, pre-warmed, with concurrency control
        self._pool: list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]] = []
        self._pool_lock = asyncio.Lock()
        self._pool_max = 50
        self._conn_ttl = 45.0           # seconds before a pooled conn is discarded
        self._semaphore = asyncio.Semaphore(50)  # max concurrent relay connections
        self._warmed = False
        self._refilling = False         # background pool refill in progress
        self._pool_min_idle = 15        # maintain at least this many idle connections
        self._maintenance_task: asyncio.Task | None = None

        # Batch collector for grouping concurrent relay() calls
        self._batch_lock = asyncio.Lock()
        self._batch_pending: list[tuple[dict, asyncio.Future]] = []
        self._batch_task: asyncio.Task | None = None
        self._batch_window_micro = 0.005  # 5ms micro-window (single req)
        self._batch_window_macro = 0.050 # 50ms macro-window (burst traffic)
        self._batch_max = 50            # max requests per batch
        self._batch_enabled = True      # disabled on first batch API failure

        # Request coalescing — dedup concurrent identical GETs
        self._coalesce: dict[str, list[asyncio.Future]] = {}

        # HTTP/2 multiplexing — one connection handles all requests
        self._h2 = None
        if mode == "apps_script":
            try:
                from h2_transport import H2Transport, H2_AVAILABLE
                if H2_AVAILABLE:
                    self._h2 = H2Transport(
                        self.connect_host, self.sni_host, self.verify_ssl
                    )
                    log.info("HTTP/2 multiplexing available — "
                             "all requests will share one connection")
            except ImportError:
                pass

    # ── helpers ───────────────────────────────────────────────────

    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _open(self):
        """Open a TLS connection to the CDN.

        The *server_hostname* parameter sets the **TLS SNI** extension.
        DPI systems see only this value.
        """
        return await asyncio.open_connection(
            self.connect_host,
            443,
            ssl=self._ssl_ctx(),
            server_hostname=self.sni_host,
        )

    async def _acquire(self):
        """Get a healthy TLS connection from pool (TTL-checked) or open new."""
        now = asyncio.get_event_loop().time()
        async with self._pool_lock:
            while self._pool:
                reader, writer, created = self._pool.pop()
                if (now - created) < self._conn_ttl and not reader.at_eof():
                    # Eagerly replace the connection we just took
                    asyncio.create_task(self._add_conn_to_pool())
                    return reader, writer, created
                try:
                    writer.close()
                except Exception:
                    pass
        reader, writer = await asyncio.wait_for(self._open(), timeout=10)
        # Pool was empty — trigger aggressive background refill
        if not self._refilling:
            self._refilling = True
            asyncio.create_task(self._refill_pool())
        return reader, writer, asyncio.get_event_loop().time()

    async def _release(self, reader, writer, created):
        """Return a connection to the pool if still young and healthy."""
        now = asyncio.get_event_loop().time()
        if (now - created) >= self._conn_ttl or reader.at_eof():
            try:
                writer.close()
            except Exception:
                pass
            return
        async with self._pool_lock:
            if len(self._pool) < self._pool_max:
                self._pool.append((reader, writer, created))
            else:
                try:
                    writer.close()
                except Exception:
                    pass

    def _next_script_id(self) -> str:
        """Round-robin across script IDs for load distribution."""
        sid = self._script_ids[self._script_idx % len(self._script_ids)]
        self._script_idx += 1
        return sid

    def _exec_path(self) -> str:
        """Get the next Apps Script endpoint path (/dev or /exec)."""
        sid = self._next_script_id()
        return f"/macros/s/{sid}/{'dev' if self._dev_available else 'exec'}"

    async def _flush_pool(self):
        """Close all pooled connections (they may be stale after errors)."""
        async with self._pool_lock:
            for _, writer, _ in self._pool:
                try:
                    writer.close()
                except Exception:
                    pass
            self._pool.clear()

    async def _refill_pool(self):
        """Background: open connections in parallel to refill empty pool."""
        try:
            coros = [self._add_conn_to_pool() for _ in range(8)]
            await asyncio.gather(*coros, return_exceptions=True)
        finally:
            self._refilling = False

    async def _add_conn_to_pool(self):
        """Open one TLS connection and add it to the pool."""
        try:
            r, w = await asyncio.wait_for(self._open(), timeout=5)
            t = asyncio.get_event_loop().time()
            async with self._pool_lock:
                if len(self._pool) < self._pool_max:
                    self._pool.append((r, w, t))
                else:
                    try:
                        w.close()
                    except Exception:
                        pass
        except Exception:
            pass

    async def _pool_maintenance(self):
        """Continuously maintain healthy pool levels in background."""
        while True:
            try:
                await asyncio.sleep(3)
                now = asyncio.get_event_loop().time()

                # Purge expired / dead connections
                async with self._pool_lock:
                    alive = []
                    for r, w, t in self._pool:
                        if (now - t) < self._conn_ttl and not r.at_eof():
                            alive.append((r, w, t))
                        else:
                            try:
                                w.close()
                            except Exception:
                                pass
                    self._pool = alive
                    idle = len(self._pool)

                # Refill if below minimum idle threshold
                needed = max(0, self._pool_min_idle - idle)
                if needed > 0:
                    coros = [self._add_conn_to_pool()
                             for _ in range(min(needed, 5))]
                    await asyncio.gather(*coros, return_exceptions=True)

            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _warm_pool(self):
        """Pre-open TLS connections in the background. Never blocks relay()."""
        if self._warmed:
            return
        self._warmed = True
        asyncio.create_task(self._do_warm())
        # Start continuous pool maintenance
        if self._maintenance_task is None:
            self._maintenance_task = asyncio.create_task(self._pool_maintenance())
        # Start H2 connection (runs alongside H1 pool)
        if self._h2:
            asyncio.create_task(self._h2_connect_and_warm())

    async def _h2_connect(self):
        """Connect the HTTP/2 transport in background."""
        try:
            await self._h2.ensure_connected()
            log.info("H2 multiplexing active — one conn handles all requests")
        except Exception as e:
            log.warning("H2 connect failed (%s), using H1 pool fallback", e)

    async def _h2_connect_and_warm(self):
        """Connect H2, pre-warm the Apps Script container, start keepalive."""
        await self._h2_connect()
        if self._h2 and self._h2.is_connected:
            asyncio.create_task(self._prewarm_script())
            asyncio.create_task(self._keepalive_loop())

    async def _prewarm_script(self):
        """Pre-warm Apps Script and detect /dev fast path (no redirect)."""
        payload = json.dumps(
            {"m": "HEAD", "u": "http://example.com/", "k": self.auth_key}
        ).encode()
        hdrs = {"content-type": "application/json"}
        sid = self._script_ids[0]

        # Test /dev endpoint — returns data inline (no 302 redirect).
        # If it works, saves ~400ms per request by eliminating one round trip.
        try:
            dev_path = f"/macros/s/{sid}/dev"
            t0 = time.perf_counter()
            status, _, body = await asyncio.wait_for(
                self._h2.request(
                    method="POST", path=dev_path, host=self.http_host,
                    headers=hdrs, body=payload,
                ),
                timeout=15,
            )
            dt = (time.perf_counter() - t0) * 1000
            data = json.loads(body.decode(errors="replace"))
            if "s" in data:
                self._dev_available = True
                log.info("/dev fast path active (%.0fms, no redirect)", dt)
                return
        except Exception as e:
            log.debug("/dev test failed: %s", e)

        # Fallback: warm up with /exec
        try:
            exec_path = f"/macros/s/{sid}/exec"
            t0 = time.perf_counter()
            await asyncio.wait_for(
                self._h2.request(
                    method="POST", path=exec_path, host=self.http_host,
                    headers=hdrs, body=payload,
                ),
                timeout=15,
            )
            dt = (time.perf_counter() - t0) * 1000
            log.info("Apps Script pre-warmed in %.0fms", dt)
        except Exception as e:
            log.debug("Pre-warm failed: %s", e)

    async def _keepalive_loop(self):
        """Send periodic pings to keep Apps Script warm + H2 connection alive."""
        while True:
            try:
                await asyncio.sleep(240)  # 4 minutes — saves ~90 quota hits/day vs 180s
                                          # Google's container timeout is ~5 min idle
                if not self._h2 or not self._h2.is_connected:
                    try:
                        await self._h2.reconnect()
                    except Exception:
                        continue

                # H2 PING to keep connection alive
                await self._h2.ping()

                # Apps Script keepalive — warm the container
                payload = {"m": "HEAD", "u": "http://example.com/", "k": self.auth_key}
                path = self._exec_path()
                t0 = time.perf_counter()
                await asyncio.wait_for(
                    self._h2.request(
                        method="POST", path=path, host=self.http_host,
                        headers={"content-type": "application/json"},
                        body=json.dumps(payload).encode(),
                    ),
                    timeout=20,
                )
                dt = (time.perf_counter() - t0) * 1000
                log.debug("Keepalive ping: %.0fms", dt)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("Keepalive failed: %s", e)

    async def _do_warm(self):
        """Open connections in parallel — failures are fine."""
        count = 30
        coros = [self._add_conn_to_pool() for _ in range(count)]
        results = await asyncio.gather(*coros, return_exceptions=True)
        opened = sum(1 for r in results if not isinstance(r, Exception))
        log.info("Pre-warmed %d/%d TLS connections", opened, count)

    def _auth_header(self) -> str:
        return f"X-Auth-Key: {self.auth_key}\r\n" if self.auth_key else ""

    # ── WebSocket tunnel (CONNECT / HTTPS) ────────────────────────

    async def tunnel(self, target_host: str, target_port: int,
                     client_r: asyncio.StreamReader,
                     client_w: asyncio.StreamWriter):
        """Tunnel raw TCP bytes through a domain-fronted WebSocket."""
        try:
            remote_r, remote_w = await self._open()
        except Exception as e:
            log.error("TLS connect to %s failed: %s", self.connect_host, e)
            return

        try:
            # ---- WebSocket upgrade ----
            ws_key = base64.b64encode(os.urandom(16)).decode()
            path = f"{self.worker_path}/tunnel?host={target_host}&port={target_port}"
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {self.http_host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"{self._auth_header()}"
                f"\r\n"
            )
            remote_w.write(handshake.encode())
            await remote_w.drain()

            # Read the 101 Switching Protocols response
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = await asyncio.wait_for(remote_r.read(4096), timeout=15)
                if not chunk:
                    raise ConnectionError("No WebSocket handshake response")
                resp += chunk

            status_line = resp.split(b"\r\n")[0]
            if b"101" not in status_line:
                raise ConnectionError(
                    f"WebSocket upgrade rejected: {status_line.decode(errors='replace')}"
                )

            log.info("Tunnel ready → %s:%d", target_host, target_port)

            # ---- bidirectional relay ----
            await asyncio.gather(
                self._client_to_ws(client_r, remote_w),
                self._ws_to_client(remote_r, client_w),
            )

        except Exception as e:
            log.error("Tunnel error (%s:%d): %s", target_host, target_port, e)
        finally:
            try:
                remote_w.close()
            except Exception:
                pass

    async def _client_to_ws(self, src: asyncio.StreamReader,
                            dst: asyncio.StreamWriter):
        """Read plaintext from the browser, wrap in WS frames, send to CDN."""
        try:
            while True:
                data = await src.read(16384)
                if not data:
                    # Send a WS close frame
                    dst.write(ws_encode(b"", opcode=0x08))
                    await dst.drain()
                    break
                dst.write(ws_encode(data))
                await dst.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass

    async def _ws_to_client(self, src: asyncio.StreamReader,
                            dst: asyncio.StreamWriter):
        """Read WS frames from CDN, unwrap, write plaintext to browser."""
        buf = b""
        try:
            while True:
                chunk = await src.read(16384)
                if not chunk:
                    break
                buf += chunk
                while buf:
                    result = ws_decode(buf)
                    if result is None:
                        break  # need more data
                    opcode, payload, consumed = result
                    buf = buf[consumed:]
                    if opcode == 0x08:  # close
                        return
                    if payload:
                        dst.write(payload)
                        await dst.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass

    # ── HTTP forwarding ───────────────────────────────────────────

    async def forward(self, raw_request: bytes) -> bytes:
        """Forward a plain HTTP request through the domain-fronted channel.

        Uses keep-alive connections from the pool for efficiency.
        """
        try:
            reader, writer, created = await self._acquire()

            # Wrap the original HTTP request inside a POST to the worker.
            request = (
                f"POST {self.worker_path}/forward HTTP/1.1\r\n"
                f"Host: {self.http_host}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(raw_request)}\r\n"
                f"Connection: keep-alive\r\n"
                f"{self._auth_header()}"
                f"\r\n"
            )
            writer.write(request.encode() + raw_request)
            await writer.drain()

            status, resp_headers, resp_body = await self._read_http_response(reader)

            await self._release(reader, writer, created)

            # The worker wraps the target's response in its own HTTP
            # envelope.  The body IS the raw HTTP response from the target.
            return resp_body

        except Exception as e:
            log.error("Forward failed: %s", e)
            return b"HTTP/1.1 502 Bad Gateway\r\n\r\nDomain fronting request failed\r\n"

    # ── Apps Script relay (apps_script mode) ──────────────────────

    async def relay(self, method: str, url: str,
                    headers: dict, body: bytes = b"") -> bytes:
        """Relay an HTTP request through Apps Script.

        Features:
          - Pre-warms TLS connections on first call
          - Coalesces concurrent identical GET requests
          - Batches concurrent calls via fetchAll() (40ms window)
          - Retries once on connection failure
          - Concurrency-limited via semaphore

        Returns a raw HTTP response (status + headers + body).
        """
        if not self._warmed:
            await self._warm_pool()

        payload = self._build_payload(method, url, headers, body)

        # Coalesce concurrent GETs for the same URL.
        # CRITICAL: do NOT coalesce when a Range header is present —
        # parallel range downloads MUST each hit the server independently.
        has_range = False
        if headers:
            for k in headers:
                if k.lower() == "range":
                    has_range = True
                    break
        if method == "GET" and not body and not has_range:
            return await self._coalesced_submit(url, payload)

        return await self._batch_submit(payload)

    async def _coalesced_submit(self, url: str, payload: dict) -> bytes:
        """Dedup concurrent requests for the same URL (no Range header)."""
        if url in self._coalesce:
            # Another task is already fetching this URL — wait for it
            future = asyncio.get_event_loop().create_future()
            self._coalesce[url].append(future)
            log.debug("Coalesced request: %s", url[:60])
            return await future

        self._coalesce[url] = []
        try:
            result = await self._batch_submit(payload)
            # Resolve all waiters
            for f in self._coalesce.get(url, []):
                if not f.done():
                    f.set_result(result)
            return result
        except Exception as e:
            for f in self._coalesce.get(url, []):
                if not f.done():
                    f.set_exception(e)
            raise
        finally:
            self._coalesce.pop(url, None)

    async def relay_parallel(self, method: str, url: str,
                             headers: dict, body: bytes = b"",
                             chunk_size: int = 256 * 1024,
                             max_parallel: int = 16) -> bytes:
        """Relay with parallel range acceleration for large downloads.

        Strategy:
          1. Send initial GET with Range: bytes=0-<chunk_size-1>
          2. If target returns 206 (supports ranges), fetch remaining
             chunks concurrently via HTTP/2 multiplexing.
          3. If target returns 200 (no range support) or small file,
             return the single response.

        Since each Apps Script call takes ~2s regardless of payload size,
        we use:
          - 256 KB chunks (safe under Apps Script response limit)
          - Up to 16 chunks in flight at once via H2 multiplexing
          - Aggregate throughput of ~2 MB per round-trip (~2-3s)
        """
        if method != "GET" or body:
            return await self.relay(method, url, headers, body)

        # Probe: first chunk with Range header
        range_headers = dict(headers) if headers else {}
        range_headers["Range"] = f"bytes=0-{chunk_size - 1}"
        first_resp = await self.relay("GET", url, range_headers, b"")

        status, resp_hdrs, resp_body = self._split_raw_response(first_resp)

        # No range support → return the single response as-is (status 200
        # from the origin). The client sent a plain GET, so 200 is what it
        # expects.
        if status != 206:
            return first_resp

        # Parse total size from Content-Range: "bytes 0-262143/1048576"
        content_range = resp_hdrs.get("content-range", "")
        m = re.search(r"/(\d+)", content_range)
        if not m:
            # Can't parse — downgrade to 200 so the client (which sent a
            # plain GET) doesn't get confused by 206 + Content-Range.
            return self._rewrite_206_to_200(first_resp)
        total_size = int(m.group(1))

        # Small file: probe already fetched it all. MUST rewrite to 200
        # because the client never sent a Range header — a stray 206 here
        # breaks fetch()/XHR on sites like x.com and Cloudflare challenges.
        if total_size <= chunk_size or len(resp_body) >= total_size:
            return self._rewrite_206_to_200(first_resp)

        # Calculate remaining ranges
        ranges = []
        start = len(resp_body)
        while start < total_size:
            end = min(start + chunk_size - 1, total_size - 1)
            ranges.append((start, end))
            start = end + 1

        log.info("Parallel download: %d bytes, %d chunks of %d KB",
                 total_size, len(ranges) + 1, chunk_size // 1024)

        # Concurrency-limited parallel fetch
        sem = asyncio.Semaphore(max_parallel)

        async def fetch_range(s, e, max_tries: int = 3):
            async with sem:
                rh_base = dict(headers) if headers else {}
                rh_base["Range"] = f"bytes={s}-{e}"
                expected = e - s + 1
                last_err = None
                for attempt in range(max_tries):
                    try:
                        raw = await self.relay("GET", url, rh_base, b"")
                        _, _, chunk_body = self._split_raw_response(raw)
                        if len(chunk_body) == expected:
                            return chunk_body
                        last_err = (
                            f"short chunk {len(chunk_body)}/{expected} B"
                        )
                    except Exception as e_:
                        last_err = repr(e_)
                    log.warning("Range %d-%d retry %d/%d: %s",
                                s, e, attempt + 1, max_tries, last_err)
                    await asyncio.sleep(0.3 * (attempt + 1))
                raise RuntimeError(
                    f"chunk {s}-{e} failed after {max_tries} tries: {last_err}"
                )

        t0 = asyncio.get_event_loop().time()
        results = await asyncio.gather(
            *[fetch_range(s, e) for s, e in ranges],
            return_exceptions=True,
        )
        elapsed = asyncio.get_event_loop().time() - t0

        # Assemble full body
        parts = [resp_body]
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                log.error("Range chunk %d failed: %s", i, r)
                return self._error_response(502, f"Parallel download failed: {r}")
            parts.append(r)

        full_body = b"".join(parts)
        kbs = (len(full_body) / 1024) / elapsed if elapsed > 0 else 0
        log.info("Parallel download complete: %d B in %.2fs = %.1f KB/s",
                 len(full_body), elapsed, kbs)

        # Return as 200 OK (client sent a normal GET)
        result = f"HTTP/1.1 200 OK\r\n"
        skip = {"transfer-encoding", "connection", "keep-alive",
                "content-length", "content-encoding", "content-range"}
        for k, v in resp_hdrs.items():
            if k.lower() not in skip:
                result += f"{k}: {v}\r\n"
        result += f"Content-Length: {len(full_body)}\r\n"
        result += "\r\n"
        return result.encode() + full_body

    @staticmethod
    def _rewrite_206_to_200(raw: bytes) -> bytes:
        """Rewrite a 206 Partial Content response to 200 OK.

        Used when we probed with a synthetic Range header but the client
        never asked for one. Handing a 206 back to the browser for a plain
        GET breaks XHR/fetch on sites like x.com and Cloudflare challenges
        (they see it as an aborted/partial response). We drop the
        Content-Range header and set Content-Length to the body size.
        """
        sep = b"\r\n\r\n"
        if sep not in raw:
            return raw
        header_section, body = raw.split(sep, 1)
        lines = header_section.decode(errors="replace").split("\r\n")
        if not lines:
            return raw
        # Replace status line
        first = lines[0]
        if " 206" in first:
            lines[0] = first.replace(" 206 Partial Content", " 200 OK")\
                             .replace(" 206", " 200 OK")
        # Drop Content-Range and recalculate Content-Length
        filtered = [lines[0]]
        for ln in lines[1:]:
            low = ln.lower()
            if low.startswith("content-range:"):
                continue
            if low.startswith("content-length:"):
                continue
            filtered.append(ln)
        filtered.append(f"Content-Length: {len(body)}")
        return ("\r\n".join(filtered) + "\r\n\r\n").encode() + body

    def _build_payload(self, method, url, headers, body):
        """Build the JSON relay payload dict."""
        payload = {
            "m": method,
            "u": url,
            "r": True,
        }
        if headers:
            # Strip Accept-Encoding: Apps Script auto-decompresses gzip
            # but NOT brotli/zstd — forwarding "br" causes garbled responses.
            filt = {k: v for k, v in headers.items()
                    if k.lower() != "accept-encoding"}
            payload["h"] = filt if filt else headers
        if body:
            payload["b"] = base64.b64encode(body).decode()
            ct = headers.get("Content-Type") or headers.get("content-type")
            if ct:
                payload["ct"] = ct
        return payload

    # ── Batch collector ───────────────────────────────────────────

    async def _batch_submit(self, payload: dict) -> bytes:
        """Submit a request to the batch collector. Returns raw HTTP response."""
        # If batching is disabled (old Code.gs), go direct
        if not self._batch_enabled:
            return await self._relay_with_retry(payload)

        future = asyncio.get_event_loop().create_future()

        async with self._batch_lock:
            self._batch_pending.append((payload, future))

            if len(self._batch_pending) >= self._batch_max:
                # Batch is full — flush now
                batch = self._batch_pending[:]
                self._batch_pending.clear()
                if self._batch_task and not self._batch_task.done():
                    self._batch_task.cancel()
                self._batch_task = None
                asyncio.create_task(self._batch_send(batch))
            elif self._batch_task is None or self._batch_task.done():
                # First request in a new batch window — start timer
                self._batch_task = asyncio.create_task(self._batch_timer())

        return await future

    async def _batch_timer(self):
        """Two-tier batch window: 5ms micro + 45ms macro.

        Single requests (link clicks) get only 5ms delay.
        Burst traffic (page sub-resources, range chunks) gets a 50ms
        window to accumulate, enabling much larger batches.
        """
        # Tier 1: micro-window — detect if burst or single
        await asyncio.sleep(self._batch_window_micro)
        async with self._batch_lock:
            if len(self._batch_pending) <= 1:
                # Single request — send immediately (only 5ms delay)
                if self._batch_pending:
                    batch = self._batch_pending[:]
                    self._batch_pending.clear()
                    self._batch_task = None
                    asyncio.create_task(self._batch_send(batch))
                return

        # Tier 2: burst detected — wait more to accumulate
        await asyncio.sleep(self._batch_window_macro - self._batch_window_micro)
        async with self._batch_lock:
            if self._batch_pending:
                batch = self._batch_pending[:]
                self._batch_pending.clear()
                self._batch_task = None
                asyncio.create_task(self._batch_send(batch))

    async def _batch_send(self, batch: list):
        """Send a batch of requests. Uses fetchAll for multi, single for one."""
        if len(batch) == 1:
            payload, future = batch[0]
            try:
                result = await self._relay_with_retry(payload)
                if not future.done():
                    future.set_result(result)
            except Exception as e:
                if not future.done():
                    future.set_result(self._error_response(502, str(e)))
        else:
            log.info("Batch relay: %d requests", len(batch))
            try:
                results = await self._relay_batch([p for p, _ in batch])
                for (_, future), result in zip(batch, results):
                    if not future.done():
                        future.set_result(result)
            except Exception as e:
                log.warning("Batch relay failed, disabling batch mode. "
                            "Redeploy Code.gs for batch support. Error: %s", e)
                self._batch_enabled = False
                # Fallback: send individually
                tasks = []
                for payload, future in batch:
                    tasks.append(self._relay_fallback(payload, future))
                await asyncio.gather(*tasks)

    async def _relay_fallback(self, payload, future):
        """Fallback: relay a single request from a failed batch."""
        try:
            result = await self._relay_with_retry(payload)
            if not future.done():
                future.set_result(result)
        except Exception as e:
            if not future.done():
                future.set_result(self._error_response(502, str(e)))

    # ── Core relay with retry ─────────────────────────────────────

    async def _relay_with_retry(self, payload: dict) -> bytes:
        """Single relay with one retry on failure. Uses H2 if available."""
        # Try HTTP/2 first — much faster (multiplexed, no pool checkout)
        if self._h2 and self._h2.is_connected:
            for attempt in range(2):
                try:
                    return await asyncio.wait_for(
                        self._relay_single_h2(payload), timeout=25
                    )
                except Exception as e:
                    if attempt == 0:
                        log.debug("H2 relay failed (%s), reconnecting", e)
                        try:
                            await self._h2.reconnect()
                        except Exception:
                            log.warning("H2 reconnect failed, falling back to H1")
                            break
                    else:
                        raise

        # HTTP/1.1 fallback (pool-based)
        async with self._semaphore:
            for attempt in range(2):
                try:
                    return await asyncio.wait_for(
                        self._relay_single(payload), timeout=25
                    )
                except Exception as e:
                    if attempt == 0:
                        log.debug("Relay attempt 1 failed (%s: %s), retrying",
                                  type(e).__name__, e)
                        await self._flush_pool()
                    else:
                        raise

    async def _relay_single_h2(self, payload: dict) -> bytes:
        """Execute a relay through HTTP/2 multiplexing.

        Uses the shared H2 connection — no pool checkout needed.
        Many concurrent calls all share one TLS connection.
        """
        full_payload = dict(payload)
        full_payload["k"] = self.auth_key
        json_body = json.dumps(full_payload).encode()

        path = self._exec_path()

        status, headers, body = await self._h2.request(
            method="POST", path=path, host=self.http_host,
            headers={"content-type": "application/json"},
            body=json_body,
        )

        return self._parse_relay_response(body)

    async def _relay_single(self, payload: dict) -> bytes:
        """Execute a single relay POST → redirect → parse."""
        # Add auth key
        full_payload = dict(payload)
        full_payload["k"] = self.auth_key
        json_body = json.dumps(full_payload).encode()

        path = self._exec_path()
        reader, writer, created = await self._acquire()

        try:
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {self.http_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(json_body)}\r\n"
                f"Accept-Encoding: gzip\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            writer.write(request.encode() + json_body)
            await writer.drain()

            status, resp_headers, resp_body = await self._read_http_response(reader)

            # Follow redirect chain on the SAME connection
            for _ in range(5):
                if status not in (301, 302, 303, 307, 308):
                    break
                location = resp_headers.get("location")
                if not location:
                    break

                parsed = urlparse(location)
                rpath = parsed.path + ("?" + parsed.query if parsed.query else "")
                request = (
                    f"GET {rpath} HTTP/1.1\r\n"
                    f"Host: {parsed.netloc}\r\n"
                    f"Accept-Encoding: gzip\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(request.encode())
                await writer.drain()
                status, resp_headers, resp_body = await self._read_http_response(reader)

            await self._release(reader, writer, created)
            return self._parse_relay_response(resp_body)

        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            raise

    async def _relay_batch(self, payloads: list[dict]) -> list[bytes]:
        """Send multiple requests in one POST using Apps Script fetchAll."""
        batch_payload = {
            "k": self.auth_key,
            "q": payloads,
        }
        json_body = json.dumps(batch_payload).encode()
        path = self._exec_path()

        # Try HTTP/2 first
        if self._h2 and self._h2.is_connected:
            try:
                status, headers, body = await asyncio.wait_for(
                    self._h2.request(
                        method="POST", path=path, host=self.http_host,
                        headers={"content-type": "application/json"},
                        body=json_body,
                    ),
                    timeout=30,
                )
                return self._parse_batch_body(body, payloads)
            except Exception as e:
                log.debug("H2 batch failed (%s), falling back to H1", e)

        # HTTP/1.1 fallback
        async with self._semaphore:
            reader, writer, created = await self._acquire()
            try:
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {self.http_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(json_body)}\r\n"
                    f"Accept-Encoding: gzip\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(request.encode() + json_body)
                await writer.drain()

                status, resp_headers, resp_body = await self._read_http_response(reader)

                # Follow redirects
                for _ in range(5):
                    if status not in (301, 302, 303, 307, 308):
                        break
                    location = resp_headers.get("location")
                    if not location:
                        break
                    parsed = urlparse(location)
                    rpath = parsed.path + ("?" + parsed.query if parsed.query else "")
                    request = (
                        f"GET {rpath} HTTP/1.1\r\n"
                        f"Host: {parsed.netloc}\r\n"
                        f"Accept-Encoding: gzip\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    writer.write(request.encode())
                    await writer.drain()
                    status, resp_headers, resp_body = await self._read_http_response(reader)

                await self._release(reader, writer, created)

            except Exception:
                try:
                    writer.close()
                except Exception:
                    pass
                raise

        return self._parse_batch_body(resp_body, payloads)

    def _parse_batch_body(self, resp_body: bytes,
                          payloads: list[dict]) -> list[bytes]:
        """Parse a batch response body into individual results."""
        text = resp_body.decode(errors="replace").strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r'\{.*\}', text, re.DOTALL)
            data = json.loads(m.group()) if m else None
        if not data:
            raise RuntimeError(f"Bad batch response: {text[:200]}")

        if "e" in data:
            raise RuntimeError(f"Batch error: {data['e']}")

        items = data.get("q", [])
        if len(items) != len(payloads):
            raise RuntimeError(
                f"Batch size mismatch: {len(items)} vs {len(payloads)}"
            )

        results = []
        for item in items:
            results.append(self._parse_relay_json(item))
        return results

    # ── HTTP response reading (keep-alive safe) ──────────────────

    async def _read_http_response(self, reader: asyncio.StreamReader):
        """Read one HTTP response. Keep-alive safe (no read-until-EOF)."""
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=8)
            if not chunk:
                break
            raw += chunk

        if b"\r\n\r\n" not in raw:
            return 0, {}, b""

        header_section, body = raw.split(b"\r\n\r\n", 1)
        lines = header_section.split(b"\r\n")

        status_line = lines[0].decode(errors="replace")
        m = re.search(r"\d{3}", status_line)
        status = int(m.group()) if m else 0

        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.decode(errors="replace").split(":", 1)
                headers[k.strip().lower()] = v.strip()

        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding", "")

        if "chunked" in transfer_encoding:
            body = await self._read_chunked(reader, body)
        elif content_length:
            remaining = int(content_length) - len(body)
            while remaining > 0:
                chunk = await asyncio.wait_for(
                    reader.read(min(remaining, 65536)), timeout=20
                )
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
        else:
            # No framing — short timeout read (keep-alive safe)
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=2)
                    if not chunk:
                        break
                    body += chunk
                except asyncio.TimeoutError:
                    break

        # Auto-decompress gzip from Google frontend
        if headers.get("content-encoding", "").lower() == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception:
                pass  # not actually gzip, use as-is

        return status, headers, body

    async def _read_chunked(self, reader, buf=b""):
        """Incrementally read chunked transfer-encoding."""
        result = b""
        while True:
            while b"\r\n" not in buf:
                data = await asyncio.wait_for(reader.read(8192), timeout=20)
                if not data:
                    return result
                buf += data

            end = buf.find(b"\r\n")
            size_str = buf[:end].decode(errors="replace").strip()
            buf = buf[end + 2:]

            if not size_str:
                continue
            try:
                size = int(size_str, 16)
            except ValueError:
                break
            if size == 0:
                break

            while len(buf) < size + 2:
                data = await asyncio.wait_for(reader.read(65536), timeout=20)
                if not data:
                    result += buf[:size]
                    return result
                buf += data

            result += buf[:size]
            buf = buf[size + 2:]

        return result

    # ── Response parsing ──────────────────────────────────────────

    def _parse_relay_response(self, body: bytes) -> bytes:
        """Parse JSON from Apps Script and reconstruct an HTTP response."""
        text = body.decode(errors="replace").strip()
        if not text:
            return self._error_response(502, "Empty response from relay")

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group())
                except json.JSONDecodeError:
                    return self._error_response(502, f"Bad JSON: {text[:200]}")
            else:
                return self._error_response(502, f"No JSON: {text[:200]}")

        return self._parse_relay_json(data)

    def _parse_relay_json(self, data: dict) -> bytes:
        """Convert a parsed relay JSON dict to raw HTTP response bytes."""
        if "e" in data:
            return self._error_response(502, f"Relay error: {data['e']}")

        status = data.get("s", 200)
        resp_headers = data.get("h", {})
        resp_body = base64.b64decode(data.get("b", ""))

        status_text = {200: "OK", 206: "Partial Content",
                       301: "Moved", 302: "Found", 304: "Not Modified",
                       400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                       500: "Internal Server Error"}.get(status, "OK")
        result = f"HTTP/1.1 {status} {status_text}\r\n"

        skip = {"transfer-encoding", "connection", "keep-alive",
                "content-length", "content-encoding"}
        for k, v in resp_headers.items():
            if k.lower() in skip:
                continue
            # Apps Script returns multi-valued headers (e.g. Set-Cookie) as a
            # JavaScript array. Emit each value as its own header line.
            # A single string that holds multiple Set-Cookie values joined
            # with ", " also needs to be split, otherwise the browser sees
            # one malformed cookie and sites like x.com fail.
            values = v if isinstance(v, list) else [v]
            if k.lower() == "set-cookie":
                expanded = []
                for item in values:
                    expanded.extend(self._split_set_cookie(str(item)))
                values = expanded
            for val in values:
                result += f"{k}: {val}\r\n"
        result += f"Content-Length: {len(resp_body)}\r\n"
        result += "\r\n"
        return result.encode() + resp_body

    @staticmethod
    def _split_set_cookie(blob: str) -> list[str]:
        """Split a Set-Cookie string that may contain multiple cookies.

        Apps Script sometimes joins multiple Set-Cookie values with ", ",
        which collides with the comma that legitimately appears inside the
        `Expires` attribute (e.g. "Expires=Wed, 21 Oct 2026 ..."). We split
        only on commas that are immediately followed by a cookie name=value
        pair (token '=' ...), leaving date commas intact.
        """
        if not blob:
            return []
        # Split on ", " but only when the following text looks like the start
        # of a new cookie (a token followed by '=').
        parts = re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)", blob)
        return [p.strip() for p in parts if p.strip()]

    def _split_raw_response(self, raw: bytes):
        """Split a raw HTTP response into (status, headers_dict, body)."""
        if b"\r\n\r\n" not in raw:
            return 0, {}, raw
        header_section, body = raw.split(b"\r\n\r\n", 1)
        lines = header_section.split(b"\r\n")
        m = re.search(r"\d{3}", lines[0].decode(errors="replace"))
        status = int(m.group()) if m else 0
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.decode(errors="replace").split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, body

    def _error_response(self, status: int, message: str) -> bytes:
        body = f"<html><body><h1>{status}</h1><p>{message}</p></body></html>"
        return (
            f"HTTP/1.1 {status} Error\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        ).encode()
