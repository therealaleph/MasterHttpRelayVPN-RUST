"""
HTTP/2 multiplexed transport for domain-fronted connections.

One TLS connection → many concurrent HTTP/2 streams → massive throughput.
Eliminates per-request TLS handshake overhead entirely.

Instead of a pool of 30 HTTP/1.1 connections (each handling 1 request),
this uses a SINGLE HTTP/2 connection handling 100+ concurrent requests.

Performance comparison:
  HTTP/1.1 pool: 30 connections × 1 request = 30 concurrent requests max
  HTTP/2 mux:    1 connection  × 100 streams = 100 concurrent requests

Requires: pip install h2
"""

import asyncio
import gzip
import logging
import socket
import ssl
from urllib.parse import urlparse

log = logging.getLogger("H2")

try:
    import h2.connection
    import h2.config
    import h2.events
    import h2.settings
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


class _StreamState:
    """State for a single in-flight HTTP/2 stream."""
    __slots__ = ("status", "headers", "data", "done", "error")

    def __init__(self):
        self.status = 0
        self.headers: dict[str, str] = {}
        self.data = bytearray()
        self.done = asyncio.Event()
        self.error: str | None = None


class H2Transport:
    """
    Persistent HTTP/2 connection with automatic stream multiplexing.

    All relay requests share ONE TLS connection. Each request becomes
    an independent HTTP/2 stream, running fully concurrently.

    Features:
      - Auto-connect on first use
      - Auto-reconnect on connection loss
      - Redirect following (as new streams, same connection)
      - Gzip decompression
      - Configurable max concurrency
    """

    def __init__(self, connect_host: str, sni_host: str,
                 verify_ssl: bool = True):
        self.connect_host = connect_host
        self.sni_host = sni_host
        self.verify_ssl = verify_ssl

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._h2: "h2.connection.H2Connection | None" = None
        self._connected = False

        self._write_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._read_task: asyncio.Task | None = None

        # Per-stream tracking
        self._streams: dict[int, _StreamState] = {}

        # Stats
        self.total_requests = 0
        self.total_streams = 0

    # ── Connection lifecycle ──────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def ensure_connected(self):
        """Connect if not already connected."""
        if self._connected:
            return
        async with self._connect_lock:
            if self._connected:
                return
            await self._do_connect()

    async def _do_connect(self):
        """Establish the HTTP/2 connection with optimized socket settings."""
        ctx = ssl.create_default_context()
        # Advertise both h2 and http/1.1 — some DPI blocks h2-only ALPN
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Create raw TCP socket with TCP_NODELAY BEFORE TLS handshake.
        # Nagle's algorithm can delay small writes (H2 frames) by up to 200ms
        # waiting to coalesce — TCP_NODELAY forces immediate send.
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        raw.setblocking(False)

        try:
            await asyncio.wait_for(
                asyncio.get_event_loop().sock_connect(
                    raw, (self.connect_host, 443)
                ),
                timeout=15,
            )
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ssl=ctx,
                    server_hostname=self.sni_host,
                    sock=raw,
                ),
                timeout=15,
            )
        except Exception:
            raw.close()
            raise

        # Verify we actually got HTTP/2
        ssl_obj = self._writer.get_extra_info("ssl_object")
        negotiated = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        if negotiated != "h2":
            self._writer.close()
            raise RuntimeError(
                f"H2 ALPN negotiation failed (got {negotiated!r})"
            )

        config = h2.config.H2Configuration(
            client_side=True,
            header_encoding="utf-8",
        )
        self._h2 = h2.connection.H2Connection(config=config)
        self._h2.initiate_connection()

        # Connection-level flow control: ~16MB window
        self._h2.increment_flow_control_window(2 ** 24 - 65535)

        # Per-stream settings: 1MB initial window, disable server push
        self._h2.update_settings({
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1 * 1024 * 1024,
            h2.settings.SettingCodes.ENABLE_PUSH: 0,
        })

        await self._flush()

        self._connected = True
        self._read_task = asyncio.create_task(self._reader_loop())
        log.info("H2 connected → %s (SNI=%s, TCP_NODELAY=on)",
                 self.connect_host, self.sni_host)

    async def reconnect(self):
        """Close current connection and re-establish."""
        await self._close_internal()
        await self._do_connect()

    async def _close_internal(self):
        self._connected = False
        if self._read_task:
            self._read_task.cancel()
            self._read_task = None
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None
        # Wake all pending streams so they can raise
        for state in self._streams.values():
            state.error = "Connection closed"
            state.done.set()
        self._streams.clear()

    # ── Public API ────────────────────────────────────────────────

    async def request(self, method: str, path: str, host: str,
                      headers: dict | None = None,
                      body: bytes | None = None,
                      timeout: float = 25,
                      follow_redirects: int = 5) -> tuple[int, dict, bytes]:
        """
        Send an HTTP/2 request and return (status, headers, body).

        Thread-safe: many concurrent calls each get their own stream.
        Redirects are followed as new streams on the same connection.
        """
        await self.ensure_connected()
        self.total_requests += 1

        for _ in range(follow_redirects + 1):
            status, resp_headers, resp_body = await self._single_request(
                method, path, host, headers, body, timeout,
            )

            if status not in (301, 302, 303, 307, 308):
                return status, resp_headers, resp_body

            location = resp_headers.get("location", "")
            if not location:
                return status, resp_headers, resp_body

            parsed = urlparse(location)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            host = parsed.netloc or host
            method = "GET"
            body = None
            headers = None  # Drop request headers on redirect

        return status, resp_headers, resp_body

    # ── Stream handling ───────────────────────────────────────────

    async def _single_request(self, method, path, host, headers, body,
                              timeout) -> tuple[int, dict, bytes]:
        """Send one HTTP/2 request on a new stream, wait for response."""
        if not self._connected:
            await self.ensure_connected()

        stream_id = None

        async with self._write_lock:
            try:
                stream_id = self._h2.get_next_available_stream_id()
            except Exception:
                # Connection is stale — reconnect
                await self.reconnect()
                stream_id = self._h2.get_next_available_stream_id()

            h2_headers = [
                (":method", method),
                (":path", path),
                (":authority", host),
                (":scheme", "https"),
                ("accept-encoding", "gzip"),
            ]
            if headers:
                for k, v in headers.items():
                    h2_headers.append((k.lower(), str(v)))

            end_stream = not body
            self._h2.send_headers(stream_id, h2_headers, end_stream=end_stream)

            if body:
                # Send body (may need chunking for flow control)
                self._send_body(stream_id, body)

            state = _StreamState()
            self._streams[stream_id] = state
            self.total_streams += 1

            await self._flush()

        # Wait for complete response
        try:
            await asyncio.wait_for(state.done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self._streams.pop(stream_id, None)
            raise TimeoutError(
                f"H2 stream {stream_id} timed out ({timeout}s)"
            )

        self._streams.pop(stream_id, None)

        if state.error:
            raise ConnectionError(f"H2 stream error: {state.error}")

        # Auto-decompress gzip
        resp_body = bytes(state.data)
        if state.headers.get("content-encoding", "").lower() == "gzip":
            try:
                resp_body = gzip.decompress(resp_body)
            except Exception:
                pass

        return state.status, state.headers, resp_body

    def _send_body(self, stream_id: int, body: bytes):
        """Send request body, respecting H2 flow control window."""
        # For small bodies (typical JSON payloads), send in one shot
        while body:
            max_size = self._h2.local_settings.max_frame_size
            window = self._h2.local_flow_control_window(stream_id)
            send_size = min(len(body), max_size, window)
            if send_size <= 0:
                # Flow control full — let the reader loop process
                # window updates before we continue
                break
            end = send_size >= len(body)
            self._h2.send_data(stream_id, body[:send_size], end_stream=end)
            body = body[send_size:]

    # ── Background reader ─────────────────────────────────────────

    async def _reader_loop(self):
        """Background: read H2 frames, dispatch events to waiting streams."""
        try:
            while self._connected:
                data = await self._reader.read(65536)
                if not data:
                    log.warning("H2 remote closed connection")
                    break

                try:
                    events = self._h2.receive_data(data)
                except Exception as e:
                    log.error("H2 protocol error: %s", e)
                    break

                for event in events:
                    self._dispatch(event)

                # Send pending data (acks, window updates, ping responses)
                async with self._write_lock:
                    await self._flush()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error("H2 reader error: %s", e)
        finally:
            self._connected = False
            for state in self._streams.values():
                if not state.done.is_set():
                    state.error = "Connection lost"
                    state.done.set()
            log.info("H2 reader loop ended")

    def _dispatch(self, event):
        """Route a single h2 event to its stream."""
        if isinstance(event, h2.events.ResponseReceived):
            state = self._streams.get(event.stream_id)
            if state:
                for name, value in event.headers:
                    n = name if isinstance(name, str) else name.decode()
                    v = value if isinstance(value, str) else value.decode()
                    if n == ":status":
                        state.status = int(v)
                    else:
                        state.headers[n] = v

        elif isinstance(event, h2.events.DataReceived):
            state = self._streams.get(event.stream_id)
            if state:
                state.data.extend(event.data)
            # Always acknowledge received data for flow control
            self._h2.acknowledge_received_data(
                event.flow_controlled_length, event.stream_id
            )

        elif isinstance(event, h2.events.StreamEnded):
            state = self._streams.get(event.stream_id)
            if state:
                state.done.set()

        elif isinstance(event, h2.events.StreamReset):
            state = self._streams.get(event.stream_id)
            if state:
                state.error = f"Stream reset (code={event.error_code})"
                state.done.set()

        elif isinstance(event, h2.events.WindowUpdated):
            pass  # h2 library handles window bookkeeping

        elif isinstance(event, h2.events.SettingsAcknowledged):
            pass

        elif isinstance(event, h2.events.PingReceived):
            pass  # h2 library auto-responds

        elif isinstance(event, h2.events.PingAckReceived):
            pass  # keepalive confirmed

    # ── Internal ──────────────────────────────────────────────────

    async def _flush(self):
        """Write pending H2 frame data to the socket."""
        data = self._h2.data_to_send()
        if data and self._writer:
            self._writer.write(data)
            await self._writer.drain()

    async def close(self):
        """Gracefully close the HTTP/2 connection."""
        if self._h2 and self._connected:
            try:
                self._h2.close_connection()
                async with self._write_lock:
                    await self._flush()
            except Exception:
                pass
        await self._close_internal()

    async def ping(self):
        """Send an H2 PING frame to keep the connection alive."""
        if not self._connected or not self._h2:
            return
        try:
            async with self._write_lock:
                if not self._connected:
                    return
                self._h2.ping(b"\x00" * 8)
                await self._flush()
        except Exception as e:
            log.debug("H2 PING failed: %s", e)
