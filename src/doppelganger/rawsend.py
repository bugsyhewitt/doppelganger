"""Byte-exact HTTP/1.1 raw-socket probe transport.

This module owns doppelganger's *mandatory* raw-request transport (criterion 5
of V0.1-CRITERIA.md). It exists because a desync probe must be delivered on the
wire **byte-for-byte** with attacker-controlled Content-Length / Transfer-Encoding
framing and **no header normalisation**. A normalising high-level client
(``httpx`` and friends) validates and rewrites headers on send and therefore
*cannot carry the probe* -- it would "fix" the very discrepancy under test. So
smuggling probes go through this dedicated stdlib-``socket`` sender, while the
well-formed baseline/differential requests go through :mod:`doppelganger.client`.

Why this is deliberately separate from ``client``:
  * ``rawsend``  -- byte-exact, no normalisation, for the *probe* path.
  * ``client``   -- scan-primitives-backed, normalised/well-formed, for the
    *baseline & differential* path.

Scope enforcement:
  Every connection is scope-checked with the **same** ``scan-primitives``
  :class:`~scan_primitives.Scope` object the baseline client uses. The check
  runs BEFORE ``socket.create_connection`` -- an out-of-scope host raises
  :class:`~scan_primitives.OutOfScopeError` and no socket is ever opened. A raw
  probe is still an out-of-scope request, so scope-checking the raw path (not
  just the high-level client) is a v0.1 safety requirement. If no scope is
  configured the sender is **fail-closed**: it refuses all egress.

Safe-testing defaults (criterion 4):
  * per-probe connection isolation -- :meth:`RawSender.send` opens one socket,
    sends, reads, and closes it, so a poisoned socket is never left in a shared
    pool. Connection *reuse* (needed for pipelining discrimination) is explicit
    via :meth:`RawSender.connect` / :class:`RawConnection`.
  * bounded + optionally randomised (jittered) timeouts.

**R5 (untrusted input):** bytes returned by the target are DATA, never
instructions. This module reads them into a buffer and returns them verbatim; it
never evaluates them, passes them to a shell, or hands them to an LLM tool call.
The engine parses response bytes only to compute a response signature / timing.
"""

from __future__ import annotations

import random
import socket
import ssl
import time
from dataclasses import dataclass

from scan_primitives import OutOfScopeError, Scope

__all__ = ["RawResponse", "RawConnection", "RawSender"]


@dataclass(slots=True)
class RawResponse:
    """The exact bytes read back from a raw probe, plus timing and why we stopped.

    Attributes:
        raw: The verbatim response bytes (untrusted data -- never executed).
        elapsed_s: Wall time from just before send to read completion.
        timed_out: ``True`` if the read hit the deadline before a complete
            response arrived -- i.e. the server hung waiting for bytes that never
            came. This is the core HTTP/1.1 desync *timing* signal.
        eof: ``True`` if the peer closed the connection.
    """

    raw: bytes
    elapsed_s: float
    timed_out: bool = False
    eof: bool = False

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_s * 1000.0

    @property
    def head(self) -> bytes:
        """The response head (up to and excluding the CRLFCRLF), or all bytes."""
        idx = self.raw.find(b"\r\n\r\n")
        return self.raw[:idx] if idx >= 0 else self.raw

    @property
    def status_line(self) -> bytes:
        return self.raw.split(b"\r\n", 1)[0]


def _parse_framing(head: bytes) -> tuple[int | None, bool, bool]:
    """Return ``(content_length, is_chunked, connection_close)`` from a head block.

    Parses response framing only -- this is how we know when a *response* is
    complete. It does not, and must not, rewrite anything on the request path.
    """
    content_length: int | None = None
    chunked = False
    conn_close = False
    for line in head.split(b"\r\n")[1:]:  # skip the status line
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        key = name.strip().lower()
        val = value.strip().lower()
        if key == b"content-length":
            try:
                content_length = int(val)
            except ValueError:
                pass
        elif key == b"transfer-encoding":
            if b"chunked" in val:
                chunked = True
        elif key == b"connection":
            if b"close" in val:
                conn_close = True
    return content_length, chunked, conn_close


def _status_code(head: bytes) -> int:
    """Extract the HTTP status integer from a response head block (0 on parse error)."""
    status_line = head.split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0


def _read_response(sock: socket.socket, deadline: float) -> tuple[bytes, bool, bool]:
    """Read one HTTP/1.1 response with a hard deadline, skipping 1xx interim responses.

    Stops when a complete final (2xx-5xx) response has arrived (headers + body
    per Content-Length or chunked framing), when the peer sends EOF, or when
    ``deadline`` passes (``timed_out``). Returns ``(raw_bytes, timed_out, eof)``
    where ``raw_bytes`` is the final response only (1xx bodies, if any, are
    consumed but not returned).

    1xx interim responses (e.g. ``100 Continue``) have no body per RFC 7230 §3.3
    and are silently consumed so callers receive only the final response.  This
    is required for the ``Expect: 100-continue`` desync probe (v0.6): a
    vulnerable front-end sends ``100 Continue`` before the back-end hangs, and
    the timing signal must come from the hang, not the interim response.
    """
    buf = bytearray()
    timed_out = False
    eof = False
    # response_start tracks where the *current* (potentially final) response
    # begins within buf.  When we consume a 1xx interim response it advances.
    response_start = 0
    header_end = -1  # absolute offset of the \r\n\r\n separator within buf
    body_start = 0
    content_length: int | None = None
    chunked = False
    conn_close = False

    while True:
        # --- process what is already in buf before blocking on recv ----------
        if header_end < 0:
            idx = buf.find(b"\r\n\r\n", response_start)
            if idx >= 0:
                head = bytes(buf[response_start:idx])
                status = _status_code(head)
                if 100 <= status <= 199:
                    # 1xx responses carry no body (RFC 7230 §3.3).  Discard the
                    # interim response and advance past it; the next iteration
                    # will scan from the new response_start WITHOUT blocking on
                    # recv again (the final response may already be in buf).
                    response_start = idx + 4
                    continue  # re-check buf from the new response_start
                # Found the final response header.
                header_end = idx
                body_start = idx + 4
                content_length, chunked, conn_close = _parse_framing(head)

        if header_end >= 0:
            if content_length is not None:
                if len(buf) - body_start >= content_length:
                    break
            elif chunked:
                body = buf[body_start:]
                if body.endswith(b"0\r\n\r\n") or b"\r\n0\r\n\r\n" in body:
                    break
            elif not conn_close:
                # No body framing and keep-alive: the response ends at the head
                # (e.g. 204/304 or an empty body). Reading further would block.
                break
            # else: Connection: close with no length -> read until EOF.

        # --- need more data: block on recv with remaining deadline -----------
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            timed_out = True
            break
        except (ConnectionResetError, OSError):
            eof = True
            break
        if not chunk:
            eof = True
            break
        buf += chunk

    return bytes(buf[response_start:]), timed_out, eof


class RawConnection:
    """A single open socket to a target, for byte-exact send/read.

    Obtained from :meth:`RawSender.connect`. Used directly for **connection
    reuse** (the pipelining-discrimination experiment sends two probes down one
    connection). For the default isolated probe use :meth:`RawSender.send`.
    """

    __slots__ = ("_sock", "host", "port", "closed")

    def __init__(self, sock: socket.socket, host: str, port: int) -> None:
        self._sock = sock
        self.host = host
        self.port = port
        self.closed = False

    def send_raw(self, raw: bytes) -> None:
        """Write ``raw`` to the socket byte-exact -- no header rewriting."""
        self._sock.sendall(raw)

    def read_response(self, timeout: float) -> RawResponse:
        """Read one response with a bounded ``timeout`` (seconds)."""
        start = time.monotonic()
        raw, timed_out, eof = _read_response(self._sock, start + timeout)
        return RawResponse(raw, time.monotonic() - start, timed_out, eof)

    def probe(self, raw: bytes, timeout: float) -> RawResponse:
        """Send ``raw`` then read the response, timing the whole exchange."""
        start = time.monotonic()
        self._sock.sendall(raw)
        raw_resp, timed_out, eof = _read_response(self._sock, start + timeout)
        return RawResponse(raw_resp, time.monotonic() - start, timed_out, eof)

    def close(self) -> None:
        if not self.closed:
            try:
                self._sock.close()
            finally:
                self.closed = True

    def __enter__(self) -> RawConnection:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class RawSender:
    """Dedicated byte-exact HTTP/1.1 raw-socket sender.

    Opens a plain (or TLS) socket to the target, writes the probe verbatim with
    no header rewriting, and reads the response with a bounded/randomised
    timeout. One isolated connection per probe unless the caller explicitly
    reuses a :class:`RawConnection`.

    The sender honours the shared :class:`~scan_primitives.Scope`: every
    connection is scope-checked before the socket is opened, and a sender with no
    scope refuses all egress (fail-closed).
    """

    def __init__(
        self,
        scope: Scope | None = None,
        *,
        timeout: float = 10.0,
        jitter: float = 0.0,
        rng: random.Random | None = None,
    ) -> None:
        self._scope = scope
        self._timeout = timeout
        # ``jitter`` (seconds) randomises the read timeout so probes are not
        # perfectly periodic -- a safe-testing default (criterion 4).
        self._jitter = max(0.0, jitter)
        self._rng = rng or random.Random()

    @property
    def scope(self) -> Scope | None:
        return self._scope

    def _check_scope(self, host: str) -> None:
        """Fail-closed scope check -- runs BEFORE any socket is opened."""
        if self._scope is None:
            raise OutOfScopeError(
                "raw sender has no scope configured; refusing egress (fail-closed)"
            )
        self._scope.assert_in_scope(host)

    def _effective_timeout(self, timeout: float | None) -> float:
        base = self._timeout if timeout is None else timeout
        if self._jitter:
            base += self._rng.uniform(0.0, self._jitter)
        return base

    def connect(
        self,
        host: str,
        port: int,
        *,
        use_tls: bool = False,
        connect_timeout: float | None = None,
    ) -> RawConnection:
        """Open a scope-checked raw connection (for explicit reuse).

        SAFETY: the scope check runs before ``socket.create_connection``; an
        out-of-scope host raises ``OutOfScopeError`` and no socket is opened.
        """
        self._check_scope(host)
        ct = connect_timeout if connect_timeout is not None else self._timeout
        sock = socket.create_connection((host, port), timeout=ct)
        if use_tls:
            # TLS is transport only -- it does not normalise the HTTP bytes.
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return RawConnection(sock, host, port)

    def send(
        self,
        host: str,
        port: int,
        raw: bytes,
        *,
        use_tls: bool = False,
        timeout: float | None = None,
        reuse_connection: bool = False,
        connection: RawConnection | None = None,
    ) -> RawResponse:
        """Send ``raw`` byte-exact and return a :class:`RawResponse`.

        By default this opens ONE isolated connection, probes, and closes it, so
        a poisoned socket is never left in a shared pool. Pass ``connection`` to
        reuse an open :class:`RawConnection` (pipelining discrimination); pass
        ``reuse_connection=True`` to keep a freshly opened connection open (the
        caller then owns closing it).
        """
        t = self._effective_timeout(timeout)
        if connection is not None:
            return connection.probe(raw, t)
        conn = self.connect(host, port, use_tls=use_tls)
        try:
            return conn.probe(raw, t)
        finally:
            if not reuse_connection:
                conn.close()
