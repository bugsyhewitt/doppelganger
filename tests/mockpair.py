"""In-process raw-socket mock front/back pair for deterministic desync tests.

V0.1-CRITERIA.md Testability calls for a "tiny raw-socket front-end and back-end
with **opposite length rules** and controllable hang/timeout, synthesizing any
``X.Y`` discrepancy on demand with millisecond-stable timing." This is that.

It is a single threaded TCP server the engine connects to (as if it were the
front-end). Internally it models a front-end length rule and a back-end length
rule; when they disagree it reproduces a real desync effect:

* **hang** -- if the back-end is left waiting for body bytes the front-end never
  forwarded, the server does NOT respond, so the client times out. This is the
  timing signal stage-1 detection keys on.
* **differential** -- when the back-end's parse leaves a *leftover* (a smuggled
  prefix), the next request is answered as if it had requested the smuggled
  resource. Two modes decide *where* that poison lives:
    - ``server_desync`` -- poison persists on a **shared** back-end connection
      across client connections. A real server-side desync: it reproduces even on
      a fresh, isolated client connection.
    - ``pipeline_only`` -- poison is **per client connection**. The effect only
      shows up when a client reuses ONE connection for two requests -- i.e.
      client-side pipelining, NOT a server-side desync. This is the false positive
      the engine must discriminate (criterion 3).

The length rules are pluggable strategies, so front=CL/back=TE gives CL.TE,
front=TE/back=CL gives TE.CL, front=CL/back=CL0 gives CL.0, dup Content-Length
gives dup-CL, and front=CL/back=lenient-TE reproduces TE.TE (the obfuscation has
already fooled the front into CL and the back into TE).

Responses are trivial and deterministic: ``/`` -> ``200 path=/``; any other path
-> ``404 path=<path>``. The engine compares (status, body) signatures.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable

# Sentinel: this side needs more body bytes than it has (would block/hang).
NEED_MORE = object()

# A length strategy: given the request's header lines (excluding the request
# line) and the available body bytes, return how many body bytes THIS side treats
# as the message body, or NEED_MORE if it needs more than it has.
Strategy = Callable[[list[bytes], bytes], "int | object"]

_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH")
_MOCK_IDLE_TIMEOUT = 8.0  # must exceed the client's per-probe timeout


# --------------------------------------------------------------------------- #
# length strategies
# --------------------------------------------------------------------------- #


def _cl_values(header_lines: list[bytes]) -> list[int]:
    vals: list[int] = []
    for line in header_lines:
        name, sep, val = line.partition(b":")
        if sep and name.strip().lower() == b"content-length":
            try:
                vals.append(int(val.strip()))
            except ValueError:
                pass
    return vals


def _chunked_consumed(body: bytes) -> "int | None":
    """Bytes consumed by a complete chunked body, or None if more are needed."""
    i, n = 0, len(body)
    while True:
        eol = body.find(b"\r\n", i)
        if eol < 0:
            return None
        size_token = body[i:eol].split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            return None
        i = eol + 2
        if size == 0:
            if body[i : i + 2] == b"\r\n":
                return i + 2
            return None if n < i + 2 else i
        if n < i + size + 2:
            return None
        i += size + 2


def cl(index: int = 0) -> Strategy:
    """Content-Length strategy honouring the ``index``-th CL header (0=first)."""

    def strategy(header_lines: list[bytes], body: bytes):
        vals = _cl_values(header_lines)
        if not vals:
            return 0
        try:
            length = vals[index]
        except IndexError:
            length = vals[-1]
        return NEED_MORE if len(body) < length else length

    return strategy


def cl0() -> Strategy:
    """CL.0 strategy: the body is always treated as zero-length."""

    def strategy(header_lines: list[bytes], body: bytes):
        return 0

    return strategy


def _has_chunked_te(header_lines: list[bytes]) -> bool:
    """Lenient recognizer: any Transfer-Encoding header mentioning chunked."""
    joined = b"\r\n".join(header_lines).lower()
    return b"transfer-encoding" in joined and b"chunked" in joined


def te(recognizer: Callable[[list[bytes]], bool] = _has_chunked_te) -> Strategy:
    """Transfer-Encoding strategy; falls back to Content-Length if not chunked."""

    def strategy(header_lines: list[bytes], body: bytes):
        if recognizer(header_lines):
            consumed = _chunked_consumed(body)
            return NEED_MORE if consumed is None else consumed
        return cl(0)(header_lines, body)

    return strategy


# --------------------------------------------------------------------------- #
# the mock server
# --------------------------------------------------------------------------- #


def _parse_path(data: bytes) -> str | None:
    """Extract the request-line path from a (possibly partial) request buffer."""
    line = data.split(b"\r\n", 1)[0]
    parts = line.split(b" ")
    if len(parts) >= 2 and parts[0] in _METHODS:
        return parts[1].decode("latin-1")
    for method in _METHODS:
        idx = data.find(method + b" ")
        if idx >= 0:
            tail = data[idx:].split(b"\r\n", 1)[0].split(b" ")
            if len(tail) >= 2:
                return tail[1].decode("latin-1")
    return None


class MockPair:
    """A threaded raw-socket server modelling a front/back length discrepancy."""

    def __init__(
        self,
        front: Strategy,
        back: Strategy,
        *,
        mode: str = "server_desync",
        hang_on_incomplete: bool = True,
        poison: bool = True,
    ) -> None:
        if mode not in ("server_desync", "pipeline_only"):
            raise ValueError(f"unknown mode {mode!r}")
        self.front = front
        self.back = back
        self.mode = mode
        self.hang = hang_on_incomplete
        # When False, the back-end never carries a smuggled prefix into the next
        # request (no differential effect) even though its parse still hangs.
        # Models "timing signal present, differential NOT confirmable" -> a
        # stage-1 *candidate* that never upgrades to confirmed.
        self.poison = poison
        self.host = "127.0.0.1"
        self.port = 0
        self._shared_pending: str | None = None
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        # Diagnostics for tests.
        self.hang_count = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "MockPair":
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def __enter__(self) -> "MockPair":
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # -- serving -----------------------------------------------------------

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return  # listener closed
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _recv(self, conn: socket.socket) -> bytes:
        try:
            return conn.recv(65536)
        except (socket.timeout, OSError):
            return b""

    def _read_front_message(
        self, conn: socket.socket, buf: bytearray
    ) -> "tuple[list[bytes], bytes] | None":
        """Read one front-end message from the client; None on EOF.

        Applies the front strategy to decide the forwarded body length, mutating
        ``buf`` to drop the consumed bytes (leftover stays for the next message).
        """
        while b"\r\n\r\n" not in buf:
            chunk = self._recv(conn)
            if not chunk:
                return None
            buf += chunk

        idx = buf.find(b"\r\n\r\n")
        header_lines = bytes(buf[:idx]).split(b"\r\n")
        head_len = idx + 4

        while True:
            body_region = bytes(buf[head_len:])
            n = self.front(header_lines[1:], body_region)
            if n is NEED_MORE:
                chunk = self._recv(conn)
                if not chunk:
                    return None
                buf += chunk
                continue
            front_body = body_region[: int(n)]
            del buf[: head_len + int(n)]
            return header_lines, front_body

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_MOCK_IDLE_TIMEOUT)
        buf = bytearray()
        conn_pending: str | None = None
        try:
            while True:
                msg = self._read_front_message(conn, buf)
                if msg is None:
                    return
                header_lines, front_body = msg

                back_n = self.back(header_lines[1:], front_body)
                if back_n is NEED_MORE:
                    # Back-end is left waiting for body bytes -> hang. Do not
                    # respond; block until the client gives up and closes.
                    self.hang_count += 1
                    if self.hang:
                        self._await_close(conn)
                        return
                    back_n = 0

                consumed = int(back_n)
                leftover = front_body[consumed:]
                own_path = _parse_path(b"\r\n".join(header_lines)) or "/"

                # Consume any pending smuggle (prepended to this request), then
                # register a new one if this request left a leftover.
                pending = self._take_pending(conn_pending)
                effective_path = pending if pending is not None else own_path
                conn_pending = None

                if leftover.strip():
                    smuggled = _parse_path(leftover)
                    if smuggled is not None:
                        conn_pending = self._set_pending(smuggled, conn_pending)

                try:
                    conn.sendall(self._response(effective_path))
                except OSError:
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _await_close(self, conn: socket.socket) -> None:
        while True:
            if not self._recv(conn):
                return

    # -- pending-smuggle state (shared vs per-connection) -----------------

    def _take_pending(self, conn_pending: str | None) -> str | None:
        if not self.poison:
            return None
        if self.mode == "server_desync":
            with self._lock:
                p, self._shared_pending = self._shared_pending, None
                return p
        return conn_pending

    def _set_pending(self, path: str, conn_pending: str | None) -> str | None:
        if not self.poison:
            return conn_pending
        if self.mode == "server_desync":
            with self._lock:
                self._shared_pending = path
            return conn_pending
        return path  # per-connection

    # -- responses ---------------------------------------------------------

    def _response(self, path: str) -> bytes:
        status = "200 OK" if path == "/" else "404 Not Found"
        body = b"path=" + path.encode("latin-1")
        head = f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n\r\n"
        return head.encode() + body


# --------------------------------------------------------------------------- #
# factory helpers: one configured pair per discrepancy
# --------------------------------------------------------------------------- #


def clte_pair(mode: str = "server_desync") -> MockPair:
    """front=Content-Length, back=Transfer-Encoding (CL.TE / TE.TE effect)."""
    return MockPair(cl(0), te(), mode=mode)


def tecl_pair(mode: str = "server_desync") -> MockPair:
    """front=Transfer-Encoding, back=Content-Length (TE.CL)."""
    return MockPair(te(), cl(0), mode=mode)


def passthrough() -> Strategy:
    """Transparent strategy: forwards ALL bytes in the body region.

    Models a TCP-level transparent proxy that does not apply HTTP framing to
    decide what to forward -- every byte after the request headers is passed
    to the back-end verbatim.  Combined with a back-end that reads
    Content-Length correctly (e.g. CL:0 on a GET request), this synthesises
    the GET+CL:0 server-side desync: the back-end reads 0 body bytes and the
    extra bytes (the smuggled request) become the next-request prefix.
    """

    def strategy(header_lines: list[bytes], body: bytes) -> "int | object":
        return len(body)

    return strategy


def cl0_pair(mode: str = "server_desync") -> MockPair:
    """front=Content-Length, back ignores the body (CL.0)."""
    return MockPair(cl(0), cl0(), mode=mode)


def get_cl0_pair(mode: str = "server_desync") -> MockPair:
    """front=passthrough (transparent TCP), back=Content-Length (GET+CL:0 desync).

    The front-end forwards every byte received after the request headers.
    The back-end reads Content-Length from the headers (CL:0 for the GET
    probe), consuming 0 body bytes and leaving the smuggled request as
    leftover -- the GET+CL:0 server-side desync.
    """
    return MockPair(passthrough(), cl(0), mode=mode)


def dupcl_pair(mode: str = "server_desync") -> MockPair:
    """front honours the first Content-Length, back the last (dup-CL)."""
    return MockPair(cl(0), cl(-1), mode=mode)


class RawCaptureServer:
    """A keep-alive server that records the exact bytes of each request.

    Used to prove the raw sender writes probes byte-for-byte with NO header
    normalisation, and to distinguish connection reuse from isolation. Each
    request's bytes are recorded (``received``), tagged with a per-connection id
    (``request_conns``) BEFORE the response is sent -- so once the client has read
    a response, the record is guaranteed present (no race). Responses are
    keep-alive (no ``Connection: close``) so a reused connection can carry more.
    """

    def __init__(self, response: bytes | None = None) -> None:
        self.host = "127.0.0.1"
        self.port = 0
        self.received: list[bytes] = []
        self.request_conns: list[int] = []
        self._response = response or (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
        self._conn_counter = 0
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None

    def start(self) -> "RawCaptureServer":
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def stop(self) -> None:
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def __enter__(self) -> "RawCaptureServer":
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_MOCK_IDLE_TIMEOUT)
        with self._lock:
            conn_id = self._conn_counter
            self._conn_counter += 1
        buf = bytearray()
        try:
            while True:
                # read one complete request (headers + declared Content-Length)
                while b"\r\n\r\n" not in buf:
                    try:
                        chunk = conn.recv(65536)
                    except (socket.timeout, OSError):
                        return
                    if not chunk:
                        return
                    buf += chunk
                idx = buf.find(b"\r\n\r\n")
                cl = _cl_values(bytes(buf[:idx]).split(b"\r\n")[1:])
                want = idx + 4 + (cl[0] if cl else 0)
                while len(buf) < want:
                    try:
                        chunk = conn.recv(65536)
                    except (socket.timeout, OSError):
                        return
                    if not chunk:
                        return
                    buf += chunk
                # Record BEFORE responding, so a read response implies a record.
                with self._lock:
                    self.received.append(bytes(buf[:want]))
                    self.request_conns.append(conn_id)
                del buf[:want]
                try:
                    conn.sendall(self._response)
                except OSError:
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass


def candidate_pair() -> MockPair:
    """front=CL/back=TE that hangs (timing signal) but never poisons.

    Reproduces a stage-1 *candidate*: the timing probe hangs, but differential
    confirmation cannot upgrade it (no observable response poison).
    """
    return MockPair(cl(0), te(), mode="server_desync", poison=False)


def robust_pair() -> MockPair:
    """A non-vulnerable server: front and back agree (Content-Length)."""
    return MockPair(cl(0), cl(0), mode="server_desync")
