"""In-process HTTP/2-downgrade mock front/back pair for deterministic H2 tests.

This is the H2 analogue of ``mockpair.MockPair``: a threaded plaintext TCP
server the H2 engine connects to (as if it were an HTTP/2 front-end). It models
a **vulnerable downgrade** -- it accepts the client's raw H2 frames, then
reconstructs an HTTP/1.1 view by copying the request headers **verbatim**,
including the RFC-7540-prohibited ones (a lying ``content-length``, an injected
``transfer-encoding: chunked``). That copied header is the whole bug: a correct
front-end would strip it, a vulnerable one forwards it, and the HTTP/1.1
back-end then frames the message differently from the front-end.

Why hand-roll the H2 parse instead of using the ``h2`` server: ``h2`` -- even
with ``validate_inbound_headers=False`` -- enforces that ``content-length``
agrees with the DATA length (``InvalidBodyLengthError``) and rejects
``transfer-encoding`` outright. Those are exactly the invariants a vulnerable
downgrade violates, so a *correct* H2 implementation cannot model the vulnerable
front. We therefore parse frames with a tiny hand-rolled splitter + ``hpack``
(which does no semantic validation), yielding the exact (headers, body) a naive
proxy would forward.

Downstream of the downgrade the logic mirrors ``mockpair.MockPair`` exactly and
reuses its back-end length **strategies** (``cl`` / ``te`` / ``cl0``):

* **hang** -- if the back-end is left waiting for body bytes (a lying CL larger
  than the body, or an unterminated chunk), the server never answers, so the H2
  client times out -- the downgrade timing signal.
* **differential** -- the back-end's parse leaves a smuggled prefix; the next
  request is answered as if it had requested that resource. ``server_desync``
  keeps the poison on a **shared** back-end (reproduces on a fresh H2 connection
  -> a real desync); ``pipeline_only`` keeps it **per H2 connection** (only
  reproduces under connection reuse -> client-side pipelining, the false
  positive the engine must discriminate).

Responses are H2 frames: ``/`` -> ``200 path=/``, any other path -> ``404
path=<path>``. The engine compares (status, body) signatures.
"""

from __future__ import annotations

import socket
import threading

from hpack import Decoder

from doppelganger.h2send import (
    FLAG_ACK,
    FLAG_END_STREAM,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    H2_PREFACE,
    build_data_frame,
    build_headers_frame,
    build_settings_frame,
    encode_header_block,
)

# Reuse the v0.1 back-end length strategies + helpers unchanged.
from mockpair import NEED_MORE, _parse_path, cl, cl0, te  # noqa: F401

_MOCK_IDLE_TIMEOUT = 8.0  # must exceed the client's per-probe timeout


class H2DowngradeMockPair:
    """A threaded HTTP/2 front-end that downgrades to a discrepant HTTP/1.1 back.

    Parameters:
        back: a ``mockpair`` length strategy the back-end applies to the
            downgraded (header_lines, body) -- ``cl(0)`` for H2.CL, ``te()`` for
            H2.TE.
        mode: ``"server_desync"`` (shared poison) or ``"pipeline_only"``
            (per-connection poison).
        hang_on_incomplete: if the back-end needs more body than it has, hang
            (never answer) so the client times out -- the timing signal.
        poison: if ``False`` the back-end never carries a smuggled prefix forward
            (models "timing signal present, differential not confirmable" -- a
            stage-1 candidate that never upgrades).
    """

    def __init__(
        self,
        back,
        *,
        mode: str = "server_desync",
        hang_on_incomplete: bool = True,
        poison: bool = True,
        correct_downgrade: bool = False,
    ) -> None:
        if mode not in ("server_desync", "pipeline_only"):
            raise ValueError(f"unknown mode {mode!r}")
        self.back = back
        self.mode = mode
        self.hang = hang_on_incomplete
        self.poison = poison
        # When True the front-end behaves CORRECTLY: it strips the prohibited
        # content-length / transfer-encoding and writes a truthful Content-Length
        # from the real DATA length -> no discrepancy (the negative control).
        self.correct_downgrade = correct_downgrade
        self.host = "127.0.0.1"
        self.port = 0
        self._shared_pending: str | None = None
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None
        self.hang_count = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "H2DowngradeMockPair":
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(16)
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
        # Plaintext (prior-knowledge) H2 for the in-process lab.
        return f"http://{self.host}:{self.port}/"

    def __enter__(self) -> "H2DowngradeMockPair":
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
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _recv(self, conn: socket.socket, buf: bytearray) -> bool:
        try:
            chunk = conn.recv(65536)
        except (socket.timeout, OSError):
            return False
        if not chunk:
            return False
        buf += chunk
        return True

    def _read_preface(self, conn: socket.socket, buf: bytearray) -> bool:
        while len(buf) < len(H2_PREFACE):
            if not self._recv(conn, buf):
                return False
        if bytes(buf[: len(H2_PREFACE)]) != H2_PREFACE:
            return False
        del buf[: len(H2_PREFACE)]
        return True

    def _read_frame(self, conn: socket.socket, buf: bytearray):
        """Read one complete frame -> (ftype, flags, sid, payload), or None on EOF."""
        while len(buf) < 9:
            if not self._recv(conn, buf):
                return None
        length = int.from_bytes(buf[:3], "big")
        while len(buf) < 9 + length:
            if not self._recv(conn, buf):
                return None
        ftype = buf[3]
        flags = buf[4]
        sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
        payload = bytes(buf[9 : 9 + length])
        del buf[: 9 + length]
        return ftype, flags, sid, payload

    def _read_stream(self, conn: socket.socket, buf: bytearray, decoder: Decoder):
        """Read one request stream -> (sid, headers, body), or None on EOF."""
        headers: list[tuple[bytes, bytes]] | None = None
        body = bytearray()
        sid_seen: int | None = None
        while True:
            fr = self._read_frame(conn, buf)
            if fr is None:
                return None
            ftype, flags, sid, payload = fr
            if ftype == FRAME_SETTINGS:
                continue  # SETTINGS / SETTINGS-ACK: no ack required by this lab
            if ftype == FRAME_HEADERS:
                sid_seen = sid
                headers = decoder.decode(payload, raw=True)
                if flags & FLAG_END_STREAM:
                    return sid, headers, bytes(body)
            elif ftype == FRAME_DATA:
                body += payload
                if flags & FLAG_END_STREAM:
                    return sid_seen if sid_seen is not None else sid, headers or [], bytes(body)
            # WINDOW_UPDATE / PING / PRIORITY / RST: ignored (client never sends).

    # -- downgrade + back-end parse ---------------------------------------

    def _downgrade(self, headers: list[tuple[bytes, bytes]], body: bytes):
        """Reconstruct the HTTP/1.1 view a downgrading front-end forwards.

        Vulnerable (default): copy regular headers VERBATIM, so a lying
        content-length / injected transfer-encoding survives. Correct
        (``correct_downgrade``): strip both and write a truthful Content-Length.

        Returns ``(header_lines, body)`` where ``header_lines[0]`` is the request
        line -- the exact shape ``mockpair`` length strategies expect (they read
        ``header_lines[1:]``).
        """
        hd = dict(headers)
        method = hd.get(b":method", b"GET")
        path = hd.get(b":path", b"/")
        authority = hd.get(b":authority", b"127.0.0.1")
        lines = [method + b" " + path + b" HTTP/1.1", b"Host: " + authority]
        if self.correct_downgrade:
            # Conformant front-end: strip prohibited framing headers, emit a
            # truthful Content-Length derived from the real DATA length.
            for name, value in headers:
                low = name.lower()
                if not name.startswith(b":") and low not in (
                    b"content-length",
                    b"transfer-encoding",
                ):
                    lines.append(name + b": " + value)
            lines.append(b"Content-Length: " + str(len(body)).encode())
        else:
            for name, value in headers:
                if not name.startswith(b":"):
                    lines.append(name + b": " + value)  # prohibited headers copied as-is
        return lines, body

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_MOCK_IDLE_TIMEOUT)
        buf = bytearray()
        decoder = Decoder()
        conn_pending: str | None = None
        try:
            if not self._read_preface(conn, buf):
                return
            conn.sendall(build_settings_frame())  # server connection preface
            while True:
                stream = self._read_stream(conn, buf, decoder)
                if stream is None:
                    return
                sid, headers, body = stream
                header_lines, h1_body = self._downgrade(headers, body)

                back_n = self.back(header_lines[1:], h1_body)
                if back_n is NEED_MORE:
                    self.hang_count += 1
                    if self.hang:
                        self._await_close(conn)
                        return
                    back_n = 0

                consumed = int(back_n)
                leftover = h1_body[consumed:]
                own_path = _parse_path(b"\r\n".join(header_lines)) or "/"

                pending = self._take_pending(conn_pending)
                effective_path = pending if pending is not None else own_path
                conn_pending = None

                if leftover.strip():
                    smuggled = _parse_path(leftover)
                    if smuggled is not None:
                        conn_pending = self._set_pending(smuggled, conn_pending)

                try:
                    conn.sendall(self._h2_response(sid, effective_path))
                except OSError:
                    return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _await_close(self, conn: socket.socket) -> None:
        buf = bytearray()
        while self._recv(conn, buf):
            buf.clear()

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

    def _h2_response(self, stream_id: int, path: str) -> bytes:
        status = b"200" if path == "/" else b"404"
        body = b"path=" + path.encode("latin-1")
        block = encode_header_block(
            [(b":status", status), (b"content-length", str(len(body)).encode())]
        )
        out = build_headers_frame(block, stream_id, end_stream=False)
        out += build_data_frame(body, stream_id, end_stream=True)
        return out


# --------------------------------------------------------------------------- #
# factory helpers: one configured H2-downgrade pair per discrepancy
# --------------------------------------------------------------------------- #


def h2cl_pair(mode: str = "server_desync") -> H2DowngradeMockPair:
    """H2.CL: the downgraded back-end honours the injected content-length."""
    return H2DowngradeMockPair(cl(0), mode=mode)


def h2te_pair(mode: str = "server_desync") -> H2DowngradeMockPair:
    """H2.TE: the downgraded back-end honours the injected transfer-encoding."""
    return H2DowngradeMockPair(te(), mode=mode)


def h2cl_candidate_pair() -> H2DowngradeMockPair:
    """H2.CL that hangs (timing signal) but never poisons -> stage-1 candidate."""
    return H2DowngradeMockPair(cl(0), mode="server_desync", poison=False)


def h2pseudo_inject_pair(mode: str = "server_desync") -> H2DowngradeMockPair:
    """H2.PseudoHdrInject: back-end honours TE injected via CRLF in header values.

    Both ``H2.PseudoHdrInject`` variants (``authority-crlf-te`` and
    ``header-val-crlf-te``) produce a ``Transfer-Encoding: chunked`` line that
    appears in the downgraded H1 header block when the mock's ``_downgrade()``
    copies decoded values verbatim.  The ``te()`` back-end strategy finds the
    injected TE and switches to chunked parsing, creating the same desync shape
    as H2.TE (hang on incomplete chunk, smuggled prefix from the terminator).
    """
    return H2DowngradeMockPair(te(), mode=mode)


def h2_robust_pair() -> H2DowngradeMockPair:
    """A non-vulnerable front-end: strips prohibited headers on downgrade.

    Models a conformant H2 front-end -- it writes a truthful Content-Length from
    the real DATA length, so a lying content-length or injected transfer-encoding
    neither smuggles nor stalls. The negative control: doppelganger must NOT
    report a desync here.
    """
    return H2DowngradeMockPair(cl(0), mode="server_desync", correct_downgrade=True)
