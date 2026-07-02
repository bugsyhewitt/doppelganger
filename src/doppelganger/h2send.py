"""Low-level HTTP/2 send layer for downgrade-desync probes (v0.2).

This module is doppelganger's H2 analogue of :mod:`doppelganger.rawsend`: a
byte-exact sender that can emit the **RFC-7540-prohibited** frames an HTTP/2 ->
HTTP/1.1 downgrade desync needs. The high-level H2 stacks refuse to build these
on purpose:

* ``h2`` / ``httpx`` **validate on send** -- ``h2`` rejects a connection-specific
  header such as ``transfer-encoding`` outright (``ProtocolError``) and, even
  with ``validate_outbound_headers=False``, enforces that ``content-length``
  agrees with the DATA-frame length (``InvalidBodyLengthError``). Those are
  exactly the invariants an H2.CL / H2.TE probe must break.

So the *send* path here is hand-rolled: a minimal literal (non-Huffman) HPACK
encoder (RFC 7541 sec 6.2.2, "Literal Header Field without Indexing -- New
Name") plus hand-built HTTP/2 frames (RFC 7540 sec 4.1). Literal encoding is
deliberate: it performs **no** validation, never touches the dynamic table, and
puts the header names/values into the wire bytes verbatim -- so a lying
``content-length``, an injected ``transfer-encoding: chunked``, and even
CRLF/colon-injected header names all reach the wire byte-for-byte, yet still
decode back to the exact pairs under any conformant HPACK decoder.

The *receive* path decodes responses with the ``hpack`` decoder (part of the
``h2`` dependency stack) over a small hand-rolled frame splitter -- enough to
pull ``:status`` + body out of a cooperative peer, and to surface a hang (the
downgrade timing signal) as a clean ``timed_out``.

Scope enforcement mirrors :mod:`doppelganger.rawsend` exactly: every connection
is scope-checked with the shared :class:`~scan_primitives.Scope` **before** any
socket is opened; a sender with no scope is fail-closed (refuses all egress).
TLS uses ALPN to negotiate ``h2``; plaintext (``http://``) uses prior-knowledge
H2 for the in-process test lab (this is *not* the h2c Upgrade dance -- that
cleartext-upgrade attack is explicitly out of scope for this lap).

**R5 (untrusted input):** response bytes are DATA, never instructions. They are
read into a buffer, HPACK-decoded to a (status, body) signature, and returned
verbatim as evidence. They are never executed, shelled out, or handed to an LLM
tool call.
"""

from __future__ import annotations

import random
import socket
import ssl
import time
from dataclasses import dataclass, field, replace

from hpack import Decoder  # part of the h2 dependency stack

from scan_primitives import OutOfScopeError, Scope

__all__ = [
    "H2_PREFACE",
    "H2NotSupportedError",
    "encode_integer",
    "encode_literal_header",
    "encode_header_block",
    "build_frame",
    "build_settings_frame",
    "build_settings_ack",
    "build_headers_frame",
    "build_data_frame",
    "serialize_request",
    "H2Request",
    "H2Response",
    "H2Connection",
    "H2Sender",
]

# HTTP/2 client connection preface (RFC 7540 sec 3.5). Sent once per connection,
# immediately followed by the client's SETTINGS frame.
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame type codes (RFC 7540 sec 6).
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

# Frame flags.
FLAG_END_STREAM = 0x1  # DATA / HEADERS
FLAG_ACK = 0x1  # SETTINGS / PING
FLAG_END_HEADERS = 0x4  # HEADERS / CONTINUATION
FLAG_PADDED = 0x8  # DATA / HEADERS
FLAG_PRIORITY = 0x20  # HEADERS

_MAX_FRAME_PAYLOAD = 0xFFFFFF  # 24-bit length field
_EVIDENCE_CAP = 2048


class H2NotSupportedError(RuntimeError):
    """Raised when a TLS target does not negotiate ``h2`` via ALPN."""


# --------------------------------------------------------------------------- #
# literal HPACK encoding (RFC 7541) -- no Huffman, no indexing, no validation
# --------------------------------------------------------------------------- #


def encode_integer(value: int, prefix_bits: int) -> bytes:
    """Encode ``value`` as an HPACK integer with an ``prefix_bits``-bit prefix.

    RFC 7541 sec 5.1. The high bits of the first octet above ``prefix_bits`` are
    left zero, so for a 7-bit length prefix the Huffman flag (bit 7) is 0 -- i.e.
    the string that follows is a raw literal, not Huffman-coded.
    """
    if value < 0:
        raise ValueError("HPACK integers are non-negative")
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([value])
    out = bytearray([max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_literal_header(name: bytes, value: bytes) -> bytes:
    """Encode one header as a literal-without-indexing, new-name field.

    RFC 7541 sec 6.2.2. First octet ``0x00`` selects "literal without indexing"
    (never added to the dynamic table) with a new (literal) name. Name and value
    are length-prefixed raw byte strings -- **no** Huffman coding and **no**
    validation, so prohibited names/values reach the wire verbatim.
    """
    return (
        b"\x00"
        + encode_integer(len(name), 7)
        + name
        + encode_integer(len(value), 7)
        + value
    )


def encode_header_block(headers: list[tuple[bytes, bytes]]) -> bytes:
    """Concatenate literal-encoded headers into an HPACK header block fragment."""
    return b"".join(encode_literal_header(n, v) for n, v in headers)


# --------------------------------------------------------------------------- #
# frame construction (RFC 7540 sec 4.1)
# --------------------------------------------------------------------------- #


def build_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Assemble one HTTP/2 frame: 9-byte header (len/type/flags/stream) + payload."""
    length = len(payload)
    if length > _MAX_FRAME_PAYLOAD:
        raise ValueError(f"frame payload {length} exceeds 24-bit length field")
    return (
        length.to_bytes(3, "big")
        + bytes([frame_type & 0xFF, flags & 0xFF])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def build_settings_frame(settings: dict[int, int] | None = None) -> bytes:
    """A SETTINGS frame (stream 0). Empty settings are legal and sufficient."""
    payload = b""
    if settings:
        for ident, val in settings.items():
            payload += ident.to_bytes(2, "big") + val.to_bytes(4, "big")
    return build_frame(FRAME_SETTINGS, 0, 0, payload)


def build_settings_ack() -> bytes:
    """A SETTINGS ACK frame (acknowledges the peer's SETTINGS)."""
    return build_frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")


def build_headers_frame(
    header_block: bytes, stream_id: int, *, end_stream: bool, end_headers: bool = True
) -> bytes:
    """A HEADERS frame carrying an HPACK header block for ``stream_id``."""
    flags = FLAG_END_HEADERS if end_headers else 0
    if end_stream:
        flags |= FLAG_END_STREAM
    return build_frame(FRAME_HEADERS, flags, stream_id, header_block)


def build_data_frame(data: bytes, stream_id: int, *, end_stream: bool) -> bytes:
    """A DATA frame carrying request-body bytes for ``stream_id``."""
    flags = FLAG_END_STREAM if end_stream else 0
    return build_frame(FRAME_DATA, flags, stream_id, data)


# --------------------------------------------------------------------------- #
# request / response models
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class H2Request:
    """A byte-exact HTTP/2 request, including deliberately-malformed headers.

    ``headers`` are the *regular* (non-pseudo) headers and may contain the
    prohibited fields the desync depends on -- a lying ``content-length`` or an
    injected ``transfer-encoding: chunked`` -- as raw ``(name, value)`` byte
    pairs. The pseudo-headers are derived from ``method``/``path``/``scheme``/
    ``authority``.
    """

    method: bytes
    path: bytes
    authority: bytes
    scheme: bytes = b"https"
    headers: tuple[tuple[bytes, bytes], ...] = ()
    body: bytes = b""
    end_stream: bool = True
    stream_id: int = 1

    @classmethod
    def get(cls, authority: str, path: str, scheme: str = "https") -> "H2Request":
        """A well-formed bodyless GET (the baseline / differential victim)."""
        return cls(
            method=b"GET",
            path=path.encode(),
            authority=authority.encode(),
            scheme=scheme.encode(),
        )

    def pseudo_headers(self) -> list[tuple[bytes, bytes]]:
        return [
            (b":method", self.method),
            (b":path", self.path),
            (b":scheme", self.scheme),
            (b":authority", self.authority),
        ]

    def header_list(self) -> list[tuple[bytes, bytes]]:
        """Full HPACK header list: pseudo-headers first, then regular headers."""
        return self.pseudo_headers() + list(self.headers)

    def render(self) -> str:
        """Human-readable rendering for finding evidence (data, never executed)."""
        lines = [f"{n.decode('latin-1')}: {v.decode('latin-1')}" for n, v in self.header_list()]
        head = "\n".join(lines)
        body = self.body.decode("latin-1")
        return f"HTTP/2 stream {self.stream_id}\n{head}\n\n{body}"


@dataclass(slots=True)
class H2Response:
    """A decoded HTTP/2 response: status + body, plus timing and stop reason.

    Attributes:
        status: The ``:status`` pseudo-header value, or ``None`` if the peer
            never answered (e.g. a downgrade hang -- see ``timed_out``).
        body: Concatenated DATA-frame payloads (untrusted -- never executed).
        raw: The verbatim response frame bytes (capped), for evidence.
        elapsed_s: Wall time from send to read completion.
        timed_out: ``True`` if no complete response arrived before the deadline
            -- the HTTP/2-downgrade desync *timing* signal (the back-end was left
            waiting for body bytes that, post-downgrade, never came).
        eof: ``True`` if the peer closed / reset before completing the response.
        headers: The decoded response header pairs (data).
    """

    status: int | None
    body: bytes
    raw: bytes
    elapsed_s: float
    timed_out: bool = False
    eof: bool = False
    headers: tuple[tuple[bytes, bytes], ...] = ()

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_s * 1000.0


def serialize_request(req: H2Request, *, include_preface: bool = True) -> bytes:
    """Serialise ``req`` to wire bytes: [preface + SETTINGS] + HEADERS [+ DATA].

    The header block is literal-HPACK encoded (no validation), so the prohibited
    framing survives to the wire byte-for-byte. When the request has a body, the
    HEADERS frame does NOT set END_STREAM -- the DATA frame does.
    """
    block = encode_header_block(req.header_list())
    out = bytearray()
    if include_preface:
        out += H2_PREFACE
        out += build_settings_frame()
    has_body = bool(req.body)
    out += build_headers_frame(
        block, req.stream_id, end_stream=req.end_stream and not has_body
    )
    if has_body:
        out += build_data_frame(req.body, req.stream_id, end_stream=req.end_stream)
    return bytes(out)


# --------------------------------------------------------------------------- #
# response frame reader (hand-rolled; hpack for header blocks only)
# --------------------------------------------------------------------------- #


def _strip_padding(payload: bytes, flags: int, *, has_priority: bool) -> bytes:
    """Strip HEADERS/DATA padding + HEADERS priority prefix, if flagged."""
    pad_len = 0
    idx = 0
    if flags & FLAG_PADDED:
        pad_len = payload[0]
        idx = 1
    if has_priority and (flags & FLAG_PRIORITY):
        idx += 5  # 4-byte stream dep + 1-byte weight
    end = len(payload) - pad_len
    return payload[idx:end] if end >= idx else b""


def _read_response(
    sock: socket.socket, deadline: float, stream_id: int, decoder: Decoder
) -> H2Response:
    """Read one HTTP/2 response for ``stream_id`` with a hard deadline.

    Sends a SETTINGS ACK when the peer's SETTINGS arrive, ignores flow-control
    and PING housekeeping, HPACK-decodes the response HEADERS to a ``:status``,
    and collects DATA until END_STREAM, EOF, or the deadline (``timed_out``).
    """
    start = time.monotonic()
    buf = bytearray()
    raw = bytearray()
    status: int | None = None
    body = bytearray()
    headers: tuple[tuple[bytes, bytes], ...] = ()
    timed_out = False
    eof = False
    done = False

    while not done:
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
        raw += chunk

        # Drain every complete frame currently buffered.
        while len(buf) >= 9:
            length = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + length:
                break
            ftype = buf[3]
            flags = buf[4]
            sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            payload = bytes(buf[9 : 9 + length])
            del buf[: 9 + length]

            if ftype == FRAME_SETTINGS and not (flags & FLAG_ACK):
                try:
                    sock.sendall(build_settings_ack())
                except OSError:
                    pass
            elif ftype == FRAME_HEADERS and sid == stream_id:
                block = _strip_padding(payload, flags, has_priority=True)
                try:
                    decoded = decoder.decode(block, raw=True)
                except Exception:  # noqa: BLE001 -- malformed header block is data
                    decoded = []
                headers = tuple(decoded)
                for name, val in decoded:
                    if name == b":status":
                        try:
                            status = int(val)
                        except ValueError:
                            status = None
                if flags & FLAG_END_STREAM:
                    done = True
            elif ftype == FRAME_DATA and sid == stream_id:
                body += _strip_padding(payload, flags, has_priority=False)
                if flags & FLAG_END_STREAM:
                    done = True
            elif ftype == FRAME_GOAWAY:
                eof = True
                done = True
            elif ftype == FRAME_RST_STREAM and sid == stream_id:
                eof = True
                done = True
            # WINDOW_UPDATE / PING / PRIORITY / CONTINUATION on other streams:
            # ignored (best-effort client; the mock lab never sends them).

    return H2Response(
        status=status,
        body=bytes(body),
        raw=bytes(raw[:_EVIDENCE_CAP]),
        elapsed_s=time.monotonic() - start,
        timed_out=timed_out,
        eof=eof,
        headers=headers,
    )


# --------------------------------------------------------------------------- #
# connection + sender
# --------------------------------------------------------------------------- #


class H2Connection:
    """A single open HTTP/2 connection for byte-exact send + response read.

    The client preface + SETTINGS are written once on open. Each
    :meth:`send_request` allocates the next odd stream id, so **reuse** (two
    requests down one connection -- the pipelining-discrimination experiment)
    uses distinct streams 1, 3, 5 ... exactly as a real H2 client multiplexes.
    A fresh connection resets to stream 1.
    """

    __slots__ = ("_sock", "host", "port", "closed", "_decoder", "_next_stream_id")

    def __init__(self, sock: socket.socket, host: str, port: int) -> None:
        self._sock = sock
        self.host = host
        self.port = port
        self.closed = False
        # One HPACK decoder per connection (response dynamic-table state).
        self._decoder = Decoder()
        self._next_stream_id = 1
        self._sock.sendall(H2_PREFACE + build_settings_frame())

    def send_request(self, req: H2Request, timeout: float) -> H2Response:
        """Send ``req`` on the next client stream and read its response."""
        stream_id = self._next_stream_id
        self._next_stream_id += 2
        payload = serialize_request(replace(req, stream_id=stream_id), include_preface=False)
        self._sock.sendall(payload)
        deadline = time.monotonic() + timeout
        return _read_response(self._sock, deadline, stream_id, self._decoder)

    def close(self) -> None:
        if not self.closed:
            try:
                self._sock.close()
            finally:
                self.closed = True

    def __enter__(self) -> "H2Connection":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class H2Sender:
    """Scope-enforcing byte-exact HTTP/2 sender for downgrade-desync probes.

    Mirrors :class:`doppelganger.rawsend.RawSender`'s safety surface: every
    connection is scope-checked before the socket opens, and a sender with no
    scope refuses all egress (fail-closed). One isolated connection per probe by
    default; :meth:`connect` yields a reusable :class:`H2Connection` for the
    pipelining-discrimination experiment.
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
        self._jitter = max(0.0, jitter)
        self._rng = rng or random.Random()

    @property
    def scope(self) -> Scope | None:
        return self._scope

    def _check_scope(self, host: str) -> None:
        """Fail-closed scope check -- runs BEFORE any socket is opened."""
        if self._scope is None:
            raise OutOfScopeError(
                "h2 sender has no scope configured; refusing egress (fail-closed)"
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
        use_tls: bool = True,
        connect_timeout: float | None = None,
    ) -> H2Connection:
        """Open a scope-checked HTTP/2 connection.

        SAFETY: the scope check runs before ``socket.create_connection``; an
        out-of-scope host raises ``OutOfScopeError`` and no socket is opened.
        TLS negotiates ``h2`` via ALPN and raises :class:`H2NotSupportedError`
        if the peer will not speak HTTP/2.
        """
        self._check_scope(host)
        ct = connect_timeout if connect_timeout is not None else self._timeout
        sock = socket.create_connection((host, port), timeout=ct)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2"])
            sock = ctx.wrap_socket(sock, server_hostname=host)
            negotiated = sock.selected_alpn_protocol()
            if negotiated != "h2":
                sock.close()
                raise H2NotSupportedError(
                    f"target {host!r} did not negotiate HTTP/2 via ALPN "
                    f"(got {negotiated!r}); H2 downgrade probes require an h2 front-end"
                )
        return H2Connection(sock, host, port)

    def send(
        self,
        host: str,
        port: int,
        req: H2Request,
        *,
        use_tls: bool = True,
        timeout: float | None = None,
        connection: H2Connection | None = None,
    ) -> H2Response:
        """Send ``req`` and return its :class:`H2Response`.

        By default opens ONE isolated connection, sends, reads, and closes it, so
        no poisoned connection is left behind. Pass ``connection`` to reuse an
        open :class:`H2Connection` (pipelining discrimination).
        """
        t = self._effective_timeout(timeout)
        if connection is not None:
            return connection.send_request(req, t)
        conn = self.connect(host, port, use_tls=use_tls)
        try:
            return conn.send_request(req, t)
        finally:
            conn.close()
