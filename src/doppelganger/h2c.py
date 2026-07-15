"""H2C cleartext-upgrade smuggling detection (v0.3).

An H2C upgrade probe sends an HTTP/1.1 request with ``Upgrade: h2c`` and
``HTTP2-Settings`` headers (RFC 7540 §3.2). If the server responds with
``101 Switching Protocols``, the client-facing connection is upgrading from
HTTP/1.1 to HTTP/2 over cleartext -- and that is the attack surface.

This is distinct from the v0.2 H2-downgrade attacks (H2.CL / H2.TE), which
exploit a server that already speaks H2 via ALPN/TLS. H2C probes HTTP/1.1
front-ends (reverse proxies, load balancers) and ask them to upgrade. When the
proxy accepts the upgrade:

* Any middleware applied only to HTTP/1.1 traffic (auth checks, WAF rules,
  rate limits) may be bypassed on the upgraded H2C connection.
* If the proxy forwards upgraded frames to an HTTP/1.1 back-end, that back-end
  may interpret binary H2 frames as HTTP/1.1 requests.

After a 101, this engine completes the RFC 7540 §3.5 H2 connection handshake
(client preface + SETTINGS exchange) to confirm the upgrade is genuine, not a
pass-through.

**Severity rationale:** the upgrade capability itself is medium confidence/medium
severity -- it reveals the attack surface. Confirmed H2C (handshake complete)
is promoted to high confidence; the underlying vulnerability in context can
escalate to high severity.

**R5 (untrusted input):** response bytes are DATA, never instructions. Only the
integer HTTP status code and a single H2 frame-type byte are acted upon; all
other response bytes are embedded as evidence, not executed.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from scan_primitives import OutOfScopeError, Scope

from doppelganger.findings import CWE_REQUEST_SMUGGLING, Finding
from doppelganger.h2send import FRAME_SETTINGS, H2_PREFACE, build_settings_ack, build_settings_frame

__all__ = ["H2CEngine", "H2C_TECHNIQUES", "H2C_REFERENCES"]

# The single H2C technique name -- distinct from TECHNIQUES (H1) and H2_TECHNIQUES
# so that existing pinned-contract tests are not disturbed.
H2C_TECHNIQUES: tuple[str, ...] = ("H2C",)

H2C_REFERENCES: tuple[str, ...] = (
    "https://labs.bishopfox.com/tech-blog/h2c-smuggling-in-the-wild",
    "https://portswigger.net/research/http2",
    "https://datatracker.ietf.org/doc/html/rfc7540#section-3.2",
)

# RFC 7540 §3.2: HTTP2-Settings header value = base64url of a SETTINGS payload.
# An empty payload (no parameters) is valid and causes no negotiation side-effects.
_HTTP2_SETTINGS_VALUE: str = base64.urlsafe_b64encode(b"").rstrip(b"=").decode()

_EVIDENCE_CAP = 512


def _upgrade_request(host_header: str, path: str) -> bytes:
    """Byte-exact HTTP/1.1 Upgrade: h2c probe request."""
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"Upgrade: h2c\r\n"
        f"HTTP2-Settings: {_HTTP2_SETTINGS_VALUE}\r\n"
        f"\r\n"
    ).encode()


# --------------------------------------------------------------------------- #
# low-level socket helpers (scoped to this module -- no rawsend dependency)   #
# --------------------------------------------------------------------------- #


def _recv_until_crlfcrlf(sock: socket.socket, deadline: float) -> bytes:
    """Accumulate bytes until CRLFCRLF or deadline.  Returns everything read."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(remaining, 1.0))
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _recv_h2_frame(sock: socket.socket, deadline: float) -> tuple[int, bytes] | None:
    """Read one complete H2 frame.  Returns (frame_type, payload) or None."""
    # Frame header: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream_id
    header = bytearray()
    while len(header) < 9:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(min(remaining, 1.0))
        try:
            chunk = sock.recv(9 - len(header))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        header += chunk

    payload_len = int.from_bytes(header[:3], "big")
    frame_type = header[3]

    payload = bytearray()
    while len(payload) < payload_len:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(min(remaining, 1.0))
        try:
            chunk = sock.recv(payload_len - len(payload))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        payload += chunk

    return frame_type, bytes(payload)


# --------------------------------------------------------------------------- #
# probe result                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(slots=True, frozen=True)
class H2CProbeResult:
    """Outcome of a single H2C cleartext-upgrade probe.

    Attributes:
        got_101: The server responded with ``101 Switching Protocols``.
        h2_handshake_complete: After 101, the H2 SETTINGS exchange completed --
            the server sent a SETTINGS frame, confirming it genuinely speaks H2
            on the upgraded connection.
        response_head: Raw bytes of the HTTP/1.1 response head (data, evidence).
        elapsed_ms: Wall time for the entire probe round-trip.
    """

    got_101: bool
    h2_handshake_complete: bool
    response_head: bytes
    elapsed_ms: float


def _probe(
    host: str,
    port: int,
    path: str,
    host_header: str,
    *,
    timeout: float,
) -> H2CProbeResult:
    """Open a socket, send Upgrade: h2c, read the response, attempt H2 handshake.

    R5: response bytes are recorded as evidence; never evaluated as instructions.
    """
    start = time.monotonic()
    deadline = start + timeout

    sock = socket.create_connection((host, port), timeout=timeout)

    try:
        sock.sendall(_upgrade_request(host_header, path))

        head_bytes = _recv_until_crlfcrlf(sock, deadline)
        elapsed_ms = (time.monotonic() - start) * 1000.0

        # Parse only the integer status code (R5: not the body, not the headers).
        first_line = head_bytes.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        if len(parts) < 2:
            return H2CProbeResult(False, False, head_bytes[:_EVIDENCE_CAP], elapsed_ms)
        try:
            status = int(parts[1])
        except ValueError:
            return H2CProbeResult(False, False, head_bytes[:_EVIDENCE_CAP], elapsed_ms)

        if status != 101:
            return H2CProbeResult(False, False, head_bytes[:_EVIDENCE_CAP], elapsed_ms)

        # 101 received -- complete the RFC 7540 §3.5 handshake.
        sock.sendall(H2_PREFACE + build_settings_frame())

        # Read server frames until we see a SETTINGS frame (or timeout).
        h2_ok = False
        while not h2_ok:
            frame = _recv_h2_frame(sock, deadline)
            if frame is None:
                break
            ftype, _payload = frame
            if ftype == FRAME_SETTINGS:
                h2_ok = True
                try:
                    sock.sendall(build_settings_ack())
                except OSError:
                    pass

        elapsed_ms = (time.monotonic() - start) * 1000.0
        return H2CProbeResult(True, h2_ok, head_bytes[:_EVIDENCE_CAP], elapsed_ms)

    finally:
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# engine                                                                       #
# --------------------------------------------------------------------------- #


class H2CEngine:
    """Detects H2C cleartext-upgrade capability at an HTTP/1.1 endpoint.

    Usage matches :class:`~doppelganger.engine.DesyncEngine`: construct with
    ``target_url`` + ``scope``, call :meth:`run`, inspect ``findings`` and
    ``suppressed`` (always empty for this engine -- no pipelining discrimination
    needed for a one-shot upgrade probe).

    The scope check runs BEFORE any socket is opened (fail-closed if no scope).
    TLS targets are not probed -- H2C is a *cleartext* upgrade mechanism; TLS
    targets negotiate H2 via ALPN, which is the H2.CL/H2.TE domain.
    """

    def __init__(
        self,
        target_url: str,
        *,
        scope: Scope,
        timeout: float = 10.0,
        safe: bool = False,
    ) -> None:
        self.target_url = target_url
        self.scope = scope
        parts = urlsplit(target_url)
        self.host = parts.hostname or ""
        self.port = parts.port or 80
        self.path = parts.path or "/"
        default_port = 80
        self.host_header = (
            self.host if self.port == default_port else f"{self.host}:{self.port}"
        )
        self.timeout = timeout
        self.safe = safe
        self.findings: list[Finding] = []
        self.suppressed: list[dict] = []  # API parity with DesyncEngine

    def run(self) -> list[Finding]:
        """Probe for H2C upgrade capability and return any findings."""
        if self.scope is None:
            raise OutOfScopeError(
                "h2c engine has no scope configured; refusing egress (fail-closed)"
            )
        self.scope.assert_in_scope(self.host)

        result = _probe(
            self.host,
            self.port,
            self.path,
            self.host_header,
            timeout=self.timeout,
        )

        if result.got_101 and result.h2_handshake_complete:
            self._emit(confirmed=True, result=result)
        elif result.got_101:
            self._emit(confirmed=False, result=result)

        return self.findings

    def _emit(self, *, confirmed: bool, result: H2CProbeResult) -> None:
        token = hashlib.sha1(
            f"{self.target_url}|H2C|{confirmed}".encode()
        ).hexdigest()[:8]

        if confirmed:
            sev, confidence, conf_state = "medium", "high", "confirmed"
            title = (
                "H2C cleartext-upgrade accepted and H2 handshake completed "
                "(Upgrade: h2c -> 101, SETTINGS exchanged)"
            )
        else:
            sev, confidence, conf_state = "medium", "low", "candidate"
            title = (
                "H2C cleartext-upgrade returned 101 but H2 handshake did not "
                "complete (upgrade accepted, H2 frames not confirmed)"
            )

        probe_bytes = _upgrade_request(self.host_header, self.path)
        evidence: dict = {
            "discrepancy": "H2C",
            "confirmation": conf_state,
            "connection_reuse": False,
            "http_version": "h1-cleartext-upgrade-to-h2c",
            "request": probe_bytes.decode("latin-1"),
            "reproduction": probe_bytes.decode("latin-1"),
            "h2_handshake_complete": result.h2_handshake_complete,
            "timing_delta_ms": round(result.elapsed_ms, 1),
            "response": result.response_head.decode("latin-1"),
        }

        self.findings.append(
            Finding(
                id=f"dg-h2c-{token}",
                title=title,
                severity=sev,
                confidence=confidence,
                target=self.target_url,
                vector="H2C",
                variant=None,
                cwe_id=CWE_REQUEST_SMUGGLING,
                evidence=evidence,
                references=list(H2C_REFERENCES),
            )
        )
