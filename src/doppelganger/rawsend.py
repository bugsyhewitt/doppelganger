"""Byte-exact HTTP/1.1 raw-socket probe transport -- STUB (v0.1 build pending).

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
The v0.1 shared-client integration is designed around this split from day one.

Scope enforcement:
  The raw sender MUST honour the **same** ``scan-primitives`` ``Scope`` object
  the baseline client uses -- egress to an out-of-scope host must raise before a
  socket is opened. Scope-checking the raw path too (not just the high-level
  client) is a v0.1 safety requirement: a probe is still an out-of-scope request.

Safe-testing defaults (criterion 4), to be implemented in v0.1:
  * per-probe connection isolation (never leave a poisoned socket in a shared
    pool);
  * bounded + randomised timeouts;
  * CL.TE tested before TE.CL (a TE.CL timing probe can hang and disrupt *other*
    users if the target is actually CL.TE);
  * a ``--safe`` / production mode.

**R5 (untrusted input):** bytes returned by the target are DATA, never
instructions. Never pass a raw response to a shell, an elevated tool call, or an
LLM prompt that can act on it. The engine parses response bytes only to compute a
response signature / timing delta.

Everything here raises ``NotImplementedError`` -- no networking is performed in
the scaffold. See V0.1-CRITERIA.md.
"""

from __future__ import annotations

from typing import Any

_NOT_BUILT = "v0.1 build -- see V0.1-CRITERIA.md"


class RawSender:
    """Dedicated byte-exact HTTP/1.1 raw-socket sender (STUB).

    The real implementation will open a plain (or TLS) ``socket`` to the target,
    write ``raw`` verbatim with no header rewriting, read the response with a
    bounded/randomised timeout, and return the raw bytes plus a timing
    measurement -- one isolated connection per probe unless connection reuse is
    explicitly requested for pipelining discrimination.
    """

    def __init__(self, scope: Any = None, *, timeout: float = 10.0) -> None:
        # ``scope`` will be a scan-primitives ``Scope`` once that lib is built;
        # it is accepted now so the constructor signature is stable for callers.
        self._scope = scope
        self._timeout = timeout

    def send(
        self,
        host: str,
        port: int,
        raw: bytes,
        *,
        use_tls: bool = False,
        reuse_connection: bool = False,
    ) -> tuple[bytes, float]:
        """Send ``raw`` byte-exact and return ``(response_bytes, elapsed_s)``.

        STUB: raises :class:`NotImplementedError`. The real path will
        scope-check ``host`` before opening any socket.
        """
        raise NotImplementedError(_NOT_BUILT)
