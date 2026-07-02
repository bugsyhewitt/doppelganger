"""scan-primitives-backed baseline / differential HTTP client -- STUB (v0.1 pending).

doppelganger uses the shared ``scan-primitives`` client for **well-formed**
requests only (criterion 5 of V0.1-CRITERIA.md, shared-infra Option C):

  * the **baseline** request (what a normal, well-formed request to the target
    returns), and
  * the **differential** follow-up request whose response, when it differs
    materially after a smuggled prefix, upgrades a timing *candidate* to a
    *confirmed* desync.

It does **not** and **must not** carry the smuggling probes themselves -- those
are byte-exact and go through :mod:`doppelganger.rawsend`. A normalising client
would rewrite the malformed framing the probe depends on.

The real implementation will wrap ``scan_primitives.ScanClient`` (an ``httpx``
-backed, scope-aware, rate-limited async client) so that:
  * ``scope.assert_in_scope()`` runs before every request -- egress to an
    out-of-scope host raises ``OutOfScopeError`` before a socket opens;
  * the **same** ``Scope`` object is shared with the raw sender;
  * an optional proxy (Caido/Burp) and a token-bucket rate limit apply.

Everything here raises ``NotImplementedError`` -- no networking is performed in
the scaffold. See V0.1-CRITERIA.md.
"""

from __future__ import annotations

from typing import Any

_NOT_BUILT = "v0.1 build -- see V0.1-CRITERIA.md"


class BaselineClient:
    """Well-formed baseline/differential request client (STUB).

    Thin wrapper-to-be around ``scan_primitives.ScanClient``. Accepts the
    ``Scope`` now so the constructor signature is stable; performs no I/O.
    """

    def __init__(
        self,
        scope: Any = None,
        *,
        rate_limit: float | None = None,
        proxy: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        # ``scope`` will be a scan-primitives ``Scope`` once that lib is built.
        self._scope = scope
        self._rate_limit = rate_limit
        self._proxy = proxy
        self._timeout = timeout

    async def get(self, url: str, **kwargs: Any) -> Any:
        """Fetch a well-formed baseline/differential response (STUB).

        The real path will scope-check ``url`` before any egress.
        """
        raise NotImplementedError(_NOT_BUILT)

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Issue an arbitrary well-formed request (STUB)."""
        raise NotImplementedError(_NOT_BUILT)
