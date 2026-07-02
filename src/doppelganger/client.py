"""scan-primitives-backed baseline / differential HTTP client.

doppelganger uses the shared ``scan-primitives`` client for **well-formed**
requests only (criterion 5 of V0.1-CRITERIA.md, shared-infra Option C):

  * the **baseline** request -- what a normal, well-formed request to the target
    returns. This is the reference the differential stage compares against.

It does **not** and **must not** carry the smuggling probes themselves -- those
are byte-exact and go through :mod:`doppelganger.rawsend`. A normalising client
would rewrite the malformed framing the probe depends on.

:class:`BaselineClient` wraps :class:`scan_primitives.ScanClient` (an ``httpx``
-backed, scope-aware, rate-limited async client) so that:
  * ``scope.assert_in_scope()`` runs before every request -- egress to an
    out-of-scope host raises ``OutOfScopeError`` before a socket opens;
  * the **same** ``Scope`` object is shared with the raw sender;
  * an optional proxy (Caido/Burp) and a token-bucket rate limit apply.

The public surface is synchronous (:meth:`BaselineClient.fetch`) because the
desync engine is a synchronous, raw-socket state machine; the async ScanClient is
driven under ``asyncio.run`` for the one-shot baseline fetch.

**R5 (untrusted input):** the response body returned here is target-controlled
data. It is used only to compute a comparison signature; it is never executed or
passed to a shell / LLM tool call.

[Worker decision: the baseline well-formed request goes through scan-primitives
(this module). The *differential victim* requests are well-formed too, but are
sent through :mod:`doppelganger.rawsend` because confirmation needs byte-level
connection control -- a fresh socket vs. a reused one -- to observe response-queue
poisoning and to discriminate pipelining. Both paths share one Scope, so scope
enforcement is identical. This honours criterion 5's split: the normalising
client serves well-formed reference traffic; raw connection control lives in the
raw layer.]
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from scan_primitives import ScanClient, Scope

__all__ = ["BaselineResponse", "BaselineClient"]


@dataclass(slots=True)
class BaselineResponse:
    """A well-formed reference response fetched via scan-primitives.

    Attributes:
        status: HTTP status code.
        body: Response body bytes (untrusted data).
        url: Final URL fetched.
        request_line: The recorded request method + URL (evidence).
    """

    status: int
    body: bytes
    url: str
    request_line: str = ""

    @property
    def signature(self) -> tuple[int, bytes]:
        """The (status, body) tuple the differential stage compares against."""
        return (self.status, self.body)


class BaselineClient:
    """Well-formed baseline/differential request client over scan-primitives.

    Thin, scope-enforcing wrapper around :class:`scan_primitives.ScanClient`.
    """

    def __init__(
        self,
        scope: Scope,
        *,
        rate_limit: float | None = None,
        proxy: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._scope = scope
        self._rate_limit = rate_limit
        self._proxy = proxy
        self._timeout = timeout

    async def afetch(
        self, url: str, method: str = "GET", **kwargs: Any
    ) -> BaselineResponse:
        """Fetch a well-formed baseline/differential response (async).

        Scope is enforced by ScanClient before any egress; an out-of-scope
        ``url`` raises ``OutOfScopeError`` and no socket is opened.
        """
        async with ScanClient(
            self._scope,
            rate_limit=self._rate_limit,
            proxy=self._proxy,
            timeout=self._timeout,
        ) as client:
            resp = await client.request(method, url, **kwargs)
            rec = client.requests[-1] if client.requests else None
            return BaselineResponse(
                status=resp.status_code,
                body=resp.content,
                url=str(resp.url),
                request_line=f"{rec.method} {rec.url}" if rec else f"{method} {url}",
            )

    def fetch(self, url: str, method: str = "GET", **kwargs: Any) -> BaselineResponse:
        """Synchronous baseline fetch (drives the async client under asyncio.run).

        SAFETY: scope is enforced before egress by the underlying ScanClient.
        """
        return asyncio.run(self.afetch(url, method, **kwargs))
