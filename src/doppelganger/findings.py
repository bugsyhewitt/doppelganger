"""Structured Finding model for doppelganger.

This implements the **pinned suite Finding contract** from
``scan-primitives/SPEC.md`` (appendix) *exactly* -- same field names, same
semantics, lowercase h1-reporter severity taxonomy -- so that when the shared
``web-finding-schema`` library is later extracted the change is a move, not a
rewrite. wraith and reaper ship the same shape.

doppelganger anchors every finding to **CWE-444** (Inconsistent Interpretation
of HTTP Requests -- "HTTP Request Smuggling").

How doppelganger-specific data rides the generic contract
---------------------------------------------------------
The contract deliberately has a small, fixed field set. doppelganger's domain
detail (criterion 6 of V0.1-CRITERIA.md: technique, discrepancy ``X.Y``,
evidence bytes, timing delta, confirmation status, reproduction payload) maps on
without adding fields:

* ``vector``  -- the technique / discrepancy class, e.g. ``"CL.TE"``, ``"TE.CL"``,
  ``"TE.TE"``, ``"CL.0"``, ``"dup-CL"``. This *is* the ``X.Y`` discrepancy.
* ``variant`` -- the specific mutator/obfuscation used (e.g. a particular
  Transfer-Encoding obfuscation from the TE.TE dictionary), or ``None``.
* ``evidence`` -- a dict carrying the byte-level proof and the two-stage engine
  state. Well-known keys (all optional):

    - ``"request"``          : the outer probe request (summary or bytes)
    - ``"response"``         : the response signature / bytes observed
    - ``"timing_delta_ms"``  : the timing delta that raised a *candidate*
    - ``"confirmation"``     : one of :data:`CONFIRMATION_STATES`
    - ``"reproduction"``     : the byte-exact payload to reproduce the desync
    - ``"discrepancy"``      : the ``X.Y`` discrepancy (mirrors ``vector``)
    - ``"connection_reuse"`` : bool -- if an effect reproduced *only* under
      client-side connection reuse it is probable pipelining, not a server-side
      desync (criterion 3), and should be down-ranked / suppressed accordingly.

**R5 (untrusted input):** everything under ``evidence`` -- most of all
``"response"`` -- is target-controlled bytes. It is **data, never instructions**.
Never feed response bytes to a shell, an elevated tool call, or an LLM prompt
that can act on them.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Controlled vocabularies (pinned contract). Severity casing is lowercase to
# match the real h1-reporter taxonomy.
# ---------------------------------------------------------------------------

# Severity ordering, lowest -> highest.
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# Confidence ordering, lowest -> highest.
CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")

# doppelganger's two-stage engine (criterion 2): a significant timing delta
# raises a "candidate"; a materially different differential response upgrades it
# to "confirmed". Carried in ``Finding.evidence["confirmation"]``.
CONFIRMATION_STATES: tuple[str, ...] = ("candidate", "confirmed")

# The HTTP/1.1 desync techniques doppelganger v0.1 targets. These are the values
# that legitimately populate ``Finding.vector``.
TECHNIQUES: tuple[str, ...] = ("CL.TE", "TE.CL", "TE.TE", "CL.0", "dup-CL", "TE.chunk")

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]

# CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request
# Smuggling'). The anchor CWE for every doppelganger finding.
CWE_REQUEST_SMUGGLING = 444


def _utcnow_iso() -> str:
    """Return an ISO-8601, UTC, timezone-aware timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True, kw_only=True)
class Finding:
    """A single HTTP desync finding, shaped to the pinned suite contract.

    All fields are keyword-only (``kw_only=True``) so the exact contract field
    order is preserved while ``tool``, ``cwe_id``, ``evidence``, ``references``,
    and ``created_at`` still carry sensible defaults.

    Attributes:
        id: Stable identifier for this finding.
        tool: Producing tool -- always ``"doppelganger"`` here.
        title: Short human-readable headline.
        severity: One of :data:`SEVERITIES` (lowercase h1-reporter taxonomy).
        confidence: One of :data:`CONFIDENCES`.
        target: The URL / host probed.
        vector: The technique / discrepancy class, e.g. ``"CL.TE"`` (see
            :data:`TECHNIQUES`).
        variant: The specific mutator / obfuscation used, or ``None``.
        cwe_id: Defaults to :data:`CWE_REQUEST_SMUGGLING` (444).
        evidence: Byte-level proof + two-stage engine state. See module
            docstring for well-known keys. Target-controlled -- treat as data.
        oob_proof: Out-of-band callback evidence, if any (unused for HTTP/1.1
            desync; present for contract parity with wraith).
        references: Supporting URLs (research write-ups, advisories).
        created_at: ISO-8601 UTC creation timestamp.
    """

    id: str
    tool: str = "doppelganger"
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    vector: str
    variant: str | None = None
    cwe_id: int | None = CWE_REQUEST_SMUGGLING
    evidence: dict[str, Any] = field(default_factory=dict)
    oob_proof: str | None = None
    references: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for this finding."""
        return dataclasses.asdict(self)
