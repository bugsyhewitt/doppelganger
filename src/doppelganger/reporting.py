"""HackerOne-markdown output for doppelganger, built on the shared h1-reporter lib.

doppelganger's internal :class:`doppelganger.findings.Finding` is desync-shaped
(technique / discrepancy / timing delta / confirmation status). The HackerOne
submission body is not doppelganger's concern -- that formatting lives in the
suite-wide ``h1_reporter`` library so every necromancer tool produces a
consistent report. This module is the thin adapter that maps a doppelganger
finding into an ``h1_reporter.Finding`` and renders it.

doppelganger is the 2nd real adopter of ``h1-reporter`` after ferryman.

**R5 (untrusted input):** evidence values come from the target. They are echoed
into the report as fenced text (data), never interpreted.
"""

from __future__ import annotations

from typing import Iterable

from h1_reporter import Finding as H1Finding
from h1_reporter import render_h1md

from doppelganger.findings import Finding

# The business-impact framing for a confirmed HTTP request-smuggling desync.
_IMPACT = (
    "An HTTP/1.1 desync lets an attacker prepend bytes to another user's "
    "request on a shared front-end/back-end connection. Depending on the "
    "target this enables request queue poisoning, credential/session capture, "
    "cache poisoning, and security-control bypass (e.g. reaching internal-only "
    "paths) -- typically a high-to-critical finding on any program that fronts "
    "an origin with a reverse proxy or CDN."
)

_CANDIDATE_NOTE = (
    "This is a *candidate* raised on a timing signal only; it has not yet been "
    "upgraded to a confirmed desync by a differential response. Treat as "
    "unconfirmed until reproduced."
)


def _description(f: Finding) -> str:
    confirmation = f.evidence.get("confirmation", "candidate")
    variant = f" (variant: {f.variant})" if f.variant else ""
    parts = [
        f"{f.vector} HTTP/1.1 request-smuggling desync{variant} against "
        f"`{f.target}` -- status: **{confirmation}**."
    ]
    delta = f.evidence.get("timing_delta_ms")
    if delta is not None:
        parts.append(f"Timing delta observed: {delta} ms.")
    if confirmation != "confirmed":
        parts.append(_CANDIDATE_NOTE)
    return " ".join(parts)


def _reproduction_steps(f: Finding) -> list[str]:
    steps: list[str] = []
    repro = f.evidence.get("reproduction")
    steps.append(
        f"Send the {f.vector} probe below to `{f.target}` through a byte-exact "
        f"raw HTTP/1.1 sender (no header normalisation)."
    )
    if repro:
        steps.append(f"Probe payload:\n{repro}")
    steps.append(
        "Compare the follow-up response against the well-formed baseline; a "
        "materially different response confirms the back-end mis-parsed the "
        "smuggled prefix."
    )
    return steps


def _evidence_blocks(f: Finding) -> list[str]:
    """Serialise the evidence dict into fenced-block strings for the report."""
    blocks: list[str] = []
    request = f.evidence.get("request")
    if request:
        blocks.append(f"request:\n{request}")
    response = f.evidence.get("response")
    if response:
        blocks.append(f"response:\n{response}")
    scalar = {
        k: f.evidence[k]
        for k in ("timing_delta_ms", "confirmation", "connection_reuse", "discrepancy")
        if k in f.evidence
    }
    if scalar:
        blocks.append("\n".join(f"{k}: {v}" for k, v in scalar.items()))
    return blocks


def _to_h1_finding(f: Finding) -> H1Finding:
    """Map one doppelganger finding into the shared h1_reporter Finding shape."""
    return H1Finding(
        title=f.title or f"{f.vector} desync",
        severity=f.severity,
        description=_description(f),
        reproduction_steps=_reproduction_steps(f),
        business_impact=_IMPACT,
        evidence=_evidence_blocks(f),
    )


def to_h1md(findings: Iterable[Finding]) -> str:
    """Render doppelganger findings to HackerOne-flavored markdown."""
    mapped = [_to_h1_finding(f) for f in findings]
    return render_h1md(mapped, title="doppelganger HTTP desync findings")
