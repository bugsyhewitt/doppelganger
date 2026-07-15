"""SARIF 2.1.0 output for doppelganger.

SARIF (Static Analysis Results Interchange Format) is the standard machine
output for security scanners: GitHub's Security tab, the VS Code Problems panel,
and most CI SAST dashboards ingest it natively. Emitting SARIF lets doppelganger
findings surface alongside professional tooling rather than only in a HackerOne
report.

Shape follows the pinned suite contract (``scan-primitives/SPEC.md``) and mirrors
ferryman/ossuary's existing 2.1.0 structure:

* ``severity`` -> ``level``: ``critical``/``high`` -> ``error``, ``medium`` ->
  ``warning``, ``low``/``info`` -> ``note``.
* a 0-100 numeric ``rank`` preserves doppelganger's finer ordering for consumers
  (e.g. GitHub) that surface it.
* ``ruleId = "<tool>/<vector-class>"`` -- e.g. ``doppelganger/CL.TE``. The vector
  *is* the discrepancy class for HTTP desync.
* ``partialFingerprints`` are derived from the finding ``id`` so re-runs
  de-duplicate.
* ``result.locations`` come from the finding ``target`` (a URL / host), carried
  as the artifact-location URI.

``to_sarif`` returns a ``dict`` (per the pinned contract); callers ``json.dumps``
it when they need a document string.
"""

from __future__ import annotations

from typing import Any, Iterable

from doppelganger import __version__
from doppelganger.findings import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/bugsyhewitt/doppelganger"

# severity -> SARIF result.level (the coarse SARIF enum).
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# severity -> SARIF rank (0.0 best .. 100.0 worst; higher = more severe).
_RANK_BY_SEVERITY = {
    "critical": 100.0,
    "high": 80.0,
    "medium": 50.0,
    "low": 20.0,
    "info": 5.0,
}

# evidence keys that are safe, compact scalars worth surfacing in SARIF
# properties. Bulk request/response bytes stay out of the machine document.
_SCALAR_EVIDENCE_KEYS = (
    "confirmation",
    "timing_delta_ms",
    "discrepancy",
    "connection_reuse",
)


def _level_for(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get(severity, "warning")


def _rank_for(severity: str) -> float:
    return _RANK_BY_SEVERITY.get(severity, 50.0)


def _rule_id(f: Finding) -> str:
    """Stable rule id: ``<tool>/<vector-class>`` (e.g. ``doppelganger/CL.TE``)."""
    return f"{f.tool}/{f.vector}"


def _result_for(f: Finding) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "severity": f.severity,
        "confidence": f.confidence,
        "vector": f.vector,
    }
    if f.variant is not None:
        properties["variant"] = f.variant
    if f.cwe_id is not None:
        properties["cwe"] = f"CWE-{f.cwe_id}"
    for key in _SCALAR_EVIDENCE_KEYS:
        if key in f.evidence:
            properties[key] = f.evidence[key]

    return {
        "ruleId": _rule_id(f),
        "level": _level_for(f.severity),
        "rank": _rank_for(f.severity),
        "message": {"text": f.title or _rule_id(f)},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f.target}}}
        ],
        "partialFingerprints": {"doppelgangerFindingId/v1": f.id},
        "properties": properties,
    }


def _rules_for(findings: list[Finding]) -> list[dict[str, Any]]:
    """One SARIF reportingDescriptor per distinct rule id, sorted for stability."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(_rule_id(f), f)
    rules: list[dict[str, Any]] = []
    for rule_id in sorted(seen):
        f = seen[rule_id]
        descriptor: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id.replace("/", "_").replace(".", "_"),
            "shortDescription": {"text": f"HTTP/1.1 desync: {f.vector}"},
            "defaultConfiguration": {"level": _level_for(f.severity)},
            "properties": {"vector": f.vector},
        }
        if f.cwe_id is not None:
            # SARIF taxa/tags surface the CWE anchor to consumers.
            descriptor["properties"]["cwe"] = f"CWE-{f.cwe_id}"
            descriptor["properties"]["tags"] = [f"external/cwe/cwe-{f.cwe_id}"]
        rules.append(descriptor)
    return rules


def to_sarif(
    findings: Iterable[Finding],
    *,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render doppelganger findings to a SARIF 2.1.0 document (as a ``dict``).

    Parameters
    ----------
    findings:
        The findings to serialise.
    stats:
        Optional scan-summary statistics dict (from :func:`doppelganger.cli.run`).
        When provided it is embedded in ``runs[0]["properties"]`` under the key
        ``"doppelganger/scanSummary"``, making it machine-readable to GitHub Code
        Scanning consumers and CI dashboards that surface run-level metadata.
    """
    findings = list(findings)
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "doppelganger",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": _rules_for(findings),
            }
        },
        "results": [_result_for(f) for f in findings],
    }
    if stats is not None:
        run["properties"] = {"doppelganger/scanSummary": stats}
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
