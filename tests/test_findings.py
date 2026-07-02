"""Tests for the doppelganger Finding contract, SARIF 2.1.0, and h1md output.

These are the real, passing tests for the scaffold's implemented layer. The
desync engine is stubbed, so there is nothing to test there yet (see
test_wheel_ship_gate.py for the skipped end-to-end lab TODO).
"""

from __future__ import annotations

import pytest

from doppelganger.findings import (
    CONFIDENCES,
    CONFIRMATION_STATES,
    CWE_REQUEST_SMUGGLING,
    SEVERITIES,
    TECHNIQUES,
    Finding,
)
from doppelganger.reporting import to_h1md
from doppelganger.sarif import SARIF_SCHEMA, SARIF_VERSION, to_sarif


# --------------------------------------------------------------------------- #
# Controlled vocabularies (pinned contract)
# --------------------------------------------------------------------------- #


def test_severities_match_h1_taxonomy():
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")


def test_confidences_are_lowercase_triple():
    assert CONFIDENCES == ("low", "medium", "high")


def test_confirmation_states():
    assert CONFIRMATION_STATES == ("candidate", "confirmed")


def test_techniques_are_the_http1_desync_family():
    assert TECHNIQUES == ("CL.TE", "TE.CL", "TE.TE", "CL.0", "dup-CL")


# --------------------------------------------------------------------------- #
# Finding dataclass -- pinned contract shape & defaults
# --------------------------------------------------------------------------- #


def test_finding_defaults_and_cwe_444(confirmed_finding: Finding):
    f = Finding(
        id="x",
        title="t",
        severity="high",
        confidence="high",
        target="https://h/",
        vector="CL.TE",
    )
    # cwe_id defaults to CWE-444 (HTTP request smuggling).
    assert f.cwe_id == 444 == CWE_REQUEST_SMUGGLING
    # tool defaults to the producing tool.
    assert f.tool == "doppelganger"
    # optional fields default cleanly.
    assert f.variant is None
    assert f.oob_proof is None
    assert f.evidence == {}
    assert f.references == []
    # created_at is auto-populated ISO-8601 (has a 'T' separator).
    assert "T" in f.created_at


def test_finding_has_exactly_the_pinned_contract_fields():
    import dataclasses

    names = {fld.name for fld in dataclasses.fields(Finding)}
    assert names == {
        "id",
        "tool",
        "title",
        "severity",
        "confidence",
        "target",
        "vector",
        "variant",
        "cwe_id",
        "evidence",
        "oob_proof",
        "references",
        "created_at",
    }


def test_finding_to_dict_roundtrips(confirmed_finding: Finding):
    d = confirmed_finding.to_dict()
    assert d["id"] == "dg-0001"
    assert d["tool"] == "doppelganger"
    assert d["vector"] == "CL.TE"
    assert d["cwe_id"] == 444
    assert d["evidence"]["confirmation"] == "confirmed"
    # rebuild from the dict -> equal finding.
    assert Finding(**d) == confirmed_finding


def test_vector_carries_the_discrepancy(candidate_finding: Finding):
    # The X.Y discrepancy rides in `vector`; timing + confirmation ride in
    # evidence -- no extra fields needed on the contract.
    assert candidate_finding.vector == "TE.CL"
    assert candidate_finding.evidence["timing_delta_ms"] == 5200
    assert candidate_finding.evidence["confirmation"] in CONFIRMATION_STATES


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #


def test_to_sarif_is_a_dict_with_211_envelope(sample_findings):
    doc = to_sarif(sample_findings)
    assert isinstance(doc, dict)
    assert doc["version"] == SARIF_VERSION == "2.1.0"
    assert doc["$schema"] == SARIF_SCHEMA
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "doppelganger"


def test_sarif_result_level_and_rank_mapping(confirmed_finding: Finding):
    doc = to_sarif([confirmed_finding])
    result = doc["runs"][0]["results"][0]
    # high -> error, rank 80.
    assert result["level"] == "error"
    assert result["rank"] == 80.0


def test_sarif_rule_id_and_fingerprint_and_location(confirmed_finding: Finding):
    doc = to_sarif([confirmed_finding])
    result = doc["runs"][0]["results"][0]
    # ruleId = "<tool>/<vector-class>"
    assert result["ruleId"] == "doppelganger/CL.TE"
    # partialFingerprints derive from the finding id.
    assert result["partialFingerprints"]["doppelgangerFindingId/v1"] == "dg-0001"
    # locations come from target.
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://target.example.com/"
    # confirmation / timing surfaced in properties.
    assert result["properties"]["confirmation"] == "confirmed"
    assert result["properties"]["cwe"] == "CWE-444"


def test_sarif_low_and_medium_levels():
    lo = Finding(id="a", title="t", severity="info", confidence="low",
                 target="https://h/", vector="CL.0")
    med = Finding(id="b", title="t", severity="medium", confidence="low",
                  target="https://h/", vector="TE.TE")
    results = to_sarif([lo, med])["runs"][0]["results"]
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["doppelganger/CL.0"]["level"] == "note"
    assert by_rule["doppelganger/TE.TE"]["level"] == "warning"


def test_sarif_one_rule_per_distinct_vector(sample_findings):
    rules = to_sarif(sample_findings)["runs"][0]["tool"]["driver"]["rules"]
    ids = {r["id"] for r in rules}
    assert ids == {"doppelganger/CL.TE", "doppelganger/TE.CL"}


# --------------------------------------------------------------------------- #
# HackerOne markdown (via h1-reporter)
# --------------------------------------------------------------------------- #


def test_to_h1md_renders_markdown(sample_findings):
    md = to_h1md(sample_findings)
    assert md.startswith("# doppelganger HTTP desync findings")
    assert "**Total findings:** 2" in md
    # most-severe first: the HIGH CL.TE finding precedes the MEDIUM candidate.
    assert md.index("CL.TE") < md.index("TE.CL")
    # severity is rendered upper-case by h1-reporter.
    assert "**Severity:** HIGH" in md


def test_h1md_candidate_gets_unconfirmed_note(candidate_finding: Finding):
    md = to_h1md([candidate_finding])
    assert "unconfirmed" in md.lower()


def test_h1md_empty_is_valid(_=None):
    md = to_h1md([])
    assert "**Total findings:** 0" in md
