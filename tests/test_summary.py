"""Tests for scan summary statistics (v0.9).

The summary is embedded in every output format:
  - JSON:  top-level ``"summary"`` key in the doppelganger output document.
  - SARIF: ``runs[0]["properties"]["doppelganger/scanSummary"]``.
  - h1md:  ``## Scan Summary`` table appended after findings.

Covers:
* JSON summary present with correct keys and types
* JSON summary ``targets_scanned`` matches the actual number of scanned targets
* JSON summary ``targets_errored`` counts out-of-scope errors
* JSON summary ``elapsed_ms`` is a non-negative float
* JSON summary ``finding_count`` mirrors top-level ``finding_count``
* JSON summary ``suppressed_pipelining_count`` matches suppressed list length
* JSON summary ``findings_by_severity`` is present only when findings exist
* SARIF output embeds summary in ``runs[0]["properties"]``
* h1md output includes a ``## Scan Summary`` section
* h1md summary section contains the targets-scanned count
* Multi-target: ``targets_scanned`` reflects two scanned targets
* Out-of-scope + in-scope mix: both ``targets_scanned`` and ``targets_errored``
  are reported correctly
"""

from __future__ import annotations

import json

import pytest

import mockpair
from doppelganger.cli import main


def _scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\n")
    return str(p)


# ---------------------------------------------------------------------------
# JSON format — summary block
# ---------------------------------------------------------------------------


def test_json_summary_present(tmp_path, capsys):
    """JSON output always includes a ``summary`` key."""
    with mockpair.clte_pair("server_desync") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert "summary" in doc


def test_json_summary_required_keys(tmp_path, capsys):
    """Summary contains all required keys regardless of whether findings exist."""
    with mockpair.robust_pair() as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    summary = doc["summary"]
    for key in (
        "targets_scanned",
        "targets_errored",
        "finding_count",
        "suppressed_pipelining_count",
        "elapsed_ms",
    ):
        assert key in summary, f"Missing key: {key!r}"


def test_json_summary_targets_scanned_single(tmp_path, capsys):
    """Single target scan: ``targets_scanned`` == 1."""
    with mockpair.robust_pair() as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["targets_scanned"] == 1
    assert doc["summary"]["targets_errored"] == 0


def test_json_summary_targets_scanned_multi(tmp_path, capsys):
    """Two targets via --target-file: ``targets_scanned`` == 2."""
    with (
        mockpair.robust_pair() as srv1,
        mockpair.robust_pair() as srv2,
    ):
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"{srv1.base_url}\n{srv2.base_url}\n")
        main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["targets_scanned"] == 2


def test_json_summary_targets_errored_counts_oos(tmp_path, capsys):
    """Out-of-scope target is counted in ``targets_errored``."""
    with mockpair.clte_pair("server_desync") as srv:
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"http://169.254.169.254/\n{srv.base_url}\n")
        main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["targets_scanned"] == 1
    assert doc["summary"]["targets_errored"] == 1


def test_json_summary_elapsed_ms_non_negative(tmp_path, capsys):
    """``elapsed_ms`` is a non-negative number."""
    with mockpair.robust_pair() as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert isinstance(doc["summary"]["elapsed_ms"], (int, float))
    assert doc["summary"]["elapsed_ms"] >= 0


def test_json_summary_finding_count_mirrors_toplevel(tmp_path, capsys):
    """``summary.finding_count`` equals top-level ``finding_count``."""
    with mockpair.clte_pair("server_desync") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["finding_count"] == doc["finding_count"]


def test_json_summary_suppressed_count(tmp_path, capsys):
    """``summary.suppressed_pipelining_count`` reflects suppressed entries."""
    with mockpair.clte_pair("pipeline_only") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["suppressed_pipelining_count"] == len(
        doc["suppressed_pipelining"]
    )


def test_json_summary_findings_by_severity_present_when_findings(tmp_path, capsys):
    """``findings_by_severity`` is present when there are findings."""
    with mockpair.clte_pair("server_desync") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert "findings_by_severity" in doc["summary"]
    sev = doc["summary"]["findings_by_severity"]
    assert isinstance(sev, dict)
    # The total count across severity levels equals finding_count.
    assert sum(sev.values()) == doc["finding_count"]


def test_json_summary_findings_by_severity_absent_when_clean(tmp_path, capsys):
    """``findings_by_severity`` is absent when there are no findings."""
    with mockpair.robust_pair() as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 0
    assert "findings_by_severity" not in doc["summary"]


# ---------------------------------------------------------------------------
# SARIF format — run-level properties
# ---------------------------------------------------------------------------


def test_sarif_run_properties_include_summary(tmp_path, capsys):
    """SARIF ``runs[0]["properties"]`` contains the scan summary."""
    with mockpair.clte_pair("server_desync") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "sarif",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    run = doc["runs"][0]
    assert "properties" in run
    assert "doppelganger/scanSummary" in run["properties"]
    summary = run["properties"]["doppelganger/scanSummary"]
    assert summary["targets_scanned"] == 1
    assert "elapsed_ms" in summary


def test_sarif_summary_finding_count_consistent(tmp_path, capsys):
    """SARIF summary ``finding_count`` equals the number of ``results``."""
    with mockpair.clte_pair("server_desync") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "sarif",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    run = doc["runs"][0]
    summary = run["properties"]["doppelganger/scanSummary"]
    assert summary["finding_count"] == len(run["results"])


# ---------------------------------------------------------------------------
# h1md format — summary section
# ---------------------------------------------------------------------------


def test_h1md_includes_scan_summary_section(tmp_path, capsys):
    """h1md output contains a ``## Scan Summary`` heading."""
    with mockpair.clte_pair("server_desync") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "h1md",
                "--timeout", "0.4",
            ]
        )
    out = capsys.readouterr().out
    assert "## Scan Summary" in out


def test_h1md_summary_contains_targets_scanned(tmp_path, capsys):
    """h1md summary table row shows ``Targets scanned``."""
    with mockpair.robust_pair() as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "h1md",
                "--timeout", "0.4",
            ]
        )
    out = capsys.readouterr().out
    # Summary section should mention targets scanned.
    assert "Targets scanned" in out
    # The count "1" should appear in context (the table row).
    summary_section = out[out.index("## Scan Summary"):]
    assert "1" in summary_section


def test_h1md_still_starts_with_title(tmp_path, capsys):
    """h1md output still begins with the expected title (no regression)."""
    with mockpair.clte_pair("server_desync") as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "h1md",
                "--timeout", "0.4",
            ]
        )
    out = capsys.readouterr().out
    assert out.startswith("# doppelganger HTTP desync findings")


def test_h1md_summary_elapsed_ms_present(tmp_path, capsys):
    """h1md summary table mentions elapsed time."""
    with mockpair.robust_pair() as srv:
        main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "h1md",
                "--timeout", "0.4",
            ]
        )
    out = capsys.readouterr().out
    assert "Elapsed" in out
    assert "ms" in out
