"""Tests for the doppelganger CLI wired end-to-end against the mock pair."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

import mockpair
from doppelganger.cli import build_parser, main


def _scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\n")
    return str(p)


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


def test_scope_file_is_required(tmp_path, capsys):
    """No --scope-file -> exit 3 (scope is enforced before any probe)."""
    code = main(["http://127.0.0.1:1/"])
    assert code == 3
    assert "scope" in capsys.readouterr().err.lower()


def test_no_target_and_no_target_file_exits_2(tmp_path, capsys):
    """Neither positional URL nor --target-file -> argparse error (exit 2)."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--scope-file", _scope_file(tmp_path)])
    assert exc_info.value.code == 2


def test_target_and_target_file_mutually_exclusive(tmp_path, capsys):
    """Providing both a URL and --target-file -> argparse error (exit 2)."""
    tf = tmp_path / "targets.txt"
    tf.write_text("http://127.0.0.1:1/\n")
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "http://127.0.0.1:1/",
                "--target-file", str(tf),
                "--scope-file", _scope_file(tmp_path),
            ]
        )
    assert exc_info.value.code == 2


def test_invalid_scope_file_exits_3(tmp_path, capsys):
    """A scope file that doesn't exist -> exit 3."""
    code = main(
        [
            "http://127.0.0.1:1/",
            "--scope-file", "/nonexistent/scope.txt",
        ]
    )
    assert code == 3
    assert "scope" in capsys.readouterr().err.lower()


def test_missing_target_file_exits_3(tmp_path, capsys):
    """--target-file pointing to a nonexistent file -> exit 3."""
    code = main(
        [
            "--scope-file", _scope_file(tmp_path),
            "--target-file", "/nonexistent/targets.txt",
        ]
    )
    assert code == 3


def test_empty_target_file_exits_3(tmp_path, capsys):
    """--target-file containing only comments -> exit 3."""
    tf = tmp_path / "empty.txt"
    tf.write_text("# only a comment\n\n")
    code = main(
        [
            "--scope-file", _scope_file(tmp_path),
            "--target-file", str(tf),
        ]
    )
    assert code == 3


# ---------------------------------------------------------------------------
# JSON findings
# ---------------------------------------------------------------------------


def test_cli_produces_confirmed_finding_json(tmp_path, capsys):
    """A CL.TE server-side desync is confirmed and emitted as JSON; exit 1."""
    with mockpair.clte_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 1  # findings -> non-zero exit
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] == "doppelganger"
    assert doc["finding_count"] == 1
    finding = doc["findings"][0]
    assert finding["vector"] == "CL.TE"
    assert finding["evidence"]["confirmation"] == "confirmed"
    assert finding["cwe_id"] == 444


def test_json_output_contains_summary_block(tmp_path, capsys):
    """JSON output always contains a 'summary' key with scan stats."""
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
    s = doc["summary"]
    assert s["targets_scanned"] >= 1
    assert "finding_count" in s
    assert "elapsed_ms" in s


def test_clean_target_exits_0(tmp_path, capsys):
    """A robust (non-vulnerable) server -> exit 0 and finding_count == 0."""
    with mockpair.robust_pair() as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 0


def test_cli_pipelining_target_reports_nothing(tmp_path, capsys):
    """A pipeline-only target yields no findings (exit 0) but records suppression."""
    with mockpair.clte_pair("pipeline_only") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 0  # no desync findings
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 0
    assert len(doc["suppressed_pipelining"]) == 1


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


def test_cli_sarif_output(tmp_path, capsys):
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
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "doppelganger"
    assert doc["runs"][0]["results"][0]["ruleId"] == "doppelganger/CL.TE"


def test_cli_sarif_contains_scan_summary(tmp_path, capsys):
    """SARIF output embeds scan summary in run properties."""
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
    props = doc["runs"][0].get("properties", {})
    assert "doppelganger/scanSummary" in props


def test_cli_h1md_output(tmp_path, capsys):
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
    assert "CL.TE" in out


def test_cli_h1md_has_scan_summary_section(tmp_path, capsys):
    """h1md output appends a '## Scan Summary' table."""
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
    assert "Scan Summary" in out


# ---------------------------------------------------------------------------
# Scope and target errors
# ---------------------------------------------------------------------------


def test_cli_out_of_scope_target_exits_3(tmp_path, capsys):
    """A target outside the scope file -> exit 3, no traffic."""
    code = main(
        [
            "http://169.254.169.254/",  # cloud metadata, not in scope
            "--scope-file", _scope_file(tmp_path),
            "--technique", "CL.TE",
            "--timeout", "0.4",
        ]
    )
    assert code == 3
    assert "scope" in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# Flags: --safe, --reuse-connection, --retries, --technique
# ---------------------------------------------------------------------------


def test_safe_flag_still_confirms_desync(tmp_path, capsys):
    """--safe mode should still detect and confirm a real desync."""
    with mockpair.clte_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--safe",
                "--timeout", "0.4",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"][0]["evidence"]["confirmation"] == "confirmed"


def test_no_reuse_connection_flag(tmp_path, capsys):
    """--no-reuse-connection is accepted and produces a clean scan on robust server."""
    with mockpair.robust_pair() as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--no-reuse-connection",
                "--timeout", "0.4",
            ]
        )
    assert code == 0


def test_technique_tecl_runs_correctly(tmp_path, capsys):
    """--technique TE.CL selects only the TE.CL probe."""
    with mockpair.tecl_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "TE.CL",
                "--timeout", "0.4",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"][0]["vector"] == "TE.CL"


def test_retries_zero_is_accepted(tmp_path, capsys):
    """--retries 0 (the default) is accepted without error."""
    with mockpair.robust_pair() as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--retries", "0",
                "--timeout", "0.4",
            ]
        )
    assert code == 0


# ---------------------------------------------------------------------------
# --target-file
# ---------------------------------------------------------------------------


def test_target_file_scans_multiple_targets(tmp_path, capsys):
    """--target-file: clean target followed by desync target -> finding_count >= 1."""
    with mockpair.robust_pair() as clean_srv, \
            mockpair.clte_pair("server_desync") as vuln_srv:
        tf = tmp_path / "targets.txt"
        tf.write_text(f"{clean_srv.base_url}\n{vuln_srv.base_url}\n")
        code = main(
            [
                "--scope-file", _scope_file(tmp_path),
                "--target-file", str(tf),
                "--technique", "CL.TE",
                "--timeout", "0.4",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] >= 1
    assert doc["summary"]["targets_scanned"] == 2


def test_target_file_skips_comment_lines(tmp_path, capsys):
    """Lines starting with '#' in the target file are ignored."""
    with mockpair.clte_pair("server_desync") as srv:
        tf = tmp_path / "targets.txt"
        tf.write_text(f"# this is a comment\n{srv.base_url}\n")
        code = main(
            [
                "--scope-file", _scope_file(tmp_path),
                "--target-file", str(tf),
                "--technique", "CL.TE",
                "--timeout", "0.4",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["targets_scanned"] == 1


# ---------------------------------------------------------------------------
# Parser structure
# ---------------------------------------------------------------------------


def test_build_parser_returns_argparse_parser():
    """build_parser() returns a configured ArgumentParser."""
    parser = build_parser()
    assert parser.prog == "doppelganger"


def test_parser_default_technique_is_all():
    parser = build_parser()
    args = parser.parse_args(["http://example.com/", "--scope-file", "s.txt"])
    assert args.technique == "all"


def test_parser_default_format_is_json():
    parser = build_parser()
    args = parser.parse_args(["http://example.com/", "--scope-file", "s.txt"])
    assert args.output_format == "json"


def test_parser_default_timeout():
    parser = build_parser()
    args = parser.parse_args(["http://example.com/", "--scope-file", "s.txt"])
    assert args.timeout == 10.0
