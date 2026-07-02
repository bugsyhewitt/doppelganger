"""Tests for the doppelganger CLI wired end-to-end against the mock pair."""

from __future__ import annotations

import json

import pytest

import mockpair
from doppelganger.cli import main


def _scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\n")
    return str(p)


def test_scope_file_is_required(tmp_path, capsys):
    """No --scope-file -> exit 3 (scope is enforced before any probe)."""
    code = main(["http://127.0.0.1:1/"])
    assert code == 3
    assert "scope" in capsys.readouterr().err.lower()


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
