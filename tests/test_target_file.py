"""v0.7 acceptance tests: --target-file multi-target scanning.

Covers:
* _load_target_file parses comments, blank lines, and valid URLs correctly
* _load_target_file raises OSError on missing file
* _load_target_file returns empty list for an all-comment/all-blank file
* main() rejects providing --target-file and a positional URL simultaneously
* main() requires at least one of target URL or --target-file
* main() exits 3 if target file cannot be read (missing file)
* main() exits 3 if target file contains no targets (all comments/blanks)
* Single target via --target-file: same behaviour as positional URL
* Multi-target: findings aggregated across two targets, exit 1
* Multi-target: clean across all targets, exit 0
* Multi-target: out-of-scope target skipped, in-scope target still scanned
* Multi-target clean + no-scope-error: exit 0 (not 3)
* --version still works (no regression from target-file addition)
"""

from __future__ import annotations

import json

import pytest

import mockpair
from doppelganger.cli import _load_target_file, build_parser, main


# ---------------------------------------------------------------------------
# _load_target_file unit tests
# ---------------------------------------------------------------------------


def test_load_target_file_basic(tmp_path):
    """Parses plain URLs and strips trailing whitespace."""
    f = tmp_path / "targets.txt"
    f.write_text("http://a.example.com/\nhttp://b.example.com/\n")
    assert _load_target_file(str(f)) == [
        "http://a.example.com/",
        "http://b.example.com/",
    ]


def test_load_target_file_skips_comments(tmp_path):
    """Lines starting with '#' are ignored."""
    f = tmp_path / "targets.txt"
    f.write_text(
        "# production scope\n"
        "http://a.example.com/\n"
        "# staging\n"
        "http://b.example.com/\n"
    )
    result = _load_target_file(str(f))
    assert result == ["http://a.example.com/", "http://b.example.com/"]
    assert all(not t.startswith("#") for t in result)


def test_load_target_file_skips_blank_lines(tmp_path):
    """Blank and whitespace-only lines are ignored."""
    f = tmp_path / "targets.txt"
    f.write_text("http://a.example.com/\n\n   \nhttp://b.example.com/\n")
    assert _load_target_file(str(f)) == [
        "http://a.example.com/",
        "http://b.example.com/",
    ]


def test_load_target_file_strips_trailing_whitespace(tmp_path):
    """Trailing spaces and tabs are stripped from each URL."""
    f = tmp_path / "targets.txt"
    f.write_text("http://a.example.com/   \n")
    assert _load_target_file(str(f)) == ["http://a.example.com/"]


def test_load_target_file_empty_result_for_all_comments(tmp_path):
    """An all-comment file yields an empty list (not an error)."""
    f = tmp_path / "targets.txt"
    f.write_text("# nothing here\n# more comments\n\n")
    assert _load_target_file(str(f)) == []


def test_load_target_file_raises_oserror_on_missing_file(tmp_path):
    """OSError when the file does not exist."""
    with pytest.raises(OSError):
        _load_target_file(str(tmp_path / "nonexistent.txt"))


# ---------------------------------------------------------------------------
# CLI argument validation
# ---------------------------------------------------------------------------


def test_parser_accepts_target_file():
    """--target-file is accepted and stored in args.target_file."""
    parser = build_parser()
    args = parser.parse_args(["--target-file", "/tmp/t.txt", "--scope-file", "s.txt"])
    assert args.target_file == "/tmp/t.txt"
    assert args.target is None


def test_main_rejects_target_and_target_file_together(tmp_path, capsys):
    """Providing both positional URL and --target-file is a usage error (exit 2)."""
    f = tmp_path / "t.txt"
    f.write_text("http://127.0.0.1/\n")
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "http://127.0.0.1/",
                "--target-file", str(f),
                "--scope-file", "/dev/null",
            ]
        )
    assert exc.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().err.lower()


def test_main_requires_target_or_target_file(capsys):
    """Neither target nor --target-file -> usage error (exit 2)."""
    with pytest.raises(SystemExit) as exc:
        main(["--scope-file", "/dev/null"])
    assert exc.value.code == 2


def test_main_exits_3_for_missing_target_file(tmp_path, capsys):
    """--target-file pointing at a non-existent file -> exit 3."""
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    code = main(
        [
            "--target-file", str(tmp_path / "nonexistent.txt"),
            "--scope-file", str(scope),
            "--technique", "CL.TE",
        ]
    )
    assert code == 3
    assert "could not read target file" in capsys.readouterr().err.lower()


def test_main_exits_3_for_empty_target_file(tmp_path, capsys):
    """--target-file with no usable targets -> exit 3."""
    scope = tmp_path / "scope.txt"
    scope.write_text("127.0.0.1\n")
    tfile = tmp_path / "t.txt"
    tfile.write_text("# only comments\n\n")
    code = main(
        [
            "--target-file", str(tfile),
            "--scope-file", str(scope),
            "--technique", "CL.TE",
        ]
    )
    assert code == 3
    err = capsys.readouterr().err.lower()
    assert "no targets" in err or "contains no targets" in err


# ---------------------------------------------------------------------------
# Single-target via --target-file (functional equivalence with positional URL)
# ---------------------------------------------------------------------------


def _scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\n")
    return str(p)


def test_single_target_via_target_file_confirmed_desync(tmp_path, capsys):
    """--target-file with one URL scans that URL and exits 1 when findings exist."""
    with mockpair.clte_pair("server_desync") as srv:
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"{srv.base_url}\n# comment\n\n")
        code = main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 1
    assert doc["findings"][0]["vector"] == "CL.TE"
    assert doc["findings"][0]["evidence"]["confirmation"] == "confirmed"


def test_single_target_via_target_file_clean(tmp_path, capsys):
    """--target-file with one non-vulnerable target exits 0 and emits zero findings."""
    with mockpair.robust_pair() as srv:
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"{srv.base_url}\n")
        code = main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 0


# ---------------------------------------------------------------------------
# Multi-target: findings aggregated
# ---------------------------------------------------------------------------


def test_multi_target_findings_aggregated(tmp_path, capsys):
    """Two vulnerable targets in a target file each produce a finding, exit 1."""
    with (
        mockpair.clte_pair("server_desync") as srv1,
        mockpair.clte_pair("server_desync") as srv2,
    ):
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"{srv1.base_url}\n{srv2.base_url}\n")
        code = main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    # Both targets should contribute findings; each clte_pair produces >= 1.
    assert doc["finding_count"] >= 2
    targets = {f["target"] for f in doc["findings"]}
    assert len(targets) == 2


def test_multi_target_all_clean_exits_0(tmp_path, capsys):
    """Two clean targets -> exit 0, zero findings."""
    with (
        mockpair.robust_pair() as srv1,
        mockpair.robust_pair() as srv2,
    ):
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"{srv1.base_url}\n{srv2.base_url}\n")
        code = main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 0


def test_multi_target_out_of_scope_skipped_in_scope_scanned(tmp_path, capsys):
    """An out-of-scope URL in the list is skipped; in-scope URLs still scanned."""
    with mockpair.clte_pair("server_desync") as srv:
        tfile = tmp_path / "t.txt"
        # 169.254.169.254 is not in scope (scope = 127.0.0.1 only).
        tfile.write_text(
            f"http://169.254.169.254/\n"
            f"{srv.base_url}\n"
        )
        code = main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    # The in-scope server produced a finding -> exit 1.
    assert code == 1
    out = capsys.readouterr()
    doc = json.loads(out.out)
    assert doc["finding_count"] >= 1
    # The out-of-scope error was printed to stderr.
    assert "scope" in out.err.lower()


def test_multi_target_suppressed_pipelining_aggregated(tmp_path, capsys):
    """Suppressed pipelining entries from multiple targets are aggregated."""
    with (
        mockpair.clte_pair("pipeline_only") as srv1,
        mockpair.clte_pair("pipeline_only") as srv2,
    ):
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"{srv1.base_url}\n{srv2.base_url}\n")
        code = main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "0.4",
            ]
        )
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 0
    # Each pipeline-only server contributes one suppressed entry.
    assert len(doc["suppressed_pipelining"]) == 2


# ---------------------------------------------------------------------------
# Output format regression (single target, --target-file)
# ---------------------------------------------------------------------------


def test_target_file_sarif_output(tmp_path, capsys):
    """--target-file works with --format sarif (SARIF 2.1.0 envelope emitted)."""
    with mockpair.clte_pair("server_desync") as srv:
        tfile = tmp_path / "t.txt"
        tfile.write_text(f"{srv.base_url}\n")
        main(
            [
                "--target-file", str(tfile),
                "--scope-file", _scope_file(tmp_path),
                "--technique", "CL.TE",
                "--format", "sarif",
                "--timeout", "0.4",
            ]
        )
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "doppelganger"


# ---------------------------------------------------------------------------
# --version regression (no breakage from target-file addition)
# ---------------------------------------------------------------------------


def test_version_flag_still_works(capsys):
    """--version exits 0 and prints the version string (no regression)."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "doppelganger" in capsys.readouterr().out
