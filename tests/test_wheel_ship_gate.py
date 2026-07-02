"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via ``pytest -m "not ship_gate"``. Runs in the full v0.1 suite.

Mirrors ferryman's ship gate. The final step drives the *installed* CLI against
the in-process raw-socket mock pair and asserts it emits a confirmed CL.TE
finding -- the end-to-end "the shipped wheel actually detects a desync" proof.
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
from pathlib import Path

import pytest

import mockpair

REPO_ROOT = Path(__file__).resolve().parent.parent
# Sibling shared libs, installed locally so the git-URL deps in pyproject.toml
# need not be fetched from GitHub during the ship gate.
_SIBLINGS = [REPO_ROOT.parent / "h1-reporter", REPO_ROOT.parent / "scan-primitives"]


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    out = tmp_path / "build-out"
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=REPO_ROOT,
    )
    wheels = list(out.glob("doppelganger-0.1.0-*.whl"))
    sdists = list(out.glob("doppelganger-0.1.0.tar.gz"))
    assert wheels, f"wheel not built; got: {list(out.iterdir())}"
    assert sdists, f"sdist not built; got: {list(out.iterdir())}"
    test_wheel_builds_cleanly._wheel = wheels[0]


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(tmp_path):
    """`pip install <wheel>` into a brand-new venv resolves the entry-point.

    Resolves the declared runtime deps (httpx, h1-reporter). In an offline/CI
    context without reachability to the h1-reporter git dep, this is where a
    local `pip install ../h1-reporter` pre-step would go.
    """
    wheel = getattr(test_wheel_builds_cleanly, "_wheel", None)
    if wheel is None:
        pytest.skip("preceding build test did not produce a wheel")

    missing = [str(s) for s in _SIBLINGS if not s.exists()]
    if missing:
        pytest.skip(f"local sibling libs not found: {missing}")

    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"

    # Install the shared libs locally first (pulls httpx), then the wheel with
    # --no-deps so the git-URL deps in pyproject.toml are not fetched.
    _run([str(pip), "install", "--quiet", *[str(s) for s in _SIBLINGS]])
    _run([str(pip), "install", "--quiet", "--no-deps", str(wheel)])

    cli = venv_dir / "bin" / "doppelganger"
    version_out = _run([str(cli), "--version"]).stdout.strip()
    assert version_out == "doppelganger 0.1.0", (
        f"unexpected --version output: {version_out!r}"
    )

    test_wheel_installs_into_fresh_venv._venv_dir = venv_dir


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv(tmp_path):
    """`import doppelganger; doppelganger.__version__` == '0.1.0' in the venv."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    _run(
        [str(py), "-c", "import doppelganger; assert doppelganger.__version__ == '0.1.0'"],
    )


@pytest.mark.ship_gate
def test_installed_wheel_public_api(tmp_path):
    """The installed wheel exposes the full public API surface."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    check_script = (
        "import doppelganger.cli, doppelganger.findings, doppelganger.sarif, "
        "doppelganger.reporting, doppelganger.rawsend, doppelganger.client"
    )
    _run([str(py), "-c", check_script])


@pytest.mark.ship_gate
def test_installed_wheel_produces_finding_against_mock_pair(tmp_path):
    """Run the INSTALLED CLI against the in-process mock pair; assert a finding.

    This is the end-to-end acceptance gate: the shipped wheel, invoked as the
    ``doppelganger`` console script from a fresh venv, must detect and confirm a
    CL.TE desync on a server-side-desync mock and emit it as a JSON finding.
    """
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    cli = venv_dir / "bin" / "doppelganger"
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n")

    with mockpair.clte_pair("server_desync") as srv:
        proc = subprocess.run(
            [
                str(cli),
                srv.base_url,
                "--scope-file", str(scope_file),
                "--technique", "CL.TE",
                "--format", "json",
                "--timeout", "1.0",
            ],
            capture_output=True,
            text=True,
        )

    # Exit code 1 == findings were produced.
    assert proc.returncode == 1, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
    doc = json.loads(proc.stdout)
    assert doc["finding_count"] >= 1
    finding = doc["findings"][0]
    assert finding["vector"] == "CL.TE"
    assert finding["evidence"]["confirmation"] == "confirmed"
    assert finding["severity"] == "high"
    assert finding["cwe_id"] == 444
