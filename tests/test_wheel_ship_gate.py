"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via ``pytest -m "not ship_gate"``. Runs in the full v0.1 suite.

Mirrors ferryman's ship gate. The final "produce a real finding against a lab"
step is intentionally a skip TODO: the desync probe engine and the
docker-compose discrepant-pair lab are not built in the scaffold pass (see
V0.1-CRITERIA.md Testability).
"""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


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

    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"

    _run([str(pip), "install", "--quiet", str(wheel)])

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
def test_installed_wheel_produces_finding_against_lab(tmp_path):
    """TODO(v0.1): run doppelganger against the docker discrepant-pair lab and
    assert it emits a confirmed CL.TE (or TE.CL) finding, severity high.

    Blocked in the scaffold: the desync probe engine, differential confirmation,
    and the docker-compose lab (HAProxy 1.7.9 + gunicorn 20.0.4, frozen
    versions) are not built. See V0.1-CRITERIA.md criteria 1-3 and Testability.
    """
    pytest.skip("v0.1 engine + docker discrepant-pair lab not built -- see V0.1-CRITERIA.md")
