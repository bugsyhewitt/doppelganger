"""Integration test: H2-downgrade desync against a REAL h2 front-end.

The hermetic ``test_h2engine`` / ``test_h2send`` suites are the load-bearing
proof of the H2 capability: they drive the real byte-exact send layer end-to-end
against an in-process HTTP/2-downgrade mock. This module adds the *over-the-wire*
integration path against an actual HTTP/2 front-end that downgrades to HTTP/1.1.

It is gated on ``@pytest.mark.integration`` and skips cleanly when nothing is
available -- which is the case in the build sandbox (no working docker
networking). Run it explicitly with::

    pytest -m integration

Two ways to point it at a real proxy:

1. ``DOPPELGANGER_H2_TARGET`` -- a URL for an HTTP/2 front-end you have
   authorization to test and that is KNOWN to be H2.CL/H2.TE vulnerable (e.g. a
   lab reproduction of PortSwigger's "HTTP/2: The Sequel is Always Worse"). When
   set, this test hard-asserts a candidate/confirmed finding.
   (``DOPPELGANGER_H2_SCOPE`` overrides the authorized host; it defaults to the
   target host.)

2. A docker-compose lab under ``tests/lab-h2/`` (front-end speaks h2 to clients,
   h1 to the back-end). Brought up only if docker is available. Because whether
   an off-the-shelf pinned front-end actually forwards the prohibited header is
   config/version-specific, the docker path **skips** (does not fail) if the
   stack comes up but does not reproduce a desync -- so it never false-fails.

NOTE (no overclaim): as shipped, this test SKIPS in the sandbox. The H2 detection
is proven hermetically, not yet against a live vulnerable proxy in CI.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from scan_primitives import Scope
from doppelganger.h2engine import H2DesyncEngine
from doppelganger.h2send import H2NotSupportedError

pytestmark = pytest.mark.integration

LAB_DIR = Path(__file__).resolve().parent / "lab-h2"
FRONT_HOST = "127.0.0.1"
FRONT_PORT = 18443  # plaintext-h2 or tls-h2 front, per the lab compose
READY_TIMEOUT = 120.0


# --------------------------------------------------------------------------- #
# path 1: operator-supplied real target via env var
# --------------------------------------------------------------------------- #


def test_h2_downgrade_against_env_target():
    """If DOPPELGANGER_H2_TARGET is set, detect a desync against that real proxy."""
    target = os.environ.get("DOPPELGANGER_H2_TARGET")
    if not target:
        pytest.skip("DOPPELGANGER_H2_TARGET not set; no real h2 proxy to test")

    host = urlsplit(target).hostname or ""
    scope_host = os.environ.get("DOPPELGANGER_H2_SCOPE", host)
    scope = Scope.from_entries([scope_host])

    engine = H2DesyncEngine(target, scope=scope, timeout=8.0, timing_timeout=8.0)
    try:
        findings = engine.run()
    except H2NotSupportedError as exc:
        pytest.skip(f"target does not speak HTTP/2 via ALPN: {exc}")

    assert len(findings) >= 1, (
        "expected >=1 H2 downgrade finding against the configured vulnerable "
        f"proxy; suppressed={engine.suppressed}"
    )
    assert all(
        f.evidence["confirmation"] in ("candidate", "confirmed") for f in findings
    )


# --------------------------------------------------------------------------- #
# path 2: docker-compose lab (skips cleanly if docker / lab unavailable)
# --------------------------------------------------------------------------- #


def _compose_cmd() -> list[str] | None:
    if shutil.which("docker"):
        try:
            subprocess.run(
                ["docker", "compose", "version"], capture_output=True, check=True
            )
            return ["docker", "compose"]
        except (subprocess.CalledProcessError, OSError):
            pass
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def _h2_reachable(host: str, port: int, deadline: float) -> bool:
    """Poll until the front-end negotiates ``h2`` via ALPN over TLS."""
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0) as raw:
                ctx = ssl._create_unverified_context()
                ctx.set_alpn_protocols(["h2"])
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    if tls.selected_alpn_protocol() == "h2":
                        return True
        except OSError:
            pass
        time.sleep(2.0)
    return False


@pytest.fixture(scope="module")
def h2_lab():
    compose = _compose_cmd()
    if compose is None:
        pytest.skip("docker / docker compose not available")
    if not (LAB_DIR / "docker-compose.yml").exists():
        pytest.skip("no tests/lab-h2/docker-compose.yml lab defined")

    base = compose + ["-f", str(LAB_DIR / "docker-compose.yml")]
    try:
        subprocess.run(base + ["up", "-d"], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        pytest.skip(f"could not start h2 docker lab: {detail}")

    try:
        if not _h2_reachable(FRONT_HOST, FRONT_PORT, time.monotonic() + READY_TIMEOUT):
            pytest.skip("h2 docker lab did not become ready (h2 ALPN) in time")
        yield f"https://{FRONT_HOST}:{FRONT_PORT}/"
    finally:
        subprocess.run(base + ["down", "-v"], capture_output=True, text=True)


def test_engine_runs_against_docker_h2_front(h2_lab):
    """Drive the engine over the wire against the docker h2 front-end.

    Asserts the engine runs cleanly and returns valid findings. If the pinned
    front-end downgrades correctly (not vulnerable), it SKIPS rather than fails --
    reproducing a live H2 desync requires a specifically vulnerable front-end.
    """
    scope = Scope.from_entries([FRONT_HOST])
    engine = H2DesyncEngine(h2_lab, scope=scope, timeout=6.0, timing_timeout=6.0)
    try:
        findings = engine.run()
    except H2NotSupportedError as exc:
        pytest.skip(f"lab front-end did not negotiate h2: {exc}")

    # Never false-fail: a conformant front-end legitimately yields nothing.
    if not findings:
        pytest.skip(
            "lab h2 front-end did not reproduce a downgrade desync "
            "(needs a known-vulnerable pinned front-end)"
        )
    assert all(
        f.evidence["confirmation"] in ("candidate", "confirmed") for f in findings
    )
