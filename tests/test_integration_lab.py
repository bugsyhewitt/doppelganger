"""Integration test: the docker-compose discrepant-pair lab (integration marker).

Brings up the pinned HAProxy 1.7.9 + gunicorn 20.0.4 pair (see ``lab/``), which
parse HTTP/1.1 message length differently and therefore reproduce a deterministic
desync, then drives the real engine against it and asserts a finding is produced.

Skips cleanly when docker is unavailable, or when the lab cannot be brought up
(image pull / environment issues) -- the mock-pair unit tests and the ship gate
already prove the engine without containers. Run explicitly with::

    pytest -m integration
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from scan_primitives import Scope
from doppelganger.engine import DesyncEngine

pytestmark = pytest.mark.integration

LAB_DIR = Path(__file__).resolve().parent / "lab"
FRONT_HOST = "127.0.0.1"
FRONT_PORT = 18080
READY_TIMEOUT = 150.0  # backend installs gunicorn on first boot


def _compose_cmd() -> list[str] | None:
    if shutil.which("docker"):
        try:
            subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                check=True,
            )
            return ["docker", "compose"]
        except (subprocess.CalledProcessError, OSError):
            pass
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def _wait_until_ready(host: str, port: int, deadline: float) -> bool:
    """Poll until the front-end answers ``GET /`` with a healthy 2xx from the back-end.

    A 5xx means HAProxy is up but the back-end is unreachable (e.g. a sandbox with
    IPv4 forwarding disabled); that is NOT ready -- we skip rather than run the
    detection against a dead back-end.
    """
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0) as s:
                s.sendall(
                    b"GET / HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n"
                    % host.encode()
                )
                s.settimeout(2.0)
                data = s.recv(128)
                parts = data.split(b" ", 2)
                if len(parts) >= 2 and parts[1].startswith(b"2"):
                    return True
        except OSError:
            pass
        time.sleep(2.0)
    return False


@pytest.fixture(scope="module")
def lab():
    compose = _compose_cmd()
    if compose is None:
        pytest.skip("docker / docker compose not available")

    base = compose + ["-f", str(LAB_DIR / "docker-compose.yml")]
    try:
        subprocess.run(base + ["up", "-d"], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        pytest.skip(f"could not start docker lab: {detail}")

    try:
        if not _wait_until_ready(FRONT_HOST, FRONT_PORT, time.monotonic() + READY_TIMEOUT):
            pytest.skip("docker lab did not become ready in time")
        yield f"http://{FRONT_HOST}:{FRONT_PORT}/"
    finally:
        subprocess.run(base + ["down", "-v"], capture_output=True, text=True)


def test_engine_detects_desync_against_frozen_pair(lab):
    """The engine detects the desync the pinned HAProxy/gunicorn pair produces."""
    scope = Scope.from_entries([FRONT_HOST])
    engine = DesyncEngine(lab, scope=scope, timeout=3.0, timing_timeout=3.0)
    findings = engine.run()  # all techniques, safe order
    # The frozen pair reliably desyncs; assert at least one candidate/confirmed
    # finding (the specific X.Y depends on the pinned versions).
    assert len(findings) >= 1, (
        "expected >=1 desync finding against the discrepant pair; "
        f"suppressed={engine.suppressed}"
    )
    assert all(
        f.evidence["confirmation"] in ("candidate", "confirmed") for f in findings
    )
