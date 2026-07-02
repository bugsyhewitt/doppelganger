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


def test_engine_discriminates_same_connection_effect_against_frozen_pair(lab):
    """The engine correctly discriminates the pinned pair's SAME-CONNECTION effect.

    Verified empirically (p-doppelganger-pipelining-001): HAProxy 1.7.9 /
    gunicorn 20.0.4 in this config produces a *same-connection-only* response-queue
    offset -- gunicorn processes a smuggled request and its response poisons the
    *reused* connection, but the effect does NOT cross to a fresh connection
    (0/8 observed) and the malformed timing probe is rejected rather than hung.
    By the cross-connection standard of an *exploitable* desync that is not a
    confirmable finding, so the engine records the effect in ``suppressed`` and
    does not emit a (false) desync.

    This proves, end-to-end against a REAL discrepant pair, that the raw probes +
    two-stage discrimination work and do NOT false-positive. (An earlier premise
    that this pair yields a reportable desync was wrong -- the effect is real but
    same-connection-only; the cross-connection confirmation standard is retained.)
    """
    scope = Scope.from_entries([FRONT_HOST])
    engine = DesyncEngine(lab, scope=scope, timeout=3.0, timing_timeout=3.0)
    findings = engine.run()  # all techniques, safe order
    # Detection MUST work end-to-end: the engine either records the
    # same-connection effect as suppressed, or -- if the back-end pool happens to
    # carry the poison across connections -- reports a genuine CONFIRM.
    assert engine.suppressed or findings, (
        "engine detected nothing against a real discrepant pair -- probes broken?"
    )
    # It must NOT false-report: this config is same-connection-only (no timing
    # hang; 0/8 cross-connection observed), so any finding must be a real
    # cross-connection confirmation, never a spurious candidate.
    assert all(
        f.evidence["confirmation"] == "confirmed" for f in findings
    ), f"unexpected non-confirmed finding against a same-connection-only pair: {findings}"
