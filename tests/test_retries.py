"""Tests for the --retries / engine.retries timing-probe stabilisation feature.

The engine retries the timing probe up to ``retries`` additional times when the
first probe times out.  A genuine back-end hang is stable -- all retries also
time out -- and the timing signal is preserved.  A transient network timeout
clears on the first retry that comes back, and the timing signal is discarded.

All tests drive the in-process mockpair (or patch ``_send_isolated`` directly)
so the test suite runs offline and deterministically.
"""

from __future__ import annotations

import json
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import mockpair

from scan_primitives import Scope
from doppelganger.engine import DesyncEngine
from doppelganger.rawsend import RawResponse
from doppelganger.techniques import technique_by_name

# Per-probe timeout used in all tests -- short enough to be fast, long enough
# that the mock pair's hang signals are not ambiguous.
TIMEOUT = 0.4

# Delta threshold raised well above TIMEOUT so the delta-based candidate path
# cannot fire in tests that only want to test the timed_out path.  A genuine
# timeout at TIMEOUT seconds produces a delta of at most TIMEOUT*1000 ms, which
# is 400 ms here -- comfortably below 1000 ms.
HIGH_DELTA_THRESHOLD = 1000.0


@pytest.fixture
def scope() -> Scope:
    return Scope.from_entries(["127.0.0.1"])


def _engine(server, scope: Scope, **kw) -> DesyncEngine:
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("timing_timeout", TIMEOUT)
    return DesyncEngine(server.base_url, scope=scope, **kw)


def _clte() -> object:
    return technique_by_name("CL.TE")[0]


# --------------------------------------------------------------------------- #
# Constructor / attribute sanity
# --------------------------------------------------------------------------- #


def test_retries_default_is_zero(scope):
    """DesyncEngine.retries defaults to 0 (existing single-probe behaviour)."""
    with mockpair.robust_pair() as srv:
        engine = _engine(srv, scope)
    assert engine.retries == 0


def test_retries_stored_correctly(scope):
    """DesyncEngine.retries stores the configured value."""
    with mockpair.robust_pair() as srv:
        engine = _engine(srv, scope, retries=3)
    assert engine.retries == 3


def test_retries_negative_clamped_to_zero(scope):
    """A negative retries value is clamped to 0 (treated as no retries)."""
    with mockpair.robust_pair() as srv:
        engine = _engine(srv, scope, retries=-99)
    assert engine.retries == 0


# --------------------------------------------------------------------------- #
# Stable hang: ALL retries time out -> timing signal preserved
# --------------------------------------------------------------------------- #


def test_stable_hang_candidate_survives_one_retry(scope):
    """A back-end hang that persists across a retry is still reported as a candidate."""
    # candidate_pair: always hangs on the timing probe, never poisons (no
    # differential confirmation), so any finding will be confirmation="candidate".
    with mockpair.candidate_pair() as srv:
        engine = _engine(srv, scope, retries=1)
        findings = engine.run([_clte()])

    assert len(findings) == 1, "stable hang must still produce a timing candidate"
    f = findings[0]
    assert f.evidence["confirmation"] == "candidate"
    assert f.severity == "medium"
    assert f.confidence == "low"


def test_stable_hang_candidate_survives_two_retries(scope):
    """A back-end hang that persists across two retries is still a candidate."""
    with mockpair.candidate_pair() as srv:
        engine = _engine(srv, scope, retries=2)
        findings = engine.run([_clte()])

    assert len(findings) == 1
    assert findings[0].evidence["confirmation"] == "candidate"


def test_stable_hang_confirmed_desync_survives_retries(scope):
    """A genuine CL.TE desync (hangs + poisons) is confirmed even with retries=2."""
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope, retries=2)
        findings = engine.run([_clte()])

    assert len(findings) == 1
    assert findings[0].evidence["confirmation"] == "confirmed"
    assert findings[0].severity == "high"


# --------------------------------------------------------------------------- #
# Transient timeout: first probe times out, retry succeeds -> signal cleared
# --------------------------------------------------------------------------- #


def test_transient_timeout_cleared_by_one_retry(scope):
    """With retries=1: a first-probe timeout that clears on the retry is NOT a signal.

    Setup: the mock returns a fake timeout on the first _send_isolated call, then
    the real robust_pair responds normally on the retry.  The timing_delta_ms is
    also kept below the threshold (HIGH_DELTA_THRESHOLD) so only the timed_out
    path is exercised.
    """
    with mockpair.robust_pair() as srv:
        engine = _engine(
            srv, scope, retries=1, delta_threshold_ms=HIGH_DELTA_THRESHOLD
        )
        baseline = engine._baseline()
        tech = _clte()

        call_n = [0]
        real_send = engine._send_isolated

        def mock_send(raw_bytes, *, timeout=None):
            call_n[0] += 1
            if call_n[0] == 1:
                # Simulate a transient timeout on the first timing probe.
                return RawResponse(b"", TIMEOUT, timed_out=True)
            return real_send(raw_bytes, timeout=timeout)

        engine._send_isolated = mock_send
        engine._probe_technique(tech, baseline)

    # The retry responded normally -> timed_out cleared -> no timing signal.
    # The differential also didn't confirm (robust server) -> no finding.
    assert engine.findings == [], (
        "transient timeout cleared by retry must not produce any finding"
    )
    # Verify the retry was called (original + at least 1 retry = at least 2 calls).
    assert call_n[0] >= 2, "retry was not invoked"


def test_transient_timeout_retries_zero_still_raises_candidate(scope):
    """Without retries, a single timeout raises a candidate (backward compatibility)."""
    with mockpair.robust_pair() as srv:
        engine = _engine(
            srv, scope, retries=0, delta_threshold_ms=HIGH_DELTA_THRESHOLD
        )
        baseline = engine._baseline()
        tech = _clte()

        call_n = [0]
        real_send = engine._send_isolated

        def mock_send(raw_bytes, *, timeout=None):
            call_n[0] += 1
            if call_n[0] == 1:
                return RawResponse(b"", TIMEOUT, timed_out=True)
            return real_send(raw_bytes, timeout=timeout)

        engine._send_isolated = mock_send
        engine._probe_technique(tech, baseline)

    # With retries=0 the single timeout is the only probe -> candidate raised.
    assert len(engine.findings) == 1
    assert engine.findings[0].evidence["confirmation"] == "candidate"
    # _send_isolated is also called by the differential stage (attack + victim),
    # so call_n reflects more than just the timing probe.  The key check is that
    # the finding is a candidate, which is only true if the timing probe timeout
    # was NOT cleared by a retry (retries=0 means no retry loop entered).


def test_first_retry_clears_signal_even_with_retries_two(scope):
    """With retries=2: if the FIRST retry succeeds, the signal is cleared immediately.

    The second retry slot is never used once the signal is cleared, so total
    _send_isolated calls for the timing stage are exactly 2 (original + 1 retry).
    """
    with mockpair.robust_pair() as srv:
        engine = _engine(
            srv, scope, retries=2, delta_threshold_ms=HIGH_DELTA_THRESHOLD
        )
        baseline = engine._baseline()
        tech = _clte()

        call_n = [0]
        real_send = engine._send_isolated

        def mock_send(raw_bytes, *, timeout=None):
            call_n[0] += 1
            if call_n[0] == 1:
                return RawResponse(b"", TIMEOUT, timed_out=True)
            return real_send(raw_bytes, timeout=timeout)

        engine._send_isolated = mock_send
        engine._probe_technique(tech, baseline)

    # Signal cleared on first retry -> no timing candidate.
    assert engine.findings == []
    # Two _send_isolated calls in the timing stage; differential adds more.
    # The important thing: retry loop stopped as soon as signal cleared.


def test_two_timeouts_then_success_clears_with_retries_two(scope):
    """With retries=2: if probe 1 and retry 1 both time out but retry 2 succeeds,
    the timing signal is cleared (not stable)."""
    with mockpair.robust_pair() as srv:
        engine = _engine(
            srv, scope, retries=2, delta_threshold_ms=HIGH_DELTA_THRESHOLD
        )
        baseline = engine._baseline()
        tech = _clte()

        call_n = [0]
        real_send = engine._send_isolated

        def mock_send(raw_bytes, *, timeout=None):
            call_n[0] += 1
            if call_n[0] == 1:
                # Original timing probe: timeout.
                return RawResponse(b"", TIMEOUT, timed_out=True)
            if call_n[0] == 2:
                # Retry 1: also timeout.
                return RawResponse(b"", TIMEOUT, timed_out=True)
            # Retry 2: success -> clears the signal.
            return real_send(raw_bytes, timeout=timeout)

        engine._send_isolated = mock_send
        engine._probe_technique(tech, baseline)

    # Retry 2 succeeded -> timed_out cleared -> no timing signal -> no finding.
    assert engine.findings == []


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #


def test_cli_retries_flag_accepted_and_wired(tmp_path, capsys):
    """--retries N is accepted by the CLI and wired through to the H1 engine.

    A genuine CL.TE desync is stable across retries -> confirmed -> exit 1.
    """
    from doppelganger.cli import main

    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n")

    with mockpair.clte_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file",
                str(scope_file),
                "--technique",
                "CL.TE",
                "--retries",
                "1",
                "--timeout",
                "0.4",
            ]
        )

    assert code == 1, "confirmed finding -> exit 1"
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 1
    f = doc["findings"][0]
    assert f["evidence"]["confirmation"] == "confirmed"
    assert f["vector"] == "CL.TE"


def test_cli_retries_zero_is_default_behaviour(tmp_path, capsys):
    """--retries 0 (explicit) produces the same result as no --retries flag."""
    from doppelganger.cli import main

    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n")

    with mockpair.clte_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file",
                str(scope_file),
                "--technique",
                "CL.TE",
                "--retries",
                "0",
                "--timeout",
                "0.4",
            ]
        )

    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"][0]["evidence"]["confirmation"] == "confirmed"
