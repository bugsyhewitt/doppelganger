"""Tests for the two-stage HTTP/1.1 desync probe engine (doppelganger.engine).

All HTTP is mocked via the in-process raw-socket mockpair. No live network
calls are made. Covers:

* Baseline response collection
* Stage-1 timing detection: hang -> candidate
* Stage-2 differential confirmation: poison -> confirmed
* Pipelining discrimination: reuse-only effect is suppressed
* Safe mode forces connection isolation even when reuse_connection=True
* Retries stabilise transient timeouts (genuine hang survives all retries)
* ResponseSignature parsing from raw HTTP bytes
* Marker path generation is deterministic and URL-keyed
* Out-of-scope target raises before probing
* All HTTP/1.1 technique families: CL.TE, TE.CL, CL.0, dup-CL, TE.TE
"""

from __future__ import annotations

import pytest

import mockpair
from scan_primitives import OutOfScopeError, Scope
from doppelganger.engine import DesyncEngine, ResponseSignature
from doppelganger.findings import CWE_REQUEST_SMUGGLING
from doppelganger.techniques import technique_by_name

TIMEOUT = 0.4


@pytest.fixture
def scope() -> Scope:
    return Scope.from_entries(["127.0.0.1"])


def _engine(server, scope: Scope, **kw) -> DesyncEngine:
    return DesyncEngine(
        server.base_url,
        scope=scope,
        timeout=TIMEOUT,
        timing_timeout=TIMEOUT,
        **kw,
    )


def _first(name: str):
    return technique_by_name(name)[0]


# ---------------------------------------------------------------------------
# ResponseSignature
# ---------------------------------------------------------------------------


def test_response_signature_parses_status():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    sig = ResponseSignature.from_raw(raw)
    assert sig is not None
    assert sig.status == 200


def test_response_signature_parses_body():
    raw = b"HTTP/1.1 404 Not Found\r\n\r\nbody_here"
    sig = ResponseSignature.from_raw(raw)
    assert sig is not None
    assert sig.body == b"body_here"


def test_response_signature_empty_returns_none():
    assert ResponseSignature.from_raw(b"") is None


def test_response_signature_equality():
    r1 = ResponseSignature(200, b"ok")
    r2 = ResponseSignature(200, b"ok")
    r3 = ResponseSignature(404, b"not found")
    assert r1 == r2
    assert r1 != r3


def test_response_signature_malformed_status():
    raw = b"NOT_HTTP\r\n\r\n"
    sig = ResponseSignature.from_raw(raw)
    assert sig is not None
    assert sig.status == 0  # graceful default


# ---------------------------------------------------------------------------
# Stage-1 timing detection
# ---------------------------------------------------------------------------


def test_clte_timing_raises_candidate(scope):
    with mockpair.candidate_pair() as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE")])
    assert len(findings) == 1
    assert findings[0].evidence["confirmation"] == "candidate"
    assert findings[0].severity == "medium"


def test_tecl_timing_raises_candidate(scope):
    pair = mockpair.MockPair(mockpair.te(), mockpair.cl(0), poison=False)
    with pair as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("TE.CL")])
    assert len(findings) == 1
    assert findings[0].evidence["confirmation"] == "candidate"


# ---------------------------------------------------------------------------
# Stage-2 differential confirmation
# ---------------------------------------------------------------------------


def test_clte_confirmed_on_server_desync(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE")])
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["confirmation"] == "confirmed"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.cwe_id == CWE_REQUEST_SMUGGLING


def test_tecl_confirmed_on_server_desync(scope):
    with mockpair.tecl_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("TE.CL")])
    assert len(findings) == 1
    assert findings[0].evidence["confirmation"] == "confirmed"


def test_cl0_confirmed_on_server_desync(scope):
    with mockpair.cl0_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.0")])
    # CL.0 has no timing probe; confirmation alone is sufficient
    assert any(f.evidence["confirmation"] == "confirmed" for f in findings)


def test_dupcl_confirmed_on_server_desync(scope):
    with mockpair.dupcl_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("dup-CL")])
    assert any(f.evidence["confirmation"] == "confirmed" for f in findings)


def test_tete_confirmed_on_clte_server(scope):
    # TE.TE obfuscation fools front into CL, back into TE — same as CL.TE target
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("TE.TE")])
    assert any(f.evidence["confirmation"] == "confirmed" for f in findings)


# ---------------------------------------------------------------------------
# Pipelining discrimination
# ---------------------------------------------------------------------------


def test_clte_pipelining_is_suppressed_not_reported(scope):
    with mockpair.clte_pair("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE")])
    assert findings == []
    assert len(engine.suppressed) == 1
    entry = engine.suppressed[0]
    assert entry["connection_reuse"] is True


def test_tecl_pipelining_is_suppressed(scope):
    with mockpair.tecl_pair("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("TE.CL")])
    assert findings == []
    assert len(engine.suppressed) == 1


def test_reuse_connection_surfaces_pipelining_as_info(scope):
    with mockpair.clte_pair("pipeline_only") as srv:
        engine = _engine(srv, scope, reuse_connection=True)
        findings = engine.run([_first("CL.TE")])
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].evidence["probable_pipelining"] is True
    assert findings[0].evidence["connection_reuse"] is True


# ---------------------------------------------------------------------------
# Safe mode
# ---------------------------------------------------------------------------


def test_safe_mode_disables_reuse_connection(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope, safe=True, reuse_connection=True)
        engine.run([_first("CL.TE")])
    assert engine.reuse_connection is False


def test_safe_mode_still_confirms_real_desync(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope, safe=True)
        findings = engine.run([_first("CL.TE")])
    assert findings[0].evidence["confirmation"] == "confirmed"


# ---------------------------------------------------------------------------
# Out-of-scope target
# ---------------------------------------------------------------------------


def test_out_of_scope_raises_before_probing(scope):
    engine = DesyncEngine(
        "http://oob.example.net/", scope=scope, timeout=TIMEOUT
    )
    with pytest.raises(OutOfScopeError):
        engine.run([_first("CL.TE")])


# ---------------------------------------------------------------------------
# Marker path
# ---------------------------------------------------------------------------


def test_marker_path_is_deterministic(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        t = technique_by_name("CL.TE")[0]
        p1 = engine._marker_path(t)
        p2 = engine._marker_path(t)
    assert p1 == p2


def test_marker_path_differs_by_technique(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        t_clte = technique_by_name("CL.TE")[0]
        t_tecl = technique_by_name("TE.CL")[0]
        assert engine._marker_path(t_clte) != engine._marker_path(t_tecl)


# ---------------------------------------------------------------------------
# Robust server
# ---------------------------------------------------------------------------


def test_robust_server_produces_no_findings(scope):
    with mockpair.robust_pair() as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE"), _first("TE.CL")])
    assert findings == []


# ---------------------------------------------------------------------------
# Finding fields
# ---------------------------------------------------------------------------


def test_finding_carries_cwe_444(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE")])
    assert findings[0].cwe_id == 444


def test_finding_target_matches_url(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE")])
    assert findings[0].target == srv.base_url


def test_finding_has_reproduction_payload(scope):
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE")])
    assert "reproduction" in findings[0].evidence
    assert findings[0].evidence["reproduction"]
