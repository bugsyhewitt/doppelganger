"""Acceptance tests for the two-stage H2-downgrade desync engine (v0.2).

Proven here, against the in-process HTTP/2-downgrade mock pair (an H2 front-end
that forwards a naively-downgraded HTTP/1.1 view to a discrepant back-end):

* **detection** -- a downgrade timing hang raises a *candidate*;
* **confirmation** -- a differential response poison upgrades H2.CL / H2.TE to
  *confirmed*;
* **pipelining discrimination** -- an effect that reproduces ONLY under H2
  connection reuse is discriminated as pipelining and NOT reported as a
  server-side desync;
* **negative control** -- a conformant front-end (strips the prohibited headers)
  yields no finding;
* the byte-exact prohibited probe (injected transfer-encoding / lying
  content-length) is what rides on the emitted finding's reproduction payload.

All hermetic: the "H2 front-end" is a local socket server; no real proxy needed.
"""

from __future__ import annotations

import json

import pytest

import h2mock
from scan_primitives import OutOfScopeError, Scope
from doppelganger.findings import CWE_REQUEST_SMUGGLING
from doppelganger.h2engine import H2DesyncEngine
from doppelganger.h2techniques import all_h2_techniques, h2_technique_by_name

TIMEOUT = 0.5


@pytest.fixture
def scope() -> Scope:
    return Scope.from_entries(["127.0.0.1"])


def _engine(server, scope: Scope, **kw) -> H2DesyncEngine:
    return H2DesyncEngine(
        server.base_url,
        scope=scope,
        timeout=TIMEOUT,
        timing_timeout=TIMEOUT,
        **kw,
    )


def _first(name: str):
    return h2_technique_by_name(name)[0]


# technique name -> factory building the matching server_desync mock.
_CONFIRM_CASES = {
    "H2.CL": h2mock.h2cl_pair,
    "H2.TE": h2mock.h2te_pair,
}


# --------------------------------------------------------------------------- #
# confirmation on a real (server-side) downgrade desync
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("technique", list(_CONFIRM_CASES))
def test_h2_technique_confirmed_on_server_desync(technique, scope):
    """H2.CL and H2.TE each differentially CONFIRM a genuine downgrade desync."""
    with _CONFIRM_CASES[technique]("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first(technique)])
    assert len(findings) == 1, f"{technique}: expected one finding"
    f = findings[0]
    assert f.vector == technique
    assert f.evidence["confirmation"] == "confirmed"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.evidence["connection_reuse"] is False
    assert f.cwe_id == CWE_REQUEST_SMUGGLING
    assert f.evidence["discrepancy"] == technique
    assert f.evidence["http_version"] == "h2-downgrade"
    assert f.evidence.get("reproduction")
    assert not engine.suppressed


def test_h2cl_reproduction_carries_the_lying_content_length(scope):
    """The emitted H2.CL finding reproduces the byte-exact lying content-length."""
    with h2mock.h2cl_pair("server_desync") as srv:
        f = _engine(srv, scope).run([_first("H2.CL")])[0]
    assert "content-length: 0" in f.evidence["reproduction"]
    assert ":method: POST" in f.evidence["reproduction"]


def test_h2te_reproduction_carries_the_injected_transfer_encoding(scope):
    """The emitted H2.TE finding reproduces the byte-exact injected TE header."""
    with h2mock.h2te_pair("server_desync") as srv:
        f = _engine(srv, scope).run([_first("H2.TE")])[0]
    assert "transfer-encoding: chunked" in f.evidence["reproduction"]


# --------------------------------------------------------------------------- #
# pipelining discrimination: reuse-only effects are NOT reported
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("technique", list(_CONFIRM_CASES))
def test_h2_pipelining_is_discriminated_not_reported(technique, scope):
    """A pipeline-only H2 downgrade yields NO desync finding; it is suppressed."""
    with _CONFIRM_CASES[technique]("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first(technique)])
    assert findings == [], f"{technique}: pipelining wrongly reported as a desync"
    assert len(engine.suppressed) == 1
    entry = engine.suppressed[0]
    assert entry["technique"] == technique
    assert entry["connection_reuse"] is True
    assert "pipelining" in entry["reason"]


# --------------------------------------------------------------------------- #
# two-stage: timing candidate, then differential upgrade
# --------------------------------------------------------------------------- #


def test_h2cl_timing_raises_candidate_without_confirmation(scope):
    """A downgrade hang with no confirmable poison is a CANDIDATE (stage 1)."""
    with h2mock.h2cl_candidate_pair() as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("H2.CL")])
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["confirmation"] == "candidate"
    assert f.severity == "medium"
    assert f.confidence == "low"
    assert f.evidence["timing_delta_ms"] >= 0


def test_h2_confirmation_upgrades_candidate_to_confirmed(scope):
    """H2.CL: no poison -> candidate; with poison -> confirmed (the upgrade)."""
    with h2mock.h2cl_candidate_pair() as srv:
        candidate = _engine(srv, scope).run([_first("H2.CL")])[0]
    with h2mock.h2cl_pair("server_desync") as srv:
        confirmed = _engine(srv, scope).run([_first("H2.CL")])[0]
    assert candidate.evidence["confirmation"] == "candidate"
    assert confirmed.evidence["confirmation"] == "confirmed"


# --------------------------------------------------------------------------- #
# specificity + safety
# --------------------------------------------------------------------------- #


def test_h2_reuse_connection_flag_surfaces_pipelining_as_info_only(scope):
    """With --reuse-connection, a reuse-only effect surfaces as an INFO signal."""
    with h2mock.h2cl_pair("pipeline_only") as srv:
        engine = _engine(srv, scope, reuse_connection=True)
        findings = engine.run([_first("H2.CL")])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"
    assert f.evidence["connection_reuse"] is True
    assert f.evidence.get("probable_pipelining") is True


def test_h2_safe_mode_confirms_and_forces_isolation(scope):
    """Safe mode still confirms a real desync and disables connection reuse."""
    with h2mock.h2cl_pair("server_desync") as srv:
        engine = _engine(srv, scope, safe=True, reuse_connection=True)
        findings = engine.run([_first("H2.CL")])
    assert engine.reuse_connection is False
    assert findings[0].evidence["confirmation"] == "confirmed"


@pytest.mark.parametrize("technique", list(_CONFIRM_CASES))
def test_h2_robust_front_end_yields_no_findings(technique, scope):
    """A conformant front-end (strips prohibited headers) is not vulnerable."""
    with h2mock.h2_robust_pair() as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first(technique)])
    assert findings == [], f"{technique}: conformant front-end wrongly flagged"
    assert engine.suppressed == []


def test_h2_safe_order_puts_h2cl_before_h2te():
    """Safe-testing ordering: H2.CL is always probed before the H2.TE hang."""
    order = [t.name for t in all_h2_techniques()]
    assert order.index("H2.CL") < order.index("H2.TE")


def test_h2_out_of_scope_target_raises_before_probing(scope):
    """The H2 engine refuses an out-of-scope target (scope enforced pre-egress)."""
    engine = H2DesyncEngine(
        "http://not-in-scope.example.net/", scope=scope, timeout=TIMEOUT
    )
    with pytest.raises(OutOfScopeError):
        engine.run([_first("H2.CL")])


# --------------------------------------------------------------------------- #
# CLI wiring: H2.CL / H2.TE are now accepted and routed to the H2 engine
# --------------------------------------------------------------------------- #


def _scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\n")
    return str(p)


def test_cli_h2cl_produces_confirmed_finding_json(tmp_path, capsys):
    """`--technique H2.CL` against a downgrade mock confirms and emits JSON; exit 1."""
    from doppelganger.cli import main

    with h2mock.h2cl_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "H2.CL",
                "--format", "json",
                "--timeout", "0.5",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] == 1
    finding = doc["findings"][0]
    assert finding["vector"] == "H2.CL"
    assert finding["evidence"]["confirmation"] == "confirmed"
    assert finding["cwe_id"] == 444


def test_cli_h2te_is_a_valid_technique_choice(tmp_path, capsys):
    """`--technique H2.TE` is accepted (v0.1 rejected all H2) and routes to H2."""
    from doppelganger.cli import main

    with h2mock.h2te_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "H2.TE",
                "--timeout", "0.5",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"][0]["vector"] == "H2.TE"
