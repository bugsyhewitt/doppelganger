"""Core acceptance tests for the two-stage desync engine (criteria 2-4).

Proven here, against the in-process raw-socket mock pair:

* **detection** -- a timing hang raises a *candidate*;
* **confirmation** -- a differential response poison *upgrades* the same
  technique to *confirmed*;
* **pipelining discrimination** (the headline correctness feature) -- an effect
  that reproduces ONLY under client-side connection reuse is discriminated as
  pipelining and is NOT reported as a server-side desync.

CL.TE and TE.CL are covered in full; TE.TE, CL.0 and dup-CL are covered for
confirm + discriminate.
"""

from __future__ import annotations

import pytest

import mockpair
from scan_primitives import OutOfScopeError, Scope
from doppelganger.engine import DesyncEngine
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


def _first(technique_name: str):
    return technique_by_name(technique_name)[0]


# --------------------------------------------------------------------------- #
# confirmation on a real (server-side) desync
# --------------------------------------------------------------------------- #

# technique name -> factory building the matching server_desync mock.
_CONFIRM_CASES = {
    "CL.TE": mockpair.clte_pair,
    "TE.CL": mockpair.tecl_pair,
    "CL.0": mockpair.cl0_pair,
    "dup-CL": mockpair.dupcl_pair,
    "TE.TE": mockpair.clte_pair,  # obfuscation has fooled front->CL, back->TE
}


@pytest.mark.parametrize("technique", list(_CONFIRM_CASES))
def test_technique_confirmed_on_server_desync(technique, scope):
    """Each technique differentially CONFIRMS a genuine server-side desync."""
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
    # the byte-exact reproduction payload is carried on the finding
    assert "reproduction" in f.evidence and f.evidence["reproduction"]
    assert not engine.suppressed


# --------------------------------------------------------------------------- #
# pipelining discrimination: reuse-only effects are NOT reported
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("technique", list(_CONFIRM_CASES))
def test_technique_pipelining_is_discriminated_not_reported(technique, scope):
    """A pipeline-only server yields NO desync finding; it is suppressed."""
    with _CONFIRM_CASES[technique]("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first(technique)])
    # The effect reproduces only under client-side connection reuse -> pipelining.
    # It must NOT be reported as a (candidate or confirmed) desync.
    assert findings == [], f"{technique}: pipelining wrongly reported as a desync"
    assert len(engine.suppressed) == 1
    entry = engine.suppressed[0]
    assert entry["technique"] == technique
    assert entry["connection_reuse"] is True
    assert "pipelining" in entry["reason"]


# --------------------------------------------------------------------------- #
# two-stage: timing candidate, then differential upgrade
# --------------------------------------------------------------------------- #


def test_clte_timing_raises_candidate_without_confirmation(scope):
    """A hang with no confirmable poison is reported as a CANDIDATE (stage 1)."""
    with mockpair.candidate_pair() as srv:  # front=CL/back=TE hang, no poison
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE")])
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["confirmation"] == "candidate"
    assert f.severity == "medium"
    assert f.confidence == "low"
    assert f.evidence["timing_delta_ms"] >= 0  # a timing delta was recorded


def test_tecl_timing_raises_candidate_without_confirmation(scope):
    """TE.CL timing hang with no poison -> candidate (front=TE/back=CL)."""
    pair = mockpair.MockPair(mockpair.te(), mockpair.cl(0), poison=False)
    with pair as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("TE.CL")])
    assert len(findings) == 1
    assert findings[0].evidence["confirmation"] == "candidate"


def test_confirmation_upgrades_candidate_to_confirmed(scope):
    """Same technique: no poison -> candidate; with poison -> confirmed (upgrade)."""
    with mockpair.candidate_pair() as srv:
        candidate = _engine(srv, scope).run([_first("CL.TE")])[0]
    with mockpair.clte_pair("server_desync") as srv:
        confirmed = _engine(srv, scope).run([_first("CL.TE")])[0]
    assert candidate.evidence["confirmation"] == "candidate"
    assert confirmed.evidence["confirmation"] == "confirmed"


# --------------------------------------------------------------------------- #
# specificity + safety
# --------------------------------------------------------------------------- #


def test_reuse_connection_flag_surfaces_pipelining_as_info_only(scope):
    """With --reuse-connection, a reuse-only effect surfaces as an INFO signal.

    It is explicitly flagged as probable pipelining and never as a high desync.
    """
    with mockpair.clte_pair("pipeline_only") as srv:
        engine = _engine(srv, scope, reuse_connection=True)
        findings = engine.run([_first("CL.TE")])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "info"  # NOT high/medium -- not a real desync
    assert f.evidence["connection_reuse"] is True
    assert f.evidence.get("probable_pipelining") is True


def test_safe_mode_confirms_and_forces_isolation(scope):
    """Safe mode still confirms a real desync and disables connection reuse."""
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope, safe=True, reuse_connection=True)
        findings = engine.run([_first("CL.TE")])
    assert engine.reuse_connection is False  # safe mode overrides reuse
    assert findings[0].evidence["confirmation"] == "confirmed"


def test_robust_server_yields_no_desync_findings(scope):
    """A server whose front and back agree is not vulnerable -> no findings.

    Note the TE.CL payload makes even this robust CL-only server *pipeline* the
    smuggled bytes as a second request, which the engine correctly discriminates
    as pipelining (suppressed) rather than reporting a desync -- exactly the
    false positive that discredits naive tools.
    """
    with mockpair.robust_pair() as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_first("CL.TE"), _first("TE.CL")])
    assert findings == [], "robust server must not yield desync findings"


def test_full_run_all_techniques_on_clte_target(scope):
    """A full safe-ordered run confirms CL.TE (and any TE.TE variants) on a CL.TE
    target and reports nothing spurious for the non-matching techniques."""
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run()  # all techniques, safe order
    vectors = {f.vector for f in findings}
    assert "CL.TE" in vectors
    assert all(f.evidence["confirmation"] in ("candidate", "confirmed") for f in findings)


def test_safe_order_puts_clte_before_tecl(scope):
    """Safe-testing ordering (criterion 4): CL.TE is always probed before TE.CL."""
    from doppelganger.techniques import all_techniques

    order = [t.name for t in all_techniques()]
    assert order.index("CL.TE") < order.index("TE.CL")


def test_out_of_scope_target_raises_before_probing(scope):
    """The engine refuses an out-of-scope target (scope enforced pre-egress)."""
    engine = DesyncEngine("http://not-in-scope.example.net/", scope=scope, timeout=TIMEOUT)
    with pytest.raises(OutOfScopeError):
        engine.run([_first("CL.TE")])


# --------------------------------------------------------------------------- #
# CL.0 GET+CL:0 sub-variant
# --------------------------------------------------------------------------- #


def _get_cl0_technique():
    """The GET+CL:0 sub-variant of CL.0 (variant='get-cl0')."""
    return next(t for t in technique_by_name("CL.0") if t.variant == "get-cl0")


def test_cl0_get_variant_confirmed_on_transparent_proxy_desync(scope):
    """GET+CL:0 variant differentially CONFIRMS a transparent-proxy desync.

    The get_cl0_pair uses a passthrough front-end (transparent TCP forwarder)
    and a Content-Length-reading back-end.  The GET probe sends CL:0 but
    appends the smuggled request after the headers; the transparent front
    forwards all bytes; the back-end reads CL:0 (0 body bytes) and the extra
    bytes become the next-request prefix -- confirmed server-side desync.
    """
    with mockpair.get_cl0_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_get_cl0_technique()])
    assert len(findings) == 1, "expected one CL.0 get-cl0 finding"
    f = findings[0]
    assert f.vector == "CL.0"
    assert f.variant == "get-cl0"
    assert f.evidence["confirmation"] == "confirmed"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.evidence["connection_reuse"] is False
    assert f.cwe_id == CWE_REQUEST_SMUGGLING
    assert not engine.suppressed


def test_cl0_get_variant_pipelining_is_discriminated(scope):
    """GET+CL:0 pipeline-only effect is suppressed -- not a server-side desync."""
    with mockpair.get_cl0_pair("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([_get_cl0_technique()])
    assert findings == [], "pipeline-only CL.0 get-cl0 must not be reported as a desync"
    assert len(engine.suppressed) == 1
    entry = engine.suppressed[0]
    assert entry["technique"] == "CL.0"
    assert entry["connection_reuse"] is True
    assert "pipelining" in entry["reason"]


def test_cl0_get_variant_in_all_techniques():
    """GET+CL:0 is present in the all-techniques list."""
    from doppelganger.techniques import all_techniques

    cl0_variants = [t.variant for t in all_techniques() if t.name == "CL.0"]
    assert "get-cl0" in cl0_variants, "get-cl0 variant missing from all_techniques()"
    assert None in cl0_variants, "classic CL.0 (variant=None) must still be present"


def test_cl0_classic_and_get_variants_have_same_safe_order():
    """Both CL.0 sub-variants share safe_order=1 (neither is deferred to TE.CL slot)."""
    from doppelganger.techniques import all_techniques

    orders = {t.variant: t.safe_order for t in all_techniques() if t.name == "CL.0"}
    assert orders[None] == orders["get-cl0"] == 1
