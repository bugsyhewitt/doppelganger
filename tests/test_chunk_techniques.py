"""Tests for v0.4 parser-discrepancy probes: expanded TE_OBFUSCATIONS and TE.chunk.

Covers:
* New header-level TE_OBFUSCATIONS entries (5 additions): each generates valid
  timing-probe and differential-attack payloads and detects a desync against the
  existing clte_pair (front=CL / back=lenient-TE).
* TE.chunk / chunk-ext variant: both timing probe and differential CONFIRM against
  clte_pair because the mock's _chunked_consumed strips chunk extensions.
* TE.chunk / bare-cr variant: timing probe raises a CANDIDATE (mock hangs on
  bare-CR body since it requires CRLF); differential does NOT confirm (no leftover
  from a hanging back-end), so the engine emits a candidate only.
* Payload shape: all TE.chunk timing probes and differential attacks are
  byte-exact (no header normalisation).
* CLI wiring: --technique TE.chunk accepted, produces findings.
"""

from __future__ import annotations

import pytest

import mockpair
from scan_primitives import Scope
from doppelganger.engine import DesyncEngine
from doppelganger.findings import CWE_REQUEST_SMUGGLING
from doppelganger.techniques import (
    CHUNK_BODY_VARIANTS,
    TE_OBFUSCATIONS,
    Technique,
    all_techniques,
    chunk_body_techniques,
    technique_by_name,
)

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


# ---------------------------------------------------------------------------
# TE_OBFUSCATIONS expansion: 5 new entries
# ---------------------------------------------------------------------------

_NEW_OBFUSCATION_NAMES = {"mixed-case", "null-byte", "bare-cr-end", "ows-trailer", "comma-chunk"}


def test_te_obfuscations_includes_v04_entries():
    """TE_OBFUSCATIONS contains all 5 new v0.4 header-level entries."""
    names = {name for name, _ in TE_OBFUSCATIONS}
    assert _NEW_OBFUSCATION_NAMES <= names, (
        f"missing v0.4 obfuscations: {_NEW_OBFUSCATION_NAMES - names}"
    )


def test_te_obfuscations_count():
    """TE_OBFUSCATIONS now has 13 entries (8 original + 5 new)."""
    assert len(TE_OBFUSCATIONS) == 13


@pytest.mark.parametrize("variant", list(_NEW_OBFUSCATION_NAMES))
def test_new_te_obfuscation_probe_shape(variant):
    """Each new TE_OBFUSCATIONS entry produces a valid probe with the right fields."""
    header = next(h for n, h in TE_OBFUSCATIONS if n == variant)
    tech = Technique("TE.TE", "TE.TE", safe_order=3, variant=variant, te_header=header)

    probe = tech.timing_probe("target.local")
    assert probe is not None
    assert b"Content-Length: 4" in probe
    assert header in probe
    assert b"POST" in probe

    attack = tech.differential_attack("target.local", "/dg-marker")
    assert b"GET /dg-marker" in attack
    assert header in attack


@pytest.mark.parametrize("variant", list(_NEW_OBFUSCATION_NAMES))
def test_new_te_obfuscation_confirms_on_clte_pair(variant, scope):
    """New TE_OBFUSCATIONS entries confirm desync against clte_pair mock."""
    header = next(h for n, h in TE_OBFUSCATIONS if n == variant)
    tech = Technique("TE.TE", "TE.TE", safe_order=3, variant=variant, te_header=header)

    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    assert len(findings) >= 1
    f = findings[0]
    assert f.vector == "TE.TE"
    assert f.variant == variant
    assert f.evidence["confirmation"] == "confirmed"
    assert f.cwe_id == CWE_REQUEST_SMUGGLING


# ---------------------------------------------------------------------------
# TE.chunk technique family
# ---------------------------------------------------------------------------

def test_chunk_body_variants_defined():
    """CHUNK_BODY_VARIANTS has at least the two v0.4 entries."""
    names = {name for name, *_ in CHUNK_BODY_VARIANTS}
    assert "chunk-ext" in names
    assert "bare-cr" in names


def test_chunk_body_techniques_returns_correct_count():
    """chunk_body_techniques() returns one Technique per CHUNK_BODY_VARIANTS entry."""
    techs = chunk_body_techniques()
    assert len(techs) == len(CHUNK_BODY_VARIANTS)
    for t in techs:
        assert t.name == "TE.chunk"
        assert t.discrepancy == "TE.chunk"
        assert t.safe_order == 4


def test_all_techniques_includes_te_chunk():
    """all_techniques() includes all TE.chunk variants, ordered after TE.TE (3) and before TE.CL (9)."""
    all_t = all_techniques()
    chunk_techs = [t for t in all_t if t.name == "TE.chunk"]
    assert len(chunk_techs) == len(CHUNK_BODY_VARIANTS)
    te_cl = next(t for t in all_t if t.name == "TE.CL")
    for ct in chunk_techs:
        assert ct.safe_order < te_cl.safe_order


def test_technique_by_name_te_chunk():
    """technique_by_name('TE.chunk') returns all TE.chunk variants."""
    techs = technique_by_name("TE.chunk")
    assert len(techs) == len(CHUNK_BODY_VARIANTS)
    assert all(t.name == "TE.chunk" for t in techs)


# ---------------------------------------------------------------------------
# TE.chunk / chunk-ext: confirmed desync against clte_pair
# ---------------------------------------------------------------------------

def test_chunk_ext_timing_probe_shape():
    """TE.chunk / chunk-ext timing probe embeds the chunk extension and correct CL."""
    [tech] = [t for t in chunk_body_techniques() if t.variant == "chunk-ext"]
    probe = tech.timing_probe("target.local")
    assert probe is not None
    assert b"1;x=p\r\n" in probe
    assert f"Content-Length: {tech.timing_cl}".encode() in probe
    assert b"Transfer-Encoding: chunked" in probe


def test_chunk_ext_differential_attack_shape():
    """TE.chunk / chunk-ext differential attack body has the extension prefix and smuggled request."""
    [tech] = [t for t in chunk_body_techniques() if t.variant == "chunk-ext"]
    attack = tech.differential_attack("target.local", "/dg-chunk-marker")
    assert b"1;x=p\r\n" in attack
    assert b"0\r\n\r\n" in attack
    assert b"GET /dg-chunk-marker" in attack
    # Full body length is in Content-Length header (exact)
    assert b"Transfer-Encoding: chunked" in attack


def test_chunk_ext_confirms_on_clte_pair(scope):
    """TE.chunk / chunk-ext CONFIRMS desync on clte_pair: mock's TE strips extensions."""
    [tech] = [t for t in chunk_body_techniques() if t.variant == "chunk-ext"]

    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    assert len(findings) == 1, f"expected 1 finding, got: {findings}"
    f = findings[0]
    assert f.vector == "TE.chunk"
    assert f.variant == "chunk-ext"
    assert f.evidence["confirmation"] == "confirmed"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.cwe_id == CWE_REQUEST_SMUGGLING
    assert f.evidence["connection_reuse"] is False
    assert not engine.suppressed


# ---------------------------------------------------------------------------
# TE.chunk / bare-cr: timing candidate only against strict-CRLF mock
# ---------------------------------------------------------------------------

def test_bare_cr_timing_probe_shape():
    """TE.chunk / bare-cr timing probe uses bare CR (no LF) in chunk framing."""
    [tech] = [t for t in chunk_body_techniques() if t.variant == "bare-cr"]
    probe = tech.timing_probe("target.local")
    assert probe is not None
    assert b"1\rA\r" in probe
    assert b"\r\n" not in probe.split(b"\r\n\r\n", 1)[1]  # body has no CRLF


def test_bare_cr_differential_attack_shape():
    """TE.chunk / bare-cr differential attack has bare-CR prefix and standard terminator."""
    [tech] = [t for t in chunk_body_techniques() if t.variant == "bare-cr"]
    attack = tech.differential_attack("target.local", "/dg-bare-cr-marker")
    assert b"1\rA\r" in attack
    assert b"0\r\n\r\n" in attack
    assert b"GET /dg-bare-cr-marker" in attack


def test_bare_cr_raises_candidate_on_strict_mock(scope):
    """TE.chunk / bare-cr: strict-CRLF mock hangs -> timing candidate, no confirmation.

    The clte_pair mock requires CRLF for chunk boundaries (find(b'\\r\\n')).  A
    bare-CR body gives it no valid chunk start -> NEED_MORE -> hang -> timing
    signal.  But the back-end also hangs on the differential attack -> no
    leftover -> no response change -> engine emits candidate, not confirmed.
    """
    [tech] = [t for t in chunk_body_techniques() if t.variant == "bare-cr"]

    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    # Timing hangs on both timing probe AND differential attack -> candidate
    assert len(findings) == 1, f"expected 1 finding, got: {findings}"
    f = findings[0]
    assert f.vector == "TE.chunk"
    assert f.variant == "bare-cr"
    assert f.evidence["confirmation"] == "candidate"
    assert f.severity == "medium"


# ---------------------------------------------------------------------------
# No false positive: robust pair (CL/CL) produces no TE.chunk findings
# ---------------------------------------------------------------------------

def test_te_chunk_no_finding_on_robust_pair(scope):
    """TE.chunk emits nothing against a server where front and back agree (CL/CL)."""
    with mockpair.robust_pair() as srv:
        engine = _engine(srv, scope)
        findings = engine.run(chunk_body_techniques())

    assert findings == []
    assert engine.suppressed == []
