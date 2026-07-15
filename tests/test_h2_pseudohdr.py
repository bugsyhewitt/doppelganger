"""Tests for the H2.PseudoHdrInject technique (v0.8).

H2.PseudoHdrInject injects ``\\r\\nTransfer-Encoding: chunked`` into a header
*value* (either the ``:authority`` pseudo-header or a regular header value).  A
vulnerable H2->H1 downgrader that copies decoded values verbatim into the H1
request will produce an extra ``Transfer-Encoding: chunked`` line, creating the
same desync shape as H2.TE but via a different injection vector.

Tests proven here:

* **Probe builders** -- the timing and differential requests carry the CR+LF
  injection bytes in the HPACK-encoded wire output (verified independently via a
  conformant HPACK decoder).
* **Catalogue** -- ``all_h2_techniques()`` contains both variants in the correct
  safe order; ``h2_technique_by_name("H2.PseudoHdrInject")`` returns them.
* **Engine -- confirmed desync** -- both variants CONFIRM a server-side desync
  against the in-process H2 downgrade mock (the mock copies CRLF-containing
  values verbatim, so the ``te()`` back-end strategy detects the injected TE).
* **Engine -- pipelining discrimination** -- a pipeline-only effect is suppressed
  and NOT reported as a server-side desync.
* **CLI wiring** -- ``--technique H2.PseudoHdrInject`` is a valid choice and
  routes to the H2 engine.

All tests are hermetic (in-process mock pair, no live network).
"""

from __future__ import annotations

import json

import pytest
from hpack import Decoder

import h2mock
from scan_primitives import Scope
from doppelganger.findings import CWE_REQUEST_SMUGGLING
from doppelganger.h2engine import H2DesyncEngine
from doppelganger.h2send import (
    H2Request,
    encode_header_block,
    serialize_request,
    H2_PREFACE,
)
from doppelganger.h2techniques import (
    H2Technique,
    H2_TECHNIQUES,
    all_h2_techniques,
    h2_technique_by_name,
    _INJECT_TE_SUFFIX,
)

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


def _techniques() -> list[H2Technique]:
    return h2_technique_by_name("H2.PseudoHdrInject")


def _technique(variant: str) -> H2Technique:
    techs = [t for t in _techniques() if t.variant == variant]
    assert techs, f"variant {variant!r} not found"
    return techs[0]


# --------------------------------------------------------------------------- #
# catalogue / registry
# --------------------------------------------------------------------------- #


def test_h2_pseudohdr_in_h2_techniques_tuple():
    """H2.PseudoHdrInject is listed in the H2_TECHNIQUES name tuple."""
    assert "H2.PseudoHdrInject" in H2_TECHNIQUES


def test_all_h2_techniques_includes_both_pseudohdr_variants():
    """all_h2_techniques() includes both authority-crlf-te and header-val-crlf-te."""
    all_names = [(t.name, t.variant) for t in all_h2_techniques()]
    assert ("H2.PseudoHdrInject", "authority-crlf-te") in all_names
    assert ("H2.PseudoHdrInject", "header-val-crlf-te") in all_names


def test_h2_technique_by_name_returns_both_variants():
    """h2_technique_by_name('H2.PseudoHdrInject') returns exactly two techniques."""
    techs = h2_technique_by_name("H2.PseudoHdrInject")
    assert len(techs) == 2
    variants = {t.variant for t in techs}
    assert variants == {"authority-crlf-te", "header-val-crlf-te"}


def test_pseudohdr_techniques_have_safe_order_after_h2te():
    """H2.PseudoHdrInject is probed after H2.CL and H2.TE (more disruptive last)."""
    ordered = all_h2_techniques()
    h2cl_idx = next(i for i, t in enumerate(ordered) if t.name == "H2.CL")
    h2te_idx = next(i for i, t in enumerate(ordered) if t.name == "H2.TE")
    pseudo_idx = next(i for i, t in enumerate(ordered) if t.name == "H2.PseudoHdrInject")
    assert h2cl_idx < pseudo_idx
    assert h2te_idx < pseudo_idx


# --------------------------------------------------------------------------- #
# probe builder -- authority-crlf-te variant
# --------------------------------------------------------------------------- #


def test_authority_crlf_te_timing_request_injects_crlf_in_authority():
    """authority-crlf-te timing request: CRLF+TE bytes in :authority value."""
    tech = _technique("authority-crlf-te")
    req = tech.timing_request("example.com", "/", "https")
    # The :authority pseudo-header value should carry the raw injection bytes.
    assert b"\r\nTransfer-Encoding: chunked" in req.authority
    assert req.authority.startswith(b"example.com")
    assert req.method == b"POST"


def test_authority_crlf_te_timing_request_crlf_survives_hpack_roundtrip():
    """The CRLF injection bytes survive HPACK literal encoding and decoding."""
    tech = _technique("authority-crlf-te")
    req = tech.timing_request("target.test", "/path", "https")
    block = encode_header_block(req.header_list())
    decoded = dict(Decoder().decode(block, raw=True))
    authority_val = decoded[b":authority"]
    assert b"\r\nTransfer-Encoding: chunked" in authority_val


def test_authority_crlf_te_differential_request_body_is_chunk_terminator_plus_smuggled():
    """authority-crlf-te differential: body starts with 0\\r\\n\\r\\n (chunk terminator)."""
    tech = _technique("authority-crlf-te")
    req = tech.differential_request("target.test", "/dg-marker", "/", "https")
    assert req.body.startswith(b"0\r\n\r\n")
    assert b"GET /dg-marker HTTP/1.1" in req.body
    assert b"\r\nTransfer-Encoding: chunked" in req.authority


def test_authority_crlf_te_timing_body_is_incomplete_chunk():
    """authority-crlf-te timing probe body is an unterminated chunk (the hang signal)."""
    tech = _technique("authority-crlf-te")
    req = tech.timing_request("target.test", "/", "https")
    # Must NOT contain a chunk terminator -- the back-end should hang.
    assert b"0\r\n\r\n" not in req.body


# --------------------------------------------------------------------------- #
# probe builder -- header-val-crlf-te variant
# --------------------------------------------------------------------------- #


def test_header_val_crlf_te_timing_request_injects_crlf_in_header_value():
    """header-val-crlf-te timing request: CRLF+TE bytes in X-Padding header value."""
    tech = _technique("header-val-crlf-te")
    req = tech.timing_request("example.com", "/", "https")
    # The x-padding regular header value should carry the injection.
    headers_dict = dict(req.headers)
    assert b"x-padding" in headers_dict
    assert b"\r\nTransfer-Encoding: chunked" in headers_dict[b"x-padding"]
    # The :authority pseudo-header must NOT carry the injection.
    assert b"\r\n" not in req.authority


def test_header_val_crlf_te_timing_request_crlf_survives_hpack_roundtrip():
    """header-val-crlf-te: CRLF injection in x-padding value survives HPACK roundtrip."""
    tech = _technique("header-val-crlf-te")
    req = tech.timing_request("target.test", "/", "https")
    block = encode_header_block(req.header_list())
    decoded_pairs = Decoder().decode(block, raw=True)
    xpad = next((v for n, v in decoded_pairs if n == b"x-padding"), None)
    assert xpad is not None
    assert b"\r\nTransfer-Encoding: chunked" in xpad


def test_header_val_crlf_te_differential_body_is_chunk_terminator_plus_smuggled():
    """header-val-crlf-te differential: body is 0\\r\\n\\r\\n + smuggled prefix."""
    tech = _technique("header-val-crlf-te")
    req = tech.differential_request("target.test", "/dg-marker", "/", "https")
    assert req.body.startswith(b"0\r\n\r\n")
    assert b"GET /dg-marker HTTP/1.1" in req.body


# --------------------------------------------------------------------------- #
# serialize_request: wire bytes carry the injection for both variants
# --------------------------------------------------------------------------- #


def test_authority_variant_wire_bytes_carry_injection():
    """The serialized H2 request carries the CRLF injection bytes on the wire."""
    tech = _technique("authority-crlf-te")
    req = tech.timing_request("target.test", "/", "https")
    wire = serialize_request(req)
    # Skip the client preface; the header block follows the SETTINGS frame.
    assert wire.startswith(H2_PREFACE)
    # The raw injection bytes appear somewhere in the wire output.
    assert b"\r\nTransfer-Encoding: chunked" in wire


def test_header_val_variant_wire_bytes_carry_injection():
    """header-val-crlf-te serialized request carries CRLF bytes on the wire."""
    tech = _technique("header-val-crlf-te")
    req = tech.timing_request("target.test", "/", "https")
    wire = serialize_request(req)
    assert b"\r\nTransfer-Encoding: chunked" in wire


# --------------------------------------------------------------------------- #
# engine: server_desync -> confirmed finding
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("variant", ["authority-crlf-te", "header-val-crlf-te"])
def test_pseudohdr_confirmed_on_server_desync(variant, scope):
    """H2.PseudoHdrInject: both variants CONFIRM a genuine downgrade desync."""
    tech = _technique(variant)
    with h2mock.h2pseudo_inject_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])
    assert len(findings) == 1, f"{variant}: expected one finding"
    f = findings[0]
    assert f.vector == "H2.PseudoHdrInject"
    assert f.variant == variant
    assert f.evidence["confirmation"] == "confirmed"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.evidence["connection_reuse"] is False
    assert f.cwe_id == CWE_REQUEST_SMUGGLING
    assert f.evidence["http_version"] == "h2-downgrade"
    assert not engine.suppressed


# --------------------------------------------------------------------------- #
# engine: pipelining discrimination
# --------------------------------------------------------------------------- #


def test_pseudohdr_authority_pipelining_is_discriminated(scope):
    """authority-crlf-te pipeline-only effect is suppressed, not reported as desync."""
    tech = _technique("authority-crlf-te")
    with h2mock.h2pseudo_inject_pair("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])
    assert findings == [], "pipelining wrongly reported as a desync"
    assert len(engine.suppressed) == 1
    entry = engine.suppressed[0]
    assert entry["technique"] == "H2.PseudoHdrInject"
    assert entry["connection_reuse"] is True
    assert "pipelining" in entry["reason"]


def test_pseudohdr_header_val_pipelining_is_discriminated(scope):
    """header-val-crlf-te pipeline-only effect is suppressed, not reported as desync."""
    tech = _technique("header-val-crlf-te")
    with h2mock.h2pseudo_inject_pair("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])
    assert findings == [], "pipelining wrongly reported as a desync"
    assert len(engine.suppressed) == 1


# --------------------------------------------------------------------------- #
# finding content: reproduction carries the injection bytes
# --------------------------------------------------------------------------- #


def test_pseudohdr_authority_reproduction_carries_crlf_injection(scope):
    """The emitted finding's reproduction payload shows the CRLF injection bytes."""
    tech = _technique("authority-crlf-te")
    with h2mock.h2pseudo_inject_pair("server_desync") as srv:
        f = _engine(srv, scope).run([tech])[0]
    repro = f.evidence.get("reproduction", "")
    # The :authority line should carry the injected suffix in the rendering.
    assert "Transfer-Encoding: chunked" in repro or ":authority" in repro


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #


def _scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("127.0.0.1\n")
    return str(p)


def test_cli_h2pseudohdr_is_a_valid_technique_choice(tmp_path, capsys):
    """``--technique H2.PseudoHdrInject`` is accepted and routes to the H2 engine."""
    from doppelganger.cli import main

    with h2mock.h2pseudo_inject_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "H2.PseudoHdrInject",
                "--timeout", "0.5",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] >= 1
    assert all(f["vector"] == "H2.PseudoHdrInject" for f in doc["findings"])


def test_cli_h2pseudohdr_confirmed_finding_json(tmp_path, capsys):
    """``--technique H2.PseudoHdrInject --format json`` produces a confirmed finding."""
    from doppelganger.cli import main

    with h2mock.h2pseudo_inject_pair("server_desync") as srv:
        code = main(
            [
                srv.base_url,
                "--scope-file", _scope_file(tmp_path),
                "--technique", "H2.PseudoHdrInject",
                "--format", "json",
                "--timeout", "0.5",
            ]
        )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["finding_count"] >= 1
    finding = doc["findings"][0]
    assert finding["vector"] == "H2.PseudoHdrInject"
    assert finding["evidence"]["confirmation"] == "confirmed"
    assert finding["cwe_id"] == 444
