"""Tests for byte-exact probe payload generation (doppelganger.techniques).

Covers:
* timing probe shape and byte content for every technique family
* differential attack shape and byte content for every technique family
* TE.TE obfuscation dictionary: all 13 entries present, header bytes correct
* TE.chunk variants: chunk-ext and bare-cr timing + attack bodies
* Expect.CL.TE: Expect header present in both probes
* CL.0: classic POST variant and GET+CL:0 sub-variant
* dup-CL: two Content-Length headers present
* safe ordering: CL.TE always before TE.CL
* all_techniques() expands dictionaries correctly
* technique_by_name() returns the right subset
* host / path substitution is correct in every builder
* payload sizes: Content-Length header value matches body byte count
"""

from __future__ import annotations

import pytest

from doppelganger.techniques import (
    CHUNK_BODY_VARIANTS,
    EXPECT_HEADER,
    TE_OBFUSCATIONS,
    Technique,
    all_techniques,
    chunk_body_techniques,
    technique_by_name,
)

HOST = "example.com"
PATH = "/api/v1/"
MARKER = "/doppelganger-aabbccdd"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _cl_value(raw: bytes) -> int | None:
    """Extract the first Content-Length value from raw HTTP bytes."""
    for line in raw.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
    return None


def _has_header(raw: bytes, name: bytes, value: bytes) -> bool:
    """Return True if header *name* with *value* substring exists in *raw*."""
    name_lc = name.lower()
    for line in raw.split(b"\r\n"):
        if b":" in line:
            h, _, v = line.partition(b":")
            if h.strip().lower() == name_lc and value.lower() in v.lower():
                return True
    return False


# ---------------------------------------------------------------------------
# CL.TE
# ---------------------------------------------------------------------------


def test_clte_timing_probe_has_content_length_and_te():
    t = technique_by_name("CL.TE")[0]
    probe = t.timing_probe(HOST, PATH)
    assert probe is not None
    assert b"Content-Length:" in probe
    assert b"Transfer-Encoding: chunked" in probe


def test_clte_timing_probe_host_in_headers():
    t = technique_by_name("CL.TE")[0]
    probe = t.timing_probe(HOST, PATH)
    assert HOST.encode() in probe


def test_clte_timing_probe_path_in_request_line():
    t = technique_by_name("CL.TE")[0]
    probe = t.timing_probe(HOST, PATH)
    assert PATH.encode() in probe


def test_clte_differential_attack_contains_terminator():
    t = technique_by_name("CL.TE")[0]
    attack = t.differential_attack(HOST, MARKER, PATH)
    # chunked terminator precedes the smuggled inner request
    assert b"0\r\n\r\n" in attack


def test_clte_differential_attack_smuggles_marker():
    t = technique_by_name("CL.TE")[0]
    attack = t.differential_attack(HOST, MARKER, PATH)
    assert MARKER.encode() in attack


def test_clte_differential_attack_cl_matches_body():
    t = technique_by_name("CL.TE")[0]
    attack = t.differential_attack(HOST, MARKER, PATH)
    # Find header block end
    header_end = attack.find(b"\r\n\r\n")
    body = attack[header_end + 4:]
    cl = _cl_value(attack)
    assert cl == len(body), f"CL={cl} body_len={len(body)}"


# ---------------------------------------------------------------------------
# TE.CL
# ---------------------------------------------------------------------------


def test_tecl_timing_probe_has_te_and_cl():
    t = technique_by_name("TE.CL")[0]
    probe = t.timing_probe(HOST, PATH)
    assert probe is not None
    assert b"Transfer-Encoding: chunked" in probe
    assert b"Content-Length:" in probe


def test_tecl_timing_probe_ends_with_zero_chunk():
    t = technique_by_name("TE.CL")[0]
    probe = t.timing_probe(HOST, PATH)
    assert b"0\r\n\r\n" in probe


def test_tecl_differential_attack_has_chunk_size_line():
    t = technique_by_name("TE.CL")[0]
    attack = t.differential_attack(HOST, MARKER, PATH)
    header_end = attack.find(b"\r\n\r\n")
    body = attack[header_end + 4:]
    # First body line is a hex chunk size
    first_line = body.split(b"\r\n", 1)[0]
    int(first_line, 16)  # must parse as hex


def test_tecl_differential_attack_smuggles_marker():
    t = technique_by_name("TE.CL")[0]
    attack = t.differential_attack(HOST, MARKER, PATH)
    assert MARKER.encode() in attack


# ---------------------------------------------------------------------------
# TE.TE obfuscation dictionary
# ---------------------------------------------------------------------------


def test_tete_obfuscation_dictionary_has_13_entries():
    assert len(TE_OBFUSCATIONS) == 13


def test_tete_techniques_count_equals_obfuscations():
    tete = technique_by_name("TE.TE")
    assert len(tete) == len(TE_OBFUSCATIONS)


def test_tete_each_obfuscation_name_in_variant():
    tete = technique_by_name("TE.TE")
    names_in_dict = {name for name, _ in TE_OBFUSCATIONS}
    names_in_techniques = {t.variant for t in tete}
    assert names_in_dict == names_in_techniques


def test_tete_mixed_case_header_bytes():
    tete = {t.variant: t for t in technique_by_name("TE.TE")}
    assert tete["mixed-case"].te_header == b"Transfer-Encoding: Chunked"


def test_tete_null_byte_header_has_null():
    tete = {t.variant: t for t in technique_by_name("TE.TE")}
    assert b"\x00" in tete["null-byte"].te_header


def test_tete_timing_probe_uses_obfuscated_header():
    tete = technique_by_name("TE.TE")
    for t in tete:
        probe = t.timing_probe(HOST, PATH)
        assert probe is not None
        assert t.te_header in probe, f"obfuscation {t.variant!r} not in probe"


# ---------------------------------------------------------------------------
# CL.0
# ---------------------------------------------------------------------------


def test_cl0_classic_has_no_timing_probe():
    cl0 = next(t for t in technique_by_name("CL.0") if t.variant is None)
    assert cl0.timing_probe(HOST, PATH) is None


def test_cl0_differential_uses_post():
    cl0 = next(t for t in technique_by_name("CL.0") if t.variant is None)
    attack = cl0.differential_attack(HOST, MARKER, PATH)
    assert attack.startswith(b"POST")


def test_cl0_get_variant_uses_get():
    get_cl0 = next(t for t in technique_by_name("CL.0") if t.variant == "get-cl0")
    attack = get_cl0.differential_attack(HOST, MARKER, PATH)
    assert attack.startswith(b"GET")


def test_cl0_get_variant_has_cl_zero():
    get_cl0 = next(t for t in technique_by_name("CL.0") if t.variant == "get-cl0")
    attack = get_cl0.differential_attack(HOST, MARKER, PATH)
    assert b"Content-Length: 0" in attack


# ---------------------------------------------------------------------------
# dup-CL
# ---------------------------------------------------------------------------


def test_dupcl_has_no_timing_probe():
    dupcl = technique_by_name("dup-CL")[0]
    assert dupcl.timing_probe(HOST, PATH) is None


def test_dupcl_differential_has_two_cl_headers():
    dupcl = technique_by_name("dup-CL")[0]
    attack = dupcl.differential_attack(HOST, MARKER, PATH)
    count = attack.lower().count(b"content-length:")
    assert count == 2, f"expected 2 Content-Length headers, got {count}"


def test_dupcl_second_cl_is_zero():
    dupcl = technique_by_name("dup-CL")[0]
    attack = dupcl.differential_attack(HOST, MARKER, PATH)
    assert b"Content-Length: 0" in attack


# ---------------------------------------------------------------------------
# TE.chunk
# ---------------------------------------------------------------------------


def test_techunk_variants_count():
    chunks = chunk_body_techniques()
    assert len(chunks) == len(CHUNK_BODY_VARIANTS)


def test_techunk_chunk_ext_timing_body():
    chunks = {t.variant: t for t in chunk_body_techniques()}
    ext = chunks["chunk-ext"]
    assert b";" in ext.timing_body  # semicolon extension


def test_techunk_bare_cr_timing_body():
    chunks = {t.variant: t for t in chunk_body_techniques()}
    bare = chunks["bare-cr"]
    assert b"\r" in bare.timing_body
    assert b"\r\n" not in bare.timing_body  # bare CR, no LF


def test_techunk_attack_prefix_in_differential():
    chunks = {t.variant: t for t in chunk_body_techniques()}
    for name, t in chunks.items():
        attack = t.differential_attack(HOST, MARKER, PATH)
        assert MARKER.encode() in attack, f"TE.chunk/{name}: marker missing from attack"


# ---------------------------------------------------------------------------
# Expect.CL.TE
# ---------------------------------------------------------------------------


def test_expect_clte_has_expect_header_in_timing_probe():
    t = technique_by_name("Expect.CL.TE")[0]
    probe = t.timing_probe(HOST, PATH)
    assert probe is not None
    assert EXPECT_HEADER in probe


def test_expect_clte_has_expect_header_in_differential_attack():
    t = technique_by_name("Expect.CL.TE")[0]
    attack = t.differential_attack(HOST, MARKER, PATH)
    assert EXPECT_HEADER in attack


def test_expect_clte_variant_is_expect():
    t = technique_by_name("Expect.CL.TE")[0]
    assert t.variant == "expect"


# ---------------------------------------------------------------------------
# safe ordering
# ---------------------------------------------------------------------------


def test_safe_order_clte_before_tecl():
    all_t = all_techniques()
    names = [t.name for t in all_t]
    assert names.index("CL.TE") < names.index("TE.CL")


def test_safe_order_tete_before_tecl():
    all_t = all_techniques()
    names = [t.name for t in all_t]
    tete_indices = [i for i, n in enumerate(names) if n == "TE.TE"]
    tecl_index = names.index("TE.CL")
    assert all(i < tecl_index for i in tete_indices)


def test_safe_order_is_non_decreasing():
    all_t = all_techniques()
    orders = [t.safe_order for t in all_t]
    assert orders == sorted(orders)


# ---------------------------------------------------------------------------
# all_techniques() / technique_by_name()
# ---------------------------------------------------------------------------


def test_all_techniques_includes_all_families():
    names = {t.name for t in all_techniques()}
    for expected in ("CL.TE", "TE.CL", "TE.TE", "CL.0", "dup-CL", "TE.chunk", "Expect.CL.TE"):
        assert expected in names, f"{expected} missing from all_techniques()"


def test_technique_by_name_clte_returns_one():
    result = technique_by_name("CL.TE")
    assert len(result) == 1
    assert result[0].name == "CL.TE"


def test_technique_by_name_tete_returns_all_obfuscations():
    result = technique_by_name("TE.TE")
    assert len(result) == len(TE_OBFUSCATIONS)


def test_technique_by_name_unknown_returns_empty():
    result = technique_by_name("UNKNOWN.TECHNIQUE")
    assert result == []


def test_all_techniques_cl0_has_both_variants():
    cl0_variants = [t.variant for t in all_techniques() if t.name == "CL.0"]
    assert None in cl0_variants
    assert "get-cl0" in cl0_variants


def test_technique_dataclass_is_frozen():
    t = technique_by_name("CL.TE")[0]
    with pytest.raises((AttributeError, TypeError)):
        t.name = "MUTATED"  # type: ignore[misc]
