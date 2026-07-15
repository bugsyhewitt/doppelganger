# doppelganger — H2.PseudoHdrInject CRLF-injection technique (v0.8)

## Status: COMPLETE

## Improvement shipped

**`H2.PseudoHdrInject` technique** — a third H2-downgrade attack class that
injects `\r\nTransfer-Encoding: chunked` into a header *value* rather than as
a prohibited regular header (H2.TE). Exploits a distinct vulnerable code path in
H2→H1 downgraders: servers that copy decoded header values verbatim without
stripping CR+LF.

### What changed

**New `H2.PseudoHdrInject` technique** with two variants:

- **`authority-crlf-te`**: Injects `\r\nTransfer-Encoding: chunked` into the
  `:authority` pseudo-header value. A vulnerable H2→H1 downgrader that copies the
  decoded authority into the `Host:` header without stripping CR+LF produces an
  extra `Transfer-Encoding: chunked` line in the H1 view.

- **`header-val-crlf-te`**: Injects `\r\nTransfer-Encoding: chunked` into a
  regular `X-Padding` header value. A downgrader that does not sanitise CRLF in
  non-pseudo header values injects the TE header into the H1 view.

Both variants use the same two-stage engine shape as H2.TE: the injected TE
switches the H1 back-end to chunked parsing; an unterminated chunk hangs it
(timing candidate); a chunk-terminator + smuggled prefix confirms differentially.
Pipelining discrimination runs on both variants as on all H2 techniques.

**Technical approach:**

RFC 9113 §8.2.1 prohibits CR+LF in H2 header values. The existing literal-HPACK
send layer (`h2send.encode_literal_header`) carries bytes verbatim with no
validation — the same property that allows H2.TE to bypass high-level library
validation now carries CRLF injection bytes to the wire for H2.PseudoHdrInject.
A conformant HPACK decoder round-trips the values intact (proven in tests).

**Why this is distinct from H2.TE:**

- H2.TE adds `transfer-encoding: chunked` as a *regular* header in the H2
  `headers` tuple. Front-ends that strip prohibited regular headers (by header
  name) but naively copy pseudo-header or other header values are NOT caught by
  H2.TE but ARE caught by H2.PseudoHdrInject.
- The two variants target different downgrade code paths: `authority-crlf-te`
  exploits the pseudo-header → `Host:` conversion; `header-val-crlf-te` exploits
  value passthrough in regular-header copying.

### Design decisions

- Reused the existing `H2Technique` dataclass (added `"H2.PseudoHdrInject"`
  dispatch in `timing_request()` and `differential_request()`). No new class
  needed; the frozen dataclass with `variant` field handles the two sub-variants.
- Safe order: `safe_order=2`, after H2.CL (0) and H2.TE (1). The TE-style hang
  is disruptive so both TE-family techniques probe last.
- `H2_TECHNIQUES` tuple extended to `("H2.CL", "H2.TE", "H2.PseudoHdrInject")`;
  CLI `--technique H2.PseudoHdrInject` routing is automatic via the existing
  `args.technique in H2_TECHNIQUES` dispatch.
- Added `h2pseudo_inject_pair()` factory to `h2mock.py`. The existing mock's
  `_downgrade()` already copies `:authority` and regular header values verbatim,
  so the CRLF injection is preserved. The `te()` back-end strategy finds the
  injected TE header via `_has_chunked_te()` which joins header bytes and searches
  for `transfer-encoding` + `chunked`.

### Files changed

| File | Change |
|------|--------|
| `src/doppelganger/h2techniques.py` | `H2.PseudoHdrInject` dispatch in `timing_request()` / `differential_request()`; `_INJECT_TE_SUFFIX` constant; updated `H2_TECHNIQUES`, `all_h2_techniques()` |
| `src/doppelganger/__init__.py` | version `0.7.0` → `0.8.0` |
| `pyproject.toml` | version `0.7.0` → `0.8.0` |
| `tests/h2mock.py` | `h2pseudo_inject_pair()` factory |
| `tests/test_h2_pseudohdr.py` | 20 new tests (new file) |
| `README.md` | H2.PseudoHdrInject in techniques table, roadmap v0.8 section, `--version` text, module table |

## Test results

185 unit tests pass (`pytest -m "not ship_gate and not integration"`).
165 were passing before this change; 20 new tests in `tests/test_h2_pseudohdr.py` cover:

- Catalogue: H2.PseudoHdrInject in H2_TECHNIQUES tuple
- Catalogue: all_h2_techniques() includes both variants
- Catalogue: h2_technique_by_name returns both variants
- Safe ordering: PseudoHdrInject after H2.CL and H2.TE
- authority-crlf-te timing request: CRLF in :authority value
- authority-crlf-te timing request: CRLF survives HPACK round-trip
- authority-crlf-te differential request: body is chunk terminator + smuggled prefix
- authority-crlf-te timing body: incomplete chunk (no 0\\r\\n\\r\\n)
- header-val-crlf-te timing request: CRLF in X-Padding value
- header-val-crlf-te timing request: CRLF survives HPACK round-trip
- header-val-crlf-te differential: body is chunk terminator + smuggled prefix
- Wire bytes: authority variant carries CRLF in serialized request
- Wire bytes: header-val variant carries CRLF in serialized request
- Engine: authority-crlf-te CONFIRMED on server_desync mock
- Engine: header-val-crlf-te CONFIRMED on server_desync mock
- Engine: authority pipelining discriminated (NOT reported as desync)
- Engine: header-val pipelining discriminated (NOT reported as desync)
- Finding: reproduction payload contains CRLF injection evidence
- CLI: --technique H2.PseudoHdrInject is accepted, confirmed finding emitted
- CLI: --format json produces confirmed finding with correct vector/CWE
