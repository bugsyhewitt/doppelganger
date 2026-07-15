# doppelganger v0.6 — Expect.CL.TE probe + rawsend 1xx skipping

## Status: COMPLETE

## Improvement shipped

**v0.6: `Expect: 100-continue` desync probe** — one focused addition landing two concrete improvements:

1. **rawsend 1xx skipping** (`src/doppelganger/rawsend.py`): `_read_response` previously stopped at the first complete HTTP response, including 1xx interim responses. When a front-end sends `HTTP/1.1 100 Continue` before the final response, the reader returned status 100 immediately (no timeout = no timing signal). The fixed implementation scans for and discards all 1xx responses from the accumulation buffer without blocking on `recv`, then continues waiting for the final 2xx–5xx response. This is a correctness fix and the prerequisite for any Expect-based probing.

2. **`Expect.CL.TE` technique** (`src/doppelganger/techniques.py`, `src/doppelganger/findings.py`, `src/doppelganger/cli.py`): A CL.TE probe that includes `Expect: 100-continue` in the request headers. Some front-ends send `100 Continue` before forwarding the body to the back-end, exercising a distinct code path compared to a plain CL.TE POST. The timing probe and differential attack are structurally identical to CL.TE (Content-Length framing on the front, chunked on the back), but the Expect header may trigger different body-forwarding behaviour. With the 1xx fix in place, the engine correctly measures the back-end hang (the timing signal) even when the front-end's 100 Continue precedes it.

## Files changed

| File | Change |
|------|--------|
| `src/doppelganger/rawsend.py` | `_status_code()` helper + restructured `_read_response` loop to skip 1xx before blocking on recv |
| `src/doppelganger/techniques.py` | `EXPECT_HEADER` constant; `extra_headers: tuple[bytes, ...]` field on `Technique`; `Expect.CL.TE` entry in `all_techniques()`; timing_probe/differential_attack plumbed through extra_headers |
| `src/doppelganger/findings.py` | `"Expect.CL.TE"` added to `TECHNIQUES` tuple |
| `tests/mockpair.py` | `_has_expect_continue`, `ExpectMockPair`, `expect_clte_pair` factory |
| `tests/test_expect_probe.py` | 18 new unit tests (new file) |
| `tests/test_findings.py` | Updated hardcoded TECHNIQUES check to set membership |
| `src/doppelganger/__init__.py` | Version: `0.5.0` → `0.6.0` |
| `pyproject.toml` | Version: `0.5.0` → `0.6.0` |
| `README.md` | Techniques table updated; v0.6 roadmap entry; CLI help updated |

## Test results

134 unit tests pass (`pytest -m "not ship_gate and not integration"`).

New tests (18) in `tests/test_expect_probe.py` cover:
- Technique registration (in all_techniques, safe_order, variant, discrepancy)
- Probe payload shape (Expect header present in timing probe and differential attack)
- rawsend 1xx skipping: timeout after 100+hang, correct 200 after 100+200, multiple 1xx skipped
- Engine: confirmed desync on ExpectMockPair, candidate without poison, pipelining suppressed, detection on Expect-unaware servers, no false positive on robust pair
- CLI: `--technique Expect.CL.TE` accepted
