# doppelganger — v1.0.0 release

## Status: COMPLETE

## What this release does

**v1.0.0** is the stable consolidation release of doppelganger. It bumps the
version from 0.9.0 to 1.0.0 and carries a clean 201-test suite (all passing)
that covers all nine technique families and H2C detection built across v0.1–v0.9.

No new techniques were added in this release; the focus is correctness, release
hygiene, and the 1.0.0 stability contract.

## Technique coverage (all proven by unit tests)

**HTTP/1.1 desync family:**
- CL.TE, TE.CL, TE.TE (13-entry obfuscation dictionary), CL.0, dup-CL
- TE.chunk (chunk-ext, bare-cr variants)
- Expect.CL.TE

**HTTP/2-downgrade family (hand-rolled literal HPACK + raw H2 frames):**
- H2.CL, H2.TE
- H2.PseudoHdrInject (authority-crlf-te, header-val-crlf-te)

**H2C cleartext-upgrade detection**

**Output formats:** `--format json/sarif/h1md` all include scan summary statistics

**Multi-target scanning:** `--target-file`, `--retries`, `--timeout`

## Files changed for this release

| File | Change |
|------|--------|
| `pyproject.toml` | version `0.9.0` → `1.0.0` |
| `src/doppelganger/__init__.py` | `__version__` `"0.9.0"` → `"1.0.0"` |
| `tests/test_wheel_ship_gate.py` | version strings `0.5.0` → `1.0.0` |
| `README.md` | `--version` output updated; v1.0.0 Roadmap entry added |
| `output.md` | this file |
| `test-output.txt` | updated test run output |

## Test results

201 passed, 8 deselected (ship_gate + integration markers excluded per task spec)
in ~47 seconds. All tests pass cleanly.

```
pytest -m "not ship_gate and not integration" -q
201 passed, 8 deselected in 47.20s
```

The `ship_gate` marker tests were updated to reference version `1.0.0` (were
stale at `0.5.0` from an earlier worker lap).
