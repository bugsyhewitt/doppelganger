# doppelganger v0.2 — HTTP/2 Desync Engine: Worker Output

## Status: COMPLETE

All v0.2 deliverables are shipped and all tests pass.

## What was done

### Assessment of branch state

The `v0.2-http2` branch (latest commit `6ac652f`) had the full H2 engine already
implemented:

- `src/doppelganger/h2send.py` — byte-exact HTTP/2 send layer: hand-rolled literal
  HPACK encoder (RFC 7541 §6.2.2, no Huffman, no validation) + hand-built H2 frames
  (RFC 7540 §4.1). Uses `hpack.Decoder` for response decoding only. Scope-enforced,
  fail-closed with no scope.
- `src/doppelganger/h2techniques.py` — H2.CL and H2.TE probe builders: timing probes
  (lying CL >> body length; unterminated chunked body) and differential attack payloads
  (CL:0 with smuggled body; chunked terminator + smuggled request).
- `src/doppelganger/h2engine.py` — two-stage H2 engine mirroring the v0.1 engine:
  timing candidate → differential confirmation + pipelining discrimination.
- `tests/h2mock.py` — in-process HTTP/2-downgrade mock: hand-rolled H2 frame parser
  (because `h2` rejects the prohibited headers on the server side too); models
  vulnerable downgrade (copies prohibited headers verbatim), pipeline-only mode, and
  the conformant (correct-downgrade) negative control.
- `tests/test_h2send.py` — 14 frame-level unit tests.
- `tests/test_h2engine.py` — 12 engine acceptance tests covering confirmation,
  pipelining discrimination, candidate staging, safe mode, negative control, CLI wiring.

### Fixes applied this lap

1. **Installed the worktree package** into the project venv so new modules were on
   `sys.path` (the venv had the old v0.1 install).

2. **Bumped version to 0.2.0** in:
   - `pyproject.toml` (`version = "0.2.0"`)
   - `src/doppelganger/__init__.py` (`__version__ = "0.2.0"`)
   - `README.md` (`--version` output reference)
   - `tests/test_wheel_ship_gate.py` (glob patterns and assertion strings still
     referenced `0.1.0`; updated all occurrences — this was the only failing test).

## Test results

80 passed, 7 skipped, 0 failed.

Skipped tests are `ship_gate` venv-install variants (require sibling libs at specific
paths; the build step itself passes) and the `integration` docker-compose lab test.

Full output: `test-output.txt`.

## v0.2 scope coverage

| Attack | Timing probe | Differential attack | In-process mock | CLI wiring |
|--------|-------------|--------------------|--------------------|------------|
| H2.CL  | content-length >> DATA length → back-end hangs | CL:0 + smuggled body | `h2cl_pair` / `h2cl_candidate_pair` | `--technique H2.CL` |
| H2.TE  | injected TE:chunked + unterminated chunk → back-end hangs | chunk terminator + smuggled request | `h2te_pair` | `--technique H2.TE` |
| H2 downgrade (conformant) | — | negative control: no finding | `h2_robust_pair` | n/a |

## Architecture

The H2 engine is a **separate low-level stack** as required:
- No reuse of the HTTP/1.1 `rawsend` sender.
- Hand-rolled literal HPACK + raw frame construction (high-level `h2`/`httpx` libs
  validate on send and refuse the prohibited framing these attacks require).
- ALPN `h2` negotiation for TLS targets; prior-knowledge plaintext H2 for the
  in-process test lab.
- R5 enforced: response bytes are parsed to (status, body) signatures only — never
  executed, shelled out, or passed to an LLM tool call.

## v0.2 NOT in scope (deferred)

H2C cleartext-upgrade, client-side desync, 0.CL, double-desync, Expect-based
desync, parser-discrepancy V-H/H-V engine, weaponization. All documented in the
README Roadmap section.
