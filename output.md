# doppelganger v0.7 — Multi-target scanning (`--target-file`)

## Status: COMPLETE

## Improvement shipped

**v0.7: `--target-file` multi-target scanning** — one focused addition that lets
users scan a list of target URLs from a file in a single invocation.

### What changed

- **`--target-file FILE`** (new CLI argument): reads a newline-delimited file of
  target URLs (same comment/blank-line format as `--scope-file`). Mutually
  exclusive with the positional URL argument.
- **Sequential multi-target scan**: all targets are probed in sequence using the
  selected technique. Findings and suppressed-pipelining entries from all targets
  are aggregated into a single output document (JSON/SARIF/h1md).
- **Graceful per-target error handling**: out-of-scope or unparseable targets are
  reported to stderr and skipped; scanning continues with the remaining targets.
- **Exit code semantics preserved**: `1` if any finding across all targets, `0`
  if all clean, `3` on a fatal error (missing scope/target file, or all targets
  failed with scope errors).

### Design decisions

The engine routing logic was extracted from `run()` into `_scan_single()`, which
returns `(findings, suppressed, exit_code)` for one target. `run()` now builds
the target list (from `args.target_file` or `[args.target]`) and calls
`_scan_single()` in a loop. Scope is loaded once and shared across all targets —
no redundant file reads. `main()` validates the mutual-exclusion constraint before
calling `run()`.

## Files changed

| File | Change |
|------|--------|
| `src/doppelganger/cli.py` | `_load_target_file()` helper; `_scan_single()` extracted from `run()`; `run()` now iterates over a target list; `--target-file` added to `build_parser()`; `main()` validates target/target-file mutual exclusion |
| `src/doppelganger/__init__.py` | Version: `0.6.0` → `0.7.0` |
| `pyproject.toml` | Version: `0.6.0` → `0.7.0` |
| `tests/test_target_file.py` | 19 new unit tests (new file) |
| `README.md` | `--target-file` in Options table; new "Multi-target scanning" section with example; v0.7 roadmap entry |

## Test results

153 unit tests pass (`pytest -m "not ship_gate and not integration"`).

New tests (19) in `tests/test_target_file.py` cover:
- `_load_target_file`: parses plain URLs, skips comments, skips blank lines,
  strips trailing whitespace, returns empty list for all-comment file, raises
  OSError on missing file
- CLI validation: `--target-file` accepted by parser; mutual exclusion error
  when both positional URL and `--target-file` are given; exit 2 when neither
  is provided; exit 3 for missing target file; exit 3 for empty target file
- Single target via `--target-file`: confirmed desync → exit 1; clean → exit 0
- Multi-target: findings aggregated across two vulnerable targets; all clean → exit 0;
  out-of-scope target skipped, in-scope target still scanned; suppressed
  pipelining entries from multiple targets aggregated
- Output format: `--format sarif` works with `--target-file`
- Regression: `--version` still exits 0
