# doppelganger — `--retries` timing-probe stabilisation

## Status: COMPLETE

## Improvement shipped

**`--retries N` flag for timing-probe stabilisation** — reduces false-positive
timing candidates from transient network timeouts without masking real desyncs.

### What changed

- **`--retries N`** (new CLI argument, default `0`): when the timing probe
  times out, the engine sends up to N additional identical timing probes.
  A genuine back-end hang is stable and times out on every retry; a transient
  network timeout (jitter, brief overload) typically clears on the first retry.
  The timing signal is only treated as stable if ALL probes (original + retries)
  time out.

- **`DesyncEngine.retries` parameter**: the engine stores `max(0, int(retries))`
  and runs the retry loop in `_probe_technique` before the differential stage.
  The loop breaks as soon as any retry responds (signal cleared). If the loop
  exhausts all retries and every probe timed out, `timed_out` remains `True`.

- **Scope**: retries apply to the HTTP/1.1 engine only (`DesyncEngine`). The H2
  (`H2DesyncEngine`) and H2C (`H2CEngine`) engines do not implement retries and
  ignore the flag at the CLI level (noted in the `--retries` help text).

### Design decisions

The retry mechanism is deliberately strict: a single non-timeout among the
retries clears the flag. A lenient majority-vote (e.g. 2/3 must timeout) would
require more scan latency and adds complexity without a proportional correctness
gain. The delta-threshold path (`timing_delta_ms >= threshold`) is not retried —
it is already a softer, non-binary signal and retrying it would double/triple
scan time for the marginal case.

Negative `retries` values are clamped to 0 at construction time.

### CLI help excerpt

```
--retries N    retry the timing probe up to N additional times when it times
               out (default: 0). A genuine back-end hang is stable and times
               out on every retry; a transient network timeout typically clears
               on the first retry and is not reported as a timing signal.
               Recommended for targets with high-jitter network paths
               (--retries 1 or --retries 2). Applies to the HTTP/1.1 engine
               only; H2 and H2C engines ignore this flag.
```

## Files changed

| File | Change |
|------|--------|
| `src/doppelganger/engine.py` | `retries` parameter added to `__init__`; retry loop in `_probe_technique` |
| `src/doppelganger/cli.py` | `--retries N` argument in `build_parser()`; wired to `DesyncEngine` in `_scan_single()` |
| `tests/test_retries.py` | 12 new unit tests (new file) |
| `README.md` | `--retries` in Options section |

## Test results

165 unit tests pass (`pytest -m "not ship_gate and not integration"`).
153 were passing before this change; 12 new tests in `tests/test_retries.py` cover:

- Constructor: default is 0; stored correctly; negative clamped to 0
- Stable hang with retries=1: candidate still produced (signal preserved)
- Stable hang with retries=2: candidate still produced
- Stable hang confirmed desync with retries=2: confirmed still produced
- Transient timeout cleared by 1 retry: no timing candidate
- Transient timeout, retries=0: single timeout raises candidate (backward compat)
- Retries=2, first retry clears signal immediately: no candidate
- Retries=2, first two time out but third succeeds: no candidate (not stable)
- CLI: `--retries 1` wired to engine; confirmed desync still confirmed
- CLI: `--retries 0` explicit same as no flag
