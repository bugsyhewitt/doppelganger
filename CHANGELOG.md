# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- README comic card header image.
- GitHub Actions pytest CI workflow (PR #12).

### Fixed
- `ship_gate` wheel test: install `h2` before running the H2-technique
  smoke-probe so the pre-installed dependency is available in the fresh venv
  (PR #12).

### Changed
- Quality sweep: corrected H2/H2C protocol labels in CLI output, removed dead
  code, fixed receive-buffer copy in the raw-socket layer (PR #11).

## [1.0.0] - 2026-07-15

First stable release. Consolidates v0.1 through v0.9 — all nine technique
families (CL.TE, TE.CL, TE.TE, CL.0, dup-CL, TE.chunk, Expect.CL.TE, H2.CL,
H2.TE, H2.PseudoHdrInject) plus H2C detection — proven by 201 unit tests. The
`ship_gate` suite builds a wheel and exercises the installed CLI end-to-end
against the in-process mock pair. No new techniques in this release; focus is
correctness, release hygiene, and the 1.0.0 stability contract (PR #10).

## [0.9.0] - 2026-07-15

### Added
- Scan summary statistics block in every output format (PR #9).
  - `--format json`: `"summary"` top-level key — `targets_scanned`,
    `targets_errored`, `finding_count`, `suppressed_pipelining_count`,
    `elapsed_ms`, and (when findings exist) `findings_by_severity`.
  - `--format sarif`: summary embedded in
    `runs[0]["properties"]["doppelganger/scanSummary"]` for GitHub Code
    Scanning / CI SAST dashboards.
  - `--format h1md`: `## Scan Summary` table appended to the report —
    targets scanned, findings, suppressed pipelining count, elapsed time.

## [0.8.0] - 2026-07-15

### Added
- `H2.PseudoHdrInject` CRLF-injection desync technique (PR #8). Two variants
  that exploit distinct vulnerable code paths in HTTP/2-to-HTTP/1.1
  downgraders:
  - `authority-crlf-te` — CR+LF injected into the `:authority` pseudo-header
    value; a downgrader that copies the decoded authority into `Host:` without
    stripping CR+LF produces an extra `Transfer-Encoding: chunked` line.
  - `header-val-crlf-te` — CR+LF injected into a regular header value
    (`X-Padding`); a downgrader that does not sanitise CRLF in non-pseudo
    header values injects the TE header into the H1 view.
  - RFC 9113 §8.2.1 prohibits CR+LF in H2 header values; the literal-HPACK
    send layer carries the bytes to the wire verbatim.
  - Both variants use the two-stage timing-hang → differential-confirmation
    engine and pipelining discrimination, same as H2.CL / H2.TE.

## [0.7.1] - 2026-07-15

### Added
- `--retries N` flag: retry the timing probe up to N additional times on
  timeout (PR #7). A genuine back-end hang is stable across retries; a
  transient network timeout typically clears on the first retry and is
  suppressed. Recommended for high-jitter paths (`--retries 1` or
  `--retries 2`). Applies to the HTTP/1.1 engine only; H2 and H2C engines
  ignore the flag.

## [0.7.0] - 2026-07-15

### Added
- `--target-file FILE` multi-target scanning (PR #6). Reads a
  newline-delimited URL file (lines starting with `#` are comments, blank
  lines skipped). All targets are scanned sequentially with the selected
  technique; findings and suppressed-pipelining entries are aggregated into a
  single output document. Out-of-scope targets are reported to stderr and
  skipped. Exit code is `1` if any target produced a finding, `0` if all
  clean, `3` on a scope/file error.

## [0.6.0] - 2026-07-15

### Added
- `Expect.CL.TE` technique: a CL.TE probe that includes `Expect:
  100-continue` (PR #5). Probes front-ends that send a `100 Continue`
  interim response before forwarding the body to a TE-based back-end,
  exercising a distinct server code path. A TE back-end that receives only
  the front-end's Content-Length bytes (an incomplete chunk) hangs, producing
  the timing signal; the differential attack then confirms.

### Fixed
- `rawsend._read_response` now skips interim 1xx responses (100 Continue,
  102 Processing, etc.) and waits for the final 2xx–5xx response. Without
  this fix the timing signal from an Expect-aware front-end was lost because
  the client stopped reading at the `100 Continue`.

## [0.5.0] - 2026-07-15

### Added
- `CL.0` GET+CL:0 probe sub-variant (PR #4): a dedicated probe that sends a
  `GET` request with `Content-Length: 0` to exercise front-ends that
  interpret Content-Length differently on GET vs. POST — a distinct
  discrepancy surface from the POST-based CL.0 probe.

## [0.4.0] - 2026-07-14

### Added
- TE.TE obfuscation dictionary expanded from 8 to 13 entries (PR #3). Five
  new parser-discrepancy variants: `mixed-case` (`Chunked`), `null-byte`
  (null after value), `bare-cr-end` (bare CR at end of header value),
  `ows-trailer` (trailing OWS), `comma-chunk` (comma-prefix list entry).
- `TE.chunk` technique family — two chunk-body-level variants:
  - `chunk-ext` — chunk size line carries a semicolon extension (`1;x=p`);
    strict back-ends reject the non-hex token; lenient back-ends strip it.
  - `bare-cr` — chunk line endings use bare CR (`\r`) instead of CRLF;
    strict parsers cannot find the chunk boundary and hang (timing
    candidate).

## [0.3.0] - 2026-07-14

### Added
- H2C cleartext-upgrade detection (PR #2). Probes HTTP/1.1 front-ends for
  `Upgrade: h2c` acceptance (RFC 7540 §3.2) and confirms genuine H2
  capability by completing the connection handshake (client preface + SETTINGS
  exchange). Wired to `--technique H2C` (note: listed under Techniques as a
  separate technique from the H2-downgrade family).

## [0.2.0] - 2026-07-14

### Added
- HTTP/2-downgrade desync engine (PR #1):
  - `h2send` — byte-exact HTTP/2 send layer: literal HPACK + hand-built
    frames carrying the RFC-prohibited framing H2.CL / H2.TE need; ALPN `h2`;
    scope-enforced. High-level H2 libraries validate on send and refuse the
    prohibited headers — a custom low-level sender is required.
  - `h2engine` — two-stage HTTP/2-downgrade detector, mirroring `engine`
    over the H2 transport (timing hang → differential confirmation +
    pipelining discrimination).
  - `h2techniques` — H2.CL / H2.TE downgrade probe builders.
  - `H2.CL` technique: H2 request carries a `content-length` that disagrees
    with the DATA frame length; a vulnerable downgrade copies it into the
    HTTP/1.1 request verbatim.
  - `H2.TE` technique: H2 request carries an RFC-prohibited
    `transfer-encoding: chunked` regular header; a vulnerable downgrade copies
    it through.
  - In-process HTTP/2-downgrade mock (`tests/h2mock.py`) for hermetic H2
    unit tests.

## [0.1.0] - 2026-07-02

### Added
- HTTP/1.1 desync detection family — five techniques on day one:
  `CL.TE`, `TE.CL`, `TE.TE` (8-entry obfuscation dictionary), `CL.0`,
  `dup-CL`.
- Two-stage engine: timing-based detection → differential-response
  confirmation. Emits a **candidate** on a significant timing delta; upgrades
  to **confirmed** when a smuggled prefix makes a follow-up request return a
  materially different response.
- Pipelining-vs-smuggling false-positive discrimination. Any effect that
  reproduces only under client-side connection reuse is flagged/suppressed
  as probable pipelining, not reported as a server-side desync. Explicit
  connection-reuse control via `--reuse-connection` / `--no-reuse-connection`.
- Safe-testing defaults: CL.TE probed before TE.CL (a TE.CL timing probe
  can hang and disrupt other users if the target is actually CL.TE);
  per-probe connection isolation; bounded + randomised timeouts; `--safe`
  mode. No poisoned socket left in a shared pool.
- Byte-exact raw-socket HTTP/1.1 sender (`rawsend`): no header
  normalisation; scope-enforced before egress; connection-reuse
  controllable. Normalising high-level HTTP clients cannot carry smuggling
  probes — a dedicated raw sender is required by the architecture.
- `scan-primitives`-backed baseline/differential client for well-formed
  requests. Both transports share one `Scope` object so scope is checked on
  every outbound path.
- Suite finding schema (CWE-444), SARIF 2.1.0 output, and HackerOne
  markdown output via `h1-reporter`.
- In-process raw-socket mock front/back pair (`tests/mockpair.py`) with
  opposite length rules to synthesize any `X.Y` discrepancy deterministically
  — proves detection, differential confirmation, and pipelining discrimination
  without container flakiness.
- Docker CI integration lab: pinned HAProxy 1.7.9 (CVE-2019-18277) +
  gunicorn 20.0.4 — a frozen discrepant pair for reproducible integration
  tests. Gated behind the `integration` pytest marker; skips cleanly if
  Docker is absent.
- Integration test fix: corrected the discrepant-pair premise for the
  pipelining-discrimination probe (p-doppelganger-pipelining-001).
