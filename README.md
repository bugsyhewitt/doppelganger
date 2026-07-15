# doppelganger

Headless HTTP/1.1 **request-smuggling / desync** detection and differential
confirmation for authorized bug-bounty and penetration-testing engagements.

doppelganger is the modern, Burp-free successor to the dead-ancestor
[`smuggler.py`](https://github.com/defparam/smuggler). It detects the HTTP/1.1
desync family and -- crucially -- **differentially confirms** it, with
first-class pipelining-vs-smuggling false-positive discrimination and
safe-testing defaults. That confirmation/correctness layer is the thing
`smuggler.py` never had and the reason its raw output can't be trusted against
real targets.

## Ethical Use

You are responsible for ensuring you have authorization to test any target.
Only probe systems you own or have explicit written permission to test. A desync
probe sends malformed HTTP to a live server and, used carelessly, can disrupt
**other users** of a shared front-end/back-end -- safe-testing defaults exist for
this reason, and scope is enforced before any probe. Use of this tool against
unauthorized targets may violate computer-fraud laws. The authors accept no
liability for misuse.

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/doppelganger
cd doppelganger
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Scope file format

A plain-text file, one entry per line. Entries can be:

- Hostnames: `api.example.com`
- IP addresses: `10.0.0.1`
- CIDR blocks: `192.168.1.0/24`

Lines starting with `#` are ignored.

```
# Production targets
api.example.com
10.20.30.0/24

# Staging
staging.example.com
```

Every probe -- both the byte-exact raw probe and the well-formed
baseline/differential request -- is checked against this scope before any bytes
leave the host. Scope handling comes from the shared `scan-primitives` library
(integrated in the v0.1 build).

## Usage

```bash
doppelganger --scope-file scope.txt --technique CL.TE https://target.example.com/
```

The scan runs a two-stage engine per technique: a timing probe raises a
**candidate**, and a differential-response probe upgrades it to **confirmed**.
Any effect that reproduces *only* under client-side connection reuse is
discriminated as pipelining and is **not** reported as a desync. Exit code is `1`
when any finding is produced, `0` when clean, `3` on a scope/target error.

### Options

```
URL                        target URL to probe (positional).
                           Mutually exclusive with --target-file.
--target-file FILE         file containing target URLs to probe, one per line.
                           Lines starting with '#' and blank lines are ignored.
                           All targets are scanned in sequence; findings are
                           aggregated in a single output document. Mutually
                           exclusive with the positional URL argument.
--technique {CL.TE,TE.CL,TE.TE,CL.0,dup-CL,TE.chunk,Expect.CL.TE,H2.CL,H2.TE,H2.PseudoHdrInject,all}
                           which desync technique to probe (default: all).
                           `all` covers the HTTP/1.1 family; the HTTP/2-downgrade
                           techniques (H2.CL, H2.TE, H2.PseudoHdrInject) are
                           opt-in per technique (they need an HTTP/2 front-end)
--scope-file FILE          authorization scope file (host / CIDR per line)
--safe                     safe/production mode: per-probe connection isolation,
                           CL.TE before TE.CL, bounded+randomised timeouts
--reuse-connection         reuse one connection across probes (pipelining
                           discrimination); default is per-probe isolation
--no-reuse-connection      force per-probe connection isolation (default)
--format {json,sarif,h1md} output format (default: json)
--timeout SECONDS          per-request timeout (default: 10.0)
--retries N                retry the timing probe up to N additional times when
                           it times out (default: 0). A genuine back-end hang is
                           stable and times out on every retry; a transient
                           network timeout typically clears on the first retry and
                           is not reported as a timing signal. Recommended for
                           targets with high-jitter network paths (--retries 1 or
                           --retries 2). Applies to the HTTP/1.1 engine only;
                           H2 and H2C engines ignore this flag.
--version                  print "doppelganger 1.0.0"
```

### Multi-target scanning

For bug-bounty programs with multiple in-scope assets, pass a newline-delimited
URL file via `--target-file`:

```bash
doppelganger --scope-file scope.txt --target-file targets.txt --technique CL.TE
```

The target file format is the same as the scope file: one URL per line, lines
beginning with `#` are comments, blank lines are skipped.

```
# Production endpoints
https://api.example.com/
https://gateway.example.com/

# Staging
https://staging.example.com/
```

All targets are scanned sequentially with the selected technique. Findings and
suppressed pipelining entries from all targets are merged into a single output
document. Out-of-scope targets are reported to stderr and skipped; scanning
continues with the remaining targets. Exit code is `1` if **any** target
produced a finding, `0` if all were clean.

### Techniques

HTTP/1.1 desync family (v0.1 + v0.4 parser-discrepancy expansion + v0.6 Expect probe):

| Technique | Discrepancy | Since |
|-----------|-------------|-------|
| `CL.TE`   | Front-end uses Content-Length, back-end uses Transfer-Encoding | v0.1 |
| `TE.CL`   | Front-end uses Transfer-Encoding, back-end uses Content-Length | v0.1 |
| `TE.TE`   | Both use TE, one is fooled by an obfuscated header (13-entry dictionary) | v0.1 |
| `CL.0`    | Content-Length honoured by front-end, treated as 0 by back-end | v0.1 |
| `dup-CL`  | Two conflicting Content-Length headers | v0.1 |
| `TE.chunk` | Both sides see chunked TE, but parse the chunk body differently — chunk extensions (`chunk-ext`) or bare-CR line endings (`bare-cr`) | v0.4 |
| `Expect.CL.TE` | CL.TE discrepancy triggered via `Expect: 100-continue` — probes front-ends that send `100 Continue` before forwarding the body to a TE back-end | v0.6 |

**TE.TE obfuscation dictionary (13 entries):** the standard 8 header-value mutations
(space/tab/vertical-tab before colon; duplicate identity+chunked; chunked+identity
comma; xchunked; quoted value; leading space) plus 5 new v0.4 parser-discrepancy
entries: `mixed-case` (`Chunked`), `null-byte` (null after value), `bare-cr-end`
(bare CR at end of header value), `ows-trailer` (trailing OWS), and `comma-chunk`
(comma-prefix list entry).

**TE.chunk chunk-body dictionary (2 entries):** probes where both sides see a
standard `Transfer-Encoding: chunked` header but the front-end forwards N bytes
via Content-Length and the back-end attempts to parse those bytes as chunks:
- `chunk-ext` — chunk size line carries a semicolon extension (`1;x=p\r\nA`);
  lenient back-ends strip the extension and parse normally; strict back-ends reject
  the non-hex token. The differential attack uses an extension-annotated data chunk
  before the standard `0\r\n\r\n` terminator.
- `bare-cr` — chunk line endings use bare CR (`\r`) instead of CRLF; strict
  parsers cannot find the chunk boundary and hang (timing candidate); lenient
  parsers consume the chunk and leave the smuggled prefix.

HTTP/2-downgrade family -- an HTTP/2 front-end that forwards to an HTTP/1.1
back-end, desynced via a length-framing disagreement the H2 layer never honours:

| Technique | Discrepancy | Since |
|-----------|-------------|-------|
| `H2.CL`   | H2 request carries a `content-length` that disagrees with the DATA length; a vulnerable downgrade copies it into the HTTP/1.1 request | v0.2 |
| `H2.TE`   | H2 request carries an (RFC-prohibited) `transfer-encoding: chunked` regular header; a vulnerable downgrade copies it through | v0.2 |
| `H2.PseudoHdrInject` | CR+LF injected into a header *value* (`:authority` pseudo-header, or a regular header value); a vulnerable downgrade that copies decoded values verbatim produces an extra `Transfer-Encoding: chunked` line in the H1 view — two variants: `authority-crlf-te` and `header-val-crlf-te` | v0.8 |

The H2 probes use a hand-rolled byte-exact HTTP/2 send layer, because the
high-level H2 stacks *validate on send* and refuse the prohibited framing these
attacks need. H2 detection is proven end-to-end against an in-process
downgrade-mock; a live vulnerable proxy runs behind the `integration` marker.

H2C cleartext-upgrade smuggling, client-side desync, and the parser-discrepancy
engine remain out of scope -- see Roadmap.

## Modules

| Module | Responsibility |
|--------|----------------|
| `doppelganger.findings`   | The pinned suite `Finding` contract (CWE-444), severity/confidence vocabularies. |
| `doppelganger.sarif`      | `to_sarif(findings) -> dict` -- SARIF 2.1.0 document. |
| `doppelganger.reporting`  | `to_h1md(findings) -> str` -- HackerOne markdown via `h1-reporter`. |
| `doppelganger.techniques` | Byte-exact probe payloads per technique + the TE.TE obfuscation dictionary. |
| `doppelganger.rawsend`    | Byte-exact raw-socket HTTP/1.1 transport (no normalisation), scope-enforced, with connection-reuse control. |
| `doppelganger.client`     | `scan-primitives`-backed, scope-enforcing well-formed baseline client. |
| `doppelganger.engine`     | Two-stage HTTP/1.1 detector: timing detection -> differential confirmation + pipelining discrimination. |
| `doppelganger.h2send`     | Byte-exact HTTP/2 send layer (v0.2): literal HPACK + hand-built frames that carry the RFC-prohibited framing H2.CL/H2.TE need; ALPN `h2`; scope-enforced. |
| `doppelganger.h2techniques` | H2.CL / H2.TE downgrade probe builders (v0.2); H2.PseudoHdrInject CRLF-injection variants (v0.8). |
| `doppelganger.h2engine`   | Two-stage HTTP/2-downgrade detector (v0.2), mirroring `engine` over the H2 transport. |
| `doppelganger.cli`        | argparse CLI. |

Two transports on purpose: a normalising high-level client **cannot** carry a
smuggling probe (it would rewrite the malformed framing under test), so probes go
through the raw sender while baseline requests go through the scope-aware client.
Both share one `Scope`, so scope is enforced before egress on **every** path.

## Example output

A confirmed CL.TE finding, as it will render (`--format json`):

```json
{
  "tool": "doppelganger",
  "finding_count": 1,
  "findings": [
    {
      "id": "dg-clte-0c249eb8",
      "tool": "doppelganger",
      "title": "CL.TE HTTP/1.1 request-smuggling desync confirmed",
      "severity": "high",
      "confidence": "high",
      "target": "https://target.example.com/",
      "vector": "CL.TE",
      "variant": null,
      "cwe_id": 444,
      "evidence": {
        "discrepancy": "CL.TE",
        "confirmation": "confirmed",
        "connection_reuse": false,
        "timing_delta_ms": 400.4,
        "request": "POST / HTTP/1.1\r\n...",
        "reproduction": "POST / HTTP/1.1\r\n..."
      },
      "references": ["https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"],
      "created_at": "2026-07-02T00:00:00+00:00"
    }
  ],
  "suppressed_pipelining": [],
  "summary": {
    "targets_scanned": 1,
    "targets_errored": 0,
    "finding_count": 1,
    "suppressed_pipelining_count": 0,
    "elapsed_ms": 520.3,
    "findings_by_severity": {"high": 1}
  }
}
```

A timing-only **candidate** looks the same with `"confirmation": "candidate"`,
`severity: "medium"`, `confidence: "low"`. Suppressed pipelining artifacts are
reported separately under `suppressed_pipelining`, never as findings.

The `summary` block is always emitted in `--format json`. It gives a glance
at targets probed, elapsed wall-time, finding counts, and -- when findings exist
-- a severity breakdown. The SARIF output embeds the same statistics in
`runs[0]["properties"]["doppelganger/scanSummary"]` for GitHub Code Scanning
consumers; `--format h1md` appends a `## Scan Summary` table to the report.

The finding also serialises to SARIF 2.1.0 (`--format sarif`, for GitHub Code
Scanning / IDEs) and HackerOne markdown (`--format h1md`).

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # resolves scan-primitives + h1-reporter via git

# Offline / local checkout of the sibling libs? Install them first, then
# doppelganger with --no-deps so the git URLs are not fetched:
#   pip install ../h1-reporter ../scan-primitives pytest pytest-socket build
#   pip install --no-deps -e .

pytest -m "not ship_gate and not integration"   # fast unit tests (mock pair)
pytest -m ship_gate                              # build wheel, fresh-venv install, CLI proof
pytest -m integration                            # docker discrepant-pair lab (needs docker)
```

Tests use an **in-process raw-socket mock front/back pair** (`tests/mockpair.py`)
with opposite length rules to synthesize any `X.Y` discrepancy deterministically
-- proving detection, differential confirmation, and pipelining discrimination
without container flakiness. The v0.2 H2 work adds an **in-process
HTTP/2-downgrade mock** (`tests/h2mock.py`): a real H2 front-end that forwards a
naively-downgraded HTTP/1.1 view to a discrepant back-end, driven by the actual
byte-exact H2 send layer -- so H2.CL / H2.TE detection + confirmation are proven
hermetically. The `ship_gate` marker builds the wheel and drives the installed
CLI against the mock pair; the `integration` marker drives the docker-compose lab
(pinned HAProxy 1.7.9 + gunicorn 20.0.4) plus the live-H2-proxy path, and skips
cleanly if docker / a real proxy is absent.

## Roadmap

**v0.1 (the build contract, [`V0.1-CRITERIA.md`](V0.1-CRITERIA.md)):** the
HTTP/1.1 desync engine (CL.TE / TE.CL / TE.TE / CL.0 / dup-CL), two-stage
timing-detection -> differential-response confirmation, pipelining
false-positive discrimination, safe-testing defaults, the raw-socket sender, and
the docker CI lab.

**v0.2 (landed): HTTP/2-downgrade request smuggling (H2.CL, H2.TE).** A dedicated
byte-exact H2 send layer (`h2send`) -- hand-rolled literal HPACK + frames,
because the high-level H2 libraries validate on send and refuse the prohibited
framing these attacks need -- plus a second two-stage engine (`h2engine`) for
HTTP/2 front-end -> HTTP/1.1 back-end downgrade desync, wired to `--technique
H2.CL` / `H2.TE`. Proven hermetically against an in-process downgrade mock; a
live vulnerable proxy runs behind the `integration` marker.

**v0.3 (landed): H2C cleartext-upgrade detection.** Probes HTTP/1.1 front-ends
for `Upgrade: h2c` acceptance (RFC 7540 §3.2) and confirms genuine H2 capability
by completing the connection handshake (client preface + SETTINGS exchange). Wired
to `--technique H2C`.

**v0.4 (landed): Parser-discrepancy probe expansion.** Expands the TE.TE
obfuscation dictionary from 8 to 13 header-level entries (mixed-case, null-byte,
bare-CR end, trailing OWS, comma-prefix list). Adds the `TE.chunk` technique
family -- two chunk-body-level variants (`chunk-ext`, `bare-cr`) that probe
parser discrepancy at the chunk framing level rather than the TE header level.

**v0.7 (landed): Multi-target scanning (`--target-file`).** Adds a
`--target-file FILE` argument that reads a newline-delimited list of target URLs
(comment lines starting with `#` ignored). All targets are scanned in sequence
with the selected technique; findings and suppressed-pipelining entries are
aggregated into a single output document. Out-of-scope targets are reported to
stderr and skipped; scanning continues. Exit code semantics are unchanged: `1` if
any finding across all targets, `0` if all clean, `3` on scope/file error.

**v0.6 (landed): `Expect: 100-continue` desync probe (`Expect.CL.TE`).** Probes
front-ends that implement `Expect: 100-continue` (sending a `100 Continue`
interim response before forwarding the body to a TE-based back-end). Two
concrete improvements ship together:

1. **rawsend 1xx skipping**: `_read_response` now skips interim 1xx responses
   (100 Continue, 102 Processing, etc.) and waits for the final 2xx–5xx
   response. Without this fix, the client would stop reading at the `100
   Continue` and never observe the back-end hang — the timing signal would be
   lost.
2. **`Expect.CL.TE` technique**: a CL.TE probe that includes `Expect:
   100-continue`. On an Expect-aware front-end the probe exercises a distinct
   server code path; a TE back-end that receives only the front-end's
   Content-Length bytes (incomplete chunk) hangs, producing the timing signal
   and confirming via the standard differential attack.

**v0.8 (landed): H2 pseudo-header / header-value CRLF injection (`H2.PseudoHdrInject`).** A
third H2-downgrade technique that injects `\r\nTransfer-Encoding: chunked` into a
header *value* rather than as a prohibited regular header (H2.TE). Two variants cover
distinct vulnerable code paths in H2→H1 downgraders:

- **`authority-crlf-te`**: CRLF injected into the `:authority` pseudo-header value; a
  vulnerable downgrader that copies the decoded authority directly into `Host:` without
  stripping CR+LF produces an extra `Transfer-Encoding: chunked` line.
- **`header-val-crlf-te`**: CRLF injected into a regular header value (`X-Padding`); a
  downgrader that does not sanitise CRLF in non-pseudo header values injects the TE
  header into the H1 view.

RFC 9113 §8.2.1 prohibits CR+LF in H2 header values; the literal-HPACK send layer
carries the bytes to the wire verbatim. Exploits a distinct vulnerable code path from
H2.TE (which targets downgraders that copy prohibited regular headers through). Both
variants use the same two-stage engine (timing hang → differential confirmation) and
pipelining discrimination as the existing H2 techniques.

**v0.9 (landed): Scan summary statistics.** Every output format now includes a
structured scan-level summary so operators can see at a glance how many targets
were probed, elapsed wall-clock time, and the severity breakdown of findings:

- **`--format json`**: a `"summary"` top-level key is always emitted. Fields:
  `targets_scanned`, `targets_errored`, `finding_count`,
  `suppressed_pipelining_count`, `elapsed_ms`, and (when findings exist)
  `findings_by_severity` (a dict of severity label → count).
- **`--format sarif`**: summary embedded in `runs[0]["properties"]["doppelganger/scanSummary"]`
  — surfaced to GitHub Code Scanning and CI SAST dashboards as run-level
  metadata.
- **`--format h1md`**: a `## Scan Summary` table is appended to the document
  with targets scanned, findings, suppressed pipelining count, and elapsed time
  — useful when submitting to a bug-bounty program with multiple in-scope assets.

**v1.0.0 (this release): stable release.** Consolidates v0.1–v0.9 into the first
stable release. All nine technique families (CL.TE, TE.CL, TE.TE, CL.0, dup-CL,
TE.chunk, Expect.CL.TE, H2.CL, H2.TE, H2.PseudoHdrInject) plus H2C detection are
proven hermetically by 201 unit tests; the `ship_gate` suite builds a wheel and
drives the installed CLI against the in-process mock pair end-to-end. No new
techniques in this release; the focus is correctness, release hygiene, and the
1.0.0 stability contract.

**Still deferred:**

- **Client-side / browser-powered desync (CSD)** -> needs a victim browser; out
  of scope for a headless CLI.
- **0.CL, double-desync, early-response gadgets**
  ("HTTP/1.1 Must Die") -> next.
- **Parser-discrepancy V-H/H-V engine** (HRS v3 flagship) -> research-grade
  sub-project.
- **Full weaponization** (cache poisoning, request capture, PoC chaining) --
  doppelganger is a detection/confirmation tool and stays one.

## License & Attribution

MIT -- see [LICENSE](LICENSE).

doppelganger resurrects the dead-ancestor
[`smuggler.py`](https://github.com/defparam/smuggler) by @defparam (CL.TE / TE.CL
baseline and the transfer-encoding mutation reference). The detection and
confirmation techniques implement the published research of **James Kettle /
PortSwigger Research** -- "HTTP Desync Attacks: Request Smuggling Reborn",
"HTTP/2: The Sequel is Always Worse", "Browser-Powered Desync Attacks", and
"Smashing the State Machine". No Burp Suite or HTTP Request Smuggler extension
code is vendored; techniques are implemented from the public write-ups. See
[NOTICE](NOTICE) and [RESEARCH.md](RESEARCH.md).
