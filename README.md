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
URL                        target URL to probe (positional)
--technique {CL.TE,TE.CL,TE.TE,CL.0,dup-CL,all}
                           which desync technique to probe (default: all)
--scope-file FILE          authorization scope file (host / CIDR per line)
--safe                     safe/production mode: per-probe connection isolation,
                           CL.TE before TE.CL, bounded+randomised timeouts
--reuse-connection         reuse one connection across probes (pipelining
                           discrimination); default is per-probe isolation
--no-reuse-connection      force per-probe connection isolation (default)
--format {json,sarif,h1md} output format (default: json)
--timeout SECONDS          per-request timeout (default: 10.0)
--version                  print "doppelganger 0.1.0"
```

### Techniques (v0.1 target family)

| Technique | Discrepancy | v0.1 |
|-----------|-------------|------|
| `CL.TE`   | Front-end uses Content-Length, back-end uses Transfer-Encoding | yes |
| `TE.CL`   | Front-end uses Transfer-Encoding, back-end uses Content-Length | yes |
| `TE.TE`   | Both use TE, one is fooled by an obfuscated header (8-entry dictionary) | yes |
| `CL.0`    | Content-Length honoured by front-end, treated as 0 by back-end | yes |
| `dup-CL`  | Two conflicting Content-Length headers | yes |

All HTTP/2 techniques (H2.CL, H2.TE, H2 tunnelling, downgrade desync) are
**out of scope for v0.1** -- see Roadmap.

## Modules

| Module | Responsibility |
|--------|----------------|
| `doppelganger.findings`   | The pinned suite `Finding` contract (CWE-444), severity/confidence vocabularies. |
| `doppelganger.sarif`      | `to_sarif(findings) -> dict` -- SARIF 2.1.0 document. |
| `doppelganger.reporting`  | `to_h1md(findings) -> str` -- HackerOne markdown via `h1-reporter`. |
| `doppelganger.techniques` | Byte-exact probe payloads per technique + the TE.TE obfuscation dictionary. |
| `doppelganger.rawsend`    | Byte-exact raw-socket HTTP/1.1 transport (no normalisation), scope-enforced, with connection-reuse control. |
| `doppelganger.client`     | `scan-primitives`-backed, scope-enforcing well-formed baseline client. |
| `doppelganger.engine`     | Two-stage detector: timing detection -> differential confirmation + pipelining discrimination. |
| `doppelganger.cli`        | argparse CLI. |

Two transports on purpose: a normalising high-level client **cannot** carry a
smuggling probe (it would rewrite the malformed framing under test), so probes go
through the raw sender while baseline requests go through the scope-aware client.
Both share one `Scope`, so scope is enforced before egress on **every** path.

## Example output

A confirmed CL.TE finding, as it will render (`--format json`):

```json
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
```

A timing-only **candidate** looks the same with `"confirmation": "candidate"`,
`severity: "medium"`, `confidence: "low"`. Suppressed pipelining artifacts are
reported separately under `suppressed_pipelining`, never as findings.

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
without container flakiness. The `ship_gate` marker builds the wheel and drives
the installed CLI against the mock pair; the `integration` marker drives the
docker-compose lab (pinned HAProxy 1.7.9 + gunicorn 20.0.4) and skips cleanly if
docker is absent.

## Roadmap

**v0.1 (the build contract, [`V0.1-CRITERIA.md`](V0.1-CRITERIA.md)):** the
HTTP/1.1 desync engine (CL.TE / TE.CL / TE.TE / CL.0 / dup-CL), two-stage
timing-detection -> differential-response confirmation, pipelining
false-positive discrimination, safe-testing defaults, the raw-socket sender, and
the docker CI lab.

**Explicitly NOT in v0.1 (deferred):**

- **All HTTP/2** (H2.CL, H2.TE, H2 tunnelling/splitting, downgrade desync)
  -> **v0.2, the highest-value follow-up.** Needs a separate low-level H2 stack
  that cannot reuse the HTTP/1.1 raw sender (high-level libs validate on send and
  refuse the prohibited headers these attacks need).
- **H2C** cleartext-upgrade smuggling -> after H2 lands.
- **Client-side / browser-powered desync (CSD)** -> needs a victim browser; out
  of scope for a headless CLI.
- **0.CL, double-desync, Expect-based desync, early-response gadgets**
  ("HTTP/1.1 Must Die") -> v0.3.
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
