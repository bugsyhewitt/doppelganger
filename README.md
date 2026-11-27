# doppelganger

<p align="center">
  <img src="https://raw.githubusercontent.com/bugsyhewitt/bugsyhewitt.github.io/main/public/cards/doppelganger.jpg" alt="doppelganger" width="680">
</p>

Headless HTTP/1.1 **request-smuggling / desync** detection and differential
confirmation for authorized bug-bounty and penetration-testing engagements.

doppelganger is the modern, Burp-free successor to the dead-ancestor
[`smuggler.py`](https://github.com/defparam/smuggler). It detects the HTTP/1.1
desync family and -- crucially -- **differentially confirms** it, with
first-class pipelining-vs-smuggling false-positive discrimination and
safe-testing defaults. That confirmation/correctness layer is the thing
`smuggler.py` never had and the reason its raw output can't be trusted against
real targets.

---

## Table of Contents

- [What is HTTP request smuggling?](#what-is-http-request-smuggling)
- [What doppelganger does](#what-doppelganger-does)
- [Real-world attack scenario](#real-world-attack-scenario)
- [Ethical Use](#ethical-use)
- [Install](#install)
- [Quickstart](#quickstart)
- [Full command reference](#full-command-reference)
- [Scope file format](#scope-file-format)
- [Target file format](#target-file-format)
- [Desync variant reference](#desync-variant-reference)
  - [HTTP/1.1 family](#http11-family)
  - [HTTP/2-downgrade family](#http2-downgrade-family)
  - [H2C cleartext-upgrade](#h2c-cleartext-upgrade)
- [Output formats](#output-formats)
  - [JSON (default)](#json-default)
  - [SARIF 2.1.0](#sarif-210)
  - [HackerOne Markdown](#hackerone-markdown)
- [Architecture](#architecture)
  - [Two-stage engine](#two-stage-engine)
  - [Pipelining discrimination](#pipelining-discrimination)
  - [Two transports](#two-transports)
  - [Module map](#module-map)
- [Development and testing](#development-and-testing)
- [Responsible disclosure](#responsible-disclosure)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License and Attribution](#license--attribution)

---

## What is HTTP request smuggling?

HTTP request smuggling (also called HTTP desync) is a class of vulnerability
that arises when two servers in an HTTP pipeline -- typically a reverse proxy
(the **front-end**) and an origin server (the **back-end**) -- disagree about
where one HTTP request ends and the next begins.

HTTP/1.1 provides two mechanisms for signalling the length of a request body:
- **Content-Length (CL):** a decimal count of body bytes in the header.
- **Transfer-Encoding: chunked (TE):** the body is delivered in chunks, each
  prefixed with its size in hexadecimal, terminated by a zero-size chunk.

RFC 7230 says that if both headers are present, Transfer-Encoding takes
precedence and Content-Length should be ignored. But real-world servers don't
always agree:

```
Client → Front-end → Back-end
                   ↑
         disagreement lives here
```

When the front-end honours Content-Length and the back-end honours
Transfer-Encoding (or vice versa), the front-end forwards a certain number of
bytes from the request body to the back-end -- but the back-end sees those
bytes as belonging to a different request. The "leftover" bytes from the first
request become the **prefix** of the next back-end request.

If the attacker controls those leftover bytes, they can craft an arbitrary
prefix: an HTTP request line, a Host header, an Authorization header, a path
-- anything. The victim's next request will be **prefixed** with the
attacker's smuggled payload. This is request smuggling.

### Why it matters

Request smuggling enables a range of serious exploits:

- **Request capture:** the smuggled prefix causes the back-end to prepend a
  form field or query parameter with the victim's cookies, authorization
  tokens, or the full body of their POST request to a URL the attacker controls.
- **Cache poisoning:** the smuggled response poisons the front-end's cache with
  attacker-supplied content, served to future visitors without further
  interaction.
- **Access control bypass:** the smuggled prefix can bypass per-path ACLs
  enforced by the front-end by routing the victim's request to a path the
  front-end would normally block.
- **Response queue poisoning:** the front-end's response queue is desynchronised
  so that one user's response is delivered to a different user.

James Kettle's research at PortSwigger introduced and systematised these attack
chains. See [RESEARCH.md](RESEARCH.md) for the original papers.

---

## What doppelganger does

doppelganger probes a target URL for HTTP desync vulnerabilities using a
**two-stage engine**:

1. **Stage 1 — timing detection.** A byte-exact probe is sent over a raw
   socket (no header normalisation). It is crafted so that if the target has
   the front/back parsing discrepancy this technique targets, the back-end will
   be left waiting for body bytes that never arrive. The resulting hang is the
   **timing signal** that raises a *candidate*.

2. **Stage 2 — differential confirmation.** A smuggling attack prepends a
   prefix that requests a distinct marker resource. A subsequent well-formed
   request is then sent on a **fresh, isolated connection**. If that request
   comes back materially different -- the smuggled prefix poisoned the shared
   back-end connection -- this is a **confirmed** server-side desync.

A key correctness feature is **pipelining discrimination**: an effect that
reproduces only when the client reuses a single connection is classified as
probable client-side HTTP pipelining, not a server-side desync. It is
suppressed from findings and recorded separately. This is the false-positive
that discredits naive timing-only tools.

doppelganger emits findings in JSON, SARIF 2.1.0 (for GitHub Code Scanning),
or HackerOne markdown. It never normalises probe bytes, enforces authorization
scope before every probe, and applies safe-testing ordering so that riskier
techniques run after safer ones.

---

## Real-world attack scenario

### Setup

An e-commerce platform has an Nginx reverse proxy in front of a Node.js origin
server. Nginx honours Content-Length. Node.js honours Transfer-Encoding.
Neither has been configured to enforce strict header consistency.

### CL.TE desync step by step

The attacker sends a carefully crafted POST to the checkout endpoint:

```
POST /checkout HTTP/1.1
Host: shop.example.com
Content-Length: 48
Transfer-Encoding: chunked

0

GET /admin/users HTTP/1.1
Host: shop.example.com
```

**What the front-end (Nginx) sees:**

Nginx reads `Content-Length: 48`. It forwards 48 bytes of the body to the
origin. The 48 bytes include the `0\r\n\r\n` terminator plus the beginning of
the smuggled inner request.

**What the back-end (Node.js) sees:**

Node.js reads Transfer-Encoding: chunked. The first (and only) chunk size is
`0` -- an empty body. Node.js considers the POST request finished after the
empty chunk. The remaining bytes in the connection buffer -- `GET /admin/users
HTTP/1.1\r\nHost: shop.example.com` -- are **not discarded**. They sit in the
TCP receive buffer as the beginning of the next request.

**What the victim sees:**

The next legitimate user to make any request to this origin worker gets their
request prepended with the attacker's bytes. Their innocent `GET /products HTTP/1.1`
becomes:

```
GET /admin/users HTTP/1.1
Host: shop.example.com
GET /products HTTP/1.1
Host: shop.example.com
...
```

Node.js parses `GET /admin/users` as the full request and responds with the
admin user list to the victim's connection. The victim's browser receives an
unexpected 200 response with privileged data.

### How doppelganger detects this

doppelganger sends a timing probe whose back-end parse leaves an incomplete
chunked body. The back-end's chunked parser waits for the missing bytes;
the front-end has already closed the connection (it forwarded what CL said to).
The back-end never responds. doppelganger measures the hang (beyond the
baseline round-trip time) and raises a **candidate**.

Then it sends the differential attack above, followed immediately by a
well-formed GET on a **fresh connection**. The well-formed GET returns
`404 path=/doppelganger-<token>` instead of the normal `200 path=/`. The
response changed on a fresh connection: this is a **confirmed** server-side
desync. doppelganger emits a CWE-444 finding at severity `high`, confidence
`high`.

---

## Ethical Use

You are responsible for ensuring you have authorization to test any target.
Only probe systems you own or have explicit written permission to test. A desync
probe sends malformed HTTP to a live server and, used carelessly, can disrupt
**other users** of a shared front-end/back-end -- safe-testing defaults exist for
this reason, and scope is enforced before any probe. Use of this tool against
unauthorized targets may violate computer-fraud laws. The authors accept no
liability for misuse.

---

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/doppelganger
cd doppelganger
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Verify:

```bash
doppelganger --version
# doppelganger 1.0.0
```

---

## Quickstart

**1. Create a scope file** listing the hosts you are authorized to test:

```bash
cat > scope.txt <<'EOF'
# Authorized targets
api.example.com
staging.example.com
10.0.1.0/24
EOF
```

**2. Run a full scan** (all HTTP/1.1 techniques, JSON output):

```bash
doppelganger \
  --scope-file scope.txt \
  https://api.example.com/ \
  --format json
```

**3. Target a specific technique:**

```bash
doppelganger \
  --scope-file scope.txt \
  --technique CL.TE \
  https://api.example.com/
```

**4. Scan a list of URLs:**

```bash
doppelganger \
  --scope-file scope.txt \
  --target-file targets.txt \
  --technique all
```

**5. Scan in safe/production mode** (extra isolation, jittered timeouts):

```bash
doppelganger \
  --scope-file scope.txt \
  --safe \
  https://api.example.com/
```

### Example terminal session

```
$ doppelganger --scope-file scope.txt --technique CL.TE https://api.example.com/ --format json
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
      "target": "https://api.example.com/",
      "vector": "CL.TE",
      "variant": null,
      "cwe_id": 444,
      ...
    }
  ],
  "suppressed_pipelining": [],
  "summary": {
    "targets_scanned": 1,
    "targets_errored": 0,
    "finding_count": 1,
    "suppressed_pipelining_count": 0,
    "elapsed_ms": 420.1,
    "findings_by_severity": {"high": 1}
  }
}
$ echo $?
1
```

Exit codes:
- `0` — scan completed, no desync findings
- `1` — one or more desync findings (candidate or confirmed)
- `2` — argument/usage error
- `3` — scope, file, or target error

---

## Full command reference

```
usage: doppelganger [-h] [--target-file FILE] [--technique TECHNIQUE]
                    [--scope-file FILE] [--safe] [--reuse-connection |
                    --no-reuse-connection] [--format FORMAT] [--timeout N]
                    [--retries N] [--version]
                    [URL]
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `URL` | Target URL to probe (e.g. `https://host/path`). Mutually exclusive with `--target-file`. |

### Optional arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--target-file FILE` | — | File containing target URLs to probe, one per line. Lines starting with `#` and blank lines are ignored. All targets are scanned in sequence. Mutually exclusive with the positional URL. |
| `--technique TECHNIQUE` | `all` | Desync technique to probe. One of: `CL.TE`, `TE.CL`, `TE.TE`, `CL.0`, `dup-CL`, `TE.chunk`, `Expect.CL.TE`, `H2.CL`, `H2.TE`, `H2.PseudoHdrInject`, `H2C`, `all`. `all` covers the full HTTP/1.1 family. The H2/H2C techniques are opt-in (they require specific server capabilities). |
| `--scope-file FILE` | _(required)_ | Authorization scope file. One host, IP, or CIDR per line. Every probe -- raw and well-formed -- is checked against this scope before any bytes leave the host. |
| `--safe` | off | Safe/production mode. Forces per-probe connection isolation, adds randomised timeout jitter, and always probes CL.TE before TE.CL. Use this when testing a production system shared with real users. |
| `--reuse-connection` | off | Reuse one client connection across probes. Primarily useful for demonstrating/reproducing pipelining. The confirmation stage always runs both isolated and reused experiments regardless of this flag -- it is used for pipelining discrimination internally. |
| `--no-reuse-connection` | (default) | Force per-probe connection isolation. This is the default; the flag explicitly opts in. |
| `--format {json,sarif,h1md}` | `json` | Output format. `json` emits the doppelganger finding document. `sarif` emits SARIF 2.1.0 for GitHub Code Scanning. `h1md` emits HackerOne-compatible markdown for submission. |
| `--timeout SECONDS` | `10.0` | Per-request timeout in seconds. The timing probe uses this as its hang wait (a hang extending beyond this is the timing signal). The baseline and differential requests also respect this timeout. |
| `--retries N` | `0` | Retry the timing probe up to N additional times on timeout. A genuine back-end hang is stable and times out on every retry. A transient network timeout typically clears on the first retry and is not counted as a timing signal. Use `--retries 1` or `--retries 2` for targets on high-jitter networks. Applies only to the HTTP/1.1 engine. |
| `--version` | — | Print `doppelganger 1.0.0` and exit. |
| `-h`, `--help` | — | Show help and exit. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no desync findings on any target. |
| `1` | Scan completed; one or more desync findings (candidate or confirmed) across all targets. |
| `2` | Argument or usage error (argparse default). |
| `3` | Scope file or target file could not be read; a target was out of scope; or every target hit a connectivity error. |

---

## Scope file format

A plain-text file, one entry per line. Entries can be:

- Hostnames: `api.example.com`
- IP addresses: `10.0.0.1`
- CIDR blocks: `192.168.1.0/24`

Lines starting with `#` are ignored. Blank lines are ignored.

```
# Production targets
api.example.com
10.20.30.0/24

# Staging
staging.example.com
```

Every probe -- both the byte-exact raw probe and the well-formed
baseline/differential request -- is checked against this scope before any bytes
leave the host. Scope handling comes from the shared `scan-primitives` library.
An out-of-scope target produces an error on stderr and exit code `3` (or, in
multi-target mode, the target is skipped and scanning continues).

---

## Target file format

The same comment/blank-line conventions as the scope file: one URL per line,
lines beginning with `#` are comments, blank lines are skipped.

```
# Production endpoints
https://api.example.com/
https://gateway.example.com/

# Staging
https://staging.example.com/
```

Multi-target scanning is useful for bug-bounty programs with large scopes:
pass the full URL list via `--target-file` and collect all findings in a single
output document. Out-of-scope targets are skipped with a warning; scanning
continues. Exit code is `1` if **any** target produced a finding.

---

## Desync variant reference

### HTTP/1.1 family

#### CL.TE

**Discrepancy:** the front-end reads `Content-Length`; the back-end reads
`Transfer-Encoding: chunked`.

**Timing signal:** the probe sends a CL-sized body that leaves the chunked
parser incomplete. The back-end waits forever for the missing bytes.

**Differential attack:** the smuggled prefix is a complete inner HTTP request.
The front-end forwards the full body (CL); the back-end terminates at the
`0\r\n\r\n` terminator, leaving the prefix in the buffer.

**When you see it:** Nginx/Apache (CL) in front of Tomcat/Node.js (TE). One of
the most common production desync configurations.

#### TE.CL

**Discrepancy:** the front-end reads `Transfer-Encoding: chunked`; the
back-end reads `Content-Length`.

**Timing signal:** the probe sends a chunked body with a chunk size of `0`
(empty body) but `Content-Length: 6`. The front-end considers the message
finished at `0\r\n\r\n`; the back-end wants 6 more bytes from CL and waits.

**Differential attack:** the smuggled prefix is wrapped in a hex-sized chunk.
The front-end forwards the entire chunk block; the back-end reads only the
declared Content-Length bytes, leaving the chunk data as the next request.

**Safe-testing order:** TE.CL is probed **after** CL.TE. A TE.CL timing probe
against a CL.TE target can leave the back-end blocked reading from the front-end's
connection -- disrupting other users. doppelganger never probes TE.CL before CL.TE.

#### TE.TE (13-entry obfuscation dictionary)

**Discrepancy:** both the front-end and back-end accept `Transfer-Encoding`,
but one of them is fooled by a non-standard encoding of the header value. One
side treats the encoding as `chunked`; the other side ignores the TE header
entirely and falls back to Content-Length.

**The 13 obfuscations:**

| Name | Header bytes |
|------|-------------|
| `space-before-colon` | `Transfer-Encoding : chunked` |
| `tab-after-colon` | `Transfer-Encoding:\tchunked` |
| `vertical-tab` | `Transfer-Encoding:\x0bchunked` |
| `dup-identity-chunked` | `Transfer-Encoding: identity\r\nTransfer-Encoding: chunked` |
| `chunked-comma-identity` | `Transfer-Encoding: chunked, identity` |
| `x-prefixed` | `Transfer-Encoding: xchunked` |
| `quoted-value` | `Transfer-Encoding: "chunked"` |
| `leading-space-value` | `Transfer-Encoding:  chunked` |
| `mixed-case` | `Transfer-Encoding: Chunked` |
| `null-byte` | `Transfer-Encoding: chunked\x00` |
| `bare-cr-end` | `Transfer-Encoding: chunked\r` |
| `ows-trailer` | `Transfer-Encoding: chunked ` |
| `comma-chunk` | `Transfer-Encoding: ,chunked` |

#### CL.0

**Discrepancy:** the front-end honours Content-Length; the back-end treats the
body as zero-length regardless of what CL says. A POST body with an explicit
Content-Length is forwarded by the front-end but ignored by the back-end --
leaving those bytes in the buffer as the next request.

Two sub-variants are probed:

- **Classic POST:** `POST` with `Content-Length: N` where the body is the
  smuggled inner request. The back-end reads 0 bytes; the N-byte body is left over.
- **GET+CL:0:** `GET` with `Content-Length: 0`. Targets transparent TCP-forwarding
  front-ends combined with a back-end that reads CL:0 as bodyless. The extra bytes
  after the headers become the next request prefix.

#### dup-CL

**Discrepancy:** the request carries two conflicting `Content-Length` headers.
RFC 7230 says this is an error; real-world parsers disagree on how to resolve it.
A front-end that honours the first CL and a back-end that honours the last (or
vice versa) produce a discrepancy.

The probe sends `Content-Length: N` (the full smuggled body) followed by
`Content-Length: 0`. The front-end forwards N bytes; the back-end reads 0 bytes;
the N bytes are left as the next request.

#### TE.chunk

**Discrepancy:** both sides see a plain `Transfer-Encoding: chunked` header, but
they parse the chunk body framing differently. The front-end also honours
Content-Length (forwarding only CL bytes); the back-end attempts to parse those
bytes as chunks.

Two chunk-body-level variants are probed:

- **chunk-ext:** the chunk size line carries a semicolon extension
  (`1;x=p\r\nA`). Lenient parsers strip the extension and read a 1-byte chunk.
  Strict parsers see an invalid hex token and cannot parse the body -- hang.
- **bare-cr:** chunk line endings use bare `\r` instead of `\r\n`. Lenient
  parsers accept bare CR as a line terminator. Strict parsers cannot find the
  chunk boundary -- hang.

#### Expect.CL.TE

**Discrepancy:** a CL.TE discrepancy in a front-end that handles
`Expect: 100-continue`. Some front-ends send a `100 Continue` interim response
before forwarding the body to the back-end. The raw sender skips interim 1xx
responses to correctly measure the back-end hang.

The technique exercises a distinct code path in Expect-aware proxies compared to
the base CL.TE probe.

---

### HTTP/2-downgrade family

These techniques target an HTTP/2 front-end that forwards to an HTTP/1.1
back-end. The H2 layer is used to smuggle framing that the HTTP/1.1 back-end
processes as an extra request.

doppelganger uses a hand-rolled byte-exact HTTP/2 send layer (`h2send`) because
high-level H2 stacks validate on send and refuse the RFC-prohibited framing these
attacks require.

#### H2.CL

**Discrepancy:** the H2 request carries a `content-length` regular header that
disagrees with the actual DATA frame length. A vulnerable H2→H1 downgrader copies
the `content-length` header verbatim into the HTTP/1.1 request it forwards, so the
back-end reads more bytes than the DATA frame contained -- the extra bytes come
from the next request.

```
:method: POST
:path: /
content-length: 100          ← declared length disagrees with DATA frame size
[DATA: 6 bytes]
```

#### H2.TE

**Discrepancy:** the H2 request carries an RFC-prohibited
`transfer-encoding: chunked` regular header (RFC 9113 §8.2.2 bans pseudo-header
names but also TE other than `trailers`). A vulnerable downgrader copies the TE
header through to the HTTP/1.1 view. The back-end sees `Transfer-Encoding:
chunked` and processes the DATA bytes as a chunked body.

#### H2.PseudoHdrInject

**Discrepancy:** CR+LF bytes are injected into an H2 header **value**. A
vulnerable downgrader that copies the decoded header value verbatim into the
HTTP/1.1 request produces an extra line in the HTTP/1.1 view -- specifically an
extra `Transfer-Encoding: chunked` line injected between existing headers.

Two variants:

- **authority-crlf-te:** CRLF injected into the `:authority` pseudo-header.
  A downgrader that copies the decoded authority into `Host:` without stripping
  CR+LF produces the extra TE header.
- **header-val-crlf-te:** CRLF injected into a regular header value
  (`X-Padding`). A downgrader that does not sanitise CRLF in non-pseudo header
  values injects TE into the H1 view.

---

### H2C cleartext-upgrade

**What it is:** RFC 7540 §3.2 defines an HTTP/1.1 upgrade mechanism that lets
a client request a cleartext HTTP/2 connection via `Upgrade: h2c`. doppelganger
probes whether the front-end accepts this upgrade and can complete the H2
handshake.

**What doppelganger does:** sends the upgrade request and, if the server
responds with `101 Switching Protocols`, completes the H2 client preface and
SETTINGS exchange to verify genuine H2 capability. This is not a desync probe
itself, but a surface-discovery step that tells you whether the H2-downgrade
techniques apply.

---

## Output formats

### JSON (default)

The default output is a JSON document with three top-level keys:

- `tool` — always `"doppelganger"`
- `finding_count` — number of findings in the scan
- `findings` — array of finding objects (see schema below)
- `suppressed_pipelining` — array of pipelining entries that were suppressed
- `summary` — scan-level statistics (always present)

**Finding schema:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Stable finding identifier (`dg-{technique}-{hash}`) |
| `tool` | string | Always `"doppelganger"` |
| `title` | string | Human-readable headline |
| `severity` | string | `"info"`, `"low"`, `"medium"`, `"high"`, or `"critical"` |
| `confidence` | string | `"low"`, `"medium"`, or `"high"` |
| `target` | string | The URL that was probed |
| `vector` | string | Technique / discrepancy class (e.g. `"CL.TE"`) |
| `variant` | string or null | Specific mutator used (e.g. TE.TE obfuscation name) |
| `cwe_id` | integer | Always 444 (CWE-444: HTTP Request Smuggling) |
| `evidence` | object | Byte-level proof and engine state (see below) |
| `references` | array | Supporting URLs (PortSwigger research write-ups) |
| `created_at` | string | ISO-8601 UTC timestamp |

**Evidence fields:**

| Field | Description |
|-------|-------------|
| `discrepancy` | The `X.Y` discrepancy class (mirrors `vector`) |
| `confirmation` | `"candidate"` or `"confirmed"` |
| `connection_reuse` | Whether the effect required connection reuse |
| `timing_delta_ms` | Measured timing delta over baseline (ms) |
| `request` | The probe request bytes (latin-1, up to 1 KB) |
| `reproduction` | Byte-exact payload to reproduce the desync |
| `baseline_request` | The baseline request line |
| `baseline_response` | Baseline response signature (status + body length) |
| `response` | Victim response signature after the attack |
| `probable_pipelining` | True when the effect is classified as pipelining |

**Severity / confidence mapping:**

| State | Severity | Confidence |
|-------|----------|------------|
| Confirmed desync | `high` | `high` |
| Timing-only candidate | `medium` | `low` |
| Pipelining (reuse-only, `--reuse-connection`) | `info` | `low` |

**Summary block:**

```json
"summary": {
  "targets_scanned": 2,
  "targets_errored": 0,
  "finding_count": 1,
  "suppressed_pipelining_count": 0,
  "elapsed_ms": 850.4,
  "findings_by_severity": {"high": 1}
}
```

**Example confirmed CL.TE finding (JSON):**

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
      "references": [
        "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
        "https://portswigger.net/web-security/request-smuggling",
        "https://portswigger.net/web-security/request-smuggling/finding"
      ],
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

**Example timing-only candidate (JSON):**

A timing-only candidate looks the same with `"confirmation": "candidate"`,
`"severity": "medium"`, `"confidence": "low"`, and no `"response"` key in
evidence (because no differential effect was observed).

```json
{
  "tool": "doppelganger",
  "finding_count": 1,
  "findings": [
    {
      "id": "dg-clte-ab12cd34",
      "title": "CL.TE HTTP/1.1 desync candidate (timing signal)",
      "severity": "medium",
      "confidence": "low",
      "target": "https://target.example.com/",
      "vector": "CL.TE",
      "variant": null,
      "cwe_id": 444,
      "evidence": {
        "discrepancy": "CL.TE",
        "confirmation": "candidate",
        "connection_reuse": false,
        "timing_delta_ms": 9850.0
      }
    }
  ],
  "suppressed_pipelining": [],
  "summary": {
    "targets_scanned": 1,
    "targets_errored": 0,
    "finding_count": 1,
    "suppressed_pipelining_count": 0,
    "elapsed_ms": 10100.5
  }
}
```

---

### SARIF 2.1.0

```bash
doppelganger --scope-file scope.txt --technique CL.TE https://target.example.com/ --format sarif
```

The SARIF document follows the [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

Key locations:

- `runs[0].tool.driver.name` — `"doppelganger"`
- `runs[0].results[*].ruleId` — `"doppelganger/{technique}"` (e.g. `"doppelganger/CL.TE"`)
- `runs[0].results[*].level` — `"error"` (confirmed), `"warning"` (candidate)
- `runs[0].properties["doppelganger/scanSummary"]` — the same statistics object
  as the JSON `"summary"` block; consumed by GitHub Code Scanning and CI SAST dashboards.

Upload to GitHub Code Scanning:

```bash
doppelganger --scope-file scope.txt --target-file targets.txt --format sarif \
  > results.sarif
gh code-scanning upload-analysis --sarif results.sarif
```

---

### HackerOne Markdown

```bash
doppelganger --scope-file scope.txt --technique CL.TE https://target.example.com/ --format h1md
```

The h1md output starts with `# doppelganger HTTP desync findings` and uses the
HackerOne finding template format via the `h1-reporter` library. It includes one
finding section per vulnerability, followed by a `## Scan Summary` table showing
targets scanned, findings, suppressed pipelining count, and elapsed time.

The output is ready to paste into a HackerOne report's "Vulnerability Information"
field or as a Markdown attachment.

---

## Architecture

### Two-stage engine

```
                        timing probe (raw socket)
                              │
                              ▼
             ┌─────────────────────────────┐
             │  Stage 1: timing detection   │
             │  hang > baseline?             │──→ candidate (medium/low)
             └─────────────────────────────┘
                              │
                    (technique has timing probe)
                              │
                              ▼
             ┌────────────────────────────────────┐
             │  Stage 2: differential confirmation │
             │  attack on fresh conn A              │
             │  victim on fresh conn B              │──→ confirmed (high/high)
             │  sig(B) ≠ baseline?                  │
             └────────────────────────────────────┘
                              │
                    (also try on reused conn)
                              │
                              ▼
             ┌────────────────────────────────────┐
             │  Pipelining discrimination          │
             │  effect only on reused conn?        │──→ suppressed (not reported)
             └────────────────────────────────────┘
```

Each technique is probed in `safe_order` (ascending), guaranteeing CL.TE before
TE.CL. Within a technique family (TE.TE, TE.chunk) all variants are probed in
dictionary order.

### Pipelining discrimination

The confirmation stage always runs both experiments:

1. **Isolated:** attack on fresh connection A, victim on fresh connection B.
   A different response on B means the poison crossed connections -- genuine
   server-side desync.

2. **Reused:** attack and victim on the **same** connection.
   A different response here (but not in the isolated experiment) means the
   effect is per-connection. This is HTTP/1.1 pipelining: the client's own
   connection was poisoned, not a shared back-end pool.

Pipelining effects are recorded under `suppressed_pipelining` and never
reported as desync findings. With `--reuse-connection`, they are surfaced as
`severity: info` and explicitly flagged with `probable_pipelining: true`.

### Two transports

doppelganger uses two distinct HTTP transports on purpose:

| Transport | Used for | Why |
|-----------|----------|-----|
| `rawsend` (raw socket) | Desync probe payloads | Normalising HTTP clients rewrite malformed headers. The probe bytes must reach the server exactly as crafted -- no CRLF normalisation, no header folding, no TE rejection. |
| `scan-primitives` baseline client | Well-formed baseline and differential victim requests | The confirmation step needs a correctly-formed request that the front-end forwards normally. Scope is enforced here too. |

Both transports share one `Scope` object so authorization is checked on every
outbound path -- raw probes and well-formed requests alike.

### Module map

| Module | Responsibility |
|--------|----------------|
| `doppelganger.findings` | Pinned suite `Finding` contract (CWE-444), severity/confidence vocabularies |
| `doppelganger.sarif` | `to_sarif(findings) -> dict` -- SARIF 2.1.0 document |
| `doppelganger.reporting` | `to_h1md(findings) -> str` -- HackerOne markdown via `h1-reporter` |
| `doppelganger.techniques` | Byte-exact probe payloads per technique + the TE.TE obfuscation dictionary |
| `doppelganger.rawsend` | Byte-exact raw-socket HTTP/1.1 transport (no normalisation), scope-enforced, with connection-reuse control |
| `doppelganger.client` | `scan-primitives`-backed, scope-enforcing well-formed baseline client |
| `doppelganger.engine` | Two-stage HTTP/1.1 detector: timing detection → differential confirmation + pipelining discrimination |
| `doppelganger.h2send` | Byte-exact HTTP/2 send layer: literal HPACK + hand-built frames carrying RFC-prohibited framing; ALPN `h2`; scope-enforced |
| `doppelganger.h2techniques` | H2.CL / H2.TE downgrade probe builders; H2.PseudoHdrInject CRLF-injection variants |
| `doppelganger.h2engine` | Two-stage HTTP/2-downgrade detector, mirroring `engine` over the H2 transport |
| `doppelganger.h2c` | H2C cleartext-upgrade probe engine |
| `doppelganger.cli` | argparse CLI, routing to the correct engine |

---

## Development and testing

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Fast unit tests (in-process mock pair, no docker)
pytest -m "not ship_gate and not integration"

# Ship-gate: build wheel, fresh-venv install, CLI smoke test
pytest -m ship_gate

# Integration: docker-compose discrepant-pair lab (needs docker)
pytest -m integration
```

### Test infrastructure

**In-process mock pair** (`tests/mockpair.py`): a raw-socket TCP server
modelling a front/back length discrepancy. The front and back length strategies
are injected; `cl()` + `te()` synthesizes CL.TE, `te()` + `cl()` synthesizes
TE.CL, and so on. The mock runs in a background thread on a random OS-assigned
port and exits cleanly via context manager. All detection, confirmation, and
pipelining-discrimination proofs run against this mock -- no docker, no live
network, deterministic millisecond-stable timing.

**In-process H2 downgrade mock** (`tests/h2mock.py`): a real H2 front-end
(ALPN, complete handshake) that naively downgrades to an HTTP/1.1 back-end. Used
to prove H2.CL, H2.TE, and H2.PseudoHdrInject detection + confirmation
hermetically.

**Docker CI lab** (`tests/lab/`): pinned HAProxy 1.7.9 (CVE-2019-18277) +
gunicorn 20.0.4 behind the `integration` marker. Skips cleanly if docker is
absent.

**Ship gate** (`tests/test_wheel_ship_gate.py`): builds the wheel with
`python -m build`, installs it into a fresh venv, and runs the CLI against the
in-process mock pair end-to-end. Proves the installed package works, not just
the development checkout.

### Test counts

```
# Unit tests (fast, no docker)
pytest -m "not ship_gate and not integration" --co -q | tail -1
# 243 tests

# All non-integration
pytest -m "not integration" --co -q | tail -1
```

### Code quality

```bash
ruff check src/ tests/        # linting (E, F, W, I)
ruff format --check src/ tests/  # formatting
```

---

## Responsible disclosure

doppelganger is a detection-only tool. It **does not**:
- Exploit a confirmed desync to capture requests or responses from real users.
- Chain a detected desync into further attacks.
- Exfiltrate data to attacker-controlled infrastructure.
- Persist any malicious state on the target.

The differential attack sends a byte-exact HTTP probe that requests a marker
resource (`/doppelganger-<token>`) on the same target. The marker path is
deterministic (SHA-1 of URL + technique) and highly unlikely to exist. The only
observable effect on the target is the probe itself.

**When you find something:** doppelganger findings should be disclosed through
the program's responsible disclosure policy (bug-bounty triage, security contact,
or VDP). Include the JSON output, the reproduction payload from `evidence.reproduction`,
and evidence that the finding is a true positive (not a timing artefact from a slow
network). The `--format h1md` output is formatted for direct HackerOne submission.

**Before testing production systems:** use `--safe` mode, limit the scan to
a single technique (start with `--technique CL.TE`), and schedule the scan
during low-traffic windows. A TE.CL timing probe against a CL.TE target can
block the back-end's connection read -- disrupting real users. doppelganger
probes TE.CL last (after CL.TE) for this reason.

---

## Contributing

1. Fork the repository.
2. Create a feature branch off `main`.
3. Run the test suite: `pytest -m "not ship_gate and not integration"`.
4. Add tests for any new technique or behavior.
5. Open a pull request with a clear description of the change.

**Adding a new technique:**

1. Add the probe builder to `doppelganger/techniques.py` (or `h2techniques.py`
   for H2 techniques). Every technique must implement `timing_probe()` and
   `differential_attack()`.
2. Register the technique name in `doppelganger/findings.py` TECHNIQUES tuple.
3. Wire it into `all_techniques()` in `techniques.py`.
4. Add a test in `tests/` using the in-process mock pair.
5. Update this README's desync variant reference.

**Security-sensitive contributions:** techniques, probe payloads, and the raw
sender are safety-critical. Changes to these must include regression tests that
prove pipelining discrimination still works and that an out-of-scope target is
still refused. The scope check in `rawsend.py` and `client.py` is not
optional.

---

## Roadmap

**v0.1 (the build contract, [`V0.1-CRITERIA.md`](V0.1-CRITERIA.md)):** the
HTTP/1.1 desync engine (CL.TE / TE.CL / TE.TE / CL.0 / dup-CL), two-stage
timing-detection -> differential-response confirmation, pipelining
false-positive discrimination, safe-testing defaults, the raw-socket sender, and
the docker CI lab.

**v0.2 (landed): HTTP/2-downgrade request smuggling (H2.CL, H2.TE).**

**v0.3 (landed): H2C cleartext-upgrade detection.**

**v0.4 (landed): Parser-discrepancy probe expansion.** TE.TE dictionary
expanded to 13 entries; TE.chunk technique family (chunk-ext, bare-cr).

**v0.5 (landed): CL.0 GET+CL:0 sub-variant.**

**v0.6 (landed): `Expect: 100-continue` desync probe (`Expect.CL.TE`).**

**v0.7 (landed): Multi-target scanning (`--target-file`) + `--retries N`.**

**v0.8 (landed): H2 pseudo-header / header-value CRLF injection (`H2.PseudoHdrInject`).**

**v0.9 (landed): Scan summary statistics in all output formats.**

**v1.0.0 (this release): stable release.** Consolidates v0.1–v0.9 into the first
stable release. All nine technique families proven hermetically by 201 unit tests.

**Still deferred:**

- **Client-side / browser-powered desync (CSD)** → needs a victim browser; out
  of scope for a headless CLI.
- **0.CL, double-desync, early-response gadgets** → next.
- **Parser-discrepancy V-H/H-V engine** (HRS v3 flagship) → research-grade.
- **Full weaponization** (cache poisoning, request capture, PoC chaining) --
  doppelganger is a detection/confirmation tool and stays one.

See [`POST_V01.md`](POST_V01.md) for detailed write-ups on each deferred item.
See [`CHANGELOG.md`](CHANGELOG.md) for the full version-by-version history.

---

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
