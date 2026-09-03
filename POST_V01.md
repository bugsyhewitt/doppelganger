# doppelganger — Post-v1.0 Roadmap

This file tracks the desync techniques and capability areas that were
explicitly deferred from v0.1 and are still unshipped as of v1.0.0. Items
are sourced from `V0.1-CRITERIA.md`'s "Explicitly NOT in v0.1 (deferred)"
section, filtered against the commit ladder to exclude anything already
landed (H2.CL, H2.TE shipped in v0.2; H2C in v0.3; Expect.CL.TE in v0.6;
H2.PseudoHdrInject in v0.8).

Each item describes what it is, why it matters for doppelganger's positioning
against Burp Suite's HTTP Request Smuggler extension, and the prerequisites
that need to be in place before it can ship.

---

## 1. "HTTP/1.1 Must Die" cluster: 0.CL, double-desync, and early-response gadgets

**What it is.** Three related 2025-era HTTP/1.1 desync primitives that build on
the CL.0 foundation doppelganger already probes:

- **0.CL** — the inverse of CL.0. The back-end honours Content-Length normally,
  but the front-end treats any positive Content-Length as zero on certain
  request paths (e.g. after a `204 No Content` response or during keep-alive
  state reuse). The discrepancy is in the *front-end's* parser, not the
  back-end's — so the standard CL.0 probe (which looks for a TE back-end
  treating CL as 0) does not detect it.
- **Double-desync** — chaining two discrepant pairs in series so that the
  smuggled prefix from the first pair is itself a malformed request that
  triggers a second desync at an internal hop. Surface is much smaller than
  single-pair desync but the attack impact is higher (cross-hop request
  capture, internal service poisoning).
- **Early-response gadgets** — exploiting `204 No Content`, `301`/`302`
  redirects, or `100 Continue` interim responses as desync amplifiers.  The
  front-end terminates the connection before the back-end has consumed the
  full smuggled prefix, leaving a poisoned socket in the shared pool that
  will be served to a subsequent victim request.

**Why it matters for positioning.** Burp's HTTP Request Smuggler extension
covers 0.CL and several gadget chains via its active-scan plugin. As long as
doppelganger lacks this cluster it cannot credibly claim parity with Burp on
HTTP/1.1 coverage — it has *better* confirmation quality (differential
confirmation + pipelining discrimination Burp's plugin does not do) but
*narrower* technique coverage. Shipping this cluster closes the coverage gap
and makes doppelganger the stronger choice on both axes for HTTP/1.1.

**Prerequisites.** CL.0 probe (already in `techniques.py`), connection-reuse
control (already in `rawsend.py`), and a keep-alive socket-state mock in
`tests/mockpair.py` to synthesize the 0.CL discrepancy deterministically.
Double-desync requires a two-hop test lab (two discrepant pairs in sequence);
the existing docker-compose lab is the right extension point. Early-response
gadget detection requires parsing interim responses in the confirmation stage —
an extension of the 1xx-skipping logic already added for Expect.CL.TE (v0.6).

---

## 2. Client-side desync (CSD)

**What it is.** Client-side desync (also: browser-powered desync) leverages a
victim user's browser rather than attacker-controlled HTTP to trigger the
desync. The attacker serves a page that causes the victim's browser to make a
fetch/XHR to the target — the browser's HTTP stack generates the malformed
framing (usually a CL.0 GET request with a body), and the front-end's
interpretation of that body as the start of a subsequent request produces the
desync. The CL.0 server-side bug is the same primitive doppelganger already
detects; what CSD adds is the weaponization vector (victim browser → attacker
page → target server).

**Why it matters for positioning.** CSD is a PortSwigger Research flagship
technique and is covered by Burp Suite's Collaborator-based active scan. Not
detecting it is a credible knock on doppelganger in bug-bounty contexts where
CSD findings are increasingly expected. However, the *server-side* precondition
(CL.0 or equivalent discrepancy) is already detected by doppelganger — CSD
adds a *reporting* and *weaponization* layer on top of an existing finding,
not a new detection primitive. A practical implementation is to: (a) when a
CL.0 candidate or confirmed finding is emitted, run a secondary probe that
checks whether the target honours a `GET` request body on reuse (the
browser-reproducible case), and (b) if so, upgrade the finding's vector label
to `CL.0 (CSD-reachable)` and include a PoC fetch payload in the evidence
block.

**Prerequisites.** Confirmed CL.0 detection (already in `techniques.py` and
`engine.py`); connection-reuse mock state in `mockpair.py` to simulate the
browser's keep-alive behaviour; a second confirmation pass in `engine.py` that
uses a reuse-connection probe instead of a new-connection probe. No browser
automation is needed — the *server-side* behaviour is probeable headlessly.
The "victim browser" framing is a weaponization concern; the detection is
purely server-side.

---

## 3. Parser-discrepancy V-H/H-V engine (HRS v3 flagship)

**What it is.** The V-H (Victim-to-HTTP/1.1-front-end sends H1, which the
front-end upgrades to H2 internally before forwarding) and H-V (attacker
sends H2 to a front-end that downgrades to H1 toward the back-end, which then
upgrades again) desync families. These arise at the boundary where a server
simultaneously speaks HTTP/1.1 to some clients and HTTP/2 to others or to
internal hops, and its two parsers disagree about request framing. The
technique was described in James Kettle's "HTTP/2: The Sequel is Always Worse"
research and is the most technically demanding class of desync to detect
headlessly — it requires controlling both the outbound framing and the
protocol-negotiation handshake at each hop.

**Why it matters for positioning.** V-H/H-V desync is where PortSwigger's
HTTP Request Smuggler extension (running inside Burp with full TLS/ALPN
visibility) has a structural advantage over headless tools. Shipping a
V-H/H-V engine would be doppelganger's largest single step toward feature
parity with the Burp extension — and the one most likely to surface novel
findings on modern HTTP/2-everywhere infrastructure (CDN edges, API gateways,
ingress controllers) that the older HTTP/1.1 techniques miss entirely.

**Prerequisites.** doppelganger already has an H2 send layer (`h2send.py`)
and an H2-downgrade engine (`h2engine.py`). V-H/H-V detection needs two
additional capabilities: (a) a protocol-negotiation probe layer that can
force HTTP/1.1 or HTTP/2 ALPN on each connection independently (to reach
V-H vs. H-V configurations), and (b) a second discrepant-hop test setup in
the docker-compose lab (e.g. nginx as an HTTP/1.1 front-end that upgrades to
H2 internally via gRPC proxy_pass). This is a research-grade sub-project;
budget it as a separate lap at no less than the Phase 1 wave-3 tier.

---

## 4. Connection-state and first-request routing probes

**What it is.** Some front-end / back-end pairs exhibit desync only on the
*first* request on a new connection (because the back-end has not yet
established its parsing state from a prior exchange) or only when the
connection pool has just been replenished (state-dependent routing). These are
not technique variants in the CL/TE sense — they are *connection lifecycle*
probes that exercise desync surfaces invisible to per-request isolation.
Concretely: send a warm-up request, then probe; or probe immediately on a
fresh connection; compare the timing and response deltas across both paths to
surface connection-state-dependent discrepancies.

**Why it matters for positioning.** Connection-state desync is a known false-
negative class for tools that default to per-probe connection isolation
(including doppelganger with `--safe` enabled and with `--no-reuse-connection`,
the default). Burp's active scanner sends probes both on fresh and reused
connections as part of its scan logic. Adding explicit first-request probes
covers a gap without requiring new technique payloads — it reuses all existing
`techniques.py` payloads through the existing `rawsend.py` transport, varying
only the connection lifecycle.

**Prerequisites.** The connection-reuse plumbing already exists in
`rawsend.py` (`--reuse-connection` / `--no-reuse-connection`). The additional
work is in `engine.py`: run each technique payload twice — once on a fresh
connection and once after a warm-up request on the same connection — and
compare results. The `mockpair.py` test harness supports connection reuse
already; extending it to model connection-state-dependent behaviour (e.g.
parse-mode toggle on second request) is the prerequisite unit-test work.
