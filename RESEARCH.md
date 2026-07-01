# doppelganger — Research Brief

**Tool:** doppelganger  
**Class:** HTTP request smuggling / desync — parser-discrepancy exploitation  
**Status:** registered, not yet built  
**[CHECK: confirm codename before first build]**

---

## Dead Ancestor

**smuggler.py** (`github.com/defparam/smuggler`) — Nahamcon 2020 era. Only covers CL.TE and TE.CL transfer-encoding mutations. Uses Chrome/78 User-Agent (stale). No CL.0, no H2-downgrade, no H2C upgrade, no client-side desync. Last meaningful commit ~2021.

**Confirmation of "dead":** verify last commit date and lack of H2 / CL.0 support before first build.

---

## Why the Niche Is Open

The modern frontier of HTTP desync is owned by PortSwigger's **HTTP Request Smuggler v3** — a Burp extension (Java/Kotlin, BApp-store, requires Burp Pro license). No headless CLI equivalent covers:
- CL.0 (Content-Length: 0 + chunked body — triggers on non-routing intermediaries)
- H2.CL / H2.TE downgrade (HTTP/2 frontend, HTTP/1.1 backend, desync via header stripping)
- H2C upgrade (plaintext HTTP/2 upgrade injection)
- Client-side desync ("HTTP/1.1 Must Die" — browser-exploitable request smuggling)
- Differential-response confirmation with false-positive reduction

Reference research: James Kettle, PortSwigger Research:
- "HTTP Request Smuggling in 2020" (original smuggler.py context)
- "HTTP/2: The Sequel is Always Worse" (H2 downgrade desync)
- "Browser-Powered Desync Attacks" (client-side desync)
- "Smashing the State Machine" (connection state attacks)

**Do not vendor Burp or PortSwigger code.** Implement techniques from Kettle's published research, not from the extension source.

---

## Niche to Stake

### Core capability (inform v0.1 criteria)

1. **Root-cause parser-discrepancy probes** — not just mutation fuzzing, but structured probes that identify which parsing rule the intermediary applies:
   - Transfer-Encoding header normalization (CL.TE, TE.CL)
   - Obfuscated TE headers (`Transfer-Encoding: identity, chunked`, `chunked\r\n`)
   - CL.0 (send Content-Length: 0 with a chunked body)
   - Conflicting CL headers (CL.CL with different values)

2. **H2-downgrade desync** — HTTP/2-only probes:
   - H2.CL: inject Content-Length in HTTP/2 request that disagrees with :data frame length
   - H2.TE: inject Transfer-Encoding: chunked in HTTP/2 header
   - Requires h2 library or direct HTTP/2 framing

3. **H2C upgrade** — HTTP/1.1 Upgrade: h2c injection to reach plaintext HTTP/2 backends

4. **Client-side desync** — requests that cause a victim browser's connection pool to desync:
   - Safe method (GET/HEAD) with a body that the server doesn't consume
   - Connection: keep-alive to maintain the pooled connection
   - Needs a delivery mechanism (reflected endpoint) — emit the payload, not the delivery

5. **Timeout / differential-response confirmation** — distinguish true desync from timeout:
   - Send a smuggled partial request and measure response time differential
   - False-positive filter: repeat probe to confirm consistency

6. **Finding schema output** — emit confirmed desncs in canonical SARIF-compatible schema with the request pair (outer + smuggled inner), the response differential, and HackerOne adapter fields

### Suite integration (non-negotiable)
- Use the suite's shared `scan-primitives` HTTP client for the outer/HTTP/1.1 layer. Add h2 framing as an internal module (not a separate tool).
- Emit findings in the canonical SARIF-compatible finding schema. No bespoke output format.

---

## Prior Art to Study Before Building

| Tool | State | Notes |
|------|-------|-------|
| smuggler.py (defparam) | Dead ancestor | CL.TE/TE.CL baseline, mutation list reference |
| HTTP Request Smuggler v3 (PortSwigger) | Active (Burp extension, closed) | Technique reference only — do NOT vendor |
| h2spacex (nxenon) | Active (low-level lib) | HTTP/2 raw framing reference for H2 probes |
| Raceocat (JavanXD) | Active (low-level) | Related but focused on race, not smuggling |
| smuggler (PortSwigger blog posts) | Reference | James Kettle's published research — primary technique source |

---

## Not in Scope (do not build, even if useful)

- Full exploit chain (e.g., cache poisoning via smuggling — that's a post-v0.1 direction)
- WebSocket upgrade desync (post-v0.1)
- TLS-terminator-specific probes (too infrastructure-specific for v0.1)
- Response queue poisoning automation beyond detection

---

## Open Questions for Overmind (resolve before v0.1 criteria)

1. Should H2-downgrade probes be in v0.1 or post-v0.1? They require a raw h2 framing dependency.
2. Should client-side desync be in v0.1 (generates a payload only) or post-v0.1?
3. Wave 3 budget (500K) — how deep should v0.1 go on the probe taxonomy? (CL.TE/TE.CL + CL.0 = strong v0.1; H2 adds significant complexity)
4. Is differential-response confirmation mandatory for v0.1, or is a "candidate" finding acceptable?
