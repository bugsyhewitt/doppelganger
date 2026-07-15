"""doppelganger -- HTTP/1.1 request-smuggling / desync detection & confirmation.

A headless CLI successor to the dead-ancestor ``smuggler.py``. doppelganger
detects and *differentially confirms* the HTTP/1.1 desync family -- CL.TE,
TE.CL, TE.TE (transfer-encoding obfuscation), CL.0, and duplicate/conflicting
Content-Length -- with first-class pipelining-vs-smuggling false-positive
discrimination and safe-testing defaults. Findings are emitted in the pinned
suite schema (CWE-444) plus SARIF 2.1.0 and HackerOne markdown via
``h1-reporter``.

The v0.1 engine is built: a two-stage detector (``engine``) drives byte-exact
raw probes (``rawsend``) for timing detection and differential confirmation with
pipelining false-positive discrimination, backed by the scope-enforcing
``scan-primitives`` client (``client``) for well-formed baseline traffic.
Findings emit to the pinned schema (``findings``) + SARIF (``sarif``) + HackerOne
markdown (``reporting``). See ``V0.1-CRITERIA.md``.

Authorized use only: this tool sends live probes to a target and can disrupt
shared back-ends if used carelessly. Only test systems you are authorized to
test.
"""

__version__ = "0.9.0"

__all__ = ["__version__"]
