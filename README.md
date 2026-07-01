# doppelganger

**Status:** registered — awaiting v0.1 criteria from Overmind  
**Slot:** 15 (wave 3, 500K budget)  
**Language:** Python  
**Niche:** HTTP request smuggling / desync

Resurrects the dead-ancestor smuggler.py with modern parser-discrepancy detection: CL.0, H2-downgrade, H2C upgrade, client-side desync ("HTTP/1.1 Must Die"), and differential-response confirmation with false-positive reduction. Headless CLI, no Burp dependency. Integrates with the suite's shared scan-primitives HTTP client and emits findings in the canonical SARIF-compatible schema.

See `RESEARCH.md` for the niche brief and prior-art analysis.

> **Do not build until the Overmind defines v0.1 criteria.**
