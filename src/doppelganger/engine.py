"""Two-stage HTTP/1.1 desync engine: timing detection -> differential confirmation.

This is doppelganger's core (criteria 2-4 of V0.1-CRITERIA.md). For each
technique it runs two stages and, crucially, discriminates pipelining from a real
server-side desync:

**Stage 1 -- timing detection (raises a candidate).** A byte-exact timing probe
(from :mod:`doppelganger.techniques`) is crafted so the back-end is left waiting
for body bytes that never arrive *iff* the target has that front/back parsing
discrepancy. A hang (or a significant timing delta over the baseline) raises a
*candidate*.

**Stage 2 -- differential confirmation (upgrades to confirmed).** A smuggling
attack prepends a prefix that requests a distinct marker resource. A following
well-formed request is then observed:

* on a **fresh, isolated** connection -- if it comes back materially different,
  the smuggled prefix poisoned the *shared back-end connection*: a genuine
  server-side desync -> **confirmed**.
* on a **reused** client connection only -- if the effect appears *only* when we
  reuse one client connection but NOT on a fresh one, it is client-side
  **pipelining**, a benign HTTP feature, not a desync. It is recorded and
  **suppressed**, never reported as a finding (criterion 3, the headline
  correctness feature -- the "false false-positive" that discredits naive tools).

Safe-testing defaults (criterion 4): techniques are probed in safe order (CL.TE
before TE.CL); every probe is an isolated connection unless reuse is explicitly
required for discrimination, and reused connections are always closed (never left
poisoned in a pool); timeouts are bounded and optionally jittered.

**R5 (untrusted input):** response bytes are parsed only to compute a
(status, body) signature and a timing measurement. They are never executed or
handed to a shell / LLM tool call.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from scan_primitives import Scope

from doppelganger.client import BaselineClient
from doppelganger.findings import CWE_REQUEST_SMUGGLING, Finding
from doppelganger.rawsend import RawResponse, RawSender
from doppelganger.techniques import Technique, all_techniques

__all__ = ["ResponseSignature", "DesyncEngine"]

# Cap on how many response bytes we embed as evidence (keep findings compact).
_EVIDENCE_CAP = 1024

# Default "significant timing delta" (ms) over the baseline that, absent a hard
# hang, still raises a candidate.
_DEFAULT_DELTA_MS = 400.0


@dataclass(slots=True, frozen=True)
class ResponseSignature:
    """The comparable fingerprint of a response: (status, body)."""

    status: int
    body: bytes

    @classmethod
    def from_raw(cls, raw: bytes) -> "ResponseSignature | None":
        """Parse a signature from raw HTTP response bytes, or ``None`` if empty."""
        if not raw:
            return None
        status = 0
        first = raw.split(b"\r\n", 1)[0]
        parts = first.split(b" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                status = 0
        idx = raw.find(b"\r\n\r\n")
        body = raw[idx + 4 :] if idx >= 0 else b""
        return cls(status, body)


@dataclass(slots=True)
class _Baseline:
    signature: ResponseSignature
    elapsed_ms: float
    request_line: str


def _safe_text(raw: bytes, cap: int = _EVIDENCE_CAP) -> str:
    """Decode bytes losslessly for evidence embedding (data, never executed)."""
    return raw[:cap].decode("latin-1")


class DesyncEngine:
    """Runs the two-stage desync probe suite against one target.

    Parameters
    ----------
    target_url:
        The target, e.g. ``https://host:port/path``.
    scope:
        The authorized :class:`~scan_primitives.Scope`. Shared by the raw sender
        AND the baseline client -- every probe (raw or well-formed) is
        scope-checked before egress.
    raw_sender / baseline_client:
        Injectable transports (defaults built from ``scope``). Tests inject a
        sender pointed at the in-process mock pair.
    timeout / timing_timeout:
        Read timeouts (seconds). ``timing_timeout`` bounds the hang wait for the
        stage-1 probe (defaults to ``timeout``).
    jitter:
        Adds up to ``jitter`` seconds of random timeout jitter (safe-testing).
    safe:
        Safe/production mode -- forces isolated probing and timeout jitter.
    reuse_connection:
        If ``True`` the *primary* probing reuses one connection (used to
        demonstrate/repro pipelining). The confirmation stage always runs BOTH an
        isolated and a reused experiment regardless, to discriminate.
    retries:
        Number of additional timing probes to send when the first probe times
        out. A genuine back-end hang is stable across retries; a transient
        network timeout (jitter, brief overload) typically clears on the first
        retry. Setting ``retries=1`` or ``retries=2`` reduces false-positive
        timing candidates without masking real desyncs: the timing signal is
        only treated as stable if **all** probes (original + retries) time out.
        Default ``0`` preserves the existing single-probe behaviour.
    """

    def __init__(
        self,
        target_url: str,
        *,
        scope: Scope,
        raw_sender: RawSender | None = None,
        baseline_client: BaselineClient | None = None,
        timeout: float = 10.0,
        timing_timeout: float | None = None,
        jitter: float = 0.0,
        safe: bool = False,
        reuse_connection: bool = False,
        rng=None,
        delta_threshold_ms: float = _DEFAULT_DELTA_MS,
        retries: int = 0,
    ) -> None:
        self.target_url = target_url
        self.scope = scope
        parts = urlsplit(target_url)
        self.use_tls = parts.scheme == "https"
        self.host = parts.hostname or ""
        self.port = parts.port or (443 if self.use_tls else 80)
        self.path = parts.path or "/"
        # Host header includes the port when non-default (byte-exact on the wire).
        default_port = 443 if self.use_tls else 80
        self.host_header = (
            self.host if self.port == default_port else f"{self.host}:{self.port}"
        )

        self.safe = safe
        if safe and jitter == 0.0:
            jitter = 0.1  # safe mode randomises timeouts by default
        self.reuse_connection = reuse_connection and not safe
        self.timeout = timeout
        self.timing_timeout = timing_timeout if timing_timeout is not None else timeout
        self.delta_threshold_ms = delta_threshold_ms
        self.retries = max(0, int(retries))

        self.raw = raw_sender or RawSender(
            scope, timeout=timeout, jitter=jitter, rng=rng
        )
        self.baseline_client = baseline_client or BaselineClient(
            scope, timeout=timeout
        )

        self.findings: list[Finding] = []
        # Pipelining artifacts we discriminated and deliberately did NOT report
        # as desyncs (criterion 3). Kept for auditing / --format transparency.
        self.suppressed: list[dict] = []

    # -- public entry point ------------------------------------------------

    def run(self, techniques: list[Technique] | None = None) -> list[Finding]:
        """Probe ``techniques`` (default: all, safe-ordered) and return findings."""
        techs = techniques if techniques is not None else all_techniques()
        techs = sorted(techs, key=lambda t: t.safe_order)
        baseline = self._baseline()
        for tech in techs:
            self._probe_technique(tech, baseline)
        return self.findings

    # -- baseline ----------------------------------------------------------

    def _victim_request(self) -> bytes:
        """A minimal well-formed request used as the differential 'victim'."""
        return (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"\r\n"
        ).encode()

    def _baseline(self) -> _Baseline:
        """Fetch the well-formed baseline (via scan-primitives) + a raw timing ref."""
        # Well-formed baseline through the shared, scope-enforcing client.
        br = self.baseline_client.fetch(self.target_url)
        sig = ResponseSignature(br.status, br.body)
        # Raw well-formed round-trip time, for the stage-1 timing delta.
        rr = self.raw.send(
            self.host,
            self.port,
            self._victim_request(),
            use_tls=self.use_tls,
            timeout=self.timeout,
        )
        return _Baseline(signature=sig, elapsed_ms=rr.elapsed_ms, request_line=br.request_line)

    # -- per-technique probing --------------------------------------------

    def _probe_technique(self, tech: Technique, baseline: _Baseline) -> None:
        # STAGE 1: timing detection -> candidate.
        timing_delta_ms: float | None = None
        timed_out = False
        timing_probe = tech.timing_probe(self.host_header, self.path)
        if timing_probe is not None:
            rr = self._send_isolated(timing_probe, timeout=self.timing_timeout)
            timed_out = rr.timed_out
            timing_delta_ms = round(rr.elapsed_ms - baseline.elapsed_ms, 1)

            # Retry stabilisation: if the first probe timed out, send up to
            # ``self.retries`` additional probes.  A genuine back-end hang is
            # stable -- all retries also time out.  A transient network timeout
            # (jitter, brief overload) typically clears on the first retry, so
            # we conservatively clear ``timed_out`` and do not treat the signal
            # as stable.  The delta threshold path is not retried (it is already
            # a softer signal and would require N+1 probes exceeding the threshold
            # to be stabilised, which adds unacceptable scan latency).
            for _attempt in range(self.retries):
                if not timed_out:
                    break
                rr_retry = self._send_isolated(timing_probe, timeout=self.timing_timeout)
                if not rr_retry.timed_out:
                    # At least one retry came back clean: the original timeout
                    # was not a stable hang -- treat the timing signal as absent.
                    timed_out = False
                    break
        candidate = timed_out or (
            timing_delta_ms is not None and timing_delta_ms >= self.delta_threshold_ms
        )

        # STAGE 2: differential confirmation + pipelining discrimination.
        attack = tech.differential_attack(self.host_header, self._marker_path(tech), self.path)
        effect_isolated, iso_sig = self._differential_isolated(attack, baseline)
        effect_reuse, _reuse_sig = self._differential_reuse(attack, baseline)

        if effect_isolated:
            # Reproduces on a fresh connection -> genuine server-side desync.
            self._emit(
                tech,
                confirmation="confirmed",
                timing_delta_ms=timing_delta_ms,
                connection_reuse=False,
                attack=attack,
                victim_sig=iso_sig,
                baseline=baseline,
            )
        elif effect_reuse:
            # Only reproduces under client-side connection reuse -> pipelining,
            # NOT a server-side desync (criterion 3). Always recorded for audit.
            self.suppressed.append(
                {
                    "technique": tech.name,
                    "variant": tech.variant,
                    "reason": "effect reproduced only under client-side connection "
                    "reuse; probable pipelining, not a server-side desync",
                    "connection_reuse": True,
                }
            )
            # By default we SUPPRESS it entirely. Only when the operator has
            # explicitly opted into connection reuse do we surface it -- and then
            # only as an info-severity, reuse-flagged signal, never a desync.
            if self.reuse_connection:
                self._emit(
                    tech,
                    confirmation="candidate",
                    timing_delta_ms=timing_delta_ms,
                    connection_reuse=True,
                    attack=attack,
                    victim_sig=None,
                    baseline=baseline,
                    severity="info",
                    pipelining=True,
                )
        elif candidate:
            # Timing signal without a differential confirmation -> candidate.
            self._emit(
                tech,
                confirmation="candidate",
                timing_delta_ms=timing_delta_ms,
                connection_reuse=False,
                attack=attack,
                victim_sig=None,
                baseline=baseline,
            )
        # else: nothing observed for this technique.

    def _marker_path(self, tech: Technique) -> str:
        """A distinct, unlikely-to-exist marker resource for the smuggled prefix."""
        token = hashlib.sha1(
            f"{self.target_url}|{tech.name}|{tech.variant}".encode()
        ).hexdigest()[:10]
        return f"/doppelganger-{token}"

    # -- transports (isolated vs reused) ----------------------------------

    def _send_isolated(self, raw: bytes, *, timeout: float | None = None) -> RawResponse:
        return self.raw.send(
            self.host, self.port, raw, use_tls=self.use_tls, timeout=timeout
        )

    def _differential_isolated(
        self, attack: bytes, baseline: _Baseline
    ) -> tuple[bool, ResponseSignature | None]:
        """Attack on one fresh connection, victim on ANOTHER fresh connection.

        A difference here means the poison crossed connections -- a real
        server-side desync.
        """
        self._send_isolated(attack)  # fresh conn, closed after
        victim = self._send_isolated(self._victim_request())
        sig = ResponseSignature.from_raw(victim.raw)
        effect = sig is not None and sig != baseline.signature
        return effect, sig

    def _differential_reuse(
        self, attack: bytes, baseline: _Baseline
    ) -> tuple[bool, ResponseSignature | None]:
        """Attack then victim on the SAME reused connection.

        A difference here (in the absence of an isolated one) is the pipelining
        signature. The connection is always closed afterwards -- never left in a
        pool (safe-testing).
        """
        conn = self.raw.connect(self.host, self.port, use_tls=self.use_tls)
        try:
            conn.probe(attack, self._jittered(self.timeout))
            victim = conn.probe(self._victim_request(), self._jittered(self.timeout))
        finally:
            conn.close()
        sig = ResponseSignature.from_raw(victim.raw)
        effect = sig is not None and sig != baseline.signature
        return effect, sig

    def _jittered(self, timeout: float) -> float:
        return timeout

    # -- finding emission --------------------------------------------------

    def _emit(
        self,
        tech: Technique,
        *,
        confirmation: str,
        timing_delta_ms: float | None,
        connection_reuse: bool,
        attack: bytes,
        victim_sig: ResponseSignature | None,
        baseline: _Baseline,
        severity: str | None = None,
        pipelining: bool = False,
    ) -> None:
        if pipelining:
            sev, confidence = "info", "low"
            title = (
                f"{tech.name} effect reproduces only under connection reuse "
                f"-- probable client-side pipelining, NOT a confirmed desync"
            )
        elif confirmation == "confirmed":
            sev, confidence = "high", "high"
            title = f"{tech.name} HTTP/1.1 request-smuggling desync confirmed"
        else:
            sev, confidence = "medium", "low"
            title = f"{tech.name} HTTP/1.1 desync candidate (timing signal)"
        if severity is not None:
            sev = severity

        evidence: dict = {
            "discrepancy": tech.discrepancy,
            "confirmation": confirmation,
            "connection_reuse": connection_reuse,
            "request": _safe_text(attack),
            "reproduction": _safe_text(attack),
            "baseline_request": baseline.request_line,
            "baseline_response": f"status={baseline.signature.status} "
            f"body_len={len(baseline.signature.body)}",
        }
        if pipelining:
            evidence["probable_pipelining"] = True
        if timing_delta_ms is not None:
            evidence["timing_delta_ms"] = timing_delta_ms
        if victim_sig is not None:
            evidence["response"] = (
                f"status={victim_sig.status} "
                f"body={_safe_text(victim_sig.body, 256)!r}"
            )

        token = hashlib.sha1(
            f"{self.target_url}|{tech.name}|{tech.variant}|{confirmation}|{pipelining}".encode()
        ).hexdigest()[:8]
        self.findings.append(
            Finding(
                id=f"dg-{tech.name.lower().replace('.', '')}-{token}",
                title=title,
                severity=sev,
                confidence=confidence,
                target=self.target_url,
                vector=tech.name,
                variant=tech.variant,
                cwe_id=CWE_REQUEST_SMUGGLING,
                evidence=evidence,
                references=list(tech.references),
            )
        )
