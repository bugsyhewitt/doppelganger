"""Two-stage HTTP/2-downgrade desync engine: timing detection -> confirmation.

This is doppelganger's v0.2 H2 core. It is the HTTP/2 analogue of
:class:`doppelganger.engine.DesyncEngine`: the same two-stage model (timing
candidate -> differential confirmation) and the same pipelining-vs-desync
discrimination, but driven over the byte-exact HTTP/2 send layer
(:mod:`doppelganger.h2send`) instead of the HTTP/1.1 raw sender, using the
H2.CL / H2.TE probe builders in :mod:`doppelganger.h2techniques`.

It is a *separate* engine rather than an extension of ``DesyncEngine`` on
purpose: H2 needs a different transport (frames + ALPN, no HTTP/1.1 raw sender)
and a different baseline (a well-formed H2 request, not the httpx client), so
keeping it separate leaves the audited v0.1 HTTP/1.1 engine untouched.

**Stage 1 -- timing detection (candidate).** An H2 request with a lying
``content-length`` (H2.CL) or an injected ``transfer-encoding: chunked``
(H2.TE), once naively downgraded to HTTP/1.1, leaves the back-end waiting for
body bytes that never arrive -> the H2 response never comes -> a read timeout.
A hang (or a significant timing delta over a well-formed H2 baseline) raises a
*candidate*.

**Stage 2 -- differential confirmation (confirmed) + pipelining discrimination.**
A smuggling attack prepends a prefix requesting a distinct marker resource. A
following well-formed H2 request is observed on a **fresh** connection (a
materially different response means the poison crossed connections -> a genuine
server-side desync -> *confirmed*) and on a **reused** connection (an effect that
appears ONLY under reuse is client-side pipelining, NOT a desync -> suppressed).

Scope + safe-testing defaults match v0.1: the shared ``Scope`` is enforced before
any egress (fail-closed), probing is isolated per-connection unless reuse is
explicitly required for discrimination, and reused connections are always closed.

**R5 (untrusted input):** response bytes are parsed only to a (status, body)
signature + a timing measurement. They are never executed or handed to a shell /
LLM tool call.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from scan_primitives import Scope

from doppelganger.engine import ResponseSignature, _DEFAULT_DELTA_MS, _EVIDENCE_CAP
from doppelganger.findings import CWE_REQUEST_SMUGGLING, Finding
from doppelganger.h2send import H2NotSupportedError, H2Request, H2Response, H2Sender
from doppelganger.h2techniques import H2Technique, all_h2_techniques

__all__ = ["H2DesyncEngine"]


@dataclass(slots=True)
class _H2Baseline:
    signature: ResponseSignature
    elapsed_ms: float
    request_line: str


def _safe_text(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Cap evidence text (already a str; data, never executed)."""
    return text[:cap]


def _sig(resp: H2Response) -> ResponseSignature:
    """The comparable (status, body) fingerprint of an H2 response."""
    return ResponseSignature(resp.status or 0, resp.body)


class H2DesyncEngine:
    """Runs the two-stage H2-downgrade probe suite against one target.

    Parameters mirror :class:`doppelganger.engine.DesyncEngine`. ``https://``
    targets negotiate ``h2`` via ALPN; ``http://`` targets use prior-knowledge
    plaintext H2 (the in-process test lab). The ``authority`` (H2 ``:authority``
    pseudo-header) includes the port when non-default, byte-exact on the wire.
    """

    def __init__(
        self,
        target_url: str,
        *,
        scope: Scope,
        h2_sender: H2Sender | None = None,
        timeout: float = 10.0,
        timing_timeout: float | None = None,
        jitter: float = 0.0,
        safe: bool = False,
        reuse_connection: bool = False,
        rng=None,
        delta_threshold_ms: float = _DEFAULT_DELTA_MS,
    ) -> None:
        self.target_url = target_url
        self.scope = scope
        parts = urlsplit(target_url)
        self.use_tls = parts.scheme == "https"
        self.scheme = "https" if self.use_tls else "http"
        self.host = parts.hostname or ""
        self.port = parts.port or (443 if self.use_tls else 80)
        self.path = parts.path or "/"
        default_port = 443 if self.use_tls else 80
        self.authority = (
            self.host if self.port == default_port else f"{self.host}:{self.port}"
        )

        self.safe = safe
        if safe and jitter == 0.0:
            jitter = 0.1
        self.reuse_connection = reuse_connection and not safe
        self.timeout = timeout
        self.timing_timeout = timing_timeout if timing_timeout is not None else timeout
        self.delta_threshold_ms = delta_threshold_ms

        self.h2 = h2_sender or H2Sender(scope, timeout=timeout, jitter=jitter, rng=rng)

        self.findings: list[Finding] = []
        self.suppressed: list[dict] = []

    # -- public entry point ------------------------------------------------

    def run(self, techniques: list[H2Technique] | None = None) -> list[Finding]:
        """Probe ``techniques`` (default: all H2, safe-ordered) and return findings."""
        techs = techniques if techniques is not None else all_h2_techniques()
        techs = sorted(techs, key=lambda t: t.safe_order)
        baseline = self._baseline()
        for tech in techs:
            self._probe_technique(tech, baseline)
        return self.findings

    # -- baseline ----------------------------------------------------------

    def _victim_request(self) -> H2Request:
        """A well-formed H2 GET used as the differential 'victim'."""
        return H2Request.get(self.authority, self.path, self.scheme)

    def _baseline(self) -> _H2Baseline:
        """Fetch the well-formed H2 baseline (status/body signature + timing ref)."""
        rr = self._send_isolated(self._victim_request(), timeout=self.timeout)
        return _H2Baseline(
            signature=_sig(rr),
            elapsed_ms=rr.elapsed_ms,
            request_line=f"GET {self.path} HTTP/2 (:authority {self.authority})",
        )

    # -- per-technique probing --------------------------------------------

    def _probe_technique(self, tech: H2Technique, baseline: _H2Baseline) -> None:
        # STAGE 1: timing detection -> candidate.
        timing_probe = tech.timing_request(self.authority, self.path, self.scheme)
        rr = self._send_isolated(timing_probe, timeout=self.timing_timeout)
        timed_out = rr.timed_out
        timing_delta_ms = round(rr.elapsed_ms - baseline.elapsed_ms, 1)
        candidate = timed_out or (timing_delta_ms >= self.delta_threshold_ms)

        # STAGE 2: differential confirmation + pipelining discrimination.
        attack = tech.differential_request(
            self.authority, self._marker_path(tech), self.path, self.scheme
        )
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
            # Only reproduces under connection reuse -> pipelining, NOT a
            # server-side desync (the headline correctness feature). Suppressed.
            self.suppressed.append(
                {
                    "technique": tech.name,
                    "variant": tech.variant,
                    "reason": "effect reproduced only under client-side connection "
                    "reuse; probable pipelining, not a server-side desync",
                    "connection_reuse": True,
                }
            )
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
            # Timing signal without differential confirmation -> candidate.
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

    def _marker_path(self, tech: H2Technique) -> str:
        """A distinct, unlikely-to-exist marker resource for the smuggled prefix."""
        token = hashlib.sha1(
            f"{self.target_url}|{tech.name}".encode()
        ).hexdigest()[:10]
        return f"/doppelganger-h2-{token}"

    # -- transports (isolated vs reused) ----------------------------------

    def _send_isolated(self, req: H2Request, *, timeout: float | None = None) -> H2Response:
        return self.h2.send(
            self.host, self.port, req, use_tls=self.use_tls, timeout=timeout
        )

    def _differential_isolated(
        self, attack: H2Request, baseline: _H2Baseline
    ) -> tuple[bool, ResponseSignature | None]:
        """Attack on one fresh connection, victim on ANOTHER fresh connection.

        A difference here means the poison crossed connections -- a real
        server-side desync.
        """
        self._send_isolated(attack)  # fresh conn, closed after
        victim = self._send_isolated(self._victim_request())
        sig = _sig(victim)
        effect = sig != baseline.signature
        return effect, sig

    def _differential_reuse(
        self, attack: H2Request, baseline: _H2Baseline
    ) -> tuple[bool, ResponseSignature | None]:
        """Attack then victim on the SAME reused connection (streams 1, 3).

        A difference here (absent an isolated one) is the pipelining signature.
        The connection is always closed afterwards -- never left open.
        """
        conn = self.h2.connect(self.host, self.port, use_tls=self.use_tls)
        try:
            conn.send_request(attack, self.timeout)
            victim = conn.send_request(self._victim_request(), self.timeout)
        finally:
            conn.close()
        sig = _sig(victim)
        effect = sig != baseline.signature
        return effect, sig

    # -- finding emission --------------------------------------------------

    def _emit(
        self,
        tech: H2Technique,
        *,
        confirmation: str,
        timing_delta_ms: float | None,
        connection_reuse: bool,
        attack: H2Request,
        victim_sig: ResponseSignature | None,
        baseline: _H2Baseline,
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
            title = f"{tech.name} HTTP/2-downgrade request-smuggling desync confirmed"
        else:
            sev, confidence = "medium", "low"
            title = f"{tech.name} HTTP/2-downgrade desync candidate (timing signal)"
        if severity is not None:
            sev = severity

        rendered = attack.render()
        evidence: dict = {
            "discrepancy": tech.discrepancy,
            "confirmation": confirmation,
            "connection_reuse": connection_reuse,
            "http_version": "h2-downgrade",
            "request": _safe_text(rendered),
            "reproduction": _safe_text(rendered),
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
                f"body={victim_sig.body[:256].decode('latin-1')!r}"
            )

        token = hashlib.sha1(
            f"{self.target_url}|{tech.name}|{confirmation}|{pipelining}".encode()
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
