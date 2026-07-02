"""Shared pytest fixtures for the doppelganger test suite.

The scaffold has no live-target fixtures (the docker discrepant-pair lab and the
in-process raw-socket mock pair are v0.1 work -- see V0.1-CRITERIA.md
Testability). These fixtures build representative :class:`Finding` objects so the
finding / SARIF / HackerOne-markdown layer is exercised end to end.
"""

from __future__ import annotations

import pytest

from doppelganger.findings import Finding


@pytest.fixture
def confirmed_finding() -> Finding:
    """A confirmed CL.TE desync with full evidence."""
    return Finding(
        id="dg-0001",
        title="CL.TE request-smuggling desync confirmed",
        severity="high",
        confidence="high",
        target="https://target.example.com/",
        vector="CL.TE",
        variant="chunked-body-CL0",
        evidence={
            "request": "POST / HTTP/1.1\r\nHost: target.example.com\r\n...",
            "response": "HTTP/1.1 200 OK\r\n...",
            "timing_delta_ms": 4800,
            "confirmation": "confirmed",
            "connection_reuse": False,
            "discrepancy": "CL.TE",
            "reproduction": "POST / HTTP/1.1\r\nContent-Length: 6\r\n...",
        },
        references=[
            "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
        ],
    )


@pytest.fixture
def candidate_finding() -> Finding:
    """A timing-only TE.CL *candidate* (not yet differentially confirmed)."""
    return Finding(
        id="dg-0002",
        title="TE.CL desync candidate (timing signal)",
        severity="medium",
        confidence="low",
        target="https://target.example.com/",
        vector="TE.CL",
        evidence={
            "timing_delta_ms": 5200,
            "confirmation": "candidate",
            "connection_reuse": False,
        },
    )


@pytest.fixture
def sample_findings(confirmed_finding: Finding, candidate_finding: Finding) -> list[Finding]:
    return [confirmed_finding, candidate_finding]
