"""v0.6 acceptance tests: Expect: 100-continue desync probe.

Covers:
* rawsend._read_response skips 1xx interim responses and waits for the final
  response; the timing signal comes from the back-end hang, NOT the 100 Continue.
* Expect.CL.TE technique is present in all_techniques() with safe_order == 0,
  after plain CL.TE.
* Probe bytes include both Transfer-Encoding: chunked and Expect: 100-continue.
* Engine detects and CONFIRMS Expect.CL.TE desync against the expect_clte_pair
  mock (front sends 100 Continue, back=TE hangs).
* Engine detects Expect.CL.TE as a CANDIDATE when the mock hangs but does not
  poison (no differential effect).
* Pipelining discrimination: a pipeline-only effect is suppressed even through
  the Expect path.
* An Expect-unaware server (sends no 100 Continue) still detects Expect.CL.TE
  via the same CL.TE timing path.
* CLI wiring: --technique Expect.CL.TE is accepted.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

import mockpair
from scan_primitives import Scope
from doppelganger.engine import DesyncEngine
from doppelganger.findings import CWE_REQUEST_SMUGGLING
from doppelganger.rawsend import RawSender, _read_response
from doppelganger.techniques import (
    EXPECT_HEADER,
    Technique,
    all_techniques,
    technique_by_name,
)

TIMEOUT = 0.4


@pytest.fixture
def scope() -> Scope:
    return Scope.from_entries(["127.0.0.1"])


def _engine(server, scope: Scope, **kw) -> DesyncEngine:
    return DesyncEngine(
        server.base_url,
        scope=scope,
        timeout=TIMEOUT,
        timing_timeout=TIMEOUT,
        **kw,
    )


def _expect_tech() -> Technique:
    """The Expect.CL.TE technique from all_techniques()."""
    techs = technique_by_name("Expect.CL.TE")
    assert techs, "Expect.CL.TE not found in all_techniques()"
    return techs[0]


# ---------------------------------------------------------------------------
# Technique registration
# ---------------------------------------------------------------------------


def test_expect_clte_in_all_techniques():
    """Expect.CL.TE is present in all_techniques()."""
    names = [t.name for t in all_techniques()]
    assert "Expect.CL.TE" in names


def test_expect_clte_safe_order_matches_clte():
    """Expect.CL.TE safe_order == 0 (same slot as CL.TE, probed before TE.CL)."""
    tech = _expect_tech()
    assert tech.safe_order == 0


def test_expect_clte_variant_is_expect():
    """Expect.CL.TE carries variant='expect'."""
    assert _expect_tech().variant == "expect"


def test_expect_clte_discrepancy_is_clte():
    """Expect.CL.TE discrepancy is 'CL.TE' (the underlying class)."""
    assert _expect_tech().discrepancy == "CL.TE"


# ---------------------------------------------------------------------------
# Probe payload shape
# ---------------------------------------------------------------------------


def test_expect_clte_timing_probe_contains_expect_header():
    """Timing probe byte stream includes Expect: 100-continue."""
    tech = _expect_tech()
    probe = tech.timing_probe("target.example.com")
    assert probe is not None
    assert EXPECT_HEADER in probe


def test_expect_clte_timing_probe_contains_te_header():
    """Timing probe includes Transfer-Encoding: chunked (CL.TE framing)."""
    tech = _expect_tech()
    probe = tech.timing_probe("target.example.com")
    assert probe is not None
    assert b"Transfer-Encoding: chunked" in probe
    assert b"Content-Length: 4" in probe


def test_expect_clte_differential_attack_contains_expect_header():
    """Differential attack payload includes Expect: 100-continue."""
    tech = _expect_tech()
    attack = tech.differential_attack("target.example.com", "/dg-expect-marker")
    assert EXPECT_HEADER in attack


def test_expect_clte_differential_attack_smuggles_marker_path():
    """Differential attack embeds the marker-path GET in the smuggled prefix."""
    tech = _expect_tech()
    attack = tech.differential_attack("target.example.com", "/dg-expect-marker")
    assert b"GET /dg-expect-marker" in attack
    assert b"0\r\n\r\n" in attack


# ---------------------------------------------------------------------------
# rawsend 1xx skipping
# ---------------------------------------------------------------------------


def _make_server_that_sends_then_hangs(preamble: bytes) -> tuple[str, int, threading.Event]:
    """Spin up a minimal server that sends ``preamble`` then blocks.

    Returns (host, port, stop_event).  Set stop_event to unblock the server.
    """
    stop = threading.Event()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(4)
    port = server_sock.getsockname()[1]

    def serve():
        server_sock.settimeout(2.0)
        while not stop.is_set():
            try:
                conn, _ = server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.settimeout(2.0)
                # Consume the request headers (don't need to parse them).
                buf = bytearray()
                while b"\r\n\r\n" not in buf:
                    try:
                        chunk = conn.recv(4096)
                    except (socket.timeout, OSError):
                        break
                    if not chunk:
                        break
                    buf += chunk
                # Send the preamble, then block until the client closes.
                conn.sendall(preamble)
                stop.wait(timeout=2.0)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        try:
            server_sock.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return "127.0.0.1", port, stop


def test_read_response_skips_100_continue_and_times_out():
    """_read_response skips a 100 Continue preamble and then times out (hang).

    The server sends ``100 Continue`` immediately, then never sends a final
    response.  Without 1xx skipping, the reader would return the 100 Continue
    (fast, no timeout).  With 1xx skipping, it continues waiting and eventually
    times out -- exactly what we need for the Expect.CL.TE timing signal.
    """
    host, port, stop = _make_server_that_sends_then_hangs(b"HTTP/1.1 100 Continue\r\n\r\n")
    timeout = 0.3
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=1.0)
    try:
        sock.sendall(b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\n\r\n")
        raw, timed_out, eof = _read_response(sock, deadline)
    finally:
        sock.close()
        stop.set()

    # The 100 Continue is consumed and not returned; we time out waiting for
    # the final response.
    assert timed_out, "expected timeout after 100 Continue preamble; got a response"
    # The raw bytes returned should be the FINAL response (nothing -- we timed out).
    assert raw == b"" or b"100" not in raw.split(b"\r\n", 1)[0]


def test_read_response_skips_100_continue_and_reads_final():
    """_read_response skips a 100 Continue and returns the subsequent 200 OK."""
    response_200 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    host, port, stop = _make_server_that_sends_then_hangs(
        b"HTTP/1.1 100 Continue\r\n\r\n" + response_200
    )
    timeout = 0.5
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=1.0)
    try:
        sock.sendall(b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\n\r\nok")
        raw, timed_out, eof = _read_response(sock, deadline)
    finally:
        sock.close()
        stop.set()

    assert not timed_out, f"unexpected timeout; raw={raw!r}"
    assert raw.startswith(b"HTTP/1.1 200 OK"), f"expected 200 OK, got: {raw[:40]!r}"
    assert b"100" not in raw.split(b"\r\n", 1)[0], "100 Continue leaked into returned bytes"


def test_read_response_skips_multiple_1xx_then_reads_final():
    """_read_response skips multiple 1xx responses (100 + 102) and returns the 200."""
    preamble = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 102 Processing\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"
    )
    host, port, stop = _make_server_that_sends_then_hangs(preamble)
    timeout = 0.5
    deadline = time.monotonic() + timeout
    sock = socket.create_connection((host, port), timeout=1.0)
    try:
        sock.sendall(b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        raw, timed_out, eof = _read_response(sock, deadline)
    finally:
        sock.close()
        stop.set()

    assert not timed_out
    assert raw.startswith(b"HTTP/1.1 200 OK")
    assert b"done" in raw


# ---------------------------------------------------------------------------
# Engine: Expect.CL.TE detection and confirmation
# ---------------------------------------------------------------------------


def test_expect_clte_confirmed_on_expect_clte_mock(scope):
    """Expect.CL.TE differentially CONFIRMS a desync on the expect_clte_pair.

    The mock sends 100 Continue (front-end Expect-aware), then applies CL.TE
    framing (front=CL/back=TE).  With the 1xx-skipping fix the engine observes
    the back-end hang AFTER the 100 Continue and upgrades to confirmed via the
    differential attack.
    """
    tech = _expect_tech()
    with mockpair.expect_clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    assert len(findings) == 1, f"expected 1 Expect.CL.TE finding; got {findings}"
    f = findings[0]
    assert f.vector == "Expect.CL.TE"
    assert f.variant == "expect"
    assert f.evidence["confirmation"] == "confirmed"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.evidence["connection_reuse"] is False
    assert f.cwe_id == CWE_REQUEST_SMUGGLING
    assert f.evidence["discrepancy"] == "CL.TE"
    assert "reproduction" in f.evidence and f.evidence["reproduction"]
    assert not engine.suppressed


def test_expect_clte_candidate_when_no_differential_poison(scope):
    """Expect.CL.TE emits a CANDIDATE when the mock hangs but never poisons."""
    tech = _expect_tech()
    with mockpair.ExpectMockPair("server_desync", poison=False) as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    assert len(findings) == 1
    f = findings[0]
    assert f.vector == "Expect.CL.TE"
    assert f.evidence["confirmation"] == "candidate"
    assert f.severity == "medium"
    assert f.confidence == "low"


def test_expect_clte_pipelining_suppressed(scope):
    """Expect.CL.TE pipeline-only effect is suppressed -- not a server-side desync."""
    tech = _expect_tech()
    with mockpair.expect_clte_pair("pipeline_only") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    assert findings == [], "pipeline-only Expect.CL.TE must not be reported as a desync"
    assert len(engine.suppressed) == 1
    entry = engine.suppressed[0]
    assert entry["technique"] == "Expect.CL.TE"
    assert entry["connection_reuse"] is True
    assert "pipelining" in entry["reason"]


def test_expect_clte_on_expect_unaware_server_still_detects(scope):
    """Expect.CL.TE detects CL.TE desync even when the server sends no 100 Continue.

    An Expect-unaware front-end simply ignores the Expect header and processes
    the request as a normal CL.TE POST -- the timing signal and differential
    confirmation still fire.
    """
    tech = _expect_tech()
    # clte_pair does not send 100 Continue; Expect header is just ignored.
    with mockpair.clte_pair("server_desync") as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    assert len(findings) >= 1
    f = findings[0]
    assert f.vector == "Expect.CL.TE"
    assert f.evidence["confirmation"] == "confirmed"


def test_expect_clte_no_finding_on_robust_pair(scope):
    """Expect.CL.TE produces no finding against a non-vulnerable (CL/CL) server."""
    tech = _expect_tech()
    with mockpair.robust_pair() as srv:
        engine = _engine(srv, scope)
        findings = engine.run([tech])

    assert findings == []
    assert engine.suppressed == []


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_accepts_expect_clte_technique():
    """--technique Expect.CL.TE is accepted by the CLI parser."""
    from doppelganger.cli import build_parser

    parser = build_parser()
    args = parser.parse_args([
        "--technique", "Expect.CL.TE",
        "--scope-file", "/dev/null",
        "http://127.0.0.1/",
    ])
    assert args.technique == "Expect.CL.TE"
