"""Tests for the byte-exact raw-socket transport (doppelganger.rawsend).

Covers: scope enforcement blocks egress BEFORE any socket opens (fail-closed),
byte-exact writes with NO header normalisation, the timing-hang signal, and
connection reuse vs. per-probe isolation.
"""

from __future__ import annotations

import pytest

import mockpair
from scan_primitives import OutOfScopeError, Scope
from doppelganger.rawsend import RawSender


@pytest.fixture
def loopback_scope() -> Scope:
    return Scope.from_entries(["127.0.0.1"])


# --------------------------------------------------------------------------- #
# scope enforcement precedes egress
# --------------------------------------------------------------------------- #


@pytest.mark.disable_socket
def test_out_of_scope_host_raises_before_any_socket(loopback_scope):
    """An out-of-scope host raises OutOfScopeError and opens NO socket.

    With sockets disabled by pytest-socket, if the sender tried to connect we
    would see SocketBlockedError instead of OutOfScopeError. Getting
    OutOfScopeError proves the scope check runs before socket creation.
    """
    sender = RawSender(loopback_scope, timeout=0.5)
    with pytest.raises(OutOfScopeError):
        sender.send("evil.example.net", 80, b"GET / HTTP/1.1\r\n\r\n")


@pytest.mark.disable_socket
def test_no_scope_is_fail_closed():
    """A sender with no scope refuses all egress (fail-closed)."""
    sender = RawSender(None, timeout=0.5)
    with pytest.raises(OutOfScopeError):
        sender.send("127.0.0.1", 80, b"GET / HTTP/1.1\r\n\r\n")


@pytest.mark.disable_socket
def test_connect_also_scope_checked(loopback_scope):
    """The explicit-reuse connect() path is scope-checked too."""
    sender = RawSender(loopback_scope, timeout=0.5)
    with pytest.raises(OutOfScopeError):
        sender.connect("169.254.169.254", 80)  # cloud metadata, not in scope


# --------------------------------------------------------------------------- #
# byte-exact: no header normalisation
# --------------------------------------------------------------------------- #


def test_probe_is_sent_byte_for_byte(loopback_scope):
    """The exact malformed bytes reach the wire -- no normalisation, no reorder."""
    # Duplicate Content-Length, odd spacing, an obfuscated TE: a normalising
    # client would rewrite or reject all of this.
    probe = (
        b"POST / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 0\r\n"
        b"Transfer-Encoding : chunked\r\n"
        b"X-Weird:   spaced\r\n"
        b"\r\n"
        b"hello"
    )
    with mockpair.RawCaptureServer() as srv:
        sender = RawSender(loopback_scope, timeout=1.0)
        sender.send(srv.host, srv.port, probe, timeout=1.0)
    assert srv.received, "server captured nothing"
    assert srv.received[0] == probe


# --------------------------------------------------------------------------- #
# timing signal
# --------------------------------------------------------------------------- #


def test_hang_produces_timed_out(loopback_scope):
    """A CL.TE timing probe against a front=CL/back=TE pair hangs -> timed_out."""
    from doppelganger.techniques import technique_by_name

    clte = technique_by_name("CL.TE")[0]
    with mockpair.clte_pair() as srv:
        sender = RawSender(loopback_scope, timeout=0.4)
        resp = sender.send(srv.host, srv.port, clte.timing_probe("127.0.0.1"), timeout=0.4)
    assert resp.timed_out is True
    assert resp.elapsed_s >= 0.35  # waited ~ the full timeout


def test_wellformed_request_returns_fast(loopback_scope):
    """A well-formed GET completes promptly (not timed out)."""
    with mockpair.clte_pair() as srv:
        sender = RawSender(loopback_scope, timeout=2.0)
        resp = sender.send(
            srv.host, srv.port, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", timeout=2.0
        )
    assert resp.timed_out is False
    assert resp.status_line.startswith(b"HTTP/1.1 200")
    assert resp.elapsed_s < 1.0


# --------------------------------------------------------------------------- #
# reuse vs isolation
# --------------------------------------------------------------------------- #


def test_connection_reuse_sends_two_on_one_socket(loopback_scope):
    """A reused RawConnection carries two requests down one socket."""
    with mockpair.RawCaptureServer() as srv:
        sender = RawSender(loopback_scope, timeout=1.0)
        conn = sender.connect(srv.host, srv.port)
        try:
            r1 = conn.probe(b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 1.0)
            r2 = conn.probe(b"GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", 1.0)
        finally:
            conn.close()
    assert r1.status_line.startswith(b"HTTP/1.1 200")
    assert r2.status_line.startswith(b"HTTP/1.1 200")
    # Two requests, one connection: both tagged with the same connection id.
    assert len(srv.received) == 2
    assert srv.request_conns[0] == srv.request_conns[1]


def test_isolated_send_opens_a_fresh_connection_each_time(loopback_scope):
    """Default send() isolates: each probe is its own connection."""
    with mockpair.RawCaptureServer() as srv:
        sender = RawSender(loopback_scope, timeout=1.0)
        sender.send(srv.host, srv.port, b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        sender.send(srv.host, srv.port, b"GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    # Two separate connections -> two distinct connection ids.
    assert len(srv.received) == 2
    assert srv.request_conns[0] != srv.request_conns[1]
