"""Tests for the H2C cleartext-upgrade smuggling detection engine (v0.3).

Each test uses an in-process mock TCP server to avoid any real network calls
and to produce millisecond-stable results.  The mock servers are:

* ``h2c_upgrade_pair`` -- accepts Upgrade: h2c with 101, completes H2 handshake
  (SETTINGS frame sent after preface).  Models the confirmed finding.
* ``h2c_101_no_h2_pair`` -- accepts with 101 but then sends garbage instead of
  a SETTINGS frame.  Models the candidate (got_101 but !h2_handshake_complete).
* ``h2c_reject_pair`` -- responds 200 (not 101).  The negative control; no
  finding should be emitted.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading

import pytest

from scan_primitives import Scope

from doppelganger.h2c import H2CEngine, H2C_TECHNIQUES, _upgrade_request
from doppelganger.h2send import FRAME_SETTINGS, build_settings_frame

# The shared 127.0.0.1 scope (``loopback_scope`` fixture from conftest.py).


# --------------------------------------------------------------------------- #
# in-process mock servers for H2C scenarios                                   #
# --------------------------------------------------------------------------- #

_IDLE_TIMEOUT = 4.0

_101_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Connection: Upgrade\r\n"
    b"Upgrade: h2c\r\n"
    b"\r\n"
)

_200_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"ok"
)

# Minimal server SETTINGS frame (9 bytes, no payload).
_SERVER_SETTINGS = build_settings_frame()

# Exact H2 client preface bytes -- we verify the client sends these.
from doppelganger.h2send import H2_PREFACE  # noqa: E402


class _H2CUpgradeMock:
    """Sends 101 then a proper H2 SETTINGS frame (models the confirmed case)."""

    def __init__(self) -> None:
        self.host = "127.0.0.1"
        self.port = 0
        self._listener: socket.socket | None = None

    def start(self) -> "_H2CUpgradeMock":
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def stop(self) -> None:
        lst, self._listener = self._listener, None
        if lst is not None:
            try:
                lst.close()
            except OSError:
                pass

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def __enter__(self) -> "_H2CUpgradeMock":
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _serve(self) -> None:
        lst = self._listener
        if lst is None:
            return
        while True:
            try:
                conn, _ = lst.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_IDLE_TIMEOUT)
        try:
            buf = bytearray()
            # Read until end of HTTP/1.1 request headers.
            while b"\r\n\r\n" not in buf:
                try:
                    chunk = conn.recv(4096)
                except (socket.timeout, OSError):
                    return
                if not chunk:
                    return
                buf += chunk

            # Send 101 Switching Protocols.
            conn.sendall(_101_RESPONSE)

            # Wait for H2 client preface (24 bytes).
            preface_buf = bytearray()
            while len(preface_buf) < len(H2_PREFACE):
                try:
                    chunk = conn.recv(len(H2_PREFACE) - len(preface_buf))
                except (socket.timeout, OSError):
                    return
                if not chunk:
                    return
                preface_buf += chunk

            # Send server SETTINGS (completes the handshake confirmation).
            conn.sendall(_SERVER_SETTINGS)

            # Drain the rest politely (client sends SETTINGS + SETTINGS ACK).
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                except (socket.timeout, OSError):
                    break
        finally:
            try:
                conn.close()
            except OSError:
                pass


class _H2C101NoH2Mock:
    """Sends 101 but then garbage (no valid H2 SETTINGS frame)."""

    def __init__(self) -> None:
        self.host = "127.0.0.1"
        self.port = 0
        self._listener: socket.socket | None = None

    def start(self) -> "_H2C101NoH2Mock":
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def stop(self) -> None:
        lst, self._listener = self._listener, None
        if lst is not None:
            try:
                lst.close()
            except OSError:
                pass

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def __enter__(self) -> "_H2C101NoH2Mock":
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _serve(self) -> None:
        lst = self._listener
        if lst is None:
            return
        while True:
            try:
                conn, _ = lst.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_IDLE_TIMEOUT)
        try:
            buf = bytearray()
            while b"\r\n\r\n" not in buf:
                try:
                    chunk = conn.recv(4096)
                except (socket.timeout, OSError):
                    return
                if not chunk:
                    return
                buf += chunk
            conn.sendall(_101_RESPONSE)
            # Send garbage instead of H2 SETTINGS -- closes immediately after.
            conn.sendall(b"\xff\xff\xff\xff garbage not-h2-at-all\r\n")
        finally:
            try:
                conn.close()
            except OSError:
                pass


class _H2CRejectMock:
    """Responds 200 to the upgrade request (no upgrade)."""

    def __init__(self) -> None:
        self.host = "127.0.0.1"
        self.port = 0
        self._listener: socket.socket | None = None

    def start(self) -> "_H2CRejectMock":
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def stop(self) -> None:
        lst, self._listener = self._listener, None
        if lst is not None:
            try:
                lst.close()
            except OSError:
                pass

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def __enter__(self) -> "_H2CRejectMock":
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def _serve(self) -> None:
        lst = self._listener
        if lst is None:
            return
        while True:
            try:
                conn, _ = lst.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_IDLE_TIMEOUT)
        try:
            buf = bytearray()
            while b"\r\n\r\n" not in buf:
                try:
                    chunk = conn.recv(4096)
                except (socket.timeout, OSError):
                    return
                if not chunk:
                    return
                buf += chunk
            conn.sendall(_200_RESPONSE)
        finally:
            try:
                conn.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# engine tests                                                                 #
# --------------------------------------------------------------------------- #


def test_h2c_confirmed_on_upgrade_and_handshake(loopback_scope: Scope):
    """Server accepts h2c and completes the H2 handshake -> confirmed finding."""
    with _H2CUpgradeMock() as srv:
        engine = H2CEngine(srv.base_url, scope=loopback_scope, timeout=2.0)
        findings = engine.run()

    assert len(findings) == 1, f"expected 1 finding, got {findings}"
    f = findings[0]
    assert f.vector == "H2C"
    assert f.severity == "medium"
    assert f.confidence == "high"
    assert f.evidence["confirmation"] == "confirmed"
    assert f.evidence["h2_handshake_complete"] is True
    assert f.evidence["connection_reuse"] is False
    assert f.cwe_id == 444
    assert any("h2c" in ref.lower() for ref in f.references)


def test_h2c_candidate_on_101_without_h2_handshake(loopback_scope: Scope):
    """Server sends 101 but doesn't complete H2 handshake -> candidate finding."""
    with _H2C101NoH2Mock() as srv:
        engine = H2CEngine(srv.base_url, scope=loopback_scope, timeout=2.0)
        findings = engine.run()

    assert len(findings) == 1, f"expected 1 candidate finding, got {findings}"
    f = findings[0]
    assert f.vector == "H2C"
    assert f.confidence == "low"
    assert f.evidence["confirmation"] == "candidate"
    assert f.evidence["h2_handshake_complete"] is False


def test_h2c_no_finding_on_200_rejection(loopback_scope: Scope):
    """Server rejects upgrade (200) -> no finding emitted (negative control)."""
    with _H2CRejectMock() as srv:
        engine = H2CEngine(srv.base_url, scope=loopback_scope, timeout=2.0)
        findings = engine.run()

    assert findings == [], f"expected no findings for a non-upgrading server, got {findings}"
    assert engine.suppressed == []


def test_h2c_scope_enforced_before_socket(loopback_scope: Scope):
    """An out-of-scope host raises OutOfScopeError before any socket is opened."""
    from scan_primitives import OutOfScopeError

    engine = H2CEngine("http://out-of-scope.example.com/", scope=loopback_scope, timeout=1.0)
    with pytest.raises(OutOfScopeError):
        engine.run()


def test_h2c_no_scope_is_fail_closed():
    """A scope=None engine refuses all egress (fail-closed)."""
    from scan_primitives import OutOfScopeError

    engine = H2CEngine.__new__(H2CEngine)
    engine.target_url = "http://127.0.0.1/"
    engine.scope = None
    engine.host = "127.0.0.1"
    engine.findings = []
    engine.suppressed = []

    with pytest.raises(OutOfScopeError):
        engine.run()


def test_h2c_finding_id_is_stable(loopback_scope: Scope):
    """The finding id is deterministic for the same target and confirmation state."""
    with _H2CUpgradeMock() as srv:
        e1 = H2CEngine(srv.base_url, scope=loopback_scope, timeout=2.0)
        f1 = e1.run()[0]
        e2 = H2CEngine(srv.base_url, scope=loopback_scope, timeout=2.0)
        f2 = e2.run()[0]

    assert f1.id == f2.id


def test_h2c_techniques_tuple():
    """H2C_TECHNIQUES is a tuple containing exactly 'H2C'."""
    assert H2C_TECHNIQUES == ("H2C",)


def test_h2c_upgrade_request_bytes():
    """The upgrade probe contains required RFC 7540 §3.2 headers."""
    req = _upgrade_request("example.com", "/")
    assert b"Upgrade: h2c" in req
    assert b"HTTP2-Settings:" in req
    assert b"Connection: Upgrade, HTTP2-Settings" in req
    assert req.startswith(b"GET / HTTP/1.1\r\n")


def test_h2c_suppressed_is_always_empty(loopback_scope: Scope):
    """H2CEngine.suppressed is always empty (no pipelining discrimination needed)."""
    with _H2CRejectMock() as srv:
        engine = H2CEngine(srv.base_url, scope=loopback_scope, timeout=2.0)
        engine.run()

    assert engine.suppressed == []


# --------------------------------------------------------------------------- #
# CLI integration                                                              #
# --------------------------------------------------------------------------- #


def test_cli_h2c_technique_is_valid_choice(loopback_scope: Scope, tmp_path):
    """--technique H2C is accepted by the CLI and routes to H2CEngine."""
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n")

    with _H2CUpgradeMock() as srv:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "doppelganger.cli",
                srv.base_url,
                "--scope-file",
                str(scope_file),
                "--technique",
                "H2C",
                "--format",
                "json",
                "--timeout",
                "2.0",
            ],
            capture_output=True,
            text=True,
        )

    # Exit code 1 == findings were produced.
    assert proc.returncode == 1, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
    import json

    doc = json.loads(proc.stdout)
    assert doc["finding_count"] >= 1
    assert doc["findings"][0]["vector"] == "H2C"
    assert doc["findings"][0]["evidence"]["confirmation"] == "confirmed"


def test_cli_h2c_no_upgrade_exits_0(loopback_scope: Scope, tmp_path):
    """--technique H2C on a non-upgrading server exits 0 (no findings)."""
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n")

    with _H2CRejectMock() as srv:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "doppelganger.cli",
                srv.base_url,
                "--scope-file",
                str(scope_file),
                "--technique",
                "H2C",
                "--format",
                "json",
                "--timeout",
                "2.0",
            ],
            capture_output=True,
            text=True,
        )

    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
