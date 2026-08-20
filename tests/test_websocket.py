"""Tests for the pure-Python WebSocket RFC 6455 implementation."""

import struct

import pytest

from tests.conftest import make_request
from xferry.websocket import (
    WS_BINARY,
    WS_CLOSE,
    WS_CONTINUATION,
    WS_PING,
    WS_PONG,
    WS_TEXT,
    WebSocketProtocolError,
    build_ws_accept_key,
    build_ws_close_frame,
    build_ws_frame,
    build_ws_handshake_response,
    check_websocket_upgrade,
    parse_ws_frame,
)

# ── Upgrade detection ─────────────────────────────────────────────


class TestWsUpgradeDetection:
    def test_valid_upgrade_request(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is True

    def test_missing_upgrade_header(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_missing_connection_header(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_missing_ws_key(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_missing_host_rejected(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_case_insensitive_headers(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "WebSocket",
                "Connection": "upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is True

    def test_connection_with_multiple_values(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "keep-alive, Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is True

    def test_post_method_rejected(self):
        req = make_request(
            "POST",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_missing_ws_version_rejected(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_wrong_ws_version_rejected(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "12",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_invalid_ws_key_base64_rejected(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "not-base64!!!",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is False

    def test_wrong_ws_key_length_rejected(self):
        req = make_request(
            "GET",
            "/notes/ws",
            headers={
                "Host": "127.0.0.1:8080",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "eA==",
                "Sec-WebSocket-Version": "13",
            },
        )
        assert check_websocket_upgrade(req) is False


# ── Accept key (RFC 6455 Section 4.2.2) ──────────────────────────


class TestWsAcceptKey:
    def test_rfc6455_test_vector(self):
        """Test vector from RFC 6455 Section 4.2.2."""
        ws_key = "dGhlIHNhbXBsZSBub25jZQ=="
        expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        assert build_ws_accept_key(ws_key) == expected


# ── Handshake response ────────────────────────────────────────────


class TestWsHandshake:
    def test_handshake_contains_101(self):
        resp = build_ws_handshake_response("dGhlIHNhbXBsZSBub25jZQ==")
        assert b"HTTP/1.1 101 Switching Protocols" in resp

    def test_handshake_contains_upgrade_headers(self):
        resp = build_ws_handshake_response("dGhlIHNhbXBsZSBub25jZQ==")
        assert b"Upgrade: websocket" in resp
        assert b"Connection: Upgrade" in resp

    def test_handshake_contains_accept_key(self):
        resp = build_ws_handshake_response("dGhlIHNhbXBsZSBub25jZQ==")
        assert b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in resp


# ── Frame parsing ─────────────────────────────────────────────────


class TestWsFrameParsing:
    @staticmethod
    def _make_masked_frame(
        opcode: int,
        payload: bytes,
        *,
        fin: bool = True,
        rsv: int = 0,
    ) -> bytes:
        """Build a client-to-server masked frame for testing."""
        mask_key = b"\x37\x38\x39\x30"
        masked = bytearray(len(payload))
        for i in range(len(payload)):
            masked[i] = payload[i] ^ mask_key[i % 4]

        header = bytearray()
        header.append((0x80 if fin else 0x00) | rsv | opcode)

        length = len(payload)
        if length < 126:
            header.append(0x80 | length)  # MASK=1
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))

        header.extend(mask_key)
        return bytes(header) + bytes(masked)

    def test_text_frame(self):
        data = self._make_masked_frame(WS_TEXT, b"hello")
        result = parse_ws_frame(data)
        assert result is not None
        opcode, payload, consumed = result
        assert opcode == WS_TEXT
        assert payload == b"hello"
        assert consumed == len(data)

    def test_binary_frame(self):
        data = self._make_masked_frame(WS_BINARY, b"\x00\x01\x02")
        result = parse_ws_frame(data)
        assert result is not None
        assert result[0] == WS_BINARY
        assert result[1] == b"\x00\x01\x02"

    def test_masked_payload_decoded_correctly(self):
        payload = b"The quick brown fox"
        data = self._make_masked_frame(WS_TEXT, payload)
        result = parse_ws_frame(data)
        assert result is not None
        assert result[1] == payload

    def test_bytearray_frame_input_returns_bytes_payload(self):
        data = bytearray(self._make_masked_frame(WS_TEXT, b"mutable input"))
        result = parse_ws_frame(data)
        assert result is not None
        assert result[1] == b"mutable input"
        assert isinstance(result[1], bytes)

    def test_126_byte_payload_length(self):
        payload = b"x" * 200
        data = self._make_masked_frame(WS_TEXT, payload)
        result = parse_ws_frame(data)
        assert result is not None
        assert result[1] == payload
        assert len(result[1]) == 200

    def test_127_byte_payload_length(self):
        payload = b"y" * 70000
        data = self._make_masked_frame(WS_TEXT, payload)
        result = parse_ws_frame(data)
        assert result is not None
        assert result[1] == payload
        assert len(result[1]) == 70000

    def test_incomplete_data_returns_none(self):
        assert parse_ws_frame(b"") is None
        assert parse_ws_frame(b"\x81") is None

    def test_incomplete_126_header(self):
        # 126-length indicator but missing the 2-byte length
        assert parse_ws_frame(b"\x81\xfe\x00") is None

    def test_incomplete_payload(self):
        # Header says 10 bytes, but only 5 provided
        data = self._make_masked_frame(WS_TEXT, b"hello world")
        assert parse_ws_frame(data[:8]) is None

    def test_close_frame(self):
        data = self._make_masked_frame(WS_CLOSE, struct.pack("!H", 1000))
        result = parse_ws_frame(data)
        assert result is not None
        assert result[0] == WS_CLOSE

    def test_ping_frame(self):
        data = self._make_masked_frame(WS_PING, b"ping-data")
        result = parse_ws_frame(data)
        assert result is not None
        assert result[0] == WS_PING
        assert result[1] == b"ping-data"

    def test_unmasked_server_frame(self):
        """Server frames (unmasked) should also parse correctly."""
        frame = build_ws_frame(b"response", opcode=WS_TEXT)
        result = parse_ws_frame(frame)
        assert result is not None
        assert result[0] == WS_TEXT
        assert result[1] == b"response"

    def test_require_mask_accepts_masked_frame(self):
        data = self._make_masked_frame(WS_TEXT, b"client request")
        result = parse_ws_frame(data, require_mask=True)
        assert result is not None
        assert result[0] == WS_TEXT
        assert result[1] == b"client request"

    def test_require_mask_rejects_unmasked_frame(self):
        frame = build_ws_frame(b"client request", opcode=WS_TEXT)
        with pytest.raises(WebSocketProtocolError, match="must be masked"):
            parse_ws_frame(frame, require_mask=True)

    def test_reserved_bits_rejected(self):
        frame = self._make_masked_frame(WS_TEXT, b"{}", rsv=0x40)
        with pytest.raises(WebSocketProtocolError, match="reserved bits"):
            parse_ws_frame(frame)

    def test_fragmented_data_frame_rejected(self):
        frame = self._make_masked_frame(WS_TEXT, b'{"type":"list"}', fin=False)
        with pytest.raises(WebSocketProtocolError, match="Fragmented"):
            parse_ws_frame(frame)

    def test_unexpected_continuation_rejected(self):
        frame = self._make_masked_frame(WS_CONTINUATION, b"fragment")
        with pytest.raises(WebSocketProtocolError, match="Continuation"):
            parse_ws_frame(frame)

    def test_unknown_opcode_rejected(self):
        frame = self._make_masked_frame(0x03, b"payload")
        with pytest.raises(WebSocketProtocolError, match="Unsupported opcode"):
            parse_ws_frame(frame)

    def test_fragmented_control_frame_rejected(self):
        frame = self._make_masked_frame(WS_PING, b"ping", fin=False)
        with pytest.raises(WebSocketProtocolError, match="Control frames"):
            parse_ws_frame(frame)

    def test_oversized_control_frame_rejected(self):
        frame = self._make_masked_frame(WS_PING, b"x" * 126)
        with pytest.raises(WebSocketProtocolError, match="Control frame payload"):
            parse_ws_frame(frame)

    def test_close_frame_one_byte_payload_rejected(self):
        frame = self._make_masked_frame(WS_CLOSE, b"\x03")
        with pytest.raises(WebSocketProtocolError, match="Close frame payload"):
            parse_ws_frame(frame)

    def test_close_frame_invalid_status_code_rejected(self):
        frame = self._make_masked_frame(WS_CLOSE, struct.pack("!H", 1005))
        with pytest.raises(WebSocketProtocolError, match="Invalid close status"):
            parse_ws_frame(frame)

    def test_close_frame_invalid_utf8_reason_rejected(self):
        frame = self._make_masked_frame(WS_CLOSE, struct.pack("!H", 1000) + b"\xff")
        with pytest.raises(WebSocketProtocolError, match="valid UTF-8") as exc_info:
            parse_ws_frame(frame)
        assert exc_info.value.close_code == 1002
        assert exc_info.value.close_reason == "Protocol error"

    def test_multiple_frames_consumed_correctly(self):
        frame1 = self._make_masked_frame(WS_TEXT, b"first")
        frame2 = self._make_masked_frame(WS_TEXT, b"second")
        data = frame1 + frame2

        result1 = parse_ws_frame(data)
        assert result1 is not None
        assert result1[1] == b"first"

        remaining = data[result1[2] :]
        result2 = parse_ws_frame(remaining)
        assert result2 is not None
        assert result2[1] == b"second"


# ── Frame building ────────────────────────────────────────────────


class TestWsFrameBuilding:
    def test_small_text_frame(self):
        frame = build_ws_frame(b"hello", opcode=WS_TEXT)
        # FIN=1, opcode=1: 0x81
        assert frame[0] == 0x81
        # No mask, length=5
        assert frame[1] == 5
        assert frame[2:] == b"hello"

    def test_medium_frame_126(self):
        payload = b"x" * 200
        frame = build_ws_frame(payload, opcode=WS_TEXT)
        assert frame[0] == 0x81
        assert frame[1] == 126
        length = struct.unpack("!H", frame[2:4])[0]
        assert length == 200
        assert frame[4:] == payload

    def test_large_frame_127(self):
        payload = b"z" * 70000
        frame = build_ws_frame(payload, opcode=WS_BINARY)
        assert frame[0] == 0x82  # FIN + binary
        assert frame[1] == 127
        length = struct.unpack("!Q", frame[2:10])[0]
        assert length == 70000
        assert frame[10:] == payload

    def test_fin_flag(self):
        frame_fin = build_ws_frame(b"x", fin=True)
        assert frame_fin[0] & 0x80 == 0x80

        frame_nofin = build_ws_frame(b"x", fin=False)
        assert frame_nofin[0] & 0x80 == 0x00

    def test_pong_frame(self):
        frame = build_ws_frame(b"ping-data", opcode=WS_PONG)
        assert frame[0] == (0x80 | WS_PONG)


# ── Close frame ───────────────────────────────────────────────────


class TestWsCloseFrame:
    def test_close_with_code(self):
        frame = build_ws_close_frame(1000)
        result = parse_ws_frame(frame)
        assert result is not None
        opcode, payload, _ = result
        assert opcode == WS_CLOSE
        code = struct.unpack("!H", payload[:2])[0]
        assert code == 1000

    def test_close_with_reason(self):
        frame = build_ws_close_frame(1001, "going away")
        result = parse_ws_frame(frame)
        assert result is not None
        _, payload, _ = result
        code = struct.unpack("!H", payload[:2])[0]
        assert code == 1001
        assert payload[2:] == b"going away"

    def test_close_with_custom_code(self):
        frame = build_ws_close_frame(4000)
        result = parse_ws_frame(frame)
        assert result is not None
        _, payload, _ = result
        code = struct.unpack("!H", payload[:2])[0]
        assert code == 4000
