"""Tests for WebSocket frame size limit (security hardening)."""

import struct

import pytest

from xferry.websocket import _MAX_FRAME_SIZE, parse_ws_frame


def _make_masked_header(opcode: int, payload_len: int) -> bytes:
    """Build the header bytes for a masked frame with the given length."""
    mask_key = b"\x01\x02\x03\x04"
    header = bytearray()
    header.append(0x80 | opcode)  # FIN=1

    if payload_len < 126:
        header.append(0x80 | payload_len)
    elif payload_len < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", payload_len))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", payload_len))

    header.extend(mask_key)
    return bytes(header)


class TestWebSocketFrameSizeLimit:
    """Verify that oversized WebSocket frames are rejected."""

    def test_max_frame_size_constant_is_10mb(self):
        assert _MAX_FRAME_SIZE == 10 * 1024 * 1024

    def test_frame_at_limit_is_accepted(self):
        """A frame exactly at _MAX_FRAME_SIZE should not raise."""
        # We only test the header parsing + length check; we don't
        # allocate a 10 MB payload; the function returns None because
        # the buffer is incomplete, but crucially it does NOT raise.
        header = _make_masked_header(0x01, _MAX_FRAME_SIZE)
        result = parse_ws_frame(header)
        assert result is None  # incomplete, but no ValueError

    def test_frame_over_limit_raises(self):
        """A frame exceeding _MAX_FRAME_SIZE should raise ValueError."""
        header = _make_masked_header(0x01, _MAX_FRAME_SIZE + 1)
        with pytest.raises(ValueError, match="too large"):
            parse_ws_frame(header)

    def test_huge_frame_raises(self):
        """A frame claiming 2^63 bytes should raise ValueError."""
        header = _make_masked_header(0x01, 2**63 - 1)
        with pytest.raises(ValueError, match="too large"):
            parse_ws_frame(header)

    def test_normal_frame_not_affected(self):
        """Normal small frames should parse without issues."""
        mask_key = b"\x01\x02\x03\x04"
        payload = b"hello"
        masked = bytes(p ^ mask_key[i % 4] for i, p in enumerate(payload))
        header = _make_masked_header(0x01, len(payload))
        data = header + masked
        result = parse_ws_frame(data)
        assert result is not None
        assert result[1] == payload
