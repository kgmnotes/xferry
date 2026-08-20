"""
Pure-Python RFC 6455 WebSocket helpers (zero external deps).

Provides the minimum functionality needed for the Secure Notepad
real-time transport: upgrade handshake, frame parsing/building,
and close frames.
"""

import base64
import binascii
import hashlib
import struct

from .http import HTTPRequest

_MAX_FRAME_SIZE = 10 * 1024 * 1024  # 10 MB

# RFC 6455 magic GUID
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Opcodes
WS_CONTINUATION = 0x00
WS_TEXT = 0x01
WS_BINARY = 0x02
WS_CLOSE = 0x08
WS_PING = 0x09
WS_PONG = 0x0A
_CONTROL_OPCODES = {WS_CLOSE, WS_PING, WS_PONG}
_SUPPORTED_OPCODES = {
    WS_CONTINUATION,
    WS_TEXT,
    WS_BINARY,
    WS_CLOSE,
    WS_PING,
    WS_PONG,
}
_INVALID_CLOSE_CODES = {1004, 1005, 1006, 1015}


class WebSocketProtocolError(Exception):
    """Raised when a frame violates the active WebSocket protocol role."""

    def __init__(
        self,
        message: str,
        *,
        close_code: int = 1002,
        close_reason: str = "Protocol error",
    ) -> None:
        super().__init__(message)
        self.close_code = close_code
        self.close_reason = close_reason


def check_websocket_upgrade(request: HTTPRequest) -> bool:
    """Return True if the request is a valid WebSocket upgrade."""
    if request.method != "GET":
        return False

    upgrade = request.headers.get("upgrade", "").lower()
    connection = request.headers.get("connection", "").lower()
    ws_key = request.headers.get("sec-websocket-key", "")
    ws_version = request.headers.get("sec-websocket-version", "")
    host = request.headers.get("host", "")

    if upgrade != "websocket":
        return False
    if "upgrade" not in {part.strip() for part in connection.split(",")}:
        return False
    if not host:
        return False
    if ws_version != "13":
        return False

    try:
        key_bytes = base64.b64decode(ws_key, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(key_bytes) == 16


def build_ws_accept_key(ws_key: str) -> str:
    """Compute ``Sec-WebSocket-Accept`` per RFC 6455 Section 4.2.2."""
    combined = ws_key.strip() + _WS_GUID
    sha1 = hashlib.sha1(combined.encode("ascii"), usedforsecurity=False).digest()
    return base64.b64encode(sha1).decode("ascii")


def build_ws_handshake_response(ws_key: str) -> bytes:
    """Build the HTTP 101 Switching Protocols response."""
    accept = build_ws_accept_key(ws_key)
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def _is_valid_close_code(code: int) -> bool:
    if code in _INVALID_CLOSE_CODES:
        return False
    if 1000 <= code <= 1014:
        return True
    return 3000 <= code <= 4999


def _validate_close_payload(payload: bytes) -> None:
    if len(payload) == 1:
        raise WebSocketProtocolError("Close frame payload cannot be one byte")
    if len(payload) < 2:
        return

    code = struct.unpack("!H", payload[:2])[0]
    if not _is_valid_close_code(code):
        raise WebSocketProtocolError(f"Invalid close status code: {code}")
    try:
        payload[2:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebSocketProtocolError("Close frame reason must be valid UTF-8") from exc


def parse_ws_frame(
    data: bytes | bytearray,
    *,
    require_mask: bool = False,
) -> tuple[int, bytes, int] | None:
    """
    Parse a single WebSocket frame from *data*.

    Returns ``(opcode, payload, total_bytes_consumed)`` or ``None``
    if *data* does not yet contain a complete frame.

    Handles client-to-server masking. Set ``require_mask`` for inbound
    client traffic; server-to-client helper parsing remains unmasked by
    default for tests and internal callers.
    """
    dlen = len(data)
    if dlen < 2:
        return None

    # Byte 0: FIN + RSV bits + opcode
    first_byte = data[0]
    fin = bool(first_byte & 0x80)
    rsv = first_byte & 0x70
    opcode = first_byte & 0x0F
    if rsv:
        raise WebSocketProtocolError("WebSocket reserved bits must be zero")
    if opcode not in _SUPPORTED_OPCODES:
        raise WebSocketProtocolError(f"Unsupported opcode: 0x{opcode:x}")
    if opcode == WS_CONTINUATION:
        raise WebSocketProtocolError("Continuation frames are not supported")
    if opcode in _CONTROL_OPCODES and not fin:
        raise WebSocketProtocolError("Control frames must not be fragmented")
    if opcode in (WS_TEXT, WS_BINARY) and not fin:
        raise WebSocketProtocolError("Fragmented WebSocket messages are not supported")

    # Byte 1: MASK flag + payload length
    masked = bool(data[1] & 0x80)
    if require_mask and not masked:
        raise WebSocketProtocolError("client WebSocket frames must be masked")

    payload_len = data[1] & 0x7F
    offset = 2

    if payload_len == 126:
        if dlen < 4:
            return None
        payload_len = struct.unpack("!H", data[2:4])[0]
        offset = 4
    elif payload_len == 127:
        if dlen < 10:
            return None
        payload_len = struct.unpack("!Q", data[2:10])[0]
        offset = 10

    if opcode in _CONTROL_OPCODES and payload_len > 125:
        raise WebSocketProtocolError("Control frame payload must be 125 bytes or less")

    if payload_len > _MAX_FRAME_SIZE:
        raise ValueError(f"WebSocket frame too large: {payload_len} bytes")

    mask_key = b""
    if masked:
        if dlen < offset + 4:
            return None
        mask_key = bytes(data[offset : offset + 4])
        offset += 4

    if dlen < offset + payload_len:
        return None

    raw_payload = data[offset : offset + payload_len]

    payload: bytes
    if masked:
        payload_bytes = bytearray(payload_len)
        for i in range(payload_len):
            payload_bytes[i] = raw_payload[i] ^ mask_key[i % 4]
        payload = bytes(payload_bytes)
    else:
        payload = bytes(raw_payload)

    if opcode == WS_CLOSE:
        _validate_close_payload(payload)

    return opcode, payload, offset + payload_len


def build_ws_frame(payload: bytes, opcode: int = WS_TEXT, fin: bool = True) -> bytes:
    """
    Build a server-to-client WebSocket frame (unmasked).
    """
    header = bytearray()
    first_byte = (0x80 if fin else 0x00) | (opcode & 0x0F)
    header.append(first_byte)

    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(127)
        header.extend(struct.pack("!Q", length))

    return bytes(header) + payload


def build_ws_close_frame(code: int = 1000, reason: str = "") -> bytes:
    """Build a WebSocket close frame with status code and optional reason."""
    payload = struct.pack("!H", code)
    if reason:
        payload += reason.encode("utf-8")
    return build_ws_frame(payload, opcode=WS_CLOSE)
