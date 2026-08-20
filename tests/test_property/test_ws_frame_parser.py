"""Property-based tests: WebSocket frame parser robustness."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from xferry.websocket import (
    WS_BINARY,
    WS_TEXT,
    WebSocketProtocolError,
    build_ws_frame,
    parse_ws_frame,
)


@given(data=st.binary(min_size=0, max_size=512))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_parse_never_crashes_on_random_bytes(data: bytes) -> None:
    """parse_ws_frame must return None, a valid tuple, or raise a documented parser error."""
    try:
        result = parse_ws_frame(data)
    except (ValueError, WebSocketProtocolError):
        return
    assert result is None or (isinstance(result, tuple) and len(result) == 3)


@given(
    payload=st.binary(min_size=0, max_size=4096),
    opcode=st.sampled_from([WS_TEXT, WS_BINARY]),
)
@settings(max_examples=100, deadline=None)
def test_build_then_parse_roundtrip(payload: bytes, opcode: int) -> None:
    """build_ws_frame + parse_ws_frame is an identity for a single frame."""
    frame = build_ws_frame(payload, opcode=opcode)
    parsed = parse_ws_frame(frame)

    assert parsed is not None
    op, data, consumed = parsed
    assert op == opcode
    assert data == payload
    assert consumed == len(frame)


@given(truncate_ratio=st.floats(min_value=0.0, max_value=0.99))
@settings(max_examples=50, deadline=None)
def test_short_frame_returns_none(truncate_ratio: float) -> None:
    """Under-length frames must return None (more data needed), not crash."""
    full = build_ws_frame(b"hello world", opcode=WS_TEXT)
    cutoff = int(len(full) * truncate_ratio)
    short = full[:cutoff]

    # short is strictly shorter than full, so parser should ask for more data.
    assert parse_ws_frame(short) is None
