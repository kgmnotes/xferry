"""Real HTTP/TLS regression coverage for connection-owned request read-ahead."""

from __future__ import annotations

import base64
import json
import socket
import ssl
from pathlib import Path
from typing import BinaryIO

import pytest

from tests.test_server_live import _LiveServer, _make_masked_frame
from xferry.websocket import WS_CLOSE, WS_TEXT, parse_ws_frame

AUTH = base64.b64encode(b"reader:river-harbor-27").decode("ascii")


def _connect(live: _LiveServer, tls: bool) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", live.port), timeout=3)
    if not tls:
        return sock
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname="127.0.0.1")


def _request(
    live: _LiveServer,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    authorized: bool = True,
    connection: str = "keep-alive",
    extra: str = "",
) -> bytes:
    auth = f"Authorization: Basic {AUTH}\r\n" if authorized else ""
    return (
        f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{live.port}\r\n"
        f"{auth}Connection: {connection}\r\nContent-Length: {len(body)}\r\n{extra}\r\n"
    ).encode("ascii") + body


def _response(reader: BinaryIO) -> tuple[int, bytes]:
    """Keep read-ahead in one buffered reader, including coalesced responses."""
    line = reader.readline()
    assert line.startswith(b"HTTP/1.1 "), line
    status = int(line.split()[1])
    headers = {}
    while (line := reader.readline()) != b"\r\n":
        assert line, "connection closed inside response headers"
        name, value = line.split(b":", 1)
        headers[name.lower()] = value.strip()
    length = int(headers.get(b"content-length", b"0"))
    body = reader.read(length)
    assert len(body) == length
    return status, body


@pytest.mark.parametrize("tls", [False, True])
def test_pipelined_uploads_keep_exact_bodies_and_release_capacity(
    tmp_path: Path, tls: bool
) -> None:
    with _LiveServer(
        tmp_path, tls=tls, auth="reader:river-harbor-27", body_memory_budget=7
    ) as live:
        with _connect(live, tls) as sock, sock.makefile("rb") as reader:
            sock.sendall(
                _request(live, "POST", "/first.txt", body=b"hello")
                + _request(live, "POST", "/second.txt", body=b"world!!")
                + _request(live, "PING", "/", connection="close")
            )
            assert _response(reader)[0] == 201
            assert _response(reader)[0] == 201
            status, body = _response(reader)
            assert status == 200
            assert json.loads(body)["health"] == "ready"
            assert reader.read() == b""
        assert (live.server.upload_dir / "first.txt").read_bytes() == b"hello"
        assert (live.server.upload_dir / "second.txt").read_bytes() == b"world!!"
        assert live.server._body_memory_budget.snapshot()["current_bytes"] == 0
        assert live.server._body_memory_budget.snapshot()["peak_bytes"] == 7
        assert live.server._transfer_capacity.snapshot()["active"] == 0


@pytest.mark.parametrize("tls", [False, True])
def test_pipelined_second_request_authentication_cannot_be_inherited(
    tmp_path: Path, tls: bool
) -> None:
    with _LiveServer(tmp_path, tls=tls, auth="reader:river-harbor-27") as live:
        with _connect(live, tls) as sock, sock.makefile("rb") as reader:
            sock.sendall(
                _request(live, "PING", "/")
                + _request(live, "POST", "/unauthorized.txt", body=b"no", authorized=False)
                + _request(live, "POST", "/after-error.txt", body=b"no", connection="close")
            )
            assert _response(reader)[0] == 200
            assert _response(reader)[0] == 401
            assert reader.read() == b""
        assert not (live.server.upload_dir / "unauthorized.txt").exists()
        assert not (live.server.upload_dir / "after-error.txt").exists()
        assert live.server._body_memory_budget.snapshot()["peak_bytes"] == 0


@pytest.mark.parametrize("stop", ["close", "maximum", "invalid-length", "oversized"])
def test_pipeline_stops_at_close_limit_or_bad_framing(tmp_path: Path, stop: str) -> None:
    with _LiveServer(tmp_path, auth="reader:river-harbor-27", max_upload_size=8) as live:
        live.server.KEEP_ALIVE_MAX = 1 if stop == "maximum" else 100
        first = _request(live, "PING", "/", connection="close" if stop == "close" else "keep-alive")
        broken = b""
        if stop in {"invalid-length", "oversized"}:
            length = "+1" if stop == "invalid-length" else "9"
            broken = _request(live, "POST", "/invalid.txt").replace(
                b"Content-Length: 0", f"Content-Length: {length}".encode()
            )
        with _connect(live, False) as sock, sock.makefile("rb") as reader:
            sock.sendall(
                first + broken + _request(live, "POST", "/never.txt", body=b"x", connection="close")
            )
            assert _response(reader)[0] == 200
            if stop == "oversized":
                assert _response(reader)[0] == 413
            assert reader.read() == b""
        assert not (live.server.upload_dir / "invalid.txt").exists()
        assert not (live.server.upload_dir / "never.txt").exists()
        assert live.server._body_memory_budget.snapshot()["current_bytes"] == 0


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_upgrade_preserves_first_frame_already_received_with_headers(
    tmp_path: Path, tls: bool, partial: bool
) -> None:
    with _LiveServer(tmp_path, tls=tls, auth="reader:river-harbor-27") as live:
        handshake = _request(
            live,
            "GET",
            "/notes/ws",
            connection="Upgrade",
            extra="Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        )
        frame = _make_masked_frame(
            WS_TEXT, b'{"action":"list","request_id":"buffered-first","input":{}}'
        )
        close = _make_masked_frame(WS_CLOSE, b"")
        with _connect(live, tls) as sock, sock.makefile("rb") as reader:
            sock.sendall(handshake + (frame[:3] if partial else frame + close))
            assert _response(reader)[0] == 101
            if partial:
                sock.sendall(frame[3:] + close)
            frames = reader.read()
        message = parse_ws_frame(frames)
        assert message is not None
        assert message[0] == WS_TEXT
        assert json.loads(message[1])["request_id"] == "buffered-first"
        closed = parse_ws_frame(frames[message[2] :])
        assert closed is not None and closed[0] == WS_CLOSE
        assert live.server.get_metrics()["websocket"]["active"] == 0


def test_rejected_upgrade_never_processes_buffered_frames(tmp_path: Path) -> None:
    with _LiveServer(tmp_path, auth="reader:river-harbor-27") as live:
        handshake = _request(
            live,
            "GET",
            "/notes/ws",
            authorized=False,
            connection="Upgrade",
            extra="Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        )
        with _connect(live, False) as sock, sock.makefile("rb") as reader:
            sock.sendall(
                handshake
                + _make_masked_frame(
                    WS_TEXT, b'{"action":"list","request_id":"must-not-run","input":{}}'
                )
            )
            assert _response(reader)[0] == 401
            assert reader.read() == b""
        assert live.server.get_metrics()["websocket"]["active"] == 0
        assert live.server.get_metrics()["websocket"]["closed"] == 0
