"""Live server tests for WebSocket upgrade validation."""

from __future__ import annotations

import json
import re
import socket
import threading
import time

import pytest

from tests.conftest import find_free_port
from tests.server_factory import make_server


def _start_server(
    port: int,
    disable_ecdh: bool = False,
    cors_origin: str | None = None,
):
    server = make_server(
        host="127.0.0.1",
        port=port,
        root_dir="/tmp",
        quiet=True,
        cors_origin=cors_origin,
    )
    if disable_ecdh:
        server._ecdh_manager = None
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    for _ in range(50):
        time.sleep(0.05)
        if server.running:
            break
    return server


def _send_raw(port: int, raw: bytes, timeout: float = 2.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(("127.0.0.1", port))
        sock.sendall(raw)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except TimeoutError:
                break
        return b"".join(chunks)
    finally:
        sock.close()


class TestWebSocketUpgradeSecurity:
    @pytest.mark.parametrize(
        "target",
        [
            "/notes/ws?transport=websocket",
            "/notes/ws/child",
        ],
    )
    def test_non_exact_notes_paths_remain_ordinary_http(self, target: str) -> None:
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Origin: http://127.0.0.1:{port}\r\n"
                "X-Request-Id: invalid value\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 404 Not Found" in response
            assert b"HTTP/1.1 101 Switching Protocols" not in response
            assert b"X-Request-Id: invalid value" not in response
        finally:
            server.stop()

    def test_cross_origin_upgrade_rejected_by_default(self) -> None:
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                f"GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Origin: https://evil.example\r\n"
                "X-Request-Id: ws-origin-live\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 403 Forbidden" in response
            assert b"X-Request-Id: ws-origin-live" in response
        finally:
            server.stop()

    def test_invalid_websocket_version_rejected(self) -> None:
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                f"GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 12\r\n"
                f"Origin: http://127.0.0.1:{port}\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 400 Bad Request" in response
            request_id_match = re.search(rb"\r\nX-Request-Id: ([^\r\n]+)", response)
            assert request_id_match is not None
            assert re.fullmatch(rb"[0-9a-f]{8}", request_id_match.group(1))
        finally:
            server.stop()

    def test_invalid_request_id_is_rejected_before_websocket_upgrade(self) -> None:
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                "GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Origin: http://127.0.0.1:{port}\r\n"
                "X-Request-Id: invalid value\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 400 Bad Request" in response
            assert b"HTTP/1.1 101 Switching Protocols" not in response
            assert json.loads(response.split(b"\r\n\r\n", 1)[1]) == {
                "error": {
                    "code": "invalid_field",
                    "message": "Invalid field",
                    "field": "X-Request-Id",
                    "details": {},
                }
            }
            assert b"X-Request-Id: invalid value" not in response
            request_id_match = re.search(rb"\r\nX-Request-Id: ([^\r\n]+)", response)
            assert request_id_match is not None
            assert re.fullmatch(rb"[0-9a-f]{8}", request_id_match.group(1))
        finally:
            server.stop()

    def test_missing_host_upgrade_rejected(self) -> None:
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                "GET /notes/ws HTTP/1.1\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 400 Bad Request" in response
        finally:
            server.stop()

    def test_same_origin_upgrade_accepted(self) -> None:
        port = find_free_port()
        server = _start_server(port)
        try:
            raw = (
                f"GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Origin: http://127.0.0.1:{port}\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 101 Switching Protocols" in response
        finally:
            server.stop()

    def test_exact_configured_origin_upgrade_accepted(self) -> None:
        port = find_free_port()
        server = _start_server(port, cors_origin="https://app.example")
        try:
            raw = (
                f"GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Origin: https://app.example\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 101 Switching Protocols" in response
        finally:
            server.stop()

    def test_wildcard_origin_upgrade_rejected(self) -> None:
        port = find_free_port()
        server = _start_server(port, cors_origin="*")
        try:
            raw = (
                f"GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Origin: https://evil.example\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 403 Forbidden" in response
        finally:
            server.stop()

    def test_upgrade_rejected_when_notepad_crypto_unavailable(self) -> None:
        port = find_free_port()
        server = _start_server(port, disable_ecdh=True)
        try:
            raw = (
                f"GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Origin: http://127.0.0.1:{port}\r\n"
                "\r\n"
            ).encode("ascii")
            response = _send_raw(port, raw)
            assert b"HTTP/1.1 501 Not Implemented" in response
        finally:
            server.stop()
