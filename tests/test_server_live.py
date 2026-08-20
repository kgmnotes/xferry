"""Live end-to-end server coverage for auth, keep-alive, advanced upload, and WebSocket notes."""

from __future__ import annotations

import base64
import json
import re
import socket
import struct
import threading
import time
from pathlib import Path

from tests.server_factory import make_server
from xferry.http import HTTPResponse
from xferry.websocket import WS_CLOSE, WS_TEXT, parse_ws_frame


def _make_masked_frame(opcode: int, payload: bytes) -> bytes:
    """Build a masked client-to-server WebSocket frame."""
    mask_key = b"\x37\x38\x39\x30"
    masked = bytearray(len(payload))
    for i, value in enumerate(payload):
        masked[i] = value ^ mask_key[i % 4]

    header = bytearray()
    header.append(0x80 | opcode)
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))

    header.extend(mask_key)
    return bytes(header) + bytes(masked)


def _recv_http_response(sock: socket.socket) -> tuple[str, dict[str, str], bytes]:
    """Read a single HTTP response from a live server socket."""
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("Connection closed before response headers were received")
        buffer.extend(chunk)

    head, body = bytes(buffer).split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    status_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, value = line.split(":", 1)
        headers[key.lower()] = value.strip()

    content_length = int(headers.get("content-length", "0"))
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("Connection closed before response body was fully received")
        body += chunk

    return status_line, headers, body[:content_length]


def _recv_until(sock: socket.socket, marker: bytes) -> bytes:
    """Read from *sock* until *marker* is present."""
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError(f"Connection closed before marker {marker!r} was received")
        data.extend(chunk)
    return bytes(data)


def _recv_ws_json(sock: socket.socket) -> dict[str, object]:
    """Read one complete server-to-client WebSocket JSON message."""
    buffer = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("WebSocket closed before a message was received")
        buffer.extend(chunk)
        frame = parse_ws_frame(bytes(buffer))
        if frame is None:
            continue
        opcode, payload, _consumed = frame
        assert opcode == WS_TEXT
        result = json.loads(payload.decode("utf-8"))
        assert isinstance(result, dict)
        return result


def _create_live_advanced_session(
    live: _LiveServer,
    *,
    prefix: str = "/advanced",
    decoder: str = "auto",
    diagnostic_headers: bool = True,
) -> str:
    request_body = json.dumps(
        {
            "prefix": prefix,
            "decoder": decoder,
            "diagnostic_headers": diagnostic_headers,
        },
        separators=(",", ":"),
    ).encode("ascii")
    with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
        sock.settimeout(2.0)
        sock.sendall(
            (
                f"POST /_xferry/advanced-sessions HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{live.port}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(request_body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            + request_body
        )
        status, _headers, body = _recv_http_response(sock)
    assert status.startswith("HTTP/1.1 201")
    metadata = json.loads(body)["advanced_session"]
    token = metadata["token"]
    assert isinstance(token, str)
    return token


def _find_free_port() -> int:
    """Reserve an ephemeral local port and return it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _LiveServer:
    """Small helper for starting and stopping a live server in tests."""

    def __init__(self, root_dir: Path, **kwargs: object) -> None:
        self.server = make_server(
            host="127.0.0.1",
            port=_find_free_port(),
            root_dir=str(root_dir),
            quiet=True,
            **kwargs,
        )
        self.port = self.server.port
        self._thread = threading.Thread(target=self.server.start, daemon=True)

    def __enter__(self) -> _LiveServer:
        self._thread.start()
        for _ in range(100):
            time.sleep(0.05)
            if self.server.running:
                return self
        raise RuntimeError("Server did not start in time")

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.server.stop()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self._thread.join(timeout=3.0)


class _TimeoutAfterHeadersSocket:
    """Socket-like test double that times out on the first streamed body chunk."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []
        self.timeouts: list[float | None] = []
        self._timeout: float | None = None

    def gettimeout(self) -> float | None:
        return self._timeout

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout
        self.timeouts.append(timeout)

    def sendall(self, payload: bytes) -> None:
        if self.payloads:
            raise TimeoutError("simulated slow reader")
        self.payloads.append(payload)


class TestLiveRequestHandling:
    def test_info_and_fetch_use_canonical_contracts_over_live_socket(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(temp_dir) as live:
            uploaded = live.server.upload_dir / "live.txt"
            uploaded.write_text("live payload", encoding="utf-8")

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"INFO /uploads/live.txt HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, headers, body = _recv_http_response(sock)

            assert status.startswith("HTTP/1.1 200")
            assert headers["content-type"] == "application/json"
            info = json.loads(body)
            assert set(info) == {"entry"}
            assert info["entry"]["path"] == "/uploads/live.txt"
            assert info["entry"]["kind"] == "file"
            assert info["entry"]["inspection"] is None
            assert "status" not in info

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"FETCH /uploads/live.txt HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, headers, body = _recv_http_response(sock)

            assert status.startswith("HTTP/1.1 200")
            assert headers["content-disposition"] == (
                "attachment; filename=\"live.txt\"; filename*=UTF-8''live.txt"
            )
            assert body == b"live payload"
            assert "x-fetch-status" not in headers
            assert "x-file-name" not in headers
            assert "x-file-size" not in headers
            assert "x-file-modified" not in headers

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"INFO /uploads?inspect=1 HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, headers, body = _recv_http_response(sock)

            assert status.startswith("HTTP/1.1 400")
            assert headers["content-type"] == "application/json"
            assert json.loads(body)["error"]["code"] == "invalid_field"

    def test_keep_alive_handles_multiple_ping_requests_on_one_connection(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(temp_dir) as live:
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)

                sock.sendall(
                    (
                        f"PING / HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        f"Connection: keep-alive\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status1, headers1, body1 = _recv_http_response(sock)
                assert status1.startswith("HTTP/1.1 200")
                assert headers1["connection"] == "keep-alive"
                ping1 = json.loads(body1)
                assert ping1["health"] == "ready"
                assert ping1["access_scope"] == "uploads"
                assert "profile" not in ping1
                assert "advanced_upload" not in ping1
                assert "capabilities" not in ping1

                sock.sendall(
                    (
                        f"PING / HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        f"Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status2, headers2, body2 = _recv_http_response(sock)
                assert status2.startswith("HTTP/1.1 200")
                assert headers2["connection"] == "close"
                ping2 = json.loads(body2)
                assert ping2["health"] == "ready"
                assert ping2["access_scope"] == "uploads"
                assert "profile" not in ping2
                assert "advanced_upload" not in ping2
                assert "capabilities" not in ping2

    def test_request_admission_rejects_when_single_worker_is_occupied(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(temp_dir, max_workers=1) as live:
            first = socket.create_connection(("127.0.0.1", live.port), timeout=2.0)
            try:
                first.settimeout(2.0)
                for _ in range(100):
                    if live.server.get_metrics()["request_admission"]["active"] == 1:
                        break
                    time.sleep(0.02)
                assert live.server.get_metrics()["request_admission"]["active"] == 1

                with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as second:
                    second.settimeout(2.0)
                    second.sendall(
                        (
                            f"PING / HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{live.port}\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                        ).encode("ascii")
                    )
                    status, _headers, body = _recv_http_response(second)

                assert status.startswith("HTTP/1.1 503")
                assert json.loads(body) == {
                    "error": {
                        "code": "server_busy",
                        "details": {},
                        "field": None,
                        "message": "Server busy",
                    }
                }
                assert live.server.get_metrics()["request_admission"] == {
                    "active": 1,
                    "accepted": 1,
                    "rejected": 1,
                }
            finally:
                first.close()

    def test_body_memory_budget_rejects_second_inflight_body_before_body_read(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(
            temp_dir,
            max_workers=2,
            max_upload_size=16,
            body_memory_budget=10,
        ) as live:
            first = socket.create_connection(("127.0.0.1", live.port), timeout=2.0)
            try:
                first.settimeout(2.0)
                first.sendall(
                    (
                        f"POST /hold HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Content-Length: 8\r\n"
                        "\r\n"
                    ).encode("ascii")
                )

                for _ in range(100):
                    body_memory = live.server.get_metrics()["body_memory"]
                    if body_memory["current_bytes"] == 8:  # type: ignore[index]
                        break
                    time.sleep(0.02)
                assert live.server.get_metrics()["body_memory"]["current_bytes"] == 8

                with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as second:
                    second.settimeout(2.0)
                    second.sendall(
                        (
                            f"POST /blocked HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{live.port}\r\n"
                            "Content-Length: 8\r\n"
                            "\r\n"
                        ).encode("ascii")
                    )
                    status, _headers, body = _recv_http_response(second)

                assert status.startswith("HTTP/1.1 503")
                assert json.loads(body) == {
                    "error": {
                        "code": "server_busy",
                        "message": "Request body memory budget exceeded",
                        "field": None,
                        "details": {},
                    }
                }
                metrics = live.server.get_metrics()
                assert metrics["body_memory"]["rejected"] == 1  # type: ignore[index]
                assert metrics["receive"]["rejection_reasons"]["body_memory_budget_exceeded"] == 1
            finally:
                first.close()

            for _ in range(100):
                body_memory = live.server.get_metrics()["body_memory"]
                if body_memory["current_bytes"] == 0:  # type: ignore[index]
                    break
                time.sleep(0.02)
            assert live.server.get_metrics()["body_memory"]["current_bytes"] == 0

    def test_slow_body_idle_timeout_releases_worker_and_records_metrics(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(temp_dir, max_workers=1, body_idle_timeout=0.1) as live:
            first = socket.create_connection(("127.0.0.1", live.port), timeout=2.0)
            try:
                first.settimeout(2.0)
                first.sendall(
                    (
                        f"POST /slow HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Content-Length: 8\r\n"
                        "\r\n"
                        "x"
                    ).encode("ascii")
                )

                for _ in range(100):
                    metrics = live.server.get_metrics()
                    if metrics["receive"]["rejection_reasons"].get("body_idle_timeout") == 1:  # type: ignore[index,union-attr]
                        break
                    time.sleep(0.02)

                metrics = live.server.get_metrics()
                assert metrics["receive"]["rejection_reasons"]["body_idle_timeout"] == 1
                assert metrics["timeouts"]["body_idle_timeout"] == 1
            finally:
                first.close()

            for _ in range(100):
                if live.server.get_metrics()["request_admission"]["active"] == 0:  # type: ignore[index]
                    break
                time.sleep(0.02)
            assert live.server.get_metrics()["request_admission"]["active"] == 0  # type: ignore[index]

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as second:
                second.settimeout(2.0)
                second.sendall(
                    (
                        f"PING / HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(second)

            assert status.startswith("HTTP/1.1 200")
            assert json.loads(body)["health"] == "ready"

    def test_streamed_response_timeout_is_bounded_and_recorded(self, temp_dir: Path) -> None:
        payload = b"x" * (70 * 1024)
        upload_dir = temp_dir / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        upload_file = upload_dir / "payload.bin"
        upload_file.write_bytes(payload)

        server = make_server(
            root_dir=str(temp_dir),
            quiet=True,
            stream_send_idle_timeout=0.05,
            stream_send_timeout=0.05,
        )
        response = HTTPResponse(200)
        response.set_file(upload_file, "application/octet-stream")
        sock = _TimeoutAfterHeadersSocket()

        bytes_sent = server._send_response(response, sock, {"keep_alive": True})

        assert bytes_sent == len(sock.payloads[0])
        metrics = server.get_metrics()
        assert metrics["timeouts"]["response_stream_timeout"] == 1
        assert metrics["response"] == {
            "bytes": 0,
            "stream_aborts": 1,
            "stream_abort_reasons": {"timeout": 1},
        }

    def test_basic_auth_rejects_missing_header_and_accepts_valid_credentials(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(temp_dir, auth="admin:secret123") as live:
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        "NOTE /notes/key HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "X-Request-Id: live-note-auth\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 401")
                assert headers["www-authenticate"] == 'Basic realm="Restricted Area"'
                assert headers["x-request-id"] == "live-note-auth"
                assert json.loads(body) == {
                    "error": {
                        "code": "authentication_required",
                        "details": {},
                        "field": "Authorization",
                        "message": "Unauthorized",
                    }
                }

            credentials = base64.b64encode(b"admin:secret123").decode("ascii")
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"PING / HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        f"Authorization: Basic {credentials}\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 200")
                assert json.loads(body)["health"] == "ready"

    def test_get_streamed_text_file_ignores_gzip_without_buffering(self, temp_dir: Path) -> None:
        payload = ("streamed live payload\n" * 200).encode("utf-8")
        upload_dir = temp_dir / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        upload_file = upload_dir / "payload.txt"
        upload_file.write_bytes(payload)

        with _LiveServer(temp_dir) as live:
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"GET /payload.txt HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Accept-Encoding: gzip\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, headers, body = _recv_http_response(sock)

        assert status.startswith("HTTP/1.1 200")
        assert headers["content-type"].startswith("text/plain")
        assert headers["content-length"] == str(len(payload))
        assert "content-encoding" not in headers
        assert body == payload


class TestLiveFullMode:
    def test_full_mode_allows_core_mutating_and_advanced_methods(self, temp_dir: Path) -> None:
        with _LiveServer(temp_dir) as live:
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, _body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 200")

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"POST /full.txt HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Content-Length: 4\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        "full"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 201")
                assert set(json.loads(body)) == {"file", "upload"}
                assert (temp_dir / "uploads" / "full.txt").read_bytes() == b"full"

            token = _create_live_advanced_session(live, prefix="/mystery")
            payload = base64.b64encode(b"session upload").decode("ascii")
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"STEALTH /mystery HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        f"X-XFerry-Advanced-Session: {token}\r\n"
                        f"X-XFerry-Data: {payload}\r\n"
                        "X-XFerry-Encoding: base64\r\n"
                        "X-XFerry-Encryption: none\r\n"
                        "X-XFerry-Name: session.txt\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 201")
                assert json.loads(body)["upload"]["kind"] == "advanced"
                assert (temp_dir / "uploads" / "session.txt").read_bytes() == b"session upload"

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"DELETE /uploads/full.txt HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 200")
                assert json.loads(body) == {
                    "deleted_file": {"name": "full.txt", "path": "/uploads/full.txt"}
                }
                assert not (temp_dir / "uploads" / "full.txt").exists()

            (temp_dir / "uploads" / "keep.txt").write_text("keep", encoding="utf-8")
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"DELETE /uploads?clear=true HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, clear_body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 200")
                assert json.loads(clear_body)["cleared_uploads"]["path"] == "/uploads"
                assert status.startswith("HTTP/1.1 200")
                assert not (temp_dir / "uploads" / "keep.txt").exists()

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"NOTE /notes/key HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "X-Request-Id: live-note:123\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, headers, _body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 200")
                assert headers["x-request-id"] == "live-note:123"

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"GET /notes/ws HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                        "Sec-WebSocket-Version: 13\r\n"
                        f"Origin: http://127.0.0.1:{live.port}\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, _body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 101")
                sock.sendall(_make_masked_frame(WS_CLOSE, struct.pack("!H", 1000)))
                close_frame = parse_ws_frame(sock.recv(4096))
                assert close_frame is not None
                assert close_frame[0] == WS_CLOSE
                assert live.server.get_metrics()["websocket"]["rejected_admissions"] == 0


class TestLiveAdvancedUploadRouting:
    def test_default_full_mode_reports_methods_and_allows_advanced_upload(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(temp_dir) as live:
            assert not (temp_dir / ".opsec_config.json").exists()
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (f"PING / HTTP/1.1\r\nHost: 127.0.0.1:{live.port}\r\n\r\n").encode("ascii")
                )
                status, headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 200")
                assert headers["server"] == "XFerry/0.1.0"
                ping = json.loads(body)
                assert ping["health"] == "ready"
                assert ping["server"] == "XFerry/0.1.0"
                assert "version" not in ping
                assert "profile" not in ping
                assert "advanced_upload" not in ping
                assert "capabilities" not in ping
                assert "SMUGGLE" in ping["supported_methods"]
                assert "NOTE" in ping["supported_methods"]
                assert ping["method_groups"] == {
                    "request": ["GET", "HEAD", "OPTIONS", "INFO", "PING"],
                    "upload": ["POST", "PUT", "PATCH", "NONE"],
                    "files": ["DELETE", "FETCH", "SMUGGLE"],
                    "notepad": ["NOTE"],
                }

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (f"INFO / HTTP/1.1\r\nHost: 127.0.0.1:{live.port}\r\n\r\n").encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                info = json.loads(body)
                assert status.startswith("HTTP/1.1 200")
                assert info["entry"]["kind"] == "directory"
                assert info["entry"]["path"] == "/uploads"
                assert "contents" in info

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"POST /workspace.txt HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Content-Length: 9\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        "workspace"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 201")
                assert set(json.loads(body)) == {"file", "upload"}
                assert (temp_dir / "uploads" / "workspace.txt").read_bytes() == b"workspace"

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"DELETE /uploads/workspace.txt HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 200")
                assert json.loads(body) == {
                    "deleted_file": {"name": "workspace.txt", "path": "/uploads/workspace.txt"}
                }
                assert not (temp_dir / "uploads" / "workspace.txt").exists()

            token = _create_live_advanced_session(live, prefix="/advanced")
            payload = base64.b64encode(b"advanced live upload").decode("ascii")
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                request_body = json.dumps(
                    {
                        "data": payload,
                        "encoding": "base64",
                        "encryption": "none",
                        "name": "advanced.txt",
                    }
                ).encode("ascii")
                sock.sendall(
                    (
                        f"SYNCDATA /advanced HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        f"X-XFerry-Advanced-Session: {token}\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(request_body)}\r\n"
                        "\r\n"
                    ).encode("ascii")
                    + request_body
                )
                status, _headers, body = _recv_http_response(sock)
                assert status.startswith("HTTP/1.1 201")
                assert json.loads(body)["upload"]["kind"] == "advanced"
                assert (temp_dir / "uploads" / "advanced.txt").read_bytes() == (
                    b"advanced live upload"
                )

    def test_unknown_method_with_session_data_uses_advanced_upload(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(temp_dir) as live:
            token = _create_live_advanced_session(live, prefix="/mystery")
            payload = base64.b64encode(b"session upload").decode("ascii")

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                sock.sendall(
                    (
                        f"STEALTH /mystery HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        f"X-XFerry-Advanced-Session: {token}\r\n"
                        f"X-XFerry-Data: {payload}\r\n"
                        "X-XFerry-Encoding: base64\r\n"
                        "X-XFerry-Encryption: none\r\n"
                        "X-XFerry-Name: session.txt\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                status, _headers, body = _recv_http_response(sock)
                result = json.loads(body)
                assert status.startswith("HTTP/1.1 201")
                assert result["upload"]["kind"] == "advanced"
                assert result["upload"]["carrier"] == "headers"
                assert (temp_dir / "uploads" / "session.txt").read_bytes() == b"session upload"

    def test_gzip_advanced_upload_expansion_limit_returns_413_without_file(
        self,
        temp_dir: Path,
    ) -> None:
        import gzip

        with _LiveServer(temp_dir) as live:
            decoded_limit = 64
            live.server.advanced_upload_decoded_size_limit = decoded_limit
            token = _create_live_advanced_session(live, prefix="/advanced")
            raw = b"A" * 10_000
            payload = base64.b64encode(gzip.compress(raw)).decode("ascii")
            assert len(payload.encode("utf-8")) <= live.server._advanced_upload_encoded_size_limit(
                "body"
            )

            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                request_body = json.dumps(
                    {
                        "data": payload,
                        "name": "live-gzip-bomb.txt",
                        "encoding": "gzip-base64",
                        "encryption": "none",
                    }
                ).encode("ascii")
                sock.sendall(
                    (
                        f"SYNCDATA /advanced HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{live.port}\r\n"
                        f"X-XFerry-Advanced-Session: {token}\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(request_body)}\r\n"
                        "\r\n"
                    ).encode("ascii")
                    + request_body
                )
                status, _headers, body = _recv_http_response(sock)

            assert status.startswith("HTTP/1.1 413")
            assert json.loads(body)["error"]["code"] == "payload_too_large"
            assert not (temp_dir / "uploads" / "live-gzip-bomb.txt").exists()


class TestLiveWebSocketNotes:
    @staticmethod
    def _send_ws_handshake(sock: socket.socket, port: int) -> None:
        sock.sendall(
            (
                f"GET /notes/ws HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Origin: http://127.0.0.1:{port}\r\n"
                "\r\n"
            ).encode("ascii")
        )

    def test_notes_websocket_admission_budget_rejects_excess_connection(
        self,
        temp_dir: Path,
    ) -> None:
        with _LiveServer(
            temp_dir,
            max_workers=2,
            max_websocket_connections=1,
            websocket_frame_idle_timeout=5.0,
        ) as live:
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as first:
                first.settimeout(2.0)
                self._send_ws_handshake(first, live.port)
                handshake = _recv_until(first, b"\r\n\r\n")
                assert b"HTTP/1.1 101 Switching Protocols" in handshake

                with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as second:
                    second.settimeout(2.0)
                    self._send_ws_handshake(second, live.port)
                    status, headers, body = _recv_http_response(second)
                    assert status.startswith("HTTP/1.1 503")
                    assert re.fullmatch(r"[0-9a-f]{8}", headers["x-request-id"])
                    assert json.loads(body) == {
                        "error": {
                            "code": "server_busy",
                            "message": "WebSocket connection limit reached",
                            "field": None,
                            "details": {},
                        }
                    }

                metrics = live.server.get_metrics()
                assert metrics["websocket"]["active"] == 1
                assert metrics["websocket"]["rejected_admissions"] == 1

                with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as http_sock:
                    http_sock.settimeout(2.0)
                    http_sock.sendall(
                        (
                            f"PING / HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{live.port}\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                        ).encode("ascii")
                    )
                    ping_status, _ping_headers, ping_body = _recv_http_response(http_sock)
                    assert ping_status.startswith("HTTP/1.1 200")
                    assert json.loads(ping_body)["health"] == "ready"

                first.sendall(_make_masked_frame(WS_CLOSE, struct.pack("!H", 1000)))
                close_frame = parse_ws_frame(first.recv(4096))
                assert close_frame is not None
                assert close_frame[0] == WS_CLOSE

    def test_notes_websocket_supports_save_list_and_load_round_trip(self, temp_dir: Path) -> None:
        with _LiveServer(temp_dir) as live:
            with socket.create_connection(("127.0.0.1", live.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                self._send_ws_handshake(sock, live.port)
                handshake = _recv_until(sock, b"\r\n\r\n")
                assert b"HTTP/1.1 101 Switching Protocols" in handshake

                # NOTE blobs use the canonical nonce(12)+ciphertext+tag(16)
                # wire minimum; the server stores this opaque payload as-is.
                note_blob = bytes(range(28))
                note_data = base64.b64encode(note_blob).decode("ascii")
                save_payload = json.dumps(
                    {
                        "action": "save",
                        "request_id": "live-save",
                        "input": {
                            "title": "Live WS Note",
                            "data": note_data,
                        },
                    }
                ).encode("utf-8")
                sock.sendall(_make_masked_frame(WS_TEXT, save_payload))
                saved = _recv_ws_json(sock)
                assert saved["action"] == "save"
                assert saved["request_id"] == "live-save"
                assert saved["result"]["created"] is True
                note_id = str(saved["result"]["note"]["id"])

                sock.sendall(
                    _make_masked_frame(
                        WS_TEXT,
                        b'{"action":"list","request_id":"live-list","input":{}}',
                    )
                )
                listed = _recv_ws_json(sock)
                assert listed["action"] == "list"
                assert listed["request_id"] == "live-list"
                notes = listed["result"]["notes"]
                assert isinstance(notes, list)
                assert any(isinstance(note, dict) and note.get("id") == note_id for note in notes)

                load_payload = json.dumps(
                    {
                        "action": "load",
                        "request_id": "live-load",
                        "input": {"id": note_id},
                    }
                ).encode("utf-8")
                sock.sendall(_make_masked_frame(WS_TEXT, load_payload))
                loaded = _recv_ws_json(sock)
                assert loaded["action"] == "load"
                assert loaded["request_id"] == "live-load"
                assert loaded["result"]["note"]["id"] == note_id
                assert loaded["result"]["note"]["title"] == "Live WS Note"
                assert loaded["result"]["data"] == note_data
                assert (temp_dir / "notes" / f"{note_id}.enc").read_bytes() == note_blob
                assert not (temp_dir / "uploads" / "notes").exists()

                sock.sendall(_make_masked_frame(WS_CLOSE, struct.pack("!H", 1000)))
                close_frame = parse_ws_frame(sock.recv(4096))
                assert close_frame is not None
                assert close_frame[0] == WS_CLOSE
