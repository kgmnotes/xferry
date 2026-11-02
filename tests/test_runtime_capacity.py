"""Real TLS/PBKDF2 regressions for independent runtime capacity ownership."""

from __future__ import annotations

import base64
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tests.server_factory import make_server
from tests.test_server_live import (
    _LiveServer,
    _make_masked_frame,
    _recv_http_response,
    _recv_until,
    _recv_ws_json,
)
from xferry.http import HTTPResponse
from xferry.lifecycle import CapacityGate
from xferry.security.auth import AuthAdmissionController, AuthAdmissionDenied, AuthAttemptLease
from xferry.websocket import WS_TEXT

_CREDENTIALS = base64.b64encode(b"reader:river-harbor-27").decode("ascii")


def _connect(live: _LiveServer, *, slow_reader: bool = False) -> ssl.SSLSocket:
    raw = socket.socket()
    if slow_reader:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
    raw.settimeout(10)
    raw.connect(("127.0.0.1", live.port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(raw, server_hostname="127.0.0.1")


def _request(
    live: _LiveServer,
    method: str,
    path: str,
    *,
    extra: str = "",
    authenticated: bool = True,
    close: bool = True,
) -> bytes:
    auth = f"Authorization: Basic {_CREDENTIALS}\r\n" if authenticated else ""
    connection = "close" if close else "keep-alive"
    return (
        f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{live.port}\r\n"
        f"{auth}Connection: {connection}\r\n{extra}\r\n"
    ).encode("ascii")


def _wait_until(predicate, *, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("runtime state did not settle")
        time.sleep(0.01)


def test_tls_browser_requests_survive_four_slow_downloads_idle_and_websocket(
    tmp_path: Path,
) -> None:
    """The original VPS failure must stay fixed with only one short-operation slot."""
    sockets: list[ssl.SSLSocket] = []
    with _LiveServer(
        tmp_path,
        tls=True,
        auth="reader:river-harbor-27",
        max_workers=1,
        stream_send_idle_timeout=30,
    ) as live:
        with (live.server.upload_dir / "slow.bin").open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        try:
            for _ in range(4):
                download = _connect(live, slow_reader=True)
                sockets.append(download)
                download.sendall(_request(live, "GET", "/uploads/slow.bin"))
                assert _recv_until(download, b"\r\n\r\n").startswith(b"HTTP/1.1 200")
            idle = _connect(live)
            sockets.append(idle)
            idle.sendall(_request(live, "PING", "/", close=False))
            assert _recv_http_response(idle)[0].startswith("HTTP/1.1 200")
            websocket = _connect(live)
            sockets.append(websocket)
            websocket.sendall(
                _request(
                    live,
                    "GET",
                    "/notes/ws",
                    close=False,
                    extra="Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                ).replace(b"Connection: keep-alive", b"Connection: Upgrade")
            )
            assert _recv_until(websocket, b"\r\n\r\n").startswith(b"HTTP/1.1 101")
            assert live.server._transfer_capacity.snapshot()["active"] == 4
            assert live.server._dispatch_capacity.snapshot()["active"] == 0

            routes = [
                ("GET", "/"),
                ("GET", "/static/ui/features.css"),
                ("GET", "/static/ui/core.js"),
                ("PING", "/"),
                ("INFO", "/"),
            ]

            def fetch(route: tuple[str, str]) -> str:
                with _connect(live) as client:
                    client.sendall(_request(live, *route))
                    return _recv_http_response(client)[0]

            with ThreadPoolExecutor(max_workers=10) as clients:
                statuses = list(clients.map(fetch, routes * 2))
            assert all(status.startswith("HTTP/1.1 200") for status in statuses)
            assert live.server._transfer_capacity.snapshot()["active"] == 4
            websocket.sendall(
                _make_masked_frame(
                    WS_TEXT, b'{"action":"list","request_id":"under-load","input":{}}'
                )
            )
            assert _recv_ws_json(websocket)["request_id"] == "under-load"
            controller = live.server._auth_controller
            assert controller is not None
            assert controller.max_active == 2
            assert controller.max_pending == 16
            assert controller.snapshot()["active"] == 0
            started = time.monotonic()
            live.server.stop()
            live._thread.join(2)
            assert not live._thread.is_alive()
            assert time.monotonic() - started < 2
            assert live.server._lifecycle.connection_snapshot()["active"] == 0
            assert live.server._transfer_capacity.snapshot()["active"] == 0
            assert live.server.get_metrics()["websocket"]["active"] == 0
        finally:
            for client in sockets:
                client.close()


def test_tls_upload_admission_precedes_body_allocation_and_stop_wakes_reads(tmp_path: Path) -> None:
    with _LiveServer(
        tmp_path,
        tls=True,
        auth="reader:river-harbor-27",
        max_transfers=1,
        admission_wait_timeout=0.05,
        body_memory_budget=64,
    ) as live:
        with _connect(live) as unauthorized:
            unauthorized.sendall(
                _request(
                    live, "POST", "/upload", authenticated=False, extra="Content-Length: 32\r\n"
                )
            )
            assert _recv_http_response(unauthorized)[0].startswith("HTTP/1.1 401")
            assert live.server._body_memory_budget.snapshot()["peak_bytes"] == 0
        with _connect(live) as first, _connect(live) as partial_headers:
            first.sendall(_request(live, "POST", "/upload", extra="Content-Length: 32\r\n"))
            partial_headers.sendall(b"GET / HTTP/1.1\r\nHost:")
            _wait_until(lambda: live.server._body_memory_budget.snapshot()["current_bytes"] == 32)
            with _connect(live) as second:
                second.sendall(_request(live, "POST", "/upload", extra="Content-Length: 32\r\n"))
                assert _recv_http_response(second)[0].startswith("HTTP/1.1 503")
            assert live.server._body_memory_budget.snapshot()["peak_bytes"] == 32
            assert live.server._transfer_capacity.snapshot()["active"] == 1
            live.server.stop()
            live._thread.join(2)
            assert not live._thread.is_alive()
            assert live.server._body_memory_budget.snapshot()["current_bytes"] == 0
            assert live.server._transfer_capacity.snapshot()["active"] == 0


def test_tls_handshake_permit_wait_uses_accept_deadline_and_shutdown(tmp_path: Path) -> None:
    with _LiveServer(tmp_path, tls=True, max_tls_handshakes=1, tls_handshake_timeout=0.2) as live:
        with socket.create_connection(("127.0.0.1", live.port)) as first:
            _wait_until(lambda: live.server._tls_capacity.snapshot()["active"] == 1)
            with socket.create_connection(("127.0.0.1", live.port)) as second:
                _wait_until(lambda: live.server._tls_capacity.snapshot()["waiting"] == 1)
                started = time.monotonic()
                first.settimeout(1)
                second.settimeout(1)
                assert first.recv(1) == b""
                assert second.recv(1) == b""
                assert time.monotonic() - started < 0.5
            _wait_until(lambda: live.server._tls_capacity.snapshot()["active"] == 0)
            assert live.server._tls_capacity.snapshot()["peak"] == 1


def test_capacity_and_auth_shutdown_cancel_waiters_and_release_once() -> None:
    gate = CapacityGate(1)
    lease = gate.acquire()
    assert lease is not None
    result = []
    waiter = threading.Thread(target=lambda: result.append(gate.acquire(30)))
    waiter.start()
    _wait_until(lambda: gate.snapshot()["waiting"] == 1)
    gate.close()
    waiter.join(1)
    assert result == [None]
    assert lease.release() is True
    assert lease.release() is False
    assert gate.snapshot()["active"] == 0
    controller = AuthAdmissionController(max_active=1, wait_timeout=30)
    active = controller.acquire("127.0.0.1")
    assert isinstance(active, AuthAttemptLease)
    auth_results = []
    auth_waiter = threading.Thread(
        target=lambda: auth_results.append(controller.acquire("127.0.0.2"))
    )
    auth_waiter.start()
    _wait_until(lambda: controller.snapshot()["queued"] == 1)
    controller.close()
    auth_waiter.join(1)
    assert isinstance(auth_results[0], AuthAdmissionDenied)
    active.finish("succeeded")
    assert controller.snapshot() == {"active": 0, "queued": 0, "peers": 0}


def test_http_and_websocket_application_permits_are_released_before_socket_writes(
    tmp_path: Path, monkeypatch
) -> None:
    server = make_server(root_dir=tmp_path, max_workers=1, quiet=True)

    class SocketProbe:
        def __init__(self) -> None:
            self.writes = 0

        def sendall(self, payload: bytes) -> None:
            assert server._dispatch_capacity.snapshot()["active"] == 0
            self.writes += 1

        def settimeout(self, timeout) -> None:
            pass

    socket_probe = SocketProbe()

    def handler(request):
        assert server._dispatch_capacity.snapshot()["active"] == 1
        response = HTTPResponse(200)
        response.set_body(b"computed")
        return response

    monkeypatch.setattr(server, "_dispatch_handler", handler)
    server._process_request(
        b"PING / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        socket_probe,
        ("127.0.0.1", 1234),
        1,
    )
    assert socket_probe.writes == 1

    def ws_handler(reply, payload):
        assert server._dispatch_capacity.snapshot()["active"] == 1
        reply.sendall(b"computed frame")

    monkeypatch.setattr(server, "_handle_ws_message", ws_handler)
    server._handle_bounded_ws_message(socket_probe, b"message")
    assert socket_probe.writes == 2
