"""Regression tests for lifecycle and WebSocket runtime ownership boundaries."""

from __future__ import annotations

import importlib.util
import struct
from collections.abc import Callable
from typing import Any

import pytest

from tests.conftest import make_request
from xferry.metrics import MetricsCollector
from xferry.websocket import WS_CLOSE, WS_TEXT, parse_ws_frame


class _TLSStub:
    def __init__(self, *, setup_error: BaseException | None = None) -> None:
        self.enabled = False
        self.ssl_context = None
        self.domain: str | None = None
        self.public_ip: str | None = None
        self.setup_error = setup_error
        self.setup_calls = 0
        self.cleanup_calls = 0

    def setup(self) -> None:
        self.setup_calls += 1
        if self.setup_error is not None:
            raise self.setup_error

    def cleanup(self) -> None:
        self.cleanup_calls += 1


class _ListenerStub:
    def __init__(
        self,
        *,
        bind_error: BaseException | None = None,
        listen_error: BaseException | None = None,
        accepted: list[tuple[object, tuple[str, int]]] | None = None,
    ) -> None:
        self.bind_error = bind_error
        self.listen_error = listen_error
        self.accepted = list(accepted or [])
        self.close_calls = 0
        self.timeouts: list[float] = []

    def setsockopt(self, _level: int, _name: int, _value: int) -> None:
        return None

    def bind(self, _address: tuple[str, int]) -> None:
        if self.bind_error is not None:
            raise self.bind_error

    def listen(self, _backlog: int) -> None:
        if self.listen_error is not None:
            raise self.listen_error

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def accept(self) -> tuple[object, tuple[str, int]]:
        if self.accepted:
            return self.accepted.pop(0)
        raise KeyboardInterrupt

    def close(self) -> None:
        self.close_calls += 1


class _ExecutorStub:
    def __init__(self, future: object | None = None) -> None:
        self.future = future
        self.shutdown_calls: list[tuple[bool, bool]] = []

    def submit(self, *_args: object) -> object:
        if self.future is None:
            raise AssertionError("unexpected worker submission")
        return self.future

    def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
        self.shutdown_calls.append((wait, cancel_futures))


class _ClientSocketStub:
    def __init__(
        self,
        recv_items: list[bytes | BaseException] | None = None,
        *,
        fail_handshake: bool = False,
        fail_close: bool = False,
    ) -> None:
        self.recv_items = list(recv_items or [])
        self.fail_handshake = fail_handshake
        self.fail_close = fail_close
        self.sent: list[bytes] = []
        self.close_calls = 0
        self.timeouts: list[float] = []

    def sendall(self, data: bytes) -> None:
        if self.fail_handshake and not self.sent:
            raise OSError("handshake write failed")
        if self.fail_close and data.startswith(b"\x88"):
            self.sent.append(data)
            raise OSError("close write failed")
        self.sent.append(data)

    def recv(self, _size: int) -> bytes:
        if not self.recv_items:
            return b""
        item = self.recv_items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)

    def close(self) -> None:
        self.close_calls += 1


def _make_masked_text(payload: bytes) -> bytes:
    mask_key = b"1234"
    masked = bytes(value ^ mask_key[index % 4] for index, value in enumerate(payload))
    return bytes((0x80 | WS_TEXT, 0x80 | len(payload))) + mask_key + masked


def _lifecycle_factory(
    *,
    tls: _TLSStub,
    listener: _ListenerStub,
    executor: _ExecutorStub | None = None,
    metrics: MetricsCollector | None = None,
) -> Any:
    from xferry.lifecycle import ServerLifecycle

    return ServerLifecycle(
        host="127.0.0.1",
        port=8080,
        max_workers=1,
        tls_manager=tls,
        metrics=metrics or MetricsCollector(),
        handle_client=lambda _sock, _address: None,
        reject_overloaded=lambda sock: sock.close(),
        on_started=lambda: None,
        on_shutdown=lambda: None,
        socket_factory=lambda: listener,
        executor_factory=(lambda _workers: executor or _ExecutorStub()),
    )


def test_runtime_components_are_real_importable_boundaries() -> None:
    """Removing either extracted component must break the boundary contract."""
    assert importlib.util.find_spec("xferry.lifecycle") is not None
    assert importlib.util.find_spec("xferry.websocket_runtime") is not None


@pytest.mark.parametrize("failure_point", ["tls", "bind", "listen"])
def test_lifecycle_startup_failures_clean_tls_and_listener_once(failure_point: str) -> None:
    """A failed startup must not leak TLS artifacts or a partially opened listener."""
    tls = _TLSStub(setup_error=RuntimeError("TLS setup failed") if failure_point == "tls" else None)
    listener = _ListenerStub(
        bind_error=OSError("bind failed") if failure_point == "bind" else None,
        listen_error=OSError("listen failed") if failure_point == "listen" else None,
    )
    lifecycle = _lifecycle_factory(tls=tls, listener=listener)

    with pytest.raises((RuntimeError, OSError), match=f"(?i){failure_point}"):
        lifecycle.start()

    lifecycle.stop()
    lifecycle.cleanup()
    assert tls.cleanup_calls == 1
    assert listener.close_calls == (0 if failure_point == "tls" else 1)


def test_lifecycle_stop_and_cleanup_are_idempotent() -> None:
    """Repeated shutdown calls must close each owned resource at most once."""
    tls = _TLSStub()
    listener = _ListenerStub()
    executor = _ExecutorStub()
    lifecycle = _lifecycle_factory(tls=tls, listener=listener, executor=executor)

    lifecycle.start()
    lifecycle.stop()
    lifecycle.stop()
    lifecycle.cleanup()
    lifecycle.cleanup()

    assert listener.close_calls == 1
    assert executor.shutdown_calls == [(True, True)]
    assert tls.cleanup_calls == 1


def test_cancelled_future_callback_twice_releases_admission_once() -> None:
    """Duplicate future callbacks must not over-release the bounded worker budget."""

    class _CancelledFuture:
        def add_done_callback(self, callback: Callable[[object], None]) -> None:
            callback(self)
            callback(self)

        def cancelled(self) -> bool:
            return True

    metrics = MetricsCollector()
    client = _ClientSocketStub()
    listener = _ListenerStub(accepted=[(client, ("127.0.0.1", 43210))])
    executor = _ExecutorStub(_CancelledFuture())
    lifecycle = _lifecycle_factory(
        tls=_TLSStub(),
        listener=listener,
        executor=executor,
        metrics=metrics,
    )

    lifecycle.start()

    assert metrics.snapshot()["request_admission"] == {
        "active": 0,
        "accepted": 1,
        "rejected": 0,
    }
    assert client.close_calls == 1


def _websocket_runtime(
    *,
    metrics: MetricsCollector,
    handle_message: Callable[[object, bytes], None],
) -> Any:
    from xferry.websocket_runtime import WebSocketRuntime

    return WebSocketRuntime(
        max_connections=1,
        frame_idle_timeout=0.5,
        idle_timeout=60.0,
        metrics=metrics,
        is_running=lambda: True,
        handle_message=handle_message,
        record_timeout=metrics.record_timeout,
    )


def test_websocket_failed_handshake_releases_admission_once() -> None:
    """Handshake write failures must release the WebSocket capacity lease."""
    metrics = MetricsCollector()
    runtime = _websocket_runtime(metrics=metrics, handle_message=lambda _sock, _data: None)
    sock = _ClientSocketStub(fail_handshake=True)
    request = make_request(
        "GET",
        "/notes/ws",
        headers={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
    )

    assert runtime.upgrade(sock, request) is True
    assert metrics.snapshot()["websocket"]["active"] == 0
    assert metrics.snapshot()["websocket"]["closed"] == 1
    assert sock.sent == []


@pytest.mark.parametrize("failure_kind", ["handler", "frame"])
def test_websocket_failures_release_once_and_send_one_close_frame(failure_kind: str) -> None:
    """Handler and frame failures must emit and account for cleanup exactly once."""
    metrics = MetricsCollector()

    def handle_message(_sock: object, _payload: bytes) -> None:
        if failure_kind == "handler":
            raise RuntimeError("handler failed")

    runtime = _websocket_runtime(metrics=metrics, handle_message=handle_message)
    frame = _make_masked_text(b"{}") if failure_kind == "handler" else b"\x81\x02{}"
    sock = _ClientSocketStub([frame])
    request = make_request(
        "GET",
        "/notes/ws",
        headers={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
    )

    assert runtime.upgrade(sock, request) is True

    close_frames = []
    for payload in sock.sent[1:]:
        parsed = parse_ws_frame(payload)
        if parsed is not None and parsed[0] == WS_CLOSE:
            close_frames.append(parsed)
    assert len(close_frames) == 1
    expected_code = 1011 if failure_kind == "handler" else 1002
    assert struct.unpack("!H", close_frames[0][1][:2])[0] == expected_code
    assert metrics.snapshot()["websocket"]["active"] == 0
    assert metrics.snapshot()["websocket"]["closed"] == 1


def test_websocket_close_write_failure_is_not_retried() -> None:
    """A failing close send is still a close-once attempt during final cleanup."""
    metrics = MetricsCollector()
    runtime = _websocket_runtime(metrics=metrics, handle_message=lambda _sock, _data: None)
    sock = _ClientSocketStub([b""], fail_close=True)
    request = make_request(
        "GET",
        "/notes/ws",
        headers={"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="},
    )

    assert runtime.upgrade(sock, request) is True
    assert sum(payload.startswith(b"\x88") for payload in sock.sent) == 1
    assert metrics.snapshot()["websocket"]["active"] == 0
