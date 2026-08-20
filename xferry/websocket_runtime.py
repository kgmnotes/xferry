"""WebSocket admission, handshake, frame loop, and cleanup ownership."""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable

from .http import HTTPRequest
from .lifecycle import AdmissionLease
from .metrics import MetricsCollector
from .websocket import (
    WS_BINARY,
    WS_CLOSE,
    WS_PING,
    WS_PONG,
    WS_TEXT,
    WebSocketProtocolError,
    build_ws_close_frame,
    build_ws_frame,
    build_ws_handshake_response,
    parse_ws_frame,
)

logger = logging.getLogger("xferry")


class WebSocketRuntime:
    """Own active-session capacity and the RFC frame-processing lifecycle."""

    def __init__(
        self,
        *,
        max_connections: int,
        frame_idle_timeout: float,
        idle_timeout: float,
        metrics: MetricsCollector,
        is_running: Callable[[], bool],
        handle_message: Callable[[socket.socket, bytes], None],
        record_timeout: Callable[[str], None],
    ) -> None:
        self.max_connections = max_connections
        self.frame_idle_timeout = frame_idle_timeout
        self.idle_timeout = idle_timeout
        self._metrics = metrics
        self._is_running = is_running
        self._handle_message = handle_message
        self._record_timeout = record_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._legacy_leases: list[AdmissionLease] = []
        self._legacy_lock = threading.Lock()

    def upgrade(self, sock: socket.socket, request: HTTPRequest) -> bool:
        """Admit and run a WebSocket session; return false when capacity is full."""
        lease = self._acquire()
        if lease is None:
            return False
        try:
            self.handle_session(sock, request)
        finally:
            lease.release()
        return True

    def handle_session(self, sock: socket.socket, request: HTTPRequest) -> None:
        """Perform the handshake and frame loop for one already-admitted socket."""
        ws_key = request.headers.get("sec-websocket-key", "")
        try:
            sock.sendall(build_ws_handshake_response(ws_key))
        except Exception:
            return

        buffer = bytearray()
        incomplete_since: float | None = None
        current_timeout: float | None = None
        close_lock = threading.Lock()
        close_sent = False

        def send_close(code: int = 1000, reason: str = "") -> None:
            nonlocal close_sent
            with close_lock:
                if close_sent:
                    return
                close_sent = True
                try:
                    sock.sendall(build_ws_close_frame(code, reason))
                except Exception:
                    return

        def set_recv_timeout(timeout: float) -> None:
            nonlocal current_timeout
            if current_timeout != timeout:
                sock.settimeout(timeout)
                current_timeout = timeout

        try:
            set_recv_timeout(self.idle_timeout)
            while self._is_running():
                try:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                except TimeoutError:
                    if (
                        buffer
                        and incomplete_since is not None
                        and time.monotonic() - incomplete_since >= self.frame_idle_timeout
                    ):
                        logger.warning("WS incomplete frame timed out")
                        self._metrics.record_websocket_incomplete_frame_timeout()
                        self._record_timeout("websocket_incomplete_frame")
                        send_close(1002, "Incomplete frame timeout")
                        return
                    if buffer:
                        continue
                    try:
                        self._metrics.record_websocket_idle_ping()
                        sock.sendall(build_ws_frame(b"", opcode=WS_PING))
                    except Exception:
                        break
                    continue

                while True:
                    try:
                        frame = parse_ws_frame(buffer, require_mask=True)
                    except WebSocketProtocolError as exc:
                        self._metrics.record_websocket_protocol_error()
                        send_close(exc.close_code, exc.close_reason)
                        return
                    except ValueError:
                        self._metrics.record_websocket_message_too_big()
                        send_close(1009, "Message too big")
                        return
                    if frame is None:
                        if buffer and incomplete_since is None:
                            incomplete_since = time.monotonic()
                            set_recv_timeout(self.frame_idle_timeout)
                        break
                    opcode, payload, consumed = frame
                    del buffer[:consumed]
                    incomplete_since = time.monotonic() if buffer else None
                    set_recv_timeout(
                        self.frame_idle_timeout
                        if incomplete_since is not None
                        else self.idle_timeout
                    )

                    if opcode == WS_CLOSE:
                        send_close()
                        return
                    if opcode == WS_PING:
                        try:
                            sock.sendall(build_ws_frame(payload, opcode=WS_PONG))
                        except Exception:
                            return
                        continue
                    if opcode == WS_PONG:
                        continue
                    if opcode == WS_BINARY:
                        send_close(1003, "Binary frames are not supported")
                        return
                    if opcode == WS_TEXT:
                        self._handle_message(sock, payload)
        except Exception:
            self._metrics.record_websocket_error()
            logger.exception("WS connection failed")
            send_close(1011, "Internal error")
        finally:
            send_close()

    def set_handle_message(self, callback: Callable[[socket.socket, bytes], None]) -> None:
        """Refresh the facade callback used by compatibility delegates."""
        self._handle_message = callback

    def try_acquire_legacy_slot(self) -> bool:
        """Compatibility delegate for focused facade admission tests."""
        lease = self._acquire()
        if lease is None:
            return False
        with self._legacy_lock:
            self._legacy_leases.append(lease)
        return True

    def release_legacy_slot(self) -> None:
        """Release a compatibility admission lease once."""
        with self._legacy_lock:
            lease = self._legacy_leases.pop() if self._legacy_leases else None
        if lease is not None:
            lease.release()

    def _acquire(self) -> AdmissionLease | None:
        if not self._slots.acquire(blocking=False):
            self._metrics.record_websocket_rejected()
            logger.warning(
                "WS admission rejected: active budget exhausted (max=%d)",
                self.max_connections,
            )
            return None
        self._metrics.record_websocket_opened()
        return AdmissionLease(self._release)

    def _release(self) -> None:
        self._slots.release()
        self._metrics.record_websocket_closed()


__all__ = ["WebSocketRuntime"]
