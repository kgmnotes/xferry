"""Listener, worker-pool, admission, and TLS lifecycle ownership."""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol

from .metrics import MetricsCollector

logger = logging.getLogger("xferry")


class TLSLifecycle(Protocol):
    """TLS state needed by the listener lifecycle without importing its implementation."""

    enabled: bool
    ssl_context: Any
    domain: str | None
    public_ip: str | None

    def setup(self) -> None: ...

    def cleanup(self) -> None: ...


class AdmissionLease:
    """Release one acquired capacity slot at most once across worker/callback races."""

    def __init__(self, release: Callable[[], None]) -> None:
        self._release = release
        self._lock = threading.Lock()
        self._released = False

    def release(self) -> bool:
        """Release capacity once and report whether this call performed the release."""
        with self._lock:
            if self._released:
                return False
            self._released = True
        self._release()
        return True

    def __enter__(self) -> AdmissionLease:
        return self

    def __exit__(self, *args: object) -> None:
        self.release()


class CapacityGate:
    """A bounded, cancellable capacity pool without a work-item queue."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._condition = threading.Condition()
        self._active = 0
        self._peak = 0
        self._waiting = 0
        self._rejected = 0
        self._closed = False

    def acquire(self, timeout: float = 0.0) -> AdmissionLease | None:
        deadline = time.monotonic() + timeout
        with self._condition:
            self._waiting += 1
            try:
                while self._active >= self.limit and not self._closed:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._condition.wait(remaining)
                if self._closed or self._active >= self.limit:
                    self._rejected += 1
                    return None
                self._active += 1
                self._peak = max(self._peak, self._active)
                return AdmissionLease(self._release)
            finally:
                self._waiting -= 1

    def _release(self) -> None:
        with self._condition:
            self._active -= 1
            self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    def snapshot(self) -> dict[str, int]:
        with self._condition:
            return {
                "limit": self.limit,
                "active": self._active,
                "waiting": self._waiting,
                "peak": self._peak,
                "rejected": self._rejected,
            }


class ServerLifecycle:
    """Own server startup, listener admission, workers, and idempotent cleanup."""

    ACCEPT_TIMEOUT = 1.0
    REQUEST_ADMISSION_WAIT_TIMEOUT = 0.05

    def __init__(
        self,
        *,
        host: str,
        port: int,
        max_connections: int,
        tls_manager: TLSLifecycle,
        metrics: MetricsCollector,
        handle_client: Callable[[Any, tuple[str, int]], None],
        reject_overloaded: Callable[[Any], None],
        on_started: Callable[[], None],
        on_shutdown: Callable[[], None],
        on_stopping: Callable[[], None] | None = None,
        on_interrupted: Callable[[], None] | None = None,
        setup_tls: Callable[[], None] | None = None,
        cleanup_tls: Callable[[], None] | None = None,
        socket_factory: Callable[[], Any] | None = None,
        executor_factory: Callable[[int], Any] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.tls_manager = tls_manager
        self._metrics = metrics
        self._handle_client_callback = handle_client
        self._reject_overloaded = reject_overloaded
        self._on_started = on_started
        self._on_shutdown = on_shutdown
        self._on_stopping = on_stopping or (lambda: None)
        self._on_interrupted = on_interrupted or (lambda: None)
        self._setup_tls = setup_tls or tls_manager.setup
        self._cleanup_tls = cleanup_tls or tls_manager.cleanup
        self._socket_factory = socket_factory or (
            lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        )
        self._executor_factory = executor_factory or (
            lambda workers: ThreadPoolExecutor(max_workers=workers)
        )
        self._connections = CapacityGate(self.max_connections)
        self._sockets_lock = threading.Lock()
        self._sockets: dict[int, Any] = {}
        self._accepted_at: dict[int, float] = {}
        self._listener: Any | None = None
        self._executor: Any | None = None
        self._running = False
        self._cleanup_lock = threading.Lock()
        self._cleaned = False

    @property
    def listener(self) -> Any | None:
        return self._listener

    @property
    def running(self) -> bool:
        return self._running

    @running.setter
    def running(self, value: bool) -> None:
        self._running = bool(value)

    def start(self) -> None:
        """Run the blocking listener loop and always clean owned resources."""
        try:
            self._setup_tls()
            listener = self._socket_factory()
            self._listener = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(128)
            self._running = True
            start_renewal = getattr(self.tls_manager, "start_renewal", None)
            if callable(start_renewal):
                start_renewal()
            self._metrics.mark_started()
            self._on_started()
            self._executor = self._executor_factory(self.max_connections)
            self._accept_loop(listener, self._executor)
        except KeyboardInterrupt:
            self._on_interrupted()
        finally:
            self.cleanup()

    def stop(self) -> None:
        """Request loop termination; cleanup remains safe when called repeatedly."""
        self._running = False
        self._connections.close()
        self._on_stopping()
        self._close_sockets()
        with self._cleanup_lock:
            listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        stop_renewal = getattr(self.tls_manager, "stop_renewal", None)
        if callable(stop_renewal):
            stop_renewal()

    def cleanup(self) -> None:
        """Close every owned runtime resource at most once."""
        with self._cleanup_lock:
            if self._cleaned:
                return
            self._cleaned = True
            self._running = False
            executor, self._executor = self._executor, None
            listener, self._listener = self._listener, None

        self._connections.close()
        self._on_stopping()
        if listener is not None:
            listener.close()
        self._close_sockets()

        stop_renewal = getattr(self.tls_manager, "stop_renewal", None)
        if callable(stop_renewal):
            stop_renewal()
        try:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
        finally:
            try:
                self._cleanup_tls()
            finally:
                self._on_shutdown()

    def acquire_connection(
        self,
        *,
        wait_timeout: float = 0.0,
    ) -> AdmissionLease | None:
        """Acquire one connection slot before submitting a connection thread."""
        lease = self._connections.acquire(wait_timeout)
        if lease is None:
            self._metrics.record_request_admission_rejected()
            logger.warning(
                "Connection admission rejected: connection capacity exhausted (max=%d)",
                self.max_connections,
            )
            return None
        self._metrics.record_request_admission_accepted()

        def release() -> None:
            lease.release()
            self._metrics.record_request_admission_released()

        return AdmissionLease(release)

    def accepted_at(self, sock: Any) -> float:
        with self._sockets_lock:
            return self._accepted_at.get(id(sock), time.monotonic())

    def replace_socket(self, original: Any, wrapped: Any) -> None:
        """Keep shutdown ownership after TLS detaches the original descriptor."""
        with self._sockets_lock:
            if id(original) in self._sockets:
                self._sockets[id(original)] = wrapped
            if not self._running:
                wrapped.close()

    def _close_sockets(self) -> None:
        with self._sockets_lock:
            sockets = tuple(self._sockets.values())
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except (AttributeError, OSError):
                pass
            try:
                sock.close()
            except OSError:
                pass

    def connection_snapshot(self) -> dict[str, int]:
        return self._connections.snapshot()

    def _accept_loop(self, listener: Any, executor: Any) -> None:
        def submit_admitted(
            client_socket: Any,
            client_address: tuple[str, int],
            lease: AdmissionLease,
        ) -> object:
            def run_admitted(sock: Any, address: tuple[str, int]) -> None:
                self._handle_admitted_client(sock, address, lease)

            return executor.submit(run_admitted, client_socket, client_address)

        while self._running:
            try:
                listener.settimeout(self.ACCEPT_TIMEOUT)
                client_socket, client_address = listener.accept()
                accepted_at = time.monotonic()
                lease = self.acquire_connection(wait_timeout=self.REQUEST_ADMISSION_WAIT_TIMEOUT)
                if lease is None:
                    self._reject_overloaded(client_socket)
                    continue
                with self._sockets_lock:
                    self._sockets[id(client_socket)] = client_socket
                    self._accepted_at[id(client_socket)] = accepted_at
                try:
                    future = submit_admitted(client_socket, client_address, lease)
                    add_done_callback = getattr(future, "add_done_callback", None)
                    if callable(add_done_callback):
                        add_done_callback(
                            lambda fut, sock=client_socket, addr=client_address, owned=lease: (
                                self._finalize_worker_future(fut, sock, addr, owned)
                            )
                        )
                except Exception as exc:
                    self._untrack_socket(client_socket)
                    lease.release()
                    client_socket.close()
                    self._metrics.record_worker_exception("worker_submit", exc)
                    logger.exception("Failed to submit accepted client to worker pool")
            except TimeoutError:
                continue
            except OSError:
                if self._running:
                    raise
                break

    def _handle_admitted_client(
        self,
        client_socket: Any,
        client_address: tuple[str, int],
        lease: AdmissionLease,
        *,
        handle_client: Callable[[Any, tuple[str, int]], None] | None = None,
    ) -> None:
        self._metrics.record_connection_opened()
        try:
            (handle_client or self._handle_client_callback)(client_socket, client_address)
        finally:
            self._untrack_socket(client_socket)
            self._metrics.record_connection_closed()
            lease.release()

    def _release_cancelled_admission(
        self,
        client_socket: Any,
        lease: AdmissionLease,
    ) -> None:
        if not lease.release():
            return
        client_socket.close()
        self._untrack_socket(client_socket)

    def _untrack_socket(self, sock: Any) -> None:
        with self._sockets_lock:
            self._sockets.pop(id(sock), None)
            self._accepted_at.pop(id(sock), None)

    def _finalize_worker_future(
        self,
        future: object,
        client_socket: Any,
        client_address: tuple[str, int],
        lease: AdmissionLease | None,
    ) -> None:
        cancelled = getattr(future, "cancelled", None)
        if callable(cancelled) and cancelled():
            if lease is not None:
                self._release_cancelled_admission(client_socket, lease)
            return

        exception = getattr(future, "exception", None)
        if not callable(exception):
            return
        try:
            exc = exception()
        except Exception as callback_exc:
            self._metrics.record_worker_exception("worker_future_callback", callback_exc)
            logger.exception("Failed to observe worker future completion")
            return
        if exc is None:
            return
        self._metrics.record_worker_exception("worker_future", exc)
        logger.error(
            "Worker future failed while handling %s:%d",
            client_address[0],
            client_address[1],
            exc_info=(type(exc), exc, exc.__traceback__),
        )


__all__ = ["AdmissionLease", "CapacityGate", "ServerLifecycle", "TLSLifecycle"]
