"""Listener, worker-pool, admission, and TLS lifecycle ownership."""

from __future__ import annotations

import logging
import socket
import threading
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


class ServerLifecycle:
    """Own server startup, listener admission, workers, and idempotent cleanup."""

    ACCEPT_TIMEOUT = 1.0
    REQUEST_ADMISSION_WAIT_TIMEOUT = 0.05

    def __init__(
        self,
        *,
        host: str,
        port: int,
        max_workers: int,
        tls_manager: TLSLifecycle,
        metrics: MetricsCollector,
        handle_client: Callable[[Any, tuple[str, int]], None],
        reject_overloaded: Callable[[Any], None],
        on_started: Callable[[], None],
        on_shutdown: Callable[[], None],
        on_interrupted: Callable[[], None] | None = None,
        setup_tls: Callable[[], None] | None = None,
        cleanup_tls: Callable[[], None] | None = None,
        socket_factory: Callable[[], Any] | None = None,
        executor_factory: Callable[[int], Any] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.tls_manager = tls_manager
        self._metrics = metrics
        self._handle_client_callback = handle_client
        self._reject_overloaded = reject_overloaded
        self._on_started = on_started
        self._on_shutdown = on_shutdown
        self._on_interrupted = on_interrupted or (lambda: None)
        self._setup_tls = setup_tls or tls_manager.setup
        self._cleanup_tls = cleanup_tls or tls_manager.cleanup
        self._socket_factory = socket_factory or (
            lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        )
        self._executor_factory = executor_factory or (
            lambda workers: ThreadPoolExecutor(max_workers=workers)
        )
        self._request_slots = threading.BoundedSemaphore(max_workers)
        self._listener: Any | None = None
        self._executor: Any | None = None
        self._running = False
        self._cleanup_lock = threading.Lock()
        self._cleaned = False
        self._legacy_leases: list[AdmissionLease] = []
        self._legacy_lock = threading.Lock()

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
            self._metrics.mark_started()
            self._on_started()
            self._executor = self._executor_factory(self.max_workers)
            self._accept_loop(listener, self._executor)
        except KeyboardInterrupt:
            self._on_interrupted()
        finally:
            self.cleanup()

    def stop(self) -> None:
        """Request loop termination; cleanup remains safe when called repeatedly."""
        self._running = False

    def cleanup(self) -> None:
        """Close every owned runtime resource at most once."""
        with self._cleanup_lock:
            if self._cleaned:
                return
            self._cleaned = True
            self._running = False
            executor, self._executor = self._executor, None
            listener, self._listener = self._listener, None

        try:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
        finally:
            try:
                if listener is not None:
                    listener.close()
            finally:
                try:
                    self._cleanup_tls()
                finally:
                    self._on_shutdown()

    def acquire_request_admission(
        self,
        *,
        wait_timeout: float = 0.0,
    ) -> AdmissionLease | None:
        """Acquire one worker slot and return its release-once lease."""
        if wait_timeout > 0:
            acquired = self._request_slots.acquire(timeout=wait_timeout)
        else:
            acquired = self._request_slots.acquire(blocking=False)
        if not acquired:
            self._metrics.record_request_admission_rejected()
            logger.warning(
                "Request admission rejected: active worker budget exhausted (max=%d)",
                self.max_workers,
            )
            return None
        self._metrics.record_request_admission_accepted()
        return AdmissionLease(self._release_request_admission)

    def acquire_legacy_admission(self, *, wait_timeout: float = 0.0) -> bool:
        """Compatibility delegate for focused facade tests."""
        lease = self.acquire_request_admission(wait_timeout=wait_timeout)
        if lease is None:
            return False
        with self._legacy_lock:
            self._legacy_leases.append(lease)
        return True

    def release_legacy_admission(self) -> None:
        """Release the most recently acquired compatibility lease."""
        lease = self._pop_legacy_lease()
        if lease is not None:
            lease.release()

    def handle_legacy_admitted_client(
        self,
        client_socket: Any,
        client_address: tuple[str, int],
        handle_client: Callable[[Any, tuple[str, int]], None] | None = None,
    ) -> None:
        """Run a facade-test client using its previously acquired lease."""
        lease = self._pop_legacy_lease()
        if lease is None:
            raise RuntimeError("request admission lease is missing")
        self._handle_admitted_client(
            client_socket,
            client_address,
            lease,
            handle_client=handle_client,
        )

    def release_legacy_cancelled(self, future: object, client_socket: Any) -> None:
        """Apply cancellation cleanup to a facade-test lease."""
        cancelled = getattr(future, "cancelled", None)
        if not callable(cancelled) or not cancelled():
            return
        lease = self._pop_legacy_lease()
        if lease is None:
            return
        self._release_cancelled_admission(client_socket, lease)

    def finalize_legacy_future(
        self,
        future: object,
        client_socket: Any,
        client_address: tuple[str, int],
    ) -> None:
        """Observe a facade-test future and use a lease only when one exists."""
        lease = self._pop_legacy_lease_if_cancelled(future)
        self._finalize_worker_future(future, client_socket, client_address, lease)

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
                lease = self.acquire_request_admission(
                    wait_timeout=self.REQUEST_ADMISSION_WAIT_TIMEOUT
                )
                if lease is None:
                    self._reject_overloaded(client_socket)
                    continue
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
                    lease.release()
                    client_socket.close()
                    self._metrics.record_worker_exception("worker_submit", exc)
                    logger.exception("Failed to submit accepted client to worker pool")
            except TimeoutError:
                continue

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

    def _release_request_admission(self) -> None:
        self._request_slots.release()
        self._metrics.record_request_admission_released()

    def _pop_legacy_lease(self) -> AdmissionLease | None:
        with self._legacy_lock:
            return self._legacy_leases.pop() if self._legacy_leases else None

    def _pop_legacy_lease_if_cancelled(self, future: object) -> AdmissionLease | None:
        cancelled = getattr(future, "cancelled", None)
        if callable(cancelled) and cancelled():
            return self._pop_legacy_lease()
        return None


__all__ = ["AdmissionLease", "ServerLifecycle", "TLSLifecycle"]
