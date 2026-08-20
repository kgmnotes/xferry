"""Socket I/O for HTTP: framing, timeouts, and Content-Length enforcement.

Kept separate from the main server loop so that protocol framing can be
unit-tested against in-memory sockets without starting a full server.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger("xferry")

HEADER_TIMEOUT = 30.0
BODY_TIMEOUT = 300.0
DEFAULT_BODY_IDLE_TIMEOUT = 5.0
DEFAULT_BODY_MIN_RATE_BYTES_PER_SECOND = 0.0
DEFAULT_BODY_MIN_RATE_GRACE = 0.25
DEFAULT_IDLE_TIMEOUT = 5.0
DEFAULT_MAX_HEADER_SIZE = 64 * 1024
RECV_CHUNK = 65536
HEADER_TERMINATOR = b"\r\n\r\n"

ReceiveRejectionReason = Literal[
    "header_too_large",
    "body_too_large",
    "header_timeout",
    "body_timeout",
    "body_idle_timeout",
    "body_rate_too_slow",
    "body_incomplete",
    "unsupported_transfer_encoding",
    "invalid_content_length",
    "body_memory_budget_exceeded",
]
ReceiveRejectCallback = Callable[[ReceiveRejectionReason], None]


class BodyMemoryBudget:
    """Thread-safe process-wide budget for declared request body bytes."""

    def __init__(self, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("body_memory_budget must be greater than 0")
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._current_bytes = 0
        self._peak_bytes = 0
        self._rejected = 0

    def try_reserve(self, byte_count: int) -> BodyMemoryReservation | None:
        """Reserve body bytes or return ``None`` when the process budget is full."""
        if byte_count < 0:
            raise ValueError("byte_count must be at least 0")
        if byte_count == 0:
            return None

        with self._lock:
            if self._current_bytes + byte_count > self.max_bytes:
                self._rejected += 1
                return None
            self._current_bytes += byte_count
            self._peak_bytes = max(self._peak_bytes, self._current_bytes)
        return BodyMemoryReservation(self, byte_count)

    def _release(self, byte_count: int) -> None:
        with self._lock:
            self._current_bytes = max(0, self._current_bytes - byte_count)

    def snapshot(self) -> dict[str, int]:
        """Return current body-budget counters."""
        with self._lock:
            return {
                "max_bytes": self.max_bytes,
                "current_bytes": self._current_bytes,
                "peak_bytes": self._peak_bytes,
                "rejected": self._rejected,
            }


class BodyMemoryReservation:
    """Idempotent handle for a body-memory reservation."""

    def __init__(self, budget: BodyMemoryBudget, byte_count: int) -> None:
        self.budget = budget
        self.byte_count = byte_count
        self._lock = threading.Lock()
        self._released = False

    def release(self) -> None:
        """Release this reservation once."""
        with self._lock:
            if self._released:
                return
            self._released = True
        self.budget._release(self.byte_count)


@dataclass
class RequestReceiveResult:
    """Raw request bytes plus any body-memory reservation held for processing."""

    data: bytes
    body_reservation: BodyMemoryReservation | None = None
    rejection_reason: ReceiveRejectionReason | None = None

    def release_body_reservation(self) -> None:
        """Release the held body reservation, if any."""
        if self.body_reservation is None:
            return
        self.body_reservation.release()
        self.body_reservation = None


def _record_rejection(
    on_reject: ReceiveRejectCallback | None,
    reason: ReceiveRejectionReason,
) -> None:
    if on_reject is None:
        return
    try:
        on_reject(reason)
    except Exception:
        logger.exception("Receive rejection callback failed")


def _parse_content_length(headers_part: str) -> int | None:
    """Return a single non-negative Content-Length, or ``None`` on conflict/parse error.

    Detects HTTP smuggling attempts via duplicate differing Content-Length headers.
    """
    values: list[int] = []
    for line in headers_part.split("\r\n"):
        if line.lower().startswith("content-length:"):
            try:
                values.append(int(line.split(":", 1)[1].strip()))
            except ValueError:
                return None
    if not values:
        return 0
    if len(set(values)) > 1 or values[0] < 0:
        return None
    return values[0]


def _has_transfer_encoding(headers_part: str) -> bool:
    """Return True when the request advertises any Transfer-Encoding."""
    for line in headers_part.split("\r\n"):
        if line.lower().startswith("transfer-encoding:"):
            return True
    return False


def receive_request(
    client_socket: socket.socket,
    *,
    max_upload_size: int,
    max_header_size: int = DEFAULT_MAX_HEADER_SIZE,
    idle_timeout: float | None = None,
    body_idle_timeout: float | None = DEFAULT_BODY_IDLE_TIMEOUT,
    body_timeout: float | None = BODY_TIMEOUT,
    body_min_rate_bytes_per_second: float = DEFAULT_BODY_MIN_RATE_BYTES_PER_SECOND,
    on_reject: ReceiveRejectCallback | None = None,
) -> bytes:
    """Read one complete HTTP request from ``client_socket``.

    Returns the raw request bytes or an empty ``bytes`` on any framing error
    (timeout, oversized headers/body, conflicting Content-Length). The caller is
    responsible for closing the socket when empty is returned.

    Args:
        client_socket: Accepted (and optionally TLS-wrapped) client socket.
        max_upload_size: Hard cap on request body bytes.
        max_header_size: Hard cap on request header bytes before ``\\r\\n\\r\\n``.
        idle_timeout: Initial timeout for the first ``recv`` (used by
            keep-alive loops waiting for the next request). ``None`` uses the
            default 5 s.
        body_idle_timeout: Maximum idle seconds between body chunks. ``None`` disables it.
        body_timeout: Maximum seconds to receive the declared body after headers arrive.
            ``None`` disables the total body deadline.
        body_min_rate_bytes_per_second: Optional minimum average body read rate. ``0`` disables
            rate enforcement.
        on_reject: Optional callback invoked with the receive-layer rejection reason.
    """
    return receive_request_result(
        client_socket,
        max_upload_size=max_upload_size,
        max_header_size=max_header_size,
        idle_timeout=idle_timeout,
        body_idle_timeout=body_idle_timeout,
        body_timeout=body_timeout,
        body_min_rate_bytes_per_second=body_min_rate_bytes_per_second,
        on_reject=on_reject,
    ).data


def receive_request_result(
    client_socket: socket.socket,
    *,
    max_upload_size: int,
    max_header_size: int = DEFAULT_MAX_HEADER_SIZE,
    idle_timeout: float | None = None,
    body_idle_timeout: float | None = DEFAULT_BODY_IDLE_TIMEOUT,
    body_timeout: float | None = BODY_TIMEOUT,
    body_min_rate_bytes_per_second: float = DEFAULT_BODY_MIN_RATE_BYTES_PER_SECOND,
    on_reject: ReceiveRejectCallback | None = None,
    body_memory_budget: BodyMemoryBudget | None = None,
) -> RequestReceiveResult:
    """Read one complete HTTP request and hold any body-memory reservation.

    The reservation is intentionally returned to the caller instead of released
    here because the raw request bytes and parsed ``HTTPRequest.body`` remain
    live until request processing finishes.
    """
    if max_upload_size <= 0:
        raise ValueError("max_upload_size must be greater than 0")
    if max_header_size <= 0:
        raise ValueError("max_header_size must be greater than 0")
    if body_idle_timeout is not None and body_idle_timeout <= 0:
        raise ValueError("body_idle_timeout must be greater than 0")
    if body_timeout is not None and body_timeout <= 0:
        raise ValueError("body_timeout must be greater than 0")
    if body_min_rate_bytes_per_second < 0:
        raise ValueError("body_min_rate_bytes_per_second must be at least 0")

    chunks: list[bytes] = []
    total_size = 0
    start_time = time.monotonic()
    body_start_time: float | None = None

    initial_timeout = idle_timeout if idle_timeout is not None else DEFAULT_IDLE_TIMEOUT
    client_socket.settimeout(initial_timeout)

    headers_received = False
    content_length = 0
    header_end_pos = 0
    first_recv = True
    body_reservation: BodyMemoryReservation | None = None
    active_body_recv_timeout_reason: ReceiveRejectionReason | None = None

    def body_received_bytes() -> int:
        if not headers_received:
            return 0
        return max(0, total_size - header_end_pos - len(HEADER_TERMINATOR))

    def body_rate_deadline() -> float | None:
        if body_start_time is None or content_length <= 0 or body_min_rate_bytes_per_second <= 0:
            return None
        required_seconds = content_length / body_min_rate_bytes_per_second
        required_seconds = max(DEFAULT_BODY_MIN_RATE_GRACE, required_seconds)
        return body_start_time + required_seconds

    def expired_body_deadline(now: float) -> ReceiveRejectionReason | None:
        if body_start_time is None or content_length <= 0:
            return None
        if body_received_bytes() >= content_length:
            return None
        if body_timeout is not None and now - body_start_time >= body_timeout:
            return "body_timeout"
        rate_deadline = body_rate_deadline()
        if rate_deadline is not None and now >= rate_deadline:
            return "body_rate_too_slow"
        return None

    def body_recv_timeout(now: float) -> tuple[float | None, ReceiveRejectionReason | None]:
        timeouts: list[tuple[float, ReceiveRejectionReason]] = []
        if body_idle_timeout is not None:
            timeouts.append((body_idle_timeout, "body_idle_timeout"))
        if body_start_time is not None:
            if body_timeout is not None:
                timeouts.append(
                    (max(0.001, body_timeout - (now - body_start_time)), "body_timeout")
                )
            rate_deadline = body_rate_deadline()
            if rate_deadline is not None:
                timeouts.append((max(0.001, rate_deadline - now), "body_rate_too_slow"))
        if not timeouts:
            return None, None
        return min(timeouts, key=lambda item: item[0])

    def reject(reason: ReceiveRejectionReason) -> RequestReceiveResult:
        nonlocal body_reservation
        _record_rejection(on_reject, reason)
        if body_reservation is not None:
            body_reservation.release()
            body_reservation = None
        return RequestReceiveResult(b"", rejection_reason=reason)

    try:
        while True:
            now = time.monotonic()
            elapsed = now - start_time
            if not headers_received and elapsed > HEADER_TIMEOUT:
                logger.warning("Header receive timeout (%.0fs)", elapsed)
                return reject("header_timeout")
            if headers_received:
                body_timeout_reason = expired_body_deadline(now)
                if body_timeout_reason is not None:
                    logger.warning(
                        "Body receive deadline exceeded (%s, %d bytes < %d bytes)",
                        body_timeout_reason,
                        body_received_bytes(),
                        content_length,
                    )
                    return reject(body_timeout_reason)
                body_timeout_value, active_body_recv_timeout_reason = body_recv_timeout(now)
                client_socket.settimeout(body_timeout_value)

            try:
                recv_size = RECV_CHUNK
                if not headers_received:
                    header_probe_limit = max_header_size + len(HEADER_TERMINATOR)
                    recv_size = min(RECV_CHUNK, max(1, header_probe_limit - total_size))
                else:
                    body_received = total_size - header_end_pos - len(HEADER_TERMINATOR)
                    if body_received >= content_length:
                        break
                    recv_size = min(RECV_CHUNK, max(1, content_length - body_received))

                chunk = client_socket.recv(recv_size)
                if not chunk:
                    if headers_received:
                        body_received = total_size - header_end_pos - len(HEADER_TERMINATOR)
                        if body_received < content_length:
                            logger.warning(
                                "Request body incomplete (%d bytes < %d bytes), dropping",
                                body_received,
                                content_length,
                            )
                            return reject("body_incomplete")
                    break

                if first_recv and idle_timeout is not None:
                    client_socket.settimeout(DEFAULT_IDLE_TIMEOUT)
                    first_recv = False

                chunks.append(chunk)
                total_size += len(chunk)

                if not headers_received:
                    data = b"".join(chunks)
                    header_end_pos = data.find(HEADER_TERMINATOR)
                    if header_end_pos >= 0:
                        if header_end_pos > max_header_size:
                            logger.warning(
                                "Request headers too large (%d bytes > %d bytes), dropping",
                                header_end_pos,
                                max_header_size,
                            )
                            return reject("header_too_large")
                        headers_part = data[:header_end_pos].decode("utf-8", errors="replace")
                        if _has_transfer_encoding(headers_part):
                            logger.warning("Transfer-Encoding is not supported; dropping request")
                            return reject("unsupported_transfer_encoding")
                        parsed = _parse_content_length(headers_part)
                        if parsed is None:
                            return reject("invalid_content_length")
                        content_length = parsed
                        if content_length > max_upload_size:
                            logger.warning(
                                "Declared Content-Length too large (%d bytes > %d bytes), dropping",
                                content_length,
                                max_upload_size,
                            )
                            return reject("body_too_large")
                        if content_length > 0 and body_memory_budget is not None:
                            body_reservation = body_memory_budget.try_reserve(content_length)
                            if body_reservation is None:
                                logger.warning(
                                    "Request body memory budget exceeded "
                                    "(declared=%d bytes, budget=%d bytes)",
                                    content_length,
                                    body_memory_budget.max_bytes,
                                )
                                return reject("body_memory_budget_exceeded")
                        headers_received = True
                        if content_length > 0:
                            body_start_time = time.monotonic()
                        body_received = total_size - header_end_pos - len(HEADER_TERMINATOR)
                        if body_received > max_upload_size:
                            logger.warning(
                                "Request body too large (%d bytes), dropping",
                                body_received,
                            )
                            return reject("body_too_large")
                        if body_received >= content_length:
                            break
                    elif len(data) > max_header_size + len(HEADER_TERMINATOR) - 1:
                        logger.warning(
                            "Request headers too large (>%d bytes), dropping",
                            max_header_size,
                        )
                        return reject("header_too_large")
                else:
                    body_received = total_size - header_end_pos - len(HEADER_TERMINATOR)
                    if body_received > max_upload_size:
                        logger.warning("Request body too large (%d bytes), dropping", body_received)
                        return reject("body_too_large")
                    if body_received >= content_length:
                        break

            except TimeoutError:
                if not headers_received:
                    break
                now = time.monotonic()
                body_timeout_reason = expired_body_deadline(now)
                if body_timeout_reason is not None:
                    logger.warning(
                        "Body receive deadline exceeded (%s, %d bytes < %d bytes)",
                        body_timeout_reason,
                        body_received_bytes(),
                        content_length,
                    )
                    return reject(body_timeout_reason)
                if active_body_recv_timeout_reason != "body_idle_timeout":
                    continue
                logger.warning(
                    "Request body idle timeout (%d bytes < %d bytes), dropping",
                    body_received_bytes(),
                    content_length,
                )
                return reject("body_idle_timeout")

        result = b"".join(chunks)
        if headers_received:
            expected_size = header_end_pos + len(HEADER_TERMINATOR) + content_length
            result = result[:expected_size]
        if result:
            logger.debug("Received %d bytes", len(result))
        return RequestReceiveResult(result, body_reservation=body_reservation)
    except BaseException:
        if body_reservation is not None:
            body_reservation.release()
            body_reservation = None
        raise
