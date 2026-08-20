"""Thread-safe in-memory metrics collector."""

import threading
import time
from collections.abc import Mapping

STORAGE_USAGE_SCOPES = frozenset({"uploads", "notes", "smuggle_temp"})
QUOTA_DENIAL_REASONS: Mapping[str, frozenset[str]] = {
    "uploads": frozenset({"bytes", "files", "free_space", "disk_full"}),
    "notes": frozenset({"bytes", "notes"}),
    "smuggle_temp": frozenset({"bytes", "files"}),
}
ADVANCED_DECODE_REJECTION_REASONS = frozenset(
    {
        "encoded_too_large",
        "decoded_too_large",
        "invalid_encoding",
        "invalid_key",
        "hmac_mismatch",
        "decrypt_failed",
        "crypto_unavailable",
    }
)
SCAN_OBSERVATION_SCOPES = frozenset(
    {
        "upload_quota",
        "info",
        "notepad_usage",
        "notepad_listing",
        "storage_snapshot",
    }
)


def _require_known(value: str, allowed: frozenset[str], label: str) -> None:
    """Reject metric labels outside a closed low-cardinality set."""
    if value not in allowed:
        expected = ", ".join(sorted(allowed))
        raise ValueError(f"unknown {label}: {value!r}; expected one of: {expected}")


class MetricsCollector:
    """Aggregates request-level counters and exposes snapshots.

    Thread-safe: every mutation holds a single lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time: float = 0.0
        self._request_count: int = 0
        self._client_error_count: int = 0
        self._server_error_count: int = 0
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._status_counts: dict[int, int] = {}
        self._receive_rejections: dict[str, int] = {}
        self._timeout_counts: dict[str, int] = {}
        self._response_stream_aborts: dict[str, int] = {}
        self._connection_active: int = 0
        self._connection_accepted: int = 0
        self._connection_closed: int = 0
        self._request_admission_active: int = 0
        self._request_admission_accepted: int = 0
        self._request_admission_rejected: int = 0
        self._request_latency_count: int = 0
        self._request_latency_total_ms: float = 0.0
        self._request_latency_max_ms: float = 0.0
        self._websocket_active: int = 0
        self._websocket_rejected_admissions: int = 0
        self._websocket_closed: int = 0
        self._websocket_protocol_errors: int = 0
        self._websocket_message_too_big: int = 0
        self._websocket_incomplete_frame_timeouts: int = 0
        self._websocket_idle_pings: int = 0
        self._websocket_errors: int = 0
        self._worker_exceptions: int = 0
        self._worker_exception_sources: dict[str, int] = {}
        self._last_worker_exception_type: str | None = None
        self._storage_usage: dict[str, tuple[int, int]] = dict.fromkeys(
            STORAGE_USAGE_SCOPES,
            (0, 0),
        )
        self._quota_denials: dict[str, dict[str, int]] = {
            scope: dict.fromkeys(reasons, 0) for scope, reasons in QUOTA_DENIAL_REASONS.items()
        }
        self._advanced_decode_rejections: dict[str, int] = dict.fromkeys(
            ADVANCED_DECODE_REJECTION_REASONS,
            0,
        )
        self._scan_observations: dict[str, dict[str, float | int]] = {
            scope: {
                "count": 0,
                "items": 0,
                "total_ms": 0.0,
                "max_ms": 0.0,
            }
            for scope in SCAN_OBSERVATION_SCOPES
        }

    def mark_started(self) -> None:
        """Mark the moment the server began accepting connections."""
        self._start_time = time.monotonic()

    def record(self, status_code: int, response_size: int, *, error: bool = False) -> None:
        """Record a single completed request.

        Error counters are status-based: 4xx responses are client errors and
        5xx responses are server errors. The ``error`` flag remains available
        for exceptional server failures that should count as server errors.
        """
        with self._lock:
            self._request_count += 1
            self._bytes_sent += response_size
            self._status_counts[status_code] = self._status_counts.get(status_code, 0) + 1
            if 400 <= status_code < 500:
                self._client_error_count += 1
            if status_code >= 500 or error:
                self._server_error_count += 1

    def record_bytes_received(self, byte_count: int) -> None:
        """Record bytes read from client request sockets."""
        if byte_count <= 0:
            return
        with self._lock:
            self._bytes_received += byte_count

    def record_connection_opened(self) -> None:
        """Record an admitted connection entering a worker."""
        with self._lock:
            self._connection_active += 1
            self._connection_accepted += 1

    def record_connection_closed(self) -> None:
        """Record a worker connection leaving the active set."""
        with self._lock:
            self._connection_active = max(0, self._connection_active - 1)
            self._connection_closed += 1

    def record_request_latency(self, duration_ms: float) -> None:
        """Record elapsed request processing time in milliseconds."""
        if duration_ms < 0:
            duration_ms = 0.0
        with self._lock:
            self._request_latency_count += 1
            self._request_latency_total_ms += duration_ms
            self._request_latency_max_ms = max(self._request_latency_max_ms, duration_ms)

    def record_timeout(self, reason: str) -> None:
        """Record a timeout signal by reason."""
        with self._lock:
            self._timeout_counts[reason] = self._timeout_counts.get(reason, 0) + 1

    def record_response_stream_abort(self, reason: str) -> None:
        """Record an aborted streamed response by reason."""
        with self._lock:
            self._response_stream_aborts[reason] = self._response_stream_aborts.get(reason, 0) + 1

    def record_websocket_opened(self) -> None:
        """Record a WebSocket connection admitted by the server."""
        with self._lock:
            self._websocket_active += 1

    def record_websocket_closed(self) -> None:
        """Record a WebSocket connection leaving the active set."""
        with self._lock:
            self._websocket_active = max(0, self._websocket_active - 1)
            self._websocket_closed += 1

    def record_websocket_rejected(self) -> None:
        """Record a WebSocket admission rejected by the resource budget."""
        with self._lock:
            self._websocket_rejected_admissions += 1

    def record_websocket_protocol_error(self) -> None:
        """Record a malformed WebSocket frame close."""
        with self._lock:
            self._websocket_protocol_errors += 1

    def record_websocket_message_too_big(self) -> None:
        """Record a WebSocket frame rejected for exceeding the size limit."""
        with self._lock:
            self._websocket_message_too_big += 1

    def record_websocket_incomplete_frame_timeout(self) -> None:
        """Record a timed-out partial WebSocket frame."""
        with self._lock:
            self._websocket_incomplete_frame_timeouts += 1

    def record_websocket_idle_ping(self) -> None:
        """Record an idle WebSocket keepalive ping."""
        with self._lock:
            self._websocket_idle_pings += 1

    def record_websocket_error(self) -> None:
        """Record an unexpected WebSocket connection error."""
        with self._lock:
            self._websocket_errors += 1

    def record_receive_rejection(self, reason: str) -> None:
        """Record a receive-layer request rejection reason."""
        with self._lock:
            self._receive_rejections[reason] = self._receive_rejections.get(reason, 0) + 1
            if reason in {
                "header_timeout",
                "body_timeout",
                "body_idle_timeout",
                "body_rate_too_slow",
            }:
                self._timeout_counts[reason] = self._timeout_counts.get(reason, 0) + 1

    def record_request_admission_accepted(self) -> None:
        """Record a socket admitted before worker submission."""
        with self._lock:
            self._request_admission_active += 1
            self._request_admission_accepted += 1

    def record_request_admission_released(self) -> None:
        """Record an admitted socket leaving the worker budget."""
        with self._lock:
            self._request_admission_active = max(0, self._request_admission_active - 1)

    def record_request_admission_rejected(self) -> None:
        """Record an accepted socket rejected because the worker budget was full."""
        with self._lock:
            self._request_admission_rejected += 1

    def record_worker_exception(self, source: str, exc: BaseException) -> None:
        """Record an exception observed in worker-related execution."""
        exc_type = type(exc).__name__
        with self._lock:
            self._worker_exceptions += 1
            self._worker_exception_sources[source] = (
                self._worker_exception_sources.get(source, 0) + 1
            )
            self._last_worker_exception_type = exc_type

    def record_storage_usage(self, scope: str, byte_count: int, item_count: int) -> None:
        """Record the latest storage usage snapshot for a known storage scope."""
        _require_known(scope, STORAGE_USAGE_SCOPES, "storage usage scope")
        if byte_count < 0:
            raise ValueError("byte_count must be at least 0")
        if item_count < 0:
            raise ValueError("item_count must be at least 0")
        with self._lock:
            self._storage_usage[scope] = (byte_count, item_count)

    def record_quota_denial(self, scope: str, reason: str) -> None:
        """Record a quota denial using closed low-cardinality labels."""
        allowed_reasons = QUOTA_DENIAL_REASONS.get(scope)
        if allowed_reasons is None:
            _require_known(scope, frozenset(QUOTA_DENIAL_REASONS), "quota scope")
            raise AssertionError("unreachable")
        _require_known(reason, allowed_reasons, f"{scope} quota denial reason")
        with self._lock:
            self._quota_denials[scope][reason] += 1

    def record_advanced_decode_rejection(self, reason: str) -> None:
        """Record an advanced-upload decode rejection with a known reason."""
        _require_known(
            reason,
            ADVANCED_DECODE_REJECTION_REASONS,
            "advanced decode rejection reason",
        )
        with self._lock:
            self._advanced_decode_rejections[reason] += 1

    def record_scan_observation(self, scope: str, duration_ms: float, *, items: int) -> None:
        """Record one filesystem scan observation for a known hot path."""
        _require_known(scope, SCAN_OBSERVATION_SCOPES, "scan observation scope")
        if items < 0:
            raise ValueError("items must be at least 0")
        if duration_ms < 0:
            duration_ms = 0.0
        with self._lock:
            stats = self._scan_observations[scope]
            stats["count"] = int(stats["count"]) + 1
            stats["items"] = int(stats["items"]) + items
            stats["total_ms"] = float(stats["total_ms"]) + duration_ms
            stats["max_ms"] = max(float(stats["max_ms"]), duration_ms)

    def _storage_usage_snapshot(self) -> dict[str, dict[str, int]]:
        usage: dict[str, dict[str, int]] = {}
        for scope in sorted(STORAGE_USAGE_SCOPES):
            byte_count, item_count = self._storage_usage[scope]
            usage[scope] = {
                "bytes": byte_count,
                "items": item_count,
            }
        return usage

    def _quota_denials_snapshot(self) -> dict[str, dict[str, int]]:
        return {
            scope: {reason: counts[reason] for reason in sorted(counts)}
            for scope, counts in sorted(self._quota_denials.items())
        }

    def _advanced_decode_rejections_snapshot(self) -> dict[str, int]:
        return {
            reason: self._advanced_decode_rejections[reason]
            for reason in sorted(self._advanced_decode_rejections)
        }

    def _scan_observations_snapshot(self) -> dict[str, dict[str, float | int]]:
        observations: dict[str, dict[str, float | int]] = {}
        for scope, stats in sorted(self._scan_observations.items()):
            count = int(stats["count"])
            total_ms = float(stats["total_ms"])
            observations[scope] = {
                "count": count,
                "items": int(stats["items"]),
                "total_ms": round(total_ms, 3),
                "avg_ms": round(total_ms / count, 3) if count else 0.0,
                "max_ms": round(float(stats["max_ms"]), 3),
            }
        return observations

    def snapshot(self) -> dict[str, object]:
        """Return a read-only view of current metrics."""
        with self._lock:
            uptime = time.monotonic() - self._start_time if self._start_time else 0.0
            receive_rejections = dict(self._receive_rejections)
            timeout_counts = dict(self._timeout_counts)
            response_stream_aborts = dict(self._response_stream_aborts)
            storage_usage = self._storage_usage_snapshot()
            quota_denials = self._quota_denials_snapshot()
            advanced_decode_rejections = self._advanced_decode_rejections_snapshot()
            scan_observations = self._scan_observations_snapshot()
            latency_avg = (
                self._request_latency_total_ms / self._request_latency_count
                if self._request_latency_count
                else 0.0
            )
            return {
                "uptime_seconds": round(uptime, 1),
                "requests": {
                    "total": self._request_count,
                    "client_errors": self._client_error_count,
                    "server_errors": self._server_error_count,
                    "status_counts": dict(self._status_counts),
                    "latency_ms": {
                        "count": self._request_latency_count,
                        "total": round(self._request_latency_total_ms, 3),
                        "avg": round(latency_avg, 3),
                        "max": round(self._request_latency_max_ms, 3),
                    },
                },
                "connections": {
                    "active": self._connection_active,
                    "accepted": self._connection_accepted,
                    "closed": self._connection_closed,
                },
                "receive": {
                    "bytes": self._bytes_received,
                    "rejections": sum(receive_rejections.values()),
                    "rejection_reasons": receive_rejections,
                },
                "timeouts": timeout_counts,
                "response": {
                    "bytes": self._bytes_sent,
                    "stream_aborts": sum(response_stream_aborts.values()),
                    "stream_abort_reasons": response_stream_aborts,
                },
                "request_admission": {
                    "active": self._request_admission_active,
                    "accepted": self._request_admission_accepted,
                    "rejected": self._request_admission_rejected,
                },
                "websocket": {
                    "active": self._websocket_active,
                    "rejected_admissions": self._websocket_rejected_admissions,
                    "closed": self._websocket_closed,
                    "protocol_errors": self._websocket_protocol_errors,
                    "message_too_big": self._websocket_message_too_big,
                    "incomplete_frame_timeouts": self._websocket_incomplete_frame_timeouts,
                    "idle_pings": self._websocket_idle_pings,
                    "errors": self._websocket_errors,
                },
                "worker": {
                    "exceptions": self._worker_exceptions,
                    "exception_sources": dict(self._worker_exception_sources),
                    "last_exception_type": self._last_worker_exception_type,
                },
                "storage": {
                    "usage": storage_usage,
                    "quota_denials": quota_denials,
                    "scans": scan_observations,
                },
                "advanced_upload": {
                    "decode_rejections": advanced_decode_rejections,
                },
            }
