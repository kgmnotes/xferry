"""Tests for xferry.metrics.MetricsCollector."""

from __future__ import annotations

import threading
from typing import Any

import pytest

from xferry.metrics import (
    ADVANCED_DECODE_REJECTION_REASONS,
    QUOTA_DENIAL_REASONS,
    SCAN_OBSERVATION_SCOPES,
    STORAGE_USAGE_SCOPES,
    MetricsCollector,
)


class TestMetricsCollector:
    def test_snapshot_on_fresh_collector_is_zero(self) -> None:
        """Catches regressions that expose legacy flat metric aliases."""
        m = MetricsCollector()
        snap = m.snapshot()

        assert set(snap) == {
            "uptime_seconds",
            "requests",
            "connections",
            "request_admission",
            "receive",
            "response",
            "timeouts",
            "websocket",
            "worker",
            "storage",
            "advanced_upload",
        }
        assert snap["requests"] == {
            "total": 0,
            "client_errors": 0,
            "server_errors": 0,
            "status_counts": {},
            "latency_ms": {
                "count": 0,
                "total": 0.0,
                "avg": 0.0,
                "max": 0.0,
            },
        }
        assert snap["connections"] == {"active": 0, "accepted": 0, "closed": 0}
        assert snap["receive"] == {
            "bytes": 0,
            "rejections": 0,
            "rejection_reasons": {},
        }
        assert snap["timeouts"] == {}
        assert snap["response"] == {
            "bytes": 0,
            "stream_aborts": 0,
            "stream_abort_reasons": {},
        }
        assert snap["request_admission"] == {"active": 0, "accepted": 0, "rejected": 0}
        assert snap["websocket"] == {
            "active": 0,
            "rejected_admissions": 0,
            "closed": 0,
            "protocol_errors": 0,
            "message_too_big": 0,
            "incomplete_frame_timeouts": 0,
            "idle_pings": 0,
            "errors": 0,
        }
        assert snap["worker"] == {
            "exceptions": 0,
            "exception_sources": {},
            "last_exception_type": None,
        }
        assert snap["storage"] == {
            "usage": {
                "notes": {"bytes": 0, "items": 0},
                "smuggle_temp": {"bytes": 0, "items": 0},
                "uploads": {"bytes": 0, "items": 0},
            },
            "quota_denials": {
                "notes": {"bytes": 0, "notes": 0},
                "smuggle_temp": {"bytes": 0, "files": 0},
                "uploads": {"bytes": 0, "disk_full": 0, "files": 0, "free_space": 0},
            },
            "scans": {
                "info": {
                    "count": 0,
                    "items": 0,
                    "total_ms": 0.0,
                    "avg_ms": 0.0,
                    "max_ms": 0.0,
                },
                "notepad_listing": {
                    "count": 0,
                    "items": 0,
                    "total_ms": 0.0,
                    "avg_ms": 0.0,
                    "max_ms": 0.0,
                },
                "notepad_usage": {
                    "count": 0,
                    "items": 0,
                    "total_ms": 0.0,
                    "avg_ms": 0.0,
                    "max_ms": 0.0,
                },
                "storage_snapshot": {
                    "count": 0,
                    "items": 0,
                    "total_ms": 0.0,
                    "avg_ms": 0.0,
                    "max_ms": 0.0,
                },
                "upload_quota": {
                    "count": 0,
                    "items": 0,
                    "total_ms": 0.0,
                    "avg_ms": 0.0,
                    "max_ms": 0.0,
                },
            },
        }
        assert snap["advanced_upload"] == {
            "decode_rejections": {
                "crypto_unavailable": 0,
                "decoded_too_large": 0,
                "decrypt_failed": 0,
                "encoded_too_large": 0,
                "hmac_mismatch": 0,
                "invalid_encoding": 0,
                "invalid_key": 0,
            }
        }
        assert snap["uptime_seconds"] == 0

    def test_mark_started_enables_uptime(self) -> None:
        m = MetricsCollector()
        m.mark_started()

        snap = m.snapshot()
        assert isinstance(snap["uptime_seconds"], float)
        # uptime is >= 0; exact value depends on timing
        assert snap["uptime_seconds"] >= 0

    def test_record_increments_counters(self) -> None:
        m = MetricsCollector()
        m.record(200, 100)
        m.record(200, 50)
        m.record(404, 30)
        m.record(500, 0)

        snap = m.snapshot()
        requests: dict[str, Any] = snap["requests"]  # type: ignore[assignment]
        response: dict[str, Any] = snap["response"]  # type: ignore[assignment]
        assert requests["total"] == 4
        assert requests["client_errors"] == 1
        assert requests["server_errors"] == 1
        assert response["bytes"] == 180
        assert requests["status_counts"] == {200: 2, 404: 1, 500: 1}

    def test_snapshot_returns_defensive_copy(self) -> None:
        m = MetricsCollector()
        m.record(200, 10)
        m.record_receive_rejection("header_too_large")
        m.record_worker_exception("handle_client", RuntimeError("boom"))

        snap = m.snapshot()
        assert isinstance(snap["requests"]["status_counts"], dict)  # type: ignore[index]
        snap["requests"]["status_counts"][500] = 999  # type: ignore[index]
        snap["receive"]["rejection_reasons"]["body_too_large"] = 999  # type: ignore[index]
        snap["response"]["stream_abort_reasons"]["timeout"] = 999  # type: ignore[index]
        snap["worker"]["exception_sources"]["worker_future"] = 999  # type: ignore[index]
        snap["storage"]["usage"]["uploads"]["bytes"] = 999  # type: ignore[index]
        snap["storage"]["quota_denials"]["uploads"]["bytes"] = 999  # type: ignore[index]
        snap["storage"]["scans"]["info"]["count"] = 999  # type: ignore[index]
        snap["advanced_upload"]["decode_rejections"]["invalid_encoding"] = 999  # type: ignore[index]

        # Original state must not be affected
        snap2 = m.snapshot()
        assert snap2["requests"]["status_counts"] == {200: 1}  # type: ignore[index]
        assert snap2["receive"] == {
            "bytes": 0,
            "rejections": 1,
            "rejection_reasons": {"header_too_large": 1},
        }
        assert snap2["response"] == {
            "bytes": 10,
            "stream_aborts": 0,
            "stream_abort_reasons": {},
        }
        assert snap2["worker"] == {
            "exceptions": 1,
            "exception_sources": {"handle_client": 1},
            "last_exception_type": "RuntimeError",
        }
        assert snap2["storage"]["usage"]["uploads"]["bytes"] == 0  # type: ignore[index]
        assert snap2["storage"]["quota_denials"]["uploads"]["bytes"] == 0  # type: ignore[index]
        assert snap2["storage"]["scans"]["info"]["count"] == 0  # type: ignore[index]
        assert (  # type: ignore[index]
            snap2["advanced_upload"]["decode_rejections"]["invalid_encoding"] == 0
        )

    def test_storage_usage_snapshots_are_scope_limited(self) -> None:
        m = MetricsCollector()
        m.record_storage_usage("uploads", 2048, 3)
        m.record_storage_usage("notes", 1024, 2)
        m.record_storage_usage("smuggle_temp", 512, 1)

        storage: dict[str, Any] = m.snapshot()["storage"]  # type: ignore[assignment]
        assert storage["usage"] == {
            "notes": {"bytes": 1024, "items": 2},
            "smuggle_temp": {"bytes": 512, "items": 1},
            "uploads": {"bytes": 2048, "items": 3},
        }

    @pytest.mark.parametrize("scope", sorted(STORAGE_USAGE_SCOPES))
    def test_storage_usage_rejects_negative_values(self, scope: str) -> None:
        m = MetricsCollector()

        with pytest.raises(ValueError, match="byte_count"):
            m.record_storage_usage(scope, -1, 0)
        with pytest.raises(ValueError, match="item_count"):
            m.record_storage_usage(scope, 0, -1)

    def test_storage_usage_rejects_unknown_scope(self) -> None:
        m = MetricsCollector()

        with pytest.raises(ValueError, match="unknown storage usage scope"):
            m.record_storage_usage("/tmp/user-file", 1, 1)

    @pytest.mark.parametrize(
        ("scope", "reason"),
        [
            (scope, reason)
            for scope, reasons in sorted(QUOTA_DENIAL_REASONS.items())
            for reason in sorted(reasons)
        ],
    )
    def test_quota_denials_are_closed_low_cardinality_labels(
        self,
        scope: str,
        reason: str,
    ) -> None:
        m = MetricsCollector()
        m.record_quota_denial(scope, reason)
        m.record_quota_denial(scope, reason)

        storage: dict[str, Any] = m.snapshot()["storage"]  # type: ignore[assignment]
        assert storage["quota_denials"][scope][reason] == 2

    def test_quota_denials_reject_unknown_labels(self) -> None:
        m = MetricsCollector()

        with pytest.raises(ValueError, match="unknown quota scope"):
            m.record_quota_denial("uploads/private-name.txt", "bytes")
        with pytest.raises(ValueError, match="unknown uploads quota denial reason"):
            m.record_quota_denial("uploads", "private-name.txt")

    @pytest.mark.parametrize("reason", sorted(ADVANCED_DECODE_REJECTION_REASONS))
    def test_advanced_decode_rejections_are_closed_low_cardinality_labels(
        self,
        reason: str,
    ) -> None:
        m = MetricsCollector()
        m.record_advanced_decode_rejection(reason)

        advanced_upload: dict[str, Any] = m.snapshot()["advanced_upload"]  # type: ignore[assignment]
        assert advanced_upload["decode_rejections"][reason] == 1

    def test_advanced_decode_rejections_reject_unknown_reason(self) -> None:
        m = MetricsCollector()

        with pytest.raises(ValueError, match="unknown advanced decode rejection reason"):
            m.record_advanced_decode_rejection("payload-name")

    @pytest.mark.parametrize("scope", sorted(SCAN_OBSERVATION_SCOPES))
    def test_scan_observations_track_count_items_total_average_and_max(
        self,
        scope: str,
    ) -> None:
        m = MetricsCollector()
        m.record_scan_observation(scope, 1.25, items=10)
        m.record_scan_observation(scope, 2.5, items=4)

        storage: dict[str, Any] = m.snapshot()["storage"]  # type: ignore[assignment]
        assert storage["scans"][scope] == {
            "count": 2,
            "items": 14,
            "total_ms": 3.75,
            "avg_ms": 1.875,
            "max_ms": 2.5,
        }

    def test_scan_observations_reject_unknown_scope_and_negative_items(self) -> None:
        m = MetricsCollector()

        with pytest.raises(ValueError, match="unknown scan observation scope"):
            m.record_scan_observation("uploads/private-name.txt", 1.0, items=1)
        with pytest.raises(ValueError, match="items"):
            m.record_scan_observation("info", 1.0, items=-1)

    def test_scan_observations_clamp_negative_duration(self) -> None:
        m = MetricsCollector()
        m.record_scan_observation("info", -1.0, items=1)

        storage: dict[str, Any] = m.snapshot()["storage"]  # type: ignore[assignment]
        assert storage["scans"]["info"] == {
            "count": 1,
            "items": 1,
            "total_ms": 0.0,
            "avg_ms": 0.0,
            "max_ms": 0.0,
        }

    def test_receive_rejection_counts_are_isolated(self) -> None:
        m = MetricsCollector()
        m.record_receive_rejection("header_too_large")
        m.record_receive_rejection("header_too_large")
        m.record_receive_rejection("body_too_large")

        snap = m.snapshot()
        assert snap["receive"] == {
            "bytes": 0,
            "rejections": 3,
            "rejection_reasons": {
                "header_too_large": 2,
                "body_too_large": 1,
            },
        }

    def test_slow_body_receive_rejections_are_counted_as_timeouts(self) -> None:
        m = MetricsCollector()
        m.record_receive_rejection("body_idle_timeout")
        m.record_receive_rejection("body_rate_too_slow")

        snap = m.snapshot()
        assert snap["receive"]["rejection_reasons"] == {  # type: ignore[index]
            "body_idle_timeout": 1,
            "body_rate_too_slow": 1,
        }
        assert snap["timeouts"] == {
            "body_idle_timeout": 1,
            "body_rate_too_slow": 1,
        }

    def test_error_counters_are_status_based(self) -> None:
        m = MetricsCollector()
        m.record(404, 10)
        m.record(500, 0)
        m.record(503, 0, error=True)

        snap = m.snapshot()
        requests: dict[str, Any] = snap["requests"]  # type: ignore[assignment]
        assert requests["client_errors"] == 1
        assert requests["server_errors"] == 2
        assert requests["status_counts"] == {404: 1, 500: 1, 503: 1}

    def test_error_flag_counts_exceptional_server_failures(self) -> None:
        m = MetricsCollector()
        m.record(200, 0, error=True)

        snap = m.snapshot()
        requests: dict[str, Any] = snap["requests"]  # type: ignore[assignment]
        assert requests["client_errors"] == 0
        assert requests["server_errors"] == 1
        assert requests["status_counts"] == {200: 1}

    def test_concurrent_record_is_thread_safe(self) -> None:
        m = MetricsCollector()

        def worker() -> None:
            for _ in range(1000):
                m.record(200, 1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = m.snapshot()
        assert snap["requests"]["total"] == 8 * 1000  # type: ignore[index]
        assert snap["response"]["bytes"] == 8 * 1000  # type: ignore[index]

    @pytest.mark.parametrize("status", [200, 301, 404, 500])
    def test_status_buckets_are_isolated(self, status: int) -> None:
        m = MetricsCollector()
        m.record(status, 10)

        snap = m.snapshot()
        requests: dict[str, Any] = snap["requests"]  # type: ignore[assignment]
        counts: dict[int, int] = requests["status_counts"]  # type: ignore[assignment]
        assert counts == {status: 1}

    def test_websocket_counters_are_thread_safe(self) -> None:
        m = MetricsCollector()
        m.record_websocket_opened()
        m.record_websocket_opened()
        m.record_websocket_rejected()
        m.record_websocket_protocol_error()
        m.record_websocket_message_too_big()
        m.record_websocket_incomplete_frame_timeout()
        m.record_websocket_idle_ping()
        m.record_websocket_error()
        m.record_websocket_closed()

        snap = m.snapshot()
        assert snap["websocket"] == {
            "active": 1,
            "rejected_admissions": 1,
            "closed": 1,
            "protocol_errors": 1,
            "message_too_big": 1,
            "incomplete_frame_timeouts": 1,
            "idle_pings": 1,
            "errors": 1,
        }

    def test_request_admission_counters_are_thread_safe(self) -> None:
        m = MetricsCollector()
        m.record_request_admission_accepted()
        m.record_request_admission_accepted()
        m.record_request_admission_rejected()
        m.record_request_admission_released()

        snap = m.snapshot()
        assert snap["request_admission"] == {
            "active": 1,
            "accepted": 2,
            "rejected": 1,
        }

    def test_connection_latency_timeout_and_worker_counters(self) -> None:
        m = MetricsCollector()
        m.record_connection_opened()
        m.record_connection_opened()
        m.record_connection_closed()
        m.record_bytes_received(100)
        m.record_bytes_received(23)
        m.record_request_latency(10.0)
        m.record_request_latency(30.0)
        m.record_timeout("websocket_incomplete_frame")
        m.record_receive_rejection("header_timeout")
        m.record_response_stream_abort("timeout")
        m.record_worker_exception("handle_client", RuntimeError("boom"))

        snap = m.snapshot()
        assert snap["connections"] == {"active": 1, "accepted": 2, "closed": 1}
        assert snap["receive"]["bytes"] == 123  # type: ignore[index]
        assert snap["requests"]["latency_ms"] == {  # type: ignore[index]
            "count": 2,
            "total": 40.0,
            "avg": 20.0,
            "max": 30.0,
        }
        assert snap["timeouts"] == {
            "websocket_incomplete_frame": 1,
            "header_timeout": 1,
        }
        assert snap["response"] == {
            "bytes": 0,
            "stream_aborts": 1,
            "stream_abort_reasons": {"timeout": 1},
        }
        assert snap["worker"] == {
            "exceptions": 1,
            "exception_sources": {"handle_client": 1},
            "last_exception_type": "RuntimeError",
        }

    def test_concurrent_operational_updates_are_thread_safe(self) -> None:
        m = MetricsCollector()

        def worker() -> None:
            for _ in range(250):
                m.record(200, 1)
                m.record_bytes_received(2)
                m.record_connection_opened()
                m.record_connection_closed()
                m.record_receive_rejection("body_timeout")
                m.record_response_stream_abort("timeout")
                m.record_request_admission_accepted()
                m.record_request_admission_released()
                m.record_request_admission_rejected()
                m.record_request_latency(1.5)
                m.record_websocket_opened()
                m.record_websocket_closed()
                m.record_websocket_rejected()
                m.record_timeout("websocket_incomplete_frame")
                m.record_worker_exception("worker_future", RuntimeError("boom"))
                m.record_storage_usage("uploads", 10, 1)
                m.record_quota_denial("uploads", "bytes")
                m.record_advanced_decode_rejection("invalid_encoding")
                m.record_scan_observation("upload_quota", 0.5, items=1)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = m.snapshot()
        assert snap["requests"]["total"] == 1000  # type: ignore[index]
        assert snap["response"]["bytes"] == 1000  # type: ignore[index]
        assert snap["receive"]["bytes"] == 2000  # type: ignore[index]
        assert snap["connections"] == {"active": 0, "accepted": 1000, "closed": 1000}
        assert snap["receive"]["rejections"] == 1000  # type: ignore[index]
        assert snap["receive"]["rejection_reasons"] == {"body_timeout": 1000}  # type: ignore[index]
        assert snap["timeouts"] == {
            "body_timeout": 1000,
            "websocket_incomplete_frame": 1000,
        }
        assert snap["response"] == {
            "bytes": 1000,
            "stream_aborts": 1000,
            "stream_abort_reasons": {"timeout": 1000},
        }
        assert snap["request_admission"] == {
            "active": 0,
            "accepted": 1000,
            "rejected": 1000,
        }
        assert snap["requests"]["latency_ms"] == {  # type: ignore[index]
            "count": 1000,
            "total": 1500.0,
            "avg": 1.5,
            "max": 1.5,
        }
        assert snap["websocket"]["active"] == 0  # type: ignore[index]
        assert snap["websocket"]["closed"] == 1000  # type: ignore[index]
        assert snap["websocket"]["rejected_admissions"] == 1000  # type: ignore[index]
        assert snap["worker"] == {
            "exceptions": 1000,
            "exception_sources": {"worker_future": 1000},
            "last_exception_type": "RuntimeError",
        }
        assert snap["storage"]["usage"]["uploads"] == {  # type: ignore[index]
            "bytes": 10,
            "items": 1,
        }
        assert snap["storage"]["quota_denials"]["uploads"]["bytes"] == 1000  # type: ignore[index]
        assert snap["storage"]["scans"]["upload_quota"] == {  # type: ignore[index]
            "count": 1000,
            "items": 1000,
            "total_ms": 500.0,
            "avg_ms": 0.5,
            "max_ms": 0.5,
        }
        assert (  # type: ignore[index]
            snap["advanced_upload"]["decode_rejections"]["invalid_encoding"] == 1000
        )
