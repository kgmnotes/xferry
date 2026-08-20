"""Integration coverage for bounded storage, decode, quota, and scan metrics."""

from __future__ import annotations

import base64
import errno
import gzip
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import xferry.storage as storage_module
from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.advanced_sessions import (
    AdvancedSession,
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
)
from xferry.handlers.smuggle import SmuggleTempPolicy, SmuggleTempQuotaExceeded
from xferry.http import HTTPRequest
from xferry.metrics import MetricsCollector
from xferry.notepad_service import (
    NotepadService,
    NotepadServiceError,
    NoteStoragePolicy,
    SaveNoteRequest,
)
from xferry.storage import (
    UploadStoragePolicy,
    UploadStorageQuotaExceeded,
    UploadStorageService,
)


def _storage_metrics(snapshot: dict[str, object]) -> dict[str, Any]:
    return cast(dict[str, Any], snapshot["storage"])


def _advanced_metrics(snapshot: dict[str, object]) -> dict[str, Any]:
    return cast(dict[str, Any], snapshot["advanced_upload"])


def _bind_advanced_session_dispatch(request: HTTPRequest) -> HTTPRequest:
    now = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    request.advanced_session_dispatch = AdvancedSessionDispatch(
        session=AdvancedSession(
            prefix="/advanced",
            decoder="json",
            diagnostic_headers=False,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
        ),
        principal=AdvancedSessionPrincipal("no_auth", None),
        direct_peer=None,
    )
    request.advanced_session_admission_prepared = True
    return request


def test_explicit_metrics_snapshot_refreshes_exact_storage_usage(tmp_path: Path) -> None:
    """Catches server metrics returning legacy usage count aliases."""
    server = make_server(root_dir=str(tmp_path), quiet=True)
    upload_name = "operator-secret.bin"
    server.upload_storage.publish_bytes(server.upload_dir / upload_name, b"abc")

    note = server._get_notepad_service().save_note(
        SaveNoteRequest(
            title="private title",
            data_b64=base64.b64encode(bytes(range(28))).decode("ascii"),
        )
    )
    smuggle_path = server._write_smuggle_temp_artifact(b"html", ".html")

    snapshot = server.get_metrics()
    storage = _storage_metrics(snapshot)

    # uploads is aggregate usage of uploads/, including the separately reported
    # generated SMUGGLE subset because both consume the upload storage volume.
    assert storage["usage"]["uploads"] == {
        "bytes": 7,
        "items": 2,
    }
    assert storage["usage"]["notes"] == {
        "bytes": 28,
        "items": 1,
    }
    assert storage["usage"]["smuggle_temp"] == {
        "bytes": 4,
        "items": 1,
    }
    assert "body_memory" in snapshot
    assert "total_requests" not in snapshot
    assert "bytes_received" not in snapshot
    assert "request_latency_ms" not in snapshot
    assert storage["scans"]["storage_snapshot"]["count"] == 3
    assert storage["scans"]["storage_snapshot"]["items"] == 4

    serialized = json.dumps(snapshot)
    assert upload_name not in serialized
    assert note.note.note_id not in serialized
    assert smuggle_path.name not in serialized
    assert "private title" not in serialized


@pytest.mark.parametrize(
    ("policy", "existing_payload", "pending_payload", "reason"),
    [
        (UploadStoragePolicy(max_total_bytes=1), None, b"xx", "bytes"),
        (UploadStoragePolicy(max_file_count=1), b"x", b"y", "files"),
    ],
)
def test_upload_quota_denials_and_scans_are_instrumented(
    tmp_path: Path,
    policy: UploadStoragePolicy,
    existing_payload: bytes | None,
    pending_payload: bytes,
    reason: str,
) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    if existing_payload is not None:
        (upload_dir / "existing.bin").write_bytes(existing_payload)
    metrics = MetricsCollector()
    service = UploadStorageService(upload_dir, policy, metrics=metrics)

    with pytest.raises(UploadStorageQuotaExceeded):
        service.publish_bytes(upload_dir / "blocked.bin", pending_payload)

    storage = _storage_metrics(metrics.snapshot())
    assert storage["quota_denials"]["uploads"][reason] == 1
    assert storage["scans"]["upload_quota"]["count"] == 1
    assert storage["scans"]["upload_quota"]["items"] == (1 if existing_payload is not None else 0)
    assert not (upload_dir / "blocked.bin").exists()


def test_upload_free_space_denial_is_instrumented(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    metrics = MetricsCollector()
    service = UploadStorageService(
        upload_dir,
        UploadStoragePolicy(reserved_free_bytes=1),
        metrics=metrics,
    )
    monkeypatch.setattr(
        storage_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=0),
    )

    with pytest.raises(UploadStorageQuotaExceeded):
        service.publish_bytes(upload_dir / "blocked.bin", b"x")

    storage = _storage_metrics(metrics.snapshot())
    assert storage["quota_denials"]["uploads"]["free_space"] == 1


def test_upload_disk_full_denial_is_instrumented(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    metrics = MetricsCollector()
    service = UploadStorageService(upload_dir, metrics=metrics)

    def fail_link(_source: Path, _destination: Path) -> None:
        raise OSError(errno.ENOSPC, "forced disk full")

    monkeypatch.setattr(storage_module.os, "link", fail_link)

    with pytest.raises(UploadStorageQuotaExceeded):
        service.publish_bytes(upload_dir / "blocked.bin", b"x")

    storage = _storage_metrics(metrics.snapshot())
    assert storage["quota_denials"]["uploads"]["disk_full"] == 1
    assert not (upload_dir / "blocked.bin").exists()


def test_info_and_advanced_decode_rejections_are_instrumented(tmp_path: Path) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True)
    for index in range(3):
        (server.upload_dir / f"item-{index}.bin").write_bytes(b"x")

    info_response = server.handle_info(make_request("INFO", "/uploads?limit=2"))
    assert info_response.status_code == 200

    invalid_response = server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "data": "%%%",
                        "encoding": "base64",
                        "encryption": "none",
                    }
                ).encode("utf-8"),
            )
        )
    )
    assert invalid_response.status_code == 400

    server.advanced_upload_decoded_size_limit = 64
    oversized_decoded = base64.b64encode(gzip.compress(b"x" * 1024)).decode("ascii")
    decoded_limit_response = server.handle_advanced_upload(
        _bind_advanced_session_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "data": oversized_decoded,
                        "encoding": "gzip-base64",
                        "encryption": "none",
                    }
                ).encode("utf-8"),
            )
        )
    )
    assert decoded_limit_response.status_code == 413

    snapshot = server._metrics.snapshot()
    storage = _storage_metrics(snapshot)
    advanced = _advanced_metrics(snapshot)
    assert storage["scans"]["info"]["count"] == 1
    assert storage["scans"]["info"]["items"] == 3
    assert advanced["decode_rejections"]["invalid_encoding"] == 1
    assert advanced["decode_rejections"]["decoded_too_large"] == 1


def test_notepad_usage_listing_and_quota_metrics_are_instrumented(tmp_path: Path) -> None:
    notes_dir = tmp_path / "notes"
    metrics = MetricsCollector()
    service = NotepadService(
        notes_dir,
        threading.Lock(),
        storage_policy=NoteStoragePolicy(
            max_total_bytes=1024,
            max_note_count=1,
            max_listed_notes=1,
        ),
        metrics=metrics,
    )
    encoded = base64.b64encode(bytes(range(28))).decode("ascii")
    service.save_note(SaveNoteRequest(title="first", data_b64=encoded))
    listed = service.list_notes()
    assert len(listed.notes) == 1

    with pytest.raises(NotepadServiceError) as count_error:
        service.save_note(SaveNoteRequest(title="second", data_b64=encoded))
    assert count_error.value.code == "storage_quota_exceeded"
    assert count_error.value.details["reason"] == "notes"

    storage = _storage_metrics(metrics.snapshot())
    assert storage["usage"]["notes"] == {
        "bytes": 28,
        "items": 1,
    }
    assert storage["quota_denials"]["notes"]["notes"] == 1
    assert storage["scans"]["notepad_usage"]["count"] == 2
    assert storage["scans"]["notepad_listing"]["count"] == 1
    assert storage["scans"]["notepad_listing"]["items"] == 1


def test_notepad_byte_quota_denial_is_instrumented(tmp_path: Path) -> None:
    notes_dir = tmp_path / "notes"
    metrics = MetricsCollector()
    service = NotepadService(
        notes_dir,
        threading.Lock(),
        storage_policy=NoteStoragePolicy(
            max_total_bytes=1,
            max_note_count=None,
            max_listed_notes=1,
        ),
        metrics=metrics,
    )

    with pytest.raises(NotepadServiceError) as byte_error:
        service.save_note(
            SaveNoteRequest(
                title="too large",
                data_b64=base64.b64encode(bytes(range(28))).decode("ascii"),
            )
        )
    assert byte_error.value.code == "storage_quota_exceeded"
    assert byte_error.value.details["reason"] == "bytes"

    storage = _storage_metrics(metrics.snapshot())
    assert storage["quota_denials"]["notes"]["bytes"] == 1


@pytest.mark.parametrize(
    ("policy", "reason"),
    [
        (
            SmuggleTempPolicy(
                max_age_seconds=None,
                max_file_count=None,
                max_total_bytes=1,
            ),
            "bytes",
        ),
        (
            SmuggleTempPolicy(
                max_age_seconds=None,
                max_file_count=0,
                max_total_bytes=None,
            ),
            "files",
        ),
    ],
)
def test_smuggle_temp_quota_denials_are_instrumented(
    tmp_path: Path,
    policy: SmuggleTempPolicy,
    reason: str,
) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True)
    server.smuggle_temp_policy = policy

    with pytest.raises(SmuggleTempQuotaExceeded):
        server._write_smuggle_temp_artifact(b"xx", ".html")

    storage = _storage_metrics(server._metrics.snapshot())
    assert storage["quota_denials"]["smuggle_temp"][reason] == 1
    assert storage["usage"]["smuggle_temp"] == {"bytes": 0, "items": 0}
