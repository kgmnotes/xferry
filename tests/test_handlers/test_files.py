"""Tests for file handler utilities."""

import base64
import errno
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import xferry.storage as storage_module
from tests.conftest import make_request
from xferry.advanced_sessions import (
    AdvancedSession,
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
)
from xferry.handlers import HandlerMixin
from xferry.http.utils import make_unique_filename, sanitize_filename
from xferry.storage import (
    UploadStoragePolicy,
    UploadStorageQuotaExceeded,
    UploadStorageService,
    UploadStorageUsage,
)


class UploadStubServer(HandlerMixin):
    """Minimal concrete class for upload handler tests."""

    def __init__(
        self,
        root_dir: Path,
        upload_dir: Path,
        *,
        upload_storage_policy: UploadStoragePolicy | None = None,
    ):
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.upload_storage = UploadStorageService(
            upload_dir,
            upload_storage_policy or UploadStoragePolicy(),
        )
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.cors_origin = None
        self.sandbox_mode = False
        self.opsec_mode = False
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()
        self._ecdh_manager = None
        self.method_handlers = self.build_method_handlers()

    def get_metrics(self):
        return {
            "uptime_seconds": 0,
            "total_requests": 0,
            "total_errors": 0,
            "client_errors": 0,
            "server_errors": 0,
            "bytes_sent": 0,
            "status_counts": {},
        }


def _run_two_uploads(upload):
    """Run two upload calls at once and return their responses."""
    start = threading.Barrier(2)
    results: list[object] = [None, None]
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            start.wait(timeout=5)
            results[index] = upload(index)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    assert all(result is not None for result in results)
    return results


def _force_first_two_exists_checks_to_miss(monkeypatch, target: Path) -> None:
    """Make the first two existence checks for *target* observe an absent file."""
    original_exists = Path.exists
    exists_barrier = threading.Barrier(2)
    lock = threading.Lock()
    calls = 0

    def fake_exists(self: Path) -> bool:
        nonlocal calls
        if self == target:
            with lock:
                calls += 1
                should_force_missing = calls <= 2
            if should_force_missing:
                exists_barrier.wait(timeout=5)
                return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)


def _upload_temp_files(upload_dir: Path) -> list[Path]:
    return sorted(path for path in upload_dir.iterdir() if path.name.startswith(".upload-tmp-"))


def _bind_advanced_session_dispatch(request):
    """Bind the landed request-local Advanced session contract for direct handler tests."""
    now = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    request.advanced_session_dispatch = AdvancedSessionDispatch(
        session=AdvancedSession(
            prefix="/advanced",
            decoder="auto",
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


def _canonical_advanced_json_request(payload: bytes, *, name: str):
    body = json.dumps(
        {
            "data": base64.b64encode(payload).decode("ascii"),
            "encoding": "base64",
            "encryption": "none",
            "name": name,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return _bind_advanced_session_dispatch(
        make_request(
            "POST",
            "/advanced",
            headers={"Content-Type": "application/json"},
            body=body,
        )
    )


class TestUploadStorageQuotaScan:
    """Regression coverage for aggregate usage scan decisions."""

    def test_no_limit_policy_publishes_without_current_usage_scan(
        self,
        upload_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        service = UploadStorageService(upload_dir, UploadStoragePolicy())

        def fail_current_usage() -> UploadStorageUsage:
            raise AssertionError("current_usage should not run for no-limit upload policy")

        monkeypatch.setattr(service, "current_usage", fail_current_usage)

        published = service.publish_bytes(upload_dir / "fast-path.txt", b"payload")

        assert published == upload_dir / "fast-path.txt"
        assert published.read_bytes() == b"payload"
        assert _upload_temp_files(upload_dir) == []

    def test_aggregate_limit_policy_still_uses_current_usage(
        self,
        upload_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        service = UploadStorageService(
            upload_dir,
            UploadStoragePolicy(max_total_bytes=10),
        )
        calls = 0

        def fake_current_usage() -> UploadStorageUsage:
            nonlocal calls
            calls += 1
            return UploadStorageUsage(total_bytes=9, file_count=1)

        monkeypatch.setattr(service, "current_usage", fake_current_usage)

        with pytest.raises(UploadStorageQuotaExceeded):
            service.publish_bytes(upload_dir / "blocked.txt", b"xx")

        assert calls == 1
        assert not (upload_dir / "blocked.txt").exists()
        assert _upload_temp_files(upload_dir) == []


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_simple_filename(self):
        """Test that simple filenames are unchanged."""
        assert sanitize_filename("document.pdf") == "document.pdf"

    def test_removes_path_separators(self):
        """Test removal of path separators."""
        result = sanitize_filename("../../../etc/passwd")
        assert "/" not in result
        assert ".." not in result

    def test_removes_backslashes(self):
        """Test removal of backslashes."""
        result = sanitize_filename("..\\..\\windows\\system32")
        assert "\\" not in result

    def test_replaces_spaces(self):
        """Test handling of spaces in filenames."""
        result = sanitize_filename("file with spaces.txt")
        assert "file" in result.lower()

    def test_empty_filename(self):
        """Test handling of empty filename."""
        result = sanitize_filename("")
        assert len(result) > 0  # Should return some default

    def test_special_characters(self):
        """Test removal of special characters."""
        result = sanitize_filename('file<>:"|?*.txt')
        # Dangerous characters should be removed/replaced
        for char in '<>:"|?*':
            assert char not in result


class TestMakeUniqueFilename:
    """Tests for make_unique_filename function."""

    def test_unique_when_not_exists(self, temp_dir: Path):
        """Test that non-existing filename is returned as-is."""
        file_path = temp_dir / "newfile.txt"

        result = make_unique_filename(file_path)

        assert result == file_path

    def test_adds_suffix_when_exists(self, temp_dir: Path):
        """Test that suffix is added when file exists."""
        file_path = temp_dir / "existing.txt"
        file_path.touch()

        result = make_unique_filename(file_path)

        assert result != file_path
        assert "existing" in result.stem
        assert result.suffix == ".txt"

    def test_increments_suffix(self, temp_dir: Path):
        """Test that suffix increments for multiple collisions."""
        base_path = temp_dir / "file.txt"
        base_path.touch()
        (temp_dir / "file_1.txt").touch()

        result = make_unique_filename(base_path)

        assert result.stem.endswith("_2") or result.stem.endswith("_1") is False

    def test_preserves_extension(self, temp_dir: Path):
        """Test that file extension is preserved."""
        file_path = temp_dir / "document.pdf"
        file_path.touch()

        result = make_unique_filename(file_path)

        assert result.suffix == ".pdf"


class TestExclusiveUploadWrites:
    """Regression coverage for concurrent same-name uploads."""

    def test_standard_upload_reserves_distinct_destination_under_race(
        self,
        temp_dir: Path,
        upload_dir: Path,
        monkeypatch,
    ):
        server = UploadStubServer(temp_dir, upload_dir)
        target = upload_dir / "race.txt"
        _force_first_two_exists_checks_to_miss(monkeypatch, target)
        payloads = [b"first standard payload", b"second standard payload"]

        def upload(index: int):
            return server.handle_none(
                make_request(
                    "POST",
                    "/",
                    headers={"X-File-Name": "race.txt"},
                    body=payloads[index],
                )
            )

        responses = _run_two_uploads(upload)

        assert [response.status_code for response in responses] == [201, 201]
        bodies = [json.loads(response.body) for response in responses]
        filenames = [body["file"]["name"] for body in bodies]
        assert len(set(filenames)) == 2
        assert {body["file"]["path"] for body in bodies} == {
            f"/uploads/{name}" for name in filenames
        }
        assert {(upload_dir / name).read_bytes() for name in filenames} == set(payloads)

    def test_advanced_upload_reserves_distinct_destination_under_race(
        self,
        temp_dir: Path,
        upload_dir: Path,
        monkeypatch,
    ):
        server = UploadStubServer(temp_dir, upload_dir)
        target = upload_dir / "advanced-race.txt"
        _force_first_two_exists_checks_to_miss(monkeypatch, target)
        payloads = [b"first advanced payload", b"second advanced payload"]

        def upload(index: int):
            return server.handle_advanced_upload(
                _canonical_advanced_json_request(
                    payloads[index],
                    name="advanced-race.txt",
                )
            )

        responses = _run_two_uploads(upload)

        assert [response.status_code for response in responses] == [201, 201]
        assert [json.loads(response.body)["upload"]["kind"] for response in responses] == [
            "advanced",
            "advanced",
        ]
        saved_files = sorted(path for path in upload_dir.iterdir() if path.is_file())
        assert len(saved_files) == 2
        assert {path.read_bytes() for path in saved_files} == set(payloads)

    def test_standard_upload_rejects_aggregate_quota_without_artifacts(
        self,
        temp_dir: Path,
        upload_dir: Path,
    ):
        (upload_dir / "existing.bin").write_bytes(b"123456789")
        server = UploadStubServer(
            temp_dir,
            upload_dir,
            upload_storage_policy=UploadStoragePolicy(max_total_bytes=10),
        )

        response = server.handle_none(
            make_request(
                "POST",
                "/",
                headers={"X-File-Name": "blocked.txt"},
                body=b"xx",
            )
        )

        assert response.status_code == 507
        body = json.loads(response.body)
        assert body["error"]["code"] == "storage_quota_exceeded"
        assert body["error"]["field"] == "file"
        assert body["error"]["details"]["scope"] == "uploads"
        assert not (upload_dir / "blocked.txt").exists()
        assert _upload_temp_files(upload_dir) == []

    def test_advanced_upload_rejects_aggregate_quota_without_artifacts(
        self,
        temp_dir: Path,
        upload_dir: Path,
    ):
        (upload_dir / "existing.bin").write_bytes(b"123456789")
        server = UploadStubServer(
            temp_dir,
            upload_dir,
            upload_storage_policy=UploadStoragePolicy(max_total_bytes=10),
        )
        response = server.handle_advanced_upload(
            _canonical_advanced_json_request(
                b"xx",
                name="blocked-advanced.txt",
            )
        )

        assert response.status_code == 507
        assert json.loads(response.body)["error"]["code"] == "storage_quota_exceeded"
        assert not (upload_dir / "blocked-advanced.txt").exists()
        assert _upload_temp_files(upload_dir) == []

    def test_upload_publish_uses_hidden_same_directory_temp_file(
        self,
        temp_dir: Path,
        upload_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        server = UploadStubServer(temp_dir, upload_dir)
        original_link = storage_module.os.link
        observed_temp_paths: list[Path] = []

        def recording_link(src: str | bytes | Path, dst: str | bytes | Path) -> None:
            observed_temp_paths.append(Path(src))
            original_link(src, dst)

        monkeypatch.setattr(storage_module.os, "link", recording_link)

        response = server.handle_none(
            make_request(
                "POST",
                "/",
                headers={"X-File-Name": "atomic.txt"},
                body=b"complete payload",
            )
        )

        assert response.status_code == 201
        assert observed_temp_paths
        assert observed_temp_paths[0].parent == upload_dir
        assert observed_temp_paths[0].name.startswith(".upload-tmp-")
        assert not observed_temp_paths[0].exists()
        assert (upload_dir / "atomic.txt").read_bytes() == b"complete payload"

    def test_upload_publish_failure_removes_temp_and_final_artifacts(
        self,
        temp_dir: Path,
        upload_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        server = UploadStubServer(temp_dir, upload_dir)

        def failing_link(src: str | bytes | Path, dst: str | bytes | Path) -> None:
            raise OSError(errno.EIO, "forced publish failure")

        monkeypatch.setattr(storage_module.os, "link", failing_link)

        response = server.handle_none(
            make_request(
                "POST",
                "/",
                headers={"X-File-Name": "failed.txt"},
                body=b"payload",
            )
        )

        assert response.status_code == 500
        assert not (upload_dir / "failed.txt").exists()
        assert _upload_temp_files(upload_dir) == []
