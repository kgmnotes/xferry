"""Resource admission, automatic limits, and large-transfer journal boundaries."""

from __future__ import annotations

import errno
import json
import threading
from pathlib import Path
from queue import Queue
from types import SimpleNamespace

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from tests.test_encrypted_api import _complete, _create, _manifest, _put_chunk
from xferry.cli import create_parser
from xferry.encrypted_storage import (
    EncryptedStorageService,
    EncryptedStoredChunk,
    EncryptedStoredFile,
)
from xferry.encrypted_transfer import metadata_aad
from xferry.settings import ServerSettings, load_settings_file, resolve_settings
from xferry.storage import UploadStorageQuotaExceeded, UploadStorageService

GIB = 1024**3
MIB = 1024**2


def capacity(server) -> dict:
    response = server._dispatch_handler(make_request("GET", "/_xferry/encrypted-uploads"))
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    return json.loads(response.body)["storage"]


def test_manifest_above_two_gib_preserves_integer_size_in_authenticated_context() -> None:
    manifest = _manifest(plaintext_size=3 * GIB + 1)
    assert manifest.chunk_count == 385
    assert int.from_bytes(metadata_aad(manifest)[-16:-8], "big") == 3 * GIB + 1


@pytest.mark.parametrize("size_mb", [0, 8192, 32768])
def test_operator_limits_accept_automatic_and_large_sizes(size_mb: int) -> None:
    namespace = create_parser().parse_args(["--encrypted-upload-max-size", str(size_mb)])
    settings = resolve_settings(cli_values={"encrypted_upload_max_size_mb": size_mb})
    assert namespace.encrypted_upload_max_size == size_mb
    assert settings.to_server_config().limits.encrypted_upload_max_size == (
        size_mb * MIB if size_mb else 32 * GIB
    )


@pytest.mark.parametrize(
    ("disk_free", "expected_maximum"),
    [
        (4 * GIB, 4 * GIB - 512 * 16),
        (8 * GIB, 8 * GIB - 1024 * 16),
        (32 * GIB, 8 * GIB - 1024 * 16),
    ],
)
def test_default_auto_advertises_available_quota_not_an_arbitrary_per_file_limit(
    tmp_path, monkeypatch, disk_free: int, expected_maximum: int
) -> None:
    monkeypatch.setattr(
        "xferry.storage.shutil.disk_usage", lambda _: SimpleNamespace(free=disk_free)
    )
    settings = ServerSettings(encrypted_uploads=True, upload_storage_limit_mb=8192)
    config = settings.to_server_config()
    from dataclasses import replace

    from xferry.server import XFerryServer

    server = XFerryServer(replace(config, root_dir=tmp_path))
    maximum = server.get_encrypted_upload_capabilities()["max_plaintext_size"]
    assert maximum == expected_maximum
    assert settings.encrypted_upload_max_size_mb == 0


def test_capacity_counts_ordinary_files_and_full_partial_reservations(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("xferry.storage.shutil.disk_usage", lambda _: SimpleNamespace(free=GIB))
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        upload_storage_limit=37,
        upload_file_limit=4,
    )
    (server.upload_dir / "ordinary.bin").write_bytes(b"regular")
    before = capacity(server)
    assert before["available_bytes"] == 30
    assert before["max_plaintext_size"] == 14
    assert before["remaining_files"] == 3
    assert _create(server, _manifest()).status_code == 201
    after = capacity(server)
    assert after["used_bytes"] == 28
    assert after["available_bytes"] == 9
    assert after["remaining_files"] == 2
    assert server.get_encrypted_upload_capabilities()["max_plaintext_size"] == 0
    denied = _create(server, _manifest(file_id="f" * 32))
    assert denied.status_code == 507
    assert json.loads(denied.body)["error"]["details"]["reason"] == "bytes"
    assert capacity(server)["used_bytes"] == 28


def test_full_file_quota_rejects_empty_files_but_allows_identical_create_retry(tmp_path) -> None:
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        upload_file_limit=1,
    )
    manifest = _manifest(plaintext_size=0)
    assert _create(server, manifest).status_code == 201
    assert capacity(server)["remaining_files"] == 0
    assert capacity(server)["max_plaintext_size"] == 0
    assert _create(server, manifest).status_code == 200
    denied = _create(server, _manifest(file_id="f" * 32, plaintext_size=0))
    assert denied.status_code == 507
    assert json.loads(denied.body)["error"]["details"]["reason"] == "files"


def test_free_space_admission_accounts_for_sparse_partial_promises(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "xferry.storage.shutil.disk_usage", lambda _: SimpleNamespace(free=100 * MIB)
    )

    def no_fallocate(*_):
        raise OSError(errno.EOPNOTSUPP, "unsupported")

    monkeypatch.setattr("xferry.encrypted_storage.os.posix_fallocate", no_fallocate)
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        upload_reserved_free_space=10 * MIB,
    )
    assert _create(server, _manifest(plaintext_size=64 * MIB)).status_code == 201
    assert capacity(server)["available_bytes"] == 26 * MIB - 128
    denied = _create(server, _manifest(file_id="f" * 32, plaintext_size=40 * MIB))
    assert denied.status_code == 507
    assert json.loads(denied.body)["error"]["details"]["reason"] == "free_space"


def test_maximum_file_journal_roundtrips_with_maximum_encrypted_metadata(tmp_path) -> None:
    manifest = _manifest(plaintext_size=32 * GIB, encrypted_metadata=b"m" * 4112)
    chunks = tuple(
        EncryptedStoredChunk(index, 8388624, b"r" * 32, b"h" * 32) for index in range(4096)
    )
    record = EncryptedStoredFile(manifest, "complete", chunks, 1.0, 2.0)
    raw = EncryptedStorageService._record_to_json(record)
    assert len(raw) < 1024 * 1024
    service = EncryptedStorageService(
        tmp_path,
        UploadStorageService(tmp_path / "uploads"),
        max_plaintext_size=32 * GIB,
        incomplete_ttl=604800,
    )
    service._write_state(record)
    decoded = service.get(manifest.file_id)
    assert decoded == record
    with pytest.raises(ValueError):
        _manifest(plaintext_size=32 * GIB + 1)


def test_approved_large_file_profile_is_loadable_and_has_resource_controls() -> None:
    settings = load_settings_file(Path(__file__).parents[1] / "examples" / "large-files.ini")
    config = settings.to_server_config()
    assert config.encrypted_uploads is True
    assert config.limits.upload_storage_limit == 24 * GIB
    assert config.limits.upload_reserved_free_space == 4 * GIB
    assert config.limits.upload_file_limit == 4096
    assert config.limits.encrypted_upload_incomplete_ttl == 604800
    assert config.limits.max_workers >= 2


def test_lower_new_upload_limit_does_not_hide_completed_or_partial_files(tmp_path) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    completed = _manifest()
    partial = _manifest(file_id="f" * 32)
    assert _create(server, completed).status_code == 201
    assert _put_chunk(server, completed, b"c" * 21).status_code == 201
    assert _complete(server).status_code == 200
    assert _create(server, partial).status_code == 201
    restarted = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        encrypted_upload_max_size=1,
    )
    for collection, manifest in [("encrypted-files", completed), ("encrypted-uploads", partial)]:
        response = restarted._dispatch_handler(
            make_request("GET", f"/_xferry/{collection}/{manifest.file_id}")
        )
        assert response.status_code == 200
    assert _put_chunk(restarted, partial, b"c" * 21).status_code == 201
    assert _complete(restarted, partial.file_id).status_code == 200


def test_startup_posture_describes_auto_limit_instead_of_a_zero_byte_allowance() -> None:
    from xferry.runtime_posture import derive_runtime_posture

    posture = derive_runtime_posture(ServerSettings(encrypted_uploads=True))
    description = "\n".join(posture.render_lines())
    assert "max: automatic" in description
    assert "max: 0 MB" not in description


def test_identical_create_retry_survives_a_lower_operator_ceiling(tmp_path) -> None:
    first = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    manifest = _manifest()
    assert _create(first, manifest).status_code == 201
    restarted = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        encrypted_upload_max_size=1,
    )
    assert _create(restarted, manifest).status_code == 200
    assert _create(restarted, _manifest(file_id="f" * 32)).status_code == 400


def test_partial_deleted_during_scan_does_not_break_ordinary_upload(tmp_path, monkeypatch) -> None:
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        upload_reserved_free_space=1,
    )
    assert _create(server, _manifest()).status_code == 201
    original_glob = Path.glob

    def discovered_then_deleted(directory, pattern):
        discovered = list(original_glob(directory, pattern))
        if directory == server.encrypted_storage.data_dir and pattern == "*.part" and discovered:
            server.encrypted_storage.delete("00112233445566778899aabbccddeeff")
        yield from discovered

    monkeypatch.setattr(Path, "glob", discovered_then_deleted)
    published = server.upload_storage.publish_bytes(server.upload_dir / "ordinary.bin", b"new")
    assert published.read_bytes() == b"new"
    assert not list(server.upload_dir.glob(".upload-tmp-*"))


def test_sparse_chunk_write_cannot_inflate_capacity_snapshot(tmp_path, monkeypatch) -> None:
    def no_fallocate(*_):
        raise OSError(errno.EOPNOTSUPP, "unsupported")

    monkeypatch.setattr("xferry.encrypted_storage.os.posix_fallocate", no_fallocate)
    monkeypatch.setattr(
        "xferry.storage.shutil.disk_usage", lambda _: SimpleNamespace(free=64 * MIB)
    )
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    manifest = _manifest()
    assert _create(server, manifest).status_code == 201
    part = server.encrypted_storage.data_dir / f"{manifest.file_id}.part"
    assert part.stat().st_blocks == 0
    original_lock = server.upload_storage._lock
    signal = Queue()
    errors: list[BaseException] = []

    class ObservedLock:
        def __enter__(self):
            if threading.current_thread().name == "capacity-chunk":
                signal.put("lock-attempt")
            return original_lock.__enter__()

        def __exit__(self, *args):
            return original_lock.__exit__(*args)

    def write_chunk():
        try:
            server.encrypted_storage.write_chunk(manifest.file_id, 0, b"c" * 21, b"r" * 32)
        except BaseException as exc:
            errors.append(exc)
        finally:
            signal.put("write-finished")

    worker = threading.Thread(target=write_chunk, name="capacity-chunk")

    def free_before_concurrent_write(_):
        free = 64 * MIB - part.stat().st_blocks * 512
        worker.start()
        signal.get(timeout=5)
        return SimpleNamespace(free=free)

    monkeypatch.setattr(server.upload_storage, "_lock", ObservedLock())
    monkeypatch.setattr("xferry.storage.shutil.disk_usage", free_before_concurrent_write)
    try:
        snapshot = server.upload_storage.capacity()
    finally:
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert not errors
    assert snapshot["available_bytes"] == 64 * MIB - 21


def test_auto_admission_checks_disk_even_without_a_free_space_reserve(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("xferry.storage.shutil.disk_usage", lambda _: SimpleNamespace(free=8 * MIB))

    def no_fallocate(*_):
        raise OSError(errno.EOPNOTSUPP, "unsupported")

    monkeypatch.setattr("xferry.encrypted_storage.os.posix_fallocate", no_fallocate)
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    assert server.get_encrypted_upload_capabilities()["max_plaintext_size"] == 8 * MIB - 16
    denied = _create(server, _manifest(plaintext_size=64 * MIB))
    assert denied.status_code == 507
    assert json.loads(denied.body)["error"]["details"]["reason"] == "free_space"
    assert not list(server.encrypted_storage.data_dir.iterdir())


def test_completion_during_usage_scan_cannot_admit_an_upload_above_quota(
    tmp_path, monkeypatch
) -> None:
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        upload_storage_limit=42,
        upload_reserved_free_space=1,
    )
    manifests = [_manifest(), _manifest(file_id="f" * 32)]
    for manifest in manifests:
        assert _create(server, manifest).status_code == 201
        assert _put_chunk(server, manifest, b"c" * 21).status_code == 201

    original_lock = server.upload_storage._lock
    original_rglob = Path.rglob
    signals: dict[str, Queue] = {}
    workers: list[threading.Thread] = []
    errors: list[BaseException] = []
    pending = [manifest.file_id for manifest in manifests]

    class ObservedLock:
        def __enter__(self):
            signal = signals.get(threading.current_thread().name)
            if signal is not None:
                # Let the scan continue when completion attempts the shared
                # lock; without that lock, wait until the real rename finishes.
                signal.put("lock-attempt")
            return original_lock.__enter__()

        def __exit__(self, *args):
            return original_lock.__exit__(*args)

    def finish(file_id, signal):
        try:
            server.encrypted_storage.complete(file_id)
        except BaseException as exc:
            errors.append(exc)
        finally:
            signal.put("completion-finished")

    def scan_with_concurrent_completion(directory, pattern):
        discovered = list(original_rglob(directory, pattern))
        target = pending[0] if directory == server.upload_dir and pending else None
        for path in discovered:
            if target is not None and path.name == f"{target}.part":
                pending.pop(0)
                signal = Queue()
                name = f"capacity-commit-{target}"
                signals[name] = signal
                worker = threading.Thread(target=finish, args=(target, signal), name=name)
                workers.append(worker)
                worker.start()
                signal.get(timeout=5)
                target = None
            yield path

    monkeypatch.setattr(server.upload_storage, "_lock", ObservedLock())
    monkeypatch.setattr(Path, "rglob", scan_with_concurrent_completion)
    try:
        with pytest.raises(UploadStorageQuotaExceeded) as denied:
            server.upload_storage.publish_bytes(server.upload_dir / "ordinary.bin", b"x")
        assert denied.value.reason == "bytes"
    finally:
        for worker in workers:
            worker.join(timeout=5)
        assert all(not worker.is_alive() for worker in workers)
        assert not errors
    monkeypatch.setattr(Path, "rglob", original_rglob)
    assert server.upload_storage.current_usage().total_bytes == 42
    assert not (server.upload_dir / "ordinary.bin").exists()
    assert not list(server.upload_dir.glob(".upload-tmp-*"))
