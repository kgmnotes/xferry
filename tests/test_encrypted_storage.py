"""Crash-safety, quota, and visibility tests for encrypted-file storage."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.encrypted_storage import (
    EncryptedStorageConflict,
    EncryptedStorageIncomplete,
    EncryptedStorageService,
)
from xferry.encrypted_transfer import EUF_CHUNK_SIZE, EncryptedTransferManifest
from xferry.storage import (
    UploadStoragePolicy,
    UploadStorageQuotaExceeded,
    UploadStorageService,
)

FILE_ID = "00112233445566778899aabbccddeeff"
SECOND_FILE_ID = "ffeeddccbbaa99887766554433221100"


def _manifest(
    *,
    file_id: str = FILE_ID,
    plaintext_size: int = 5,
    encrypted_metadata: bytes = b"m" * 16,
) -> EncryptedTransferManifest:
    chunk_count = (plaintext_size + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE
    return EncryptedTransferManifest(
        file_id=file_id,
        plaintext_size=plaintext_size,
        chunk_size=EUF_CHUNK_SIZE,
        chunk_count=chunk_count,
        salt=bytes(range(16)),
        nonce_prefix=bytes(range(8)),
        encrypted_metadata=encrypted_metadata,
    )


def _service(
    root: Path,
    *,
    policy: UploadStoragePolicy | None = None,
    ttl: float = 86400,
    clock=None,
) -> EncryptedStorageService:
    upload_dir = root / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_storage = UploadStorageService(upload_dir, policy)
    return EncryptedStorageService(
        root,
        upload_storage,
        max_plaintext_size=2048 * 1024 * 1024,
        incomplete_ttl=ttl,
        clock=clock,
    )


def _chunk(manifest: EncryptedTransferManifest, index: int = 0, fill: bytes = b"c") -> bytes:
    plaintext_length = min(
        manifest.chunk_size,
        manifest.plaintext_size - index * manifest.chunk_size,
    )
    return fill * (plaintext_length + 16)


def test_create_reserves_hidden_ciphertext_and_is_idempotent(tmp_path: Path) -> None:
    service = _service(tmp_path)
    manifest = _manifest()

    created = service.create(manifest)
    repeated = service.create(manifest)

    assert created.created is True
    assert repeated.created is False
    assert repeated.file == created.file
    assert created.file.status == "partial"
    assert created.file.received_chunks == ()
    assert service.data_dir == tmp_path / "uploads" / ".xferry-encrypted"
    assert service.state_dir == tmp_path / ".xferry" / "encrypted-uploads"
    assert (service.data_dir / f"{FILE_ID}.part").stat().st_size == manifest.ciphertext_size
    assert stat.S_IMODE(service.data_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(service.state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((service.state_dir / f"{FILE_ID}.json").stat().st_mode) == 0o600
    assert not list(service.state_dir.glob("*.tmp"))

    usage = service.upload_storage.current_usage()
    assert usage.total_bytes == manifest.ciphertext_size
    assert usage.file_count == 1


def test_create_rejects_same_id_with_conflicting_manifest(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.create(_manifest())

    with pytest.raises(EncryptedStorageConflict):
        service.create(_manifest(encrypted_metadata=b"x" * 16))


@pytest.mark.parametrize(
    "policy",
    [
        UploadStoragePolicy(max_total_bytes=20),
        UploadStoragePolicy(max_file_count=0),
    ],
)
def test_create_obeys_shared_upload_quota_without_leaking_reservations(
    tmp_path: Path,
    policy: UploadStoragePolicy,
) -> None:
    service = _service(tmp_path, policy=policy)

    with pytest.raises(UploadStorageQuotaExceeded):
        service.create(_manifest())

    assert not list(service.data_dir.iterdir())
    assert not list(service.state_dir.iterdir())
    assert service.upload_storage.current_usage().total_bytes == 0


def test_chunk_write_is_durable_idempotent_and_conflict_safe(tmp_path: Path) -> None:
    service = _service(tmp_path)
    manifest = _manifest()
    service.create(manifest)
    ciphertext = _chunk(manifest)
    resume_mac = b"r" * 32

    first = service.write_chunk(FILE_ID, 0, ciphertext, resume_mac)
    repeated = service.write_chunk(FILE_ID, 0, ciphertext, resume_mac)

    assert first.stored is True
    assert repeated.stored is False
    assert first.file.received_chunks == repeated.file.received_chunks
    assert first.file.received_chunks[0].index == 0
    assert first.file.received_chunks[0].resume_mac == resume_mac
    assert (service.data_dir / f"{FILE_ID}.part").read_bytes() == ciphertext
    persisted = json.loads((service.state_dir / f"{FILE_ID}.json").read_text("utf-8"))
    assert persisted["received_chunks"]["0"]["resume_mac"]
    assert not list(service.state_dir.glob("*.tmp"))

    with pytest.raises(EncryptedStorageConflict):
        service.write_chunk(FILE_ID, 0, b"d" * len(ciphertext), resume_mac)
    with pytest.raises(EncryptedStorageConflict):
        service.write_chunk(FILE_ID, 0, ciphertext, b"s" * 32)


def test_complete_requires_every_chunk_and_is_idempotent(tmp_path: Path) -> None:
    service = _service(tmp_path)
    manifest = _manifest()
    service.create(manifest)

    with pytest.raises(EncryptedStorageIncomplete):
        service.complete(FILE_ID)

    service.write_chunk(FILE_ID, 0, _chunk(manifest), b"r" * 32)
    completed = service.complete(FILE_ID)
    repeated = service.complete(FILE_ID)

    assert completed.completed is True
    assert repeated.completed is False
    assert repeated.file.status == "complete"
    assert not (service.data_dir / f"{FILE_ID}.part").exists()
    assert (service.data_dir / f"{FILE_ID}.xfr").is_file()
    assert service.list_files(status="partial") == ()
    assert service.list_files(status="complete") == (repeated.file,)


def test_delete_removes_data_and_state_for_partial_or_complete_files(tmp_path: Path) -> None:
    service = _service(tmp_path)
    partial = _manifest()
    complete = _manifest(file_id=SECOND_FILE_ID, plaintext_size=0)
    service.create(partial)
    service.create(complete)
    service.complete(SECOND_FILE_ID)

    assert service.delete(FILE_ID) is True
    assert service.delete(SECOND_FILE_ID) is True
    assert service.delete(SECOND_FILE_ID) is False
    assert list(service.data_dir.iterdir()) == []
    assert list(service.state_dir.iterdir()) == []


def test_expiry_removes_only_inactive_partial_uploads(tmp_path: Path) -> None:
    now = [1000.0]
    service = _service(tmp_path, ttl=60, clock=lambda: now[0])
    service.create(_manifest())
    service.create(_manifest(file_id=SECOND_FILE_ID, plaintext_size=0))
    service.complete(SECOND_FILE_ID)

    now[0] += 61
    expired = service.expire_incomplete()

    assert expired == (FILE_ID,)
    assert service.get(FILE_ID) is None
    assert service.get(SECOND_FILE_ID).status == "complete"


def test_expired_partial_is_removed_lazily_when_it_is_accessed(tmp_path: Path) -> None:
    now = [1000.0]
    service = _service(tmp_path, ttl=60, clock=lambda: now[0])
    service.create(_manifest())

    now[0] += 61

    assert service.get(FILE_ID) is None
    assert not (service.data_dir / f"{FILE_ID}.part").exists()
    assert not (service.state_dir / f"{FILE_ID}.json").exists()


def test_list_files_lazily_removes_expired_partials(tmp_path: Path) -> None:
    now = [1000.0]
    service = _service(tmp_path, ttl=60, clock=lambda: now[0])
    service.create(_manifest())

    now[0] += 61

    assert service.list_files() == ()
    assert not (service.data_dir / f"{FILE_ID}.part").exists()
    assert not (service.state_dir / f"{FILE_ID}.json").exists()


def test_create_reclaims_other_expired_partial_before_quota_admission(tmp_path: Path) -> None:
    now = [1000.0]
    ciphertext_size = _manifest().ciphertext_size
    service = _service(
        tmp_path,
        policy=UploadStoragePolicy(max_total_bytes=ciphertext_size),
        ttl=60,
        clock=lambda: now[0],
    )
    service.create(_manifest())

    now[0] += 61
    replacement = service.create(_manifest(file_id=SECOND_FILE_ID))

    assert replacement.created is True
    assert service.get(FILE_ID) is None
    assert service.upload_storage.current_usage().total_bytes == ciphertext_size


def test_restart_reconciles_rename_completed_before_final_state_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    manifest = _manifest()
    service.create(manifest)
    service.write_chunk(FILE_ID, 0, _chunk(manifest), b"r" * 32)
    real_write_state = service._write_state

    def fail_final_state(record) -> None:
        if record.status == "complete":
            raise OSError("simulated crash after rename")
        real_write_state(record)

    monkeypatch.setattr(service, "_write_state", fail_final_state)
    with pytest.raises(OSError, match="simulated crash"):
        service.complete(FILE_ID)

    assert (service.data_dir / f"{FILE_ID}.xfr").exists()
    persisted = json.loads((service.state_dir / f"{FILE_ID}.json").read_text("utf-8"))
    assert persisted["status"] == "committing"

    restarted = _service(tmp_path)

    assert restarted.get(FILE_ID).status == "complete"
    reconciled = json.loads((restarted.state_dir / f"{FILE_ID}.json").read_text("utf-8"))
    assert reconciled["status"] == "complete"


def test_restart_does_not_delete_ciphertext_when_reconciliation_io_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path)
    manifest = _manifest()
    service.create(manifest)
    service.write_chunk(FILE_ID, 0, _chunk(manifest), b"r" * 32)
    real_write_state = service._write_state

    def fail_first_final_state(record) -> None:
        if record.status == "complete":
            raise OSError("simulated crash after rename")
        real_write_state(record)

    monkeypatch.setattr(service, "_write_state", fail_first_final_state)
    with pytest.raises(OSError):
        service.complete(FILE_ID)

    xfr_path = service.data_dir / f"{FILE_ID}.xfr"
    state_path = service.state_dir / f"{FILE_ID}.json"
    assert xfr_path.exists() and state_path.exists()

    def fail_recovery_state(_self, _record) -> None:
        raise OSError("temporary state filesystem failure")

    monkeypatch.setattr(EncryptedStorageService, "_write_state", fail_recovery_state)

    with pytest.raises(OSError, match="temporary state filesystem failure"):
        _service(tmp_path)

    assert xfr_path.exists()
    assert state_path.exists()


def test_restart_removes_orphan_partial_data_without_a_sidecar(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    data_dir = upload_dir / ".xferry-encrypted"
    data_dir.mkdir(parents=True)
    orphan = data_dir / f"{FILE_ID}.part"
    orphan.write_bytes(b"orphan")

    service = _service(tmp_path)

    assert not orphan.exists()
    assert service.list_files() == ()


def test_server_accounts_hidden_data_but_ordinary_operations_cannot_reach_it(
    tmp_path: Path,
) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    manifest = _manifest()
    server.encrypted_storage.create(manifest)

    usage = server.upload_storage.current_usage()
    assert usage.total_bytes == manifest.ciphertext_size
    assert usage.file_count == 1

    hidden_path = f"/uploads/.xferry-encrypted/{FILE_ID}.part"
    assert server._dispatch_handler(make_request("GET", hidden_path)).status_code == 404
    assert server._dispatch_handler(make_request("INFO", hidden_path)).status_code == 404
    assert server._dispatch_handler(make_request("DELETE", hidden_path)).status_code == 404

    cleared = server._dispatch_handler(make_request("DELETE", "/uploads?clear=true"))
    assert cleared.status_code == 200
    assert (server.encrypted_storage.data_dir / f"{FILE_ID}.part").exists()
    assert server.handler_context.encrypted_storage is server.encrypted_storage
