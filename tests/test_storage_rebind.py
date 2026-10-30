"""Offline snapshot validation must precede any encrypted-directory rebinding."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from tests.test_encrypted_storage import FILE_ID, _chunk, _manifest, _service
from xferry.config import __version__
from xferry.encrypted_storage import EncryptedStorageConflict, EncryptedStorageService
from xferry.management import storage_rebind
from xferry.management.storage_rebind import StorageRebindError, rebind_storage

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux offline rebind")


def _snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        str(path.relative_to(root)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def _copy(tmp_path: Path, status: str = "partial") -> tuple[Path, Path, Path]:
    original = tmp_path / "original"
    service = _service(original, clock=lambda: 1)
    for path in (original, original / "uploads", original / ".xferry"):
        path.chmod(0o700)
    manifest = _manifest()
    service.create(manifest)
    service.write_chunk(FILE_ID, 0, _chunk(manifest), b"r" * 32)
    if status == "complete":
        service.complete(FILE_ID)
    elif status == "committing":
        journal = service.state_dir / f"{FILE_ID}.json"
        payload = json.loads(journal.read_text())
        payload["status"] = "committing"
        journal.write_text(json.dumps(payload))
    restored = tmp_path / "restored"
    shutil.copytree(original, restored)
    version_file = tmp_path / "xferry-version.txt"
    version_file.write_text(f"xferry {__version__}\n")
    version_file.chmod(0o600)
    return original, restored, version_file


def _binding(root: Path) -> Path:
    return root / ".xferry" / "encrypted-storage-root"


@pytest.mark.parametrize("status", ["partial", "complete", "committing"])
def test_validate_then_apply_changes_only_binding_and_preserves_source(tmp_path, status):
    original, restored, version_file = _copy(tmp_path, status)
    source_before, target_before = _snapshot(original), _snapshot(restored)
    result = rebind_storage(restored, restored / "uploads", version_file)
    assert result["status"] == "rebind_required"
    assert result["applied"] is False
    assert result["records"][status] == 1
    assert result["verified_chunks"] == 1
    assert _snapshot(restored) == target_before

    result = rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert result["status"] == "applied"
    assert _snapshot(original) == source_before
    new = _snapshot(restored)
    changed = {key for key in new if new[key] != target_before[key]}
    assert changed == {".xferry/encrypted-storage-root"}
    assert stat.S_IMODE(_binding(restored).stat().st_mode) == 0o600
    expected = (restored / "uploads").stat()
    assert json.loads(_binding(restored).read_bytes()) == {
        "version": 1,
        "files_dir": str(restored / "uploads"),
        "device": expected.st_dev,
        "inode": expected.st_ino,
    }
    before_noop = _binding(restored).stat().st_ino
    assert (
        rebind_storage(restored, restored / "uploads", version_file, apply=True)["status"]
        == "verified"
    )
    assert _binding(restored).stat().st_ino == before_noop

    restarted = _service(restored, clock=lambda: 1)
    assert restarted.get(FILE_ID).status == ("complete" if status == "committing" else status)


def test_runtime_still_refuses_a_new_inode_until_explicit_apply(tmp_path):
    _original, restored, version_file = _copy(tmp_path)
    with pytest.raises(EncryptedStorageConflict, match="files_dir does not match"):
        _service(restored, clock=lambda: 1)
    rebind_storage(restored, restored / "uploads", version_file)
    with pytest.raises(EncryptedStorageConflict, match="files_dir does not match"):
        _service(restored, clock=lambda: 1)


def test_rebind_keeps_partial_timestamps_and_startup_applies_original_expiry(tmp_path):
    _original, restored, version_file = _copy(tmp_path)
    journal = restored / ".xferry" / "encrypted-uploads" / f"{FILE_ID}.json"
    before = journal.read_bytes()
    rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert journal.read_bytes() == before
    restarted = _service(restored, ttl=10, clock=lambda: 100)
    assert restarted.get(FILE_ID) is None
    assert not journal.exists()


def test_committing_final_payload_validates_without_finishing_commit(tmp_path):
    _original, restored, version_file = _copy(tmp_path, "committing")
    data = restored / "uploads" / ".xferry-encrypted"
    (data / f"{FILE_ID}.part").rename(data / f"{FILE_ID}.xfr")
    journal = restored / ".xferry" / "encrypted-uploads" / f"{FILE_ID}.json"
    before = journal.read_bytes()
    rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert journal.read_bytes() == before
    assert json.loads(before)["status"] == "committing"
    restarted = _service(restored, clock=lambda: 1)
    assert restarted.get(FILE_ID).status == "complete"


def test_validator_never_constructs_reconciles_or_expires_runtime_store(tmp_path, monkeypatch):
    _original, restored, version_file = _copy(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("offline inspection instantiated or reconciled runtime storage")

    for method in ("__init__", "reconcile", "expire_incomplete"):
        monkeypatch.setattr(EncryptedStorageService, method, forbidden)
    result = rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert result["status"] == "applied"


@pytest.mark.parametrize(
    "damage",
    [
        "orphan",
        "missing",
        "truncated",
        "hash",
        "schema",
        "unknown_entry",
        "both_payloads",
        "invalid_status",
    ],
)
def test_corrupt_copy_fails_before_binding_change_or_cleanup(tmp_path, damage):
    original, restored, version_file = _copy(tmp_path)
    data = restored / "uploads" / ".xferry-encrypted" / f"{FILE_ID}.part"
    journal = restored / ".xferry" / "encrypted-uploads" / f"{FILE_ID}.json"
    if damage == "orphan":
        journal.unlink()
    elif damage == "missing":
        data.unlink()
    elif damage == "truncated":
        data.write_bytes(b"short")
    elif damage == "hash":
        data.write_bytes(b"x" * data.stat().st_size)
    elif damage in {"schema", "invalid_status"}:
        payload = json.loads(journal.read_bytes())
        payload["schema_version" if damage == "schema" else "status"] = (
            999 if damage == "schema" else []
        )
        journal.write_text(json.dumps(payload))
    elif damage == "unknown_entry":
        (journal.parent / "interrupted.tmp").write_bytes(b"unfinished")
    elif damage == "both_payloads":
        shutil.copy2(data, data.with_suffix(".xfr"))
    target_before, source_before = _snapshot(restored), _snapshot(original)
    with pytest.raises(StorageRebindError) as error:
        rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert error.value.exit_code == 3
    assert _snapshot(restored) == target_before
    assert _snapshot(original) == source_before


@pytest.mark.parametrize("location", ["journal", "payload", "binding", "parent"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_link_substitutions_are_rejected(tmp_path, location, kind):
    _original, restored, version_file = _copy(tmp_path)
    paths = {
        "journal": restored / ".xferry" / "encrypted-uploads" / f"{FILE_ID}.json",
        "payload": restored / "uploads" / ".xferry-encrypted" / f"{FILE_ID}.part",
        "binding": _binding(restored),
        "parent": restored / "uploads",
    }
    path = paths[location]
    if location == "parent" and kind == "hardlink":
        pytest.skip("directory hard links are not supported")
    external = tmp_path / "external"
    path.rename(external)
    if kind == "symlink":
        path.symlink_to(external, target_is_directory=location == "parent")
    else:
        os.link(external, path)
    before = _binding(restored).read_bytes()
    with pytest.raises(StorageRebindError):
        rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert _binding(restored).read_bytes() == before


def test_version_is_captured_exactly_and_failures_are_redacted(tmp_path, capsys):
    _original, restored, version_file = _copy(tmp_path)
    version_file.write_text("xferry 0.0.0\n")
    before = _snapshot(restored)
    status = storage_rebind.main(
        [
            "--state-root",
            str(restored),
            "--files-dir",
            str(restored / "uploads"),
            "--snapshot-version-file",
            str(version_file),
            "--apply",
            "--json",
        ]
    )
    assert status == 2
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["code"] == "version_mismatch"
    assert str(tmp_path) not in json.dumps(receipt)
    assert _snapshot(restored) == before


def test_public_state_overlap_and_writable_private_directories_are_rejected(tmp_path):
    _original, restored, version_file = _copy(tmp_path)
    with pytest.raises(StorageRebindError, match="outside"):
        rebind_storage(restored, restored, version_file)
    (restored / ".xferry" / "encrypted-uploads").chmod(0o770)
    with pytest.raises(StorageRebindError, match="permissions"):
        rebind_storage(restored, restored / "uploads", version_file, apply=True)


def test_changed_directory_identity_during_apply_fails_without_new_binding(tmp_path, monkeypatch):
    _original, restored, version_file = _copy(tmp_path)
    original_recheck = storage_rebind._Snapshot.recheck
    checks = 0
    before = _binding(restored).read_bytes()

    def replace_before_publish(snapshot):
        nonlocal checks
        checks += 1
        if checks == 2:
            (restored / "uploads").rename(restored / "saved-uploads")
            (restored / "uploads").mkdir()
        original_recheck(snapshot)

    monkeypatch.setattr(storage_rebind._Snapshot, "recheck", replace_before_publish)
    with pytest.raises(StorageRebindError) as error:
        rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert error.value.code == "snapshot_changed"
    assert error.value.exit_code == 4
    assert _binding(restored).read_bytes() == before
    assert not list((restored / ".xferry").glob("*.tmp"))


@pytest.mark.parametrize("change", ["modify", "add"])
def test_changed_payload_or_added_journal_during_apply_cannot_publish(
    tmp_path, monkeypatch, change
):
    _original, restored, version_file = _copy(tmp_path)
    original_recheck = storage_rebind._Snapshot.recheck
    before = _binding(restored).read_bytes()
    checks = 0

    def change_before_publish(snapshot):
        nonlocal checks
        checks += 1
        if checks == 2:
            if change == "modify":
                data = restored / "uploads" / ".xferry-encrypted" / f"{FILE_ID}.part"
                data.write_bytes(b"changed after hashing")
            else:
                (restored / ".xferry" / "encrypted-uploads" / "extra.json").write_text("{}")
        original_recheck(snapshot)

    monkeypatch.setattr(storage_rebind._Snapshot, "recheck", change_before_publish)
    with pytest.raises(StorageRebindError) as error:
        rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert error.value.code == "snapshot_changed"
    assert _binding(restored).read_bytes() == before


def test_failed_replace_keeps_original_binding(tmp_path, monkeypatch):
    _original, restored, version_file = _copy(tmp_path)
    before = _snapshot(restored)

    def fail_replace(*_args, **_kwargs):
        raise OSError("injected rename failure")

    monkeypatch.setattr(storage_rebind.os, "replace", fail_replace)
    with pytest.raises(StorageRebindError) as error:
        rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert error.value.code == "publication_failed"
    assert error.value.exit_code == 4
    assert _snapshot(restored) == before


def test_failed_binding_write_keeps_original_binding(tmp_path, monkeypatch):
    _original, restored, version_file = _copy(tmp_path)
    before = _snapshot(restored)

    def fail_write(*_args, **_kwargs):
        raise OSError("injected write failure")

    monkeypatch.setattr(storage_rebind.os, "write", fail_write)
    with pytest.raises(StorageRebindError) as error:
        rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert error.value.code == "publication_failed"
    assert _snapshot(restored) == before


@pytest.mark.parametrize("failure_call", [1, 2])
def test_fsync_failure_reports_whether_binding_publication_is_uncertain(
    tmp_path, monkeypatch, failure_call
):
    original, restored, version_file = _copy(tmp_path)
    before, source_before = _binding(restored).read_bytes(), _snapshot(original)
    original_fsync = os.fsync
    calls = 0

    def fail_fsync(descriptor):
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise OSError("injected fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(storage_rebind.os, "fsync", fail_fsync)
    with pytest.raises(StorageRebindError) as error:
        rebind_storage(restored, restored / "uploads", version_file, apply=True)
    assert error.value.exit_code == 4
    assert error.value.code == (
        "publication_failed" if failure_call == 1 else "publication_uncertain"
    )
    assert (_binding(restored).read_bytes() == before) is (failure_call == 1)
    assert _snapshot(original) == source_before


def test_unsupported_platform_rejected_before_reading_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(storage_rebind.sys, "platform", "win32")
    with pytest.raises(StorageRebindError) as error:
        rebind_storage(tmp_path / "absent", tmp_path / "files", tmp_path / "version")
    assert error.value.code == "unsupported_platform"
    assert error.value.exit_code == 2


def test_linux_double_slash_alias_has_runtime_canonical_binding(tmp_path):
    _original, restored, version_file = _copy(tmp_path)
    alias = Path("/" + str(restored))
    result = rebind_storage(alias, alias / "uploads", version_file, apply=True)
    assert result["status"] == "applied"
    assert json.loads(_binding(restored).read_bytes())["files_dir"] == str(restored / "uploads")
    assert _service(restored, clock=lambda: 1).get(FILE_ID) is not None
    with pytest.raises(StorageRebindError, match="outside"):
        rebind_storage(alias, restored, version_file)


@pytest.mark.parametrize("location", ["journal", "binding"])
def test_deeply_nested_json_is_a_redacted_snapshot_failure(tmp_path, capsys, location):
    _original, restored, version_file = _copy(tmp_path)
    target = (
        _binding(restored)
        if location == "binding"
        else restored / ".xferry" / "encrypted-uploads" / f"{FILE_ID}.json"
    )
    target.write_bytes(b"[" * 1500 + b"0" + b"]" * 1500)
    before = _snapshot(restored)
    exit_code = storage_rebind.main(
        [
            "--state-root",
            str(restored),
            "--files-dir",
            str(restored / "uploads"),
            "--snapshot-version-file",
            str(version_file),
            "--apply",
            "--json",
        ]
    )
    output = capsys.readouterr()
    assert exit_code == 3
    assert json.loads(output.out)["status"] == "error"
    assert "Traceback" not in output.err
    assert str(tmp_path) not in output.out
    assert _snapshot(restored) == before
