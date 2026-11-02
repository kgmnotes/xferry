"""Fail-closed ownership binding for the current encrypted storage format."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from tests.test_encrypted_storage import FILE_ID, _chunk, _manifest, _service
from xferry.encrypted_storage import EncryptedStorageConflict, EncryptedStorageService

requires_posix = pytest.mark.skipif(os.name != "posix", reason="requires POSIX file identities")


def _binding(root: Path) -> Path:
    return root / ".xferry" / "encrypted-storage-root"


def _snapshot(root: Path):
    return {
        path.relative_to(root): (path.read_bytes(), path.stat().st_mode, path.stat().st_ino)
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


@pytest.mark.parametrize("complete", [False, True])
def test_current_bound_store_restarts_without_changing_journals_or_ciphertext(
    tmp_path: Path, complete: bool
) -> None:
    service = _service(tmp_path, clock=lambda: 1)
    manifest = _manifest()
    service.create(manifest)
    service.write_chunk(FILE_ID, 0, _chunk(manifest), b"r" * 32)
    if complete:
        service.complete(FILE_ID)
    before = _snapshot(tmp_path)
    restarted = _service(tmp_path, clock=lambda: 2)
    assert restarted.get(FILE_ID).status == ("complete" if complete else "partial")
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize("remaining", ["journal", "ciphertext", "both"])
@pytest.mark.parametrize("complete", [False, True])
def test_missing_binding_refuses_existing_data_without_reconciliation_or_expiry(
    tmp_path: Path, remaining: str, complete: bool, monkeypatch
) -> None:
    service = _service(tmp_path, clock=lambda: 1)
    manifest = _manifest()
    service.create(manifest)
    service.write_chunk(FILE_ID, 0, _chunk(manifest), b"r" * 32)
    if complete:
        service.complete(FILE_ID)
    _binding(tmp_path).unlink()
    if remaining == "journal":
        (service.data_dir / f"{FILE_ID}.{'xfr' if complete else 'part'}").unlink()
    elif remaining == "ciphertext":
        (service.state_dir / f"{FILE_ID}.json").unlink()
    before = _snapshot(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("unbound data must be rejected before reconciliation or expiry")

    monkeypatch.setattr(EncryptedStorageService, "reconcile", forbidden)
    monkeypatch.setattr(EncryptedStorageService, "expire_incomplete", forbidden)
    with pytest.raises(EncryptedStorageConflict, match="files_dir"):
        _service(tmp_path, clock=lambda: 999999)
    assert _snapshot(tmp_path) == before
    assert not _binding(tmp_path).exists()


@pytest.mark.parametrize(
    "kind",
    [
        "corrupt",
        "mismatch",
        "symlink",
        "hardlink",
        "fifo",
        "oversized",
        "duplicate",
        "boolean-version",
        "public-mode",
    ],
)
@requires_posix
def test_existing_unsafe_or_mismatched_binding_is_never_overwritten(
    tmp_path: Path, kind: str
) -> None:
    service = _service(tmp_path)
    service.create(_manifest())
    target = _binding(tmp_path)
    payload = target.read_bytes()
    if kind == "corrupt":
        target.write_bytes(b"not JSON")
    elif kind == "mismatch":
        value = json.loads(payload)
        value["inode"] += 1
        target.write_text(json.dumps(value))
    elif kind == "symlink":
        target.unlink()
        secret = tmp_path / "unrelated"
        secret.write_bytes(payload)
        target.symlink_to(secret)
    elif kind == "hardlink":
        os.link(target, tmp_path / "other-binding")
    elif kind == "fifo":
        target.unlink()
        os.mkfifo(target, 0o600)
    elif kind == "oversized":
        target.write_bytes(b" " * 4097)
    elif kind == "duplicate":
        target.write_bytes(payload[:-1] + b', "version": 1}')
    elif kind == "boolean-version":
        value = json.loads(payload)
        value["version"] = True
        target.write_text(json.dumps(value))
    else:
        target.chmod(0o644)
    metadata = target.lstat()
    preserved_payload = target.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
    preserved_link = target.readlink() if stat.S_ISLNK(metadata.st_mode) else None
    if preserved_payload is not None:
        # Reading under relatime should exercise atime changes without relying
        # on the operation crossing a wall-clock second.
        os.utime(target, ns=(1, metadata.st_mtime_ns))
    metadata = target.lstat()
    with pytest.raises(EncryptedStorageConflict):
        _service(tmp_path)
    after = target.lstat()
    for field in (
        "st_mode",
        "st_ino",
        "st_dev",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    ):
        assert getattr(after, field) == getattr(metadata, field), field
    if preserved_payload is not None:
        assert target.read_bytes() == preserved_payload
    if preserved_link is not None:
        assert target.readlink() == preserved_link


@requires_posix
def test_binding_open_checks_identity_before_reading_a_replaced_fifo(
    tmp_path: Path, monkeypatch
) -> None:
    service = _service(tmp_path)
    service.create(_manifest())
    target = _binding(tmp_path)
    original_open = os.open
    calls = []

    def swap_before_open(path, flags, *args, **kwargs):
        if Path(path) == target:
            calls.append(flags)
            target.unlink()
            os.mkfifo(target, 0o600)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_before_open)
    with pytest.raises(EncryptedStorageConflict, match="binding changed"):
        _service(tmp_path)
    assert len(calls) == 1
    assert calls[0] & os.O_NOFOLLOW
    assert calls[0] & os.O_NONBLOCK
    assert stat.S_ISFIFO(target.lstat().st_mode)
    assert (service.state_dir / f"{FILE_ID}.json").exists()
    assert (service.data_dir / f"{FILE_ID}.part").exists()


def test_ciphertext_directory_replacement_during_binding_inspection_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    service = _service(tmp_path)
    service.create(_manifest())
    before = _binding(tmp_path).read_bytes()
    original_iterdir = Path.iterdir
    moved = service.data_dir.with_name("original-ciphertext")

    def swap_after_scan(path):
        entries = list(original_iterdir(path))
        if path == service.data_dir:
            path.rename(moved)
            path.mkdir(mode=0o700)
        return iter(entries)

    monkeypatch.setattr(Path, "iterdir", swap_after_scan)
    with pytest.raises(EncryptedStorageConflict, match="binding changed"):
        _service(tmp_path)
    assert (moved / f"{FILE_ID}.part").exists()
    assert (service.state_dir / f"{FILE_ID}.json").exists()
    assert _binding(tmp_path).read_bytes() == before
