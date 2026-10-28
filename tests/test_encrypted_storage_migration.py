"""Read-only adoption checks for old encrypted journals during an explicit migration."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from tests.test_encrypted_storage import FILE_ID, _chunk, _manifest, _service
from xferry.encrypted_storage import (
    EncryptedStorageConflict,
    EncryptedStorageService,
    prepare_legacy_encrypted_binding,
)
from xferry.storage import UploadStorageService

requires_posix = pytest.mark.skipif(
    os.name != "posix", reason="requires POSIX encrypted-state adoption guarantees"
)


def _binding(root: Path) -> Path:
    return root / ".xferry" / "encrypted-storage-root"


def _snapshot(root: Path):
    return {
        path.relative_to(root): (path.read_bytes(), path.stat().st_mode, path.stat().st_ino)
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def _legacy(root: Path, *, complete: bool = False):
    service = _service(root, clock=lambda: 1)
    manifest = _manifest()
    service.create(manifest)
    service.write_chunk(FILE_ID, 0, _chunk(manifest), b"r" * 32)
    if complete:
        service.complete(FILE_ID)
    _binding(root).unlink()
    # Native services use a private umask; normalize only our synthetic legacy
    # fixture rather than relying on the developer shell's group-writable umask.
    (root / "uploads").chmod(0o755)
    (root / ".xferry").chmod(0o755)
    return service


@pytest.mark.parametrize("complete", [False, True])
@requires_posix
def test_prepare_preserves_actual_old_journals_and_ciphertext_then_allows_explicit_startup(
    tmp_path: Path, complete: bool
) -> None:
    old = _legacy(tmp_path, complete=complete)
    before = _snapshot(tmp_path)
    folders = {path: path.stat().st_mode for path in tmp_path.rglob("*") if path.is_dir()}
    proposal = prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
    assert proposal is not None
    target, payload, uid, gid = proposal
    assert target == _binding(tmp_path)
    private = (tmp_path / ".xferry").stat()
    assert (uid, gid) == (private.st_uid, private.st_gid)
    metadata = (tmp_path / "uploads").stat()
    assert json.loads(payload) == {
        "version": 1,
        "files_dir": str(tmp_path / "uploads"),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }
    assert payload == json.dumps(json.loads(payload), sort_keys=True).encode()
    assert not target.exists()
    assert _snapshot(tmp_path) == before
    assert {path: path.stat().st_mode for path in folders} == folders
    assert (old.state_dir / f"{FILE_ID}.json").exists()

    # Only the explicit migration's writer publishes the proposal. The ordinary
    # runtime's stricter allow_legacy_adoption=False guard remains unchanged.
    target.write_bytes(payload)
    target.chmod(0o600)
    restarted = EncryptedStorageService(
        tmp_path,
        UploadStorageService(tmp_path / "uploads"),
        max_plaintext_size=32,
        incomplete_ttl=86400,
        clock=lambda: 1,
        allow_legacy_adoption=False,
    )
    assert restarted.get(FILE_ID) is not None
    assert restarted.get(FILE_ID).status == ("complete" if complete else "partial")
    assert {
        key: value
        for key, value in _snapshot(tmp_path).items()
        if key != target.relative_to(tmp_path)
    } == before
    assert prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads") is None


@requires_posix
def test_prepare_never_constructs_reconciles_or_expires_the_store(
    tmp_path: Path, monkeypatch
) -> None:
    old = _legacy(tmp_path)
    before = _snapshot(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("preparation must not instantiate or mutate the runtime store")

    monkeypatch.setattr(EncryptedStorageService, "__init__", forbidden)
    monkeypatch.setattr(EncryptedStorageService, "reconcile", forbidden)
    monkeypatch.setattr(EncryptedStorageService, "expire_incomplete", forbidden)
    assert prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads") is not None
    assert (old.state_dir / f"{FILE_ID}.json").exists()
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize("remaining", ["journal", "ciphertext"])
@requires_posix
def test_either_legacy_half_prepares_without_reading_or_removing_the_other(
    tmp_path: Path, remaining: str
) -> None:
    old = _legacy(tmp_path)
    if remaining == "journal":
        (old.data_dir / f"{FILE_ID}.part").unlink()
    else:
        (old.state_dir / f"{FILE_ID}.json").unlink()
    before = _snapshot(tmp_path)
    assert prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads") is not None
    assert _snapshot(tmp_path) == before


def test_missing_or_empty_storage_is_a_noop_without_creating_directories(tmp_path: Path) -> None:
    root = tmp_path / "absent"
    assert prepare_legacy_encrypted_binding(root, root / "uploads") is None
    assert not root.exists()
    root.mkdir()
    (root / ".xferry").mkdir(mode=0o755)
    before = list(root.rglob("*"))
    private_mode = (root / ".xferry").stat().st_mode
    assert prepare_legacy_encrypted_binding(root, root / "uploads") is None
    assert list(root.rglob("*")) == before
    assert (root / ".xferry").stat().st_mode == private_mode


@pytest.mark.parametrize("private_mode", [0o700, 0o755])
@requires_posix
def test_old_private_parent_mode_and_runtime_identity_are_preserved(
    tmp_path: Path, private_mode: int, monkeypatch
) -> None:
    _legacy(tmp_path)
    private = tmp_path / ".xferry"
    private.chmod(private_mode)
    metadata = private.stat()
    original_lstat = Path.lstat

    def metadata_with_runtime_owner(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path == private:
            values = list(info)
            values[4:6] = [1234, 2345]
            return os.stat_result(values)
        return info

    monkeypatch.setattr(Path, "lstat", metadata_with_runtime_owner)
    proposal = prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
    assert proposal is not None
    assert proposal[2:] == (1234, 2345)
    assert stat.S_IMODE(private.stat().st_mode) == private_mode
    assert (metadata.st_uid, metadata.st_gid) != (1234, 2345)


@requires_posix
def test_nonlegacy_files_folder_with_existing_journals_fails_without_changes(
    tmp_path: Path,
) -> None:
    _legacy(tmp_path)
    different = tmp_path / "different"
    different.mkdir()
    before = _snapshot(tmp_path)
    with pytest.raises(EncryptedStorageConflict, match="does not match legacy"):
        prepare_legacy_encrypted_binding(tmp_path, different)
    assert _snapshot(tmp_path) == before
    assert not _binding(tmp_path).exists()


@pytest.mark.parametrize(
    "component", ["ancestor", "state", "private", "journals", "files", "ciphertext"]
)
@requires_posix
def test_symlinked_relevant_directory_is_rejected_before_adoption(
    tmp_path: Path, component: str
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    old = _legacy(root)
    paths = {
        "state": root,
        "private": root / ".xferry",
        "journals": old.state_dir,
        "files": root / "uploads",
        "ciphertext": old.data_dir,
    }
    if component == "ancestor":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        state, files = alias, alias / "uploads"
    else:
        path = paths[component]
        moved = path.with_name(path.name + "-original")
        path.rename(moved)
        path.symlink_to(moved, target_is_directory=True)
        state, files = root, root / "uploads"
    with pytest.raises(EncryptedStorageConflict, match="unsafe"):
        prepare_legacy_encrypted_binding(state, files)
    assert not _binding(root).exists()


@pytest.mark.parametrize("component", ["state", "private", "journals", "files", "ciphertext"])
@requires_posix
def test_writable_or_nonprivate_migration_directories_fail_closed(
    tmp_path: Path, component: str
) -> None:
    old = _legacy(tmp_path)
    path = {
        "state": tmp_path,
        "private": tmp_path / ".xferry",
        "journals": old.state_dir,
        "files": tmp_path / "uploads",
        "ciphertext": old.data_dir,
    }[component]
    path.chmod(0o777 if component in {"state", "private", "files"} else 0o755)
    with pytest.raises(EncryptedStorageConflict, match="unsafe"):
        prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
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
    _service(tmp_path)
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
    with pytest.raises(EncryptedStorageConflict):
        prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
    assert target.lstat() == metadata


@requires_posix
def test_directory_identity_replacement_during_inspection_fails_without_new_binding(
    tmp_path: Path, monkeypatch
) -> None:
    old = _legacy(tmp_path)
    original_iterdir = Path.iterdir
    moved = old.data_dir.with_name("old-ciphertext")

    def swap_after_scan(path):
        entries = list(original_iterdir(path))
        if path == old.data_dir:
            path.rename(moved)
            path.mkdir(mode=0o700)
        return iter(entries)

    monkeypatch.setattr(Path, "iterdir", swap_after_scan)
    with pytest.raises((EncryptedStorageConflict, FileNotFoundError)):
        prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
    assert (moved / f"{FILE_ID}.part").exists()
    assert not _binding(tmp_path).exists()


@pytest.mark.parametrize("mode", [0o755, 0o775, 0o777])
def test_no_encrypted_state_does_not_restrict_an_unrelated_shared_folder(
    tmp_path: Path, mode: int
) -> None:
    files = tmp_path / "uploads"
    files.mkdir(mode=mode)
    files.chmod(mode)
    initial_mode = files.stat().st_mode
    (tmp_path / ".xferry").mkdir(mode=0o755)
    before = list(tmp_path.rglob("*"))
    assert prepare_legacy_encrypted_binding(tmp_path, files) is None
    assert list(tmp_path.rglob("*")) == before
    assert files.stat().st_mode == initial_mode


@pytest.mark.parametrize("capability", ["O_NOFOLLOW", "O_NONBLOCK"])
@requires_posix
def test_encrypted_migration_without_safe_open_capabilities_preserves_all_state(
    tmp_path: Path, monkeypatch, capability: str
) -> None:
    _legacy(tmp_path)
    before = _snapshot(tmp_path)
    monkeypatch.delattr(os, capability, raising=False)
    with pytest.raises(ValueError, match="unsupported on this platform"):
        prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
    assert _snapshot(tmp_path) == before
    assert not _binding(tmp_path).exists()


def test_missing_safe_capability_does_not_break_unencrypted_portable_migration(
    tmp_path: Path, monkeypatch
) -> None:
    files = tmp_path / "uploads"
    files.mkdir()
    files.chmod(0o775)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)
    assert prepare_legacy_encrypted_binding(tmp_path, files) is None
    assert not (tmp_path / ".xferry").exists()


@requires_posix
def test_binding_open_checks_flags_and_inode_before_reading_a_replaced_fifo(
    tmp_path: Path, monkeypatch
) -> None:
    _legacy(tmp_path)
    target = _binding(tmp_path)
    # Obtain exactly the proposed valid bytes without publishing from the helper.
    proposal = prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
    assert proposal is not None
    target.write_bytes(proposal[1])
    target.chmod(0o600)
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
        prepare_legacy_encrypted_binding(tmp_path, tmp_path / "uploads")
    assert len(calls) == 1
    assert calls[0] & os.O_NOFOLLOW
    assert calls[0] & os.O_NONBLOCK
    assert stat.S_ISFIFO(target.lstat().st_mode)
