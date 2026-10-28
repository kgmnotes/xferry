"""Checkpoint ownership regressions with unequal administrative and service identities."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from xferry.management.model import ManagedLayout
from xferry.management.release_configuration import ReleaseConfigurationStore


class _OwnedStat:
    def __init__(self, original: os.stat_result, uid: int, gid: int) -> None:
        self.original = original
        self.st_uid, self.st_gid = uid, gid

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)


@pytest.fixture
def managed_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Use real bytes/modes/checkpoints and a narrow ownership view without requiring root."""
    root_uid, root_gid = os.getuid(), os.getgid()
    runtime_uid, runtime_gid = root_uid + 10001, root_gid + 10001
    layout = ManagedLayout(
        config_file=tmp_path / "etc/xferry/xferry.ini",
        auth_file=tmp_path / "etc/xferry/auth",
        unit_file=tmp_path / "etc/systemd/system/xferry.service",
        data_root=tmp_path / "var/lib/xferry",
    )
    layout.config_file.parent.mkdir(parents=True, mode=0o750)
    layout.unit_file.parent.mkdir(parents=True, mode=0o755)
    layout.data_root.mkdir(parents=True, mode=0o750)
    layout.data_root.parent.chmod(0o755)
    layout.data_root.chmod(0o750)
    layout.config_file.write_bytes(b"[server]\naccess = private\n")
    layout.config_file.chmod(0o640)
    layout.unit_file.write_bytes(b"[Service]\nUser=xferry\n")
    layout.unit_file.chmod(0o644)
    layout.auth_file.write_bytes(b"admin:retained-test-password\n")
    layout.auth_file.chmod(0o400)

    original_stat, original_fstat = Path.stat, os.fstat
    owners: dict[tuple[int, int], tuple[int, int]] = {}

    def set_owner(path: Path, uid: int, gid: int = runtime_gid) -> None:
        metadata = original_stat(path, follow_symlinks=False)
        owners[metadata.st_dev, metadata.st_ino] = uid, gid

    def owned(metadata: os.stat_result) -> Any:
        identity = owners.get((metadata.st_dev, metadata.st_ino))
        return _OwnedStat(metadata, *identity) if identity else metadata

    def path_stat(path: Path, *, follow_symlinks: bool = True) -> Any:
        return owned(original_stat(path, follow_symlinks=follow_symlinks))

    def descriptor_chown(descriptor: int, uid: int, gid: int) -> None:
        metadata = original_fstat(descriptor)
        owners[metadata.st_dev, metadata.st_ino] = uid, gid

    set_owner(layout.data_root, runtime_uid)
    set_owner(layout.auth_file, runtime_uid)
    monkeypatch.setattr(Path, "stat", path_stat)
    monkeypatch.setattr(Path, "lstat", lambda path: path_stat(path, follow_symlinks=False))
    monkeypatch.setattr(os, "fstat", lambda descriptor: owned(original_fstat(descriptor)))
    monkeypatch.setattr(os, "fchown", descriptor_chown)
    return SimpleNamespace(
        layout=layout,
        store=ReleaseConfigurationStore(layout, root_uid=root_uid),
        set_owner=set_owner,
        root_uid=root_uid,
        runtime_uid=runtime_uid,
        runtime_gid=runtime_gid,
        other_uid=runtime_uid + 1,
    )


@pytest.mark.parametrize("service_owned", [False, True])
def test_auth_checkpoint_round_trip_preserves_distinct_owner_group_mode_and_bytes(
    managed_store: Any, service_owned: bool
) -> None:
    case = managed_store
    assert case.root_uid != case.runtime_uid
    uid = case.runtime_uid if service_owned else case.root_uid
    mode = 0o400 if service_owned else 0o640
    case.set_owner(case.layout.auth_file, uid)
    case.layout.auth_file.chmod(mode)
    before = case.store.capture()
    auth = before["auth"]
    assert auth is not None
    assert (auth.uid, auth.gid, auth.mode, auth.content) == (
        uid,
        case.runtime_gid,
        mode,
        b"admin:retained-test-password\n",
    )

    manifest = b"verified immutable manifest"
    case.store.save("0.2.1", manifest, before, legacy=True)
    loaded = case.store.load("0.2.1", manifest)
    assert loaded == (before, True)

    # Restoring must accept either valid owner even when the current file uses
    # the other supported representation, as a schema migration can do.
    case.layout.auth_file.chmod(0o600)
    case.layout.auth_file.write_bytes(b"admin:temporary-test-password\n")
    case.set_owner(case.layout.auth_file, case.root_uid if service_owned else case.runtime_uid)
    assert loaded is not None
    case.store.apply(loaded[0])
    assert case.store.capture() == before
    checkpoint = case.store.directory / "0.2.1.json"
    assert checkpoint.stat().st_uid == case.root_uid
    assert checkpoint.stat().st_mode & 0o777 == 0o600


def test_auth_capture_rejects_an_owner_outside_root_and_the_delegated_service(
    managed_store: Any,
) -> None:
    case = managed_store
    case.set_owner(case.layout.auth_file, case.other_uid)
    with pytest.raises(ValueError, match="authentication file owner"):
        case.store.capture()


@pytest.mark.parametrize("operation", ["apply", "save", "load"])
def test_checkpoint_rejects_an_unrelated_auth_owner_in_every_restore_boundary(
    managed_store: Any, operation: str
) -> None:
    case = managed_store
    before = case.store.capture()
    auth = before["auth"]
    assert auth is not None
    invalid = before | {"auth": replace(auth, uid=case.other_uid)}
    manifest = b"verified immutable manifest"
    if operation == "load":
        case.store.save("0.2.1", manifest, before, legacy=True)
        checkpoint = case.store.directory / "0.2.1.json"
        document = json.loads(checkpoint.read_bytes())
        document["files"]["auth"]["uid"] = case.other_uid
        checkpoint.write_text(json.dumps(document), encoding="utf-8")
    config_inode = case.layout.config_file.stat().st_ino
    with pytest.raises(ValueError, match="invalid release configuration"):
        if operation == "apply":
            case.store.apply(invalid)
        elif operation == "save":
            case.store.save("0.2.1", manifest, invalid, legacy=True)
        else:
            case.store.load("0.2.1", manifest)
    assert case.store.capture() == before
    assert case.layout.config_file.stat().st_ino == config_inode
    if operation == "save":
        assert not case.store.directory.exists()


@pytest.mark.parametrize("key", ["config", "unit", "state", "mapping"])
def test_auth_owner_exception_does_not_allow_service_owned_control_files(
    managed_store: Any, key: str
) -> None:
    case = managed_store
    path = case.store.paths[key]
    if not path.exists():
        path.write_bytes(b"{}")
    case.set_owner(path, case.runtime_uid)
    with pytest.raises(ValueError, match="unsafe release configuration file"):
        case.store.capture()


def test_checkpoint_envelope_remains_root_owned(managed_store: Any) -> None:
    case = managed_store
    manifest = b"verified immutable manifest"
    case.store.save("0.2.1", manifest, case.store.capture(), legacy=True)
    case.set_owner(case.store.directory / "0.2.1.json", case.runtime_uid)
    with pytest.raises(ValueError, match="unsafe release configuration file"):
        case.store.load("0.2.1", manifest)


@pytest.mark.parametrize(
    "unsafe",
    ["symlink", "writable", "parent-symlink", "parent-writable", "parent-owner", "missing"],
)
def test_service_auth_owner_requires_a_real_protected_runtime_directory(
    managed_store: Any, unsafe: str
) -> None:
    case = managed_store
    directory = case.layout.data_root
    if unsafe in {"symlink", "parent-symlink"}:
        path = directory if unsafe == "symlink" else directory.parent
        moved = path.with_name(path.name + "-original")
        path.rename(moved)
        path.symlink_to(moved, target_is_directory=True)
    elif unsafe == "writable":
        directory.chmod(0o770)
    elif unsafe == "parent-writable":
        directory.parent.chmod(0o775)
    elif unsafe == "parent-owner":
        case.set_owner(directory.parent, case.other_uid)
    else:
        directory.rmdir()
    with pytest.raises(ValueError, match="unsafe managed runtime directory"):
        case.store.capture()


@pytest.mark.parametrize("owner", ["root", "service", "unrelated"])
def test_encrypted_binding_keeps_its_service_only_owner_policy(
    managed_store: Any, owner: str
) -> None:
    case = managed_store
    binding = case.store.paths["encrypted_binding"]
    binding.parent.mkdir(mode=0o700)
    binding.write_bytes(b"verified encrypted binding")
    binding.chmod(0o600)
    case.set_owner(binding.parent, case.runtime_uid)
    uid = {
        "root": case.root_uid,
        "service": case.runtime_uid,
        "unrelated": case.other_uid,
    }[owner]
    case.set_owner(binding, uid)
    if owner == "service":
        saved = case.store.capture()["encrypted_binding"]
        assert saved is not None and saved.uid == case.runtime_uid
    else:
        with pytest.raises(ValueError, match="unsafe encrypted storage binding"):
            case.store.capture()
