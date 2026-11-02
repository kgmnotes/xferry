"""Secret publication and host-folder access guarantees of the init container."""

from __future__ import annotations

import os
import stat
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from xferry.management import docker_init, ownership


def _secret_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    source, target, files = tmp_path / "source-auth", tmp_path / "volume/auth", tmp_path / "files"
    source.write_bytes(b"operator:long-secret:with-colon\n")
    files.mkdir()
    files.chmod(0o777)
    (files / "keep.txt").write_text("operator-owned content")
    return source, target, files


def _simulate_container_ownership(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int]]:
    ownership = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: ownership.append((uid, gid)))
    monkeypatch.setattr(os, "fchown", lambda descriptor, uid, gid: ownership.append((uid, gid)))
    return ownership


def _acl_entries(payload: bytes) -> list[tuple[int, int, int]]:
    assert struct.unpack_from("<I", payload)[0] == 2
    return [struct.unpack_from("<HHI", payload, offset) for offset in range(4, len(payload), 8)]


def test_initialize_publishes_a_private_secret_without_changing_accessible_host_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, target, files = _secret_paths(tmp_path)
    before = files.stat()
    ownership = _simulate_container_ownership(monkeypatch)
    docker_init.initialize(source, target, files, host_uid=os.getuid())
    assert target.read_bytes() == source.read_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == 0o400
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert ownership == [(10001, 10001), (10001, 10001)]
    assert (files.stat().st_mode, files.stat().st_uid, files.stat().st_gid) == (
        before.st_mode,
        before.st_uid,
        before.st_gid,
    )
    assert (files / "keep.txt").read_text() == "operator-owned content"
    assert not list(target.parent.glob(".auth-*"))


@pytest.mark.parametrize("failure", ["flush", "publication"])
def test_failed_secret_publication_keeps_the_previous_credential_and_cleans_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    source, target, files = _secret_paths(tmp_path)
    target.parent.mkdir()
    target.write_text("admin:previous-secret\n")
    target.chmod(0o400)
    _simulate_container_ownership(monkeypatch)
    if failure == "flush":

        def fail_flush(_descriptor):
            raise OSError("secret volume is full")

        monkeypatch.setattr(os, "fsync", fail_flush)
    else:
        original_replace = Path.replace

        def fail_publication(path, destination):
            if destination == target:
                raise OSError("secret volume became read-only")
            return original_replace(path, destination)

        monkeypatch.setattr(Path, "replace", fail_publication)
    with pytest.raises(OSError):
        docker_init.initialize(source, target, files, host_uid=os.getuid())
    assert target.read_text() == "admin:previous-secret\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o400
    assert source.read_bytes() == b"operator:long-secret:with-colon\n"
    assert not list(target.parent.glob(".auth-*"))


@pytest.mark.parametrize(
    ("uid", "gid", "mode", "requires_acl"),
    [
        (10001, 123, 0o700, False),
        (123, 10001, 0o770, False),
        (123, 456, 0o707, False),
        (123, 456, 0o700, True),
        (10001, 456, 0o577, True),
        (123, 10001, 0o757, True),
    ],
)
def test_initializer_uses_the_runtime_identity_permission_class(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    uid: int,
    gid: int,
    mode: int,
    requires_acl: bool,
) -> None:
    source, target, files = _secret_paths(tmp_path)
    original_stat = Path.stat

    def container_stat(path, *args, **kwargs):
        if path == files:
            return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=stat.S_IFDIR | mode)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", container_stat)
    _simulate_container_ownership(monkeypatch)
    monkeypatch.setattr(
        os, "setxattr", lambda *_: pytest.fail("initializer must not modify host ACLs")
    )
    docker_init.initialize(source, target, files, host_uid=88)
    assert target.read_bytes() == source.read_bytes()


@pytest.mark.parametrize("kind", ["missing", "regular-file", "symlink"])
def test_initializer_rejects_unsafe_host_folder_before_publishing_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    source, target, files = _secret_paths(tmp_path)
    selected = tmp_path / "unsafe-folder"
    if kind == "regular-file":
        selected.write_text("unrelated")
    elif kind == "symlink":
        selected.symlink_to(files, target_is_directory=True)
    monkeypatch.setattr(
        os, "chown", lambda *_: pytest.fail("unsafe folder changed secret ownership")
    )
    with pytest.raises(ValueError, match="real directory"):
        docker_init.initialize(source, target, selected, host_uid=88)
    assert not target.parent.exists()
    assert (files / "keep.txt").read_text() == "operator-owned content"


@pytest.mark.parametrize(
    "credential",
    [
        b"",
        b"missing-separator\n",
        b"user:secret\nsecond:line\n",
        b"user:secret\0\n",
        b"user:\xff\n",
    ],
)
def test_invalid_source_secret_never_replaces_the_usable_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, credential: bytes
) -> None:
    source, target, files = _secret_paths(tmp_path)
    source.write_bytes(credential)
    target.parent.mkdir()
    target.write_text("admin:previous-secret\n")
    monkeypatch.setattr(os, "chown", lambda *_: pytest.fail("invalid secret changed ownership"))
    with pytest.raises((ValueError, UnicodeError)):
        docker_init.initialize(source, target, files, host_uid=88)
    assert target.read_text() == "admin:previous-secret\n"
    assert not list(target.parent.glob(".auth-*"))


@pytest.mark.parametrize("raw", [b"\x02", struct.pack("<I", 1), struct.pack("<I", 2) + b"invalid"])
def test_malformed_existing_acl_is_preserved_instead_of_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    monkeypatch.setattr(os, "getxattr", lambda *_: raw)
    monkeypatch.setattr(os, "setxattr", lambda *_: pytest.fail("malformed ACL was overwritten"))
    with pytest.raises(ValueError, match="unsupported POSIX ACL"):
        ownership._grant(raw, 0o750, 10001)


def test_acl_creation_keeps_unrelated_permissions() -> None:
    entries = _acl_entries(ownership._grant(None, 0o750, 10001))
    assert (2, 7, 10001) in entries
    assert (4, 5, 0xFFFFFFFF) in entries and (32, 0, 0xFFFFFFFF) in entries


def test_runtime_owned_folder_updates_owner_permission_without_duplicate_access_grant() -> None:
    runtime_uid = os.getuid()
    access = _acl_entries(ownership._grant(None, 0o500, runtime_uid, owner_uid=runtime_uid))
    assert (1, 7, 0xFFFFFFFF) in access
    assert not any(tag == 2 and identity == runtime_uid for tag, _, identity in access)
    assert (32, 0, 0xFFFFFFFF) in access


def test_initializer_does_not_change_host_access_even_when_it_is_restricted(tmp_path, monkeypatch):
    source, target, files = _secret_paths(tmp_path)
    files.chmod(0o700)
    _simulate_container_ownership(monkeypatch)
    before = files.stat()
    monkeypatch.setattr(
        os, "setxattr", lambda *_: pytest.fail("host ACL must be managed with a receipt")
    )
    docker_init.initialize(source, target, files, host_uid=88)
    assert files.stat() == before
    assert target.read_bytes() == source.read_bytes()


def test_init_cli_success_passes_only_the_fixed_mounts_and_host_identity(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = []
    monkeypatch.setattr("sys.argv", ["xferry-init", "--host-uid", "88"])
    monkeypatch.setattr(docker_init, "initialize", lambda *args: calls.append(args))
    assert docker_init.main() == 0
    assert calls == [(Path("/source/auth"), Path("/secrets/xferry_auth"), Path("/host-files"), 88)]
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "failure",
    [
        OSError("private-volume:secret"),
        ValueError("inline-private-secret"),
        UnicodeError("bad-private-secret"),
    ],
)
def test_init_cli_errors_are_actionable_without_disclosing_private_material(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failure: Exception
) -> None:
    monkeypatch.setattr("sys.argv", ["xferry-init", "--host-uid", "88"])

    def failed_initialization(*_args):
        raise failure

    monkeypatch.setattr(docker_init, "initialize", failed_initialization)
    assert docker_init.main() == 1
    output = capsys.readouterr()
    assert "ACL support" in output.out and "auth permissions" in output.out
    assert str(failure) not in output.out + output.err
