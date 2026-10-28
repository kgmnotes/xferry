"""Private deployment checkpoints for a verified cross-schema release switch."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .model import ManagedLayout

_LIMITS = {
    "config": 1024 * 1024,
    "unit": 65536,
    "auth": 16384,
    "state": 16384,
    "mapping": 65536,
    "encrypted_binding": 4096,
}
_MAX_SNAPSHOT = 2 * 1024 * 1024


@dataclass(frozen=True)
class DeploymentFile:
    content: bytes = field(repr=False)
    mode: int
    uid: int
    gid: int


Deployment = dict[str, DeploymentFile | None]


def _read_file(path: Path, limit: int, *, owner: int) -> DeploymentFile | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != owner
        or metadata.st_size > limit
    ):
        raise ValueError("unsafe release configuration file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("release configuration changed during inspection")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("release configuration exceeds the supported size limit")
    return DeploymentFile(content, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid)


def _atomic_write(path: Path, value: DeploymentFile) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value.content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), value.mode)
            current = os.fstat(stream.fileno())
            if (current.st_uid, current.st_gid) != (value.uid, value.gid):
                os.fchown(stream.fileno(), value.uid, value.gid)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _binding_parent(path: Path, *, owner: int) -> Iterator[int | None]:
    """Pin the service-owned parent so a renamed/symlinked path cannot redirect root."""
    try:
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        yield None
        return
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != owner or metadata.st_mode & 0o022:
            raise ValueError("unsafe encrypted storage binding directory")
        named = path.parent.lstat()
        if (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("encrypted storage binding directory changed")
        yield descriptor
        named = path.parent.lstat()
        if (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("encrypted storage binding directory changed")
    finally:
        os.close(descriptor)


def _read_binding(path: Path, *, owner: int) -> DeploymentFile | None:
    with _binding_parent(path, owner=owner) as parent:
        if parent is None:
            return None
        try:
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != owner
                or metadata.st_nlink != 1
                or metadata.st_size > 4096
            ):
                raise ValueError("unsafe encrypted storage binding")
            content = stream.read(4097)
        if len(content) > 4096:
            raise ValueError("encrypted storage binding exceeds its size limit")
        return DeploymentFile(
            content, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid
        )


def apply_encrypted_binding(path: Path, value: DeploymentFile | None, *, owner: int) -> None:
    """Publish or undo only the fixed binding entry through its held parent descriptor."""
    with _binding_parent(path, owner=owner) as parent:
        if parent is None:
            if value is not None:
                raise ValueError("encrypted storage binding parent is missing")
            return
        try:
            metadata = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or metadata.st_nlink != 1
            or metadata.st_size > 4096
        ):
            raise ValueError("unsafe encrypted storage binding")
        if value is None:
            if metadata is not None:
                os.unlink(path.name, dir_fd=parent)
            return
        if value.uid != owner or value.mode != 0o600 or len(value.content) > 4096:
            raise ValueError("invalid encrypted storage binding identity")
        temporary = f".encrypted-binding-{secrets.token_hex(12)}"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value.content)
                stream.flush()
                os.fsync(stream.fileno())
                current = os.fstat(stream.fileno())
                if (current.st_uid, current.st_gid) != (value.uid, value.gid):
                    os.fchown(stream.fileno(), value.uid, value.gid)
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


class ReleaseConfigurationStore:
    """Read only known managed paths; never accept paths from a saved checkpoint."""

    def __init__(self, layout: ManagedLayout, *, root_uid: int = 0) -> None:
        self.root_uid = root_uid
        self.paths = {
            "config": layout.config_file,
            "unit": layout.unit_file,
            "auth": layout.auth_file,
            "state": layout.config_file.with_name(f".{layout.config_file.name}.state.json"),
            "mapping": layout.config_file.parent / "deployment.json",
            "encrypted_binding": layout.data_root / ".xferry/encrypted-storage-root",
        }
        self.directory = layout.config_file.parent / "release-configs"
        self.data_root = layout.data_root

    def _owner(self, key: str) -> int:
        if key != "encrypted_binding":
            return self.root_uid
        parent = self.paths[key].parent
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            return self.root_uid
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o022
            or metadata.st_uid != self.data_root.stat().st_uid
        ):
            raise ValueError("unsafe encrypted storage binding directory")
        return metadata.st_uid

    def _read(self, key: str) -> DeploymentFile | None:
        if key == "encrypted_binding":
            return _read_binding(self.paths[key], owner=self._owner(key))
        return _read_file(self.paths[key], _LIMITS[key], owner=self.root_uid)

    def capture(self) -> Deployment:
        return {key: self._read(key) for key in self.paths}

    def apply(self, deployment: Deployment) -> None:
        if set(deployment) != set(self.paths):
            raise ValueError("invalid release configuration checkpoint")
        for key, path in self.paths.items():
            self._read(key)
            value = deployment[key]
            if key == "encrypted_binding":
                apply_encrypted_binding(path, value, owner=self._owner(key))
                continue
            if value is None:
                path.unlink(missing_ok=True)
            else:
                if value.uid != self._owner(key) or len(value.content) > _LIMITS[key]:
                    raise ValueError("invalid release configuration identity")
                _atomic_write(path, value)

    def _path(self, version: str) -> Path:
        from .versions import is_supported_release_version

        if not is_supported_release_version(version):
            raise ValueError("invalid checkpoint release version")
        return self.directory / f"{version}.json"

    def _check_directory(self, *, create: bool = False) -> bool:
        try:
            metadata = self.directory.lstat()
        except FileNotFoundError:
            if not create:
                return False
            self.directory.mkdir(mode=0o700)
            metadata = self.directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.root_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("unsafe release configuration checkpoint directory")
        return True

    def load(self, version: str, manifest: bytes) -> tuple[Deployment, bool] | None:
        if not self._check_directory():
            return None
        value = _read_file(self._path(version), _MAX_SNAPSHOT, owner=self.root_uid)
        if value is None:
            return None
        if value.mode != 0o600:
            raise ValueError("unsafe release configuration checkpoint permissions")
        try:
            document = json.loads(value.content)
            if (
                not isinstance(document, dict)
                or document.get("schema") != 1
                or document.get("version") != version
                or document.get("manifest_sha256") != hashlib.sha256(manifest).hexdigest()
                or type(document.get("legacy")) is not bool
                or not isinstance(document.get("files"), dict)
                or set(document["files"]) != set(self.paths)
            ):
                raise ValueError
            deployment: Deployment = {}
            for key, item in document["files"].items():
                if item is None:
                    deployment[key] = None
                    continue
                if not isinstance(item, dict) or set(item) != {"content", "mode", "uid", "gid"}:
                    raise ValueError
                content = base64.b64decode(item["content"], validate=True)
                mode, uid, gid = item["mode"], item["uid"], item["gid"]
                if (
                    any(type(number) is not int for number in (mode, uid, gid))
                    or not 0 <= mode <= 0o777
                    or uid != self._owner(key)
                    or gid < 0
                    or len(content) > _LIMITS[key]
                ):
                    raise ValueError
                deployment[key] = DeploymentFile(content, mode, uid, gid)
            if deployment["config"] is None or deployment["unit"] is None:
                raise ValueError
            return deployment, document["legacy"]
        except (TypeError, KeyError, ValueError, UnicodeError) as exc:
            raise ValueError("invalid release configuration checkpoint") from exc

    def save(self, version: str, manifest: bytes, deployment: Deployment, *, legacy: bool) -> None:
        self._check_directory(create=True)
        # An existing checkpoint must belong to the same verified immutable release.
        self.load(version, manifest)
        files = {
            key: None
            if value is None
            else {
                "content": base64.b64encode(value.content).decode("ascii"),
                "mode": value.mode,
                "uid": value.uid,
                "gid": value.gid,
            }
            for key, value in deployment.items()
        }
        content = (
            json.dumps(
                {
                    "schema": 1,
                    "version": version,
                    "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                    "legacy": legacy,
                    "files": files,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()
        if len(content) > _MAX_SNAPSHOT:
            raise ValueError("release configuration checkpoint exceeds its size limit")
        _atomic_write(
            self._path(version), DeploymentFile(content, 0o600, self.root_uid, os.getgid())
        )

    def remove(self, version: str) -> None:
        if self._check_directory():
            _read_file(self._path(version), _MAX_SNAPSHOT, owner=self.root_uid)
            self._path(version).unlink(missing_ok=True)
