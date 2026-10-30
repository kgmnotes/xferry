"""Validate a cold encrypted-storage copy and explicitly bind its new directory.

This maintenance module never constructs the runtime storage service: startup
reconciliation may delete incomplete or corrupt copies. Stop all writers and
operate on an isolated restored copy in the final runtime mount namespace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

from xferry.config import __version__
from xferry.encrypted_storage import (
    EncryptedStorageError,
    EncryptedStoredFile,
    decode_encrypted_state,
)
from xferry.encrypted_transfer import EUF_GCM_TAG_SIZE, file_id_bytes

_BINDING_NAME = "encrypted-storage-root"
_MAX_JOURNAL_BYTES = 1024 * 1024
_READ_BLOCK = 1024 * 1024


class StorageRebindError(Exception):
    """A redacted maintenance failure with a stable exit status."""

    def __init__(self, code: str, message: str, exit_code: int = 3) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True)
class _FileWitness:
    parent: Path
    name: str
    metadata: os.stat_result


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (*_identity(value), value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _absolute(path: Path) -> Path:
    candidate = path.expanduser()
    if ".." in candidate.parts:
        raise StorageRebindError("unsafe_path", "Parent traversal is not accepted.")
    # Linux resolves //path exactly as /path; pathlib preserves the former.
    # Normalize lexically so alias paths cannot bypass the overlap check or
    # produce a binding that differs from the runtime's resolved path.
    return Path("/" + str(candidate.absolute()).lstrip("/"))


def _require_platform() -> None:
    if (
        not sys.platform.startswith("linux")
        or any(not getattr(os, flag, 0) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
        or not all(fn in os.supports_dir_fd for fn in (os.open, os.stat, os.unlink, os.rename))
        or os.listdir not in os.supports_fd
        or not hasattr(os, "pread")
    ):
        raise StorageRebindError(
            "unsupported_platform",
            "Offline storage rebind requires Linux/POSIX file operations.",
            2,
        )


class _Snapshot(AbstractContextManager["_Snapshot"]):
    """Open no-follow directory descriptors and witness every inspected object."""

    def __init__(self) -> None:
        self.directories: dict[Path, tuple[int, os.stat_result]] = {}
        self.files: dict[Path, _FileWitness] = {}
        self.listings: dict[Path, tuple[str, ...]] = {}

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for descriptor, _metadata in reversed(tuple(self.directories.values())):
            os.close(descriptor)

    def directory(self, path: Path) -> tuple[int, os.stat_result]:
        path = _absolute(path)
        current = Path(path.anchor)
        if current not in self.directories:
            descriptor = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.directories[current] = (descriptor, os.fstat(descriptor))
        for component in path.parts[1:]:
            parent = current
            current /= component
            if current in self.directories:
                continue
            descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self.directories[parent][0],
            )
            self.directories[current] = (descriptor, os.fstat(descriptor))
        return self.directories[current]

    def private_directory(
        self, path: Path, *, owner: tuple[int, int], exact_mode: bool = False
    ) -> None:
        _descriptor, metadata = self.directory(path)
        if (
            (metadata.st_uid, metadata.st_gid) != owner
            or metadata.st_mode & 0o022
            or (exact_mode and stat.S_IMODE(metadata.st_mode) != 0o700)
        ):
            raise StorageRebindError(
                "unsafe_permissions", "Restore private-directory ownership and permissions first."
            )

    def names(self, path: Path) -> tuple[str, ...]:
        descriptor, _metadata = self.directory(path)
        names = tuple(sorted(os.listdir(descriptor)))  # noqa: PTH208 - list the validated dir-fd
        self.listings[path] = names
        return names

    @contextmanager
    def regular_file(
        self,
        path: Path,
        *,
        owner: tuple[int, int] | None = None,
        private: bool = True,
        maximum: int | None = None,
    ) -> Iterator[int]:
        path = _absolute(path)
        parent_fd, _parent_metadata = self.directory(path.parent)
        before = os.stat(  # noqa: PTH116 - relative no-follow stat anchors the opened parent
            path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (maximum is not None and before.st_size > maximum)
            or (private and stat.S_IMODE(before.st_mode) != 0o600)
            or before.st_mode & 0o022
            or (owner is not None and (before.st_uid, before.st_gid) != owner)
        ):
            raise StorageRebindError("unsafe_file", "Snapshot contains an unsafe file or metadata.")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        try:
            if _file_identity(os.fstat(descriptor)) != _file_identity(before):
                raise StorageRebindError(
                    "snapshot_changed", "Snapshot changed during inspection.", 4
                )
            yield descriptor
            if _file_identity(os.fstat(descriptor)) != _file_identity(before):
                raise StorageRebindError(
                    "snapshot_changed", "Snapshot changed during inspection.", 4
                )
            self.files[path] = _FileWitness(path.parent, path.name, before)
        finally:
            os.close(descriptor)

    def read(
        self,
        path: Path,
        *,
        maximum: int,
        owner: tuple[int, int] | None = None,
        private: bool = True,
    ) -> bytes:
        with self.regular_file(path, maximum=maximum, owner=owner, private=private) as descriptor:
            payload = bytearray()
            while len(payload) <= maximum:
                chunk = os.read(descriptor, min(_READ_BLOCK, maximum + 1 - len(payload)))
                if not chunk:
                    return bytes(payload)
                payload.extend(chunk)
            raise StorageRebindError("invalid_snapshot", "Snapshot metadata exceeds its limit.")

    def recheck(self) -> None:
        """Detect replaced parents, changed files and added or removed records."""
        try:
            for path, (_descriptor, original) in self.directories.items():
                if _identity(path.lstat()) != _identity(original):
                    raise OSError("directory identity changed")
            for path, names in self.listings.items():
                current_names = os.listdir(self.directories[path][0])  # noqa: PTH208 - anchored fd
                if tuple(sorted(current_names)) != names:
                    raise OSError("directory contents changed")
            for witness in self.files.values():
                current = os.stat(  # noqa: PTH116 - preserve the validated parent descriptor
                    witness.name,
                    dir_fd=self.directories[witness.parent][0],
                    follow_symlinks=False,
                )
                if _file_identity(current) != _file_identity(witness.metadata):
                    raise OSError("file changed")
        except OSError as exc:
            raise StorageRebindError(
                "snapshot_changed", "Snapshot changed during inspection.", 4
            ) from exc


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate binding field")
        result[name] = value
    return result


def _binding(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_object_pairs)
        if (
            not isinstance(value, dict)
            or set(value) != {"version", "files_dir", "device", "inode"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or not isinstance(value["files_dir"], str)
            or not Path(value["files_dir"]).is_absolute()
            or type(value["device"]) is not int
            or type(value["inode"]) is not int
            or value["device"] < 0
            or value["inode"] < 0
        ):
            raise ValueError("invalid binding")
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise StorageRebindError(
            "invalid_binding", "Snapshot binding is malformed or unsupported."
        ) from exc
    return dict(value)


def _verify_payload(
    snapshot: _Snapshot,
    path: Path,
    record: EncryptedStoredFile,
    owner: tuple[int, int],
) -> int:
    with snapshot.regular_file(path, owner=owner) as descriptor:
        if os.fstat(descriptor).st_size != record.manifest.ciphertext_size:
            raise StorageRebindError("invalid_payload", "Encrypted payload has the wrong size.")
        for chunk in record.received_chunks:
            digest = hashlib.sha256()
            offset = chunk.index * (record.manifest.chunk_size + EUF_GCM_TAG_SIZE)
            remaining = chunk.length
            while remaining:
                data = os.pread(descriptor, min(remaining, _READ_BLOCK), offset)
                if not data:
                    raise StorageRebindError("invalid_payload", "Encrypted payload is truncated.")
                digest.update(data)
                remaining -= len(data)
                offset += len(data)
            if digest.digest() != chunk.ciphertext_sha256:
                raise StorageRebindError(
                    "hash_mismatch", "A recorded ciphertext chunk failed verification."
                )
    return len(record.received_chunks)


def _publish_binding(snapshot: _Snapshot, path: Path, payload: bytes) -> None:
    parent_fd, parent_metadata = snapshot.directory(path.parent)
    temporary = f".{path.name}.{secrets.token_hex(12)}.tmp"
    published = False
    created = False
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (metadata.st_uid, metadata.st_gid) != (parent_metadata.st_uid, parent_metadata.st_gid):
            os.fchown(descriptor, parent_metadata.st_uid, parent_metadata.st_gid)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short binding write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        snapshot.recheck()
        os.replace(  # noqa: PTH105 - atomic publication relative to the validated parent
            temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
        )
        published = True
        os.fsync(parent_fd)
    except OSError as exc:
        code = "publication_uncertain" if published else "publication_failed"
        message = (
            "Binding was replaced but durability is uncertain; run validation again before startup."
            if published
            else "Binding publication failed; preserve the copy and repeat validation."
        )
        raise StorageRebindError(code, message, 4) from exc
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if created and not published:
            try:
                os.unlink(temporary, dir_fd=parent_fd)  # noqa: PTH108 - descriptor-relative cleanup
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise StorageRebindError(
                    "publication_cleanup_failed",
                    "Temporary binding cleanup failed; inspect the isolated copy before retrying.",
                    4,
                ) from exc


def rebind_storage(
    state_root: Path,
    files_dir: Path,
    snapshot_version_file: Path,
    *,
    apply: bool = False,
) -> dict[str, Any]:
    """Validate every encrypted object, optionally publish only the new binding.

    The caller must stop all writers and isolate the restored copy. There is no
    cross-process runtime lock, and this function does not claim to establish
    offline status. Client keys and unacknowledged chunk bytes are not validated.
    """
    _require_platform()
    state_root, files_dir = _absolute(state_root), _absolute(files_dir)
    if state_root == files_dir or state_root.is_relative_to(files_dir):
        raise StorageRebindError(
            "unsafe_layout", "Private state must be outside the public files folder."
        )
    private = state_root / ".xferry"
    journals = private / "encrypted-uploads"
    ciphertext = files_dir / ".xferry-encrypted"
    target = private / _BINDING_NAME
    try:
        with _Snapshot() as snapshot:
            version_raw = snapshot.read(
                _absolute(snapshot_version_file), maximum=256, private=False
            )
            if version_raw != f"xferry {__version__}\n".encode("ascii"):
                raise StorageRebindError(
                    "version_mismatch",
                    "Snapshot and recovery package must have the same exact version.",
                    2,
                )
            _private_fd, private_metadata = snapshot.directory(private)
            owner = (private_metadata.st_uid, private_metadata.st_gid)
            if os.geteuid() != owner[0]:
                raise StorageRebindError(
                    "wrong_owner", "Run as the owner of the restored private state."
                )
            for path in (state_root, private, files_dir):
                snapshot.private_directory(path, owner=owner)
            for path in (journals, ciphertext):
                snapshot.private_directory(path, owner=owner, exact_mode=True)
            old_binding = _binding(snapshot.read(target, maximum=4096, owner=owner))
            _files_fd, files_metadata = snapshot.directory(files_dir)
            new_binding: dict[str, object] = {
                "version": 1,
                "files_dir": str(files_dir),
                "device": files_metadata.st_dev,
                "inode": files_metadata.st_ino,
            }
            journal_names = snapshot.names(journals)
            data_names = set(snapshot.names(ciphertext))
            expected_data: set[str] = set()
            counts = {"partial": 0, "committing": 0, "complete": 0}
            verified_chunks = 0
            for name in journal_names:
                if not name.endswith(".json"):
                    raise StorageRebindError(
                        "unexpected_record", "Snapshot contains an unexpected journal entry."
                    )
                file_id = name.removesuffix(".json")
                file_id_bytes(file_id)
                record = decode_encrypted_state(
                    snapshot.read(journals / name, maximum=_MAX_JOURNAL_BYTES, owner=owner),
                    expected_file_id=file_id,
                )
                part, complete = f"{file_id}.part", f"{file_id}.xfr"
                present = {part, complete} & data_names
                if len(present) != 1:
                    raise StorageRebindError(
                        "unmatched_payload", "Each journal must have exactly one payload."
                    )
                payload_name = next(iter(present))
                if (record.status == "partial" and payload_name != part) or (
                    record.status == "complete" and payload_name != complete
                ):
                    raise StorageRebindError(
                        "invalid_payload_state", "Payload suffix disagrees with journal state."
                    )
                verified_chunks += _verify_payload(
                    snapshot, ciphertext / payload_name, record, owner
                )
                expected_data.add(payload_name)
                counts[record.status] += 1
            if data_names != expected_data:
                raise StorageRebindError(
                    "orphan_payload", "Snapshot contains payloads without journals."
                )
            snapshot.recheck()
            changed = old_binding != new_binding
            if apply and changed:
                _publish_binding(
                    snapshot, target, json.dumps(new_binding, sort_keys=True).encode("utf-8")
                )
            return {
                "schema_version": 1,
                "version": __version__,
                "status": "applied"
                if apply and changed
                else "rebind_required"
                if changed
                else "verified",
                "action": "rebind" if changed else "none",
                "applied": bool(apply and changed),
                "records": counts,
                "verified_chunks": verified_chunks,
                "expiry_policy": "original timestamps retained; startup applies configured TTL",
                "offline_required": True,
            }
    except StorageRebindError:
        raise
    except (EncryptedStorageError, ValueError, TypeError, OverflowError) as exc:
        raise StorageRebindError(
            "invalid_snapshot", "Snapshot contains invalid encrypted metadata."
        ) from exc
    except OSError as exc:
        raise StorageRebindError(
            "inaccessible_snapshot", "Snapshot is missing, unsafe or inaccessible."
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate an isolated cold encrypted-storage copy; "
            "change only its binding with --apply."
        ),
        epilog="Stop all writers first. Use the final runtime mount namespace and data owner.",
    )
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--files-dir", required=True, type=Path)
    parser.add_argument("--snapshot-version-file", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = rebind_storage(
            args.state_root, args.files_dir, args.snapshot_version_file, apply=args.apply
        )
    except StorageRebindError as exc:
        result = {"status": "error", "code": exc.code, "message": str(exc)}
        print(json.dumps(result) if args.json else f"{exc.code}: {exc}")
        return exc.exit_code
    print(json.dumps(result, sort_keys=True) if args.json else result["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
