"""Crash-safe hidden storage for EUF v1 encrypted transfers."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, cast

from .encrypted_transfer import (
    EUF_CHUNK_SIZE,
    EUF_GCM_TAG_SIZE,
    EUF_MAX_FILE_SIZE,
    EncryptedTransferManifest,
    EncryptedTransferValidationError,
    b64url_decode,
    b64url_encode,
    file_id_bytes,
)
from .storage import UploadStorageQuotaExceeded, UploadStorageService

EncryptedStorageStatus = Literal["partial", "committing", "complete"]

_STATE_SCHEMA_VERSION = 1
_MAX_STATE_BYTES = 1024 * 1024
_DATA_DIRECTORY_NAME = ".xferry-encrypted"
_STATE_DIRECTORY_PARTS = (".xferry", "encrypted-uploads")
_STORAGE_BINDING_NAME = "encrypted-storage-root"
_SUPPORTED_FALLOCATE_ERRORS = frozenset(
    {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
)


class EncryptedStorageError(Exception):
    """Base class for stable encrypted-storage failures."""


class EncryptedStorageNotFound(EncryptedStorageError):
    """Raised when an encrypted file ID is unknown."""


class EncryptedStorageConflict(EncryptedStorageError):
    """Raised when an idempotent operation conflicts with persisted bytes."""


class EncryptedStorageIncomplete(EncryptedStorageError):
    """Raised when completion is requested before every chunk is durable."""


class EncryptedStorageCorrupt(EncryptedStorageError):
    """Raised when persisted encrypted state violates the storage schema."""


@dataclass(frozen=True, slots=True)
class EncryptedStoredChunk:
    """Durable identity for one received ciphertext chunk."""

    index: int
    length: int
    resume_mac: bytes
    ciphertext_sha256: bytes


@dataclass(frozen=True, slots=True)
class EncryptedStoredFile:
    """Immutable persisted state for one encrypted transfer."""

    manifest: EncryptedTransferManifest
    status: EncryptedStorageStatus
    received_chunks: tuple[EncryptedStoredChunk, ...]
    created_at: float
    updated_at: float

    @property
    def file_id(self) -> str:
        return self.manifest.file_id


@dataclass(frozen=True, slots=True)
class EncryptedCreateResult:
    file: EncryptedStoredFile
    created: bool


@dataclass(frozen=True, slots=True)
class EncryptedChunkWriteResult:
    file: EncryptedStoredFile
    stored: bool


@dataclass(frozen=True, slots=True)
class EncryptedCompleteResult:
    file: EncryptedStoredFile
    completed: bool


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate state field")
        result[name] = value
    return result


def _require_exact_keys(value: dict[str, object], expected: set[str], *, field: str) -> None:
    if set(value) != expected:
        raise EncryptedStorageCorrupt(f"invalid {field} fields")


def _require_int(value: object, *, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EncryptedStorageCorrupt(f"invalid {field}")
    return value


def _require_number(value: object, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise EncryptedStorageCorrupt(f"invalid {field}")
    result = float(value)
    if result < 0 or not math.isfinite(result):
        raise EncryptedStorageCorrupt(f"invalid {field}")
    return result


def encrypted_chunk_length(manifest: EncryptedTransferManifest, index: int) -> int:
    """Return one ciphertext chunk length without accessing storage."""
    if isinstance(index, bool) or not isinstance(index, int):
        raise EncryptedTransferValidationError("chunk index is outside the manifest")
    if index < 0 or index >= manifest.chunk_count:
        raise EncryptedTransferValidationError("chunk index is outside the manifest")
    plaintext_length = min(
        manifest.chunk_size,
        manifest.plaintext_size - index * manifest.chunk_size,
    )
    return plaintext_length + EUF_GCM_TAG_SIZE


def _decode_encrypted_manifest(raw: object) -> EncryptedTransferManifest:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise EncryptedStorageCorrupt("invalid manifest")
    manifest_data = raw
    _require_exact_keys(
        manifest_data,
        {
            "version",
            "file_id",
            "plaintext_size",
            "chunk_size",
            "chunk_count",
            "salt",
            "nonce_prefix",
            "encrypted_metadata",
        },
        field="manifest",
    )
    file_id = manifest_data["file_id"]
    if not isinstance(file_id, str):
        raise EncryptedStorageCorrupt("invalid manifest file_id")
    for name in ("salt", "nonce_prefix", "encrypted_metadata"):
        if not isinstance(manifest_data[name], str):
            raise EncryptedStorageCorrupt(f"invalid manifest {name}")
    try:
        manifest = EncryptedTransferManifest(
            version=_require_int(manifest_data["version"], field="manifest version"),
            file_id=file_id,
            plaintext_size=_require_int(
                manifest_data["plaintext_size"],
                field="manifest plaintext_size",
            ),
            chunk_size=_require_int(
                manifest_data["chunk_size"],
                field="manifest chunk_size",
            ),
            chunk_count=_require_int(
                manifest_data["chunk_count"],
                field="manifest chunk_count",
            ),
            salt=b64url_decode(manifest_data["salt"], field="salt"),
            nonce_prefix=b64url_decode(
                manifest_data["nonce_prefix"],
                field="nonce_prefix",
            ),
            encrypted_metadata=b64url_decode(
                manifest_data["encrypted_metadata"],
                field="encrypted_metadata",
            ),
        )
        # The operator's new-upload limit must not hide existing files or
        # invalidate their recovery journal after a configuration change.
    except (EncryptedTransferValidationError, TypeError, ValueError) as exc:
        raise EncryptedStorageCorrupt("invalid manifest") from exc
    return manifest


def decode_encrypted_state(raw: bytes, *, expected_file_id: str) -> EncryptedStoredFile:
    """Decode a bounded journal without opening, reconciling or expiring storage."""
    if len(raw) > _MAX_STATE_BYTES:
        raise EncryptedStorageCorrupt("encrypted recovery journal exceeds its limit")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_members,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise EncryptedStorageCorrupt("invalid state JSON") from exc
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise EncryptedStorageCorrupt("invalid state object")
    _require_exact_keys(
        decoded,
        {
            "schema_version",
            "status",
            "created_at",
            "updated_at",
            "manifest",
            "received_chunks",
        },
        field="state",
    )
    if _require_int(decoded["schema_version"], field="schema_version") != 1:
        raise EncryptedStorageCorrupt("unsupported state schema")
    status_value = decoded["status"]
    if not isinstance(status_value, str) or status_value not in {
        "partial",
        "committing",
        "complete",
    }:
        raise EncryptedStorageCorrupt("invalid state status")
    status = cast(EncryptedStorageStatus, status_value)
    manifest = _decode_encrypted_manifest(decoded["manifest"])
    if manifest.file_id != expected_file_id:
        raise EncryptedStorageCorrupt("state file ID does not match manifest")
    chunks_raw = decoded["received_chunks"]
    if not isinstance(chunks_raw, dict):
        raise EncryptedStorageCorrupt("invalid received_chunks")
    chunks: list[EncryptedStoredChunk] = []
    for raw_index, raw_chunk in chunks_raw.items():
        if (
            not isinstance(raw_index, str)
            or not raw_index
            or (
                raw_index != "0"
                and (not raw_index.isascii() or not raw_index.isdigit() or raw_index[0] == "0")
            )
        ):
            raise EncryptedStorageCorrupt("invalid chunk index")
        index = int(raw_index)
        expected_length = encrypted_chunk_length(manifest, index)
        if not isinstance(raw_chunk, dict):
            raise EncryptedStorageCorrupt("invalid chunk state")
        _require_exact_keys(
            raw_chunk,
            {"length", "resume_mac", "ciphertext_sha256"},
            field="chunk state",
        )
        length = _require_int(raw_chunk["length"], field="chunk length")
        if length != expected_length:
            raise EncryptedStorageCorrupt("invalid chunk length")
        resume_mac_raw = raw_chunk["resume_mac"]
        ciphertext_hash_raw = raw_chunk["ciphertext_sha256"]
        if not isinstance(resume_mac_raw, str) or not isinstance(ciphertext_hash_raw, str):
            raise EncryptedStorageCorrupt("invalid chunk digest")
        try:
            resume_mac = b64url_decode(resume_mac_raw, field="resume_mac")
            ciphertext_hash = b64url_decode(
                ciphertext_hash_raw,
                field="ciphertext_sha256",
            )
        except EncryptedTransferValidationError as exc:
            raise EncryptedStorageCorrupt("invalid chunk digest") from exc
        if len(resume_mac) != 32 or len(ciphertext_hash) != 32:
            raise EncryptedStorageCorrupt("invalid chunk digest length")
        chunks.append(
            EncryptedStoredChunk(
                index=index,
                length=length,
                resume_mac=resume_mac,
                ciphertext_sha256=ciphertext_hash,
            )
        )
    chunks.sort(key=lambda chunk: chunk.index)
    if status in {"committing", "complete"} and len(chunks) != manifest.chunk_count:
        raise EncryptedStorageCorrupt("final state is missing chunks")
    created_at = _require_number(decoded["created_at"], field="created_at")
    updated_at = _require_number(decoded["updated_at"], field="updated_at")
    if updated_at < created_at:
        raise EncryptedStorageCorrupt("updated_at predates created_at")
    return EncryptedStoredFile(
        manifest=manifest,
        status=status,
        received_chunks=tuple(chunks),
        created_at=created_at,
        updated_at=updated_at,
    )


def prepare_legacy_encrypted_binding(
    state_dir: Path, files_dir: Path
) -> tuple[Path, bytes, int, int] | None:
    """Prepare an explicit old-layout adoption without touching journals or ciphertext.

    The caller owns locking and atomic publication of the returned private file.
    This function never instantiates the runtime store, reconciles, expires, or
    creates storage directories. Every inspected directory is rechecked before
    returning so replacing a mount or private parent cannot change the proposal.
    """
    message = "unsafe encrypted storage migration path; preserve the files and private state"
    witnessed: dict[Path, os.stat_result] = {}

    def directory(path: Path) -> os.stat_result | None:
        absolute = path.expanduser().absolute()
        current = Path(absolute.anchor)
        metadata: os.stat_result | None = None
        for component in absolute.parts[1:]:
            current /= component
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                return None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise EncryptedStorageConflict(message)
            before = witnessed.get(current)
            if before is not None and (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_gid,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
            ):
                raise EncryptedStorageConflict(message)
            witnessed[current] = metadata
        return metadata

    def trusted_permissions(metadata: os.stat_result | None, *, private: bool = False) -> None:
        if metadata is not None and (
            metadata.st_mode & 0o022 or (private and stat.S_IMODE(metadata.st_mode) != 0o700)
        ):
            raise EncryptedStorageConflict(message)

    def unchanged() -> None:
        for path, before in witnessed.items():
            try:
                after = path.lstat()
            except OSError as exc:
                raise EncryptedStorageConflict(message) from exc
            if (
                not stat.S_ISDIR(after.st_mode)
                or stat.S_ISLNK(after.st_mode)
                or (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid)
                != (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)
            ):
                raise EncryptedStorageConflict(message)

    state = Path(state_dir).expanduser().absolute()
    files = Path(files_dir).expanduser().absolute()
    state_metadata = directory(state)
    files_metadata = directory(files)
    private_dir = state / _STATE_DIRECTORY_PARTS[0]
    private_metadata = directory(private_dir)
    journals = private_dir / _STATE_DIRECTORY_PARTS[1]
    journals_metadata = directory(journals)
    ciphertext = files / _DATA_DIRECTORY_NAME
    ciphertext_metadata = directory(ciphertext)

    def check_permissions() -> None:
        for metadata in (state_metadata, files_metadata, private_metadata):
            trusted_permissions(metadata)
        for metadata in (journals_metadata, ciphertext_metadata):
            trusted_permissions(metadata, private=True)

    def require_safe_capabilities() -> None:
        if os.name != "posix" or any(
            type(getattr(os, name, None)) is not int or not getattr(os, name, 0)
            for name in ("O_NOFOLLOW", "O_NONBLOCK")
        ):
            raise ValueError(
                "safe encrypted-state migration is unsupported on this platform; "
                "preserve the ciphertext and private journals before migrating"
            )

    # Only now normalize: no lexical parent may hide a symlink.
    state, files = state.resolve(), files.resolve()
    target = state / _STATE_DIRECTORY_PARTS[0] / _STORAGE_BINDING_NAME
    expected = (
        None
        if files_metadata is None
        else {
            "version": 1,
            "files_dir": str(files),
            "device": files_metadata.st_dev,
            "inode": files_metadata.st_ino,
        }
    )
    try:
        saved = target.lstat()
    except FileNotFoundError:
        saved = None
    if saved is not None:
        require_safe_capabilities()
        check_permissions()
        if (
            private_metadata is None
            or not stat.S_ISREG(saved.st_mode)
            or saved.st_nlink != 1
            or saved.st_size > 4096
            or stat.S_IMODE(saved.st_mode) != 0o600
            or (saved.st_uid, saved.st_gid) != (private_metadata.st_uid, private_metadata.st_gid)
        ):
            raise EncryptedStorageConflict("invalid encrypted storage folder binding")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(target, flags)
        try:
            current = os.fstat(descriptor)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino, current.st_size)
                != (saved.st_dev, saved.st_ino, saved.st_size)
            ):
                raise EncryptedStorageConflict("encrypted storage folder binding changed")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                payload = stream.read(4097)
            if len(payload) > 4096:
                raise EncryptedStorageConflict("invalid encrypted storage folder binding")
            binding = json.loads(payload, object_pairs_hook=_reject_duplicate_json_members)
        except (UnicodeError, ValueError) as exc:
            raise EncryptedStorageConflict("invalid encrypted storage folder binding") from exc
        finally:
            if descriptor != -1:
                os.close(descriptor)
        if (
            not isinstance(binding, dict)
            or set(binding) != {"version", "files_dir", "device", "inode"}
            or type(binding.get("version")) is not int
            or binding["version"] != 1
            or not isinstance(binding.get("files_dir"), str)
            or type(binding.get("device")) is not int
            or type(binding.get("inode")) is not int
            or binding != expected
        ):
            raise EncryptedStorageConflict("files_dir does not match encrypted upload state")
        latest = target.lstat()
        if (latest.st_dev, latest.st_ino, latest.st_mode, latest.st_nlink) != (
            saved.st_dev,
            saved.st_ino,
            saved.st_mode,
            saved.st_nlink,
        ):
            raise EncryptedStorageConflict("encrypted storage folder binding changed")
        unchanged()
        return None

    def existing_data(path: Path, *, records: bool) -> bool:
        if path not in witnessed:
            return False
        found = False
        for child in path.iterdir():
            if records and not child.name.endswith(".json"):
                continue
            metadata = child.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or (records and metadata.st_size > _MAX_STATE_BYTES)
            ):
                raise EncryptedStorageConflict("invalid encrypted upload migration state")
            found = True
        return found

    has_records = existing_data(journals, records=True)
    has_ciphertext = existing_data(ciphertext, records=False)
    if not has_records and not has_ciphertext:
        unchanged()
        return None
    if files != state / "uploads" or files_metadata is None or private_metadata is None:
        raise EncryptedStorageConflict(
            "files_dir does not match legacy encrypted upload state; preserve both folders"
        )
    require_safe_capabilities()
    check_permissions()
    unchanged()
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    else:
        raise EncryptedStorageConflict("encrypted storage folder binding changed")
    assert expected is not None
    return (
        target,
        json.dumps(expected, sort_keys=True).encode("utf-8"),
        private_metadata.st_uid,
        private_metadata.st_gid,
    )


class EncryptedStorageService:
    """Own encrypted partials, state sidecars, and crash reconciliation."""

    def __init__(
        self,
        root_dir: Path,
        upload_storage: UploadStorageService,
        *,
        max_plaintext_size: int,
        incomplete_ttl: float,
        clock: Callable[[], float] | None = None,
        allow_legacy_adoption: bool = True,
    ) -> None:
        if (
            isinstance(max_plaintext_size, bool)
            or not isinstance(max_plaintext_size, int)
            or max_plaintext_size < 0
        ):
            raise ValueError("max_plaintext_size must be a non-negative integer")
        if (
            isinstance(incomplete_ttl, bool)
            or not isinstance(incomplete_ttl, int | float)
            or incomplete_ttl <= 0
            or not math.isfinite(float(incomplete_ttl))
        ):
            raise ValueError("incomplete_ttl must be a positive finite number")

        self.root_dir = Path(root_dir)
        self.upload_storage = upload_storage
        self.max_plaintext_size = min(max_plaintext_size or EUF_MAX_FILE_SIZE, EUF_MAX_FILE_SIZE)
        self.incomplete_ttl = float(incomplete_ttl)
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self.data_dir = upload_storage.upload_dir / _DATA_DIRECTORY_NAME
        self.state_dir = self.root_dir.joinpath(*_STATE_DIRECTORY_PARTS)
        self._ensure_private_directory(self.data_dir)
        self._ensure_private_directory(self.state_dir)
        self._bind_storage_root(allow_legacy_adoption=allow_legacy_adoption)
        self.reconcile()
        self.expire_incomplete()

    def _bind_storage_root(self, *, allow_legacy_adoption: bool) -> None:
        """Refuse to reconcile private journals against a different files folder.

        Device/inode identity also detects a changed bind-mount source when
        the runtime path stays the same. The binding lives outside both the
        public file tree and the per-upload journal directory.
        """
        target = self.state_dir.parent / _STORAGE_BINDING_NAME
        directory = self.upload_storage.upload_dir.resolve()
        metadata = directory.stat()
        binding = {
            "version": 1,
            "files_dir": str(directory),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
        has_records = any(self.state_dir.glob("*.json"))
        has_data = any(self.data_dir.iterdir())
        old_binding: object | None = None
        try:
            saved_metadata = target.lstat()
            if (
                not stat.S_ISREG(saved_metadata.st_mode)
                or saved_metadata.st_size > 4096
                or saved_metadata.st_nlink != 1
            ):
                raise EncryptedStorageConflict("invalid encrypted storage folder binding")
            old_binding = json.loads(target.read_text(encoding="utf-8"))
            if (
                not isinstance(old_binding, dict)
                or set(old_binding) != set(binding)
                or old_binding.get("version") != 1
                or not isinstance(old_binding.get("files_dir"), str)
                or type(old_binding.get("device")) is not int
                or type(old_binding.get("inode")) is not int
            ):
                raise EncryptedStorageConflict("invalid encrypted storage folder binding")
        except FileNotFoundError:
            pass
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EncryptedStorageConflict("invalid encrypted storage folder binding") from exc

        legacy_directory = (self.root_dir / "uploads").resolve()
        if old_binding is None:
            incompatible = (directory != legacy_directory or not allow_legacy_adoption) and (
                has_records or has_data
            )
        else:
            incompatible = old_binding != binding and (has_records or has_data)
        if incompatible:
            raise EncryptedStorageConflict(
                "files_dir does not match encrypted upload state; preserve both folders "
                "and migrate encrypted data with its private state before changing the folder"
            )
        if old_binding != binding:
            self._write_private_payload(
                target,
                json.dumps(binding, sort_keys=True).encode("utf-8"),
            )

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise OSError(f"encrypted storage path is not a directory: {path}")
        path.chmod(0o700)

    def _now(self) -> float:
        now = float(self._clock())
        if now < 0 or not math.isfinite(now):
            raise ValueError("clock must return a non-negative finite timestamp")
        return now

    def _validate_manifest(self, manifest: EncryptedTransferManifest) -> None:
        if not isinstance(manifest, EncryptedTransferManifest):
            raise TypeError("manifest must be an EncryptedTransferManifest")
        if manifest.plaintext_size > self.max_plaintext_size:
            raise EncryptedTransferValidationError(
                f"plaintext_size exceeds configured maximum {self.max_plaintext_size}"
            )

    def capacity(self) -> dict[str, int | None]:
        """Advertise the largest new file after tags, quota and disk headroom."""
        with self._lock:
            self._expire_incomplete_locked(self._now())
            snapshot = self.upload_storage.capacity()
            available = snapshot["available_bytes"]
            assert available is not None
            low, high = 0, min(self.max_plaintext_size, available)
            while low < high:
                middle = (low + high + 1) // 2
                chunks = (middle + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE
                if middle + chunks * EUF_GCM_TAG_SIZE <= available:
                    low = middle
                else:
                    high = middle - 1
            snapshot["max_plaintext_size"] = 0 if snapshot["remaining_files"] == 0 else low
            snapshot["technical_max_plaintext_size"] = EUF_MAX_FILE_SIZE
            snapshot["configured_max_plaintext_size"] = self.max_plaintext_size
            return snapshot

    def _state_path(self, file_id: str) -> Path:
        file_id_bytes(file_id)
        return self.state_dir / f"{file_id}.json"

    def _part_path(self, file_id: str) -> Path:
        file_id_bytes(file_id)
        return self.data_dir / f"{file_id}.part"

    def _complete_path(self, file_id: str) -> Path:
        file_id_bytes(file_id)
        return self.data_dir / f"{file_id}.xfr"

    @staticmethod
    def _expected_chunk_length(manifest: EncryptedTransferManifest, index: int) -> int:
        return encrypted_chunk_length(manifest, index)

    @staticmethod
    def _chunk_offset(manifest: EncryptedTransferManifest, index: int) -> int:
        return index * (manifest.chunk_size + EUF_GCM_TAG_SIZE)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _create_sized_file(self, path: Path, size: int) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            fallocate = os.posix_fallocate if hasattr(os, "posix_fallocate") else None
            if size and fallocate is not None:
                try:
                    fallocate(descriptor, 0, size)
                except OSError as exc:
                    if exc.errno not in _SUPPORTED_FALLOCATE_ERRORS:
                        raise
                    os.ftruncate(descriptor, size)
            else:
                os.ftruncate(descriptor, size)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                raise UploadStorageQuotaExceeded(
                    "Upload storage has insufficient disk space.",
                    reason="free_space",
                ) from exc
            raise
        finally:
            os.close(descriptor)
        self._fsync_directory(self.data_dir)

    @staticmethod
    def _record_to_json(record: EncryptedStoredFile) -> bytes:
        manifest = record.manifest
        payload = {
            "schema_version": _STATE_SCHEMA_VERSION,
            "status": record.status,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "manifest": {
                "version": manifest.version,
                "file_id": manifest.file_id,
                "plaintext_size": manifest.plaintext_size,
                "chunk_size": manifest.chunk_size,
                "chunk_count": manifest.chunk_count,
                "salt": b64url_encode(manifest.salt),
                "nonce_prefix": b64url_encode(manifest.nonce_prefix),
                "encrypted_metadata": b64url_encode(manifest.encrypted_metadata),
            },
            "received_chunks": {
                str(chunk.index): {
                    "length": chunk.length,
                    "resume_mac": b64url_encode(chunk.resume_mac),
                    "ciphertext_sha256": b64url_encode(chunk.ciphertext_sha256),
                }
                for chunk in record.received_chunks
            },
        }
        return json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def _write_state(self, record: EncryptedStoredFile) -> None:
        payload = self._record_to_json(record)
        if len(payload) > _MAX_STATE_BYTES:
            raise EncryptedTransferValidationError("encrypted recovery journal exceeds its limit")
        target = self._state_path(record.file_id)
        self._write_private_payload(target, payload)

    def _write_private_payload(self, target: Path, payload: bytes) -> None:
        temporary = target.parent / f".{target.name}.{secrets.token_hex(12)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), 0o600)
                os.fsync(stream.fileno())
            os.replace(temporary, target)  # noqa: PTH105 - atomic sidecar publication
            self._fsync_directory(target.parent)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _decode_state(raw: bytes, *, expected_file_id: str) -> EncryptedStoredFile:
        return decode_encrypted_state(raw, expected_file_id=expected_file_id)

    def _read_state_path(self, path: Path) -> EncryptedStoredFile:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            raise EncryptedStorageNotFound("encrypted file not found") from None
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > _MAX_STATE_BYTES
        ):
            raise EncryptedStorageCorrupt("invalid state sidecar")
        raw = path.read_bytes()
        return self._decode_state(raw, expected_file_id=path.stem)

    def get(self, file_id: str) -> EncryptedStoredFile | None:
        """Return current state for *file_id*, or ``None`` when absent."""
        path = self._state_path(file_id)
        with self._lock:
            if not path.exists() and not path.is_symlink():
                return None
            record = self._read_state_path(path)
            if record.status == "partial" and self._now() - record.updated_at > self.incomplete_ttl:
                self._delete_locked(record.file_id)
                return None
            return record

    def _require_file(self, file_id: str) -> EncryptedStoredFile:
        record = self.get(file_id)
        if record is None:
            raise EncryptedStorageNotFound("encrypted file not found")
        return record

    def create(self, manifest: EncryptedTransferManifest) -> EncryptedCreateResult:
        """Create a pre-sized partial file, or validate an identical retry."""
        if not isinstance(manifest, EncryptedTransferManifest):
            raise TypeError("manifest must be an EncryptedTransferManifest")
        with self._lock:
            self._expire_incomplete_locked(self._now())
            existing = self.get(manifest.file_id)
            if existing is not None:
                if existing.manifest != manifest:
                    raise EncryptedStorageConflict("encrypted file ID already has another manifest")
                return EncryptedCreateResult(existing, created=False)

            self._validate_manifest(manifest)

            part_path = self._part_path(manifest.file_id)
            complete_path = self._complete_path(manifest.file_id)
            if (
                part_path.exists()
                or part_path.is_symlink()
                or complete_path.exists()
                or complete_path.is_symlink()
            ):
                raise EncryptedStorageConflict("encrypted file ID already has data")

            now = self._now()
            record = EncryptedStoredFile(
                manifest=manifest,
                status="partial",
                received_chunks=(),
                created_at=now,
                updated_at=now,
            )
            with self.upload_storage.reservation(manifest.ciphertext_size):
                try:
                    self._create_sized_file(part_path, manifest.ciphertext_size)
                    self._write_state(record)
                except BaseException:
                    part_path.unlink(missing_ok=True)
                    self._state_path(manifest.file_id).unlink(missing_ok=True)
                    self._fsync_directory(self.data_dir)
                    self._fsync_directory(self.state_dir)
                    raise
            return EncryptedCreateResult(record, created=True)

    def _data_path_for_record(self, record: EncryptedStoredFile) -> Path:
        if record.status == "partial":
            return self._part_path(record.file_id)
        return self._complete_path(record.file_id)

    @staticmethod
    def _open_regular_file(path: Path, *, write: bool) -> int:
        flags = (os.O_RDWR if write else os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise EncryptedStorageCorrupt("encrypted data is not a regular file")
        return descriptor

    @staticmethod
    def _read_exact(descriptor: int, offset: int, length: int) -> bytes:
        os.lseek(descriptor, offset, os.SEEK_SET)
        remaining = length
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise EncryptedStorageCorrupt("encrypted data is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _write_all(descriptor: int, offset: int, data: bytes) -> None:
        os.lseek(descriptor, offset, os.SEEK_SET)
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("encrypted chunk write made no progress")
            written += count

    def write_chunk(
        self,
        file_id: str,
        index: int,
        ciphertext: bytes,
        resume_mac: bytes,
    ) -> EncryptedChunkWriteResult:
        """Durably write one exact-position chunk or validate an identical retry."""
        if not isinstance(ciphertext, bytes):
            raise EncryptedTransferValidationError("chunk ciphertext must be bytes")
        if not isinstance(resume_mac, bytes) or len(resume_mac) != 32:
            raise EncryptedTransferValidationError("resume MAC must contain exactly 32 bytes")
        with self._lock, self.upload_storage.mutation():
            record = self._require_file(file_id)
            expected_length = self._expected_chunk_length(record.manifest, index)
            if len(ciphertext) != expected_length:
                raise EncryptedTransferValidationError(
                    f"chunk ciphertext must contain exactly {expected_length} bytes"
                )
            offset = self._chunk_offset(record.manifest, index)
            digest = hashlib.sha256(ciphertext).digest()
            existing = next(
                (chunk for chunk in record.received_chunks if chunk.index == index),
                None,
            )
            data_path = self._data_path_for_record(record)
            if existing is not None:
                descriptor = self._open_regular_file(data_path, write=False)
                try:
                    persisted = self._read_exact(descriptor, offset, expected_length)
                finally:
                    os.close(descriptor)
                if (
                    existing.length == expected_length
                    and existing.resume_mac == resume_mac
                    and existing.ciphertext_sha256 == digest
                    and persisted == ciphertext
                ):
                    return EncryptedChunkWriteResult(record, stored=False)
                raise EncryptedStorageConflict("encrypted chunk conflicts with persisted data")
            if record.status != "partial":
                raise EncryptedStorageConflict("encrypted file is no longer writable")

            descriptor = self._open_regular_file(data_path, write=True)
            try:
                if os.fstat(descriptor).st_size != record.manifest.ciphertext_size:
                    raise EncryptedStorageCorrupt("encrypted partial has an unexpected size")
                self._write_all(descriptor, offset, ciphertext)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

            chunk = EncryptedStoredChunk(
                index=index,
                length=expected_length,
                resume_mac=resume_mac,
                ciphertext_sha256=digest,
            )
            chunks = tuple(sorted((*record.received_chunks, chunk), key=lambda item: item.index))
            updated = replace(
                record,
                received_chunks=chunks,
                updated_at=max(record.updated_at, self._now()),
            )
            self._write_state(updated)
            return EncryptedChunkWriteResult(updated, stored=True)

    def _validate_data_file(self, path: Path, *, expected_size: int) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise EncryptedStorageCorrupt("encrypted data is missing") from exc
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != expected_size
        ):
            raise EncryptedStorageCorrupt("encrypted data has an unexpected type or size")

    def _finish_committing(self, record: EncryptedStoredFile) -> EncryptedStoredFile:
        with self.upload_storage.mutation():
            return self._publish_committing_locked(record)

    def _publish_committing_locked(self, record: EncryptedStoredFile) -> EncryptedStoredFile:
        part_path = self._part_path(record.file_id)
        complete_path = self._complete_path(record.file_id)
        part_exists = part_path.exists() and not part_path.is_symlink()
        complete_exists = complete_path.exists() and not complete_path.is_symlink()
        if part_exists and complete_exists:
            raise EncryptedStorageCorrupt("both partial and complete encrypted data exist")
        if part_exists:
            self._validate_data_file(part_path, expected_size=record.manifest.ciphertext_size)
            os.replace(part_path, complete_path)  # noqa: PTH105 - atomic data publication
            self._fsync_directory(self.data_dir)
        elif complete_exists:
            self._validate_data_file(complete_path, expected_size=record.manifest.ciphertext_size)
        else:
            raise EncryptedStorageCorrupt("committing encrypted data is missing")
        completed = replace(
            record,
            status="complete",
            updated_at=max(record.updated_at, self._now()),
        )
        self._write_state(completed)
        return completed

    def complete(self, file_id: str) -> EncryptedCompleteResult:
        """Atomically publish a fully received encrypted file."""
        with self._lock:
            record = self._require_file(file_id)
            if record.status == "complete":
                return EncryptedCompleteResult(record, completed=False)
            if len(record.received_chunks) != record.manifest.chunk_count:
                raise EncryptedStorageIncomplete("encrypted file is missing chunks")
            if record.status == "partial":
                record = replace(
                    record,
                    status="committing",
                    updated_at=max(record.updated_at, self._now()),
                )
                self._write_state(record)
            completed = self._finish_committing(record)
            return EncryptedCompleteResult(completed, completed=True)

    def list_files(
        self,
        *,
        status: EncryptedStorageStatus | None = None,
    ) -> tuple[EncryptedStoredFile, ...]:
        """Return sidecar-backed files in stable ID order."""
        if status not in {None, "partial", "committing", "complete"}:
            raise ValueError("invalid encrypted storage status")
        with self._lock:
            self._expire_incomplete_locked(self._now())
            return self._list_files_locked(status=status)

    def _list_files_locked(
        self,
        *,
        status: EncryptedStorageStatus | None = None,
    ) -> tuple[EncryptedStoredFile, ...]:
        records: list[EncryptedStoredFile] = []
        for path in sorted(self.state_dir.glob("*.json"), key=lambda item: item.name):
            record = self._read_state_path(path)
            if status is None or record.status == status:
                records.append(record)
        return tuple(records)

    def delete(self, file_id: str) -> bool:
        """Durably remove one encrypted file and its sidecar."""
        with self._lock:
            return self._delete_locked(file_id)

    def _delete_locked(self, file_id: str) -> bool:
        state_path = self._state_path(file_id)
        part_path = self._part_path(file_id)
        complete_path = self._complete_path(file_id)
        with self.upload_storage.mutation():
            existed = any(
                path.exists() or path.is_symlink()
                for path in (state_path, part_path, complete_path)
            )
            for path in (part_path, complete_path, state_path):
                path.unlink(missing_ok=True)
            if existed:
                self._fsync_directory(self.data_dir)
                self._fsync_directory(self.state_dir)
        return existed

    def _expire_incomplete_locked(self, current: float) -> tuple[str, ...]:
        expired: list[str] = []
        for record in self._list_files_locked(status="partial"):
            if current - record.updated_at > self.incomplete_ttl:
                self._delete_locked(record.file_id)
                expired.append(record.file_id)
        return tuple(expired)

    def expire_incomplete(self, *, now: float | None = None) -> tuple[str, ...]:
        """Delete partial uploads whose last durable activity exceeded the TTL."""
        current = self._now() if now is None else float(now)
        if current < 0 or not math.isfinite(current):
            raise ValueError("now must be a non-negative finite timestamp")
        with self._lock:
            return self._expire_incomplete_locked(current)

    def _remove_record_artifacts(self, file_id: str) -> None:
        for path in (
            self._part_path(file_id),
            self._complete_path(file_id),
            self._state_path(file_id),
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def _reconcile_record(self, record: EncryptedStoredFile) -> EncryptedStoredFile:
        part_path = self._part_path(record.file_id)
        complete_path = self._complete_path(record.file_id)
        if record.status == "partial":
            if complete_path.exists() or complete_path.is_symlink():
                raise EncryptedStorageCorrupt("partial state has complete data")
            self._validate_data_file(part_path, expected_size=record.manifest.ciphertext_size)
            return record
        if record.status == "committing":
            return self._finish_committing(record)
        if part_path.exists() or part_path.is_symlink():
            raise EncryptedStorageCorrupt("complete state has partial data")
        self._validate_data_file(complete_path, expected_size=record.manifest.ciphertext_size)
        return record

    def reconcile(self) -> None:
        """Recover interrupted commits and remove unowned/corrupt artifacts."""
        with self._lock, self.upload_storage.mutation():
            expected_data_names: set[str] = set()
            for temporary in self.state_dir.glob("*.tmp"):
                temporary.unlink(missing_ok=True)
            for path in sorted(self.state_dir.glob("*.json"), key=lambda item: item.name):
                file_id = path.stem
                try:
                    file_id_bytes(file_id)
                    record = self._read_state_path(path)
                    record = self._reconcile_record(record)
                except (EncryptedStorageError, EncryptedTransferValidationError, ValueError):
                    try:
                        file_id_bytes(file_id)
                    except EncryptedTransferValidationError:
                        path.unlink(missing_ok=True)
                    else:
                        self._remove_record_artifacts(file_id)
                    continue
                suffix = ".part" if record.status == "partial" else ".xfr"
                expected_data_names.add(f"{record.file_id}{suffix}")

            for path in self.data_dir.iterdir():
                if path.name not in expected_data_names:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
            self._fsync_directory(self.data_dir)
            self._fsync_directory(self.state_dir)


__all__ = [
    "EncryptedChunkWriteResult",
    "EncryptedCompleteResult",
    "EncryptedCreateResult",
    "EncryptedStorageConflict",
    "EncryptedStorageCorrupt",
    "EncryptedStorageError",
    "EncryptedStorageIncomplete",
    "EncryptedStorageNotFound",
    "EncryptedStorageService",
    "EncryptedStoredChunk",
    "EncryptedStoredFile",
    "decode_encrypted_state",
    "encrypted_chunk_length",
]
