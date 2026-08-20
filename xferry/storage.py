"""Upload storage quota and atomic publish helpers."""

from __future__ import annotations

import errno
import os
import secrets
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .metrics import MetricsCollector

_UPLOAD_TEMP_PREFIX = ".upload-tmp-"


def _format_bytes(size: int) -> str:
    fsize = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if fsize < 1024:
            return f"{fsize:.1f} {unit}"
        fsize /= 1024
    return f"{fsize:.1f} TB"


def _filename_with_unique_suffix(file_path: Path) -> Path:
    unique_suffix = secrets.token_hex(4)
    name_parts = file_path.name.rsplit(".", 1)

    if len(name_parts) == 2:
        new_name = f"{name_parts[0]}_{unique_suffix}.{name_parts[1]}"
    else:
        new_name = f"{file_path.name}_{unique_suffix}"

    return file_path.parent / new_name


@dataclass(frozen=True)
class UploadStorageUsage:
    """Current accounted usage in the upload directory."""

    total_bytes: int
    file_count: int


@dataclass(frozen=True)
class UploadStoragePolicy:
    """Aggregate upload storage limits.

    ``None`` byte/file limits are intentionally unlimited so existing local
    workflows keep their historical behavior unless operators opt in.
    """

    max_total_bytes: int | None = None
    max_file_count: int | None = None
    reserved_free_bytes: int = 0

    def __post_init__(self) -> None:
        if self.max_total_bytes is not None and self.max_total_bytes < 0:
            raise ValueError("upload_storage_limit must be at least 0")
        if self.max_file_count is not None and self.max_file_count < 0:
            raise ValueError("upload_file_limit must be at least 0")
        if self.reserved_free_bytes < 0:
            raise ValueError("upload_reserved_free_space must be at least 0")

    @property
    def has_limits(self) -> bool:
        return (
            self.max_total_bytes is not None
            or self.max_file_count is not None
            or self.reserved_free_bytes > 0
        )


class UploadStorageQuotaExceeded(Exception):
    """Raised when an upload cannot be committed under the storage policy."""

    def __init__(self, message: str, *, status_code: int = 507) -> None:
        super().__init__(message)
        self.status_code = status_code


class UploadStorageService:
    """Publish uploads atomically while enforcing aggregate storage policy."""

    def __init__(
        self,
        upload_dir: Path,
        policy: UploadStoragePolicy | None = None,
        *,
        metrics: MetricsCollector | None = None,
    ) -> None:
        self.upload_dir = upload_dir
        self.policy = policy or UploadStoragePolicy()
        self._metrics = metrics
        self._lock = threading.RLock()
        self._reserved_bytes = 0
        self._reserved_files = 0

    @staticmethod
    def is_service_temp_path(path: Path) -> bool:
        return path.name.startswith(_UPLOAD_TEMP_PREFIX)

    def current_usage(self) -> UploadStorageUsage:
        """Return current regular-file usage, excluding in-flight temp files."""
        total_bytes = 0
        file_count = 0
        with self._lock:
            if self.upload_dir.exists():
                for path in self.upload_dir.rglob("*"):
                    if self.is_service_temp_path(path):
                        continue
                    try:
                        if path.is_symlink() or not path.is_file():
                            continue
                        total_bytes += path.stat().st_size
                        file_count += 1
                    except OSError:
                        continue

        usage = UploadStorageUsage(total_bytes=total_bytes, file_count=file_count)
        if self._metrics is not None:
            self._metrics.record_storage_usage(
                "uploads",
                usage.total_bytes,
                usage.file_count,
            )
        return usage

    def describe_limit(self) -> str:
        """Return a short human-readable description for startup output."""
        if not self.policy.has_limits:
            return "unlimited"

        parts: list[str] = []
        if self.policy.max_total_bytes is not None:
            parts.append(f"max {_format_bytes(self.policy.max_total_bytes)}")
        if self.policy.max_file_count is not None:
            parts.append(f"max {self.policy.max_file_count} files")
        if self.policy.reserved_free_bytes:
            parts.append(f"reserve {_format_bytes(self.policy.reserved_free_bytes)} free")
        return ", ".join(parts)

    def publish_bytes(
        self,
        file_path: Path,
        data: bytes,
        *,
        max_attempts: int = 64,
    ) -> Path:
        """Write bytes to a hidden temp file and atomically publish a unique name."""
        if file_path.parent.resolve() != self.upload_dir.resolve():
            raise ValueError("upload destination must be directly under upload_dir")

        self.upload_dir.mkdir(parents=True, exist_ok=True)
        size = len(data)
        temp_path: Path | None = None
        reservation_released = False
        self._reserve(size)

        try:
            temp_path = self._write_temp_file(file_path.parent, data)
            with self._lock:
                self._release(size)
                reservation_released = True
                self._check_accepts(size, require_free_for_size=False)
                return self._link_unique_temp(temp_path, file_path, max_attempts=max_attempts)
        finally:
            if not reservation_released:
                self._release(size)
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def _reserve(self, size: int) -> None:
        with self._lock:
            self._check_accepts(size, require_free_for_size=True)
            self._reserved_bytes += size
            self._reserved_files += 1

    def _release(self, size: int) -> None:
        with self._lock:
            self._reserved_bytes -= size
            self._reserved_files -= 1

    def _check_accepts(self, size: int, *, require_free_for_size: bool) -> None:
        if size < 0:
            raise ValueError("upload size must be at least 0")

        if self.policy.max_total_bytes is not None or self.policy.max_file_count is not None:
            scan_started = time.perf_counter()
            usage = self.current_usage()
            if self._metrics is not None:
                self._metrics.record_scan_observation(
                    "upload_quota",
                    (time.perf_counter() - scan_started) * 1000,
                    items=usage.file_count,
                )
            total_after = usage.total_bytes + self._reserved_bytes + size
            file_count_after = usage.file_count + self._reserved_files + 1

            if (
                self.policy.max_total_bytes is not None
                and total_after > self.policy.max_total_bytes
            ):
                if self._metrics is not None:
                    self._metrics.record_quota_denial("uploads", "bytes")
                raise UploadStorageQuotaExceeded(
                    "Upload storage quota exceeded. "
                    f"Current usage: {_format_bytes(usage.total_bytes)}; "
                    f"attempted upload: {_format_bytes(size)}; "
                    f"limit: {_format_bytes(self.policy.max_total_bytes)}."
                )

            if (
                self.policy.max_file_count is not None
                and file_count_after > self.policy.max_file_count
            ):
                if self._metrics is not None:
                    self._metrics.record_quota_denial("uploads", "files")
                raise UploadStorageQuotaExceeded(
                    "Upload file count quota exceeded. "
                    f"Current files: {usage.file_count}; limit: {self.policy.max_file_count}."
                )

        if self.policy.reserved_free_bytes:
            required_free = self.policy.reserved_free_bytes
            if require_free_for_size:
                required_free += self._reserved_bytes + size
            free_bytes = shutil.disk_usage(self.upload_dir).free
            if free_bytes < required_free:
                if self._metrics is not None:
                    self._metrics.record_quota_denial("uploads", "free_space")
                raise UploadStorageQuotaExceeded(
                    "Upload storage free-space reserve would be exceeded. "
                    f"Available: {_format_bytes(free_bytes)}; "
                    f"required reserve: {_format_bytes(self.policy.reserved_free_bytes)}."
                )

    def _write_temp_file(self, directory: Path, data: bytes) -> Path:
        last_error: FileExistsError | None = None
        for _attempt in range(64):
            temp_path = directory / f"{_UPLOAD_TEMP_PREFIX}{secrets.token_hex(16)}.tmp"
            try:
                with temp_path.open("xb") as output_file:
                    output_file.write(data)
                return temp_path
            except FileExistsError as exc:
                last_error = exc
            except OSError as exc:
                temp_path.unlink(missing_ok=True)
                if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                    if self._metrics is not None:
                        self._metrics.record_quota_denial("uploads", "disk_full")
                    raise UploadStorageQuotaExceeded(
                        "Upload storage has insufficient disk space."
                    ) from exc
                raise

        raise FileExistsError("Could not reserve an upload temp file") from last_error

    def _link_unique_temp(
        self,
        temp_path: Path,
        file_path: Path,
        *,
        max_attempts: int,
    ) -> Path:
        candidate = file_path
        attempts = max(1, max_attempts)

        for _attempt in range(attempts):
            try:
                os.link(temp_path, candidate)
                return candidate
            except FileExistsError:
                candidate = _filename_with_unique_suffix(file_path)
            except OSError as exc:
                if exc.errno in {errno.ENOSPC, errno.EDQUOT}:
                    if self._metrics is not None:
                        self._metrics.record_quota_denial("uploads", "disk_full")
                    raise UploadStorageQuotaExceeded(
                        "Upload storage has insufficient disk space."
                    ) from exc
                raise

        raise FileExistsError(f"Could not reserve a unique filename for {file_path.name!r}")
