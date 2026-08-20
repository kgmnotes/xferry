"""Bounded, synchronized storage for one-shot SMUGGLE artifacts.

The HTTP handler deliberately does not know how temporary files are named or
how retention is applied.  ``SmuggleArtifactStore`` owns that lifecycle and
only ever touches files that match the server-generated artifact grammar.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from ..metrics import MetricsCollector
from .policy import (
    SMUGGLE_TEMP_EXTENSIONS,
    SMUGGLE_TEMP_TOKEN_LENGTH,
    SmuggleTempArtifact,
    SmuggleTempPolicy,
    SmuggleTempQuotaExceeded,
    SmuggleTempUsage,
)

if TYPE_CHECKING:  # pragma: no cover - imported only for static checking
    from ..handlers.context import SmuggleTempCoordinator, SmuggleTempRegistry


_TOKEN_RE = re.compile(rf"[0-9a-f]{{{SMUGGLE_TEMP_TOKEN_LENGTH}}}\Z", re.ASCII)
_NAME_RE = re.compile(
    rf"smuggle_[0-9a-f]{{{SMUGGLE_TEMP_TOKEN_LENGTH}}}\.[A-Za-z0-9]+\Z",
    re.ASCII,
)


class SmuggleArtifactStore:
    """Store generated pages under a bounded one-shot retention policy.

    ``coordinator`` is the narrow runtime registry used by the file-serving
    handler.  Keeping the registry injected preserves the existing runtime
    ownership boundary while moving all file/quota logic into this module.
    """

    def __init__(
        self,
        directory: Path,
        policy: SmuggleTempPolicy,
        *,
        coordinator: SmuggleTempCoordinator | None = None,
        metrics: MetricsCollector | None = None,
        token_factory: Callable[[int], str] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.policy = policy
        self.metrics = metrics
        self._token_factory = token_factory or secrets.token_hex
        self._clock = clock or time.time
        if coordinator is None:
            # Lazy import avoids making the context module depend on this
            # implementation at import time.
            from ..handlers.context import SmuggleTempCoordinator

            coordinator = SmuggleTempCoordinator()
        self.coordinator = coordinator

    def write(self, content: bytes, extension: str) -> Path:
        """Atomically create and register one generated artifact.

        The destination is opened with ``xb`` and the returned path is always
        a direct child of ``directory`` with a server-generated token.
        """
        if not isinstance(content, bytes):
            raise TypeError("SMUGGLE artifact content must be bytes")
        safe_extension = self.normalize_extension(extension)
        self.directory.mkdir(parents=True, exist_ok=True)

        last_error: FileExistsError | None = None
        with self.coordinator.transaction() as registry:
            self._ensure_capacity_locked(registry, len(content))
            for _attempt in range(64):
                token = self._token_factory(8)
                if not isinstance(token, str) or _TOKEN_RE.fullmatch(token) is None:
                    # A custom test token must not weaken the path grammar.
                    token = secrets.token_hex(8)
                path = self.directory / f"smuggle_{token}{safe_extension}"
                try:
                    with path.open("xb") as output:
                        output.write(content)
                    registry.add(path)
                    return path
                except FileExistsError as exc:
                    last_error = exc
                except OSError:
                    self._unlink_safe(path)
                    raise
        raise FileExistsError("Could not reserve a SMUGGLE temp file") from last_error

    def cleanup(self, *, remove_all: bool = False) -> int:
        """Prune stale artifacts or remove all generated artifacts."""
        with self.coordinator.transaction() as registry:
            return self._cleanup_locked(registry, remove_all=remove_all)

    def usage(self) -> SmuggleTempUsage:
        """Return current generated artifact bytes and count."""
        with self.coordinator.transaction() as registry:
            artifacts = self._artifacts_locked(registry)
            usage = SmuggleTempUsage(
                total_bytes=sum(item.size for item in artifacts),
                file_count=len(artifacts),
            )
            if self.metrics is not None:
                self.metrics.record_storage_usage(
                    "smuggle_temp", usage.total_bytes, usage.file_count
                )
            return usage

    def contains(self, path: str | Path) -> bool:
        """Return whether a path is registered as a generated artifact."""
        return self.coordinator.contains(path)

    def discard(self, path: str | Path) -> None:
        """Forget a generated artifact after its one-shot stream finishes."""
        self.coordinator.discard(path)

    def claim(self, path: str | Path) -> bool:
        """Atomically reserve a registered artifact for one response stream."""
        claim = getattr(self.coordinator, "_claim", None)
        if callable(claim):
            return bool(claim(path))
        return self.coordinator.contains(path)

    def release(self, path: str | Path) -> None:
        """Release a stream reservation and unregister the artifact."""
        release = getattr(self.coordinator, "_release", None)
        if callable(release):
            release(path)
        else:
            self.coordinator.discard(path)

    def snapshot(self) -> frozenset[str]:
        """Return the registered path snapshot."""
        return self.coordinator.snapshot()

    @staticmethod
    def normalize_extension(extension: str) -> str:
        """Return an allowed outer-artifact suffix, including the dot."""
        value = str(extension).strip().lower()
        if not value.startswith("."):
            value = f".{value}"
        if value not in SMUGGLE_TEMP_EXTENSIONS:
            raise ValueError("Invalid SMUGGLE artifact extension")
        return value

    @classmethod
    def is_artifact_path(cls, path: Path, *, directory: Path | None = None) -> bool:
        """Validate the generated filename and (optionally) its directory."""
        candidate = Path(path)
        if directory is not None and candidate.parent != Path(directory):
            return False
        if _NAME_RE.fullmatch(candidate.name) is None:
            return False
        return candidate.suffix.lower() in SMUGGLE_TEMP_EXTENSIONS

    def _ensure_capacity_locked(
        self,
        registry: SmuggleTempRegistry,
        pending_bytes: int,
    ) -> None:
        self._cleanup_locked(
            registry,
            pending_bytes=pending_bytes,
            pending_files=1,
        )
        artifacts = self._artifacts_locked(registry)
        current_bytes = sum(item.size for item in artifacts)
        current_files = len(artifacts)
        projected_files = current_files + 1
        projected_bytes = current_bytes + pending_bytes
        if self.policy.max_file_count is not None and projected_files > self.policy.max_file_count:
            self._record_denial("files")
            raise SmuggleTempQuotaExceeded(
                "SMUGGLE temp file count quota exceeded. "
                f"Current files: {current_files}; limit: {self.policy.max_file_count}."
            )
        if (
            self.policy.max_total_bytes is not None
            and projected_bytes > self.policy.max_total_bytes
        ):
            self._record_denial("bytes")
            raise SmuggleTempQuotaExceeded(
                "SMUGGLE temp storage quota exceeded. "
                f"Current usage: {self._format_size(current_bytes)}; "
                f"attempted artifact: {self._format_size(pending_bytes)}; "
                f"limit: {self._format_size(self.policy.max_total_bytes)}."
            )

    def _cleanup_locked(
        self,
        registry: SmuggleTempRegistry,
        *,
        pending_bytes: int = 0,
        pending_files: int = 0,
        remove_all: bool = False,
    ) -> int:
        artifacts = self._artifacts_locked(registry)
        removed = 0
        if remove_all:
            for artifact in artifacts:
                if registry.is_claimed(artifact.path):
                    continue
                if self._remove_locked(registry, artifact.path):
                    removed += 1
            return removed

        max_age = self.policy.max_age_seconds
        if max_age is not None:
            now = self._clock()
            fresh: list[SmuggleTempArtifact] = []
            for artifact in artifacts:
                if now - artifact.mtime > max_age and not registry.is_claimed(artifact.path):
                    if self._remove_locked(registry, artifact.path):
                        removed += 1
                else:
                    fresh.append(artifact)
            artifacts = fresh

        artifacts.sort(key=lambda item: item.mtime)
        while artifacts and self._projection_exceeds(
            artifacts,
            pending_bytes=pending_bytes,
            pending_files=pending_files,
        ):
            evictable_index = next(
                (
                    index
                    for index, artifact in enumerate(artifacts)
                    if not registry.is_claimed(artifact.path)
                ),
                None,
            )
            if evictable_index is None:
                break
            oldest = artifacts.pop(evictable_index)
            if self._remove_locked(registry, oldest.path):
                removed += 1
        return removed

    def _projection_exceeds(
        self,
        artifacts: list[SmuggleTempArtifact],
        *,
        pending_bytes: int,
        pending_files: int,
    ) -> bool:
        count = len(artifacts) + pending_files
        total = sum(item.size for item in artifacts) + pending_bytes
        return (self.policy.max_file_count is not None and count > self.policy.max_file_count) or (
            self.policy.max_total_bytes is not None and total > self.policy.max_total_bytes
        )

    def _artifacts_locked(self, registry: SmuggleTempRegistry) -> list[SmuggleTempArtifact]:
        artifacts: list[SmuggleTempArtifact] = []
        try:
            entries = tuple(self.directory.iterdir())
        except OSError:
            return artifacts
        for path in entries:
            if not self.is_artifact_path(path, directory=self.directory):
                continue
            try:
                # Never follow a symlink while discovering or deleting a
                # generated file.  This is important when uploads/ is shared
                # with user-controlled files.
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = path.resolve(strict=True)
                resolved.relative_to(self.directory.resolve())
                stat_result = path.stat()
            except (OSError, ValueError):
                registry.discard(path)
                continue
            artifacts.append(
                SmuggleTempArtifact(
                    path=path,
                    size=stat_result.st_size,
                    mtime=stat_result.st_mtime,
                )
            )
        return artifacts

    def _remove_locked(self, registry: SmuggleTempRegistry, path: Path) -> bool:
        if registry.is_claimed(path):
            return False
        if not self.is_artifact_path(path, directory=self.directory):
            registry.discard(path)
            return False
        try:
            if path.is_symlink() or not path.is_file():
                registry.discard(path)
                return False
            path.unlink()
        except OSError:
            return False
        registry.discard(path)
        return True

    def _unlink_safe(self, path: Path) -> None:
        try:
            if self.is_artifact_path(path, directory=self.directory) and not path.is_symlink():
                path.unlink(missing_ok=True)
        except OSError:
            pass

    def _record_denial(self, reason: str) -> None:
        if self.metrics is not None:
            self.metrics.record_quota_denial("smuggle_temp", reason)

    @staticmethod
    def _format_size(value: int) -> str:
        # Match the existing operator-facing formatting without depending on
        # a handler instance.
        if value < 1024:
            return f"{value:.1f} B"
        if value < 1024 * 1024:
            return f"{value / 1024:.1f} KB"
        if value < 1024 * 1024 * 1024:
            return f"{value / (1024 * 1024):.1f} MB"
        return f"{value / (1024 * 1024 * 1024):.1f} GB"


# Short aliases make the ownership boundary discoverable without forcing a
# particular class name on callers.
SmuggleTempStore = SmuggleArtifactStore
Store = SmuggleArtifactStore

__all__ = [
    "SmuggleArtifactStore",
    "SmuggleTempStore",
    "Store",
]
