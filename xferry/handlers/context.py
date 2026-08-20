"""Narrow runtime dependencies shared by built-in HTTP handlers."""

from __future__ import annotations

import threading
from _thread import LockType
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..metrics import MetricsCollector
from ..storage import UploadStorageService


class SmuggleTempRegistry:
    """Registered SMUGGLE paths available only while coordination is held."""

    __slots__ = ("_claimed", "_paths")

    def __init__(self, paths: set[str], claimed: set[str]) -> None:
        self._paths = paths
        self._claimed = claimed

    def contains(self, path: str | Path) -> bool:
        """Return whether *path* is a registered temporary artifact."""
        return str(path) in self._paths

    def add(self, path: str | Path) -> None:
        """Register *path* as a temporary artifact."""
        self._paths.add(str(path))

    def discard(self, path: str | Path) -> None:
        """Forget *path* without failing when it is already absent."""
        key = str(path)
        self._paths.discard(key)
        self._claimed.discard(key)

    def is_claimed(self, path: str | Path) -> bool:
        """Return whether a registered path is reserved for an active stream."""
        return str(path) in self._claimed

    def snapshot(self) -> frozenset[str]:
        """Return an immutable snapshot of registered paths."""
        return frozenset(self._paths)

    def clear(self) -> None:
        """Forget every registered path."""
        self._paths.clear()
        self._claimed.clear()


class SmuggleTempCoordinator:
    """Own synchronization around the server's registered SMUGGLE paths."""

    __slots__ = ("_lock", "_registry", "_claimed")

    def __init__(
        self,
        *,
        lock: LockType | None = None,
        paths: set[str] | None = None,
    ) -> None:
        self._claimed: set[str] = set()
        self._lock = lock if lock is not None else threading.Lock()
        self._registry = SmuggleTempRegistry(
            paths if paths is not None else set(),
            self._claimed,
        )

    @contextmanager
    def transaction(self) -> Iterator[SmuggleTempRegistry]:
        """Yield registry operations while holding the coordinator lock."""
        with self._lock:
            yield self._registry

    def contains(self, path: str | Path) -> bool:
        """Thread-safely report whether *path* is registered."""
        with self.transaction() as registry:
            return registry.contains(path)

    def discard(self, path: str | Path) -> None:
        """Thread-safely forget *path*."""
        with self.transaction() as registry:
            registry.discard(path)

    def snapshot(self) -> frozenset[str]:
        """Return a thread-safe immutable snapshot of registered paths."""
        with self.transaction() as registry:
            return registry.snapshot()

    def remove_all_registered(self) -> int:
        """Best-effort unlink and forget every currently registered path."""
        removed = 0
        with self.transaction() as registry:
            for path_str in registry.snapshot():
                try:
                    path = Path(path_str)
                    if path.is_symlink() or not path.is_file():
                        continue
                    path.unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    pass
            registry.clear()
        return removed

    def _claim(self, path: str | Path) -> bool:
        """Atomically reserve one registered artifact for a response stream."""
        key = str(path)
        with self.transaction() as registry:
            if not registry.contains(key) or registry.is_claimed(key):
                return False
            self._claimed.add(key)
            return True

    def _release(self, path: str | Path) -> None:
        """Release a stream reservation and unregister its artifact."""
        key = str(path)
        with self.transaction() as registry:
            self._claimed.discard(key)
            registry.discard(key)


@dataclass(frozen=True, slots=True)
class HandlerRuntimeContext:
    """Documented built-in handler dependencies for storage and SMUGGLE state."""

    upload_dir: Path
    upload_storage: UploadStorageService
    metrics: MetricsCollector | None
    smuggle_temp: SmuggleTempCoordinator


__all__ = [
    "HandlerRuntimeContext",
    "SmuggleTempCoordinator",
    "SmuggleTempRegistry",
]
