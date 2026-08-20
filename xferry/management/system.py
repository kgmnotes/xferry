"""Reusable process, locking, and transactional filesystem boundaries."""

from __future__ import annotations

import fcntl
import os
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol


@dataclass(frozen=True)
class CommandResult:
    """Captured subprocess outcome without implicit printing or logging."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    not_found: bool = False


class Runner(Protocol):
    """Small injectable command execution interface."""

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult: ...


class CommandRunner:
    """Run a command without a shell and capture all output."""

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Return captured output; never echo argv, stdout, or stderr."""
        command = tuple(str(item) for item in argv)
        process_environment = None
        if env is not None:
            process_environment = os.environ.copy()
            process_environment.update(env)
        try:
            completed = subprocess.run(  # noqa: S603 - fixed administrative argv
                command,
                check=False,
                capture_output=True,
                text=True,
                env=process_environment,
            )
        except FileNotFoundError:
            return CommandResult(argv=command, returncode=127, not_found=True)
        except OSError:
            return CommandResult(argv=command, returncode=127)
        return CommandResult(
            argv=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def stream(self, argv: Sequence[str]) -> int:
        """Run a command with inherited stdout/stderr for long-lived operator streams."""
        command = tuple(str(item) for item in argv)
        try:
            completed = subprocess.run(command, check=False)  # noqa: S603 - fixed administrative argv
        except OSError:
            return 127
        return completed.returncode


class MutationError(RuntimeError):
    """Base error for failure to enter the managed mutation boundary."""


class InsufficientPrivilege(MutationError):
    """Raised when a real managed mutation is attempted without root."""


class MutationLocked(MutationError):
    """Raised when another managed operation already owns the shared lock."""


class UnsafeLock(MutationError):
    """Raised when the shared lock path is not a safe root-owned file."""


@contextmanager
def managed_mutation(
    lock_path: Path,
    *,
    effective_uid: Callable[[], int] = os.geteuid,
    root_uid: int = 0,
) -> Iterator[None]:
    """Require root and exclusively hold the shared managed-operation lock."""
    if effective_uid() != 0:
        raise InsufficientPrivilege("managed mutations require root")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = _open_managed_lock(lock_path, root_uid=root_uid)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MutationLocked("another managed operation is in progress") from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _open_managed_lock(lock_path: Path, *, root_uid: int) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(lock_path, flags)
        except OSError as exc:
            raise UnsafeLock("managed operation lock is unsafe") from exc
    except OSError as exc:
        raise UnsafeLock("managed operation lock could not be created safely") from exc

    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != root_uid
            or metadata.st_nlink != 1
        ):
            raise UnsafeLock("managed operation lock is unsafe")
        if created:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise UnsafeLock("managed operation lock permissions are unsafe")
        return descriptor
    except Exception:
        os.close(descriptor)
        if created:
            try:
                lock_path.unlink()
            except OSError:
                pass
        raise


@dataclass(frozen=True)
class _PathState:
    kind: Literal["absent", "file", "directory", "symlink"]
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    content: bytes | None = None
    link_target: str | None = None


class FilesystemTransaction:
    """Snapshot only managed paths and restore them in reverse mutation order."""

    def __init__(self, *, chown: Callable[[Path, int, int], None] | None = None) -> None:
        self._states: dict[Path, _PathState] = {}
        self._order: list[Path] = []
        self._chown = chown or os.chown
        self._committed = False

    def ensure_directory(self, path: Path, *, mode: int, uid: int, gid: int) -> None:
        """Create or restat one directory without replacing its contents."""
        if path.parent != path and not path.parent.exists():
            self.ensure_directory(path.parent, mode=0o755, uid=0, gid=0)
        self._remember(path)
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            self._remove_current(path)
        path.mkdir(exist_ok=True)
        path.chmod(mode)
        self._chown(path, uid, gid)

    def atomic_write(
        self,
        path: Path,
        content: bytes,
        *,
        mode: int,
        uid: int,
        gid: int,
    ) -> None:
        """Atomically replace one managed file after recording its prior state."""
        if not path.parent.exists():
            self.ensure_directory(path.parent, mode=0o755, uid=0, gid=0)
        self._remember(path)
        self._atomic_replace(path, content, mode=mode, uid=uid, gid=gid)

    def rollback(self) -> None:
        """Restore every recorded path, removing only paths created by this transaction."""
        if self._committed:
            return
        for path in reversed(self._order):
            self._restore(path, self._states[path])
        self._states.clear()
        self._order.clear()

    def commit(self) -> None:
        """Forget snapshots after all external health checks succeed."""
        self._committed = True
        self._states.clear()
        self._order.clear()

    def _remember(self, path: Path) -> None:
        if path in self._states:
            return
        self._states[path] = self._capture(path)
        self._order.append(path)

    @staticmethod
    def _capture(path: Path) -> _PathState:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return _PathState(kind="absent")
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            return _PathState(
                kind="symlink",
                mode=mode,
                uid=metadata.st_uid,
                gid=metadata.st_gid,
                link_target=str(path.readlink()),
            )
        if stat.S_ISDIR(metadata.st_mode):
            return _PathState(
                kind="directory",
                mode=mode,
                uid=metadata.st_uid,
                gid=metadata.st_gid,
            )
        if stat.S_ISREG(metadata.st_mode):
            return _PathState(
                kind="file",
                mode=mode,
                uid=metadata.st_uid,
                gid=metadata.st_gid,
                content=path.read_bytes(),
            )
        raise OSError(f"unsupported managed path type: {path}")

    def _restore(self, path: Path, state: _PathState) -> None:
        if state.kind == "absent":
            self._remove_current(path)
            return
        if state.kind == "file":
            assert state.content is not None
            assert state.mode is not None and state.uid is not None and state.gid is not None
            if not path.parent.exists():
                path.parent.mkdir(parents=True)
            self._atomic_replace(
                path,
                state.content,
                mode=state.mode,
                uid=state.uid,
                gid=state.gid,
            )
            return
        if state.kind == "symlink":
            assert state.link_target is not None
            self._remove_current(path)
            path.symlink_to(state.link_target)
            if state.uid is not None and state.gid is not None:
                os.chown(path, state.uid, state.gid, follow_symlinks=False)
            return

        assert state.mode is not None and state.uid is not None and state.gid is not None
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            self._remove_current(path)
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(state.mode)
        self._chown(path, state.uid, state.gid)

    @staticmethod
    def _remove_current(path: Path) -> None:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)

    def _atomic_replace(
        self,
        path: Path,
        content: bytes,
        *,
        mode: int,
        uid: int,
        gid: int,
    ) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".xferry-",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(mode)
            self._chown(temporary, uid, gid)
            temporary.replace(path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
