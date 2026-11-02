"""Portable injectable boundaries for deployment commands."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol


class ProcessResult(Protocol):
    @property
    def returncode(self) -> int: ...

    @property
    def stdout(self) -> str: ...

    @property
    def stderr(self) -> str: ...


class ProcessRunner(Protocol):
    def run(self, argv: Sequence[str]) -> ProcessResult: ...


class ReadDownloader(Protocol):
    def read(self, url: str, max_bytes: int) -> bytes: ...


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    not_found: bool = False


class AdministrativeRunner(Protocol):
    def run(
        self, argv: Sequence[str], *, env: Mapping[str, str] | None = None
    ) -> CommandResult: ...


class CommandRunner:
    """Portable process execution; Linux service locking is imported separately."""

    def run(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None) -> CommandResult:
        command = tuple(str(item) for item in argv)
        environment = None if env is None else {**os.environ, **env}
        try:
            result = subprocess.run(
                command, check=False, capture_output=True, text=True, env=environment
            )
        except FileNotFoundError:
            return CommandResult(command, 127, not_found=True)
        except OSError:
            return CommandResult(command, 127)
        return CommandResult(command, result.returncode, result.stdout, result.stderr)

    def stream(self, argv: Sequence[str]) -> int:
        try:
            return subprocess.run(tuple(argv), check=False).returncode
        except OSError:
            return 127
