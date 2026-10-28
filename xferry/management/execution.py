"""Portable injectable boundaries for deployment commands."""

from __future__ import annotations

from collections.abc import Sequence
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
