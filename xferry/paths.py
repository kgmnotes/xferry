"""Stable operator paths shared by launch, setup and configuration tools."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path


def default_user_data_dir() -> Path:
    if sys.platform == "win32":
        return (
            Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "xferry"
        )
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "xferry"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "xferry"


def default_config_path() -> Path:
    return default_user_data_dir() / "xferry.ini"


default_config_file = default_config_path


def default_files_dir() -> Path:
    return default_user_data_dir() / "files"


def runtime_state_dir() -> Path | None:
    """Return the private state location supplied by a service or container."""
    runtime_home = os.environ.get("XFERRY_STATE_HOME")
    return Path(runtime_home).expanduser().resolve() if runtime_home else None


def automatic_state_dir(
    files_dir: str | Path | None = None,
    config_path: str | Path | None = None,
) -> Path:
    """Keep state stable for a profile, including after files-folder changes."""
    runtime_home = runtime_state_dir()
    if runtime_home is not None:
        return runtime_home
    selected_config = (
        Path(config_path).expanduser().resolve()
        if config_path is not None
        else default_config_path()
    )
    identity = str(selected_config)
    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return default_user_data_dir() / "state" / key


@dataclass(frozen=True)
class StateLayout:
    """All private runtime storage belongs to one explicit deployment root."""

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).expanduser().resolve())

    @property
    def notes(self) -> Path:
        return self.root / "notes"

    @property
    def acme(self) -> Path:
        return self.root / "acme"

    @property
    def transfer(self) -> Path:
        return self.root / ".xferry"

    def ensure_private(self) -> None:
        for path in (self.root, self.notes, self.acme, self.transfer):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f"private state must be a directory: {path}")
