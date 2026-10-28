"""Stable operator paths shared by launch, setup and configuration tools."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
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


def state_for_config(config_path: str | Path) -> Path | None:
    """Read the bounded private context produced by one-off config migration."""
    config = Path(config_path).expanduser().resolve()
    sidecar = config.with_name(f".{config.name}.state.json")
    try:
        metadata = sidecar.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16384:
        raise ValueError(f"invalid migrated state context: {sidecar}")
    try:
        with sidecar.open(encoding="utf-8") as context_file:
            text = context_file.read(16385)
        if len(text.encode("utf-8")) > 16384:
            raise ValueError("context exceeds size limit")
        value = json.loads(text)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"invalid migrated state context: {sidecar}") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema") != 1
        or not isinstance(value.get("state_dir"), str)
        or not isinstance(value.get("files_dir"), str)
        or not Path(value["state_dir"]).is_absolute()
        or not Path(value["files_dir"]).is_absolute()
    ):
        raise ValueError(f"invalid migrated state context: {sidecar}")
    return Path(value["state_dir"]).resolve()


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
