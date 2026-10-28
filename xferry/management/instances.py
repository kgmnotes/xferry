"""Discover installations without making users select a deployment backend."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Target = Literal["managed", "portable", "docker"]


@dataclass(frozen=True)
class Instance:
    config: Path
    target: Target


def user_data_dir() -> Path:
    from xferry.paths import default_user_data_dir

    return default_user_data_dir()


def foreground_config() -> Path:
    from xferry.paths import default_config_path

    return default_config_path()


def target_for_config(path: Path) -> Target:
    path = path.expanduser().absolute()
    if path == Path("/etc/xferry/xferry.ini"):
        return "managed"
    if (path.parent / ".xferry-deployment.json").is_file():
        return "docker"
    return "portable"


def discover_instances() -> tuple[Instance, ...]:
    candidates: list[Path] = []
    registry = user_data_dir() / "instances.json"
    try:
        metadata = registry.lstat()
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 65536:
            document = json.loads(registry.read_text(encoding="utf-8"))
            if isinstance(document, dict) and document.get("schema") == 1:
                candidates.extend(
                    Path(value) for value in document.get("configs", []) if isinstance(value, str)
                )
    except (OSError, ValueError):
        pass
    candidates.extend((Path("/etc/xferry/xferry.ini"), user_data_dir() / "deployment/xferry.ini"))
    found: dict[Path, Instance] = {}
    for candidate in candidates:
        try:
            path = candidate.expanduser().absolute()
            # A retained installation can be resumed after its runtime is removed.
            retained = path.parent / "retained-state"
            if (
                path.is_file()
                or retained.is_file()
                or (
                    path == Path("/etc/xferry/xferry.ini")
                    and Path("/opt/xferry/current/xferry").is_file()
                )
            ):
                found[path] = Instance(path, target_for_config(path))
        except OSError:
            continue
    return tuple(found.values())


def resolve_instance(
    config: str | Path | None = None, *, prefer_portable: bool = False
) -> Instance:
    if config is not None:
        path = Path(config).expanduser().absolute()
        return Instance(path, target_for_config(path))
    if prefer_portable:
        return Instance(foreground_config(), "portable")
    found = discover_instances()
    if len(found) > 1:
        raise ValueError("more than one server was found; choose it with --config FILE")
    if found:
        return found[0]
    return Instance(foreground_config(), "portable")


def select_instance(
    config: str | Path | None = None, *, interactive: bool = False, language: str = "en"
) -> Instance:
    if config is not None:
        return resolve_instance(config)
    found = discover_instances()
    if len(found) <= 1 or not interactive:
        return resolve_instance()
    print("Выберите сервер:" if language == "ru" else "Choose a server:")
    for index, instance in enumerate(found, 1):
        print(f"  {index}. {instance.config} ({instance.target})")
    answer = input("Номер: " if language == "ru" else "Number: ").strip()
    try:
        index = int(answer) - 1
        if not 0 <= index < len(found):
            raise ValueError
    except ValueError:
        raise ValueError("choose one of the listed server numbers") from None
    return found[index]


def register_instance(path: Path, target: str) -> None:
    if target == "portable":
        return
    path = path.expanduser().absolute()
    root = user_data_dir()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    registry = root / "instances.json"
    configs = [str(instance.config) for instance in discover_instances()]
    if str(path) not in configs:
        configs.append(str(path))
    descriptor, name = tempfile.mkstemp(prefix=".instances-", dir=root)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"schema": 1, "configs": configs}, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(registry)
    finally:
        temporary.unlink(missing_ok=True)
