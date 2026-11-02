"""Discovery indexes validated manifests; INI files do not imply deployments."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .deployment import Backend, DeploymentSpec, load_manifest, read_document


@dataclass(frozen=True)
class Instance:
    id: str
    backend: Backend
    config: Path
    manifest: Path

    @property
    def target(self) -> str:
        return "managed" if self.backend == "native" else "docker"

    @property
    def spec(self) -> DeploymentSpec:
        spec = load_manifest(self.manifest)
        if (
            spec.instance_id != self.id
            or spec.backend != self.backend
            or spec.profile != self.config
        ):
            raise ValueError("deployment identity changed; select the instance again")
        return spec


def user_data_dir() -> Path:
    from xferry.paths import default_user_data_dir

    return default_user_data_dir()


def foreground_config() -> Path:
    from xferry.paths import default_config_path

    return default_config_path()


def _registry_paths() -> list[Path]:
    try:
        document = read_document(user_data_dir() / "instances.json", maximum=65536)
        if document.get("schema") != 2:
            return []
        values = document.get("manifests", [])
        if not isinstance(values, list):
            return []
        return [
            Path(value) for value in values if isinstance(value, str) and Path(value).is_absolute()
        ]
    except (OSError, ValueError, TypeError):
        return []


def _instance(path: Path) -> Instance:
    spec = load_manifest(path)
    return Instance(spec.instance_id, spec.backend, spec.profile, path)


def discover_instances() -> tuple[Instance, ...]:
    candidates = [
        *_registry_paths(),
        Path("/etc/xferry/deployment.json"),
        user_data_dir() / "deployment/.xferry-deployment.json",
    ]
    found: dict[str, Instance] = {}
    for path in candidates:
        try:
            item = _instance(path)
            found[item.id] = item
        except (OSError, ValueError, TypeError):
            continue
    return tuple(found.values())


def resolve_instance(instance: str | Path | Instance | None = None) -> Instance:
    if isinstance(instance, Instance):
        _ = instance.spec
        return instance
    found = discover_instances()
    if instance is not None:
        selected = str(instance)
        matches = [item for item in found if item.id == selected or str(item.manifest) == selected]
        if matches:
            return matches[0]
        path = Path(selected).expanduser()
        if path.is_absolute():
            return _instance(path)
        raise ValueError("unknown instance; use its ID or absolute deployment manifest path")
    if len(found) > 1:
        raise ValueError("more than one server was found; choose it with --instance ID")
    if found:
        return found[0]
    raise ValueError("no persistent deployment found; run xferry setup or xferry run --config FILE")


def select_instance(
    instance: str | Path | None = None, *, interactive: bool = False, language: str = "en"
) -> Instance:
    found = discover_instances()
    if instance is not None or len(found) <= 1 or not interactive:
        return resolve_instance(instance)
    print("Выберите сервер:" if language == "ru" else "Choose a server:")
    for index, item in enumerate(found, 1):
        print(f"  {index}. {item.id} ({item.backend}, {item.config})")
    try:
        selection = int(input("Номер: " if language == "ru" else "Number: ")) - 1
        if not 0 <= selection < len(found):
            raise ValueError
    except ValueError:
        raise ValueError("choose one of the listed server numbers") from None
    return found[selection]


def register_instance(path: Path, target: str | None = None) -> None:
    path = path.expanduser().absolute()
    _instance(path)
    from .configuration import _portable_lock
    from .docker_deploy import _atomic_write

    root = user_data_dir()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    registry = root / "instances.json"
    with _portable_lock(registry):
        paths = list(dict.fromkeys([*_registry_paths(), path]))
        _atomic_write(
            registry,
            (
                json.dumps({"schema": 2, "manifests": [str(p) for p in paths]}, indent=2) + "\n"
            ).encode(),
            0o600,
        )


def unregister_instance(path: Path) -> None:
    from .configuration import _portable_lock
    from .docker_deploy import _atomic_write

    registry = user_data_dir() / "instances.json"
    if not registry.exists():
        return
    with _portable_lock(registry):
        paths = [p for p in _registry_paths() if p != path.absolute()]
        _atomic_write(
            registry,
            (
                json.dumps({"schema": 2, "manifests": [str(p) for p in paths]}, indent=2) + "\n"
            ).encode(),
            0o600,
        )


def target_for_config(path: Path) -> str:
    """Only registered identity can give a profile a persistent backend."""
    path = path.expanduser().absolute()
    for instance in discover_instances():
        if instance.config == path:
            return instance.target
    return "portable"


def ensure_dedicated_files_folder(folder: Path, *, exclude_id: str | None = None) -> None:
    """Require a separate public tree for each known persistent deployment."""
    selected = folder.expanduser().resolve()
    try:
        metadata = selected.stat()
        selected_identity = (metadata.st_dev, metadata.st_ino)
    except FileNotFoundError:
        selected_identity = None
    for instance in discover_instances():
        if instance.id == exclude_id:
            continue
        other = instance.spec.files_dir.expanduser().resolve()
        try:
            metadata = other.stat()
            other_identity = (metadata.st_dev, metadata.st_ino)
        except FileNotFoundError:
            other_identity = None
        if (
            selected == other
            or selected.is_relative_to(other)
            or other.is_relative_to(selected)
            or selected_identity is not None
            and selected_identity == other_identity
        ):
            raise ValueError(
                f"files folder is reserved by instance {instance.id}; "
                "choose a separate dedicated folder"
            )


@contextmanager
def deployment_setup_lock() -> Iterator[None]:
    """Serialize setup/removal across outputs before publishing an indexed identity."""
    from .configuration import _portable_lock

    with _portable_lock(user_data_dir() / "deployment-setup"):
        yield


@contextmanager
def dedicated_files_folder(folder: Path, *, exclude_id: str | None = None) -> Iterator[None]:
    with deployment_setup_lock():
        ensure_dedicated_files_folder(folder, exclude_id=exclude_id)
        yield
