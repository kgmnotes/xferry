"""Compose rendering and process primitives used by the deployment adapter."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from xferry.config import __version__

from .deployment import OperationResult
from .execution import ProcessRunner

_METADATA = ".xferry-deployment.json"
# A container mount declaration, not a host temporary filename.
_CONTAINER_TMPFS = "/tmp:mode=1777"  # nosec B108


@dataclass(frozen=True)
class DockerResult:
    exit_code: int
    message: str
    url: str | None = None
    files_dir: str | None = None
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    project: str | None = None
    details: dict[str, object] | None = None


def default_files_directory() -> Path:
    """Stable host storage independent of the installer's working directory."""
    if sys.platform == "win32":
        return (
            Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
            / "xferry/files"
        )
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/xferry/files"
    if getattr(os, "geteuid", lambda: -1)() == 0:
        return Path("/var/lib/xferry/files")
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "xferry/files"


class _Runner:
    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, capture_output=True, text=True, check=False)


def _atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        prior = path.lstat()
    except FileNotFoundError:
        prior = None
    if prior is not None and (not stat.S_ISREG(prior.st_mode) or prior.st_nlink != 1):
        raise ValueError("deployment files must be regular files with one link")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        if prior is not None and hasattr(os, "fchown"):
            current = os.fstat(fd)
            if (current.st_uid, current.st_gid) != (prior.st_uid, prior.st_gid):
                os.fchown(fd, prior.st_uid, prior.st_gid)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        requested_mode = (
            mode if mode is not None else (prior.st_mode & 0o777 if prior is not None else 0o600)
        )
        Path(temporary).chmod(requested_mode)
        Path(temporary).replace(path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def _bundle_lock(output: Path) -> Iterator[None]:
    from .configuration import _portable_lock

    # The OS releases this lock even when an installer process crashes.
    with _portable_lock(output / "xferry.ini"):
        yield


def _compose(
    project: str,
    output: Path,
    files: Path,
    private: bool,
    hostname: str,
    *,
    image: str | None = None,
    published_port: int | None = None,
    acme_port: int = 80,
) -> bytes:
    image = image or f"ghcr.io/kgmnotes/xferry:v{__version__}"
    host_uid = getattr(os, "getuid", lambda: 1000)()
    health_script = (
        "from xferry.management.health import HealthEndpoint,authenticated_ping; "
        "from pathlib import Path; "
        "u,p=Path('/run/secrets/xferry_auth').read_text().strip().split(':',1); "
        f"endpoint=HealthEndpoint('127.0.0.1',{8080 if private else 8443},"
        f"{hostname!r},tls={not private!r}); "
        "raise SystemExit(0 if authenticated_ping(endpoint,u,p,4).ok else 1)"
    )
    document = {
        "name": project,
        "services": {
            "secrets-init": {
                "image": image,
                "user": "0:0",
                "network_mode": "none",
                "read_only": True,
                "labels": {"io.xferry.managed": "true"},
                "cap_drop": ["ALL"],
                "cap_add": ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
                "security_opt": ["no-new-privileges:true"],
                "entrypoint": ["python", "-m", "xferry.management.docker_init"],
                "command": ["--host-uid", str(host_uid)],
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(output / "secrets/xferry_auth"),
                        "target": "/source/auth",
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    },
                    {
                        "type": "bind",
                        "source": str(files),
                        "target": "/host-files",
                        "bind": {"create_host_path": False},
                    },
                    "xferry-secrets:/secrets",
                ],
            },
            "xferry": {
                "image": image,
                "restart": "unless-stopped",
                "init": True,
                "read_only": True,
                "labels": {"io.xferry.managed": "true"},
                "mem_limit": "768m",
                "cpus": 1.0,
                "pids_limit": 256,
                "tmpfs": [_CONTAINER_TMPFS],
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "stop_grace_period": "30s",
                "environment": {"XFERRY_STATE_HOME": "/data"},
                "ports": [f"127.0.0.1:{published_port or 8080}:8080"]
                if private
                else [f"{acme_port}:8080", f"{published_port or 443}:8443"],
                "volumes": [
                    "xferry-data:/data",
                    "xferry-secrets:/run/secrets:ro",
                    {
                        "type": "bind",
                        "source": str(output / "runtime.ini"),
                        "target": "/etc/xferry/xferry.ini",
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    },
                    {
                        "type": "bind",
                        "source": str(files),
                        "target": "/data/files",
                        "bind": {"create_host_path": False},
                    },
                ],
                "command": ["run", "--config", "/etc/xferry/xferry.ini"],
                "healthcheck": {
                    "test": ["CMD", "python", "-c", health_script],
                    "interval": "5s",
                    "timeout": "5s",
                    "retries": 3,
                    "start_period": "90s",
                },
            },
        },
        "volumes": {"xferry-data": {}, "xferry-secrets": {}},
    }
    return (json.dumps(document, indent=2) + "\n").encode()


def _activate(runner: ProcessRunner, prefix: tuple[str, ...], *, start: bool = True) -> None:
    commands: list[tuple[str, ...]] = [
        ("run", "--rm", "--no-deps", "secrets-init"),
    ]
    if start:
        commands.append(
            (
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "180",
                "xferry",
            )
        )
    for arguments in commands:
        result = runner.run((*prefix, *arguments))
        if result.returncode != 0:
            output = (result.stderr + result.stdout).lower()
            reason = (
                "check folder access/ACL support and auth file"
                if arguments[0] == "run"
                else "container health check did not pass"
            )
            for fragment, detail in (
                ("port is already allocated", "a required host port is already allocated"),
                ("address already in use", "a required host port is already allocated"),
                ("permission denied", "Docker or filesystem permission was denied"),
                ("no space left", "storage is full"),
                ("manifest unknown", "the selected image version is unavailable"),
                ("cannot connect", "Docker daemon is unavailable"),
            ):
                if fragment in output:
                    reason = detail
                    break
            stage = "secret initialization" if arguments[0] == "run" else "server startup"
            raise RuntimeError(f"Docker {stage} failed: {reason}")


def _restore_bundle(snapshots: Mapping[Path, bytes | None]) -> bool:
    try:
        for path, content in snapshots.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, content)
        for path in snapshots:
            if path.name == "xferry_auth":
                try:
                    path.parent.rmdir()
                except OSError:
                    pass
        return True
    except (OSError, ValueError):
        return False


def deploy_docker(output: Path, **options: Any) -> DockerResult:
    """Thin programmatic entry point; all lifecycle behavior lives in adapters."""
    from .application import ManagementApplication

    runner = options.pop("runner", None)
    if options.pop("reset_credentials", False):
        raise ValueError("credentials require a selected deployment instance")
    if options.pop("private", False):
        options["access"] = "private"
    result = ManagementApplication(runner=runner).setup_compose(output, **options)
    return _docker_result(result)


def docker_operation(config_file: Path, action: str, **options: Any) -> DockerResult:
    """Programmatic adapter entry point using an explicit schema-2 manifest."""
    from .application import ManagementApplication

    runner = options.pop("runner", None)
    if "purge_data" in options:
        options["purge"] = options.pop("purge_data")
    result = ManagementApplication(runner=runner).operate(action, config_file, **options)
    return _docker_result(result)


def _docker_result(result: OperationResult) -> DockerResult:
    credentials = result.credentials
    return DockerResult(
        result.exit_code,
        result.message,
        result.url,
        str(result.details["files_dir"]) if result.details.get("files_dir") else None,
        credentials.username if credentials else None,
        credentials.password if credentials else None,
        details=dict(result.details),
    )
