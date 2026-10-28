"""Prepare and activate an operator-owned Docker deployment from the host CLI."""

from __future__ import annotations

import configparser
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from xferry.config import __version__
from xferry.settings import load_settings_text, render_sample_profile
from xferry.settings_schema import format_ini_value

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


def _configuration(domain: str | None, private: bool, public_ip: str | None) -> tuple[str, str]:
    from xferry.security.tls import (
        normalize_domain,
        resolve_public_ipv4,
        sslip_domain_for_ip,
        validate_public_ipv4,
    )

    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(render_sample_profile("docker"))
    parser.set("server", "files_dir", "/data/files")
    parser.remove_option("tls", "acme_server")
    parser.remove_option("tls", "public_ip")
    if private:
        # The container listens on its own interface; host publication is loopback-only.
        parser.set("server", "access", "lab")
        parser.set("server", "port", "8080")
        parser.remove_section("tls")
        parser.add_section("tls")
        parser.set("tls", "https_mode", "off")
        parser.set("security", "allowed_hosts", "127.0.0.1 localhost")
        url = "http://127.0.0.1:8080/"
    elif domain:
        hostname = normalize_domain(domain)
        parser.set("server", "access", "public")
        parser.set("tls", "https_mode", "domain")
        parser.set("tls", "domain", hostname)
        parser.set("security", "allowed_hosts", hostname)
        url = f"https://{hostname}/"
    else:
        address = validate_public_ipv4(public_ip) if public_ip else resolve_public_ipv4()
        hostname = sslip_domain_for_ip(address)
        parser.set("server", "access", "public")
        parser.set("tls", "https_mode", "auto")
        parser.set("tls", "public_ip", address)
        parser.set("security", "allowed_hosts", hostname)
        url = f"https://{hostname}/"
    import io

    stream = io.StringIO()
    parser.write(stream)
    text = stream.getvalue()
    load_settings_text(text, state_dir="/data").to_server_config()
    return text, url


def _compose(
    project: str,
    output: Path,
    files: Path,
    private: bool,
    hostname: str,
    *,
    image: str | None = None,
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
                "ports": ["127.0.0.1:8080:8080"] if private else ["80:8080", "443:8443"],
                "volumes": [
                    "xferry-data:/data",
                    "xferry-acme-state:/home/xferry/.xferry",
                    "xferry-secrets:/run/secrets:ro",
                    {
                        "type": "bind",
                        "source": str(output / "xferry.ini"),
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
        "volumes": {"xferry-data": {}, "xferry-acme-state": {}, "xferry-secrets": {}},
    }
    return (json.dumps(document, indent=2) + "\n").encode()


def deploy_docker(
    output: Path,
    *,
    files_dir: Path | None = None,
    domain: str | None = None,
    private: bool = False,
    public_ip: str | None = None,
    dry_run: bool = False,
    runner: ProcessRunner | None = None,
    settings_changes: Mapping[str, object] | None = None,
    reset_credentials: bool = False,
    image: str | None = None,
) -> DockerResult:
    """Generate, initialize and health-check Compose; restore prior bundle on failure."""
    runner = runner or _Runner()
    output = output.expanduser().resolve()
    if domain and private:
        return DockerResult(2, "private mode cannot use a public domain")
    try:
        if runner.run(("docker", "compose", "version")).returncode != 0:
            return DockerResult(1, "Docker Compose v2 is required")
        if runner.run(("docker", "info")).returncode != 0:
            return DockerResult(1, "Docker daemon is unavailable or access is denied")
        metadata_path = output / _METADATA
        paths = [
            output / "compose.yaml",
            output / "xferry.ini",
            output / "secrets/xferry_auth",
            metadata_path,
            output / ".gitignore",
        ]
        if any(path.is_symlink() or (path.exists() and not path.is_file()) for path in paths):
            raise ValueError("deployment files must be regular files")
        if (output / "secrets").is_symlink():
            raise ValueError("secrets directory must not be a symlink")
        baseline = {path: path.read_bytes() if path.exists() else None for path in paths}
        previous = None
        if metadata_path.exists():
            if metadata_path.is_symlink() or metadata_path.stat().st_size > 65536:
                raise ValueError("unsafe deployment metadata")
            metadata_bytes = baseline[metadata_path]
            if metadata_bytes is None:
                raise ValueError("deployment metadata changed during preparation")
            previous = json.loads(metadata_bytes)
            if (
                not isinstance(previous, dict)
                or previous.get("schema") != 1
                or previous.get("kind") != "docker"
                or not isinstance(previous.get("project"), str)
                or not isinstance(previous.get("files_dir"), str)
                or not isinstance(previous.get("private"), bool)
            ):
                raise ValueError("unsupported deployment metadata")
            required = paths[:2] if previous.get("status") == "purged" else paths[:3]
            if any(baseline[path] is None for path in required):
                raise ValueError("deployment bundle is incomplete")
        elif output.exists() and any(output.iterdir()):
            raise ValueError("output directory is not an XFerry deployment")
        files = (
            Path(files_dir or (previous or {}).get("files_dir") or default_files_directory())
            .expanduser()
            .resolve()
        )
        if output.is_relative_to(files):
            raise ValueError("files directory must not expose the deployment configuration")
        private_secrets = (output / "secrets").resolve()
        if files.is_relative_to(private_secrets) or private_secrets.is_relative_to(files):
            raise ValueError("files directory must not expose deployment secrets")
        if files.exists() and not files.is_dir():
            raise ValueError("files path is not a directory")
        if previous and str(files) != previous["files_dir"]:
            if (Path(previous["files_dir"]) / ".xferry-encrypted").exists() or (
                files / ".xferry-encrypted"
            ).exists():
                raise ValueError("encrypted data requires a coordinated storage migration")
        project = previous["project"] if previous else f"xferry-{secrets.token_hex(6)}"
        if (
            not isinstance(project, str)
            or len(project) > 64
            or not project.startswith("xferry-")
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in project)
        ):
            raise ValueError("invalid deployment project identity")
        owned = runner.run(
            (
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                '{{.Label "io.xferry.managed"}}',
            )
        )
        if owned.returncode != 0 or any(line != "true" for line in owned.stdout.splitlines()):
            raise ValueError("Compose project contains containers not managed by XFerry")
        if previous:
            from .configuration import edit_ini

            config_bytes = baseline[paths[1]]
            if config_bytes is None:
                raise ValueError("deployment configuration is missing")
            config_text = config_bytes.decode()
            if domain is not None or public_ip is not None or private:
                generated, _ = _configuration(domain, private, public_ip)
                network = load_settings_text(generated, state_dir="/data")
                changes = {
                    key: getattr(network, key)
                    for key in (
                        "access",
                        "https_mode",
                        "host",
                        "port",
                        "domain",
                        "public_ip",
                        "allowed_hosts",
                        "cert_file",
                        "key_file",
                        "acme_http_port",
                    )
                }
                if private:
                    changes.update(email=None, acme_server=None, acme_http_address="")
                # Empty cert/key strings deliberately fail runtime validation; remove
                # the old file-certificate entries when choosing managed ACME instead.
                config_text = re.sub(
                    r"(?m)^[ \t]*(?:cert_file|key_file)[ \t]*[=:][^\r\n]*(?:\r?\n|$)",
                    "",
                    config_text,
                )
                changes.pop("cert_file")
                changes.pop("key_file")
                config_text = edit_ini(
                    config_text,
                    {key: format_ini_value(key, value) for key, value in changes.items()},
                )
        else:
            config_text, _ = _configuration(domain, private, public_ip)
        if settings_changes:
            from .configuration import edit_ini

            if any(key in {"auth_file", "files_dir"} for key in settings_changes):
                raise ValueError(
                    "deployment-owned paths and credentials require their dedicated workflow"
                )
            config_text = edit_ini(config_text, settings_changes)
        resolved = load_settings_text(config_text, state_dir="/data")
        if resolved.auth is not None:
            raise ValueError("Docker deployment credentials must use the protected auth file")
        resolved.to_server_config()
        private = not resolved.effective_tls_enabled()
        effective_host = resolved.domain
        if not effective_host and resolved.sslip and resolved.public_ip:
            from xferry.security.tls import sslip_domain_for_ip

            effective_host = sslip_domain_for_ip(resolved.public_ip)
        url = f"https://{effective_host}/" if not private else "http://127.0.0.1:8080/"
        if resolved.port != (8080 if private else 8443):
            raise ValueError("container listen port is deployment-owned; use the network workflow")
        hostname = url.split("://", 1)[1].split(":", 1)[0].rstrip("/")
        selected_image = _selected_image(previous, baseline.get(paths[0]), image)
        compose = _compose(project, output, files, private, hostname, image=selected_image)
        if dry_run:
            return DockerResult(
                0,
                "deployment validated; no files or containers changed",
                url,
                str(files),
                project=project,
            )
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _bundle_lock(output):
            if any(path.is_symlink() or (path.exists() and not path.is_file()) for path in paths):
                raise ValueError("deployment files must be regular files")
            snapshots = {path: path.read_bytes() if path.exists() else None for path in paths}
            if snapshots != baseline:
                return DockerResult(1, "deployment changed during preparation; retry the operation")
            should_start = True
            if (
                previous
                and previous.get("credentials_shown", False)
                and previous.get("status") not in {"removed", "purged"}
            ):
                active = runner.run(
                    (
                        "docker",
                        "ps",
                        "-q",
                        "--filter",
                        f"label=com.docker.compose.project={project}",
                        "--filter",
                        "label=com.docker.compose.service=xferry",
                    )
                )
                if active.returncode != 0:
                    return DockerResult(1, "could not determine the existing Docker server state")
                should_start = bool(active.stdout.strip())
            if reset_credentials and not should_start:
                return DockerResult(2, "start the Docker server before rotating credentials")
            password = None
            metadata = {
                "schema": 1,
                "kind": "docker",
                "project": project,
                "files_dir": str(files),
                "url": url,
                "private": private,
                "image": selected_image,
                "version": _image_version(selected_image),
                "state_dir": "/data",
                "status": "running" if should_start else "stopped",
                "credentials_shown": bool((previous or {}).get("credentials_shown", False)),
            }
            prefix = ("docker", "compose", "-p", project, "-f", str(paths[0]))
            try:
                files.mkdir(parents=True, exist_ok=True, mode=0o700)
                if snapshots[paths[2]] is None or reset_credentials:
                    from .credentials import generate_password

                    password = generate_password()
                    _atomic_write(paths[2], f"admin:{password}\n".encode())
                _atomic_write(paths[0], compose)
                _atomic_write(paths[1], config_text.encode(), 0o644)
                _atomic_write(metadata_path, (json.dumps(metadata, indent=2) + "\n").encode())
                _atomic_write(
                    paths[4],
                    b"secrets/\n.xferry-deployment.json\n.xferry-history.json\n.xferry.ini.lock\n",
                )
            except (OSError, ValueError):
                restored = _restore_bundle(snapshots)
                return DockerResult(
                    1,
                    "bundle write failed; "
                    + ("prior files restored" if restored else "file restoration incomplete"),
                    files_dir=str(files),
                    project=project,
                )
            try:
                _activate(runner, prefix, start=should_start)
                if not metadata["credentials_shown"] or reset_credentials:
                    username, password = paths[2].read_text().strip().split(":", 1)
                    metadata["credentials_shown"] = True
                    _atomic_write(metadata_path, (json.dumps(metadata, indent=2) + "\n").encode())
                else:
                    username, password = None, None
            except (RuntimeError, OSError) as failure:
                if previous:
                    if not _restore_bundle(snapshots):
                        return DockerResult(
                            1, "deployment failed; bundle restoration incomplete", project=project
                        )
                    try:
                        _activate(runner, prefix, start=should_start)
                    except (RuntimeError, OSError):
                        return DockerResult(
                            1,
                            "deployment failed; prior bundle restored but runtime recovery failed",
                            url,
                            str(files),
                            project=project,
                        )
                    return DockerResult(
                        1,
                        f"{failure}; prior deployment restored",
                        url,
                        str(files),
                        project=project,
                    )
                runner.run((*prefix, "stop", "xferry"))
                return DockerResult(
                    1,
                    f"{failure}; bundle, password and data were preserved",
                    url,
                    str(files),
                    project=project,
                )
            try:
                from .instances import register_instance

                register_instance(output / "xferry.ini", "docker")
            except (ImportError, OSError):
                pass
            return DockerResult(
                0,
                "Docker server is healthy"
                if should_start
                else "configuration saved; Docker server remains stopped",
                url,
                str(files),
                username,
                password,
                project,
            )
    except FileExistsError:
        return DockerResult(1, "another deployment operation is in progress")
    except (OSError, ValueError, KeyError, configparser.Error) as exc:
        return DockerResult(1, f"Docker deployment failed: {exc}")


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
                _atomic_write(path, content, 0o644 if path.name == "xferry.ini" else None)
        for path in snapshots:
            if path.name == "xferry_auth":
                try:
                    path.parent.rmdir()
                except OSError:
                    pass
        return True
    except (OSError, ValueError):
        return False


def _image_version(image: str) -> str | None:
    from .versions import is_supported_release_version

    prefix = "ghcr.io/kgmnotes/xferry:v"
    version = image.removeprefix(prefix)
    return version if image.startswith(prefix) and is_supported_release_version(version) else None


def _selected_image(
    metadata: Mapping[str, object] | None, compose: bytes | None, requested: str | None
) -> str:
    """Configuration edits retain the installed image, including older bundles."""
    image = requested or (metadata or {}).get("image")
    if image is None and compose is not None:
        try:
            document = json.loads(compose)
            image = document["services"]["xferry"]["image"]
        except (ValueError, KeyError, TypeError):
            raise ValueError("deployment image identity is missing") from None
    if image is None:
        image = f"ghcr.io/kgmnotes/xferry:v{__version__}"
    if not isinstance(image, str) or not (
        _image_version(image)
        or re.fullmatch(r"ghcr\.io/kgmnotes/xferry@sha256:[0-9a-f]{64}", image)
    ):
        raise ValueError("deployment requires an exact XFerry image version or digest")
    return image


def _operation_context(
    config: Path, runner: ProcessRunner
) -> tuple[Path, dict[str, object], tuple[str, ...]]:
    output = config.expanduser().resolve().parent
    metadata_path = output / _METADATA
    if (
        metadata_path.is_symlink()
        or not metadata_path.is_file()
        or metadata_path.stat().st_size > 65536
    ):
        raise ValueError("not an XFerry Docker deployment")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if (
        not isinstance(metadata, dict)
        or metadata.get("schema") != 1
        or metadata.get("kind") != "docker"
    ):
        raise ValueError("unsupported Docker deployment metadata")
    project = metadata.get("project")
    if not isinstance(project, str) or not re.fullmatch(r"xferry-[a-z0-9_-]{1,57}", project):
        raise ValueError("invalid Docker project identity")
    compose_path = output / "compose.yaml"
    if (
        compose_path.is_symlink()
        or not compose_path.is_file()
        or compose_path.stat().st_size > 1024 * 1024
    ):
        raise ValueError("deployment Compose file is missing or unsafe")
    metadata["image"] = _selected_image(metadata, compose_path.read_bytes(), None)
    ownership = runner.run(
        (
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            '{{.Label "io.xferry.managed"}}',
        )
    )
    if ownership.returncode or any(line != "true" for line in ownership.stdout.splitlines()):
        raise ValueError("Docker project contains containers not owned by XFerry")
    return output, metadata, ("docker", "compose", "-p", project, "-f", str(compose_path))


def docker_operation(
    config_file: Path,
    action: str,
    *,
    version: str | None = None,
    purge_data: bool = False,
    dry_run: bool = False,
    lines: int = 100,
    since: str | None = None,
    follow: bool = False,
    runner: ProcessRunner | None = None,
) -> DockerResult:
    """Use the same server commands for an owned Docker installation."""
    from .versions import is_supported_release_version

    process = runner or _Runner()
    try:
        output, metadata, prefix = _operation_context(config_file, process)
        project = str(metadata["project"])
        active = process.run(
            (
                "docker",
                "ps",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--filter",
                "label=com.docker.compose.service=xferry",
            )
        )
        if active.returncode:
            raise ValueError("could not determine Docker server status")
        running = bool(active.stdout.strip())
        details: dict[str, object] = {
            "status": "running"
            if running
            else (
                str(metadata["status"])
                if metadata.get("status") in {"removed", "purged"}
                else "stopped"
            ),
            "running": running,
            "image": metadata["image"],
            "version": metadata.get("version"),
            "project": project,
            "config": str(output / "xferry.ini"),
            "url": metadata.get("url"),
            "files_dir": metadata.get("files_dir"),
        }
        if action == "status":
            if running:
                health = process.run(
                    (
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Health.Status}}",
                        active.stdout.splitlines()[0],
                    )
                )
                details["health"] = health.stdout.strip() if health.returncode == 0 else "unknown"
            return DockerResult(
                0,
                "Docker server is running" if running else "Docker server is stopped",
                project=project,
                details=details,
            )
        if action == "logs":
            if lines < 1 or lines > 10000:
                raise ValueError("log lines must be between 1 and 10000")
            arguments = [*prefix, "logs", "--no-color", "--tail", str(lines)]
            if since:
                arguments.extend(("--since", since))
            if follow:
                arguments.append("--follow")
            arguments.append("xferry")
            if dry_run:
                return DockerResult(0, "log request validated", details=details)
            if follow and runner is None:
                code = subprocess.run(arguments, check=False).returncode
                return DockerResult(code, "Docker log stream ended", project=project)
            result = process.run(arguments)
            details["logs"] = result.stdout
            return DockerResult(result.returncode, "Docker logs", project=project, details=details)
        if action not in {"start", "stop", "restart", "update", "rollback", "uninstall"}:
            raise ValueError("unsupported Docker server action")
        if action == "update" and (version is None or not is_supported_release_version(version)):
            raise ValueError("update requires an exact supported version")
        if dry_run:
            return DockerResult(
                0, f"Docker {action} validated; no changes made", project=project, details=details
            )
        with _bundle_lock(output):
            # Re-read project identity and ownership after acquiring the shared editor lock.
            _, locked_metadata, locked_prefix = _operation_context(config_file, process)
            if locked_metadata != metadata or locked_prefix != prefix:
                raise ValueError("Docker deployment changed during preparation; retry")
            active = process.run(
                (
                    "docker",
                    "ps",
                    "-q",
                    "--filter",
                    f"label=com.docker.compose.project={project}",
                    "--filter",
                    "label=com.docker.compose.service=xferry",
                )
            )
            if active.returncode:
                raise ValueError("could not determine Docker server status")
            running = bool(active.stdout.strip())
            if action in {"start", "restart"}:
                if metadata.get("status") == "purged":
                    raise ValueError("Docker private state was purged; run xferry setup again")
                _activate(process, prefix)
                metadata["status"] = "running"
                running = True
            elif action == "stop":
                if process.run((*prefix, "stop", "xferry")).returncode:
                    raise RuntimeError("Docker server could not be stopped")
                metadata["status"] = "stopped"
                running = False
            elif action == "uninstall":
                arguments = [*prefix, "down", "--remove-orphans"]
                if purge_data:
                    arguments.append("--volumes")
                if process.run(arguments).returncode:
                    raise RuntimeError("Docker server could not be removed")
                metadata["status"] = "purged" if purge_data else "removed"
                running = False
                # The operator-owned host files folder is never removed here.
                if purge_data:
                    (output / "secrets/xferry_auth").unlink(missing_ok=True)
                    metadata["credentials_shown"] = False
            else:
                metadata = _change_docker_release(
                    output, metadata, prefix, process, action, version, running
                )
                details.update(
                    (key, metadata.get(key))
                    for key in ("status", "image", "version", "url", "files_dir")
                )
                details["running"] = running
                return DockerResult(
                    0, f"Docker {action} completed", project=project, details=details
                )
            _atomic_write(output / _METADATA, (json.dumps(metadata, indent=2) + "\n").encode())
            details.update(
                (key, metadata.get(key))
                for key in ("status", "image", "version", "url", "files_dir")
            )
            details["running"] = running
        return DockerResult(0, f"Docker {action} completed", project=project, details=details)
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
        return DockerResult(1, f"Docker operation failed: {exc}")


def _change_docker_release(
    output: Path,
    metadata: dict[str, object],
    prefix: tuple[str, ...],
    runner: ProcessRunner,
    action: str,
    version: str | None,
    running: bool,
) -> dict[str, object]:
    from .versions import compare_release_versions

    paths = (output / "compose.yaml", output / "xferry.ini", output / _METADATA)
    for path in paths:
        entry = path.lstat()
        if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or entry.st_size > 1024 * 1024:
            raise ValueError("unsafe Docker deployment file")
    before: dict[Path, bytes | None] = {path: path.read_bytes() for path in paths}
    old_compose, old_config = before[paths[0]], before[paths[1]]
    assert old_compose is not None and old_config is not None
    history_path = output / ".xferry-history.json"
    history: list[dict[str, object]] = []
    if history_path.exists():
        history_metadata = history_path.lstat()
        if (
            not stat.S_ISREG(history_metadata.st_mode)
            or history_metadata.st_nlink != 1
            or history_metadata.st_size > 1024 * 1024
        ):
            raise ValueError("unsafe Docker rollback history")
        parsed = json.loads(history_path.read_text())
        if (
            not isinstance(parsed, list)
            or len(parsed) > 5
            or not all(isinstance(item, dict) for item in parsed)
        ):
            raise ValueError("invalid Docker rollback history")
        history = parsed
    elif history_path.is_symlink():
        raise ValueError("unsafe Docker rollback history")
    before[history_path] = history_path.read_bytes() if history_path.exists() else None
    candidate: dict[str, object]
    if action == "update":
        image = f"ghcr.io/kgmnotes/xferry:v{version}"
        if str(metadata.get("image")) == image:
            return {**metadata, "status": "running" if running else "stopped"}
        current_version = _image_version(str(metadata.get("image")))
        if (
            current_version is not None
            and version is not None
            and compare_release_versions(version, current_version) < 0
        ):
            raise ValueError("Docker updates cannot downgrade; use rollback")
        if runner.run(("docker", "pull", image)).returncode:
            raise RuntimeError("selected Docker image could not be downloaded")
        document = json.loads(old_compose)
        for service in document["services"].values():
            service["image"] = image
        candidate = {**metadata, "image": image, "version": version}
        compose = (json.dumps(document, indent=2) + "\n").encode()
        config = old_config
    else:
        if not history:
            raise ValueError("no previous Docker release is available")
        saved = history[-1]
        saved_metadata = saved.get("metadata")
        if (
            not isinstance(saved_metadata, dict)
            or not isinstance(saved.get("compose"), str)
            or not isinstance(saved.get("config"), str)
        ):
            raise ValueError("invalid previous Docker metadata")
        candidate = dict(saved_metadata)
        if (
            candidate.get("project") != metadata["project"]
            or candidate.get("kind") != "docker"
            or candidate.get("schema") != 1
        ):
            raise ValueError("previous Docker release belongs to a different deployment")
        old_files = Path(str(metadata["files_dir"]))
        new_files = Path(str(candidate["files_dir"]))
        if old_files != new_files and any(
            (path / ".xferry-encrypted").exists() for path in (old_files, new_files)
        ):
            raise ValueError("encrypted storage requires coordinated migration before rollback")
        _selected_image(candidate, None, None)
        compose = str(saved["compose"]).encode()
        config = str(saved["config"]).encode()
        candidate["credentials_shown"] = metadata.get("credentials_shown", True)
    document = json.loads(compose)
    services = document.get("services")
    if (
        document.get("name") != metadata["project"]
        or not isinstance(services, dict)
        or set(services) != {"xferry", "secrets-init"}
    ):
        raise ValueError("invalid Docker release Compose identity")
    selected_image = _selected_image(candidate, compose, None)
    if any(
        not isinstance(service, dict) or service.get("image") != selected_image
        for service in services.values()
    ):
        raise ValueError("Docker release services must use the selected image")
    resolved = load_settings_text(config.decode(), state_dir="/data")
    resolved.to_server_config()
    if resolved.auth_file != "/run/secrets/xferry_auth" or resolved.files_dir != "/data/files":
        raise ValueError("Docker release must preserve deployment-owned paths")
    candidate["status"] = "running" if running else "stopped"
    snapshot: dict[str, object] = {
        "metadata": dict(metadata),
        "compose": old_compose.decode(),
        "config": old_config.decode(),
    }
    if action == "update":
        history.append(snapshot)
    else:
        history.pop()
    try:
        _atomic_write(paths[0], compose)
        _atomic_write(paths[1], config, 0o644)
        _atomic_write(paths[2], (json.dumps(candidate, indent=2) + "\n").encode())
        _atomic_write(history_path, (json.dumps(history[-5:], indent=2) + "\n").encode())
        _activate(runner, prefix, start=running)
    except (OSError, RuntimeError, ValueError) as failure:
        if not _restore_bundle(before):
            raise RuntimeError("Docker release failed; bundle restoration incomplete") from failure
        if running:
            try:
                _activate(runner, prefix)
            except (OSError, RuntimeError) as recovery:
                raise RuntimeError(
                    "Docker release failed; saved bundle restored but runtime recovery failed"
                ) from recovery
        raise
    return candidate
