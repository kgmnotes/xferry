"""Portable configuration discovery and lossless, validated configuration edits.

Linux lifecycle modules are imported only when a managed operation is requested.
"""

from __future__ import annotations

import difflib
import errno
import json
import os
import re
import stat
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from xferry.settings import ServerSettings, SettingsError, load_settings_text, resolve_settings
from xferry.settings_schema import SETTING_SPEC_BY_NAME, SETTING_SPECS, format_ini_value

_BASIC = frozenset(
    {
        "access",
        "https_mode",
        "files_dir",
        "port",
        "max_size_mb",
        "upload_storage_limit_mb",
        "upload_reserve_free_mb",
        "encrypted_uploads",
    }
)
_SECTION = re.compile(r"^\s*\[([^]]+)\]\s*(?:[#;].*)?$")
_ENTRY = re.compile(r"^(\s*)([^\s#;][^=:]*?)(\s*[=:]\s*)(.*?)(\r?\n)?$")


@dataclass(frozen=True)
class ConfigurationResult:
    exit_code: int
    message: str
    changed: bool = False
    applied: bool = False
    diff: str = ""


@dataclass(frozen=True)
class PasswordResult:
    exit_code: int
    message: str
    username: str | None = None
    password: str | None = field(default=None, repr=False)


def default_user_data_dir() -> Path:
    from xferry.paths import default_user_data_dir as shared_default

    return shared_default()


def default_files_dir(*, managed: bool = False) -> Path:
    from xferry.paths import default_files_dir as shared_default

    return Path("/var/lib/xferry/files") if managed else shared_default()


def resolve_config_path(config: str | Path | None, target: str | None = None) -> tuple[Path, str]:
    from .instances import resolve_instance

    instance = resolve_instance(config, prefer_portable=target == "portable")
    return instance.config, target or instance.target


def state_for_config(path: Path, target: str) -> Path | None:
    if target == "managed":
        return Path("/var/lib/xferry")
    if target == "docker":
        return Path("/data")
    from xferry.paths import state_for_config as migrated_state

    return migrated_state(path)


def _public_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return list(value)
    return value


def resolve_with_origins(
    text: str,
    *,
    env: Mapping[str, str] | None = None,
    cli_values: Mapping[str, object] | None = None,
    state_dir: Path | None = None,
    config_path: Path | None = None,
) -> tuple[ServerSettings, dict[str, str]]:
    """Use the runtime resolver's layer provenance."""
    settings = resolve_settings(
        file_settings=load_settings_text(text, validate=False),
        env=dict(env or {}),
        cli_values=dict(cli_values or {}),
        state_dir=state_dir,
        config_path=config_path,
    )
    return settings, settings._origins


def describe_settings(
    text: str,
    *,
    env: Mapping[str, str] | None = None,
    all_settings: bool = False,
    group: str | None = None,
    search: str | None = None,
    key: str | None = None,
    state_dir: Path | None = None,
    config_path: Path | None = None,
) -> list[dict[str, object]]:
    settings, origins = resolve_with_origins(
        text, env=env, state_dir=state_dir, config_path=config_path
    )
    runtime = settings.to_server_config()
    defaults = ServerSettings()
    if key is not None and key not in SETTING_SPEC_BY_NAME:
        raise SettingsError(f"unknown setting: {key}")
    rows: list[dict[str, object]] = []
    for spec in SETTING_SPECS:
        description = spec.description.format(default=getattr(defaults, spec.name))
        if key is not None and spec.name != key:
            continue
        if (
            key is None
            and not all_settings
            and group is None
            and search is None
            and spec.name not in _BASIC
        ):
            continue
        if group is not None and spec.section != group:
            continue
        if (
            search is not None
            and search.casefold() not in f"{spec.name} {description} {spec.section}".casefold()
        ):
            continue
        secret = spec.redaction == "secret"
        unit = "MiB" if spec.name.endswith("_mb") else "KiB" if spec.name.endswith("_kb") else None
        if (
            "timeout" in spec.name
            or spec.name.endswith("_seconds")
            or spec.name == "smuggle_temp_age"
        ):
            unit = "seconds"
        if spec.name == "body_min_rate":
            unit = "bytes/s"
        if spec.name == "files_dir":
            apply_kind = "files-folder workflow; updates the service or container mapping"
        elif spec.name == "auth_file":
            apply_kind = "credentials workflow; use Password or credentials reset"
        elif spec.section == "tls":
            apply_kind = "HTTPS workflow; validates certificates and verifies the restarted server"
        else:
            apply_kind = "restart"
        configured = getattr(settings, spec.name)
        value = configured
        automatic = False
        if spec.name == "body_memory_budget_mb" and configured is None:
            value = (runtime.limits.body_memory_budget or 0) / (1024 * 1024)
            automatic = True
        elif spec.name == "max_websocket_connections" and configured is None:
            value = runtime.websocket.max_connections
            automatic = True
        default_value = _public_value(getattr(defaults, spec.name))
        if default_value is None:
            default_value = {
                "https_mode": "off for private/lab; auto for public",
                "files_dir": str(default_files_dir()),
                "body_memory_budget_mb": "automatic from request size and worker count",
                "max_websocket_connections": "automatic: half of the worker count",
            }.get(spec.name, "not set")
        rows.append(
            {
                "name": spec.name,
                "group": spec.section,
                "description": description,
                "value": "***" if secret and value else _public_value(value),
                "default": "***" if secret and getattr(defaults, spec.name) else default_value,
                "source": "automatic" if automatic else origins[spec.name],
                "configured": _public_value(configured),
                "effective": _public_value(value),
                "example": spec.example,
                "constraints": spec.constraints,
                "dependencies": spec.dependencies,
                "applicability": spec.applicability,
                "unit": unit,
                "ini": f"[{spec.section}] {spec.ini_key}",
                "environment": spec.env_name,
                "cli": list(spec.cli_flags),
                "apply": apply_kind,
            }
        )
    return rows


def parse_assignments(assignments: Sequence[str]) -> dict[str, str]:
    changes: dict[str, str] = {}
    for assignment in assignments:
        key, separator, value = assignment.partition("=")
        if not separator or key not in SETTING_SPEC_BY_NAME:
            raise SettingsError(f"expected a known KEY=VALUE, received {key!r}")
        if SETTING_SPEC_BY_NAME[key].redaction == "secret":
            raise SettingsError(
                "inline secrets cannot be set here; use a protected auth_file or credentials reset"
            )
        if "\n" in value or "\r" in value or "\x00" in value:
            raise SettingsError(f"{key}: values must occupy one INI line")
        changes[key] = value
    return changes


def edit_ini(text: str, changes: Mapping[str, object]) -> str:
    """Replace entries while preserving comments; clearing cert/key removes them.

    File-certificate settings use the string grammar, so emitting an empty
    option would create an invalid runtime path. The editor removes such an
    option instead; raw runtime flag validation remains unchanged.
    """
    load_settings_text(text, validate=False)
    pending = dict(changes)
    if set(pending) - set(SETTING_SPEC_BY_NAME):
        raise SettingsError("unknown setting in configuration changes")
    removed = {
        name
        for name, value in pending.items()
        if name in {"cert_file", "key_file"} and (value is None or value == "")
    }
    pending = {name: format_ini_value(name, value) for name, value in pending.items()}
    if any(
        any(character in str(value) for character in ("\n", "\r", "\x00"))
        for value in pending.values()
    ):
        raise SettingsError("new settings values must occupy one INI line")
    lines = text.splitlines(keepends=True)
    result: list[str] = []
    section: str | None = None
    skipping_continuation = False

    def append_missing(current: str | None) -> None:
        names = [
            spec.name for spec in SETTING_SPECS if spec.section == current and spec.name in pending
        ]
        for name in names:
            if name in removed:
                pending.pop(name)
                continue
            if result and not result[-1].endswith(("\n", "\r")):
                result[-1] += "\n"
            value = pending.pop(name)
            result.append(f"{name} = {value}\n")

    for line in lines:
        header = _SECTION.match(line.rstrip("\r\n"))
        if header:
            append_missing(section)
            section = header.group(1).strip().lower()
            skipping_continuation = False
            result.append(line)
            continue
        if (
            skipping_continuation
            and line[:1].isspace()
            and line.strip()
            and not line.lstrip().startswith(("#", ";"))
        ):
            continue
        skipping_continuation = False
        entry = _ENTRY.match(line)
        if entry:
            key = entry.group(2).strip().lower()
            spec = SETTING_SPEC_BY_NAME.get(key)
            if spec is not None and spec.section == section and key in pending:
                value = pending.pop(key)
                if key in removed:
                    skipping_continuation = True
                    continue
                newline = entry.group(5) or "\n"
                result.append(f"{entry.group(1)}{entry.group(2)}{entry.group(3)}{value}{newline}")
                skipping_continuation = True
                continue
        result.append(line)
    append_missing(section)
    for name in removed:
        pending.pop(name, None)
    for new_section in dict.fromkeys(SETTING_SPEC_BY_NAME[name].section for name in pending):
        if result and not result[-1].endswith(("\n", "\r")):
            result[-1] += "\n"
        result.append(f"\n[{new_section}]\n")
        append_missing(new_section)
    candidate = "".join(result)
    load_settings_text(candidate, validate=False)
    return candidate


def _redacted_text(text: str) -> str:
    secret_keys = {"auth"} | {spec.name for spec in SETTING_SPECS if spec.redaction == "secret"}
    lines = []
    continuation = False
    for line in text.splitlines(keepends=True):
        if (
            continuation
            and line[:1].isspace()
            and line.strip()
            and not line.lstrip().startswith(("#", ";"))
        ):
            lines.append("    ***\n")
            continue
        match = _ENTRY.match(line)
        continuation = bool(match and match.group(2).strip().lower() in secret_keys)
        lines.append(f"{match.group(2)} = ***\n" if continuation and match else line)
    return "".join(lines)


def configuration_diff(before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            _redacted_text(before).splitlines(True),
            _redacted_text(after).splitlines(True),
            fromfile="current",
            tofile="proposed",
        )
    )


def _read_config(path: Path) -> str:
    if not path.exists():
        return ""
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SettingsError("configuration must be a regular file with one link")
    return path.read_text(encoding="utf-8")


def _atomic_write(path: Path, text: str | bytes, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = path.stat() if path.exists() else None
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(text.encode("utf-8") if isinstance(text, str) else text)
            stream.flush()
            os.fsync(stream.fileno())
            if metadata is not None:
                if hasattr(os, "fchmod"):
                    os.fchmod(
                        stream.fileno(),
                        mode if mode is not None else stat.S_IMODE(metadata.st_mode),
                    )
                else:
                    temporary_path.chmod(
                        mode if mode is not None else stat.S_IMODE(metadata.st_mode)
                    )
                if hasattr(os, "fchown"):
                    os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def reset_portable_password(
    path: Path, *, changes: Mapping[str, str] | None = None
) -> PasswordResult:
    """Create a private generated credential without logging its contents."""
    if {"XFERRY_AUTH", "XFERRY_AUTH_FILE"} & os.environ.keys():
        raise SettingsError(
            "remove authentication environment overrides before rotating credentials"
        )
    with _portable_lock(path):
        before = _read_config(path)
        settings = load_settings_text(
            before,
            config_path=path,
            state_dir=state_for_config(path, "portable"),
        )
        auth_path = (
            Path(settings.auth_file).expanduser().absolute()
            if settings.auth_file
            else path.parent / "xferry.auth"
        )
        metadata = auth_path.lstat() if auth_path.exists() or auth_path.is_symlink() else None
        if metadata is not None and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1):
            raise SettingsError("auth file must be a regular file with one link")
        previous_secret = auth_path.read_bytes() if metadata is not None else None
        previous_mode = stat.S_IMODE(metadata.st_mode) if metadata is not None else 0o600
        candidate = edit_ini(before, {**dict(changes or {}), "auth_file": str(auth_path)})
        checked = load_settings_text(
            candidate, config_path=path, state_dir=state_for_config(path, "portable")
        )
        checked.to_server_config()
        files_folder = Path(checked.files_dir or default_files_dir()).resolve()
        if path.resolve().is_relative_to(files_folder) or auth_path.resolve().is_relative_to(
            files_folder
        ):
            raise SettingsError(
                "configuration and auth file must be outside the public files folder"
            )
        from .credentials import generate_password

        password = generate_password()
        try:
            _atomic_write(auth_path, f"admin:{password}\n", mode=0o600)
            _atomic_write(path, candidate)
        except OSError:
            restored = True
            try:
                if previous_secret is None:
                    auth_path.unlink(missing_ok=True)
                else:
                    _atomic_write(auth_path, previous_secret, mode=previous_mode)
                if path.exists():
                    _atomic_write(path, before)
            except OSError:
                restored = False
            return PasswordResult(
                1,
                "Password change failed; "
                + (
                    "previous files restored." if restored else "check private configuration files."
                ),
            )
        return PasswordResult(
            0, f"Password saved. Restart with: xferry run --config {path}", "admin", password
        )


@contextmanager
def _portable_lock(path: Path) -> Iterator[None]:
    """Hold a kernel lock; a crashed editor cannot leave an operation blocked."""
    import sys

    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(f".{path.name}.lock")
    if lock.is_symlink():
        raise SettingsError("configuration lock must be a regular file")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SettingsError("configuration lock must be a regular file with one link")
        if sys.platform == "win32":
            import msvcrt

            if metadata.st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise SettingsError("another configuration operation is in progress") from None
                raise
            try:
                yield
            finally:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SettingsError("another configuration operation is in progress") from None
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        # Keep the inode: unlinking permits a second process to lock a new file
        # while an existing waiter still refers to the old one.
        os.close(descriptor)


def change_configuration(
    path: Path,
    changes: Mapping[str, str],
    *,
    target: str = "portable",
    apply: bool = True,
    dry_run: bool = False,
    confirm: Callable[[str], bool] | None = None,
) -> ConfigurationResult:
    before = _read_config(path)
    changes = dict(changes)
    if target == "managed":
        protected = {"auth_file"} & set(changes)
        if protected:
            raise SettingsError(
                "managed state/auth paths are installation-owned; "
                "use credentials reset for the password"
            )
    candidate_changes = dict(changes)
    if "files_dir" in candidate_changes:
        candidate_changes["files_dir"] = str(
            Path(candidate_changes["files_dir"]).expanduser().resolve()
            if candidate_changes["files_dir"]
            else default_files_dir(managed=target == "managed")
        )
    if "files_dir" in changes and not changes["files_dir"]:
        changes["files_dir"] = candidate_changes["files_dir"]
    if target == "managed" and "files_dir" in candidate_changes:
        from .managed_files import managed_files_path
        from .model import ManagedLayout

        layout = ManagedLayout()
        host_folder = Path(candidate_changes["files_dir"])
        if managed_files_path(layout).resolve() == host_folder:
            changes.pop("files_dir", None)
            candidate_changes.pop("files_dir", None)
        else:
            for private in (
                layout.config_file.parent,
                layout.data_root / "notes",
                layout.acme_root,
            ):
                if private.resolve().is_relative_to(host_folder):
                    raise SettingsError("files folder would expose private XFerry state")
            candidate_changes["files_dir"] = str(layout.data_root / "files")
    candidate = edit_ini(before, candidate_changes)
    environment = dict(os.environ) if target == "portable" else {}
    resolved = resolve_settings(
        file_settings=load_settings_text(candidate, validate=False),
        env=environment,
        state_dir=state_for_config(path, target),
        config_path=path,
    )
    resolved.to_server_config()
    files_folder = Path(resolved.files_dir or default_files_dir()).resolve()
    if target == "portable" and path.resolve().is_relative_to(files_folder):
        raise SettingsError("configuration file must be outside the public files folder")
    diff = configuration_diff(before, candidate)
    # Folder mappings may change even when the runtime destination is unchanged.
    mapping_change = target == "managed" and "files_dir" in changes
    if mapping_change:
        diff += f"Host files folder: {Path(changes['files_dir']).expanduser().resolve()}\n"
    if candidate == before and not mapping_change:
        return ConfigurationResult(0, "Configuration is unchanged.")
    if dry_run:
        return ConfigurationResult(0, "Configuration is valid; no changes made.", diff=diff)
    if confirm is not None and not confirm(diff):
        return ConfigurationResult(0, "Cancelled; no changes made.")
    if target == "managed":
        return _change_managed(path, before, candidate, changes, apply=apply, diff=diff)
    with _portable_lock(path):
        if _read_config(path) != before:
            raise SettingsError("configuration changed during editing; retry")
        _atomic_write(path, candidate)
    message = f"Saved {path}. Restart with: xferry run --config {path}"
    if any(spec.env_name in environment for spec in SETTING_SPECS if spec.name in changes):
        message += ". Environment overrides still take precedence."
    return ConfigurationResult(0, message, changed=True, diff=diff)


def _change_managed(
    path: Path,
    before: str,
    candidate: str,
    changes: Mapping[str, str],
    *,
    apply: bool,
    diff: str,
) -> ConfigurationResult:
    if os.geteuid() != 0:
        return ConfigurationResult(3, "managed configuration changes require root")
    from .health import authenticated_ping
    from .model import ManagedLayout
    from .service import _credentials, _endpoint
    from .setup import _wait_for_health
    from .system import CommandRunner, FilesystemTransaction, managed_mutation

    layout = ManagedLayout()
    runner = CommandRunner()
    with managed_mutation(layout.lock_file):
        if path != layout.config_file or _read_config(path) != before:
            raise SettingsError("managed configuration changed during editing; retry")
        old_settings = load_settings_text(before, state_dir=layout.data_root, config_path=path)
        new_settings = load_settings_text(candidate, state_dir=layout.data_root, config_path=path)
        if "files_dir" in changes:
            root = Path(old_settings.root_dir)
            if any((root / ".xferry" / "encrypted-uploads").glob("*.json")):
                raise SettingsError(
                    "move encrypted payloads and their state together "
                    "before changing the files folder"
                )
        metadata = path.stat()
        active = runner.run(("systemctl", "is-active", "--quiet", "xferry.service")).returncode == 0
        if active and not apply:
            return ConfigurationResult(
                2, "running service changes must be applied; use --dry-run to preview", diff=diff
            )
        from .managed_files import managed_files_path

        host_folder = (
            Path(changes["files_dir"]).expanduser().resolve()
            if "files_dir" in changes
            else managed_files_path(layout)
        )
        private_files = tuple(
            Path(value).expanduser().resolve()
            for value in (new_settings.cert_file, new_settings.key_file, new_settings.auth_file)
            if value is not None
        )
        if any(private.is_relative_to(host_folder) for private in private_files):
            raise SettingsError("files folder would expose a certificate, private key or auth file")
        transaction = FilesystemTransaction()
        try:
            mapping = "files_dir" in changes
            if mapping:
                import pwd

                from .managed_files import stage_managed_files_folder

                account = pwd.getpwnam("xferry")
                stage_managed_files_folder(
                    layout,
                    Path(changes["files_dir"]).expanduser().resolve(),
                    transaction,
                    account.pw_uid,
                    account.pw_gid,
                    private_files=private_files,
                )
            transaction.atomic_write(
                path,
                candidate.encode(),
                mode=stat.S_IMODE(metadata.st_mode),
                uid=metadata.st_uid,
                gid=metadata.st_gid,
            )
            result = runner.run(
                (str(layout.current_executable), "config", "check", "--config", str(path))
            )
            if result.returncode:
                raise SettingsError("installed runtime rejected the configuration")
            if mapping and runner.run(("systemctl", "daemon-reload")).returncode:
                raise SettingsError("could not reload the service folder mapping")
            if apply and active:
                if runner.run(("systemctl", "restart", "xferry.service")).returncode:
                    raise SettingsError("service restart failed")
                endpoint = _endpoint(new_settings)
                credentials = _credentials(layout.auth_file)
                if endpoint is None or credentials is None:
                    raise SettingsError("cannot verify service health")
                readiness = _wait_for_health(
                    authenticated_ping,
                    endpoint,
                    *credentials,
                    readiness_timeout=120,
                    timeout=2,
                    monotonic=time.monotonic,
                    sleep=time.sleep,
                )
                if not readiness.health.ok:
                    raise SettingsError("service health check failed")
            transaction.commit()
        except Exception as error:
            transaction.rollback()
            runner.run(("systemctl", "daemon-reload"))
            rollback_ok = True
            if apply and active:
                rollback_ok = runner.run(("systemctl", "restart", "xferry.service")).returncode == 0
                old_endpoint = _endpoint(old_settings)
                old_credentials = _credentials(layout.auth_file)
                if rollback_ok and old_endpoint is not None and old_credentials is not None:
                    rollback_ok = _wait_for_health(
                        authenticated_ping,
                        old_endpoint,
                        *old_credentials,
                        readiness_timeout=120,
                        timeout=2,
                        monotonic=time.monotonic,
                        sleep=time.sleep,
                    ).health.ok
            message = "Configuration failed and was restored."
            if isinstance(error, ValueError):
                message += f" {error}"
            if not rollback_ok:
                message += " The previous service needs attention; run xferry doctor."
            return ConfigurationResult(1, message, diff=diff)
    applied = apply and active
    message = "Configuration applied and service is healthy." if applied else "Configuration saved."
    if not active:
        message += " The service remains stopped."
    elif not apply:
        message += " Run sudo xferry restart to apply it."
    return ConfigurationResult(0, message, changed=True, applied=applied, diff=diff)


def render_rows(rows: Sequence[Mapping[str, object]], *, json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(list(rows), ensure_ascii=False, indent=2))
    else:
        for row in rows:
            unit = f" {row['unit']}" if row.get("unit") else ""
            value = row["value"]
            if value is None:
                value = "not set"
            elif isinstance(value, bool):
                value = str(value).lower()
            elif isinstance(value, list):
                value = ", ".join(str(item) for item in value) or "not set"
            print(f"{row['name']} = {value}{unit} ({row['source']})")
            print(f"  {row['description']}")


def annotate_host_folder(rows: list[dict[str, object]], path: Path, target: str) -> None:
    """Present the host folder rather than an internal service/container mount."""
    if target == "managed":
        from .managed_files import managed_files_path
        from .model import ManagedLayout

        host = str(managed_files_path(ManagedLayout()))
    elif target == "docker":
        document = json.loads((path.parent / ".xferry-deployment.json").read_text(encoding="utf-8"))
        host = str(document["files_dir"])
    else:
        return
    for row in rows:
        if row["name"] == "files_dir":
            row["runtime_value"] = row["value"]
            row["value"] = host
