"""Explicit one-time conversion of retired operator settings.

Normal configuration loading never accepts the retired names. This module only
prepares a reviewable conversion and preserves private storage through a sidecar.
"""

from __future__ import annotations

import configparser
import io
import json
import os
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .credentials import generate_password

if TYPE_CHECKING:
    from .model import ManagedLayout

LEGACY_MANAGED_UPGRADE_INSTRUCTIONS = (
    "The installed service still uses the retired --check-config startup command. "
    "Use the new portable XFerry CLI to run xferry update --to VERSION; "
    "it switches the verified runtime, settings and service unit together. "
    "For a retained reinstall instead, run xferry uninstall without --purge-data, "
    "then migrate settings with xferry config and run xferry setup. "
    "See docs/migration.md."
)


def requires_schema_upgrade(layout: ManagedLayout) -> bool:
    """Detect the old unit before a new parser can strand its installed runtime."""
    if not layout.current_executable.is_file():
        return False
    try:
        layout.unit_file.lstat()
    except FileNotFoundError:
        return False
    metadata = _safe_regular(layout.unit_file)
    assert metadata is not None
    if metadata.st_size > 65536:
        raise ValueError("managed service unit exceeds the supported size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(layout.unit_file, flags)
    with os.fdopen(descriptor, "rb") as stream:
        current = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise ValueError("managed service unit changed during inspection")
        content = stream.read(65537)
    if len(content) > 65536:
        raise ValueError("managed service unit exceeds the supported size limit")
    return b"--check-config" in content


RETIRED_SETTINGS = frozenset(
    {
        "preset",
        "public_direct",
        "tls",
        "letsencrypt",
        "sslip",
        "acme_staging",
        "auth",
        "quiet",
        "debug",
        "json_log",
        "root_dir",
        "open_browser",
    }
)


@dataclass(frozen=True)
class MigrationPlan:
    text: str
    state_dir: Path
    files_dir: Path
    auth_file: Path | None = None
    credentials: tuple[str, str] | None = field(default=None, repr=False)
    auth_content: bytes | None = field(default=None, repr=False)
    changed: bool = True


@dataclass(frozen=True)
class MigrationResult:
    exit_code: int
    message: str
    changed: bool = False
    credentials: tuple[str, str] | None = field(default=None, repr=False)


def needs_migration(text: str) -> bool:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise ValueError("invalid or duplicate INI entries") from exc
    return any(key in RETIRED_SETTINGS for section in parser.sections() for key in parser[section])


def canonicalize_legacy_text(
    text: str,
    *,
    auth_file: Path,
    state_dir: Path | str | None = None,
    config_path: Path | None = None,
) -> MigrationPlan:
    """Prepare conversion without reading credentials files or modifying storage."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(text)
    if parser.defaults():
        raise ValueError("legacy DEFAULT settings must be moved into their named sections")
    values: dict[str, str] = {}
    for section in parser.sections():
        for key, value in parser[section].items():
            if key in values:
                raise ValueError(f"ambiguous duplicate legacy setting: {key}")
            values[key] = value
    old = {name: values[name] for name in RETIRED_SETTINGS if name in values}
    if old and any(name in values for name in ("access", "https_mode", "log_level", "log_format")):
        raise ValueError(
            "configuration mixes retired and current settings; migrate one version at a time"
        )

    def enabled(name: str) -> bool:
        value = old.get(name, "false").strip().casefold()
        if value not in {"true", "yes", "on", "1", "false", "no", "off", "0"}:
            raise ValueError(f"invalid old boolean setting: {name}")
        return value in {"true", "yes", "on", "1"}

    preset = old.get("preset", "").strip()
    if preset not in {"", "local", "local-secure", "public-direct"}:
        raise ValueError("unknown retired launch preset")
    public = enabled("public_direct") if "public_direct" in old else preset == "public-direct"
    if preset == "public-direct" and not public:
        raise ValueError(
            "old public configuration disabled its protections; "
            "explicitly choose public or lab before migration"
        )
    # explicit public mode.
    default_host = "0.0.0.0" if public else "127.0.0.1"  # nosec B104
    host = values.get("host", default_host).strip()
    access = (
        "public" if public else ("private" if host in {"127.0.0.1", "localhost", "::1"} else "lab")
    )
    mode = (
        "auto"
        if enabled("sslip")
        else "domain"
        if enabled("letsencrypt")
        else "files"
        if values.get("cert_file") or values.get("key_file")
        else "self-signed"
        if enabled("tls") or preset == "local-secure"
        else "off"
    )
    if public and mode in {"off", "self-signed"}:
        raise ValueError(
            "old public configuration has no trusted HTTPS; "
            "explicitly choose HTTPS before migration"
        )
    old_root = Path(old.get("root_dir") or ".").expanduser()
    if state_dir is None and not old_root.is_absolute():
        raise ValueError(
            "old runtime working directory is unknown; "
            "supply its absolute state directory before migration"
        )
    if old_root.is_absolute():
        root = old_root.resolve()
        if state_dir is not None and root != Path(state_dir).expanduser().resolve():
            raise ValueError(
                "legacy root_dir differs from the deployment state directory; "
                "preserve that directory and migrate its deployment mapping explicitly"
            )
    else:
        assert state_dir is not None
        root = (Path(state_dir).expanduser() / old_root).resolve()
    files = Path(values.get("files_dir") or root / "uploads").expanduser()
    if not files.is_absolute():
        raise ValueError(
            "make the legacy files_dir absolute before migration; its launch directory is unknown"
        )
    files = files.resolve()
    for name in ("auth_file", "cert_file", "key_file"):
        if values.get(name):
            auxiliary = Path(values[name]).expanduser()
            if not auxiliary.is_absolute():
                raise ValueError(
                    f"make the legacy {name} absolute before migration; "
                    "its launch directory is unknown"
                )
            values[name] = str(auxiliary.resolve())
            for section in parser.sections():
                if parser.has_option(section, name):
                    parser.set(section, name, values[name])
    target_auth = auth_file.expanduser().absolute()
    if config_path is not None and config_path.resolve().is_relative_to(files):
        raise ValueError("configuration file must be outside the public files folder")
    credentials = None
    content = None
    auth_value = old.get("auth")
    existing_auth = values.get("auth_file", "").strip()
    if not existing_auth and (auth_value or preset == "local-secure"):
        if auth_value and ":" in auth_value:
            username, password = auth_value.split(":", 1)
        else:
            username = auth_value if auth_value not in {None, "random"} else "admin"
            password = generate_password()
            credentials = (username, password)
        if not username or not password or any(char in username + password for char in "\r\n\x00"):
            raise ValueError("old inline authentication is invalid")
        if target_auth.is_relative_to(files):
            raise ValueError("migrated credentials must be outside the public files folder")
        content = f"{username}:{password}\n".encode()
        existing_auth = str(target_auth)
    for section in parser.sections():
        for name in RETIRED_SETTINGS:
            parser.remove_option(section, name)
    for section in ("server", "tls", "security"):
        if not parser.has_section(section):
            parser.add_section(section)
    parser.set("server", "access", access)
    parser.set("server", "files_dir", str(files))
    parser.set("server", "host", host)
    parser.set(
        "server",
        "log_level",
        "debug" if enabled("debug") else "warning" if enabled("quiet") else "info",
    )
    parser.set("server", "log_format", "json" if enabled("json_log") else "text")
    parser.set("tls", "https_mode", mode)
    if enabled("acme_staging") and not values.get("acme_server"):
        parser.set("tls", "acme_server", "staging")
    if existing_auth:
        parser.set("security", "auth_file", existing_auth)
    stream = io.StringIO()
    parser.write(stream)
    return MigrationPlan(
        stream.getvalue(),
        root,
        files,
        target_auth if content else None,
        credentials,
        content,
        bool(old),
    )


def inspect_migration(path: Path, *, state_dir: Path | str | None = None) -> MigrationPlan:
    _safe_regular(path)
    return canonicalize_legacy_text(
        path.read_text(encoding="utf-8"),
        auth_file=path.parent / "auth",
        state_dir=state_dir,
        config_path=path,
    )


def _safe_regular(path: Path, *, optional: bool = False) -> os.stat_result | None:
    current = path.parent
    while current != current.parent:
        if current.is_symlink() or not current.is_dir():
            raise ValueError("migration paths must have real directory parents")
        current = current.parent
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > 1024 * 1024
    ):
        raise ValueError("migration files must be bounded regular files with one link")
    return metadata


def _write(path: Path, content: bytes, mode: int, *, owner: tuple[int, int] | None = None) -> None:
    metadata = _safe_regular(path, optional=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            desired = (metadata.st_uid, metadata.st_gid) if metadata else None
            current = os.fstat(stream.fileno())
            if desired is not None and (current.st_uid, current.st_gid) != desired:
                os.fchown(stream.fileno(), *desired)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def migrate_config(
    path: Path,
    *,
    state_dir: Path | str | None = None,
    confirm: Callable[[MigrationPlan], bool] | None = None,
) -> MigrationResult:
    """Convert a chosen old INI atomically; the protected backup is not a runtime alias."""
    path = path.expanduser().absolute()
    try:
        metadata = _safe_regular(path)
        assert metadata is not None
        before = path.read_bytes()
        if not needs_migration(before.decode()):
            return MigrationResult(0, "Configuration already uses current settings.")
        from .model import ManagedLayout

        layout = ManagedLayout()
        if path == layout.config_file and requires_schema_upgrade(layout):
            return MigrationResult(2, LEGACY_MANAGED_UPGRADE_INSTRUCTIONS)
        plan = inspect_migration(path, state_dir=state_dir)
        from xferry.settings import load_settings_text

        load_settings_text(plan.text, state_dir=plan.state_dir, config_path=path).to_server_config()
        if confirm is not None and not confirm(plan):
            return MigrationResult(0, "Migration cancelled; no files changed.")
        sidecar = path.with_name(f".{path.name}.state.json")
        backup = path.with_name(f".{path.name}.before-migration")
        for extra in (sidecar, backup):
            _safe_regular(extra, optional=True)
        if plan.auth_file is not None:
            _safe_regular(plan.auth_file, optional=True)
        previous_sidecar = sidecar.read_bytes() if sidecar.exists() else None
        previous_auth = (
            plan.auth_file.read_bytes() if plan.auth_file and plan.auth_file.exists() else None
        )
        if backup.exists() and backup.read_bytes() != before:
            raise ValueError(
                "a different migration backup already exists; preserve it before retrying"
            )
        if previous_auth is not None and previous_auth != plan.auth_content:
            raise ValueError(
                "migration would replace an existing auth file; select a separate credentials path"
            )
        from .configuration import _portable_lock

        if os.name == "posix" and path == layout.config_file:
            from .system import managed_mutation

            lock = managed_mutation(layout.lock_file)
        else:
            lock = _portable_lock(path)
        with lock:
            if path == layout.config_file and requires_schema_upgrade(layout):
                return MigrationResult(2, LEGACY_MANAGED_UPGRADE_INSTRUCTIONS)
            return _apply_migration(
                path, before, metadata, plan, sidecar, backup, previous_sidecar, previous_auth
            )
    except configparser.Error:
        return MigrationResult(
            2, "Configuration migration failed: invalid or duplicate INI entries."
        )
    except (OSError, ValueError, RuntimeError) as exc:
        return MigrationResult(2, f"Configuration migration failed: {exc}")


def _apply_migration(
    path: Path,
    before: bytes,
    metadata: os.stat_result,
    plan: MigrationPlan,
    sidecar: Path,
    backup: Path,
    previous_sidecar: bytes | None,
    previous_auth: bytes | None,
) -> MigrationResult:
    for extra in (path, backup, sidecar):
        _safe_regular(extra, optional=extra != path)
    if (
        path.read_bytes() != before
        or (sidecar.read_bytes() if sidecar.exists() else None) != previous_sidecar
    ):
        raise ValueError("configuration changed during migration; retry")
    if plan.auth_file is not None:
        _safe_regular(plan.auth_file, optional=True)
        if (plan.auth_file.read_bytes() if plan.auth_file.exists() else None) != previous_auth:
            raise ValueError("credentials changed during migration; retry")
    if backup.exists() and backup.read_bytes() != before:
        raise ValueError("a different migration backup already exists; preserve it before retrying")
    from xferry.encrypted_storage import EncryptedStorageConflict, prepare_legacy_encrypted_binding

    from .release_configuration import DeploymentFile, apply_encrypted_binding

    try:
        binding = prepare_legacy_encrypted_binding(plan.state_dir, plan.files_dir)
    except EncryptedStorageConflict as exc:
        raise ValueError("encrypted storage cannot be safely migrated") from exc
    if binding is not None:
        _safe_regular(binding[0], optional=True)
        if binding[0].exists():
            raise ValueError("encrypted storage binding changed during migration; retry")
    try:
        _write(backup, before, 0o600)
        if plan.auth_file is not None and plan.auth_content is not None:
            _write(plan.auth_file, plan.auth_content, 0o600)
        _write(
            sidecar,
            (
                json.dumps(
                    {
                        "schema": 1,
                        "state_dir": str(plan.state_dir),
                        "files_dir": str(plan.files_dir),
                    }
                )
                + "\n"
            ).encode(),
            0o600,
        )
        if binding is not None:
            target, payload, uid, gid = binding
            apply_encrypted_binding(target, DeploymentFile(payload, 0o600, uid, gid), owner=uid)
        _write(path, plan.text.encode(), stat.S_IMODE(metadata.st_mode))
    except (OSError, ValueError):
        if binding is not None:
            apply_encrypted_binding(binding[0], None, owner=binding[2])
        _write(path, before, stat.S_IMODE(metadata.st_mode))
        if previous_sidecar is None:
            sidecar.unlink(missing_ok=True)
        else:
            _write(sidecar, previous_sidecar, 0o600)
        if plan.auth_file is not None:
            if previous_auth is None:
                plan.auth_file.unlink(missing_ok=True)
            else:
                _write(plan.auth_file, previous_auth, 0o600)
        raise
    return MigrationResult(
        0,
        "Configuration migrated; file contents and storage locations were retained.",
        True,
        plan.credentials,
    )
