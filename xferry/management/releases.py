"""Verified immutable release updates, rollback, and conservative uninstall."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any, Protocol
from urllib.parse import urljoin, urlsplit

from xferry.security.tls import sslip_domain_for_ip
from xferry.settings import SettingsError, load_settings_file

from .health import HealthEndpoint, HealthResult, authenticated_ping
from .managed_state import has_unsupported_managed_state
from .model import ManagedLayout
from .system import (
    CommandRunner,
    InsufficientPrivilege,
    MutationLocked,
    Runner,
    UnsafeLock,
    managed_mutation,
)
from .versions import is_canonical_release_version, is_supported_release_version

_SERVICE = "xferry.service"
_MANIFEST_NAME = "xferry-release.json"
_EXECUTABLE_NAME = "xferry"
_PLATFORM = "linux-x86_64"
_MAX_MANIFEST_BYTES = 64 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

HealthCheck = Callable[[HealthEndpoint, str, str, float], HealthResult]


class _ServiceState(Enum):
    ACTIVE = "active"
    CONFIRMED_INACTIVE = "inactive"
    PROBE_ERROR = "probe_error"


class Downloader(Protocol):
    """Download one HTTPS resource to a caller-selected staging path."""

    def download(self, url: str, destination: Path, max_bytes: int) -> None: ...


class _UrlOpener(Protocol):
    def open(self, request: urllib.request.Request, *, timeout: float) -> Any: ...


class _HttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirect destinations that leave the HTTPS credential-free boundary."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        resolved = urljoin(request.full_url, new_url)
        _require_https_redirect_url(resolved)
        return super().redirect_request(
            request,
            fp,
            code,
            message,
            headers,
            resolved,
        )


class HttpsDownloader:
    """Bounded HTTPS downloader that never logs request or response material."""

    def __init__(self, *, timeout: float = 30.0, opener: _UrlOpener | None = None) -> None:
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener(_HttpsRedirectHandler())

    def download(self, url: str, destination: Path, max_bytes: int) -> None:
        """Write at most ``max_bytes`` from a credential-free HTTPS URL."""
        _require_https_url(url)
        request = urllib.request.Request(url, method="GET")  # noqa: S310 - HTTPS checked above
        with self.opener.open(request, timeout=self.timeout) as response:
            _require_https_redirect_url(response.geturl())
            with destination.open("xb") as stream:
                remaining = max_bytes + 1
                while remaining:
                    chunk = response.read(min(64 * 1024, remaining))
                    if not chunk:
                        break
                    stream.write(chunk)
                    remaining -= len(chunk)
                stream.flush()
                os.fsync(stream.fileno())
        if destination.stat().st_size > max_bytes:
            raise OSError("download exceeded the permitted size")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


@dataclass(frozen=True)
class ReleaseManifest:
    """Exact Task 1 release-bundle metadata needed to verify one SCIE."""

    schema_version: int
    version: str
    tag: str
    platform: str
    executable_name: str
    executable_size: int
    executable_sha256: str

    @classmethod
    def parse(cls, payload: bytes) -> ReleaseManifest:
        """Parse only the literal schema emitted by ``build_scie_release.py``."""
        try:
            if not isinstance(payload, bytes) or len(payload) > _MAX_MANIFEST_BYTES:
                raise ValueError
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
            if not isinstance(document, dict) or set(document) != {
                "schema_version",
                "version",
                "tag",
                "platform",
                "executable",
            }:
                raise ValueError
            schema_version = document["schema_version"]
            version = document["version"]
            tag = document["tag"]
            platform_id = document["platform"]
            executable = document["executable"]
            if schema_version != 1 or isinstance(schema_version, bool):
                raise ValueError
            if not all(isinstance(value, str) for value in (version, tag, platform_id)):
                raise ValueError
            if _safe_version(version) is None or tag != f"v{version}":
                raise ValueError
            if platform_id not in {_PLATFORM}:
                if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9_]+)+", platform_id):
                    raise ValueError
            if not isinstance(executable, dict) or set(executable) != {
                "name",
                "size",
                "sha256",
            }:
                raise ValueError
            name = executable["name"]
            size = executable["size"]
            sha256 = executable["sha256"]
            if not isinstance(name, str) or not _safe_basename(name):
                raise ValueError
            if name != f"xferry-{version}-{platform_id}":
                raise ValueError
            if not isinstance(size, int) or isinstance(size, bool) or size < 1:
                raise ValueError
            if not isinstance(sha256, str) or _SHA256_RE.fullmatch(sha256) is None:
                raise ValueError
            return cls(
                schema_version=schema_version,
                version=version,
                tag=tag,
                platform=platform_id,
                executable_name=name,
                executable_size=size,
                executable_sha256=sha256,
            )
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise ValueError("invalid release manifest") from None

    def to_bytes(self) -> bytes:
        """Serialize the exact public manifest schema beside an installed binary."""
        return (
            json.dumps(
                {
                    "schema_version": self.schema_version,
                    "version": self.version,
                    "tag": self.tag,
                    "platform": self.platform,
                    "executable": {
                        "name": self.executable_name,
                        "size": self.executable_size,
                        "sha256": self.executable_sha256,
                    },
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8")


@dataclass(frozen=True)
class ReleaseResult:
    """Secret-free stable result returned by each release lifecycle operation."""

    exit_code: int
    message: str
    version: str | None = None
    dry_run: bool = False


class _ReleaseFailure(RuntimeError):
    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


@dataclass(frozen=True)
class _HealthContext:
    endpoint: HealthEndpoint
    username: str
    password: str


class ReleaseManager:
    """Coordinate verified immutable releases through one shared host lock."""

    def __init__(
        self,
        *,
        layout: ManagedLayout | None = None,
        runner: Runner | None = None,
        downloader: Downloader | None = None,
        health_check: HealthCheck = authenticated_ping,
        effective_uid: Callable[[], int] = os.geteuid,
        root_uid: int = 0,
        release_base_url: str = "https://github.com/kgmnotes/xferry/releases",
        platform_id: Callable[[], str] | None = None,
        unit_path: Path = Path("/etc/systemd/system/xferry.service"),
        cli_link: Path = Path("/usr/local/bin/xferry"),
        acme_root: Path | None = None,
        staging_parent: Path | None = None,
        health_timeout: float = 2.0,
    ) -> None:
        self.layout = replace(
            layout or ManagedLayout(),
            unit_file=unit_path,
            cli_link=cli_link,
        )
        self.runner = runner or CommandRunner()
        self.downloader = downloader or HttpsDownloader()
        self.health_check = health_check
        self.effective_uid = effective_uid
        self.root_uid = root_uid
        self.release_base_url = release_base_url.rstrip("/")
        self.platform_id = platform_id or _local_platform
        self.unit_path = unit_path
        self.cli_link = cli_link
        self.acme_root = acme_root or self.layout.acme_root
        self.staging_parent = staging_parent
        self.health_timeout = health_timeout

    def update(self, version: str | None, dry_run: bool) -> ReleaseResult:
        """Download, verify, install, switch, and health-gate one exact release."""
        if not dry_run and self.effective_uid() != 0:
            return ReleaseResult(3, "release_requires_root")
        requested = None if version is None else _safe_version(version)
        if version is not None and requested is None:
            return ReleaseResult(2, "invalid_release_version")
        if requested is not None and not is_supported_release_version(requested):
            return ReleaseResult(2, "unsupported_release_major", version=requested)
        try:
            self._require_supported_managed_installation()
            _require_https_url(self.release_base_url)
            self._current_supported_version()
            with self._staging_directory() as staging:
                manifest = self._download_manifest(staging, requested)
                if requested is not None and manifest.version != requested:
                    raise _ReleaseFailure(1, "release_manifest_mismatch")
                if not is_supported_release_version(manifest.version):
                    return ReleaseResult(
                        2,
                        "unsupported_release_major",
                        version=manifest.version,
                    )
                if manifest.platform != self.platform_id():
                    raise _ReleaseFailure(4, "release_platform_unsupported")
                candidate = self._download_candidate(staging, manifest)
                if dry_run:
                    self._validate_candidate(candidate)
                    return ReleaseResult(
                        0,
                        "update_dry_run",
                        version=manifest.version,
                        dry_run=True,
                    )
                with managed_mutation(
                    self.layout.lock_file,
                    effective_uid=self.effective_uid,
                    root_uid=self.root_uid,
                ):
                    self._require_supported_managed_installation()
                    self._validate_candidate(candidate)
                    return self._update_locked(manifest, candidate)
        except _ReleaseFailure as failure:
            return ReleaseResult(failure.exit_code, failure.message, version=requested)
        except InsufficientPrivilege:
            return ReleaseResult(3, "release_requires_root")
        except MutationLocked:
            return ReleaseResult(1, "release_operation_locked")
        except UnsafeLock:
            return ReleaseResult(1, "release_lock_unsafe")
        except (OSError, SettingsError, ValueError):
            return ReleaseResult(1, "release_operation_failed", version=requested)

    def rollback(self, to_version: str | None, dry_run: bool) -> ReleaseResult:
        """Switch to a verified installed release and health-gate the result."""
        if not dry_run and self.effective_uid() != 0:
            return ReleaseResult(3, "release_requires_root")
        requested = None if to_version is None else _safe_version(to_version)
        if to_version is not None and requested is None:
            return ReleaseResult(2, "invalid_release_version")
        if requested is not None and not is_supported_release_version(requested):
            return ReleaseResult(2, "unsupported_release_major", version=requested)
        try:
            self._require_supported_managed_installation()
            if dry_run:
                target = self._select_rollback_target(requested)
                self._validate_candidate(target[1] / _EXECUTABLE_NAME)
                return ReleaseResult(0, "rollback_dry_run", version=target[0], dry_run=True)
            self._select_rollback_target(requested)
            with managed_mutation(
                self.layout.lock_file,
                effective_uid=self.effective_uid,
                root_uid=self.root_uid,
            ):
                self._require_supported_managed_installation()
                target_version, target_path, _manifest = self._select_rollback_target(requested)
                self._validate_candidate(target_path / _EXECUTABLE_NAME)
                return self._rollback_locked(target_version)
        except _ReleaseFailure as failure:
            return ReleaseResult(failure.exit_code, failure.message, version=requested)
        except InsufficientPrivilege:
            return ReleaseResult(3, "release_requires_root")
        except MutationLocked:
            return ReleaseResult(1, "release_operation_locked")
        except UnsafeLock:
            return ReleaseResult(1, "release_lock_unsafe")
        except (OSError, SettingsError, ValueError):
            return ReleaseResult(1, "release_operation_failed", version=requested)

    def uninstall(
        self,
        purge_data: bool,
        confirmed: bool,
        dry_run: bool,
    ) -> ReleaseResult:
        """Remove runtime paths, preserving operator state unless purge is double-gated."""
        if purge_data and not confirmed:
            return ReleaseResult(2, "purge_confirmation_required")
        try:
            self._require_supported_managed_installation()
            if dry_run:
                return ReleaseResult(0, "uninstall_dry_run", dry_run=True)
            if self.effective_uid() != 0:
                return ReleaseResult(3, "release_requires_root")
            # Reject malformed or symlinked scopes before even creating the
            # shared lock file, then repeat under the lock for race resistance.
            self._validate_uninstall_paths(purge_data)
            with managed_mutation(
                self.layout.lock_file,
                effective_uid=self.effective_uid,
                root_uid=self.root_uid,
            ):
                self._require_supported_managed_installation()
                self._validate_uninstall_paths(purge_data)
                if self.runner.run(("systemctl", "disable", "--now", _SERVICE)).returncode != 0:
                    raise _ReleaseFailure(1, "uninstall_service_failed")
                # Revalidate after the external process boundary and before any
                # unlink or recursive removal can observe changed ancestors.
                self._validate_uninstall_paths(purge_data)
                self._unlink_managed_unit()
                self._unlink_managed_cli()
                self._remove_uninstall_tree(self.layout.release_root, ("opt", "xferry"))
                if purge_data:
                    self._remove_uninstall_tree(
                        self.layout.config_file.parent,
                        ("etc", "xferry"),
                    )
                    self._remove_uninstall_tree(
                        self.acme_root,
                        ("var", "lib", "xferry", ".xferry"),
                    )
                    self._remove_uninstall_tree(
                        self.layout.data_root,
                        ("var", "lib", "xferry"),
                    )
                if self.runner.run(("systemctl", "daemon-reload")).returncode != 0:
                    raise _ReleaseFailure(1, "uninstall_reload_failed")
                return ReleaseResult(0, "purge_complete" if purge_data else "uninstall_complete")
        except _ReleaseFailure as failure:
            return ReleaseResult(failure.exit_code, failure.message)
        except InsufficientPrivilege:
            return ReleaseResult(3, "release_requires_root")
        except MutationLocked:
            return ReleaseResult(1, "release_operation_locked")
        except UnsafeLock:
            return ReleaseResult(1, "release_lock_unsafe")
        except OSError:
            return ReleaseResult(1, "uninstall_failed")

    def _download_manifest(self, staging: Path, requested: str | None) -> ReleaseManifest:
        url = (
            f"{self.release_base_url}/latest/download/{_MANIFEST_NAME}"
            if requested is None
            else f"{self.release_base_url}/download/v{requested}/{_MANIFEST_NAME}"
        )
        destination = staging / _MANIFEST_NAME
        try:
            self.downloader.download(url, destination, _MAX_MANIFEST_BYTES)
        except OSError:
            raise _ReleaseFailure(5, "release_download_failed") from None
        try:
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError
            return ReleaseManifest.parse(destination.read_bytes())
        except (OSError, ValueError):
            raise _ReleaseFailure(1, "release_manifest_invalid") from None

    def _download_candidate(self, staging: Path, manifest: ReleaseManifest) -> Path:
        url = f"{self.release_base_url}/download/{manifest.tag}/{manifest.executable_name}"
        destination = staging / manifest.executable_name
        try:
            self.downloader.download(url, destination, manifest.executable_size)
        except OSError:
            raise _ReleaseFailure(5, "release_download_failed") from None
        try:
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError
            if metadata.st_size != manifest.executable_size:
                raise ValueError
            if _file_sha256(destination) != manifest.executable_sha256:
                raise ValueError
            destination.chmod(0o755)
        except (OSError, ValueError):
            raise _ReleaseFailure(1, "release_integrity_failed") from None
        return destination

    def _validate_candidate(self, executable: Path) -> None:
        command = (
            str(executable),
            "run",
            "--config",
            str(self.layout.config_file),
            "--check-config",
        )
        try:
            result = self.runner.run(command)
        except OSError:
            raise _ReleaseFailure(2, "candidate_config_invalid") from None
        if result.returncode != 0:
            raise _ReleaseFailure(2, "candidate_config_invalid")

    def _update_locked(self, manifest: ReleaseManifest, candidate: Path) -> ReleaseResult:
        self._validate_release_layout()
        previous = self._current_supported_version()
        if previous == manifest.version:
            if self._installed_manifest(self._release_path(previous)) != manifest:
                raise _ReleaseFailure(1, "installed_release_conflict")
            return ReleaseResult(0, "update_complete", version=manifest.version)
        service_state = self._service_state()
        if service_state is _ServiceState.PROBE_ERROR:
            raise _ReleaseFailure(1, "release_operation_failed")
        was_active = service_state is _ServiceState.ACTIVE
        health = self._health_context()
        created = False
        try:
            created = self._install_verified_release(manifest, candidate)
            failure = self._activate(manifest.version, previous, health, was_active=was_active)
            if failure is not None:
                if created:
                    self._remove_created_if_inactive(manifest.version)
                return ReleaseResult(failure.exit_code, failure.message, version=manifest.version)
            self._prune_verified(manifest.version, previous)
            return ReleaseResult(0, "update_complete", version=manifest.version)
        except _ReleaseFailure:
            if created:
                self._remove_created_if_inactive(manifest.version)
            raise

    def _rollback_locked(self, target: str) -> ReleaseResult:
        self._validate_release_layout()
        previous = self._current_supported_version()
        if previous == target:
            return ReleaseResult(0, "rollback_complete", version=target)
        service_state = self._service_state()
        if service_state is _ServiceState.PROBE_ERROR:
            raise _ReleaseFailure(1, "release_operation_failed")
        was_active = service_state is _ServiceState.ACTIVE
        health = self._health_context()
        failure = self._activate(target, previous, health, was_active=was_active)
        if failure is not None:
            return ReleaseResult(failure.exit_code, failure.message, version=target)
        self._prune_verified(target, previous)
        return ReleaseResult(0, "rollback_complete", version=target)

    def _activate(
        self,
        target: str,
        previous: str,
        health: _HealthContext,
        *,
        was_active: bool,
    ) -> _ReleaseFailure | None:
        switched = False
        failure: _ReleaseFailure | None = None
        try:
            self._atomic_current(target)
            switched = True
            if self.runner.run(("systemctl", "restart", _SERVICE)).returncode != 0:
                raise _ReleaseFailure(6, "candidate_restart_failed")
            if self._service_state() is not _ServiceState.ACTIVE:
                raise _ReleaseFailure(6, "candidate_restart_failed")
            if not self._ping(health).ok:
                raise _ReleaseFailure(6, "candidate_unhealthy")
            if not was_active:
                if self.runner.run(("systemctl", "stop", _SERVICE)).returncode != 0:
                    raise _ReleaseFailure(6, "candidate_state_restore_failed")
                if self._service_state() is not _ServiceState.CONFIRMED_INACTIVE:
                    raise _ReleaseFailure(6, "candidate_state_restore_failed")
            return None
        except _ReleaseFailure as caught:
            failure = caught
        except (OSError, ValueError):
            failure = _ReleaseFailure(1, "release_switch_failed")

        if not switched:
            try:
                if self._current_version() == previous:
                    return failure
            except (OSError, _ReleaseFailure):
                pass
        if not self._restore(previous, health, was_active=was_active):
            return _ReleaseFailure(1, "restore_incomplete")
        return failure

    def _restore(
        self,
        previous: str,
        health: _HealthContext,
        *,
        was_active: bool,
    ) -> bool:
        try:
            self._atomic_current(previous, require_verified=False)
            link_restored = self._current_version() == previous
            if was_active:
                restarted = self.runner.run(("systemctl", "restart", _SERVICE)).returncode == 0
                state = self._service_state()
                healthy = restarted and state is _ServiceState.ACTIVE and self._ping(health).ok
                return link_restored and healthy
            stopped = self.runner.run(("systemctl", "stop", _SERVICE)).returncode == 0
            state = self._service_state()
            return link_restored and stopped and state is _ServiceState.CONFIRMED_INACTIVE
        except (OSError, ValueError, _ReleaseFailure):
            return False

    def _ping(self, context: _HealthContext) -> HealthResult:
        try:
            return self.health_check(
                context.endpoint,
                context.username,
                context.password,
                self.health_timeout,
            )
        except (OSError, RuntimeError, ValueError):
            return HealthResult(False, "authenticated health check failed")

    def _service_state(self) -> _ServiceState:
        result = self.runner.run(
            ("systemctl", "show", "--property=ActiveState", "--value", _SERVICE)
        )
        if result.returncode != 0:
            return _ServiceState.PROBE_ERROR
        state = result.stdout.strip().casefold()
        if state == "active":
            return _ServiceState.ACTIVE
        if state == "inactive":
            return _ServiceState.CONFIRMED_INACTIVE
        return _ServiceState.PROBE_ERROR

    def _health_context(self) -> _HealthContext:
        try:
            settings = load_settings_file(self.layout.config_file)
            raw_auth = self.layout.auth_file.read_text(encoding="utf-8").strip()
            username, separator, password = raw_auth.partition(":")
            if not separator or not username or not password or "\n" in password:
                raise ValueError
            host = settings.domain
            if host is None and settings.sslip and settings.public_ip:
                host = sslip_domain_for_ip(settings.public_ip)
            if host is None:
                host = "127.0.0.1"
            endpoint = HealthEndpoint(
                "127.0.0.1",
                settings.port,
                host,
                tls=settings.effective_tls_enabled(),
            )
            return _HealthContext(endpoint, username, password)
        except (OSError, SettingsError, UnicodeError, ValueError):
            raise _ReleaseFailure(2, "managed_config_unavailable") from None

    def _install_verified_release(self, manifest: ReleaseManifest, candidate: Path) -> bool:
        releases = self.layout.release_root / "releases"
        releases.mkdir(mode=0o755, exist_ok=True)
        _require_real_directory(releases)
        target = self._release_path(manifest.version)
        if target.exists() or target.is_symlink():
            installed = self._installed_manifest(target)
            if installed != manifest:
                raise _ReleaseFailure(1, "installed_release_conflict")
            return False

        temporary = Path(tempfile.mkdtemp(prefix=f".install-{manifest.version}-", dir=releases))
        try:
            executable = temporary / _EXECUTABLE_NAME
            with candidate.open("rb") as source, executable.open("xb") as destination:
                shutil.copyfileobj(source, destination)
                destination.flush()
                os.fsync(destination.fileno())
            executable.chmod(0o755)
            metadata = temporary / _MANIFEST_NAME
            with metadata.open("xb") as stream:
                stream.write(manifest.to_bytes())
                stream.flush()
                os.fsync(stream.fileno())
            metadata.chmod(0o644)
            # This method runs only inside the root-gated managed mutation. Publish
            # the completed root-owned directory with service-traversable permissions.
            temporary.chmod(0o755)
            if any(
                path.stat().st_uid != self.root_uid for path in (temporary, executable, metadata)
            ):
                raise _ReleaseFailure(1, "release_install_owner_invalid")
            os.replace(temporary, target)  # noqa: PTH105 - atomic directory publication
            return True
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _atomic_current(self, version: str, *, require_verified: bool = True) -> None:
        target = self._release_path(version)
        if require_verified:
            if self._installed_manifest(target) is None:
                raise _ReleaseFailure(1, "rollback_target_unverified")
        else:
            try:
                _require_real_directory(target)
                executable = (target / _EXECUTABLE_NAME).lstat()
                if not stat.S_ISREG(executable.st_mode):
                    raise OSError
            except OSError:
                raise _ReleaseFailure(1, "managed_installation_invalid") from None
        temporary = self.layout.release_root / f".current-{version}-{os.getpid()}"
        temporary.unlink(missing_ok=True)
        try:
            temporary.symlink_to(Path("releases") / version)
            os.replace(  # noqa: PTH105 - contract requires atomic current-link switch
                temporary, self.layout.release_root / "current"
            )
        finally:
            temporary.unlink(missing_ok=True)
        if self._current_version() != version:
            raise _ReleaseFailure(1, "release_switch_failed")

    def _current_version(self) -> str:
        current = self.layout.release_root / "current"
        try:
            metadata = current.lstat()
            if not stat.S_ISLNK(metadata.st_mode):
                raise ValueError
            target = current.readlink()
        except (OSError, ValueError):
            raise _ReleaseFailure(1, "managed_installation_invalid") from None
        if target.is_absolute() or len(target.parts) != 2 or target.parts[0] != "releases":
            raise _ReleaseFailure(1, "managed_installation_invalid")
        version = _safe_version(target.parts[1])
        if version is None:
            raise _ReleaseFailure(1, "managed_installation_invalid")
        release = self._release_path(version)
        try:
            _require_real_directory(release)
        except OSError:
            raise _ReleaseFailure(1, "managed_installation_invalid") from None
        return version

    def _current_supported_version(self) -> str:
        version = self._current_version()
        if not is_supported_release_version(version):
            raise _ReleaseFailure(2, "unsupported_release_major")
        return version

    def _require_supported_managed_installation(self) -> None:
        if has_unsupported_managed_state(self.layout):
            raise _ReleaseFailure(1, "unsupported_managed_state")

    def _select_rollback_target(self, requested: str | None) -> tuple[str, Path, ReleaseManifest]:
        self._validate_release_layout()
        current = self._current_supported_version()
        verified: list[tuple[str, Path, ReleaseManifest]] = []
        releases = self.layout.release_root / "releases"
        for path in releases.iterdir():
            manifest = self._installed_manifest(path)
            if manifest is not None and is_supported_release_version(manifest.version):
                verified.append((manifest.version, path, manifest))
        if requested is not None:
            match = next((item for item in verified if item[0] == requested), None)
            if match is None:
                raise _ReleaseFailure(1, "rollback_target_unverified")
            return match
        previous = [item for item in verified if item[0] != current]
        if not previous:
            raise _ReleaseFailure(1, "rollback_target_unverified")
        return max(previous, key=lambda item: item[1].stat().st_mtime_ns)

    def _installed_manifest(self, release: Path) -> ReleaseManifest | None:
        try:
            _require_real_directory(release)
            if _safe_version(release.name) is None:
                return None
            executable = release / _EXECUTABLE_NAME
            metadata_path = release / _MANIFEST_NAME
            executable_stat = executable.lstat()
            metadata_stat = metadata_path.lstat()
            if not stat.S_ISREG(executable_stat.st_mode) or not stat.S_ISREG(metadata_stat.st_mode):
                return None
            manifest = ReleaseManifest.parse(metadata_path.read_bytes())
            if manifest.version != release.name or manifest.platform != self.platform_id():
                return None
            if executable_stat.st_size != manifest.executable_size:
                return None
            if _file_sha256(executable) != manifest.executable_sha256:
                return None
            return manifest
        except (OSError, ValueError):
            return None

    def _prune_verified(self, current: str, previous: str) -> None:
        keep = {current, previous}
        releases = self.layout.release_root / "releases"
        for path in list(releases.iterdir()):
            if path.name in keep:
                continue
            manifest = self._installed_manifest(path)
            if manifest is not None and is_supported_release_version(manifest.version):
                _remove_managed_tree(path)

    def _remove_created_if_inactive(self, version: str) -> None:
        """Remove a failed new release only when ``current`` safely targets elsewhere."""
        try:
            if self._current_version() == version:
                return
        except _ReleaseFailure:
            return
        _remove_managed_tree(self._release_path(version))

    def _validate_release_layout(self) -> None:
        try:
            _require_real_directory(self.layout.release_root)
            releases = self.layout.release_root / "releases"
            if releases.exists() or releases.is_symlink():
                _require_real_directory(releases)
        except OSError:
            raise _ReleaseFailure(1, "managed_installation_invalid") from None

    def _release_path(self, version: str) -> Path:
        safe = _safe_version(version)
        if safe is None:
            raise _ReleaseFailure(2, "invalid_release_version")
        return self.layout.release_root / "releases" / safe

    def _validate_uninstall_paths(self, purge_data: bool) -> None:
        paths: list[tuple[Path, tuple[str, ...], bool]] = [
            (self.layout.release_root, ("opt", "xferry"), False)
        ]
        if purge_data:
            paths.extend(
                (
                    (self.layout.config_file.parent, ("etc", "xferry"), False),
                    (self.layout.data_root, ("var", "lib", "xferry"), False),
                    (self.acme_root, ("var", "lib", "xferry", ".xferry"), False),
                )
            )
        paths.extend(
            (
                (
                    self.unit_path,
                    ("etc", "systemd", "system", "xferry.service"),
                    True,
                ),
                (self.cli_link, ("usr", "local", "bin", "xferry"), True),
            )
        )
        for path, suffix, allow_final_symlink in paths:
            _validate_canonical_managed_path(
                path,
                suffix,
                allow_final_symlink=allow_final_symlink,
            )

    @staticmethod
    def _remove_uninstall_tree(path: Path, suffix: tuple[str, ...]) -> None:
        _validate_canonical_managed_path(path, suffix, allow_final_symlink=False)
        _remove_managed_tree(path)

    def _unlink_managed_unit(self) -> None:
        if self.unit_path.is_symlink() or self.unit_path.is_file():
            self.unit_path.unlink()
        elif self.unit_path.exists():
            raise _ReleaseFailure(1, "uninstall_path_unsafe")

    def _unlink_managed_cli(self) -> None:
        if not self.cli_link.is_symlink():
            return
        try:
            target = self.cli_link.readlink()
        except OSError:
            return
        if target == Path("/opt/xferry/current/xferry"):
            self.cli_link.unlink()

    @contextmanager
    def _staging_directory(self) -> Iterator[Path]:
        parent = self.staging_parent
        created_parent = False
        if parent is not None and not parent.exists():
            parent.mkdir(parents=True)
            created_parent = True
        try:
            with tempfile.TemporaryDirectory(prefix="xferry-release-", dir=parent) as temporary:
                staging = Path(temporary)
                release_root = self.layout.release_root.resolve(strict=False)
                if staging.resolve().is_relative_to(release_root):
                    raise _ReleaseFailure(1, "staging_path_unsafe")
                yield staging
        finally:
            if created_parent:
                try:
                    parent.rmdir()  # type: ignore[union-attr]
                except OSError:
                    pass


def default_release_manager() -> ReleaseManager:
    """Return the real dependency set used by management CLI commands."""
    return ReleaseManager()


def _safe_version(value: object) -> str | None:
    if not is_canonical_release_version(value):
        return None
    return value


def _safe_basename(value: str) -> bool:
    return (
        value not in {"", ".", ".."}
        and Path(value).name == value
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def _require_https_url(url: str) -> None:
    _require_https_redirect_url(url)
    parsed = urlsplit(url)
    if parsed.query:
        raise _ReleaseFailure(5, "release_url_unsafe")


def _require_https_redirect_url(url: str) -> None:
    """Allow hosted-release query signatures but never downgrade or expose userinfo."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise _ReleaseFailure(5, "release_url_unsafe")


def _local_platform() -> str:
    if platform.system() == "Linux" and platform.machine() == "x86_64":
        return _PLATFORM
    return f"{platform.system().casefold()}-{platform.machine().casefold()}"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_real_directory(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise OSError("managed directory is unsafe")


def _validate_canonical_managed_path(
    path: Path,
    suffix: tuple[str, ...],
    *,
    allow_final_symlink: bool,
) -> None:
    """Require a canonical suffix and reject every existing symlinked ancestor."""
    if not path.is_absolute() or tuple(path.parts[-len(suffix) :]) != suffix:
        raise _ReleaseFailure(1, "uninstall_path_unsafe")
    checked = path.parent if allow_final_symlink else path
    try:
        resolved = checked.resolve(strict=False)
        expected_resolved_suffix = suffix[:-1] if allow_final_symlink else suffix
        if (
            resolved == Path(resolved.anchor)
            or tuple(resolved.parts[-len(expected_resolved_suffix) :]) != expected_resolved_suffix
        ):
            raise _ReleaseFailure(1, "uninstall_path_unsafe")

        current = Path(path.anchor)
        components = checked.parts[1:]
        for component in components:
            current /= component
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise _ReleaseFailure(1, "uninstall_path_unsafe")
    except FileNotFoundError:
        pass
    except (OSError, RuntimeError):
        raise _ReleaseFailure(1, "uninstall_path_unsafe") from None
    if not allow_final_symlink and path.is_symlink():
        raise _ReleaseFailure(1, "uninstall_path_unsafe")


def _remove_managed_tree(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise OSError("managed path is unsafe")
    if stat.S_ISDIR(metadata.st_mode):
        shutil.rmtree(path)
        return
    path.unlink()
