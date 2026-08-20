"""Transactional managed setup and credential rotation."""

from __future__ import annotations

import grp
import os
import pwd
import re
import secrets
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from importlib import resources
from pathlib import Path

from .health import HealthEndpoint, HealthResult, authenticated_ping
from .model import ManagedLayout, SetupMode, SetupPlan, SetupPreflight, SetupProbes
from .planning import check_setup_preflight, render_managed_config
from .system import (
    CommandRunner,
    FilesystemTransaction,
    InsufficientPrivilege,
    MutationLocked,
    Runner,
    UnsafeLock,
    managed_mutation,
)

_PASSWORD_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_SERVICE = "xferry.service"
_MIN_READINESS_SECONDS = 120.0
_INITIAL_READINESS_BACKOFF = 0.25
_MAX_READINESS_BACKOFF = 2.0
_C_LOCALE_ENV = {"LANG": "C", "LC_ALL": "C"}

HealthCheck = Callable[[HealthEndpoint, str, str, float], HealthResult]


def _resolve_identity() -> tuple[int, int]:
    return pwd.getpwnam("xferry").pw_uid, grp.getgrnam("xferry").gr_gid


@dataclass(frozen=True)
class Credentials:
    """One-time operator credential returned only after authenticated health."""

    username: str
    password: str = field(repr=False)
    url: str


@dataclass(frozen=True)
class SetupResult:
    """Sanitized managed setup outcome."""

    exit_code: int
    message: str
    credentials: Credentials | None = field(default=None, repr=False)


@dataclass(frozen=True)
class CredentialsResult:
    """Sanitized credential-reset outcome."""

    exit_code: int
    message: str
    credentials: Credentials | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RestoreStatus:
    """Sanitized verification of every rollback boundary that was attempted."""

    filesystem: bool = True
    firewall: bool = True
    daemon_reload: bool = True
    enabled_state: bool = True
    active_state: bool = True

    @property
    def ok(self) -> bool:
        return all(
            (
                self.filesystem,
                self.firewall,
                self.daemon_reload,
                self.enabled_state,
                self.active_state,
            )
        )


@dataclass(frozen=True)
class ServiceActivationState:
    """Confirmed fixed-unit presence, enablement, and activity before mutation."""

    present: bool
    enabled: bool
    active: bool


@dataclass(frozen=True)
class ReadinessResult:
    """Typed deadline outcome used to distinguish startup from health failures."""

    health: HealthResult
    endpoint_observed: bool


class _UfwState(str, Enum):
    ABSENT = "absent"
    INACTIVE = "inactive"
    ACTIVE = "active"
    ERROR = "error"


@dataclass(frozen=True)
class _UfwStatus:
    state: _UfwState
    allowed_ports: frozenset[int] = frozenset()


@dataclass(frozen=True)
class CredentialsContext:
    """Injected boundaries needed for a managed credential reset."""

    layout: ManagedLayout
    endpoint: HealthEndpoint
    runner: Runner
    health_check: HealthCheck = authenticated_ping
    effective_uid: Callable[[], int] = os.geteuid
    root_uid: int = 0
    resolve_identity: Callable[[], tuple[int, int]] = _resolve_identity
    chown: Callable[[Path, int, int], None] = os.chown
    readiness_timeout: float = _MIN_READINESS_SECONDS
    health_timeout: float = 2.0
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


class _SetupFailure(RuntimeError):
    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


def generate_password() -> str:
    """Generate the approved unambiguous 12-character password."""
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(12))


class SetupExecutor:
    """Apply one immutable plan under a plan-bound transactional mutation."""

    def __init__(
        self,
        *,
        runner: Runner | None = None,
        preflight_check: Callable[[SetupPlan], SetupPreflight] | None = None,
        health_check: HealthCheck = authenticated_ping,
        effective_uid: Callable[[], int] = os.geteuid,
        root_uid: int = 0,
        resolve_identity: Callable[[], tuple[int, int]] | None = None,
        chown: Callable[[Path, int, int], None] = os.chown,
        unit_path: Path = Path("/etc/systemd/system/xferry.service"),
        acme_root: Path | None = None,
        readiness_timeout: float = _MIN_READINESS_SECONDS,
        health_timeout: float = 2.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        transaction_factory: Callable[[], FilesystemTransaction] | None = None,
    ) -> None:
        self.runner = runner or CommandRunner()
        self.preflight_check = preflight_check or self._check_preflight
        self.health_check = health_check
        self.effective_uid = effective_uid
        self.root_uid = root_uid
        self.resolve_identity = resolve_identity or _resolve_identity
        self.chown = chown
        self.unit_path = unit_path
        self.acme_root = acme_root
        self.readiness_timeout = max(_MIN_READINESS_SECONDS, readiness_timeout)
        self.health_timeout = health_timeout
        self.monotonic = monotonic
        self.sleep = sleep
        self.transaction_factory = transaction_factory or (
            lambda: FilesystemTransaction(chown=self.chown)
        )

    def apply(self, plan: SetupPlan) -> SetupResult:
        """Apply ``plan`` or restore every pre-existing managed state."""
        if self.effective_uid() != 0:
            return SetupResult(3, "managed setup requires root")
        initial_preflight = self.preflight_check(plan)
        if not initial_preflight.ok:
            return _preflight_result(initial_preflight)

        try:
            with managed_mutation(
                plan.layout.lock_file,
                effective_uid=self.effective_uid,
                root_uid=self.root_uid,
            ):
                locked_preflight = self.preflight_check(plan)
                if not locked_preflight.ok:
                    return _preflight_result(locked_preflight)
                return self._apply_locked(plan)
        except InsufficientPrivilege:
            return SetupResult(3, "managed setup requires root")
        except MutationLocked:
            return SetupResult(1, "another managed operation is in progress")
        except UnsafeLock:
            return SetupResult(1, "managed mutation lock is unsafe")
        except OSError:
            return SetupResult(1, "managed mutation lock failed")

    def _apply_locked(self, plan: SetupPlan) -> SetupResult:
        initial_state = self._service_activation_state()
        if initial_state is None:
            return SetupResult(1, "service state probe failed")
        was_active = initial_state.active
        transaction = self.transaction_factory()
        added_ports: list[int] = []
        group_created = False
        user_created = False
        reload_attempted = False
        activation_touched = False

        try:
            group_created, user_created = self._ensure_identities(plan.layout.runtime_home)
            runtime_uid, runtime_gid = self.resolve_identity()
            password = self._stage_files(plan, transaction, runtime_uid, runtime_gid)
            self._checked(
                (
                    str(plan.layout.current_executable),
                    "run",
                    "--config",
                    str(plan.layout.config_file),
                    "--check-config",
                ),
                exit_code=2,
                message="managed configuration validation failed",
            )
            reload_attempted = True
            self._checked(
                ("systemctl", "daemon-reload"),
                exit_code=1,
                message="systemd daemon reload failed",
            )
            self._apply_firewall(plan, added_ports)
            activation_touched = True
            self._checked(
                ("systemctl", "enable", _SERVICE),
                exit_code=1,
                message="service enable failed",
            )
            action = "restart" if was_active else "start"
            self._checked(
                ("systemctl", action, _SERVICE),
                exit_code=6,
                message="installed service failed to start",
            )
            endpoint = _health_endpoint(plan)
            readiness = _wait_for_health(
                self.health_check,
                endpoint,
                "admin",
                password,
                readiness_timeout=self.readiness_timeout,
                timeout=self.health_timeout,
                monotonic=self.monotonic,
                sleep=self.sleep,
            )
            if not readiness.health.ok:
                if plan.mode is not SetupMode.PRIVATE and not readiness.endpoint_observed:
                    raise _SetupFailure(5, "public service readiness timed out before first bind")
                raise _SetupFailure(6, "installed service is unhealthy")
            transaction.commit()
            return SetupResult(
                exit_code=0,
                message="managed service is healthy",
                credentials=Credentials("admin", password, endpoint.url),
            )
        except _SetupFailure as failure:
            restore = self._rollback(
                transaction,
                added_ports,
                initial_state=initial_state,
                reload_attempted=reload_attempted,
                activation_touched=activation_touched,
            )
            self._remove_new_identities(user_created=user_created, group_created=group_created)
            if not restore.ok:
                return SetupResult(1, "managed setup failed and rollback is incomplete")
            return SetupResult(failure.exit_code, failure.message)
        except (KeyError, OSError, ValueError):
            restore = self._rollback(
                transaction,
                added_ports,
                initial_state=initial_state,
                reload_attempted=reload_attempted,
                activation_touched=activation_touched,
            )
            self._remove_new_identities(user_created=user_created, group_created=group_created)
            if not restore.ok:
                return SetupResult(1, "managed setup failed and rollback is incomplete")
            return SetupResult(1, "managed setup failed")

    def _stage_files(
        self,
        plan: SetupPlan,
        transaction: FilesystemTransaction,
        runtime_uid: int,
        runtime_gid: int,
    ) -> str:
        transaction.ensure_directory(
            plan.layout.config_file.parent,
            mode=0o750,
            uid=0,
            gid=runtime_gid,
        )
        transaction.ensure_directory(
            plan.layout.data_root,
            mode=0o750,
            uid=runtime_uid,
            gid=runtime_gid,
        )
        transaction.ensure_directory(
            self.acme_root or plan.layout.acme_root,
            mode=0o750,
            uid=runtime_uid,
            gid=runtime_gid,
        )
        transaction.atomic_write(
            plan.layout.config_file,
            render_managed_config(plan).encode("utf-8"),
            mode=0o640,
            uid=0,
            gid=runtime_gid,
        )
        password = generate_password()
        transaction.atomic_write(
            plan.layout.auth_file,
            f"admin:{password}\n".encode(),
            mode=0o400,
            uid=runtime_uid,
            gid=runtime_gid,
        )
        transaction.ensure_directory(self.unit_path.parent, mode=0o755, uid=0, gid=0)
        transaction.atomic_write(
            self.unit_path,
            _packaged_unit(),
            mode=0o644,
            uid=0,
            gid=0,
        )
        return password

    def _check_preflight(self, plan: SetupPlan) -> SetupPreflight:
        return default_setup_preflight(plan, self.runner)

    def _ensure_identities(self, runtime_home: Path) -> tuple[bool, bool]:
        group_created = False
        user_created = False
        if self.runner.run(("getent", "group", "xferry")).returncode != 0:
            self._checked(
                ("groupadd", "--system", "xferry"),
                exit_code=1,
                message="managed group creation failed",
            )
            group_created = True
        try:
            if self.runner.run(("id", "-u", "xferry")).returncode != 0:
                self._checked(
                    (
                        "useradd",
                        "--system",
                        "--gid",
                        "xferry",
                        "--home-dir",
                        str(runtime_home),
                        "--no-create-home",
                        "--shell",
                        "/usr/sbin/nologin",
                        "xferry",
                    ),
                    exit_code=1,
                    message="managed user creation failed",
                )
                user_created = True
        except _SetupFailure:
            if group_created:
                self.runner.run(("groupdel", "xferry"))
            raise
        return group_created, user_created

    def _apply_firewall(self, plan: SetupPlan, added: list[int]) -> None:
        if not set(plan.firewall_ports) <= {80, 443}:
            raise _SetupFailure(2, "managed firewall plan is invalid")
        if plan.firewall_action != "allow":
            return
        status = _read_ufw_status(self.runner)
        if status.state is _UfwState.ERROR:
            raise _SetupFailure(1, "firewall status probe failed")
        if status.state is not _UfwState.ACTIVE:
            return
        existing = status.allowed_ports
        for port in plan.firewall_ports:
            if port in existing:
                continue
            self._checked(
                ("ufw", "allow", f"{port}/tcp"),
                exit_code=1,
                message="firewall rule update failed",
            )
            added.append(port)

    def _rollback(
        self,
        transaction: FilesystemTransaction,
        added_ports: list[int],
        *,
        initial_state: ServiceActivationState,
        reload_attempted: bool,
        activation_touched: bool,
    ) -> RestoreStatus:
        firewall_restored = True
        for port in reversed(added_ports):
            result = self.runner.run(("ufw", "--force", "delete", "allow", f"{port}/tcp"))
            firewall_restored = firewall_restored and result.returncode == 0
        if added_ports:
            status = _read_ufw_status(self.runner)
            firewall_restored = (
                firewall_restored
                and status.state is not _UfwState.ERROR
                and not set(added_ports).intersection(status.allowed_ports)
            )
        quiesced = True
        if activation_touched:
            quiesced = self.runner.run(("systemctl", "stop", _SERVICE)).returncode == 0
        filesystem_restored = True
        try:
            transaction.rollback()
        except OSError:
            filesystem_restored = False
        daemon_reloaded = True
        if reload_attempted:
            daemon_reloaded = self.runner.run(("systemctl", "daemon-reload")).returncode == 0
        enabled_restored = True
        active_restored = True
        if activation_touched:
            if initial_state.present and initial_state.enabled:
                enabled_command = self.runner.run(("systemctl", "enable", _SERVICE))
            elif initial_state.present:
                enabled_command = self.runner.run(("systemctl", "disable", _SERVICE))
            else:
                enabled_command = None
            if initial_state.present and initial_state.active:
                active_command = self.runner.run(("systemctl", "restart", _SERVICE))
            elif initial_state.present:
                active_command = self.runner.run(("systemctl", "stop", _SERVICE))
            else:
                active_command = None
            observed = self._service_activation_state()
            state_proven = observed == initial_state
            enabled_restored = state_proven and (
                enabled_command is None or enabled_command.returncode == 0
            )
            active_restored = (
                quiesced
                and state_proven
                and (active_command is None or active_command.returncode == 0)
            )
        return RestoreStatus(
            filesystem=filesystem_restored,
            firewall=firewall_restored,
            daemon_reload=daemon_reloaded,
            enabled_state=enabled_restored,
            active_state=active_restored,
        )

    def _remove_new_identities(self, *, user_created: bool, group_created: bool) -> None:
        if user_created:
            self.runner.run(("userdel", "xferry"))
        if group_created:
            self.runner.run(("groupdel", "xferry"))

    def _checked(self, argv: tuple[str, ...], *, exit_code: int, message: str) -> None:
        if self.runner.run(argv).returncode != 0:
            raise _SetupFailure(exit_code, message)

    def _service_activation_state(self) -> ServiceActivationState | None:
        result = self.runner.run(
            (
                "systemctl",
                "show",
                "--property=LoadState",
                "--property=UnitFileState",
                "--property=ActiveState",
                _SERVICE,
            )
        )
        if result.returncode != 0:
            return None
        values: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                return None
            values[key] = value.strip().casefold()
        if set(values) != {"LoadState", "UnitFileState", "ActiveState"}:
            return None
        if values["LoadState"] == "not-found":
            if values["UnitFileState"] or values["ActiveState"] != "inactive":
                return None
            return ServiceActivationState(False, False, False)
        if values["LoadState"] != "loaded":
            return None
        enabled_value = values["UnitFileState"]
        active_value = values["ActiveState"]
        if enabled_value not in {"enabled", "disabled"}:
            return None
        if active_value not in {"active", "inactive"}:
            return None
        return ServiceActivationState(
            True,
            enabled_value == "enabled",
            active_value == "active",
        )


def reset_credentials(context: CredentialsContext) -> CredentialsResult:
    """Atomically rotate managed auth, restart, and reveal only after health."""
    if context.effective_uid() != 0:
        return CredentialsResult(3, "credential reset requires root")
    if not context.layout.auth_file.is_file():
        return CredentialsResult(1, "managed auth file is missing")
    try:
        with managed_mutation(
            context.layout.lock_file,
            effective_uid=context.effective_uid,
            root_uid=context.root_uid,
        ):
            transaction = FilesystemTransaction(chown=context.chown)
            try:
                runtime_uid, runtime_gid = context.resolve_identity()
                password = generate_password()
                transaction.atomic_write(
                    context.layout.auth_file,
                    f"admin:{password}\n".encode(),
                    mode=0o400,
                    uid=runtime_uid,
                    gid=runtime_gid,
                )
                if context.runner.run(("systemctl", "restart", _SERVICE)).returncode != 0:
                    raise _SetupFailure(6, "installed service failed to restart")
                readiness = _wait_for_health(
                    context.health_check,
                    context.endpoint,
                    "admin",
                    password,
                    readiness_timeout=context.readiness_timeout,
                    timeout=context.health_timeout,
                    monotonic=context.monotonic,
                    sleep=context.sleep,
                )
                if not readiness.health.ok:
                    raise _SetupFailure(6, "installed service is unhealthy")
                transaction.commit()
                return CredentialsResult(
                    exit_code=0,
                    message="credentials reset and service is healthy",
                    credentials=Credentials("admin", password, context.endpoint.url),
                )
            except _SetupFailure as failure:
                transaction.rollback()
                context.runner.run(("systemctl", "restart", _SERVICE))
                return CredentialsResult(failure.exit_code, failure.message)
            except (KeyError, OSError, ValueError):
                transaction.rollback()
                context.runner.run(("systemctl", "restart", _SERVICE))
                return CredentialsResult(1, "credential reset failed")
    except InsufficientPrivilege:
        return CredentialsResult(3, "credential reset requires root")
    except MutationLocked:
        return CredentialsResult(1, "another managed operation is in progress")
    except UnsafeLock:
        return CredentialsResult(1, "managed mutation lock is unsafe")
    except OSError:
        return CredentialsResult(1, "managed mutation lock failed")


def default_setup_preflight(
    plan: SetupPlan,
    runner: Runner,
    *,
    interactive: bool = False,
) -> SetupPreflight:
    """Run the shared read-only setup gate against current host state."""
    from .managed_state import has_unsupported_managed_state

    return check_setup_preflight(
        plan,
        SetupProbes(
            executable_is_ready=lambda path: path.is_file() and os.access(path, os.X_OK),
            port_is_available=_port_is_available,
            ufw_is_active=lambda: ufw_is_active(runner),
            interactive=interactive,
            unsupported_managed_state_detected=has_unsupported_managed_state,
        ),
    )


def preflight_result(preflight: SetupPreflight) -> SetupResult:
    """Map a failed read-only gate into the stable setup exit taxonomy."""
    return _preflight_result(preflight)


def ufw_is_active(runner: Runner) -> bool:
    """Return current UFW activation without changing firewall policy."""
    status = _read_ufw_status(runner)
    if status.state is _UfwState.ERROR:
        raise OSError("UFW status probe failed")
    return status.state is _UfwState.ACTIVE


def _packaged_unit() -> bytes:
    package = resources.files("xferry.management")
    return package.joinpath("data").joinpath("xferry.service").read_bytes()


def _port_is_available(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((host, port))
    except OSError:
        return False
    return True


def _read_ufw_status(runner: Runner) -> _UfwStatus:
    result = runner.run(("ufw", "status"), env=_C_LOCALE_ENV)
    if result.not_found:
        return _UfwStatus(_UfwState.ABSENT)
    if result.returncode != 0:
        return _UfwStatus(_UfwState.ERROR)
    lines = result.stdout.splitlines()
    status_lines = [line.strip().casefold() for line in lines if line.strip()]
    if "status: active" in status_lines:
        state = _UfwState.ACTIVE
    elif "status: inactive" in status_lines:
        state = _UfwState.INACTIVE
    else:
        return _UfwStatus(_UfwState.ERROR)
    allowed: set[int] = set()
    for line in lines:
        match = re.match(r"^\s*(\d+)/tcp\s+ALLOW\b", line, flags=re.IGNORECASE)
        if match:
            allowed.add(int(match.group(1)))
    return _UfwStatus(state, frozenset(allowed))


def _health_endpoint(plan: SetupPlan) -> HealthEndpoint:
    if plan.mode is SetupMode.PRIVATE:
        return HealthEndpoint("127.0.0.1", plan.port, "127.0.0.1", tls=False)
    assert plan.domain is not None
    return HealthEndpoint("127.0.0.1", plan.port, plan.domain, tls=True)


def _wait_for_health(
    check: HealthCheck,
    endpoint: HealthEndpoint,
    username: str,
    password: str,
    *,
    readiness_timeout: float,
    timeout: float,
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
) -> ReadinessResult:
    deadline = monotonic() + max(_MIN_READINESS_SECONDS, readiness_timeout)
    result = HealthResult(ok=False, detail="health check not attempted")
    endpoint_observed = False
    backoff = _INITIAL_READINESS_BACKOFF
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0:
            return ReadinessResult(result, endpoint_observed)
        result = check(endpoint, username, password, min(timeout, remaining))
        endpoint_observed = endpoint_observed or result.detail != "connection failed"
        if result.ok:
            return ReadinessResult(result, endpoint_observed)
        remaining = deadline - monotonic()
        if remaining <= 0:
            return ReadinessResult(result, endpoint_observed)
        sleep(min(backoff, remaining))
        backoff = min(backoff * 2, _MAX_READINESS_BACKOFF)


def _preflight_result(preflight: SetupPreflight) -> SetupResult:
    from .managed_state import UNSUPPORTED_MANAGED_STATE_CODE

    unsupported_managed_state_failure = next(
        (
            failure
            for failure in preflight.failures
            if failure.code == UNSUPPORTED_MANAGED_STATE_CODE
        ),
        None,
    )
    if unsupported_managed_state_failure is not None:
        return SetupResult(1, unsupported_managed_state_failure.message)
    codes = {failure.code for failure in preflight.failures}
    if "unsupported-platform" in codes:
        return SetupResult(4, "unsupported managed platform")
    if "port-unavailable" in codes:
        return SetupResult(5, "required network port is unavailable")
    if codes & {"firewall-denied", "firewall-consent-required", "invalid-firewall-port"}:
        return SetupResult(2, "explicit firewall consent is required")
    return SetupResult(1, "managed setup preflight failed")
