"""Read-only diagnostics and fixed-unit lifecycle operations for XFerry."""

from __future__ import annotations

import os
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from xferry.security.tls import sslip_domain_for_ip
from xferry.settings import ServerSettings, SettingsError, load_settings_file

from .health import HealthEndpoint, HealthResult, authenticated_ping
from .model import (
    MANAGED_HOST_REQUIRED_MESSAGE,
    HostFacts,
    ManagedLayout,
    supported_managed_host_matrix,
)
from .platform import detect_host_facts
from .system import (
    CommandRunner,
    InsufficientPrivilege,
    MutationLocked,
    Runner,
    UnsafeLock,
    managed_mutation,
)

_SERVICE = "xferry.service"
_HealthCheck = Callable[[HealthEndpoint, str, str, float], HealthResult]
_EndpointReachable = Callable[[HealthEndpoint, float], bool]


@dataclass(frozen=True)
class ServiceContext:
    """Injectable managed-service boundaries shared by commands and tests."""

    layout: ManagedLayout
    runner: Runner
    facts: Callable[[], HostFacts]
    health_check: _HealthCheck = authenticated_ping
    endpoint_reachable: _EndpointReachable | None = None
    effective_uid: Callable[[], int] = os.geteuid
    root_uid: int = 0
    health_timeout: float = 2.0


@dataclass(frozen=True)
class ServiceStatus:
    """Secret-free stable service status suitable for text or JSON rendering."""

    exit_code: int
    installation: str
    config: str
    enabled: str
    service: str
    health: str = "unknown"

    def to_json(self) -> dict[str, object]:
        """Return fixed English machine fields with no config or credential contents."""
        return {
            "config": self.config,
            "enabled": self.enabled,
            "exit_code": self.exit_code,
            "health": self.health,
            "installation": self.installation,
            "service": self.service,
            "status": "ok" if self.exit_code == 0 else "error",
        }


@dataclass(frozen=True)
class DoctorOptions:
    """Documented controls for the optional remote checks."""

    deep: bool = False
    skip_network: bool = False


@dataclass(frozen=True)
class DoctorCheck:
    """One secret-free diagnostic result with a stable English status."""

    status: str
    detail: str


@dataclass(frozen=True)
class DoctorReport:
    """All doctor findings and their selected stable process exit code."""

    exit_code: int
    checks: dict[str, DoctorCheck]
    code: str = "doctor-result"
    message: str = "Managed diagnostics completed."
    detail: str = "Managed diagnostics completed."
    next_actions: tuple[str, ...] = ()
    facts: HostFacts | None = None

    def to_json(self) -> dict[str, object]:
        """Return a stable JSON document without paths, errors, or credentials."""
        return {
            "checks": {
                name: {"detail": check.detail, "status": check.status}
                for name, check in self.checks.items()
            },
            "code": self.code,
            "detail": self.detail,
            "detected": None if self.facts is None else self.facts.detected_managed_host,
            "exit_code": self.exit_code,
            "message": self.message,
            "next_actions": list(self.next_actions),
            "status": "ok" if self.exit_code == 0 else "error",
            "supported_matrix": supported_managed_host_matrix(),
        }


def default_service_context() -> ServiceContext:
    """Build the real managed context without starting or modifying the service."""
    layout = ManagedLayout()
    return ServiceContext(
        layout=layout,
        runner=CommandRunner(),
        facts=lambda: detect_host_facts(data_path=layout.data_root),
    )


def service_status(context: ServiceContext) -> ServiceStatus:
    """Read fixed-unit state only; this command never enters the mutation lock."""
    if context.effective_uid() != 0:
        return ServiceStatus(3, "unknown", "unknown", "unknown", "unknown")
    installation = "installed" if context.layout.current_executable.is_file() else "missing"
    settings, config = _load_candidate_config(context.layout, context.runner)
    enabled = _enabled_state(context.runner)
    service = _service_state(context.runner)
    exit_code = _status_exit(installation, config, service)
    del settings
    return ServiceStatus(exit_code, installation, config, enabled, service)


def service_action(action: Literal["start", "stop", "restart"], context: ServiceContext) -> int:
    """Mutate only the fixed systemd unit under the shared managed-operation lock."""
    if action not in {"start", "stop", "restart"}:
        return 2
    if context.effective_uid() != 0:
        return 3
    try:
        with managed_mutation(
            context.layout.lock_file,
            effective_uid=context.effective_uid,
            root_uid=context.root_uid,
        ):
            return 0 if context.runner.run(("systemctl", action, _SERVICE)).returncode == 0 else 1
    except (InsufficientPrivilege, MutationLocked, UnsafeLock, OSError):
        return 1


def stream_logs(lines: int, since: str | None, follow: bool, context: ServiceContext) -> int:
    """Print fixed-unit journal output and preserve journalctl's process exit status."""
    if lines < 1:
        return 2
    argv = ["journalctl", "--unit", _SERVICE, "--lines", str(lines)]
    if since is not None:
        argv.extend(("--since", since))
    if follow:
        argv.append("--follow")
    argv.append("--no-pager")
    if follow:
        stream = getattr(context.runner, "stream", None)
        if not callable(stream):
            return 1
        return _operation_exit(stream(tuple(argv)))
    result = context.runner.run(tuple(argv))
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return _operation_exit(result.returncode)


def run_doctor(options: DoctorOptions, context: ServiceContext) -> DoctorReport:
    """Run local checks plus explicitly enabled endpoint and authenticated-health checks."""
    if context.effective_uid() != 0:
        return DoctorReport(
            3,
            {"privilege": DoctorCheck("required", "managed diagnostics require root")},
            code="privilege-required",
            message="Managed diagnostics require root.",
            detail="Protected managed state was not inspected.",
            next_actions=("Rerun the diagnostic with `sudo xferry doctor`.",),
        )
    checks: dict[str, DoctorCheck] = {}
    facts = context.facts()
    checks["platform"] = DoctorCheck(
        "supported" if facts.is_supported else "unsupported",
        "supported platform" if facts.is_supported else facts.managed_support_detail,
    )

    installed = context.layout.current_executable.is_file()
    checks["installation"] = DoctorCheck(
        "installed" if installed else "missing",
        "managed executable present" if installed else "managed executable missing",
    )
    settings, config = _load_candidate_config(context.layout, context.runner)
    checks["configuration"] = DoctorCheck(
        config,
        "configuration valid" if config == "valid" else "configuration unavailable",
    )

    state = _service_state(context.runner)
    checks["service"] = DoctorCheck(state, f"service {state}")

    endpoint = _endpoint(settings)
    if options.skip_network:
        checks["network"] = DoctorCheck("skipped", "network checks skipped")
        checks["health"] = DoctorCheck("skipped", "authenticated health check skipped")
    elif endpoint is None:
        checks["network"] = DoctorCheck("unavailable", "endpoint unavailable")
        checks["health"] = DoctorCheck("skipped", "authenticated health check skipped")
    else:
        reachable = _reachable(context, endpoint)
        checks["network"] = DoctorCheck(
            "reachable" if reachable else "unreachable",
            "endpoint reachable" if reachable else "endpoint unreachable",
        )
        if options.deep and reachable:
            credentials = _credentials(context.layout.auth_file)
            if credentials is None:
                checks["health"] = DoctorCheck("unhealthy", "credentials unavailable")
            else:
                username, password = credentials
                health = context.health_check(endpoint, username, password, context.health_timeout)
                checks["health"] = DoctorCheck(
                    "healthy" if health.ok else "unhealthy",
                    "authenticated health check passed" if health.ok else _health_detail(health),
                )
        else:
            checks["health"] = DoctorCheck("skipped", "authenticated health check skipped")

    exit_code = _doctor_exit(checks)
    code, message, detail, next_actions = _doctor_diagnostic(exit_code, checks, facts)
    return DoctorReport(
        exit_code,
        checks,
        code=code,
        message=message,
        detail=detail,
        next_actions=next_actions,
        facts=facts,
    )


def _load_config(path: Path) -> tuple[ServerSettings | None, str]:
    if not path.is_file():
        return None, "missing"
    try:
        return load_settings_file(path), "valid"
    except (OSError, SettingsError, ValueError):
        return None, "invalid"


def _load_candidate_config(
    layout: ManagedLayout, runner: Runner
) -> tuple[ServerSettings | None, str]:
    """Validate the parsed config with the managed current executable only."""
    settings, config = _load_config(layout.config_file)
    if config != "valid":
        return settings, config
    result = runner.run(
        (
            str(layout.current_executable),
            "run",
            "--config",
            str(layout.config_file),
            "--check-config",
        )
    )
    return (settings, "valid") if result.returncode == 0 else (None, "invalid")


def _enabled_state(runner: Runner) -> str:
    return (
        "enabled"
        if runner.run(("systemctl", "is-enabled", _SERVICE)).returncode == 0
        else "disabled"
    )


def _service_state(runner: Runner) -> str:
    result = runner.run(("systemctl", "show", "--property=ActiveState", "--value", _SERVICE))
    state = result.stdout.strip().casefold()
    return state if state in {"active", "inactive", "failed"} else "unknown"


def _status_exit(installation: str, config: str, service: str) -> int:
    if installation == "missing":
        return 1
    if config != "valid":
        return 2
    return 0 if service == "active" else 6


def _endpoint(settings: ServerSettings | None) -> HealthEndpoint | None:
    if settings is None:
        return None
    tls = settings.effective_tls_enabled()
    host = settings.domain
    if host is None and settings.sslip and settings.public_ip:
        host = sslip_domain_for_ip(settings.public_ip)
    if host is None:
        host = "127.0.0.1"
    return HealthEndpoint("127.0.0.1", settings.port, host, tls=tls)


def _reachable(context: ServiceContext, endpoint: HealthEndpoint) -> bool:
    if context.endpoint_reachable is not None:
        return context.endpoint_reachable(endpoint, context.health_timeout)
    try:
        with socket.create_connection(
            (endpoint.connect_host, endpoint.port), context.health_timeout
        ):
            return True
    except OSError:
        return False


def _credentials(path: Path) -> tuple[str, str] | None:
    try:
        username, separator, password = path.read_text(encoding="utf-8").strip().partition(":")
    except OSError:
        return None
    if not separator or not username or not password:
        return None
    return username, password


def _health_detail(result: HealthResult) -> str:
    if result.detail == "TLS verification failed":
        return "TLS verification failed"
    if result.detail == "connection failed":
        return "connection failed"
    return "authenticated health check failed"


def _doctor_exit(checks: dict[str, DoctorCheck]) -> int:
    if checks["platform"].status == "unsupported":
        return 4
    if checks["installation"].status == "missing":
        return 1
    if checks["configuration"].status != "valid":
        return 2
    if checks["service"].status != "active":
        return 6
    if checks["network"].status in {"unavailable", "unreachable"}:
        return 5
    if checks["health"].detail in {"TLS verification failed", "connection failed"}:
        return 5
    if checks["health"].status in {"unavailable", "unhealthy"}:
        return 6
    return 0


def _doctor_diagnostic(
    exit_code: int,
    checks: dict[str, DoctorCheck],
    facts: HostFacts,
) -> tuple[str, str, str, tuple[str, ...]]:
    """Map doctor findings to a stable, actionable, secret-free summary."""
    if exit_code == 0:
        return (
            "doctor-ok",
            "Managed diagnostics passed.",
            "All requested managed checks passed.",
            (),
        )
    if exit_code == 4:
        return (
            "unsupported-platform",
            MANAGED_HOST_REQUIRED_MESSAGE,
            facts.managed_support_detail,
            facts.managed_support_next_actions,
        )
    if exit_code == 1:
        return (
            "installation-missing",
            "Managed installation is missing.",
            checks["installation"].detail,
            ("Run `sudo xferry setup`, then rerun `sudo xferry doctor`.",),
        )
    if exit_code == 2:
        return (
            "configuration-unavailable",
            "Managed configuration is unavailable.",
            checks["configuration"].detail,
            ("Review the managed configuration, then rerun `sudo xferry doctor`.",),
        )
    if exit_code == 5:
        failed_check = (
            checks["network"]
            if checks["network"].status in {"unavailable", "unreachable"}
            else checks["health"]
        )
        return (
            "network-unavailable",
            "Managed network checks failed.",
            failed_check.detail,
            ("Check DNS, firewall, and TLS connectivity, then rerun `sudo xferry doctor`.",),
        )
    failed_check = checks["service"] if checks["service"].status != "active" else checks["health"]
    return (
        "service-unhealthy",
        "Managed service is unhealthy.",
        failed_check.detail,
        ("Run `sudo xferry status` and `xferry logs`, then rerun `sudo xferry doctor`.",),
    )


def _operation_exit(returncode: int) -> int:
    """Collapse child operation results into the public managed exit taxonomy."""
    return 0 if returncode == 0 else 1
