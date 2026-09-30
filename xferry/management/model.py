"""Immutable values shared by managed XFerry setup planning and execution."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal

from .release_contract import SUPPORTED_PLATFORM_IDS, platform_id_for_host

SUPPORTED_MANAGED_DISTRIBUTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ubuntu", ("22.04", "24.04", "26.04")),
    ("debian", ("12", "13")),
)
SUPPORTED_MANAGED_ARCHITECTURES: tuple[str, ...] = tuple(
    platform_id.removeprefix("linux-") for platform_id in SUPPORTED_PLATFORM_IDS
)
SUPPORTED_MANAGED_HOST_SUMMARY = (
    "Ubuntu 22.04/24.04/26.04 and Debian 12/13 on x86_64/aarch64 with systemd"
)
MANAGED_HOST_REQUIRED_MESSAGE = "Managed commands are Linux/systemd-only on supported hosts."
MANAGED_HOST_NEXT_ACTIONS = (
    (
        "Use a supported managed host: Ubuntu 22.04/24.04/26.04 or Debian 12/13 "
        "on x86_64/aarch64 with systemd."
    ),
    (
        "For portable use, run `pipx install xferry`; use `pipx upgrade xferry` "
        "and `pipx uninstall xferry` for lifecycle management."
    ),
)

_SUPPORTED_MANAGED_OS_RELEASES = frozenset(
    (os_id, version) for os_id, versions in SUPPORTED_MANAGED_DISTRIBUTIONS for version in versions
)
_DIAGNOSTIC_TOKEN_RE = re.compile(r"[^0-9A-Za-z._+-]")


def supported_managed_host_matrix() -> dict[str, object]:
    """Return the stable, secret-free managed host support contract."""
    return {
        "architectures": list(SUPPORTED_MANAGED_ARCHITECTURES),
        "distributions": {
            os_id: list(versions) for os_id, versions in SUPPORTED_MANAGED_DISTRIBUTIONS
        },
        "init_system": "systemd",
    }


def _diagnostic_token(value: str) -> str:
    """Bound detected host text to one safe token for logs and diagnostics."""
    sanitized = _DIAGNOSTIC_TOKEN_RE.sub("?", value)[:64]
    return sanitized or "unknown"


@dataclass(frozen=True)
class ManagedLayout:
    """Filesystem locations owned by a managed XFerry installation."""

    release_root: Path = Path("/opt/xferry")
    config_file: Path = Path("/etc/xferry/xferry.ini")
    auth_file: Path = Path("/etc/xferry/auth")
    data_root: Path = Path("/var/lib/xferry")
    lock_file: Path = Path("/run/lock/xferry-ops.lock")
    unit_file: Path = Path("/etc/systemd/system/xferry.service")
    cli_link: Path = Path("/usr/local/bin/xferry")

    @property
    def current_executable(self) -> Path:
        """Return the executable installed through the managed current link."""
        return self.release_root / "current" / "xferry"

    @property
    def runtime_home(self) -> Path:
        """Return the systemd-visible HOME used by the managed runtime user."""
        return self.data_root

    @property
    def acme_root(self) -> Path:
        """Return the private state root used by the TLS/ACME implementation."""
        return self.runtime_home / ".xferry"


@dataclass(frozen=True)
class HostFacts:
    """Read-only host capacity and platform observations."""

    os_id: str
    os_version: str
    machine: str
    has_systemd: bool
    ram_mib: int
    cpu_count: int
    disk_free_mib: int

    @property
    def is_supported_os(self) -> bool:
        """Return whether the operating system is in the managed support boundary."""
        return (self.os_id, self.os_version) in _SUPPORTED_MANAGED_OS_RELEASES

    @property
    def is_supported_architecture(self) -> bool:
        """Return whether the canonical release contract recognizes this Linux machine."""
        return platform_id_for_host("linux", self.machine) in SUPPORTED_PLATFORM_IDS

    @property
    def is_supported(self) -> bool:
        """Return whether this host meets the managed platform boundary."""
        return self.is_supported_os and self.is_supported_architecture and self.has_systemd

    @property
    def detected_managed_host(self) -> dict[str, object]:
        """Return bounded host facts safe for text or JSON diagnostic output."""
        return {
            "architecture": _diagnostic_token(self.machine),
            "os": _diagnostic_token(self.os_id),
            "systemd": self.has_systemd,
            "version": _diagnostic_token(self.os_version),
        }

    @property
    def managed_support_detail(self) -> str:
        """Describe the detected host and complete managed support matrix."""
        detected = self.detected_managed_host
        systemd = "present" if detected["systemd"] else "absent"
        return (
            f"Detected os={detected['os']}, version={detected['version']}, "
            f"architecture={detected['architecture']}, systemd={systemd}. "
            f"Supported matrix: {SUPPORTED_MANAGED_HOST_SUMMARY}."
        )

    @property
    def managed_support_next_actions(self) -> tuple[str, ...]:
        """Return deterministic local remediation without network calls or telemetry."""
        return MANAGED_HOST_NEXT_ACTIONS


@dataclass(frozen=True)
class ResourceOverrides:
    """Optional explicit replacements for automatically calculated limits."""

    body_budget_mib: int | None = None
    max_upload_mib: int | None = None
    workers: int | None = None
    reserve_mib: int | None = None
    upload_storage_mib: int | None = None


@dataclass(frozen=True)
class ResourcePlan:
    """Finite resource limits selected for the managed service."""

    body_budget_mib: int
    max_upload_mib: int
    workers: int
    reserve_mib: int
    upload_storage_mib: int


class SetupMode(str, Enum):
    """Supported managed network exposure modes."""

    SSLIP = "sslip"
    DOMAIN = "domain"
    PRIVATE = "private"


@dataclass(frozen=True)
class SetupOptions:
    """Operator-selected, non-secret setup inputs."""

    mode: SetupMode = SetupMode.SSLIP
    domain: str | None = None
    public_ip: str | None = None
    email: str | None = None
    firewall_answer: bool | None = None
    resources: ResourceOverrides = field(default_factory=ResourceOverrides)
    layout: ManagedLayout = field(default_factory=ManagedLayout)


@dataclass(frozen=True)
class SetupPlan:
    """Complete immutable input to a later transactional setup executor."""

    layout: ManagedLayout
    facts: HostFacts
    resources: ResourcePlan
    mode: SetupMode
    bind_host: str
    port: int
    acme_port: int | None
    domain: str | None
    public_ip: str | None
    email: str | None
    firewall_answer: bool | None
    firewall_action: Literal["allow"] | None
    firewall_ports: tuple[int, ...]


@dataclass(frozen=True)
class PreflightFailure:
    """A stable code and remediation for one pre-mutation setup blocker."""

    code: str
    message: str
    detail: str = ""
    next_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class SetupPreflight:
    """Result of all read-only checks required before setup can mutate a host."""

    executable_ready: bool
    required_bind_ports: tuple[int, ...]
    unavailable_bind_ports: tuple[int, ...]
    ufw_active: bool
    failures: tuple[PreflightFailure, ...] = ()

    @property
    def ok(self) -> bool:
        """Return whether setup may enter its future mutation boundary."""
        return not self.failures


@dataclass(frozen=True)
class SetupProbes:
    """Injectable read-only probes used by setup preflight."""

    executable_is_ready: Callable[[Path], bool]
    port_is_available: Callable[[str, int], bool]
    ufw_is_active: Callable[[], bool]
    interactive: bool = True
    unsupported_managed_state_detected: Callable[[ManagedLayout], bool] = lambda _layout: False
