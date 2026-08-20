"""Immutable values shared by managed XFerry setup planning and execution."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal


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
        return (self.os_id, self.os_version) in {
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
            ("ubuntu", "26.04"),
            ("debian", "12"),
        }

    @property
    def is_supported(self) -> bool:
        """Return whether this host meets the managed platform boundary."""
        return self.is_supported_os and self.machine == "x86_64" and self.has_systemd


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
