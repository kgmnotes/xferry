"""Read-only, injectable host facts detection for managed setup."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .model import HostFacts

_MIB = 1024 * 1024


class _DiskUsage(Protocol):
    """The read-only portion of a filesystem usage result used by detection."""

    free: int


def parse_os_release(text: str) -> dict[str, str]:
    """Parse the small ID/VERSION_ID subset of an os-release file."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"ID", "VERSION_ID"}:
            continue
        values[key] = value.strip().strip('"').strip("'").casefold()
    return values


def detect_host_facts(
    *,
    os_release_text: str | None = None,
    machine: str | None = None,
    has_systemd: bool | None = None,
    page_size: int | None = None,
    physical_pages: int | None = None,
    cpu_count: int | None = None,
    disk_free_bytes: int | None = None,
    os_release_path: Path = Path("/etc/os-release"),
    data_path: Path = Path("/var/lib/xferry"),
    read_text: Callable[[Path], str] | None = None,
    disk_usage: Callable[[Path], _DiskUsage] | None = None,
) -> HostFacts:
    """Collect host facts without writing to the host or opening network connections."""
    read = read_text or (lambda path: path.read_text(encoding="utf-8"))
    raw_release = os_release_text if os_release_text is not None else read(os_release_path)
    release = parse_os_release(raw_release)
    detected_machine = machine if machine is not None else os.uname().machine
    normalized_machine = detected_machine.casefold()
    if normalized_machine in {"amd64", "x86_64"}:
        normalized_machine = "x86_64"
    selected_page_size = page_size if page_size is not None else os.sysconf("SC_PAGE_SIZE")
    selected_physical_pages = (
        physical_pages if physical_pages is not None else os.sysconf("SC_PHYS_PAGES")
    )
    selected_cpu_count = cpu_count if cpu_count is not None else (os.cpu_count() or 1)
    usage = disk_usage or shutil.disk_usage
    selected_disk_free = (
        disk_free_bytes
        if disk_free_bytes is not None
        else usage(_nearest_existing_ancestor(data_path)).free
    )
    return HostFacts(
        os_id=release.get("ID", ""),
        os_version=release.get("VERSION_ID", ""),
        machine=normalized_machine,
        has_systemd=(Path("/run/systemd/system").is_dir() if has_systemd is None else has_systemd),
        ram_mib=(selected_page_size * selected_physical_pages) // _MIB,
        cpu_count=selected_cpu_count,
        disk_free_mib=selected_disk_free // _MIB,
    )


def _nearest_existing_ancestor(path: Path) -> Path:
    """Return the existing path whose filesystem holds a future managed data root."""
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate
