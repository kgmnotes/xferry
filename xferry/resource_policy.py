"""Conservative host/container resource defaults shared by all delivery methods."""

from __future__ import annotations

import os
from pathlib import Path

_MIB = 1024 * 1024


def effective_memory_bytes() -> int:
    """Return the tightest physical/cgroup memory ceiling, never host RAM alone."""
    limits: list[int] = []
    try:
        limits.append(int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE")))
    except (OSError, ValueError, AttributeError):
        pass
    for name in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            value = Path(name).read_text(encoding="ascii").strip()
            if value != "max" and 0 < int(value) < 1 << 60:
                limits.append(int(value))
        except (OSError, ValueError):
            continue
    return min(limits) if limits else 512 * _MIB


def default_body_memory_budget() -> int:
    """Finite aggregate body admission budget, independent of workers/connections."""
    memory_mb = effective_memory_bytes() // _MIB
    return min(128, max(32, memory_mb // 8)) * _MIB
