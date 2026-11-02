"""Automatic body budgets respect container memory and remain independent of sockets."""

from pathlib import Path

import pytest

from xferry import resource_policy
from xferry.settings import resolve_settings


@pytest.mark.parametrize(
    "physical_mb,cgroup,budget_mb", [(8192, "536870912", 64), (889, "max", 111), (128, "max", 32)]
)
def test_effective_memory_controls_admission_budget(monkeypatch, physical_mb, cgroup, budget_mb):
    monkeypatch.setattr(
        resource_policy.os,
        "sysconf",
        lambda name: physical_mb * 256 if name == "SC_PHYS_PAGES" else 4096,
    )

    def read_limit(path, **_):
        if str(path) == "/sys/fs/cgroup/memory.max":
            return cgroup
        raise FileNotFoundError

    monkeypatch.setattr(Path, "read_text", read_limit)
    assert resource_policy.default_body_memory_budget() == budget_mb * 1024 * 1024
    small = resolve_settings(cli_values={"workers": 1, "max_connections": 4})
    large = resolve_settings(cli_values={"workers": 16, "max_connections": 128})
    assert small.body_memory_budget_mb == large.body_memory_budget_mb == budget_mb
    assert small.to_server_config().limits.body_memory_budget == budget_mb * 1024 * 1024
