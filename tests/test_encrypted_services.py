"""Behavioral tests for retrying transfers and durable ciphertext-only browser storage."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "scenario",
    [
        "network_retries",
        "network_terminal",
        "network_stalls",
        "network_chunk_bounds",
        "network_cancellation",
        "network_xhr",
        "network_active_cancel",
        "network_progress_watchdog",
        "network_empty_progress_watchdog",
        "network_offline_recovery",
        "persistence_durable",
        "persistence_abort",
        "persistence_ciphertext",
        "persistence_quota",
        "persistence_cleanup",
        "persistence_locks",
        "persistence_unavailable",
        "persistence_manifest_conflict",
        "persistence_corrupt_cache",
        "persistence_orphan_recovery",
        "persistence_stats_readonly",
        "persistence_stats_concurrent_delete",
    ],
)
def test_encrypted_service_behavior(scenario: str) -> None:
    completed = subprocess.run(
        ["node", str(REPO_ROOT / "tests" / "encrypted_services_node.cjs"), scenario],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
