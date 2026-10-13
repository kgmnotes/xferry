"""Bounded-memory resource smoke tests for encrypted streaming transfers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from xferry.encrypted_transfer import EUF_CHUNK_SIZE, EUF_GCM_TAG_SIZE

REPO_ROOT = Path(__file__).resolve().parents[1]
RESOURCE_SMOKE = REPO_ROOT / "tools" / "encrypted_transfer_resource_smoke.py"
MIB = 1024 * 1024


def _expected_digest(size_bytes: int) -> str:
    digest = hashlib.sha256()
    for index, start in enumerate(range(0, size_bytes, EUF_CHUNK_SIZE)):
        length = min(EUF_CHUNK_SIZE, size_bytes - start)
        digest.update(bytes([index % 251]) * length)
    return digest.hexdigest()


def _run_resource_smoke(size_mib: int, *, timeout: float) -> dict[str, object]:
    command = [
        sys.executable,
        str(RESOURCE_SMOKE),
        "--size-mib",
        str(size_mib),
        "--json",
    ]
    if size_mib == 2048:
        command.append("--allow-2gib")
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    return json.loads(completed.stdout)


def _assert_round_trip(result: dict[str, object], size_mib: int) -> None:
    size_bytes = size_mib * MIB
    chunk_count = (size_bytes + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE
    expected_digest = _expected_digest(size_bytes)

    assert result["schema_version"] == 1
    assert result["plaintext_bytes"] == size_bytes
    assert result["ciphertext_bytes"] == size_bytes + chunk_count * EUF_GCM_TAG_SIZE
    assert result["chunk_count"] == chunk_count
    assert result["roundtrip_bytes"] == size_bytes
    assert result["source_sha256"] == expected_digest
    assert result["roundtrip_sha256"] == expected_digest
    assert result["max_plaintext_chunk_bytes"] == EUF_CHUNK_SIZE
    assert result["plaintext_artifact_created"] is False
    assert isinstance(result["elapsed_seconds"], float)
    assert result["elapsed_seconds"] > 0
    assert isinstance(result["peak_rss_bytes"], int)
    assert result["peak_rss_bytes"] > 0
    assert isinstance(result["peak_rss_delta_bytes"], int)
    assert 0 <= result["peak_rss_delta_bytes"] < 256 * MIB


def test_64_mib_encrypted_streaming_round_trip_is_bounded() -> None:
    result = _run_resource_smoke(64, timeout=240)

    _assert_round_trip(result, 64)


def test_large_smoke_requires_explicit_disk_cost_acknowledgement() -> None:
    completed = subprocess.run(
        [sys.executable, str(RESOURCE_SMOKE), "--size-mib", "3072", "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 2
    assert "requires --allow-large" in completed.stderr


@pytest.mark.skipif(
    os.environ.get("XFERRY_RUN_2GIB_SMOKE") != "1",
    reason="set XFERRY_RUN_2GIB_SMOKE=1 to allocate and round-trip 2 GiB",
)
def test_2_gib_encrypted_streaming_resource_smoke_records_peak_memory() -> None:
    result = _run_resource_smoke(2048, timeout=1800)

    _assert_round_trip(result, 2048)
    print(json.dumps(result, sort_keys=True))
