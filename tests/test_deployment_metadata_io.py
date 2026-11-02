"""Bounded deployment metadata reads reject special files without blocking."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from xferry.management.deployment import read_document


def test_deployment_document_accepts_exact_byte_limit_and_rejects_larger_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "deployment.json"
    payload = b'{"schema": 2}'
    path.write_bytes(payload)
    assert read_document(path, maximum=len(payload)) == {"schema": 2}
    before = path.stat()
    with pytest.raises(ValueError, match="bounded"):
        read_document(path, maximum=len(payload) - 1)
    assert path.read_bytes() == payload
    assert path.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX symbolic/hard links")
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_deployment_document_refuses_links_and_directories(tmp_path: Path, kind: str) -> None:
    original = tmp_path / "unrelated.json"
    payload = b'{"schema": 2}'
    original.write_bytes(payload)
    candidate = tmp_path / "deployment.json"
    if kind == "symlink":
        candidate.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, candidate)
    else:
        candidate.mkdir()
    before = candidate.lstat()
    with pytest.raises((OSError, ValueError)):
        read_document(candidate)
    assert original.read_bytes() == payload
    assert candidate.lstat().st_ino == before.st_ino
    assert candidate.lstat().st_mode == before.st_mode


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX FIFO")
def test_deployment_document_fifo_without_writer_returns_without_blocking(tmp_path: Path) -> None:
    candidate = tmp_path / "deployment.json"
    os.mkfifo(candidate, 0o600)
    # A process timeout bounds the test even if a future implementation regresses
    # into opening the FIFO synchronously before checking its descriptor type.
    script = (
        "import sys; from pathlib import Path; "
        "from xferry.management.deployment import read_document\n"
        "try:\n"
        "    read_document(Path(sys.argv[1]))\n"
        "except (OSError, ValueError):\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(3)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(candidate)],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert completed.returncode == 0, completed.stderr
