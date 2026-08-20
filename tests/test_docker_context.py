"""Behavioral checks for the effective Docker build context."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "forbidden_path",
    (
        "CLAU" + "DE.md",
        "/".join(("implementation" + "-plan", "private.md")),
        "/".join(("docs", "super" + "powers", "private.md")),
        "/".join(("nested", "AG" + "ENTS.md")),
    ),
)
def test_effective_docker_context_excludes_internal_public_surface(
    tmp_path: Path, forbidden_path: str
) -> None:
    """Catches Docker receiving an internal path even when the image does not copy it."""
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable")

    context = tmp_path / "context"
    context.mkdir()
    shutil.copy2(REPO_ROOT / ".dockerignore", context / ".dockerignore")
    target = context / forbidden_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("private\n", encoding="utf-8")
    dockerfile = context / "Dockerfile"
    dockerfile.write_text(
        f"FROM scratch\nCOPY {forbidden_path} /private\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [docker, "build", "--no-cache", "--progress=plain", "-f", str(dockerfile), str(context)],
        cwd=context,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0, result.stdout + result.stderr
    assert "not found" in (result.stdout + result.stderr).casefold()


def test_docker_image_verifier_rejects_nested_internal_layer_path(tmp_path: Path) -> None:
    """Catches layer scanning that treats internal paths as repository-root-only."""
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable")

    image = f"xferry-public-surface-negative:{tmp_path.name}"
    dockerfile = tmp_path / "Dockerfile"
    nested_path = "/usr/local/lib/xferry/.super" + "powers/private.txt"
    dockerfile.write_text(
        "FROM busybox:1.36.1\n"
        f"RUN mkdir -p {nested_path.rsplit('/', 1)[0]} && printf private > {nested_path}\n",
        encoding="utf-8",
    )
    try:
        build = subprocess.run(
            [docker, "build", "--no-cache", "--tag", image, str(tmp_path)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert build.returncode == 0, build.stdout + build.stderr
        verify = subprocess.run(
            [sys.executable, "tools/verify_docker_image.py", "--image", image],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert verify.returncode == 1, verify.stdout + verify.stderr
        assert ".super" + "powers" in verify.stdout
    finally:
        subprocess.run([docker, "image", "rm", "--force", image], capture_output=True, check=False)
