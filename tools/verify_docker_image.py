#!/usr/bin/env python3
"""Reject Docker images that contain an internal public-surface artifact."""

from __future__ import annotations

import argparse
import subprocess
import tarfile
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    from tools.check_public_surface import is_forbidden_path
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from check_public_surface import is_forbidden_path


def image_members(image: str) -> tuple[str, ...]:
    """Enumerate file names from the image's saved layer archives."""
    with TemporaryDirectory(prefix="xferry-image-surface-") as temporary_directory:
        archive_path = Path(temporary_directory) / "image.tar"
        result = subprocess.run(
            ["docker", "image", "save", "--output", str(archive_path), image],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"docker image save failed for {image}")
        members: set[str] = set()
        with tarfile.open(archive_path) as image_archive:
            for layer in image_archive.getmembers():
                if not layer.isfile():
                    continue
                layer_stream = image_archive.extractfile(layer)
                if layer_stream is None:
                    continue
                try:
                    with tarfile.open(fileobj=layer_stream, mode="r|*") as layer_archive:
                        members.update(member.name.removeprefix("./") for member in layer_archive)
                except tarfile.ReadError:
                    continue
        return tuple(sorted(members))


def main(argv: Sequence[str] | None = None) -> int:
    """Validate the final filesystem layers of a local Docker image."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args(argv)
    forbidden = [member for member in image_members(args.image) if is_forbidden_path(member)]
    if forbidden:
        print("Docker image contains forbidden public-surface paths:")
        print("\n".join(forbidden))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
