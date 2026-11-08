#!/usr/bin/env python3
"""Use the official Ubuntu archive for browser dependencies on CI runners."""

from __future__ import annotations

import argparse
import re
from collections.abc import Sequence
from pathlib import Path

_SOURCE_FILES = (
    "apt-mirrors.txt",
    "apt-mirrors-security.txt",
    "sources.list",
    "sources.list.d/ubuntu.sources",
)
_AZURE_ARCHIVE = re.compile(
    rb"(?<!\S)https?://azure\.archive\.ubuntu\.com/ubuntu(?P<slash>/?)(?=\s|$)"
)
_UBUNTU_ARCHIVE = b"https://archive.ubuntu.com/ubuntu"


def _rewrite_line(line: bytes) -> bytes:
    comment = line.find(b"#")

    def replace(match: re.Match[bytes]) -> bytes:
        if 0 <= comment < match.start():
            return match.group()
        return _UBUNTU_ARCHIVE + match.group("slash")

    return _AZURE_ARCHIVE.sub(replace, line)


def configure(apt_root: Path) -> tuple[Path, ...]:
    """Rewrite Azure URLs in the runner's direct sources and mirror lists."""
    changed = []
    for relative in _SOURCE_FILES:
        path = apt_root / relative
        if not path.exists():
            continue
        original = path.read_bytes()
        updated = b"".join(_rewrite_line(line) for line in original.splitlines(keepends=True))
        if updated != original:
            path.write_bytes(updated)
            changed.append(path)
    return tuple(changed)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apt-root", type=Path, default=Path("/etc/apt"))
    args = parser.parse_args(argv)
    for path in configure(args.apt_root):
        print(f"{path}: using https://archive.ubuntu.com/ubuntu")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
