#!/usr/bin/env python3
"""Sync root-canonical Markdown files into MkDocs mirrors under ``docs/``."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class MirrorSpec:
    """Describe one root-canonical document mirrored into ``docs/``."""

    source: str
    target: str
    replacements: tuple[tuple[str, str], ...] = ()


MIRRORS: tuple[MirrorSpec, ...] = (
    MirrorSpec(
        "API.md",
        "docs/api.md",
        replacements=(("(docs/ADR/", "(ADR/"),),
    ),
    MirrorSpec("CHANGELOG.md", "docs/changelog.md"),
    MirrorSpec(
        "CONTRIBUTING.md",
        "docs/contributing.md",
        replacements=(
            ("(docs/ADR/", "(ADR/"),
            ("(SECURITY.md)", "(security.md)"),
        ),
    ),
    MirrorSpec(
        "SECURITY.md",
        "docs/security.md",
        replacements=(
            ("(docs/threat-model.md)", "(threat-model.md)"),
            ("(docs/public-direct.md)", "(public-direct.md)"),
            ("(docs/operations.md)", "(operations.md)"),
        ),
    ),
)


def render_target(spec: MirrorSpec) -> bytes:
    """Render the target document content for *spec*."""
    source_path = REPO_ROOT / spec.source
    text = source_path.read_text(encoding="utf-8")
    for old, new in spec.replacements:
        text = text.replace(old, new)

    banner = (
        f"<!-- Generated from ../{spec.source} by tools/sync_docs.py. "
        f"Edit {spec.source} and rerun the sync tool. -->\n\n"
    )
    return (banner + text).encode("utf-8")


def sync(check: bool) -> int:
    """Sync or check every configured mirror."""
    drifted: list[str] = []
    updated: list[str] = []

    for spec in MIRRORS:
        target_path = REPO_ROOT / spec.target
        expected = render_target(spec)
        current = target_path.read_bytes() if target_path.exists() else None

        if current == expected:
            continue

        if check:
            drifted.append(f"{spec.source} -> {spec.target}")
            continue

        target_path.write_bytes(expected)
        updated.append(spec.target)

    if check:
        if drifted:
            print("Documentation mirrors are out of sync:", file=sys.stderr)
            for item in drifted:
                print(f"  - {item}", file=sys.stderr)
            print(
                "\nRun './.venv/bin/python tools/sync_docs.py --write' "
                "or 'python3 tools/sync_docs.py --write' to regenerate them.",
                file=sys.stderr,
            )
            return 1
        print("Documentation mirrors are in sync.")
        return 0

    if updated:
        print("Updated documentation mirrors:")
        for path in updated:
            print(f"  - {path}")
    else:
        print("Documentation mirrors already up to date.")
    return 0


def parse_args() -> argparse.Namespace:
    """Parse command-line flags."""
    parser = argparse.ArgumentParser(
        description=("Sync root-canonical Markdown files into docs/ mirrors used by MkDocs.")
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when any generated docs/ mirror has drifted",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="rewrite the generated docs/ mirrors in place",
    )
    return parser.parse_args()


def main() -> int:
    """Entry point."""
    args = parse_args()
    check = args.check and not args.write
    return sync(check=check)


if __name__ == "__main__":
    raise SystemExit(main())
