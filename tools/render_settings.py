#!/usr/bin/env python3
"""Render schema-backed settings regions in deployment samples."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from xferry.settings import render_sample_profile  # noqa: E402

_ANY_MARKER_RE = re.compile(rb"(?m)^# (?:BEGIN|END) GENERATED:[^\r\n]*\r?$")


def start_marker(profile: str) -> bytes:
    """Return the exact start marker for one settings profile."""
    return f"# BEGIN GENERATED: xferry-settings/{profile}".encode("ascii")


def end_marker(profile: str) -> bytes:
    """Return the exact end marker for one settings profile."""
    return f"# END GENERATED: xferry-settings/{profile}".encode("ascii")


class MarkerError(ValueError):
    """Raised when a generated region cannot be identified unambiguously."""


@dataclass(frozen=True, slots=True)
class SettingsTarget:
    """One deployment sample backed by a named schema profile."""

    path: str
    profile: str


TARGETS: tuple[SettingsTarget, ...] = (
    SettingsTarget(
        path="deploy/docker/xferry.ini.example",
        profile="docker",
    ),
    SettingsTarget(
        path="deploy/systemd/xferry.ini.example",
        profile="systemd",
    ),
)


def replace_generated_region(document: bytes, generated: bytes, *, profile: str) -> bytes:
    """Replace one exact generated region while preserving all outside bytes."""
    expected_start = start_marker(profile)
    expected_end = end_marker(profile)
    markers = tuple(match.group(0).rstrip(b"\r") for match in _ANY_MARKER_RE.finditer(document))
    if markers != (expected_start, expected_end):
        raise MarkerError("expected one ordered marker pair for the target profile")
    if document.count(expected_start) != 1:
        raise MarkerError("expected exactly one start marker")
    if document.count(expected_end) != 1:
        raise MarkerError("expected exactly one end marker")

    start = document.index(expected_start)
    end = document.index(expected_end)
    if start >= end:
        raise MarkerError("generated settings markers are reordered")

    start_line_end = document.find(b"\n", start)
    if start_line_end < 0 or start_line_end > end:
        raise MarkerError("start marker must occupy a complete line")
    if document[start:start_line_end].rstrip(b"\r") != expected_start:
        raise MarkerError("start marker must be the only content on its line")

    end_line_start = document.rfind(b"\n", 0, end) + 1
    end_line_end = document.find(b"\n", end)
    if end_line_end < 0:
        end_line_end = len(document)
    if document[end_line_start:end_line_end].rstrip(b"\r") != expected_end:
        raise MarkerError("end marker must be the only content on its line")

    normalized_generated = generated.rstrip(b"\r\n") + b"\n"
    return document[: start_line_end + 1] + normalized_generated + document[end_line_start:]


def render_target(target: SettingsTarget, document: bytes) -> bytes:
    """Return the expected bytes for one schema-backed deployment sample."""
    generated = render_sample_profile(target.profile).encode("utf-8")
    return replace_generated_region(document, generated, profile=target.profile)


def render_all(*, check: bool, repo_root: Path = REPO_ROOT) -> int:
    """Check or rewrite every registered settings target."""
    drifted: list[str] = []
    updated: list[str] = []
    rendered_targets: list[tuple[SettingsTarget, Path, bytes, bytes]] = []
    for target in TARGETS:
        path = repo_root / target.path
        try:
            current = path.read_bytes()
            expected = render_target(target, current)
        except (OSError, MarkerError, UnicodeError, ValueError) as exc:
            print(f"{target.path}: {exc}", file=sys.stderr)
            return 2

        rendered_targets.append((target, path, current, expected))

    for target, path, current, expected in rendered_targets:
        if current == expected:
            continue
        if check:
            drifted.append(target.path)
        else:
            path.write_bytes(expected)
            updated.append(target.path)

    if check and drifted:
        print("Generated settings regions are out of date:", file=sys.stderr)
        for path in drifted:
            print(f"  - {path}", file=sys.stderr)
        print("Run 'python3 tools/render_settings.py --write'.", file=sys.stderr)
        return 1
    if check:
        print("Generated settings regions are current.")
    elif updated:
        print("Updated generated settings regions:")
        for path in updated:
            print(f"  - {path}")
    else:
        print("Generated settings regions already current.")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse one required render mode."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail when a region has drifted")
    mode.add_argument("--write", action="store_true", help="rewrite generated regions")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    args = parse_args(argv)
    return render_all(check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
