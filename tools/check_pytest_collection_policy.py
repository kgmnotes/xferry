#!/usr/bin/env python3
"""Fail when ignored local test files can drift from CI pytest collection."""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_ROOTS: tuple[Path, ...] = (Path("tests"),)
PYTEST_FILE_PATTERNS: tuple[str, ...] = ("test_*.py",)
ALLOWED_IGNORED_TESTS: frozenset[Path] = frozenset({Path("tests/test_close_plan_stages.py")})


@dataclass(frozen=True)
class PolicyResult:
    """Ignored pytest-style files split by explicit policy."""

    allowed: tuple[Path, ...]
    disallowed: tuple[Path, ...]


def _relative_to_root(path: Path, repo_root: Path) -> Path:
    """Return *path* relative to *repo_root* when possible."""
    try:
        return path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return path


def _is_under_test_root(path: Path, test_roots: Sequence[Path] = TEST_ROOTS) -> bool:
    """Return whether *path* is under a configured pytest test root."""
    return any(path == root or root in path.parents for root in test_roots)


def is_pytest_file(path: Path) -> bool:
    """Return whether a relative path matches this repo's pytest file policy."""
    return _is_under_test_root(path) and any(
        fnmatch.fnmatchcase(path.name, pattern) for pattern in PYTEST_FILE_PATTERNS
    )


def ignored_paths(repo_root: Path = REPO_ROOT) -> list[Path]:
    """Return Git-ignored untracked paths under pytest test roots."""
    command = [
        "git",
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "-z",
        "--",
        *(str(root) for root in TEST_ROOTS),
    ]
    completed = subprocess.run(
        command,
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode(errors="replace").strip()
        raise RuntimeError(stderr or "git ls-files failed while checking ignored test files")

    return [
        _relative_to_root(repo_root / raw.decode(), repo_root)
        for raw in completed.stdout.split(b"\0")
        if raw
    ]


def evaluate_policy(
    paths: Sequence[Path],
    allowed_ignored_tests: frozenset[Path] = ALLOWED_IGNORED_TESTS,
) -> PolicyResult:
    """Classify ignored pytest-style paths against the explicit allowlist."""
    pytest_files = sorted(path for path in paths if is_pytest_file(path))
    allowed = tuple(path for path in pytest_files if path in allowed_ignored_tests)
    disallowed = tuple(path for path in pytest_files if path not in allowed_ignored_tests)
    return PolicyResult(allowed=allowed, disallowed=disallowed)


def check_policy(repo_root: Path = REPO_ROOT) -> PolicyResult:
    """Return ignored pytest-style file policy results for *repo_root*."""
    return evaluate_policy(ignored_paths(repo_root))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Check that Git-ignored local pytest files cannot silently change "
            "local collection relative to CI."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="repository root to inspect",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    result = check_policy(args.repo_root)

    if result.disallowed:
        print("Ignored pytest-style test files are not allowed:", file=sys.stderr)
        for path in result.disallowed:
            print(f"  - {path}", file=sys.stderr)
        print(
            "Move local-only tests outside pytest collection, track them, or add a "
            "reviewed allowlist entry plus pytest collection ignore.",
            file=sys.stderr,
        )
        return 1

    if result.allowed:
        allowed = ", ".join(str(path) for path in result.allowed)
        print(f"Ignored pytest-style files are explicitly allowed: {allowed}.")
    else:
        print("No ignored pytest-style test files found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
