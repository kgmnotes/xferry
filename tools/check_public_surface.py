#!/usr/bin/env python3
"""Reject tracked repository content that is not part of the public surface."""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_EXACT_PATHS = frozenset(
    {
        "CLAUDE.md",
        "DESIGN.md",
        "docs/branding-name-notes.md",
    }
)
FORBIDDEN_PATH_PREFIXES = (
    ".superpowers/",
    "codex-analysis/",
    "implementation-plan/",
    "docs/superpowers/",
    ".claude/",
    ".codex/",
)
FORBIDDEN_ASSISTANT_FILENAMES = frozenset({"AGENTS.md", "CODEX.md"})
REMOVED_PATH_REFERENCES = (
    ".superpowers",
    "codex-analysis",
    "implementation-plan",
    "docs/superpowers",
    "CLAUDE.md",
    "DESIGN.md",
    "docs/branding-name-notes.md",
)
REFERENCE_POLICY_FILES = frozenset(
    {
        ".dockerignore",
        "tools/check_public_surface.py",
        "tests/test_public_surface.py",
    }
)
CYRILLIC = re.compile(r"[\u0400-\u04ff]")
XFERRY_23 = re.compile(r"\bxferry\s+v?(?:2|3)(?:\.\d+){0,2}\b", re.IGNORECASE)
PRE_REBOOT = re.compile(r"\bpre[- ]reboot\b", re.IGNORECASE)
VERSION_REBOOT = re.compile(r"\bversion[- ]reboot\b", re.IGNORECASE)


def is_forbidden_path(relative: str) -> bool:
    """Return whether a path contains an internal public-surface component or suffix."""
    path = PurePosixPath(relative)
    parts = path.parts
    if not parts:
        return False
    if relative in FORBIDDEN_EXACT_PATHS or any(
        relative.startswith(prefix) for prefix in FORBIDDEN_PATH_PREFIXES
    ):
        return True
    if path.name in FORBIDDEN_ASSISTANT_FILENAMES:
        return True
    if any(part in {"CLAUDE.md", "DESIGN.md"} for part in parts):
        return True
    if any(
        part in {".superpowers", "codex-analysis", "implementation-plan", ".claude", ".codex"}
        for part in parts
    ):
        return True
    return any(
        parts[index : index + 2]
        in {
            ("docs", "superpowers"),
            ("docs", "branding-name-notes.md"),
        }
        for index in range(len(parts) - 1)
    )


def is_public_document(relative: str) -> bool:
    """Return whether the path is human-facing documentation that must be English."""
    if relative in {
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "API.md",
        "mkdocs.yml",
    }:
        return True
    return relative.endswith(".md") and (
        relative.startswith("docs/") or relative.startswith("examples/")
    )


def _read_utf8(path: Path) -> str | None:
    """Read tracked UTF-8 text while deliberately ignoring binary files."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _content_findings(relative: str, text: str) -> list[str]:
    findings: list[str] = []
    if "\u2014" in text:
        findings.append(f"{relative}: U+2014 EM DASH is not allowed")
    if is_public_document(relative) and CYRILLIC.search(text):
        findings.append(f"{relative}: Cyrillic is not allowed in public documentation")
    if relative not in REFERENCE_POLICY_FILES:
        for removed_path in REMOVED_PATH_REFERENCES:
            if removed_path in text:
                findings.append(f"{relative}: reference to removed internal path {removed_path!r}")
    if XFERRY_23.search(text):
        findings.append(f"{relative}: retired XFerry " + "2/3 terminology")
    if VERSION_REBOOT.search(text):
        findings.append(f"{relative}: retired version" + "-reboot narrative")
    if PRE_REBOOT.search(text):
        findings.append(f"{relative}: retired pre" + "-reboot narrative")
    return findings


def scan_public_surface(repo_root: Path, tracked_paths: Iterable[str]) -> list[str]:
    """Return every public-surface finding for supplied tracked repository paths."""
    findings: list[str] = []
    for relative in sorted(set(tracked_paths)):
        if is_forbidden_path(relative):
            findings.append(f"{relative}: forbidden internal path")
        text = _read_utf8(repo_root / relative)
        if text is not None:
            findings.extend(_content_findings(relative, text))
    return findings


def tracked_files(repo_root: Path) -> tuple[str, ...]:
    """Read the authoritative tracked-file set without consulting ignored files."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(message or "git ls-files failed")
    return tuple(path for path in result.stdout.decode("utf-8").split("\0") if path)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the tracked public-surface policy."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    findings = scan_public_surface(repo_root, tracked_files(repo_root))
    if findings:
        print("Public-surface policy violations:")
        print("\n".join(findings))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
