"""Check release tag, literal source version, and the latest dated changelog entry."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
_TAG_RE = re.compile(rf"v({_VERSION})\Z")
_HEADING_RE = re.compile(rf"## \[({_VERSION})\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})\Z")


def version_from_tag(tag: str) -> str:
    """Require the final release spelling, excluding prereleases and leading zeros."""
    match = _TAG_RE.fullmatch(tag)
    if match is None:
        raise ValueError("release tag must have exact vX.Y.Z syntax without leading zeros")
    return match.group(1)


def _source_version(workspace: Path) -> str:
    """Read source syntax without importing or executing any workspace code."""
    try:
        tree = ast.parse((workspace / "xferry/config.py").read_text(encoding="utf-8"))
    except SyntaxError as error:
        raise ValueError("source config is not valid Python") from error
    writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "__version__"
        and isinstance(node.ctx, ast.Store)
    ]
    definitions = [
        node
        for node in tree.body
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__version__"
        )
        or (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "__version__"
        )
    ]
    if len(writes) != 1 or len(definitions) != 1:
        raise ValueError("source must contain exactly one literal __version__ assignment")
    value = definitions[0].value
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        raise ValueError("source __version__ must be a string literal")
    version_from_tag(f"v{value.value}")
    return value.value


def check_source(workspace: Path, tag: str) -> str:
    """Require the requested final tag to match source and the top released entry."""
    version = version_from_tag(tag)
    supported_major = _source_version(REPO_ROOT).split(".", 1)[0]
    if version.split(".", 1)[0] != supported_major:
        raise ValueError("requested version is outside the supported source release line")
    source_version = _source_version(Path(workspace))
    if source_version != version:
        raise ValueError("requested tag does not match source __version__")
    headings = [
        line.strip()
        for line in (Path(workspace) / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
        if re.match(r" {0,3}##[ \t]", line)
    ]
    releases: list[str] = []
    for index, heading in enumerate(headings):
        if heading == "## [Unreleased]" and index == 0:
            continue
        match = _HEADING_RE.fullmatch(heading)
        if match is None:
            raise ValueError("changelog release headings must use ## [X.Y.Z] - YYYY-MM-DD")
        try:
            date.fromisoformat(match.group(2))
        except ValueError as error:
            raise ValueError("changelog release date is invalid") from error
        releases.append(match.group(1))
    if releases.count(version) != 1:
        raise ValueError("changelog must contain exactly one dated entry for the requested version")
    if releases[0] != version:
        raise ValueError("requested version must be the top released changelog entry")
    return version


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--workspace", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    try:
        print(check_source(args.workspace, args.tag))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"release preflight failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
