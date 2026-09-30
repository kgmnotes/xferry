"""Canonical XFerry release-version validation."""

from __future__ import annotations

import re
from typing import TypeGuard

from xferry.config import __version__

_CANONICAL_RELEASE_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?\Z"
)


def is_canonical_release_version(value: object) -> TypeGuard[str]:
    """Return whether ``value`` uses the published three-component release grammar."""
    return isinstance(value, str) and _CANONICAL_RELEASE_VERSION_RE.fullmatch(value) is not None


# Keep this derived: release tooling must move lines only when the package
# authority itself moves through a separately approved change.
if not is_canonical_release_version(__version__):
    raise RuntimeError("xferry.config.__version__ is not a canonical release version")

SUPPORTED_RELEASE_MAJOR: str = __version__.split(".", 1)[0]


def is_supported_release_version(value: object) -> TypeGuard[str]:
    """Return whether ``value`` is canonical and belongs to the current release line."""
    return is_canonical_release_version(value) and value.split(".", 1)[0] == SUPPORTED_RELEASE_MAJOR


def compare_release_versions(left: str, right: str) -> int:
    """Compare canonical release precedence while ignoring build metadata."""
    if not is_canonical_release_version(left) or not is_canonical_release_version(right):
        raise ValueError("invalid release version")
    left_core, left_prerelease = _release_parts(left)
    right_core, right_prerelease = _release_parts(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    if left_prerelease is None:
        return 0 if right_prerelease is None else 1
    if right_prerelease is None:
        return -1
    for left_identifier, right_identifier in zip(
        left_prerelease,
        right_prerelease,
        strict=False,
    ):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdigit()
        right_numeric = right_identifier.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_identifier) < int(right_identifier) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_identifier < right_identifier else 1
    if len(left_prerelease) == len(right_prerelease):
        return 0
    return -1 if len(left_prerelease) < len(right_prerelease) else 1


def _release_parts(value: str) -> tuple[tuple[int, int, int], tuple[str, ...] | None]:
    without_build = value.split("+", 1)[0]
    core, separator, prerelease = without_build.partition("-")
    major, minor, patch = (int(component) for component in core.split("."))
    return (major, minor, patch), tuple(prerelease.split(".")) if separator else None
