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
