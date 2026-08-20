from __future__ import annotations

import pytest

from xferry.config import __version__
from xferry.management import versions


def test_current_version_starts_the_pre_1_0_line() -> None:
    assert __version__ == "0.1.0"
    assert versions.SUPPORTED_RELEASE_MAJOR == __version__.split(".", 1)[0] == "0"


@pytest.mark.parametrize(
    "value",
    ["0.0.0", "0.1.0", "0.9.9", "0.1.0-rc.1", "0.1.0+build.1"],
)
def test_supported_release_policy_accepts_canonical_0x(value: str) -> None:
    assert versions.is_supported_release_version(value) is True


@pytest.mark.parametrize(
    "value",
    [None, 0, "", "0.1", "0.01.0", "1.0.0", "2.1.0", "3.0.0"],
)
def test_supported_release_policy_rejects_malformed_and_other_majors(value: object) -> None:
    assert versions.is_supported_release_version(value) is False


@pytest.mark.parametrize("value", ["1.0.0", "2.1.0", "3.0.0"])
def test_canonical_parser_remains_major_neutral(value: str) -> None:
    assert versions.is_canonical_release_version(value) is True
