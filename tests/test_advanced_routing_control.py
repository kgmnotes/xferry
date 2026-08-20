"""Routing compatibility tests for the 7D token-scoped Advanced data plane."""

from __future__ import annotations

import pytest

from xferry.advanced_sessions import (
    advanced_session_prefix_matches,
    validate_advanced_session_prefix,
)


@pytest.mark.parametrize(
    "prefix",
    [
        "/",
        "/advanced",
        "/advanced/nested",
        "/UPPER-and_underscore",
    ],
)
def test_session_prefix_validator_accepts_normalized_data_prefixes(prefix: str) -> None:
    """Catches the 7D prefix grammar becoming stricter than session creation."""
    validate_advanced_session_prefix(prefix)


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "relative",
        "/advanced/",
        "/advanced//nested",
        "/advanced/.",
        "/advanced/..",
        "/advanced%2fchild",
        "/advanced\\child",
        "/advanced?x=1",
        "/advanced#frag",
        "/_xferry",
        "/_xferry/advanced-sessions",
        "/advanced/\x7f",
    ],
)
def test_session_prefix_validator_rejects_unsafe_or_service_prefixes(prefix: str) -> None:
    """Catches process-global prefix validation remnants allowing unsafe routes."""
    with pytest.raises(ValueError):
        validate_advanced_session_prefix(prefix)


@pytest.mark.parametrize(
    ("prefix", "raw_path", "decoded_path", "matches"),
    [
        ("/", "/", "/", True),
        ("/", "/advanced", "/advanced", True),
        ("/", "/_xferry/not-control", "/_xferry/not-control", False),
        ("/", "/%5Fxferry/not-control", "/_xferry/not-control", False),
        ("/", "/_%78ferry/not-control", "/_xferry/not-control", False),
        ("/advanced", "/advanced", "/advanced", True),
        ("/advanced", "/advanced/file", "/advanced/file", True),
        ("/advanced", "/advancedist", "/advancedist", False),
        ("/advanced", "/Advanced/file", "/Advanced/file", False),
        ("/advanced", "/%61dvanced/file", "/advanced/file", False),
        ("/advanced", "/advanced%2ffile", "/advanced/file", False),
    ],
)
def test_session_prefix_match_is_raw_case_sensitive_and_segment_aware(
    prefix: str,
    raw_path: str,
    decoded_path: str,
    matches: bool,
) -> None:
    """Catches decoded or near-prefix request paths gaining routing authority."""
    assert advanced_session_prefix_matches(prefix, raw_path, decoded_path) is matches
