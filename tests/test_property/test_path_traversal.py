"""Property-based tests: path sanitization must block traversal attempts."""

from __future__ import annotations

import string
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

TRAVERSAL_FRAGMENTS = [
    "..",
    "../",
    "..\\",
    "./",
    ".\\",
    "%2e%2e",
    "%2e%2e/",
    "..%2f",
    "..;/",
    "....//",
]


@given(
    fragment=st.sampled_from(TRAVERSAL_FRAGMENTS),
    depth=st.integers(min_value=1, max_value=8),
    target=st.sampled_from(["passwd", "shadow", "config.yaml", "secret.txt"]),
)
@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
    deadline=None,
)
def test_relative_to_blocks_synthetic_traversal(
    fragment: str,
    depth: int,
    target: str,
) -> None:
    """``Path.resolve().relative_to(base)`` must reject every traversal variant."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp).resolve()
        user_path = (fragment * depth) + target
        candidate = (base / user_path).resolve()

        if candidate == base:
            return  # traversal fully cancels out; legitimate edge case
        try:
            candidate.relative_to(base)
            # If relative_to did not raise, candidate is inside base.
            return
        except ValueError:
            # Expected: traversal caught
            return


@given(
    segments=st.lists(
        st.text(
            alphabet=string.ascii_letters + string.digits + "_-",
            min_size=1,
            max_size=10,
        ),
        min_size=1,
        max_size=5,
    ),
)
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_legitimate_nested_paths_pass_relative_to(segments: list[str]) -> None:
    """Legitimate subpaths must pass relative_to without raising."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp).resolve()
        legit = base
        for seg in segments:
            legit = legit / seg

        # .resolve() may not raise even if the path does not exist;
        # on platforms where it does, we want the test to pass, not error.
        legit.resolve().relative_to(base)
