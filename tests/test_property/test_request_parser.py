"""Property-based tests: HTTPRequest.parse must not crash on random bytes."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from xferry.http import HTTPRequest


@given(data=st.binary(min_size=0, max_size=4096))
@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)
def test_parse_never_raises_on_random_bytes(data: bytes) -> None:
    """Fuzz the request parser with arbitrary bytes.

    The parser must either produce an HTTPRequest (possibly with empty method/
    path) or raise a controlled exception, never a crash we do not catch in
    production.
    """
    try:
        HTTPRequest(data)
    except (ValueError, UnicodeDecodeError):
        pass


# Printable ASCII only, excluding space and control characters; safe for
# HTTP request lines and latin-1 encoding.
_PATH_CHAR = st.sampled_from(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./",
)


@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
    path_tail=st.lists(_PATH_CHAR, min_size=1, max_size=32).map("".join),
    body=st.binary(min_size=0, max_size=512),
)
@settings(max_examples=100, deadline=None)
def test_parse_well_formed_request_preserves_method_and_body(
    method: str,
    path_tail: str,
    body: bytes,
) -> None:
    """A well-formed request round-trips method and body through the parser."""
    path = "/" + path_tail.lstrip("/")
    raw = (
        f"{method} {path} HTTP/1.1\r\nHost: example.com\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode("latin-1") + body

    req = HTTPRequest(raw)

    assert req.method == method
    assert req.body == body
