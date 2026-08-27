"""Trusted request-authority and protected-header admission tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from xferry.http import HTTPRequest
from xferry.request_admission import (
    AdmissionFailure,
    RequestAdmissionConfig,
    RequestAdmissionContext,
    RequestAdmissionPolicy,
)


def _request(
    *header_lines: str,
    version: str = "HTTP/1.1",
    method: str = "GET",
    target: str = "/",
) -> HTTPRequest:
    raw = "\r\n".join((f"{method} {target} {version}", *header_lines, "", ""))
    return HTTPRequest(raw.encode("utf-8"))


def _policy(
    *allowed_hosts: str,
    bind_host: str = "127.0.0.1",
    tls_enabled: bool = False,
    port: int = 8080,
    certificate_domain: str | None = None,
) -> RequestAdmissionPolicy:
    return RequestAdmissionPolicy.from_config(
        RequestAdmissionConfig(
            bind_host=bind_host,
            server_port=port,
            tls_enabled=tls_enabled,
            allowed_hosts=tuple(allowed_hosts),
            certificate_domain=certificate_domain,
        )
    )


@pytest.mark.parametrize(
    ("version", "headers", "expected_host", "expected_port"),
    [
        ("HTTP/1.0", (), None, None),
        ("HTTP/1.1", ("Host: LOCALHOST.",), "localhost", None),
        ("HTTP/1.1", ("Host: localhost:1",), "localhost", 1),
        ("HTTP/2.0", ("Host: localhost:65535",), "localhost", 65535),
        ("HTTP/1.1", ("Host: 127.0.0.1:8080",), "127.0.0.1", 8080),
        ("HTTP/1.1", ("Host: [0:0:0:0:0:0:0:1]:443",), "::1", 443),
        ("HTTP/1.1", ("Host: b\u00fccher.example",), "xn--bcher-kva.example", None),
    ],
)
def test_admit_canonicalizes_valid_request_authorities(
    version: str,
    headers: tuple[str, ...],
    expected_host: str | None,
    expected_port: int | None,
) -> None:
    """Catch rejecting valid HTTP/1.0 omission or canonical authority aliases."""
    policy = _policy("localhost", "127.0.0.1", "[::1]", "xn--bcher-kva.example")

    result = policy.admit(_request(*headers, version=version))

    assert isinstance(result, RequestAdmissionContext)
    if expected_host is None:
        assert result.authority is None
    else:
        assert result.authority is not None
        assert result.authority.host == expected_host
        assert result.authority.port == expected_port


@pytest.mark.parametrize("version", ["HTTP/1.1", "HTTP/1.01", "HTTP/2.0"])
def test_admit_requires_host_for_every_version_except_exact_http_1_0(version: str) -> None:
    """Catch alternate parser-accepted versions bypassing the Host requirement."""
    result = _policy("example.test").admit(_request(version=version))

    assert result == AdmissionFailure(
        status=400,
        code="invalid_header",
        message="Invalid Host header",
        field="Host",
    )


@pytest.mark.parametrize(
    "authority",
    [
        "",
        "   ",
        "example.test:",
        "example.test:0",
        "example.test:+443",
        "example.test:65536",
        "example.test:abc",
        "127.000.000.001",
        "::1",
        "[::1",
        "[::1]extra",
        "[::1]:",
        "user@example.test",
        "http://example.test",
        "example.test/path",
        "example.test?query",
        "example.test#fragment",
        "*.example.test",
        "192.0.2.0/24",
        "example.test,localhost",
        "bad host.test",
        "-bad.example",
        "bad-.example",
        "bad..example",
    ],
)
def test_admit_rejects_malformed_host_authority(authority: str) -> None:
    """Catch malformed authorities reaching downstream security consumers."""
    result = _policy("example.test").admit(_request(f"Host: {authority}"))

    assert result == AdmissionFailure(
        status=400,
        code="invalid_header",
        message="Invalid Host header",
        field="Host",
    )


def test_admit_distinguishes_disallowed_valid_host_from_invalid_header() -> None:
    """Catch a forged valid Host plus matching Origin proving its own authority."""
    result = _policy("files.example").admit(
        _request("Host: attacker.example", "Origin: https://attacker.example")
    )

    assert result == AdmissionFailure(
        status=421,
        code="misdirected_request",
        message="Misdirected Request",
        field="Host",
    )


_PROTECTED_FIELDS = (
    ("Host", "example.test"),
    ("Authorization", "Basic Zm9vOmJhcg=="),
    ("Origin", "http://example.test"),
    ("Sec-Fetch-Site", "same-origin"),
    ("Connection", "keep-alive"),
    ("Upgrade", "websocket"),
    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ("Sec-WebSocket-Version", "13"),
    ("Access-Control-Request-Method", "STEALTH"),
    ("Access-Control-Request-Headers", "Content-Type, X-XFerry-Data"),
)


@pytest.mark.parametrize(("field", "value"), _PROTECTED_FIELDS)
@pytest.mark.parametrize("reverse", [False, True], ids=["original-order", "reverse-order"])
def test_admit_rejects_every_duplicate_protected_field(
    field: str,
    value: str,
    reverse: bool,
) -> None:
    """Catch first/last selection for identical or conflicting protected fields."""
    second = "example.test" if field == "Host" else f"{value}-other"
    duplicates = (f"{field}: {value}", f"{field.lower()}: {second}")
    if reverse:
        duplicates = tuple(reversed(duplicates))
    host = () if field == "Host" else ("Host: example.test",)

    result = _policy("example.test").admit(_request(*host, *duplicates))

    assert result == AdmissionFailure(
        status=400,
        code="invalid_header",
        message=f"Invalid {field} header",
        field=field,
    )


@pytest.mark.parametrize(("field", "value"), _PROTECTED_FIELDS)
def test_admit_rejects_obs_fold_for_every_protected_field(field: str, value: str) -> None:
    """Catch normalized continuation lines hiding obs-fold from the admission gate."""
    host = "" if field == "Host" else "Host: example.test\r\n"
    request = HTTPRequest(
        (f"GET / HTTP/1.1\r\n{host}{field}: {value}\r\n folded\r\n\r\n").encode("ascii")
    )

    result = _policy("example.test").admit(request)

    assert result == AdmissionFailure(
        status=400,
        code="invalid_header",
        message=f"Invalid {field} header",
        field=field,
    )


@pytest.mark.parametrize(("field", "value"), _PROTECTED_FIELDS)
@pytest.mark.parametrize("padding", [" ", "\t"], ids=["space", "tab"])
def test_admit_rejects_whitespace_before_protected_header_colon(
    field: str,
    value: str,
    padding: str,
) -> None:
    """Catch malformed aliases hiding a protected occurrence from singleton checks."""
    host = ("Host: example.test",)

    result = _policy("example.test").admit(_request(*host, f"{field}{padding}: {value}"))

    assert result == AdmissionFailure(
        status=400,
        code="invalid_header",
        message=f"Invalid {field} header",
        field=field,
    )


def test_http_1_0_rejects_malformed_host_instead_of_treating_it_as_omitted() -> None:
    """Catch optional HTTP/1.0 Host semantics accepting a malformed Host field-name."""
    result = _policy("example.test").admit(_request("Host : attacker.example", version="HTTP/1.0"))

    assert result == AdmissionFailure(
        status=400,
        code="invalid_header",
        message="Invalid Host header",
        field="Host",
    )


def test_admit_preserves_single_security_values_and_valid_comma_lists() -> None:
    """Catch admission dropping trusted singleton values needed downstream."""
    result = _policy("example.test").admit(
        _request(
            "Host: example.test:8080",
            "Authorization: Basic Zm9vOmJhcg==",
            "Origin: http://example.test:8080",
            "Sec-Fetch-Site: same-origin",
            "Connection: keep-alive, Upgrade",
            "Upgrade: websocket",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version: 13",
            "Access-Control-Request-Method: STEALTH",
            "Access-Control-Request-Headers: Content-Type, X-XFerry-Data",
        )
    )

    assert isinstance(result, RequestAdmissionContext)
    assert result.authorization == "Basic Zm9vOmJhcg=="
    assert result.origin == "http://example.test:8080"
    assert result.sec_fetch_site == "same-origin"
    assert result.connection == "keep-alive, Upgrade"
    assert result.upgrade == "websocket"
    assert result.websocket_key == "dGhlIHNhbXBsZSBub25jZQ=="
    assert result.websocket_version == "13"
    assert result.preflight_method == "STEALTH"
    assert result.preflight_headers == "Content-Type, X-XFerry-Data"


@pytest.mark.parametrize(
    ("bind_host", "request_host"),
    [
        ("0.0.0.0", "localhost"),
        ("0.0.0.0", "127.99.1.2"),
        ("::", "[::1]"),
        ("localhost", "127.0.0.1"),
        ("127.8.9.10", "localhost"),
        ("127.8.9.10", "127.222.1.2"),
        ("192.0.2.40", "192.0.2.40"),
        ("Files.Example.", "files.example"),
    ],
)
def test_auto_mode_admits_only_the_bind_class_authorities(
    bind_host: str,
    request_host: str,
) -> None:
    """Catch auto mode either rejecting legitimate binds or trusting arbitrary names."""
    result = _policy(bind_host=bind_host).admit(_request(f"Host: {request_host}"))

    assert isinstance(result, RequestAdmissionContext)


def test_wildcard_auto_mode_rejects_non_loopback_authority() -> None:
    """Catch wildcard bind auto mode becoming a wildcard Host policy."""
    result = _policy(bind_host="0.0.0.0").admit(_request("Host: files.example"))

    assert isinstance(result, AdmissionFailure)
    assert (result.status, result.code) == (421, "misdirected_request")


def test_explicit_list_replaces_auto_loopback_authorities() -> None:
    """Catch an explicit allowlist being merged with permissive auto defaults."""
    policy = _policy("files.example", bind_host="127.0.0.1")

    assert isinstance(policy.admit(_request("Host: files.example")), RequestAdmissionContext)
    assert isinstance(policy.admit(_request("Host: localhost")), AdmissionFailure)


def test_certificate_domain_is_added_to_auto_mode() -> None:
    """Catch the final certificate identity not becoming an admitted authority."""
    result = _policy(
        bind_host="0.0.0.0",
        certificate_domain="203-0-113-10.sslip.io",
    ).admit(_request("Host: 203-0-113-10.sslip.io"))

    assert isinstance(result, RequestAdmissionContext)


@pytest.mark.parametrize(
    "configured_host",
    [
        "*",
        "*.example.test",
        "192.0.2.0/24",
        "https://example.test",
        "example.test:443",
        "user@example.test",
        "example.test/path",
        "example.test?query",
        "example.test#fragment",
        "example.test,localhost",
    ],
)
def test_policy_rejects_non_host_allowed_host_entries(configured_host: str) -> None:
    """Catch URL, wildcard, network, port, or comma syntax widening operator policy."""
    with pytest.raises(ValueError, match="invalid allowed host"):
        _policy(configured_host)


def test_policy_accepts_bare_or_bracketed_ipv6_config_and_canonicalizes_it() -> None:
    """Catch ambiguity in the ruled IPv6 config spelling contract."""
    policy = _policy("::1", "[2001:0db8::1]")

    assert policy.allowed_hosts == frozenset({"::1", "2001:db8::1"})


@pytest.mark.parametrize(
    ("tls_enabled", "host", "port", "origin", "expected"),
    [
        (False, "LOCALHOST.", None, "http://localhost", True),
        (False, "localhost", 80, "http://LOCALHOST.:80/", True),
        (True, "xn--bcher-kva.example", None, "https://b\u00fccher.example:443", True),
        (True, "::1", 8443, "https://[0:0:0:0:0:0:0:1]:8443/", True),
        (True, "example.test", None, "http://example.test", False),
        (True, "example.test", 8443, "https://example.test", False),
        (False, "example.test", None, "https://user@example.test", False),
        (False, "example.test", None, "http://example.test/path", False),
    ],
)
def test_same_origin_compares_effective_scheme_canonical_host_and_port(
    tls_enabled: bool,
    host: str,
    port: int | None,
    origin: str,
    expected: bool,
) -> None:
    """Catch raw-string Origin/Host comparisons accepting or rejecting aliases wrongly."""
    request_host = f"[{host}]" if ":" in host else host
    if port is not None:
        request_host = f"{request_host}:{port}"
    policy = _policy(host, tls_enabled=tls_enabled, port=8443 if tls_enabled else 80)
    context = policy.admit(_request(f"Host: {request_host}", f"Origin: {origin}"))
    assert isinstance(context, RequestAdmissionContext)

    assert policy.is_same_origin(context, origin) is expected


def test_admitted_types_are_immutable() -> None:
    """Catch downstream code mutating trusted authority facts after admission."""
    result = _policy("example.test").admit(_request("Host: example.test"))
    assert isinstance(result, RequestAdmissionContext)
    assert result.authority is not None

    with pytest.raises(FrozenInstanceError):
        result.authority.host = "attacker.example"  # type: ignore[misc]
