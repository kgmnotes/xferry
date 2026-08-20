"""Behavioral coverage for the token-scoped advanced-session control API."""

from __future__ import annotations

import base64
import json
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.server_factory import make_server
from xferry.advanced_sessions import AdvancedSessionPrincipal, AdvancedSessionStore
from xferry.extensions import PluginMethodSpec, PluginSpec
from xferry.http import HTTPRequest, HTTPResponse
from xferry.security.auth import BasicAuthenticator

COLLECTION = "/_xferry/advanced-sessions"
CURRENT = "/_xferry/advanced-sessions/current"
SESSION_HEADER = "X-XFerry-Advanced-Session"
VALID_CREATE = b'{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true}'
HOST = "127.0.0.1:8080"
EXACT_ORIGIN = f"http://{HOST}"
LOOPBACK = ("127.0.0.1", 4567)
REMOTE = ("203.0.113.25", 4567)
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class Clock:
    """Deterministic UTC clock for endpoint lifecycle tests."""

    def __init__(self) -> None:
        self.value = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


class SequentialBytes:
    """Deterministic 32-byte source that records token allocations."""

    def __init__(self, *values: bytes) -> None:
        self.values = list(values)
        self.counter = 0
        self.calls: list[int] = []

    def __call__(self, length: int) -> bytes:
        self.calls.append(length)
        if self.values:
            return self.values.pop(0)
        self.counter += 1
        return self.counter.to_bytes(32, "big")


class _SendSocket:
    """Minimal socket for exercising the real request pipeline."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeout: float | None = None

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def gettimeout(self) -> float | None:
        return self.timeout

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout


@dataclass(frozen=True)
class ParsedResponse:
    status: int
    headers: dict[str, str]
    body: dict[str, object]
    raw: bytes


def _plugin_handler(_request: HTTPRequest, _context: object) -> HTTPResponse:
    return HTTPResponse(204)


def _basic_header(username: str = "Alice", password: str = "secret") -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {encoded}"


def _raw_request(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | Sequence[tuple[str, str]] | None = None,
    body: bytes = b"",
) -> bytes:
    header_items = list(headers.items()) if isinstance(headers, dict) else list(headers or ())
    lines = [f"{method} {path} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in header_items)
    if body and not any(key.lower() == "content-length" for key, _value in header_items):
        lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(lines).encode("ascii") + b"\r\n\r\n" + body


def _parse_response(payload: bytes) -> ParsedResponse:
    header_blob, body = payload.split(b"\r\n\r\n", 1)
    header_lines = header_blob.decode("iso-8859-1").split("\r\n")
    status = int(header_lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        key, value = line.split(":", 1)
        headers[key.lower()] = value.strip()
    return ParsedResponse(status, headers, json.loads(body), payload)


def _send(
    server: object,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | Sequence[tuple[str, str]] | None = None,
    body: bytes = b"",
    peer: tuple[str, int] = LOOPBACK,
) -> ParsedResponse:
    socket = _SendSocket()
    server._process_request(  # type: ignore[attr-defined]
        _raw_request(method, path, headers=headers, body=body),
        socket,
        peer,
        1,
    )
    assert len(socket.sent) == 1
    return _parse_response(socket.sent[0])


def _make_control_server(
    root: Path,
    *,
    auth: str | None = None,
    cors_origin: str | None = None,
    plugins: Sequence[PluginSpec] = (),
    plugins_override_core: bool = False,
    clock: Clock | None = None,
    source: SequentialBytes | None = None,
) -> object:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    kwargs: dict[str, object] = {
        "root_dir": str(root),
        "quiet": True,
        "plugins": tuple(plugins),
        "plugins_override_core": plugins_override_core,
    }
    if auth is not None:
        kwargs["auth"] = auth
    if cors_origin is not None:
        kwargs["cors_origin"] = cors_origin
    server = make_server(**kwargs)
    if clock is not None or source is not None:
        server.advanced_session_store = AdvancedSessionStore(
            now=(clock or Clock()).now,
            random_bytes=source or SequentialBytes(),
        )
    return server


def _create_session(
    server: object,
    principal: AdvancedSessionPrincipal,
    *,
    prefix: str = "/advanced",
) -> str:
    created = server.advanced_session_store.create(  # type: ignore[attr-defined]
        prefix=prefix,
        decoder="auto",
        diagnostic_headers=True,
        principal=principal,
    )
    return created.token


def _create_headers(*extra: tuple[str, str], auth: str | None = None) -> list[tuple[str, str]]:
    headers = [("Host", HOST), ("Content-Type", "application/json")]
    if auth is not None:
        headers.append(("Authorization", auth))
    headers.extend(extra)
    return headers


def _current_headers(
    token: str | None, *extra: tuple[str, str], auth: str | None = None
) -> list[tuple[str, str]]:
    headers = [("Host", HOST)]
    if auth is not None:
        headers.append(("Authorization", auth))
    if token is not None:
        headers.append((SESSION_HEADER, token))
    headers.extend(extra)
    return headers


def _assert_json_no_store_no_cors(response: ParsedResponse) -> None:
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    assert not any(header.startswith("access-control-") for header in response.headers)


def _error(response: ParsedResponse) -> dict[str, object]:
    error = response.body["error"]
    assert isinstance(error, dict)
    return error


def _assert_error(
    response: ParsedResponse,
    *,
    status: int,
    code: str,
    field: str | None,
) -> None:
    assert response.status == status
    _assert_json_no_store_no_cors(response)
    assert _error(response)["code"] == code
    assert _error(response)["field"] == field


def _assert_rejected_current_header_does_not_touch(
    temp_dir: Path,
    raw_header_value: str,
) -> None:
    clock = Clock()
    server = _make_control_server(temp_dir, clock=clock)
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None))

    clock.advance(timedelta(minutes=14, seconds=59))
    rejected = _send(
        server,
        "GET",
        CURRENT,
        headers=[("Host", HOST), (SESSION_HEADER, raw_header_value.format(token=token))],
    )
    clock.advance(timedelta(seconds=1))
    expired = _send(server, "GET", CURRENT, headers=_current_headers(token))

    _assert_error(rejected, status=400, code="invalid_field", field=SESSION_HEADER)
    assert "allow" not in rejected.headers
    _assert_error(expired, status=404, code="advanced_session_not_found", field=SESSION_HEADER)


def test_session_control_success_contract_create_inspect_and_revoke(temp_dir: Path) -> None:
    """Catches token leakage after create, missing no-store JSON, or inspect not touching idle."""
    clock = Clock()
    source = SequentialBytes(bytes(range(32)))
    server = _make_control_server(temp_dir / "success", clock=clock, source=source)

    created = _send(
        server,
        "POST",
        COLLECTION,
        headers=_create_headers(),
        body=VALID_CREATE,
    )

    assert created.status == 201
    _assert_json_no_store_no_cors(created)
    metadata = created.body["advanced_session"]
    assert isinstance(metadata, dict)
    token = metadata["token"]
    assert isinstance(token, str) and TOKEN_RE.fullmatch(token)
    assert metadata == {
        "token": token,
        "prefix": "/advanced",
        "decoder": "auto",
        "diagnostic_headers": True,
        "created_at": "2026-08-14T12:00:00Z",
        "expires_at": "2026-08-14T13:00:00Z",
        "idle_timeout_seconds": 900,
    }

    clock.advance(timedelta(minutes=5))
    inspected = _send(server, "GET", CURRENT, headers=_current_headers(token))

    assert inspected.status == 200
    _assert_json_no_store_no_cors(inspected)
    inspected_metadata = inspected.body["advanced_session"]
    assert isinstance(inspected_metadata, dict)
    assert "token" not in inspected_metadata
    assert inspected_metadata == {
        "prefix": "/advanced",
        "decoder": "auto",
        "diagnostic_headers": True,
        "created_at": "2026-08-14T12:00:00Z",
        "expires_at": "2026-08-14T13:00:00Z",
        "idle_timeout_seconds": 900,
    }

    clock.advance(timedelta(minutes=14, seconds=59))
    revoked = _send(server, "DELETE", CURRENT, headers=_current_headers(token))

    assert revoked.status == 200
    _assert_json_no_store_no_cors(revoked)
    assert revoked.body == {"advanced_session": {"revoked": True}}

    later = _send(server, "GET", CURRENT, headers=_current_headers(token))
    _assert_error(
        later,
        status=404,
        code="advanced_session_not_found",
        field=SESSION_HEADER,
    )


@pytest.mark.parametrize(
    ("headers", "body", "status", "code", "field"),
    [
        ([("Host", HOST)], VALID_CREATE, 415, "unsupported_media_type", "Content-Type"),
        (
            [("Host", HOST), ("Content-Type", "text/plain")],
            VALID_CREATE,
            415,
            "unsupported_media_type",
            "Content-Type",
        ),
        (_create_headers(), b"\xff", 400, "malformed_json", None),
        (_create_headers(), b"not json", 400, "malformed_json", None),
        (_create_headers(), b"[]", 400, "invalid_json_type", None),
        (
            _create_headers(),
            b'{"decoder":"auto","diagnostic_headers":true}',
            400,
            "missing_field",
            "prefix",
        ),
        (
            _create_headers(),
            b'{"prefix":"/advanced","decoder":"auto","diagnostic_headers":true,"extra":1}',
            400,
            "invalid_field",
            "extra",
        ),
        (
            _create_headers(),
            b'{"prefix":"/one","prefix":"/two","decoder":"auto","diagnostic_headers":true}',
            400,
            "invalid_field",
            "prefix",
        ),
        (
            _create_headers(),
            b'{"prefix":7,"decoder":"auto","diagnostic_headers":true}',
            400,
            "invalid_field",
            "prefix",
        ),
        (
            _create_headers(),
            b'{"prefix":"/_xferry","decoder":"auto","diagnostic_headers":true}',
            400,
            "invalid_field",
            "prefix",
        ),
        (
            _create_headers(),
            b'{"prefix":"/advanced","decoder":"base64","diagnostic_headers":true}',
            400,
            "invalid_field",
            "decoder",
        ),
        (
            _create_headers(),
            b'{"prefix":"/advanced","decoder":"auto","diagnostic_headers":"true"}',
            400,
            "invalid_field",
            "diagnostic_headers",
        ),
    ],
)
def test_post_validation_rejects_closed_json_contract_before_allocating_tokens(
    temp_dir: Path,
    headers: list[tuple[str, str]],
    body: bytes,
    status: int,
    code: str,
    field: str | None,
) -> None:
    """Catches POST accepting malformed media/JSON or allocating on invalid input."""
    source = SequentialBytes(bytes(range(32)))
    server = _make_control_server(temp_dir / f"validation-{status}-{code}", source=source)

    response = _send(server, "POST", COLLECTION, headers=headers, body=body)

    _assert_error(response, status=status, code=code, field=field)
    assert source.calls == []


def test_plugin_upload_method_conflict_is_atomic_and_sorted_before_token_allocation(
    temp_dir: Path,
) -> None:
    """Catches plugin conflicts being found after token allocation or in unstable order."""
    source = SequentialBytes(bytes(range(32)))
    server = _make_control_server(
        temp_dir / "plugin-conflict",
        plugins=(
            PluginSpec(
                name="patch-owner",
                methods=(PluginMethodSpec(method="PATCH", handler=_plugin_handler),),
            ),
            PluginSpec(
                name="post-owner",
                methods=(PluginMethodSpec(method="POST", handler=_plugin_handler),),
            ),
        ),
        plugins_override_core=True,
        source=source,
    )

    response = _send(
        server,
        "POST",
        COLLECTION,
        headers=_create_headers(),
        body=VALID_CREATE,
    )

    _assert_error(response, status=409, code="advanced_method_conflict", field=None)
    assert _error(response)["details"] == {"methods": ["PATCH", "POST"]}
    assert source.calls == []


def test_capacity_exhaustion_reports_fixed_limit_without_extra_randomness(temp_dir: Path) -> None:
    """Catches capacity being checked after allocating another token."""
    clock = Clock()
    source = SequentialBytes()
    server = _make_control_server(temp_dir / "capacity", clock=clock, source=source)
    for _ in range(64):
        _create_session(server, AdvancedSessionPrincipal("no_auth", None))

    response = _send(
        server,
        "POST",
        COLLECTION,
        headers=_create_headers(),
        body=VALID_CREATE,
    )

    _assert_error(
        response,
        status=503,
        code="advanced_session_capacity_exhausted",
        field=None,
    )
    assert _error(response)["details"] == {"limit": 64}
    assert source.calls == [32] * 64


def test_missing_current_header_and_non_header_token_sources_are_rejected(
    temp_dir: Path,
) -> None:
    """Catches cookie, body, or path tokens being accepted as session authority."""
    server = _make_control_server(temp_dir / "missing-header")
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None))

    missing = _send(server, "GET", CURRENT, headers=_current_headers(None))
    cookie_body = _send(
        server,
        "GET",
        CURRENT,
        headers=[("Host", HOST), ("Cookie", f"advanced_session={token}")],
        body=json.dumps({SESSION_HEADER: token}).encode("ascii"),
    )
    query_target = _send(
        server,
        "GET",
        f"{CURRENT}?advanced_session={token}",
        headers=[("Host", HOST), ("Cookie", f"advanced_session={token}")],
        body=json.dumps({SESSION_HEADER: token}).encode("ascii"),
    )

    for response in (missing, cookie_body):
        _assert_error(response, status=400, code="missing_field", field=SESSION_HEADER)
    assert query_target.status == 404
    assert _error(query_target)["code"] == "resource_not_found"
    assert _error(query_target)["field"] == "path"


@pytest.mark.parametrize(
    "header_values",
    [
        [""],
        ["TOKEN"],
        ["A" * 42],
        ["A" * 44],
        ["A" * 42 + "="],
        ["A" * 20 + " " + "A" * 22],
        ["A" * 20 + "," + "A" * 22],
        ["A" * 42 + "*"],
        ["valid", "valid"],
    ],
)
def test_session_header_singleton_grammar_fails_before_not_found_or_method(
    temp_dir: Path,
    header_values: list[str],
) -> None:
    """Catches malformed, duplicate, folded, or combined session headers leaking an oracle."""
    server = _make_control_server(
        temp_dir / f"bad-header-{len(header_values)}-{len(header_values[0])}"
    )
    headers: list[tuple[str, str]] = [("Host", HOST)]
    for index, value in enumerate(header_values):
        name = SESSION_HEADER if index == 0 else SESSION_HEADER.lower()
        headers.append((name, value))

    response = _send(server, "POST", CURRENT, headers=headers)

    _assert_error(response, status=400, code="invalid_field", field=SESSION_HEADER)
    assert "allow" not in response.headers


@pytest.mark.parametrize(
    ("case_name", "raw_header_value"),
    [
        pytest.param("leading-ows", " {token}", id="leading-ows"),
        pytest.param("trailing-ows", "{token} ", id="trailing-ows"),
        pytest.param("obs-fold", "{token}\r\n\tcontinued", id="obs-fold"),
    ],
)
def test_padded_or_folded_session_header_is_rejected_before_touch(
    temp_dir: Path,
    case_name: str,
    raw_header_value: str,
) -> None:
    """Catches raw OWS or obs-fold being stripped before token validation."""
    _assert_rejected_current_header_does_not_touch(temp_dir / case_name, raw_header_value)


@pytest.mark.parametrize(
    ("header_name", "bad_value", "good_value", "field"),
    [
        ("Host", "evil.example", HOST, "Host"),
        ("Origin", "https://evil.example", EXACT_ORIGIN, "Origin"),
        ("Sec-Fetch-Site", "cross-site", "same-origin", "Sec-Fetch-Site"),
        ("Content-Type", "text/plain", "application/json", "Content-Type"),
    ],
)
@pytest.mark.parametrize("order", ["bad-then-good", "good-then-bad"])
def test_duplicate_control_headers_fail_closed_before_allocation(
    temp_dir: Path,
    header_name: str,
    bad_value: str,
    good_value: str,
    field: str,
    order: str,
) -> None:
    """Catches collapsed duplicate control headers bypassing strict policy."""
    source = SequentialBytes(bytes(range(32)))
    server = _make_control_server(
        temp_dir / f"duplicate-{header_name.lower()}-{order}",
        cors_origin="https://evil.example",
        source=source,
    )
    first, second = (bad_value, good_value) if order == "bad-then-good" else (good_value, bad_value)
    headers: list[tuple[str, str]] = []
    if header_name != "Host":
        headers.append(("Host", HOST))
    if header_name != "Content-Type":
        headers.append(("Content-Type", "application/json"))
    headers.extend(((header_name, first), (header_name, second)))

    response = _send(
        server,
        "POST",
        COLLECTION,
        headers=headers,
        body=VALID_CREATE,
    )

    _assert_error(response, status=400, code="invalid_field", field=field)
    assert "allow" not in response.headers
    assert source.calls == []


@pytest.mark.parametrize(
    ("header_name", "bad_value", "good_value"),
    [
        ("Host", "evil.example", HOST),
        ("Origin", "https://evil.example", EXACT_ORIGIN),
        ("Sec-Fetch-Site", "cross-site", "same-origin"),
    ],
)
@pytest.mark.parametrize("order", ["bad-then-good", "good-then-bad"])
def test_remote_no_auth_duplicate_policy_headers_forbid_peer_before_header_oracle(
    temp_dir: Path,
    header_name: str,
    bad_value: str,
    good_value: str,
    order: str,
) -> None:
    """Catches duplicate policy-header validation outranking no-auth peer rejection."""
    clock = Clock()
    source = SequentialBytes(bytes(range(32)))
    server = _make_control_server(
        temp_dir / f"remote-duplicate-{header_name.lower()}-{order}",
        cors_origin="https://evil.example",
        clock=clock,
        source=source,
    )
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None))
    source.calls.clear()
    first, second = (bad_value, good_value) if order == "bad-then-good" else (good_value, bad_value)

    create_headers: list[tuple[str, str]] = [("Content-Type", "application/json")]
    current_headers: list[tuple[str, str]] = [(SESSION_HEADER, token)]
    if header_name != "Host":
        create_headers.append(("Host", HOST))
        current_headers.append(("Host", HOST))
    create_headers.extend(((header_name, first), (header_name, second)))
    current_headers.extend(((header_name, first), (header_name, second)))

    rejected_create = _send(
        server,
        "POST",
        COLLECTION,
        headers=create_headers,
        body=VALID_CREATE,
        peer=REMOTE,
    )
    clock.advance(timedelta(minutes=14, seconds=59))
    rejected_current = _send(
        server,
        "GET",
        CURRENT,
        headers=current_headers,
        peer=REMOTE,
    )
    clock.advance(timedelta(seconds=1))
    expired = _send(server, "GET", CURRENT, headers=_current_headers(token))

    for response in (rejected_create, rejected_current):
        _assert_error(response, status=403, code="forbidden_peer", field=None)
        assert "allow" not in response.headers
    assert source.calls == []
    _assert_error(expired, status=404, code="advanced_session_not_found", field=SESSION_HEADER)


def test_invalid_basic_and_rate_limited_control_requests_precede_all_other_checks(
    temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches control auth being rerun or ordered after peer/origin/header/method disclosure."""
    calls: list[tuple[str, str]] = []

    def verifier(username: str, password: str) -> bool:
        calls.append((username, password))
        return False

    server = _make_control_server(temp_dir / "auth-precedence")
    server.set_authenticator(BasicAuthenticator(auth_callback=verifier))  # type: ignore[attr-defined]
    invalid = _send(
        server,
        "POST",
        CURRENT,
        headers=_current_headers(
            "bad token",
            ("Origin", "https://evil.example"),
            auth=_basic_header("Mallory", "wrong"),
        ),
        peer=REMOTE,
    )

    _assert_error(invalid, status=401, code="authentication_required", field="Authorization")
    assert invalid.headers["www-authenticate"] == 'Basic realm="Restricted Area"'
    assert "allow" not in invalid.headers
    assert calls == [("Mallory", "wrong")]

    calls.clear()
    assert server._rate_limiter is not None  # type: ignore[attr-defined]
    monkeypatch.setattr(server._rate_limiter, "is_blocked", lambda _ip: True)  # type: ignore[attr-defined]
    limited = _send(
        server,
        "POST",
        CURRENT,
        headers=_current_headers(
            "bad token",
            ("Origin", "https://evil.example"),
            auth=_basic_header("Mallory", "wrong"),
        ),
        peer=REMOTE,
    )

    _assert_error(limited, status=429, code="rate_limited", field="Authorization")
    assert "www-authenticate" not in limited.headers
    assert "allow" not in limited.headers
    assert calls == []


def test_control_auth_logs_do_not_include_owner_names_or_session_tokens(
    temp_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catches Basic-auth logging exposing control owners or bearer tokens."""
    server = _make_control_server(temp_dir / "auth-log-redaction", auth="Alice:secret")
    token = "Z" * 43

    caplog.set_level(logging.DEBUG, logger="xferry")
    response = _send(
        server,
        "GET",
        CURRENT,
        headers=_current_headers(token, auth=_basic_header("SensitiveOwner", "wrong")),
        peer=REMOTE,
    )

    _assert_error(response, status=401, code="authentication_required", field="Authorization")
    assert "SensitiveOwner" not in caplog.text
    assert "wrong" not in caplog.text
    assert token not in caplog.text


def test_no_auth_remote_peer_cannot_use_forwarding_headers_and_basic_owner_can_be_remote(
    temp_dir: Path,
) -> None:
    """Catches forged forwarding headers as loopback evidence or Basic owners bound to IP."""
    no_auth_server = _make_control_server(temp_dir / "remote-no-auth")
    token = _create_session(no_auth_server, AdvancedSessionPrincipal("no_auth", None))

    forbidden = _send(
        no_auth_server,
        "GET",
        CURRENT,
        headers=_current_headers(token, ("X-Forwarded-For", "127.0.0.1")),
        peer=REMOTE,
    )

    _assert_error(forbidden, status=403, code="forbidden_peer", field=None)

    auth_server = _make_control_server(temp_dir / "remote-basic", auth="Alice:secret")
    created = _send(
        auth_server,
        "POST",
        COLLECTION,
        headers=_create_headers(auth=_basic_header("Alice", "secret")),
        body=VALID_CREATE,
        peer=REMOTE,
    )
    token = created.body["advanced_session"]["token"]  # type: ignore[index]
    inspected = _send(
        auth_server,
        "GET",
        CURRENT,
        headers=_current_headers(str(token), auth=_basic_header("Alice", "secret")),
        peer=REMOTE,
    )

    assert inspected.status == 200
    _assert_json_no_store_no_cors(inspected)


@pytest.mark.parametrize(
    ("method", "origin", "fetch_site", "expected_status", "code", "field"),
    [
        ("POST", None, None, 201, None, None),
        ("GET", EXACT_ORIGIN, None, 200, None, None),
        ("DELETE", EXACT_ORIGIN, "same-origin", 200, None, None),
        ("POST", EXACT_ORIGIN, "none", 201, None, None),
        ("GET", None, "same-origin", 200, None, None),
        ("DELETE", None, "none", 200, None, None),
        ("GET", None, "cross-site", 403, "forbidden_origin", "Sec-Fetch-Site"),
        ("DELETE", EXACT_ORIGIN, "same-site", 403, "forbidden_origin", "Sec-Fetch-Site"),
        ("POST", "https://admin.example", None, 403, "forbidden_origin", "Origin"),
        ("POST", "null", None, 403, "forbidden_origin", "Origin"),
        ("GET", "*", None, 403, "forbidden_origin", "Origin"),
        ("DELETE", "http://127.0.0.1:9999", None, 403, "forbidden_origin", "Origin"),
        ("POST", "https://127.0.0.1:8080", None, 403, "forbidden_origin", "Origin"),
        ("GET", "not an origin", "cross-site", 403, "forbidden_origin", "Origin"),
    ],
)
def test_control_origin_and_fetch_metadata_matrix_never_uses_configured_cors(
    temp_dir: Path,
    method: str,
    origin: str | None,
    fetch_site: str | None,
    expected_status: int,
    code: str | None,
    field: str | None,
) -> None:
    """Catches configured CORS origins granting control or fetch metadata being ignored."""
    server = _make_control_server(
        temp_dir / f"origin-{method}-{expected_status}-{field or 'ok'}",
        cors_origin="https://admin.example",
    )
    headers: list[tuple[str, str]]
    body = b""
    path = COLLECTION if method == "POST" else CURRENT
    if method == "POST":
        headers = _create_headers()
        body = VALID_CREATE
    else:
        token = _create_session(server, AdvancedSessionPrincipal("no_auth", None))
        headers = _current_headers(token)
    if origin is not None:
        headers.append(("Origin", origin))
    if fetch_site is not None:
        headers.append(("Sec-Fetch-Site", fetch_site))

    response = _send(server, method, path, headers=headers, body=body)

    if code is None:
        assert response.status == expected_status
        _assert_json_no_store_no_cors(response)
    else:
        _assert_error(response, status=expected_status, code=code, field=field)
        assert "allow" not in response.headers


def test_forbidden_origin_does_not_touch_idle_or_disclose_current_methods(temp_dir: Path) -> None:
    """Catches origin rejection refreshing activity or becoming an Allow oracle."""
    clock = Clock()
    server = _make_control_server(temp_dir / "origin-no-touch", clock=clock)
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None))

    clock.advance(timedelta(minutes=14, seconds=59))
    rejected = _send(
        server,
        "POST",
        CURRENT,
        headers=_current_headers(token, ("Origin", "https://admin.example")),
    )
    clock.advance(timedelta(seconds=1))
    expired = _send(server, "GET", CURRENT, headers=_current_headers(token))

    _assert_error(rejected, status=403, code="forbidden_origin", field="Origin")
    assert "allow" not in rejected.headers
    _assert_error(expired, status=404, code="advanced_session_not_found", field=SESSION_HEADER)


def test_owner_and_not_found_outcomes_are_indistinguishable_and_do_not_touch(
    temp_dir: Path,
) -> None:
    """Catches owner, mode, revoked, expired, or unknown token outcomes diverging."""

    def body_for(case_name: str, setup: object) -> dict[str, object]:
        clock = Clock()
        server = _make_control_server(
            temp_dir / f"not-found-{case_name}",
            auth="Alice:secret",
            clock=clock,
        )
        server.set_authenticator(  # type: ignore[attr-defined]
            BasicAuthenticator({"Alice": "secret", "Bob": "secret", "alice": "secret"})
        )
        token, auth_header = setup(server, clock)
        response = _send(
            server,
            "GET",
            CURRENT,
            headers=_current_headers(token, auth=auth_header),
            peer=REMOTE,
        )
        _assert_error(
            response,
            status=404,
            code="advanced_session_not_found",
            field=SESSION_HEADER,
        )
        return response.body

    def unknown(_server: object, _clock: Clock) -> tuple[str, str]:
        return "Z" * 43, _basic_header("Alice", "secret")

    def wrong_owner(server: object, _clock: Clock) -> tuple[str, str]:
        token = _create_session(server, AdvancedSessionPrincipal("basic", "Alice"))
        return token, _basic_header("Bob", "secret")

    def wrong_case(server: object, _clock: Clock) -> tuple[str, str]:
        token = _create_session(server, AdvancedSessionPrincipal("basic", "Alice"))
        return token, _basic_header("alice", "secret")

    def wrong_mode(server: object, _clock: Clock) -> tuple[str, str]:
        token = _create_session(server, AdvancedSessionPrincipal("no_auth", None))
        return token, _basic_header("Alice", "secret")

    def expired(server: object, clock: Clock) -> tuple[str, str]:
        token = _create_session(server, AdvancedSessionPrincipal("basic", "Alice"))
        clock.advance(timedelta(minutes=60))
        return token, _basic_header("Alice", "secret")

    def revoked(server: object, _clock: Clock) -> tuple[str, str]:
        token = _create_session(server, AdvancedSessionPrincipal("basic", "Alice"))
        assert server.advanced_session_store.revoke(  # type: ignore[attr-defined]
            token,
            AdvancedSessionPrincipal("basic", "Alice"),
        )
        return token, _basic_header("Alice", "secret")

    bodies = [
        body_for("unknown", unknown),
        body_for("wrong-owner", wrong_owner),
        body_for("wrong-case", wrong_case),
        body_for("wrong-mode", wrong_mode),
        body_for("expired", expired),
        body_for("revoked", revoked),
    ]

    assert bodies == [bodies[0]] * len(bodies)

    exact_server = _make_control_server(temp_dir / "exact-owner", auth="Alice:secret")
    token = _create_session(exact_server, AdvancedSessionPrincipal("basic", "Alice"))
    exact = _send(
        exact_server,
        "GET",
        CURRENT,
        headers=_current_headers(token, auth=_basic_header("Alice", "secret")),
        peer=REMOTE,
    )
    assert exact.status == 200


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_collection_wrong_methods_disclose_only_after_authz_with_canonical_allow(
    temp_dir: Path,
    method: str,
) -> None:
    """Catches collection Allow disclosure before peer/origin/header authorization."""
    server = _make_control_server(temp_dir / f"collection-wrong-{method}")

    response = _send(server, method, COLLECTION, headers=[("Host", HOST)])

    _assert_error(response, status=405, code="method_not_allowed", field=None)
    assert response.headers["allow"] == "POST"
    assert _error(response)["details"] == {"method": method}


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "OPTIONS"])
def test_current_wrong_methods_are_owner_checked_before_allow_for_token_bearing_requests(
    temp_dir: Path,
    method: str,
) -> None:
    """Catches current-session wrong methods becoming malformed-token or owner oracles."""
    server = _make_control_server(temp_dir / f"current-wrong-{method}")
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None))

    headerless = _send(server, method, CURRENT, headers=[("Host", HOST)])
    valid = _send(server, method, CURRENT, headers=_current_headers(token))
    malformed = _send(server, method, CURRENT, headers=_current_headers("bad token"))
    unknown = _send(server, method, CURRENT, headers=_current_headers("Z" * 43))

    _assert_error(headerless, status=405, code="method_not_allowed", field=None)
    assert headerless.headers["allow"] == "GET, DELETE"
    _assert_error(valid, status=405, code="method_not_allowed", field=None)
    assert valid.headers["allow"] == "GET, DELETE"
    _assert_error(malformed, status=400, code="invalid_field", field=SESSION_HEADER)
    assert "allow" not in malformed.headers
    _assert_error(unknown, status=404, code="advanced_session_not_found", field=SESSION_HEADER)
    assert "allow" not in unknown.headers


def test_current_token_bearing_wrong_method_hides_allow_from_wrong_owner(temp_dir: Path) -> None:
    """Catches current-session method disclosure before owner matching."""
    server = _make_control_server(temp_dir / "wrong-owner-method", auth="Alice:secret")
    server.set_authenticator(  # type: ignore[attr-defined]
        BasicAuthenticator({"Alice": "secret", "Bob": "secret"})
    )
    token = _create_session(server, AdvancedSessionPrincipal("basic", "Alice"))

    response = _send(
        server,
        "POST",
        CURRENT,
        headers=_current_headers(token, auth=_basic_header("Bob", "secret")),
        peer=REMOTE,
    )

    _assert_error(response, status=404, code="advanced_session_not_found", field=SESSION_HEADER)
    assert "allow" not in response.headers


def test_exact_session_control_paths_win_over_legacy_root_prefix_data_routing(
    temp_dir: Path,
) -> None:
    """Catches a root advanced-routing prefix swallowing the new exact control paths."""
    server = _make_control_server(temp_dir / "root-prefix")
    _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/")

    response = _send(
        server,
        "POST",
        COLLECTION,
        headers=_create_headers(),
        body=VALID_CREATE,
    )

    assert response.status == 201
    _assert_json_no_store_no_cors(response)
    assert "advanced_session" in response.body
    assert "upload" not in response.body


@pytest.mark.parametrize(
    ("case_name", "target"),
    [
        ("encoded-leading-underscore", "/%5Fxferry/advanced-sessions"),
        ("encoded-x", "/_%78ferry/advanced-sessions"),
        ("encoded-separator", "/_xferry%2Fadvanced-sessions"),
        ("collection-query", f"{COLLECTION}?unexpected=1"),
        ("encoded-current-leading-underscore", "/%5Fxferry/advanced-sessions/current"),
        ("current-query", f"{CURRENT}?unexpected=1"),
    ],
)
def test_non_literal_control_targets_remain_headerless_basic_uploads(
    temp_dir: Path,
    case_name: str,
    target: str,
) -> None:
    """Catches decoded or query-bearing aliases allocating or handling control sessions."""
    source = SequentialBytes(bytes(range(32)))
    server = _make_control_server(
        temp_dir / f"nonliteral-{case_name}",
        cors_origin="https://app.example",
        source=source,
    )

    response = _send(
        server,
        "POST",
        target,
        headers=_create_headers(("Origin", "https://app.example")),
        body=VALID_CREATE,
    )

    assert response.status == 201
    assert response.body["upload"]["kind"] == "basic"  # type: ignore[index]
    assert response.headers["access-control-allow-origin"] == "https://app.example"
    assert "advanced_session" not in response.body
    assert source.calls == []


def _advanced_upload_headers(
    token: str | None = None,
    *,
    name: str = "advanced.txt",
) -> list[tuple[str, str]]:
    payload = base64.b64encode(b"advanced upload").decode("ascii")
    headers = [
        ("Host", HOST),
        ("X-XFerry-Data", payload),
        ("X-XFerry-Encoding", "base64"),
        ("X-XFerry-Encryption", "none"),
        ("X-XFerry-Name", name),
    ]
    if token is not None:
        headers.append((SESSION_HEADER, token))
    return headers


def test_no_header_unknown_method_never_sniffs_legacy_payload_carriers(
    temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches body/header/query/cookie/path payload sniffing selecting Advanced."""
    server = _make_control_server(temp_dir / "no-sniff")
    advanced_calls: list[str] = []

    def forbidden_advanced_handler(request: HTTPRequest) -> HTTPResponse:
        advanced_calls.append(request.path)
        response = HTTPResponse(299)
        response.set_body(json.dumps({"advanced": True}), "application/json")
        return response

    monkeypatch.setattr(server, "handle_advanced_upload", forbidden_advanced_handler)

    response = _send(
        server,
        "XUPLOAD",
        "/looks-like-path-payload?d=cGF5bG9hZA&path_payload=1",
        headers=[
            ("Host", HOST),
            ("X-D", "cGF5bG9hZA=="),
            ("X-D-0", "cGF5"),
            ("Cookie", "xf_d=cGF5bG9hZA==; xf_data=cGF5bG9hZA=="),
        ],
        body=b'{"d":"cGF5bG9hZA==","n":"sniffed.txt"}',
    )

    assert response.status == 405
    assert _error(response)["code"] == "method_not_allowed"
    assert _error(response)["field"] is None
    assert advanced_calls == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "NONE"])
def test_headerless_upload_methods_remain_basic_even_with_legacy_advanced_carriers(
    temp_dir: Path,
    method: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches the four ordinary upload methods being stolen without a session."""
    server = _make_control_server(temp_dir / f"basic-{method.lower()}")
    advanced_calls: list[str] = []

    def forbidden_advanced_handler(request: HTTPRequest) -> HTTPResponse:
        advanced_calls.append(request.path)
        response = HTTPResponse(299)
        response.set_body(json.dumps({"advanced": True}), "application/json")
        return response

    monkeypatch.setattr(server, "handle_advanced_upload", forbidden_advanced_handler)

    response = _send(
        server,
        method,
        f"/basic-{method.lower()}.bin?d=ignored",
        headers=[
            ("Host", HOST),
            ("X-D", "cGF5bG9hZA=="),
            ("X-File-Name", f"basic-{method.lower()}.bin"),
        ],
        body=f"basic {method}".encode("ascii"),
    )

    assert response.status == 201
    assert response.body["upload"]["kind"] == "basic"  # type: ignore[index]
    assert advanced_calls == []


@pytest.mark.parametrize(
    ("method", "path", "name"),
    [
        ("POST", "/advanced", "post.txt"),
        ("PUT", "/advanced/put", "put.txt"),
        ("PATCH", "/advanced/patch", "patch.txt"),
        ("NONE", "/advanced/none", "none.txt"),
        ("XUPLOAD", "/advanced/custom", "custom.txt"),
    ],
)
def test_authorized_matching_session_admits_upload_and_custom_methods(
    temp_dir: Path,
    method: str,
    path: str,
    name: str,
) -> None:
    """Catches valid token-scoped methods falling through to Basic or 405."""
    server = _make_control_server(temp_dir / f"admit-{method.lower()}")
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")

    response = _send(server, method, path, headers=_advanced_upload_headers(token, name=name))

    assert response.status == 201
    assert response.body["upload"]["kind"] == "advanced"  # type: ignore[index]
    assert response.headers["x-xferry-handler"] == "advanced"
    assert (server.upload_dir / name).read_bytes() == b"advanced upload"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("path", "expected_status", "code", "details"),
    [
        ("/advanced", 201, "", {}),
        ("/advanced/nested", 201, "", {}),
        ("/advancedist", 409, "advanced_route_mismatch", {"prefix": "/advanced"}),
        ("/%61dvanced/nested", 409, "advanced_route_mismatch", {"prefix": "/advanced"}),
        ("/Advanced/nested", 409, "advanced_route_mismatch", {"prefix": "/advanced"}),
        ("/outside?next=/advanced", 409, "advanced_route_mismatch", {"prefix": "/advanced"}),
    ],
)
def test_session_prefix_matching_uses_raw_case_sensitive_segments_without_query(
    temp_dir: Path,
    path: str,
    expected_status: int,
    code: str,
    details: dict[str, str],
) -> None:
    """Catches decoded, near-prefix, case-folded, or query-manufactured matches."""
    server = _make_control_server(
        temp_dir / f"prefix-{expected_status}-{path.strip('/') or 'root'}"
    )
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")

    response = _send(server, "POST", path, headers=_advanced_upload_headers(token))

    assert response.status == expected_status
    rendered = response.raw.decode("utf-8", errors="replace")
    assert token not in rendered
    if expected_status == 201:
        assert response.body["upload"]["kind"] == "advanced"  # type: ignore[index]
    else:
        assert _error(response)["code"] == code
        assert _error(response)["field"] == "prefix"
        assert _error(response)["details"] == details
        assert path not in rendered


@pytest.mark.parametrize(
    "path",
    [
        "/_xferry/not-a-control",
        "/%5Fxferry/not-a-control",
        "/_%78ferry/not-a-control",
        "/%5Fxferry/advanced-sessions",
        "/_%78ferry/advanced-sessions",
        "/_xferry%2Fadvanced-sessions",
        f"{COLLECTION}?unexpected=1",
        "/%5Fxferry/advanced-sessions/current",
        f"{CURRENT}?unexpected=1",
    ],
)
def test_root_session_cannot_claim_non_control_xferry_namespace(
    temp_dir: Path,
    path: str,
) -> None:
    """Catches a root data-plane session swallowing reserved service paths."""
    server = _make_control_server(temp_dir / path.replace("/", "-").replace("%", "pct"))
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/")
    upload_name = "must-not-exist.txt"

    response = _send(
        server,
        "POST",
        path,
        headers=_advanced_upload_headers(token, name=upload_name),
    )

    _assert_error(response, status=409, code="advanced_route_mismatch", field="prefix")
    assert _error(response)["details"] == {"prefix": "/"}
    assert not (server.upload_dir / upload_name).exists()  # type: ignore[attr-defined]


def test_real_pipeline_redacts_all_path_carrier_suffixes_but_not_ordinary_routes(
    temp_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catches valid data or malformed raw names escaping into request logs."""
    server = _make_control_server(temp_dir / "path-log-redaction")
    token = _create_session(
        server,
        AdvancedSessionPrincipal("no_auth", None),
        prefix="/advanced",
    )
    encoded_data = "U0VOU0lUSVZFLVBBWUxPQUQ"
    path_headers = _current_headers(token)

    with caplog.at_level(logging.INFO, logger="xferry"):
        canonical = _send(
            server,
            "POST",
            f"/advanced/_payload/report.bin/{encoded_data}?encryption=none",
            headers=path_headers,
        )
        malformed = _send(
            server,
            "POST",
            f"/advanced/_payload/MALFORMED-NAME-SENTINEL%2Fhidden/{encoded_data}?encryption=none",
            headers=path_headers,
        )
        ordinary = _send(
            server,
            "POST",
            "/advanced/ordinary-route",
            headers=_advanced_upload_headers(token, name="ordinary.txt"),
        )

    assert canonical.status == 201
    assert malformed.status == 400
    assert _error(malformed)["code"] == "invalid_field"
    assert _error(malformed)["field"] == "name"
    assert ordinary.status == 201
    assert encoded_data not in caplog.text
    assert "MALFORMED-NAME-SENTINEL" not in caplog.text
    assert "POST /advanced/_payload/[redacted] -> 201" in caplog.text
    assert "POST /advanced/_payload/[redacted] -> 400" in caplog.text
    assert "POST /advanced/ordinary-route -> 201" in caplog.text


@pytest.mark.parametrize(
    "method",
    ["GET", "HEAD", "DELETE", "OPTIONS", "FETCH", "INFO", "PING", "NOTE", "SMUGGLE"],
)
def test_registered_core_non_upload_methods_conflict_after_session_authorization(
    temp_dir: Path,
    method: str,
) -> None:
    """Catches registered methods being shadowed by Advanced or leaking before auth."""
    server = _make_control_server(temp_dir / f"core-conflict-{method.lower()}")
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")

    response = _send(server, method, "/advanced/resource", headers=_current_headers(token))

    _assert_error(response, status=409, code="advanced_method_conflict", field=None)
    assert _error(response)["details"] == {"method": method}


def test_registered_plugin_method_conflicts_after_session_authorization(temp_dir: Path) -> None:
    """Catches plugin methods being used as token-scoped Advanced uploads."""
    plugin = PluginSpec(
        name="plugin",
        methods=(PluginMethodSpec(method="ECHO", handler=_plugin_handler),),
    )
    server = _make_control_server(temp_dir / "plugin-conflict-data", plugins=(plugin,))
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")

    response = _send(server, "ECHO", "/advanced/resource", headers=_current_headers(token))

    _assert_error(response, status=409, code="advanced_method_conflict", field=None)
    assert _error(response)["details"] == {"method": "ECHO"}


def test_session_data_auth_origin_precede_header_grammar_and_touch(temp_dir: Path) -> None:
    """Catches peer/origin checks becoming token grammar or idle-touch oracles."""
    clock = Clock()
    server = _make_control_server(temp_dir / "data-auth-origin", cors_origin="*", clock=clock)
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")

    remote_bad_token = _send(
        server,
        "POST",
        "/advanced",
        headers=_advanced_upload_headers("bad token"),
        peer=REMOTE,
    )
    wildcard_origin = _send(
        server,
        "POST",
        "/advanced",
        headers=[*_advanced_upload_headers(token), ("Origin", "https://app.example")],
    )
    clock.advance(timedelta(minutes=14, seconds=59))
    duplicate_origin = _send(
        server,
        "POST",
        "/advanced",
        headers=[
            *_advanced_upload_headers(token),
            ("Origin", EXACT_ORIGIN),
            ("Origin", "https://app.example"),
        ],
    )
    clock.advance(timedelta(seconds=1))
    expired = _send(server, "GET", CURRENT, headers=_current_headers(token))

    _assert_error(remote_bad_token, status=403, code="forbidden_peer", field=None)
    _assert_error(wildcard_origin, status=403, code="forbidden_origin", field="Origin")
    _assert_error(duplicate_origin, status=400, code="invalid_field", field="Origin")
    _assert_error(expired, status=404, code="advanced_session_not_found", field=SESSION_HEADER)


def test_exact_configured_data_origin_can_use_authorized_session(temp_dir: Path) -> None:
    """Catches the 7D data-origin seam rejecting the allowed exact CORS origin."""
    server = _make_control_server(
        temp_dir / "exact-data-origin",
        cors_origin="https://app.example",
    )
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")

    response = _send(
        server,
        "POST",
        "/advanced",
        headers=[
            *_advanced_upload_headers(token, name="cors.txt"),
            ("Origin", "https://app.example"),
        ],
    )

    assert response.status == 201
    assert response.body["upload"]["kind"] == "advanced"  # type: ignore[index]


def test_successful_advanced_data_use_touches_once_and_rejections_do_not_touch(
    temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches rejection touches or multiple post-success idle refreshes."""
    clock = Clock()
    server = _make_control_server(temp_dir / "touch", clock=clock)
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")
    resolve_calls: list[bool] = []
    touch_reprs: list[str] = []
    original_resolve = server.advanced_session_store.resolve  # type: ignore[attr-defined]
    original_touch_dispatch = getattr(server.advanced_session_store, "touch_dispatch", None)  # type: ignore[attr-defined]
    assert callable(original_touch_dispatch)

    def recording_resolve(*args: object, **kwargs: object) -> object:
        resolve_calls.append(bool(kwargs.get("touch", False)))
        return original_resolve(*args, **kwargs)

    def recording_touch_dispatch(dispatch: object) -> object:
        touch_reprs.append(repr(dispatch))
        return original_touch_dispatch(dispatch)

    monkeypatch.setattr(server.advanced_session_store, "resolve", recording_resolve)  # type: ignore[attr-defined]
    monkeypatch.setattr(  # type: ignore[attr-defined]
        server.advanced_session_store,
        "touch_dispatch",
        recording_touch_dispatch,
    )

    rejected = _send(server, "GET", "/advanced", headers=_current_headers(token))
    success = _send(
        server,
        "POST",
        "/advanced",
        headers=_advanced_upload_headers(token, name="touch.txt"),
    )

    _assert_error(rejected, status=409, code="advanced_method_conflict", field=None)
    assert success.status == 201
    assert resolve_calls == [False, False]
    assert len(touch_reprs) == 1
    assert token not in touch_reprs[0]
    assert AdvancedSessionStore._digest(token).hex() not in touch_reprs[0]


def test_successful_advanced_data_use_keeps_201_when_touch_expires_after_publish(
    temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches a post-publication touch expiry rolling back the committed upload."""
    clock = Clock()
    server = _make_control_server(temp_dir / "touch-expiry-race", clock=clock)
    token = _create_session(server, AdvancedSessionPrincipal("no_auth", None), prefix="/advanced")
    original_publish = server._get_upload_storage().publish_bytes  # type: ignore[attr-defined]

    def publish_then_expire(*args: object, **kwargs: object) -> object:
        result = original_publish(*args, **kwargs)
        clock.advance(timedelta(seconds=2))
        return result

    monkeypatch.setattr(
        server._get_upload_storage(),  # type: ignore[attr-defined]
        "publish_bytes",
        publish_then_expire,
    )

    clock.advance(timedelta(minutes=14, seconds=59))
    response = _send(
        server,
        "POST",
        "/advanced",
        headers=_advanced_upload_headers(token, name="touch-race.txt"),
    )
    later = _send(server, "GET", CURRENT, headers=_current_headers(token))

    assert response.status == 201
    assert response.body["file"]["name"] == "touch-race.txt"  # type: ignore[index]
    assert (Path(server.upload_dir) / "touch-race.txt").read_bytes() == b"advanced upload"  # type: ignore[attr-defined]
    _assert_error(later, status=404, code="advanced_session_not_found", field=SESSION_HEADER)


def test_token_owner_and_forwarding_headers_are_absent_from_data_errors_and_repr(
    temp_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catches token, owner, Authorization, or forwarding identity leakage."""
    server = _make_control_server(temp_dir / "redaction", auth="Alice:secret")
    token = _create_session(server, AdvancedSessionPrincipal("basic", "Alice"), prefix="/advanced")
    digest_hex = AdvancedSessionStore._digest(token).hex()
    caplog.set_level(logging.DEBUG, logger="xferry")

    response = _send(
        server,
        "GET",
        "/advanced",
        headers=[
            *_current_headers(token, auth=_basic_header("Alice", "secret")),
            ("X-Forwarded-For", "SensitiveForwardedPeer"),
            ("Forwarded", "for=SensitiveForwardedPeer"),
        ],
        peer=REMOTE,
    )
    rendered = response.raw.decode("utf-8", errors="replace")
    dispatch_repr = repr(
        HTTPRequest(_raw_request("GET", "/advanced", headers=[(SESSION_HEADER, token)]))
    )

    _assert_error(response, status=409, code="advanced_method_conflict", field=None)
    for sensitive in (
        token,
        digest_hex,
        "Alice",
        "Authorization",
        "Basic",
        "SensitiveForwardedPeer",
    ):
        assert sensitive not in rendered
        assert sensitive not in dispatch_repr
        assert sensitive not in caplog.text


def test_control_success_and_error_never_emit_cors_under_matching_cors_config(
    temp_dir: Path,
) -> None:
    """Catches normal response finalization decorating control responses with CORS."""
    server = _make_control_server(
        temp_dir / "no-cors",
        cors_origin=EXACT_ORIGIN,
    )

    created = _send(
        server,
        "POST",
        COLLECTION,
        headers=_create_headers(("Origin", EXACT_ORIGIN)),
        body=VALID_CREATE,
    )
    error = _send(
        server,
        "GET",
        CURRENT,
        headers=[("Host", HOST), ("Origin", EXACT_ORIGIN)],
    )

    assert created.status == 201
    _assert_json_no_store_no_cors(created)
    _assert_error(error, status=400, code="missing_field", field=SESSION_HEADER)
