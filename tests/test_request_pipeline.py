"""Focused tests for request pipeline orchestration and failure handling."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from pathlib import Path

import pytest

import xferry.http as http
from xferry.advanced_sessions import (
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
    AdvancedSessionStore,
)
from xferry.http import HTTPRequest, HTTPResponse
from xferry.request_pipeline import RequestPipeline


def _make_raw_request(
    method: str = "GET",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> bytes:
    """Build raw HTTP request bytes for pipeline tests."""
    header_lines = [f"{method} {path} HTTP/1.1"]
    if headers:
        for key, value in headers.items():
            header_lines.append(f"{key}: {value}")
    if body:
        header_lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(header_lines).encode("ascii") + b"\r\n\r\n" + body


class _SocketStub:
    """Capture writes performed by the pipeline."""

    def __init__(self, *, fail_on_send: bool = False) -> None:
        self.fail_on_send = fail_on_send
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        if self.fail_on_send:
            raise OSError("send failed")
        self.sent.append(data)


class _PipelineServerStub:
    """Small configurable stand-in for RequestPipelineServer."""

    KEEP_ALIVE_TIMEOUT = 15

    def __init__(self) -> None:
        self.cors_origin: str | None = None
        self.resolved_cors_origin: str | None = None
        self._ecdh_manager: object | None = object()
        self.use_keep_alive = False
        self.remaining_requests = 0
        self.auth_error: HTTPResponse | None = None
        self.size_error: HTTPResponse | None = None
        self.dispatch_response = HTTPResponse(200)
        self.send_response_bytes = 0
        self.websocket_attempt = False
        self.websocket_origin_allowed = True
        self.websocket_slot_available = True
        self.browser_mutation_allowed = True
        self.session_admission_error: HTTPResponse | None = None
        self.raise_on_dispatch = False
        self.call_order: list[str] = []
        self.resolve_calls: list[tuple[str, int]] = []
        self.cors_resolve_calls: list[str | None] = []
        self.auth_calls: list[tuple[str, tuple[str, int]]] = []
        self.session_admission_calls: list[str] = []
        self.size_calls: list[str] = []
        self.browser_mutation_calls: list[tuple[str, str]] = []
        self.dispatch_calls: list[str] = []
        self.dispatched_security_contexts: list[object] = []
        self.post_process_calls: list[tuple[str, int, str]] = []
        self.send_calls: list[dict[str, object]] = []
        self.record_calls: list[tuple[int, int, bool]] = []
        self.latency_calls: list[float] = []
        self.handled_websocket_paths: list[str] = []
        self.websocket_upgrade_calls = 0

    def _resolve_keep_alive(self, request: HTTPRequest, request_num: int) -> tuple[bool, int]:
        self.resolve_calls.append((request.path, request_num))
        return self.use_keep_alive, self.remaining_requests

    def _authenticate_request(
        self,
        request: HTTPRequest,
        client_address: tuple[str, int],
    ) -> HTTPResponse | None:
        self.auth_calls.append((request.path, client_address))
        return self.auth_error

    def _is_websocket_upgrade_attempt(self, request: HTTPRequest) -> bool:
        self.call_order.append("websocket-attempt")
        return self.websocket_attempt

    def _build_error_response(
        self,
        status: int,
        message: str,
        *,
        code: str | None = None,
        field: str | None = None,
        details: Mapping[str, object] | None = None,
        no_store: bool = False,
    ) -> HTTPResponse:
        fallback_codes = {
            400: "bad_request",
            401: "authentication_required",
            403: "forbidden",
            413: "payload_too_large",
            500: "internal_error",
            501: "feature_unavailable",
            503: "server_busy",
        }
        return http.error_response(
            status,
            code or fallback_codes.get(status, "http_error"),
            message,
            field=field,
            details=details,
            no_store=no_store,
        )

    def _resolve_cors_origin(self, request: HTTPRequest) -> str | None:
        self.cors_resolve_calls.append(request.headers.get("origin"))
        return self.resolved_cors_origin

    def _is_websocket_origin_allowed(self, request: HTTPRequest) -> bool:
        return self.websocket_origin_allowed

    def _upgrade_websocket(self, sock: _SocketStub, request: HTTPRequest) -> bool:
        self.websocket_upgrade_calls += 1
        if not self.websocket_slot_available:
            return False
        self.handled_websocket_paths.append(request.path)
        return True

    def _check_payload_size(self, request: HTTPRequest) -> HTTPResponse | None:
        self.call_order.append("size")
        self.size_calls.append(request.path)
        return self.size_error

    def _is_browser_mutation_allowed(self, request: HTTPRequest) -> bool:
        self.call_order.append("browser-mutation")
        self.browser_mutation_calls.append((request.method, request.path))
        return self.browser_mutation_allowed

    def _prepare_advanced_session_dispatch(self, request: HTTPRequest) -> HTTPResponse | None:
        self.call_order.append("session-admission")
        self.session_admission_calls.append(request.path)
        return self.session_admission_error

    def _dispatch_handler(self, request: HTTPRequest) -> HTTPResponse:
        self.call_order.append("dispatch")
        self.dispatch_calls.append(request.path)
        self.dispatched_security_contexts.append(request.security_context)
        if self.raise_on_dispatch:
            raise RuntimeError("boom")
        return self.dispatch_response

    def _post_process_response(
        self,
        request: HTTPRequest,
        response: HTTPResponse,
        request_id: str,
    ) -> None:
        self.post_process_calls.append((request.path, response.status_code, request_id))

    def _send_response(
        self,
        response: HTTPResponse,
        client_socket: _SocketStub,
        _bld: dict[str, object],
    ) -> int:
        self.send_calls.append({"status": response.status_code, "build_args": dict(_bld)})
        return self.send_response_bytes

    def _record_metric(
        self,
        status_code: int,
        response_size: int,
        *,
        error: bool = False,
    ) -> None:
        self.record_calls.append((status_code, response_size, error))

    def _record_request_latency(self, duration_ms: float) -> None:
        self.latency_calls.append(duration_ms)


class TestRequestPipeline:
    @pytest.mark.parametrize(
        ("prefix", "path", "expected_path"),
        [
            ("/advanced", "/advanced/_payload", "/advanced/_payload/[redacted]"),
            (
                "/advanced",
                "/advanced/_payload/report.bin/U0VOU0lUSVZFLVBBWUxPQUQ",
                "/advanced/_payload/[redacted]",
            ),
            (
                "/advanced",
                "/advanced/_payload/U0VOU0lUSVZFLVBBWUxPQUQ",
                "/advanced/_payload/[redacted]",
            ),
            (
                "/advanced",
                "/advanced/_payload/MALFORMED-NAME-SENTINEL%2Fhidden/U0VOU0lUSVZFLVBBWUxPQUQ",
                "/advanced/_payload/[redacted]",
            ),
            (
                "/advanced",
                "/advanced/_payload/report.bin/U0VOU0lUSVZFLVBBWUxPQUQ/extra",
                "/advanced/_payload/[redacted]",
            ),
            (
                "/",
                "/_payload/root.bin/U0VOU0lUSVZFLVBBWUxPQUQ",
                "/_payload/[redacted]",
            ),
        ],
    )
    def test_request_log_redacts_authorized_path_carrier_payloads_fail_closed(
        self,
        caplog: pytest.LogCaptureFixture,
        prefix: str,
        path: str,
        expected_path: str,
    ) -> None:
        """Canonical and malformed path carriers must not disclose encoded payload bytes."""
        server = _PipelineServerStub()
        principal = AdvancedSessionPrincipal("no_auth", None)
        created = AdvancedSessionStore().create(
            prefix=prefix,
            decoder="auto",
            diagnostic_headers=False,
            principal=principal,
        )
        dispatch = AdvancedSessionDispatch(
            session=created.session,
            principal=principal,
        )

        def prepare_dispatch(request: HTTPRequest) -> HTTPResponse | None:
            request.advanced_session_dispatch = dispatch
            return None

        server._prepare_advanced_session_dispatch = prepare_dispatch  # type: ignore[method-assign]
        pipeline = RequestPipeline(server)

        with caplog.at_level(logging.INFO, logger="xferry"):
            result = pipeline.process(
                _make_raw_request("POST", path, {"Host": "example.test"}),
                _SocketStub(),
                ("127.0.0.1", 12345),
                1,
            )

        assert result is False
        assert "U0VOU0lUSVZFLVBBWUxPQUQ" not in caplog.text
        assert "MALFORMED-NAME-SENTINEL" not in caplog.text
        assert f"POST {expected_path} -> 200" in caplog.text

    def test_request_log_leaves_ordinary_decoded_paths_unchanged(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        server = _PipelineServerStub()
        principal = AdvancedSessionPrincipal("no_auth", None)
        created = AdvancedSessionStore().create(
            prefix="/advanced",
            decoder="auto",
            diagnostic_headers=False,
            principal=principal,
        )
        dispatch = AdvancedSessionDispatch(
            session=created.session,
            principal=principal,
        )

        def prepare_dispatch(request: HTTPRequest) -> HTTPResponse | None:
            request.advanced_session_dispatch = dispatch
            return None

        server._prepare_advanced_session_dispatch = prepare_dispatch  # type: ignore[method-assign]
        pipeline = RequestPipeline(server)

        with caplog.at_level(logging.INFO, logger="xferry"):
            result = pipeline.process(
                _make_raw_request("GET", "/ordinary%20path", {"Host": "example.test"}),
                _SocketStub(),
                ("127.0.0.1", 12345),
                1,
            )

        assert result is False
        assert "GET /ordinary path -> 200" in caplog.text

    def test_dispatch_sees_accepted_peer_not_forged_forwarding_headers(self) -> None:
        """Forwarding headers must not override the socket peer recorded for security checks."""
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/",
                {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                },
            ),
            _SocketStub(),
            ("198.51.100.14", 54421),
            1,
        )

        assert result is False
        assert server.dispatched_security_contexts[0].direct_peer == ("198.51.100.14", 54421)
        assert server.dispatched_security_contexts[0].verified_principal is None

    def test_successful_server_auth_exposes_verified_principal_without_reverification(self) -> None:
        """Downstream dispatch consumes the principal set by the one authentication pass."""
        # The stub models the server handoff after verifying this request once.
        server = _PipelineServerStub()

        def authenticate(
            request: HTTPRequest,
            client_address: tuple[str, int],
        ) -> HTTPResponse | None:
            assert client_address == ("203.0.113.7", 9443)
            request.set_verified_principal("CaseUser")
            return None

        server._authenticate_request = authenticate  # type: ignore[method-assign]
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request("GET", "/"),
            _SocketStub(),
            ("203.0.113.7", 9443),
            1,
        )

        assert result is False
        assert server.dispatched_security_contexts[0].verified_principal == "CaseUser"

    def test_auth_failure_never_dispatches_a_request(self) -> None:
        """Authentication short-circuit prevents an unverified request reaching handlers."""
        server = _PipelineServerStub()
        server.auth_error = HTTPResponse(401)
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request("GET", "/"),
            _SocketStub(),
            ("203.0.113.7", 9443),
            1,
        )

        assert result is False
        assert server.dispatch_calls == []

    def test_malformed_request_error_returns_400_before_side_effects(self) -> None:
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            b"SYNCDATA\r\nX-D: cGF5bG9hZA==\r\n\r\n",
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 400" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "malformed_request",
                "message": "Bad Request",
                "field": None,
                "details": {},
            }
        }
        assert server.resolve_calls == []
        assert server.auth_calls == []
        assert server.size_calls == []
        assert server.dispatch_calls == []
        assert server.post_process_calls == []
        assert server.send_calls == []
        assert server.record_calls == [(400, len(sock.sent[0]), False)]

    def test_invalid_request_target_error_returns_400_before_side_effects(self) -> None:
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            b"XUPLOAD /\t HTTP/1.1\r\nX-D: cGF5bG9hZA==\r\n\r\n",
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 400" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "malformed_request",
                "message": "Bad Request",
                "field": None,
                "details": {},
            }
        }
        assert server.resolve_calls == []
        assert server.auth_calls == []
        assert server.size_calls == []
        assert server.dispatch_calls == []
        assert server.record_calls == [(400, len(sock.sent[0]), False)]

    def test_auth_error_short_circuits_and_uses_keep_alive_headers(self) -> None:
        server = _PipelineServerStub()
        server.use_keep_alive = True
        server.remaining_requests = 4
        auth_error = HTTPResponse(401)
        auth_error.set_body("unauthorized")
        server.auth_error = auth_error
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request("GET", "/", {"Host": "example.test"}),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 401" in sock.sent[0]
        assert b"Connection: keep-alive" in sock.sent[0]
        assert b"Keep-Alive: timeout=15, max=4" in sock.sent[0]
        assert server.dispatch_calls == []
        assert server.record_calls == [(401, len(sock.sent[0]), False)]

    @pytest.mark.parametrize(
        ("status", "error_code", "guard_header", "guard_value"),
        [
            (401, "authentication_required", "WWW-Authenticate", 'Basic realm="xferry"'),
            (429, "rate_limited", "Retry-After", "60"),
        ],
    )
    def test_note_auth_errors_keep_guard_headers_and_client_correlation(
        self,
        status: int,
        error_code: str,
        guard_header: str,
        guard_value: str,
    ) -> None:
        server = _PipelineServerStub()
        auth_error = http.error_response(status, error_code, "Denied")
        auth_error.set_header(guard_header, guard_value)
        server.auth_error = auth_error
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "NOTE",
                "/notes?action=list",
                {
                    "Host": "example.test",
                    "X-Request-Id": "client-auth:123",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert f"HTTP/1.1 {status}".encode() in sock.sent[0]
        assert f"{guard_header}: {guard_value}".encode() in sock.sent[0]
        assert b"X-Request-Id: client-auth:123" in sock.sent[0]
        assert server.session_admission_calls == []
        assert server.dispatch_calls == []

    def test_note_invalid_request_id_does_not_precede_authentication(self) -> None:
        server = _PipelineServerStub()
        auth_error = http.error_response(401, "authentication_required", "Denied")
        auth_error.set_header("WWW-Authenticate", 'Basic realm="xferry"')
        server.auth_error = auth_error
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "NOTE",
                "/notes?action=list",
                {"Host": "example.test", "X-Request-Id": "invalid value"},
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert b"HTTP/1.1 401" in sock.sent[0]
        assert b'WWW-Authenticate: Basic realm="xferry"' in sock.sent[0]
        assert b'"code":"authentication_required"' in sock.sent[0]
        assert b"X-Request-Id: invalid value" not in sock.sent[0]
        request_id_match = re.search(rb"\r\nX-Request-Id: ([^\r\n]+)", sock.sent[0])
        assert request_id_match is not None
        assert re.fullmatch(rb"[0-9a-f]{8}", request_id_match.group(1))
        assert server.session_admission_calls == []

    @pytest.mark.parametrize("request_id", ["client-123:trace.v1", "A" * 128])
    def test_note_http_accepts_client_request_id_for_response_correlation(
        self,
        request_id: str,
    ) -> None:
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request(
                "NOTE",
                "/notes?action=list",
                {"Host": "example.test", "X-Request-Id": request_id},
            ),
            _SocketStub(),
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert server.post_process_calls == [("/notes", 200, request_id)]
        assert server.dispatch_calls == ["/notes"]

    def test_note_http_generates_eight_hex_request_id_when_client_omits_it(self) -> None:
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request("NOTE", "/notes?action=list", {"Host": "example.test"}),
            _SocketStub(),
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(server.post_process_calls) == 1
        assert re.fullmatch(r"[0-9a-f]{8}", server.post_process_calls[0][2])

    @pytest.mark.parametrize(
        "request_id",
        ["", "invalid value", "comma,combined", "A" * 129],
    )
    def test_note_http_rejects_invalid_request_id_before_domain_dispatch(
        self,
        request_id: str,
    ) -> None:
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "NOTE",
                "/notes?action=list",
                {"Host": "example.test", "X-Request-Id": request_id},
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert b"HTTP/1.1 400" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "invalid_field",
                "message": "Invalid field",
                "field": "X-Request-Id",
                "details": {},
            }
        }
        request_id_match = re.search(rb"\r\nX-Request-Id: ([^\r\n]+)", sock.sent[0])
        assert request_id_match is not None
        assert re.fullmatch(rb"[0-9a-f]{8}", request_id_match.group(1))
        assert server.auth_calls == [("/notes", ("127.0.0.1", 12345))]
        assert server.session_admission_calls == ["/notes"]
        assert server.call_order == ["session-admission"]
        assert server.dispatch_calls == []

    def test_note_http_rejects_duplicate_request_id_header(self) -> None:
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)
        sock = _SocketStub()
        raw = (
            b"NOTE /notes?action=list HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"X-Request-Id: first\r\n"
            b"x-request-id: second\r\n\r\n"
        )

        result = pipeline.process(raw, sock, ("127.0.0.1", 12345), 1)

        assert result is False
        assert b"HTTP/1.1 400" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1])["error"] == {
            "code": "invalid_field",
            "message": "Invalid field",
            "field": "X-Request-Id",
            "details": {},
        }
        assert server.session_admission_calls == ["/notes"]
        assert server.dispatch_calls == []

    def test_invalid_client_request_id_does_not_change_non_note_http_behavior(self) -> None:
        server = _PipelineServerStub()
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/ordinary",
                {"Host": "example.test", "X-Request-Id": "invalid value"},
            ),
            _SocketStub(),
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert server.dispatch_calls == ["/ordinary"]
        assert len(server.post_process_calls) == 1
        assert re.fullmatch(r"[0-9a-f]{8}", server.post_process_calls[0][2])

    def test_payload_size_error_short_circuits_before_dispatch(self) -> None:
        server = _PipelineServerStub()
        size_error = HTTPResponse(413)
        size_error.set_body("too large")
        server.size_error = size_error
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request("POST", "/upload", {"Host": "example.test"}, b"x"),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 413" in sock.sent[0]
        assert server.dispatch_calls == []
        assert server.record_calls == [(413, len(sock.sent[0]), False)]

    def test_session_admission_precedes_payload_size_for_token_bearing_requests(self) -> None:
        """A session error must not leak payload-size behavior before authorization."""
        server = _PipelineServerStub()
        server.session_admission_error = http.error_response(
            404,
            "advanced_session_not_found",
            "Advanced session not found",
            field="X-XFerry-Advanced-Session",
            no_store=True,
        )
        size_error = HTTPResponse(413)
        size_error.set_body("too large")
        server.size_error = size_error
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "POST",
                "/advanced/upload",
                {
                    "Host": "example.test",
                    "X-XFerry-Advanced-Session": "Z" * 43,
                },
                b"x",
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 404" in sock.sent[0]
        assert server.session_admission_calls == ["/advanced/upload"]
        assert server.size_calls == []
        assert server.dispatch_calls == []
        assert "websocket-attempt" not in server.call_order
        assert server.record_calls == [(404, len(sock.sent[0]), False)]

    def test_session_admission_precedes_websocket_upgrade_for_token_bearing_requests(self) -> None:
        """A session conflict must win before a token-bearing WebSocket-looking request."""
        server = _PipelineServerStub()
        server.websocket_attempt = True
        server.session_admission_error = http.error_response(
            409,
            "advanced_method_conflict",
            "Advanced method conflict",
            details={"method": "GET"},
            no_store=True,
        )
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "X-XFerry-Advanced-Session": "Z" * 43,
                    "X-Request-Id": "ws-admission:123",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 409" in sock.sent[0]
        assert server.session_admission_calls == ["/notes/ws"]
        assert server.handled_websocket_paths == []
        assert server.websocket_upgrade_calls == 0
        assert "websocket-attempt" not in server.call_order
        assert b"X-Request-Id: ws-admission:123" in sock.sent[0]

    def test_invalid_websocket_request_id_is_rejected_after_session_admission(
        self,
    ) -> None:
        server = _PipelineServerStub()
        server.websocket_attempt = True
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "X-Request-Id": "invalid value",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert b"HTTP/1.1 400" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1])["error"] == {
            "code": "invalid_field",
            "message": "Invalid field",
            "field": "X-Request-Id",
            "details": {},
        }
        request_id_match = re.search(rb"\r\nX-Request-Id: ([^\r\n]+)", sock.sent[0])
        assert request_id_match is not None
        assert re.fullmatch(rb"[0-9a-f]{8}", request_id_match.group(1))
        assert server.session_admission_calls == ["/notes/ws"]
        assert server.call_order == ["session-admission"]
        assert server.websocket_upgrade_calls == 0

    def test_session_admission_error_precedes_invalid_websocket_request_id(self) -> None:
        server = _PipelineServerStub()
        server.websocket_attempt = True
        server.session_admission_error = http.error_response(
            409,
            "advanced_method_conflict",
            "Advanced method conflict",
            no_store=True,
        )
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "X-Request-Id": "invalid value",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert b"HTTP/1.1 409" in sock.sent[0]
        assert b'"code":"advanced_method_conflict"' in sock.sent[0]
        assert b"X-Request-Id: invalid value" not in sock.sent[0]
        request_id_match = re.search(rb"\r\nX-Request-Id: ([^\r\n]+)", sock.sent[0])
        assert request_id_match is not None
        assert re.fullmatch(rb"[0-9a-f]{8}", request_id_match.group(1))
        assert server.session_admission_calls == ["/notes/ws"]
        assert server.call_order == ["session-admission"]
        assert server.websocket_upgrade_calls == 0

    def test_browser_mutation_error_short_circuits_before_size_and_dispatch(self) -> None:
        server = _PipelineServerStub()
        server.browser_mutation_allowed = False
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "POST",
                "/upload",
                {
                    "Host": "example.test",
                    "Origin": "https://evil.example",
                },
                b"x",
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 403" in sock.sent[0]
        assert b"Forbidden cross-origin browser mutation" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "forbidden",
                "message": "Forbidden cross-origin browser mutation",
                "field": None,
                "details": {},
            }
        }
        assert server.auth_calls == [("/upload", ("127.0.0.1", 12345))]
        assert server.browser_mutation_calls == [("POST", "/upload")]
        assert server.size_calls == []
        assert server.dispatch_calls == []
        assert server.record_calls == [(403, len(sock.sent[0]), False)]

    def test_success_path_records_metric_and_returns_keep_alive(self) -> None:
        server = _PipelineServerStub()
        server.use_keep_alive = True
        server.remaining_requests = 2
        server.dispatch_response = HTTPResponse(204)
        server.send_response_bytes = 321
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request("PING", "/", {"Host": "example.test"}),
            sock,
            ("127.0.0.1", 12345),
            3,
        )

        assert result is True
        assert server.post_process_calls
        assert server.send_calls == [
            {
                "status": 204,
                "build_args": {
                    "cors_origin": None,
                    "keep_alive": True,
                    "keep_alive_timeout": 15,
                    "keep_alive_max": 2,
                },
            }
        ]
        assert server.record_calls == [(204, 321, False)]

    def test_handler_returned_500_records_error_metric(self) -> None:
        server = _PipelineServerStub()
        server.dispatch_response = HTTPResponse(500)
        server.send_response_bytes = 111
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request("GET", "/handler-error", {"Host": "example.test"}),
            _SocketStub(),
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert server.post_process_calls
        assert server.send_calls == [
            {"status": 500, "build_args": {"cors_origin": None, "keep_alive": False}}
        ]
        assert server.record_calls == [(500, 111, True)]

    def test_streaming_response_forces_connection_close(self, temp_dir: Path) -> None:
        file_path = temp_dir / "payload.bin"
        file_path.write_bytes(b"streamed")
        response = HTTPResponse(200)
        response.set_file(file_path, "application/octet-stream")

        server = _PipelineServerStub()
        server.use_keep_alive = True
        server.dispatch_response = response
        server.send_response_bytes = 123
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request("GET", "/download", {"Host": "example.test"}),
            _SocketStub(),
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert server.record_calls == [(200, 123, False)]

    def test_invalid_websocket_upgrade_error_returns_400(self) -> None:
        server = _PipelineServerStub()
        server.websocket_attempt = True
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "X-Request-Id": "ws-invalid-upgrade",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 400" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "bad_request",
                "message": "Invalid WebSocket upgrade request",
                "field": None,
                "details": {},
            }
        }
        assert b"X-Request-Id: ws-invalid-upgrade" in sock.sent[0]
        assert server.handled_websocket_paths == []
        assert server.record_calls == [(400, len(sock.sent[0]), False)]

    def test_forbidden_websocket_origin_error_returns_403(self) -> None:
        server = _PipelineServerStub()
        server.websocket_attempt = True
        server.websocket_origin_allowed = False
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Origin": "https://evil.example",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "X-Request-Id": "ws-origin",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 403" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "forbidden",
                "message": "Forbidden WebSocket origin",
                "field": None,
                "details": {},
            }
        }
        assert b"X-Request-Id: ws-origin" in sock.sent[0]
        assert server.handled_websocket_paths == []
        assert server.record_calls == [(403, len(sock.sent[0]), False)]

    def test_websocket_upgrade_feature_error_without_crypto_returns_501(self) -> None:
        server = _PipelineServerStub()
        server.websocket_attempt = True
        server._ecdh_manager = None
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Origin": "http://example.test",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "X-Request-Id": "ws-crypto",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 501" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "feature_unavailable",
                "message": "Secure Notepad requires the default cryptography runtime dependency; "
                "repair or reinstall xferry",
                "field": None,
                "details": {},
            }
        }
        assert b"X-Request-Id: ws-crypto" in sock.sent[0]
        assert server.handled_websocket_paths == []
        assert server.record_calls == [(501, len(sock.sent[0]), True)]

    def test_valid_websocket_upgrade_dispatches_handler(self) -> None:
        server = _PipelineServerStub()
        server.websocket_attempt = True
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Origin": "http://example.test",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert sock.sent == []
        assert server.handled_websocket_paths == ["/notes/ws"]
        assert server.websocket_upgrade_calls == 1
        assert server.record_calls == []

    def test_websocket_upgrade_server_busy_error_when_admission_budget_is_full(self) -> None:
        server = _PipelineServerStub()
        server.websocket_attempt = True
        server.websocket_slot_available = False
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request(
                "GET",
                "/notes/ws",
                {
                    "Host": "example.test",
                    "Origin": "http://example.test",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "X-Request-Id": "ws-capacity",
                },
            ),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 503" in sock.sent[0]
        assert b"WebSocket connection limit reached" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "server_busy",
                "message": "WebSocket connection limit reached",
                "field": None,
                "details": {},
            }
        }
        assert b"X-Request-Id: ws-capacity" in sock.sent[0]
        assert server.handled_websocket_paths == []
        assert server.websocket_upgrade_calls == 1
        assert server.record_calls == [(503, len(sock.sent[0]), True)]

    def test_internal_error_records_metric_and_sends_500(self) -> None:
        server = _PipelineServerStub()
        server.raise_on_dispatch = True
        pipeline = RequestPipeline(server)
        sock = _SocketStub()

        result = pipeline.process(
            _make_raw_request("GET", "/explode", {"Host": "example.test"}),
            sock,
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert len(sock.sent) == 1
        assert b"HTTP/1.1 500" in sock.sent[0]
        assert json.loads(sock.sent[0].split(b"\r\n\r\n", 1)[1]) == {
            "error": {
                "code": "internal_error",
                "message": "Internal Server Error",
                "field": None,
                "details": {},
            }
        }
        assert server.record_calls == [(500, 0, True)]

    def test_internal_error_ignores_secondary_socket_failure(self) -> None:
        server = _PipelineServerStub()
        server.raise_on_dispatch = True
        pipeline = RequestPipeline(server)

        result = pipeline.process(
            _make_raw_request("GET", "/explode", {"Host": "example.test"}),
            _SocketStub(fail_on_send=True),
            ("127.0.0.1", 12345),
            1,
        )

        assert result is False
        assert server.record_calls == [(500, 0, True)]
