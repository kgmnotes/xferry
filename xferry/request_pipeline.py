"""Request orchestration for authenticated HTTP and WebSocket upgrade handling."""

from __future__ import annotations

import logging
import re
import secrets
import socket
import time
from collections.abc import Mapping
from typing import Any, Protocol, TypedDict

from .features import websocket_route_enabled
from .http import HTTPRequest, HTTPResponse
from .websocket import check_websocket_upgrade

logger = logging.getLogger("xferry")

_REQUEST_ID_HEADER = "X-Request-Id"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _is_note_transport_request(request: HTTPRequest) -> bool:
    """Return whether request-ID admission applies to this NOTE transport."""
    if request.method == "NOTE":
        return True
    return (
        request.method == "GET"
        and request.raw_target == "/notes/ws"
        and websocket_route_enabled(request.raw_path)
    )


def _resolve_note_request_id(
    request: HTTPRequest,
    generated_request_id: str,
) -> tuple[str, bool]:
    """Select the NOTE correlation ID and report malformed client input."""
    values = request.get_header_values(_REQUEST_ID_HEADER)
    if not values:
        return generated_request_id, False
    if len(values) != 1 or _REQUEST_ID_RE.fullmatch(values[0]) is None:
        return generated_request_id, True
    return values[0], False


def _request_log_path(request: HTTPRequest) -> str:
    """Redact data embedded in an authorized Advanced path carrier."""
    dispatch = request.advanced_session_dispatch
    if dispatch is None:
        return request.path

    prefix = dispatch.prefix
    payload_prefix = "/_payload" if prefix == "/" else f"{prefix}/_payload"
    if request.raw_path == payload_prefix or request.raw_path.startswith(payload_prefix + "/"):
        return f"{payload_prefix}/[redacted]"
    return request.path


class ResponseBuildArgs(TypedDict, total=False):
    """Parameters threaded into :class:`HTTPResponse` header building."""

    cors_origin: str | None
    cors_allow_methods: str | None
    keep_alive: bool
    keep_alive_timeout: int
    keep_alive_max: int


class RequestPipelineServer(Protocol):
    """The subset of server behavior the request pipeline orchestrates."""

    cors_origin: str | None
    KEEP_ALIVE_TIMEOUT: int
    _ecdh_manager: Any

    def _resolve_keep_alive(self, request: HTTPRequest, request_num: int) -> tuple[bool, int]: ...

    def _authenticate_request(
        self,
        request: HTTPRequest,
        client_address: tuple[str, int],
    ) -> HTTPResponse | None: ...

    def _is_websocket_upgrade_attempt(self, request: HTTPRequest) -> bool: ...

    def _build_error_response(
        self,
        status: int,
        message: str,
        *,
        code: str | None = None,
        field: str | None = None,
        details: Mapping[str, object] | None = None,
        no_store: bool = False,
    ) -> HTTPResponse: ...

    def _resolve_cors_origin(self, request: HTTPRequest) -> str | None: ...

    def _is_websocket_origin_allowed(self, request: HTTPRequest) -> bool: ...

    def _upgrade_websocket(self, sock: socket.socket, request: HTTPRequest) -> bool: ...

    def _check_payload_size(self, request: HTTPRequest) -> HTTPResponse | None: ...

    def _is_browser_mutation_allowed(self, request: HTTPRequest) -> bool: ...

    def _is_advanced_session_control_route(self, request: HTTPRequest) -> bool: ...

    def _authorize_advanced_session_control(
        self,
        request: HTTPRequest,
        client_address: tuple[str, int],
    ) -> HTTPResponse | None: ...

    def _prepare_advanced_session_dispatch(self, request: HTTPRequest) -> HTTPResponse | None: ...

    def _dispatch_handler(self, request: HTTPRequest) -> HTTPResponse: ...

    def _post_process_response(
        self,
        request: HTTPRequest,
        response: HTTPResponse,
        request_id: str,
    ) -> None: ...

    def _send_response(
        self,
        response: HTTPResponse,
        client_socket: socket.socket,
        _bld: ResponseBuildArgs,
    ) -> int: ...

    def _record_metric(
        self,
        status_code: int,
        response_size: int,
        *,
        error: bool = False,
    ) -> None: ...

    def _record_request_latency(self, duration_ms: float) -> None: ...


class RequestPipeline:
    """Coordinate request parsing, auth, dispatch, and response emission."""

    def __init__(self, server: RequestPipelineServer) -> None:
        self._server = server

    def process(
        self,
        data: bytes,
        client_socket: socket.socket,
        client_address: tuple[str, int],
        request_num: int,
    ) -> bool:
        """Process one request and return ``True`` when the connection should stay open."""
        start_time = time.monotonic()
        request_id = secrets.token_hex(4)
        direct_response_request_id: str | None = None
        build_args: ResponseBuildArgs = {"cors_origin": None}

        try:
            request = HTTPRequest(data)
            request.attach_direct_peer(client_address)
            if not request.is_valid:
                logger.warning(
                    "[%s] Malformed request from %s: %s",
                    request_id,
                    client_address[0],
                    request.parse_error,
                )
                response = self._server._build_error_response(
                    400,
                    "Bad Request",
                    code="malformed_request",
                )
                self._send_direct_response(response, client_socket, build_args)
                return False
            is_session_control_route = False
            session_control_route = getattr(
                self._server,
                "_is_advanced_session_control_route",
                None,
            )
            if callable(session_control_route):
                is_session_control_route = bool(session_control_route(request))

            is_note_transport = not is_session_control_route and _is_note_transport_request(request)
            invalid_request_id = False
            if is_note_transport:
                request_id, invalid_request_id = _resolve_note_request_id(request, request_id)
                direct_response_request_id = request_id

            use_keep_alive, remaining = self._server._resolve_keep_alive(request, request_num)
            build_args["keep_alive"] = use_keep_alive
            if use_keep_alive:
                build_args["keep_alive_timeout"] = self._server.KEEP_ALIVE_TIMEOUT
                build_args["keep_alive_max"] = remaining

            auth_error = self._server._authenticate_request(request, client_address)
            if auth_error is not None:
                if is_session_control_route:
                    auth_error.set_header("Cache-Control", "no-store")
                self._send_direct_response(
                    auth_error,
                    client_socket,
                    build_args,
                    request_id=direct_response_request_id,
                )
                return False

            if is_session_control_route:
                session_control_authorize = getattr(
                    self._server,
                    "_authorize_advanced_session_control",
                    None,
                )
                if callable(session_control_authorize):
                    control_error = session_control_authorize(request, client_address)
                    if control_error is not None:
                        self._send_direct_response(control_error, client_socket, build_args)
                        return False

                response = self._server._dispatch_handler(request)
                self._send_direct_response(response, client_socket, build_args)
                return False

            session_admission = getattr(self._server, "_prepare_advanced_session_dispatch", None)
            if callable(session_admission):
                admission_error = session_admission(request)
                if admission_error is not None:
                    self._send_direct_response(
                        admission_error,
                        client_socket,
                        build_args,
                        request_id=direct_response_request_id,
                    )
                    return False

            if invalid_request_id:
                response = self._server._build_error_response(
                    400,
                    "Invalid field",
                    code="invalid_field",
                    field=_REQUEST_ID_HEADER,
                )
                self._send_direct_response(
                    response,
                    client_socket,
                    build_args,
                    request_id=request_id,
                )
                return False

            if self._server._is_websocket_upgrade_attempt(request):
                return self._process_websocket_upgrade(
                    request,
                    client_socket,
                    build_args,
                    request_id,
                )

            if not self._server._is_browser_mutation_allowed(request):
                response = self._server._build_error_response(
                    403,
                    "Forbidden cross-origin browser mutation",
                    code="forbidden",
                )
                self._send_direct_response(
                    response,
                    client_socket,
                    build_args,
                    request_id=direct_response_request_id,
                )
                return False

            build_args["cors_origin"] = self._server._resolve_cors_origin(request)
            cors_methods = getattr(self._server, "_cors_allow_methods_header", None)
            if callable(cors_methods):
                build_args["cors_allow_methods"] = cors_methods()

            size_error = self._server._check_payload_size(request)
            if size_error is not None:
                self._send_direct_response(
                    size_error,
                    client_socket,
                    build_args,
                    request_id=direct_response_request_id,
                )
                return False

            response = self._server._dispatch_handler(request)
            self._server._post_process_response(request, response, request_id)

            bytes_sent = self._server._send_response(response, client_socket, build_args)
            self._server._record_metric(
                response.status_code,
                bytes_sent,
                error=response.status_code >= 500,
            )

            if response.stream_path is not None:
                use_keep_alive = False

            duration_ms = (time.monotonic() - start_time) * 1000
            logger.info(
                "[%s] %s - %s %s -> %d (%dms)",
                request_id,
                client_address[0],
                request.method,
                _request_log_path(request),
                response.status_code,
                duration_ms,
            )

            return use_keep_alive

        except Exception:
            logger.exception(
                "[%s] Request handling error from %s",
                request_id,
                client_address[0],
            )
            self._server._record_metric(500, 0, error=True)
            error_response = self._server._build_error_response(
                500,
                "Internal Server Error",
                code="internal_error",
            )
            if direct_response_request_id is not None:
                error_response.set_header(_REQUEST_ID_HEADER, direct_response_request_id)
            try:
                client_socket.sendall(error_response.build(**build_args))
            except Exception:
                pass
            return False
        finally:
            self._server._record_request_latency((time.monotonic() - start_time) * 1000)

    def _send_direct_response(
        self,
        response: HTTPResponse,
        client_socket: socket.socket,
        build_args: ResponseBuildArgs,
        *,
        request_id: str | None = None,
    ) -> None:
        """Send a direct response outside the normal response pipeline and record metrics."""
        if request_id is not None:
            response.set_header(_REQUEST_ID_HEADER, request_id)
        payload = response.build(**build_args)
        client_socket.sendall(payload)
        self._server._record_metric(
            response.status_code,
            len(payload),
            error=response.status_code >= 500,
        )

    def _process_websocket_upgrade(
        self,
        request: HTTPRequest,
        client_socket: socket.socket,
        build_args: ResponseBuildArgs,
        request_id: str,
    ) -> bool:
        """Validate and dispatch the Secure Notepad WebSocket upgrade path."""
        if not check_websocket_upgrade(request):
            response = self._server._build_error_response(
                400,
                "Invalid WebSocket upgrade request",
                code="bad_request",
            )
            self._send_direct_response(
                response,
                client_socket,
                build_args,
                request_id=request_id,
            )
            return False

        if not self._server._is_websocket_origin_allowed(request):
            response = self._server._build_error_response(
                403,
                "Forbidden WebSocket origin",
                code="forbidden",
            )
            self._send_direct_response(
                response,
                client_socket,
                build_args,
                request_id=request_id,
            )
            return False

        if self._server._ecdh_manager is None:
            response = self._server._build_error_response(
                501,
                "Secure Notepad requires the default cryptography runtime dependency; "
                "repair or reinstall xferry",
                code="feature_unavailable",
            )
            self._send_direct_response(
                response,
                client_socket,
                build_args,
                request_id=request_id,
            )
            return False

        if not self._server._upgrade_websocket(client_socket, request):
            response = self._server._build_error_response(
                503,
                "WebSocket connection limit reached",
                code="server_busy",
            )
            self._send_direct_response(
                response,
                client_socket,
                build_args,
                request_id=request_id,
            )
            return False
        return False


__all__ = ["RequestPipeline", "RequestPipelineServer", "ResponseBuildArgs"]
