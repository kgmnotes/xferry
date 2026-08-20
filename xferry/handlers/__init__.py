"""
HTTP method handlers module.
"""

import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, cast

from ..advanced_sessions import (
    ADVANCED_SESSION_DECODERS,
    ADVANCED_UPLOAD_METHODS,
    AdvancedSession,
    AdvancedSessionCapacityExhausted,
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
    AdvancedSessionStore,
    advanced_session_prefix_matches,
    validate_advanced_session_prefix,
)
from ..features import core_method_specs
from ..http import HTTPRequest, HTTPResponse, error_response, json_response
from .advanced_upload import AdvancedUploadHandlersMixin
from .base import BaseHandler
from .files import FileHandlersMixin
from .info import InfoHandlersMixin
from .notepad import NotepadHandlersMixin
from .registry import HandlerRegistry
from .smuggle import SmuggleHandlersMixin

ADVANCED_SESSION_COLLECTION_PATH = "/_xferry/advanced-sessions"
ADVANCED_SESSION_CURRENT_PATH = "/_xferry/advanced-sessions/current"
ADVANCED_SESSION_CONTROL_TARGETS = frozenset(
    {ADVANCED_SESSION_COLLECTION_PATH, ADVANCED_SESSION_CURRENT_PATH}
)
ADVANCED_SESSION_HEADER = "X-XFerry-Advanced-Session"
_ADVANCED_SESSION_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_ADVANCED_SESSION_CREATE_FIELDS = ("prefix", "decoder", "diagnostic_headers")
_ADVANCED_SESSION_IDLE_TIMEOUT_SECONDS = 900


class _DuplicateJSONMember(ValueError):
    """Internal signal for duplicate JSON object member rejection."""

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def _reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateJSONMember(key)
        seen.add(key)
        result[key] = value
    return result


def _is_advanced_session_control_target(request: HTTPRequest) -> bool:
    return request.raw_target in ADVANCED_SESSION_CONTROL_TARGETS


class HandlerMixin(
    FileHandlersMixin,
    InfoHandlersMixin,
    NotepadHandlersMixin,
    AdvancedUploadHandlersMixin,
    SmuggleHandlersMixin,
):
    """
    Combined mixin with all HTTP method handlers.

    Includes:
    - FileHandlersMixin: GET, POST, OPTIONS, FETCH, NONE
    - InfoHandlersMixin: INFO, PING
    - NotepadHandlersMixin: NOTE
    - AdvancedUploadHandlersMixin: handle_advanced_upload
    - SmuggleHandlersMixin: SMUGGLE
    """

    def build_method_handlers(self) -> HandlerRegistry:
        """Build the canonical HTTP method registry for this handler set."""
        method_handlers = HandlerRegistry()
        method_handlers.register_many(
            {spec.method: getattr(self, spec.handler_name) for spec in core_method_specs()}
        )
        return method_handlers

    def _dispatch_handler(self, request: HTTPRequest) -> HTTPResponse:
        """Look up and invoke the handler for ``request.method``."""
        if not request.is_valid:
            return self._bad_request("Bad Request")

        if _is_advanced_session_control_target(request):
            return self._handle_advanced_session_control(request)

        if (
            self._request_has_advanced_session_header(request)
            and not request.advanced_session_admission_prepared
        ):
            admission_error = self._prepare_advanced_session_dispatch(request)
            if admission_error is not None:
                return admission_error

        if request.advanced_session_dispatch is not None:
            return self.handle_advanced_upload(request)

        handler = self.method_handlers.get(request.method)
        if handler:
            return handler(request)

        return self._method_not_allowed(request.method)

    def _prepare_advanced_session_dispatch(self, request: HTTPRequest) -> HTTPResponse | None:
        """Authorize and cache one request-local Advanced data-plane dispatch."""
        if _is_advanced_session_control_target(request):
            request.advanced_session_admission_prepared = True
            return None

        if not self._request_has_advanced_session_header(request):
            request.advanced_session_dispatch = None
            request.advanced_session_admission_prepared = True
            return None

        data_authorizer = getattr(self, "_authorize_advanced_session_data_request", None)
        if callable(data_authorizer):
            authorization_error = cast(
                Callable[[HTTPRequest], HTTPResponse | None],
                data_authorizer,
            )(request)
            if authorization_error is not None:
                request.advanced_session_admission_prepared = True
                return authorization_error

        token, header_error = self._advanced_session_header_token(request, required=True)
        if header_error is not None:
            request.advanced_session_admission_prepared = True
            return header_error
        assert token is not None

        principal = self._advanced_session_control_principal(request)
        store = self._advanced_session_store()
        session = store.resolve(token, principal, touch=False)
        if session is None:
            request.advanced_session_admission_prepared = True
            return self._advanced_session_not_found()

        if not advanced_session_prefix_matches(
            session.prefix,
            request.raw_path,
            request.path,
        ):
            request.advanced_session_admission_prepared = True
            return self._advanced_session_route_mismatch(session.prefix)

        method = request.method.upper()
        plugin_policies = getattr(self, "_plugin_method_policies", {})
        if method in plugin_policies or (
            method in self.method_handlers and method not in ADVANCED_UPLOAD_METHODS
        ):
            request.advanced_session_admission_prepared = True
            return self._advanced_session_method_conflict(method)

        touch_handle = store.touch_handle_for_resolved_session(token, session)
        request.advanced_session_dispatch = AdvancedSessionDispatch(
            session=session,
            principal=principal,
            direct_peer=request.security_context.direct_peer,
            touch_handle=touch_handle,
        )
        request.advanced_session_admission_prepared = True
        return None

    @staticmethod
    def _request_has_advanced_session_header(request: HTTPRequest) -> bool:
        return bool(
            request.get_header_values(ADVANCED_SESSION_HEADER)
            or request.get_raw_header_values(ADVANCED_SESSION_HEADER)
        )

    def _handle_advanced_session_control(self, request: HTTPRequest) -> HTTPResponse:
        """Serve exact 7C advanced-session control endpoints after pipeline authz."""
        if request.raw_target == ADVANCED_SESSION_COLLECTION_PATH:
            _token, header_error = self._advanced_session_header_token(request, required=False)
            if header_error is not None:
                return header_error
            if request.method != "POST":
                return self._advanced_session_method_not_allowed(request.method, "POST")
            return self._create_advanced_session(request)

        assert request.raw_target == ADVANCED_SESSION_CURRENT_PATH
        token, header_error = self._advanced_session_header_token(
            request,
            required=request.method in {"GET", "DELETE"},
        )
        if header_error is not None:
            return header_error

        if request.method == "GET":
            assert token is not None
            session = self._resolve_advanced_session(request, token, touch=True)
            if session is None:
                return self._advanced_session_not_found()
            return self._advanced_session_metadata_response(session)

        if request.method == "DELETE":
            assert token is not None
            if not self._advanced_session_store().revoke(
                token,
                self._advanced_session_control_principal(request),
            ):
                return self._advanced_session_not_found()
            return json_response(
                {"advanced_session": {"revoked": True}},
                status=200,
                no_store=True,
            )

        if (
            token is not None
            and self._resolve_advanced_session(request, token, touch=False) is None
        ):
            return self._advanced_session_not_found()
        return self._advanced_session_method_not_allowed(request.method, "GET, DELETE")

    def _create_advanced_session(self, request: HTTPRequest) -> HTTPResponse:
        content_type_values = request.get_header_values("Content-Type")
        if len(content_type_values) > 1:
            return self._advanced_session_invalid_field("Content-Type")
        if not content_type_values or content_type_values[0] != "application/json":
            return self._advanced_session_error(
                415,
                "unsupported_media_type",
                "Unsupported media type",
                field="Content-Type",
                details={"supported": ["application/json"]},
            )

        payload, error = self._load_advanced_session_create_payload(request.body)
        if error is not None:
            return error
        assert payload is not None

        conflict_methods = sorted(
            set(getattr(self, "_plugin_method_policies", {})) & ADVANCED_UPLOAD_METHODS
        )
        if conflict_methods:
            return self._advanced_session_error(
                409,
                "advanced_method_conflict",
                "Advanced method conflict",
                field=None,
                details={"methods": conflict_methods},
            )

        try:
            created = self._advanced_session_store().create(
                prefix=payload["prefix"],
                decoder=payload["decoder"],
                diagnostic_headers=payload["diagnostic_headers"],
                principal=self._advanced_session_control_principal(request),
            )
        except AdvancedSessionCapacityExhausted:
            return self._advanced_session_error(
                503,
                "advanced_session_capacity_exhausted",
                "Advanced session capacity exhausted",
                field=None,
                details={"limit": 64},
            )

        return self._advanced_session_metadata_response(
            created.session,
            status=201,
            token=created.token,
        )

    def _load_advanced_session_create_payload(
        self,
        body: bytes,
    ) -> tuple[dict[str, Any] | None, HTTPResponse | None]:
        try:
            decoded = body.decode("utf-8")
            payload = json.loads(decoded, object_pairs_hook=_reject_duplicate_json_members)
        except _DuplicateJSONMember as exc:
            return None, self._advanced_session_error(
                400,
                "invalid_field",
                "Invalid field",
                field=exc.field,
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, self._advanced_session_error(
                400,
                "malformed_json",
                "Malformed JSON",
                field=None,
            )

        if not isinstance(payload, dict):
            return None, self._advanced_session_error(
                400,
                "invalid_json_type",
                "Invalid JSON type",
                field=None,
                details={"expected": "object"},
            )

        for field in _ADVANCED_SESSION_CREATE_FIELDS:
            if field not in payload:
                return None, self._advanced_session_error(
                    400,
                    "missing_field",
                    "Missing field",
                    field=field,
                )

        for field in payload:
            if field not in _ADVANCED_SESSION_CREATE_FIELDS:
                return None, self._advanced_session_error(
                    400,
                    "invalid_field",
                    "Invalid field",
                    field=field,
                )

        prefix = payload["prefix"]
        if not isinstance(prefix, str):
            return None, self._advanced_session_invalid_field("prefix")
        try:
            validate_advanced_session_prefix(prefix)
        except ValueError:
            return None, self._advanced_session_invalid_field("prefix")

        decoder = payload["decoder"]
        if not isinstance(decoder, str) or decoder not in ADVANCED_SESSION_DECODERS:
            return None, self._advanced_session_invalid_field("decoder")

        diagnostic_headers = payload["diagnostic_headers"]
        if not isinstance(diagnostic_headers, bool):
            return None, self._advanced_session_invalid_field("diagnostic_headers")

        return {
            "prefix": prefix,
            "decoder": decoder,
            "diagnostic_headers": diagnostic_headers,
        }, None

    def _advanced_session_invalid_field(self, field: str) -> HTTPResponse:
        return self._advanced_session_error(
            400,
            "invalid_field",
            "Invalid field",
            field=field,
        )

    def _advanced_session_header_token(
        self,
        request: HTTPRequest,
        *,
        required: bool,
    ) -> tuple[str | None, HTTPResponse | None]:
        values = request.get_header_values(ADVANCED_SESSION_HEADER)
        raw_values = request.get_raw_header_values(ADVANCED_SESSION_HEADER)
        if not values:
            if required:
                return None, self._advanced_session_error(
                    400,
                    "missing_field",
                    "Missing field",
                    field=ADVANCED_SESSION_HEADER,
                )
            return None, None
        if (
            len(values) != 1
            or len(raw_values) != 1
            or not self._is_exact_session_header_value(raw_values[0], values[0])
            or _ADVANCED_SESSION_TOKEN_RE.fullmatch(values[0]) is None
        ):
            return None, self._advanced_session_error(
                400,
                "invalid_field",
                "Invalid field",
                field=ADVANCED_SESSION_HEADER,
            )
        return values[0], None

    def _resolve_advanced_session(
        self,
        request: HTTPRequest,
        token: str,
        *,
        touch: bool,
    ) -> AdvancedSession | None:
        return self._advanced_session_store().resolve(
            token,
            self._advanced_session_control_principal(request),
            touch=touch,
        )

    def _advanced_session_control_principal(
        self,
        request: HTTPRequest,
    ) -> AdvancedSessionPrincipal:
        principal_factory = getattr(self, "_advanced_session_principal", None)
        if callable(principal_factory):
            principal = principal_factory(request)
            if isinstance(principal, AdvancedSessionPrincipal):
                return principal
            raise RuntimeError("advanced session principal factory returned invalid principal")
        return AdvancedSessionPrincipal("no_auth", None)

    def _advanced_session_store(self) -> AdvancedSessionStore:
        store = getattr(self, "advanced_session_store", None)
        if not isinstance(store, AdvancedSessionStore):
            raise RuntimeError("advanced session store is unavailable")
        return store

    @staticmethod
    def _advanced_session_metadata_response(
        session: AdvancedSession,
        *,
        status: int = 200,
        token: str | None = None,
    ) -> HTTPResponse:
        metadata: dict[str, object] = {}
        if token is not None:
            metadata["token"] = token
        metadata.update(
            {
                "prefix": session.prefix,
                "decoder": session.decoder,
                "diagnostic_headers": session.diagnostic_headers,
                "created_at": HandlerMixin._format_control_time(session.created_at),
                "expires_at": HandlerMixin._format_control_time(session.expires_at),
                "idle_timeout_seconds": _ADVANCED_SESSION_IDLE_TIMEOUT_SECONDS,
            }
        )
        return json_response({"advanced_session": metadata}, status=status, no_store=True)

    @staticmethod
    def _format_control_time(value: datetime) -> str:
        return (
            value.astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace(
                "+00:00",
                "Z",
            )
        )

    @staticmethod
    def _is_exact_session_header_value(raw_value: str, normalized_value: str) -> bool:
        if "\r" in raw_value or "\n" in raw_value:
            return False
        if raw_value.startswith(" "):
            raw_value = raw_value[1:]
        return raw_value == normalized_value

    @staticmethod
    def _advanced_session_error(
        status: int,
        code: str,
        message: str,
        *,
        field: str | None,
        details: dict[str, object] | None = None,
    ) -> HTTPResponse:
        return error_response(
            status,
            code,
            message,
            field=field,
            details=details,
            no_store=True,
        )

    @staticmethod
    def _advanced_session_not_found() -> HTTPResponse:
        return HandlerMixin._advanced_session_error(
            404,
            "advanced_session_not_found",
            "Advanced session not found",
            field=ADVANCED_SESSION_HEADER,
        )

    @staticmethod
    def _advanced_session_method_not_allowed(method: str, allow: str) -> HTTPResponse:
        response = HandlerMixin._advanced_session_error(
            405,
            "method_not_allowed",
            "Method not allowed",
            field=None,
            details={"method": method},
        )
        response.set_header("Allow", allow)
        return response

    @staticmethod
    def _advanced_session_route_mismatch(prefix: str) -> HTTPResponse:
        return HandlerMixin._advanced_session_error(
            409,
            "advanced_route_mismatch",
            "Advanced route mismatch",
            field="prefix",
            details={"prefix": prefix},
        )

    @staticmethod
    def _advanced_session_method_conflict(method: str) -> HTTPResponse:
        return HandlerMixin._advanced_session_error(
            409,
            "advanced_method_conflict",
            "Advanced method conflict",
            field=None,
            details={"method": method},
        )

    def _touch_advanced_session_dispatch(self, request: HTTPRequest) -> None:
        """Best-effort post-success idle touch; expiry races silently no-op."""
        dispatch = request.advanced_session_dispatch
        if dispatch is None:
            return
        store = getattr(self, "advanced_session_store", None)
        if not isinstance(store, AdvancedSessionStore):
            return
        store.touch_dispatch(dispatch)


__all__ = [
    "BaseHandler",
    "HandlerMixin",
    "AdvancedUploadHandlersMixin",
    "FileHandlersMixin",
    "InfoHandlersMixin",
    "NotepadHandlersMixin",
    "SmuggleHandlersMixin",
]
