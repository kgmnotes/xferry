"""
HTTP Response builder.
"""

import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from ..config import HTTP_STATUS_MESSAGES, __version__
from .cors import (
    CORS_ALLOW_HEADERS_HEADER,
    CORS_ALLOW_METHODS_HEADER,
    CORS_EXPOSE_HEADERS_HEADER,
    CORS_WILDCARD_ALLOW_HEADERS_HEADER,
    normalize_cors_header_origin,
)

_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")


class HTTPResponse:
    """HTTP response builder."""

    def __init__(self, status_code: int = 200):
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self.body: bytes = b""
        self.stream_path: Path | None = None
        self.stream_cleanup: Callable[[], None] | None = None
        self._additional_cors_expose_headers: list[str] = []

    def set_header(self, key: str, value: str) -> None:
        """Set a response header."""
        self.headers[key] = value

    def add_cors_expose_headers(self, *names: str) -> None:
        """Expose response headers only when CORS headers are emitted."""
        known = {name.lower() for name in self._additional_cors_expose_headers}
        for name in names:
            if name.lower() not in known:
                self._additional_cors_expose_headers.append(name)
                known.add(name.lower())

    def set_body(self, body: bytes | str, content_type: str = "text/plain") -> None:
        """Set the response body."""
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.body = body
        self.stream_path = None
        self.stream_cleanup = None
        self.set_header("Content-Type", content_type)
        self.set_header("Content-Length", str(len(self.body)))

    def set_file(
        self,
        file_path: Path,
        content_type: str,
        *,
        stream_cleanup: Callable[[], None] | None = None,
    ) -> None:
        """Set a file for streaming response (no memory copy)."""
        self.stream_path = file_path
        self.stream_cleanup = stream_cleanup
        self.body = b""
        size = file_path.stat().st_size
        self.set_header("Content-Type", content_type)
        self.set_header("Content-Length", str(size))

    def build_headers(
        self,
        cors_origin: str | None = None,
        cors_allow_methods: str | None = None,
        keep_alive: bool = False,
        keep_alive_timeout: int = 15,
        keep_alive_max: int = 100,
    ) -> bytes:
        """Build only the HTTP header portion (for streaming)."""
        self._finalize_headers(
            cors_origin,
            cors_allow_methods,
            keep_alive,
            keep_alive_timeout,
            keep_alive_max,
        )

        status_message = HTTP_STATUS_MESSAGES.get(self.status_code, "Unknown")
        response = f"HTTP/1.1 {self.status_code} {status_message}\r\n"

        for key, value in self.headers.items():
            response += f"{key}: {value}\r\n"

        response += "\r\n"
        return response.encode("utf-8")

    def build(
        self,
        cors_origin: str | None = None,
        cors_allow_methods: str | None = None,
        keep_alive: bool = False,
        keep_alive_timeout: int = 15,
        keep_alive_max: int = 100,
    ) -> bytes:
        """Build the full HTTP response as bytes."""
        return (
            self.build_headers(
                cors_origin,
                cors_allow_methods,
                keep_alive,
                keep_alive_timeout,
                keep_alive_max,
            )
            + self.body
        )

    def _finalize_headers(
        self,
        cors_origin: str | None = None,
        cors_allow_methods: str | None = None,
        keep_alive: bool = False,
        keep_alive_timeout: int = 15,
        keep_alive_max: int = 100,
    ) -> None:
        """Add standard headers (Server, Date, Connection, CORS)."""
        self.set_header("Server", f"XFerry/{__version__}")
        if "X-Content-Type-Options" not in self.headers:
            self.set_header("X-Content-Type-Options", "nosniff")

        self.set_header("Date", datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"))

        if keep_alive:
            self.set_header("Connection", "keep-alive")
            self.set_header("Keep-Alive", f"timeout={keep_alive_timeout}, max={keep_alive_max}")
        else:
            self.set_header("Connection", "close")

        self._set_cors_headers(cors_origin, cors_allow_methods)

    def _set_cors_headers(
        self,
        cors_origin: str | None = None,
        cors_allow_methods: str | None = None,
    ) -> None:
        """Set CORS headers."""
        cors_origin = normalize_cors_header_origin(cors_origin)
        if not cors_origin:
            return

        if "Access-Control-Allow-Origin" not in self.headers:
            self.set_header("Access-Control-Allow-Origin", cors_origin)
        if cors_origin != "*":
            self._add_vary_header("Origin")

        if "Access-Control-Allow-Methods" not in self.headers:
            self.set_header(
                "Access-Control-Allow-Methods",
                cors_allow_methods or CORS_ALLOW_METHODS_HEADER,
            )

        if "Access-Control-Allow-Headers" not in self.headers:
            allow_headers = (
                CORS_WILDCARD_ALLOW_HEADERS_HEADER
                if cors_origin == "*"
                else CORS_ALLOW_HEADERS_HEADER
            )
            self.set_header("Access-Control-Allow-Headers", allow_headers)

        if "Access-Control-Expose-Headers" not in self.headers:
            exposed = CORS_EXPOSE_HEADERS_HEADER
            if self._additional_cors_expose_headers:
                exposed = ", ".join(
                    (CORS_EXPOSE_HEADERS_HEADER, *self._additional_cors_expose_headers)
                )
            self.set_header("Access-Control-Expose-Headers", exposed)

    def _add_vary_header(self, value: str) -> None:
        """Append a Vary token if it is not already present."""
        current = self.headers.get("Vary")
        if not current:
            self.set_header("Vary", value)
            return

        tokens = [token.strip() for token in current.split(",") if token.strip()]
        if value.lower() not in {token.lower() for token in tokens}:
            tokens.append(value)
        self.set_header("Vary", ", ".join(tokens))

    def __repr__(self) -> str:
        return f"HTTPResponse(status={self.status_code})"


def json_response(
    payload: Mapping[str, object],
    status: int = 200,
    *,
    no_store: bool = False,
) -> HTTPResponse:
    """Build a UTF-8 JSON response from a mapping payload."""
    response = HTTPResponse(status)
    response.set_body(
        json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")),
        "application/json",
    )
    if no_store:
        response.set_header("Cache-Control", "no-store")
    return response


def error_response(
    status: int,
    code: str,
    message: str,
    *,
    field: str | None = None,
    details: Mapping[str, object] | None = None,
    no_store: bool = False,
) -> HTTPResponse:
    """Build the canonical XFerry JSON error envelope."""
    if not isinstance(code, str):
        raise TypeError("code must be a string")
    if _ERROR_CODE_RE.fullmatch(code) is None:
        raise ValueError("code must be a lowercase snake_case token")
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    if not message:
        raise ValueError("message must not be empty")
    if field is not None and not isinstance(field, str):
        raise TypeError("field must be a string or None")
    if details is not None and not isinstance(details, Mapping):
        raise TypeError("details must be a mapping or None")

    error_details = dict(details) if details is not None else {}
    return json_response(
        {
            "error": {
                "code": code,
                "message": message,
                "field": field,
                "details": error_details,
            }
        },
        status,
        no_store=no_store,
    )
