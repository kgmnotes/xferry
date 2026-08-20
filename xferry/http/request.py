"""
HTTP Request parser.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, parse_qsl, unquote, urlparse

from ..advanced_sessions import AdvancedSessionDispatch

logger = logging.getLogger("xferry")

_HTTP_METHOD_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HTTP_VERSION_RE = re.compile(r"^HTTP/\d+\.\d+$")
_REQUEST_TARGET_INVALID_RE = re.compile(r"[\x00-\x20\x7f]")


@dataclass(frozen=True)
class RequestSecurityContext:
    """Security facts bound to one request by the server pipeline."""

    direct_peer: tuple[str, int] | None = None
    verified_principal: str | None = None


class HTTPRequest:
    """HTTP request parser."""

    def __init__(self, raw_data: bytes):
        self.method: str = ""
        self.path: str = ""
        self.raw_target: str = ""
        self.raw_path: str = ""
        self.query_string: str = ""
        self.query_params: dict[str, str] = {}
        self.query_occurrences: tuple[tuple[str, str], ...] = ()
        self.http_version: str = ""
        self.headers: dict[str, str] = {}
        self.header_occurrences: tuple[tuple[str, str], ...] = ()
        self.header_values: dict[str, tuple[str, ...]] = {}
        self.raw_header_values: dict[str, tuple[str, ...]] = {}
        self.body: bytes = b""
        self.parse_error: str | None = None
        self.advanced_session_dispatch: AdvancedSessionDispatch | None = None
        self.advanced_session_admission_prepared = False
        self.security_context = RequestSecurityContext()
        self._parse(raw_data)

    @property
    def is_valid(self) -> bool:
        """Return True when the request line parsed into a usable HTTP request."""
        return self.parse_error is None

    def _parse(self, raw_data: bytes) -> None:
        """Parse raw HTTP data."""
        try:
            # Split headers and body
            if b"\r\n\r\n" in raw_data:
                header_part, self.body = raw_data.split(b"\r\n\r\n", 1)
            else:
                header_part = raw_data
                self.body = b""

            lines = header_part.decode("utf-8").split("\r\n")

            # Parse request line
            if lines:
                self._parse_request_line(lines[0])
            else:
                self.parse_error = "Malformed request line"

            # Parse headers
            header_occurrences: list[tuple[str, str]] = []
            header_values: dict[str, list[str]] = {}
            raw_header_values: dict[str, list[str]] = {}
            current_header_name: str | None = None
            current_header_index: int | None = None
            for line in lines[1:]:
                if line.startswith((" ", "\t")) and current_header_name is not None:
                    continuation = line.strip()
                    values = header_values[current_header_name]
                    normalized_value = values[-1]
                    if continuation:
                        normalized_value = f"{normalized_value} {continuation}".strip()
                    values[-1] = normalized_value
                    raw_header_values[current_header_name][-1] += f"\r\n{line}"
                    self.headers[current_header_name] = normalized_value
                    if current_header_index is not None:
                        original_name = header_occurrences[current_header_index][0]
                        header_occurrences[current_header_index] = (
                            original_name,
                            normalized_value,
                        )
                elif ":" in line:
                    key, value = line.split(":", 1)
                    current_header_name = key.lower()
                    normalized_value = value.strip()
                    header_occurrences.append((key, normalized_value))
                    current_header_index = len(header_occurrences) - 1
                    header_values.setdefault(current_header_name, []).append(normalized_value)
                    raw_header_values.setdefault(current_header_name, []).append(value)
                    self.headers[current_header_name] = normalized_value
            self.header_occurrences = tuple(header_occurrences)
            self.header_values = {key: tuple(values) for key, values in header_values.items()}
            self.raw_header_values = {
                key: tuple(values) for key, values in raw_header_values.items()
            }

        except Exception as e:
            self.parse_error = self.parse_error or "Request parse error"
            logger.error(f"Request parsing error: {e}")

    def _parse_request_line(self, request_line: str) -> None:
        """Parse and validate the HTTP request line."""
        parts = request_line.split(" ")
        if len(parts) != 3:
            self.parse_error = "Malformed request line"
            return

        method, raw_url, http_version = parts
        if not _HTTP_METHOD_RE.fullmatch(method):
            self.parse_error = "Invalid HTTP method"
            return
        if not raw_url or _REQUEST_TARGET_INVALID_RE.search(raw_url):
            self.parse_error = "Invalid request target"
            return
        if not _HTTP_VERSION_RE.fullmatch(http_version):
            self.parse_error = "Invalid HTTP version"
            return

        parsed = urlparse(raw_url)
        self.method = method
        self.raw_target = raw_url
        self.raw_path = parsed.path
        self.path = unquote(parsed.path)
        self.query_string = parsed.query
        # Single-value query params (last value wins)
        self.query_params = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        self.query_occurrences = tuple(parse_qsl(parsed.query, keep_blank_values=True))
        self.http_version = http_version

    def attach_direct_peer(self, direct_peer: tuple[str, int]) -> None:
        """Attach the accepted-socket peer before any authentication checks."""
        self.security_context = RequestSecurityContext(direct_peer=direct_peer)

    def set_verified_principal(self, principal: str) -> None:
        """Record the exact principal returned by the one successful auth check."""
        self.security_context = RequestSecurityContext(
            direct_peer=self.security_context.direct_peer,
            verified_principal=principal,
        )

    @property
    def content_length(self) -> int:
        """Get Content-Length from headers."""
        try:
            return int(self.headers.get("content-length", 0))
        except ValueError:
            return 0

    @property
    def content_type(self) -> str:
        """Get Content-Type from headers."""
        return self.headers.get("content-type", "application/octet-stream")

    def get_header(self, name: str, default: str = "") -> str:
        """Get header by name (case-insensitive)."""
        return self.headers.get(name.lower(), default)

    def get_header_values(self, name: str) -> tuple[str, ...]:
        """Return every normalized header field-value for *name* in wire order."""
        return self.header_values.get(name.lower(), ())

    def get_raw_header_values(self, name: str) -> tuple[str, ...]:
        """Return every untrimmed header field-value for *name* in wire order."""
        return self.raw_header_values.get(name.lower(), ())

    def __repr__(self) -> str:
        return f"HTTPRequest(method={self.method!r}, path={self.path!r})"
