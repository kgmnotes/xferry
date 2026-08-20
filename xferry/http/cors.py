"""CORS policy helpers."""

from __future__ import annotations

import re

from ..features import allows_unknown_cors_method, cors_methods

CORS_ALLOW_METHODS: tuple[str, ...] = cors_methods()

CORS_BASIC_ALLOW_HEADERS: tuple[str, ...] = (
    "Authorization",
    "Content-Type",
    "If-None-Match",
    "X-File-Name",
    "X-Request-Id",
    "X-XFerry-No-Gzip",
    "X-Exphttp-No-Gzip",
)

CORS_ADVANCED_ALLOW_HEADERS: tuple[str, ...] = (
    "X-XFerry-Advanced-Session",
    "X-XFerry-Data",
    *(f"X-XFerry-Data-{index}" for index in range(256)),
    "X-XFerry-Encryption",
    "X-XFerry-Key",
    "X-XFerry-Key-Is-Base64",
    "X-XFerry-Name",
    "X-XFerry-HMAC",
    "X-XFerry-Encoding",
    "X-XFerry-Method-Override",
)

CORS_ALLOW_HEADERS: tuple[str, ...] = (
    *CORS_BASIC_ALLOW_HEADERS,
    *CORS_ADVANCED_ALLOW_HEADERS,
)

CORS_EXPOSE_HEADERS: tuple[str, ...] = (
    "Content-Disposition",
    "ETag",
    "X-Request-Id",
)

CORS_ALLOW_METHODS_HEADER = ", ".join(CORS_ALLOW_METHODS)
CORS_ALLOW_HEADERS_HEADER = ", ".join(CORS_ALLOW_HEADERS)
CORS_WILDCARD_ALLOW_HEADERS_HEADER = ", ".join(CORS_BASIC_ALLOW_HEADERS)
CORS_EXPOSE_HEADERS_HEADER = ", ".join(CORS_EXPOSE_HEADERS)

_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_BASIC_HEADER_NAME_MAP = {header.lower(): header for header in CORS_BASIC_ALLOW_HEADERS}
_ADVANCED_HEADER_NAME_MAP = {header.lower(): header for header in CORS_ADVANCED_ALLOW_HEADERS}


def parse_cors_origins(configured_origin: str | None) -> tuple[str, ...]:
    """Parse a comma-separated CORS origin config into an allowlist."""
    if not configured_origin:
        return ()

    origins: list[str] = []
    seen: set[str] = set()
    for raw_origin in configured_origin.split(","):
        origin = raw_origin.strip()
        if not origin or origin in seen:
            continue
        origins.append(origin)
        seen.add(origin)

    if "*" in seen and len(origins) > 1:
        raise ValueError("CORS wildcard origin '*' cannot be combined with explicit origins")
    if "*" in seen:
        return ("*",)
    return tuple(origins)


def resolve_cors_origin(
    configured_origin: str | None,
    request_origin: str | None,
) -> str | None:
    """Return the browser-valid ACAO value for a request, or None."""
    origins = parse_cors_origins(configured_origin)
    if not origins:
        return None
    if origins == ("*",):
        return "*"
    if request_origin and request_origin in origins:
        return request_origin
    return None


def normalize_cors_header_origin(cors_origin: str | None) -> str | None:
    """Accept only a single valid ACAO value for response emission."""
    origins = parse_cors_origins(cors_origin)
    if len(origins) != 1:
        return None
    return origins[0]


def is_http_token(value: str) -> bool:
    """Return True when value is an RFC HTTP token."""
    return bool(_HTTP_TOKEN_RE.fullmatch(value))


def resolve_preflight_allow_methods(
    requested_method: str,
    *,
    read_only: bool = False,
) -> str:
    """Return allowed methods, including a requested advanced upload token."""
    methods = list(cors_methods(read_only=read_only))
    method = requested_method.strip().upper()
    if (
        allows_unknown_cors_method(method, read_only=read_only)
        and method
        and method not in methods
        and is_http_token(method)
    ):
        methods.append(method)
    return ", ".join(methods)


def resolve_preflight_allow_headers(
    requested_headers: str,
    *,
    allow_advanced: bool = True,
) -> str | None:
    """Return the allowed subset of requested CORS headers."""
    header_name_map = dict(_BASIC_HEADER_NAME_MAP)
    if allow_advanced:
        header_name_map.update(_ADVANCED_HEADER_NAME_MAP)

    allowed: list[str] = []
    seen: set[str] = set()
    for raw_header in requested_headers.split(","):
        header = raw_header.strip()
        if not header or not is_http_token(header):
            continue
        header_lower = header.lower()
        canonical = header_name_map.get(header_lower)
        if canonical is None or canonical.lower() in seen:
            continue
        allowed.append(canonical)
        seen.add(canonical.lower())

    if not allowed:
        return None
    return ", ".join(allowed)
