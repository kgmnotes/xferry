"""Immutable trusted request-admission policy and admitted security facts."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

_PROTECTED_FIELDS: tuple[tuple[str, str], ...] = (
    ("Host", "host"),
    ("Authorization", "authorization"),
    ("Origin", "origin"),
    ("Sec-Fetch-Site", "sec-fetch-site"),
    ("Connection", "connection"),
    ("Upgrade", "upgrade"),
    ("Sec-WebSocket-Key", "sec-websocket-key"),
    ("Sec-WebSocket-Version", "sec-websocket-version"),
    ("Access-Control-Request-Method", "access-control-request-method"),
    ("Access-Control-Request-Headers", "access-control-request-headers"),
)
_PROTECTED_FIELD_NAMES = {
    normalized_name: display_name for display_name, normalized_name in _PROTECTED_FIELDS
}
_INVALID_AUTHORITY_CHAR_RE = re.compile(r"[\x00-\x20\x7f,@/\\?#*]")
_ASCII_PORT_RE = re.compile(r"[0-9]+")
_DNS_HOST_RE = re.compile(r"[a-z0-9.-]+")


class _AdmissionRequest(Protocol):
    http_version: str
    header_occurrences: tuple[tuple[str, str], ...]

    def get_header_values(self, name: str) -> tuple[str, ...]: ...

    def get_raw_header_values(self, name: str) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class RequestAuthority:
    """One syntactically valid, canonical request authority."""

    host: str
    port: int | None = None

    def effective_port(self, scheme: str) -> int:
        """Return the explicit port or the standard port for *scheme*."""
        if self.port is not None:
            return self.port
        return 443 if scheme == "https" else 80


@dataclass(frozen=True, slots=True)
class RequestAdmissionContext:
    """Trusted singleton security values produced by one admission decision."""

    authority: RequestAuthority | None
    authorization: str | None = field(default=None, repr=False)
    origin: str | None = field(default=None, repr=False)
    sec_fetch_site: str | None = None
    connection: str | None = None
    upgrade: str | None = None
    websocket_key: str | None = None
    websocket_version: str | None = None
    preflight_method: str | None = None
    preflight_headers: str | None = None


@dataclass(frozen=True, slots=True)
class AdmissionFailure:
    """Transport-independent admission rejection."""

    status: int
    code: str
    message: str
    field: str | None


@dataclass(frozen=True, slots=True)
class RequestAdmissionConfig:
    """Listener facts and operator authority inputs used to build a policy."""

    bind_host: str
    server_port: int
    tls_enabled: bool
    allowed_hosts: tuple[str, ...] | None = None
    certificate_domain: str | None = None


@dataclass(frozen=True, slots=True)
class RequestAdmissionPolicy:
    """Pure authority and protected-singleton validation policy."""

    scheme: str
    server_port: int
    allowed_hosts: frozenset[str]
    allow_loopback: bool

    @classmethod
    def from_config(cls, config: RequestAdmissionConfig) -> RequestAdmissionPolicy:
        """Normalize *config* and construct one immutable policy."""
        if not isinstance(config.server_port, int) or isinstance(config.server_port, bool):
            raise ValueError("server port must be an integer")
        if not 1 <= config.server_port <= 65535:
            raise ValueError("server port must be between 1 and 65535")

        configured = _normalize_allowed_hosts(config.allowed_hosts or ())
        explicit = bool(configured)
        allowed = set(configured)
        allow_loopback = False

        bind_host = _canonical_config_host(config.bind_host, field="bind host", allow_wildcard=True)
        if not explicit:
            if (
                is_unspecified_host(bind_host)
                or bind_host == "localhost"
                or _is_loopback_ip(bind_host)
            ):
                allow_loopback = True
            else:
                allowed.add(bind_host)

        if config.certificate_domain:
            certificate_host = _canonical_config_host(
                config.certificate_domain,
                field="certificate domain",
                allow_wildcard=False,
            )
            if explicit and certificate_host not in allowed:
                raise ValueError("certificate domain must be included in allowed_hosts")
            if not explicit:
                allowed.add(certificate_host)

        return cls(
            scheme="https" if config.tls_enabled else "http",
            server_port=config.server_port,
            allowed_hosts=frozenset(allowed),
            allow_loopback=allow_loopback,
        )

    def admit(
        self,
        request: _AdmissionRequest,
    ) -> RequestAdmissionContext | AdmissionFailure:
        """Validate protected fields and return immutable trusted values."""
        for original_name, _value in request.header_occurrences:
            normalized_name = original_name.strip().lower()
            if original_name.lower() != normalized_name and (
                display_name := _PROTECTED_FIELD_NAMES.get(normalized_name)
            ):
                return _invalid_header(display_name)

        for display_name, normalized_name in _PROTECTED_FIELDS:
            values = request.get_header_values(normalized_name)
            raw_values = request.get_raw_header_values(normalized_name)
            if len(values) > 1 or any("\r" in value or "\n" in value for value in raw_values):
                return _invalid_header(display_name)

        host_values = request.get_header_values("host")
        if not host_values:
            if request.http_version != "HTTP/1.0":
                return _invalid_header("Host")
            authority = None
        else:
            try:
                authority = _parse_request_authority(host_values[0])
            except ValueError:
                return _invalid_header("Host")
            if not self._host_is_allowed(authority.host):
                return AdmissionFailure(
                    status=421,
                    code="misdirected_request",
                    message="Misdirected Request",
                    field="Host",
                )

        return RequestAdmissionContext(
            authority=authority,
            authorization=_single_value(request, "authorization"),
            origin=_single_value(request, "origin"),
            sec_fetch_site=_single_value(request, "sec-fetch-site"),
            connection=_single_value(request, "connection"),
            upgrade=_single_value(request, "upgrade"),
            websocket_key=_single_value(request, "sec-websocket-key"),
            websocket_version=_single_value(request, "sec-websocket-version"),
            preflight_method=_single_value(request, "access-control-request-method"),
            preflight_headers=_single_value(request, "access-control-request-headers"),
        )

    def is_same_origin(self, context: RequestAdmissionContext, origin: str) -> bool:
        """Compare Origin with admitted Host using effective scheme and ports."""
        authority = context.authority
        if authority is None:
            return False
        try:
            origin_scheme, origin_authority = parse_http_origin(origin)
        except (ValueError, UnicodeError):
            return False

        return (
            origin_scheme == self.scheme
            and origin_authority.host == authority.host
            and origin_authority.effective_port(origin_scheme)
            == authority.effective_port(self.scheme)
        )

    def _host_is_allowed(self, host: str) -> bool:
        if host in self.allowed_hosts:
            return True
        return self.allow_loopback and (host == "localhost" or _is_loopback_ip(host))


def normalize_allowed_hosts(values: tuple[str, ...]) -> tuple[str, ...]:
    """Return de-duplicated canonical configured Host/IP entries."""
    return _normalize_allowed_hosts(values)


def is_unspecified_host(value: str) -> bool:
    """Return whether *value* is an IPv4/IPv6 unspecified-address spelling."""
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_address(candidate).is_unspecified
    except ValueError:
        return False


def parse_http_origin(value: str) -> tuple[str, RequestAuthority]:
    """Parse one lossless HTTP Origin into its scheme and canonical authority."""
    if (
        not value
        or "?" in value
        or "#" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F or char.isspace() for char in value)
    ):
        raise ValueError("invalid HTTP origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid HTTP origin")
    return parsed.scheme, _parse_request_authority(parsed.netloc)


def _normalize_allowed_hosts(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("invalid allowed host: entries must be strings")
        if not value.strip():
            continue
        host = _canonical_config_host(value, field="allowed host", allow_wildcard=False)
        if host not in seen:
            normalized.append(host)
            seen.add(host)
    return tuple(normalized)


def _canonical_config_host(value: str, *, field: str, allow_wildcard: bool) -> str:
    candidate = value.strip()
    if not candidate or _INVALID_AUTHORITY_CHAR_RE.search(candidate):
        raise ValueError(f"invalid {field}: {value!r}")

    if candidate.startswith("["):
        if not candidate.endswith("]") or candidate.count("[") != 1 or candidate.count("]") != 1:
            raise ValueError(f"invalid {field}: {value!r}")
        candidate = candidate[1:-1]

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if ":" in candidate or candidate.endswith(".."):
            raise ValueError(f"invalid {field}: {value!r}") from None
        if candidate.replace(".", "").isdigit():
            raise ValueError(f"invalid {field}: {value!r}") from None
        try:
            return _normalize_dns_host(candidate)
        except ValueError:
            raise ValueError(f"invalid {field}: {value!r}") from None

    if not allow_wildcard and address.is_unspecified:
        raise ValueError(f"invalid {field}: {value!r}")
    return address.compressed


def _parse_request_authority(value: str) -> RequestAuthority:
    if not value or value != value.strip() or _INVALID_AUTHORITY_CHAR_RE.search(value):
        raise ValueError("invalid request authority")

    port: int | None = None
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or value.count("[") != 1 or value.count("]") != 1:
            raise ValueError("invalid request authority")
        literal = value[1:closing]
        suffix = value[closing + 1 :]
        if not suffix:
            port_text = None
        elif suffix.startswith(":"):
            port_text = suffix[1:]
        else:
            raise ValueError("invalid request authority")
        try:
            address = ipaddress.ip_address(literal)
        except ValueError:
            raise ValueError("invalid request authority") from None
        if address.version != 6:
            raise ValueError("invalid request authority")
        host = address.compressed
    else:
        if "[" in value or "]" in value or value.count(":") > 1:
            raise ValueError("invalid request authority")
        host_text, separator, port_text_value = value.partition(":")
        port_text = port_text_value if separator else None
        if not host_text:
            raise ValueError("invalid request authority")
        try:
            address = ipaddress.ip_address(host_text)
        except ValueError:
            if host_text.replace(".", "").isdigit() or host_text.endswith(".."):
                raise ValueError("invalid request authority") from None
            try:
                host = _normalize_dns_host(host_text)
            except ValueError:
                raise ValueError("invalid request authority") from None
        else:
            if address.version != 4:
                raise ValueError("invalid request authority")
            host = address.compressed

    if port_text is not None:
        if _ASCII_PORT_RE.fullmatch(port_text) is None:
            raise ValueError("invalid request authority")
        port = int(port_text, 10)
        if not 1 <= port <= 65535:
            raise ValueError("invalid request authority")

    return RequestAuthority(host=host, port=port)


def _single_value(request: _AdmissionRequest, name: str) -> str | None:
    values = request.get_header_values(name)
    return values[0] if values else None


def _invalid_header(field: str) -> AdmissionFailure:
    return AdmissionFailure(
        status=400,
        code="invalid_header",
        message=f"Invalid {field} header",
        field=field,
    )


def _is_loopback_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalize_dns_host(value: str) -> str:
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or candidate.endswith("."):
        raise ValueError("invalid DNS host")
    source = unicodedata.normalize("NFC", candidate.lower())
    if not candidate.isascii() and source.isascii():
        raise ValueError("invalid DNS host")
    try:
        normalized = source.encode("idna").decode("ascii").lower()
        if not source.isascii():
            round_trip = unicodedata.normalize(
                "NFC",
                normalized.encode("ascii").decode("idna").lower(),
            )
            if round_trip != source:
                raise ValueError("invalid DNS host")
    except UnicodeError as exc:
        raise ValueError("invalid DNS host") from exc
    if not normalized or len(normalized) > 253 or _DNS_HOST_RE.fullmatch(normalized) is None:
        raise ValueError("invalid DNS host")
    for label in normalized.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError("invalid DNS host")
    return normalized


__all__ = [
    "AdmissionFailure",
    "RequestAdmissionConfig",
    "RequestAdmissionContext",
    "RequestAdmissionPolicy",
    "RequestAuthority",
    "is_unspecified_host",
    "normalize_allowed_hosts",
    "parse_http_origin",
]
