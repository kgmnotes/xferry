"""Authenticated, secret-safe health checks for managed XFerry services."""

from __future__ import annotations

import base64
import json
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass

from xferry.security.tls import normalize_domain

_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 64 * 1024


@dataclass(frozen=True)
class HealthEndpoint:
    """Local connection target and externally verified HTTP identity."""

    connect_host: str
    port: int
    host: str
    tls: bool

    @property
    def url(self) -> str:
        """Return the operator-facing URL for this endpoint."""
        scheme = "https" if self.tls else "http"
        default_port = 443 if self.tls else 80
        suffix = "" if self.port == default_port else f":{self.port}"
        return f"{scheme}://{self.host}{suffix}"


@dataclass(frozen=True)
class HealthResult:
    """Sanitized outcome of an authenticated PING request."""

    ok: bool
    detail: str


def authenticated_ping(
    endpoint: HealthEndpoint,
    username: str,
    password: str,
    timeout: float,
) -> HealthResult:
    """Require authenticated HTTP 200 plus a bounded ``health == "ready"`` body.

    Credentials exist only in process memory and sanitized result messages never
    include request bytes or caught exception text.
    """
    if timeout <= 0 or not 1 <= endpoint.port <= 65535:
        return HealthResult(ok=False, detail="invalid health endpoint")

    try:
        host = normalize_domain(endpoint.host)
        credentials = f"{username}:{password}".encode()
        token = base64.b64encode(credentials).decode("ascii")
        request = (
            "PING / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Authorization: Basic {token}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
    except (UnicodeError, ValueError):
        return HealthResult(ok=False, detail="invalid health endpoint")

    response = bytearray()
    try:
        with socket.create_connection(
            (endpoint.connect_host, endpoint.port), timeout=timeout
        ) as connection:
            connection.settimeout(timeout)
            if endpoint.tls:
                context = ssl.create_default_context()
                with context.wrap_socket(connection, server_hostname=host) as tls_socket:
                    _exchange(tls_socket, request, response)
            else:
                _exchange(connection, request, response)
    except ssl.SSLCertVerificationError:
        return HealthResult(ok=False, detail="TLS verification failed")
    except (OSError, ssl.SSLError):
        return HealthResult(ok=False, detail="connection failed")

    return _parse_health_response(bytes(response))


def _exchange(connection: socket.socket, request: bytes, response: bytearray) -> None:
    connection.sendall(request)
    while len(response) < _MAX_HEADER_BYTES + _MAX_BODY_BYTES:
        chunk = connection.recv(4096)
        if not chunk:
            break
        response.extend(chunk)

        header, separator, body = response.partition(b"\r\n\r\n")
        if not separator:
            continue
        if len(header) > _MAX_HEADER_BYTES:
            break

        content_length = _content_length(bytes(header))
        if content_length is not None:
            if not 0 <= content_length <= _MAX_BODY_BYTES or len(body) >= content_length:
                break
        elif len(body) > _MAX_BODY_BYTES:
            break


def _content_length(header: bytes) -> int | None:
    for line in header.split(b"\r\n")[1:]:
        name, delimiter, value = line.partition(b":")
        if delimiter and name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return -1
    return None


def _parse_health_response(response: bytes) -> HealthResult:
    header, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        return HealthResult(ok=False, detail="invalid health response")
    if len(header) > _MAX_HEADER_BYTES or len(body) > _MAX_BODY_BYTES:
        return HealthResult(ok=False, detail="invalid health response")
    content_length = _content_length(header)
    if content_length is not None and (
        not 0 <= content_length <= _MAX_BODY_BYTES or len(body) != content_length
    ):
        return HealthResult(ok=False, detail="invalid health response")
    lines = header.split(b"\r\n")
    status = lines[0].split(b" ", 2) if lines else []
    status_ok = len(status) >= 2 and status[1] == b"200"
    if not status_ok:
        return HealthResult(ok=False, detail="invalid health response")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return HealthResult(ok=False, detail="invalid health response")
    if not isinstance(payload, Mapping) or payload.get("health") != "ready":
        return HealthResult(ok=False, detail="invalid health response")
    return HealthResult(ok=True, detail="healthy")
