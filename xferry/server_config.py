"""Immutable, side-effect-free runtime configuration for :mod:`xferry.server`."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

from .extensions import PluginSpec
from .features import registry_methods
from .runtime_posture import RuntimePosture

DEFAULT_STREAM_SEND_IDLE_TIMEOUT = 5.0
DEFAULT_STREAM_SEND_TIMEOUT = 300.0
DEFAULT_WEBSOCKET_FRAME_IDLE_TIMEOUT = 5.0

_MODULE_PART_RE = re.compile(r"^[A-Za-z_]\w*$")


@dataclass(frozen=True, slots=True)
class ServerLimits:
    """Request, storage, and worker limits used by one server instance."""

    max_upload_size: int = 100 * 1024 * 1024
    upload_storage_limit: int | None = None
    upload_file_limit: int | None = None
    upload_reserved_free_space: int = 0
    upload_quota_externally_managed: bool = False
    note_storage_limit: int | None = 256 * 1024 * 1024
    note_count_limit: int | None = 1000
    smuggle_temp_max_age: float | None = 3600
    smuggle_temp_file_limit: int | None = 32
    smuggle_temp_storage_limit: int | None = 128 * 1024 * 1024
    max_header_size: int = 64 * 1024
    body_memory_budget: int | None = None
    body_idle_timeout: float | None = 5.0
    body_timeout: float | None = 300.0
    body_min_rate: float = 0.0
    stream_send_idle_timeout: float = DEFAULT_STREAM_SEND_IDLE_TIMEOUT
    stream_send_timeout: float | None = DEFAULT_STREAM_SEND_TIMEOUT
    max_workers: int = 10


@dataclass(frozen=True, slots=True)
class WebSocketConfig:
    """WebSocket admission and frame-read limits."""

    max_connections: int | None = None
    frame_idle_timeout: float = DEFAULT_WEBSOCKET_FRAME_IDLE_TIMEOUT


@dataclass(frozen=True, slots=True)
class TLSConfig:
    """Validated TLS and ACME inputs; certificate acquisition stays at runtime."""

    enabled: bool = False
    cert_file: Path | str | None = None
    key_file: Path | str | None = None
    letsencrypt: bool = False
    domain: str | None = None
    email: str | None = None
    sslip: bool = False
    public_ip: str | None = None
    acme_staging: bool = False
    acme_server: str | None = None
    acme_http_address: str = ""
    acme_http_port: int = 80


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """Basic-auth source configuration without resolved credentials."""

    auth: str | None = None
    auth_file: Path | str | None = None


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    """Logging and operator-display switches."""

    quiet: bool = False
    debug: bool = False
    open_browser: bool = False
    json_log: bool = False


@dataclass(frozen=True, slots=True)
class PluginConfig:
    """Direct and module-backed plugin declarations."""

    direct: tuple[PluginSpec, ...] = ()
    module_entries: tuple[str, ...] = ()
    override_core: bool = False
    allow_public_direct: bool = False


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """Complete immutable input to :class:`xferry.server.XFerryServer`."""

    host: str = "127.0.0.1"
    port: int = 8080
    root_dir: Path | str = Path()
    limits: ServerLimits = field(default_factory=ServerLimits)
    websocket: WebSocketConfig = field(default_factory=WebSocketConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    cors_origin: str | None = None
    cors_origins: tuple[str, ...] = ()
    public_direct: bool = False
    runtime_posture: RuntimePosture | None = None


def resolve_server_config(config: ServerConfig) -> ServerConfig:
    """Normalize and validate *config* without performing runtime side effects."""
    if not isinstance(config, ServerConfig):
        raise TypeError("config must be a ServerConfig")

    host = config.host.strip()
    if not host:
        raise ValueError("host must not be empty")
    _require_int("port", config.port, minimum=1, maximum=65535)

    limits = config.limits
    _require_int("max_upload_size", limits.max_upload_size, minimum=1)
    _require_optional_int("upload_storage_limit", limits.upload_storage_limit, minimum=0)
    _require_optional_int("upload_file_limit", limits.upload_file_limit, minimum=0)
    _require_int("upload_reserved_free_space", limits.upload_reserved_free_space, minimum=0)
    _require_optional_int("note_storage_limit", limits.note_storage_limit, minimum=0)
    _require_optional_int("note_count_limit", limits.note_count_limit, minimum=0)
    _require_optional_number("smuggle_temp_max_age", limits.smuggle_temp_max_age, minimum=0)
    _require_optional_int("smuggle_temp_file_limit", limits.smuggle_temp_file_limit, minimum=0)
    _require_optional_int(
        "smuggle_temp_storage_limit", limits.smuggle_temp_storage_limit, minimum=0
    )
    _require_int("max_header_size", limits.max_header_size, minimum=1)
    _require_optional_int("body_memory_budget", limits.body_memory_budget, minimum=1)
    _require_optional_number("body_idle_timeout", limits.body_idle_timeout, minimum_exclusive=0)
    _require_optional_number("body_timeout", limits.body_timeout, minimum_exclusive=0)
    _require_number("body_min_rate", limits.body_min_rate, minimum=0)
    _require_number(
        "stream_send_idle_timeout", limits.stream_send_idle_timeout, minimum_exclusive=0
    )
    _require_optional_number("stream_send_timeout", limits.stream_send_timeout, minimum_exclusive=0)
    _require_int("max_workers", limits.max_workers, minimum=1)
    body_memory_budget = limits.body_memory_budget
    if config.public_direct and body_memory_budget is None:
        raise ValueError("public_direct requires body_memory_budget")
    if body_memory_budget is None:
        body_memory_budget = limits.max_upload_size * limits.max_workers
    limits = replace(
        limits,
        upload_storage_limit=limits.upload_storage_limit or None,
        upload_file_limit=limits.upload_file_limit or None,
        note_storage_limit=limits.note_storage_limit or None,
        note_count_limit=limits.note_count_limit or None,
        smuggle_temp_max_age=limits.smuggle_temp_max_age or None,
        smuggle_temp_file_limit=limits.smuggle_temp_file_limit or None,
        smuggle_temp_storage_limit=limits.smuggle_temp_storage_limit or None,
        body_memory_budget=body_memory_budget,
    )

    websocket = config.websocket
    _require_optional_int("max_websocket_connections", websocket.max_connections, minimum=0)
    _require_number(
        "websocket_frame_idle_timeout", websocket.frame_idle_timeout, minimum_exclusive=0
    )
    max_connections = websocket.max_connections
    if max_connections is None:
        max_connections = max(0, limits.max_workers // 2)
    websocket = replace(websocket, max_connections=max_connections)

    auth = config.auth
    if auth.auth_file == "":
        raise ValueError("--auth-file value must not be empty")
    if auth.auth and auth.auth_file:
        raise ValueError("--auth and --auth-file cannot be combined")
    auth = replace(auth, auth_file=_resolve_optional_path(auth.auth_file))

    tls = _resolve_tls(config.tls)
    cors_origin, cors_origins = _resolve_cors(config.cors_origin, config.cors_origins)
    plugins = _resolve_plugins(config.plugins)

    if config.public_direct:
        if not (tls.cert_file and tls.key_file) and not (tls.letsencrypt or tls.sslip):
            raise ValueError(
                "public_direct requires real TLS via cert_file/key_file, letsencrypt, or sslip"
            )
        if not auth.auth_file:
            raise ValueError("public_direct requires auth_file")
        if not (
            limits.upload_storage_limit
            or limits.upload_file_limit
            or limits.upload_reserved_free_space
            or limits.upload_quota_externally_managed
        ):
            raise ValueError("public_direct requires an upload storage control")
        if limits.body_idle_timeout is None or limits.body_timeout is None:
            raise ValueError("public_direct requires enabled body timeouts")
        if limits.stream_send_timeout is None:
            raise ValueError("public_direct requires enabled stream send timeouts")
        if cors_origins == ("*",):
            raise ValueError("public_direct does not allow wildcard cors_origin")
        if (plugins.direct or plugins.module_entries) and not plugins.allow_public_direct:
            raise ValueError(
                "public_direct disables plugins unless plugins_allow_public_direct is true"
            )

    return replace(
        config,
        host=host,
        root_dir=Path(config.root_dir).expanduser().resolve(),
        limits=limits,
        websocket=websocket,
        tls=tls,
        auth=auth,
        plugins=plugins,
        cors_origin=cors_origin,
        cors_origins=cors_origins,
    )


def _resolve_tls(tls: TLSConfig) -> TLSConfig:
    if tls.cert_file == "" or tls.key_file == "":
        raise ValueError("--cert and --key values must not be empty")
    cert_file = _resolve_optional_path(tls.cert_file)
    key_file = _resolve_optional_path(tls.key_file)
    if (cert_file is None) != (key_file is None):
        raise ValueError("--cert and --key must be provided together")
    acme_mode = tls.letsencrypt or tls.sslip
    if cert_file and acme_mode:
        raise ValueError("--cert/--key cannot be combined with --letsencrypt or --sslip")
    if tls.letsencrypt and not tls.domain and not tls.sslip:
        raise ValueError("--letsencrypt requires --domain unless --sslip is used")
    if tls.sslip and tls.domain:
        raise ValueError("--sslip cannot be combined with --domain")
    if tls.public_ip and not tls.sslip:
        raise ValueError("--public-ip requires --sslip")
    _require_int("acme_http_port", tls.acme_http_port, minimum=1, maximum=65535)
    if not acme_mode and any(
        (
            tls.domain,
            tls.email,
            tls.acme_staging,
            tls.acme_server,
            tls.acme_http_address,
            tls.acme_http_port != 80,
        )
    ):
        raise ValueError("ACME options require --letsencrypt or --sslip")
    return replace(
        tls,
        enabled=tls.enabled or cert_file is not None or acme_mode,
        cert_file=cert_file,
        key_file=key_file,
    )


def _resolve_cors(
    configured: str | None, pre_parsed: tuple[str, ...]
) -> tuple[str | None, tuple[str, ...]]:
    raw_values = configured.split(",") if configured else list(pre_parsed)
    origins: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        origin = raw.strip()
        if not origin or origin in seen:
            continue
        if origin != "*":
            parsed = urlsplit(origin)
            try:
                port = parsed.port
            except ValueError:
                raise ValueError(f"invalid CORS origin: {origin!r}") from None
            del port
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(f"invalid CORS origin: {origin!r}")
        origins.append(origin)
        seen.add(origin)
    if "*" in seen and len(origins) > 1:
        raise ValueError("CORS wildcard origin '*' cannot be combined with explicit origins")
    normalized = tuple(origins)
    return (",".join(normalized) or None), normalized


def _resolve_plugins(plugins: PluginConfig) -> PluginConfig:
    direct = tuple(plugin.normalized() for plugin in plugins.direct)
    validate_plugin_specs(direct, override_core=plugins.override_core)

    entries: list[str] = []
    seen_entries: set[str] = set()
    for raw_entry in plugins.module_entries:
        entry = raw_entry.strip()
        if not entry or entry in seen_entries:
            continue
        module_name, separator, attr_name = entry.partition(":")
        if not module_name or any(
            not _MODULE_PART_RE.fullmatch(part) for part in module_name.split(".")
        ):
            raise ValueError(f"invalid plugin module entry: {raw_entry!r}")
        if separator and (not attr_name or not _MODULE_PART_RE.fullmatch(attr_name)):
            raise ValueError(f"invalid plugin module entry: {raw_entry!r}")
        entries.append(entry)
        seen_entries.add(entry)
    return replace(plugins, direct=direct, module_entries=tuple(entries))


def validate_plugin_specs(plugins: tuple[PluginSpec, ...], *, override_core: bool) -> None:
    """Validate already loaded plugin specs without importing or mutating anything."""
    names: set[str] = set()
    methods: set[str] = set()
    core_methods = set(registry_methods())
    for plugin in plugins:
        if plugin.name in names:
            raise ValueError(f"duplicate plugin name: {plugin.name}")
        names.add(plugin.name)
        for method in plugin.methods:
            if method.method in methods:
                raise ValueError(f"duplicate plugin method: {method.method}")
            if method.method in core_methods and not override_core:
                raise ValueError(f"plugin method {method.method} would override a core method")
            methods.add(method.method)


def _resolve_optional_path(value: Path | str | None) -> Path | None:
    if value is None:
        return None
    if str(value) == "":
        return None
    return Path(value).expanduser().resolve()


def _require_int(name: str, value: object, *, minimum: int, maximum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        if maximum is None:
            raise ValueError(f"{name} must be at least {minimum}")
        raise ValueError(f"{name} must be between {minimum} and {maximum}")


def _require_optional_int(name: str, value: object, *, minimum: int) -> None:
    if value is not None:
        _require_int(name, value, minimum=minimum)


def _require_number(
    name: str,
    value: object,
    *,
    minimum: float | None = None,
    minimum_exclusive: float | None = None,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum:g}")
    if minimum_exclusive is not None and value <= minimum_exclusive:
        raise ValueError(f"{name} must be greater than {minimum_exclusive:g}")


def _require_optional_number(
    name: str,
    value: object,
    *,
    minimum: float | None = None,
    minimum_exclusive: float | None = None,
) -> None:
    if value is not None:
        _require_number(name, value, minimum=minimum, minimum_exclusive=minimum_exclusive)


__all__ = [
    "AuthConfig",
    "LoggingConfig",
    "PluginConfig",
    "ServerConfig",
    "ServerLimits",
    "TLSConfig",
    "WebSocketConfig",
    "resolve_server_config",
    "validate_plugin_specs",
]
