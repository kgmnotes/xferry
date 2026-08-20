"""Test-only adapters for constructing the immutable server configuration."""

from __future__ import annotations

from typing import Any

from xferry.extensions import PluginSpec
from xferry.server import XFerryServer
from xferry.server_config import (
    AuthConfig,
    LoggingConfig,
    PluginConfig,
    ServerConfig,
    ServerLimits,
    TLSConfig,
    WebSocketConfig,
)


def make_server_config(**kwargs: Any) -> ServerConfig:
    """Translate pre-3.0 test arguments into a real :class:`ServerConfig`."""
    limit_defaults = ServerLimits()
    websocket_defaults = WebSocketConfig()
    tls_defaults = TLSConfig()
    auth_defaults = AuthConfig()
    logging_defaults = LoggingConfig()
    plugin_defaults = PluginConfig()
    config_defaults = ServerConfig()
    optional_zero_limits = {
        "upload_storage_limit",
        "upload_file_limit",
        "note_storage_limit",
        "note_count_limit",
        "smuggle_temp_max_age",
        "smuggle_temp_file_limit",
        "smuggle_temp_storage_limit",
    }
    for field_name in optional_zero_limits:
        if kwargs.get(field_name) == 0:
            kwargs[field_name] = None
    limits = ServerLimits(
        max_upload_size=kwargs.pop("max_upload_size", limit_defaults.max_upload_size),
        upload_storage_limit=kwargs.pop(
            "upload_storage_limit", limit_defaults.upload_storage_limit
        ),
        upload_file_limit=kwargs.pop("upload_file_limit", limit_defaults.upload_file_limit),
        upload_reserved_free_space=kwargs.pop(
            "upload_reserved_free_space", limit_defaults.upload_reserved_free_space
        ),
        note_storage_limit=kwargs.pop("note_storage_limit", limit_defaults.note_storage_limit),
        note_count_limit=kwargs.pop("note_count_limit", limit_defaults.note_count_limit),
        smuggle_temp_max_age=kwargs.pop(
            "smuggle_temp_max_age", limit_defaults.smuggle_temp_max_age
        ),
        smuggle_temp_file_limit=kwargs.pop(
            "smuggle_temp_file_limit", limit_defaults.smuggle_temp_file_limit
        ),
        smuggle_temp_storage_limit=kwargs.pop(
            "smuggle_temp_storage_limit", limit_defaults.smuggle_temp_storage_limit
        ),
        max_header_size=kwargs.pop("max_header_size", limit_defaults.max_header_size),
        body_memory_budget=kwargs.pop("body_memory_budget", limit_defaults.body_memory_budget),
        body_idle_timeout=kwargs.pop("body_idle_timeout", limit_defaults.body_idle_timeout),
        body_timeout=kwargs.pop("body_timeout", limit_defaults.body_timeout),
        body_min_rate=kwargs.pop("body_min_rate", limit_defaults.body_min_rate),
        stream_send_idle_timeout=kwargs.pop(
            "stream_send_idle_timeout", limit_defaults.stream_send_idle_timeout
        ),
        stream_send_timeout=kwargs.pop("stream_send_timeout", limit_defaults.stream_send_timeout),
        max_workers=kwargs.pop("max_workers", limit_defaults.max_workers),
    )
    websocket = WebSocketConfig(
        max_connections=kwargs.pop("max_websocket_connections", websocket_defaults.max_connections),
        frame_idle_timeout=kwargs.pop(
            "websocket_frame_idle_timeout", websocket_defaults.frame_idle_timeout
        ),
    )
    tls = TLSConfig(
        enabled=kwargs.pop("tls", tls_defaults.enabled),
        cert_file=kwargs.pop("cert_file", tls_defaults.cert_file),
        key_file=kwargs.pop("key_file", tls_defaults.key_file),
        letsencrypt=kwargs.pop("letsencrypt", tls_defaults.letsencrypt),
        domain=kwargs.pop("domain", tls_defaults.domain),
        email=kwargs.pop("email", tls_defaults.email),
        sslip=kwargs.pop("sslip", tls_defaults.sslip),
        public_ip=kwargs.pop("public_ip", tls_defaults.public_ip),
        acme_staging=kwargs.pop("acme_staging", tls_defaults.acme_staging),
        acme_server=kwargs.pop("acme_server", tls_defaults.acme_server),
        acme_http_address=kwargs.pop("acme_http_address", tls_defaults.acme_http_address),
        acme_http_port=kwargs.pop("acme_http_port", tls_defaults.acme_http_port),
    )
    auth = AuthConfig(
        auth=kwargs.pop("auth", auth_defaults.auth),
        auth_file=kwargs.pop("auth_file", auth_defaults.auth_file),
    )
    logging = LoggingConfig(
        quiet=kwargs.pop("quiet", logging_defaults.quiet),
        debug=kwargs.pop("debug", logging_defaults.debug),
        open_browser=kwargs.pop("open_browser", logging_defaults.open_browser),
        json_log=kwargs.pop("json_log", logging_defaults.json_log),
    )
    direct = tuple(kwargs.pop("plugins", ()))
    if not all(isinstance(plugin, PluginSpec) for plugin in direct):
        raise TypeError("plugins must contain PluginSpec instances")
    plugins = PluginConfig(
        direct=direct,
        module_entries=tuple(kwargs.pop("plugin_modules", ())),
        override_core=kwargs.pop("plugins_override_core", plugin_defaults.override_core),
        allow_public_direct=kwargs.pop(
            "plugins_allow_public_direct", plugin_defaults.allow_public_direct
        ),
    )
    config = ServerConfig(
        host=kwargs.pop("host", config_defaults.host),
        port=kwargs.pop("port", config_defaults.port),
        root_dir=kwargs.pop("root_dir", config_defaults.root_dir),
        limits=limits,
        websocket=websocket,
        tls=tls,
        auth=auth,
        logging=logging,
        plugins=plugins,
        cors_origin=kwargs.pop("cors_origin", config_defaults.cors_origin),
        public_direct=kwargs.pop("public_direct", config_defaults.public_direct),
        runtime_posture=kwargs.pop("runtime_posture", config_defaults.runtime_posture),
    )
    if kwargs:
        unknown = ", ".join(sorted(kwargs))
        raise TypeError(f"unexpected legacy server arguments: {unknown}")
    return config


def make_server(**kwargs: Any) -> XFerryServer:
    """Construct the real server through its sole public config constructor."""
    return XFerryServer(make_server_config(**kwargs))
