"""Operator-facing configuration loading for xferry."""

from __future__ import annotations

import configparser
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any, cast

from .handlers.smuggle import (
    DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS,
    DEFAULT_SMUGGLE_TEMP_MAX_BYTES,
    DEFAULT_SMUGGLE_TEMP_MAX_FILES,
)
from .http.io import (
    BODY_TIMEOUT,
    DEFAULT_BODY_IDLE_TIMEOUT,
    DEFAULT_BODY_MIN_RATE_BYTES_PER_SECOND,
    DEFAULT_MAX_HEADER_SIZE,
)
from .notepad_service import DEFAULT_MAX_NOTE_STORAGE_BYTES, DEFAULT_MAX_NOTES
from .runtime_posture import (
    BODY_ADMISSION_BUDGET_NOTE,
    WEBSOCKET_WORKER_NOTE,
    LaunchPreset,
    RuntimePosture,
    derive_runtime_posture,
    parse_launch_preset,
)
from .server_config import (
    DEFAULT_STREAM_SEND_IDLE_TIMEOUT,
    DEFAULT_STREAM_SEND_TIMEOUT,
    DEFAULT_WEBSOCKET_FRAME_IDLE_TIMEOUT,
    AuthConfig,
    LoggingConfig,
    PluginConfig,
    ServerConfig,
    ServerLimits,
    TLSConfig,
    WebSocketConfig,
    resolve_server_config,
)

_MIB = 1024 * 1024


class SettingsError(ValueError):
    """Raised when an operator configuration is invalid."""


@dataclass(frozen=True)
class ServerSettings:
    """Normalized operator settings before conversion to runtime configuration."""

    preset: LaunchPreset | None = None
    host: str = "127.0.0.1"
    port: int = 8080
    root_dir: str = "."
    quiet: bool = False
    debug: bool = False
    open_browser: bool = False
    json_log: bool = False
    public_direct: bool = False

    max_size_mb: int = 100
    upload_storage_limit_mb: int = 0
    upload_file_limit: int = 0
    upload_reserve_free_mb: int = 0
    upload_quota_externally_managed: bool = False
    note_storage_limit_mb: int = DEFAULT_MAX_NOTE_STORAGE_BYTES // _MIB
    note_count_limit: int = DEFAULT_MAX_NOTES
    smuggle_temp_age: int = DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS
    smuggle_temp_file_limit: int = DEFAULT_SMUGGLE_TEMP_MAX_FILES
    smuggle_temp_storage_limit_mb: int = DEFAULT_SMUGGLE_TEMP_MAX_BYTES // _MIB
    max_header_size_kb: int = DEFAULT_MAX_HEADER_SIZE // 1024
    body_memory_budget_mb: int | None = None
    body_idle_timeout: float = DEFAULT_BODY_IDLE_TIMEOUT
    body_timeout: float = BODY_TIMEOUT
    body_min_rate: float = DEFAULT_BODY_MIN_RATE_BYTES_PER_SECOND
    stream_send_idle_timeout: float = DEFAULT_STREAM_SEND_IDLE_TIMEOUT
    stream_send_timeout: float = DEFAULT_STREAM_SEND_TIMEOUT
    max_websocket_connections: int | None = None
    websocket_frame_idle_timeout: float = DEFAULT_WEBSOCKET_FRAME_IDLE_TIMEOUT
    workers: int = 10

    tls: bool = False
    cert_file: str | None = None
    key_file: str | None = None
    letsencrypt: bool = False
    domain: str | None = None
    email: str | None = None
    sslip: bool = False
    public_ip: str | None = None
    acme_staging: bool = False
    acme_server: str | None = None
    acme_http_address: str = ""
    acme_http_port: int = 80

    auth: str | None = None
    auth_file: str | None = None
    cors_origin: str = ""

    plugin_allowlist: tuple[str, ...] = ()
    plugins_allow_public_direct: bool = False
    plugins_override_core: bool = False
    _explicit_fields: frozenset[str] = field(
        default_factory=frozenset,
        repr=False,
        compare=False,
    )

    def validate(self) -> None:
        """Validate settings independently from argparse."""
        if self.preset is not None and not isinstance(self.preset, LaunchPreset):
            try:
                parse_launch_preset(self.preset)
            except ValueError as exc:
                raise SettingsError(str(exc)) from None
        if not self.host:
            raise SettingsError("host must not be empty")
        _require_int_range("port", self.port, minimum=1, maximum=65535)
        _require_int_range("max_size_mb", self.max_size_mb, minimum=1)
        _require_int_range("upload_storage_limit_mb", self.upload_storage_limit_mb, minimum=0)
        _require_int_range("upload_file_limit", self.upload_file_limit, minimum=0)
        _require_int_range("upload_reserve_free_mb", self.upload_reserve_free_mb, minimum=0)
        _require_int_range("note_storage_limit_mb", self.note_storage_limit_mb, minimum=0)
        _require_int_range("note_count_limit", self.note_count_limit, minimum=0)
        _require_int_range("smuggle_temp_age", self.smuggle_temp_age, minimum=0)
        _require_int_range("smuggle_temp_file_limit", self.smuggle_temp_file_limit, minimum=0)
        _require_int_range(
            "smuggle_temp_storage_limit_mb",
            self.smuggle_temp_storage_limit_mb,
            minimum=0,
        )
        _require_int_range("max_header_size_kb", self.max_header_size_kb, minimum=1)
        if self.body_memory_budget_mb is not None:
            _require_int_range("body_memory_budget_mb", self.body_memory_budget_mb, minimum=1)
        _require_float_range("body_idle_timeout", self.body_idle_timeout, minimum=0)
        _require_float_range("body_timeout", self.body_timeout, minimum=0)
        _require_float_range("body_min_rate", self.body_min_rate, minimum=0)
        _require_float_range(
            "stream_send_idle_timeout",
            self.stream_send_idle_timeout,
            minimum=0.001,
        )
        _require_float_range("stream_send_timeout", self.stream_send_timeout, minimum=0)
        if self.max_websocket_connections is not None:
            _require_int_range(
                "max_websocket_connections",
                self.max_websocket_connections,
                minimum=0,
            )
        _require_float_range(
            "websocket_frame_idle_timeout",
            self.websocket_frame_idle_timeout,
            minimum=0.001,
        )
        _require_int_range("workers", self.workers, minimum=1)
        _require_int_range("acme_http_port", self.acme_http_port, minimum=1, maximum=65535)

        has_cert = self.cert_file is not None
        has_key = self.key_file is not None
        acme_mode = self.letsencrypt or self.sslip
        if has_cert != has_key:
            raise SettingsError("--cert and --key must be provided together")
        if has_cert and (not self.cert_file or not self.key_file):
            raise SettingsError("--cert and --key values must not be empty")
        if has_cert and acme_mode:
            raise SettingsError("--cert/--key cannot be combined with --letsencrypt or --sslip")
        if self.letsencrypt and not self.domain and not self.sslip:
            raise SettingsError("--letsencrypt requires --domain unless --sslip is used")
        if self.sslip and self.domain:
            raise SettingsError("--sslip cannot be combined with --domain")
        if self.public_ip and not self.sslip:
            raise SettingsError("--public-ip requires --sslip")
        if not acme_mode:
            acme_only = {
                "domain": self.domain,
                "email": self.email,
                "acme_staging": self.acme_staging,
                "acme_server": self.acme_server,
                "acme_http_address": self.acme_http_address,
                "acme_http_port": self.acme_http_port != 80,
            }
            for name, active in acme_only.items():
                if active:
                    raise SettingsError(f"{name} requires --letsencrypt or --sslip")

        if self.auth and self.auth_file:
            raise SettingsError("--auth and --auth-file cannot be combined")
        if self.auth_file == "":
            raise SettingsError("--auth-file value must not be empty")

        if self.public_direct:
            self._validate_public_direct()

    def _validate_public_direct(self) -> None:
        real_tls = bool((self.cert_file and self.key_file) or self.letsencrypt or self.sslip)
        if not real_tls:
            raise SettingsError(
                "public_direct requires real TLS via cert_file/key_file, letsencrypt, or sslip"
            )
        if not self.auth_file:
            raise SettingsError("public_direct requires auth_file")
        if self.body_memory_budget_mb is None:
            raise SettingsError("public_direct requires body_memory_budget_mb")
        if not (
            self.upload_storage_limit_mb > 0
            or self.upload_file_limit > 0
            or self.upload_reserve_free_mb > 0
            or self.upload_quota_externally_managed
        ):
            raise SettingsError(
                "public_direct requires upload_storage_limit_mb, upload_file_limit, or "
                "upload_reserve_free_mb to be greater than zero unless "
                "upload_quota_externally_managed is true"
            )
        if self.body_idle_timeout <= 0 or self.body_timeout <= 0:
            raise SettingsError("public_direct requires enabled body timeouts")
        if self.stream_send_idle_timeout <= 0 or self.stream_send_timeout <= 0:
            raise SettingsError("public_direct requires enabled stream send timeouts")
        if self.cors_origin.strip() == "*":
            raise SettingsError("public_direct does not allow wildcard cors_origin")
        if self.plugin_allowlist and not self.plugins_allow_public_direct:
            raise SettingsError(
                "public_direct disables plugins unless plugins_allow_public_direct is true"
            )

    def to_server_config(self) -> ServerConfig:
        """Convert operator settings to one fully resolved runtime configuration."""
        self.validate()
        return resolve_server_config(
            ServerConfig(
                host=self.host,
                port=self.port,
                root_dir=self.root_dir,
                limits=ServerLimits(
                    max_upload_size=self.max_size_mb * _MIB,
                    upload_storage_limit=(
                        self.upload_storage_limit_mb * _MIB
                        if self.upload_storage_limit_mb
                        else None
                    ),
                    upload_file_limit=self.upload_file_limit or None,
                    upload_reserved_free_space=self.upload_reserve_free_mb * _MIB,
                    upload_quota_externally_managed=self.upload_quota_externally_managed,
                    note_storage_limit=(
                        self.note_storage_limit_mb * _MIB if self.note_storage_limit_mb else None
                    ),
                    note_count_limit=self.note_count_limit or None,
                    smuggle_temp_max_age=self.smuggle_temp_age or None,
                    smuggle_temp_file_limit=self.smuggle_temp_file_limit or None,
                    smuggle_temp_storage_limit=(
                        self.smuggle_temp_storage_limit_mb * _MIB
                        if self.smuggle_temp_storage_limit_mb
                        else None
                    ),
                    max_header_size=self.max_header_size_kb * 1024,
                    body_memory_budget=(
                        self.body_memory_budget_mb * _MIB if self.body_memory_budget_mb else None
                    ),
                    body_idle_timeout=self.body_idle_timeout or None,
                    body_timeout=self.body_timeout or None,
                    body_min_rate=self.body_min_rate,
                    stream_send_idle_timeout=self.stream_send_idle_timeout,
                    stream_send_timeout=self.stream_send_timeout or None,
                    max_workers=self.workers,
                ),
                websocket=WebSocketConfig(
                    max_connections=self.max_websocket_connections,
                    frame_idle_timeout=self.websocket_frame_idle_timeout,
                ),
                tls=TLSConfig(
                    enabled=self.effective_tls_enabled(),
                    cert_file=self.cert_file,
                    key_file=self.key_file,
                    letsencrypt=self.letsencrypt,
                    domain=self.domain,
                    email=self.email,
                    sslip=self.sslip,
                    public_ip=self.public_ip,
                    acme_staging=self.acme_staging,
                    acme_server=self.acme_server,
                    acme_http_address=self.acme_http_address,
                    acme_http_port=self.acme_http_port,
                ),
                auth=AuthConfig(auth=self.auth, auth_file=self.auth_file),
                logging=LoggingConfig(
                    quiet=self.quiet,
                    debug=self.debug,
                    open_browser=self.open_browser,
                    json_log=self.json_log,
                ),
                plugins=PluginConfig(
                    module_entries=self.plugin_allowlist,
                    override_core=self.plugins_override_core,
                    allow_public_direct=self.plugins_allow_public_direct,
                ),
                cors_origin=self.cors_origin,
                public_direct=self.public_direct,
                runtime_posture=self.runtime_posture(),
            )
        )

    def effective_tls_enabled(self) -> bool:
        """Return whether runtime HTTPS will be enabled after normalization."""
        return self.tls or bool(self.cert_file) or self.letsencrypt or self.sslip

    def to_redacted_dict(self) -> dict[str, object]:
        """Return settings as JSON-safe data without inline secrets."""
        data = asdict(self)
        data.pop("_explicit_fields", None)
        data["preset"] = self.preset.value if self.preset is not None else None
        if data.get("auth"):
            data["auth"] = "***"
        data["effective_tls"] = self.effective_tls_enabled()
        return data

    def runtime_posture(self) -> RuntimePosture:
        """Return the shared secret-free effective runtime posture."""
        return derive_runtime_posture(self)


_PRESET_DEFAULTS: dict[LaunchPreset, dict[str, object]] = {
    LaunchPreset.LOCAL: {},
    LaunchPreset.LOCAL_SECURE: {
        "tls": True,
        "auth": "random",
    },
    LaunchPreset.PUBLIC_DIRECT: {
        # Public-direct mode intentionally listens on all interfaces.
        "host": "0.0.0.0",  # nosec B104
        "port": 8443,
        "public_direct": True,
        "json_log": True,
        "body_memory_budget_mb": 512,
        "upload_storage_limit_mb": 4096,
        "upload_file_limit": 4096,
        "upload_reserve_free_mb": 1024,
    },
}

_PRESET_EXCLUSIVE_GROUPS = (
    frozenset({"auth", "auth_file"}),
    frozenset({"tls", "cert_file", "key_file", "letsencrypt", "sslip"}),
)


_SECTION_KEYS: dict[str, dict[str, str]] = {
    "server": {
        "preset": "preset",
        "host": "host",
        "port": "port",
        "root_dir": "root_dir",
        "quiet": "quiet",
        "debug": "debug",
        "open_browser": "open_browser",
        "json_log": "json_log",
        "public_direct": "public_direct",
        "workers": "workers",
    },
    "limits": {
        "max_size_mb": "max_size_mb",
        "upload_storage_limit_mb": "upload_storage_limit_mb",
        "upload_file_limit": "upload_file_limit",
        "upload_reserve_free_mb": "upload_reserve_free_mb",
        "upload_quota_externally_managed": "upload_quota_externally_managed",
        "note_storage_limit_mb": "note_storage_limit_mb",
        "note_count_limit": "note_count_limit",
        "smuggle_temp_age": "smuggle_temp_age",
        "smuggle_temp_file_limit": "smuggle_temp_file_limit",
        "smuggle_temp_storage_limit_mb": "smuggle_temp_storage_limit_mb",
        "max_header_size_kb": "max_header_size_kb",
        "body_memory_budget_mb": "body_memory_budget_mb",
        "body_idle_timeout": "body_idle_timeout",
        "body_timeout": "body_timeout",
        "body_min_rate": "body_min_rate",
        "stream_send_idle_timeout": "stream_send_idle_timeout",
        "stream_send_timeout": "stream_send_timeout",
        "max_websocket_connections": "max_websocket_connections",
        "websocket_frame_idle_timeout": "websocket_frame_idle_timeout",
    },
    "tls": {
        "tls": "tls",
        "cert_file": "cert_file",
        "key_file": "key_file",
        "letsencrypt": "letsencrypt",
        "domain": "domain",
        "email": "email",
        "sslip": "sslip",
        "public_ip": "public_ip",
        "acme_staging": "acme_staging",
        "acme_server": "acme_server",
        "acme_http_address": "acme_http_address",
        "acme_http_port": "acme_http_port",
    },
    "security": {
        "auth": "auth",
        "auth_file": "auth_file",
    },
    "cors": {
        "cors_origin": "cors_origin",
    },
    "plugins": {
        "plugin_allowlist": "plugin_allowlist",
        "plugins_allow_public_direct": "plugins_allow_public_direct",
        "plugins_override_core": "plugins_override_core",
    },
}

_ENV_KEYS: dict[str, str] = {
    f"XFERRY_{settings_field.name.upper()}": settings_field.name
    for settings_field in fields(ServerSettings)
    if not settings_field.name.startswith("_")
}


def load_settings_file(
    path: str | Path,
    *,
    validate: bool = True,
) -> ServerSettings:
    """Load settings from an INI file."""
    config_path = Path(path)
    try:
        text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SettingsError(f"config file does not exist: {config_path}") from None
    except OSError as exc:
        raise SettingsError(f"config file could not be read: {config_path}") from exc
    return load_settings_text(text, validate=validate)


def load_settings_text(text: str, *, validate: bool = True) -> ServerSettings:
    """Load settings from an INI string."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise SettingsError(f"config file is not valid INI: {exc}") from exc

    values: dict[str, object] = {}
    for section in parser.sections():
        section_key = section.strip().lower()
        if section_key not in _SECTION_KEYS:
            raise SettingsError(f"unknown config section: {section}")
        key_map = _SECTION_KEYS[section_key]
        for raw_key, raw_value in parser.items(section):
            key = raw_key.strip().lower()
            if key not in key_map:
                raise SettingsError(f"unknown config key: {section}.{raw_key}")
            field_name = key_map[key]
            values[field_name] = _parse_field_value(field_name, raw_value)

    settings = replace(
        ServerSettings(),
        **cast(Any, values),
        _explicit_fields=frozenset(values),
    )
    if validate:
        return resolve_settings(file_settings=settings)
    return settings


def resolve_settings(
    *,
    file_settings: ServerSettings | None = None,
    env: dict[str, str] | None = None,
    cli_values: dict[str, object] | None = None,
) -> ServerSettings:
    """Resolve defaults < preset < explicit file < env < CLI values."""
    file_values = _file_layer_values(file_settings)
    env_values: dict[str, object] = {}
    for env_name, field_name in _ENV_KEYS.items():
        if env and env_name in env:
            env_values[field_name] = _parse_field_value(field_name, env[env_name])
    normalized_cli_values = dict(cli_values or {})

    selected_preset: LaunchPreset | None = None
    for layer in (file_values, env_values, normalized_cli_values):
        if "preset" not in layer:
            continue
        try:
            selected_preset = parse_launch_preset(layer["preset"])
        except ValueError as exc:
            raise SettingsError(str(exc)) from None

    explicit_fields = set(file_values) | set(env_values) | set(normalized_cli_values)
    preset_values = dict(_PRESET_DEFAULTS[selected_preset]) if selected_preset is not None else {}
    for group in _PRESET_EXCLUSIVE_GROUPS:
        if explicit_fields & group:
            for field_name in group:
                preset_values.pop(field_name, None)

    settings = replace(ServerSettings(), **cast(Any, preset_values))
    for layer in (file_values, env_values, normalized_cli_values):
        explicit_layer = {key: value for key, value in layer.items() if key != "preset"}
        if explicit_layer:
            settings = replace(settings, **cast(Any, explicit_layer))
    settings = replace(
        settings,
        preset=selected_preset,
        _explicit_fields=frozenset(explicit_fields),
    )
    settings.validate()
    return settings


def sample_config_text() -> str:
    """Return a public-direct sample configuration."""
    return """# xferry public-direct sample configuration
[server]
preset = public-direct
host = 0.0.0.0
port = 8443
root_dir = /var/lib/xferry
public_direct = true
json_log = true
workers = 10

[security]
auth_file = /etc/xferry/auth

[tls]
# Runtime TLS becomes active through sslip/letsencrypt/cert+key even if
# the explicit self-signed `tls` flag remains false in normalized output.
# Use sslip for first-run public IPv4 deployments, or replace with:
# letsencrypt = true
# domain = files.example.com
sslip = true
# public_ip = 203.0.113.10
# acme_staging = true

[limits]
max_size_mb = 100
body_memory_budget_mb = 512
body_idle_timeout = 5
body_timeout = 300
body_min_rate = 0
stream_send_idle_timeout = 5
stream_send_timeout = 300
upload_storage_limit_mb = 4096
upload_file_limit = 4096
upload_reserve_free_mb = 1024
upload_quota_externally_managed = false

[cors]
cors_origin =

[plugins]
plugin_allowlist =
plugins_allow_public_direct = false
plugins_override_core = false
"""


def _parse_field_value(field_name: str, raw_value: object) -> object:
    if raw_value is None:
        return None
    value = str(raw_value).strip()
    if field_name == "preset":
        try:
            return parse_launch_preset(value)
        except ValueError as exc:
            raise SettingsError(str(exc)) from None
    if field_name in {
        "quiet",
        "debug",
        "open_browser",
        "json_log",
        "public_direct",
        "upload_quota_externally_managed",
        "tls",
        "letsencrypt",
        "sslip",
        "acme_staging",
        "plugins_allow_public_direct",
        "plugins_override_core",
    }:
        return _parse_bool(field_name, value)
    if field_name in {
        "port",
        "max_size_mb",
        "upload_storage_limit_mb",
        "upload_file_limit",
        "upload_reserve_free_mb",
        "note_storage_limit_mb",
        "note_count_limit",
        "smuggle_temp_age",
        "smuggle_temp_file_limit",
        "smuggle_temp_storage_limit_mb",
        "max_header_size_kb",
        "body_memory_budget_mb",
        "max_websocket_connections",
        "workers",
        "acme_http_port",
    }:
        if value == "" and field_name in {"body_memory_budget_mb", "max_websocket_connections"}:
            return None
        try:
            return int(value, 10)
        except ValueError:
            raise SettingsError(f"{field_name} must be an integer") from None
    if field_name in {
        "body_idle_timeout",
        "body_timeout",
        "body_min_rate",
        "stream_send_idle_timeout",
        "stream_send_timeout",
        "websocket_frame_idle_timeout",
    }:
        try:
            return float(value)
        except ValueError:
            raise SettingsError(f"{field_name} must be a number") from None
    if field_name == "plugin_allowlist":
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if value == "" and field_name in {
        "domain",
        "email",
        "public_ip",
        "acme_server",
        "auth",
        "auth_file",
    }:
        return None
    return value


def _file_layer_values(file_settings: ServerSettings | None) -> dict[str, object]:
    """Recover only explicit INI values, retaining false/zero/default values."""
    if file_settings is None:
        return {}
    if file_settings._explicit_fields:
        return {
            field_name: getattr(file_settings, field_name)
            for field_name in file_settings._explicit_fields
        }

    # Compatibility for callers that constructed a ServerSettings layer
    # directly. Exact explicit-equals-default provenance requires the INI
    # loader, but non-default values and a selected preset remain useful.
    defaults = ServerSettings()
    values: dict[str, object] = {}
    for settings_field in fields(ServerSettings):
        field_name = settings_field.name
        if field_name.startswith("_"):
            continue
        value = getattr(file_settings, field_name)
        if value != getattr(defaults, field_name):
            values[field_name] = value
    return values


def _parse_bool(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise SettingsError(f"{name} must be a boolean")


def _require_int_range(
    name: str,
    value: int,
    *,
    minimum: int,
    maximum: int | None = None,
) -> None:
    if value < minimum or (maximum is not None and value > maximum):
        if maximum is None:
            raise SettingsError(f"{name} must be at least {minimum}")
        raise SettingsError(f"{name} must be between {minimum} and {maximum}")


def _require_float_range(
    name: str,
    value: float,
    *,
    minimum: float,
    maximum: float | None = None,
) -> None:
    if value < minimum or (maximum is not None and value > maximum):
        if maximum is None:
            raise SettingsError(f"{name} must be at least {minimum:g}")
        raise SettingsError(f"{name} must be between {minimum:g} and {maximum:g}")


__all__ = [
    "BODY_ADMISSION_BUDGET_NOTE",
    "WEBSOCKET_WORKER_NOTE",
    "LaunchPreset",
    "RuntimePosture",
    "ServerSettings",
    "SettingsError",
    "derive_runtime_posture",
    "load_settings_file",
    "load_settings_text",
    "resolve_settings",
    "sample_config_text",
]
