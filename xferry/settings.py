"""Operator-facing configuration loading for xferry."""

from __future__ import annotations

import configparser
import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from .encrypted_transfer import EUF_MAX_FILE_SIZE
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
from .paths import automatic_state_dir, default_files_dir, runtime_state_dir, state_for_config
from .request_admission import is_unspecified_host, normalize_allowed_hosts
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
from .settings_schema import (
    SETTING_SPEC_BY_NAME,
    SETTING_SPECS,
    SampleProfile,
    SampleTarget,
    env_to_setting_map,
    get_sample_profile,
    get_sample_target,
    render_ini_entry,
    sample_specs,
    section_key_map,
)

_MIB = 1024 * 1024


class SettingsError(ValueError):
    """Raised when an operator configuration is invalid."""


@dataclass(frozen=True)
class ServerSettings:
    """Normalized operator settings before conversion to runtime configuration."""

    access: str = field(default="private", kw_only=True)
    https_mode: str | None = field(default=None, kw_only=True)
    log_level: str = field(default="info", kw_only=True)
    log_format: str = field(default="text", kw_only=True)
    preset: LaunchPreset | None = None
    host: str = "127.0.0.1"
    port: int = 8080
    root_dir: str = "."
    files_dir: str | None = field(default=None, kw_only=True)
    quiet: bool = False
    debug: bool = False
    open_browser: bool = False
    json_log: bool = False
    public_direct: bool = False
    encrypted_uploads: bool = False

    max_size_mb: int = 100
    encrypted_upload_max_size_mb: int = 0
    encrypted_upload_incomplete_ttl_seconds: int = 86400
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
    allowed_hosts: tuple[str, ...] = ()
    cors_origin: str = ""

    plugin_allowlist: tuple[str, ...] = ()
    plugins_allow_public_direct: bool = False
    plugins_override_core: bool = False
    _explicit_fields: frozenset[str] = field(
        default_factory=frozenset,
        repr=False,
        compare=False,
    )

    _derived: bool = field(default=False, repr=False, compare=False, kw_only=True)
    _origins: dict[str, str] = field(default_factory=dict, repr=False, compare=False, kw_only=True)
    _config_path: str | None = field(default=None, repr=False, compare=False, kw_only=True)
    _state_explicit: bool = field(default=False, repr=False, compare=False, kw_only=True)

    def _runtime_settings(self) -> ServerSettings:
        if not self._derived and (
            self.access != "private"
            or self.https_mode is not None
            or self.log_level != "info"
            or self.log_format != "text"
        ):
            return _derive_operator_settings(
                self,
                set(self._explicit_fields),
                state_dir=self.root_dir if self.root_dir != "." else None,
                config_path=self._config_path,
            )
        return self

    def validate(self) -> None:
        """Validate settings independently from argparse."""
        runtime = self._runtime_settings()
        if runtime is not self:
            runtime.validate()
            return
        if self.access not in {"private", "public", "lab"}:
            raise SettingsError("access must be private, public or lab")
        if self.https_mode not in {None, "off", "auto", "domain", "files", "self-signed"}:
            raise SettingsError("https_mode must be off, auto, domain, files or self-signed")
        if self.log_level not in {"warning", "info", "debug"}:
            raise SettingsError("log_level must be warning, info or debug")
        if self.log_format not in {"text", "json"}:
            raise SettingsError("log_format must be text or json")
        if self.acme_server is not None:
            directory = urlsplit(self.acme_server)
            if directory.scheme != "https" or not directory.hostname or directory.username:
                raise SettingsError("acme_server must be an HTTPS directory URL or staging")
        if self._derived and self.access == "private" and not _is_loopback_host(self.host):
            raise SettingsError(
                "private access requires a loopback host; choose public or lab explicitly"
            )
        if self.preset is not None and not isinstance(self.preset, LaunchPreset):
            try:
                parse_launch_preset(self.preset)
            except ValueError as exc:
                raise SettingsError(str(exc)) from None
        if not self.host:
            raise SettingsError("host must not be empty")
        if self.files_dir == "":
            raise SettingsError("files_dir must not be empty")
        _require_int_range("port", self.port, minimum=1, maximum=65535)
        _require_int_range("max_size_mb", self.max_size_mb, minimum=1)
        _require_int_range(
            "encrypted_upload_max_size_mb",
            self.encrypted_upload_max_size_mb,
            minimum=0,
            maximum=EUF_MAX_FILE_SIZE // _MIB,
        )
        _require_int_range(
            "encrypted_upload_incomplete_ttl_seconds",
            self.encrypted_upload_incomplete_ttl_seconds,
            minimum=1,
        )
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
        if self._derived and self.https_mode == "files" and not (has_cert and has_key):
            raise SettingsError("https_mode = files requires cert_file and key_file")
        if has_cert != has_key:
            raise SettingsError("--cert and --key must be provided together")
        if has_cert and (not self.cert_file or not self.key_file):
            raise SettingsError("--cert and --key values must not be empty")
        if has_cert and acme_mode:
            raise SettingsError("certificate files require https_mode = files")
        if self.letsencrypt and not self.domain and not self.sslip:
            raise SettingsError("https_mode = domain requires domain")
        if self.sslip and self.domain:
            raise SettingsError("domain requires https_mode = domain")
        if self.public_ip and not self.sslip:
            raise SettingsError("public_ip requires https_mode = auto")
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
                    raise SettingsError(f"{name} requires https_mode = auto or domain")

        if self.auth and self.auth_file:
            raise SettingsError("--auth and --auth-file cannot be combined")
        if self.auth_file == "":
            raise SettingsError("--auth-file value must not be empty")

        try:
            normalized_allowed_hosts = normalize_allowed_hosts(tuple(self.allowed_hosts))
        except (TypeError, ValueError) as exc:
            raise SettingsError(str(exc)) from None
        if self.domain and normalized_allowed_hosts:
            certificate_domain = normalize_allowed_hosts((self.domain,))[0]
            if certificate_domain not in normalized_allowed_hosts:
                raise SettingsError("certificate domain must be included in allowed_hosts")

        if self.public_direct:
            self._validate_public_direct()

    def _validate_public_direct(self) -> None:
        real_tls = bool((self.cert_file and self.key_file) or self.letsencrypt or self.sslip)
        if not real_tls:
            raise SettingsError(
                "public access requires verified HTTPS: https_mode = auto, domain or files"
            )
        if not self.auth_file:
            raise SettingsError("public access requires auth_file")
        if self.body_memory_budget_mb is None:
            raise SettingsError("public access requires body_memory_budget_mb")
        if not (
            self.upload_storage_limit_mb > 0
            or self.upload_file_limit > 0
            or self.upload_reserve_free_mb > 0
            or self.upload_quota_externally_managed
        ):
            raise SettingsError(
                "public access requires upload_storage_limit_mb, upload_file_limit, or "
                "upload_reserve_free_mb to be greater than zero unless "
                "upload_quota_externally_managed is true"
            )
        if self.body_idle_timeout <= 0 or self.body_timeout <= 0:
            raise SettingsError("public access requires enabled body timeouts")
        if self.stream_send_idle_timeout <= 0 or self.stream_send_timeout <= 0:
            raise SettingsError("public access requires enabled stream send timeouts")
        if self.cors_origin.strip() == "*":
            raise SettingsError("public access does not allow wildcard cors_origin")
        if self.plugin_allowlist and not self.plugins_allow_public_direct:
            raise SettingsError(
                "public access disables plugins unless plugins_allow_public_direct is true"
            )
        wildcard_bind = is_unspecified_host(self.host)
        if (
            wildcard_bind
            and self.cert_file
            and self.key_file
            and not normalize_allowed_hosts(tuple(self.allowed_hosts))
        ):
            raise SettingsError(
                "public access with a wildcard host and certificate files requires allowed_hosts"
            )

    def to_server_config(self) -> ServerConfig:
        """Convert operator settings to one fully resolved runtime configuration."""
        runtime = self._runtime_settings()
        if runtime is not self:
            return runtime.to_server_config()
        self.validate()
        return resolve_server_config(
            ServerConfig(
                host=self.host,
                port=self.port,
                root_dir=self.root_dir,
                files_dir=self.files_dir,
                encrypted_uploads=self.encrypted_uploads,
                limits=ServerLimits(
                    max_upload_size=self.max_size_mb * _MIB,
                    encrypted_upload_max_size=self.encrypted_upload_max_size_mb * _MIB,
                    encrypted_upload_incomplete_ttl=(self.encrypted_upload_incomplete_ttl_seconds),
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
                allowed_hosts=self.allowed_hosts,
                public_direct=self.public_direct,
                runtime_posture=self.runtime_posture(),
            )
        )

    def effective_tls_enabled(self) -> bool:
        """Return whether runtime HTTPS will be enabled after normalization."""
        runtime = self._runtime_settings()
        return runtime.tls or bool(runtime.cert_file) or runtime.letsencrypt or runtime.sslip

    def to_redacted_dict(self) -> dict[str, object]:
        """Return settings as JSON-safe data without inline secrets."""
        runtime = self._runtime_settings()
        data = {spec.name: getattr(runtime, spec.name) for spec in SETTING_SPECS}
        data["effective_tls"] = runtime.effective_tls_enabled()
        return data

    def runtime_posture(self) -> RuntimePosture:
        """Return the shared secret-free effective runtime posture."""
        return derive_runtime_posture(self._runtime_settings())


RETIRED_SETTINGS: Mapping[str, str] = {
    "preset": "access",
    "public_direct": "access",
    "tls": "https_mode",
    "letsencrypt": "https_mode",
    "sslip": "https_mode",
    "acme_staging": "acme_server",
    "auth": "auth_file / credentials reset",
    "quiet": "log_level",
    "debug": "log_level",
    "json_log": "log_format",
    "root_dir": "automatic private state",
    "open_browser": "run --open",
}
_SECTION_KEYS: Mapping[str, Mapping[str, str]] = section_key_map()
_ENV_KEYS: Mapping[str, str] = env_to_setting_map()


def load_settings_file(
    path: str | Path, *, validate: bool = True, state_dir: str | Path | None = None
) -> ServerSettings:
    config_path = Path(path).expanduser().resolve()
    try:
        text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SettingsError(f"config file does not exist: {config_path}") from None
    except OSError as exc:
        raise SettingsError(f"config file could not be read: {config_path}") from exc
    explicit_state = state_dir is not None
    if state_dir is None:
        state_dir = runtime_state_dir()
    if state_dir is None:
        state_dir = state_for_config(config_path)
    settings = load_settings_text(
        text, validate=validate, state_dir=state_dir, config_path=config_path
    )
    settings = replace(settings, _state_explicit=explicit_state)
    selected = Path(settings.files_dir or default_files_dir()).expanduser().resolve()
    if config_path.is_relative_to(selected):
        raise SettingsError("config file must be outside the public files_dir")
    return settings


def load_settings_text(
    text: str,
    *,
    validate: bool = True,
    state_dir: str | Path | None = None,
    config_path: str | Path | None = None,
) -> ServerSettings:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise SettingsError("config file is not valid INI") from exc
    if parser.defaults():
        raise SettingsError("config DEFAULT values are not supported; use named sections")
    values: dict[str, object] = {}
    for section in parser.sections():
        section_key = section.strip().lower()
        if section_key not in _SECTION_KEYS:
            raise SettingsError(f"unknown config section: {section}")
        for raw_key, raw_value in parser.items(section):
            key = raw_key.strip().lower()
            if key in RETIRED_SETTINGS:
                raise SettingsError(
                    f"removed setting {key}; use {RETIRED_SETTINGS[key]} (run config migration)"
                )
            if key not in _SECTION_KEYS[section_key]:
                raise SettingsError(f"unknown config key: {section}.{raw_key}")
            field_name = _SECTION_KEYS[section_key][key]
            values[field_name] = _parse_field_value(field_name, raw_value)
    settings = replace(
        ServerSettings(),
        **cast(Any, values),
        _explicit_fields=frozenset(values),
        _config_path=str(Path(config_path).expanduser().resolve()) if config_path else None,
    )
    if state_dir is not None:
        settings = replace(
            settings, root_dir=str(Path(state_dir).expanduser().resolve()), _state_explicit=True
        )
    if validate:
        return resolve_settings(
            file_settings=settings, state_dir=state_dir, config_path=config_path
        )
    return settings


def _derive_operator_settings(
    settings: ServerSettings,
    explicit: set[str],
    *,
    state_dir: str | Path | None = None,
    config_path: str | Path | None = None,
) -> ServerSettings:
    access = settings.access
    mode = settings.https_mode or ("auto" if access == "public" else "off")
    values: dict[str, object] = {
        "https_mode": mode,
        "public_direct": access == "public",
        "preset": None,
        "tls": mode == "self-signed",
        "letsencrypt": mode == "domain",
        "sslip": mode == "auto",
        "acme_staging": False,
        "auth": None,
        "quiet": settings.log_level == "warning",
        "debug": settings.log_level == "debug",
        "json_log": settings.log_format == "json",
        "_derived": True,
    }
    if settings.acme_server == "staging":
        from .security.tls import LE_STAGING_DIRECTORY

        values["acme_server"] = LE_STAGING_DIRECTORY
    if mode != "files" and (settings.cert_file is not None or settings.key_file is not None):
        raise SettingsError("certificate files require https_mode = files")
    if access == "public":
        defaults: dict[str, object] = {
            # guarded public-mode default.
            "host": "0.0.0.0",  # nosec B104
            "port": 8443,
            "body_memory_budget_mb": 512,
            "upload_storage_limit_mb": 4096,
            "upload_file_limit": 4096,
            "upload_reserve_free_mb": 1024,
        }
        values.update({name: value for name, value in defaults.items() if name not in explicit})
    selected_files = settings.files_dir or str(default_files_dir())
    values["files_dir"] = str(Path(selected_files).expanduser().resolve())
    values["root_dir"] = (
        str(Path(state_dir).expanduser().resolve())
        if state_dir is not None
        else str(automatic_state_dir(selected_files, config_path))
    )
    return replace(settings, **cast(Any, values))


def resolve_settings(
    *,
    file_settings: ServerSettings | None = None,
    env: dict[str, str] | None = None,
    cli_values: dict[str, object] | None = None,
    state_dir: str | Path | None = None,
    config_path: str | Path | None = None,
) -> ServerSettings:
    file_values = _file_layer_values(file_settings)
    env_values: dict[str, object] = {}
    environment = env or {}
    for name in RETIRED_SETTINGS:
        if f"XFERRY_{name.upper()}" in environment:
            raise SettingsError(
                f"removed environment setting XFERRY_{name.upper()}; use {RETIRED_SETTINGS[name]}"
            )
    for env_name, field_name in _ENV_KEYS.items():
        if env_name in environment:
            env_values[field_name] = _parse_field_value(field_name, environment[env_name])
    cli = dict(cli_values or {})
    removed = set(cli) & set(RETIRED_SETTINGS)
    if removed:
        name = sorted(removed)[0]
        raise SettingsError(f"removed setting {name}; use {RETIRED_SETTINGS[name]}")
    unknown = set(cli) - set(SETTING_SPEC_BY_NAME)
    if unknown:
        raise SettingsError(f"unknown setting: {sorted(unknown)[0]}")
    values: dict[str, object] = {}
    origins = {spec.name: "default" for spec in SETTING_SPECS}
    for layer, origin in ((file_values, "file"), (env_values, "environment"), (cli, "cli")):
        values.update(layer)
        origins.update(dict.fromkeys(layer, origin))
    explicit = set(values)
    # State injection is internal and unavailable through operator configuration.
    inherited_state = state_dir
    explicit_state = state_dir is not None or bool(file_settings and file_settings._state_explicit)
    if inherited_state is None and file_settings is not None and file_settings._state_explicit:
        inherited_state = file_settings.root_dir
    if inherited_state is None:
        inherited_state = runtime_state_dir()
    if inherited_state is None and file_settings is not None and file_settings.root_dir != ".":
        inherited_state = file_settings.root_dir
    settings = replace(
        ServerSettings(),
        **cast(Any, values),
        _explicit_fields=frozenset(explicit),
        _origins=origins,
        _state_explicit=explicit_state,
        _config_path=(
            str(config_path)
            if config_path is not None
            else file_settings._config_path
            if file_settings is not None
            else None
        ),
    )
    settings = _derive_operator_settings(
        settings, explicit, state_dir=inherited_state, config_path=settings._config_path
    )
    for name in (
        "host",
        "port",
        "body_memory_budget_mb",
        "upload_storage_limit_mb",
        "upload_file_limit",
        "upload_reserve_free_mb",
    ):
        if settings.access == "public" and name not in explicit:
            origins[name] = "automatic"
    if "https_mode" not in explicit:
        origins["https_mode"] = "automatic"
    settings.validate()
    return settings


def render_settings_ini(
    *,
    target: SampleTarget | str,
    values: Mapping[str, object],
    field_names: Iterable[str] | None = None,
    comments: Mapping[str, Iterable[str]] | None = None,
) -> str:
    """Render a deterministic schema-backed INI fragment.

    ``field_names`` lets managed setup select a validated dynamic subset while
    retaining the schema's section/key order. Every selected field must be
    present on the chosen target; callers cannot use this helper to bypass a
    target's explicit omission policy.
    """
    resolved_target = get_sample_target(target)
    defaults = ServerSettings()
    requested = (
        {spec.name for spec in sample_specs(resolved_target)}
        if field_names is None
        else set(field_names)
    )
    unknown = requested - set(SETTING_SPEC_BY_NAME)
    if unknown:
        raise ValueError(f"unknown settings fields for rendering: {sorted(unknown)}")
    omitted = {
        name
        for name in requested
        if SETTING_SPEC_BY_NAME[name].sample_disposition(resolved_target.name) == "omitted"
    }
    if omitted:
        raise ValueError(
            f"settings fields are omitted from {resolved_target.name}: {sorted(omitted)}"
        )

    comment_overrides = dict(resolved_target.comment_map())
    if comments is not None:
        comment_overrides.update(
            {name: tuple(field_comments) for name, field_comments in comments.items()}
        )
    lines: list[str] = []
    for section in resolved_target.section_order:
        section_specs = [
            spec
            for spec in sample_specs(resolved_target)
            if spec.section == section and spec.name in requested
        ]
        if not section_specs:
            continue
        if lines:
            lines.append("")
        lines.append(f"[{section}]")
        for spec in section_specs:
            field_comments = comment_overrides.get(
                spec.name,
                spec.sample_comments if resolved_target.include_setting_comments else (),
            )
            for comment in field_comments:
                lines.append(f"# {comment}")
            value = values.get(spec.name, getattr(defaults, spec.name))
            disposition = spec.sample_disposition(resolved_target.name)
            lines.append(
                render_ini_entry(
                    spec.name,
                    value,
                    commented=disposition == "commented",
                )
            )
    return "\n".join(lines) + "\n"


def render_sample_profile(profile: SampleProfile | str) -> str:
    """Render one complete static sample profile without a human preamble."""
    resolved = get_sample_profile(profile)
    return render_settings_ini(target=resolved.target, values=resolved.value_map())


def public_direct_sample_ini(
    *,
    root_dir: str = "/var/lib/xferry",
    port: int = 8443,
    auth_file: str = "/etc/xferry/auth",
    acme_http_port: int | None = None,
    allowed_hosts_comment: str | None = None,
    tls_comments: tuple[str, ...] | None = None,
) -> str:
    """Return the main or deployment public-direct INI body.

    The main generated sample omits ``acme_http_port`` and therefore follows
    the runtime default. Passing a port selects the deployment surface, where
    that listener mapping must be explicit (Docker uses 8080; systemd uses 80).
    """
    base_profile = get_sample_profile("public-direct")
    values: dict[str, object] = {
        **base_profile.value_map(),
        "files_dir": str(Path(root_dir) / "files"),
        "port": port,
        "auth_file": auth_file,
    }
    target = "public-direct"
    if acme_http_port is not None:
        values["acme_http_port"] = acme_http_port
        # Docker and systemd share the same field layout. Callers replace the
        # target-specific comments below, so the Docker layout is sufficient
        # for this parameterized compatibility API.
        target = "docker"
    comments: dict[str, tuple[str, ...]] = {}
    if allowed_hosts_comment is not None:
        comments["allowed_hosts"] = (allowed_hosts_comment,)
    if tls_comments is not None:
        comments["https_mode"] = tls_comments
    return render_settings_ini(
        target=target,
        values=values,
        comments=comments,
    )


def sample_config_text() -> str:
    """Return a public-direct sample configuration."""
    return "# xferry public-direct sample configuration\n" + public_direct_sample_ini()


def _parse_field_value(field_name: str, raw_value: object) -> object:
    if raw_value is None:
        return None
    value = str(raw_value).strip()
    value_kind = SETTING_SPEC_BY_NAME[field_name].value_kind
    if value_kind == "choice":
        spec = SETTING_SPEC_BY_NAME[field_name]
        choices = spec.cli.choices if spec.cli else ()
        if value not in choices:
            raise SettingsError(f"{field_name} must be one of: {', '.join(choices)}")
        return value
    if value_kind == "boolean":
        return _parse_bool(field_name, value)
    if value_kind in {"integer", "optional_integer"}:
        if value == "" and value_kind == "optional_integer":
            return None
        try:
            return int(value, 10)
        except ValueError:
            raise SettingsError(f"{field_name} must be an integer") from None
    if value_kind == "number":
        try:
            return float(value)
        except ValueError:
            raise SettingsError(f"{field_name} must be a number") from None
    if value_kind == "plugin_allowlist":
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if value_kind == "allowed_hosts":
        return tuple(part for part in re.split(r"[ \t\r\n\f\v]+", value) if part)
    if value == "" and value_kind == "optional_string":
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
        if field_name not in SETTING_SPEC_BY_NAME:
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


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


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
    "public_direct_sample_ini",
    "render_sample_profile",
    "render_settings_ini",
    "resolve_settings",
    "sample_config_text",
]
