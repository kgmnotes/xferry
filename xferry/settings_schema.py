"""Canonical metadata for every operator-facing setting.

Runtime defaults and validation intentionally remain in
``xferry.settings.ServerSettings``. This module contains only stdlib-backed
descriptions of the INI, environment, CLI, redaction, and generated-sample
surfaces, so tooling can import it without importing the server runtime.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Literal

SettingValueKind = Literal[
    "allowed_hosts",
    "boolean",
    "integer",
    "number",
    "optional_integer",
    "optional_string",
    "plugin_allowlist",
    "preset",
    "string",
]
CliAction = Literal["append", "boolean_optional", "store", "store_true"]
CliGroup = Literal["Configuration", "Basic", "Modes", "Limits", "TLS", "Authentication"]
CliParserKind = Literal["integer", "number"]
RedactionClass = Literal["none", "secret"]
SampleDisposition = Literal["active", "commented", "omitted"]
SampleScalar = str | int | float | bool | None

SETTINGS_SECTION_ORDER = ("server", "limits", "tls", "security", "cors", "plugins")
SAMPLE_TARGET_NAMES = ("public-direct", "docker", "systemd", "managed")
SAMPLE_PROFILE_NAMES = ("public-direct", "docker", "systemd")
CLI_GROUP_ORDER: tuple[CliGroup, ...] = (
    "Configuration",
    "Basic",
    "Modes",
    "Limits",
    "TLS",
    "Authentication",
)
NO_CLI_SETTING_NAMES = frozenset(
    {
        "public_direct",
        "plugin_allowlist",
        "plugins_allow_public_direct",
        "plugins_override_core",
    }
)


@dataclass(frozen=True, slots=True)
class CliSpec:
    """Exact argparse declaration for one settings option."""

    option_strings: tuple[str, ...]
    dest: str
    group: CliGroup
    help: str
    action: CliAction = "store"
    metavar: str | None = None
    parser_kind: CliParserKind | None = None
    parser_label: str | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    choices: tuple[str, ...] = ()
    normal_help: bool = False
    default_from_runtime: bool = True


@dataclass(frozen=True, slots=True)
class SettingSpec:
    """External-surface metadata for one public ``ServerSettings`` field."""

    name: str
    section: str
    value_kind: SettingValueKind
    redaction: RedactionClass
    cli: CliSpec | None
    sample_dispositions: tuple[
        SampleDisposition,
        SampleDisposition,
        SampleDisposition,
        SampleDisposition,
    ]
    sample_comments: tuple[str, ...] = ()

    @property
    def ini_key(self) -> str:
        """Return the canonical INI key."""
        return self.name

    @property
    def env_name(self) -> str:
        """Return the canonical environment variable name."""
        return f"XFERRY_{self.name.upper()}"

    @property
    def cli_dest(self) -> str | None:
        """Return the argparse destination, if one exists."""
        return None if self.cli is None else self.cli.dest

    @property
    def cli_flags(self) -> tuple[str, ...]:
        """Return declared argparse flags, excluding derived ``--no-*`` flags."""
        return () if self.cli is None else self.cli.option_strings

    def sample_disposition(self, target: str) -> SampleDisposition:
        """Return this field's explicit disposition for a sample target."""
        try:
            index = SAMPLE_TARGET_NAMES.index(target)
        except ValueError:
            choices = ", ".join(SAMPLE_TARGET_NAMES)
            raise ValueError(
                f"unknown settings sample target {target!r}; choose one of: {choices}"
            ) from None
        return self.sample_dispositions[index]

    @property
    def public_direct_sample(self) -> bool:
        """Compatibility view for the main public-direct sample."""
        return self.sample_disposition("public-direct") != "omitted"


@dataclass(frozen=True, slots=True)
class SampleTarget:
    """Deterministic field/section ordering for one generated surface."""

    name: str
    section_order: tuple[str, ...]
    field_order: tuple[str, ...]
    include_setting_comments: bool = True
    comment_overrides: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def comment_map(self) -> Mapping[str, tuple[str, ...]]:
        """Return immutable per-target comment replacements."""
        return MappingProxyType(dict(self.comment_overrides))


@dataclass(frozen=True, slots=True)
class SampleProfile:
    """Immutable value overrides for a static generated sample."""

    name: str
    target: str
    values: tuple[tuple[str, SampleScalar], ...]

    def value_map(self) -> Mapping[str, SampleScalar]:
        """Return an immutable name-to-value view."""
        return MappingProxyType(dict(self.values))


def _c(
    *option_strings: str,
    dest: str,
    group: CliGroup,
    help: str,
    action: CliAction = "store",
    metavar: str | None = None,
    parser_kind: CliParserKind | None = None,
    parser_label: str | None = None,
    minimum: int | float | None = None,
    maximum: int | float | None = None,
    choices: tuple[str, ...] = (),
    normal_help: bool = False,
    default_from_runtime: bool = True,
) -> CliSpec:
    return CliSpec(
        option_strings=option_strings,
        dest=dest,
        group=group,
        help=help,
        action=action,
        metavar=metavar,
        parser_kind=parser_kind,
        parser_label=parser_label,
        minimum=minimum,
        maximum=maximum,
        choices=choices,
        normal_help=normal_help,
        default_from_runtime=default_from_runtime,
    )


_CLI_ROWS: tuple[tuple[str, CliSpec], ...] = (
    (
        "preset",
        _c(
            "--preset",
            dest="preset",
            group="Configuration",
            choices=("local", "local-secure", "public-direct"),
            help="Select journey defaults below every explicit file/env/CLI value",
            normal_help=True,
        ),
    ),
    (
        "host",
        _c(
            "-H",
            "--host",
            dest="host",
            group="Basic",
            metavar="HOST",
            help="Bind host (default: {default})",
            normal_help=True,
        ),
    ),
    (
        "port",
        _c(
            "-p",
            "--port",
            dest="port",
            group="Basic",
            metavar="PORT",
            parser_kind="integer",
            parser_label="port",
            minimum=1,
            maximum=65535,
            help="Listen port (default: {default})",
            normal_help=True,
        ),
    ),
    (
        "root_dir",
        _c(
            "-d",
            "--dir",
            dest="dir",
            group="Basic",
            metavar="DIR",
            help="Root directory (default: current)",
            normal_help=True,
        ),
    ),
    (
        "quiet",
        _c(
            "-q",
            "--quiet",
            dest="quiet",
            group="Modes",
            action="store_true",
            help="Quiet mode (minimal logging)",
        ),
    ),
    (
        "debug",
        _c(
            "--debug",
            dest="debug",
            group="Modes",
            action="store_true",
            help="Debug mode (verbose logging)",
        ),
    ),
    (
        "open_browser",
        _c(
            "--open",
            dest="open",
            group="Modes",
            action="store_true",
            help="Open browser after start",
            normal_help=True,
        ),
    ),
    (
        "json_log",
        _c(
            "--json-log",
            dest="json_log",
            group="Modes",
            action="store_true",
            help="Structured JSON log format",
        ),
    ),
    (
        "max_size_mb",
        _c(
            "-m",
            "--max-size",
            dest="max_size",
            group="Limits",
            metavar="MB",
            parser_kind="integer",
            parser_label="max size",
            minimum=1,
            help="Max per-request upload body size in MB (default: {default})",
        ),
    ),
    (
        "upload_storage_limit_mb",
        _c(
            "--upload-storage-limit",
            dest="upload_storage_limit",
            group="Limits",
            metavar="MB",
            parser_kind="integer",
            parser_label="upload storage limit",
            minimum=0,
            help="Aggregate uploads/ storage quota in MB; 0 disables (default: {default})",
        ),
    ),
    (
        "upload_file_limit",
        _c(
            "--upload-file-limit",
            dest="upload_file_limit",
            group="Limits",
            metavar="N",
            parser_kind="integer",
            parser_label="upload file limit",
            minimum=0,
            help="Aggregate uploads/ file count quota; 0 disables (default: {default})",
        ),
    ),
    (
        "upload_reserve_free_mb",
        _c(
            "--upload-reserve-free",
            dest="upload_reserve_free",
            group="Limits",
            metavar="MB",
            parser_kind="integer",
            parser_label="upload reserve free",
            minimum=0,
            help=(
                "Minimum free disk space to preserve while committing uploads in MB "
                "(default: {default})"
            ),
        ),
    ),
    (
        "upload_quota_externally_managed",
        _c(
            "--upload-quota-externally-managed",
            dest="upload_quota_externally_managed",
            group="Limits",
            action="boolean_optional",
            help=(
                "Acknowledge that upload disk capacity is enforced outside xferry; "
                "required for public-direct only when all app upload disk controls are disabled"
            ),
        ),
    ),
    (
        "note_storage_limit_mb",
        _c(
            "--note-storage-limit",
            dest="note_storage_limit",
            group="Limits",
            metavar="MB",
            parser_kind="integer",
            parser_label="note storage limit",
            minimum=0,
            help="Aggregate encrypted notes/ blob quota in MB; 0 disables (default: {default})",
        ),
    ),
    (
        "note_count_limit",
        _c(
            "--note-count-limit",
            dest="note_count_limit",
            group="Limits",
            metavar="N",
            parser_kind="integer",
            parser_label="note count limit",
            minimum=0,
            help="Aggregate encrypted note count quota; 0 disables (default: {default})",
        ),
    ),
    (
        "smuggle_temp_age",
        _c(
            "--smuggle-temp-age",
            dest="smuggle_temp_age",
            group="Limits",
            metavar="SECONDS",
            parser_kind="integer",
            parser_label="SMUGGLE temp max age",
            minimum=0,
            help=(
                "Max age for retained SMUGGLE temp pages in seconds; 0 disables "
                "(default: {default})"
            ),
        ),
    ),
    (
        "smuggle_temp_file_limit",
        _c(
            "--smuggle-temp-file-limit",
            dest="smuggle_temp_file_limit",
            group="Limits",
            metavar="N",
            parser_kind="integer",
            parser_label="SMUGGLE temp file limit",
            minimum=0,
            help="Max retained SMUGGLE temp page count; 0 disables (default: {default})",
        ),
    ),
    (
        "smuggle_temp_storage_limit_mb",
        _c(
            "--smuggle-temp-storage-limit",
            dest="smuggle_temp_storage_limit",
            group="Limits",
            metavar="MB",
            parser_kind="integer",
            parser_label="SMUGGLE temp storage limit",
            minimum=0,
            help="Max retained SMUGGLE temp page bytes in MB; 0 disables (default: {default})",
        ),
    ),
    (
        "max_header_size_kb",
        _c(
            "--max-header-size",
            dest="max_header_size",
            group="Limits",
            metavar="KB",
            parser_kind="integer",
            parser_label="max header size",
            minimum=1,
            help="Max HTTP request header size in KiB (default: {default})",
        ),
    ),
    (
        "body_memory_budget_mb",
        _c(
            "--body-memory-budget",
            dest="body_memory_budget",
            group="Limits",
            metavar="MB",
            parser_kind="integer",
            parser_label="body memory budget",
            minimum=1,
            help=(
                "Admission budget for aggregate in-flight request bodies in MB, not an "
                "RSS ceiling (default: workers * max size)"
            ),
        ),
    ),
    (
        "body_idle_timeout",
        _c(
            "--body-idle-timeout",
            dest="body_idle_timeout",
            group="Limits",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="body idle timeout",
            minimum=0,
            help="Max idle seconds between request body chunks; 0 disables (default: {default})",
        ),
    ),
    (
        "body_timeout",
        _c(
            "--body-timeout",
            dest="body_timeout",
            group="Limits",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="body timeout",
            minimum=0,
            help=(
                "Max seconds to receive a request body after headers; 0 disables "
                "(default: {default})"
            ),
        ),
    ),
    (
        "body_min_rate",
        _c(
            "--body-min-rate",
            dest="body_min_rate",
            group="Limits",
            metavar="BYTES_PER_SECOND",
            parser_kind="number",
            parser_label="body minimum read rate",
            minimum=0,
            help=(
                "Minimum average request body read rate in bytes/s; 0 disables (default: {default})"
            ),
        ),
    ),
    (
        "stream_send_idle_timeout",
        _c(
            "--stream-send-idle-timeout",
            dest="stream_send_idle_timeout",
            group="Limits",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="stream send idle timeout",
            minimum=0.001,
            help="Max seconds a streamed response send may block per chunk (default: {default})",
        ),
    ),
    (
        "stream_send_timeout",
        _c(
            "--stream-send-timeout",
            dest="stream_send_timeout",
            group="Limits",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="stream send timeout",
            minimum=0,
            help=(
                "Max total seconds for a streamed response transfer; 0 disables "
                "(default: {default})"
            ),
        ),
    ),
    (
        "max_websocket_connections",
        _c(
            "--max-websocket-connections",
            dest="max_websocket_connections",
            group="Limits",
            metavar="N",
            parser_kind="integer",
            parser_label="max websocket connections",
            minimum=0,
            help=(
                "Max active WebSocket connections; each occupies a worker and 0 rejects "
                "all (default: workers // 2)"
            ),
        ),
    ),
    (
        "websocket_frame_idle_timeout",
        _c(
            "--websocket-frame-idle-timeout",
            dest="websocket_frame_idle_timeout",
            group="Limits",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="websocket frame idle timeout",
            minimum=0.001,
            help=(
                "Max idle seconds while waiting for the rest of an incomplete WebSocket frame "
                "(default: {default})"
            ),
        ),
    ),
    (
        "workers",
        _c(
            "-w",
            "--workers",
            dest="workers",
            group="Limits",
            metavar="N",
            parser_kind="integer",
            parser_label="workers",
            minimum=1,
            help="Number of worker threads (default: {default})",
        ),
    ),
    (
        "tls",
        _c(
            "--tls",
            dest="tls",
            group="TLS",
            action="boolean_optional",
            help="Enable HTTPS with a generated self-signed certificate",
            normal_help=True,
        ),
    ),
    (
        "cert_file",
        _c(
            "--cert",
            dest="cert",
            group="TLS",
            metavar="FILE",
            help="Path to certificate file (PEM)",
        ),
    ),
    (
        "key_file",
        _c(
            "--key",
            dest="key",
            group="TLS",
            metavar="FILE",
            help="Path to private key file (PEM)",
        ),
    ),
    (
        "letsencrypt",
        _c(
            "--letsencrypt",
            dest="letsencrypt",
            group="TLS",
            action="store_true",
            help="Obtain Let's Encrypt certificate with built-in ACME HTTP-01",
        ),
    ),
    (
        "domain",
        _c(
            "--domain",
            dest="domain",
            group="TLS",
            metavar="DOMAIN",
            help="Domain for Let's Encrypt certificate",
        ),
    ),
    (
        "email",
        _c(
            "--email",
            dest="email",
            group="TLS",
            metavar="EMAIL",
            help="Email for Let's Encrypt notifications (optional)",
        ),
    ),
    (
        "sslip",
        _c(
            "--sslip",
            dest="sslip",
            group="TLS",
            action="store_true",
            help="Obtain a Let's Encrypt certificate for the public IPv4 sslip.io hostname",
        ),
    ),
    (
        "public_ip",
        _c(
            "--public-ip",
            dest="public_ip",
            group="TLS",
            metavar="IP",
            help="Public IPv4 override for --sslip (default: auto-detect)",
        ),
    ),
    (
        "acme_staging",
        _c(
            "--acme-staging",
            dest="acme_staging",
            group="TLS",
            action="store_true",
            help="Use Let's Encrypt staging ACME directory",
        ),
    ),
    (
        "acme_server",
        _c(
            "--acme-server",
            dest="acme_server",
            group="TLS",
            metavar="URL",
            help="Custom ACME directory URL (overrides --acme-staging)",
        ),
    ),
    (
        "acme_http_address",
        _c(
            "--acme-http-address",
            dest="acme_http_address",
            group="TLS",
            metavar="ADDR",
            help="Bind address for HTTP-01 challenge server (default: all interfaces)",
        ),
    ),
    (
        "acme_http_port",
        _c(
            "--acme-http-port",
            dest="acme_http_port",
            group="TLS",
            metavar="PORT",
            parser_kind="integer",
            parser_label="ACME HTTP port",
            minimum=1,
            maximum=65535,
            help="Bind port for HTTP-01 challenge server (default: {default})",
        ),
    ),
    (
        "auth",
        _c(
            "--auth",
            dest="auth",
            group="Authentication",
            metavar="CREDS",
            help="Basic Auth: 'user:pass', 'random', or 'user' (random password)",
            normal_help=True,
        ),
    ),
    (
        "auth_file",
        _c(
            "--auth-file",
            dest="auth_file",
            group="Authentication",
            metavar="FILE",
            help="Read Basic Auth credentials from one user:pass line in FILE",
            normal_help=True,
        ),
    ),
    (
        "allowed_hosts",
        _c(
            "--allowed-host",
            dest="allowed_host",
            group="Authentication",
            action="append",
            metavar="HOST",
            help="Admit this Host/IP (repeatable; replaces file/env list)",
            normal_help=True,
            default_from_runtime=False,
        ),
    ),
    (
        "cors_origin",
        _c(
            "--cors-origin",
            dest="cors_origin",
            group="Modes",
            metavar="ORIGIN",
            help="Enable CORS for an explicit origin (default: disabled)",
        ),
    ),
)
_CLI_SPEC_BY_SETTING: Mapping[str, CliSpec] = MappingProxyType(dict(_CLI_ROWS))


def _s(
    name: str,
    section: str,
    value_kind: SettingValueKind,
    redaction: RedactionClass,
    samples: tuple[
        SampleDisposition,
        SampleDisposition,
        SampleDisposition,
        SampleDisposition,
    ],
    comments: tuple[str, ...] = (),
) -> SettingSpec:
    return SettingSpec(
        name=name,
        section=section,
        value_kind=value_kind,
        redaction=redaction,
        cli=_CLI_SPEC_BY_SETTING.get(name),
        sample_dispositions=samples,
        sample_comments=comments,
    )


# Sample tuple positions are explicit and fixed as:
# public-direct, Docker, systemd, managed setup.
SETTING_SPECS: tuple[SettingSpec, ...] = (
    _s("preset", "server", "preset", "none", ("active", "active", "active", "active")),
    _s("host", "server", "string", "none", ("active", "active", "active", "active")),
    _s("port", "server", "integer", "none", ("active", "active", "active", "active")),
    _s("root_dir", "server", "string", "none", ("active", "active", "active", "active")),
    _s("quiet", "server", "boolean", "none", ("omitted", "omitted", "omitted", "omitted")),
    _s("debug", "server", "boolean", "none", ("omitted", "omitted", "omitted", "omitted")),
    _s(
        "open_browser",
        "server",
        "boolean",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s("json_log", "server", "boolean", "none", ("active", "active", "active", "omitted")),
    _s(
        "public_direct",
        "server",
        "boolean",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "max_size_mb",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "upload_storage_limit_mb",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "upload_file_limit",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "omitted"),
    ),
    _s(
        "upload_reserve_free_mb",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "upload_quota_externally_managed",
        "limits",
        "boolean",
        "none",
        ("active", "active", "active", "omitted"),
    ),
    _s(
        "note_storage_limit_mb",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "note_count_limit",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "smuggle_temp_age",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "smuggle_temp_file_limit",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "smuggle_temp_storage_limit_mb",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "max_header_size_kb",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "body_memory_budget_mb",
        "limits",
        "optional_integer",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "body_idle_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "body_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "body_min_rate",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "omitted"),
    ),
    _s(
        "stream_send_idle_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "stream_send_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "max_websocket_connections",
        "limits",
        "optional_integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "websocket_frame_idle_timeout",
        "limits",
        "number",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s("workers", "server", "integer", "none", ("active", "active", "active", "active")),
    _s("tls", "tls", "boolean", "none", ("omitted", "omitted", "omitted", "omitted")),
    _s("cert_file", "tls", "string", "none", ("omitted", "omitted", "omitted", "omitted")),
    _s("key_file", "tls", "string", "none", ("omitted", "omitted", "omitted", "omitted")),
    _s(
        "letsencrypt",
        "tls",
        "boolean",
        "none",
        ("omitted", "omitted", "omitted", "active"),
    ),
    _s(
        "domain",
        "tls",
        "optional_string",
        "none",
        ("omitted", "omitted", "omitted", "active"),
    ),
    _s(
        "email",
        "tls",
        "optional_string",
        "none",
        ("omitted", "omitted", "omitted", "active"),
    ),
    _s(
        "sslip",
        "tls",
        "boolean",
        "none",
        ("active", "active", "active", "active"),
        (
            "Runtime TLS becomes active through sslip/letsencrypt/cert+key even if",
            "the explicit self-signed `tls` flag remains false in normalized output.",
            "Use sslip for first-run public IPv4 deployments, or replace with:",
            "letsencrypt = true",
            "domain = files.example.com",
        ),
    ),
    _s(
        "public_ip",
        "tls",
        "optional_string",
        "none",
        ("commented", "commented", "commented", "active"),
    ),
    _s(
        "acme_staging",
        "tls",
        "boolean",
        "none",
        ("commented", "commented", "commented", "omitted"),
    ),
    _s(
        "acme_server",
        "tls",
        "optional_string",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "acme_http_address",
        "tls",
        "string",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "acme_http_port",
        "tls",
        "integer",
        "none",
        ("omitted", "active", "active", "active"),
    ),
    _s(
        "auth",
        "security",
        "optional_string",
        "secret",
        ("omitted", "omitted", "omitted", "omitted"),
    ),
    _s(
        "auth_file",
        "security",
        "optional_string",
        "none",
        ("active", "active", "active", "active"),
    ),
    _s(
        "allowed_hosts",
        "security",
        "allowed_hosts",
        "none",
        ("active", "active", "active", "active"),
        ("ASCII-whitespace-separated host/IP values; empty uses listener auto-mode.",),
    ),
    _s(
        "cors_origin",
        "cors",
        "string",
        "none",
        ("active", "active", "active", "omitted"),
    ),
    _s(
        "plugin_allowlist",
        "plugins",
        "plugin_allowlist",
        "none",
        ("active", "active", "active", "omitted"),
    ),
    _s(
        "plugins_allow_public_direct",
        "plugins",
        "boolean",
        "none",
        ("active", "active", "active", "omitted"),
    ),
    _s(
        "plugins_override_core",
        "plugins",
        "boolean",
        "none",
        ("active", "active", "active", "omitted"),
    ),
)


_STATIC_FIELD_ORDER = (
    "preset",
    "host",
    "port",
    "root_dir",
    "public_direct",
    "json_log",
    "workers",
    "auth_file",
    "allowed_hosts",
    "sslip",
    "public_ip",
    "acme_staging",
    "acme_http_port",
    "max_size_mb",
    "body_memory_budget_mb",
    "body_idle_timeout",
    "body_timeout",
    "body_min_rate",
    "stream_send_idle_timeout",
    "stream_send_timeout",
    "upload_storage_limit_mb",
    "upload_file_limit",
    "upload_reserve_free_mb",
    "upload_quota_externally_managed",
    "cors_origin",
    "plugin_allowlist",
    "plugins_allow_public_direct",
    "plugins_override_core",
)
_PUBLIC_DIRECT_FIELD_ORDER = tuple(
    field_name for field_name in _STATIC_FIELD_ORDER if field_name != "acme_http_port"
)
_MANAGED_FIELD_ORDER = (
    "host",
    "port",
    "root_dir",
    "workers",
    "preset",
    "public_direct",
    "auth_file",
    "allowed_hosts",
    "max_size_mb",
    "body_memory_budget_mb",
    "upload_storage_limit_mb",
    "upload_reserve_free_mb",
    "body_idle_timeout",
    "body_timeout",
    "stream_send_idle_timeout",
    "stream_send_timeout",
    "letsencrypt",
    "sslip",
    "public_ip",
    "domain",
    "email",
    "acme_http_port",
)
_STATIC_SECTION_ORDER = ("server", "security", "tls", "limits", "cors", "plugins")
SAMPLE_TARGETS: tuple[SampleTarget, ...] = (
    SampleTarget("public-direct", _STATIC_SECTION_ORDER, _PUBLIC_DIRECT_FIELD_ORDER),
    SampleTarget(
        "docker",
        _STATIC_SECTION_ORDER,
        _STATIC_FIELD_ORDER,
        comment_overrides=(
            (
                "allowed_hosts",
                ("Auto-mode admits loopback plus the final sslip certificate hostname.",),
            ),
            (
                "sslip",
                (
                    "Runtime TLS becomes active through sslip/letsencrypt/cert+key even if",
                    "the explicit self-signed `tls` flag remains false in normalized output.",
                ),
            ),
        ),
    ),
    SampleTarget(
        "systemd",
        _STATIC_SECTION_ORDER,
        _STATIC_FIELD_ORDER,
        comment_overrides=(
            (
                "allowed_hosts",
                ("Auto-mode admits loopback plus the final sslip certificate hostname.",),
            ),
            (
                "sslip",
                (
                    "Runtime TLS becomes active through sslip/letsencrypt/cert+key even if",
                    "the explicit self-signed `tls` flag remains false in normalized output.",
                    "First-run public IPv4 option. For a real domain, replace sslip with:",
                    "letsencrypt = true",
                    "domain = files.example.com",
                ),
            ),
        ),
    ),
    SampleTarget(
        "managed",
        ("server", "security", "limits", "tls", "cors", "plugins"),
        _MANAGED_FIELD_ORDER,
        include_setting_comments=False,
    ),
)

_COMMON_PROFILE_VALUES: tuple[tuple[str, SampleScalar], ...] = (
    ("preset", "public-direct"),
    ("host", "0.0.0.0"),  # nosec B104 - documented public-direct sample.
    ("public_direct", True),
    ("json_log", True),
    ("body_memory_budget_mb", 512),
    ("upload_storage_limit_mb", 4096),
    ("upload_file_limit", 4096),
    ("upload_reserve_free_mb", 1024),
    ("sslip", True),
    ("public_ip", "203.0.113.10"),
    ("acme_staging", True),
)


def _profile(
    name: str,
    *,
    root_dir: str,
    port: int,
    auth_file: str,
    acme_http_port: int | None,
) -> SampleProfile:
    specific: tuple[tuple[str, SampleScalar], ...] = (
        ("root_dir", root_dir),
        ("port", port),
        ("auth_file", auth_file),
    )
    if acme_http_port is not None:
        specific = (*specific, ("acme_http_port", acme_http_port))
    return SampleProfile(name=name, target=name, values=(*_COMMON_PROFILE_VALUES, *specific))


SAMPLE_PROFILES: tuple[SampleProfile, ...] = (
    _profile(
        "public-direct",
        root_dir="/var/lib/xferry",
        port=8443,
        auth_file="/etc/xferry/auth",
        acme_http_port=None,
    ),
    _profile(
        "docker",
        root_dir="/data",
        port=8443,
        auth_file="/run/secrets/xferry_auth",
        acme_http_port=8080,
    ),
    _profile(
        "systemd",
        root_dir="/var/lib/xferry",
        port=443,
        auth_file="/etc/xferry/auth",
        acme_http_port=80,
    ),
)


def _accepted_cli_flags(cli: CliSpec) -> tuple[str, ...]:
    flags = list(cli.option_strings)
    if cli.action == "boolean_optional":
        flags.extend(f"--no-{flag[2:]}" for flag in cli.option_strings if flag.startswith("--"))
    return tuple(flags)


def _validate_specs(specs: Iterable[SettingSpec]) -> None:
    names: set[str] = set()
    env_names: set[str] = set()
    cli_dests: set[str] = set()
    cli_flags: set[str] = set()
    no_cli_names: set[str] = set()
    for spec in specs:
        if spec.section not in SETTINGS_SECTION_ORDER:
            raise ValueError(f"unknown settings section: {spec.section}")
        if spec.name in names:
            raise ValueError(f"duplicate setting name: {spec.name}")
        if spec.env_name in env_names:
            raise ValueError(f"duplicate environment setting: {spec.env_name}")
        if len(spec.sample_dispositions) != len(SAMPLE_TARGET_NAMES):
            raise ValueError(f"incomplete sample dispositions: {spec.name}")

        cli = spec.cli
        if cli is None:
            no_cli_names.add(spec.name)
        else:
            if not cli.option_strings:
                raise ValueError(f"missing CLI option strings: {spec.name}")
            if cli.dest in cli_dests:
                raise ValueError(f"duplicate CLI destination: {cli.dest}")
            accepted_flags = _accepted_cli_flags(cli)
            if cli_flags.intersection(accepted_flags):
                raise ValueError(f"duplicate CLI option string: {spec.name}")
            if cli.parser_kind is not None and cli.parser_label is None:
                raise ValueError(f"missing CLI parser label: {spec.name}")
            if cli.parser_kind is None and (cli.minimum is not None or cli.maximum is not None):
                raise ValueError(f"CLI bounds without a parser: {spec.name}")
            if cli.action in {"boolean_optional", "store_true"} and (
                cli.metavar is not None or cli.parser_kind is not None or cli.choices
            ):
                raise ValueError(f"value metadata on non-store CLI action: {spec.name}")
            cli_dests.add(cli.dest)
            cli_flags.update(accepted_flags)

        names.add(spec.name)
        env_names.add(spec.env_name)

    if set(_CLI_SPEC_BY_SETTING) - names:
        raise ValueError("CLI metadata references unknown settings")
    if no_cli_names != set(NO_CLI_SETTING_NAMES):
        mismatch = sorted(no_cli_names ^ set(NO_CLI_SETTING_NAMES))
        raise ValueError(f"settings without CLI metadata differ from the allowlist: {mismatch}")


def _validate_targets(targets: Iterable[SampleTarget], specs: Iterable[SettingSpec]) -> None:
    spec_map = {spec.name: spec for spec in specs}
    seen: set[str] = set()
    for target in targets:
        if target.name in seen:
            raise ValueError(f"duplicate sample target: {target.name}")
        if len(target.field_order) != len(set(target.field_order)):
            raise ValueError(f"duplicate field in sample target: {target.name}")
        unknown = set(target.field_order) - set(spec_map)
        if unknown:
            raise ValueError(f"unknown fields in sample target {target.name}: {sorted(unknown)}")
        present = {spec.name for spec in specs if spec.sample_disposition(target.name) != "omitted"}
        if present != set(target.field_order):
            mismatch = sorted(present ^ set(target.field_order))
            raise ValueError(
                f"sample target order/dispositions differ for {target.name}: {mismatch}"
            )
        if set(target.section_order) != set(SETTINGS_SECTION_ORDER):
            raise ValueError(f"incomplete section order for sample target: {target.name}")
        seen.add(target.name)
    if seen != set(SAMPLE_TARGET_NAMES):
        raise ValueError("sample targets differ from SAMPLE_TARGET_NAMES")


def _validate_profiles(profiles: Iterable[SampleProfile]) -> None:
    known_names = {spec.name for spec in SETTING_SPECS}
    profile_names: set[str] = set()
    for profile in profiles:
        if profile.name in profile_names:
            raise ValueError(f"duplicate sample profile: {profile.name}")
        value_names = [name for name, _value in profile.values]
        if len(value_names) != len(set(value_names)):
            raise ValueError(f"duplicate sample value in profile: {profile.name}")
        unknown = set(value_names) - known_names
        if unknown:
            raise ValueError(f"unknown sample values in {profile.name}: {sorted(unknown)}")
        if profile.target not in SAMPLE_TARGET_NAMES:
            raise ValueError(f"unknown target in sample profile: {profile.name}")
        profile_names.add(profile.name)
    if profile_names != set(SAMPLE_PROFILE_NAMES):
        raise ValueError("sample profiles differ from SAMPLE_PROFILE_NAMES")


_validate_specs(SETTING_SPECS)
_validate_targets(SAMPLE_TARGETS, SETTING_SPECS)
_validate_profiles(SAMPLE_PROFILES)

SETTING_SPEC_BY_NAME: Mapping[str, SettingSpec] = MappingProxyType(
    {spec.name: spec for spec in SETTING_SPECS}
)
SAMPLE_TARGET_BY_NAME: Mapping[str, SampleTarget] = MappingProxyType(
    {target.name: target for target in SAMPLE_TARGETS}
)
SAMPLE_PROFILE_BY_NAME: Mapping[str, SampleProfile] = MappingProxyType(
    {profile.name: profile for profile in SAMPLE_PROFILES}
)

_section_keys: dict[str, dict[str, str]] = {section: {} for section in SETTINGS_SECTION_ORDER}
for _setting_spec in SETTING_SPECS:
    _section_keys[_setting_spec.section][_setting_spec.ini_key] = _setting_spec.name
SECTION_KEY_MAP: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {section: MappingProxyType(keys) for section, keys in _section_keys.items()}
)
ENV_TO_SETTING_MAP: Mapping[str, str] = MappingProxyType(
    {spec.env_name: spec.name for spec in SETTING_SPECS}
)
CLI_TO_SETTING_MAP: Mapping[str, str] = MappingProxyType(
    {spec.cli.dest: spec.name for spec in SETTING_SPECS if spec.cli is not None}
)
del _section_keys, _setting_spec


def section_key_map() -> Mapping[str, Mapping[str, str]]:
    """Return immutable ``section -> ini_key -> settings field`` metadata."""
    return SECTION_KEY_MAP


def env_to_setting_map() -> Mapping[str, str]:
    """Return immutable ``XFERRY_*`` name-to-field metadata."""
    return ENV_TO_SETTING_MAP


def cli_to_setting_map() -> Mapping[str, str]:
    """Return immutable argparse destination-to-field metadata."""
    return CLI_TO_SETTING_MAP


def format_ini_value(field_name: str, value: object) -> str:
    """Serialize one value using the field's canonical INI grammar."""
    try:
        value_kind = SETTING_SPEC_BY_NAME[field_name].value_kind
    except KeyError:
        raise ValueError(f"unknown settings field: {field_name}") from None
    if value is None:
        return ""
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, tuple):
        separator = ", " if value_kind == "plugin_allowlist" else " "
        return separator.join(str(part) for part in value)
    return str(value)


def render_ini_entry(field_name: str, value: object, *, commented: bool = False) -> str:
    """Render one canonical ``key = value`` line without a final newline."""
    try:
        ini_key = SETTING_SPEC_BY_NAME[field_name].ini_key
    except KeyError:
        raise ValueError(f"unknown settings field: {field_name}") from None
    rendered_value = format_ini_value(field_name, value)
    line = f"{ini_key} = {rendered_value}" if rendered_value else f"{ini_key} ="
    return f"# {line}" if commented else line


def cli_setting_specs(group: CliGroup | None = None) -> tuple[SettingSpec, ...]:
    """Return settings with CLI declarations, optionally for one group."""
    return tuple(
        spec
        for spec in SETTING_SPECS
        if spec.cli is not None and (group is None or spec.cli.group == group)
    )


def get_sample_target(target: SampleTarget | str) -> SampleTarget:
    """Resolve a target name or return a supplied immutable target."""
    if isinstance(target, SampleTarget):
        return target
    try:
        return SAMPLE_TARGET_BY_NAME[target]
    except KeyError:
        choices = ", ".join(SAMPLE_TARGET_NAMES)
        raise ValueError(
            f"unknown settings sample target {target!r}; choose one of: {choices}"
        ) from None


def get_sample_profile(profile: SampleProfile | str) -> SampleProfile:
    """Resolve a profile name or return a supplied immutable profile."""
    if isinstance(profile, SampleProfile):
        return profile
    try:
        return SAMPLE_PROFILE_BY_NAME[profile]
    except KeyError:
        choices = ", ".join(SAMPLE_PROFILE_NAMES)
        raise ValueError(
            f"unknown settings sample profile {profile!r}; choose one of: {choices}"
        ) from None


def sample_specs(target: SampleTarget | str = "public-direct") -> tuple[SettingSpec, ...]:
    """Return present fields in the target's deterministic order."""
    resolved = get_sample_target(target)
    return tuple(SETTING_SPEC_BY_NAME[name] for name in resolved.field_order)


def public_direct_sample_specs() -> tuple[SettingSpec, ...]:
    """Return fields present in the main public-direct sample."""
    return sample_specs("public-direct")


__all__ = [
    "CLI_GROUP_ORDER",
    "CLI_TO_SETTING_MAP",
    "ENV_TO_SETTING_MAP",
    "NO_CLI_SETTING_NAMES",
    "SAMPLE_PROFILE_BY_NAME",
    "SAMPLE_PROFILE_NAMES",
    "SAMPLE_PROFILES",
    "SAMPLE_TARGET_BY_NAME",
    "SAMPLE_TARGET_NAMES",
    "SAMPLE_TARGETS",
    "SECTION_KEY_MAP",
    "SETTING_SPECS",
    "SETTING_SPEC_BY_NAME",
    "SETTINGS_SECTION_ORDER",
    "CliAction",
    "CliGroup",
    "CliParserKind",
    "CliSpec",
    "RedactionClass",
    "SampleDisposition",
    "SampleProfile",
    "SampleScalar",
    "SampleTarget",
    "SettingSpec",
    "SettingValueKind",
    "cli_setting_specs",
    "cli_to_setting_map",
    "env_to_setting_map",
    "format_ini_value",
    "get_sample_profile",
    "get_sample_target",
    "public_direct_sample_specs",
    "render_ini_entry",
    "sample_specs",
    "section_key_map",
]
