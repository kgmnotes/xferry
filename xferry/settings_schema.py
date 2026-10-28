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
    "choice",
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
    {"plugin_allowlist", "plugins_allow_public_direct", "plugins_override_core"}
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
    description: str
    example: str
    constraints: str
    dependencies: str
    applicability: str
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
        "access",
        CliSpec(
            option_strings=("--access",),
            dest="access",
            group="Basic",
            help="Server access: private loopback, public HTTPS, or explicit lab testing",
            action="store",
            metavar=None,
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=("private", "public", "lab"),
            normal_help=True,
            default_from_runtime=True,
        ),
    ),
    (
        "https_mode",
        CliSpec(
            option_strings=("--https",),
            dest="https_mode",
            group="TLS",
            help="HTTPS mode; default: off for private/lab, automatic address for public",
            action="store",
            metavar=None,
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=("off", "auto", "domain", "files", "self-signed"),
            normal_help=True,
            default_from_runtime=True,
        ),
    ),
    (
        "log_level",
        CliSpec(
            option_strings=("--log-level",),
            dest="log_level",
            group="Modes",
            help="Logging detail",
            action="store",
            metavar=None,
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=("warning", "info", "debug"),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "log_format",
        CliSpec(
            option_strings=("--log-format",),
            dest="log_format",
            group="Modes",
            help="Log output format",
            action="store",
            metavar=None,
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=("text", "json"),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "host",
        CliSpec(
            option_strings=("-H", "--host"),
            dest="host",
            group="Basic",
            help="Bind host (default: {default})",
            action="store",
            metavar="HOST",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=True,
            default_from_runtime=True,
        ),
    ),
    (
        "port",
        CliSpec(
            option_strings=("-p", "--port"),
            dest="port",
            group="Basic",
            help="Listen port (default: {default})",
            action="store",
            metavar="PORT",
            parser_kind="integer",
            parser_label="port",
            minimum=1,
            maximum=65535,
            choices=(),
            normal_help=True,
            default_from_runtime=True,
        ),
    ),
    (
        "files_dir",
        CliSpec(
            option_strings=("--files-dir",),
            dest="files_dir",
            group="Basic",
            help="Folder for uploads and downloads (default: per-user xferry/files)",
            action="store",
            metavar="DIR",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=True,
            default_from_runtime=True,
        ),
    ),
    (
        "encrypted_uploads",
        CliSpec(
            option_strings=("--encrypted-uploads",),
            dest="encrypted_uploads",
            group="Modes",
            help="Enable resumable browser-encrypted large-file transfers",
            action="boolean_optional",
            metavar=None,
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "max_size_mb",
        CliSpec(
            option_strings=("-m", "--max-size"),
            dest="max_size",
            group="Limits",
            help="Max per-request upload body size in MB (default: {default})",
            action="store",
            metavar="MB",
            parser_kind="integer",
            parser_label="max size",
            minimum=1,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "encrypted_upload_max_size_mb",
        CliSpec(
            option_strings=("--encrypted-upload-max-size",),
            dest="encrypted_upload_max_size",
            group="Limits",
            help="Max encrypted-upload plaintext size in MB; 0 = automatic (default: {default})",
            action="store",
            metavar="MB",
            parser_kind="integer",
            parser_label="encrypted upload max size",
            minimum=0,
            maximum=32768,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "encrypted_upload_incomplete_ttl_seconds",
        CliSpec(
            option_strings=("--encrypted-upload-incomplete-ttl",),
            dest="encrypted_upload_incomplete_ttl",
            group="Limits",
            help="Expiry for inactive encrypted uploads in seconds (default: {default})",
            action="store",
            metavar="SECONDS",
            parser_kind="integer",
            parser_label="encrypted upload incomplete TTL",
            minimum=1,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "upload_storage_limit_mb",
        CliSpec(
            option_strings=("--upload-storage-limit",),
            dest="upload_storage_limit",
            group="Limits",
            help="Aggregate uploads/ storage quota in MB; 0 disables (default: {default})",
            action="store",
            metavar="MB",
            parser_kind="integer",
            parser_label="upload storage limit",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "upload_file_limit",
        CliSpec(
            option_strings=("--upload-file-limit",),
            dest="upload_file_limit",
            group="Limits",
            help="Aggregate uploads/ file count quota; 0 disables (default: {default})",
            action="store",
            metavar="N",
            parser_kind="integer",
            parser_label="upload file limit",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "upload_reserve_free_mb",
        CliSpec(
            option_strings=("--upload-reserve-free",),
            dest="upload_reserve_free",
            group="Limits",
            help=(
                "Minimum free disk space to preserve while committing uploads in MB "
                "(default: {default})"
            ),
            action="store",
            metavar="MB",
            parser_kind="integer",
            parser_label="upload reserve free",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "upload_quota_externally_managed",
        CliSpec(
            option_strings=("--upload-quota-externally-managed",),
            dest="upload_quota_externally_managed",
            group="Limits",
            help=(
                "Acknowledge that upload disk capacity is enforced outside xferry; "
                "required for public access when all upload disk controls are disabled"
            ),
            action="boolean_optional",
            metavar=None,
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "note_storage_limit_mb",
        CliSpec(
            option_strings=("--note-storage-limit",),
            dest="note_storage_limit",
            group="Limits",
            help="Aggregate encrypted notes/ blob quota in MB; 0 disables (default: {default})",
            action="store",
            metavar="MB",
            parser_kind="integer",
            parser_label="note storage limit",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "note_count_limit",
        CliSpec(
            option_strings=("--note-count-limit",),
            dest="note_count_limit",
            group="Limits",
            help="Aggregate encrypted note count quota; 0 disables (default: {default})",
            action="store",
            metavar="N",
            parser_kind="integer",
            parser_label="note count limit",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "smuggle_temp_age",
        CliSpec(
            option_strings=("--smuggle-temp-age",),
            dest="smuggle_temp_age",
            group="Limits",
            help=(
                "Max age for retained SMUGGLE temp pages in seconds; 0 disables "
                "(default: {default})"
            ),
            action="store",
            metavar="SECONDS",
            parser_kind="integer",
            parser_label="SMUGGLE temp max age",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "smuggle_temp_file_limit",
        CliSpec(
            option_strings=("--smuggle-temp-file-limit",),
            dest="smuggle_temp_file_limit",
            group="Limits",
            help="Max retained SMUGGLE temp page count; 0 disables (default: {default})",
            action="store",
            metavar="N",
            parser_kind="integer",
            parser_label="SMUGGLE temp file limit",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "smuggle_temp_storage_limit_mb",
        CliSpec(
            option_strings=("--smuggle-temp-storage-limit",),
            dest="smuggle_temp_storage_limit",
            group="Limits",
            help="Max retained SMUGGLE temp page bytes in MB; 0 disables (default: {default})",
            action="store",
            metavar="MB",
            parser_kind="integer",
            parser_label="SMUGGLE temp storage limit",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "max_header_size_kb",
        CliSpec(
            option_strings=("--max-header-size",),
            dest="max_header_size",
            group="Limits",
            help="Max HTTP request header size in KiB (default: {default})",
            action="store",
            metavar="KB",
            parser_kind="integer",
            parser_label="max header size",
            minimum=1,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "body_memory_budget_mb",
        CliSpec(
            option_strings=("--body-memory-budget",),
            dest="body_memory_budget",
            group="Limits",
            help=(
                "Admission budget for aggregate in-flight request bodies in MB, not an "
                "RSS ceiling (default: workers * max size)"
            ),
            action="store",
            metavar="MB",
            parser_kind="integer",
            parser_label="body memory budget",
            minimum=1,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "body_idle_timeout",
        CliSpec(
            option_strings=("--body-idle-timeout",),
            dest="body_idle_timeout",
            group="Limits",
            help="Max idle seconds between request body chunks; 0 disables (default: {default})",
            action="store",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="body idle timeout",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "body_timeout",
        CliSpec(
            option_strings=("--body-timeout",),
            dest="body_timeout",
            group="Limits",
            help=(
                "Max seconds to receive a request body after headers; 0 disables "
                "(default: {default})"
            ),
            action="store",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="body timeout",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "body_min_rate",
        CliSpec(
            option_strings=("--body-min-rate",),
            dest="body_min_rate",
            group="Limits",
            help=(
                "Minimum average request body read rate in bytes/s; 0 disables (default: {default})"
            ),
            action="store",
            metavar="BYTES_PER_SECOND",
            parser_kind="number",
            parser_label="body minimum read rate",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "stream_send_idle_timeout",
        CliSpec(
            option_strings=("--stream-send-idle-timeout",),
            dest="stream_send_idle_timeout",
            group="Limits",
            help="Max seconds a streamed response send may block per chunk (default: {default})",
            action="store",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="stream send idle timeout",
            minimum=0.001,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "stream_send_timeout",
        CliSpec(
            option_strings=("--stream-send-timeout",),
            dest="stream_send_timeout",
            group="Limits",
            help=(
                "Max total seconds for a streamed response transfer; 0 disables "
                "(default: {default})"
            ),
            action="store",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="stream send timeout",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "max_websocket_connections",
        CliSpec(
            option_strings=("--max-websocket-connections",),
            dest="max_websocket_connections",
            group="Limits",
            help=(
                "Max active WebSocket connections; each occupies a worker and 0 rejects "
                "all (default: workers // 2)"
            ),
            action="store",
            metavar="N",
            parser_kind="integer",
            parser_label="max websocket connections",
            minimum=0,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "websocket_frame_idle_timeout",
        CliSpec(
            option_strings=("--websocket-frame-idle-timeout",),
            dest="websocket_frame_idle_timeout",
            group="Limits",
            help=(
                "Max idle seconds while waiting for the rest of an incomplete WebSocket "
                "frame (default: {default})"
            ),
            action="store",
            metavar="SECONDS",
            parser_kind="number",
            parser_label="websocket frame idle timeout",
            minimum=0.001,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "workers",
        CliSpec(
            option_strings=("-w", "--workers"),
            dest="workers",
            group="Limits",
            help="Number of worker threads (default: {default})",
            action="store",
            metavar="N",
            parser_kind="integer",
            parser_label="workers",
            minimum=1,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "cert_file",
        CliSpec(
            option_strings=("--cert",),
            dest="cert",
            group="TLS",
            help="Path to certificate file (PEM)",
            action="store",
            metavar="FILE",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "key_file",
        CliSpec(
            option_strings=("--key",),
            dest="key",
            group="TLS",
            help="Path to private key file (PEM)",
            action="store",
            metavar="FILE",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "domain",
        CliSpec(
            option_strings=("--domain",),
            dest="domain",
            group="TLS",
            help="Domain for Let's Encrypt certificate",
            action="store",
            metavar="DOMAIN",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "email",
        CliSpec(
            option_strings=("--email",),
            dest="email",
            group="TLS",
            help="Email for Let's Encrypt notifications (optional)",
            action="store",
            metavar="EMAIL",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "public_ip",
        CliSpec(
            option_strings=("--public-ip",),
            dest="public_ip",
            group="TLS",
            help="Public IPv4 for --https auto (default: auto-detect)",
            action="store",
            metavar="IP",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "acme_server",
        CliSpec(
            option_strings=("--acme-server",),
            dest="acme_server",
            group="TLS",
            help="Custom ACME directory URL (overrides --acme-staging)",
            action="store",
            metavar="URL",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "acme_http_address",
        CliSpec(
            option_strings=("--acme-http-address",),
            dest="acme_http_address",
            group="TLS",
            help="Bind address for HTTP-01 challenge server (default: all interfaces)",
            action="store",
            metavar="ADDR",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "acme_http_port",
        CliSpec(
            option_strings=("--acme-http-port",),
            dest="acme_http_port",
            group="TLS",
            help="Bind port for HTTP-01 challenge server (default: {default})",
            action="store",
            metavar="PORT",
            parser_kind="integer",
            parser_label="ACME HTTP port",
            minimum=1,
            maximum=65535,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
    (
        "auth_file",
        CliSpec(
            option_strings=("--auth-file",),
            dest="auth_file",
            group="Authentication",
            help="Read Basic Auth credentials from one user:pass line in FILE",
            action="store",
            metavar="FILE",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=True,
            default_from_runtime=True,
        ),
    ),
    (
        "allowed_hosts",
        CliSpec(
            option_strings=("--allowed-host",),
            dest="allowed_host",
            group="Authentication",
            help="Admit this Host/IP (repeatable; replaces file/env list)",
            action="append",
            metavar="HOST",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=True,
            default_from_runtime=False,
        ),
    ),
    (
        "cors_origin",
        CliSpec(
            option_strings=("--cors-origin",),
            dest="cors_origin",
            group="Modes",
            help="Enable CORS for an explicit origin (default: disabled)",
            action="store",
            metavar="ORIGIN",
            parser_kind=None,
            parser_label=None,
            minimum=None,
            maximum=None,
            choices=(),
            normal_help=False,
            default_from_runtime=True,
        ),
    ),
)


_CLI_SPEC_BY_SETTING: Mapping[str, CliSpec] = MappingProxyType(dict(_CLI_ROWS))


def _s(
    name: str,
    section: str,
    value_kind: SettingValueKind,
    redaction: RedactionClass,
    samples: tuple[SampleDisposition, SampleDisposition, SampleDisposition, SampleDisposition],
    comments: tuple[str, ...],
    description: str,
    example: str,
    constraints: str,
    dependencies: str,
    applicability: str,
) -> SettingSpec:
    return SettingSpec(
        name=name,
        section=section,
        value_kind=value_kind,
        redaction=redaction,
        cli=_CLI_SPEC_BY_SETTING.get(name),
        sample_dispositions=samples,
        sample_comments=comments,
        description=description,
        example=f"{name} = {example}",
        constraints=constraints,
        dependencies=dependencies,
        applicability=applicability,
    )


SETTING_SPECS: tuple[SettingSpec, ...] = (
    _s(
        "access",
        "server",
        "choice",
        "none",
        ("active", "active", "active", "active"),
        (),
        (
            "Who can reach the server. Public mode always enforces verified HTTPS, "
            "file-backed access and finite limits."
        ),
        "public",
        "private, public, lab",
        "Public mode defaults to automatic HTTPS; private binds loopback.",
        "all",
    ),
    _s(
        "https_mode",
        "tls",
        "choice",
        "none",
        ("active", "active", "active", "active"),
        (),
        (
            "How the server obtains HTTPS certificates. Automatic uses a public IPv4 "
            "hostname; domain uses your DNS name."
        ),
        "auto",
        "off, auto, domain, files, self-signed",
        (
            "domain requires domain; files requires cert_file and key_file; self-signed is "
            "private/lab only."
        ),
        "all; file certificates in Docker require explicit mounts",
    ),
    _s(
        "log_level",
        "server",
        "choice",
        "none",
        ("active", "active", "active", "active"),
        (),
        "How much diagnostic information the server records.",
        "info",
        "warning, info, debug",
        "",
        "all",
    ),
    _s(
        "log_format",
        "server",
        "choice",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Whether logs are readable text or structured JSON.",
        "text",
        "text, json",
        "",
        "all",
    ),
    _s(
        "host",
        "server",
        "string",
        "none",
        ("active", "active", "active", "active"),
        (),
        (
            "Address the server listens on. Private mode accepts only loopback; public "
            "defaults to all interfaces."
        ),
        "127.0.0.1",
        "An IP address or hostname; private requires localhost or a loopback IP",
        "Default: 127.0.0.1 for private/lab, 0.0.0.0 for public.",
        "all",
    ),
    _s(
        "port",
        "server",
        "integer",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Listen port",
        "8080",
        "Minimum 1; maximum 65535",
        (
            "Default: 8080 for private/lab, 8443 for public. Open this port in the host "
            "firewall when sharing."
        ),
        "all",
    ),
    _s(
        "files_dir",
        "server",
        "optional_string",
        "none",
        ("active", "active", "active", "active"),
        (),
        (
            "Exact folder for downloadable files and new uploads. Existing files in this "
            "folder are available too."
        ),
        "/srv/share",
        "A readable and writable directory",
        (
            "If omitted, uses the stable per-user xferry/files folder. Relative paths resolve"
            " from the launch directory. Private state and configuration must be outside it."
        ),
        "all; installation-owned mappings use the files-folder action",
    ),
    _s(
        "encrypted_uploads",
        "server",
        "boolean",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Enable resumable browser-encrypted large-file transfers",
        "true",
        "true or false",
        (
            "Encrypted transfers require at least two workers and a body budget for two "
            "encrypted chunks."
        ),
        "advanced",
    ),
    _s(
        "max_size_mb",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "active"),
        (),
        (
            "Maximum HTTP request body in MiB, including multipart overhead; this is not a "
            "per-file size guarantee."
        ),
        "100",
        "Integer at least 1 MiB",
        "",
        "all",
    ),
    _s(
        "encrypted_upload_max_size_mb",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Max encrypted-upload plaintext size in MiB; 0 = automatic",
        "0",
        "Integer from 0 to 32768 MiB; 0 selects the available quota/free-space limit",
        (
            "Used only when encrypted_uploads is true; max_size_mb still limits each "
            "encrypted chunk request."
        ),
        "advanced",
    ),
    _s(
        "encrypted_upload_incomplete_ttl_seconds",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Expiry for inactive encrypted uploads in seconds",
        "604800",
        "Minimum 1",
        (
            "Used only when encrypted_uploads is true; inactive partial uploads are cleaned "
            "up after this time."
        ),
        "advanced",
    ),
    _s(
        "upload_storage_limit_mb",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Aggregate files folder storage quota in MiB; 0 disables",
        "4096",
        "Minimum 0",
        (
            "Public defaults to 4096 MiB. At least one disk control must remain enabled "
            "unless upload_quota_externally_managed is true."
        ),
        "advanced",
    ),
    _s(
        "upload_file_limit",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "omitted"),
        (),
        "Aggregate files folder file count quota; 0 disables",
        "4096",
        "Minimum 0",
        "Public defaults to 4096 files. Existing files in files_dir count toward the limit.",
        "advanced",
    ),
    _s(
        "upload_reserve_free_mb",
        "limits",
        "integer",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Free disk space to preserve when committing uploads, in MiB; 0 disables this reserve.",
        "1024",
        "Minimum 0",
        "Public defaults to 1024 MiB. Applies to the filesystem containing files_dir.",
        "advanced",
    ),
    _s(
        "upload_quota_externally_managed",
        "limits",
        "boolean",
        "none",
        ("active", "active", "active", "omitted"),
        (),
        "Confirm that storage is limited outside xferry, for example by a filesystem quota.",
        "false",
        "true or false",
        "Public access permits all three upload disk controls to be zero only when this is true.",
        "advanced",
    ),
    _s(
        "note_storage_limit_mb",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Total encrypted-note storage quota in MiB; 0 disables the quota.",
        "256",
        "Minimum 0",
        "Notes are stored in private state, outside files_dir.",
        "advanced",
    ),
    _s(
        "note_count_limit",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Aggregate encrypted note count quota; 0 disables",
        "1000",
        "Minimum 0",
        "Limits encrypted notes in private state, independently of upload_file_limit.",
        "advanced",
    ),
    _s(
        "smuggle_temp_age",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Max age for retained SMUGGLE temp pages in seconds; 0 disables",
        "3600",
        "Minimum 0",
        "Applies only to retained SMUGGLE pages in the files folder; 0 disables age-based cleanup.",
        "advanced",
    ),
    _s(
        "smuggle_temp_file_limit",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Max retained SMUGGLE temp page count; 0 disables",
        "32",
        "Minimum 0",
        "Applies only to retained SMUGGLE pages; 0 disables the count limit.",
        "advanced",
    ),
    _s(
        "smuggle_temp_storage_limit_mb",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Max retained SMUGGLE temp page bytes in MiB; 0 disables",
        "128",
        "Minimum 0",
        "Applies only to retained SMUGGLE pages; 0 disables the storage limit.",
        "advanced",
    ),
    _s(
        "max_header_size_kb",
        "limits",
        "integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Max HTTP request header size in KiB",
        "64",
        "Minimum 1",
        "Rejects oversized HTTP headers before request bodies are read.",
        "advanced",
    ),
    _s(
        "body_memory_budget_mb",
        "limits",
        "optional_integer",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Admission budget for aggregate in-flight request bodies in MiB, not an RSS ceiling",
        "256",
        "Empty means automatic; otherwise an integer at least 1 MiB",
        (
            "Automatic is max_size_mb \u00d7 workers, raised for encrypted chunks when needed. "
            "Public defaults to 512 MiB."
        ),
        "advanced",
    ),
    _s(
        "body_idle_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Max idle seconds between request body chunks; 0 disables",
        "5",
        "Minimum 0",
        "Public access requires a positive value.",
        "advanced",
    ),
    _s(
        "body_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Max seconds to receive a request body after headers; 0 disables",
        "300",
        "Minimum 0",
        "Public access requires a positive value.",
        "advanced",
    ),
    _s(
        "body_min_rate",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "omitted"),
        (),
        "Minimum average request body read rate in bytes/s; 0 disables",
        "1024",
        "Minimum 0",
        "Measured across body reads; 0 disables the minimum rate without disabling timeouts.",
        "advanced",
    ),
    _s(
        "stream_send_idle_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Max seconds a streamed response send may block per chunk",
        "5",
        "Minimum 0.001",
        "Must stay positive in every access mode.",
        "advanced",
    ),
    _s(
        "stream_send_timeout",
        "limits",
        "number",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Max total seconds for a streamed response transfer; 0 disables",
        "300",
        "Minimum 0",
        "Public access requires a positive value.",
        "advanced",
    ),
    _s(
        "max_websocket_connections",
        "limits",
        "optional_integer",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Max active WebSocket connections; each occupies a worker and 0 rejects all",
        "5",
        "Empty means automatic; otherwise an integer at least 0",
        (
            "Automatic reserves half the workers for WebSockets (workers // 2). Each active "
            "connection occupies one worker; 0 rejects all."
        ),
        "advanced",
    ),
    _s(
        "websocket_frame_idle_timeout",
        "limits",
        "number",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Max idle seconds while waiting for the rest of an incomplete WebSocket frame",
        "5",
        "Minimum 0.001",
        (
            "Applies while reading an incomplete WebSocket frame; it does not close an "
            "otherwise idle connection."
        ),
        "advanced",
    ),
    _s(
        "workers",
        "server",
        "integer",
        "none",
        ("active", "active", "active", "active"),
        (),
        "Number of worker threads",
        "4",
        "Minimum 1",
        (
            "Encrypted uploads require at least 2. Automatic memory and WebSocket limits "
            "depend on this value."
        ),
        "advanced",
    ),
    _s(
        "cert_file",
        "tls",
        "string",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Path to certificate file (PEM)",
        "/etc/xferry/server.pem",
        "A readable PEM certificate or certificate-chain file",
        (
            "Requires https_mode = files and key_file. Public wildcard binds also require "
            "allowed_hosts."
        ),
        "advanced",
    ),
    _s(
        "key_file",
        "tls",
        "string",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Path to private key file (PEM)",
        "/etc/xferry/server.key",
        "A readable PEM private-key file matching cert_file",
        "Requires https_mode = files and cert_file. Protect this file from other users.",
        "advanced",
    ),
    _s(
        "domain",
        "tls",
        "optional_string",
        "none",
        ("omitted", "omitted", "omitted", "active"),
        (),
        "DNS hostname used for an automatically issued domain certificate.",
        "files.example.com",
        "A DNS hostname without URL or port",
        (
            "Requires https_mode = domain, DNS pointing to this host, and public HTTP port 80"
            " reaching the challenge listener."
        ),
        "all",
    ),
    _s(
        "email",
        "tls",
        "optional_string",
        "none",
        ("omitted", "omitted", "omitted", "active"),
        (),
        "Email for Let's Encrypt notifications (optional)",
        "admin@example.com",
        "An email address, or empty to omit contact details",
        "Used only with https_mode = auto or domain for certificate-account contact details.",
        "advanced",
    ),
    _s(
        "public_ip",
        "tls",
        "optional_string",
        "none",
        ("commented", "commented", "commented", "active"),
        (),
        "Public IPv4 address used to form an automatic sslip.io certificate hostname.",
        "203.0.113.10",
        "A public IPv4 address; empty means automatic detection",
        (
            "Requires https_mode = auto. Use when automatic public-IP detection selects the "
            "wrong address."
        ),
        "advanced",
    ),
    _s(
        "acme_server",
        "tls",
        "optional_string",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "ACME directory URL or staging for test certificates.",
        "staging",
        "HTTPS directory URL or staging",
        (
            "Requires https_mode = auto or domain. Empty selects the production service; "
            "staging issues certificates browsers will not trust."
        ),
        "advanced",
    ),
    _s(
        "acme_http_address",
        "tls",
        "string",
        "none",
        ("omitted", "omitted", "omitted", "omitted"),
        (),
        "Bind address for HTTP-01 challenge server",
        # documentation example for the ACME listener.
        "0.0.0.0",  # nosec B104
        "An IP address; empty listens on all interfaces",
        (
            "Requires https_mode = auto or domain. Public HTTP port 80 must reach this "
            "HTTP-01 listener."
        ),
        "advanced",
    ),
    _s(
        "acme_http_port",
        "tls",
        "integer",
        "none",
        ("omitted", "active", "active", "active"),
        (),
        "Bind port for HTTP-01 challenge server",
        "80",
        "Minimum 1; maximum 65535",
        (
            "Requires https_mode = auto or domain. Default 80; use another internal port only"
            " when public port 80 is forwarded to it."
        ),
        "advanced",
    ),
    _s(
        "auth_file",
        "security",
        "optional_string",
        "none",
        ("active", "active", "active", "active"),
        (),
        (
            "Protected file containing one username:password line. Generate or change it "
            "through the credentials action."
        ),
        "/etc/xferry/auth",
        "A readable protected file with one nonempty username:password line",
        (
            "Required for public access; optional for private/lab. Use xferry credentials to "
            "generate or reset it."
        ),
        "all; installation-owned paths are managed automatically",
    ),
    _s(
        "allowed_hosts",
        "security",
        "allowed_hosts",
        "none",
        ("active", "active", "active", "active"),
        ("ASCII-whitespace-separated host/IP values; empty uses listener auto-mode.",),
        (
            "HTTP Host names/IP addresses admitted by the server. Empty means automatic "
            "listener/certificate names."
        ),
        "files.example.com localhost",
        "Whitespace-separated names/IPs without URLs, ports, CIDRs or wildcards",
        (
            "Empty derives allowed hosts from the listener/certificate. Public wildcard binds"
            " with file certificates require an explicit list containing the certificate "
            "hostname."
        ),
        "advanced",
    ),
    _s(
        "cors_origin",
        "cors",
        "string",
        "none",
        ("active", "active", "active", "omitted"),
        (),
        (
            "Browser origin allowed to read responses from a separate web application. Empty "
            "disables cross-origin access."
        ),
        "https://portal.example.com",
        "An exact origin; empty disables",
        (
            "Public access rejects *. Set an exact origin only when using a separate browser "
            "application."
        ),
        "advanced",
    ),
    _s(
        "plugin_allowlist",
        "plugins",
        "plugin_allowlist",
        "none",
        ("active", "active", "active", "omitted"),
        (),
        "Explicit extension modules allowed to load.",
        "example.module:plugin",
        "Comma-separated module entry points",
        "Installed plugins only; public access also requires plugins_allow_public_direct = true.",
        "advanced",
    ),
    _s(
        "plugins_allow_public_direct",
        "plugins",
        "boolean",
        "none",
        ("active", "active", "active", "omitted"),
        (),
        "Permit allowlisted extensions in public mode.",
        "false",
        "true or false",
        "Only matters with access = public and a nonempty plugin_allowlist.",
        "advanced",
    ),
    _s(
        "plugins_override_core",
        "plugins",
        "boolean",
        "none",
        ("active", "active", "active", "omitted"),
        (),
        "Permit extensions to replace built-in HTTP method handlers.",
        "false",
        "true or false",
        "Only matters with plugin_allowlist; allows a plugin to replace a built-in HTTP method.",
        "advanced",
    ),
)

_STATIC_SECTION_ORDER = ("server", "security", "tls", "limits", "cors", "plugins")
SAMPLE_TARGETS: tuple[SampleTarget, ...] = tuple(
    SampleTarget(
        name,
        _STATIC_SECTION_ORDER,
        tuple(spec.name for spec in SETTING_SPECS if spec.sample_disposition(name) != "omitted"),
        include_setting_comments=False,
    )
    for name in SAMPLE_TARGET_NAMES
)
_COMMON_PROFILE_VALUES: tuple[tuple[str, SampleScalar], ...] = (
    ("access", "public"),
    ("https_mode", "auto"),
    # public deployment sample.
    ("host", "0.0.0.0"),  # nosec B104
    ("log_format", "json"),
    ("body_memory_budget_mb", 512),
    ("upload_storage_limit_mb", 4096),
    ("upload_file_limit", 4096),
    ("upload_reserve_free_mb", 1024),
    ("public_ip", "203.0.113.10"),
)
SAMPLE_PROFILES: tuple[SampleProfile, ...] = (
    SampleProfile(
        "public-direct",
        "public-direct",
        (
            *_COMMON_PROFILE_VALUES,
            ("files_dir", "/var/lib/xferry/files"),
            ("port", 8443),
            ("auth_file", "/etc/xferry/auth"),
        ),
    ),
    SampleProfile(
        "docker",
        "docker",
        (
            *_COMMON_PROFILE_VALUES,
            ("files_dir", "/data/files"),
            ("port", 8443),
            ("auth_file", "/run/secrets/xferry_auth"),
            ("acme_http_port", 8080),
        ),
    ),
    SampleProfile(
        "systemd",
        "systemd",
        (
            *_COMMON_PROFILE_VALUES,
            ("files_dir", "/var/lib/xferry/files"),
            ("port", 443),
            ("auth_file", "/etc/xferry/auth"),
            ("acme_http_port", 80),
        ),
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
