#!/usr/bin/env python3
"""
CLI entry point for XFerryServer.
"""

import argparse
import json
import os
import signal
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from .config import __version__
from .features import registry_methods
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
from .server import XFerryServer
from .server_config import (
    DEFAULT_STREAM_SEND_IDLE_TIMEOUT,
    DEFAULT_STREAM_SEND_TIMEOUT,
    DEFAULT_WEBSOCKET_FRAME_IDLE_TIMEOUT,
)
from .settings import (
    BODY_ADMISSION_BUDGET_NOTE,
    WEBSOCKET_WORKER_NOTE,
    LaunchPreset,
    load_settings_file,
    resolve_settings,
    sample_config_text,
)

_MIB = 1024 * 1024

_NORMAL_HELP_DESTS = frozenset(
    {
        "help",
        "help_all",
        "version",
        "preset",
        "config",
        "check_config",
        "print_config",
        "write_sample_config",
        "host",
        "port",
        "dir",
        "open",
        "tls",
        "auth",
        "auth_file",
    }
)


class _HelpAllAction(argparse.Action):
    """Print the exhaustive parser help without changing accepted arguments."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        del namespace, values, option_string
        create_parser(show_all_help=True).print_help()
        parser.exit()


def _bounded_int(name: str, *, minimum: int, maximum: int | None = None) -> Callable[[str], int]:
    """Return an argparse type function for an integer with inclusive bounds."""

    def parse(value: str) -> int:
        try:
            parsed = int(value, 10)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from None

        if parsed < minimum:
            if maximum is None:
                raise argparse.ArgumentTypeError(f"{name} must be at least {minimum}")
            raise argparse.ArgumentTypeError(f"{name} must be between {minimum} and {maximum}")
        if maximum is not None and parsed > maximum:
            raise argparse.ArgumentTypeError(f"{name} must be between {minimum} and {maximum}")
        return parsed

    return parse


def _bounded_float(
    name: str,
    *,
    minimum: float,
    maximum: float | None = None,
) -> Callable[[str], float]:
    """Return an argparse type function for a float with inclusive bounds."""

    def parse(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{name} must be a number") from None

        if parsed < minimum:
            if maximum is None:
                raise argparse.ArgumentTypeError(f"{name} must be at least {minimum:g}")
            raise argparse.ArgumentTypeError(f"{name} must be between {minimum:g} and {maximum:g}")
        if maximum is not None and parsed > maximum:
            raise argparse.ArgumentTypeError(f"{name} must be between {minimum:g} and {maximum:g}")
        return parsed

    return parse


def create_parser(*, show_all_help: bool = False) -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    description = f"""HTTP server with custom methods, TLS, Auth, and uploads-only file access.

Choose a launch journey:
  local          Loopback HTTP for first-run and demos.
                 xferry run --preset local --open
  local-secure   Loopback self-signed TLS plus generated auth in an interactive TTY.
                 Service form: xferry run --preset local-secure --auth-file FILE
  public-direct  Advanced public path. Start from the generated INI; real TLS,
                 file-backed auth, finite quotas, and strict validation are required.
                 xferry run --write-sample-config ./xferry.ini
                 xferry run --config ./xferry.ini --check-config

Capacity model:
  {BODY_ADMISSION_BUDGET_NOTE}
  {WEBSOCKET_WORKER_NOTE}

Use --help-all for every tuning and protocol option."""
    if show_all_help:
        epilog = f"""
Examples:
    xferry run --preset local
    xferry run --preset local-secure
    xferry run --preset local-secure --auth-file ./auth.txt
    xferry run --write-sample-config ./xferry.ini
    xferry run --config ./xferry.ini --check-config

Custom HTTP methods:
    Core methods: {", ".join(registry_methods())}
        """
    else:
        epilog = """
The named journeys select defaults only; every explicit INI, XFERRY_* or CLI
value remains authoritative. Use --help-all for the exhaustive option list.
        """
    parser = argparse.ArgumentParser(
        prog="xferry run",
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )

    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--help-all",
        action=_HelpAllAction,
        nargs=0,
        help="Show every configuration, limit, TLS and protocol option",
    )

    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--preset",
        choices=[preset.value for preset in LaunchPreset],
        help="Select journey defaults below every explicit file/env/CLI value",
    )
    config_group.add_argument(
        "--config",
        metavar="FILE",
        help="Read settings from an INI configuration file",
    )
    config_group.add_argument(
        "--check-config",
        action="store_true",
        help="Validate the resolved configuration and exit without starting",
    )
    config_group.add_argument(
        "--print-config",
        action="store_true",
        help="Print the resolved configuration as redacted JSON and exit",
    )
    config_group.add_argument(
        "--write-sample-config",
        metavar="FILE",
        help="Write a public-direct sample INI configuration and exit",
    )

    # Basic
    basic = parser.add_argument_group("Basic")
    basic.add_argument(
        "-H", "--host", default="127.0.0.1", metavar="HOST", help="Bind host (default: 127.0.0.1)"
    )
    basic.add_argument(
        "-p",
        "--port",
        type=_bounded_int("port", minimum=1, maximum=65535),
        default=8080,
        metavar="PORT",
        help="Listen port (default: 8080)",
    )
    basic.add_argument(
        "-d", "--dir", default=".", metavar="DIR", help="Root directory (default: current)"
    )

    # Operating modes
    modes = parser.add_argument_group("Modes")
    modes.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (minimal logging)")
    modes.add_argument("--debug", action="store_true", help="Debug mode (verbose logging)")
    modes.add_argument("--open", action="store_true", help="Open browser after start")
    modes.add_argument("--json-log", action="store_true", help="Structured JSON log format")
    modes.add_argument(
        "--cors-origin",
        default="",
        metavar="ORIGIN",
        help="Enable CORS for an explicit origin (default: disabled)",
    )
    # Limits
    limits = parser.add_argument_group("Limits")
    limits.add_argument(
        "-m",
        "--max-size",
        type=_bounded_int("max size", minimum=1),
        default=100,
        metavar="MB",
        help="Max per-request upload body size in MB (default: 100)",
    )
    limits.add_argument(
        "--upload-storage-limit",
        type=_bounded_int("upload storage limit", minimum=0),
        default=0,
        metavar="MB",
        help="Aggregate uploads/ storage quota in MB; 0 disables (default: 0)",
    )
    limits.add_argument(
        "--upload-file-limit",
        type=_bounded_int("upload file limit", minimum=0),
        default=0,
        metavar="N",
        help="Aggregate uploads/ file count quota; 0 disables (default: 0)",
    )
    limits.add_argument(
        "--upload-reserve-free",
        type=_bounded_int("upload reserve free", minimum=0),
        default=0,
        metavar="MB",
        help="Minimum free disk space to preserve while committing uploads in MB (default: 0)",
    )
    limits.add_argument(
        "--upload-quota-externally-managed",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Acknowledge that upload disk capacity is enforced outside xferry; "
            "required for public-direct only when all app upload disk controls are disabled"
        ),
    )
    limits.add_argument(
        "--note-storage-limit",
        type=_bounded_int("note storage limit", minimum=0),
        default=DEFAULT_MAX_NOTE_STORAGE_BYTES // _MIB,
        metavar="MB",
        help=(
            "Aggregate encrypted notes/ blob quota in MB; 0 disables "
            f"(default: {DEFAULT_MAX_NOTE_STORAGE_BYTES // _MIB})"
        ),
    )
    limits.add_argument(
        "--note-count-limit",
        type=_bounded_int("note count limit", minimum=0),
        default=DEFAULT_MAX_NOTES,
        metavar="N",
        help=f"Aggregate encrypted note count quota; 0 disables (default: {DEFAULT_MAX_NOTES})",
    )
    limits.add_argument(
        "--smuggle-temp-age",
        type=_bounded_int("SMUGGLE temp max age", minimum=0),
        default=DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS,
        metavar="SECONDS",
        help=(
            "Max age for retained SMUGGLE temp pages in seconds; 0 disables "
            f"(default: {DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS})"
        ),
    )
    limits.add_argument(
        "--smuggle-temp-file-limit",
        type=_bounded_int("SMUGGLE temp file limit", minimum=0),
        default=DEFAULT_SMUGGLE_TEMP_MAX_FILES,
        metavar="N",
        help=(
            "Max retained SMUGGLE temp page count; 0 disables "
            f"(default: {DEFAULT_SMUGGLE_TEMP_MAX_FILES})"
        ),
    )
    limits.add_argument(
        "--smuggle-temp-storage-limit",
        type=_bounded_int("SMUGGLE temp storage limit", minimum=0),
        default=DEFAULT_SMUGGLE_TEMP_MAX_BYTES // _MIB,
        metavar="MB",
        help=(
            "Max retained SMUGGLE temp page bytes in MB; 0 disables "
            f"(default: {DEFAULT_SMUGGLE_TEMP_MAX_BYTES // _MIB})"
        ),
    )
    limits.add_argument(
        "--max-header-size",
        type=_bounded_int("max header size", minimum=1),
        default=DEFAULT_MAX_HEADER_SIZE // 1024,
        metavar="KB",
        help="Max HTTP request header size in KiB (default: 64)",
    )
    limits.add_argument(
        "--body-memory-budget",
        type=_bounded_int("body memory budget", minimum=1),
        default=None,
        metavar="MB",
        help=(
            "Admission budget for aggregate in-flight request bodies in MB, not an "
            "RSS ceiling (default: workers * max size)"
        ),
    )
    limits.add_argument(
        "--body-idle-timeout",
        type=_bounded_float("body idle timeout", minimum=0),
        default=DEFAULT_BODY_IDLE_TIMEOUT,
        metavar="SECONDS",
        help=(
            "Max idle seconds between request body chunks; 0 disables "
            f"(default: {DEFAULT_BODY_IDLE_TIMEOUT:g})"
        ),
    )
    limits.add_argument(
        "--body-timeout",
        type=_bounded_float("body timeout", minimum=0),
        default=BODY_TIMEOUT,
        metavar="SECONDS",
        help=(
            "Max seconds to receive a request body after headers; 0 disables "
            f"(default: {BODY_TIMEOUT:g})"
        ),
    )
    limits.add_argument(
        "--body-min-rate",
        type=_bounded_float("body minimum read rate", minimum=0),
        default=DEFAULT_BODY_MIN_RATE_BYTES_PER_SECOND,
        metavar="BYTES_PER_SECOND",
        help="Minimum average request body read rate in bytes/s; 0 disables (default: 0)",
    )
    limits.add_argument(
        "--stream-send-idle-timeout",
        type=_bounded_float("stream send idle timeout", minimum=0.001),
        default=DEFAULT_STREAM_SEND_IDLE_TIMEOUT,
        metavar="SECONDS",
        help=(
            "Max seconds a streamed response send may block per chunk "
            f"(default: {DEFAULT_STREAM_SEND_IDLE_TIMEOUT:g})"
        ),
    )
    limits.add_argument(
        "--stream-send-timeout",
        type=_bounded_float("stream send timeout", minimum=0),
        default=DEFAULT_STREAM_SEND_TIMEOUT,
        metavar="SECONDS",
        help=(
            "Max total seconds for a streamed response transfer; 0 disables "
            f"(default: {DEFAULT_STREAM_SEND_TIMEOUT:g})"
        ),
    )
    limits.add_argument(
        "--max-websocket-connections",
        type=_bounded_int("max websocket connections", minimum=0),
        default=None,
        metavar="N",
        help=(
            "Max active WebSocket connections; each occupies a worker and 0 rejects "
            "all (default: workers // 2)"
        ),
    )
    limits.add_argument(
        "--websocket-frame-idle-timeout",
        type=_bounded_float("websocket frame idle timeout", minimum=0.001),
        default=DEFAULT_WEBSOCKET_FRAME_IDLE_TIMEOUT,
        metavar="SECONDS",
        help=(
            "Max idle seconds while waiting for the rest of an incomplete WebSocket frame "
            f"(default: {DEFAULT_WEBSOCKET_FRAME_IDLE_TIMEOUT:g})"
        ),
    )
    limits.add_argument(
        "-w",
        "--workers",
        type=_bounded_int("workers", minimum=1),
        default=10,
        metavar="N",
        help="Number of worker threads (default: 10)",
    )

    # TLS options
    tls = parser.add_argument_group("TLS")
    tls.add_argument(
        "--tls",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable HTTPS with a generated self-signed certificate",
    )
    tls.add_argument("--cert", metavar="FILE", help="Path to certificate file (PEM)")
    tls.add_argument("--key", metavar="FILE", help="Path to private key file (PEM)")
    tls.add_argument(
        "--letsencrypt",
        action="store_true",
        help="Obtain Let's Encrypt certificate with built-in ACME HTTP-01",
    )
    tls.add_argument("--domain", metavar="DOMAIN", help="Domain for Let's Encrypt certificate")
    tls.add_argument(
        "--email", metavar="EMAIL", help="Email for Let's Encrypt notifications (optional)"
    )
    tls.add_argument(
        "--sslip",
        action="store_true",
        help="Obtain a Let's Encrypt certificate for the public IPv4 sslip.io hostname",
    )
    tls.add_argument(
        "--public-ip",
        metavar="IP",
        help="Public IPv4 override for --sslip (default: auto-detect)",
    )
    tls.add_argument(
        "--acme-staging",
        action="store_true",
        help="Use Let's Encrypt staging ACME directory",
    )
    tls.add_argument(
        "--acme-server",
        metavar="URL",
        help="Custom ACME directory URL (overrides --acme-staging)",
    )
    tls.add_argument(
        "--acme-http-address",
        default="",
        metavar="ADDR",
        help="Bind address for HTTP-01 challenge server (default: all interfaces)",
    )
    tls.add_argument(
        "--acme-http-port",
        type=_bounded_int("ACME HTTP port", minimum=1, maximum=65535),
        default=80,
        metavar="PORT",
        help="Bind port for HTTP-01 challenge server (default: 80)",
    )

    # Authentication
    auth = parser.add_argument_group("Authentication")
    auth.add_argument(
        "--auth",
        metavar="CREDS",
        help="Basic Auth: 'user:pass', 'random', or 'user' (random password)",
    )
    auth.add_argument(
        "--auth-file",
        metavar="FILE",
        help="Read Basic Auth credentials from one user:pass line in FILE",
    )

    if not show_all_help:
        for action in parser._actions:
            if action.dest not in _NORMAL_HELP_DESTS:
                action.help = argparse.SUPPRESS

    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    acme_mode = args.letsencrypt or args.sslip
    has_cert = args.cert is not None
    has_key = args.key is not None

    if has_cert != has_key:
        parser.error("--cert and --key must be provided together")
    if has_cert and (not args.cert or not args.key):
        parser.error("--cert and --key values must not be empty")
    if has_cert and acme_mode:
        parser.error("--cert/--key cannot be combined with --letsencrypt or --sslip")

    if args.letsencrypt and not args.domain and not args.sslip:
        parser.error("--letsencrypt requires --domain unless --sslip is used")
    if args.sslip and args.domain:
        parser.error("--sslip cannot be combined with --domain")
    if args.public_ip and not args.sslip:
        parser.error("--public-ip requires --sslip")

    if not acme_mode:
        acme_only_flags = [
            ("--domain", args.domain),
            ("--email", args.email),
            ("--acme-staging", args.acme_staging),
            ("--acme-server", args.acme_server),
            ("--acme-http-address", args.acme_http_address),
            ("--acme-http-port", args.acme_http_port != 80),
        ]
        for flag, active in acme_only_flags:
            if active:
                parser.error(f"{flag} requires --letsencrypt or --sslip")

    if args.auth and args.auth_file:
        parser.error("--auth and --auth-file cannot be combined")
    if args.auth_file == "":
        parser.error("--auth-file value must not be empty")


def _collect_explicit_cli_dests(
    parser: argparse.ArgumentParser,
    argv: Sequence[str],
) -> set[str]:
    """Return argparse destinations explicitly present in ``argv``."""
    option_to_dest: dict[str, str] = {}
    for action in parser._actions:
        for option in action.option_strings:
            option_to_dest[option] = action.dest

    explicit: set[str] = set()
    for token in argv:
        option = token.split("=", 1)[0]
        if option in option_to_dest:
            explicit.add(option_to_dest[option])
            continue
        if token.startswith("-") and not token.startswith("--"):
            for short_option, dest in option_to_dest.items():
                if (
                    len(short_option) == 2
                    and short_option.startswith("-")
                    and token.startswith(short_option)
                    and len(token) > len(short_option)
                ):
                    explicit.add(dest)
                    break
    return explicit


_CLI_TO_SETTINGS: dict[str, str] = {
    "preset": "preset",
    "host": "host",
    "port": "port",
    "dir": "root_dir",
    "quiet": "quiet",
    "debug": "debug",
    "open": "open_browser",
    "json_log": "json_log",
    "cors_origin": "cors_origin",
    "max_size": "max_size_mb",
    "upload_storage_limit": "upload_storage_limit_mb",
    "upload_file_limit": "upload_file_limit",
    "upload_reserve_free": "upload_reserve_free_mb",
    "upload_quota_externally_managed": "upload_quota_externally_managed",
    "note_storage_limit": "note_storage_limit_mb",
    "note_count_limit": "note_count_limit",
    "smuggle_temp_age": "smuggle_temp_age",
    "smuggle_temp_file_limit": "smuggle_temp_file_limit",
    "smuggle_temp_storage_limit": "smuggle_temp_storage_limit_mb",
    "max_header_size": "max_header_size_kb",
    "body_memory_budget": "body_memory_budget_mb",
    "body_idle_timeout": "body_idle_timeout",
    "body_timeout": "body_timeout",
    "body_min_rate": "body_min_rate",
    "stream_send_idle_timeout": "stream_send_idle_timeout",
    "stream_send_timeout": "stream_send_timeout",
    "max_websocket_connections": "max_websocket_connections",
    "websocket_frame_idle_timeout": "websocket_frame_idle_timeout",
    "workers": "workers",
    "tls": "tls",
    "cert": "cert_file",
    "key": "key_file",
    "letsencrypt": "letsencrypt",
    "domain": "domain",
    "email": "email",
    "sslip": "sslip",
    "public_ip": "public_ip",
    "acme_staging": "acme_staging",
    "acme_server": "acme_server",
    "acme_http_address": "acme_http_address",
    "acme_http_port": "acme_http_port",
    "auth": "auth",
    "auth_file": "auth_file",
}


def _cli_values_from_args(
    args: argparse.Namespace,
    explicit_dests: set[str],
) -> dict[str, object]:
    """Build settings values from only explicitly supplied CLI options."""
    values: dict[str, object] = {}
    for dest, field_name in _CLI_TO_SETTINGS.items():
        if dest not in explicit_dests:
            continue
        values[field_name] = getattr(args, dest)
    return values


def _install_shutdown_signal_handlers(server: XFerryServer) -> dict[signal.Signals, Any]:
    """Install graceful shutdown handlers for container-style termination."""
    previous_handlers: dict[signal.Signals, Any] = {}
    sigterm = getattr(signal, "SIGTERM", None)
    if sigterm is None:
        return previous_handlers

    def _handle_shutdown(_signum: int, _frame: FrameType | None) -> None:
        server.stop()

    previous_handlers[sigterm] = signal.getsignal(sigterm)
    signal.signal(sigterm, _handle_shutdown)
    return previous_handlers


def _restore_signal_handlers(previous_handlers: dict[signal.Signals, Any]) -> None:
    """Restore any signal handlers replaced for graceful shutdown."""
    for sig, handler in previous_handlers.items():
        signal.signal(sig, handler)


def _stdout_is_interactive() -> bool:
    """Return whether generated credentials can be shown to the operator."""
    return bool(sys.stdout.isatty())


def run_main(argv: Sequence[str] | None = None) -> int:
    """Main entry point."""
    parser = create_parser()
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    explicit_dests = _collect_explicit_cli_dests(parser, actual_argv)
    args = parser.parse_args(actual_argv)

    if args.write_sample_config:
        Path(args.write_sample_config).write_text(sample_config_text(), encoding="utf-8")
        return 0

    try:
        file_settings = load_settings_file(args.config, validate=False) if args.config else None
        settings = resolve_settings(
            file_settings=file_settings,
            env=dict(os.environ),
            cli_values=_cli_values_from_args(args, explicit_dests),
        )
        server_config = settings.to_server_config()
    except ValueError as exc:
        parser.error(str(exc))

    posture = server_config.runtime_posture
    assert posture is not None

    if args.check_config:
        print("Configuration valid.")
        print("\n".join(posture.render_lines()))
        return 0

    if args.print_config:
        rendered = settings.to_redacted_dict()
        rendered["runtime_posture"] = posture.to_dict()
        print(json.dumps(rendered, indent=2, sort_keys=True))
        return 0

    if settings.preset is LaunchPreset.LOCAL_SECURE and not _stdout_is_interactive():
        if settings.auth_file is None:
            parser.error(
                "local-secure non-interactive/service launches require --auth-file FILE; "
                "generated or inline credentials are interactive-only"
            )

    try:
        server = XFerryServer(server_config)
        previous_handlers = _install_shutdown_signal_handlers(server)
        try:
            server.start()
        finally:
            _restore_signal_handlers(previous_handlers)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the public console command through the management CLI."""
    from .management.cli import main as management_main

    return management_main(argv)


if __name__ == "__main__":
    sys.exit(main())
