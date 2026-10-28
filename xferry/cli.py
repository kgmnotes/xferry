#!/usr/bin/env python3
"""
CLI entry point for XFerryServer.
"""

import argparse
import os
import signal
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import replace
from pathlib import Path
from types import FrameType
from typing import Any, TypeVar, overload

from .config import __version__
from .paths import default_config_path
from .server import XFerryServer
from .settings import (
    ServerSettings,
    load_settings_file,
    resolve_settings,
)
from .settings_schema import (
    CLI_GROUP_ORDER,
    SETTING_SPECS,
    CliGroup,
    cli_setting_specs,
    cli_to_setting_map,
)

_NORMAL_HELP_DESTS = frozenset(
    {
        "help",
        "help_all",
        "version",
        "config",
        "open_browser",
    }
    | {spec.cli.dest for spec in SETTING_SPECS if spec.cli is not None and spec.cli.normal_help}
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


class _StableHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep option invocations stable across supported argparse versions."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, width=78)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            (metavar,) = self._metavar_formatter(action, default)(1)
            return metavar
        if action.nargs == 0:
            return ", ".join(action.option_strings)

        default = self._get_default_metavar_for_optional(action)
        arguments = self._format_args(action, default)
        return ", ".join(f"{option} {arguments}" for option in action.option_strings)


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


def _format_cli_default(value: object) -> str:
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _add_setting_arguments(
    group: argparse._ArgumentGroup,
    group_name: CliGroup,
    defaults: ServerSettings,
) -> None:
    """Declare one argparse group entirely from canonical settings metadata."""
    for spec in cli_setting_specs(group_name):
        cli = spec.cli
        assert cli is not None
        runtime_default = getattr(defaults, spec.name)
        help_text = cli.help.format(default=_format_cli_default(runtime_default))
        kwargs: dict[str, Any] = {
            "dest": cli.dest,
            "default": runtime_default if cli.default_from_runtime else None,
            "help": help_text,
        }
        if cli.action == "append":
            kwargs["action"] = "append"
        elif cli.action == "boolean_optional":
            kwargs["action"] = argparse.BooleanOptionalAction
        elif cli.action == "store_true":
            kwargs["action"] = "store_true"
        if cli.metavar is not None:
            kwargs["metavar"] = cli.metavar
        if cli.choices:
            kwargs["choices"] = list(cli.choices)
        if cli.parser_kind == "integer":
            assert cli.parser_label is not None and cli.minimum is not None
            kwargs["type"] = _bounded_int(
                cli.parser_label,
                minimum=int(cli.minimum),
                maximum=None if cli.maximum is None else int(cli.maximum),
            )
        elif cli.parser_kind == "number":
            assert cli.parser_label is not None and cli.minimum is not None
            kwargs["type"] = _bounded_float(
                cli.parser_label,
                minimum=float(cli.minimum),
                maximum=None if cli.maximum is None else float(cli.maximum),
            )
        action = group.add_argument(*cli.option_strings, **kwargs)
        if cli.action == "boolean_optional":
            # Python 3.10 mutates this help string while constructing the action.
            action.help = help_text


_RETIRED_OPTIONS = {
    "--preset": "--access private|public|lab",
    "--public-direct": "--access public",
    "--tls": "--https self-signed",
    "--no-tls": "--https off",
    "--letsencrypt": "--https domain",
    "--sslip": "--https auto",
    "--acme-staging": "--acme-server staging",
    "--auth": "--auth-file FILE (generate it with xferry credentials)",
    "--quiet": "--log-level warning",
    "-q": "--log-level warning",
    "--debug": "--log-level debug",
    "--json-log": "--log-format json",
    "--dir": "--files-dir DIR",
    "-d": "--files-dir DIR",
    "--check-config": "xferry config check",
    "--print-config": "xferry config show",
    "--write-sample-config": "xferry config sample",
}


_NamespaceT = TypeVar("_NamespaceT")


class _RunArgumentParser(argparse.ArgumentParser):
    @overload
    def parse_known_args(
        self,
        args: Iterable[str] | None = None,
        namespace: None = None,
    ) -> tuple[argparse.Namespace, list[str]]: ...

    @overload
    def parse_known_args(
        self,
        args: Iterable[str] | None,
        namespace: _NamespaceT,
    ) -> tuple[_NamespaceT, list[str]]: ...

    @overload
    def parse_known_args(
        self,
        *,
        namespace: _NamespaceT,
    ) -> tuple[_NamespaceT, list[str]]: ...

    def parse_known_args(
        self,
        args: Iterable[str] | None = None,
        namespace: Any = None,
    ) -> tuple[Any, list[str]]:
        # Reject secrets-bearing retired options before argparse can echo values.
        tokens = list(sys.argv[1:] if args is None else args)
        for token in tokens:
            option = token.split("=", 1)[0]
            if option in _RETIRED_OPTIONS:
                self.error(f"removed option {option}; use {_RETIRED_OPTIONS[option]}")
            if token.startswith("-d") and not token.startswith("--") and len(token) > 2:
                self.error("removed option -d; use --files-dir DIR")
        return super().parse_known_args(tokens, namespace)


def create_parser(*, show_all_help: bool = False) -> argparse.ArgumentParser:
    """Create and configure the foreground-server argument parser."""
    description = """Run the file server on this host.

By default it listens at http://127.0.0.1:8080 and uses your saved configuration.
Use xferry setup for an installed service, or xferry config to change settings.
Use --help-all for every limit, certificate and protocol option."""
    epilog = """Examples:
  xferry run --open
  xferry run --files-dir ./shared
  xferry run --access public --auth-file /path/to/auth
  xferry run --config ./xferry.ini

INI settings are overridden by XFERRY_* environment variables, then explicit
command options. Use xferry config show --all to see effective values and sources.
"""
    parser = _RunArgumentParser(
        prog="xferry run",
        description=description,
        formatter_class=_StableHelpFormatter,
        epilog=epilog,
        allow_abbrev=False,
    )

    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--help-all",
        action=_HelpAllAction,
        nargs=0,
        help="Show every configuration, limit, TLS and protocol option",
    )

    defaults = ServerSettings()
    groups: dict[CliGroup, argparse._ArgumentGroup] = {}
    config_group = parser.add_argument_group("Configuration")
    groups["Configuration"] = config_group
    _add_setting_arguments(config_group, "Configuration", defaults)
    config_group.add_argument(
        "--config",
        metavar="FILE",
        help="Read settings from an INI configuration file",
    )
    config_group.add_argument(
        "--open",
        dest="open_browser",
        action="store_true",
        help="Open the server in your browser after it starts",
    )

    # Basic
    basic = parser.add_argument_group("Basic")
    groups["Basic"] = basic
    _add_setting_arguments(basic, "Basic", defaults)

    # Operating modes
    modes = parser.add_argument_group("Modes")
    groups["Modes"] = modes
    _add_setting_arguments(modes, "Modes", defaults)
    # Limits
    limits = parser.add_argument_group("Limits")
    groups["Limits"] = limits
    _add_setting_arguments(limits, "Limits", defaults)

    # TLS options
    tls = parser.add_argument_group("TLS")
    groups["TLS"] = tls
    _add_setting_arguments(tls, "TLS", defaults)

    # Authentication
    auth = parser.add_argument_group("Authentication")
    groups["Authentication"] = auth
    _add_setting_arguments(auth, "Authentication", defaults)

    assert tuple(groups) == CLI_GROUP_ORDER

    if not show_all_help:
        for action in parser._actions:
            if action.dest not in _NORMAL_HELP_DESTS:
                action.help = argparse.SUPPRESS

    return parser


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


_CLI_TO_SETTINGS = cli_to_setting_map()


def _cli_values_from_args(
    args: argparse.Namespace,
    explicit_dests: set[str],
) -> dict[str, object]:
    """Build settings values from only explicitly supplied CLI options."""
    values: dict[str, object] = {}
    for dest, field_name in _CLI_TO_SETTINGS.items():
        if dest not in explicit_dests:
            continue
        value = getattr(args, dest)
        values[field_name] = tuple(value) if dest == "allowed_host" else value
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


def run_main(argv: Sequence[str] | None = None) -> int:
    """Resolve one foreground launch and keep process lifecycle predictable."""
    parser = create_parser()
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    explicit_dests = _collect_explicit_cli_dests(parser, actual_argv)
    args = parser.parse_args(actual_argv)
    config_path = Path(args.config).expanduser() if args.config else default_config_path()
    try:
        file_settings = (
            load_settings_file(config_path, validate=False)
            if args.config or config_path.exists()
            else None
        )
        settings = resolve_settings(
            file_settings=file_settings,
            env=dict(os.environ),
            cli_values=_cli_values_from_args(args, explicit_dests),
            config_path=config_path if file_settings is not None else None,
        )
        settings = replace(settings, open_browser=args.open_browser)
        server_config = settings.to_server_config()
        if file_settings is not None:
            assert server_config.files_dir is not None
            if config_path.resolve().is_relative_to(Path(server_config.files_dir)):
                raise ValueError("config file must be outside the public files_dir")
    except ValueError as exc:
        parser.error(str(exc))

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
