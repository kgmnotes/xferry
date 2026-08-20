"""Dispatcher for XFerry management commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

from xferry.config import __version__

from .i18n import LanguageSelection, Translator, resolve_language

if TYPE_CHECKING:
    from .model import SetupPlan, SetupPreflight
    from .releases import ReleaseResult
    from .setup import Credentials, CredentialsResult, SetupResult
_PRIMARY_COMMANDS = (
    "run",
    "setup",
    "status",
    "logs",
    "start",
    "stop",
    "restart",
    "doctor",
    "credentials",
    "examples",
    "uninstall",
)
_MAINTENANCE_COMMANDS = (
    "update",
    "rollback",
)
_COMMANDS = (
    *_PRIMARY_COMMANDS,
    *_MAINTENANCE_COMMANDS,
    "help",
)
_LINUX_MANAGEMENT_COMMANDS = frozenset(_COMMANDS) - {"examples", "help", "run"}

_COMMAND_EXAMPLES = {
    "run": "xferry run --preset local",
    "setup": "sudo xferry setup",
    "status": "sudo xferry status",
    "logs": "xferry logs",
    "start": "sudo xferry start",
    "stop": "sudo xferry stop",
    "restart": "sudo xferry restart",
    "doctor": "sudo xferry doctor",
    "credentials": "sudo xferry credentials reset",
    "update": f"sudo xferry update --version {__version__}",
    "rollback": f"sudo xferry rollback --to {__version__}",
    "uninstall": "sudo xferry uninstall",
    "examples": "xferry examples",
}


@dataclass(frozen=True)
class ManagementContext:
    """Shared dispatcher state provided to management command handlers."""

    language: LanguageSelection
    translator: Translator


CommandHandler = Callable[[argparse.Namespace, ManagementContext], int]


class _Parser(argparse.ArgumentParser):
    """Argument parser that provides an integer usage result to the dispatcher."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def _strip_global_language(argv: Sequence[str]) -> list[str]:
    """Remove global language options while preserving the remaining token order."""
    remaining: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--lang":
            if index + 1 == len(argv):
                raise ValueError("--lang requires a language value")
            index += 2
            continue
        if token.startswith("--lang="):
            if token == "--lang=":
                raise ValueError("--lang requires a language value")
            index += 1
            continue
        remaining.append(token)
        index += 1
    return remaining


def _root_help(translator: Translator) -> str:
    """Build the compact management reference shown by ``xferry help``."""
    command_lines = "\n".join(f"  {command}" for command in _PRIMARY_COMMANDS)
    maintenance_lines = "\n".join(f"  {command}" for command in _MAINTENANCE_COMMANDS)
    return "\n".join(
        (
            "usage: xferry [--lang LANG] COMMAND [OPTIONS]",
            "",
            translator.get("root_description"),
            "",
            translator.get("commands_heading"),
            command_lines,
            "",
            translator.get("maintenance_heading"),
            maintenance_lines,
            "",
            translator.get("examples_heading"),
            translator.get("root_examples"),
        )
    )


def _command_parser(command: str, translator: Translator) -> _Parser:
    """Build a focused parser for one current or future management command."""
    description = translator.get(f"command_{command}")
    parser = _Parser(
        prog=f"xferry {command}",
        description=description,
        epilog=translator.get("command_example", example=_COMMAND_EXAMPLES[command]),
        formatter_class=lambda prog: argparse.HelpFormatter(prog, width=100),
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help=translator.get("help_option"))
    if command == "setup":
        setup_mode = parser.add_mutually_exclusive_group()
        setup_mode.add_argument("--domain", metavar="DOMAIN")
        setup_mode.add_argument("--private", action="store_true")
        parser.add_argument("--public-ip", metavar="IP")
        parser.add_argument("--email", metavar="EMAIL")
        parser.add_argument("--body-budget-mib", type=int, metavar="MIB")
        parser.add_argument("--max-upload-mib", type=int, metavar="MIB")
        parser.add_argument("--workers", type=int, metavar="COUNT")
        parser.add_argument("--reserve-mib", type=int, metavar="MIB")
        parser.add_argument("--upload-storage-mib", type=int, metavar="MIB")
        parser.add_argument("--firewall", choices=("allow", "deny"))
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--json", action="store_true")
    elif command == "credentials":
        parser.add_argument("action", choices=("reset",))
        parser.add_argument("--json", action="store_true")
    elif command == "status":
        parser.add_argument("--json", action="store_true")
    elif command == "logs":
        parser.add_argument("--lines", type=int, default=100, metavar="COUNT")
        parser.add_argument("--since", metavar="WHEN")
        parser.add_argument("--follow", action="store_true")
    elif command == "doctor":
        parser.add_argument("--deep", action="store_true")
        parser.add_argument("--skip-network", action="store_true")
        parser.add_argument("--json", action="store_true")
    elif command == "update":
        parser.add_argument("--version", metavar="VERSION")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--json", action="store_true")
    elif command == "rollback":
        parser.add_argument("--to", metavar="VERSION")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--json", action="store_true")
    elif command == "uninstall":
        parser.add_argument("--purge-data", action="store_true")
        parser.add_argument("--yes", action="store_true")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--json", action="store_true")
    return parser


def _examples_handler(_args: argparse.Namespace, context: ManagementContext) -> int:
    """Print localized, copy-paste-safe management examples."""
    print(context.translator.get("examples_heading"))
    print(context.translator.get("all_examples"))
    return 0


def _not_implemented_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    """Return the stable operation failure result until later command tasks land."""
    print(context.translator.get("not_implemented", command=args.command), file=sys.stderr)
    return 1


def _setup_handler(args: argparse.Namespace, _context: ManagementContext) -> int:
    """Plan, display, and transactionally apply a managed setup."""
    option_error = _setup_option_error(args)
    if option_error is not None:
        print(f"xferry setup: error: {option_error}", file=sys.stderr)
        return 2
    if not args.dry_run and os.geteuid() != 0:
        return _render_operation_result(
            _OperationResult(3, "managed setup requires root"),
            json_output=args.json,
        )
    try:
        plan, preflight = _prepare_setup_plan(args)
    except ValueError as exc:
        print(f"xferry setup: error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError:
        print("xferry setup: network discovery failed", file=sys.stderr)
        return 5
    except OSError:
        print("xferry setup: host inspection failed", file=sys.stderr)
        return 1

    if not preflight.ok:
        from .setup import preflight_result

        result = preflight_result(preflight)
        return _render_operation_result(result, json_output=args.json)
    if args.dry_run:
        _render_dry_run(plan, json_output=args.json)
        return 0

    _display_plan_before_mutation(plan, json_output=args.json)
    result = _apply_setup_plan(plan, preflight)
    return _render_operation_result(result, json_output=args.json)


def _credentials_handler(args: argparse.Namespace, _context: ManagementContext) -> int:
    """Rotate managed credentials under the shared mutation boundary."""
    if os.geteuid() != 0:
        return _render_operation_result(
            _OperationResult(3, "credential reset requires root"),
            json_output=args.json,
        )
    try:
        from xferry.security.tls import sslip_domain_for_ip
        from xferry.settings import load_settings_file

        from .health import HealthEndpoint
        from .model import ManagedLayout
        from .setup import CredentialsContext, reset_credentials
        from .system import CommandRunner

        settings = load_settings_file("/etc/xferry/xferry.ini")
        tls = settings.effective_tls_enabled()
        host = settings.domain
        if host is None and settings.sslip and settings.public_ip:
            host = sslip_domain_for_ip(settings.public_ip)
        if host is None:
            host = "127.0.0.1"
        result = reset_credentials(
            CredentialsContext(
                layout=ManagedLayout(),
                endpoint=HealthEndpoint("127.0.0.1", settings.port, host, tls=tls),
                runner=CommandRunner(),
            )
        )
    except (OSError, ValueError) as exc:
        print(f"xferry credentials: error: {exc}", file=sys.stderr)
        return 2
    return _render_operation_result(result, json_output=args.json)


def _status_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    """Render root-gated, read-only fixed-unit status without taking the mutation lock."""
    from .service import default_service_context, service_status

    status = service_status(default_service_context())
    if args.json:
        print(json.dumps(status.to_json(), sort_keys=True))
    else:
        print(
            context.translator.get(
                "service_status_text",
                installation=context.translator.managed_text("status", status.installation),
                config=context.translator.managed_text("status", status.config),
                enabled=context.translator.managed_text("status", status.enabled),
                service=context.translator.managed_text("status", status.service),
                health=context.translator.managed_text("status", status.health),
            )
        )
    return status.exit_code


def _logs_handler(args: argparse.Namespace, _context: ManagementContext) -> int:
    """Delegate fixed-unit journal output while preserving journalctl's exit code."""
    from .service import default_service_context, stream_logs

    return stream_logs(args.lines, args.since, args.follow, default_service_context())


def _service_action_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    """Perform one root-gated fixed-unit lifecycle operation."""
    from .service import default_service_context, service_action

    exit_code = service_action(args.command, default_service_context())
    if exit_code:
        print(
            context.translator.get(
                "service_action_failed",
                action=context.translator.managed_text("action", args.command),
            ),
            file=sys.stderr,
        )
    else:
        print(
            context.translator.get(
                "service_action_done",
                action=context.translator.managed_text("action", args.command),
            )
        )
    return exit_code


def _doctor_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    """Render local and optionally deep secret-free managed diagnostics."""
    from .service import DoctorOptions, default_service_context, run_doctor

    report = run_doctor(
        DoctorOptions(deep=args.deep, skip_network=args.skip_network), default_service_context()
    )
    if args.json:
        print(json.dumps(report.to_json(), sort_keys=True))
    else:
        for name, check in report.checks.items():
            print(
                context.translator.get(
                    "doctor_check_text",
                    name=context.translator.managed_text("check", name),
                    status=context.translator.managed_text("status", check.status),
                    detail=context.translator.managed_text("detail", check.detail),
                )
            )
    return report.exit_code


def _release_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    """Run one verified release lifecycle command through injectable boundaries."""
    from .releases import default_release_manager

    manager = default_release_manager()
    if args.command == "update":
        result = manager.update(args.version, args.dry_run)
    elif args.command == "rollback":
        result = manager.rollback(args.to, args.dry_run)
    else:
        confirmed = bool(args.yes)
        if args.purge_data and not confirmed and sys.stdin.isatty():
            response = input(context.translator.get("purge_prompt"))
            confirmed = response.strip().casefold() in {"y", "yes"}
        result = manager.uninstall(args.purge_data, confirmed, args.dry_run)
    return _render_release_result(result, context=context, json_output=args.json)


def _render_release_result(
    result: ReleaseResult,
    *,
    context: ManagementContext,
    json_output: bool,
) -> int:
    if json_output:
        payload: dict[str, object] = {
            "dry_run": result.dry_run,
            "exit_code": result.exit_code,
            "message": result.message,
            "status": "ok" if result.exit_code == 0 else "error",
        }
        if result.version is not None:
            payload["version"] = result.version
        print(json.dumps(payload, sort_keys=True))
        return result.exit_code
    message = context.translator.release_text(result.message, version=result.version)
    print(message, file=sys.stderr if result.exit_code else sys.stdout)
    return result.exit_code


def _setup_option_error(args: argparse.Namespace) -> str | None:
    if args.private and args.public_ip is not None:
        return "--private cannot be combined with --public-ip"
    if args.private and args.email is not None:
        return "--private cannot be combined with --email"
    if args.domain is not None and args.public_ip is not None:
        return "--domain cannot be combined with --public-ip"
    return None


def _prepare_setup_plan(args: argparse.Namespace) -> tuple[SetupPlan, SetupPreflight]:
    """Create and preflight one immutable plan without changing the host."""
    from .model import ManagedLayout, ResourceOverrides, SetupMode, SetupOptions
    from .planning import build_setup_plan
    from .platform import detect_host_facts
    from .setup import default_setup_preflight, ufw_is_active
    from .system import CommandRunner

    layout = ManagedLayout()
    runner = CommandRunner()
    mode = (
        SetupMode.PRIVATE
        if args.private
        else (SetupMode.DOMAIN if args.domain is not None else SetupMode.SSLIP)
    )
    firewall_answer = {"allow": True, "deny": False}.get(args.firewall)
    interactive = bool(sys.stdin.isatty())
    if mode is not SetupMode.PRIVATE and firewall_answer is None and ufw_is_active(runner):
        if interactive:
            response = input("Allow UFW rules for 80/tcp and 443/tcp? [y/N] ")
            firewall_answer = response.strip().casefold() in {"y", "yes"}
    facts = detect_host_facts(data_path=layout.data_root)
    plan = build_setup_plan(
        SetupOptions(
            mode=mode,
            domain=args.domain,
            public_ip=args.public_ip,
            email=args.email,
            firewall_answer=firewall_answer,
            resources=ResourceOverrides(
                body_budget_mib=args.body_budget_mib,
                max_upload_mib=args.max_upload_mib,
                workers=args.workers,
                reserve_mib=args.reserve_mib,
                upload_storage_mib=args.upload_storage_mib,
            ),
            layout=layout,
        ),
        facts,
    )
    return plan, default_setup_preflight(plan, runner, interactive=interactive)


def _apply_setup_plan(plan: SetupPlan, preflight: SetupPreflight) -> SetupResult:
    """Apply the exact successfully preflighted plan, rechecking it under lock."""
    from .setup import SetupExecutor, preflight_result

    if not preflight.ok:
        return preflight_result(preflight)
    return SetupExecutor().apply(plan)


def _display_plan_before_mutation(plan: SetupPlan, *, json_output: bool) -> None:
    message = (
        f"Setup plan: mode={plan.mode.value}, port={plan.port}, "
        f"workers={plan.resources.workers}, body_budget_mib={plan.resources.body_budget_mib}, "
        f"upload_storage_mib={plan.resources.upload_storage_mib}"
    )
    print(message, file=sys.stderr if json_output else sys.stdout)


def _render_dry_run(plan: SetupPlan, *, json_output: bool) -> None:
    payload = {
        "body_budget_mib": plan.resources.body_budget_mib,
        "dry_run": True,
        "firewall_action": plan.firewall_action,
        "firewall_ports": list(plan.firewall_ports),
        "mode": plan.mode.value,
        "port": plan.port,
        "status": "ok",
        "upload_storage_mib": plan.resources.upload_storage_mib,
        "workers": plan.resources.workers,
    }
    if json_output:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("Dry run; no managed state was changed.")
        _display_plan_before_mutation(plan, json_output=False)


def _render_operation_result(
    result: _OperationResult | SetupResult | CredentialsResult,
    *,
    json_output: bool,
) -> int:
    credentials: Credentials | None = result.credentials
    if json_output:
        payload: dict[str, object] = {
            "exit_code": result.exit_code,
            "status": "ok" if result.exit_code == 0 else "error",
        }
        if credentials is not None:
            payload["url"] = credentials.url
        else:
            payload["message"] = result.message
        print(json.dumps(payload, sort_keys=True))
        if credentials is not None:
            print(
                f"Credentials: {credentials.username}:{credentials.password}",
                file=sys.stderr,
            )
        return result.exit_code

    if credentials is None:
        print(result.message, file=sys.stderr if result.exit_code else sys.stdout)
        return result.exit_code
    print(f"URL: {credentials.url}")
    print(f"Credentials: {credentials.username}:{credentials.password}")
    return result.exit_code


@dataclass(frozen=True)
class _OperationResult:
    """Portable operation result used before a Linux backend is available."""

    exit_code: int
    message: str
    credentials: None = None


def _run_management(command: str, argv: Sequence[str], context: ManagementContext) -> int:
    """Parse and run an internal management command."""
    if command == "help":
        if not argv:
            print(_root_help(context.translator))
            return 0
        if len(argv) != 1 or argv[0] not in _COMMAND_EXAMPLES:
            print(f"xferry help: {context.translator.get('usage_error')}", file=sys.stderr)
            return 2
        _command_parser(argv[0], context.translator).print_help()
        return 0

    parser = _command_parser(command, context.translator)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    args.command = command
    if command in _LINUX_MANAGEMENT_COMMANDS and sys.platform != "linux":
        print(f"xferry {command}: managed operations require Linux", file=sys.stderr)
        return 4
    handlers: dict[str, CommandHandler] = {
        "credentials": _credentials_handler,
        "doctor": _doctor_handler,
        "examples": _examples_handler,
        "logs": _logs_handler,
        "rollback": _release_handler,
        "setup": _setup_handler,
        "start": _service_action_handler,
        "status": _status_handler,
        "stop": _service_action_handler,
        "uninstall": _release_handler,
        "update": _release_handler,
        "restart": _service_action_handler,
    }
    handler = handlers.get(command, _not_implemented_handler)
    return handler(args, context)


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch management commands and the canonical ``xferry run`` server CLI."""
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        language = resolve_language(actual_argv, os.environ)
        remaining = _strip_global_language(actual_argv)
    except ValueError as exc:
        print(f"xferry: error: {exc}", file=sys.stderr)
        return 2

    context = ManagementContext(language=language, translator=Translator(language))
    if not remaining:
        print(_root_help(context.translator))
        return 0

    if len(remaining) == 1 and remaining[0] in {"-h", "--help"}:
        print(_root_help(context.translator))
        return 0

    if remaining and remaining[0] in _COMMANDS:
        command = remaining[0]
        if command == "run":
            from xferry.cli import run_main

            return run_main(remaining[1:])
        return _run_management(command, remaining[1:], context)

    print(_root_help(context.translator), file=sys.stderr)
    print(f"xferry: error: {context.translator.get('usage_error')}", file=sys.stderr)
    return 2
