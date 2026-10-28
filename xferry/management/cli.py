"""Dispatcher for XFerry management commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast

from xferry.config import __version__

from .i18n import LanguageSelection, Translator, resolve_language

if TYPE_CHECKING:
    from .model import SetupPlan, SetupPreflight
    from .releases import ReleaseResult
    from .setup import Credentials, CredentialsResult, SetupResult
_PRIMARY_COMMANDS = (
    "run",
    "setup",
    "config",
    "status",
    "logs",
    "start",
    "stop",
    "restart",
    "doctor",
    "credentials",
    "uninstall",
)
_MAINTENANCE_COMMANDS = ("update", "rollback")
_COMMANDS = (*_PRIMARY_COMMANDS, *_MAINTENANCE_COMMANDS, "help")
_LINUX_MANAGEMENT_COMMANDS = frozenset({"doctor"})
_COMMAND_EXAMPLES = {
    "run": "xferry run --files-dir ~/Shared",
    "setup": "xferry setup",
    "config": "xferry config explain files_dir",
    "status": "xferry status",
    "logs": "xferry logs --follow",
    "start": "xferry start",
    "stop": "xferry stop",
    "restart": "xferry restart",
    "doctor": "xferry doctor",
    "credentials": "xferry credentials reset",
    "update": f"xferry update --to {__version__}",
    "rollback": "xferry rollback",
    "uninstall": "xferry uninstall",
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
    lines = [
        "usage: xferry [--lang LANG] COMMAND [OPTIONS]",
        "",
        translator.get("root_description"),
        "",
    ]
    for command in (*_PRIMARY_COMMANDS, *_MAINTENANCE_COMMANDS):
        lines.append(f"  {command:<13} {translator.get(f'command_{command}')}")
    lines.extend(
        (
            "",
            translator.get("root_options"),
            "",
            translator.get("examples_heading"),
            translator.get("root_examples"),
        )
    )
    return "\n".join(lines)


def _command_parser(command: str, translator: Translator) -> _Parser:
    parser = _Parser(
        prog=f"xferry {command}",
        description=translator.get(f"command_{command}"),
        epilog=translator.get("command_example", example=_COMMAND_EXAMPLES[command]),
        formatter_class=lambda prog: argparse.HelpFormatter(prog, width=100),
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help=translator.get("help_option"))
    parser.add_argument("--help-all", action="help", help="Show all command options.")
    parser.add_argument(
        "--config", metavar="FILE", help="Select a server by its configuration file."
    )
    if command == "setup":
        parser.add_argument(
            "--docker", action="store_true", help="Use Docker Compose instead of a Linux service."
        )
        parser.add_argument(
            "--access",
            choices=("private", "public"),
            help="Private access or public HTTPS (default: public).",
        )
        parser.add_argument("--domain", metavar="DOMAIN", help="Use your domain for public HTTPS.")
        parser.add_argument(
            "--files-dir", metavar="DIR", help="Host folder for uploads and downloads."
        )
        parser.add_argument(
            "--public-ip", metavar="IP", help="Public IPv4 for the automatic HTTPS address."
        )
        parser.add_argument(
            "--email", metavar="EMAIL", help="Optional certificate contact address."
        )
        parser.add_argument(
            "--firewall", choices=("allow", "deny"), help="Allow or decline required UFW rules."
        )
        parser.add_argument(
            "--to",
            default=__version__,
            metavar="VERSION",
            help="Signed release version to install.",
        )
        parser.set_defaults(
            body_budget_mib=None,
            max_upload_mib=None,
            workers=None,
            reserve_mib=None,
            upload_storage_mib=None,
        )
    elif command == "config":
        parser.add_argument(
            "action",
            nargs="?",
            choices=("show", "explain", "check", "set"),
            help="Omit to open the settings wizard.",
        )
        parser.add_argument("values", nargs="*", metavar="KEY[=VALUE]")
        parser.add_argument("--all", action="store_true", help="Show every setting.")
        parser.add_argument("--group", metavar="GROUP", help="Show one settings group.")
        parser.add_argument(
            "--search", metavar="TEXT", help="Find settings by name or description."
        )
    elif command == "credentials":
        parser.add_argument(
            "action", choices=("reset",), help="Generate a new 12-character password."
        )
    elif command == "logs":
        parser.add_argument(
            "--lines",
            type=int,
            default=100,
            metavar="COUNT",
            help="Number of recent log lines (default: 100).",
        )
        parser.add_argument("--since", metavar="WHEN", help="Show logs since this time.")
        parser.add_argument("--follow", action="store_true", help="Stream new log lines.")
    elif command == "doctor":
        parser.add_argument(
            "--deep", action="store_true", help="Include external connectivity checks."
        )
        parser.add_argument("--skip-network", action="store_true", help="Check local state only.")
    elif command in {"update", "rollback"}:
        parser.add_argument(
            "--to", required=command == "update", metavar="VERSION", help="Exact release version."
        )
    elif command == "uninstall":
        parser.add_argument(
            "--purge-data",
            action="store_true",
            help="Also delete configuration, credentials and stored data.",
        )
        parser.add_argument("--yes", action="store_true", help="Confirm deletion without a prompt.")
    if command in {"setup", "config", "update", "rollback", "uninstall"}:
        parser.add_argument("--dry-run", action="store_true", help="Validate and preview changes.")
    if command not in {"logs", "start", "stop", "restart"}:
        parser.add_argument("--json", action="store_true", help="Print machine-readable results.")
    return parser


def _not_implemented_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    """Return the stable operation failure result until later command tasks land."""
    print(context.translator.get("not_implemented", command=args.command), file=sys.stderr)
    return 1


def _configure_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    from .wizard import configure

    if not sys.stdin.isatty():
        print(
            "xferry config requires a terminal; use config show/check/set for automation",
            file=sys.stderr,
        )
        return 2
    if args.json or args.dry_run or args.all or args.group or args.search:
        print(
            "xferry config: choose show/check/set to use output or preview options", file=sys.stderr
        )
        return 2
    return configure(
        Path(args.config),
        args.target,
        context.language.code,
        dispatch=lambda argv: main(["--lang", context.language.code, *argv]),
    )


def _config_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    from xferry.settings import load_settings_text, resolve_settings

    from .configuration import (
        annotate_host_folder,
        change_configuration,
        describe_settings,
        parse_assignments,
        render_rows,
        state_for_config,
    )

    try:
        if args.action is None:
            return _configure_handler(args, context)
        path = Path(args.config) if args.config else None
        target = args.target
        environment = dict(os.environ) if target == "portable" else {}
        if args.action == "set":
            if not args.values or path is None:
                raise ValueError("config set requires at least one KEY=VALUE")
            changes = parse_assignments(args.values)
            if target == "docker":
                from .docker_deploy import default_files_directory, deploy_docker

                folder = changes.pop("files_dir", None)
                selected_folder = (
                    (Path(folder).expanduser().resolve() if folder else default_files_directory())
                    if folder is not None
                    else None
                )
                result = deploy_docker(
                    path.parent,
                    files_dir=selected_folder,
                    settings_changes=changes,
                    dry_run=args.dry_run,
                )
                print(
                    json.dumps({"exit_code": result.exit_code, "message": result.message})
                    if args.json
                    else result.message
                )
                return result.exit_code
            changed = change_configuration(path, changes, target=target, dry_run=args.dry_run)
            if args.json:
                print(
                    json.dumps(
                        {
                            "exit_code": changed.exit_code,
                            "message": changed.message,
                            "changed": changed.changed,
                            "applied": changed.applied,
                            "diff": changed.diff,
                        },
                        ensure_ascii=False,
                    )
                )
            else:
                if changed.diff:
                    print(changed.diff, end="")
                print(changed.message)
            return changed.exit_code
        key = None
        if args.action == "explain":
            if len(args.values) != 1:
                raise ValueError("config explain requires one setting name")
            key = args.values[0]
        elif args.values:
            raise ValueError(f"config {args.action} does not accept positional values")
        text = path.read_text(encoding="utf-8") if path and path.exists() else ""
        state = state_for_config(path, target) if path else None
        if args.action == "check":
            if path is None or not path.is_file():
                raise ValueError("configuration file does not exist; run xferry config first")
            resolve_settings(
                file_settings=load_settings_text(text, validate=False),
                env=environment,
                state_dir=state,
                config_path=path,
            ).to_server_config()
            print(
                json.dumps({"status": "ok", "config": str(path)})
                if args.json
                else "Configuration is valid."
            )
            return 0
        rows = describe_settings(
            text,
            env=environment,
            all_settings=args.all,
            group=args.group,
            search=args.search,
            key=key,
            state_dir=state,
            config_path=path,
        )
        if path and path.exists():
            annotate_host_folder(rows, path, target)
        if args.action == "show" and args.all and not args.group and not args.search:
            effective = resolve_settings(
                file_settings=load_settings_text(text, validate=False),
                env=environment,
                state_dir=state,
                config_path=path,
            )
            rows.append(
                {
                    "name": "state_directory",
                    "group": "paths",
                    "description": "Private notes and server state. "
                    "Managed automatically; this is not a setting.",
                    "value": effective.root_dir,
                    "effective": effective.root_dir,
                    "source": "internal",
                    "read_only": True,
                }
            )
        render_rows(rows, json_output=args.json)
        if key and not args.json:
            row = rows[0]
            for label, field in (
                ("Default", "default"),
                ("INI", "ini"),
                ("Environment", "environment"),
                ("CLI", "cli"),
                ("Example", "example"),
                ("Constraints", "constraints"),
                ("Dependencies", "dependencies"),
                ("Applies to", "applicability"),
                ("Apply", "apply"),
            ):
                print(f"{label}: {row[field]}")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        if args.json:
            print(json.dumps({"status": "error", "exit_code": 2, "message": str(exc)}))
        else:
            print(f"xferry config: error: {exc}", file=sys.stderr)
        return 2


def _setup_handler(args: argparse.Namespace, _context: ManagementContext) -> int:
    """Plan, display, and transactionally apply a managed setup."""
    from .versions import is_supported_release_version

    if not is_supported_release_version(args.to):
        raise ValueError("--to requires an exact supported release version, such as " + __version__)
    interactive_wizard = bool(sys.stdin.isatty()) and not args.json and not args.dry_run
    if args.docker:
        from .docker_deploy import deploy_docker
        from .instances import user_data_dir
        from .wizard import docker_wizard

        path = (
            Path(args.config).expanduser().absolute()
            if args.config
            else user_data_dir() / "deployment/xferry.ini"
        )
        if path.name != "xferry.ini":
            raise ValueError("Docker configuration filename must be xferry.ini")
        if path.is_file() and not args.dry_run and interactive_wizard:
            return main(["--lang", _context.language.code, "config", "--config", str(path)])
        if (
            interactive_wizard
            and not args.access
            and not args.domain
            and not args.files_dir
            and args.public_ip is None
            and args.email is None
            and args.to == __version__
        ):
            return docker_wizard(path.parent, _context.language.code)
        docker_result = deploy_docker(
            path.parent,
            files_dir=Path(args.files_dir).expanduser().resolve() if args.files_dir else None,
            domain=args.domain,
            private=args.access == "private",
            public_ip=args.public_ip,
            settings_changes={"email": args.email} if args.email else None,
            image=f"ghcr.io/kgmnotes/xferry:v{args.to}",
            dry_run=args.dry_run,
        )
        payload = {
            "exit_code": docker_result.exit_code,
            "message": docker_result.message,
            "url": docker_result.url,
            "files_dir": docker_result.files_dir,
            "username": docker_result.username,
            "password": docker_result.password,
        }
        if args.json:
            print(json.dumps(payload))
        else:
            print(docker_result.message)
            if docker_result.url:
                print(f"URL: {docker_result.url}\nFiles: {docker_result.files_dir}")
            if docker_result.password:
                print(f"Credentials: {docker_result.username}:{docker_result.password}")
        return docker_result.exit_code
    if args.config and Path(args.config).expanduser().absolute() != Path("/etc/xferry/xferry.ini"):
        raise ValueError(
            "the Linux service uses --config /etc/xferry/xferry.ini; use --docker for Docker"
        )
    from .managed_state import has_retained_state
    from .model import ManagedLayout

    layout = ManagedLayout()
    if has_retained_state(layout):
        if args.dry_run:
            return _render_operation_result(
                _OperationResult(
                    0,
                    "Saved configuration and data will be resumed "
                    "after signed runtime installation.",
                ),
                json_output=args.json,
            )
        from .bootstrap import install_release
        from .setup import SetupExecutor

        if not layout.current_executable.is_file():
            installed = install_release(args.to)
            if installed.exit_code:
                return _render_operation_result(
                    _OperationResult(installed.exit_code, installed.message), json_output=args.json
                )
        resumed = SetupExecutor().resume(layout)
        return _render_operation_result(resumed, json_output=args.json)
    if Path("/etc/xferry/xferry.ini").is_file() and not args.dry_run:
        if interactive_wizard:
            return main(
                ["--lang", _context.language.code, "config", "--config", "/etc/xferry/xferry.ini"]
            )
        return _render_operation_result(
            _OperationResult(2, "already configured; use xferry config or config set"),
            json_output=args.json,
        )
    from .platform import detect_host_facts

    facts = detect_host_facts()
    if not facts.is_supported:
        return _non_linux_management_result("setup", args)
    args.private = args.access == "private"
    if interactive_wizard and not args.domain and args.access is None and args.public_ip is None:
        from .wizard import prepare_setup

        try:
            prepare_setup(args, _context.language.code)
        except (EOFError, KeyboardInterrupt):
            return 0
        except ValueError as exc:
            print(f"xferry setup: error: {exc}", file=sys.stderr)
            return 2
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

    if not preflight.executable_ready:
        preflight = replace(
            preflight,
            failures=tuple(
                failure for failure in preflight.failures if failure.code != "executable-missing"
            ),
        )
    if not preflight.ok:
        from .setup import preflight_result

        result = preflight_result(preflight)
        return _render_operation_result(result, json_output=args.json)
    if args.dry_run:
        _render_dry_run(plan, json_output=args.json, version=args.to)
        return 0

    _display_plan_before_mutation(plan, json_output=args.json)
    if interactive_wizard:
        from .wizard import confirm

        try:
            if not confirm(_context.language.code):
                return 0
        except (EOFError, KeyboardInterrupt):
            return 0
    if not plan.layout.current_executable.is_file():
        from .bootstrap import install_release

        installed = install_release(args.to)
        if installed.exit_code:
            return _render_operation_result(
                _OperationResult(installed.exit_code, installed.message), json_output=args.json
            )
    result = _apply_setup_plan(plan, preflight)
    return _render_operation_result(result, json_output=args.json, files_dir=plan.files_dir)


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
        if getattr(status, "files_dir", None):
            print(f"Files: {status.files_dir}")
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
        for action in report.next_actions:
            print(context.translator.get("next_action_text", action=action))
    return report.exit_code


def _release_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    """Run one verified release lifecycle command through injectable boundaries."""
    from .releases import default_release_manager, default_update_manager

    if args.command == "update":
        manager = default_update_manager()
        result = manager.update(args.to, args.dry_run)
    elif args.command == "rollback":
        manager = default_release_manager()
        result = manager.rollback(args.to, args.dry_run)
    else:
        manager = default_release_manager()
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
            "active": result.active,
            "before": result.before,
            "code": result.code or result.message,
            "detail": result.detail,
            "dry_run": result.dry_run,
            "exit_code": result.exit_code,
            "message": Translator("en").release_text(
                result.message,
                version=result.target or result.version,
            ),
            "next_actions": list(result.next_actions),
            "rollback": result.rollback,
            "status": "ok" if result.exit_code == 0 else "error",
            "target": result.target,
        }
        if result.version is not None:
            payload["version"] = result.version
        print(json.dumps(payload, sort_keys=True))
        return result.exit_code
    output = sys.stderr if result.exit_code else sys.stdout
    message = context.translator.release_text(
        result.message,
        version=result.target or result.version,
    )
    print(message, file=output)
    if result.detail:
        print(result.detail, file=output)
    for action in result.next_actions:
        print(context.translator.get("next_action_text", action=action), file=output)
    return result.exit_code


def _setup_option_error(args: argparse.Namespace) -> str | None:
    if args.private and args.domain is not None:
        return "--access private cannot be combined with --domain"
    if args.private and args.public_ip is not None:
        return "--access private cannot be combined with --public-ip"
    if args.private and args.email is not None:
        return "--access private cannot be combined with --email"
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
    interactive = bool(sys.stdin.isatty()) and not args.dry_run and not args.json
    if mode is not SetupMode.PRIVATE and firewall_answer is None and ufw_is_active(runner):
        if interactive:
            response = input("Allow UFW rules for 80/tcp and 443/tcp? [y/N] ")
            firewall_answer = response.strip().casefold() in {"y", "yes"}
    facts = detect_host_facts(
        data_path=Path(args.files_dir).expanduser().resolve()
        if args.files_dir
        else layout.data_root
    )
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
            files_dir=Path(args.files_dir).expanduser().resolve() if args.files_dir else None,
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
    access = "Private HTTP on this host" if plan.mode.value == "private" else "Public HTTPS"
    if plan.domain:
        access += f" ({plan.domain})"
    message = f"Server: {access}\nFiles: {plan.files_dir}\nConfiguration: {plan.layout.config_file}"
    if plan.firewall_action:
        message += "\nFirewall: allow 80/tcp and 443/tcp"
    print(message, file=sys.stderr if json_output else sys.stdout)


def _render_dry_run(plan: SetupPlan, *, json_output: bool, version: str | None = None) -> None:
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
        "files_dir": str(plan.files_dir),
        "runtime_install_required": not plan.layout.current_executable.is_file(),
        "version": version or __version__,
    }
    if json_output:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("Dry run; no managed state was changed.")
        if payload["runtime_install_required"]:
            print(f"Setup will download and verify signed release {payload['version']}.")
        _display_plan_before_mutation(plan, json_output=False)


def _render_operation_result(
    result: _OperationResult | SetupResult | CredentialsResult,
    *,
    json_output: bool,
    files_dir: Path | None = None,
) -> int:
    credentials: Credentials | None = result.credentials
    if json_output:
        payload: dict[str, object] = {
            "exit_code": result.exit_code,
            "status": "ok" if result.exit_code == 0 else "error",
        }
        if result.exit_code == 0 and files_dir is not None:
            payload["files_dir"] = str(files_dir)
        if credentials is not None:
            payload["url"] = credentials.url
        else:
            payload["message"] = result.message
            if result.code is not None:
                payload.update(
                    {
                        "code": result.code,
                        "detail": result.detail,
                        "next_actions": list(result.next_actions),
                    }
                )
        print(json.dumps(payload, sort_keys=True))
        if credentials is not None:
            print(
                f"Credentials: {credentials.username}:{credentials.password}",
                file=sys.stderr,
            )
        return result.exit_code

    if credentials is None:
        print(result.message, file=sys.stderr if result.exit_code else sys.stdout)
        if result.detail:
            print(f"Detail: {result.detail}", file=sys.stderr if result.exit_code else sys.stdout)
        for action in result.next_actions:
            print(
                f"Next action: {action}",
                file=sys.stderr if result.exit_code else sys.stdout,
            )
        return result.exit_code
    print(f"URL: {credentials.url}")
    print(f"Credentials: {credentials.username}:{credentials.password}")
    if files_dir is not None:
        print(f"Files: {files_dir}")
    return result.exit_code


@dataclass(frozen=True)
class _OperationResult:
    """Portable operation result used before a Linux backend is available."""

    exit_code: int
    message: str
    credentials: None = None
    code: str | None = None
    detail: str = ""
    next_actions: tuple[str, ...] = ()


def _non_linux_management_result(command: str, args: argparse.Namespace) -> int:
    """Reject managed commands before backend import with portable next actions."""
    from .model import (
        MANAGED_HOST_NEXT_ACTIONS,
        MANAGED_HOST_REQUIRED_MESSAGE,
        SUPPORTED_MANAGED_HOST_SUMMARY,
    )

    display_name = {
        "darwin": "macOS",
        "win32": "Windows",
    }.get(sys.platform, sys.platform)
    detail = (
        f"Detected operating system: {display_name}. "
        f"Supported matrix: {SUPPORTED_MANAGED_HOST_SUMMARY}."
    )
    if bool(getattr(args, "json", False)):
        payload: dict[str, object] = {
            "code": "unsupported-platform",
            "detail": detail,
            "exit_code": 4,
            "message": MANAGED_HOST_REQUIRED_MESSAGE,
            "next_actions": list(MANAGED_HOST_NEXT_ACTIONS),
            "status": "error",
        }
        if command == "update":
            target = getattr(args, "to", None)
            payload.update(
                {
                    "active": None,
                    "before": None,
                    "dry_run": bool(getattr(args, "dry_run", False)),
                    "rollback": "not_attempted",
                    "target": target,
                    "version": target,
                }
            )
        print(json.dumps(payload, sort_keys=True))
        return 4

    print(f"xferry {command}: {MANAGED_HOST_REQUIRED_MESSAGE}", file=sys.stderr)
    print(f"Detail: {detail}", file=sys.stderr)
    for action in MANAGED_HOST_NEXT_ACTIONS:
        print(f"Next action: {action}", file=sys.stderr)
    return 4


def _privileged(argv: Sequence[str], context: ManagementContext) -> int:
    """Handoff through absolute executables; never resolve commands in a shell."""
    import subprocess

    sudo = next(
        (path for path in (Path("/usr/bin/sudo"), Path("/bin/sudo")) if path.is_file()), None
    )
    if sudo is None:
        print(
            "Root privileges are required; install sudo or run this command as root.",
            file=sys.stderr,
        )
        return 3
    executable = [str(Path(sys.executable).absolute()), "-I", "-m", "xferry"]
    # A frozen/scie launch owns its embedded interpreter and package search path.
    # Re-enter that same executable; an unrelated installed version may be older.
    launcher = Path(sys.argv[0])
    if launcher.is_absolute() and launcher.is_file():
        with launcher.open("rb") as stream:
            magic = stream.read(4)
        if magic.startswith((b"\x7fELF", b"MZ")) or magic in {
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
        }:
            executable = [str(launcher)]
    proxy_names = (
        "HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,"
        "all_proxy,no_proxy,SSL_CERT_FILE,REQUESTS_CA_BUNDLE"
    )
    command = [str(sudo)]
    if not sys.stdin.isatty():
        command.append("-n")
    command.extend(
        (f"--preserve-env={proxy_names}", "--", *executable, "--lang", context.language.code, *argv)
    )
    result = subprocess.run(command, check=False)
    if result.returncode == 0 and argv[0] == "setup":
        from .instances import register_instance

        register_instance(Path("/etc/xferry/xferry.ini"), "managed")
    return result.returncode


def _docker_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    from .docker_deploy import deploy_docker, docker_operation

    path = Path(args.config)
    if args.command == "credentials":
        result = deploy_docker(path.parent, reset_credentials=True)
    else:
        if args.command == "uninstall" and args.purge_data and not args.yes and not args.dry_run:
            from .wizard import confirm

            if not sys.stdin.isatty() or not confirm(
                context.language.code, "Delete Docker configuration, credentials and stored data?"
            ):
                raise ValueError("data deletion requires --yes or terminal confirmation")
        result = docker_operation(
            path,
            args.command,
            version=getattr(args, "to", None),
            purge_data=getattr(args, "purge_data", False),
            dry_run=getattr(args, "dry_run", False),
            lines=getattr(args, "lines", 100),
            since=getattr(args, "since", None),
            follow=getattr(args, "follow", False),
        )
    if getattr(args, "json", False):
        print(
            json.dumps(
                {
                    "exit_code": result.exit_code,
                    "message": result.message,
                    **(result.details or {}),
                    **(
                        {"username": result.username, "password": result.password}
                        if result.password
                        else {}
                    ),
                }
            )
        )
    else:
        print(result.message)
        if result.details:
            for name, value in result.details.items():
                if value is not None:
                    print(f"{name}: {value}")
        if result.password:
            print(f"Credentials: {result.username}:{result.password}")
    return result.exit_code


def _run_management(command: str, argv: Sequence[str], context: ManagementContext) -> int:
    if command == "help":
        if not argv:
            print(_root_help(context.translator))
            return 0
        if len(argv) != 1 or argv[0] not in _COMMAND_EXAMPLES:
            print(
                f"xferry help: {context.translator.get('usage_error')}: "
                + (
                    context.translator.get("unknown_command", command=argv[0])
                    if len(argv) == 1 and argv[0] not in _COMMANDS
                    else "choose one available command"
                ),
                file=sys.stderr,
            )
            return 2
        try:
            return main(["--lang", context.language.code, argv[0], "--help"])
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 1
    parser = _command_parser(command, context.translator)
    try:
        args = (
            parser.parse_intermixed_args(argv) if command == "config" else parser.parse_args(argv)
        )
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    args.command = command
    try:
        from .instances import discover_instances, select_instance, target_for_config

        if command == "setup":
            from .versions import is_supported_release_version

            if not is_supported_release_version(args.to):
                raise ValueError(
                    "--to requires an exact supported release version, such as " + __version__
                )
            args.private = args.access == "private"
            option_error = _setup_option_error(args)
            if option_error:
                raise ValueError(option_error)
        if command == "setup" and not args.docker:
            if args.config and target_for_config(Path(args.config)) == "docker":
                args.docker = True
            elif not args.config and discover_instances():
                existing = select_instance(
                    interactive=sys.stdin.isatty(), language=context.language.code
                )
                args.docker = existing.target == "docker"
                args.config = str(existing.config)
        explain_without_file = command == "config" and args.action == "explain" and not args.config
        if command != "setup" and not explain_without_file:
            instance = select_instance(
                args.config, interactive=sys.stdin.isatty(), language=context.language.code
            )
            args.config, args.target = str(instance.config), instance.target
        elif command == "setup":
            args.target = "docker" if args.docker else "managed"
            if args.docker and args.firewall is not None:
                raise ValueError(
                    "--firewall is for Linux services; Docker port mappings are managed by Compose"
                )
        else:
            args.target = "portable"
        if (
            command == "setup"
            and args.target == "managed"
            and args.config
            and Path(args.config).expanduser().absolute() != Path("/etc/xferry/xferry.ini")
        ):
            raise ValueError(
                "the Linux service uses /etc/xferry/xferry.ini; "
                "use --docker for a Docker deployment"
            )
        native = args.target == "managed" or command == "doctor"
        if sys.platform != "linux" and args.target == "portable" and command != "config":
            native = True
        if native and sys.platform != "linux":
            return _non_linux_management_result(command, args)
        read_only_config = command == "config" and args.action in {"show", "explain", "check"}
        readable_config = read_only_config and (not args.config or os.access(args.config, os.R_OK))
        if (
            native
            and not readable_config
            and getattr(os, "geteuid", lambda: -1)() != 0
            and not getattr(args, "dry_run", False)
        ):
            return _privileged([command, *argv], context)
        if command == "credentials" and args.target == "portable":
            from .configuration import reset_portable_password

            password_result = reset_portable_password(Path(args.config))
            if args.json:
                print(
                    json.dumps(
                        {
                            "exit_code": password_result.exit_code,
                            "message": password_result.message,
                            "username": password_result.username,
                            "password": password_result.password,
                        }
                    )
                )
            else:
                print(password_result.message)
                if password_result.password:
                    print(f"Credentials: {password_result.username}:{password_result.password}")
            return password_result.exit_code
        if command != "setup" and args.target == "portable" and command not in {"config", "doctor"}:
            raise ValueError("no installed server was found; run xferry setup or xferry run")
        if args.target == "docker" and command not in {"setup", "config"}:
            return _docker_handler(args, context)
        if (
            command == "config"
            and args.action is None
            and (
                not sys.stdin.isatty()
                or args.json
                or args.dry_run
                or args.all
                or args.group
                or args.search
            )
        ):
            return _configure_handler(args, context)
        if command == "config" and args.config and Path(args.config).is_file():
            from .migration import inspect_migration, migrate_config, needs_migration

            path = Path(args.config)
            if needs_migration(path.read_text(encoding="utf-8")):
                if args.action is not None or args.dry_run:
                    raise ValueError(
                        "old settings require a one-time migration; "
                        "run xferry config to review and migrate"
                    )
                from .configuration import state_for_config
                from .wizard import confirm, prompt

                migration_state = state_for_config(path, args.target)
                try:
                    inspect_migration(path, state_dir=migration_state)
                except ValueError as error:
                    if args.target != "portable" or "working directory is unknown" not in str(
                        error
                    ):
                        raise
                    answer = prompt("Previous server working directory (absolute path)")
                    if not answer or not Path(answer).expanduser().is_absolute():
                        raise ValueError(
                            "an absolute previous server directory is required"
                        ) from None
                    migration_state = Path(answer).expanduser().resolve()
                migration = migrate_config(
                    path,
                    state_dir=migration_state,
                    confirm=(
                        lambda plan: confirm(
                            context.language.code,
                            f"Private state: {plan.state_dir}\nFiles: {plan.files_dir}\n"
                            "Migrate settings? A private backup will be saved.",
                        )
                    )
                    if sys.stdin.isatty()
                    else None,
                )
                print(migration.message)
                if migration.exit_code or not migration.changed:
                    return migration.exit_code
                if migration.credentials:
                    print(f"Credentials: {migration.credentials[0]}:{migration.credentials[1]}")
        handlers: dict[str, CommandHandler] = {
            "config": _config_handler,
            "credentials": _credentials_handler,
            "doctor": _doctor_handler,
            "logs": _logs_handler,
            "update": _release_handler,
            "rollback": _release_handler,
            "setup": _setup_handler,
            "start": _service_action_handler,
            "status": _status_handler,
            "stop": _service_action_handler,
            "uninstall": _release_handler,
            "restart": _service_action_handler,
        }
        return handlers.get(command, _not_implemented_handler)(args, context)
    except (EOFError, KeyboardInterrupt):
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        if getattr(args, "json", False):
            print(json.dumps({"status": "error", "exit_code": 2, "message": str(exc)}))
        else:
            print(f"xferry {command}: error: {exc}", file=sys.stderr)
        return 2


def _verify_release_envelope_handler(argv: Sequence[str]) -> int:
    """Serve the signed installer through a hidden, read-only trust boundary."""
    from .release_contract import SUPPORTED_PLATFORM_IDS, PlatformId
    from .release_verifier import ReleaseEnvelopeError, verify_release_envelope

    parser = _Parser(prog="xferry _verify-release-envelope", add_help=False)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", required=True, choices=SUPPORTED_PLATFORM_IDS)
    try:
        args = parser.parse_args(argv)
        verify_release_envelope(
            args.manifest,
            args.signature,
            args.executable,
            expected_version=args.version,
            expected_platform=cast(PlatformId, args.platform),
        )
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    except ReleaseEnvelopeError as failure:
        print(f"Release envelope verification failed: {failure.code}", file=sys.stderr)
        return 1
    print("Release envelope verified.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch management commands and the canonical ``xferry run`` server CLI."""
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    if any(
        token == "--auth"
        or token.startswith("--auth=")
        or token.startswith("-a")
        and not token.startswith("--")
        for token in actual_argv
    ):
        print(
            "xferry: removed option --auth; use --auth-file or xferry credentials reset",
            file=sys.stderr,
        )
        return 2
    try:
        language = resolve_language(actual_argv, os.environ)
        remaining = _strip_global_language(actual_argv)
    except ValueError as exc:
        print(f"xferry: error: {exc}", file=sys.stderr)
        return 2

    context = ManagementContext(language=language, translator=Translator(language))
    if not remaining:
        if sys.stdin.isatty() and sys.stdout.isatty():
            from .wizard import menu

            try:
                return menu(
                    context.language.code,
                    lambda argv: main(["--lang", context.language.code, *argv]),
                )
            except (OSError, ValueError) as exc:
                print(f"xferry: error: {exc}", file=sys.stderr)
                return 2
        print(_root_help(context.translator))
        return 0

    if len(remaining) == 1 and remaining[0] in {"-h", "--help", "--help-all"}:
        print(_root_help(context.translator))
        return 0

    if remaining == ["--version"]:
        print(f"xferry {__version__}")
        return 0

    if remaining and remaining[0] == "_verify-release-envelope":
        return _verify_release_envelope_handler(remaining[1:])

    if remaining and remaining[0] in _COMMANDS:
        command = remaining[0]
        if command == "run":
            from xferry.cli import run_main

            return run_main(remaining[1:])
        return _run_management(command, remaining[1:], context)

    print(_root_help(context.translator), file=sys.stderr)
    message = context.translator.get("unknown_command", command=remaining[0])
    print(f"xferry: error: {message}", file=sys.stderr)
    return 2
