"""Dispatcher for XFerry management commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast

from xferry.config import __version__

from .i18n import LanguageSelection, Translator, resolve_language

if TYPE_CHECKING:
    from .application import ManagementApplication
    from .deployment import OperationResult
    from .instances import Instance
    from .terminal import TerminalUI

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
_COMMAND_EXAMPLES = {
    "run": "xferry run --files-dir ~/Shared",
    "setup": "xferry setup --backend native",
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
    plain: bool = False


CommandHandler = Callable[[argparse.Namespace, ManagementContext], int]


class _Parser(argparse.ArgumentParser):
    """Argument parser that provides an integer usage result to the dispatcher."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def _strip_global_language(argv: Sequence[str]) -> list[str]:
    """Remove global presentation options while preserving remaining token order."""
    remaining: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--plain":
            index += 1
            continue
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


def _dispatch_arguments(context: ManagementContext, argv: Sequence[str]) -> list[str]:
    return ["--lang", context.language.code, *(["--plain"] if context.plain else []), *argv]


def _terminal(context: ManagementContext, *, disabled: bool = False) -> TerminalUI:
    from .terminal import get_ui

    return get_ui(context.language.code, plain=context.plain or disabled)


def _explicit_options(parser: argparse.ArgumentParser, argv: Sequence[str]) -> frozenset[str]:
    """Normalize successful argparse abbreviations before deciding which fields to ask."""
    options = {
        option: "--" + action.dest.replace("_", "-")
        for action in parser._actions
        for option in action.option_strings
    }
    selected: set[str] = set()
    for token in argv:
        if not token.startswith("--"):
            continue
        flag = token.split("=", 1)[0]
        if flag in options:
            selected.add(options[flag])
        else:
            matching = {value for option, value in options.items() if option.startswith(flag)}
            if len(matching) == 1:
                selected.update(matching)
    return frozenset(selected)


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


def _command_parser(
    command: str, translator: Translator, *, show_all_help: bool = False
) -> _Parser:
    parser = _Parser(
        prog=f"xferry {command}",
        description=translator.get(f"command_{command}"),
        epilog=translator.get("command_example", example=_COMMAND_EXAMPLES[command]),
        formatter_class=lambda prog: argparse.HelpFormatter(prog, width=100),
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help=translator.get("help_option"))
    parser.add_argument("--help-all", action="help", help="Show all command options.")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--instance", metavar="ID", help="Select a persistent deployment by ID.")
    if command in {"config", "credentials"}:
        selection.add_argument(
            "--config", metavar="FILE", help="Edit an explicit foreground configuration profile."
        )
    else:
        parser.set_defaults(config=None)
    if command == "setup":
        parser.add_argument(
            "--backend",
            choices=("native", "docker"),
            default="native",
            help="Install a Linux service or Docker Compose deployment (default: native).",
        )
        parser.add_argument(
            "--output",
            metavar="DIRECTORY",
            help="Create a Docker deployment bundle in this directory."
            if show_all_help
            else argparse.SUPPRESS,
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
        artifact = parser.add_mutually_exclusive_group()
        artifact.add_argument(
            "--to",
            default=None,
            metavar="VERSION",
            help=f"Signed release version to install (default: {__version__}).",
        )
        artifact.add_argument(
            "--image",
            metavar="REPOSITORY@sha256:DIGEST",
            help="Use an explicit immutable Docker image instead of a release version.",
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
            "--purge",
            action="store_true",
            help="Delete owned configuration, credentials and private state; keep external files.",
        )
        parser.add_argument("--yes", action="store_true", help="Confirm deletion without a prompt.")
    if command in {"setup", "config", "update", "rollback", "uninstall"}:
        parser.add_argument("--dry-run", action="store_true", help="Validate and preview changes.")
    if command != "logs":
        parser.add_argument("--json", action="store_true", help="Print machine-readable results.")
    else:
        parser.set_defaults(json=False)
    return parser


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
        dispatch=lambda argv: main(_dispatch_arguments(context, argv)),
        instance=getattr(args, "instance_record", None),
        **({"plain": True} if context.plain else {}),
    )


def _annotate_deployment_rows(rows: list[dict[str, object]], instance: Instance) -> None:
    """Present real backend storage rather than an internal compilation path."""
    if instance.backend != "docker":
        return
    storage = instance.spec.backend_options.get("state_storage")
    if not isinstance(storage, Mapping) or not isinstance(storage.get("name"), str):
        raise ValueError("Docker deployment does not declare its private state volume")
    for row in rows:
        if row["name"] == "state_dir":
            location = "Docker volume " + str(storage["name"])
            row.update(
                value=location,
                effective=location,
                configured=None,
                runtime_value="/data",
                source="deployment",
                read_only=True,
            )


def _config_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    from xferry.settings import load_settings_text, resolve_settings

    from .configuration import (
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
            if target != "portable":
                from .application import default_application

                result = default_application().configure(
                    args.instance_record, changes, apply=not args.dry_run
                )
                return _render_application_result(
                    result, json_output=args.json, language=context.language.code
                )
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
                file_settings=load_settings_text(
                    text or "[server]\nconfig_version = 1\n", validate=False
                ),
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
        if target != "portable":
            _annotate_deployment_rows(rows, args.instance_record)
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


def _render_application_result(
    result: OperationResult, *, json_output: bool, language: str = "en"
) -> int:
    translator = Translator(language)
    if json_output:
        print(json.dumps(result.to_json(), ensure_ascii=False, sort_keys=True))
    else:
        output = sys.stderr if result.exit_code else sys.stdout
        print(translator.managed_text("message", result.message), file=output)
        if result.plan:
            for step in result.plan.steps:
                print(f"  {step}", file=output)
            for retained in result.plan.retains:
                print(translator.get("retained_text", path=retained), file=output)
        if result.state:
            state = result.state
            print(
                translator.get(
                    "deployment_state_text",
                    instance=state.instance_id,
                    backend=state.backend,
                    state=translator.managed_text("status", state.state),
                    health=translator.managed_text("status", state.health),
                ),
                file=output,
            )
            if state.detail:
                print(translator.managed_text("detail", state.detail), file=output)
        if result.url:
            print(f"URL: {result.url}", file=output)
        for name, value in result.details.items():
            if name == "checks" and isinstance(value, Mapping):
                for check_name, check in value.items():
                    if isinstance(check, Mapping):
                        print(
                            translator.get(
                                "doctor_check_text",
                                name=translator.managed_text("check", str(check_name)),
                                status=translator.managed_text(
                                    "status", str(check.get("status", "unknown"))
                                ),
                                detail=translator.managed_text(
                                    "detail", str(check.get("detail", ""))
                                ),
                            ),
                            file=output,
                        )
            elif value is not None:
                label = translator.managed_text("check", name)
                print(f"{label}: {value}", file=output)
    credentials = result.credentials
    if credentials is not None and not json_output:
        print(f"Credentials: {credentials.username}:{credentials.password}")
    return result.exit_code


def _setup_options(args: argparse.Namespace) -> dict[str, object]:
    return {
        "backend": args.backend,
        "instance_id": args.instance,
        "version": None if args.image else (args.to or __version__),
        "image": args.image,
        "output": Path(args.output).expanduser().absolute() if args.output else None,
        "files_dir": Path(args.files_dir).expanduser().absolute() if args.files_dir else None,
        "access": args.access or "public",
        "domain": args.domain,
        "public_ip": args.public_ip,
        "email": args.email,
        "firewall": {"allow": True, "deny": False}.get(args.firewall),
    }


def _setup_arguments(args: argparse.Namespace) -> list[str]:
    """Carry the reviewed wizard answers through sudo without asking them again."""
    arguments = ["setup"]
    for name in (
        "backend",
        "instance",
        "access",
        "files_dir",
        "domain",
        "public_ip",
        "email",
        "firewall",
        "output",
        "to",
        "image",
    ):
        value = getattr(args, name, None)
        if value is not None:
            arguments.extend(("--" + name.replace("_", "-"), str(value)))
    for name in ("dry_run", "json"):
        if getattr(args, name, False):
            arguments.append("--" + name.replace("_", "-"))
    return arguments


def _setup_call(
    app: ManagementApplication, ui: TerminalUI, options: Mapping[str, object], *, dry_run: bool
) -> OperationResult:
    if not ui.enhanced:
        return app.setup(**options, dry_run=dry_run)  # type: ignore[arg-type]
    with ui.progress() as observer:
        previous = getattr(app, "progress", None)
        app.progress = observer
        try:
            return app.setup(**options, dry_run=dry_run)  # type: ignore[arg-type]
        finally:
            app.progress = previous


def _setup_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    from .application import default_application
    from .wizard import confirm, prepare_setup, review_setup

    interactive = sys.stdin.isatty() and not args.json and not args.dry_run
    ui = _terminal(context, disabled=not interactive)
    if (
        interactive
        and not ui.enhanced
        and not args.instance
        and not any((args.access, args.domain, args.public_ip))
    ):
        if not prepare_setup(
            args, context.language.code, **({"plain": True} if context.plain else {})
        ):
            return 0
    app = default_application()
    while True:
        options = _setup_options(args)
        if interactive:
            preview = _setup_call(app, ui, options, dry_run=True)
            if preview.details.get("firewall_consent_required"):
                supplied_ports = preview.details.get("firewall_ports")
                ports = supplied_ports if isinstance(supplied_ports, list | tuple) else (80, 443)
                rules = ", ".join(f"{port}/tcp" for port in ports)
                description = (
                    f"Разрешить правила UFW: {rules}?"
                    if context.language.code == "ru"
                    else f"Allow UFW rules for {rules}?"
                )
                if ui.enhanced:
                    accepted = ui.confirm(description)
                else:
                    accepted = confirm(
                        context.language.code,
                        description,
                        **({"plain": True} if context.plain else {}),
                    )
                if not accepted:
                    return 0
                args.firewall = "allow"
                options["firewall"] = True
                preview = _setup_call(app, ui, options, dry_run=True)
            if ui.enhanced:
                decision = review_setup(args, preview, context.language.code)
                if decision == "edit":
                    if not prepare_setup(args, context.language.code, edit=True):
                        return 0
                    if args.backend == "native" and getattr(os, "geteuid", lambda: -1)() != 0:
                        return _privileged(_setup_arguments(args), context)
                    continue
                if decision != "apply":
                    return preview.exit_code
            else:
                _render_application_result(
                    preview, json_output=False, language=context.language.code
                )
                if preview.exit_code:
                    return preview.exit_code
                accepted = (
                    confirm(context.language.code, plain=True)
                    if context.plain
                    else confirm(context.language.code)
                )
                if not accepted:
                    return 0
        try:
            result = _setup_call(app, ui, options, dry_run=args.dry_run)
        except KeyboardInterrupt:
            if not ui.enhanced:
                raise
            ui.message(
                "Установка прервана. Проверьте состояние: xferry status или xferry doctor."
                if context.language.code == "ru"
                else "Setup interrupted. Check the deployment with xferry status or xferry doctor.",
                kind="warning",
            )
            return 130
        if ui.enhanced:
            from .interactive import render_result

            return render_result(ui, result, files_dir=args.files_dir)
        return _render_application_result(
            result, json_output=args.json, language=context.language.code
        )


def _credentials_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    if args.target == "portable":
        from .configuration import reset_portable_password

        result = reset_portable_password(Path(args.config))
        if args.json:
            print(json.dumps({"exit_code": result.exit_code, "message": result.message}))
        else:
            print(result.message)
        if result.password and not args.json:
            print(f"Credentials: {result.username}:{result.password}")
        return result.exit_code
    from .application import default_application

    return _render_application_result(
        default_application().credentials(args.instance_record),
        json_output=args.json,
        language=context.language.code,
    )


def _persistent_handler(args: argparse.Namespace, context: ManagementContext) -> int:
    from .application import default_application

    app = default_application()
    instance = args.instance_record
    if args.command == "doctor":
        result = app.doctor(instance, check_http=args.deep and not args.skip_network)
    else:
        options: dict[str, object] = {}
        if args.command == "logs":
            options.update(lines=args.lines, since=args.since, follow=args.follow)
        if args.command in {"update", "rollback"}:
            options.update(version=args.to, dry_run=args.dry_run)
        if args.command == "uninstall":
            confirmed = args.yes
            if (
                args.purge
                and not confirmed
                and not args.dry_run
                and not args.json
                and sys.stdin.isatty()
            ):
                from .wizard import confirm

                preview = app.operate(
                    "uninstall", instance, purge=True, confirmed=True, dry_run=True
                )
                _render_application_result(
                    preview, json_output=False, language=context.language.code
                )
                if preview.exit_code:
                    return preview.exit_code
                confirmed = confirm(
                    context.language.code,
                    context.translator.get("purge_prompt"),
                    **({"plain": True} if context.plain else {}),
                )
                if not confirmed:
                    return 0
            options.update(purge=args.purge, confirmed=confirmed, dry_run=args.dry_run)
        result = app.operate(args.command, instance, **options)
    return _render_application_result(result, json_output=args.json, language=context.language.code)


def _setup_option_error(args: argparse.Namespace) -> str | None:
    if args.output and args.backend != "docker":
        return "--output requires --backend docker"
    if args.image and args.backend != "docker":
        return "--image requires --backend docker"
    if args.access == "private" and args.domain is not None:
        return "--access private cannot be combined with --domain"
    if args.access == "private" and args.public_ip is not None:
        return "--access private cannot be combined with --public-ip"
    if args.access == "private" and args.email is not None:
        return "--access private cannot be combined with --email"
    if args.domain is not None and args.public_ip is not None:
        return "--domain cannot be combined with --public-ip"
    if args.backend == "docker" and args.firewall is not None:
        return "--firewall is for native services; Docker manages its published ports"
    return None


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
        "all_proxy,no_proxy,SSL_CERT_FILE,REQUESTS_CA_BUNDLE,NO_COLOR,TERM"
    )
    command = [str(sudo)]
    if not sys.stdin.isatty():
        command.append("-n")
    command.extend(
        (f"--preserve-env={proxy_names}", "--", *executable, *_dispatch_arguments(context, argv))
    )
    result = subprocess.run(command, check=False)
    return result.returncode


def _select_persistent_instance(
    selector: str | None, context: ManagementContext, *, interactive: bool = True
) -> Instance:
    from .application import default_application
    from .instances import discover_instances

    app = default_application()
    found = discover_instances() if selector is None else ()
    if len(found) > 1 and sys.stdin.isatty() and interactive:
        from .terminal import Back, Choice

        ui = _terminal(context)
        if ui.enhanced:
            try:
                selector = ui.select(
                    "Выберите сервер" if context.language.code == "ru" else "Choose a server",
                    [
                        Choice(item.id, f"{item.id} ({item.backend})", str(item.config))
                        for item in found
                    ],
                )
            except Back as error:
                raise EOFError from error
            return app.resolve(selector)
        from .wizard import prompt

        print("Выберите сервер:" if context.language.code == "ru" else "Choose a server:")
        for index, instance in enumerate(found, 1):
            print(f"  {index}. {instance.id} ({instance.backend}) - {instance.config}")
        answer = prompt("Номер" if context.language.code == "ru" else "Number")
        if not answer.isdigit() or not 1 <= int(answer) <= len(found):
            raise ValueError("choose one of the listed server numbers")
        selector = found[int(answer) - 1].id
    return app.resolve(selector)


def _run_management(command: str, argv: Sequence[str], context: ManagementContext) -> int:
    if command == "help":
        if not argv:
            print(_root_help(context.translator))
            return 0
        if len(argv) != 1 or argv[0] not in _COMMAND_EXAMPLES:
            message = (
                context.translator.get("unknown_command", command=argv[0])
                if len(argv) == 1 and argv[0] not in _COMMANDS
                else "choose one available command"
            )
            print(
                f"xferry help: {context.translator.get('usage_error')}: {message}", file=sys.stderr
            )
            return 2
        try:
            return main(_dispatch_arguments(context, [argv[0], "--help"]))
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 1
    parser = _command_parser(command, context.translator, show_all_help="--help-all" in argv)
    try:
        args = (
            parser.parse_intermixed_args(argv) if command == "config" else parser.parse_args(argv)
        )
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    args.command = command
    args.explicit_options = _explicit_options(parser, argv)
    from .terminal import Back

    try:
        if command == "status" and not args.instance:
            from .application import default_application
            from .deployment import OperationResult
            from .instances import discover_instances

            if not discover_instances():
                observed = default_application().observe(None)
                if observed.state == "absent":
                    return _render_application_result(
                        OperationResult(
                            0, "No persistent deployment is installed.", state=observed
                        ),
                        json_output=args.json,
                        language=context.language.code,
                    )
        if command == "setup":
            from .versions import is_supported_release_version

            if args.to is not None and not is_supported_release_version(args.to):
                raise ValueError(
                    "--to requires an exact supported release version, such as " + __version__
                )
            error = _setup_option_error(args)
            if error:
                raise ValueError(error)
            ui = _terminal(context, disabled=args.json or args.dry_run)
            if ui.enhanced and not args.instance:
                from .wizard import prepare_setup

                if not prepare_setup(args, context.language.code):
                    return 0
                args.wizard_prepared = True
                error = _setup_option_error(args)
                if error:
                    raise ValueError(error)
            args.target = "managed" if args.backend == "native" else "docker"
        elif command in {"config", "credentials"} and args.config:
            args.config = str(Path(args.config).expanduser().absolute())
            args.target = "portable"
        elif command == "config" and args.action == "explain" and not args.instance:
            args.target = "portable"
        else:
            # Platform rejection precedes Linux backend imports. Docker is portable
            # when an explicitly selected deployment is present in the registry.
            if sys.platform != "linux" and not args.instance:
                if command == "config":
                    from .instances import foreground_config

                    args.config, args.target = str(foreground_config()), "portable"
                else:
                    return _non_linux_management_result(command, args)
            else:
                from .instances import discover_instances, foreground_config

                if command == "config" and not args.instance and not discover_instances():
                    args.config, args.target = str(foreground_config()), "portable"
                else:
                    instance = _select_persistent_instance(
                        args.instance,
                        context,
                        interactive=not (args.json or getattr(args, "dry_run", False)),
                    )
                    args.instance_record = instance
                    args.config, args.target = str(instance.config), instance.target
        if command == "config" and not args.config and args.target == "portable":
            from .instances import foreground_config

            args.config = str(foreground_config())
        native = args.target == "managed"
        if native and sys.platform != "linux":
            return _non_linux_management_result(command, args)
        read_only = command == "config" and args.action in {"show", "explain", "check"}
        readable = read_only and (not args.config or os.access(args.config, os.R_OK))
        if (
            native
            and not readable
            and getattr(os, "geteuid", lambda: -1)() != 0
            and not (command == "setup" and getattr(args, "dry_run", False))
        ):
            forwarded = (
                _setup_arguments(args)
                if command == "setup" and getattr(args, "wizard_prepared", False)
                else [command, *argv]
            )
            return _privileged(forwarded, context)
        if command == "setup":
            return _setup_handler(args, context)
        if command == "config":
            return _config_handler(args, context)
        if command == "credentials":
            return _credentials_handler(args, context)
        return _persistent_handler(args, context)
    except (Back, EOFError, KeyboardInterrupt):
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        if getattr(args, "json", False):
            print(json.dumps({"exit_code": 2, "message": str(exc)}))
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

    context = ManagementContext(
        language=language, translator=Translator(language), plain="--plain" in actual_argv
    )
    if not remaining:
        if sys.stdin.isatty() and sys.stdout.isatty():
            from .wizard import menu

            try:
                return menu(
                    context.language.code,
                    lambda argv: main(_dispatch_arguments(context, argv)),
                    **({"plain": True} if context.plain else {}),
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
