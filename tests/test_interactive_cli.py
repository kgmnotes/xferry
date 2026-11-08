"""Presentation choices preserve automation, privilege handoff and apply boundaries."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from xferry.management import application, cli, instances, terminal, wizard
from xferry.management.deployment import Credentials, OperationResult
from xferry.management.i18n import LanguageSelection, Translator
from xferry.management.progress import ProgressEvent


class SetupUI:
    enhanced = True

    def __init__(self) -> None:
        self.messages: list[str] = []

    @contextmanager
    def progress(self):
        yield lambda event: None

    def message(self, text: str, *, kind: str = "info") -> None:
        self.messages.append(text)


def test_automation_and_help_do_not_import_terminal_libraries(tmp_path: Path) -> None:
    config = tmp_path / "profile.ini"
    config.write_text("[server]\nconfig_version = 1\naccess = private\n")
    code = """
import builtins
import io
import json
import sys
from contextlib import redirect_stdout
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] in {'rich', 'prompt_toolkit'}:
        raise AssertionError('terminal library imported in automation')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
from xferry.management.cli import main
assert main(['--plain', '--help']) == 0
buffer = io.StringIO()
with redirect_stdout(buffer):
    assert main(['config', 'show', '--config', sys.argv[1], '--json', '--plain']) == 0
json.loads(buffer.getvalue())
assert '\\x1b' not in buffer.getvalue()
print('JSON_OK')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(config)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "--plain" in result.stdout
    assert "\x1b" not in result.stdout + result.stderr
    assert result.stdout.splitlines()[-1] == "JSON_OK"


def test_wizard_answers_survive_privilege_handoff(monkeypatch: pytest.MonkeyPatch) -> None:
    ui = SetupUI()
    monkeypatch.setattr(cli, "_terminal", lambda *args, **kwargs: ui)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    forwarded: list[list[str]] = []

    def prepare(args, language):
        assert args.explicit_options == frozenset({"--email"})
        args.backend = "native"
        args.files_dir = "/srv/shared files"
        args.access = "public"
        args.domain = "files.example.test"
        return True

    monkeypatch.setattr(wizard, "prepare_setup", prepare)
    monkeypatch.setattr(cli, "_privileged", lambda args, context: forwarded.append(args) or 0)
    assert cli.main(["setup", "--email", "operator@example.test"]) == 0
    args = forwarded[0]
    assert args[args.index("--files-dir") + 1] == "/srv/shared files"
    assert args[args.index("--access") + 1] == "public"
    assert args[args.index("--domain") + 1] == "files.example.test"
    assert args[args.index("--email") + 1] == "operator@example.test"


@pytest.mark.parametrize("option", ["--json", "--dry-run"])
def test_output_modes_never_start_wizard(
    monkeypatch: pytest.MonkeyPatch, option: str, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(
        wizard, "prepare_setup", lambda *args, **kwargs: pytest.fail("unexpected wizard")
    )
    monkeypatch.setattr(
        application,
        "default_application",
        lambda: SimpleNamespace(
            setup=lambda **options: calls.append(options) or OperationResult(0, "validated")
        ),
    )
    assert cli.main(["setup", option]) == 0
    assert len(calls) == 1
    assert calls[0]["dry_run"] is (option == "--dry-run")
    output = capsys.readouterr()
    assert "\x1b" not in output.out + output.err
    if option == "--json":
        assert json.loads(output.out)["exit_code"] == 0


def test_cancelled_review_never_applies(monkeypatch: pytest.MonkeyPatch) -> None:
    ui = SetupUI()
    calls: list[bool] = []
    app = SimpleNamespace(
        progress=None,
        setup=lambda **options: calls.append(options["dry_run"]) or OperationResult(0, "ready"),
    )
    monkeypatch.setattr(cli, "_terminal", lambda *args, **kwargs: ui)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr(wizard, "prepare_setup", lambda *args, **kwargs: True)
    monkeypatch.setattr(wizard, "review_setup", lambda *args, **kwargs: "cancel")
    assert cli.main(["setup", "--access", "private"]) == 0
    assert calls == [True]
    assert app.progress is None


def test_interrupt_after_apply_does_not_claim_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    ui = SetupUI()
    previous = object()

    def setup(**options):
        if options["dry_run"]:
            return OperationResult(0, "ready")
        raise KeyboardInterrupt

    app = SimpleNamespace(setup=setup, progress=previous)
    monkeypatch.setattr(cli, "_terminal", lambda *args, **kwargs: ui)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr(wizard, "prepare_setup", lambda *args, **kwargs: True)
    monkeypatch.setattr(wizard, "review_setup", lambda *args, **kwargs: "apply")
    assert cli.main(["setup", "--access", "private"]) == 130
    assert app.progress is previous
    assert "xferry doctor" in ui.messages[0]
    assert "no changes" not in ui.messages[0]


def test_plain_preference_is_carried_to_sudo(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []
    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda p: p == Path("/usr/bin/sudo") or original(p))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: captured.append(args) or SimpleNamespace(returncode=0),
    )
    context = cli.ManagementContext(
        LanguageSelection("en", "default"), Translator("en"), plain=True
    )
    assert cli._privileged(["setup", "--access", "private"], context) == 0
    assert "--plain" in captured[0]
    assert captured[0].index("--plain") < captured[0].index("setup")


@pytest.mark.parametrize("firewall_consent", [False, True])
def test_plain_setup_keeps_text_confirmation_on_a_tty(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    firewall_consent: bool,
) -> None:
    calls: list[bool] = []

    def setup(**options):
        calls.append(options["dry_run"])
        if firewall_consent and options.get("firewall") is not True:
            return OperationResult(
                2, "consent required", details={"firewall_consent_required": True}
            )
        return OperationResult(0, "ready")

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(application, "default_application", lambda: SimpleNamespace(setup=setup))
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    monkeypatch.setattr(
        terminal.TerminalUI,
        "select",
        lambda *args, **kwargs: pytest.fail("plain confirmation opened the rich interface"),
    )
    assert cli.main(["--plain", "setup", "--access", "public"]) == 0
    assert calls == ([True, True, False] if firewall_consent else [True, False])
    output = capsys.readouterr()
    assert "\x1b" not in output.out + output.err


def test_plain_setup_shows_progress_and_instance_commands_for_preview_controller(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    previous = object()
    app = SimpleNamespace(progress=previous)

    def setup(**options):
        if options["dry_run"]:
            return OperationResult(0, "ready")
        assert callable(app.progress) and app.progress is not previous
        app.progress(ProgressEvent("download", "running"))
        app.progress(ProgressEvent("download", "done"))
        return OperationResult(
            0,
            "Server is healthy.",
            details={"instance_id": "deployment-123"},
            credentials=Credentials("admin", "synthetic-password", "https://example.test"),
            url="https://example.test",
        )

    app.setup = setup
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys, "argv", ["/operator/bin/xferry-preview"])
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    assert cli.main(["--plain", "setup", "--access", "public"]) == 0
    assert app.progress is previous
    output = capsys.readouterr().out
    assert "Running: Downloading the runtime or image" in output
    assert "Done: Downloading the runtime or image" in output
    assert "Deployment ID: deployment-123" in output
    assert "xferry-preview status --instance deployment-123" in output
    assert "xferry-preview config --instance deployment-123" in output
    assert "xferry-preview doctor --instance deployment-123 --deep" in output
    assert "Save these credentials" in output
    assert output.count("synthetic-password") == 1
    assert "\x1b" not in output


def test_privileged_module_setup_followups_use_the_same_controller(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    controller = tmp_path / "preview controller" / "bin" / "python"
    module = tmp_path / "preview controller" / "lib" / "xferry" / "__main__.py"
    commands: list[list[str]] = []

    def setup(**options):
        return OperationResult(0, "ready", details={"instance_id": "deployment-123"})

    monkeypatch.setattr(cli.sys, "argv", ["/operator/bin/xferry-preview"])
    monkeypatch.setattr(cli.sys, "executable", str(controller))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(application, "default_application", lambda: SimpleNamespace(setup=setup))
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path, "is_file", lambda path: path == Path("/usr/bin/sudo") or original_is_file(path)
    )

    def sudo_reentry(command, **kwargs):
        commands.append(command)
        forwarded = command[command.index("--") + 1 :]
        assert forwarded[:4] == [str(controller), "-I", "-m", "xferry"]
        with monkeypatch.context() as privileged:
            privileged.setattr(cli.sys, "argv", [str(module), *forwarded[4:]])
            return SimpleNamespace(returncode=cli.main(forwarded[4:]))

    monkeypatch.setattr(subprocess, "run", sudo_reentry)
    context = cli.ManagementContext(
        LanguageSelection("en", "default"), Translator("en"), plain=True
    )
    assert cli._privileged(["setup", "--access", "public"], context) == 0
    assert len(commands) == 1
    output = capsys.readouterr().out
    followups = [shlex.split(line.strip()) for line in output.splitlines() if "--instance" in line]
    assert len(followups) == 3
    for command, action in zip(followups, ("status", "config", "doctor"), strict=True):
        assert command[:7] == [
            str(controller),
            "-I",
            "-m",
            "xferry",
            action,
            "--instance",
            "deployment-123",
        ]
    assert followups[-1][-1] == "--deep"


def test_module_setup_followups_are_copyable_in_powershell(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli.sys, "argv", ["C:/Preview/xferry/__main__.py"])
    monkeypatch.setattr(cli.sys, "executable", "C:/Program Files/O'Brien/Preview/python.exe")
    result = cli._setup_next_actions(
        OperationResult(0, "ready", details={"instance_id": "deployment-123"})
    )
    prefix = "& 'C:/Program Files/O''Brien/Preview/python.exe' -I -m xferry"
    assert result.next_actions == (
        f"{prefix} status --instance deployment-123",
        f"{prefix} config --instance deployment-123",
        f"{prefix} doctor --instance deployment-123 --deep",
    )


@pytest.mark.parametrize("arguments", (["--json"], ["--dry-run"]))
def test_setup_output_modes_do_not_install_observer_or_add_followups(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    previous = object()
    app = SimpleNamespace(progress=previous)

    def setup(**options):
        assert app.progress is previous
        return OperationResult(0, "validated", details={"instance_id": "deployment-123"})

    app.setup = setup
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(application, "default_application", lambda: app)

    assert cli.main(["--plain", "setup", "--access", "private", *arguments]) == 0
    output = capsys.readouterr().out
    assert "Running:" not in output and "Next steps:" not in output and "\x1b" not in output
    if "--json" in arguments:
        assert json.loads(output)["details"] == {"instance_id": "deployment-123"}


@pytest.mark.parametrize("action", ("save", "password"))
@pytest.mark.parametrize("interrupt", (False, True))
def test_plain_configuration_operations_show_progress_and_restore_observer(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    action: str,
    interrupt: bool,
) -> None:
    path = tmp_path / "operator.ini"
    path.write_text("[server]\nconfig_version = 1\naccess = private\n")
    previous = object()
    app = SimpleNamespace(progress=previous)

    def apply():
        assert callable(app.progress) and app.progress is not previous
        app.progress(ProgressEvent("restart", "running"))
        if interrupt:
            raise KeyboardInterrupt
        app.progress(ProgressEvent("restart", "done"))
        return OperationResult(0, "applied")

    def configure(instance, changes, **options):
        return apply() if options["apply"] else OperationResult(0, "validated")

    app.configure = configure
    app.credentials = lambda instance: apply()
    answers = iter(("9" if action == "save" else "8", "yes"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(application, "default_application", lambda: app)

    assert wizard.configure(path, "managed", "en", plain=True) == (130 if interrupt else 0)
    assert app.progress is previous
    output = capsys.readouterr().out
    assert "Running: Restarting the server" in output
    assert ("Failed:" if interrupt else "Done:") + " Restarting the server" in output
    assert "no changes made" not in output and "\x1b" not in output
    if interrupt:
        assert "Check xferry status and xferry doctor" in output


@pytest.mark.parametrize("mode", ("human", "json", "dry-run"))
def test_config_set_progress_is_only_for_interactive_apply(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    mode: str,
) -> None:
    previous = object()
    app = SimpleNamespace(progress=previous)

    def configure(instance, changes, *, apply):
        assert changes == {"max_size_mb": "128"}
        assert apply is (mode != "dry-run")
        if mode == "human":
            assert callable(app.progress) and app.progress is not previous
            app.progress(ProgressEvent("apply_config", "running"))
            app.progress(ProgressEvent("apply_config", "done"))
        else:
            assert app.progress is previous
        return OperationResult(0, "validated")

    app.configure = configure
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(application, "default_application", lambda: app)
    context = cli.ManagementContext(
        LanguageSelection("en", "default"), Translator("en"), plain=True
    )
    args = SimpleNamespace(
        action="set",
        values=["max_size_mb=128"],
        config=str(tmp_path / "profile.ini"),
        target="managed",
        instance_record=None,
        json=mode == "json",
        dry_run=mode == "dry-run",
    )

    assert cli._config_handler(args, context) == 0
    assert app.progress is previous
    output = capsys.readouterr().out
    assert ("Running: Applying configuration changes" in output) is (mode == "human")
    assert "\x1b" not in output
    if mode == "json":
        assert json.loads(output)["exit_code"] == 0


def test_abbreviated_explicit_setup_choices_are_not_asked_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ui = SetupUI()
    selected: list[object] = []
    monkeypatch.setattr(terminal, "get_ui", lambda *args, **kwargs: ui)
    monkeypatch.setattr(cli, "_setup_handler", lambda args, context: selected.append(args) or 7)
    assert (
        cli.main(["setup", "--back", "docker", "--acc", "private", "--files", str(tmp_path)]) == 7
    )
    args = selected[0]
    assert args.explicit_options == frozenset({"--backend", "--access", "--files-dir"})
    assert (args.backend, args.access, args.files_dir) == ("docker", "private", str(tmp_path))


@pytest.mark.parametrize(
    "arguments",
    [["status", "--json"], ["config", "show", "--json"], ["uninstall", "--purge", "--dry-run"]],
)
def test_automation_requires_unambiguous_instance_even_on_a_tty(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    def resolve(identity):
        raise ValueError("more than one server; choose --instance ID")

    monkeypatch.setattr(instances, "discover_instances", lambda: (object(), object()))
    monkeypatch.setattr(
        application, "default_application", lambda: SimpleNamespace(resolve=resolve)
    )
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unexpected prompt"))
    monkeypatch.setattr(
        cli, "_terminal", lambda *args, **kwargs: pytest.fail("unexpected terminal interface")
    )
    assert cli.main(arguments) == 2
    output = capsys.readouterr()
    assert "\x1b" not in output.out + output.err
    if "--json" in arguments:
        assert json.loads(output.out)["exit_code"] == 2


def test_json_purge_requires_confirmation_without_prompting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    instance = SimpleNamespace(id="server", backend="docker", target="docker", config=tmp_path)
    calls: list[dict[str, object]] = []

    def operate(action, selected, **options):
        assert selected is instance
        calls.append(options)
        return OperationResult(2, "Purge requires confirmation; use --yes")

    app = SimpleNamespace(resolve=lambda identity: instance, operate=operate)
    monkeypatch.setattr(instances, "discover_instances", lambda: (instance,))
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unexpected prompt"))
    assert cli.main(["uninstall", "--purge", "--json"]) == 2
    assert calls == [{"purge": True, "confirmed": False, "dry_run": False}]
    assert json.loads(capsys.readouterr().out)["exit_code"] == 2
