"""Operator journeys use one setup, configuration and lifecycle vocabulary."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from xferry.management import cli, configuration, instances, wizard
from xferry.management.docker_deploy import DockerResult
from xferry.management.i18n import LanguageSelection, Translator


@pytest.mark.parametrize("command", cli._COMMAND_EXAMPLES)
def test_help_command_matches_direct_help(command: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["help", command]) == 0
    indirect = capsys.readouterr()
    try:
        result = cli.main([command, "--help"])
    except SystemExit as exc:
        result = exc.code
    assert result == 0
    direct = capsys.readouterr()
    assert indirect == direct


@pytest.mark.parametrize(
    "arguments",
    [
        ["install", "--to", "0.2.0"],
        ["configure"],
        ["examples"],
        ["setup", "--private"],
        ["config", "show", "--target", "portable"],
        ["config", "show", "--output", "/tmp/config"],
        ["config", "set", "port=8081", "--apply"],
    ],
)
def test_removed_management_spellings_are_rejected(arguments: list[str]) -> None:
    assert cli.main(arguments) == 2


def test_explain_works_without_configuration_or_discovery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(instances, "select_instance", lambda *_a, **_kw: pytest.fail("discovery"))
    assert cli.main(["config", "explain", "files_dir", "--json"]) == 0
    row = json.loads(capsys.readouterr().out)[0]
    assert row["name"] == "files_dir"
    assert all(
        row[key]
        for key in ("description", "example", "constraints", "dependencies", "applicability")
    )
    assert row["ini"] == "[server] files_dir"


def test_automatic_limits_show_effective_values() -> None:
    rows = {row["name"]: row for row in configuration.describe_settings("", all_settings=True)}
    memory = rows["body_memory_budget_mb"]
    websocket = rows["max_websocket_connections"]
    assert memory["configured"] is None and memory["source"] == "automatic"
    assert memory["effective"] > 0
    assert websocket["configured"] is None and websocket["effective"] >= 0


def test_readable_native_check_never_elevates_service_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "xferry.ini"
    path.write_text("[server]\naccess = private\n")
    monkeypatch.setattr(
        instances, "select_instance", lambda *_a, **_kw: instances.Instance(path, "managed")
    )
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(cli, "_privileged", lambda *_: pytest.fail("read-only check elevated"))
    assert cli.main(["config", "check", "--config", str(path)]) == 0


def test_native_setup_checks_permissions_before_questions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("question before permissions"))
    handed_off = []
    monkeypatch.setattr(cli, "_privileged", lambda argv, _context: handed_off.append(argv) or 3)
    assert cli.main(["setup"]) == 3
    assert handed_off == [["setup"]]


def test_sudo_handoff_uses_absolute_interpreter_and_separate_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = []
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: (
            self == Path("/usr/bin/sudo")
            or (self != Path("/opt/xferry/current/xferry") and original_is_file(self))
        ),
    )
    interpreter = tmp_path / "venv with spaces/bin/python"
    monkeypatch.setattr(cli.sys, "executable", str(interpreter))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy-secret.example:1234")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: captured.append((argv, kwargs)) or SimpleNamespace(returncode=0),
    )
    context = cli.ManagementContext(LanguageSelection("en", "default"), Translator("en"))
    assert (
        cli._privileged(["restart", "--config", str(tmp_path / "custom config.ini")], context) == 0
    )
    argv, kwargs = captured[0]
    assert argv[0] == "/usr/bin/sudo" and "-n" in argv
    assert [str(interpreter), "-I", "-m", "xferry"] == argv[
        argv.index("--") + 1 : argv.index("--") + 5
    ]
    assert str(tmp_path / "custom config.ini") in argv
    assert "private-proxy-secret" not in repr(argv)
    assert kwargs == {"check": False}


@pytest.mark.parametrize(
    "action", ["status", "start", "stop", "restart", "logs", "update", "rollback", "uninstall"]
)
def test_lifecycle_dispatches_discovered_docker_without_linux_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    import xferry.management.docker_deploy as docker

    path = tmp_path / "custom deployment/xferry.ini"
    path.parent.mkdir()
    path.write_text("[server]\naccess = lab\n")
    (path.parent / ".xferry-deployment.json").write_text("{}")
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    calls = []
    monkeypatch.setattr(
        docker,
        "docker_operation",
        lambda config, command, **kwargs: (
            calls.append((config, command, kwargs)) or DockerResult(0, "done")
        ),
    )
    argv = [action, "--config", str(path)]
    if action == "update":
        argv.extend(("--to", "0.2.0"))
    assert cli.main(argv) == 0
    assert calls[0][0:2] == (path, action)


def test_custom_docker_installation_is_remembered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(instances, "user_data_dir", lambda: tmp_path / "user")
    config = tmp_path / "nonstandard location/xferry.ini"
    config.parent.mkdir()
    config.write_text("[server]\naccess = lab\n")
    (config.parent / ".xferry-deployment.json").write_text("{}")
    instances.register_instance(config, "docker")
    assert instances.resolve_instance() == instances.Instance(config, "docker")
    assert (tmp_path / "user/instances.json").stat().st_mode & 0o777 == 0o600


def test_advanced_settings_can_be_selected_by_number(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = configuration.describe_settings("", all_settings=True)
    group = str(next(row["group"] for row in rows if row["name"] == "workers"))
    groups = list(dict.fromkeys(str(row["group"]) for row in rows))
    group_rows = [row for row in rows if row["group"] == group]
    number = next(index for index, row in enumerate(group_rows, 1) if row["name"] == "workers")
    answers = iter((str(groups.index(group) + 1), str(number), "8"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    changes = {}
    wizard._advanced(changes, rows, "en")
    assert changes == {"workers": "8"}


def test_new_portable_public_settings_and_password_save_together(tmp_path: Path) -> None:
    path = tmp_path / "xferry.ini"
    result = configuration.reset_portable_password(
        path,
        changes={
            "access": "public",
            "https_mode": "domain",
            "domain": "files.example.com",
            "allowed_hosts": "files.example.com",
            "files_dir": str(tmp_path / "files"),
        },
    )
    assert result.exit_code == 0 and result.password and len(result.password) == 12
    settings = configuration.load_settings_text(path.read_text(), config_path=path)
    assert settings.access == "public" and settings.domain == "files.example.com"
    assert Path(settings.auth_file).read_text().strip() == f"admin:{result.password}"


def test_portable_credentials_command_uses_selected_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    assert cli.main(["credentials", "reset", "--config", str(config), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["password"]) == 12
    assert payload["password"] not in config.read_text()
    assert configuration.load_settings_text(config.read_text()).auth_file


def test_show_all_reports_private_state_without_offering_a_setting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\naccess = private\n")
    assert cli.main(["config", "show", "--all", "--config", str(config), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    state = next(row for row in rows if row["name"] == "state_directory")
    assert state["read_only"] and Path(state["value"]).is_absolute()
    with pytest.raises(configuration.SettingsError):
        configuration.parse_assignments(["state_directory=/tmp/state"])


def test_sudo_keeps_current_cli_when_older_native_runtime_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = []
    old_native = Path("/opt/xferry/current/xferry")
    monkeypatch.setattr(Path, "is_file", lambda path: path in {Path("/usr/bin/sudo"), old_native})
    interpreter = tmp_path / "new-pipx/bin/python"
    monkeypatch.setattr(cli.sys, "executable", str(interpreter))
    monkeypatch.setattr(cli.sys, "argv", [str(tmp_path / "new-pipx/bin/xferry")])
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **_kwargs: captured.append(argv) or SimpleNamespace(returncode=0),
    )
    context = cli.ManagementContext(LanguageSelection("en", "default"), Translator("en"))
    assert cli._privileged(["restart"], context) == 0
    assert str(interpreter) in captured[0] and str(old_native) not in captured[0]


def test_sudo_reenters_same_scie_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    launcher = tmp_path / "xferry"
    launcher.write_bytes(b"\x7fELFfake scie")
    captured = []
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path, "is_file", lambda path: path == Path("/usr/bin/sudo") or original_is_file(path)
    )
    monkeypatch.setattr(cli.sys, "argv", [str(launcher)])
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **_kwargs: captured.append(argv) or SimpleNamespace(returncode=0),
    )
    context = cli.ManagementContext(LanguageSelection("en", "default"), Translator("en"))
    assert cli._privileged(["restart"], context) == 0
    argv = captured[0]
    assert argv[argv.index("--") + 1] == str(launcher)
    assert "-m" not in argv


@pytest.mark.parametrize("blocked", [False, True])
def test_complete_setup_plans_before_signed_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked: bool
) -> None:
    import xferry.management.bootstrap as bootstrap
    import xferry.management.managed_state as managed_state
    import xferry.management.platform as platform
    from xferry.management.model import PreflightFailure, SetupPreflight
    from xferry.management.setup import SetupResult

    events = []
    plan = SimpleNamespace(
        layout=SimpleNamespace(current_executable=tmp_path / "runtime"),
        files_dir=tmp_path / "files",
    )
    failures = (PreflightFailure("executable-missing", "not installed"),)
    if blocked:
        failures += (PreflightFailure("port-unavailable", "port occupied"),)
    preflight = SetupPreflight(False, (8080,), (8080,) if blocked else (), False, failures)
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    monkeypatch.setattr(managed_state, "has_retained_state", lambda _: False)
    monkeypatch.setattr(
        platform, "detect_host_facts", lambda **_kw: SimpleNamespace(is_supported=True)
    )
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        cli, "_prepare_setup_plan", lambda _: events.append("plan") or (plan, preflight)
    )
    monkeypatch.setattr(
        cli, "_display_plan_before_mutation", lambda *_a, **_kw: events.append("summary")
    )
    monkeypatch.setattr(
        bootstrap,
        "install_release",
        lambda *_a, **_kw: events.append("bootstrap") or SimpleNamespace(exit_code=0),
    )
    monkeypatch.setattr(
        cli, "_apply_setup_plan", lambda *_a: events.append("apply") or SetupResult(0, "done")
    )
    result = cli.main(["setup", "--access", "private"])
    if blocked:
        assert result != 0 and events == ["plan"]
    else:
        assert result == 0 and events == ["plan", "summary", "bootstrap", "apply"]


def test_incompatible_setup_options_never_elevate_or_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(instances, "discover_instances", lambda: pytest.fail("instance probe"))
    monkeypatch.setattr(cli, "_privileged", lambda *_: pytest.fail("elevation"))
    assert cli.main(["setup", "--domain", "files.example.com", "--access", "private"]) == 2


def test_clearing_files_folder_restores_stable_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text(f"[server]\nfiles_dir = {tmp_path / 'old files'}\n")
    launch = tmp_path / "launch"
    launch.mkdir()
    monkeypatch.chdir(launch)
    result = configuration.change_configuration(config, {"files_dir": ""})
    assert result.exit_code == 0
    assert configuration.load_settings_text(config.read_text()).files_dir == str(
        configuration.default_files_dir()
    )
    assert configuration.load_settings_text(config.read_text()).files_dir != str(launch)


@pytest.mark.parametrize("invalid", ["not-a-number", "-1"])
def test_wizard_can_recover_from_invalid_scalar_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\naccess = private\n")
    answers = iter(("2", invalid, "2", "25", "9", "yes"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert configuration.load_settings_text(config.read_text()).max_size_mb == 25


def test_wizard_can_recover_from_runtime_validation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\naccess = private\n")
    rows = configuration.describe_settings("", all_settings=True)
    groups = list(dict.fromkeys(row["group"] for row in rows))
    cors = [row for row in rows if row["group"] == "cors"]
    group_number = str(groups.index("cors") + 1)
    setting_number = str(
        next(index for index, row in enumerate(cors, 1) if row["name"] == "cors_origin")
    )
    answers = iter(
        (
            "7",
            group_number,
            setting_number,
            "https://example.test/path",
            "7",
            group_number,
            setting_number,
            "https://example.test",
            "9",
            "yes",
        )
    )
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert (
        configuration.load_settings_text(config.read_text()).cors_origin == "https://example.test"
    )


def test_migration_cancellation_leaves_old_file_and_no_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "xferry.ini"
    before = f"[server]\npreset = local\nroot_dir = {tmp_path / 'old state'}\n"
    config.write_text(before)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert cli.main(["config", "--config", str(config)]) == 0
    assert config.read_text() == before
    assert not config.with_name(f".{config.name}.state.json").exists()


def test_native_setup_rejects_custom_config_before_elevation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "_privileged", lambda *_: pytest.fail("unneeded elevation"))
    assert cli.main(["setup", "--config", "/tmp/custom.ini"]) == 2


@pytest.mark.parametrize(
    "arguments",
    [
        ["--auth=admin:do-not-echo-this"],
        ["setup", "--auth", "admin:do-not-echo-this"],
        ["config", "show", "--auth=admin:do-not-echo-this"],
        ["run", "-aadmin:do-not-echo-this"],
    ],
)
def test_retired_inline_credentials_are_rejected_without_echoing(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(arguments) == 2
    output = capsys.readouterr()
    assert "do-not-echo-this" not in output.out + output.err
    assert "--auth-file" in output.err and "credentials reset" in output.err


def test_invalid_setup_version_fails_before_discovery_and_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        instances, "discover_instances", lambda: pytest.fail("discovery before version validation")
    )
    assert cli.main(["setup", "--to", "latest", "--dry-run"]) == 2


def test_native_setup_keeps_explicit_files_folder(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse

    args = argparse.Namespace(files_dir="/srv/explicit-share", domain=None, private=False)
    prompts = []
    monkeypatch.setattr("builtins.input", lambda prompt: prompts.append(prompt) or "3")
    assert wizard.prepare_setup(args, "en")
    assert args.files_dir == "/srv/explicit-share" and args.private
    assert all("Files folder" not in prompt for prompt in prompts)


def test_docker_setup_preserves_all_explicit_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import xferry.management.docker_deploy as docker

    calls = []
    monkeypatch.setattr(
        wizard, "docker_wizard", lambda *_a, **_kw: pytest.fail("explicit options lost in wizard")
    )
    monkeypatch.setattr(
        docker,
        "deploy_docker",
        lambda output, **kwargs: calls.append((output, kwargs)) or DockerResult(0, "configured"),
    )
    path = tmp_path / "deployment/xferry.ini"
    assert (
        cli.main(
            [
                "setup",
                "--docker",
                "--config",
                str(path),
                "--public-ip",
                "8.8.8.8",
                "--email",
                "ops@example.com",
                "--to",
                "0.2.0",
            ]
        )
        == 0
    )
    _, kwargs = calls[0]
    assert kwargs["public_ip"] == "8.8.8.8"
    assert kwargs["settings_changes"] == {"email": "ops@example.com"}
    assert kwargs["image"] == "ghcr.io/kgmnotes/xferry:v0.2.0"


def test_wizard_preview_uses_effective_environment_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\nport = 8080\n")
    monkeypatch.setenv("XFERRY_PORT", "9090")
    monkeypatch.setattr("builtins.input", lambda _: "0")
    assert wizard.configure(config, "portable", "en") == 0
    assert "URL: http://127.0.0.1:9090" in capsys.readouterr().out
    assert configuration.load_settings_text(config.read_text()).port == 8080


@pytest.mark.parametrize("mode", ["automatic", "domain", "private"])
def test_first_docker_setup_walks_through_folder_access_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    import xferry.management.docker_deploy as docker

    config = tmp_path / "deployment/xferry.ini"
    shared = tmp_path / "files with spaces"
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(docker, "default_files_directory", lambda: shared)
    answers = ["", {"automatic": "1", "domain": "2", "private": "3"}[mode]]
    if mode == "domain":
        answers.append("files.example.com")
    answers.append("yes")
    iterator = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _: next(iterator))
    calls = []
    url = "http://127.0.0.1:8080" if mode == "private" else "https://files.example.com"

    def activate(output, **kwargs):
        calls.append((output, kwargs))
        return DockerResult(
            0,
            "Server ready",
            url=url,
            files_dir=str(shared),
            username="admin",
            password="abcdefgh2345",
        )

    monkeypatch.setattr(docker, "deploy_docker", activate)
    assert cli.main(["setup", "--docker", "--config", str(config)]) == 0
    assert calls == [
        (
            config.parent,
            {
                "files_dir": shared,
                "domain": "files.example.com" if mode == "domain" else None,
                "private": mode == "private",
                "dry_run": False,
            },
        )
    ]
    output = capsys.readouterr().out
    assert f"URL: {url}" in output and str(shared) in output
    assert output.count("Credentials: admin:abcdefgh2345") == 1
    assert not config.exists()


@pytest.mark.parametrize(
    "answers,expected", [(["", "3", "no"], 0), (["", "9"], 2), (["", "2", ""], 2)]
)
def test_first_docker_setup_can_be_cancelled_or_corrected_without_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answers: list[str], expected: int
) -> None:
    import xferry.management.docker_deploy as docker

    config = tmp_path / "deployment/xferry.ini"
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(docker, "deploy_docker", lambda *_a, **_kw: pytest.fail("activation"))
    iterator = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _: next(iterator))
    assert cli.main(["setup", "--docker", "--config", str(config)]) == expected
    assert not config.parent.exists()


@pytest.mark.parametrize("installed_runtime", [False, True])
@pytest.mark.parametrize("dry_run", [False, True])
def test_retained_setup_resumes_saved_files_and_credentials_without_questions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed_runtime: bool,
    dry_run: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import xferry.management.bootstrap as bootstrap
    import xferry.management.managed_state as managed_state
    import xferry.management.model as model
    import xferry.management.setup as setup

    runtime = tmp_path / "runtime"
    if installed_runtime:
        runtime.write_text("signed runtime placeholder")
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\naccess = private\n")
    auth = tmp_path / "xferry.auth"
    auth.write_text("admin:original-password\n")
    layout = SimpleNamespace(current_executable=runtime, config_file=config, auth_file=auth)
    before = (config.read_bytes(), auth.read_bytes())
    events = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(instances, "discover_instances", lambda: ())
    monkeypatch.setattr(model, "ManagedLayout", lambda: layout)
    monkeypatch.setattr(managed_state, "has_retained_state", lambda selected: selected is layout)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("retained setup asked questions"))

    def install(version):
        events.append(("install", version))
        return SimpleNamespace(exit_code=0)

    def resume(selected):
        assert selected is layout
        events.append(("resume", selected.config_file))
        return setup.SetupResult(0, "Saved credentials preserved", detail="http://127.0.0.1:8080")

    monkeypatch.setattr(bootstrap, "install_release", install)
    monkeypatch.setattr(setup, "SetupExecutor", lambda: SimpleNamespace(resume=resume))
    arguments = ["setup", "--config", "/etc/xferry/xferry.ini", "--json"]
    if dry_run:
        arguments.append("--dry-run")
    assert cli.main(arguments) == 0
    if dry_run:
        assert events == []
    else:
        assert [event[0] for event in events] == (
            ["resume"] if installed_runtime else ["install", "resume"]
        )
    assert (config.read_bytes(), auth.read_bytes()) == before
    output = json.loads(capsys.readouterr().out)
    assert "original-password" not in json.dumps(output)


def test_portable_wizard_creates_public_profile_and_password_in_one_journey(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    answers = iter(("6", "2", "files.example.com", "8", "yes"))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.main(["config", "--config", str(config)]) == 0
    settings = configuration.load_settings_text(config.read_text(), config_path=config)
    assert settings.access == "public" and settings.https_mode == "domain"
    assert settings.domain == "files.example.com"
    auth = Path(settings.auth_file)
    username, password = auth.read_text().strip().split(":")
    assert username == "admin" and len(password) == 12
    assert auth.stat().st_mode & 0o777 == 0o600
    output = capsys.readouterr().out
    assert output.count(f"Credentials: {username}:{password}") == 1
    assert password not in config.read_text()


def test_wizard_cancelled_password_rotation_preserves_existing_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "xferry.ini"
    auth = tmp_path / "xferry.auth"
    config.write_text(f"[security]\nauth_file = {auth}\n")
    auth.write_text("operator:unchanged-password\n")
    before = (config.read_bytes(), auth.read_bytes())
    answers = iter(("8", "no", "0"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert (config.read_bytes(), auth.read_bytes()) == before


def test_wizard_refuses_saving_invalid_draft_and_keeps_it_correctable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\naccess = private\n")
    answers = iter(("2", "many", "9", "2", "32", "9", "yes"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert configuration.load_settings_text(config.read_text()).max_size_mb == 32
    assert "Correct the draft before saving" in capsys.readouterr().out


def test_multiple_saved_servers_require_explicit_script_choice_but_offer_terminal_numbers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import xferry.management.docker_deploy as docker

    first = instances.Instance(tmp_path / "first/xferry.ini", "docker")
    second = instances.Instance(tmp_path / "second/xferry.ini", "docker")
    monkeypatch.setattr(instances, "discover_instances", lambda: (first, second))
    calls = []
    monkeypatch.setattr(
        docker,
        "docker_operation",
        lambda path, action, **kwargs: calls.append((path, action)) or DockerResult(0, "running"),
    )
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert cli.main(["status"]) == 2
    assert "--config FILE" in capsys.readouterr().err
    assert calls == []
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "2")
    assert cli.main(["status"]) == 0
    assert calls == [(second.config, "status")]
    output = capsys.readouterr().out
    assert str(first.config) in output and str(second.config) in output


@pytest.mark.parametrize("answer", ["0", "3", "invalid"])
def test_invalid_instance_choice_cannot_act_on_another_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    import xferry.management.docker_deploy as docker

    found = (
        instances.Instance(tmp_path / "first.ini", "docker"),
        instances.Instance(tmp_path / "second.ini", "docker"),
    )
    monkeypatch.setattr(instances, "discover_instances", lambda: found)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: answer)
    monkeypatch.setattr(docker, "docker_operation", lambda *_a, **_kw: pytest.fail("wrong server"))
    assert cli.main(["restart"]) == 2


def test_thematic_settings_redirect_password_changes_to_password_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    before = "[server]\naccess = private\n"
    config.write_text(before)
    rows = configuration.describe_settings(before, all_settings=True)
    groups = list(dict.fromkeys(row["group"] for row in rows))
    group = next(row["group"] for row in rows if row["name"] == "auth_file")
    matching = [row for row in rows if row["group"] == group]
    index = next(index for index, row in enumerate(matching, 1) if row["name"] == "auth_file")
    answers = iter(("7", str(groups.index(group) + 1), str(index), "0"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert config.read_text() == before
    assert "Use Password to generate credentials" in capsys.readouterr().out


def test_invalid_thematic_group_keeps_editor_open_and_source_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    before = "[server]\naccess = private\n"
    config.write_text(before)
    answers = iter(("7", "not-a-number", "0"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert config.read_text() == before
    assert "choose a listed group number" in capsys.readouterr().out


def test_human_explanation_shows_automatic_default_and_every_input_surface(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["config", "explain", "https_mode"]) == 0
    output = capsys.readouterr().out
    assert "Default: off for private/lab; auto for public" in output
    assert "INI: [tls] https_mode" in output and "XFERRY_HTTPS_MODE" in output
    assert "--https" in output
    for label in ("Example:", "Constraints:", "Dependencies:", "Applies to:", "Apply:"):
        assert label in output


def test_settings_filters_find_certificate_options_without_printing_all_limits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\naccess = private\n")
    assert (
        cli.main(
            [
                "config",
                "show",
                "--config",
                str(config),
                "--group",
                "tls",
                "--search",
                "file",
                "--json",
            ]
        )
        == 0
    )
    rows = json.loads(capsys.readouterr().out)
    assert rows and all(row["group"] == "tls" for row in rows)
    assert {"cert_file", "key_file"} <= {row["name"] for row in rows}
    assert "max_size_mb" not in {row["name"] for row in rows}


@pytest.mark.parametrize(
    "action,values,error_fragment",
    [
        ("set", [], "at least one KEY=VALUE"),
        ("explain", [], "one setting name"),
        ("show", ["port"], "does not accept positional values"),
        ("check", [], "does not exist"),
        ("explain", ["unknown_setting"], "unknown setting"),
    ],
)
def test_configuration_input_errors_are_actionable_and_do_not_create_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    action: str,
    values: list[str],
    error_fragment: str,
) -> None:
    config = tmp_path / "not-created/xferry.ini"
    assert cli.main(["config", action, *values, "--config", str(config), "--json"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "error" and error_fragment in payload["message"]
    assert not config.parent.exists()
