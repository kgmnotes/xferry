"""Operator journeys use one setup, configuration and lifecycle vocabulary."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from xferry.management import cli, configuration, instances, wizard
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


def test_resource_limits_show_configured_and_effective_defaults() -> None:
    rows = {row["name"]: row for row in configuration.describe_settings("", all_settings=True)}
    memory = rows["body_memory_budget_mb"]
    websocket = rows["max_websocket_connections"]
    assert memory["configured"] == 128 and memory["source"] == "default"
    assert memory["effective"] == 128
    assert websocket["configured"] is None and websocket["effective"] == 8


def test_readable_native_check_never_elevates_service_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "xferry.ini"
    path.write_text("[server]\nconfig_version = 1\naccess = private\n")
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
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "password" not in payload
    settings = configuration.load_settings_text(config.read_text())
    password = Path(settings.auth_file).read_text().strip().split(":", 1)[1]
    assert len(password) == 12
    assert password not in config.read_text()
    assert password not in captured.out + captured.err
    assert captured.err == ""


def test_show_all_reports_canonical_private_state_without_an_alias(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\nconfig_version = 1\naccess = private\n")
    assert cli.main(["config", "show", "--all", "--config", str(config), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    state = next(row for row in rows if row["name"] == "state_dir")
    assert Path(state["value"]).is_absolute()
    assert not any(row["name"] == "state_directory" for row in rows)
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


def test_incompatible_setup_options_never_elevate_or_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(instances, "discover_instances", lambda: pytest.fail("instance probe"))
    monkeypatch.setattr(cli, "_privileged", lambda *_: pytest.fail("elevation"))
    assert cli.main(["setup", "--domain", "files.example.com", "--access", "private"]) == 2


def test_clearing_files_folder_restores_stable_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text(f"[server]\nconfig_version = 1\nfiles_dir = {tmp_path / 'old files'}\n")
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
    config.write_text("[server]\nconfig_version = 1\naccess = private\n")
    answers = iter(("2", invalid, "2", "25", "9", "yes"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert configuration.load_settings_text(config.read_text()).max_size_mb == 25


def test_wizard_can_recover_from_runtime_validation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\nconfig_version = 1\naccess = private\n")
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


def test_unsupported_profile_is_refused_without_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "xferry.ini"
    before = f"[server]\nconfig_version = 1\npreset = local\nroot_dir = {tmp_path / 'old state'}\n"
    config.write_text(before)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert cli.main(["config", "--config", str(config)]) == 2
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
    assert args.files_dir == "/srv/explicit-share" and args.access == "private"
    assert all("Files folder" not in prompt for prompt in prompts)


def test_wizard_preview_uses_effective_environment_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    config.write_text("[server]\nconfig_version = 1\nport = 8080\n")
    monkeypatch.setenv("XFERRY_PORT", "9090")
    monkeypatch.setattr("builtins.input", lambda _: "0")
    assert wizard.configure(config, "portable", "en") == 0
    assert "URL: http://127.0.0.1:9090" in capsys.readouterr().out
    assert configuration.load_settings_text(config.read_text()).port == 8080


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
    config.write_text(f"[server]\nconfig_version = 1\n[security]\nauth_file = {auth}\n")
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
    config.write_text("[server]\nconfig_version = 1\naccess = private\n")
    answers = iter(("2", "many", "9", "2", "32", "9", "yes"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert wizard.configure(config, "portable", "en") == 0
    assert configuration.load_settings_text(config.read_text()).max_size_mb == 32
    assert "Correct the draft before saving" in capsys.readouterr().out


def test_thematic_settings_redirect_password_changes_to_password_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "xferry.ini"
    before = "[server]\nconfig_version = 1\naccess = private\n"
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
    before = "[server]\nconfig_version = 1\naccess = private\n"
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
    config.write_text("[server]\nconfig_version = 1\naccess = private\n")
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
