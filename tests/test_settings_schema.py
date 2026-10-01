"""Contract tests for the canonical operator-settings metadata."""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

from xferry.cli import create_parser
from xferry.settings import (
    ServerSettings,
    load_settings_text,
    render_sample_profile,
    resolve_settings,
)
from xferry.settings_schema import (
    CLI_TO_SETTING_MAP,
    ENV_TO_SETTING_MAP,
    NO_CLI_SETTING_NAMES,
    SAMPLE_PROFILE_BY_NAME,
    SAMPLE_PROFILE_NAMES,
    SAMPLE_TARGET_NAMES,
    SECTION_KEY_MAP,
    SETTING_SPEC_BY_NAME,
    SETTING_SPECS,
    cli_to_setting_map,
    env_to_setting_map,
    format_ini_value,
    render_ini_entry,
    sample_specs,
    section_key_map,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_schema_covers_all_48_public_runtime_fields_in_dataclass_order() -> None:
    runtime_fields = tuple(
        settings_field.name
        for settings_field in fields(ServerSettings)
        if not settings_field.name.startswith("_")
    )

    assert len(runtime_fields) == 48
    assert tuple(spec.name for spec in SETTING_SPECS) == runtime_fields
    assert tuple(SETTING_SPEC_BY_NAME) == runtime_fields
    assert len(ENV_TO_SETTING_MAP) == 48
    assert len(CLI_TO_SETTING_MAP) == 44
    assert (
        {spec.name for spec in SETTING_SPECS if spec.cli is None}
        == set(NO_CLI_SETTING_NAMES)
        == {
            "public_direct",
            "plugin_allowlist",
            "plugins_allow_public_direct",
            "plugins_override_core",
        }
    )


def test_schema_records_an_explicit_disposition_for_every_target_and_field() -> None:
    assert SAMPLE_TARGET_NAMES == ("public-direct", "docker", "systemd", "managed")
    for spec in SETTING_SPECS:
        assert len(spec.sample_dispositions) == len(SAMPLE_TARGET_NAMES)
        assert set(spec.sample_dispositions) <= {"active", "commented", "omitted"}

    assert SETTING_SPEC_BY_NAME["acme_http_port"].sample_dispositions == (
        "omitted",
        "active",
        "active",
        "active",
    )
    assert tuple(spec.name for spec in sample_specs("public-direct"))[:7] == (
        "preset",
        "host",
        "port",
        "root_dir",
        "public_direct",
        "json_log",
        "workers",
    )


def test_schema_objects_and_all_derived_maps_are_deeply_read_only() -> None:
    with pytest.raises(FrozenInstanceError):
        SETTING_SPECS[0].name = "changed"  # type: ignore[misc]
    assert not hasattr(SETTING_SPECS[0], "__dict__")

    with pytest.raises(TypeError):
        SETTING_SPEC_BY_NAME["new"] = SETTING_SPECS[0]  # type: ignore[index]
    with pytest.raises(TypeError):
        ENV_TO_SETTING_MAP["XFERRY_NEW"] = "new"  # type: ignore[index]
    with pytest.raises(TypeError):
        CLI_TO_SETTING_MAP["new"] = "new"  # type: ignore[index]
    with pytest.raises(TypeError):
        SECTION_KEY_MAP["server"]["new"] = "new"  # type: ignore[index]
    with pytest.raises(TypeError):
        SAMPLE_PROFILE_BY_NAME["docker"].value_map()["port"] = 1  # type: ignore[index]

    assert section_key_map() is SECTION_KEY_MAP
    assert env_to_setting_map() is ENV_TO_SETTING_MAP
    assert cli_to_setting_map() is CLI_TO_SETTING_MAP


def test_settings_schema_import_does_not_pull_in_runtime_or_handlers() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import xferry.settings_schema; "
                "blocked = sorted(name for name in sys.modules "
                "if name == 'xferry.server' or name.startswith('xferry.handlers')); "
                "raise SystemExit(repr(blocked) if blocked else 0)"
            ),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_argparse_setting_actions_are_derived_from_exact_schema_metadata() -> None:
    parser = create_parser(show_all_help=True)
    actions = {action.dest: action for action in parser._actions}
    defaults = ServerSettings()

    for spec in SETTING_SPECS:
        cli = spec.cli
        if cli is None:
            assert spec.name not in CLI_TO_SETTING_MAP.values()
            continue
        action = actions[cli.dest]
        expected_options = list(cli.option_strings)
        if cli.action == "boolean_optional":
            expected_options.extend(
                f"--no-{option[2:]}" for option in cli.option_strings if option.startswith("--")
            )
            assert isinstance(action, argparse.BooleanOptionalAction)
        elif cli.action == "append":
            assert isinstance(action, argparse._AppendAction)
        elif cli.action == "store_true":
            assert isinstance(action, argparse._StoreTrueAction)
        else:
            assert isinstance(action, argparse._StoreAction)

        assert action.option_strings == expected_options
        assert action.default == (
            getattr(defaults, spec.name) if cli.default_from_runtime else None
        )
        assert action.metavar == cli.metavar
        expected_help = cli.help.format(
            default=(
                f"{getattr(defaults, spec.name):g}"
                if isinstance(getattr(defaults, spec.name), float)
                else str(getattr(defaults, spec.name))
            )
        )
        assert action.help == expected_help
        assert action.choices == (list(cli.choices) if cli.choices else None)


def test_cli_defaults_and_schema_defaults_stay_in_lockstep() -> None:
    namespace = create_parser().parse_args([])
    defaults = ServerSettings()

    for spec in SETTING_SPECS:
        if spec.cli is None:
            continue
        expected = getattr(defaults, spec.name) if spec.cli.default_from_runtime else None
        assert getattr(namespace, spec.cli.dest) == expected


def test_ascii_whitespace_and_plugin_csv_grammars_remain_distinct() -> None:
    file_settings = load_settings_text(
        """
        [security]
        allowed_hosts = lower.example
        [plugins]
        plugin_allowlist = first.module:plugin, second.module:plugin
        """,
        validate=False,
    )
    settings = resolve_settings(
        file_settings=file_settings,
        env={
            "XFERRY_ALLOWED_HOSTS": (
                "one.example\ttwo.example\r\nthree.example\ffour.example\vfive.example"
            )
        },
    )

    assert settings.allowed_hosts == (
        "one.example",
        "two.example",
        "three.example",
        "four.example",
        "five.example",
    )
    assert settings.plugin_allowlist == (
        "first.module:plugin",
        "second.module:plugin",
    )

    replaced = resolve_settings(
        file_settings=file_settings,
        env={"XFERRY_ALLOWED_HOSTS": ""},
    )
    assert replaced.allowed_hosts == ()


def test_redaction_policy_is_schema_owned_and_paths_are_not_secrets() -> None:
    assert {spec.name for spec in SETTING_SPECS if spec.redaction == "secret"} == {"auth"}

    rendered = ServerSettings(
        auth="researcher:credential", auth_file="/run/xferry/auth"
    ).to_redacted_dict()

    assert rendered["auth"] == "***"
    assert rendered["auth_file"] == "/run/xferry/auth"


def test_ini_entry_helper_preserves_external_list_grammars_and_empty_shape() -> None:
    assert render_ini_entry("allowed_hosts", ()) == "allowed_hosts ="
    assert render_ini_entry("allowed_hosts", ("one.example", "two.example")) == (
        "allowed_hosts = one.example two.example"
    )
    assert render_ini_entry("plugin_allowlist", ("one:plugin", "two:plugin")) == (
        "plugin_allowlist = one:plugin, two:plugin"
    )
    assert render_ini_entry("public_direct", True, commented=True) == ("# public_direct = true")
    assert format_ini_value("body_timeout", 300.0) == "300"
    with pytest.raises(ValueError, match="unknown settings field"):
        render_ini_entry("remote_update", True)


def test_static_profiles_are_parseable_deterministic_and_whitespace_clean() -> None:
    assert SAMPLE_PROFILE_NAMES == ("public-direct", "docker", "systemd")
    for profile_name in SAMPLE_PROFILE_NAMES:
        first = render_sample_profile(profile_name)
        second = render_sample_profile(profile_name)

        assert first == second
        assert first.endswith("\n") and not first.endswith("\n\n")
        assert all(not line.endswith(" ") for line in first.splitlines())
        parsed = load_settings_text(first)
        assert parsed.public_direct is True

    assert "acme_http_port" not in render_sample_profile("public-direct")
    assert "acme_http_port = 8080\n" in render_sample_profile("docker")
    assert "acme_http_port = 80\n" in render_sample_profile("systemd")
