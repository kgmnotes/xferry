"""Tests for the compatible XFerry management command dispatcher."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

import pytest

from xferry.config import __version__
from xferry.management.cli import _COMMAND_EXAMPLES, main
from xferry.management.i18n import Translator, resolve_language

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    from setuptools._vendor import tomli as tomllib  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_module_with_blocked_management_backends(
    tmp_path: Path,
    argv: Sequence[str],
    *,
    non_linux: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the package entry point where Linux-only backends cannot import."""
    (tmp_path / "sitecustomize.py").write_text(
        """
import importlib.abc
import os
import sys


class BlockedManagementBackends(importlib.abc.MetaPathFinder):
    blocked = frozenset(
        {
            "xferry.management.releases",
            "xferry.management.service",
            "xferry.management.setup",
            "xferry.management.system",
        }
    )

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.blocked:
            raise ModuleNotFoundError(f"blocked management backend: {fullname}")
        return None


sys.meta_path.insert(0, BlockedManagementBackends())
if os.environ.get("XFERRY_TEST_NON_LINUX") == "1":
    sys.platform = "win32"
""",
        encoding="utf-8",
    )
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(tmp_path), str(REPO_ROOT))),
    }
    if non_linux:
        environment["XFERRY_TEST_NON_LINUX"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "xferry", *argv],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


class _BlockedServerCli(ModuleType):
    """Fail when root dispatch imports the server CLI for non-run commands."""

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"server CLI must not be imported for root dispatch: {name}")


def _block_server_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "xferry.cli", _BlockedServerCli("xferry.cli"))


def _configured_console_entrypoint() -> tuple[str, str]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        script = tomllib.load(pyproject_file)["project"]["scripts"]["xferry"]
    module_name, separator, function_name = script.partition(":")
    assert separator and module_name and function_name
    return module_name, function_name


@pytest.mark.parametrize("argv", [[], ["--port", "8123"], ["unsupported-command"]])
def test_configured_console_entrypoint_dispatches_non_run_without_server_runtime(
    argv: list[str],
) -> None:
    """The packaged root entry point must remain lightweight for non-run arguments."""
    module_name, function_name = _configured_console_entrypoint()
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import importlib
import json
import sys
from types import ModuleType


class BlockedServer(ModuleType):
    def __getattr__(self, name):
        raise AssertionError(f"server runtime must not be imported for root dispatch: {name}")


sys.modules["xferry.server"] = BlockedServer("xferry.server")
entrypoint = getattr(importlib.import_module(sys.argv[1]), sys.argv[2])
raise SystemExit(entrypoint(json.loads(sys.argv[3])))
            """,
            module_name,
            function_name,
            json.dumps(argv),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert child.returncode == (0 if not argv else 2), child.stderr
    assert "usage: xferry [--lang LANG] COMMAND [OPTIONS]" in (child.stdout + child.stderr)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--help"], "usage: xferry [--lang LANG] COMMAND [OPTIONS]"),
        (["help", "setup"], "usage: xferry setup"),
        (["run", "--help"], "usage: xferry run"),
        (["examples"], "Examples:"),
    ],
)
def test_module_entrypoint_keeps_portable_commands_available_without_linux_backends(
    tmp_path: Path, argv: Sequence[str], expected: str
) -> None:
    """Eager management imports would prevent portable package commands from starting."""
    child = _run_module_with_blocked_management_backends(tmp_path, argv)

    assert child.returncode == 0, child.stderr
    assert expected in child.stdout
    assert "blocked management backend" not in child.stderr


@pytest.mark.parametrize("command", _COMMAND_EXAMPLES)
def test_module_entrypoint_keeps_help_subcommands_portable_without_linux_backends(
    tmp_path: Path, command: str
) -> None:
    """Every documented command help path must avoid Linux-only management backends."""
    child = _run_module_with_blocked_management_backends(tmp_path, ["help", command])

    assert child.returncode == 0, child.stderr
    assert f"usage: xferry {command}" in child.stdout
    assert "blocked management backend" not in child.stderr


@pytest.mark.parametrize("command", _COMMAND_EXAMPLES)
def test_module_entrypoint_keeps_direct_command_help_portable_without_linux_backends(
    tmp_path: Path, command: str
) -> None:
    """Every direct command help path must avoid Linux-only management backends."""
    child = _run_module_with_blocked_management_backends(tmp_path, [command, "--help"])

    assert child.returncode == 0, child.stderr
    assert f"usage: xferry {command}" in child.stdout
    assert "blocked management backend" not in child.stderr


@pytest.mark.parametrize(
    "argv",
    (("update", "--help"), ("help", "update")),
)
def test_update_help_requires_exact_version_and_states_managed_root_scope(
    argv: tuple[str, ...],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Update help must prevent portable or mutable-channel use before backend import."""
    assert main(argv) == 0

    output = capsys.readouterr().out
    assert "usage: xferry update" in output
    assert "--to VERSION" in output
    assert "managed Linux/systemd" in output
    assert "root" in output
    assert "pipx upgrade xferry" in output


def test_update_requires_target_before_backend_import(tmp_path: Path) -> None:
    """Omitting an immutable target must stop before release/network dependencies load."""
    child = _run_module_with_blocked_management_backends(tmp_path, ["update", "--dry-run"])

    assert child.returncode == 2
    assert "--to" in child.stderr
    assert "required" in child.stderr
    assert "blocked management backend" not in child.stderr


def test_internal_release_envelope_verifier_is_hidden_and_forwards_exact_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The installer needs a read-only trust seam without advertising a user lifecycle command."""
    observed: list[tuple[Path, Path, Path, str, str]] = []

    def verify(
        manifest: Path,
        signature: Path,
        executable: Path,
        *,
        expected_version: str,
        expected_platform: str,
    ) -> object:
        observed.append((manifest, signature, executable, expected_version, expected_platform))
        return object()

    monkeypatch.setattr(
        "xferry.management.release_verifier.verify_release_envelope",
        verify,
    )
    paths = [tmp_path / name for name in ("manifest", "signature", "xferry")]

    assert (
        main(
            [
                "_verify-release-envelope",
                "--manifest",
                str(paths[0]),
                "--signature",
                str(paths[1]),
                "--executable",
                str(paths[2]),
                "--version",
                "0.2.0",
                "--platform",
                "linux-x86_64",
            ]
        )
        == 0
    )

    assert observed == [(*paths, "0.2.0", "linux-x86_64")]
    assert capsys.readouterr().out == "Release envelope verified.\n"
    assert main(["help"]) == 0
    assert "_verify-release-envelope" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["setup", "--dry-run"],
        ["credentials", "reset"],
        ["status"],
        ["logs"],
        ["start"],
        ["stop"],
        ["restart"],
        ["doctor"],
        ["update", "--to", "0.1.0", "--dry-run"],
        ["rollback", "--dry-run"],
        ["uninstall", "--dry-run"],
    ],
)
def test_module_entrypoint_rejects_linux_management_operations_before_backend_imports(
    tmp_path: Path, argv: Sequence[str]
) -> None:
    """A non-Linux operation must fail before it can import or run a backend."""
    child = _run_module_with_blocked_management_backends(tmp_path, argv, non_linux=True)

    assert child.returncode == 4
    assert "blocked management backend" not in child.stderr
    assert "Linux/systemd-only" in child.stderr
    assert "pipx install xferry" in child.stderr
    assert "pipx upgrade xferry" in child.stderr
    assert "pipx uninstall xferry" in child.stderr


@pytest.mark.parametrize(
    ("platform_name", "display_name"),
    [("win32", "Windows"), ("darwin", "macOS")],
)
def test_non_linux_managed_diagnostics_are_actionable_in_text_and_json(
    platform_name: str,
    display_name: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from xferry.management import cli

    monkeypatch.setattr(cli.sys, "platform", platform_name)

    assert main(["doctor", "--json"]) == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["code"] == "unsupported-platform"
    assert payload["message"] == "Managed commands are Linux/systemd-only on supported hosts."
    assert display_name in payload["detail"]
    assert payload["next_actions"] == [
        (
            "Use a supported managed host: Ubuntu 22.04/24.04/26.04 or Debian 12/13 "
            "on x86_64/aarch64 with systemd."
        ),
        (
            "For portable use, run `pipx install xferry`; use `pipx upgrade xferry` "
            "and `pipx uninstall xferry` for lifecycle management."
        ),
    ]

    assert main(["--lang", "ru", "update", "--to", "0.2.0", "--dry-run", "--json"]) == 4
    update_payload = json.loads(capsys.readouterr().out)
    update_detail = update_payload.pop("detail")
    assert update_payload == {
        "active": None,
        "before": None,
        "code": "unsupported-platform",
        "dry_run": True,
        "exit_code": 4,
        "message": "Managed commands are Linux/systemd-only on supported hosts.",
        "next_actions": payload["next_actions"],
        "rollback": "not_attempted",
        "status": "error",
        "target": "0.2.0",
        "version": "0.2.0",
    }
    assert display_name in update_detail
    assert "Supported matrix:" in update_detail

    assert main(["status"]) == 4
    text = capsys.readouterr().err
    assert "Linux/systemd-only" in text
    assert display_name in text
    assert "pipx install xferry" in text


@pytest.mark.parametrize(
    ("argv", "env", "expected"),
    [
        (["--lang", "ru", "examples"], {"XFERRY_LANG": "en"}, "ru"),
        ([], {"LC_ALL": "ru_RU.UTF-8", "LANG": "en_US.UTF-8"}, "ru"),
        ([], {"LANG": "de_DE.UTF-8"}, "en"),
    ],
)
def test_language_precedence(argv: Sequence[str], env: dict[str, str], expected: str) -> None:
    """A more-specific locale source must win over lower-priority values."""
    assert resolve_language(argv, env).code == expected


@pytest.mark.parametrize(
    ("locale", "expected"),
    [("ru", "ru"), ("ru-RU", "ru"), ("RU_utf8", "ru"), ("en_US.UTF-8", "en")],
)
def test_russian_prefix_is_selected_and_other_locales_fall_back_to_english(
    locale: str, expected: str
) -> None:
    """Changing the locale prefix matching branch must change the selection."""
    assert resolve_language([], {"LANG": locale}).code == expected


def test_explicit_language_is_removed_before_canonical_run_is_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing the run command or forwarding --lang would break server dispatch."""
    received: list[list[str]] = []

    def fake_run_main(argv: Sequence[str] | None = None) -> int:
        received.append(list(argv or []))
        return 41

    monkeypatch.setattr("xferry.cli.run_main", fake_run_main)

    assert main(["--lang", "ru", "run", "--port", "8123", "--quiet"]) == 41
    assert received == [["--port", "8123", "--quiet"]]


def test_empty_argv_prints_root_help_without_importing_server_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Falling through from empty argv would construct a server instead of showing help."""
    _block_server_cli(monkeypatch)

    assert main([]) == 0

    captured = capsys.readouterr()
    assert "usage: xferry [--lang LANG] COMMAND [OPTIONS]" in captured.out
    assert "xferry run --preset local" in captured.out
    assert "Legacy server options" not in captured.out
    assert captured.err == ""


@pytest.mark.parametrize("argv", [["-h"], ["--help"]])
def test_root_help_flags_print_root_help_without_importing_server_cli(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Conventional root help must be discoverable without entering server dispatch."""
    _block_server_cli(monkeypatch)

    assert main(argv) == 0

    captured = capsys.readouterr()
    assert "usage: xferry [--lang LANG] COMMAND [OPTIONS]" in captured.out
    assert "xferry run --preset local" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize("argv", [["--version"], ["--lang", "ru", "--version"]])
def test_root_version_uses_package_authority_without_server_imports(
    argv: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Root version is available even when server backends cannot be imported."""
    _block_server_cli(monkeypatch)
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.out == f"xferry {__version__}\n"
    assert captured.err == ""


@pytest.mark.parametrize(
    ("language", "portable_heading", "managed_heading"),
    [
        ("en", "Portable commands (Windows, macOS, Linux):", "Managed Linux/systemd commands:"),
        ("ru", "Переносимые команды (Windows, macOS, Linux):", "Команды Linux/systemd:"),
    ],
)
def test_root_help_labels_portable_and_managed_lifecycles(
    language: str,
    portable_heading: str,
    managed_heading: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--lang", language, "--help"]) == 0
    output = capsys.readouterr().out
    portable, managed = output.split(managed_heading)
    assert portable_heading in portable
    for command in ("run", "examples", "help"):
        assert f"  {command}\n" in portable
    assert "  setup\n" in managed
    assert "  setup\n" not in portable
    assert "pipx upgrade xferry" in output
    assert "pipx uninstall xferry" in output
    assert "--version" in output


@pytest.mark.parametrize("language", ["en", "ru"])
@pytest.mark.parametrize("argv", [["typo"], ["help", "typo"]])
def test_unknown_command_names_the_token_and_points_to_help(
    language: str, argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--lang", language, *argv]) == 2
    captured = capsys.readouterr()
    assert "'typo'" in captured.err
    assert "xferry help" in captured.err


@pytest.mark.parametrize(
    ("language", "usage_error", "unknown_command"),
    [
        ("en", "usage error", "Unknown command"),
        ("ru", "ошибка использования", "Неизвестная команда"),
    ],
)
def test_help_for_known_command_without_details_is_a_usage_error(
    language: str,
    usage_error: str,
    unknown_command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A known command without focused help must not be mislabeled as unknown."""
    assert main(["--lang", language, "help", "help"]) == 2
    captured = capsys.readouterr()
    assert usage_error in captured.err
    assert unknown_command not in captured.err


@pytest.mark.parametrize("argv", [["--port", "8123"], ["unsupported-command"]])
def test_root_rejects_bare_server_flags_and_unknown_positionals_without_server_cli(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Forwarding root tokens to run_main would preserve the removed compatibility path."""
    _block_server_cli(monkeypatch)

    assert main(argv) == 2

    captured = capsys.readouterr()
    assert "usage: xferry [--lang LANG] COMMAND [OPTIONS]" in captured.err
    assert "xferry run" in captured.err


def test_management_usage_errors_return_the_stable_usage_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A malformed management command must be distinguishable from operation failure."""
    assert main(["examples", "unexpected"]) == 2
    assert "usage:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["examples"], "xferry setup"),
        (["--lang", "ru", "examples"], "xferry setup"),
    ],
)
def test_examples_are_rendered_in_the_selected_language(
    argv: Sequence[str], expected: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Removing localized example rendering would leave operators without copy-paste commands."""
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert expected in output
    if "--lang" in argv:
        assert "Примеры" in output
    else:
        assert "Examples" in output


@pytest.mark.parametrize(
    ("argv", "heading"),
    [
        (["examples"], "Examples:"),
        (["--lang", "ru", "examples"], "Примеры:"),
    ],
)
def test_examples_cover_the_primary_disposable_lifecycle_without_maintenance_commands(
    argv: Sequence[str], heading: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Ordinary examples must keep the temporary deployment journey short."""
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert heading in output
    for example in (
        "xferry run --preset local",
        "sudo xferry setup",
        "sudo xferry status",
        "xferry logs",
        "sudo xferry start",
        "sudo xferry stop",
        "sudo xferry restart",
        "sudo xferry doctor",
        "sudo xferry credentials reset",
        "xferry examples",
        "sudo xferry uninstall",
    ):
        assert example in output
    assert "xferry update" not in output
    assert "xferry rollback" not in output


@pytest.mark.parametrize(
    ("argv", "maintenance_heading"),
    [
        (["help"], "Optional maintenance:"),
        (["--lang", "ru", "help"], "Необязательное обслуживание:"),
    ],
)
def test_root_help_separates_optional_long_lived_maintenance(
    argv: Sequence[str],
    maintenance_heading: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Local rollback must not look required for a disposable deployment."""
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert maintenance_heading in output
    assert "  update" in output
    assert "  rollback" in output
    assert "Legacy server options" not in output
    assert "xferry [SERVER OPTIONS]" not in output


@pytest.mark.parametrize("command", ["update", "rollback"])
def test_optional_maintenance_commands_keep_focused_help(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Moving rollback out of primary help must not remove its explicit help."""
    assert main(["help", command]) == 0
    assert f"usage: xferry {command}" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "example"),
    [
        ("update", f"sudo xferry update --to {__version__}"),
        ("rollback", f"sudo xferry rollback --to {__version__}"),
    ],
)
def test_maintenance_help_uses_only_the_authoritative_release_examples(
    command: str, example: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Maintenance help must derive copy-paste examples from package authority."""
    assert main(["help", command]) == 0
    output = capsys.readouterr().out
    assert f"Example: {example}" in output


def test_help_run_shows_the_canonical_copy_paste_example(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Rejecting listed `run` help would leave the canonical command undocumented."""
    assert main(["help", "run"]) == 0
    output = capsys.readouterr().out
    assert "usage: xferry run" in output
    assert "Example: xferry run --preset local" in output


def test_root_help_is_compact_and_contains_a_concrete_example(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Expanding root help beyond the compact operator reference is a regression."""
    assert main(["help"]) == 0
    output = capsys.readouterr().out
    assert "xferry run --preset local" in output
    assert len(output.splitlines()) < 80


def test_command_help_localizes_its_description_and_example(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An English-only command parser would regress the selected Russian interface."""
    assert main(["--lang", "ru", "setup", "--help"]) == 0
    output = capsys.readouterr().out
    assert "Установить и настроить" in output
    assert "Пример: sudo xferry setup" in output
    assert "Показать эту справку и выйти" in output


def test_translator_formats_localized_values_without_changing_machine_keys() -> None:
    """A missing catalog entry or formatting value would break operator-facing output."""
    assert Translator("ru").get("not_implemented", command="status") == (
        "Команда 'status' пока не реализована."
    )
    assert Translator("en").get("not_implemented", command="status") == (
        "The 'status' command is not implemented yet."
    )
    assert Translator("en").release_text("unsupported_release_major", version="4.1.0") == (
        "XFerry maintenance accepts only 0.x releases; 4.1.0 requires a separately "
        "approved release line."
    )
    assert Translator("ru").release_text("unsupported_release_major", version="4.1.0") == (
        "Обслуживание XFerry принимает только выпуски 0.x; для 4.1.0 требуется отдельно "
        "утверждённая линия выпусков."
    )
    assert Translator("en").release_text("unsupported_managed_state") == (
        "Unsupported or ambiguous XFerry managed state was detected and preserved; "
        "no changes were made. Back up its configuration and data, remove it with its "
        "original tooling, then install XFerry in a clean environment."
    )
    assert Translator("ru").release_text("unsupported_managed_state") == (
        "Обнаружено неподдерживаемое или неоднозначное управляемое состояние XFerry; "
        "оно сохранено, изменения не внесены. Создайте резервную копию его настроек и данных, "
        "удалите его исходными инструментами, затем установите XFerry в чистом окружении."
    )
