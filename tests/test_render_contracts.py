"""Mutation, completeness, and orchestration tests for generated API contracts."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import fields
from pathlib import Path

import pytest

from tools import render_contracts, sync_docs
from xferry.features import CoreMethodSpec, core_method_specs
from xferry.management.model import supported_managed_host_matrix
from xferry.smuggle.policy import build_smuggle_capabilities

CORE_REGION = "xferry-contracts/core-methods"
SMUGGLE_REGION = "xferry-contracts/smuggle-capabilities"
CLI_REGION = "xferry-contracts/cli-reference"
MANAGED_HOSTS_REGION = "xferry-contracts/managed-hosts"


def _marked_document(
    core_body: bytes = b"stale core\n",
    smuggle_body: bytes = b"stale capabilities\n",
) -> bytes:
    return (
        b"human preamble\n"
        + render_contracts.start_marker(CORE_REGION)
        + b"\n"
        + core_body
        + render_contracts.end_marker(CORE_REGION)
        + b"\nhuman middle\n"
        + render_contracts.start_marker(SMUGGLE_REGION)
        + b"\n"
        + smuggle_body
        + render_contracts.end_marker(SMUGGLE_REGION)
        + b"\nhuman suffix\n"
    )


def _generated() -> dict[str, bytes]:
    return {
        CORE_REGION: render_contracts.render_core_methods(),
        SMUGGLE_REGION: render_contracts.render_smuggle_capabilities(),
    }


def _single_marked_document(region: str) -> bytes:
    return (
        b"human preamble\n"
        + render_contracts.start_marker(region)
        + b"\nstale body\n"
        + render_contracts.end_marker(region)
        + b"\nhuman suffix\n"
    )


def _table_cells(line: str) -> list[str]:
    assert line.startswith("| ") and line.endswith(" |")
    return line[2:-2].split(" | ")


def _unquote_code(cell: str) -> str:
    assert cell.startswith("`") and cell.endswith("`")
    return cell[1:-1]


def _assert_ordered_equal(actual: object, expected: object) -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        assert list(actual) == list(expected)
        for key in expected:
            _assert_ordered_equal(actual[key], expected[key])
        return
    if isinstance(expected, list):
        assert isinstance(actual, list)
        assert len(actual) == len(expected)
        for actual_item, expected_item in zip(actual, expected, strict=True):
            _assert_ordered_equal(actual_item, expected_item)
        return
    assert actual == expected


@pytest.mark.parametrize("argv", ([], ["--check", "--write"]))
def test_cli_requires_exactly_one_explicit_mode(argv: list[str]) -> None:
    with pytest.raises(SystemExit, match="2"):
        render_contracts.parse_args(argv)


def test_repository_contract_regions_are_current() -> None:
    assert render_contracts.render_all(check=True) == 0


def test_core_table_contains_every_public_spec_field_except_handler_name() -> None:
    lines = render_contracts.render_core_methods().decode("utf-8").splitlines()
    public_fields = [
        field.name
        for field in fields(CoreMethodSpec)
        if not field.name.startswith("_") and field.name != "handler_name"
    ]
    assert [_unquote_code(cell) for cell in _table_cells(lines[0])] == public_fields
    assert len(lines) == len(core_method_specs()) + 2

    actual_rows = [_table_cells(line) for line in lines[2:]]
    for row, spec in zip(actual_rows, core_method_specs(), strict=True):
        expected = []
        for name in public_fields:
            value = getattr(spec, name)
            if name == "exposure_note":
                expected.append(value)
            elif isinstance(value, bool):
                expected.append(f"`{'true' if value else 'false'}`")
            else:
                expected.append(f"`{value}`")
        assert row == expected

    rendered = render_contracts.render_core_methods().decode("utf-8")
    assert "handler_name" not in rendered
    assert all(spec.handler_name not in rendered for spec in core_method_specs())


def test_smuggle_table_round_trips_every_root_value_in_runtime_order() -> None:
    lines = render_contracts.render_smuggle_capabilities().decode("utf-8").splitlines()
    capabilities = build_smuggle_capabilities()
    rows = [_table_cells(line) for line in lines[2:]]

    assert [_unquote_code(row[0]) for row in rows] == list(capabilities)
    assert len(rows) == len(capabilities)
    for (expected_name, expected_value), row in zip(capabilities.items(), rows, strict=True):
        assert _unquote_code(row[0]) == expected_name
        actual_value = json.loads(_unquote_code(row[1]))
        _assert_ordered_equal(actual_value, expected_value)


def test_managed_support_table_contains_exactly_every_runtime_host_pair() -> None:
    lines = render_contracts.render_managed_support_matrix().decode("utf-8").splitlines()
    rows = [_table_cells(line) for line in lines[2:]]
    contract = supported_managed_host_matrix()
    expected = [
        [f"`{distribution} {version}`", f"`{architecture}`", "`systemd`"]
        for distribution, versions in contract["distributions"].items()
        for version in versions
        for architecture in contract["architectures"]
    ]

    assert rows == expected
    assert len(rows) == 10


def test_cli_reference_captures_real_english_root_and_per_command_help() -> None:
    rendered = render_contracts.render_cli_reference().decode("utf-8")

    assert rendered.startswith("## `xferry --help`\n")
    assert "usage: xferry [--lang LANG] COMMAND [OPTIONS]" in rendered
    for command in (
        "run",
        "setup",
        "status",
        "logs",
        "start",
        "stop",
        "restart",
        "doctor",
        "credentials",
        "config",
        "update",
        "rollback",
        "uninstall",
    ):
        assert f"## `xferry {command} --help`" in rendered
    assert "Signed release version to install (default:" in rendered
    assert "Управляем" not in rendered


def _observed_setup_usage_variants() -> tuple[str, str]:
    """Actual Python 3.12 and 3.13/3.14 layouts of the same setup grammar."""
    common = (
        "usage: xferry setup [-h] [--help-all] [--instance ID] [--backend {native,docker}]\n"
        "                    [--access {private,public}] [--domain DOMAIN] [--files-dir DIR] "
        "[--public-ip IP]\n"
    )
    return (
        common
        + "                    [--email EMAIL] [--firewall {allow,deny}]\n"
        + "                    [--to VERSION | --image REPOSITORY@sha256:DIGEST] "
        + "[--dry-run] [--json]",
        common
        + "                    [--email EMAIL] [--firewall {allow,deny}] [--to VERSION |\n"
        + "                    --image REPOSITORY@sha256:DIGEST] [--dry-run] [--json]",
    )


def test_cli_usage_reflows_actual_python_variants_without_changing_grammar() -> None:
    older, newer = _observed_setup_usage_variants()
    canonical = render_contracts._canonicalize_initial_usage(older)

    assert canonical == render_contracts._canonicalize_initial_usage(newer)
    assert canonical.split() == older.split() == newer.split()
    assert "[--to VERSION | --image REPOSITORY@sha256:DIGEST]" in " ".join(canonical.split())
    assert all(len(line) <= 100 for line in canonical.splitlines())


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_cli_usage_reflow_preserves_description_and_option_table_bytes(newline: str) -> None:
    usage = _observed_setup_usage_variants()[1].replace("\n", newline)
    body = newline.join(
        (
            "",
            "",
            "Description  with\ttabs and double spaces.",
            "",
            "options:",
            "  -H HOST, --host HOST, --bind-host HOST  Keep  this spacing.",
            "      wrapped option explanation\twith tabs",
            "",
            "usage: this later example must not be reflowed",
            "   [--example VALUE]",
            "",
        )
    )

    canonical = render_contracts._canonicalize_initial_usage(usage + body)

    assert canonical.endswith(body)
    assert canonical[: -len(body)].split() == usage.split()


@pytest.mark.parametrize("text", ["", "Overview\n\nusage: example --option VALUE", "Usage: text"])
def test_cli_usage_reflow_leaves_noninitial_usage_text_unchanged(text: str) -> None:
    assert render_contracts._canonicalize_initial_usage(text) == text


def test_cli_help_capture_applies_usage_reflow_without_normalizing_option_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = []
    body = "\n\nDescription  keeps spacing.\n\noptions:\n  --to VERSION  Keep\tthis detail."
    for usage in _observed_setup_usage_variants():

        def main(arguments: list[str], help_text: str = usage + body) -> int:
            assert arguments == ["--lang", "en", "setup", "--help"]
            print(help_text)
            return 0

        monkeypatch.setattr(render_contracts.management_cli, "main", main)
        captured.append(render_contracts._capture_english_help(["setup"]))

    assert captured[0] == captured[1]
    assert captured[0].endswith(body)


def test_cli_usage_reflow_retains_real_parser_aliases_metavars_and_nargs() -> None:
    parser = argparse.ArgumentParser(prog="xferry semantic-contract", add_help=False)
    parser.add_argument("-q", "--quiet", action="store_true", help="A flag without an argument.")
    parser.add_argument("-H", "--host", "--bind-host", metavar="HOST", help="A hostname.")
    parser.add_argument("--pair", nargs=2, metavar=("SOURCE", "TARGET"), help="A pair.")
    parser.add_argument("--maybe", nargs="?", const="soon", metavar="TIME", help="Optional time.")
    parser.add_argument("--item", action="append", metavar="ITEM", help="Repeatable item.")
    parser.add_argument("--many", nargs="+", metavar="VALUE", help="One or more values.")
    parser.add_argument("command", choices=("upload", "download"))
    parser.add_argument("destination", nargs="?", metavar="DESTINATION")
    original = parser.format_help().rstrip()

    canonical = render_contracts._canonicalize_initial_usage(original)

    original_usage, separator, original_body = original.partition("\n\n")
    canonical_usage, canonical_separator, canonical_body = canonical.partition("\n\n")
    assert canonical_usage.split() == original_usage.split()
    assert canonical_separator == separator == "\n\n"
    assert canonical_body == original_body
    for action in parser._actions:
        for option in action.option_strings:
            assert re.search(rf"(?<![\w-]){re.escape(option)}(?![\w-])", canonical)
    for metavar in ("HOST", "SOURCE", "TARGET", "TIME", "ITEM", "VALUE", "DESTINATION"):
        assert metavar in canonical
    assert "{upload,download}" in canonical
    parsed = parser.parse_args(
        [
            "-q",
            "--bind-host",
            "files.example",
            "--pair",
            "from",
            "to",
            "--maybe",
            "--item",
            "one",
            "--item",
            "two",
            "--many",
            "first",
            "second",
            "--",
            "upload",
            "there",
        ]
    )
    assert parsed.quiet and parsed.host == "files.example"
    assert parsed.pair == ["from", "to"] and parsed.maybe == "soon"
    assert parsed.item == ["one", "two"] and parsed.many == ["first", "second"]
    assert parsed.command == "upload" and parsed.destination == "there"


@pytest.mark.parametrize("change", ["added-option", "removed-option", "changed-metavar"])
def test_cli_usage_reflow_still_detects_real_parser_contract_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    original_parser = render_contracts.management_cli._command_parser
    selected = {"present": change != "added-option", "metavar": "ORIGINAL_VALUE"}

    def parser(command, translator, **options):
        result = original_parser(command, translator, **options)
        if command == "setup" and selected["present"]:
            result.add_argument(
                "--contract-probe", metavar=selected["metavar"], help="Runtime contract probe."
            )
        return result

    monkeypatch.setattr(render_contracts.management_cli, "_command_parser", parser)
    monkeypatch.setattr(
        render_contracts,
        "TARGETS",
        (render_contracts.ContractTarget("docs/cli-reference.md", (render_contracts.CLI_REGION,)),),
    )
    destination = tmp_path / "docs" / "cli-reference.md"
    destination.parent.mkdir()
    destination.write_bytes(_single_marked_document(CLI_REGION))
    assert render_contracts.render_all(check=False, repo_root=tmp_path) == 0
    original = destination.read_bytes()
    assert render_contracts.render_all(check=True, repo_root=tmp_path) == 0

    if change == "changed-metavar":
        selected["metavar"] = "CHANGED_VALUE"
    else:
        selected["present"] = change == "added-option"

    assert render_contracts.render_all(check=True, repo_root=tmp_path) == 1
    assert destination.read_bytes() == original
    changed = render_contracts.render_cli_reference()
    assert changed != original
    if change == "removed-option":
        assert b"--contract-probe" not in changed
    else:
        assert b"--contract-probe" in changed
        assert selected["metavar"].encode() in changed
    assert render_contracts.render_all(check=False, repo_root=tmp_path) == 0
    assert render_contracts.render_all(check=True, repo_root=tmp_path) == 0


def test_cli_and_managed_support_contracts_have_canonical_document_targets() -> None:
    targets = {
        target.path: tuple(region.name for region in target.regions)
        for target in render_contracts.TARGETS
    }

    assert targets["docs/cli-reference.md"] == (CLI_REGION,)
    assert targets["docs/managed-hosts.md"] == (MANAGED_HOSTS_REGION,)


def test_replace_generated_regions_preserves_every_outside_byte() -> None:
    core_start = render_contracts.start_marker(CORE_REGION)
    core_end = render_contracts.end_marker(CORE_REGION)
    smuggle_start = render_contracts.start_marker(SMUGGLE_REGION)
    smuggle_end = render_contracts.end_marker(SMUGGLE_REGION)
    document = (
        b"\xef\xbb\xbfoutside\r\n"
        + core_start
        + b"\r\nold core\r\n"
        + core_end
        + b"\r\n\x00between\r\n"
        + smuggle_start
        + b"\nold smuggle\n"
        + smuggle_end
        + b"\ntrailer\x00"
    )

    rendered = render_contracts.replace_generated_regions(
        document,
        {CORE_REGION: b"new core\n", SMUGGLE_REGION: b"new smuggle\n"},
    )

    assert rendered == (
        b"\xef\xbb\xbfoutside\r\n"
        + core_start
        + b"\r\nnew core\n"
        + core_end
        + b"\r\n\x00between\r\n"
        + smuggle_start
        + b"\nnew smuggle\n"
        + smuggle_end
        + b"\ntrailer\x00"
    )


@pytest.mark.parametrize(
    "document",
    (
        b"no markers\n",
        (
            render_contracts.start_marker(CORE_REGION)
            + b"\nbody\n"
            + render_contracts.end_marker(CORE_REGION)
            + b"\n"
        ),
        _marked_document()
        + render_contracts.start_marker(CORE_REGION)
        + b"\nduplicate\n"
        + render_contracts.end_marker(CORE_REGION)
        + b"\n",
        (
            render_contracts.start_marker(SMUGGLE_REGION)
            + b"\nbody\n"
            + render_contracts.end_marker(SMUGGLE_REGION)
            + b"\n"
            + render_contracts.start_marker(CORE_REGION)
            + b"\nbody\n"
            + render_contracts.end_marker(CORE_REGION)
            + b"\n"
        ),
        _marked_document()
        + b"<!-- BEGIN GENERATED: foreign -->\nforeign\n"
        + b"<!-- END GENERATED: foreign -->\n",
        (
            render_contracts.start_marker(CORE_REGION)
            + b"\n"
            + render_contracts.start_marker(SMUGGLE_REGION)
            + b"\nnested\n"
            + render_contracts.end_marker(SMUGGLE_REGION)
            + b"\n"
            + render_contracts.end_marker(CORE_REGION)
            + b"\n"
        ),
        (
            render_contracts.start_marker(CORE_REGION)
            + b" extra\nbody\n"
            + render_contracts.end_marker(CORE_REGION)
            + b"\n"
            + render_contracts.start_marker(SMUGGLE_REGION)
            + b"\nbody\n"
            + render_contracts.end_marker(SMUGGLE_REGION)
            + b"\n"
        ),
    ),
)
def test_replace_generated_regions_fails_closed_for_malformed_markers(
    document: bytes,
) -> None:
    with pytest.raises(render_contracts.MarkerError):
        render_contracts.replace_generated_regions(document, _generated())


def test_render_all_detects_drift_writes_and_is_idempotent(tmp_path: Path) -> None:
    api_path = tmp_path / "API.md"
    api_path.write_bytes(_marked_document())
    docs = tmp_path / "docs"
    docs.mkdir()
    docs.joinpath("cli-reference.md").write_bytes(_single_marked_document(CLI_REGION))
    docs.joinpath("managed-hosts.md").write_bytes(_single_marked_document(MANAGED_HOSTS_REGION))
    docs.joinpath("settings.md").write_bytes(
        _single_marked_document("xferry-contracts/settings-reference")
    )

    assert render_contracts.render_all(check=True, repo_root=tmp_path) == 1
    assert render_contracts.render_all(check=False, repo_root=tmp_path) == 0
    first = api_path.read_bytes()
    assert render_contracts.render_all(check=True, repo_root=tmp_path) == 0
    assert render_contracts.render_all(check=False, repo_root=tmp_path) == 0
    second = api_path.read_bytes()

    assert first == second
    assert first.startswith(b"human preamble\n")
    assert first.endswith(b"human suffix\n")


def test_render_all_validates_every_target_before_any_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_target = render_contracts.ContractTarget("first.md", render_contracts.REGIONS)
    malformed_target = render_contracts.ContractTarget("malformed.md", render_contracts.REGIONS)
    monkeypatch.setattr(
        render_contracts,
        "TARGETS",
        (first_target, malformed_target),
    )
    first_path = tmp_path / first_target.path
    first_path.write_bytes(_marked_document())
    original = first_path.read_bytes()
    malformed_path = tmp_path / malformed_target.path
    malformed_path.write_bytes(b"human document without markers\n")

    assert render_contracts.render_all(check=False, repo_root=tmp_path) == 2
    assert first_path.read_bytes() == original
    assert malformed_path.read_bytes() == b"human document without markers\n"


def test_sync_write_renders_contracts_before_building_api_mirror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "API.md").write_text("stale canonical API\n", encoding="utf-8")
    events: list[str] = []

    def render_first(*, check: bool, repo_root: Path) -> int:
        assert check is False
        assert repo_root == tmp_path
        events.append("contracts")
        (repo_root / "API.md").write_text("rendered canonical API\n", encoding="utf-8")
        return 0

    original_render_target = sync_docs.render_target

    def render_mirror(spec: sync_docs.MirrorSpec) -> bytes:
        events.append("mirror")
        assert (tmp_path / "API.md").read_text(encoding="utf-8") == ("rendered canonical API\n")
        return original_render_target(spec)

    monkeypatch.setattr(sync_docs, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        sync_docs,
        "MIRRORS",
        (sync_docs.MirrorSpec("API.md", "docs/api.md"),),
    )
    monkeypatch.setattr(sync_docs.render_contracts, "render_all", render_first)
    monkeypatch.setattr(sync_docs, "render_target", render_mirror)

    assert sync_docs.sync(check=False) == 0
    assert events == ["contracts", "mirror"]
    assert "rendered canonical API" in (tmp_path / "docs/api.md").read_text(encoding="utf-8")


def test_sync_check_stops_on_contract_drift_before_mirror_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def drifted(*, check: bool, repo_root: Path) -> int:
        assert check is True
        calls.append("contracts")
        return 1

    def unexpected_mirror(_spec: sync_docs.MirrorSpec) -> bytes:
        calls.append("mirror")
        raise AssertionError("mirror rendering must not run after contract drift")

    monkeypatch.setattr(sync_docs.render_contracts, "render_all", drifted)
    monkeypatch.setattr(sync_docs, "render_target", unexpected_mirror)

    assert sync_docs.sync(check=True) == 1
    assert calls == ["contracts"]


def test_settings_reference_examples_are_valid_ini_and_cover_every_setting() -> None:
    """Every documented setting must have a usable example, even with dependencies."""
    from xferry.settings import load_settings_text
    from xferry.settings_schema import SETTING_SPECS

    rendered = render_contracts.render_settings_reference().decode("utf-8")
    examples = re.findall(r"```ini\n(.*?)```", rendered, flags=re.DOTALL)
    assert len(examples) == len(SETTING_SPECS)
    for spec in SETTING_SPECS:
        section = rendered.split(f"#### `{spec.name}`", 1)[1].split("\n#### ", 1)[0]
        example = re.findall(r"```ini\n(.*?)```", section, flags=re.DOTALL)[0]
        assert spec.description in section
        assert spec.constraints in section
        assert spec.example in example
        assert f"{spec.name} = {spec.name} =" not in example
        settings = load_settings_text(example, validate=False)
        assert spec.name in settings._explicit_fields


def test_settings_reference_does_not_embed_the_build_machine_home(monkeypatch) -> None:
    before = render_contracts.render_settings_reference()
    monkeypatch.setenv("XDG_DATA_HOME", "/tmp/another-build-machine")
    monkeypatch.setenv("LOCALAPPDATA", "/tmp/another-windows-build-machine")
    assert render_contracts.render_settings_reference() == before
