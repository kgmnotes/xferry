#!/usr/bin/env python3
"""Render runtime-backed public contract tables in canonical documentation."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from xferry.features import CoreMethodSpec, core_method_specs  # noqa: E402
from xferry.management import cli as management_cli  # noqa: E402
from xferry.management.model import supported_managed_host_matrix  # noqa: E402
from xferry.smuggle.policy import build_smuggle_capabilities  # noqa: E402

_ANY_MARKER_RE = re.compile(rb"(?m)^<!-- (?:BEGIN|END) GENERATED:[^\r\n]* -->\r?$")


class MarkerError(ValueError):
    """Raised when generated contract regions are not exact and unambiguous."""


@dataclass(frozen=True, slots=True)
class ContractRegion:
    """One named generated region and its runtime-backed renderer."""

    name: str
    renderer: Callable[[], bytes]


@dataclass(frozen=True, slots=True)
class ContractTarget:
    """One canonical document containing ordered generated regions."""

    path: str
    regions: tuple[ContractRegion, ...]


def start_marker(name: str) -> bytes:
    """Return the exact opening marker for *name*."""
    return f"<!-- BEGIN GENERATED: {name} -->".encode("ascii")


def end_marker(name: str) -> bytes:
    """Return the exact closing marker for *name*."""
    return f"<!-- END GENERATED: {name} -->".encode("ascii")


def _markdown_text(value: object) -> str:
    """Render a value as safe, deterministic inline Markdown text."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")


def _code_cell(value: object) -> str:
    """Render a scalar in a Markdown code span."""
    if isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    return f"`{_markdown_text(text)}`"


def render_core_methods() -> bytes:
    """Render every public ``CoreMethodSpec`` field except the handler binding."""
    public_fields = tuple(
        field.name
        for field in fields(CoreMethodSpec)
        if not field.name.startswith("_") and field.name != "handler_name"
    )
    lines = [
        "| " + " | ".join(f"`{name}`" for name in public_fields) + " |",
        "| " + " | ".join("---" for _ in public_fields) + " |",
    ]
    for spec in core_method_specs():
        values: list[str] = []
        for name in public_fields:
            value = getattr(spec, name)
            values.append(_markdown_text(value) if name == "exposure_note" else _code_cell(value))
        lines.append("| " + " | ".join(values) + " |")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _json_cell(value: object) -> str:
    """Render JSON without sorting so runtime list and mapping order stays visible."""
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(", ", ": "),
        sort_keys=False,
    )
    return f"`{_markdown_text(encoded)}`"


def render_smuggle_capabilities() -> bytes:
    """Render every root capability and its complete canonical runtime value."""
    capabilities: Mapping[str, object] = build_smuggle_capabilities()
    lines = [
        "| Root field | Canonical runtime value (JSON) |",
        "| --- | --- |",
    ]
    lines.extend(
        f"| `{_markdown_text(name)}` | {_json_cell(value)} |"
        for name, value in capabilities.items()
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_managed_support_matrix() -> bytes:
    """Render every supported distro/version/architecture pair from runtime data."""
    contract = supported_managed_host_matrix()
    distributions = contract.get("distributions")
    architectures = contract.get("architectures")
    init_system = contract.get("init_system")
    if (
        not isinstance(distributions, dict)
        or not all(
            isinstance(distribution, str)
            and isinstance(versions, list)
            and all(isinstance(version, str) for version in versions)
            for distribution, versions in distributions.items()
        )
        or not isinstance(architectures, list)
        or not all(isinstance(architecture, str) for architecture in architectures)
        or not isinstance(init_system, str)
    ):
        raise ValueError("invalid managed host support contract")
    lines = [
        "| Distribution | Architecture | Init system |",
        "| --- | --- | --- |",
    ]
    lines.extend(
        f"| {_code_cell(f'{distribution} {version}')} | {_code_cell(architecture)} | "
        f"{_code_cell(init_system)} |"
        for distribution, versions in distributions.items()
        for version in versions
        for architecture in architectures
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


CLI_REFERENCE_COMMANDS: tuple[str, ...] = (
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
    "update",
    "rollback",
    "uninstall",
)


def _capture_english_help(arguments: list[str]) -> str:
    """Capture the real dispatcher help under an explicit English selection."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = 0
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            exit_code = management_cli.main(["--lang", "en", *arguments, "--help"])
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 1
    if exit_code != 0 or stderr.getvalue():
        raise ValueError(f"CLI help failed for {' '.join(arguments) or 'root'}")
    rendered = stdout.getvalue().rstrip()
    if not rendered:
        raise ValueError(f"CLI help was empty for {' '.join(arguments) or 'root'}")
    return rendered


def render_cli_reference() -> bytes:
    """Render root and every public command's actual English help output."""
    sections: list[str] = []
    for command in (None, *CLI_REFERENCE_COMMANDS):
        arguments = [] if command is None else [command]
        invocation = "xferry --help" if command is None else f"xferry {command} --help"
        sections.extend(
            (
                f"## `{invocation}`",
                "",
                "```text",
                _capture_english_help(arguments),
                "```",
                "",
            )
        )
    return "\n".join(sections).encode("utf-8")


REGIONS: tuple[ContractRegion, ...] = (
    ContractRegion("xferry-contracts/core-methods", render_core_methods),
    ContractRegion(
        "xferry-contracts/smuggle-capabilities",
        render_smuggle_capabilities,
    ),
)
CLI_REGION = ContractRegion("xferry-contracts/cli-reference", render_cli_reference)
MANAGED_HOSTS_REGION = ContractRegion(
    "xferry-contracts/managed-hosts",
    render_managed_support_matrix,
)
TARGETS: tuple[ContractTarget, ...] = (
    ContractTarget("API.md", REGIONS),
    ContractTarget("docs/cli-reference.md", (CLI_REGION,)),
    ContractTarget("docs/managed-hosts.md", (MANAGED_HOSTS_REGION,)),
)


def replace_generated_regions(
    document: bytes,
    generated: Mapping[str, bytes],
    *,
    regions: tuple[ContractRegion, ...] = REGIONS,
) -> bytes:
    """Replace exact ordered regions while preserving every byte outside them."""
    expected_markers = tuple(
        marker
        for region in regions
        for marker in (start_marker(region.name), end_marker(region.name))
    )
    actual_markers = tuple(
        match.group(0).rstrip(b"\r") for match in _ANY_MARKER_RE.finditer(document)
    )
    if actual_markers != expected_markers:
        raise MarkerError("expected one ordered marker pair for every registered region")
    if set(generated) != {region.name for region in regions}:
        raise MarkerError("generated content does not match the registered regions")

    rendered = bytearray()
    cursor = 0
    for region in regions:
        opening = start_marker(region.name)
        closing = end_marker(region.name)
        if document.count(opening) != 1 or document.count(closing) != 1:
            raise MarkerError(f"expected exactly one marker pair for {region.name}")

        start = document.index(opening)
        end = document.index(closing)
        if start < cursor or start >= end:
            raise MarkerError(f"markers are nested or reordered for {region.name}")

        start_line_end = document.find(b"\n", start)
        if start_line_end < 0 or start_line_end > end:
            raise MarkerError(f"opening marker must occupy a complete line for {region.name}")
        if document[start:start_line_end].rstrip(b"\r") != opening:
            raise MarkerError(f"opening marker must be exact for {region.name}")

        end_line_start = document.rfind(b"\n", 0, end) + 1
        end_line_end = document.find(b"\n", end)
        if end_line_end < 0:
            end_line_end = len(document)
        if document[end_line_start:end_line_end].rstrip(b"\r") != closing:
            raise MarkerError(f"closing marker must be exact for {region.name}")

        body = generated[region.name].rstrip(b"\r\n") + b"\n"
        rendered.extend(document[cursor : start_line_end + 1])
        rendered.extend(body)
        cursor = end_line_start

    rendered.extend(document[cursor:])
    return bytes(rendered)


def render_target(target: ContractTarget, document: bytes) -> bytes:
    """Return expected bytes for one registered canonical document."""
    generated = {region.name: region.renderer() for region in target.regions}
    return replace_generated_regions(document, generated, regions=target.regions)


def render_all(*, check: bool, repo_root: Path = REPO_ROOT) -> int:
    """Check or rewrite all targets after validating every target first."""
    rendered_targets: list[tuple[ContractTarget, Path, bytes, bytes]] = []
    for target in TARGETS:
        path = repo_root / target.path
        try:
            current = path.read_bytes()
            expected = render_target(target, current)
        except (OSError, MarkerError, TypeError, UnicodeError, ValueError) as exc:
            print(f"{target.path}: {exc}", file=sys.stderr)
            return 2
        rendered_targets.append((target, path, current, expected))

    drifted: list[str] = []
    updated: list[str] = []
    for target, path, current, expected in rendered_targets:
        if current == expected:
            continue
        if check:
            drifted.append(target.path)
        else:
            path.write_bytes(expected)
            updated.append(target.path)

    if check and drifted:
        print("Generated public contract regions are out of date:", file=sys.stderr)
        for path in drifted:
            print(f"  - {path}", file=sys.stderr)
        print("Run 'python3 tools/render_contracts.py --write'.", file=sys.stderr)
        return 1
    if check:
        print("Generated public contract regions are current.")
    elif updated:
        print("Updated generated public contract regions:")
        for path in updated:
            print(f"  - {path}")
    else:
        print("Generated public contract regions already current.")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse exactly one required rendering mode."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail when a table has drifted")
    mode.add_argument("--write", action="store_true", help="rewrite generated tables")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    args = parse_args(argv)
    return render_all(check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
