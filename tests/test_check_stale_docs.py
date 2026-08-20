"""Contracts for the compact active-documentation checker."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import check_stale_docs


def write_minimal_docs(root: Path) -> None:
    """Create the default scan roots used by focused mutation tests."""
    (root / "docs").mkdir()
    (root / "examples").mkdir()
    (root / "README.md").write_text("# README\n", encoding="utf-8")
    (root / "API.md").write_text("# API\n", encoding="utf-8")
    (root / "examples" / "basic.sh").write_text("#!/bin/sh\n", encoding="utf-8")


def test_repository_documentation_contract_is_clean() -> None:
    targets = check_stale_docs.DEFAULT_TARGETS
    findings = check_stale_docs.find_stale_references(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_semantic_contract_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_ordered_contract_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_source_first_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_adr_navigation_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_contributor_command_issues(
        check_stale_docs.REPO_ROOT, targets
    )
    findings += check_stale_docs.find_version_consistency_issues(
        check_stale_docs.REPO_ROOT, targets
    )

    assert findings == []


@pytest.mark.parametrize(
    ("text", "message"),
    (
        ("Run xferry --root /srv.\n", "legacy CLI flag"),
        ("Set X-HMAC when creating notes.\n", "removed Secure Notepad HMAC"),
        ("Run xferry --profile experimental.\n", "feature-profile flag"),
        ("NOTE is experimental-only.\n", "experimental-only availability"),
        ("SMUGGLE is profile-gated.\n", "profile-gated availability"),
        ("pip install xferry[crypto,dev]\n", "crypto-extra guidance"),
        ("SMUGGLE supports DLP/proxy bypass.\n", "avoid bypass wording"),
        ("python -m src --help\n", "python -m xferry"),
        ("from src import XFerryServer\n", "from xferry"),
    ),
)
def test_stale_contract_families_are_reported(
    tmp_path: Path,
    text: str,
    message: str,
) -> None:
    write_minimal_docs(tmp_path)
    (tmp_path / "README.md").write_text(text, encoding="utf-8")

    findings = check_stale_docs.find_stale_references(tmp_path)

    assert any(message in finding.message for finding in findings)


def test_current_managed_and_compose_profile_flags_are_allowed(tmp_path: Path) -> None:
    write_minimal_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        "sudo xferry setup --max-upload-mib 64\n",
        encoding="utf-8",
    )
    (tmp_path / "examples" / "compose.md").write_text(
        "docker compose --profile auth-tls up xferry-auth-tls\n",
        encoding="utf-8",
    )

    assert check_stale_docs.find_stale_references(tmp_path) == []


def test_browser_smoke_may_assert_removed_smuggle_aliases_are_absent(tmp_path: Path) -> None:
    smoke = tmp_path / "tools" / "browser_smoke.playwright.js"
    smoke.parent.mkdir()
    smoke.write_text(
        'const aliases = ["encrypt", "use_constructor", "b64"];\n',
        encoding="utf-8",
    )

    assert check_stale_docs.find_stale_references(tmp_path, ("tools",)) == []


@pytest.mark.parametrize(
    "marker",
    (
        "PUT /_xferry/advanced-routing",
        "X-D: payload",
        "X-N: file.bin",
        '{"d":"payload"}',
    ),
)
def test_retired_advanced_markers_are_scoped_to_active_docs(
    tmp_path: Path,
    marker: str,
) -> None:
    active = tmp_path / "examples" / "active.md"
    active.parent.mkdir(parents=True)
    active.write_text(f"{marker}\n", encoding="utf-8")
    historical = tmp_path / "docs" / "ADR" / "ADR-099-history.md"
    historical.parent.mkdir(parents=True)
    historical.write_text(
        f"# History\n\n- **Status:** superseded by ADR-100\n\n{marker}\n",
        encoding="utf-8",
    )

    active_findings = check_stale_docs.find_stale_references(tmp_path, ("examples",))
    historical_findings = check_stale_docs.find_stale_references(tmp_path, ("docs/ADR",))

    assert any("retired Advanced" in finding.message for finding in active_findings)
    assert historical_findings == []


@pytest.mark.parametrize(
    "command",
    (
        "xferry --preset local --open\n",
        "exec xferry \\\n  --host 127.0.0.1\n",
        "python -m xferry --config /etc/xferry/xferry.ini --check-config\n",
    ),
)
def test_server_launch_requires_run_subcommand(tmp_path: Path, command: str) -> None:
    example = tmp_path / "examples" / "launch.md"
    example.parent.mkdir(parents=True)
    example.write_text(command, encoding="utf-8")

    findings = check_stale_docs.find_stale_references(tmp_path, ("examples",))

    assert any("run` subcommand" in finding.message for finding in findings)


def test_server_guard_allows_management_and_root_help(tmp_path: Path) -> None:
    example = tmp_path / "examples" / "launch.md"
    example.parent.mkdir(parents=True)
    example.write_text(
        "xferry run --preset local --open\n"
        "sudo xferry setup --private\n"
        "xferry status --json\n"
        "xferry --help\n",
        encoding="utf-8",
    )

    assert check_stale_docs.find_stale_references(tmp_path, ("examples",)) == []


def test_server_guard_tracks_multiline_argument_arrays(tmp_path: Path) -> None:
    example = tmp_path / "examples" / "launch.md"
    example.parent.mkdir(parents=True)
    example.write_text(
        'XFERRY_ARGS=(\n  --preset local\n  --host 127.0.0.1\n)\nxferry "${XFERRY_ARGS[@]}"\n',
        encoding="utf-8",
    )

    findings = check_stale_docs.find_stale_references(tmp_path, ("examples",))

    assert len([finding for finding in findings if "run` subcommand" in finding.message]) == 1


def test_smuggle_api_contract_reports_missing_codes_and_details(tmp_path: Path) -> None:
    api = tmp_path / "API.md"
    api.write_text(
        """Current SMUGGLE code tokens are `invalid_smuggle_locale`. Clients should
render `error.message` for operators.

**Too large response (413):**
```json
{"error":{"code":"smuggle_source_too_large","details":{"limit_bytes":1}}}
```
""",
        encoding="utf-8",
    )

    findings = check_stale_docs.find_semantic_contract_issues(tmp_path, ("API.md",))

    messages = {finding.message for finding in findings}
    assert any("complete SMUGGLE error-code list" in message for message in messages)
    assert any("SMUGGLE 413 details" in message for message in messages)


@pytest.mark.parametrize(
    ("path", "message"),
    (
        ("README.md", "README must keep source installation"),
        ("SECURITY.md", "SECURITY must preserve authorized-use"),
        ("CONTRIBUTING.md", "CONTRIBUTING must preserve local checks"),
        ("docs/operations.md", "operations must own source lifecycle"),
        ("docs/public-direct.md", "public-direct must defer"),
        ("docs/threat-model.md", "duplicate Content-Length"),
    ),
)
def test_public_document_owner_rejects_missing_contract(
    tmp_path: Path,
    path: str,
    message: str,
) -> None:
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# Incomplete\n", encoding="utf-8")

    findings = check_stale_docs.find_semantic_contract_issues(tmp_path, (path,))

    assert any(message in finding.message for finding in findings)


def test_quick_start_order_and_source_route_are_enforced(tmp_path: Path) -> None:
    quick_start = tmp_path / "docs" / "quick-start.md"
    quick_start.parent.mkdir(parents=True)
    quick_start.write_text(
        "## Install\n"
        "## Try a custom method\n"
        "## Send a first file\n"
        "## Stop and protect data\n"
        "ghcr.io/kgmnotes/xferry@sha256:digest\n",
        encoding="utf-8",
    )

    order_findings = check_stale_docs.find_ordered_contract_issues(
        tmp_path,
        ("docs/quick-start.md",),
    )
    source_findings = check_stale_docs.find_source_first_issues(
        tmp_path,
        ("docs/quick-start.md",),
    )

    assert order_findings
    assert source_findings


def test_adr_navigation_requires_every_current_decision(tmp_path: Path) -> None:
    index = tmp_path / "docs" / "ADR" / "README.md"
    index.parent.mkdir(parents=True)
    index.write_text("ADR-001\nADR-002\n", encoding="utf-8")

    findings = check_stale_docs.find_adr_navigation_issues(
        tmp_path,
        ("docs/ADR/README.md",),
    )

    assert any("ADR-010" in finding.message for finding in findings)


def test_version_consistency_reports_ui_and_api_drift(tmp_path: Path) -> None:
    config = tmp_path / "xferry" / "config.py"
    config.parent.mkdir()
    config.write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    html = tmp_path / "xferry" / "data" / "index.html"
    html.parent.mkdir()
    html.write_text('<p id="appVersion" data-app-version="0.2.0">v0.2.0</p>\n', encoding="utf-8")
    (tmp_path / "API.md").write_text('{"server": "XFerry/0.2.0"}\n', encoding="utf-8")

    findings = check_stale_docs.find_version_consistency_issues(
        tmp_path,
        ("xferry", "API.md"),
    )

    assert any("UI version" in finding.message for finding in findings)
    assert any("API server example" in finding.message for finding in findings)


def test_contributor_commands_must_match_ci(tmp_path: Path) -> None:
    contributing = tmp_path / "CONTRIBUTING.md"
    contributing.write_text("ruff check src tests\n", encoding="utf-8")

    findings = check_stale_docs.find_contributor_command_issues(
        tmp_path,
        ("CONTRIBUTING.md",),
    )

    assert set(check_stale_docs.CANONICAL_QUALITY_COMMANDS) == {
        finding.message.split("`", 2)[1] for finding in findings
    }


def test_main_returns_actionable_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_minimal_docs(tmp_path)
    (tmp_path / "examples" / "legacy.md").write_text(
        "Run xferry --root /srv.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_stale_docs, "REPO_ROOT", tmp_path)

    assert check_stale_docs.main([]) == 1

    captured = capsys.readouterr()
    assert "Found stale documented contract references" in captured.err
    assert "examples/legacy.md:1" in captured.err
