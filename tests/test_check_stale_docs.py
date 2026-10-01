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


SAFE_CONTROLLED_PUBLISH_WORKFLOW = """name: Controlled release

on:
  push:
    tags:
      - "v[0-9]+.[0-9]+.[0-9]+"

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      - run: python -m build
      - uses: actions/upload-artifact@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        with:
          name: release-candidate
          path: dist/

  publish-pypi:
    needs: build
    runs-on: ubuntu-latest
    environment: production
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/download-artifact@cccccccccccccccccccccccccccccccccccccccc
        with:
          name: release-candidate
          path: dist/
      - uses: pypa/gh-action-pypi-publish@dddddddddddddddddddddddddddddddddddddddd
"""


def test_repository_documentation_contract_is_clean() -> None:
    targets = check_stale_docs.DEFAULT_TARGETS
    findings = check_stale_docs.find_stale_references(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_semantic_contract_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_ordered_contract_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_source_first_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_adr_navigation_issues(check_stale_docs.REPO_ROOT, targets)
    findings += check_stale_docs.find_release_policy_issues(check_stale_docs.REPO_ROOT, targets)
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
        (
            "Download Quarterly-Report.pdf.\n",
            "neutral controlled-test artifact",
        ),
        ("python -m src --help\n", "python -m xferry"),
        ("from src import XFerryServer\n", "from xferry"),
        ("No release artifact is currently public.\n", "temporal publication wording"),
        (
            "No GitHub Release,\nPyPI package, or GHCR image has been published.\n",
            "temporal publication wording",
        ),
        (
            "There is no published binary or container image to use as a rollback target at\n"
            "this time.\n",
            "temporal publication wording",
        ),
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


@pytest.mark.parametrize(
    "text",
    (
        "The accepted design reserves `xferry update` for a later stage.\n",
        "Production publication requires an immutable version tag.\n",
        "PyPI uses pypa/gh-action-pypi-publish with trusted publishing.\n",
        "The image name will be ghcr.io/kgmnotes/xferry.\n",
        "GitHub Release assets are promoted without rebuilding.\n",
    ),
)
def test_future_distribution_contract_language_is_not_unconditionally_stale(
    tmp_path: Path,
    text: str,
) -> None:
    """Policy documents may describe guarded channels before user activation."""
    write_minimal_docs(tmp_path)
    policy = tmp_path / "docs" / "ADR" / "ADR-099-future-distribution.md"
    policy.parent.mkdir()
    policy.write_text(text, encoding="utf-8")

    assert check_stale_docs.find_stale_references(tmp_path) == []


@pytest.mark.parametrize(
    "route",
    (
        "https://github.com/kgmnotes/xferry/releases/latest",
        "ghcr.io/kgmnotes/xferry:latest",
        "pip install xferry==1.2.3",
        "pip install --upgrade xferry",
        "curl https://example.test/install.sh | sudo sh",
        "xferry update",
        "xferry update --to latest",
        "xferry update --version 1.2.3",
    ),
)
@pytest.mark.parametrize(
    "path",
    (
        Path("README.md"),
        Path("docs/quick-start.md"),
        Path("docs/operations.md"),
        Path("docs/public-direct.md"),
    ),
)
def test_current_user_install_docs_reject_unsafe_distribution_routes(
    tmp_path: Path,
    route: str,
    path: Path,
) -> None:
    document = tmp_path / path
    document.parent.mkdir(parents=True, exist_ok=True)
    document.write_text(f"Install with `{route}`.\n", encoding="utf-8")

    findings = check_stale_docs.find_source_first_issues(tmp_path, (str(path),))

    assert any("unsafe distribution or lifecycle route" in item.message for item in findings)


@pytest.mark.parametrize(
    "route",
    (
        "pipx install xferry",
        "python3 -m pip install --user pipx",
        "ghcr.io/kgmnotes/xferry:v1.2.3",
        "ghcr.io/kgmnotes/xferry@sha256:" + "a" * 64,
        "xferry update --to 1.2.3",
    ),
)
def test_current_user_docs_allow_immutable_supported_routes(
    tmp_path: Path,
    route: str,
) -> None:
    path = tmp_path / "docs" / "quick-start.md"
    path.parent.mkdir(parents=True)
    path.write_text(f"Use `{route}`.\n", encoding="utf-8")

    findings = check_stale_docs.find_source_first_issues(
        tmp_path,
        ("docs/quick-start.md",),
    )

    assert not any("unsafe distribution or lifecycle route" in item.message for item in findings)


def test_safe_future_controlled_publisher_workflow_is_expressible() -> None:
    findings = check_stale_docs.release_workflow_policy_findings(SAFE_CONTROLLED_PUBLISH_WORKFLOW)

    assert findings == []


def test_safe_future_publisher_accepts_inline_least_privilege_permissions() -> None:
    workflow = SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
        "permissions:\n  contents: read",
        "permissions: {contents: read}",
        1,
    ).replace(
        "    permissions:\n      contents: read\n      id-token: write",
        "    permissions: {contents: read, id-token: write}",
    )

    assert check_stale_docs.release_workflow_policy_findings(workflow) == []


@pytest.mark.parametrize(
    ("workflow", "message"),
    (
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                '    tags:\n      - "v[0-9]+.[0-9]+.[0-9]+"',
                "    branches:\n      - main",
            ),
            "version-tag-only push",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                '  push:\n    tags:\n      - "v[0-9]+.[0-9]+.[0-9]+"',
                "  pull_request:",
            ),
            "pull-request publication",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "      - uses: pypa/gh-action-pypi-publish",
                "      - env:\n          password: ${{ secrets.PYPI_API_TOKEN }}\n"
                "        uses: pypa/gh-action-pypi-publish",
            ),
            "static PyPI credential",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "pypa/gh-action-pypi-publish@dddddddddddddddddddddddddddddddddddddddd",
                "pypa/gh-action-pypi-publish@release/v1",
            ),
            "external actions must use a lowercase 40-hex commit SHA",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "      - uses: pypa/gh-action-pypi-publish@"
                "dddddddddddddddddddddddddddddddddddddddd",
                '      - "uses": pypa/gh-action-pypi-publish@release/v1',
            ),
            "external actions must use a lowercase 40-hex commit SHA",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "permissions:\n  contents: read", "permissions: write-all", 1
            ),
            "workflow-level write permission",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "permissions:\n  contents: read",
                "permissions: {contents: write}",
                1,
            ),
            "workflow-level write permission",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "permissions:\n  contents: read",
                '"permissions": {contents: write}',
                1,
            ),
            "workflow-level write permission",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "      - uses: actions/download-artifact@",
                "      - run: python -m build\n      - uses: actions/download-artifact@",
            ),
            "must not rebuild release artifacts",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace("    environment: production\n", ""),
            "protected `production` environment",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                '      - "v[0-9]+.[0-9]+.[0-9]+"', '      - "*"'
            ),
            "exact `vX.Y.Z` version tag filters",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace("    tags:\n", "    tags-ignore:\n"),
            "exact `vX.Y.Z` version tag filters",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace("  publish-pypi:", "  _publish-pypi:").replace(
                "    environment: production\n", ""
            ),
            "protected `production` environment",
        ),
        (
            SAFE_CONTROLLED_PUBLISH_WORKFLOW.replace(
                "  publish-pypi:", '  "publish-pypi":'
            ).replace("    environment: production\n", ""),
            "protected `production` environment",
        ),
    ),
    ids=(
        "branch",
        "pull-request",
        "static-pypi-token",
        "unpinned-action",
        "quoted-unpinned-action",
        "broad-permissions",
        "inline-broad-permissions",
        "quoted-inline-broad-permissions",
        "publisher-rebuild",
        "unprotected-production",
        "wildcard-tag",
        "tags-ignore",
        "underscore-job-id",
        "quoted-job-id",
    ),
)
def test_controlled_publisher_policy_rejects_unsafe_workflows(
    workflow: str,
    message: str,
) -> None:
    findings = check_stale_docs.release_workflow_policy_findings(workflow)

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


@pytest.mark.parametrize("forbidden", ('"dlp"', '"red-team"'))
def test_package_metadata_rejects_non_neutral_security_keywords(
    tmp_path: Path,
    forbidden: str,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "keywords = [\n"
        '  "security-research",\n'
        '  "authorized-testing",\n'
        '  "controlled-testing",\n'
        '  "http-testing",\n'
        f"  {forbidden},\n"
        "]\n",
        encoding="utf-8",
    )

    findings = check_stale_docs.find_semantic_contract_issues(
        tmp_path,
        ("pyproject.toml",),
    )

    assert any("authorized, controlled security research" in item.message for item in findings)


def test_package_metadata_accepts_neutral_authorized_research_keywords(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "keywords = [\n"
        '  "security-research",\n'
        '  "authorized-testing",\n'
        '  "controlled-testing",\n'
        '  "http-testing",\n'
        "]\n",
        encoding="utf-8",
    )

    assert (
        check_stale_docs.find_semantic_contract_issues(
            tmp_path,
            ("pyproject.toml",),
        )
        == []
    )


def test_unrelated_storage_publication_wording_remains_allowed(tmp_path: Path) -> None:
    """Distribution guards must not flag ordinary atomic file-publication terminology."""
    write_minimal_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        "Upload publication remains atomic inside the local storage transaction.\n",
        encoding="utf-8",
    )

    assert check_stale_docs.find_stale_references(tmp_path) == []


def test_unrelated_markdown_tags_frontmatter_remains_allowed(tmp_path: Path) -> None:
    """Manual workflow guards must not reserve an ordinary documentation key."""
    write_minimal_docs(tmp_path)
    (tmp_path / "README.md").write_text(
        "---\ntags:\n  - security-research\n---\n",
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
        ("README.md", "README must route portable"),
        ("SECURITY.md", "SECURITY must preserve authorized-use"),
        ("CONTRIBUTING.md", "CONTRIBUTING must preserve local checks"),
        ("docs/operations.md", "operations must own portable"),
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


def test_quick_start_order_and_journey_route_are_enforced(tmp_path: Path) -> None:
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


def test_version_consistency_accepts_current_release_before_retained_history(
    tmp_path: Path,
) -> None:
    config = tmp_path / "xferry" / "config.py"
    config.parent.mkdir()
    config.write_text('__version__ = "0.2.0"\n', encoding="utf-8")
    html = tmp_path / "xferry" / "data" / "index.html"
    html.parent.mkdir()
    html.write_text('<p id="appVersion" data-app-version="0.2.0">v0.2.0</p>\n', encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "![Version](https://img.shields.io/badge/version-0.2.0-orange.svg)\n",
        encoding="utf-8",
    )
    (tmp_path / "API.md").write_text('{"server": "XFerry/0.2.0"}\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n## [0.1.0] - 2026-08-20\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        'version = {attr = "xferry.config.__version__"}\n', encoding="utf-8"
    )

    findings = check_stale_docs.find_version_consistency_issues(
        tmp_path,
        ("xferry", "README.md", "API.md", "CHANGELOG.md", "pyproject.toml"),
    )

    assert findings == []


def test_version_consistency_reports_ui_readme_and_api_drift(tmp_path: Path) -> None:
    config = tmp_path / "xferry" / "config.py"
    config.parent.mkdir()
    config.write_text('__version__ = "0.2.0"\n', encoding="utf-8")
    html = tmp_path / "xferry" / "data" / "index.html"
    html.parent.mkdir()
    html.write_text('<p id="appVersion" data-app-version="0.1.0">v0.1.0</p>\n', encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)\n",
        encoding="utf-8",
    )
    (tmp_path / "API.md").write_text('{"server": "XFerry/0.1.0"}\n', encoding="utf-8")

    findings = check_stale_docs.find_version_consistency_issues(
        tmp_path,
        ("xferry", "README.md", "API.md"),
    )

    assert any("UI version" in finding.message for finding in findings)
    assert any("README badge" in finding.message for finding in findings)
    assert any("API server example" in finding.message for finding in findings)


@pytest.mark.parametrize(
    ("changelog", "message"),
    (
        (
            "## [Unreleased]\n\n## [0.1.0] - 2026-08-20\n",
            "exactly one released section for current package version 0.2.0",
        ),
        (
            "## [Unreleased]\n\n## [0.2.0] - 2026-10-01\n\n## [0.2.0] - 2026-10-02\n",
            "released version 0.2.0 must not be duplicated",
        ),
        (
            "## [Unreleased]\n\n## [0.2.0] - 2026-02-30\n",
            "release date is not a valid ISO date: 2026-02-30",
        ),
        (
            "## [Unreleased]\n\n## [0.2.0] - 2026-1-01\n",
            "release date must use canonical ISO YYYY-MM-DD: 2026-1-01",
        ),
        (
            "## [Unreleased]\n\n## [0.1.0] - 2026-08-20\n\n## [0.2.0] - 2026-10-01\n",
            "current package version 0.2.0 must be the first released section",
        ),
        (
            "## [Unreleased]\n\n"
            "## [0.2.0] - 2026-10-01\n\n"
            "## [0.1.0] - 2026-08-20\n\n"
            "## [0.1.0] - 2026-08-21\n",
            "released version 0.1.0 must not be duplicated",
        ),
    ),
)
def test_version_consistency_rejects_invalid_release_history(
    tmp_path: Path,
    changelog: str,
    message: str,
) -> None:
    config = tmp_path / "xferry" / "config.py"
    config.parent.mkdir()
    config.write_text('__version__ = "0.2.0"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")

    findings = check_stale_docs.find_version_consistency_issues(
        tmp_path,
        ("xferry/config.py", "CHANGELOG.md"),
    )

    assert any(message in finding.message for finding in findings)


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
