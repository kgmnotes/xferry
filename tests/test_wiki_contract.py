"""Contracts for the compact public documentation site."""

from __future__ import annotations

import re
from pathlib import Path

from tools import sync_docs

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_TEXT_PATHS = (
    Path("README.md"),
    Path("API.md"),
    Path("SECURITY.md"),
    Path("CONTRIBUTING.md"),
    Path("pyproject.toml"),
    Path("mkdocs.yml"),
    Path("packaging/install.sh.in"),
    Path("deploy/systemd/xferry.service"),
    Path("deploy/docker/docker-compose.public-direct.yml"),
    Path("xferry/management/data/xferry.service"),
    Path("xferry/management/releases.py"),
    Path(".github/workflows/release.yml"),
)


def _read(path: str | Path) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _word_count(markdown: str) -> int:
    return len(re.findall(r"\b[\w.-]+\b", markdown, flags=re.UNICODE))


def test_active_project_coordinates_use_kgmnotes() -> None:
    stale_paths = [path for path in ACTIVE_TEXT_PATHS if "gkumurzhi/xferry" in _read(path)]

    assert stale_paths == []
    assert "https://github.com/kgmnotes/xferry" in _read("pyproject.toml")
    assert "ghcr.io/kgmnotes/xferry" in _read(".github/workflows/release.yml")


def test_landing_pages_are_compact_routes() -> None:
    readme = _read("README.md")
    index = _read("docs/index.md")

    assert _word_count(readme) <= 700
    assert _word_count(index) <= 450
    assert "https://xferry.kgmnotes.ru/" in readme
    assert "## Start here" in index


def test_mkdocs_navigation_is_english_and_task_oriented() -> None:
    config = _read("mkdocs.yml")

    for label in (
        "Home",
        "Quick start",
        "Scenarios",
        "Operations",
        "Security",
        "Reference",
        "Development",
    ):
        assert f"  - {label}" in config
    assert "language: en" in config
    assert "site_url: https://xferry.kgmnotes.ru/" in config


def test_pages_workflow_builds_and_deploys_strict_docs() -> None:
    workflow = _read(".github/workflows/docs-pages.yml")

    for marker in (
        "pages: write",
        "id-token: write",
        "python tools/sync_docs.py --check",
        "python tools/check_stale_docs.py",
        "mkdocs build --strict",
        "actions/upload-pages-artifact@7b1f4a764d45c48632c6b24a0339c27f5614fb0b",
        "actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
        "environment:",
        "name: github-pages",
    ):
        assert marker in workflow


def test_primary_user_journey_is_english() -> None:
    expected_headings = {
        "docs/quick-start.md": "# Quick start",
        "docs/scenarios.md": "# Scenarios",
        "docs/disposable-ssh-tunnel.md": "# Disposable SSH tunnel",
        "docs/operations.md": "# Operations",
        "docs/public-direct.md": "# Public deployment",
        "SECURITY.md": "# Security Policy",
        "docs/threat-model.md": "# Threat model",
    }

    for path, heading in expected_headings.items():
        assert _read(path).startswith(heading), path


def test_security_mirror_rewrites_docs_links_for_mkdocs() -> None:
    """Catches root-relative links that become docs/docs in the mirror."""
    security_spec = next(spec for spec in sync_docs.MIRRORS if spec.source == "SECURITY.md")

    mirror = sync_docs.render_target(security_spec).decode("utf-8")

    assert "[public deployment guide](public-direct.md)" in mirror
    assert "[threat model](threat-model.md)" in mirror
    assert "(docs/public-direct.md)" not in mirror
    assert "(docs/threat-model.md)" not in mirror
