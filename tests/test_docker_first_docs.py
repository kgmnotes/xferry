"""Semantic guards for journey-first onboarding and contributor examples."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from tools import check_stale_docs

REPO_ROOT = Path(__file__).resolve().parents[1]
QUICK_START = Path("docs/quick-start.md")
OPERATIONS = Path("docs/operations.md")


def _read(relative_path: Path) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_quick_start_routes_portable_managed_and_container_users_first() -> None:
    text = _read(QUICK_START)

    assert text.index("## Portable") < text.index("## Managed Linux")
    assert text.index("## Managed Linux") < text.index("## Container")
    assert "pipx install xferry" in text
    assert "xferry run --open" in text
    assert "py -m pip install --user pipx" in text
    assert "sudo apt install pipx" in text
    assert "brew install pipx" in text
    assert "python3 -m pip install --user pipx" not in text
    assert "managed-hosts.md" in text
    assert "archive/0.2.0-installation.md" in text
    assert "git clone https://github.com/kgmnotes/xferry.git" not in text
    assert "releases/latest" not in text
    assert "ghcr.io/kgmnotes/xferry:latest" not in text
    assert "curl | sudo sh" not in text


def test_quick_start_guard_accepts_package_manager_bootstrap(tmp_path: Path) -> None:
    """Catches the semantic guard requiring a PEP 668-incompatible bootstrap."""
    text = _read(QUICK_START).replace(
        "python3 -m pip install --user pipx",
        "sudo apt install pipx\nbrew install pipx",
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / QUICK_START).write_text(text, encoding="utf-8")

    assert check_stale_docs.find_semantic_contract_issues(tmp_path, (str(QUICK_START),)) == []


def test_quick_start_guard_rejects_generic_pip_bootstrap(tmp_path: Path) -> None:
    """Catches onboarding drifting back to a system-Python pipx install."""
    (tmp_path / "docs").mkdir()
    (tmp_path / QUICK_START).write_text(
        _read(QUICK_START) + "\npython3 -m pip install --user pipx\n", encoding="utf-8"
    )

    assert check_stale_docs.find_semantic_contract_issues(tmp_path, (str(QUICK_START),))


def test_foreground_data_default_is_stable_and_current_directory_is_explicit() -> None:
    settings = _read(Path("docs/settings.md"))
    quick_start = _read(QUICK_START)
    assert "independent of the launch directory" in " ".join(settings.split())
    assert "xferry run --files-dir ." in quick_start
    assert "%LOCALAPPDATA%" in settings
    assert "~/Library/Application Support/xferry/files" in settings
    assert "~/.local/share/xferry/files" in settings
    assert "private state" in settings.lower()


@pytest.mark.parametrize("path", [Path("SECURITY.md"), Path("docs/security.md")])
def test_privileged_release_downloads_follow_only_https_redirects(path: Path) -> None:
    text = _read(path).split("### Privileged installer verification order", 1)[1]
    block = text.split("```console\n", 1)[1].split("```", 1)[0]
    commands = [
        shlex.split(line)
        for line in block.replace("\\\n", " ").splitlines()
        if line.startswith("curl ")
    ]

    assert len(commands) == 4
    for command in commands:
        assert "--location" in command
        assert command[command.index("--proto") + 1] == "=https"
        assert command[command.index("--proto-redir") + 1] == "=https"
        assert "--fail" in command


def test_release_runbook_separates_staging_and_production_publishers() -> None:
    text = _read(Path("docs/release-runbook.md"))

    assert "TestPyPI rehearsal mapping uses workflow `testpypi.yml`" in text
    assert "Environment `testpypi`" in text
    assert "production PyPI mapping uses workflow `release-production.yml`" in text
    assert "Environment `release-production`" in text
    assert "separate registries" in " ".join(text.split())


def test_landing_pages_route_instead_of_duplicating_procedures() -> None:
    readme = _read(Path("README.md"))
    index = _read(Path("docs/index.md"))

    assert "docker compose" not in readme
    assert "docker compose" not in index
    for marker in (
        "docs/quick-start.md",
        "docs/managed-hosts.md",
        "docs/operations.md",
        "docs/public-direct.md",
    ):
        assert marker in readme
    for marker in (
        "quick-start.md",
        "managed-hosts.md",
        "operations.md",
        "public-direct.md",
    ):
        assert marker in index


def test_local_compose_example_labels_source_build_and_destructive_cleanup() -> None:
    examples_readme = _read(Path("examples/README.md")).lower()
    compose = _read(Path("examples/docker/docker-compose.yml"))
    compose_header = compose.split("services:", maxsplit=1)[0].lower()

    assert "builds `xferry:local` from the checkout" in examples_readme
    assert "named volumes" in examples_readme
    assert "--volumes" in examples_readme and "deletes" in examples_readme
    assert "current" in compose_header and "checkout" in compose_header
    assert "down" in compose_header and "preserves" in compose_header
    assert "--volumes" in compose_header and "destructive" in compose_header
