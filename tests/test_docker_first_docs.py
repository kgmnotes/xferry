"""Semantic guards for journey-first onboarding and contributor examples."""

from __future__ import annotations

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
    assert "xferry run --preset local --open" in text
    assert "py -m pip install --user pipx" in text
    assert "sudo apt install pipx" in text
    assert "brew install pipx" in text
    assert "python3 -m pip install --user pipx" not in text
    assert "managed-hosts.md" in text
    assert "ghcr.io/kgmnotes/xferry:v0.2.0" in text
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


@pytest.mark.parametrize("path", [QUICK_START, Path("docs/public-direct.md"), OPERATIONS])
def test_container_journey_declares_released_platforms(path: Path) -> None:
    """Catches container onboarding omitting the released host architectures."""
    text = _read(path)

    assert "linux/amd64" in text
    assert "linux/arm64" in text


def test_portable_process_documents_persistent_data_root() -> None:
    text = _read(OPERATIONS)
    normalized = " ".join(text.split())

    for marker in (
        '--dir "$PWD/xferry-data"',
        "`uploads/`",
        "`notes/`",
        "Press `Ctrl+C`",
    ):
        assert marker in text
    assert "preserves uploads and encrypted note state" in normalized


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
