"""Semantic guards for source-first onboarding and local container examples."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
QUICK_START = Path("docs/quick-start.md")
OPERATIONS = Path("docs/operations.md")


def _read(relative_path: Path) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_quick_start_is_source_first_until_publication_exists() -> None:
    text = _read(QUICK_START)

    for marker in (
        "No GitHub Release, PyPI package,",
        "git clone https://github.com/kgmnotes/xferry.git",
        "python3 -m venv .venv",
        "python -m pip install .",
        "xferry run --preset local --open",
    ):
        assert marker in text
    assert text.index("git clone") < text.index("xferry run --preset local --open")
    assert "releases/latest" not in text
    assert "ghcr.io/kgmnotes/xferry" not in text


def test_source_process_documents_persistent_data_root() -> None:
    text = _read(OPERATIONS)

    for marker in (
        '--dir "$PWD/xferry-data"',
        "`uploads/`",
        "`notes/`",
        "Press `Ctrl+C`",
        "preserves\nuploads and encrypted note state",
    ):
        assert marker in text


def test_landing_pages_route_instead_of_duplicating_procedures() -> None:
    readme = _read(Path("README.md"))
    index = _read(Path("docs/index.md"))

    assert "docker compose" not in readme
    assert "docker compose" not in index
    for marker in (
        "docs/quick-start.md",
        "docs/operations.md",
        "docs/public-direct.md",
    ):
        assert marker in readme
    for marker in ("quick-start.md", "operations.md", "public-direct.md"):
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
