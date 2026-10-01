"""Executable negative checks for the strict MkDocs validation contract."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mkdocs")


def _write_site(tmp_path: Path, index: str, *, extra_files: dict[str, str] | None = None) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    docs.joinpath("index.md").write_text(index, encoding="utf-8")
    for relative, content in (extra_files or {}).items():
        destination = docs / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    tmp_path.joinpath("mkdocs.yml").write_text(
        "site_name: validation fixture\n"
        "docs_dir: docs\n"
        "site_dir: site\n"
        "nav:\n"
        "  - Home: index.md\n"
        "validation:\n"
        "  nav:\n"
        "    omitted_files: warn\n"
        "    absolute_links: warn\n"
        "  links:\n"
        "    not_found: warn\n"
        "    absolute_links: relative_to_docs\n"
        "    unrecognized_links: warn\n"
        "    anchors: warn\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("index", "extra_files"),
    (
        ("# Home\n", {"omitted.md": "# Omitted\n"}),
        ("# Home\n\n[Absolute](/missing.md)\n", None),
        ("# Home\n\n[Unknown](missing.md)\n", None),
        ("# Home\n\n[Bad anchor](target.md#missing)\n", {"target.md": "# Target\n"}),
    ),
    ids=("omitted-nav-file", "absolute-link", "missing-link", "bad-anchor"),
)
def test_strict_mkdocs_rejects_navigation_and_link_contract_violations(
    tmp_path: Path,
    index: str,
    extra_files: dict[str, str] | None,
) -> None:
    _write_site(tmp_path, index, extra_files=extra_files)

    result = subprocess.run(
        [sys.executable, "-m", "mkdocs", "build", "--strict", "--config-file", "mkdocs.yml"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0, result.stdout + result.stderr
