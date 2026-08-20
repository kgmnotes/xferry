"""Guards against reintroducing obsolete environment wording in the active surface."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ACTIVE_SURFACE_PATHS = (
    REPO_ROOT / "xferry",
    REPO_ROOT / "tools",
    REPO_ROOT / "README.md",
    REPO_ROOT / "API.md",
    REPO_ROOT / "CHANGELOG.md",
    REPO_ROOT / "docs" / "api.md",
    REPO_ROOT / "docs" / "security.md",
    REPO_ROOT / "docs" / "changelog.md",
)

OBSOLETE_ENVIRONMENT_PATTERN = re.compile(
    r"\b" + "la" + r"b\b|" + "la" + r"b-only|" + "la" + r"b_|" + "la" + r"b%|%20" + "la" + r"b",
    re.IGNORECASE,
)


def iter_active_text_files() -> list[Path]:
    files: list[Path] = []
    for path in ACTIVE_SURFACE_PATHS:
        if path.is_file():
            files.append(path)
            continue
        files.extend(
            child
            for child in path.rglob("*")
            if child.is_file()
            and child.suffix.lower()
            in {
                ".css",
                ".html",
                ".js",
                ".json",
                ".md",
                ".py",
                ".svg",
                ".txt",
                ".yml",
                ".yaml",
            }
        )
    return sorted(files)


def test_active_surface_does_not_use_obsolete_environment_wording() -> None:
    offenders: list[str] = []
    for path in iter_active_text_files():
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if OBSOLETE_ENVIRONMENT_PATTERN.search(line):
                rel_path = path.relative_to(REPO_ROOT)
                offenders.append(f"{rel_path}:{line_number}: {line.strip()}")

    assert offenders == []
