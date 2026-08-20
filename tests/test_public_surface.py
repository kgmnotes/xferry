"""Behavioral contracts for the tracked public repository surface."""

from __future__ import annotations

from pathlib import Path

import pytest


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _guard():
    try:
        from tools import check_public_surface
    except ImportError:
        pytest.fail("public surface guard is missing")
    return check_public_surface


def test_scan_public_surface_reports_each_tracked_policy_violation(tmp_path: Path) -> None:
    """Catches a guard that silently permits an internal or non-public tracked surface."""
    _write(
        tmp_path,
        "README.md",
        "XFerry "
        + "3.0 \u2014 Пример\nSee .super"
        + "powers/notes and the version"
        + "-reboot guide.\n",
    )
    _write(tmp_path, "AGENTS.md", "assistant instructions\n")
    _write(tmp_path, "docs/guide.md", "pre" + "-reboot procedure\n")
    _write(tmp_path, "untracked.md", "Русский \u2014 XFerry " + "3.0\n")

    findings = _guard().scan_public_surface(
        tmp_path,
        ("README.md", "AGENTS.md", "docs/guide.md"),
    )

    assert findings == [
        "AGENTS.md: forbidden internal path",
        "README.md: U+2014 EM DASH is not allowed",
        "README.md: Cyrillic is not allowed in public documentation",
        "README.md: reference to removed internal path '.super" + "powers'",
        "README.md: retired XFerry " + "2/3 terminology",
        "README.md: retired version" + "-reboot narrative",
        "docs/guide.md: retired pre" + "-reboot narrative",
    ]


def test_scan_public_surface_preserves_nonpublic_localization_and_skips_binary_files(
    tmp_path: Path,
) -> None:
    """Catches a scanner that mistakes product localization or binary data for public docs."""
    _write(tmp_path, "xferry/data/static/ui/core.js", 'const label = "Русский";\n')
    binary = tmp_path / "xferry/data/icon.bin"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_bytes(b"\xff\xfe\x00")

    findings = _guard().scan_public_surface(
        tmp_path,
        ("xferry/data/static/ui/core.js", "xferry/data/icon.bin"),
    )

    assert findings == []


@pytest.mark.parametrize(
    "path",
    (
        "CLAU" + "DE.md",
        "DESIGN.md",
        "docs/branding-name-notes.md",
        "AG" + "ENTS.md",
        "CODEX.md",
        ".super" + "powers/private.md",
        "codex-analysis/private.md",
        "implementation" + "-plan/private.md",
        "docs/super" + "powers/private.md",
        ".claude/private.md",
        ".codex/private.md",
    ),
)
def test_scan_public_surface_rejects_every_forbidden_path_family(tmp_path: Path, path: str) -> None:
    """Catches a future internal-path family escaping the tracked public tree policy."""
    _write(tmp_path, path, "safe text\n")

    findings = _guard().scan_public_surface(tmp_path, (path,))

    assert findings == [f"{path}: forbidden internal path"]


@pytest.mark.parametrize("path", ("tools/check_public_surface.py", "tests/test_public_surface.py"))
def test_scan_public_surface_rejects_em_dash_in_implementation_paths(
    tmp_path: Path, path: str
) -> None:
    """Catches a guard or its test being exempt from the global punctuation rule."""
    _write(tmp_path, path, "text \u2014 punctuation\n")

    assert _guard().scan_public_surface(tmp_path, (path,)) == [
        f"{path}: U+2014 EM DASH is not allowed"
    ]


@pytest.mark.parametrize(
    ("path", "text", "expected"),
    (
        (
            "tools/check_public_surface.py",
            "XFerry " + "3.0\n",
            "retired XFerry " + "2/3 terminology",
        ),
        (
            "tests/test_public_surface.py",
            "pre" + "-reboot\n",
            "retired pre" + "-reboot narrative",
        ),
        (
            "tools/check_public_surface.py",
            "version" + "-reboot\n",
            "retired version" + "-reboot narrative",
        ),
    ),
)
def test_scan_public_surface_applies_retired_wording_rules_to_policy_files(
    tmp_path: Path, path: str, text: str, expected: str
) -> None:
    """Catches policy-file exemptions that hide retired product wording."""
    _write(tmp_path, path, text)

    assert _guard().scan_public_surface(tmp_path, (path,)) == [f"{path}: {expected}"]


@pytest.mark.parametrize(
    "path",
    (
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "API.md",
        "mkdocs.yml",
        "docs/nested/guide.md",
        "examples/nested/guide.md",
    ),
)
def test_scan_public_surface_rejects_cyrillic_in_every_public_document_class(
    tmp_path: Path, path: str
) -> None:
    """Catches a public-document class accidentally escaping the English-only rule."""
    _write(tmp_path, path, "Русский\n")

    assert _guard().scan_public_surface(tmp_path, (path,)) == [
        f"{path}: Cyrillic is not allowed in public documentation"
    ]
