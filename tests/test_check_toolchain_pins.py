"""Behavior tests for the pre-commit and CI toolchain pin contract."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tools import check_toolchain_pins

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_constraints(path: Path) -> None:
    path.write_text(
        """acme==5.5.0
cryptography==50.0.0
josepy==2.2.0
mypy==1.20.1
PyOpenSSL==26.4.0
ruff==0.15.5
""",
        encoding="utf-8",
    )


def _matching_pre_commit(*, cryptography_requirement: str = "cryptography==50.0.0") -> str:
    return f"""repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.5
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.20.1
    hooks:
      - id: mypy
        additional_dependencies:
          - acme==5.5.0
          - {cryptography_requirement}
          - josepy==2.2.0
          - PyOpenSSL==26.4.0
"""


def test_main_rejects_pre_commit_dependency_pin_that_differs_from_constraints(
    tmp_path: Path, capsys
) -> None:
    """Catches a hook environment silently using a different crypto release."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    constraints.write_text("cryptography==50.0.0\nmypy==1.20.1\n", encoding="utf-8")
    pre_commit.write_text(
        """repos:
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.20.1
    hooks:
      - id: mypy
        additional_dependencies:
          - cryptography==49.0.0
""",
        encoding="utf-8",
    )

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    captured = capsys.readouterr()
    assert "cryptography" in captured.err
    assert "49.0.0" in captured.err
    assert "50.0.0" in captured.err


def test_main_accepts_matching_hook_and_constraint_pins(tmp_path: Path, capsys) -> None:
    """Protects the clean toolchain path after a deliberate pin refresh."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    _write_constraints(constraints)
    pre_commit.write_text(_matching_pre_commit(), encoding="utf-8")

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 0
    )

    assert "match constraints" in capsys.readouterr().out


def test_main_rejects_mypy_hook_without_required_cryptography_pin(tmp_path: Path, capsys) -> None:
    """Catches an accidental removal of the mandatory crypto hook dependency."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    _write_constraints(constraints)
    pre_commit.write_text(
        _matching_pre_commit().replace("          - cryptography==50.0.0\n", ""),
        encoding="utf-8",
    )

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    assert "cryptography" in capsys.readouterr().err


def test_main_rejects_non_exact_mypy_dependency_specification(tmp_path: Path, capsys) -> None:
    """Catches a range that would allow a hook environment to resolve differently."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    _write_constraints(constraints)
    pre_commit.write_text(
        _matching_pre_commit(cryptography_requirement="cryptography>=50.0.0"),
        encoding="utf-8",
    )

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    captured = capsys.readouterr()
    assert "cryptography" in captured.err
    assert ">=50.0.0" in captured.err


def test_main_rejects_non_exact_dependency_from_any_hook_environment(
    tmp_path: Path, capsys
) -> None:
    """Catches unpinned dependencies outside the mandatory mypy crypto pin."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    _write_constraints(constraints)
    pre_commit.write_text(
        _matching_pre_commit().replace("          - acme==5.5.0", "          - acme>=5.5.0"),
        encoding="utf-8",
    )

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    captured = capsys.readouterr()
    assert "acme" in captured.err
    assert ">=5.5.0" in captured.err


def test_main_rejects_crypto_pin_on_mypy_repo_sibling_hook(tmp_path: Path, capsys) -> None:
    """Catches crypto isolated from the actual mypy hook environment."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    _write_constraints(constraints)
    pre_commit.write_text(
        _matching_pre_commit()
        .replace("          - cryptography==50.0.0\n", "")
        .replace(
            "      - id: mypy\n",
            """      - id: sibling-check
        additional_dependencies:
          - cryptography==50.0.0
      - id: mypy
""",
        ),
        encoding="utf-8",
    )

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    captured = capsys.readouterr()
    assert "cryptography" in captured.err
    assert "mypy" in captured.err


@pytest.mark.parametrize(
    ("pre_commit_source", "expected"),
    [
        (
            _matching_pre_commit().replace(
                """      - id: ruff
        args: [--fix]
""",
                "",
            ),
            "id ruff",
        ),
        (
            _matching_pre_commit().replace("      - id: ruff-format\n", ""),
            "id ruff-format",
        ),
        (
            _matching_pre_commit().replace("      - id: mypy\n", "      - id: sibling-check\n"),
            "id mypy",
        ),
    ],
)
def test_main_rejects_required_hook_id_missing_from_known_repository(
    tmp_path: Path, capsys, pre_commit_source: str, expected: str
) -> None:
    """Catches a matching repository revision whose required hook is not configured."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    _write_constraints(constraints)
    pre_commit.write_text(pre_commit_source, encoding="utf-8")

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    assert expected in capsys.readouterr().err


@pytest.mark.parametrize(
    ("pre_commit_source", "expected"),
    [
        (
            _matching_pre_commit().replace(
                """  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.5
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
""",
                "",
            ),
            "ruff",
        ),
        (_matching_pre_commit().replace("    rev: v1.20.1\n", "", 1), "mypy"),
    ],
)
def test_main_rejects_missing_required_hook_repository_or_revision(
    tmp_path: Path, capsys, pre_commit_source: str, expected: str
) -> None:
    """Catches required lint/type hooks being removed or left unpinned."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    _write_constraints(constraints)
    pre_commit.write_text(pre_commit_source, encoding="utf-8")

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    assert expected in capsys.readouterr().err


def test_main_rejects_hook_revision_that_differs_from_constraints(tmp_path: Path, capsys) -> None:
    """Catches formatter behavior drifting even when no dependency is injected."""
    constraints = tmp_path / "ci.txt"
    pre_commit = tmp_path / ".pre-commit-config.yaml"
    constraints.write_text("ruff==0.15.5\n", encoding="utf-8")
    pre_commit.write_text(
        """repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.4
    hooks:
      - id: ruff-format
""",
        encoding="utf-8",
    )

    assert (
        check_toolchain_pins.main(
            ["--constraints", str(constraints), "--pre-commit-config", str(pre_commit)]
        )
        == 1
    )

    captured = capsys.readouterr()
    assert "ruff" in captured.err
    assert "0.15.4" in captured.err
    assert "0.15.5" in captured.err


@pytest.mark.parametrize(
    ("reference", "expected_action", "expected_ref"),
    [
        ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", None, None),
        ("actions/checkout@v7", "actions/checkout", "v7"),
        ("pypa/gh-action-pypi-publish@release/v1", "pypa/gh-action-pypi-publish", "release/v1"),
    ],
)
def test_workflow_action_refs_require_full_lowercase_commit_shas(
    tmp_path: Path, reference: str, expected_action: str | None, expected_ref: str | None
) -> None:
    """Allows immutable action commits while explaining mutable tags precisely."""
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(f"steps:\n  - uses: {reference}\n", encoding="utf-8")

    mismatches = check_toolchain_pins.find_workflow_action_pin_mismatches((workflow,))

    if expected_action is None:
        assert mismatches == []
    else:
        assert len(mismatches) == 1
        assert workflow.name in mismatches[0]
        assert expected_action in mismatches[0]
        assert expected_ref in mismatches[0]


def test_local_workflow_action_path_is_allowed(tmp_path: Path) -> None:
    """Retains support for repository-owned composite actions."""
    workflow = tmp_path / "workflow.yaml"
    workflow.write_text("steps:\n  - uses: ./.github/actions/publish\n", encoding="utf-8")

    assert check_toolchain_pins.find_workflow_action_pin_mismatches((workflow,)) == []


@pytest.mark.parametrize(
    ("workflow_source", "expected_ref"),
    (
        (
            'steps:\n  - uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"\n',
            None,
        ),
        (
            "steps:\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 "
            "# actions/checkout@v7\n",
            None,
        ),
        (
            "steps:\n  - uses: actions/checkout@3D3C42E5AAC5BA805825DA76410C181273BA90B1\n",
            "3D3C42E5AAC5BA805825DA76410C181273BA90B1",
        ),
    ),
    ids=("quoted-sha", "adjacent-comment", "uppercase-sha"),
)
def test_workflow_action_ref_parser_handles_yaml_spelling_edges(
    tmp_path: Path, workflow_source: str, expected_ref: str | None
) -> None:
    """Catches quote/comment parsing drift without accepting uppercase commit refs."""
    workflow = tmp_path / "workflow.yml"
    workflow.write_text(workflow_source, encoding="utf-8")

    mismatches = check_toolchain_pins.find_workflow_action_pin_mismatches((workflow,))

    if expected_ref is None:
        assert mismatches == []
    else:
        assert len(mismatches) == 1
        assert workflow.name in mismatches[0]
        assert "actions/checkout" in mismatches[0]
        assert expected_ref in mismatches[0]


@pytest.mark.parametrize("suffix", ("yml", "yaml"))
def test_cli_discovers_default_workflow_extensions(tmp_path: Path, suffix: str) -> None:
    """Catches the direct CLI silently skipping either supported workflow suffix."""
    constraints = tmp_path / "constraints" / "ci.txt"
    constraints.parent.mkdir()
    _write_constraints(constraints)
    (tmp_path / ".pre-commit-config.yaml").write_text(_matching_pre_commit(), encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / f"release.{suffix}"
    workflow.write_text("steps:\n  - uses: actions/checkout@v7\n", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools/check_toolchain_pins.py")],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert str(workflow.relative_to(tmp_path)) in completed.stderr
    assert "actions/checkout" in completed.stderr
    assert "v7" in completed.stderr


def test_repository_workflow_integration_rejects_a_mutable_external_ref(tmp_path: Path) -> None:
    """Protects the real CI workflow inventory from a later tag regression."""
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        (REPO_ROOT / ".github/workflows/ci.yml")
        .read_text(encoding="utf-8")
        .replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
            1,
        ),
        encoding="utf-8",
    )

    mismatches = check_toolchain_pins.find_workflow_action_pin_mismatches((workflow,))

    assert len(mismatches) == 1
    assert workflow.name in mismatches[0]
    assert "actions/checkout" in mismatches[0]
    assert "v7" in mismatches[0]
