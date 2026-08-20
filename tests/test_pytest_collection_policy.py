"""Tests for ignored local pytest collection policy."""

from __future__ import annotations

from pathlib import Path

from tools import check_pytest_collection_policy


def test_known_local_runner_test_is_explicitly_allowed() -> None:
    result = check_pytest_collection_policy.evaluate_policy(
        [Path("tests/test_close_plan_stages.py")]
    )

    assert result.allowed == (Path("tests/test_close_plan_stages.py"),)
    assert result.disallowed == ()


def test_unapproved_ignored_pytest_module_is_reported() -> None:
    result = check_pytest_collection_policy.evaluate_policy(
        [
            Path("tests/test_local_only.py"),
            Path("tests/helper.py"),
            Path("tests/__pycache__/test_cached.cpython-312.pyc"),
        ]
    )

    assert result.allowed == ()
    assert result.disallowed == (Path("tests/test_local_only.py"),)


def test_main_fails_for_unapproved_ignored_pytest_module(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        check_pytest_collection_policy,
        "ignored_paths",
        lambda _repo_root: [Path("tests/test_local_only.py")],
    )

    assert check_pytest_collection_policy.main([]) == 1

    captured = capsys.readouterr()
    assert "Ignored pytest-style test files are not allowed" in captured.err
    assert "tests/test_local_only.py" in captured.err
