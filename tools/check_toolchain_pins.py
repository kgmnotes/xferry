#!/usr/bin/env python3
"""Keep pre-commit hook dependencies aligned with CI constraints."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

_NAME_RE = re.compile(r"[-_.]+")
_DEPENDENCY_RE = re.compile(r"^\s*-\s*(\S+)")
_EXACT_PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s#]+)$")
_REPO_RE = re.compile(r"^\s*-\s*repo:\s*(\S+)\s*$")
_REV_RE = re.compile(r"^\s*rev:\s*(\S+)\s*$")
_HOOK_ID_RE = re.compile(r"^\s*-\s*id:\s*(\S+)\s*$")
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<reference>\S+)")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_ADDITIONAL_DEPENDENCIES = "additional_dependencies:"
_REQUIRED_HOOK_REPOS = {
    "https://github.com/astral-sh/ruff-pre-commit": ("ruff", ("ruff", "ruff-format")),
    "https://github.com/pre-commit/mirrors-mypy": ("mypy", ("mypy",)),
}
_MYPY_REPOSITORY = "https://github.com/pre-commit/mirrors-mypy"
_REQUIRED_MYPY_DEPENDENCY = "cryptography"


@dataclass(frozen=True)
class Hook:
    """One configured pre-commit hook and its isolated dependencies."""

    identifier: str
    additional_dependencies: tuple[str, ...]


@dataclass(frozen=True)
class HookRepository:
    """One pre-commit repository and its configured hook blocks."""

    repo: str
    revision: str | None
    hooks: tuple[Hook, ...]


def _normalize_name(name: str) -> str:
    return _NAME_RE.sub("-", name).lower()


def _read_pins(path: Path) -> dict[str, str]:
    """Return normalized exact pins from a requirements-style file."""
    pins: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _EXACT_PIN_RE.fullmatch(line)
        if match:
            pins[_normalize_name(match.group(1))] = match.group(2)
    return pins


def _parse_hook_repositories(path: Path) -> tuple[HookRepository, ...]:
    """Read pre-commit repository and hook blocks without merging environments."""
    repositories: list[HookRepository] = []
    current_repo: str | None = None
    current_revision: str | None = None
    hooks: list[Hook] = []
    current_hook_id: str | None = None
    dependencies: list[str] = []
    in_additional_dependencies = False
    dependency_indent = 0

    def flush_hook() -> None:
        nonlocal current_hook_id, dependencies
        if current_hook_id is not None:
            hooks.append(Hook(current_hook_id, tuple(dependencies)))
        current_hook_id = None
        dependencies = []

    def flush_repository() -> None:
        nonlocal current_repo, current_revision, hooks
        flush_hook()
        if current_repo is not None:
            repositories.append(HookRepository(current_repo, current_revision, tuple(hooks)))
        current_repo = None
        current_revision = None
        hooks = []

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        repo_match = _REPO_RE.match(raw_line)
        if repo_match:
            flush_repository()
            current_repo = repo_match.group(1)
            in_additional_dependencies = False
            continue

        if current_repo is None:
            continue

        revision_match = _REV_RE.match(raw_line)
        if revision_match:
            current_revision = revision_match.group(1)
            continue

        hook_match = _HOOK_ID_RE.match(raw_line)
        if hook_match:
            flush_hook()
            current_hook_id = hook_match.group(1)
            in_additional_dependencies = False
            continue

        stripped = raw_line.strip()
        if stripped == _ADDITIONAL_DEPENDENCIES and current_hook_id is not None:
            in_additional_dependencies = True
            dependency_indent = len(raw_line) - len(raw_line.lstrip())
            continue
        if not in_additional_dependencies:
            continue

        indent = len(raw_line) - len(raw_line.lstrip())
        if stripped and indent <= dependency_indent:
            in_additional_dependencies = False
            continue
        dependency_match = _DEPENDENCY_RE.match(raw_line)
        if dependency_match:
            dependencies.append(dependency_match.group(1))

    flush_repository()
    return tuple(repositories)


def _validate_dependency(requirement: str, constraint_pins: dict[str, str]) -> str | None:
    """Return an actionable mismatch for one hook environment requirement."""
    match = _EXACT_PIN_RE.fullmatch(requirement)
    if match is None:
        package = requirement.split("=", 1)[0].split(">", 1)[0].split("<", 1)[0]
        return f"{package}: hook dependency must use an exact == pin, got {requirement}"

    package = _normalize_name(match.group(1))
    version = match.group(2)
    constraint_version = constraint_pins.get(package)
    if constraint_version is None:
        return f"{package}: hook pins {version}, absent from constraints"
    if version != constraint_version:
        return f"{package}: hook pins {version}, constraints pin {constraint_version}"
    return None


def find_pin_mismatches(constraints: Path, pre_commit_config: Path) -> list[str]:
    """Describe missing, non-exact, or mismatched required hook toolchain pins."""
    constraint_pins = _read_pins(constraints)
    repositories = _parse_hook_repositories(pre_commit_config)
    by_repo = {repository.repo: repository for repository in repositories}
    mismatches: list[str] = []

    for repo, (package, required_hook_ids) in _REQUIRED_HOOK_REPOS.items():
        repository = by_repo.get(repo)
        if repository is None:
            mismatches.append(f"{package}: required pre-commit repository {repo} is missing")
            continue
        if repository.revision is None:
            mismatches.append(f"{package}: required pre-commit repository revision is missing")
        else:
            revision = repository.revision.removeprefix("v")
            constraint_version = constraint_pins.get(package)
            if constraint_version is None:
                mismatches.append(f"{package}: hook revision {revision}, absent from constraints")
            elif revision != constraint_version:
                mismatches.append(
                    f"{package}: hook revision {revision}, constraints pin {constraint_version}"
                )

        configured_ids = {hook.identifier for hook in repository.hooks}
        for required_hook_id in required_hook_ids:
            if required_hook_id not in configured_ids:
                mismatches.append(
                    f"{package}: required pre-commit hook id {required_hook_id} is missing"
                )

    for repository in repositories:
        for hook in repository.hooks:
            for requirement in hook.additional_dependencies:
                mismatch = _validate_dependency(requirement, constraint_pins)
                if mismatch is not None:
                    mismatches.append(f"{repository.repo} id {hook.identifier}: {mismatch}")

    mypy_repository = by_repo.get(_MYPY_REPOSITORY)
    if mypy_repository is not None:
        mypy_hook = next(
            (hook for hook in mypy_repository.hooks if hook.identifier == "mypy"),
            None,
        )
        if mypy_hook is not None:
            dependency_names = {
                _normalize_name(match.group(1))
                for requirement in mypy_hook.additional_dependencies
                if (match := _EXACT_PIN_RE.fullmatch(requirement)) is not None
            }
            if _REQUIRED_MYPY_DEPENDENCY not in dependency_names:
                mismatches.append(
                    "cryptography: required exact pin is missing from the id mypy hook"
                )

    return mismatches


def find_workflow_action_pin_mismatches(workflows: tuple[Path, ...]) -> list[str]:
    """Describe external workflow actions that are not pinned to a commit SHA."""
    mismatches: list[str] = []
    for workflow in workflows:
        for line_number, raw_line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            match = _USES_RE.match(raw_line)
            if match is None:
                continue

            reference = match.group("reference").strip("\"'")
            if reference.startswith("./"):
                continue

            action, separator, ref = reference.partition("@")
            if separator and _COMMIT_SHA_RE.fullmatch(ref):
                continue

            received_ref = ref if separator else "(missing ref)"
            mismatches.append(
                f"{workflow}:{line_number}: {action}: external action ref must be a "
                f"lowercase 40-hex commit SHA, got {received_ref}"
            )
    return mismatches


def _default_workflows() -> tuple[Path, ...]:
    workflows_dir = Path(".github/workflows")
    return tuple(sorted((*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml"))))


def main(argv: list[str] | None = None) -> int:
    """Exit nonzero when a pre-commit dependency drifts from CI constraints."""
    parser = argparse.ArgumentParser(
        description="Check pre-commit hook dependency pins against CI constraints.",
    )
    parser.add_argument(
        "--constraints",
        default="constraints/ci.txt",
        type=Path,
        help="Pinned CI constraints file.",
    )
    parser.add_argument(
        "--pre-commit-config",
        default=".pre-commit-config.yaml",
        type=Path,
        help="Pre-commit configuration to inspect.",
    )
    parser.add_argument(
        "--workflow",
        action="append",
        default=[],
        type=Path,
        help="Workflow file to inspect; may be specified more than once.",
    )
    args = parser.parse_args(argv)

    mismatches = find_pin_mismatches(args.constraints, args.pre_commit_config)
    workflow_mismatches = find_workflow_action_pin_mismatches(
        tuple(args.workflow) if args.workflow else _default_workflows()
    )
    if mismatches:
        print("Pre-commit dependency pins drift from CI constraints:", file=sys.stderr)
        for mismatch in mismatches:
            print(f"  {mismatch}", file=sys.stderr)
    if workflow_mismatches:
        print("Workflow action refs must use immutable commit SHAs:", file=sys.stderr)
        for mismatch in workflow_mismatches:
            print(f"  {mismatch}", file=sys.stderr)
    if mismatches or workflow_mismatches:
        return 1

    print(
        f"Pre-commit dependency pins match constraints in {args.constraints}; "
        "workflow action refs are immutable."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
