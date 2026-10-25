"""Keep the safe contributor toolchain separate from application Python support."""

from __future__ import annotations

from importlib.metadata import requires
from pathlib import Path

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    from setuptools._vendor import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK_PACKAGES = frozenset({"pre-commit", "filelock", "virtualenv"})


def _project() -> dict:
    with (REPO_ROOT / "pyproject.toml").open("rb") as source:
        return tomllib.load(source)["project"]


def _environment(python_version: str) -> dict[str, str]:
    return {
        **default_environment(),
        "python_version": python_version,
        "python_full_version": f"{python_version}.0",
        "extra": "",
    }


def _active_requirements(items: list[str], python_version: str) -> list[Requirement]:
    environment = _environment(python_version)
    requirements = [Requirement(item) for item in items]
    return [
        requirement
        for requirement in requirements
        if requirement.marker is None or requirement.marker.evaluate(environment)
    ]


def _constraints() -> dict[str, Requirement]:
    constraints: dict[str, Requirement] = {}
    for raw_line in (REPO_ROOT / "constraints/ci.txt").read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        requirement = Requirement(line)
        name = canonicalize_name(requirement.name)
        assert name not in constraints, f"duplicate constraint for {name}"
        constraints[name] = requirement
    return constraints


@pytest.mark.parametrize("python_version", ["3.10", "3.11", "3.12", "3.13", "3.14"])
def test_application_python_support_is_preserved(python_version: str) -> None:
    """Raising the hook interpreter floor must not raise the application floor."""
    assert python_version in SpecifierSet(_project()["requires-python"])


@pytest.mark.parametrize("python_version", ["3.9", "3.15"])
def test_application_does_not_expand_supported_python_range(python_version: str) -> None:
    assert python_version not in SpecifierSet(_project()["requires-python"])


@pytest.mark.parametrize("python_version", ["3.10", "3.11", "3.12", "3.13", "3.14"])
def test_runtime_dependencies_exclude_hook_toolchain(python_version: str) -> None:
    """Inspect active installed metadata, including transitive runtime requirements."""
    pending = _active_requirements(_project()["dependencies"], python_version)
    inspected: set[tuple[str, frozenset[str]]] = set()
    while pending:
        requirement = pending.pop()
        name = canonicalize_name(requirement.name)
        assert name not in HOOK_PACKAGES, f"runtime pulls contributor dependency {name}"
        identity = (name, frozenset(requirement.extras))
        if identity in inspected:
            continue
        inspected.add(identity)
        for raw_dependency in requires(requirement.name) or ():
            dependency = Requirement(raw_dependency)
            environments = [
                {**_environment(python_version), "extra": extra}
                for extra in (requirement.extras or {""})
            ]
            if dependency.marker is None or any(
                dependency.marker.evaluate(environment) for environment in environments
            ):
                pending.append(dependency)


@pytest.mark.parametrize("python_version", ["3.10", "3.11", "3.12", "3.13", "3.14"])
def test_dev_extra_selects_hooks_only_on_supported_tooling_python(python_version: str) -> None:
    dev = _active_requirements(_project()["optional-dependencies"]["dev"], python_version)
    selected = {canonicalize_name(requirement.name): requirement for requirement in dev}
    if python_version == "3.10":
        assert HOOK_PACKAGES.isdisjoint(selected)
    else:
        assert "pre-commit" in selected
        assert _pinned_version(_constraints()["pre-commit"]) in selected["pre-commit"].specifier
    assert {"build", "pytest", "pytest-cov", "hypothesis", "setuptools", "wheel"} <= set(selected)


def _pinned_version(requirement: Requirement) -> Version:
    assert requirement.marker is None, f"security pin must be unconditional: {requirement}"
    assert requirement.url is None
    specifiers = list(requirement.specifier)
    assert len(specifiers) == 1
    assert specifiers[0].operator == "=="
    assert "*" not in specifiers[0].version
    return Version(specifiers[0].version)


@pytest.mark.parametrize(
    ("package", "fixed_version"),
    [("filelock", "4.2.4"), ("virtualenv", "21.14.13")],
)
def test_security_constraints_require_fixed_toolchain_versions(
    package: str, fixed_version: str
) -> None:
    """Reject vulnerable downgrades and interpreter-specific vulnerable fallbacks."""
    assert _pinned_version(_constraints()[package]) >= Version(fixed_version)


@pytest.mark.parametrize("extra", ["lint", "test"])
def test_minimum_python_checks_do_not_select_hook_toolchain(extra: str) -> None:
    requirements = _active_requirements(_project()["optional-dependencies"][extra], "3.10")
    assert HOOK_PACKAGES.isdisjoint(
        canonicalize_name(requirement.name) for requirement in requirements
    )
