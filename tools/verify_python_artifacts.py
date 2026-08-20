#!/usr/bin/env python3
"""Validate and smoke-test XFerry wheel/sdist release artifacts."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

try:
    from tools.check_public_surface import is_forbidden_path
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from check_public_surface import is_forbidden_path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    from setuptools._vendor import tomli as tomllib  # type: ignore[no-redef]


class ArtifactValidationError(ValueError):
    """A shipping artifact or its verification boundary is unsafe or incomplete."""


@dataclass(frozen=True)
class ValidatedArtifacts:
    """Normalized contents accepted by the wheel/sdist contract."""

    wheel_members: frozenset[str]
    sdist_members: frozenset[str]
    expected_package_data: frozenset[str]


def normalized_parts(name: str) -> tuple[str, ...]:
    """Return safe relative POSIX archive parts or reject the member name."""
    if not name or "\\" in name:
        raise ArtifactValidationError(f"unsafe archive member: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts:
        raise ArtifactValidationError(f"unsafe archive member: {name!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactValidationError(f"unsafe archive member: {name!r}")
    return path.parts


def declared_package_data(project_root: Path) -> frozenset[str]:
    """Expand setuptools' declared XFerry package-data patterns from the source tree."""
    pyproject_path = project_root / "pyproject.toml"
    with pyproject_path.open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    try:
        patterns = pyproject["tool"]["setuptools"]["package-data"]["xferry"]
    except (KeyError, TypeError) as exc:
        raise ArtifactValidationError("missing tool.setuptools.package-data.xferry") from exc
    if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
        raise ArtifactValidationError("XFerry package-data patterns must be a string list")

    package_root = project_root / "xferry"
    if not package_root.is_dir():
        raise ArtifactValidationError(f"XFerry package root is missing: {package_root}")

    expected: set[str] = set()
    for source_path in package_root.rglob("*"):
        if not source_path.is_file():
            continue
        relative = source_path.relative_to(package_root)
        if "__pycache__" in relative.parts or source_path.suffix in {".pyc", ".pyo"}:
            continue
        posix_relative = relative.as_posix()
        if any(fnmatchcase(posix_relative, pattern) for pattern in patterns):
            expected.add((PurePosixPath("xferry") / posix_relative).as_posix())
    if not expected:
        raise ArtifactValidationError("declared XFerry package data expanded to an empty set")
    return frozenset(expected)


def validate_package_members(
    members: Iterable[str],
    *,
    expected_data: frozenset[str],
    artifact_label: str,
    wheel_metadata_stem: str | None = None,
) -> frozenset[str]:
    """Validate a wheel's XFerry-only package boundary and complete declared data."""
    normalized = validate_public_surface_members(members, artifact_label=artifact_label)
    for member in sorted(normalized):
        parts = PurePosixPath(member).parts
        if "src" in parts:
            raise ArtifactValidationError(
                f"{artifact_label} contains forbidden src path component: {member}"
            )
        root = parts[0]
        if root == "xferry":
            continue
        if wheel_metadata_stem is not None and root == f"{wheel_metadata_stem}.dist-info":
            continue
        if (
            wheel_metadata_stem is not None
            and root == f"{wheel_metadata_stem}.data"
            and len(parts) >= 2
        ):
            category = parts[1]
            if category in {"data", "headers", "scripts"}:
                continue
            if category in {"purelib", "platlib"} and len(parts) >= 3 and parts[2] == "xferry":
                continue
        raise ArtifactValidationError(
            f"{artifact_label} contains non-xferry wheel content: {member}"
        )

    _require_package_data(normalized, expected_data=expected_data, artifact_label=artifact_label)
    return normalized


def _normalized_member_set(members: Iterable[str]) -> frozenset[str]:
    return frozenset(PurePosixPath(*normalized_parts(member)).as_posix() for member in members)


def validate_public_surface_members(
    members: Iterable[str], *, artifact_label: str
) -> frozenset[str]:
    """Normalize archive members and reject internal public-surface artifacts."""
    normalized = _normalized_member_set(members)
    _reject_forbidden_public_members(normalized, artifact_label)
    return normalized


def _require_package_data(
    members: frozenset[str], *, expected_data: frozenset[str], artifact_label: str
) -> None:
    missing = expected_data - members
    if missing:
        raise ArtifactValidationError(
            f"{artifact_label} is missing declared package data: {', '.join(sorted(missing))}"
        )


def _reject_forbidden_public_members(members: frozenset[str], artifact_label: str) -> None:
    """Reject internal repository surfaces from every distributable archive."""
    for member in sorted(members):
        if is_forbidden_path(member):
            raise ArtifactValidationError(
                f"{artifact_label} contains forbidden public-surface path: {member}"
            )


def validate_sdist_members(
    members: Iterable[str],
    *,
    expected_data: frozenset[str],
    artifact_label: str,
) -> frozenset[str]:
    """Validate the broader stripped source-release boundary and declared data."""
    normalized = validate_public_surface_members(members, artifact_label=artifact_label)
    for member in sorted(normalized):
        if "src" in PurePosixPath(member).parts:
            raise ArtifactValidationError(
                f"{artifact_label} contains forbidden src path component: {member}"
            )
    _require_package_data(normalized, expected_data=expected_data, artifact_label=artifact_label)
    return normalized


def validate_artifacts(*, wheel: Path, sdist: Path, project_root: Path) -> ValidatedArtifacts:
    """Inspect one real wheel and one real rooted sdist."""
    wheel = wheel.resolve()
    sdist = sdist.resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        raise ArtifactValidationError(f"wheel artifact is missing or invalid: {wheel}")
    if not sdist.is_file() or not sdist.name.endswith(".tar.gz"):
        raise ArtifactValidationError(f"sdist artifact is missing or invalid: {sdist}")

    expected_data = declared_package_data(project_root.resolve())
    wheel_filename_parts = wheel.name.removesuffix(".whl").split("-")
    if len(wheel_filename_parts) < 5 or wheel_filename_parts[0].replace("_", "-") != "xferry":
        raise ArtifactValidationError(f"wheel filename is not an XFerry wheel: {wheel.name}")
    wheel_metadata_stem = "-".join(wheel_filename_parts[:2])
    with zipfile.ZipFile(wheel) as wheel_archive:
        wheel_members = validate_package_members(
            wheel_archive.namelist(),
            expected_data=expected_data,
            artifact_label=wheel.name,
            wheel_metadata_stem=wheel_metadata_stem,
        )

    expected_root = sdist.name.removesuffix(".tar.gz")
    stripped_sdist_members: list[str] = []
    with tarfile.open(sdist, "r:gz") as sdist_archive:
        archive_members = sdist_archive.getmembers()
        if not archive_members:
            raise ArtifactValidationError(f"{sdist.name} is empty")
        for member in archive_members:
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ArtifactValidationError(
                    f"{sdist.name} contains unsafe tar member type: {member.name}"
                )
            parts = normalized_parts(member.name)
            if parts[0] != expected_root:
                raise ArtifactValidationError(
                    f"{sdist.name} member is outside exact root {expected_root!r}: {member.name}"
                )
            if len(parts) > 1:
                stripped_sdist_members.append(PurePosixPath(*parts[1:]).as_posix())

    sdist_members = validate_sdist_members(
        stripped_sdist_members,
        expected_data=expected_data,
        artifact_label=sdist.name,
    )
    return ValidatedArtifacts(
        wheel_members=wheel_members,
        sdist_members=sdist_members,
        expected_package_data=expected_data,
    )


def resolve_exactly_one(pattern: str, *, workspace: Path, label: str) -> Path:
    """Resolve an artifact glob to one literal file path."""
    candidate_pattern = Path(pattern)
    if candidate_pattern.is_absolute():
        if any(character in pattern for character in "*?["):
            raise ArtifactValidationError("absolute artifact patterns cannot contain wildcards")
        matches = [candidate_pattern.resolve()]
    else:
        matches = sorted(path.resolve() for path in workspace.glob(pattern))
    files = [match for match in matches if match.is_file()]
    if len(files) != 1:
        raise ArtifactValidationError(
            f"expected exactly one {label} for {pattern!r}, found {len(files)}"
        )
    return files[0]


def wheelhouse_download_command(
    *, python: Path, wheel: Path, wheelhouse: Path, constraints: Path
) -> tuple[str, ...]:
    """Build the sole connected command from the wheel's dependency metadata."""
    return (
        str(python),
        "-m",
        "pip",
        "download",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--dest",
        str(wheelhouse),
        "--constraint",
        str(constraints),
        "--only-binary=:all:",
        str(wheel),
        "setuptools>=75.0",
        "wheel",
    )


def pip_install_command(
    *,
    python: Path,
    wheelhouse: Path,
    constraints: Path,
    requirements: Sequence[str | Path],
    no_build_isolation: bool = False,
) -> tuple[str, ...]:
    """Build an isolated, index-free artifact/dependency install command."""
    command = [
        str(python),
        "-m",
        "pip",
        "--isolated",
        "install",
        "--no-index",
        "--find-links",
        str(wheelhouse),
        "--no-cache-dir",
        "--constraint",
        str(constraints),
    ]
    if no_build_isolation:
        command.append("--no-build-isolation")
    command.extend(str(requirement) for requirement in requirements)
    return tuple(command)


def _run_checked(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    quiet_stdout: bool = False,
) -> None:
    print(f"+ {shlex.join(command)}", flush=True)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.DEVNULL if quiet_stdout else None,
        check=False,
    )
    if result.returncode != 0:
        raise ArtifactValidationError(
            f"command failed with exit {result.returncode}: {shlex.join(command)}"
        )


def _require_outside_workspace(path: Path, *, workspace: Path, label: str) -> Path:
    resolved = path.resolve()
    if resolved == workspace or resolved.is_relative_to(workspace):
        raise ArtifactValidationError(f"{label} must be outside the checkout: {resolved}")
    return resolved


def prepare_wheelhouse(
    *, wheel: Path, wheelhouse: Path, constraints: Path, workspace: Path
) -> None:
    """Resolve runtime and sdist-build dependencies during the connected phase."""
    wheelhouse = _require_outside_workspace(
        wheelhouse, workspace=workspace, label="artifact wheelhouse"
    )
    wheelhouse.mkdir(parents=True, exist_ok=True)
    if any(wheelhouse.iterdir()):
        raise ArtifactValidationError(f"artifact wheelhouse must start empty: {wheelhouse}")
    _run_checked(
        wheelhouse_download_command(
            python=Path(sys.executable),
            wheel=wheel,
            wheelhouse=wheelhouse,
            constraints=constraints,
        ),
        cwd=workspace,
    )


_IMPORT_PROBE = """
import importlib.util
import inspect
import os
from pathlib import Path

import acme
import cryptography
import josepy
from OpenSSL import SSL
import xferry
from xferry import XFerryServer

del acme, cryptography, josepy, SSL
assert importlib.util.find_spec("src") is None
repo = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
for value in (xferry, XFerryServer):
    location = Path(inspect.getfile(value)).resolve()
    assert location != repo and not location.is_relative_to(repo), location
""".strip()


def _venv_commands(venv_dir: Path) -> tuple[Path, Path]:
    if os.name == "nt":
        return venv_dir / "Scripts/python.exe", venv_dir / "Scripts/xferry.exe"
    return venv_dir / "bin/python", venv_dir / "bin/xferry"


def _probe_installed_artifact(*, venv_dir: Path, probe_dir: Path, workspace: Path) -> None:
    python, console = _venv_commands(venv_dir)
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["GITHUB_WORKSPACE"] = str(workspace)
    commands: tuple[tuple[tuple[str, ...], bool], ...] = (
        ((str(python), "-m", "pip", "check"), False),
        ((str(python), "-c", _IMPORT_PROBE), False),
        ((str(console), "--help"), True),
        ((str(console), "run", "--version"), False),
        ((str(python), "-m", "xferry", "--help"), True),
        ((str(python), "-m", "xferry", "run", "--version"), False),
        ((str(python), "-m", "xferry", "run", "--check-config"), False),
    )
    for command, quiet_stdout in commands:
        _run_checked(
            command,
            cwd=probe_dir,
            env=environment,
            quiet_stdout=quiet_stdout,
        )


def offline_smoke(
    *,
    wheel: Path,
    sdist: Path,
    wheelhouse: Path,
    constraints: Path,
    fresh_root: Path,
    workspace: Path,
) -> None:
    """Install and probe separate wheel/sdist venvs with the index disabled."""
    wheelhouse = _require_outside_workspace(
        wheelhouse, workspace=workspace, label="artifact wheelhouse"
    )
    fresh_root = _require_outside_workspace(
        fresh_root, workspace=workspace, label="fresh artifact root"
    )
    if not wheelhouse.is_dir() or not any(wheelhouse.iterdir()):
        raise ArtifactValidationError(f"prepared artifact wheelhouse is empty: {wheelhouse}")
    if fresh_root.exists() and any(fresh_root.iterdir()):
        raise ArtifactValidationError(f"fresh artifact root must start empty: {fresh_root}")

    fresh_root.mkdir(parents=True, exist_ok=True)
    probe_dir = fresh_root / "outside-checkout"
    probe_dir.mkdir()
    wheel_venv = fresh_root / "wheel-venv"
    sdist_venv = fresh_root / "sdist-venv"

    _run_checked((sys.executable, "-m", "venv", str(wheel_venv)), cwd=fresh_root)
    wheel_python, _ = _venv_commands(wheel_venv)
    _run_checked(
        pip_install_command(
            python=wheel_python,
            wheelhouse=wheelhouse,
            constraints=constraints,
            requirements=(wheel,),
        ),
        cwd=probe_dir,
    )

    _run_checked((sys.executable, "-m", "venv", str(sdist_venv)), cwd=fresh_root)
    sdist_python, _ = _venv_commands(sdist_venv)
    _run_checked(
        pip_install_command(
            python=sdist_python,
            wheelhouse=wheelhouse,
            constraints=constraints,
            requirements=("setuptools>=75.0", "wheel"),
        ),
        cwd=probe_dir,
    )
    _run_checked(
        pip_install_command(
            python=sdist_python,
            wheelhouse=wheelhouse,
            constraints=constraints,
            requirements=(sdist,),
            no_build_isolation=True,
        ),
        cwd=probe_dir,
    )

    _probe_installed_artifact(venv_dir=wheel_venv, probe_dir=probe_dir, workspace=workspace)
    _probe_installed_artifact(venv_dir=sdist_venv, probe_dir=probe_dir, workspace=workspace)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_artifacts(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--workspace", type=Path, required=True)
        subparser.add_argument("--wheel", required=True)
        subparser.add_argument("--sdist", required=True)

    validate_parser = subparsers.add_parser("validate")
    add_artifacts(validate_parser)

    prepare_parser = subparsers.add_parser("prepare-wheelhouse")
    prepare_parser.add_argument("--workspace", type=Path, required=True)
    prepare_parser.add_argument("--wheel", required=True)
    prepare_parser.add_argument("--wheelhouse", type=Path, required=True)
    prepare_parser.add_argument("--constraints", type=Path, required=True)

    smoke_parser = subparsers.add_parser("offline-smoke")
    add_artifacts(smoke_parser)
    smoke_parser.add_argument("--wheelhouse", type=Path, required=True)
    smoke_parser.add_argument("--fresh-root", type=Path, required=True)
    smoke_parser.add_argument("--constraints", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        raise ArtifactValidationError(f"workspace is missing: {workspace}")

    if args.command == "validate":
        wheel = resolve_exactly_one(args.wheel, workspace=workspace, label="wheel")
        sdist = resolve_exactly_one(args.sdist, workspace=workspace, label="sdist")
        validated = validate_artifacts(wheel=wheel, sdist=sdist, project_root=workspace)
        print(
            f"validated {wheel.name} and {sdist.name}: "
            f"{len(validated.expected_package_data)} declared data files"
        )
        return 0

    constraints = args.constraints.resolve()
    if not constraints.is_file():
        raise ArtifactValidationError(f"constraints file is missing: {constraints}")
    wheel = resolve_exactly_one(args.wheel, workspace=workspace, label="wheel")
    if args.command == "prepare-wheelhouse":
        prepare_wheelhouse(
            wheel=wheel,
            wheelhouse=args.wheelhouse,
            constraints=constraints,
            workspace=workspace,
        )
        return 0

    sdist = resolve_exactly_one(args.sdist, workspace=workspace, label="sdist")
    offline_smoke(
        wheel=wheel,
        sdist=sdist,
        wheelhouse=args.wheelhouse,
        constraints=constraints,
        fresh_root=args.fresh_root,
        workspace=workspace,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ArtifactValidationError as exc:
        print(f"artifact verification failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
