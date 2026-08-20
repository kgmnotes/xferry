"""Package-boundary regressions for the XFerry pre-1.0 baseline."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
import zipfile
from dataclasses import dataclass
from fnmatch import fnmatchcase
from importlib import resources
from pathlib import Path, PurePosixPath

import pytest
from packaging.requirements import Requirement
from setuptools import find_packages

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    from setuptools._vendor import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_probe(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(source)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _run(
    command: list[str] | tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


@dataclass(frozen=True)
class BuiltArtifacts:
    wheel: Path
    sdist: Path
    source_root: Path
    build_command: tuple[str, ...]
    build_environment: dict[str, str]


@pytest.fixture(scope="module")
def built_artifacts(tmp_path_factory: pytest.TempPathFactory) -> BuiltArtifacts:
    """Build one wheel and one sdist through the declared setuptools backend."""
    build_root = tmp_path_factory.mktemp("xferry-artifact-build")
    source_root = build_root / "source"
    artifact_dir = build_root / "artifacts"
    artifact_dir.mkdir()
    shutil.copytree(
        REPO_ROOT,
        source_root,
        ignore=shutil.ignore_patterns(
            ".git",
            ".benchmarks",
            ".hypothesis",
            ".mypy_cache",
            ".playwright-cli",
            ".pytest_cache",
            ".ruff_cache",
            ".venv",
            "__pycache__",
            "*.py[co]",
            ".coverage",
            "coverage.xml",
            "build",
            "dist",
            "site",
            "output",
            "uploads",
            "xferry.egg-info",
            ".env",
            ".env.*",
            "*.key",
            "*.pem",
        ),
    )

    build_environment = os.environ.copy()
    build_environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_EXTRA_INDEX_URL": "",
            "PIP_INDEX_URL": "",
            "PIP_NO_INDEX": "1",
            "UV_OFFLINE": "1",
            "UV_PYTHON_DOWNLOADS": "never",
        }
    )

    pep517_build = _run(
        [sys.executable, "-m", "build", "--version"],
        cwd=source_root,
        env=build_environment,
    )
    if pep517_build.returncode == 0:
        command = (
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--wheel",
            "--outdir",
            str(artifact_dir),
        )
    elif uv := shutil.which("uv"):
        command = (
            uv,
            "build",
            "--offline",
            "--no-python-downloads",
            "--sdist",
            "--wheel",
            "--out-dir",
            str(artifact_dir),
            str(source_root),
        )
    else:
        pytest.skip("no PEP 517 frontend is available for real artifact tests")

    result = _run(command, cwd=source_root, env=build_environment)
    assert result.returncode == 0, result.stderr or result.stdout
    wheels = list(artifact_dir.glob("xferry-*.whl"))
    sdists = list(artifact_dir.glob("xferry-*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    return BuiltArtifacts(
        wheel=wheels[0],
        sdist=sdists[0],
        source_root=source_root,
        build_command=command,
        build_environment=build_environment,
    )


def _declared_package_data() -> frozenset[str]:
    """Expand the package-data contract independently from the artifact validator."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    patterns = pyproject["tool"]["setuptools"]["package-data"]["xferry"]
    package_root = REPO_ROOT / "xferry"
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
    return frozenset(expected)


def test_repository_discovery_has_only_xferry_and_the_pre_1_0_version_authority() -> None:
    """Catches a second package tree or metadata still rooted at ``src``."""
    assert not (REPO_ROOT / "src").exists()

    with (REPO_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    assert pyproject["tool"]["setuptools"]["include-package-data"] is False
    package_finder = pyproject["tool"]["setuptools"]["packages"]["find"]
    assert package_finder["namespaces"] is False
    assert set(package_finder["include"]) == {"xferry*"}
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {
        "attr": "xferry.config.__version__"
    }
    development_requirements = {
        Requirement(item).name for item in pyproject["project"]["optional-dependencies"]["dev"]
    }
    assert "build" in development_requirements
    assert {
        Requirement(item).name for item in pyproject["build-system"]["requires"]
    } <= development_requirements

    discovered_packages = set(
        find_packages(
            where=str(REPO_ROOT),
            include=package_finder["include"],
            exclude=package_finder["exclude"],
        )
    )
    assert "xferry" in discovered_packages
    assert not {name for name in discovered_packages if name == "src" or name.startswith("src.")}

    from xferry import __version__

    assert __version__ == "0.1.0"


def test_runtime_dependencies_include_the_pinned_xml_hardening_library() -> None:
    """The runtime install must include the XML hardening dependency directly."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    runtime_requirements = {
        requirement.name: requirement
        for item in pyproject["project"]["dependencies"]
        if (requirement := Requirement(item))
    }

    assert runtime_requirements["defusedxml"].specifier == "==0.7.1"


def test_public_exports_keep_identity_and_do_not_eagerly_load_acme_or_josepy() -> None:
    """Catches wrappers, legacy imports, and eager optional dependency imports."""
    result = _run_probe(
        """
        import importlib.abc
        import sys

        class BlockAcmeAndJosepy(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname.startswith(("acme", "josepy")):
                    raise ImportError(f"{fullname} intentionally blocked")
                return None

        sys.meta_path.insert(0, BlockAcmeAndJosepy())

        import xferry
        import xferry.http
        import xferry.security
        import xferry.security.auth
        import xferry.security.crypto
        assert "xferry.security.tls" not in sys.modules
        assert xferry.HTTPRequest is xferry.http.HTTPRequest
        assert xferry.HTTPResponse is xferry.http.HTTPResponse
        assert xferry.security.BasicAuthenticator is xferry.security.auth.BasicAuthenticator
        assert xferry.security.xor_encrypt is xferry.security.crypto.xor_encrypt

        import xferry.server

        assert xferry.XFerryServer is xferry.server.XFerryServer

        from xferry.security import generate_self_signed_cert
        import xferry.security.tls

        assert generate_self_signed_cert is xferry.security.tls.generate_self_signed_cert
        assert not [
            name
            for name in sys.modules
            if name == "src" or name.startswith(("src.", "acme", "josepy"))
        ]
        """
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_package_resources_are_loaded_from_xferry_data_and_management() -> None:
    """Catches resource package lookups still rooted at the removed package."""
    from xferry.handlers.base import get_package_resource

    data_root = (REPO_ROOT / "xferry" / "data").resolve()
    for resource_name in ("index.html", "static/ui/app.js", "static/crypto-js.min.js"):
        resource_path = get_package_resource(resource_name)
        assert resource_path is not None
        assert resource_path.resolve().is_relative_to(data_root)

    packaged_unit = (
        resources.files("xferry.management").joinpath("data/xferry.service").read_bytes()
    )
    assert packaged_unit == (REPO_ROOT / "deploy" / "systemd" / "xferry.service").read_bytes()


def test_artifact_member_normalization_rejects_unsafe_paths() -> None:
    """Catches empty, absolute, traversal, and non-POSIX archive member names."""
    try:
        from tools.verify_python_artifacts import ArtifactValidationError, normalized_parts
    except ModuleNotFoundError:
        pytest.fail("artifact validation helper is missing")

    for unsafe_name in (
        "",
        ".",
        "..",
        "/xferry/__init__.py",
        "xferry/../src/x.py",
        "xferry\\data\\index.html",
    ):
        with pytest.raises(ArtifactValidationError):
            normalized_parts(unsafe_name)


def test_artifact_validator_rejects_a_synthetic_src_package() -> None:
    """Catches any archive reintroducing the removed top-level ``src`` package."""
    try:
        from tools.verify_python_artifacts import ArtifactValidationError, validate_package_members
    except ModuleNotFoundError:
        pytest.fail("artifact validation helper is missing")

    expected_data = _declared_package_data()
    members = {"xferry/__init__.py", "src/__init__.py", *expected_data}
    with pytest.raises(ArtifactValidationError, match=r"src"):
        validate_package_members(members, expected_data=expected_data, artifact_label="synthetic")


@pytest.mark.parametrize("foreign_member", ["other/module.py", "setup.py"])
def test_wheel_validator_rejects_every_non_xferry_importable_module(
    foreign_member: str,
) -> None:
    """Catches namespace-package and root-module code escaping the XFerry wheel boundary."""
    from tools.verify_python_artifacts import ArtifactValidationError, validate_package_members

    expected_data = _declared_package_data()
    members = {"xferry/__init__.py", foreign_member, *expected_data}
    with pytest.raises(ArtifactValidationError, match=foreign_member):
        validate_package_members(members, expected_data=expected_data, artifact_label="wheel")


def test_artifact_validator_rejects_any_missing_declared_package_data() -> None:
    """Catches package-data assertions that cover only representative files."""
    try:
        from tools.verify_python_artifacts import ArtifactValidationError, validate_package_members
    except ModuleNotFoundError:
        pytest.fail("artifact validation helper is missing")

    expected_data = _declared_package_data()
    assert expected_data
    removed = min(expected_data)
    members = {"xferry/__init__.py", *(expected_data - {removed})}
    with pytest.raises(ArtifactValidationError, match=removed):
        validate_package_members(members, expected_data=expected_data, artifact_label="synthetic")


@pytest.mark.parametrize(
    "forbidden_member",
    (
        "CLAU" + "DE.md",
        "/".join(("implementation" + "-plan", "private.md")),
        "/".join(("docs", "super" + "powers", "private.md")),
        "/".join(("nested", "AG" + "ENTS.md")),
        "/".join(("xferry", "implementation" + "-plan", "private.md")),
        "/".join(("xferry", ".super" + "powers", "private.md")),
    ),
)
def test_sdist_validator_rejects_internal_public_surface_members(forbidden_member: str) -> None:
    """Catches an archive that ships an internal planning or assistant artifact."""
    from tools.verify_python_artifacts import ArtifactValidationError, validate_sdist_members

    expected_data = _declared_package_data()
    with pytest.raises(ArtifactValidationError, match=forbidden_member):
        validate_sdist_members(
            {"xferry/__init__.py", forbidden_member, *expected_data},
            expected_data=expected_data,
            artifact_label="synthetic",
        )


def test_built_wheel_and_sdist_contain_complete_xferry_package_data(
    built_artifacts: BuiltArtifacts,
) -> None:
    """Catches either real shipping artifact dropping data or adding another package tree."""
    try:
        from tools.verify_python_artifacts import validate_artifacts
    except ModuleNotFoundError:
        pytest.fail("artifact validation helper is missing")

    expected_data = _declared_package_data()
    validated = validate_artifacts(
        wheel=built_artifacts.wheel,
        sdist=built_artifacts.sdist,
        project_root=REPO_ROOT,
    )

    assert validated.expected_package_data == expected_data
    assert expected_data <= validated.wheel_members
    assert expected_data <= validated.sdist_members
    assert built_artifacts.wheel.name == "xferry-0.1.0-py3-none-any.whl"
    assert built_artifacts.sdist.name == "xferry-0.1.0.tar.gz"

    with zipfile.ZipFile(built_artifacts.wheel) as wheel:
        assert len(wheel.namelist()) == len(validated.wheel_members)
        metadata = wheel.read("xferry-0.1.0.dist-info/METADATA").decode("utf-8")
        assert "Version: 0.1.0" in metadata.splitlines()
    with tarfile.open(built_artifacts.sdist, "r:gz") as sdist:
        assert sdist.getmembers()
        pkg_info = sdist.extractfile("xferry-0.1.0/PKG-INFO")
        assert pkg_info is not None
        assert "Version: 0.1.0" in pkg_info.read().decode("utf-8").splitlines()


def test_real_artifact_build_is_index_free_and_mirrors_checkout_candidates(
    built_artifacts: BuiltArtifacts,
) -> None:
    """Catches pytest builds regaining an index or pre-filtering unexpected package inputs."""
    build_command = getattr(built_artifacts, "build_command", ())
    build_environment = getattr(built_artifacts, "build_environment", {})
    source_root = getattr(built_artifacts, "source_root", None)

    assert build_command
    assert build_environment.get("PIP_NO_INDEX") == "1"
    assert build_environment.get("PIP_INDEX_URL") == ""
    assert build_environment.get("PIP_EXTRA_INDEX_URL") == ""
    assert build_environment.get("UV_OFFLINE") == "1"
    if build_command[:3] == (sys.executable, "-m", "build"):
        assert "--no-isolation" in build_command
    else:
        assert "--offline" in build_command
        assert "--no-python-downloads" in build_command

    assert isinstance(source_root, Path)
    for relative in (
        Path("tests/server_factory.py"),
        Path("tools/verify_python_artifacts.py"),
        Path("mkdocs.yml"),
    ):
        assert (source_root / relative).read_bytes() == (REPO_ROOT / relative).read_bytes()


def test_offline_install_argv_blocks_indexes_caches_and_sdist_build_isolation() -> None:
    """Catches fresh artifact installs regaining any hidden package-index path."""
    try:
        from tools.verify_python_artifacts import pip_install_command
    except ModuleNotFoundError:
        pytest.fail("artifact validation helper is missing")

    common = {
        "python": Path("/fresh/bin/python"),
        "wheelhouse": Path("/wheelhouse"),
        "constraints": Path("/checkout/constraints/ci.txt"),
    }
    wheel_command = pip_install_command(
        **common,
        requirements=(Path("/checkout/dist/xferry.whl"),),
    )
    sdist_command = pip_install_command(
        **common,
        requirements=(Path("/checkout/dist/xferry.tar.gz"),),
        no_build_isolation=True,
    )

    required_offline_argv = {
        "--isolated",
        "--no-index",
        "--find-links",
        "/wheelhouse",
        "--no-cache-dir",
        "--constraint",
        "/checkout/constraints/ci.txt",
    }
    assert required_offline_argv <= set(wheel_command)
    assert required_offline_argv <= set(sdist_command)
    assert "--no-build-isolation" not in wheel_command
    assert "--no-build-isolation" in sdist_command


def test_connected_wheelhouse_argv_resolves_metadata_and_sdist_build_tools() -> None:
    """Catches a hand-copied dependency list or wheelhouse preparation without build tools."""
    try:
        from tools.verify_python_artifacts import wheelhouse_download_command
    except ModuleNotFoundError:
        pytest.fail("artifact validation helper is missing")

    command = wheelhouse_download_command(
        python=Path("/python"),
        wheel=Path("/checkout/dist/xferry.whl"),
        wheelhouse=Path("/runner/wheelhouse"),
        constraints=Path("/checkout/constraints/ci.txt"),
    )

    assert command == (
        "/python",
        "-m",
        "pip",
        "download",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--dest",
        "/runner/wheelhouse",
        "--constraint",
        "/checkout/constraints/ci.txt",
        "--only-binary=:all:",
        "/checkout/dist/xferry.whl",
        "setuptools>=75.0",
        "wheel",
    )


def test_artifact_glob_must_resolve_to_exactly_one_literal_path(tmp_path: Path) -> None:
    """Catches stale or duplicate distributions making the gate validate an ambiguous input."""
    from tools.verify_python_artifacts import ArtifactValidationError, resolve_exactly_one

    dist = tmp_path / "dist"
    dist.mkdir()
    first = dist / "xferry-0.1.0-py3-none-any.whl"
    first.touch()
    assert (
        resolve_exactly_one("dist/xferry-*.whl", workspace=tmp_path, label="wheel")
        == first.resolve()
    )

    (dist / "xferry-0.1.1-py3-none-any.whl").touch()
    with pytest.raises(ArtifactValidationError, match="exactly one wheel"):
        resolve_exactly_one("dist/xferry-*.whl", workspace=tmp_path, label="wheel")


def test_fresh_wheel_install_without_dependencies_has_no_src_module(
    tmp_path: Path, built_artifacts: BuiltArtifacts
) -> None:
    """Catches source-checkout false passes without allowing a package-index request."""
    venv_dir = tmp_path / "wheel-venv"
    create_venv = _run([sys.executable, "-m", "venv", str(venv_dir)], cwd=tmp_path)
    assert create_venv.returncode == 0, create_venv.stderr or create_venv.stdout
    python = _venv_python(venv_dir)
    install = _run(
        [
            str(python),
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-cache-dir",
            "--no-deps",
            "--constraint",
            str(REPO_ROOT / "constraints/ci.txt"),
            str(built_artifacts.wheel),
        ],
        cwd=tmp_path,
    )
    assert install.returncode == 0, install.stderr or install.stdout

    probe_dir = tmp_path / "outside-checkout"
    probe_dir.mkdir()
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    probe = subprocess.run(
        [
            str(python),
            "-c",
            "import importlib.util; import xferry; "
            "assert xferry.__version__ == '0.1.0'; "
            "assert importlib.util.find_spec('src') is None",
        ],
        cwd=probe_dir,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr or probe.stdout

    legacy_module = subprocess.run(
        [str(python), "-m", "src"],
        cwd=probe_dir,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert legacy_module.returncode != 0
    assert "No module named" in legacy_module.stderr


def test_managed_state_module_exposes_only_the_renamed_contract() -> None:
    """The removed compatibility module must not remain as an import alias."""
    from xferry.management import managed_state

    assert managed_state.UNSUPPORTED_MANAGED_STATE_CODE == "unsupported-managed-state"
    assert callable(managed_state.has_unsupported_managed_state)
    assert isinstance(managed_state.UNSUPPORTED_MANAGED_STATE_INSTRUCTIONS, str)

    legacy_module = subprocess.run(
        [sys.executable, "-c", "import xferry.management.legacy"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert legacy_module.returncode != 0
    assert "No module named 'xferry.management.legacy'" in legacy_module.stderr
