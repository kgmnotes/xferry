"""Build deterministic SCIE products for local and automated verification."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xferry.management.managed_state import (  # noqa: E402
    UNSUPPORTED_MANAGED_STATE_INSTRUCTIONS,
)
from xferry.management.model import (  # noqa: E402
    SUPPORTED_MANAGED_DISTRIBUTIONS,
    SUPPORTED_MANAGED_HOST_SUMMARY,
)
from xferry.management.release_contract import (  # noqa: E402
    MAX_ARTIFACT_DIGESTS,
    SUPPORTED_PLATFORM_IDS,
    PlatformId,
    ReleaseManifest,
    artifact_name,
    current_platform_id,
    machine_aliases,
    platform_display_name,
    require_platform_id,
    require_source_commit,
    require_workflow_run,
)
from xferry.management.versions import (  # noqa: E402
    SUPPORTED_RELEASE_MAJOR,
    is_supported_release_version,
)


class CommandRunner(Protocol):
    """Run one release-build command from its supplied working directory."""

    def __call__(self, command: Sequence[str], cwd: Path) -> None: ...


@dataclass(frozen=True)
class ReleaseBundle:
    """Paths to the immutable release assets written by one build."""

    output_dir: Path
    executable: Path
    installer: Path
    manifest: Path
    checksums: Path


def _run_command(command: Sequence[str], cwd: Path) -> None:
    subprocess.run(list(command), cwd=cwd, check=True)


def _source_commit(repo_root: Path) -> str:
    """Resolve the immutable source identity for a local or CI bundle."""
    environment_commit = os.environ.get("GITHUB_SHA")
    if environment_commit:
        return environment_commit
    result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _render_installer(
    template: Path,
    *,
    version: str,
    executable: Path,
    manifest_payload: str,
    platform_id: PlatformId,
) -> str:
    payload = executable.read_bytes()
    managed_os_cases = "|".join(
        f"{os_id}:{version}"
        for os_id, versions in SUPPORTED_MANAGED_DISTRIBUTIONS
        for version in versions
    )
    replacements = {
        "@VERSION@": version,
        "@EXECUTABLE_NAME@": executable.name,
        "@EXECUTABLE_SIZE@": str(len(payload)),
        "@EXECUTABLE_SHA256@": hashlib.sha256(payload).hexdigest(),
        "@MANIFEST_JSON@": manifest_payload.rstrip("\n"),
        "@PLATFORM_ID@": platform_id,
        "@MACHINE_CASE_PATTERN@": "|".join(machine_aliases(platform_id)),
        "@MANAGED_HOST_DESCRIPTION@": SUPPORTED_MANAGED_HOST_SUMMARY,
        "@MANAGED_OS_CASE_PATTERN@": managed_os_cases,
        "@MAX_ARTIFACT_DIGESTS@": str(MAX_ARTIFACT_DIGESTS),
        "@PLATFORM_DESCRIPTION@": platform_display_name(platform_id),
        "@SUPPORTED_RELEASE_MAJOR@": SUPPORTED_RELEASE_MAJOR,
        "@UNSUPPORTED_MANAGED_STATE_INSTRUCTIONS@": UNSUPPORTED_MANAGED_STATE_INSTRUCTIONS,
    }
    rendered = template.read_text(encoding="utf-8")
    for token, value in replacements.items():
        rendered = rendered.replace(token, value)
    if "@" in rendered:
        raise ValueError("installer template contains an unresolved placeholder")
    return rendered


def _single_wheel(wheel_dir: Path) -> Path:
    wheels = sorted(wheel_dir.glob("xferry-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one xferry wheel in {wheel_dir}, found {len(wheels)}")
    return wheels[0]


def _validate_scie_wheel(wheel: Path) -> None:
    """Reject a SCIE input wheel that carries an internal repository surface."""
    try:
        from tools.verify_python_artifacts import (
            ArtifactValidationError,
            validate_public_surface_members,
        )
    except ModuleNotFoundError:  # pragma: no cover - direct script execution
        from verify_python_artifacts import (
            ArtifactValidationError,
            validate_public_surface_members,
        )

    try:
        with zipfile.ZipFile(wheel) as archive:
            validate_public_surface_members(archive.namelist(), artifact_label=wheel.name)
    except (ArtifactValidationError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f"SCIE wheel violates public-surface policy: {exc}") from exc


def build_release_bundle(
    repo_root: Path,
    output_dir: Path,
    version: str,
    runner: CommandRunner,
    *,
    platform_id: PlatformId,
    source_commit: str | None = None,
    workflow_run: str | None = None,
) -> ReleaseBundle:
    """Build one native pinned-CPython SCIE and its bootstrap metadata."""

    if not is_supported_release_version(version):
        raise ValueError("release bundle version must belong to the supported release line")
    repo_root = repo_root.resolve()
    selected_platform = require_platform_id(platform_id)
    build_host_platform = current_platform_id()
    if build_host_platform != selected_platform:
        raise RuntimeError(
            f"requested SCIE platform {selected_platform} does not match "
            f"build host {build_host_platform}; use a native matching runner"
        )
    selected_source_commit = require_source_commit(
        _source_commit(repo_root) if source_commit is None else source_commit
    )
    selected_workflow_run = require_workflow_run(
        os.environ.get("GITHUB_RUN_ID", "local") if workflow_run is None else workflow_run
    )
    output_dir = output_dir.resolve()
    if output_dir.is_symlink() or output_dir.exists():
        raise ValueError("SCIE output directory must not already exist")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    executable_name = artifact_name(version, selected_platform)
    with TemporaryDirectory(prefix=".xferry-scie-", dir=output_dir.parent) as temporary_dir:
        staging_dir = Path(temporary_dir)
        wheel_dir = staging_dir / "wheel"
        lock = staging_dir / "xferry-release.lock.json"
        bundle_dir = staging_dir / "bundle"
        bundle_dir.mkdir()
        executable = bundle_dir / executable_name
        runner(
            ["python", "-m", "build", "--wheel", "--outdir", str(wheel_dir)],
            repo_root,
        )
        wheel = _single_wheel(wheel_dir)
        _validate_scie_wheel(wheel)
        runner(
            [
                "pex3",
                "lock",
                "create",
                "--style",
                "strict",
                "--constraint",
                "constraints/ci.txt",
                str(wheel),
                "-o",
                str(lock),
            ],
            repo_root,
        )
        runner(
            [
                "pex",
                "--lock",
                str(lock),
                "-c",
                "xferry",
                "--scie",
                "eager",
                "--scie-only",
                "--scie-platform",
                selected_platform,
                "--interpreter-constraint",
                "CPython>=3.12,<3.13",
                "-o",
                str(executable),
            ],
            repo_root,
        )
        candidates = sorted(bundle_dir.glob("xferry-*-linux-*"))
        if candidates != [executable] or not executable.is_file():
            raise RuntimeError(
                "PEX must produce exactly one SCIE executable for the requested platform"
            )

        payload = executable.read_bytes()
        sha256 = hashlib.sha256(payload).hexdigest()
        release_manifest = ReleaseManifest.create_v2(
            version=version,
            platform=selected_platform,
            executable_size=len(payload),
            executable_sha256=sha256,
            source_commit=selected_source_commit,
            workflow_run=selected_workflow_run,
        )
        manifest_payload = release_manifest.to_bytes().decode("utf-8")
        manifest = bundle_dir / "xferry-release.json"
        manifest.write_text(manifest_payload, encoding="utf-8")
        checksums = bundle_dir / "SHA256SUMS"
        checksums.write_text(f"{sha256}  {executable_name}\n", encoding="utf-8")
        installer = bundle_dir / "install.sh"
        installer.write_text(
            _render_installer(
                repo_root / "packaging" / "install.sh.in",
                version=version,
                executable=executable,
                manifest_payload=manifest_payload,
                platform_id=selected_platform,
            ),
            encoding="utf-8",
        )
        installer.chmod(0o755)
        bundle_dir.replace(output_dir)

    return ReleaseBundle(
        output_dir,
        output_dir / executable_name,
        output_dir / "install.sh",
        output_dir / "xferry-release.json",
        output_dir / "SHA256SUMS",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--platform", choices=SUPPORTED_PLATFORM_IDS, required=True)
    parser.add_argument("--version")
    parser.add_argument("--source-commit")
    parser.add_argument("--workflow-run")
    arguments = parser.parse_args(argv)
    version = arguments.version
    if version is None:
        from xferry.config import __version__

        version = __version__
    bundle = build_release_bundle(
        REPO_ROOT,
        arguments.output_dir,
        version,
        _run_command,
        platform_id=arguments.platform,
        source_commit=arguments.source_commit,
        workflow_run=arguments.workflow_run,
    )
    for asset in (bundle.executable, bundle.installer, bundle.manifest, bundle.checksums):
        print(asset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
