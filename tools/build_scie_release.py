"""Build the deterministic SCIE assets verified by the release workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
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


def _render_installer(
    template: Path,
    *,
    version: str,
    executable: Path,
    manifest_payload: str,
) -> str:
    payload = executable.read_bytes()
    replacements = {
        "@VERSION@": version,
        "@EXECUTABLE_NAME@": executable.name,
        "@EXECUTABLE_SIZE@": str(len(payload)),
        "@EXECUTABLE_SHA256@": hashlib.sha256(payload).hexdigest(),
        "@MANIFEST_JSON@": manifest_payload.rstrip("\n"),
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
) -> ReleaseBundle:
    """Build a pinned CPython 3.12 eager SCIE and its bootstrap metadata."""

    if not is_supported_release_version(version):
        raise ValueError("release bundle version must belong to the supported release line")
    repo_root = repo_root.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    executable_name = f"xferry-{version}-linux-x86_64"
    executable = output_dir / executable_name
    with TemporaryDirectory(prefix="xferry-scie-") as temporary_dir:
        staging_dir = Path(temporary_dir)
        wheel_dir = staging_dir / "wheel"
        lock = staging_dir / "xferry-release.lock.json"
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
                "--interpreter-constraint",
                "CPython>=3.12,<3.13",
                "-o",
                str(executable),
            ],
            repo_root,
        )
    if not executable.is_file():
        raise RuntimeError("PEX did not produce the SCIE executable")

    payload = executable.read_bytes()
    sha256 = hashlib.sha256(payload).hexdigest()
    manifest_payload = (
        json.dumps(
            {
                "schema_version": 1,
                "version": version,
                "tag": f"v{version}",
                "platform": "linux-x86_64",
                "executable": {
                    "name": executable_name,
                    "size": len(payload),
                    "sha256": sha256,
                },
            },
            indent=2,
        )
        + "\n"
    )
    manifest = output_dir / "xferry-release.json"
    manifest.write_text(manifest_payload, encoding="utf-8")
    checksums = output_dir / "SHA256SUMS"
    checksums.write_text(f"{sha256}  {executable_name}\n", encoding="utf-8")
    installer = output_dir / "install.sh"
    installer.write_text(
        _render_installer(
            repo_root / "packaging" / "install.sh.in",
            version=version,
            executable=executable,
            manifest_payload=manifest_payload,
        ),
        encoding="utf-8",
    )
    installer.chmod(0o755)
    return ReleaseBundle(output_dir, executable, installer, manifest, checksums)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version")
    arguments = parser.parse_args(argv)
    version = arguments.version
    if version is None:
        from xferry.config import __version__

        version = __version__
    bundle = build_release_bundle(REPO_ROOT, arguments.output_dir, version, _run_command)
    for asset in (bundle.executable, bundle.installer, bundle.manifest, bundle.checksums):
        print(asset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
