"""Install an exact signed managed release without a source checkout."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .execution import ProcessRunner, ReadDownloader
from .release_contract import (
    MAX_MANIFEST_BYTES,
    current_platform_id,
    release_manifest_asset_name,
    require_platform_id,
)
from .release_trust import (
    DEFAULT_RELEASE_KEY_RING,
    INSTALLER_SIGNATURE_TYPE,
    MAX_SIGNATURE_BYTES,
    ReleaseKeyRing,
    ReleaseTrustError,
    verify_detached_signature,
    verify_signed_manifest,
)
from .versions import is_supported_release_version


@dataclass(frozen=True)
class InstallResult:
    exit_code: int
    message: str
    version: str | None = None
    dry_run: bool = False


def install_release(
    version: str,
    *,
    dry_run: bool = False,
    runner: ProcessRunner | None = None,
    downloader: ReadDownloader | None = None,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> InstallResult:
    """Authenticate manifest and installer bytes before any privileged execution."""
    if not is_supported_release_version(version):
        return InstallResult(2, "an exact supported release version is required")
    if not dry_run and os.geteuid() != 0:
        return InstallResult(3, "managed installation requires root", version)
    from .platform import detect_host_facts
    from .releases import HttpsDownloader

    try:
        facts = detect_host_facts()
        if not facts.is_supported:
            return InstallResult(4, facts.managed_support_detail, version, dry_run)
        platform = require_platform_id(current_platform_id())
        client = downloader or HttpsDownloader()
        base = f"https://github.com/kgmnotes/xferry/releases/download/v{version}"
        manifest_name = release_manifest_asset_name(platform)
        payload = client.read(f"{base}/{manifest_name}", MAX_MANIFEST_BYTES)
        signature = client.read(f"{base}/{manifest_name}.sig", MAX_SIGNATURE_BYTES)
        manifest = verify_signed_manifest(payload, signature, key_ring=key_ring)
        if manifest.version != version or manifest.platform != platform:
            return InstallResult(1, "release identity mismatch", version, dry_run)
        name = f"install-{platform}.sh"
        installer = client.read(f"{base}/{name}", 1024 * 1024)
        installer_signature = client.read(f"{base}/{name}.sig", MAX_SIGNATURE_BYTES)
        verify_detached_signature(
            installer,
            installer_signature,
            payload_type=INSTALLER_SIGNATURE_TYPE,
            key_ring=key_ring,
        )
        if dict(manifest.artifact_digests).get(name) != hashlib.sha256(installer).hexdigest():
            return InstallResult(1, "installer does not match signed release", version, dry_run)
        if dry_run:
            return InstallResult(0, "signed release and installer verified", version, True)
        with tempfile.TemporaryDirectory(prefix="xferry-install-") as temporary:
            path = Path(temporary) / name
            path.write_bytes(installer)
            path.chmod(0o600)
            argv = ("sh", str(path))
            if runner is None:
                environment = {
                    key: value
                    for key, value in os.environ.items()
                    if key not in {"DESTDIR", "XFERRY_RELEASE_BASE_URL", "ENV", "BASH_ENV"}
                }
                code = subprocess.run(argv, check=False, env=environment).returncode
            else:
                code = runner.run(argv).returncode
        return InstallResult(
            code, "managed release installed" if code == 0 else "installer failed", version
        )
    except ReleaseTrustError:
        return InstallResult(1, "release signature verification failed", version, dry_run)
    except (OSError, ValueError, RuntimeError):
        return InstallResult(1, "release installation failed before activation", version, dry_run)
