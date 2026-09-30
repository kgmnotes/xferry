"""Verify XFerry release metadata or an installer with the embedded public-key ring."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xferry.management.release_trust import (  # noqa: E402
    DEFAULT_RELEASE_KEY_RING,
    INSTALLER_SIGNATURE_TYPE,
    ReleaseKeyRing,
    verify_detached_signature,
    verify_signed_manifest,
)


def verify_manifest_files(
    manifest: Path,
    signature: Path,
    *,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> None:
    """Authenticate a local manifest without network access."""
    verify_signed_manifest(
        manifest.read_bytes(),
        signature.read_bytes(),
        key_ring=key_ring,
    )


def verify_installer_files(
    installer: Path,
    signature: Path,
    *,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> None:
    """Authenticate installer bytes before any privileged execution."""
    verify_detached_signature(
        installer.read_bytes(),
        signature.read_bytes(),
        payload_type=INSTALLER_SIGNATURE_TYPE,
        key_ring=key_ring,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    payload = parser.add_mutually_exclusive_group(required=True)
    payload.add_argument("--manifest", type=Path)
    payload.add_argument("--installer", type=Path)
    parser.add_argument("--signature", type=Path, required=True)
    arguments = parser.parse_args(argv)

    if arguments.manifest is not None:
        verify_manifest_files(arguments.manifest, arguments.signature)
    else:
        verify_installer_files(arguments.installer, arguments.signature)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
