"""Offline verification for one executable and its signed release envelope."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

from .channels import Channel, key_ring_for_channel, validate_version_for_channel
from .release_contract import MAX_MANIFEST_BYTES, PlatformId, ReleaseManifest, require_platform_id
from .release_trust import (
    MAX_SIGNATURE_BYTES,
    ReleaseKeyRing,
    ReleaseTrustError,
    verify_signed_manifest,
)


class ReleaseEnvelopeError(ValueError):
    """Stable, secret-free failure raised by the installer verification boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _read_regular(path: Path, maximum: int, code: str) -> bytes:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum
        ):
            raise OSError
        payload = path.read_bytes()
        if len(payload) != metadata.st_size:
            raise OSError
        return payload
    except OSError:
        raise ReleaseEnvelopeError(code) from None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise ReleaseEnvelopeError("release_integrity_failed") from None
    return digest.hexdigest()


def verify_release_envelope(
    manifest_path: Path,
    signature_path: Path,
    executable_path: Path,
    *,
    expected_version: str,
    expected_platform: PlatformId,
    key_ring: ReleaseKeyRing | None = None,
    channel: Channel = "stable",
) -> ReleaseManifest:
    """Verify exact signed metadata and bind it to one already-authenticated executable."""
    try:
        validate_version_for_channel(expected_version, channel)
    except ValueError:
        raise ReleaseEnvelopeError("invalid_release_version") from None
    try:
        selected_platform = require_platform_id(expected_platform)
    except ValueError:
        raise ReleaseEnvelopeError("release_platform_unsupported") from None

    manifest_payload = _read_regular(
        manifest_path,
        MAX_MANIFEST_BYTES,
        "release_manifest_invalid",
    )
    signature_payload = _read_regular(
        signature_path,
        MAX_SIGNATURE_BYTES,
        "release_signature_invalid",
    )
    try:
        manifest = verify_signed_manifest(
            manifest_payload,
            signature_payload,
            key_ring=key_ring or key_ring_for_channel(channel),
            channel=channel,
        )
    except ReleaseTrustError as failure:
        raise ReleaseEnvelopeError(failure.code) from None

    if manifest.version != expected_version:
        raise ReleaseEnvelopeError("release_manifest_mismatch")
    if manifest.platform != selected_platform:
        raise ReleaseEnvelopeError("release_platform_unsupported")
    try:
        executable = executable_path.lstat()
        if not stat.S_ISREG(executable.st_mode) or executable.st_nlink != 1:
            raise OSError
    except OSError:
        raise ReleaseEnvelopeError("release_integrity_failed") from None
    if (
        executable.st_size != manifest.executable_size
        or _sha256(executable_path) != manifest.executable_sha256
    ):
        raise ReleaseEnvelopeError("release_integrity_failed")
    return manifest
