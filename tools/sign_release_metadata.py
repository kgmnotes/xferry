"""Sign an already-built canonical XFerry release manifest with an external key."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xferry.management.release_trust import (  # noqa: E402
    INSTALLER_SIGNATURE_TYPE,
    MANIFEST_SIGNATURE_TYPE,
    create_detached_signature,
    parse_signed_manifest,
)

_MAX_PRIVATE_KEY_BYTES = 64 * 1024


def _read_private_key_path(path: Path) -> bytes:
    """Read a permission-restricted regular file without following a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("private key path must be one regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("private key path must not be accessible by group or other users")
        return _read_bounded(stream)


def _read_bounded(stream: BinaryIO) -> bytes:
    payload = stream.read(_MAX_PRIVATE_KEY_BYTES + 1)
    if not payload or len(payload) > _MAX_PRIVATE_KEY_BYTES:
        raise ValueError("private key input is empty or too large")
    return payload


def _read_private_key_fd(descriptor: int) -> bytes:
    if descriptor < 0:
        raise ValueError("private key descriptor must be non-negative")
    with os.fdopen(os.dup(descriptor), "rb", closefd=True) as stream:
        return _read_bounded(stream)


def _load_private_key(payload: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(payload, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    return key


def sign_manifest(
    manifest_payload: bytes,
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> bytes:
    """Validate then sign the exact canonical manifest bytes without rebuilding assets."""
    manifest = parse_signed_manifest(manifest_payload)
    if manifest.signing_key_ids != (key_id,):
        raise ValueError("manifest signing key ID does not match the selected private key")
    return create_detached_signature(
        manifest_payload,
        payload_type=MANIFEST_SIGNATURE_TYPE,
        key_id=key_id,
        signer=private_key,
    )


def sign_installer(
    installer_payload: bytes,
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> bytes:
    """Sign an already-built installer under a distinct signature domain."""
    return create_detached_signature(
        installer_payload,
        payload_type=INSTALLER_SIGNATURE_TYPE,
        key_id=key_id,
        signer=private_key,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    payload_input = parser.add_mutually_exclusive_group(required=True)
    payload_input.add_argument("--manifest", type=Path)
    payload_input.add_argument("--installer", type=Path)
    parser.add_argument("--signature-output", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    private_input = parser.add_mutually_exclusive_group(required=True)
    private_input.add_argument("--private-key", type=Path)
    private_input.add_argument("--private-key-fd", type=int)
    arguments = parser.parse_args(argv)

    payload_path = arguments.manifest or arguments.installer
    payload = payload_path.read_bytes()
    key_payload = (
        _read_private_key_path(arguments.private_key)
        if arguments.private_key is not None
        else _read_private_key_fd(arguments.private_key_fd)
    )
    private_key = _load_private_key(key_payload)
    signature_payload = (
        sign_manifest(
            payload,
            key_id=arguments.key_id,
            private_key=private_key,
        )
        if arguments.manifest is not None
        else sign_installer(
            payload,
            key_id=arguments.key_id,
            private_key=private_key,
        )
    )

    output = arguments.signature_output
    with output.open("xb") as stream:
        stream.write(signature_payload)
        stream.flush()
        os.fsync(stream.fileno())
    output.chmod(0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
