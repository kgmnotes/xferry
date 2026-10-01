"""Offline Ed25519 trust for canonical release metadata and installer assets."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Literal, NoReturn, Protocol, TypeAlias

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .release_contract import (
    MANIFEST_NAME,
    ReleaseManifest,
    require_signing_key_id,
)
from .release_contract import (
    MAX_SIGNATURE_BYTES as MAX_SIGNATURE_BYTES,
)

SIGNATURE_NAME = f"{MANIFEST_NAME}.sig"
SignatureType: TypeAlias = Literal["release-manifest-v2", "installer-v1"]
MANIFEST_SIGNATURE_TYPE: Literal["release-manifest-v2"] = "release-manifest-v2"
INSTALLER_SIGNATURE_TYPE: Literal["installer-v1"] = "installer-v1"
_SIGNATURE_CONTEXT = b"xferry-release-signature-v1\x00"
_ED25519_SIGNATURE_BYTES = 64
_ED25519_PUBLIC_KEY_BYTES = 32


class ReleaseTrustError(ValueError):
    """Stable, secret-free trust failure suitable for a release result code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ReleaseKeyStatus(Enum):
    """Reviewed lifecycle state for one embedded publisher public key."""

    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True)
class TrustedReleaseKey:
    """One public Ed25519 trust root and its local revocation state."""

    key_id: str
    public_key: bytes
    status: ReleaseKeyStatus = ReleaseKeyStatus.ACTIVE

    def __post_init__(self) -> None:
        require_signing_key_id(self.key_id)
        if (
            not isinstance(self.public_key, bytes)
            or len(self.public_key) != _ED25519_PUBLIC_KEY_BYTES
        ):
            raise ValueError("invalid Ed25519 public key")
        if not isinstance(self.status, ReleaseKeyStatus):
            raise ValueError("invalid release key status")


class ReleaseKeyRing:
    """Immutable, duplicate-free set of active and revoked release keys."""

    def __init__(self, keys: Sequence[TrustedReleaseKey]) -> None:
        selected = tuple(keys)
        key_ids = tuple(key.key_id for key in selected)
        if len(key_ids) != len(set(key_ids)):
            raise ValueError("duplicate release signing key ID")
        self._keys = selected
        self._by_id = {key.key_id: key for key in selected}

    @property
    def keys(self) -> tuple[TrustedReleaseKey, ...]:
        return self._keys

    def get(self, key_id: str) -> TrustedReleaseKey | None:
        return self._by_id.get(key_id)


# Owner-approved production trust roots. Private material is held only by the
# protected GitHub ``production-release`` environment; never add it here.
EMBEDDED_RELEASE_KEYS: tuple[TrustedReleaseKey, ...] = (
    TrustedReleaseKey(
        key_id="xferry-release-2026-09",
        public_key=bytes.fromhex(
            "4fe9ccd46e154ff6d866957995395993a584f50c80e3384d5db4068791684efc"
        ),
    ),
)
DEFAULT_RELEASE_KEY_RING = ReleaseKeyRing(EMBEDDED_RELEASE_KEYS)


class _Signer(Protocol):
    def sign(self, data: bytes) -> bytes: ...


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate signature key")
        document[key] = value
    return document


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON value")


def _require_signature_type(value: object) -> SignatureType:
    if value == MANIFEST_SIGNATURE_TYPE:
        return MANIFEST_SIGNATURE_TYPE
    if value == INSTALLER_SIGNATURE_TYPE:
        return INSTALLER_SIGNATURE_TYPE
    raise ValueError("invalid signature payload type")


def _signature_message(payload: bytes, payload_type: SignatureType, key_id: str) -> bytes:
    """Domain-separate the exact payload and bind its selected key identifier."""
    return (
        _SIGNATURE_CONTEXT
        + payload_type.encode("ascii")
        + b"\x00"
        + key_id.encode("ascii")
        + b"\x00"
        + payload
    )


@dataclass(frozen=True)
class DetachedReleaseSignature:
    """Strict canonical detached-signature envelope."""

    key_id: str
    payload_type: SignatureType
    signature: bytes

    @classmethod
    def parse(cls, payload: bytes) -> DetachedReleaseSignature:
        try:
            if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_SIGNATURE_BYTES:
                raise ValueError
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
            if not isinstance(document, dict) or set(document) != {
                "schema_version",
                "algorithm",
                "key_id",
                "payload_type",
                "signature",
            }:
                raise ValueError
            schema_version = document["schema_version"]
            if (
                isinstance(schema_version, bool)
                or schema_version != 1
                or document["algorithm"] != "ed25519"
            ):
                raise ValueError
            key_id = require_signing_key_id(document["key_id"])
            payload_type = _require_signature_type(document["payload_type"])
            encoded_signature = document["signature"]
            if not isinstance(encoded_signature, str) or not encoded_signature.isascii():
                raise ValueError
            signature = base64.b64decode(encoded_signature, validate=True)
            if (
                len(signature) != _ED25519_SIGNATURE_BYTES
                or base64.b64encode(signature).decode("ascii") != encoded_signature
            ):
                raise ValueError
            parsed = cls(key_id, payload_type, signature)
            if parsed.to_bytes() != payload:
                raise ValueError
            return parsed
        except (
            UnicodeError,
            json.JSONDecodeError,
            binascii.Error,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise ReleaseTrustError("release_signature_invalid") from None

    def to_bytes(self) -> bytes:
        document = {
            "schema_version": 1,
            "algorithm": "ed25519",
            "key_id": require_signing_key_id(self.key_id),
            "payload_type": _require_signature_type(self.payload_type),
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }
        if len(self.signature) != _ED25519_SIGNATURE_BYTES:
            raise ValueError("invalid Ed25519 signature")
        return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def create_detached_signature(
    payload: bytes,
    *,
    payload_type: SignatureType,
    key_id: str,
    signer: _Signer,
) -> bytes:
    """Sign exact already-built bytes without exposing or serializing the signer."""
    selected_type = _require_signature_type(payload_type)
    selected_key_id = require_signing_key_id(key_id)
    signature = signer.sign(_signature_message(payload, selected_type, selected_key_id))
    return DetachedReleaseSignature(selected_key_id, selected_type, signature).to_bytes()


def parse_signed_manifest(payload: bytes) -> ReleaseManifest:
    """Parse one canonical signed v2 manifest before trusting any of its references."""
    try:
        manifest = ReleaseManifest.parse_new(payload)
    except ValueError:
        raise ReleaseTrustError("release_manifest_invalid") from None
    if manifest.signing_scheme != "ed25519" or not manifest.signing_key_ids:
        raise ReleaseTrustError("release_manifest_unsigned")
    if manifest.to_bytes() != payload:
        raise ReleaseTrustError("release_manifest_noncanonical")
    return manifest


def verify_detached_signature(
    payload: bytes,
    signature_payload: bytes,
    *,
    payload_type: SignatureType,
    key_ring: ReleaseKeyRing,
) -> str:
    """Verify exact bytes against an active key and return its stable key ID."""
    envelope = DetachedReleaseSignature.parse(signature_payload)
    if envelope.payload_type != payload_type:
        raise ReleaseTrustError("release_signature_invalid")
    trusted_key = key_ring.get(envelope.key_id)
    if trusted_key is None:
        raise ReleaseTrustError("release_signing_key_unknown")
    if trusted_key.status is ReleaseKeyStatus.REVOKED:
        raise ReleaseTrustError("release_signing_key_revoked")
    try:
        verifier = Ed25519PublicKey.from_public_bytes(trusted_key.public_key)
        verifier.verify(
            envelope.signature,
            _signature_message(payload, envelope.payload_type, envelope.key_id),
        )
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        raise ReleaseTrustError("release_signature_invalid") from None
    return envelope.key_id


def verify_manifest_signature(
    payload: bytes,
    manifest: ReleaseManifest,
    signature_payload: bytes,
    *,
    key_ring: ReleaseKeyRing,
) -> None:
    """Authenticate a parsed canonical manifest and bind its declared signer."""
    key_id = verify_detached_signature(
        payload,
        signature_payload,
        payload_type=MANIFEST_SIGNATURE_TYPE,
        key_ring=key_ring,
    )
    if manifest.signing_key_ids != (key_id,):
        raise ReleaseTrustError("release_signature_invalid")


def verify_signed_manifest(
    payload: bytes,
    signature_payload: bytes,
    *,
    key_ring: ReleaseKeyRing = DEFAULT_RELEASE_KEY_RING,
) -> ReleaseManifest:
    """Parse and verify canonical v2 metadata using only the selected local key ring."""
    manifest = parse_signed_manifest(payload)
    verify_manifest_signature(payload, manifest, signature_payload, key_ring=key_ring)
    return manifest
