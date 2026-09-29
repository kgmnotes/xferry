"""EUF v1 client-encrypted transfer primitives."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

EUF_VERSION = 1
EUF_CHUNK_SIZE = 8 * 1024 * 1024
EUF_MAX_FILE_SIZE = 2048 * 1024 * 1024
EUF_PBKDF2_ITERATIONS = 600_000
EUF_GCM_TAG_SIZE = 16
EUF_MAX_METADATA_SIZE = 4096
EUF_METADATA_INDEX = 0xFFFFFFFF

_METADATA_AAD_PREFIX = b"XFERRY-EUF1-META\0"
_CHUNK_AAD_PREFIX = b"XFERRY-EUF1-CHUNK\0"
_RESUME_PREFIX = b"XFERRY-EUF1-RESUME\0"


class EncryptedTransferValidationError(ValueError):
    """Raised when an EUF value is not canonical or violates the v1 contract."""


@dataclass(frozen=True, slots=True)
class EncryptedTransferManifest:
    """Validated public manifest for one EUF v1 encrypted file."""

    file_id: str
    plaintext_size: int
    chunk_size: int
    chunk_count: int
    salt: bytes
    nonce_prefix: bytes
    encrypted_metadata: bytes
    version: int = EUF_VERSION

    def __post_init__(self) -> None:
        file_id_bytes(self.file_id)
        if self.version != EUF_VERSION:
            raise EncryptedTransferValidationError("version must be 1")
        if (
            isinstance(self.plaintext_size, bool)
            or not isinstance(self.plaintext_size, int)
            or not 0 <= self.plaintext_size <= EUF_MAX_FILE_SIZE
        ):
            raise EncryptedTransferValidationError(
                f"plaintext_size must be between 0 and {EUF_MAX_FILE_SIZE}"
            )
        if self.chunk_size != EUF_CHUNK_SIZE:
            raise EncryptedTransferValidationError(f"chunk_size must be exactly {EUF_CHUNK_SIZE}")
        expected_count = math.ceil(self.plaintext_size / self.chunk_size)
        if self.chunk_count != expected_count:
            raise EncryptedTransferValidationError(f"chunk_count must be exactly {expected_count}")
        if not isinstance(self.salt, bytes) or len(self.salt) != 16:
            raise EncryptedTransferValidationError("salt must contain exactly 16 bytes")
        if not isinstance(self.nonce_prefix, bytes) or len(self.nonce_prefix) != 8:
            raise EncryptedTransferValidationError("nonce_prefix must contain exactly 8 bytes")
        metadata_limit = EUF_MAX_METADATA_SIZE + EUF_GCM_TAG_SIZE
        if (
            not isinstance(self.encrypted_metadata, bytes)
            or not EUF_GCM_TAG_SIZE <= len(self.encrypted_metadata) <= metadata_limit
        ):
            raise EncryptedTransferValidationError(
                f"encrypted_metadata must contain between {EUF_GCM_TAG_SIZE} "
                f"and {metadata_limit} bytes"
            )

    @property
    def ciphertext_size(self) -> int:
        """Return the exact concatenated ciphertext size."""
        return self.plaintext_size + self.chunk_count * EUF_GCM_TAG_SIZE


@dataclass(frozen=True, slots=True)
class EncryptedFileMetadata:
    """Private metadata encrypted with the reserved EUF metadata nonce."""

    name: str
    content_type: str
    last_modified_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or "\x00" in self.name:
            raise EncryptedTransferValidationError("metadata name must be a non-empty string")
        if (
            not isinstance(self.content_type, str)
            or "\r" in self.content_type
            or "\n" in self.content_type
        ):
            raise EncryptedTransferValidationError("metadata content_type must be header-safe text")
        if (
            isinstance(self.last_modified_ms, bool)
            or not isinstance(self.last_modified_ms, int)
            or not 0 <= self.last_modified_ms <= 9_007_199_254_740_991
        ):
            raise EncryptedTransferValidationError(
                "metadata last_modified_ms must be a non-negative safe integer"
            )


def b64url_encode(data: bytes) -> str:
    """Encode bytes as canonical unpadded base64url."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str, *, field: str) -> bytes:
    """Decode one canonical unpadded base64url field."""
    if not isinstance(value, str) or _BASE64URL_RE.fullmatch(value) is None:
        raise EncryptedTransferValidationError(f"{field} must be unpadded base64url")
    if len(value) % 4 == 1:
        raise EncryptedTransferValidationError(f"{field} must be unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise EncryptedTransferValidationError(f"{field} must be unpadded base64url") from None
    if b64url_encode(decoded) != value:
        raise EncryptedTransferValidationError(f"{field} must be canonical base64url")
    return decoded


def file_id_bytes(file_id: str) -> bytes:
    """Return the 16 bytes represented by one canonical EUF file ID."""
    if not isinstance(file_id, str) or _FILE_ID_RE.fullmatch(file_id) is None:
        raise EncryptedTransferValidationError(
            "file_id must be exactly 32 lowercase hexadecimal characters"
        )
    return bytes.fromhex(file_id)


def derive_keys(password: str, *, salt: bytes, file_id: str) -> tuple[bytes, bytes]:
    """Derive the independent EUF v1 content and resume keys."""
    if not isinstance(password, str) or len(password) < 14:
        raise EncryptedTransferValidationError(
            "password must contain at least 14 Unicode code points"
        )
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 1024:
        raise EncryptedTransferValidationError("password must not exceed 1024 UTF-8 bytes")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise EncryptedTransferValidationError("salt must contain exactly 16 bytes")
    file_id_raw = file_id_bytes(file_id)
    master_key = hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        salt,
        EUF_PBKDF2_ITERATIONS,
        dklen=32,
    )

    def expand(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=file_id_raw,
            info=info,
        ).derive(master_key)

    return expand(b"xferry-euf-v1/content"), expand(b"xferry-euf-v1/resume")


def metadata_aad(manifest: EncryptedTransferManifest) -> bytes:
    """Build the canonical authenticated metadata context."""
    return (
        _METADATA_AAD_PREFIX
        + file_id_bytes(manifest.file_id)
        + struct.pack(
            ">QII",
            manifest.plaintext_size,
            manifest.chunk_size,
            manifest.chunk_count,
        )
    )


def chunk_aad(
    manifest: EncryptedTransferManifest,
    *,
    index: int,
    plaintext_length: int,
) -> bytes:
    """Build the canonical authenticated context for one content chunk."""
    if (
        isinstance(index, bool)
        or not isinstance(index, int)
        or not 0 <= index < manifest.chunk_count
    ):
        raise EncryptedTransferValidationError("chunk index is outside the manifest")
    expected_length = min(
        manifest.chunk_size,
        manifest.plaintext_size - index * manifest.chunk_size,
    )
    if plaintext_length != expected_length:
        raise EncryptedTransferValidationError(
            f"plaintext_length must be exactly {expected_length} for chunk {index}"
        )
    return (
        _CHUNK_AAD_PREFIX
        + file_id_bytes(manifest.file_id)
        + struct.pack(
            ">QIIII",
            manifest.plaintext_size,
            manifest.chunk_size,
            manifest.chunk_count,
            index,
            plaintext_length,
        )
    )


def _require_aes_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise EncryptedTransferValidationError("AES content key must contain exactly 32 bytes")


def _nonce(manifest: EncryptedTransferManifest, index: int) -> bytes:
    return manifest.nonce_prefix + struct.pack(">I", index)


def _metadata_json(metadata: EncryptedFileMetadata) -> bytes:
    encoded = json.dumps(
        {
            "name": metadata.name,
            "content_type": metadata.content_type,
            "last_modified_ms": metadata.last_modified_ms,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > EUF_MAX_METADATA_SIZE:
        raise EncryptedTransferValidationError(
            f"metadata JSON must not exceed {EUF_MAX_METADATA_SIZE} bytes"
        )
    return encoded


def encrypt_metadata(
    metadata: EncryptedFileMetadata,
    *,
    key: bytes,
    manifest: EncryptedTransferManifest,
) -> bytes:
    """Encrypt the canonical private metadata JSON."""
    _require_aes_key(key)
    return AESGCM(key).encrypt(
        _nonce(manifest, EUF_METADATA_INDEX),
        _metadata_json(metadata),
        metadata_aad(manifest),
    )


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate metadata field")
        result[name] = value
    return result


def decrypt_metadata(
    *,
    key: bytes,
    manifest: EncryptedTransferManifest,
) -> EncryptedFileMetadata | None:
    """Authenticate and decode private metadata, returning ``None`` on failure."""
    _require_aes_key(key)
    try:
        plaintext = AESGCM(key).decrypt(
            _nonce(manifest, EUF_METADATA_INDEX),
            manifest.encrypted_metadata,
            metadata_aad(manifest),
        )
        if len(plaintext) > EUF_MAX_METADATA_SIZE:
            return None
        decoded = json.loads(
            plaintext.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_members,
        )
        if not isinstance(decoded, dict) or set(decoded) != {
            "name",
            "content_type",
            "last_modified_ms",
        }:
            return None
        return EncryptedFileMetadata(
            name=decoded["name"],
            content_type=decoded["content_type"],
            last_modified_ms=decoded["last_modified_ms"],
        )
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return None


def encrypt_chunk(
    plaintext: bytes,
    *,
    key: bytes,
    manifest: EncryptedTransferManifest,
    index: int,
) -> bytes:
    """Encrypt one exact-position plaintext chunk."""
    _require_aes_key(key)
    if not isinstance(plaintext, bytes):
        raise EncryptedTransferValidationError("chunk plaintext must be bytes")
    aad = chunk_aad(manifest, index=index, plaintext_length=len(plaintext))
    return AESGCM(key).encrypt(_nonce(manifest, index), plaintext, aad)


def decrypt_chunk(
    ciphertext: bytes,
    *,
    key: bytes,
    manifest: EncryptedTransferManifest,
    index: int,
) -> bytes | None:
    """Authenticate and decrypt one exact-position ciphertext chunk."""
    _require_aes_key(key)
    plaintext_length = min(
        manifest.chunk_size,
        manifest.plaintext_size - index * manifest.chunk_size,
    )
    aad = chunk_aad(manifest, index=index, plaintext_length=plaintext_length)
    if not isinstance(ciphertext, bytes) or len(ciphertext) != plaintext_length + EUF_GCM_TAG_SIZE:
        return None
    try:
        return AESGCM(key).decrypt(_nonce(manifest, index), ciphertext, aad)
    except InvalidTag:
        return None


def compute_resume_mac(
    plaintext: bytes,
    *,
    key: bytes,
    manifest: EncryptedTransferManifest,
    index: int,
) -> bytes:
    """Return the keyed identity used to verify a resumed local file chunk."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise EncryptedTransferValidationError("resume key must contain exactly 32 bytes")
    chunk_aad(manifest, index=index, plaintext_length=len(plaintext))
    message = (
        _RESUME_PREFIX
        + file_id_bytes(manifest.file_id)
        + struct.pack(">II", index, len(plaintext))
        + plaintext
    )
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_resume_mac(
    plaintext: bytes,
    *,
    key: bytes,
    manifest: EncryptedTransferManifest,
    index: int,
    expected: bytes,
) -> bool:
    """Verify one resume MAC in constant time."""
    if not isinstance(expected, bytes) or len(expected) != 32:
        return False
    computed = compute_resume_mac(
        plaintext,
        key=key,
        manifest=manifest,
        index=index,
    )
    return hmac.compare_digest(computed, expected)
