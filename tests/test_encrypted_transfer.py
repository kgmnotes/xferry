"""EUF v1 encrypted-transfer wire contract tests."""

from __future__ import annotations

import importlib
import json

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server

FILE_ID = "00112233445566778899aabbccddeeff"
SALT = bytes(range(16))
NONCE_PREFIX = bytes(range(0xA0, 0xA8))


def _encrypted_transfer_module():
    try:
        return importlib.import_module("xferry.encrypted_transfer")
    except ModuleNotFoundError:
        pytest.fail("xferry.encrypted_transfer is not implemented", pytrace=False)


def test_base64url_codec_is_unpadded_and_strict() -> None:
    """Padding or permissive decoding would make canonical manifests ambiguous."""
    codec = _encrypted_transfer_module()

    encoded = codec.b64url_encode(bytes.fromhex("fbff00"))

    assert encoded == "-_8A"
    assert codec.b64url_decode(encoded, field="salt") == bytes.fromhex("fbff00")
    for malformed in ("-_8A=", "+/8A", " -_8A", "-_8A\n"):
        with pytest.raises(codec.EncryptedTransferValidationError, match="salt"):
            codec.b64url_decode(malformed, field="salt")


def test_file_id_requires_exact_lowercase_128_bit_hex() -> None:
    """Case folding or variable IDs could alias persistent resource paths."""
    codec = _encrypted_transfer_module()
    canonical = "00112233445566778899aabbccddeeff"

    assert codec.file_id_bytes(canonical) == bytes.fromhex(canonical)
    for malformed in (canonical.upper(), canonical[:-1], canonical + "00", "g" * 32):
        with pytest.raises(codec.EncryptedTransferValidationError, match="file_id"):
            codec.file_id_bytes(malformed)


def test_manifest_enforces_v1_sizes_and_derives_ciphertext_length() -> None:
    """Wrong chunk arithmetic could permit nonce reuse or truncated publication."""
    codec = _encrypted_transfer_module()

    manifest = codec.EncryptedTransferManifest(
        file_id=FILE_ID,
        plaintext_size=20,
        chunk_size=8 * 1024 * 1024,
        chunk_count=1,
        salt=SALT,
        nonce_prefix=NONCE_PREFIX,
        encrypted_metadata=b"x" * 16,
    )

    assert manifest.version == 1
    assert manifest.ciphertext_size == 36
    with pytest.raises(codec.EncryptedTransferValidationError, match="chunk_count"):
        codec.EncryptedTransferManifest(
            file_id=FILE_ID,
            plaintext_size=8 * 1024 * 1024 + 1,
            chunk_size=8 * 1024 * 1024,
            chunk_count=1,
            salt=SALT,
            nonce_prefix=NONCE_PREFIX,
            encrypted_metadata=b"x" * 16,
        )


def test_manifest_allows_an_empty_file_without_content_chunks() -> None:
    codec = _encrypted_transfer_module()

    manifest = codec.EncryptedTransferManifest(
        file_id=FILE_ID,
        plaintext_size=0,
        chunk_size=8 * 1024 * 1024,
        chunk_count=0,
        salt=SALT,
        nonce_prefix=NONCE_PREFIX,
        encrypted_metadata=b"x" * 16,
    )

    assert manifest.ciphertext_size == 0


def test_metadata_uses_the_4096_byte_json_limit_not_filesystem_name_limits() -> None:
    codec = _encrypted_transfer_module()
    manifest = _vector_manifest(codec)
    metadata = codec.EncryptedFileMetadata(
        name="x" * 300,
        content_type="application/" + "x" * 300,
        last_modified_ms=0,
    )
    content_key, _resume_key = codec.derive_keys(
        "correct horse battery staple",
        salt=SALT,
        file_id=FILE_ID,
    )

    ciphertext = codec.encrypt_metadata(metadata, key=content_key, manifest=manifest)
    published = _vector_manifest(codec, ciphertext)

    assert codec.decrypt_metadata(key=content_key, manifest=published) == metadata


def test_metadata_allows_an_empty_browser_content_type() -> None:
    codec = _encrypted_transfer_module()

    metadata = codec.EncryptedFileMetadata(
        name="unknown",
        content_type="",
        last_modified_ms=0,
    )

    assert metadata.content_type == ""


def test_pbkdf2_hkdf_and_aad_match_the_independent_v1_vector() -> None:
    """Changing KDF labels or integer layout would break browser interoperability."""
    codec = _encrypted_transfer_module()
    manifest = codec.EncryptedTransferManifest(
        file_id=FILE_ID,
        plaintext_size=20,
        chunk_size=8 * 1024 * 1024,
        chunk_count=1,
        salt=SALT,
        nonce_prefix=NONCE_PREFIX,
        encrypted_metadata=b"x" * 16,
    )

    content_key, resume_key = codec.derive_keys(
        "correct horse battery staple",
        salt=SALT,
        file_id=FILE_ID,
    )

    assert content_key.hex() == "705dbd0114261bde4c7c288d8d03c4ccc02fcc345393fd1540d74312728272a7"
    assert resume_key.hex() == "b59df99ac6b971eba4cb05fa3bc444152a30ca025a3abaa6c131aa16e8348e73"
    assert codec.metadata_aad(manifest).hex() == (
        "5846455252592d455546312d4d45544100"
        "00112233445566778899aabbccddeeff"
        "00000000000000140080000000000001"
    )
    assert codec.chunk_aad(manifest, index=0, plaintext_length=20).hex() == (
        "5846455252592d455546312d4348554e4b00"
        "00112233445566778899aabbccddeeff"
        "00000000000000140080000000000001"
        "0000000000000014"
    )


def test_password_validation_is_exact_and_bounded() -> None:
    """Implicit trimming or normalization could make a saved password unrecoverable."""
    codec = _encrypted_transfer_module()

    with pytest.raises(codec.EncryptedTransferValidationError, match="14"):
        codec.derive_keys("weak password", salt=SALT, file_id=FILE_ID)
    with pytest.raises(codec.EncryptedTransferValidationError, match="1024"):
        codec.derive_keys("a" * 1025, salt=SALT, file_id=FILE_ID)

    left = codec.derive_keys("é" * 14, salt=SALT, file_id=FILE_ID)
    right = codec.derive_keys(("e\u0301") * 14, salt=SALT, file_id=FILE_ID)
    assert left != right


def _vector_manifest(codec, encrypted_metadata: bytes = b"x" * 16):
    return codec.EncryptedTransferManifest(
        file_id=FILE_ID,
        plaintext_size=20,
        chunk_size=8 * 1024 * 1024,
        chunk_count=1,
        salt=SALT,
        nonce_prefix=NONCE_PREFIX,
        encrypted_metadata=encrypted_metadata,
    )


def test_metadata_ciphertext_matches_vector_and_rejects_wrong_key() -> None:
    """Metadata field order, nonce, or AAD drift would hide filenames permanently."""
    codec = _encrypted_transfer_module()
    manifest = _vector_manifest(codec)
    metadata = codec.EncryptedFileMetadata(
        name="report.txt",
        content_type="text/plain",
        last_modified_ms=1_720_000_000_123,
    )
    content_key, _resume_key = codec.derive_keys(
        "correct horse battery staple",
        salt=SALT,
        file_id=FILE_ID,
    )

    ciphertext = codec.encrypt_metadata(metadata, key=content_key, manifest=manifest)

    assert ciphertext.hex() == (
        "c9419088375171101e8744899f32bad858d280dad0b3a268f364d9df86d0bd36"
        "b65bc8ba828cdb4ca0a1cce53debe06cef4a82f3e089a6c42b2fb0babb6ea5e"
        "484713f9b3c165355385edc1ba52904f30840b85fab544fb4d1db8ef391c8c900d439"
    )
    published = _vector_manifest(codec, ciphertext)
    assert codec.decrypt_metadata(key=content_key, manifest=published) == metadata
    assert codec.decrypt_metadata(key=b"\x00" * 32, manifest=published) is None


def test_chunk_ciphertext_and_resume_mac_match_independent_vectors() -> None:
    """Browser and server must agree on chunk nonce, AAD, and keyed resume identity."""
    codec = _encrypted_transfer_module()
    manifest = _vector_manifest(codec)
    plaintext = b"0123456789abcdefghij"
    content_key, resume_key = codec.derive_keys(
        "correct horse battery staple",
        salt=SALT,
        file_id=FILE_ID,
    )

    ciphertext = codec.encrypt_chunk(
        plaintext,
        key=content_key,
        manifest=manifest,
        index=0,
    )
    resume_mac = codec.compute_resume_mac(
        plaintext,
        key=resume_key,
        manifest=manifest,
        index=0,
    )

    assert ciphertext.hex() == (
        "6cdb3b6906e069eae77291067f066f9fdbb39f55d5e684ddb01ae8b19b43244d36eea649"
    )
    assert resume_mac.hex() == ("12d418de7276b55498b8c45cae1f6e703a38d5411ce6577128e5102427d60da6")
    assert codec.decrypt_chunk(ciphertext, key=content_key, manifest=manifest, index=0) == plaintext
    assert codec.verify_resume_mac(
        plaintext,
        key=resume_key,
        manifest=manifest,
        index=0,
        expected=resume_mac,
    )


def test_chunk_tampering_and_wrong_position_fail_closed() -> None:
    """Modified or repositioned ciphertext must never yield unauthenticated plaintext."""
    codec = _encrypted_transfer_module()
    manifest = _vector_manifest(codec)
    content_key, _resume_key = codec.derive_keys(
        "correct horse battery staple",
        salt=SALT,
        file_id=FILE_ID,
    )
    ciphertext = bytearray(
        codec.encrypt_chunk(
            b"0123456789abcdefghij",
            key=content_key,
            manifest=manifest,
            index=0,
        )
    )
    ciphertext[0] ^= 1

    assert (
        codec.decrypt_chunk(
            bytes(ciphertext),
            key=content_key,
            manifest=manifest,
            index=0,
        )
        is None
    )
    with pytest.raises(codec.EncryptedTransferValidationError, match="index"):
        codec.decrypt_chunk(
            bytes(ciphertext),
            key=content_key,
            manifest=manifest,
            index=1,
        )


def test_ping_reports_disabled_encrypted_upload_capability(temp_dir) -> None:
    server = make_server(root_dir=str(temp_dir), quiet=True)

    response = server.handle_ping(make_request("PING", "/"))

    assert response.status_code == 200
    assert json.loads(response.body)["encrypted_uploads"] == {"enabled": False}


def test_ping_reports_enabled_encrypted_upload_capability(temp_dir) -> None:
    server = make_server(
        root_dir=str(temp_dir),
        quiet=True,
        encrypted_uploads=True,
        encrypted_upload_max_size=1536 * 1024 * 1024,
    )

    response = server.handle_ping(make_request("PING", "/"))

    assert response.status_code == 200
    assert json.loads(response.body)["encrypted_uploads"] == {
        "enabled": True,
        "version": 1,
        "max_plaintext_size": 1536 * 1024 * 1024,
        "chunk_size": 8 * 1024 * 1024,
        "parallel_chunks": 2,
        "browser_decryption": True,
        "server_decryption": True,
    }


@pytest.mark.parametrize(
    ("host", "server_decryption"),
    [("localhost", True), ("192.0.2.10", False)],
)
def test_ping_limits_server_decryption_to_secure_or_loopback_connections(
    temp_dir,
    host: str,
    server_decryption: bool,
) -> None:
    server = make_server(
        root_dir=str(temp_dir),
        quiet=True,
        host=host,
        encrypted_uploads=True,
    )

    capability = json.loads(server.handle_ping(make_request("PING", "/")).body)["encrypted_uploads"]

    assert capability["server_decryption"] is server_decryption
