"""Tests for cryptographic functions."""

import base64
import inspect
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.conftest import make_request
from xferry.advanced_sessions import (
    AdvancedSession,
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
)
from xferry.handlers import HandlerMixin
from xferry.security.crypto import (
    aes_decrypt,
    aes_encrypt,
    compute_hmac,
    decrypt,
    encrypt,
    verify_hmac,
    xor_decrypt,
    xor_decrypt_file,
    xor_decrypt_with_hmac,
    xor_encrypt,
    xor_encrypt_file,
    xor_encrypt_with_hmac,
)


class CryptoUploadServer(HandlerMixin):
    """Minimal handler composition for Advanced crypto-order tests."""

    def __init__(self, root_dir: Path, upload_dir: Path) -> None:
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.cors_origin = None
        self.cors_origins = ()
        self.sandbox_mode = False
        self.opsec_mode = False
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()
        self._ecdh_manager = None
        self.method_handlers = self.build_method_handlers()


def _bind_crypto_dispatch(request, *, decoder: str = "json"):
    now = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    request.advanced_session_dispatch = AdvancedSessionDispatch(
        session=AdvancedSession(
            prefix="/advanced",
            decoder=decoder,
            diagnostic_headers=False,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
        ),
        principal=AdvancedSessionPrincipal("no_auth", None),
        direct_peer=None,
    )
    request.advanced_session_admission_prepared = True
    return request


class TestXOREncryption:
    """Tests for XOR encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypt then decrypt returns original data."""
        data = b"Hello, World!"
        password = "secret_key"

        encrypted = xor_encrypt(data, password)
        decrypted = xor_decrypt(encrypted, password)

        assert decrypted == data

    def test_encryption_changes_data(self):
        """Test that encryption produces different data."""
        data = b"Hello, World!"
        password = "secret_key"

        encrypted = xor_encrypt(data, password)

        assert encrypted != data

    def test_different_passwords_different_results(self):
        """Test that different passwords produce different encrypted data."""
        data = b"Hello, World!"

        encrypted1 = xor_encrypt(data, "key1")
        encrypted2 = xor_encrypt(data, "key2")

        assert encrypted1 != encrypted2

    def test_empty_password_uses_the_sha256_empty_digest(self):
        """An empty password still has a defined SHA-256-derived XOR key."""
        data = b"Hello, World!"

        encrypted = xor_encrypt(data, "")

        assert encrypted != data
        assert xor_decrypt(encrypted, "") == data

    def test_sha256_derived_xor_matches_the_cross_language_vector(self):
        """Raw-password repetition cannot satisfy the canonical XOR wire contract."""
        plaintext = bytes.fromhex("58466572727920332064657465726d696e697374696320e29c93")

        encrypted = xor_encrypt(plaintext, "correct horse battery staple")

        assert encrypted.hex() == "9cfdae6dccb0bd569f3dbd28e9c4438bb5ff4c7b8865d461453c"
        assert xor_decrypt(encrypted, "correct horse battery staple") == plaintext

    def test_binary_data(self):
        """Test encryption of binary data."""
        data = bytes(range(256))
        password = "binary_key"

        encrypted = xor_encrypt(data, password)
        decrypted = xor_decrypt(encrypted, password)

        assert decrypted == data


class TestXORFileEncryption:
    """Tests for XOR file encryption/decryption."""

    def test_encrypt_file(self, temp_dir: Path):
        """Test file encryption."""
        input_file = temp_dir / "input.txt"
        output_file = temp_dir / "output.enc"
        input_file.write_bytes(b"Test content for encryption")

        size = xor_encrypt_file(str(input_file), str(output_file), "password")

        assert output_file.exists()
        assert size == len(b"Test content for encryption")
        assert output_file.read_bytes() != input_file.read_bytes()

    def test_decrypt_file(self, temp_dir: Path):
        """Test file decryption."""
        input_file = temp_dir / "input.txt"
        encrypted_file = temp_dir / "encrypted.enc"
        decrypted_file = temp_dir / "decrypted.txt"
        original_content = b"Original content"

        input_file.write_bytes(original_content)
        xor_encrypt_file(str(input_file), str(encrypted_file), "password")
        xor_decrypt_file(str(encrypted_file), str(decrypted_file), "password")

        assert decrypted_file.read_bytes() == original_content


class TestHMAC:
    """Tests for HMAC functions."""

    def test_compute_hmac(self):
        """Test HMAC computation."""
        data = b"test data"
        key = "secret_key"

        hmac_value = compute_hmac(data, key)

        assert isinstance(hmac_value, str)
        assert len(hmac_value) == 64  # SHA256 hex digest

    def test_hmac_matches_the_cross_language_aes_wire_vector(self):
        """The HMAC key is the raw UTF-8 password and the input is the AES wire."""
        aes_wire = base64.b64decode(
            "AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhtUVBi3YoaIROve/LypgRmT"
            "f1HpkO8E9klfo+b3D3vjGxz/C3mk/XjkTEI="
        )

        assert compute_hmac(aes_wire, "correct horse battery staple") == (
            "22fcd72c80c002a91d7eea3f7ea4e5b9cd031feb90674e6ce2f30251f599b0cc"
        )

    def test_verify_hmac_valid(self):
        """Test HMAC verification with valid HMAC."""
        data = b"test data"
        key = "secret_key"

        hmac_value = compute_hmac(data, key)

        assert verify_hmac(data, key, hmac_value) is True

    def test_verify_hmac_invalid(self):
        """Test HMAC verification with invalid HMAC."""
        data = b"test data"
        key = "secret_key"

        assert verify_hmac(data, key, "invalid_hmac") is False

    def test_verify_hmac_wrong_key(self):
        """Test HMAC verification with wrong key."""
        data = b"test data"

        hmac_value = compute_hmac(data, "key1")

        assert verify_hmac(data, "key2", hmac_value) is False

    def test_verify_hmac_modified_data(self):
        """Test HMAC verification with modified data."""
        data = b"original data"
        key = "secret_key"

        hmac_value = compute_hmac(data, key)

        assert verify_hmac(b"modified data", key, hmac_value) is False


def test_advanced_upload_hmac_mismatch_never_calls_decrypt_or_publishes(
    temp_dir: Path,
    upload_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches decrypt being attempted before HMAC-SHA256 verification."""
    server = CryptoUploadServer(temp_dir, upload_dir)
    decrypt_calls: list[tuple[bytes, str]] = []

    def forbidden_xor_decrypt(data: bytes, key: str) -> bytes:
        decrypt_calls.append((data, key))
        return b"should-not-run"

    monkeypatch.setattr("xferry.handlers.advanced_upload.xor_decrypt", forbidden_xor_decrypt)
    key = "hmac-first-key"
    ciphertext = xor_encrypt(b"plaintext", key)
    body = json.dumps(
        {
            "data": base64.b64encode(ciphertext).decode("ascii"),
            "encoding": "base64",
            "encryption": "xor",
            "key": key,
            "hmac": "0" * 64,
            "name": "must-not-publish.bin",
        },
        separators=(",", ":"),
    ).encode("utf-8")

    response = server.handle_advanced_upload(
        _bind_crypto_dispatch(
            make_request(
                "POST",
                "/advanced",
                headers={"Content-Type": "application/json"},
                body=body,
            )
        )
    )
    rendered = json.loads(response.body)

    assert response.status_code == 400
    assert rendered["error"]["code"] == "hmac_mismatch"
    assert rendered["error"]["field"] == "hmac"
    assert decrypt_calls == []
    assert list(upload_dir.iterdir()) == []


class TestXORWithHMAC:
    """Tests for XOR encryption with HMAC."""

    def test_encrypt_with_hmac(self):
        """Test encryption with HMAC generation."""
        data = b"sensitive data"
        password = "password"

        encrypted, hmac_value = xor_encrypt_with_hmac(data, password)

        assert encrypted != data
        assert len(hmac_value) == 64

    def test_decrypt_with_hmac_valid(self):
        """Test decryption with valid HMAC."""
        data = b"sensitive data"
        password = "password"

        encrypted, hmac_value = xor_encrypt_with_hmac(data, password)
        decrypted = xor_decrypt_with_hmac(encrypted, password, hmac_value)

        assert decrypted == data

    def test_decrypt_with_hmac_invalid(self):
        """Test decryption with invalid HMAC returns None."""
        data = b"sensitive data"
        password = "password"

        encrypted, _ = xor_encrypt_with_hmac(data, password)
        result = xor_decrypt_with_hmac(encrypted, password, "invalid_hmac")

        assert result is None

    def test_decrypt_with_hmac_tampered_data(self):
        """Test decryption of tampered data returns None."""
        data = b"sensitive data"
        password = "password"

        encrypted, hmac_value = xor_encrypt_with_hmac(data, password)
        tampered = bytes([b ^ 1 for b in encrypted])  # Flip bits
        result = xor_decrypt_with_hmac(tampered, password, hmac_value)

        assert result is None


class TestAES256GCM:
    """Tests for AES-256-GCM encryption/decryption."""

    def test_aes_encrypt_decrypt_roundtrip(self):
        """Test AES encrypt then decrypt returns original data."""
        data = b"Hello, AES-256-GCM!"
        password = "strong_password"

        encrypted = aes_encrypt(data, password)
        decrypted = aes_decrypt(encrypted, password)

        assert decrypted == data

    def test_aes_version_marker(self):
        """Test that AES ciphertext starts with version byte 0x01."""
        encrypted = aes_encrypt(b"test", "pw")
        assert encrypted[0] == 0x01

    def test_aes_different_each_time(self):
        """Test that two encryptions of same data differ (random salt/nonce)."""
        data = b"same data"
        enc1 = aes_encrypt(data, "pw")
        enc2 = aes_encrypt(data, "pw")
        assert enc1 != enc2

    def test_aes_wrong_password(self):
        """Test that wrong password returns None."""
        encrypted = aes_encrypt(b"secret", "correct_pw")
        result = aes_decrypt(encrypted, "wrong_pw")
        assert result is None

    def test_aes_tampered_ciphertext(self):
        """Test that tampered ciphertext returns None."""
        encrypted = aes_encrypt(b"data", "pw")
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF  # Flip last byte (part of GCM tag)
        result = aes_decrypt(bytes(tampered), "pw")
        assert result is None

    def test_aes_too_short_data(self):
        """Test that truncated data returns None."""
        result = aes_decrypt(b"\x01" + b"\x00" * 10, "pw")
        assert result is None

    def test_aes_binary_data(self):
        """Test AES encryption of binary data."""
        data = bytes(range(256)) * 10
        password = "binary_key"
        encrypted = aes_encrypt(data, password)
        decrypted = aes_decrypt(encrypted, password)
        assert decrypted == data

    def test_aes_empty_data(self):
        """Test AES encryption of empty data."""
        encrypted = aes_encrypt(b"", "pw")
        decrypted = aes_decrypt(encrypted, "pw")
        assert decrypted == b""

    def test_aes_decrypts_the_fixed_cross_language_wire_vector(self):
        """Version, salt, nonce, PBKDF2, ciphertext, and tag stay interoperable."""
        wire = base64.b64decode(
            "AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhtUVBi3YoaIROve/LypgRmT"
            "f1HpkO8E9klfo+b3D3vjGxz/C3mk/XjkTEI="
        )

        assert aes_decrypt(wire, "correct horse battery staple") == bytes.fromhex(
            "58466572727920332064657465726d696e697374696320e29c93"
        )

    def test_aes_encrypts_the_fixed_cross_language_wire_vector(self, monkeypatch):
        """Changing any AES wire parameter breaks the literal interoperability vector."""
        random_values = iter(
            (
                bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                bytes.fromhex("101112131415161718191a1b"),
            )
        )
        monkeypatch.setattr("xferry.security.crypto.os.urandom", lambda _size: next(random_values))

        wire = aes_encrypt(
            bytes.fromhex("58466572727920332064657465726d696e697374696320e29c93"),
            "correct horse battery staple",
        )

        assert base64.b64encode(wire).decode("ascii") == (
            "AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhtUVBi3YoaIROve/LypgRmT"
            "f1HpkO8E9klfo+b3D3vjGxz/C3mk/XjkTEI="
        )


class TestUnifiedEncryptDecrypt:
    """Tests for the AES-only public encrypt/decrypt interface."""

    def test_encrypt_uses_aes_when_available(self):
        """Test that encrypt() uses AES when cryptography is installed."""
        data = b"test data"
        encrypted = encrypt(data, "pw")
        # Should have AES version marker
        assert encrypted[0] == 0x01

    def test_decrypt_accepts_the_aes_wire_without_algorithm_selection(self):
        """decrypt() has one meaning and needs no algorithm selector."""
        data = b"test data"
        encrypted = encrypt(data, "pw")
        decrypted = decrypt(encrypted, "pw")
        assert decrypted == data

    def test_decrypt_does_not_fall_back_to_xor(self):
        """Non-AES input fails closed instead of being XOR-transformed."""
        data = b"test data"
        password = "key"
        xor_encrypted = xor_encrypt(data, password)
        decrypted = decrypt(xor_encrypted, password)
        assert decrypted is None

    def test_public_api_has_no_availability_flag_or_algorithm_selector(self):
        """Callers cannot negotiate crypto availability or choose an implicit mode."""
        import xferry.security as security
        import xferry.security.crypto as crypto

        assert not hasattr(crypto, "HAS_CRYPTOGRAPHY")
        assert not hasattr(security, "HAS_CRYPTOGRAPHY")
        assert tuple(inspect.signature(encrypt).parameters) == ("data", "password")
        assert tuple(inspect.signature(decrypt).parameters) == ("data", "password")
        with pytest.raises(TypeError):
            decrypt(b"ciphertext", "pw", algorithm="xor")  # type: ignore[call-arg]

    def test_roundtrip_large_payload(self):
        """Test encrypt/decrypt with a larger payload."""
        data = b"A" * 1_000_000  # 1 MB
        encrypted = encrypt(data, "password")
        decrypted = decrypt(encrypted, "password")
        assert decrypted == data
