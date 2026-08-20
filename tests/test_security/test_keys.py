"""Tests for the ECDH key exchange manager."""

import importlib.util
import logging
from pathlib import Path

import pytest

from xferry.security.keys import HAS_ECDH, ECDHKeyManager, session_fingerprint

pytestmark = pytest.mark.skipif(not HAS_ECDH, reason="cryptography not installed")


def _load_notepad_client_example():
    example_path = Path(__file__).resolve().parents[2] / "examples" / "notepad_client.py"
    spec = importlib.util.spec_from_file_location("notepad_client_example", example_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestECDHKeyManager:
    def test_public_key_is_65_bytes(self):
        mgr = ECDHKeyManager()
        raw = mgr.get_public_key_raw()
        assert len(raw) == 65
        assert raw[0] == 0x04  # uncompressed point prefix

    def test_derive_session_returns_id_and_key(self):
        server = ECDHKeyManager()
        client = ECDHKeyManager()

        client_pub = client.get_public_key_raw()
        session_id, key = server.derive_session(client_pub)

        assert len(session_id) == 32  # hex(16 bytes)
        assert len(key) == 32  # 256-bit AES key

    def test_notepad_client_example_derives_server_compatible_key(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        example = _load_notepad_client_example()
        server = ECDHKeyManager()
        client_private = ec.generate_private_key(ec.SECP256R1())
        client_public = client_private.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        _session_id, server_key = server.derive_session(client_public)
        example_key = example.derive_shared_key(server.get_public_key_raw(), client_private)

        server_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            server.get_public_key_raw(),
        )
        shared_secret = client_private.exchange(ec.ECDH(), server_public)
        old_example_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"xferry-notepad",
        ).derive(shared_secret)

        assert old_example_key != server_key
        assert example_key == server_key

    def test_get_session_key_returns_key(self):
        mgr = ECDHKeyManager()
        client = ECDHKeyManager()
        session_id, key = mgr.derive_session(client.get_public_key_raw())

        assert mgr.get_session_key(session_id) == key

    def test_get_session_key_unknown_returns_none(self):
        mgr = ECDHKeyManager()
        assert mgr.get_session_key("nonexistent") is None

    def test_remove_session(self):
        mgr = ECDHKeyManager()
        client = ECDHKeyManager()
        session_id, _ = mgr.derive_session(client.get_public_key_raw())

        mgr.remove_session(session_id)
        assert mgr.get_session_key(session_id) is None

    def test_remove_nonexistent_session_is_noop(self):
        mgr = ECDHKeyManager()
        mgr.remove_session("doesnotexist")  # should not raise

    def test_encrypt_decrypt_roundtrip(self):
        mgr = ECDHKeyManager()
        client = ECDHKeyManager()
        session_id, _ = mgr.derive_session(client.get_public_key_raw())

        plaintext = b"Hello, encrypted notepad!"
        encrypted = mgr.encrypt(session_id, plaintext)

        # encrypted = nonce(12) + ciphertext + tag(16)
        assert len(encrypted) > 12 + 16
        assert encrypted != plaintext

        decrypted = mgr.decrypt(session_id, encrypted)
        assert decrypted == plaintext

    def test_encrypt_unknown_session_raises(self):
        mgr = ECDHKeyManager()
        with pytest.raises(ValueError, match="Unknown session"):
            mgr.encrypt("bad_session", b"data")

    def test_decrypt_unknown_session_raises(self):
        mgr = ECDHKeyManager()
        with pytest.raises(ValueError, match="Unknown session"):
            mgr.decrypt("bad_session", b"x" * 30)

    def test_unknown_session_errors_do_not_echo_identifier(self):
        mgr = ECDHKeyManager()
        unknown_session_id = "deadbeefdeadbeefdeadbeefdeadbeef"

        with pytest.raises(ValueError) as encrypt_error:
            mgr.encrypt(unknown_session_id, b"data")
        with pytest.raises(ValueError) as decrypt_error:
            mgr.decrypt(unknown_session_id, b"x" * 30)

        assert str(encrypt_error.value) == "Unknown session"
        assert str(decrypt_error.value) == "Unknown session"
        assert unknown_session_id not in str(encrypt_error.value)
        assert unknown_session_id not in str(decrypt_error.value)

    def test_decrypt_too_short_raises(self):
        mgr = ECDHKeyManager()
        client = ECDHKeyManager()
        session_id, _ = mgr.derive_session(client.get_public_key_raw())

        with pytest.raises(ValueError, match="Data too short"):
            mgr.decrypt(session_id, b"short")

    def test_decrypt_tampered_data_fails(self):
        mgr = ECDHKeyManager()
        client = ECDHKeyManager()
        session_id, _ = mgr.derive_session(client.get_public_key_raw())

        encrypted = mgr.encrypt(session_id, b"secret")
        # Tamper with a byte in the ciphertext
        tampered = bytearray(encrypted)
        tampered[-5] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises((ValueError, Exception)):  # InvalidTag from cryptography
            mgr.decrypt(session_id, tampered)

    def test_multiple_sessions_independent(self):
        mgr = ECDHKeyManager()

        client1 = ECDHKeyManager()
        sid1, _ = mgr.derive_session(client1.get_public_key_raw())

        client2 = ECDHKeyManager()
        sid2, _ = mgr.derive_session(client2.get_public_key_raw())

        assert sid1 != sid2
        assert mgr.get_session_key(sid1) != mgr.get_session_key(sid2)

        # Each session encrypts independently
        enc1 = mgr.encrypt(sid1, b"msg1")
        enc2 = mgr.encrypt(sid2, b"msg2")

        assert mgr.decrypt(sid1, enc1) == b"msg1"
        assert mgr.decrypt(sid2, enc2) == b"msg2"

    def test_public_key_stable(self):
        """Same manager returns the same public key each time."""
        mgr = ECDHKeyManager()
        assert mgr.get_public_key_raw() == mgr.get_public_key_raw()

    def test_expired_sessions_cleaned_on_access(self):
        current_time = [1000.0]

        def fake_time() -> float:
            return current_time[0]

        mgr = ECDHKeyManager(session_ttl_seconds=10.0, time_fn=fake_time)
        client = ECDHKeyManager()
        session_id, _ = mgr.derive_session(client.get_public_key_raw())

        assert mgr.active_session_count() == 1

        current_time[0] += 11.0

        assert mgr.get_session_key(session_id) is None
        assert mgr.active_session_count() == 0

    def test_created_and_expired_session_logs_use_fingerprint(self, caplog):
        current_time = [1000.0]

        def fake_time() -> float:
            return current_time[0]

        caplog.set_level(logging.DEBUG, logger="xferry")
        mgr = ECDHKeyManager(session_ttl_seconds=10.0, time_fn=fake_time)
        client = ECDHKeyManager()
        session_id, _ = mgr.derive_session(client.get_public_key_raw())
        fingerprint = session_fingerprint(session_id)

        assert "ECDH session created" in caplog.text
        assert fingerprint in caplog.text
        assert session_id not in caplog.text

        caplog.clear()
        current_time[0] += 11.0
        assert mgr.get_session_key(session_id) is None

        assert "ECDH session expired" in caplog.text
        assert fingerprint in caplog.text
        assert session_id not in caplog.text

    def test_lru_session_cap_evicts_oldest_active_session(self):
        current_time = [2000.0]

        def fake_time() -> float:
            return current_time[0]

        mgr = ECDHKeyManager(max_sessions=2, time_fn=fake_time)
        client1 = ECDHKeyManager()
        sid1, _ = mgr.derive_session(client1.get_public_key_raw())

        current_time[0] += 1.0
        client2 = ECDHKeyManager()
        sid2, _ = mgr.derive_session(client2.get_public_key_raw())

        current_time[0] += 1.0
        assert mgr.get_session_key(sid1) is not None

        current_time[0] += 1.0
        client3 = ECDHKeyManager()
        sid3, _ = mgr.derive_session(client3.get_public_key_raw())

        assert mgr.active_session_count() == 2
        assert mgr.get_session_key(sid1) is not None
        assert mgr.get_session_key(sid2) is None
        assert mgr.get_session_key(sid3) is not None

    def test_lru_eviction_log_uses_fingerprint(self, caplog):
        current_time = [2000.0]

        def fake_time() -> float:
            return current_time[0]

        caplog.set_level(logging.DEBUG, logger="xferry")
        mgr = ECDHKeyManager(max_sessions=1, time_fn=fake_time)
        client1 = ECDHKeyManager()
        sid1, _ = mgr.derive_session(client1.get_public_key_raw())

        caplog.clear()
        current_time[0] += 1.0
        client2 = ECDHKeyManager()
        sid2, _ = mgr.derive_session(client2.get_public_key_raw())

        assert "ECDH session evicted by LRU cap" in caplog.text
        assert session_fingerprint(sid1) in caplog.text
        assert session_fingerprint(sid2) in caplog.text
        assert sid1 not in caplog.text
        assert sid2 not in caplog.text
