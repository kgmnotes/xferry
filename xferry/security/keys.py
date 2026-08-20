"""
ECDH key exchange manager for Secure Notepad v2.

Uses Elliptic Curve Diffie-Hellman (P-256) to negotiate a shared
AES-256-GCM encryption key between client and server without any
user-entered password.

Wire format for encrypted messages:
    nonce(12) + ciphertext + tag(16)

Requires the ``cryptography`` package.
"""

import logging
import os
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from time import monotonic

logger = logging.getLogger("xferry")

HAS_ECDH = False

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    HAS_ECDH = True
except ImportError:
    pass

_HKDF_SALT = b"\x00" * 32
_HKDF_INFO = b"notepad-e2e-key"
_NONCE_LEN = 12
_DEFAULT_SESSION_TTL_SECONDS = 3600.0
_DEFAULT_MAX_SESSIONS = 1024
_SESSION_FINGERPRINT_LEN = 12
_SESSION_FINGERPRINT_PREFIX = "sidfp:"


def session_fingerprint(session_id: str) -> str:
    """Return a stable, non-identifying fingerprint for session diagnostics."""
    digest = sha256(session_id.encode("utf-8", errors="replace")).hexdigest()
    return f"{_SESSION_FINGERPRINT_PREFIX}{digest[:_SESSION_FINGERPRINT_LEN]}"


@dataclass
class _SessionRecord:
    """In-memory ECDH session state."""

    key: bytes
    last_seen: float


class ECDHKeyManager:
    """Manages ECDH key pairs and bounded per-session derived AES-256-GCM keys."""

    def __init__(
        self,
        *,
        session_ttl_seconds: float = _DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = _DEFAULT_MAX_SESSIONS,
        time_fn: Callable[[], float] = monotonic,
    ) -> None:
        if not HAS_ECDH:
            raise RuntimeError("cryptography package required for ECDH")
        if session_ttl_seconds <= 0:
            raise ValueError("session_ttl_seconds must be positive")
        if max_sessions <= 0:
            raise ValueError("max_sessions must be positive")
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._session_ttl_seconds = session_ttl_seconds
        self._max_sessions = max_sessions
        self._time_fn = time_fn
        self._lock = threading.RLock()
        self._sessions: OrderedDict[str, _SessionRecord] = OrderedDict()

    @property
    def session_ttl_seconds(self) -> float:
        """Return the idle TTL applied to derived sessions."""
        return self._session_ttl_seconds

    def active_session_count(self) -> int:
        """Return the number of currently active sessions after cleanup."""
        with self._lock:
            self._cleanup_sessions_unlocked()
            return len(self._sessions)

    def _cleanup_sessions(self, now: float | None = None) -> None:
        """Expire idle sessions and cap the in-memory session store."""
        with self._lock:
            self._cleanup_sessions_unlocked(now)

    def _cleanup_sessions_unlocked(self, now: float | None = None) -> None:
        """Expire idle sessions and cap the in-memory session store while holding ``_lock``."""
        current_time = self._time_fn() if now is None else now
        expiry_cutoff = current_time - self._session_ttl_seconds

        while self._sessions:
            oldest_session_id, oldest_session = next(iter(self._sessions.items()))
            if oldest_session.last_seen > expiry_cutoff:
                break
            self._sessions.popitem(last=False)
            logger.debug("ECDH session expired: %s", session_fingerprint(oldest_session_id))

        while len(self._sessions) > self._max_sessions:
            evicted_session_id, _evicted = self._sessions.popitem(last=False)
            logger.debug(
                "ECDH session evicted by LRU cap: %s",
                session_fingerprint(evicted_session_id),
            )

    def get_public_key_raw(self) -> bytes:
        """Return the server's public key as 65-byte uncompressed point."""
        return self._private_key.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint,
        )

    def derive_session(self, client_pub_raw: bytes) -> tuple[str, bytes]:
        """
        Perform ECDH key exchange with a client's raw public key.

        Args:
            client_pub_raw: 65-byte uncompressed EC P-256 public key.

        Returns:
            A tuple containing ``session_id`` and a 32-byte derived AES key.
        """
        current_time = self._time_fn()
        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            client_pub_raw,
        )
        shared_secret = self._private_key.exchange(ec.ECDH(), client_pub)

        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=_HKDF_SALT,
            info=_HKDF_INFO,
        ).derive(shared_secret)

        session_id = secrets.token_hex(16)
        with self._lock:
            self._cleanup_sessions_unlocked(current_time)
            self._sessions[session_id] = _SessionRecord(
                key=derived_key,
                last_seen=current_time,
            )
            self._cleanup_sessions_unlocked(current_time)
        logger.debug("ECDH session created: %s", session_fingerprint(session_id))
        return session_id, derived_key

    def get_session_key(self, session_id: str) -> bytes | None:
        """Return the AES key for an active session, or None if unknown/expired."""
        current_time = self._time_fn()
        with self._lock:
            self._cleanup_sessions_unlocked(current_time)

            session = self._sessions.get(session_id)
            if session is None:
                return None

            session.last_seen = current_time
            self._sessions.move_to_end(session_id)
            return session.key

    def remove_session(self, session_id: str) -> None:
        """Remove a session (e.g. on disconnect)."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def encrypt(self, session_id: str, plaintext: bytes) -> bytes:
        """
        Encrypt data with the session's AES-256-GCM key.

        Returns:
            nonce(12) + ciphertext + tag(16).
        """
        key = self.get_session_key(session_id)
        if key is None:
            raise ValueError("Unknown session")
        nonce = os.urandom(_NONCE_LEN)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, session_id: str, data: bytes) -> bytes:
        """
        Decrypt data with the session's AES-256-GCM key.

        Args:
            data: nonce(12) + ciphertext + tag(16).
        """
        key = self.get_session_key(session_id)
        if key is None:
            raise ValueError("Unknown session")
        if len(data) < _NONCE_LEN + 16:
            raise ValueError("Data too short")
        nonce = data[:_NONCE_LEN]
        ct = data[_NONCE_LEN:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)
