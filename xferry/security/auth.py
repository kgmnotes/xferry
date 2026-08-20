"""
HTTP Basic Authentication.
"""

import base64
import hashlib
import logging
import secrets
import threading
import time
from collections.abc import Callable

logger = logging.getLogger("xferry")


def parse_basic_auth(auth_header: str) -> tuple[str, str] | None:
    """
    Parse the Authorization header for Basic Auth.

    Args:
        auth_header: Value of the Authorization header.

    Returns:
        Tuple (username, password) or None if the format is invalid.
    """
    if not auth_header:
        return None

    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None

    try:
        decoded = base64.b64decode(parts[1]).decode("utf-8")
        if ":" not in decoded:
            return None
        username, password = decoded.split(":", 1)
        return username, password
    except Exception:
        return None


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """
    Hash a password with salt using PBKDF2-SHA256.

    Args:
        password: Password to hash.
        salt: Salt value (if None, a new one is generated).

    Returns:
        Tuple (hash, salt).
    """
    if salt is None:
        salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=600_000,
    ).hex()
    return hashed, salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """
    Verify a password against stored hash.

    Args:
        password: Password to verify.
        hashed: Stored hash value.
        salt: Salt value.

    Returns:
        True if the password is correct.
    """
    computed, _ = hash_password(password, salt)
    return secrets.compare_digest(computed, hashed)


class BasicAuthenticator:
    """
    HTTP Basic Authentication handler.

    Supports:
    - Simple username:password verification
    - Hashed password storage
    - Custom authentication callback
    """

    def __init__(
        self,
        credentials: dict[str, str] | None = None,
        auth_callback: Callable[[str, str], bool] | None = None,
        realm: str = "Restricted Area",
    ):
        """
        Args:
            credentials: Dict {username: password} (plaintext).
            auth_callback: Verification function (username, password) -> bool.
            realm: Realm for the WWW-Authenticate header.
        """
        self.realm = realm
        self.auth_callback = auth_callback

        # Hash passwords
        self._credentials: dict[str, tuple[str, str]] = {}  # {user: (hash, salt)}
        if credentials:
            for username, password in credentials.items():
                hashed, salt = hash_password(password)
                self._credentials[username] = (hashed, salt)

    def add_user(self, username: str, password: str) -> None:
        """Add a user."""
        hashed, salt = hash_password(password)
        self._credentials[username] = (hashed, salt)

    def remove_user(self, username: str) -> None:
        """Remove a user."""
        self._credentials.pop(username, None)

    def authenticate(self, auth_header: str | None) -> bool:
        """
        Verify authentication.

        Args:
            auth_header: Value of the Authorization header.

        Returns:
            True if authentication is successful.
        """
        return self.verify(auth_header) is not None

    def verify(self, auth_header: str | None) -> str | None:
        """Return the exact verified username, or ``None`` when verification fails."""
        parsed = parse_basic_auth(auth_header) if auth_header else None
        if parsed is None:
            return None

        username, password = parsed
        logger.debug("Auth attempt")

        # Custom callback
        if self.auth_callback:
            result = self.auth_callback(username, password)
            if result:
                logger.debug("Auth OK")
            else:
                logger.warning("Auth failed")
            return username if result else None

        # Check stored credentials
        if username not in self._credentials:
            verify_password(password, "0" * 64, "0" * 32)
            logger.warning("Auth failed")
            return None

        hashed, salt = self._credentials[username]
        result = verify_password(password, hashed, salt)
        if result:
            logger.debug("Auth OK")
        else:
            logger.warning("Auth failed")
        return username if result else None

    def get_www_authenticate_header(self) -> str:
        """Get the WWW-Authenticate header value."""
        return f'Basic realm="{self.realm}"'


def generate_random_credentials() -> tuple[str, str]:
    """
    Generate random credentials.

    Returns:
        Tuple (username, password).
    """
    username = f"user_{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(16)
    return username, password


class AuthRateLimiter:
    """IP-based auth rate limiting. Blocks IP after max_attempts failures for cooldown seconds."""

    def __init__(self, max_attempts: int = 5, cooldown: float = 30.0):
        self.max_attempts = max_attempts
        self.cooldown = cooldown
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently rate-limited."""
        with self._lock:
            now = time.monotonic()
            if ip not in self._failures:
                return False
            # Clean expired entries
            self._failures[ip] = [t for t in self._failures[ip] if now - t < self.cooldown]
            if not self._failures[ip]:
                del self._failures[ip]
                return False
            return len(self._failures[ip]) >= self.max_attempts

    def record_failure(self, ip: str) -> None:
        """Record a failed auth attempt."""
        with self._lock:
            if ip not in self._failures:
                self._failures[ip] = []
            self._failures[ip].append(time.monotonic())

    def reset(self, ip: str) -> None:
        """Reset failures for IP after successful auth."""
        with self._lock:
            self._failures.pop(ip, None)
