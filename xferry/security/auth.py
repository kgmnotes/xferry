"""
HTTP Basic Authentication.
"""

import base64
import hashlib
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

AuthAttemptOutcome = Literal["succeeded", "failed", "error"]
AuthAdmissionDenialReason = Literal["capacity", "cooldown", "peer_capacity", "timeout"]
_DUMMY_HASH = "0" * 64
_DUMMY_SALT = "0" * 32


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
        self._lock = threading.Lock()
        self.realm = realm
        self._auth_callback = auth_callback

        # Hash passwords
        self._credentials: dict[str, tuple[str, str]] = {}  # {user: (hash, salt)}
        if credentials:
            for username, password in credentials.items():
                hashed, salt = hash_password(password)
                self._credentials[username] = (hashed, salt)

    def add_user(self, username: str, password: str) -> None:
        """Add a user."""
        hashed, salt = hash_password(password)
        with self._lock:
            self._credentials[username] = (hashed, salt)

    def remove_user(self, username: str) -> None:
        """Remove a user."""
        with self._lock:
            self._credentials.pop(username, None)

    @property
    def auth_callback(self) -> Callable[[str, str], bool] | None:
        """Return the current custom verifier as one synchronized snapshot."""
        with self._lock:
            return self._auth_callback

    @auth_callback.setter
    def auth_callback(self, callback: Callable[[str, str], bool] | None) -> None:
        """Atomically replace the custom verifier used by future attempts."""
        with self._lock:
            self._auth_callback = callback

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

        with self._lock:
            auth_callback = self._auth_callback
            credential = self._credentials.get(username)

        if auth_callback:
            result = auth_callback(username, password)
            return username if result else None

        if credential is None:
            verify_password(password, _DUMMY_HASH, _DUMMY_SALT)
            return None

        hashed, salt = credential
        result = verify_password(password, hashed, salt)
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


@dataclass(slots=True)
class _PeerAuthState:
    failures: int = 0
    verifying: int = 0
    outstanding: int = 0
    cooldown_until: float = 0.0
    last_seen: float = 0.0
    last_failure: float = 0.0


@dataclass(slots=True)
class _AuthWaiter:
    peer: str = field(repr=False)
    deadline: float
    wait_deadline: float
    granted: bool = False
    denied: "AuthAdmissionDenied | None" = None


@dataclass(frozen=True, slots=True)
class AuthAdmissionDenied:
    """Closed admission denial returned before password verification starts."""

    reason: AuthAdmissionDenialReason
    retry_after: int


class AuthAttemptLease:
    """One reserved authentication verification slot."""

    __slots__ = ("_controller", "_finished", "_peer")

    def __init__(self, controller: "AuthAdmissionController", peer: str) -> None:
        self._controller = controller
        self._peer = peer
        self._finished = False

    def finish(self, outcome: AuthAttemptOutcome) -> None:
        """Release the reserved verification slot exactly once."""
        self._controller._finish(self, outcome)

    def __repr__(self) -> str:
        return f"AuthAttemptLease(finished={self._finished!r})"


class AuthAdmissionController:
    """Bound Basic Auth verification concurrency and per-peer failure admission."""

    def __init__(
        self,
        *,
        workers: int = 10,
        max_failures: int = 5,
        cooldown: float = 30.0,
        max_peers: int = 4096,
        prune_interval: float = 5.0,
        wait_timeout: float = 2.0,
        max_pending: int | None = None,
        max_active: int | None = None,
        per_peer_pending: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if workers < 1:
            raise ValueError("workers must be at least 1")
        derived_max_pending = min(6, max(1, workers - 2))
        self.max_failures = _positive_int(max_failures, "max_failures")
        self.cooldown = _positive_float(cooldown, "cooldown")
        self.max_peers = _positive_int(max_peers, "max_peers")
        self.prune_interval = _non_negative_float(prune_interval, "prune_interval")
        self.wait_timeout = _non_negative_float(wait_timeout, "wait_timeout")
        self.max_pending = _positive_int(
            derived_max_pending if max_pending is None else max_pending,
            "max_pending",
        )
        self.max_active = _positive_int(
            min(2, self.max_pending) if max_active is None else max_active,
            "max_active",
        )
        self.per_peer_pending = _positive_int(
            self.max_pending if per_peer_pending is None else per_peer_pending,
            "per_peer_pending",
        )
        if self.max_active > self.max_pending:
            raise ValueError("max_active must not exceed max_pending")
        if self.per_peer_pending > self.max_pending:
            raise ValueError("per_peer_pending must not exceed max_pending")

        self._clock = clock
        self._condition = threading.Condition()
        self._peers: dict[str, _PeerAuthState] = {}
        self._waiters: list[_AuthWaiter] = []
        self._active = 0
        self._outstanding = 0
        self._last_prune = clock()

    def acquire(self, peer: str) -> AuthAttemptLease | AuthAdmissionDenied:
        """Reserve an auth verification slot or return a bounded denial."""
        if not isinstance(peer, str) or not peer:
            raise ValueError("peer must be a non-empty string")
        now = self._clock()
        with self._condition:
            self._prune_if_needed_locked(now, force=False)
            state = self._peers.get(peer)
            if state is None:
                if self._outstanding >= self.max_pending:
                    return self._deny("capacity", retry_after=1)
                state = self._state_for_peer_locked(peer, now)
                if state is None:
                    return self._deny("peer_capacity", retry_after=1)
            else:
                state.last_seen = now

            cooldown_denial = self._cooldown_denial_locked(state, now)
            if cooldown_denial is not None:
                self._drop_idle_peer_locked(peer, state)
                return cooldown_denial

            if state.outstanding >= self.per_peer_pending:
                return self._deny("peer_capacity", retry_after=1)
            if self._outstanding >= self.max_pending:
                return self._deny("capacity", retry_after=1)

            state.outstanding += 1
            state.last_seen = now
            self._outstanding += 1
            if not self._waiters and self._can_start_locked(state, now):
                self._start_locked(state, now)
                return AuthAttemptLease(self, peer)

            waiter = _AuthWaiter(
                peer=peer,
                deadline=now + self.wait_timeout,
                wait_deadline=time.monotonic() + self.wait_timeout,
            )
            self._waiters.append(waiter)
            self._promote_waiters_locked(now)
            self._condition.notify_all()

            while True:
                if waiter.granted:
                    return AuthAttemptLease(self, peer)
                if waiter.denied is not None:
                    return waiter.denied

                now = self._clock()
                self._promote_waiters_locked(now)
                if waiter.granted:
                    return AuthAttemptLease(self, peer)
                if waiter.denied is not None:
                    return waiter.denied

                remaining = min(
                    waiter.deadline - now,
                    waiter.wait_deadline - time.monotonic(),
                )
                if remaining <= 0:
                    denial = self._deny("timeout", retry_after=1)
                    waiter.denied = denial
                    self._remove_waiter_locked(waiter)
                    return denial
                self._condition.wait(timeout=remaining)

    def snapshot(self) -> dict[str, int]:
        """Return low-cardinality controller state for tests and diagnostics."""
        with self._condition:
            return {
                "active": self._active,
                "queued": len(self._waiters),
                "peers": len(self._peers),
            }

    def _finish(self, lease: AuthAttemptLease, outcome: AuthAttemptOutcome) -> None:
        if outcome not in {"succeeded", "failed", "error"}:
            raise ValueError("unknown auth attempt outcome")
        now = self._clock()
        with self._condition:
            if lease._finished:
                return
            lease._finished = True
            state = self._peers.get(lease._peer)
            if state is None or state.verifying < 1 or state.outstanding < 1:
                raise RuntimeError("authentication lease state is inconsistent")
            self._active -= 1
            state.verifying -= 1
            state.outstanding -= 1
            state.last_seen = now
            self._outstanding -= 1
            if outcome == "succeeded":
                state.failures = 0
                state.cooldown_until = 0.0
                state.last_failure = 0.0
            else:
                state.failures += 1
                state.last_failure = now
                if state.failures >= self.max_failures:
                    state.cooldown_until = now + self.cooldown
            self._drop_idle_peer_locked(lease._peer, state)
            self._promote_waiters_locked(now)
            self._condition.notify_all()

    def _state_for_peer_locked(self, peer: str, now: float) -> _PeerAuthState | None:
        state = self._peers.get(peer)
        if state is not None:
            state.last_seen = now
            return state

        if len(self._peers) >= self.max_peers:
            self._prune_if_needed_locked(now, force=True)
        if len(self._peers) >= self.max_peers:
            return None
        state = _PeerAuthState(last_seen=now)
        self._peers[peer] = state
        return state

    def _can_start_locked(self, state: _PeerAuthState, now: float) -> bool:
        return (
            self._active < self.max_active
            and self._cooldown_denial_locked(state, now) is None
            and state.failures + state.verifying < self.max_failures
        )

    def _start_locked(self, state: _PeerAuthState, now: float) -> None:
        self._active += 1
        state.verifying += 1
        state.last_seen = now

    def _promote_waiters_locked(self, now: float) -> None:
        index = 0
        while self._active < self.max_active and index < len(self._waiters):
            waiter = self._waiters[index]
            state = self._peers.get(waiter.peer)
            if state is None:
                waiter.denied = self._deny("peer_capacity", retry_after=1)
                del self._waiters[index]
                continue

            cooldown_denial = self._cooldown_denial_locked(state, now)
            if cooldown_denial is not None:
                waiter.denied = cooldown_denial
                self._release_waiter_reservation_locked(waiter, state)
                del self._waiters[index]
                continue

            if waiter.deadline <= now or waiter.wait_deadline <= time.monotonic():
                waiter.denied = self._deny("timeout", retry_after=1)
                self._release_waiter_reservation_locked(waiter, state)
                del self._waiters[index]
                continue

            if self._can_start_locked(state, now):
                waiter.granted = True
                del self._waiters[index]
                self._start_locked(state, now)
                continue

            index += 1

    def _remove_waiter_locked(self, waiter: _AuthWaiter) -> None:
        try:
            self._waiters.remove(waiter)
        except ValueError:
            return
        state = self._peers.get(waiter.peer)
        if state is not None:
            self._release_waiter_reservation_locked(waiter, state)

    def _release_waiter_reservation_locked(
        self,
        waiter: _AuthWaiter,
        state: _PeerAuthState,
    ) -> None:
        if state.outstanding < 1 or self._outstanding < 1:
            raise RuntimeError("authentication waiter reservation is inconsistent")
        state.outstanding -= 1
        self._outstanding -= 1
        self._drop_idle_peer_locked(waiter.peer, state)

    def _cooldown_denial_locked(
        self,
        state: _PeerAuthState,
        now: float,
    ) -> AuthAdmissionDenied | None:
        if state.failures < self.max_failures:
            return None
        if now >= state.cooldown_until:
            state.failures = 0
            state.cooldown_until = 0.0
            state.last_failure = 0.0
            return None
        return self._deny(
            "cooldown",
            retry_after=max(1, math.ceil(state.cooldown_until - now)),
        )

    def _prune_if_needed_locked(self, now: float, *, force: bool) -> None:
        if not force and now - self._last_prune < self.prune_interval:
            return
        self._last_prune = now
        for peer, state in list(self._peers.items()):
            if state.outstanding:
                continue
            if state.failures and now - state.last_failure < self.cooldown:
                continue
            del self._peers[peer]

    def _drop_idle_peer_locked(self, peer: str, state: _PeerAuthState) -> None:
        if state.outstanding == 0 and state.failures == 0:
            self._peers.pop(peer, None)

    @staticmethod
    def _deny(
        reason: AuthAdmissionDenialReason,
        *,
        retry_after: int,
    ) -> AuthAdmissionDenied:
        return AuthAdmissionDenied(reason=reason, retry_after=max(1, int(retry_after)))


def _positive_int(value: int, name: str) -> int:
    if value < 1:
        raise ValueError(f"{name} must be at least 1")
    return value


def _non_negative_float(value: float, name: str) -> float:
    if value < 0:
        raise ValueError(f"{name} must be at least 0")
    return float(value)


def _positive_float(value: float, name: str) -> float:
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return float(value)
