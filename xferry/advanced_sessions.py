"""Immutable, per-server storage for token-scoped advanced sessions."""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Literal, TypeAlias

AuthMode: TypeAlias = Literal["basic", "no_auth"]
ADVANCED_UPLOAD_METHODS = frozenset({"POST", "PUT", "PATCH", "NONE"})
ADVANCED_SESSION_DECODERS = frozenset({"auto", "raw", "json", "text", "form", "xml", "multipart"})
_TOKEN_BYTES = 32
_MAX_SESSIONS = 64
_ABSOLUTE_LIFETIME = timedelta(minutes=60)
_IDLE_TIMEOUT = timedelta(minutes=15)
_MAX_COLLISION_ATTEMPTS = 3


class AdvancedSessionCapacityExhausted(Exception):
    """Raised when all 64 live advanced-session slots are occupied."""


class AdvancedSessionTokenCollision(RuntimeError):
    """Raised when a random source repeatedly returns a live token value."""


class AdvancedSessionPrincipal:
    """The already-authorized auth mode and exact Basic owner, if any."""

    __slots__ = ("_auth_mode", "_owner")
    _auth_mode: AuthMode
    _owner: str | None

    def __init__(self, auth_mode: AuthMode, owner: str | None) -> None:
        if auth_mode == "basic" and isinstance(owner, str):
            object.__setattr__(self, "_auth_mode", auth_mode)
            object.__setattr__(self, "_owner", owner)
            return
        if auth_mode == "no_auth" and owner is None:
            object.__setattr__(self, "_auth_mode", auth_mode)
            object.__setattr__(self, "_owner", owner)
            return
        raise ValueError("invalid advanced-session principal")

    @property
    def auth_mode(self) -> AuthMode:
        return self._auth_mode

    @property
    def owner(self) -> str | None:
        return self._owner

    def __repr__(self) -> str:
        owner = "'<redacted>'" if self._owner is not None else "None"
        return f"AdvancedSessionPrincipal(auth_mode={self._auth_mode!r}, owner={owner})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AdvancedSessionPrincipal):
            return NotImplemented
        return self.auth_mode == other.auth_mode and self.owner == other.owner

    def __hash__(self) -> int:
        return hash((self.auth_mode, self.owner))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AdvancedSessionPrincipal is immutable")


SessionPrincipal: TypeAlias = AdvancedSessionPrincipal


@dataclass(frozen=True, slots=True)
class AdvancedSession:
    """Immutable public session settings and lifecycle metadata."""

    prefix: str
    decoder: str
    diagnostic_headers: bool
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime


class AdvancedSessionCreation:
    """The sole result that contains a newly minted raw bearer token."""

    __slots__ = ("_token", "_session")
    _token: str
    _session: AdvancedSession

    def __init__(self, token: str, session: AdvancedSession) -> None:
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_session", session)

    @property
    def token(self) -> str:
        return self._token

    @property
    def session(self) -> AdvancedSession:
        return self._session

    def __repr__(self) -> str:
        return f"AdvancedSessionCreation(token='<redacted>', session={self._session!r})"

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AdvancedSessionCreation is immutable")


AdvancedSessionCreationResult: TypeAlias = AdvancedSessionCreation
AdvancedSessionDispatchValue: TypeAlias = str | bool | None


class _AdvancedSessionTouchHandle:
    """Private redacted handle for one already-authorized data-plane touch."""

    __slots__ = ("_token_digest", "_created_at")
    _token_digest: bytes
    _created_at: datetime

    def __init__(self, *, token_digest: bytes, created_at: datetime) -> None:
        object.__setattr__(self, "_token_digest", token_digest)
        object.__setattr__(self, "_created_at", created_at)

    def __repr__(self) -> str:
        return "_AdvancedSessionTouchHandle(token_digest='<redacted>')"

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("_AdvancedSessionTouchHandle is immutable")


class AdvancedSessionDispatch(Mapping[str, AdvancedSessionDispatchValue]):
    """One authorized request-local Advanced data-plane routing decision."""

    __slots__ = ("_session", "_principal", "_direct_peer", "_touch_handle")
    _session: AdvancedSession
    _principal: AdvancedSessionPrincipal
    _direct_peer: tuple[str, int] | None
    _touch_handle: _AdvancedSessionTouchHandle | None

    def __init__(
        self,
        *,
        session: AdvancedSession,
        principal: AdvancedSessionPrincipal,
        direct_peer: tuple[str, int] | None = None,
        touch_handle: _AdvancedSessionTouchHandle | None = None,
    ) -> None:
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_principal", principal)
        object.__setattr__(self, "_direct_peer", direct_peer)
        object.__setattr__(self, "_touch_handle", touch_handle)

    @property
    def session(self) -> AdvancedSession:
        return self._session

    @property
    def principal(self) -> AdvancedSessionPrincipal:
        return self._principal

    @property
    def direct_peer(self) -> tuple[str, int] | None:
        return self._direct_peer

    @property
    def prefix(self) -> str:
        return self._session.prefix

    @property
    def decoder(self) -> str:
        return self._session.decoder

    @property
    def diagnostic_headers(self) -> bool:
        return self._session.diagnostic_headers

    def __repr__(self) -> str:
        return (
            "AdvancedSessionDispatch("
            f"prefix={self.prefix!r}, "
            f"decoder={self.decoder!r}, "
            f"diagnostic_headers={self.diagnostic_headers!r}, "
            f"direct_peer={self._direct_peer!r})"
        )

    def __getitem__(self, key: str) -> AdvancedSessionDispatchValue:
        if key == "prefix":
            return self.prefix
        if key == "decoder":
            return self.decoder
        if key == "diagnostic_headers":
            return self.diagnostic_headers
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("prefix", "decoder", "diagnostic_headers"))

    def __len__(self) -> int:
        return 3

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AdvancedSessionDispatch is immutable")


class _StoredAdvancedSession:
    """Private lookup material paired with a public immutable session snapshot."""

    __slots__ = ("_token_digest", "_session", "_principal")
    _token_digest: bytes
    _session: AdvancedSession
    _principal: AdvancedSessionPrincipal

    def __init__(
        self,
        *,
        token_digest: bytes,
        session: AdvancedSession,
        principal: AdvancedSessionPrincipal,
    ) -> None:
        object.__setattr__(self, "_token_digest", token_digest)
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_principal", principal)

    @property
    def session(self) -> AdvancedSession:
        return self._session

    @property
    def principal(self) -> AdvancedSessionPrincipal:
        return self._principal

    def with_session(self, session: AdvancedSession) -> _StoredAdvancedSession:
        return _StoredAdvancedSession(
            token_digest=self._token_digest,
            session=session,
            principal=self._principal,
        )

    def __repr__(self) -> str:
        return (
            "_StoredAdvancedSession("
            "token_digest='<redacted>', "
            f"session={self._session!r}, "
            f"principal={self._principal!r})"
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("_StoredAdvancedSession is immutable")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_advanced_session_prefix(prefix: str) -> None:
    """Validate the immutable data-plane prefix used by an Advanced session."""
    if not isinstance(prefix, str) or not prefix.startswith("/"):
        raise ValueError("prefix must be an absolute path")
    if (
        "?" in prefix
        or "#" in prefix
        or "%" in prefix
        or "\\" in prefix
        or _has_control_characters(prefix)
    ):
        raise ValueError("prefix contains unsupported characters")
    if prefix != "/" and prefix.endswith("/"):
        raise ValueError("prefix must be normalized")

    if prefix == "/":
        return

    segments = prefix.split("/")[1:]
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError("prefix must be normalized")
    if prefix == "/_xferry" or prefix.startswith("/_xferry/"):
        raise ValueError("prefix cannot use the /_xferry namespace")


def advanced_session_prefix_matches(
    prefix: str,
    raw_path: str,
    decoded_path: str,
) -> bool:
    """Match the raw prefix while reserving ``/_xferry`` in both path forms."""
    if (
        not isinstance(raw_path, str)
        or not raw_path.startswith("/")
        or not isinstance(decoded_path, str)
        or not decoded_path.startswith("/")
    ):
        return False
    if any(path == "/_xferry" or path.startswith("/_xferry/") for path in (raw_path, decoded_path)):
        return False
    if prefix == "/":
        return raw_path.startswith("/")
    return raw_path == prefix or raw_path.startswith(prefix + "/")


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


class AdvancedSessionStore:
    """A bounded, lock-protected in-memory store owned by one server instance."""

    def __init__(
        self,
        *,
        now: Callable[[], datetime] = _utc_now,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._now = now
        self._random_bytes = random_bytes
        self._lock = threading.RLock()
        self._sessions: dict[bytes, _StoredAdvancedSession] = {}

    def create(
        self,
        *,
        prefix: str,
        decoder: str,
        diagnostic_headers: bool,
        principal: AdvancedSessionPrincipal,
    ) -> AdvancedSessionCreation:
        """Create a session after purging expiry and checking fixed capacity."""
        self._validate_principal(principal)
        with self._lock:
            now = self._current_time()
            self._purge_expired_locked(now)
            if len(self._sessions) >= _MAX_SESSIONS:
                raise AdvancedSessionCapacityExhausted("advanced session capacity exhausted")

            for _attempt in range(_MAX_COLLISION_ATTEMPTS):
                raw_bytes = self._random_bytes(_TOKEN_BYTES)
                if not isinstance(raw_bytes, bytes) or len(raw_bytes) != _TOKEN_BYTES:
                    raise ValueError("advanced-session random source must return 32 bytes")
                token = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
                token_digest = self._digest(token)
                if self._locate_digest_locked(token_digest) is None:
                    session = AdvancedSession(
                        prefix=prefix,
                        decoder=decoder,
                        diagnostic_headers=diagnostic_headers,
                        created_at=now,
                        expires_at=now + _ABSOLUTE_LIFETIME,
                        last_activity_at=now,
                    )
                    self._sessions[token_digest] = _StoredAdvancedSession(
                        token_digest=token_digest,
                        session=session,
                        principal=principal,
                    )
                    return AdvancedSessionCreation(token=token, session=session)

            raise AdvancedSessionTokenCollision("advanced-session token collision")

    def resolve(
        self,
        token: str,
        principal: AdvancedSessionPrincipal,
        *,
        touch: bool = False,
    ) -> AdvancedSession | None:
        """Return a matching session and optionally refresh only its idle activity."""
        self._validate_principal(principal)
        with self._lock:
            now = self._current_time()
            self._purge_expired_locked(now)
            stored = self._locate_locked(token)
            if stored is None or not self._principal_matches(stored.principal, principal):
                return None
            if not touch:
                return stored.session

            refreshed = replace(stored.session, last_activity_at=now)
            self._sessions[stored._token_digest] = stored.with_session(refreshed)
            return refreshed

    def touch_handle_for_resolved_session(
        self,
        token: str,
        session: AdvancedSession,
    ) -> _AdvancedSessionTouchHandle:
        """Bind a private touch handle after the admission lookup has succeeded."""
        return _AdvancedSessionTouchHandle(
            token_digest=self._digest(token),
            created_at=session.created_at,
        )

    def touch_dispatch(self, dispatch: AdvancedSessionDispatch) -> AdvancedSession | None:
        """Refresh idle activity for an already-bound dispatch without bearer lookup."""
        handle = dispatch._touch_handle
        if handle is None:
            return None
        with self._lock:
            now = self._current_time()
            self._purge_expired_locked(now)
            stored = self._sessions.get(handle._token_digest)
            if stored is None or stored.session.created_at != handle._created_at:
                return None
            refreshed = replace(stored.session, last_activity_at=now)
            self._sessions[handle._token_digest] = stored.with_session(refreshed)
            return refreshed

    def revoke(self, token: str, principal: AdvancedSessionPrincipal) -> bool:
        """Remove a matching session exactly once without disclosing misses."""
        self._validate_principal(principal)
        with self._lock:
            now = self._current_time()
            self._purge_expired_locked(now)
            stored = self._locate_locked(token)
            if stored is None or not self._principal_matches(stored.principal, principal):
                return False
            del self._sessions[stored._token_digest]
            return True

    def invalidate_all(self) -> None:
        """Drop every live session, for example after an auth-mode transition."""
        with self._lock:
            self._purge_expired_locked(self._current_time())
            self._sessions.clear()

    def _purge_expired_locked(self, now: datetime) -> None:
        expired = [
            digest
            for digest, stored in self._sessions.items()
            if (
                now >= stored.session.expires_at
                or now >= stored.session.last_activity_at + _IDLE_TIMEOUT
            )
        ]
        for digest in expired:
            del self._sessions[digest]

    def _locate_locked(self, token: str) -> _StoredAdvancedSession | None:
        if not isinstance(token, str):
            return None
        return self._locate_digest_locked(self._digest(token))

    def _locate_digest_locked(self, candidate: bytes) -> _StoredAdvancedSession | None:
        match: _StoredAdvancedSession | None = None
        for stored in self._sessions.values():
            if secrets.compare_digest(candidate, stored._token_digest):
                match = stored
        return match

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8")).digest()

    @staticmethod
    def _principal_matches(
        stored_principal: AdvancedSessionPrincipal,
        principal: AdvancedSessionPrincipal,
    ) -> bool:
        return (
            stored_principal.auth_mode == principal.auth_mode
            and stored_principal.owner == principal.owner
        )

    @staticmethod
    def _validate_principal(principal: AdvancedSessionPrincipal) -> None:
        if not isinstance(principal, AdvancedSessionPrincipal):
            raise TypeError("principal must be an AdvancedSessionPrincipal")

    def _current_time(self) -> datetime:
        now = self._now()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("advanced-session clock must return an aware datetime")
        return now.astimezone(timezone.utc)
