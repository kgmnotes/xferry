"""Behavioral coverage for the in-memory advanced-session store."""

from __future__ import annotations

import base64
import concurrent.futures
import dataclasses
import re
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest

from tests.server_factory import make_server
from xferry.security.auth import BasicAuthenticator


class Clock:
    """Small deterministic UTC clock for store behavior tests."""

    def __init__(self) -> None:
        self.value = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


class SequentialBytes:
    """Deterministic 32-byte source that records random allocations."""

    def __init__(self, *values: bytes) -> None:
        self.values = list(values)
        self.calls: list[int] = []

    def __call__(self, length: int) -> bytes:
        self.calls.append(length)
        return self.values.pop(0)


def basic(owner: str = "Alice") -> object:
    from xferry.advanced_sessions import AdvancedSessionPrincipal

    return AdvancedSessionPrincipal("basic", owner)


def no_auth() -> object:
    from xferry.advanced_sessions import AdvancedSessionPrincipal

    return AdvancedSessionPrincipal("no_auth", None)


def make_store(
    clock: Clock,
    random_bytes: Callable[[int], bytes],
) -> object:
    from xferry.advanced_sessions import AdvancedSessionStore

    return AdvancedSessionStore(now=clock.now, random_bytes=random_bytes)


def create(store: object, *, principal: object, prefix: str = "/advanced") -> object:
    return store.create(  # type: ignore[attr-defined]
        prefix=prefix,
        decoder="auto",
        diagnostic_headers=True,
        principal=principal,
    )


def test_create_returns_only_creation_token_and_an_immutable_session_snapshot() -> None:
    """Catches a session record retaining/exposing its bearer token or mutable settings."""
    clock = Clock()
    source = SequentialBytes(bytes(range(32)))
    result = create(make_store(clock, source), principal=basic())
    session = result.session  # type: ignore[attr-defined]

    assert result.token == "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"  # type: ignore[attr-defined]
    assert source.calls == [32]
    assert not hasattr(session, "token")
    assert session.prefix == "/advanced"
    assert session.decoder == "auto"
    assert session.diagnostic_headers is True
    assert session.created_at == clock.value
    assert session.last_activity_at == clock.value
    assert session.expires_at == datetime(2026, 8, 14, 13, 0, tzinfo=timezone.utc)

    with pytest.raises(dataclasses.FrozenInstanceError):
        session.prefix = "/changed"  # type: ignore[misc]


def test_public_session_metadata_never_exposes_token_digest_or_owner() -> None:
    """Catches internal lookup material leaking through a returned session record."""
    clock = Clock()
    created = create(
        make_store(clock, SequentialBytes(b"x" * 32)),
        principal=basic("SensitiveOwner"),
    )
    session = created.session  # type: ignore[attr-defined]
    field_names = {field.name for field in dataclasses.fields(session)}
    session_repr = repr(session)
    session_metadata = dataclasses.asdict(session)

    assert field_names.isdisjoint({"token", "token_digest", "digest", "owner", "auth_mode"})
    assert "token" not in session_repr
    assert "digest" not in session_repr
    assert "SensitiveOwner" not in session_repr
    assert "token" not in session_metadata
    assert "digest" not in session_metadata
    assert "owner" not in session_metadata
    assert "auth_mode" not in session_metadata
    assert created.token not in session_repr  # type: ignore[attr-defined]
    assert created.token not in repr(session_metadata)  # type: ignore[attr-defined]
    assert "SensitiveOwner" not in repr(session_metadata)


def test_sensitive_session_objects_are_not_generically_dataclass_serializable() -> None:
    """Catches token, owner, or digest exposure through asdict/repr debug paths."""
    from xferry.advanced_sessions import (
        AdvancedSessionDispatch,
        AdvancedSessionPrincipal,
        AdvancedSessionStore,
    )

    clock = Clock()
    store = make_store(clock, SequentialBytes(b"s" * 32))
    principal = AdvancedSessionPrincipal("basic", "SensitiveOwner")
    created = create(store, principal=principal)
    session = created.session  # type: ignore[attr-defined]
    token = created.token  # type: ignore[attr-defined]
    digest_hex = AdvancedSessionStore._digest(token).hex()
    stored = next(iter(store._sessions.values()))  # type: ignore[attr-defined]
    dispatch = AdvancedSessionDispatch(
        session=session,
        principal=principal,
        direct_peer=("203.0.113.77", 4444),
    )

    for sensitive_object in (created, principal, dispatch, stored):
        with pytest.raises(TypeError):
            dataclasses.asdict(sensitive_object)
        rendered = repr(sensitive_object)
        assert token not in rendered
        assert "SensitiveOwner" not in rendered
        assert digest_hex not in rendered

    assert dict(dispatch) == {
        "prefix": "/advanced",
        "decoder": "auto",
        "diagnostic_headers": True,
    }
    assert list(dispatch) == ["prefix", "decoder", "diagnostic_headers"]
    assert token not in repr(dict(dispatch))
    assert "SensitiveOwner" not in repr(dict(dispatch))
    assert digest_hex not in repr(dict(dispatch))


def test_authorized_dispatch_keeps_no_raw_bearer_property_slot_or_debug_surface() -> None:
    """Catches admission retaining the authorized bearer after binding its touch handle."""
    from xferry.advanced_sessions import AdvancedSessionDispatch

    clock = Clock()
    store = make_store(clock, SequentialBytes(b"d" * 32))
    created = create(
        store,
        principal=basic("SensitiveOwner"),
    )
    token = created.token  # type: ignore[attr-defined]
    dispatch = AdvancedSessionDispatch(
        session=created.session,  # type: ignore[attr-defined]
        principal=basic("SensitiveOwner"),
        direct_peer=("203.0.113.77", 4444),
        touch_handle=store.touch_handle_for_resolved_session(token, created.session),  # type: ignore[attr-defined]
    )

    assert not hasattr(dispatch, "token")
    assert "_token" not in AdvancedSessionDispatch.__slots__
    assert token not in repr(dispatch)
    assert token not in repr(dict(dispatch))
    assert token not in repr(tuple(dispatch.items()))


def test_token_is_256_bits_unpadded_base64url_and_sequential_sessions_are_independent() -> None:
    """Catches weak, padded, non-URL-safe, or reused token allocation."""
    clock = Clock()
    source = SequentialBytes(b"\xff" * 32, b"\x01" * 32)
    store = make_store(clock, source)

    first = create(store, principal=no_auth())
    second = create(store, principal=no_auth())

    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", first.token)  # type: ignore[attr-defined]
    assert "=" not in first.token  # type: ignore[attr-defined]
    assert base64.urlsafe_b64decode(first.token + "=") == b"\xff" * 32  # type: ignore[attr-defined]
    assert first.token != second.token  # type: ignore[attr-defined]
    assert store.resolve(first.token, no_auth()) is first.session  # type: ignore[attr-defined]
    assert store.resolve(second.token, no_auth()) is second.session  # type: ignore[attr-defined]


def test_wrong_random_length_and_repeated_token_collision_fail_closed() -> None:
    """Catches malformed entropy and collision handling that overwrites a live session."""
    clock = Clock()
    malformed = make_store(clock, lambda _length: b"too short")
    with pytest.raises(ValueError, match="32"):
        create(malformed, principal=no_auth())

    source = SequentialBytes(b"x" * 32, b"x" * 32, b"x" * 32, b"x" * 32)
    store = make_store(clock, source)
    first = create(store, principal=no_auth())

    with pytest.raises(RuntimeError, match="collision"):
        create(store, principal=no_auth())

    assert store.resolve(first.token, no_auth()) is first.session  # type: ignore[attr-defined]


def test_expiry_boundaries_touch_and_no_touch_preserve_fixed_absolute_expiry() -> None:
    """Catches inclusive expiry, no-touch refresh, or touches extending absolute lifetime."""
    clock = Clock()
    store = make_store(clock, SequentialBytes(b"a" * 32, b"b" * 32))
    created = create(store, principal=basic())

    clock.advance(timedelta(minutes=14, seconds=59))
    untouched = store.resolve(created.token, basic())  # type: ignore[attr-defined]
    assert untouched is created.session  # type: ignore[attr-defined]
    assert untouched.last_activity_at == created.session.last_activity_at  # type: ignore[attr-defined]

    touched = store.resolve(created.token, basic(), touch=True)  # type: ignore[attr-defined]
    assert touched is not created.session  # type: ignore[attr-defined]
    assert touched.last_activity_at == clock.value
    assert touched.expires_at == created.session.expires_at  # type: ignore[attr-defined]

    clock.value = created.session.expires_at  # type: ignore[attr-defined]
    assert store.resolve(created.token, basic(), touch=True) is None  # type: ignore[attr-defined]
    replacement = create(store, principal=basic())
    assert replacement.token != created.token  # type: ignore[attr-defined]


def test_idle_expiry_at_its_exact_boundary_and_rejected_lookups_never_touch() -> None:
    """Catches rejected or no-touch operations prolonging the idle lifetime."""
    clock = Clock()
    store = make_store(clock, SequentialBytes(b"a" * 32))
    created = create(store, principal=basic("Alice"))

    clock.advance(timedelta(minutes=14, seconds=59))
    assert store.resolve(created.token, basic("Bob"), touch=True) is None  # type: ignore[attr-defined]
    assert store.resolve(created.token, no_auth(), touch=True) is None  # type: ignore[attr-defined]
    assert store.resolve("unknown", basic("Alice"), touch=True) is None

    clock.advance(timedelta(seconds=1))
    assert store.resolve(created.token, basic("Alice"), touch=True) is None  # type: ignore[attr-defined]


def test_capacity_is_64_purges_before_randomness_and_revoke_frees_a_slot() -> None:
    """Catches eviction, allocation before capacity, or stale sessions blocking replacement."""
    from xferry.advanced_sessions import AdvancedSessionCapacityExhausted

    clock = Clock()
    source = SequentialBytes(*(number.to_bytes(32, "big") for number in range(66)))
    store = make_store(clock, source)
    sessions = [create(store, principal=no_auth()) for _ in range(64)]

    with pytest.raises(AdvancedSessionCapacityExhausted):
        create(store, principal=no_auth())
    assert source.calls == [32] * 64
    assert store.resolve(sessions[0].token, no_auth()) is sessions[0].session  # type: ignore[attr-defined]

    assert store.revoke(sessions[0].token, no_auth()) is True  # type: ignore[attr-defined]
    replacement = create(store, principal=no_auth())
    assert replacement.token != sessions[0].token  # type: ignore[attr-defined]

    clock.advance(timedelta(minutes=60))
    assert create(store, principal=no_auth()).token  # type: ignore[attr-defined]
    assert source.calls == [32] * 66


def test_revoke_owner_and_mode_outcomes_are_generic_and_case_sensitive() -> None:
    """Catches owner normalization or revoking a session belonging to another principal."""
    clock = Clock()
    store = make_store(clock, SequentialBytes(b"a" * 32, b"b" * 32))
    alice = create(store, principal=basic("Alice"))
    lower = create(store, principal=basic("alice"))

    assert store.resolve(alice.token, basic("alice")) is None  # type: ignore[attr-defined]
    assert store.revoke(alice.token, basic("Bob")) is False  # type: ignore[attr-defined]
    assert store.revoke(alice.token, no_auth()) is False  # type: ignore[attr-defined]
    assert store.revoke("unknown", basic("Alice")) is False
    assert store.resolve(alice.token, basic("Alice")) is alice.session  # type: ignore[attr-defined]
    assert store.resolve(lower.token, basic("alice")) is lower.session  # type: ignore[attr-defined]
    assert store.revoke(alice.token, basic("Alice")) is True  # type: ignore[attr-defined]
    assert store.revoke(alice.token, basic("Alice")) is False  # type: ignore[attr-defined]


def test_lookup_compares_every_live_digest_for_hit_at_any_position_and_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches an early-exit token comparison that leaks lookup position."""
    import xferry.advanced_sessions as sessions

    clock = Clock()
    store = make_store(clock, SequentialBytes(b"a" * 32, b"b" * 32, b"c" * 32))
    created = [create(store, principal=no_auth()) for _ in range(3)]
    calls: list[tuple[bytes, bytes]] = []
    real_compare = sessions.secrets.compare_digest

    def recording_compare(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(sessions.secrets, "compare_digest", recording_compare)

    lookups = (
        (created[0].token, created[0].session),  # type: ignore[attr-defined]
        (created[-1].token, created[-1].session),  # type: ignore[attr-defined]
        ("missing", None),
    )
    for token, expected in lookups:
        calls.clear()
        assert store.resolve(token, no_auth()) is expected
        assert len(calls) == 3


def test_server_store_is_per_instance_and_auth_mode_transitions_invalidate_only_on_boundary(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """Catches process-wide sessions or credential rotation being treated as a mode change."""
    first = make_server(root_dir=str(tmp_path / "first"), quiet=True)
    second = make_server(root_dir=str(tmp_path / "second"), quiet=True)
    created = first.advanced_session_store.create(
        prefix="/advanced",
        decoder="auto",
        diagnostic_headers=False,
        principal=no_auth(),
    )

    assert second.advanced_session_store.resolve(created.token, no_auth()) is None
    first.set_authenticator(BasicAuthenticator({"Alice": "first"}))
    assert first.advanced_session_store.resolve(created.token, no_auth()) is None

    retained = first.advanced_session_store.create(
        prefix="/advanced",
        decoder="auto",
        diagnostic_headers=False,
        principal=basic(),
    )
    first.set_authenticator(BasicAuthenticator({"Alice": "rotated"}))
    assert first.advanced_session_store.resolve(retained.token, basic()) is retained.session
    first.set_authenticator(None)
    assert first.advanced_session_store.resolve(retained.token, basic()) is None


def test_concurrent_creation_is_bounded_to_64_successes() -> None:
    """Catches a create race allowing more than the fixed live-session capacity."""
    from xferry.advanced_sessions import AdvancedSessionCapacityExhausted

    clock = Clock()
    counter = 0
    counter_lock = threading.Lock()

    def random_bytes(length: int) -> bytes:
        nonlocal counter
        assert length == 32
        with counter_lock:
            counter += 1
            return counter.to_bytes(32, "big")

    store = make_store(clock, random_bytes)
    barrier = threading.Barrier(80)

    def attempt() -> bool:
        barrier.wait()
        try:
            create(store, principal=no_auth())
        except AdvancedSessionCapacityExhausted:
            return False
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as executor:
        outcomes = list(executor.map(lambda _unused: attempt(), range(80)))

    assert sum(outcomes) == 64
