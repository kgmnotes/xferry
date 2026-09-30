"""Concurrency and integration tests for bounded Basic Auth admission."""

from __future__ import annotations

import base64
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.security import auth as auth_module
from xferry.security.auth import (
    AuthAdmissionController,
    AuthAdmissionDenied,
    AuthAttemptLease,
    BasicAuthenticator,
)


@dataclass
class _FakeClock:
    value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __call__(self) -> float:
        with self._lock:
            return self.value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.value += seconds


def _basic_header(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {encoded}"


def _auth_request(username: str = "admin", password: str = "secret") -> Any:
    return make_request(
        "GET",
        "/",
        headers={"Authorization": _basic_header(username, password)},
    )


def _require_lease(result: AuthAttemptLease | AuthAdmissionDenied) -> AuthAttemptLease:
    assert isinstance(result, AuthAttemptLease)
    return result


def _wait_for_pending(controller: AuthAdmissionController, expected: int) -> None:
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        with controller._condition:
            if len(controller._waiters) == expected:
                return
        time.sleep(0.001)
    raise AssertionError(f"expected {expected} pending auth attempts")


class TestAuthAdmissionController:
    def test_worker_derived_defaults_are_bounded(self) -> None:
        normal = AuthAdmissionController(workers=10)
        constrained = AuthAdmissionController(workers=3)

        assert normal.max_failures == 5
        assert normal.cooldown == 30.0
        assert normal.max_peers == 4096
        assert normal.prune_interval == 5.0
        assert normal.wait_timeout == 2.0
        assert normal.max_pending == 6
        assert normal.max_active == 2
        assert normal.per_peer_pending == 6
        assert constrained.max_pending == 1
        assert constrained.max_active == 1
        assert constrained.per_peer_pending == 1

    def test_concurrent_precheck_reserves_at_most_five_failure_slots(self) -> None:
        controller = AuthAdmissionController(
            workers=10,
            max_active=5,
            max_pending=6,
        )
        release = threading.Event()
        five_started = threading.Event()
        started = 0
        started_lock = threading.Lock()

        def attempt() -> AuthAttemptLease | AuthAdmissionDenied:
            nonlocal started
            result = controller.acquire("198.51.100.10")
            if isinstance(result, AuthAttemptLease):
                with started_lock:
                    started += 1
                    if started == 5:
                        five_started.set()
                assert release.wait(1.0)
                result.finish("failed")
            return result

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(attempt) for _ in range(6)]
            assert five_started.wait(1.0)
            release.set()
            results = [future.result(timeout=2.0) for future in futures]

        assert sum(isinstance(result, AuthAttemptLease) for result in results) == 5
        denied = [result for result in results if isinstance(result, AuthAdmissionDenied)]
        assert len(denied) == 1
        assert denied[0].reason == "cooldown"

    def test_six_valid_attempts_queue_behind_two_active_slots(self) -> None:
        controller = AuthAdmissionController(workers=10)
        release = threading.Event()
        two_started = threading.Event()
        lock = threading.Lock()
        active = 0
        maximum_active = 0

        def attempt() -> AuthAttemptLease | AuthAdmissionDenied:
            nonlocal active, maximum_active
            result = controller.acquire("198.51.100.11")
            if isinstance(result, AuthAttemptLease):
                with lock:
                    active += 1
                    maximum_active = max(maximum_active, active)
                    if active == 2:
                        two_started.set()
                assert release.wait(1.0)
                result.finish("succeeded")
                with lock:
                    active -= 1
            return result

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(attempt) for _ in range(6)]
            assert two_started.wait(1.0)
            release.set()
            results = [future.result(timeout=2.0) for future in futures]

        assert all(isinstance(result, AuthAttemptLease) for result in results)
        assert maximum_active == 2

    def test_global_and_per_peer_pending_limits_are_distinct(self) -> None:
        controller = AuthAdmissionController(
            workers=10,
            max_active=2,
            max_pending=2,
            per_peer_pending=1,
        )
        first = _require_lease(controller.acquire("198.51.100.12"))

        same_peer = controller.acquire("198.51.100.12")
        second = _require_lease(controller.acquire("198.51.100.13"))
        at_capacity = controller.acquire("198.51.100.14")

        assert isinstance(same_peer, AuthAdmissionDenied)
        assert same_peer.reason == "peer_capacity"
        assert isinstance(at_capacity, AuthAdmissionDenied)
        assert at_capacity.reason == "capacity"
        first.finish("succeeded")
        second.finish("succeeded")

    def test_waiter_timeout_releases_pending_capacity(self) -> None:
        controller = AuthAdmissionController(
            workers=10,
            max_active=1,
            max_pending=2,
            wait_timeout=0.0,
        )
        active = _require_lease(controller.acquire("198.51.100.15"))

        timed_out = controller.acquire("198.51.100.16")

        assert isinstance(timed_out, AuthAdmissionDenied)
        assert timed_out.reason == "timeout"
        active.finish("succeeded")
        replacement = _require_lease(controller.acquire("198.51.100.17"))
        replacement.finish("succeeded")

    def test_waiter_timeout_has_real_deadline_when_fake_clock_is_frozen(self) -> None:
        clock = _FakeClock()
        controller = AuthAdmissionController(
            workers=10,
            max_active=1,
            max_pending=2,
            wait_timeout=0.01,
            clock=clock,
        )
        active = _require_lease(controller.acquire("198.51.100.18"))
        result: list[AuthAttemptLease | AuthAdmissionDenied] = []

        waiter = threading.Thread(target=lambda: result.append(controller.acquire("198.51.100.19")))
        waiter.start()
        waiter.join(timeout=1.0)

        assert not waiter.is_alive()
        assert len(result) == 1
        assert isinstance(result[0], AuthAdmissionDenied)
        assert result[0].reason == "timeout"
        active.finish("succeeded")
        replacement = _require_lease(controller.acquire("198.51.100.20"))
        replacement.finish("succeeded")

    def test_real_deadline_also_applies_when_promoting_waiters(self) -> None:
        clock = _FakeClock()
        controller = AuthAdmissionController(
            workers=10,
            max_active=1,
            max_pending=2,
            wait_timeout=0.01,
            clock=clock,
        )
        active = _require_lease(controller.acquire("198.51.100.21"))
        result: list[AuthAttemptLease | AuthAdmissionDenied] = []

        waiter = threading.Thread(target=lambda: result.append(controller.acquire("198.51.100.22")))
        waiter.start()
        _wait_for_pending(controller, 1)

        with controller._condition:
            time.sleep(0.02)
            active.finish("succeeded")

        waiter.join(timeout=1.0)
        assert not waiter.is_alive()
        assert len(result) == 1
        assert isinstance(result[0], AuthAdmissionDenied)
        assert result[0].reason == "timeout"

    def test_temporarily_blocked_fifo_head_does_not_block_another_peer(self) -> None:
        controller = AuthAdmissionController(
            workers=10,
            max_failures=1,
            max_active=2,
            max_pending=4,
            wait_timeout=1.0,
        )
        first_peer_active = _require_lease(controller.acquire("198.51.100.20"))
        other_active = _require_lease(controller.acquire("198.51.100.21"))
        finish_waiters = threading.Event()
        first_result: list[AuthAttemptLease | AuthAdmissionDenied] = []
        later_result: list[AuthAttemptLease | AuthAdmissionDenied] = []
        later_promoted = threading.Event()

        def wait_as_blocked_head() -> None:
            result = controller.acquire("198.51.100.20")
            first_result.append(result)
            if isinstance(result, AuthAttemptLease):
                assert finish_waiters.wait(1.0)
                result.finish("succeeded")

        def wait_as_eligible_peer() -> None:
            result = controller.acquire("198.51.100.22")
            later_result.append(result)
            later_promoted.set()
            if isinstance(result, AuthAttemptLease):
                assert finish_waiters.wait(1.0)
                result.finish("succeeded")

        first_thread = threading.Thread(target=wait_as_blocked_head)
        first_thread.start()
        _wait_for_pending(controller, 1)
        later_thread = threading.Thread(target=wait_as_eligible_peer)
        later_thread.start()
        _wait_for_pending(controller, 2)

        other_active.finish("succeeded")

        assert later_promoted.wait(1.0)
        assert isinstance(later_result[0], AuthAttemptLease)
        assert first_result == []

        first_peer_active.finish("succeeded")
        deadline = time.monotonic() + 1.0
        while not first_result and time.monotonic() < deadline:
            time.sleep(0.001)
        assert isinstance(first_result[0], AuthAttemptLease)
        finish_waiters.set()
        first_thread.join(timeout=1.0)
        later_thread.join(timeout=1.0)
        assert not first_thread.is_alive()
        assert not later_thread.is_alive()

    def test_peer_table_is_bounded_and_stale_failures_are_pruned(self) -> None:
        clock = _FakeClock()
        controller = AuthAdmissionController(
            workers=10,
            max_peers=2,
            max_active=2,
            max_pending=2,
            cooldown=30.0,
            clock=clock,
        )
        first = _require_lease(controller.acquire("198.51.100.30"))
        second = _require_lease(controller.acquire("198.51.100.31"))
        first.finish("failed")
        second.finish("failed")

        capped = controller.acquire("198.51.100.32")
        assert isinstance(capped, AuthAdmissionDenied)
        assert capped.reason == "peer_capacity"

        clock.advance(30.0)
        admitted = _require_lease(controller.acquire("198.51.100.32"))
        admitted.finish("succeeded")

    def test_cooldown_uses_integer_retry_after_and_opens_at_exact_boundary(self) -> None:
        clock = _FakeClock()
        controller = AuthAdmissionController(
            workers=10,
            max_failures=1,
            cooldown=30.0,
            clock=clock,
        )
        first = _require_lease(controller.acquire("198.51.100.40"))
        first.finish("failed")

        blocked = controller.acquire("198.51.100.40")
        assert isinstance(blocked, AuthAdmissionDenied)
        assert blocked.reason == "cooldown"
        assert blocked.retry_after == 30
        assert isinstance(blocked.retry_after, int)

        clock.advance(29.01)
        almost = controller.acquire("198.51.100.40")
        assert isinstance(almost, AuthAdmissionDenied)
        assert almost.retry_after == 1

        clock.advance(0.99)
        boundary = _require_lease(controller.acquire("198.51.100.40"))
        boundary.finish("succeeded")

    def test_finish_is_idempotent_and_lease_repr_hides_peer(self) -> None:
        controller = AuthAdmissionController(
            workers=10,
            max_failures=2,
            max_active=1,
            max_pending=1,
        )
        lease = _require_lease(controller.acquire("sensitive-peer.example"))

        lease.finish("failed")
        lease.finish("failed")

        assert "sensitive-peer" not in repr(lease)
        second = _require_lease(controller.acquire("sensitive-peer.example"))
        second.finish("succeeded")


class TestAuthenticatorConcurrency:
    def test_known_invalid_user_runs_exactly_one_stored_verification(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        authenticator = BasicAuthenticator({"known": "secret"})
        calls: list[tuple[str, str, str]] = []

        def controlled_verify(password: str, hashed: str, salt: str) -> bool:
            calls.append((password, hashed, salt))
            return False

        monkeypatch.setattr(auth_module, "verify_password", controlled_verify)

        assert authenticator.verify(_basic_header("known", "candidate")) is None
        assert len(calls) == 1
        assert calls[0][0] == "candidate"
        assert calls[0][1:] != ("0" * 64, "0" * 32)

    def test_unknown_user_runs_exactly_one_dummy_verification(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        authenticator = BasicAuthenticator({"known": "secret"})
        calls: list[tuple[str, str, str]] = []

        def controlled_verify(password: str, hashed: str, salt: str) -> bool:
            calls.append((password, hashed, salt))
            return False

        monkeypatch.setattr(auth_module, "verify_password", controlled_verify)

        assert authenticator.verify(_basic_header("unknown", "candidate")) is None
        assert calls == [("candidate", "0" * 64, "0" * 32)]

    def test_credential_snapshot_does_not_hold_lock_during_verification(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        authenticator = BasicAuthenticator({"admin": "secret"})
        verifier_entered = threading.Event()
        verifier_release = threading.Event()
        removal_finished = threading.Event()
        result: list[str | None] = []

        def controlled_verify(_password: str, _hashed: str, _salt: str) -> bool:
            verifier_entered.set()
            assert verifier_release.wait(1.0)
            return True

        monkeypatch.setattr(auth_module, "verify_password", controlled_verify)

        verify_thread = threading.Thread(
            target=lambda: result.append(authenticator.verify(_basic_header("admin", "secret")))
        )
        verify_thread.start()
        assert verifier_entered.wait(1.0)

        remove_thread = threading.Thread(
            target=lambda: (authenticator.remove_user("admin"), removal_finished.set())
        )
        remove_thread.start()
        assert removal_finished.wait(0.5)

        verifier_release.set()
        verify_thread.join(timeout=1.0)
        remove_thread.join(timeout=1.0)
        assert result == ["admin"]


class TestServerAuthAdmission:
    def test_auth_event_log_throttles_at_the_exact_interval_boundary(
        self,
        temp_dir: Any,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        clock = _FakeClock()
        server = make_server(root_dir=str(temp_dir), quiet=True)
        monkeypatch.setattr("xferry.server.time.monotonic", clock)
        caplog.set_level("WARNING", logger="xferry")

        server._log_authentication_event()
        clock.advance(4.999)
        server._log_authentication_event()
        clock.advance(0.001)
        server._log_authentication_event()

        messages = [
            record.message for record in caplog.records if "Authentication events" in record.message
        ]
        assert messages == [
            "Authentication events observed (suppressed=0)",
            "Authentication events observed (suppressed=1)",
        ]

    def test_fifth_failure_is_401_and_next_request_is_private_429(self, temp_dir: Any) -> None:
        calls = 0

        def reject(_username: str, _password: str) -> bool:
            nonlocal calls
            calls += 1
            return False

        server = make_server(root_dir=str(temp_dir), quiet=True)
        server.set_authenticator(BasicAuthenticator(auth_callback=reject))
        address = ("198.51.100.50", 12345)

        failures = [server._authenticate_request(_auth_request(), address) for _ in range(5)]
        limited = server._authenticate_request(_auth_request(), address)

        assert calls == 5
        assert all(response is not None and response.status_code == 401 for response in failures)
        for response in failures:
            assert response is not None
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted Area"'
        assert limited is not None
        assert limited.status_code == 429
        assert limited.headers["Cache-Control"] == "no-store"
        assert limited.headers["Retry-After"].isdigit()
        assert "WWW-Authenticate" not in limited.headers
        assert json.loads(limited.body) == {
            "error": {
                "code": "rate_limited",
                "message": "Too Many Requests",
                "field": "Authorization",
                "details": {},
            }
        }

    def test_six_valid_requests_share_two_verifier_slots(self, temp_dir: Any) -> None:
        lock = threading.Lock()
        release = threading.Event()
        two_started = threading.Event()
        calls = 0
        active = 0
        maximum_active = 0

        def accept(_username: str, _password: str) -> bool:
            nonlocal calls, active, maximum_active
            with lock:
                calls += 1
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 2:
                    two_started.set()
            assert release.wait(1.0)
            with lock:
                active -= 1
            return True

        server = make_server(root_dir=str(temp_dir), quiet=True)
        server.set_authenticator(BasicAuthenticator(auth_callback=accept))
        address = ("198.51.100.51", 12345)

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(server._authenticate_request, _auth_request(), address)
                for _ in range(6)
            ]
            assert two_started.wait(1.0)
            release.set()
            results = [future.result(timeout=2.0) for future in futures]

        assert results == [None] * 6
        assert calls == 6
        assert maximum_active == 2
        assert server.get_metrics()["authentication"] == {
            "active": 0,
            "attempts": 6,
            "succeeded": 6,
            "failed": 0,
            "errors": 0,
            "denials": 0,
            "denial_reasons": {
                "capacity": 0,
                "cooldown": 0,
                "peer_capacity": 0,
                "timeout": 0,
            },
        }

    def test_six_invalid_requests_start_only_five_verifications(self, temp_dir: Any) -> None:
        lock = threading.Lock()
        release = threading.Event()
        two_started = threading.Event()
        calls = 0
        active = 0
        maximum_active = 0

        def reject(_username: str, _password: str) -> bool:
            nonlocal calls, active, maximum_active
            with lock:
                calls += 1
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 2:
                    two_started.set()
            assert release.wait(1.0)
            with lock:
                active -= 1
            return False

        server = make_server(root_dir=str(temp_dir), quiet=True)
        server.set_authenticator(BasicAuthenticator(auth_callback=reject))
        address = ("198.51.100.52", 12345)

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(server._authenticate_request, _auth_request(), address)
                for _ in range(6)
            ]
            assert two_started.wait(1.0)
            release.set()
            responses = [future.result(timeout=2.0) for future in futures]

        statuses = sorted(response.status_code for response in responses if response is not None)
        assert statuses == [401, 401, 401, 401, 401, 429]
        assert calls == 5
        assert maximum_active == 2

    def test_callback_exception_releases_lease_and_is_separately_metriced(
        self,
        temp_dir: Any,
    ) -> None:
        calls = 0

        def verifier(_username: str, _password: str) -> bool:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("credential-shaped sentinel must not be logged")
            return True

        server = make_server(root_dir=str(temp_dir), quiet=True)
        server.set_authenticator(BasicAuthenticator(auth_callback=verifier))
        address = ("198.51.100.53", 12345)

        failed = server._authenticate_request(_auth_request(), address)
        assert failed is not None
        assert failed.status_code == 401
        assert failed.headers["Cache-Control"] == "no-store"
        assert failed.headers["WWW-Authenticate"] == 'Basic realm="Restricted Area"'
        assert b"credential-shaped sentinel" not in failed.body
        assert server._authenticate_request(_auth_request(), address) is None

        authentication = server.get_metrics()["authentication"]
        assert authentication["active"] == 0
        assert authentication["attempts"] == 2
        assert authentication["succeeded"] == 1
        assert authentication["failed"] == 0
        assert authentication["errors"] == 1

    def test_authenticator_replacement_does_not_mix_old_attempt_with_new_controller(
        self,
        temp_dir: Any,
    ) -> None:
        old_entered = threading.Event()
        release_old = threading.Event()
        old_result: list[Any] = []
        new_calls = 0

        def old_verifier(_username: str, _password: str) -> bool:
            old_entered.set()
            assert release_old.wait(1.0)
            return False

        def new_verifier(_username: str, _password: str) -> bool:
            nonlocal new_calls
            new_calls += 1
            return False

        server = make_server(root_dir=str(temp_dir), quiet=True)
        server.set_authenticator(BasicAuthenticator(auth_callback=old_verifier))
        address = ("198.51.100.54", 12345)
        old_thread = threading.Thread(
            target=lambda: old_result.append(
                server._authenticate_request(_auth_request("old", "secret"), address)
            )
        )
        old_thread.start()
        assert old_entered.wait(1.0)

        server.set_authenticator(BasicAuthenticator(auth_callback=new_verifier))
        release_old.set()
        old_thread.join(timeout=1.0)
        assert old_result[0].status_code == 401

        new_failures = [
            server._authenticate_request(_auth_request("new", "wrong"), address) for _ in range(5)
        ]
        limited = server._authenticate_request(_auth_request("new", "wrong"), address)

        assert new_calls == 5
        assert all(
            response is not None and response.status_code == 401 for response in new_failures
        )
        assert limited is not None and limited.status_code == 429

    def test_auth_logs_and_metrics_never_include_identity_or_credentials(
        self,
        temp_dir: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        username = "SensitiveOwner"
        password = "credential-shaped-password"
        address = ("198.51.100.55", 12345)
        authorization = _basic_header(username, password)

        def reject(_username: str, _password: str) -> bool:
            return False

        server = make_server(root_dir=str(temp_dir), quiet=True)
        server.set_authenticator(BasicAuthenticator(auth_callback=reject))
        caplog.set_level("DEBUG", logger="xferry")

        for _ in range(6):
            request = make_request("GET", "/", headers={"Authorization": authorization})
            server._authenticate_request(request, address)

        serialized_metrics = json.dumps(server.get_metrics(), sort_keys=True)
        combined = caplog.text + serialized_metrics
        for secret in (username, password, address[0], authorization):
            assert secret not in combined
        auth_records = [record for record in caplog.records if "Authentication" in record.message]
        assert len(auth_records) <= 2
        assert all(record.exc_info is None for record in auth_records)
