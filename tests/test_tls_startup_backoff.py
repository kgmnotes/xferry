"""Persisted issuance limits survive startup failures and ordinary restarts."""

from __future__ import annotations

import datetime as dt
import json
from email.utils import format_datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_tls_renewal import manager, pair
from xferry.security.renewal import UTC, certificate_schedule
from xferry.security.tls_manager import TLSManager


def startup_manager() -> TLSManager:
    return TLSManager(
        enabled=True,
        cert_file=None,
        key_file=None,
        letsencrypt=True,
        domain="example.com",
        email=None,
        host="127.0.0.1",
    )


def live_root(home: Path) -> Path:
    return home / ".xferry" / "acme" / "live" / "example.com"


def test_restart_honors_persisted_ari_due_instead_of_fallback(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    cert, _, _ = pair(live_root(tmp_path), elapsed=65)
    fingerprint, _, _ = certificate_schedule(cert.read_bytes())
    cert.with_name("renewal.json").write_text(
        json.dumps(
            {
                "fingerprint": fingerprint,
                "due": (dt.datetime.now(UTC) + dt.timedelta(days=2)).timestamp(),
            }
        )
    )
    monkeypatch.setattr(
        "xferry.security.tls_manager.obtain_letsencrypt_cert",
        lambda **_: pytest.fail("startup ignored the persisted ARI schedule"),
    )
    m = startup_manager()
    m.setup()
    assert m.cert_file == str(cert)
    assert m.ssl_context is not None
    m.cleanup()


def test_persisted_early_ari_due_is_respected_at_startup(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    cert, key, private = pair(live_root(tmp_path), elapsed=10)
    candidate, _, _ = pair(tmp_path / "candidate", key=private)
    fingerprint, _, _ = certificate_schedule(cert.read_bytes())
    cert.with_name("renewal.json").write_text(
        json.dumps({"fingerprint": fingerprint, "due": dt.datetime.now(UTC).timestamp() - 10})
    )
    calls = []

    def obtain(**kwargs):
        calls.append(kwargs)
        kwargs["publish_certificate"](candidate, key, cert)
        return cert, key

    monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", obtain)
    m = startup_manager()
    m.setup()
    assert len(calls) == 1
    assert cert.read_bytes() == candidate.read_bytes()
    m.cleanup()


@pytest.mark.parametrize("expired", [False, True])
def test_failed_initial_or_expired_issuance_is_deferred_without_extending_deadline(
    tmp_path: Path, monkeypatch, expired: bool
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    if expired:
        pair(live_root(tmp_path), days=90, elapsed=91)
    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("CA temporarily unavailable")

    monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fail)
    with pytest.raises(RuntimeError, match="CA temporarily unavailable"):
        startup_manager().setup()
    retry = live_root(tmp_path) / "issuance-retry.json"
    original = retry.read_bytes()
    deadline = json.loads(original)["next_attempt"]
    assert deadline > dt.datetime.now(UTC).timestamp()

    for _ in range(3):
        with pytest.raises(RuntimeError, match="deferred"):
            startup_manager().setup()
        assert retry.read_bytes() == original
    assert len(calls) == 1


def test_failed_due_renewal_keeps_valid_cache_and_defers_restart(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    cert, _, _ = pair(live_root(tmp_path), elapsed=65)
    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("CA temporarily unavailable")

    monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fail)
    first = startup_manager()
    first.setup()
    retry = cert.with_name("issuance-retry.json").read_bytes()
    second = startup_manager()
    second.setup()
    assert len(calls) == 1
    assert first.ssl_context is not None and second.ssl_context is not None
    assert cert.with_name("issuance-retry.json").read_bytes() == retry
    first.cleanup()
    second.cleanup()


@pytest.mark.parametrize("kind", ["seconds", "http-date", "datetime", "response", "cause"])
def test_retry_after_is_respected_without_storing_error_text(tmp_path: Path, kind: str) -> None:
    cert, key, _ = pair(tmp_path, elapsed=65)
    m = manager(cert, key)
    now = dt.datetime.now(UTC)
    minimum = (now + dt.timedelta(hours=2)).timestamp()
    error = RuntimeError("private error text must not enter the state file")
    if kind == "seconds":
        error.retry_after = "7200"
    elif kind == "http-date":
        error.retry_after = format_datetime(now + dt.timedelta(hours=2), usegmt=True)
    elif kind == "datetime":
        error.retry_after = now + dt.timedelta(hours=2)
    elif kind == "response":
        error = RuntimeError((SimpleNamespace(headers={"Retry-After": "7200"}), ValueError()))
    else:
        cause = RuntimeError()
        cause.retry_after = "7200"
        error.__cause__ = cause
    m._record_renewal_failure(error)
    state = json.loads(cert.with_name("issuance-retry.json").read_bytes())
    assert state["next_attempt"] >= minimum - 1
    assert "private error text" not in cert.with_name("issuance-retry.json").read_text()
    m.cleanup()


def test_successful_renewal_clears_global_issuance_backoff(tmp_path: Path, monkeypatch) -> None:
    cert, key, private = pair(tmp_path / "live", elapsed=65)
    candidate, _, _ = pair(tmp_path / "candidate", key=private)
    m = manager(cert, key)
    m._record_renewal_failure()
    monkeypatch.setattr(
        m, "_renewal_info", lambda _: (None, dt.datetime.now(UTC) + dt.timedelta(hours=6))
    )

    def obtain(**kwargs):
        kwargs["publish_certificate"](candidate, key, cert)
        return cert, key

    monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", obtain)
    assert m.renew_if_due(now=dt.datetime.now(UTC) + dt.timedelta(hours=3))
    assert not cert.with_name("issuance-retry.json").exists()
    assert m._retry_not_before == 0
    m.cleanup()


def test_ari_refresh_does_not_randomly_postpone_persisted_due(tmp_path: Path, monkeypatch) -> None:
    cert, key, _ = pair(tmp_path)
    fingerprint, _, _ = certificate_schedule(cert.read_bytes())
    now = dt.datetime.now(UTC)
    due = (now + dt.timedelta(days=1)).timestamp()
    cert.with_name("renewal.json").write_text(json.dumps({"fingerprint": fingerprint, "due": due}))
    m = manager(cert, key)
    monkeypatch.setattr(
        m, "_renewal_info", lambda _: (now + dt.timedelta(days=2), now + dt.timedelta(hours=6))
    )
    assert not m.renew_if_due(now)
    assert json.loads(cert.with_name("renewal.json").read_bytes())["due"] == due
    m.cleanup()


def test_memory_backoff_survives_retry_state_write_failure(tmp_path: Path, monkeypatch) -> None:
    cert, key, _ = pair(tmp_path, elapsed=65)
    m = manager(cert, key)

    def fail(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("xferry.security.tls_manager._write_atomic", fail)
    m._record_renewal_failure(RuntimeError("CA failed"))
    monkeypatch.setattr(m, "_renewal_info", lambda _: pytest.fail("memory backoff ignored"))
    assert not m.renew_if_due()
    m.cleanup()
