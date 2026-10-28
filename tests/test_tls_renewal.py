"""Lifetime scheduling, safe publication and retry behavior of TLS renewal."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from xferry.security.renewal import UTC, certificate_schedule, load_schedule
from xferry.security.tls import check_cert_needs_renewal
from xferry.security.tls_manager import TLSManager


def pair(
    root: Path,
    *,
    days: int = 90,
    elapsed: int = 0,
    domain: str = "example.com",
    key: rsa.RSAPrivateKey | None = None,
) -> tuple[Path, Path, rsa.RSAPrivateKey]:
    root.mkdir(parents=True, exist_ok=True)
    private = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=elapsed))
        .not_valid_after(now + dt.timedelta(days=days - elapsed))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), False)
        .sign(private, hashes.SHA256())
    )
    cert_path, key_path = root / "fullchain.pem", root / "privkey.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, private


def manager(cert: Path, key: Path) -> TLSManager:
    result = TLSManager(
        enabled=True,
        cert_file=str(cert),
        key_file=str(key),
        letsencrypt=True,
        domain="example.com",
        email=None,
        host="127.0.0.1",
    )
    result._build_context()
    result._used_letsencrypt = True
    return result


@pytest.mark.parametrize("days,remaining", [(90, 30), (45, 15), (6, 3), (1, 0.5)])
def test_schedule_uses_real_lifetime(tmp_path: Path, days: int, remaining: float) -> None:
    cert, _, _ = pair(tmp_path, days=days)
    _, due, expiry = certificate_schedule(cert.read_bytes())
    assert (expiry - due).total_seconds() == remaining * 86400
    assert not check_cert_needs_renewal(cert)


def test_renewal_replaces_context_only_after_validating(tmp_path: Path, monkeypatch) -> None:
    cert, key, private = pair(tmp_path / "live", elapsed=65)
    candidate, _, _ = pair(tmp_path / "candidate", key=private)
    m = manager(cert, key)
    old_context = m.ssl_context
    old_key = key.read_bytes()
    monkeypatch.setattr(
        m, "_renewal_info", lambda _: (None, dt.datetime.now(UTC) + dt.timedelta(hours=6))
    )
    calls = []

    def obtain(**kwargs):
        calls.append(kwargs)
        kwargs["publish_certificate"](candidate, key, cert)
        return cert, key

    monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", obtain)
    assert m.renew_if_due()
    assert isinstance(m.ssl_context, ssl.SSLContext)
    assert m.ssl_context is not old_context
    assert key.read_bytes() == old_key
    assert cert.read_bytes() == candidate.read_bytes()
    assert not m.renew_if_due()
    assert len(calls) == 1
    m.cleanup()


def test_wrong_hostname_keeps_live_files_and_context(tmp_path: Path) -> None:
    cert, key, private = pair(tmp_path / "live")
    candidate, _, _ = pair(tmp_path / "candidate", domain="other.example", key=private)
    m = manager(cert, key)
    old_context, old_cert = m.ssl_context, cert.read_bytes()
    with pytest.raises(RuntimeError, match="hostname"):
        m._publish_certificate(candidate, key, cert)
    assert m.ssl_context is old_context
    assert cert.read_bytes() == old_cert
    m.cleanup()


def test_shared_cache_reloads_fresh_certificate_without_new_issuance(
    tmp_path: Path, monkeypatch
) -> None:
    cert, key, private = pair(tmp_path / "live", elapsed=65)
    candidate, _, _ = pair(tmp_path / "candidate", key=private)
    first, second = manager(cert, key), manager(cert, key)
    old_second = second.ssl_context
    first._publish_certificate(candidate, key, cert)
    monkeypatch.setattr(
        second, "_renewal_info", lambda _: (None, dt.datetime.now(UTC) + dt.timedelta(hours=6))
    )
    monkeypatch.setattr(
        "xferry.security.tls_manager.obtain_letsencrypt_cert",
        lambda **_: pytest.fail("a fresh shared certificate must not be issued again"),
    )
    assert not second.renew_if_due()
    assert second.ssl_context is not old_second
    assert second._active_fingerprint == first._active_fingerprint
    first.cleanup()
    second.cleanup()


def test_retry_survives_restart_and_cleanup_prevents_publication(
    tmp_path: Path, monkeypatch
) -> None:
    cert, key, private = pair(tmp_path / "live", elapsed=65)
    m = manager(cert, key)
    m._record_renewal_failure()
    fingerprint, _, _ = certificate_schedule(cert.read_bytes())
    state = load_schedule(cert.with_name("renewal.json"), fingerprint)
    assert state["failures"] == 1
    restarted = manager(cert, key)
    monkeypatch.setattr(restarted, "_renewal_info", lambda _: pytest.fail("backoff ignored"))
    assert not restarted.renew_if_due()
    candidate, _, _ = pair(tmp_path / "candidate", key=private)
    old_cert = cert.read_bytes()
    restarted.cleanup()
    with pytest.raises(InterruptedError):
        restarted._publish_certificate(candidate, key, cert)
    assert cert.read_bytes() == old_cert
    m.cleanup()


def test_active_tls_connection_survives_context_replacement(tmp_path: Path) -> None:
    cert, key, private = pair(tmp_path / "live", elapsed=65)
    candidate, _, _ = pair(tmp_path / "candidate", key=private)
    m = manager(cert, key)
    clients: list[ssl.SSLSocket] = []
    threads: list[threading.Thread] = []

    def connect() -> ssl.SSLSocket:
        server_socket, client_socket = socket.socketpair()
        server_socket.settimeout(2)
        client_socket.settimeout(2)
        context = m.ssl_context
        assert context is not None

        def echo() -> None:
            try:
                with context.wrap_socket(server_socket, server_side=True) as stream:
                    while data := stream.recv(32):
                        stream.sendall(data)
            except OSError:
                server_socket.close()

        thread = threading.Thread(target=echo, daemon=True)
        threads.append(thread)
        thread.start()
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client = client_context.wrap_socket(client_socket, server_hostname="example.com")
        clients.append(client)
        return client

    try:
        old = connect()
        old_certificate = old.getpeercert(binary_form=True)
        m._renewing = True
        m._publish_certificate(candidate, key, cert)
        new = connect()
        assert new.getpeercert(binary_form=True) != old_certificate
        for client in (old, new):
            client.sendall(b"still connected")
            assert client.recv(32) == b"still connected"
    finally:
        for client in clients:
            client.close()
        for thread in threads:
            thread.join(timeout=2)
        m.cleanup()


def test_failed_certificate_write_keeps_old_context_and_cache(tmp_path: Path, monkeypatch) -> None:
    cert, key, private = pair(tmp_path / "live", elapsed=65)
    candidate, _, _ = pair(tmp_path / "candidate", key=private)
    m = manager(cert, key)
    before, context = cert.read_bytes(), m.ssl_context

    def fail_write(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("xferry.security.tls_manager._write_atomic", fail_write)
    with pytest.raises(OSError):
        m._publish_certificate(candidate, key, cert)
    assert cert.read_bytes() == before
    assert m.ssl_context is context
    m.cleanup()


def test_acme_json_rate_limit_preserves_retry_after(monkeypatch) -> None:
    from acme import client, messages
    from requests import Response

    from xferry.security.tls import ACMERetryAfterError, _acme_client_for_key

    directory = messages.Directory.from_json(
        {
            "newNonce": "https://ca.invalid/nonce",
            "newAccount": "https://ca.invalid/account",
            "newOrder": "https://ca.invalid/order",
            "revokeCert": "https://ca.invalid/revoke",
            "keyChange": "https://ca.invalid/key-change",
        }
    )
    monkeypatch.setattr(client.ClientV2, "get_directory", lambda *_: directory)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    acme_client = _acme_client_for_key(
        private, directory_url="https://ca.invalid/directory", user_agent="test", timeout=1
    )
    response = Response()
    response.status_code = 429
    response.headers.update({"Content-Type": "application/problem+json", "Retry-After": "7200"})
    response._content = b'{"type":"urn:ietf:params:acme:error:rateLimited","detail":"retry later"}'
    with pytest.raises(ACMERetryAfterError) as error:
        acme_client.net._check_response(response)
    assert error.value.retry_after == "7200"


def test_acme_poll_cancels_between_requests() -> None:
    from types import SimpleNamespace

    from acme import messages

    from xferry.security.tls import _poll_interruptibly

    stopped = threading.Event()

    class Client:
        def poll(self, auth):
            stopped.set()
            return auth, object()

        def retry_after(self, *_):
            return dt.datetime.now() + dt.timedelta(hours=1)

    auth = SimpleNamespace(body=SimpleNamespace(status=messages.STATUS_PENDING))
    order = SimpleNamespace(authorizations=[auth])
    with pytest.raises(InterruptedError):
        _poll_interruptibly(Client(), order, dt.datetime.now() + dt.timedelta(minutes=1), stopped)
