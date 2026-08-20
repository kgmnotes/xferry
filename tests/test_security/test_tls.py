"""Tests for TLS certificate utilities."""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from xferry.security import tls as tls_module
from xferry.security.tls import (
    check_cert_needs_renewal,
    check_certbot_available,
    check_openssl_available,
    generate_cert_in_memory,
    generate_self_signed_cert,
    get_cert_info,
    normalize_domain,
    obtain_letsencrypt_cert,
    resolve_public_ipv4,
    sslip_domain_for_ip,
    validate_cert_key_pair,
    validate_private_key_file,
    validate_public_ipv4,
)


@pytest.mark.parametrize(
    "domain",
    ["bad\n.example", "bad\x00.example", "-bad.example", "bad..example"],
)
def test_normalize_domain_rejects_control_and_invalid_labels(domain: str) -> None:
    """Accepting controls or invalid labels would make the normalized host unsafe downstream."""
    with pytest.raises(ValueError, match="invalid domain"):
        normalize_domain(domain)


def test_normalize_domain_returns_lowercase_idna_without_trailing_dot() -> None:
    """Leaving Unicode, casing, or a trailing dot would create inconsistent host identities."""
    assert normalize_domain("BÜCHER.Example.") == "xn--bcher-kva.example"


class TestCheckOpenSSL:
    def test_returns_bool(self):
        result = check_openssl_available()
        assert isinstance(result, bool)

    def test_returns_false_when_openssl_missing(self, monkeypatch):
        def fake_run(*_args, **_kwargs):
            raise FileNotFoundError

        monkeypatch.setattr("xferry.security.tls.subprocess.run", fake_run)

        assert check_openssl_available() is False

    def test_returns_false_when_openssl_check_times_out(self, monkeypatch):
        def fake_run(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd="openssl version", timeout=5)

        monkeypatch.setattr("xferry.security.tls.subprocess.run", fake_run)

        assert check_openssl_available() is False


class TestCheckCertbot:
    def test_returns_bool(self):
        result = check_certbot_available()
        assert isinstance(result, bool)

    def test_returns_false_when_certbot_returns_nonzero(self, monkeypatch):
        monkeypatch.setattr(
            "xferry.security.tls.subprocess.run",
            lambda cmd, **_kwargs: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom"),
        )

        assert check_certbot_available() is False

    def test_returns_false_when_certbot_missing(self, monkeypatch):
        def fake_run(*_args, **_kwargs):
            raise FileNotFoundError

        monkeypatch.setattr("xferry.security.tls.subprocess.run", fake_run)

        assert check_certbot_available() is False


class TestGenerateCertInMemory:
    def test_returns_string_paths(self, monkeypatch, tmp_path):
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        monkeypatch.setattr(
            "xferry.security.tls.generate_self_signed_cert",
            lambda: (cert_path, key_path),
        )

        cert_result, key_result = generate_cert_in_memory()

        assert cert_result == str(cert_path)
        assert key_result == str(key_path)


class TestGenerateSelfSignedCert:
    def test_generates_cert_and_key_files(self, tmp_path):
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"

        result_cert, result_key = generate_self_signed_cert(
            cert_path=cert_path,
            key_path=key_path,
        )

        assert result_cert == cert_path
        assert result_key == key_path
        assert cert_path.read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
        assert key_path.read_text(encoding="utf-8").startswith("-----BEGIN RSA PRIVATE KEY-----")
        if os.name != "nt":
            assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    def test_generates_temp_files_when_no_path(self):
        cert_path, key_path = generate_self_signed_cert()
        try:
            assert cert_path.exists()
            assert key_path.exists()
        finally:
            cert_path.unlink(missing_ok=True)
            key_path.unlink(missing_ok=True)

    def test_custom_common_name_and_san(self, tmp_path):
        cert_path, key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
            common_name="myhost.local",
        )

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

        assert cn == "myhost.local"
        assert "myhost.local" in san.get_values_for_type(x509.DNSName)
        key_path.unlink(missing_ok=True)

    def test_custom_validity_days(self, tmp_path):
        cert_path, _key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
            days=7,
        )

        assert check_cert_needs_renewal(cert_path, days=30) is True


class TestCheckCertNeedsRenewal:
    def test_nonexistent_cert_needs_renewal(self, tmp_path):
        assert check_cert_needs_renewal(tmp_path / "nope.pem") is True

    def test_fresh_cert_does_not_need_renewal(self, tmp_path):
        cert_path, _key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
            days=365,
        )

        assert check_cert_needs_renewal(cert_path, days=30) is False

    def test_short_lived_cert_needs_renewal(self, tmp_path):
        cert_path, _key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
            days=1,
        )

        assert check_cert_needs_renewal(cert_path, days=30) is True

    def test_invalid_cert_needs_renewal(self, tmp_path):
        cert_path = tmp_path / "cert.pem"
        cert_path.write_text("not a cert", encoding="utf-8")

        assert check_cert_needs_renewal(cert_path, days=30) is True


class TestValidateCertKeyPair:
    def test_generated_pair_is_valid(self, tmp_path):
        cert_path, key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
        )

        result = validate_cert_key_pair(cert_path, key_path)

        assert result.valid is True
        assert result.reason == ""

    def test_missing_key_is_invalid_and_recoverable(self, tmp_path):
        cert_path, key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
        )
        key_path.unlink()

        result = validate_cert_key_pair(cert_path, key_path)

        assert result.valid is False
        assert result.recoverable_by_renewal is True
        assert "private key file is missing" in result.reason

    def test_unparsable_key_is_invalid_without_exposing_contents(self, tmp_path):
        cert_path, key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
        )
        key_path.write_text("not a private key", encoding="utf-8")

        result = validate_cert_key_pair(cert_path, key_path)

        assert result.valid is False
        assert result.recoverable_by_renewal is False
        assert "private key file is not a valid unencrypted PEM private key" in result.reason
        assert "not a private key" not in result.reason

    def test_mismatched_key_is_invalid_and_recoverable(self, tmp_path):
        cert_path, key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
        )
        other_cert = tmp_path / "other-cert.pem"
        other_key = tmp_path / "other-key.pem"
        generate_self_signed_cert(cert_path=other_cert, key_path=other_key)
        key_path.write_bytes(other_key.read_bytes())

        result = validate_cert_key_pair(cert_path, key_path)

        assert result.valid is False
        assert result.recoverable_by_renewal is True
        assert "certificate and private key do not match" in result.reason


class TestValidatePrivateKeyFile:
    def test_generated_private_key_is_valid(self, tmp_path):
        _cert_path, key_path = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
        )

        result = validate_private_key_file(key_path)

        assert result.valid is True
        assert result.reason == ""

    def test_unparsable_private_key_is_invalid_without_exposing_contents(self, tmp_path):
        key_path = tmp_path / "key.pem"
        key_path.write_text("not a private key", encoding="utf-8")

        result = validate_private_key_file(key_path)

        assert result.valid is False
        assert "private key file is not a valid unencrypted PEM private key" in result.reason
        assert "not a private key" not in result.reason


class TestGetCertInfo:
    def test_returns_dict_with_subject_and_dates(self, tmp_path):
        cert_path, _ = generate_self_signed_cert(
            cert_path=tmp_path / "cert.pem",
            key_path=tmp_path / "key.pem",
            common_name="test.local",
        )

        info = get_cert_info(cert_path)

        assert "error" not in info
        assert "CN=test.local" in info["subject"]
        assert "notBefore" in info
        assert "notAfter" in info

    def test_nonexistent_cert_returns_error(self, tmp_path):
        info = get_cert_info(tmp_path / "nope.pem")

        assert "error" in info


class TestObtainLetsEncryptCert:
    def test_uses_default_acme_config_dir_when_not_provided(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        monkeypatch.setattr("xferry.security.tls.Path.home", lambda: fake_home)
        self._patch_acme_success(monkeypatch)

        result_cert, result_key = obtain_letsencrypt_cert(domain="Example.COM")

        assert (
            result_cert == fake_home / ".xferry" / "acme" / "live" / "example.com" / "fullchain.pem"
        )
        assert result_key == fake_home / ".xferry" / "acme" / "live" / "example.com" / "privkey.pem"
        assert result_cert.read_text(encoding="utf-8") == "FULLCHAIN"
        assert result_key.exists()

    def test_writes_generated_certificate_and_private_key(self, tmp_path, monkeypatch):
        calls: dict[str, object] = {}
        self._patch_acme_success(monkeypatch, calls=calls)

        result_cert, result_key = obtain_letsencrypt_cert(
            domain="example.com",
            email="ops@example.com",
            config_dir=tmp_path,
            server_url="https://acme.example/directory",
            http_address="127.0.0.1",
            http_port=5002,
        )

        assert result_cert == tmp_path / "live" / "example.com" / "fullchain.pem"
        assert result_key == tmp_path / "live" / "example.com" / "privkey.pem"
        assert result_cert.read_text(encoding="utf-8") == "FULLCHAIN"
        assert (tmp_path / "accounts").exists()
        assert calls["email"] == "ops@example.com"
        assert calls["server"] == ("127.0.0.1", 5002)
        if os.name != "nt":
            assert stat.S_IMODE(result_key.stat().st_mode) == 0o600

    def test_invalid_domain_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError, match="invalid domain"):
            obtain_letsencrypt_cert(domain="../example.com", config_dir=tmp_path)

    def test_wildcard_domain_is_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="wildcard"):
            obtain_letsencrypt_cert(domain="*.example.com", config_dir=tmp_path)

    def test_challenge_bind_error_is_runtime_error(self, tmp_path, monkeypatch):
        self._patch_acme_success(monkeypatch)

        def fail_server(*_args, **_kwargs):
            raise OSError("address in use")

        monkeypatch.setattr(tls_module, "_challenge_server", fail_server)

        with pytest.raises(RuntimeError, match="could not bind ACME HTTP-01"):
            obtain_letsencrypt_cert(domain="example.com", config_dir=tmp_path)

    @staticmethod
    def _patch_acme_success(monkeypatch, calls: dict[str, object] | None = None) -> None:
        calls = calls if calls is not None else {}

        class FakeClient:
            def __init__(self) -> None:
                self.answered = []

            def new_order(self, csr_pem: bytes):
                calls["csr_prefix"] = csr_pem[:20]
                return object()

            def answer_challenge(self, challenge_body, response) -> None:
                self.answered.append((challenge_body, response))

            def poll_and_finalize(self, order, deadline):
                calls["deadline"] = deadline
                return SimpleNamespace(fullchain_pem="FULLCHAIN")

        fake_client = FakeClient()

        def fake_client_factory(_account_key, *, directory_url, user_agent, timeout):
            calls["directory_url"] = directory_url
            calls["user_agent"] = user_agent
            calls["timeout"] = timeout
            return fake_client

        def fake_ensure_account(_acme_client, *, email):
            calls["email"] = email
            return None

        def fake_http01_challenges(_acme_client, _order):
            return set(), [("challenge", "response")]

        @contextlib.contextmanager
        def fake_challenge_server(_resources, *, address, port, timeout):
            calls["server"] = (address, port)
            calls["challenge_timeout"] = timeout
            yield object()

        monkeypatch.setattr(tls_module, "_acme_client_for_key", fake_client_factory)
        monkeypatch.setattr(tls_module, "_ensure_account", fake_ensure_account)
        monkeypatch.setattr(tls_module, "_http01_challenges", fake_http01_challenges)
        monkeypatch.setattr(tls_module, "_challenge_server", fake_challenge_server)


class TestPublicIpHelpers:
    def test_resolve_public_ipv4(self, monkeypatch):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _limit: int) -> bytes:
                return b"8.8.8.8\n"

        monkeypatch.setattr(
            "xferry.security.tls.urllib.request.urlopen",
            lambda _request, timeout: FakeResponse(),
        )

        assert resolve_public_ipv4() == "8.8.8.8"

    def test_validate_public_ipv4_rejects_private_address(self):
        with pytest.raises(ValueError, match="not globally routable"):
            validate_public_ipv4("192.168.0.1")

    def test_resolve_public_ipv4_rejects_non_https_url(self):
        with pytest.raises(ValueError, match="must be https"):
            resolve_public_ipv4(url="http://example.com/ip")

    def test_sslip_domain_for_ip(self):
        assert sslip_domain_for_ip("8.8.4.4") == "8-8-4-4.sslip.io"
