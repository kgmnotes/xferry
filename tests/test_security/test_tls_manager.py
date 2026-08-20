"""Tests for xferry.security.tls_manager.TLSManager."""

from __future__ import annotations

import ssl
from pathlib import Path
from unittest.mock import Mock

import pytest

from xferry.security.tls import generate_self_signed_cert
from xferry.security.tls_manager import TLSManager


def _write_cert_pair(cert_path: Path, key_path: Path, common_name: str = "example.com") -> None:
    generate_self_signed_cert(
        cert_path=cert_path,
        key_path=key_path,
        common_name=common_name,
    )


class TestTLSManagerDisabled:
    def test_disabled_setup_is_noop(self) -> None:
        m = TLSManager(
            enabled=False,
            cert_file=None,
            key_file=None,
            letsencrypt=False,
            domain=None,
            email=None,
            host="127.0.0.1",
        )
        m.setup()

        assert m.ssl_context is None
        assert m.enabled is False

    def test_describe_unknown_when_no_cert(self) -> None:
        m = TLSManager(
            enabled=False,
            cert_file=None,
            key_file=None,
            letsencrypt=False,
            domain=None,
            email=None,
            host="127.0.0.1",
        )
        assert m.describe() == "unknown"


class TestTLSManagerSelfSigned:
    def test_self_signed_generated_on_setup(self, tmp_path: Path) -> None:
        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=False,
            domain=None,
            email=None,
            host="127.0.0.1",
        )

        m.setup()
        try:
            assert isinstance(m.ssl_context, ssl.SSLContext)
            assert m.ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2
            assert m.cert_file and Path(m.cert_file).exists()
            assert m.describe() == "self-signed"
            assert m.temp_cert_files
        finally:
            m.cleanup()
            # After cleanup, temp files should be removed
            for path in m.temp_cert_files:
                assert not Path(path).exists()
            assert not m.temp_cert_files


class TestTLSManagerWithProvidedCert:
    def test_uses_provided_cert_without_generating(self, tmp_path: Path) -> None:
        from xferry.security.tls import generate_self_signed_cert

        cert, key = generate_self_signed_cert(common_name="localhost")
        try:
            m = TLSManager(
                enabled=True,
                cert_file=str(cert),
                key_file=str(key),
                letsencrypt=False,
                domain=None,
                email=None,
                host="localhost",
            )
            m.setup()

            assert m.enabled
            assert isinstance(m.ssl_context, ssl.SSLContext)
            assert m.describe() == str(cert)
            # User-supplied cert is not marked for cleanup
            assert m.temp_cert_files == []
        finally:
            cert.unlink(missing_ok=True)
            key.unlink(missing_ok=True)


class TestTLSManagerDescribe:
    def test_provided_cert_description_does_not_claim_letsencrypt(self) -> None:
        m = TLSManager(
            enabled=True,
            cert_file="/tmp/fake.pem",
            key_file="/tmp/fake.key",
            letsencrypt=True,
            domain="example.com",
            email=None,
            host="example.com",
        )
        assert m.describe() == "/tmp/fake.pem"


class TestTLSManagerControlFlow:
    def test_try_letsencrypt_uses_existing_certificate(self, tmp_path: Path, monkeypatch) -> None:
        config_dir = tmp_path / ".xferry" / "acme"
        live_dir = config_dir / "live" / "example.com"
        cert_path = live_dir / "fullchain.pem"
        key_path = live_dir / "privkey.pem"
        _write_cert_pair(cert_path, key_path)

        obtain_mock = Mock()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal",
            lambda _path: False,
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", obtain_mock)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        m._try_letsencrypt()

        assert m.cert_file == str(cert_path)
        assert m.key_file == str(key_path)
        assert m.describe() == "Let's Encrypt (example.com)"
        obtain_mock.assert_not_called()

    def test_try_letsencrypt_renews_when_fresh_cache_key_is_missing(
        self,
        tmp_path: Path,
        monkeypatch,
        capsys,
    ) -> None:
        config_dir = tmp_path / ".xferry" / "acme"
        live_dir = config_dir / "live" / "example.com"
        cert_path = live_dir / "fullchain.pem"
        key_path = live_dir / "privkey.pem"
        _write_cert_pair(cert_path, key_path)
        key_path.unlink()

        obtain_calls: list[dict[str, object]] = []

        def fake_obtain(**kwargs):
            obtain_calls.append(kwargs)
            _write_cert_pair(cert_path, key_path)
            return cert_path, key_path

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal",
            lambda _path: False,
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fake_obtain)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        m._try_letsencrypt()

        assert obtain_calls
        assert m.cert_file == str(cert_path)
        assert m.key_file == str(key_path)
        output = capsys.readouterr().out
        assert "private key file is missing" in output
        assert "BEGIN RSA PRIVATE KEY" not in output

    def test_try_letsencrypt_fails_early_for_unparsable_cached_key(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        config_dir = tmp_path / ".xferry" / "acme"
        live_dir = config_dir / "live" / "example.com"
        cert_path = live_dir / "fullchain.pem"
        key_path = live_dir / "privkey.pem"
        _write_cert_pair(cert_path, key_path)
        key_path.write_text("not a private key", encoding="utf-8")

        obtain_mock = Mock()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal",
            lambda _path: False,
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", obtain_mock)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        with pytest.raises(RuntimeError) as exc_info:
            m._try_letsencrypt()

        message = str(exc_info.value)
        assert "private key file is not a valid unencrypted PEM private key" in message
        assert "not a private key" not in message
        obtain_mock.assert_not_called()

    def test_try_letsencrypt_fails_early_when_cert_missing_and_cached_key_is_unparsable(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        live_dir = tmp_path / ".xferry" / "acme" / "live" / "example.com"
        key_path = live_dir / "privkey.pem"
        live_dir.mkdir(parents=True)
        key_path.write_text("not a private key", encoding="utf-8")

        obtain_mock = Mock()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", obtain_mock)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        with pytest.raises(RuntimeError) as exc_info:
            m._try_letsencrypt()

        message = str(exc_info.value)
        assert "private key file is not a valid unencrypted PEM private key" in message
        assert "not a private key" not in message
        assert "MalformedFraming" not in message
        obtain_mock.assert_not_called()

    def test_try_letsencrypt_renews_mismatched_cached_pair(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        config_dir = tmp_path / ".xferry" / "acme"
        live_dir = config_dir / "live" / "example.com"
        cert_path = live_dir / "fullchain.pem"
        key_path = live_dir / "privkey.pem"
        _write_cert_pair(cert_path, key_path)
        other_cert = tmp_path / "other-fullchain.pem"
        other_key = tmp_path / "other-privkey.pem"
        _write_cert_pair(other_cert, other_key, common_name="other.example.com")
        key_path.write_bytes(other_key.read_bytes())

        obtain_calls: list[dict[str, object]] = []

        def fake_obtain(**kwargs):
            obtain_calls.append(kwargs)
            _write_cert_pair(cert_path, key_path)
            return cert_path, key_path

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal",
            lambda _path: False,
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fake_obtain)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        m._try_letsencrypt()

        assert obtain_calls
        assert m.cert_file == str(cert_path)
        assert m.key_file == str(key_path)

    def test_try_letsencrypt_obtains_when_certificate_needs_renewal(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        config_dir = tmp_path / ".xferry" / "acme"
        obtained_cert = config_dir / "live" / "example.com" / "fullchain.pem"
        obtained_key = config_dir / "live" / "example.com" / "privkey.pem"

        def fake_obtain(**_kwargs):
            _write_cert_pair(obtained_cert, obtained_key)
            return obtained_cert, obtained_key

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal", lambda _path: True
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fake_obtain)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        m._try_letsencrypt()

        assert m.cert_file == str(obtained_cert)
        assert m.key_file == str(obtained_key)
        assert m.describe() == "Let's Encrypt (example.com)"

    def test_try_letsencrypt_rejects_invalid_obtained_pair(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        config_dir = tmp_path / ".xferry" / "acme"
        obtained_cert = config_dir / "live" / "example.com" / "fullchain.pem"
        obtained_key = config_dir / "live" / "example.com" / "privkey.pem"

        def fake_obtain(**_kwargs):
            _write_cert_pair(obtained_cert, obtained_key)
            other_cert = tmp_path / "obtained-other-fullchain.pem"
            other_key = tmp_path / "obtained-other-privkey.pem"
            _write_cert_pair(other_cert, other_key, common_name="other.example.com")
            obtained_key.write_bytes(other_key.read_bytes())
            return obtained_cert, obtained_key

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal", lambda _path: True
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fake_obtain)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        with pytest.raises(RuntimeError) as exc_info:
            m._try_letsencrypt()

        message = str(exc_info.value)
        assert "Obtained Let's Encrypt certificate cache for example.com is unusable" in message
        assert "certificate and private key do not match" in message
        assert "BEGIN RSA PRIVATE KEY" not in message

    def test_try_letsencrypt_reuses_fresh_legacy_cert_when_new_store_is_empty(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        legacy_dir = tmp_path / ".xferry" / "letsencrypt" / "live" / "example.com"
        legacy_cert = legacy_dir / "fullchain.pem"
        legacy_key = legacy_dir / "privkey.pem"
        _write_cert_pair(legacy_cert, legacy_key)

        obtain_mock = Mock()
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal", lambda _path: False
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", obtain_mock)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        m._try_letsencrypt()

        assert m.cert_file == str(legacy_cert)
        assert m.key_file == str(legacy_key)
        obtain_mock.assert_not_called()

    def test_try_letsencrypt_renews_mismatched_legacy_cache(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        config_dir = tmp_path / ".xferry" / "acme"
        obtained_cert = config_dir / "live" / "example.com" / "fullchain.pem"
        obtained_key = config_dir / "live" / "example.com" / "privkey.pem"
        legacy_dir = tmp_path / ".xferry" / "letsencrypt" / "live" / "example.com"
        legacy_cert = legacy_dir / "fullchain.pem"
        legacy_key = legacy_dir / "privkey.pem"
        _write_cert_pair(legacy_cert, legacy_key)
        other_cert = tmp_path / "legacy-other-fullchain.pem"
        other_key = tmp_path / "legacy-other-privkey.pem"
        _write_cert_pair(other_cert, other_key, common_name="other.example.com")
        legacy_key.write_bytes(other_key.read_bytes())

        obtain_calls: list[dict[str, object]] = []

        def fake_obtain(**kwargs):
            obtain_calls.append(kwargs)
            _write_cert_pair(obtained_cert, obtained_key)
            return obtained_cert, obtained_key

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(
            "xferry.security.tls_manager.check_cert_needs_renewal", lambda _path: False
        )
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fake_obtain)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email="ops@example.com",
            host="example.com",
        )

        m._try_letsencrypt()

        assert obtain_calls
        assert m.cert_file == str(obtained_cert)
        assert m.key_file == str(obtained_key)

    def test_setup_propagates_acme_failure(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        def fail_obtain(**_kwargs):
            raise RuntimeError("acme failed")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fail_obtain)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=True,
            domain="example.com",
            email=None,
            host="127.0.0.1",
        )

        with pytest.raises(RuntimeError, match="acme failed"):
            m.setup()

    def test_sslip_resolves_public_ip_and_domain(self, tmp_path: Path, monkeypatch) -> None:
        obtained_cert = (
            tmp_path / ".xferry" / "acme" / "live" / "8-8-8-8.sslip.io" / "fullchain.pem"
        )
        obtained_key = tmp_path / ".xferry" / "acme" / "live" / "8-8-8-8.sslip.io" / "privkey.pem"

        def fake_obtain(**kwargs):
            assert kwargs["domain"] == "8-8-8-8.sslip.io"
            _write_cert_pair(obtained_cert, obtained_key, common_name="8-8-8-8.sslip.io")
            return obtained_cert, obtained_key

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr("xferry.security.tls_manager.resolve_public_ipv4", lambda: "8.8.8.8")
        monkeypatch.setattr("xferry.security.tls_manager.obtain_letsencrypt_cert", fake_obtain)

        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=False,
            domain=None,
            email="ops@example.com",
            host="0.0.0.0",
            sslip=True,
        )

        m._prepare_sslip_domain()
        m._try_letsencrypt()

        assert m.domain == "8-8-8-8.sslip.io"
        assert m.public_ip == "8.8.8.8"
        assert m.describe() == "Let's Encrypt sslip.io (8-8-8-8.sslip.io)"

    def test_sslip_rejects_domain_combination(self) -> None:
        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=False,
            domain="example.com",
            email=None,
            host="0.0.0.0",
            sslip=True,
        )

        with pytest.raises(RuntimeError, match="cannot be combined"):
            m._prepare_sslip_domain()

    def test_setup_propagates_self_signed_generation_failure(
        self,
        monkeypatch,
    ) -> None:
        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=False,
            domain=None,
            email=None,
            host="127.0.0.1",
        )

        def fail_self_signed() -> None:
            raise RuntimeError("self signed failed")

        monkeypatch.setattr(m, "_generate_self_signed", fail_self_signed)

        build_mock = Mock()
        monkeypatch.setattr(m, "_build_context", build_mock)

        with pytest.raises(RuntimeError, match="self signed failed"):
            m.setup()
        build_mock.assert_not_called()

    def test_setup_requires_cert_and_key_together(self) -> None:
        m = TLSManager(
            enabled=True,
            cert_file="/tmp/cert.pem",
            key_file=None,
            letsencrypt=False,
            domain=None,
            email=None,
            host="127.0.0.1",
        )

        with pytest.raises(RuntimeError, match="--cert and --key"):
            m.setup()

    def test_cleanup_ignores_unlink_errors_and_clears_list(self, monkeypatch) -> None:
        m = TLSManager(
            enabled=True,
            cert_file=None,
            key_file=None,
            letsencrypt=False,
            domain=None,
            email=None,
            host="127.0.0.1",
        )
        m.temp_cert_files = ["/tmp/cert.pem", "/tmp/key.pem"]

        def fake_unlink(self) -> None:
            raise OSError("locked")

        monkeypatch.setattr(Path, "unlink", fake_unlink)

        m.cleanup()

        assert m.temp_cert_files == []
