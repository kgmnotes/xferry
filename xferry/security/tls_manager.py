"""TLS context lifecycle management.

Encapsulates certificate acquisition (Let's Encrypt, self-signed, user-supplied),
SSL context creation with modern defaults, and cleanup of temporary files.
"""

from __future__ import annotations

import atexit
import logging
import ssl
from pathlib import Path

from .tls import (
    DEFAULT_ACME_HTTP_ADDRESS,
    DEFAULT_ACME_HTTP_PORT,
    LE_PRODUCTION_DIRECTORY,
    LE_STAGING_DIRECTORY,
    check_cert_needs_renewal,
    generate_self_signed_cert,
    obtain_letsencrypt_cert,
    resolve_public_ipv4,
    sslip_domain_for_ip,
    validate_cert_key_pair,
    validate_private_key_file,
    validate_public_ipv4,
)

logger = logging.getLogger("xferry")
_WILDCARD_BIND_HOST = "0.0.0.0"  # nosec B104


class TLSManager:
    """Owns the SSL context and the temporary files backing it."""

    def __init__(
        self,
        *,
        enabled: bool,
        cert_file: str | None,
        key_file: str | None,
        letsencrypt: bool,
        domain: str | None,
        email: str | None,
        host: str,
        sslip: bool = False,
        public_ip: str | None = None,
        acme_staging: bool = False,
        acme_server: str | None = None,
        acme_http_address: str = DEFAULT_ACME_HTTP_ADDRESS,
        acme_http_port: int = DEFAULT_ACME_HTTP_PORT,
    ) -> None:
        self.enabled = enabled
        self.cert_file = cert_file
        self.key_file = key_file
        self.letsencrypt = letsencrypt
        self.domain = domain
        self.email = email
        self.host = host
        self.sslip = sslip
        self.public_ip = public_ip
        self.acme_staging = acme_staging
        self.acme_server = acme_server
        self.acme_http_address = acme_http_address
        self.acme_http_port = acme_http_port
        self.ssl_context: ssl.SSLContext | None = None
        self.temp_cert_files: list[str] = []
        self._used_self_signed = False
        self._used_letsencrypt = False
        self._used_sslip = False

    def setup(self) -> None:
        """Acquire a certificate and build the SSL context."""
        if not self.enabled:
            return
        if (self.cert_file is None) != (self.key_file is None):
            raise RuntimeError("--cert and --key must be provided together")

        if self.sslip:
            self._prepare_sslip_domain()

        if self.letsencrypt or self.sslip:
            if not self.domain:
                raise RuntimeError("--letsencrypt requires --domain unless --sslip is used.")
            self._try_letsencrypt()

        if not self.cert_file or not self.key_file:
            self._generate_self_signed()

        self._build_context()

    def _prepare_sslip_domain(self) -> None:
        if self.domain:
            raise RuntimeError("--sslip cannot be combined with --domain.")
        ip = validate_public_ipv4(self.public_ip) if self.public_ip else resolve_public_ipv4()
        self.public_ip = ip
        self.domain = sslip_domain_for_ip(ip)
        self._used_sslip = True

    def _try_letsencrypt(self) -> None:
        assert self.domain is not None
        config_dir = Path.home() / ".xferry" / "acme"
        cert_path = config_dir / "live" / self.domain / "fullchain.pem"
        key_path = config_dir / "live" / self.domain / "privkey.pem"
        legacy_cert_path = (
            Path.home() / ".xferry" / "letsencrypt" / "live" / self.domain / "fullchain.pem"
        )
        legacy_key_path = (
            Path.home() / ".xferry" / "letsencrypt" / "live" / self.domain / "privkey.pem"
        )

        if cert_path.exists() and not check_cert_needs_renewal(cert_path):
            validation = validate_cert_key_pair(cert_path, key_path)
            if validation.valid:
                print(f"[TLS] Using existing Let's Encrypt certificate for {self.domain}")
            elif validation.recoverable_by_renewal:
                print(
                    f"[TLS] Existing Let's Encrypt cache for {self.domain} is unusable "
                    f"({validation.reason}); renewing..."
                )
                cert_path, key_path = self._obtain_valid_letsencrypt_cert(config_dir)
            else:
                self._raise_broken_acme_cache(validation.reason)
        else:
            if key_path.exists():
                validation = validate_private_key_file(key_path)
                if not validation.valid:
                    self._raise_broken_acme_cache(validation.reason)
            if cert_path.exists():
                validation = validate_cert_key_pair(cert_path, key_path)
                if not validation.valid and not validation.recoverable_by_renewal:
                    self._raise_broken_acme_cache(validation.reason)
            if (
                not cert_path.exists()
                and legacy_cert_path.exists()
                and not check_cert_needs_renewal(legacy_cert_path)
            ):
                validation = validate_cert_key_pair(legacy_cert_path, legacy_key_path)
                if validation.valid:
                    print(f"[TLS] Using legacy Let's Encrypt certificate for {self.domain}")
                    cert_path = legacy_cert_path
                    key_path = legacy_key_path
                else:
                    print(
                        f"[TLS] Legacy Let's Encrypt cache for {self.domain} is unusable "
                        f"({validation.reason}); obtaining a new certificate..."
                    )
                    cert_path, key_path = self._obtain_valid_letsencrypt_cert(config_dir)
            else:
                cert_path, key_path = self._obtain_valid_letsencrypt_cert(config_dir)

        self.cert_file = str(cert_path)
        self.key_file = str(key_path)
        self._used_letsencrypt = True

    def _obtain_valid_letsencrypt_cert(self, config_dir: Path) -> tuple[Path, Path]:
        assert self.domain is not None
        print(f"[TLS] Obtaining Let's Encrypt certificate for {self.domain}...")
        cert_path, key_path = obtain_letsencrypt_cert(
            domain=self.domain,
            email=self.email,
            config_dir=config_dir,
            server_url=self._acme_directory_url(),
            http_address=self.acme_http_address,
            http_port=self.acme_http_port,
            user_agent="xferry/acme",
        )
        validation = validate_cert_key_pair(cert_path, key_path)
        if not validation.valid:
            raise RuntimeError(
                f"Obtained Let's Encrypt certificate cache for {self.domain} is unusable: "
                f"{validation.reason}. Remove the broken ACME cache directory "
                f"{cert_path.parent} and retry."
            )
        print(f"[TLS] Certificate obtained: {cert_path}")
        return cert_path, key_path

    def _raise_broken_acme_cache(self, reason: str) -> None:
        assert self.domain is not None
        cache_dir = Path.home() / ".xferry" / "acme" / "live" / self.domain
        raise RuntimeError(
            f"Cached Let's Encrypt certificate for {self.domain} is unusable: {reason}. "
            f"Remove the broken ACME cache directory {cache_dir} and retry."
        )

    def _generate_self_signed(self) -> None:
        print("[TLS] Generating self-signed certificate...")
        common_name = self.host if self.host != _WILDCARD_BIND_HOST else "localhost"
        cert_path, key_path = generate_self_signed_cert(common_name=common_name)
        self.cert_file = str(cert_path)
        self.key_file = str(key_path)
        self.temp_cert_files = [self.cert_file, self.key_file]
        self._used_self_signed = True
        atexit.register(self.cleanup)

    def _build_context(self) -> None:
        assert self.cert_file is not None and self.key_file is not None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")
        self.ssl_context = context

    def describe(self) -> str:
        """Short human-readable description of the active certificate."""
        if self._used_letsencrypt and self.domain:
            if self._used_sslip:
                return f"Let's Encrypt sslip.io ({self.domain})"
            return f"Let's Encrypt ({self.domain})"
        if self._used_self_signed:
            return "self-signed"
        return self.cert_file or "unknown"

    def _acme_directory_url(self) -> str:
        if self.acme_server:
            return self.acme_server
        if self.acme_staging:
            return LE_STAGING_DIRECTORY
        return LE_PRODUCTION_DIRECTORY

    def cleanup(self) -> None:
        """Remove any temporary cert/key files we created."""
        for path in self.temp_cert_files:
            try:
                Path(path).unlink()
            except OSError:
                pass
        self.temp_cert_files.clear()
