"""TLS context lifecycle management.

Encapsulates certificate acquisition (Let's Encrypt, self-signed, user-supplied),
SSL context creation with modern defaults, and cleanup of temporary files.
"""

from __future__ import annotations

import atexit
import datetime as dt
import hashlib
import json
import logging
import math
import ssl
import threading
from email.utils import parsedate_to_datetime
from pathlib import Path

from cryptography import x509

from .renewal import UTC, certificate_schedule, load_schedule
from .tls import (
    DEFAULT_ACME_HTTP_ADDRESS,
    DEFAULT_ACME_HTTP_PORT,
    LE_PRODUCTION_DIRECTORY,
    LE_STAGING_DIRECTORY,
    _account_key_path,
    _acme_client_for_key,
    _load_private_key,
    _write_atomic,
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


class _CertificateRetryDeferred(RuntimeError):
    """A previous issuance failed; skipped retries must not extend its deadline."""


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
        self._renewal_stop = threading.Event()
        self._publication_lock = threading.Lock()
        self._renewal_thread: threading.Thread | None = None
        self._renewing = False
        self._active_expiry: dt.datetime | None = None
        self._active_fingerprint: str | None = None
        self._retry_not_before = 0.0
        self._retry_failures = 0

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
            try:
                self._try_letsencrypt()
            except (_CertificateRetryDeferred, InterruptedError):
                raise
            except Exception as exc:
                retained = self._retain_valid_cache()
                self._record_renewal_failure(exc)
                if not retained:
                    raise
                logger.warning("TLS renewal failed; retaining the valid cached certificate")

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
        if self._issuance_deferred():
            if self._retain_valid_cache():
                return
            raise _CertificateRetryDeferred(
                "certificate issuance is deferred by the persisted retry schedule"
            )
        config_dir = Path.home() / ".xferry" / "acme"
        cert_path = config_dir / "live" / self.domain / "fullchain.pem"
        key_path = config_dir / "live" / self.domain / "privkey.pem"
        legacy_cert_path = (
            Path.home() / ".xferry" / "letsencrypt" / "live" / self.domain / "fullchain.pem"
        )
        legacy_key_path = (
            Path.home() / ".xferry" / "letsencrypt" / "live" / self.domain / "privkey.pem"
        )

        if cert_path.exists() and not self._cached_certificate_due(cert_path):
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
            publish_certificate=self._publish_certificate,
        )
        validation = validate_cert_key_pair(cert_path, key_path)
        if not validation.valid:
            raise RuntimeError(
                f"Obtained Let's Encrypt certificate cache for {self.domain} is unusable: "
                f"{validation.reason}. Remove the broken ACME cache directory "
                f"{cert_path.parent} and retry."
            )
        self._clear_issuance_retry(cert_path)
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
        self.ssl_context = self._context_for(Path(self.cert_file), Path(self.key_file))
        fingerprint, _, expiry = certificate_schedule(Path(self.cert_file).read_bytes())
        self._active_fingerprint, self._active_expiry = fingerprint, expiry

    @staticmethod
    def _context_for(cert_file: Path, key_file: Path) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")
        return context

    def _publish_certificate(self, candidate: Path, key: Path, destination: Path) -> None:
        """Validate before touching live files or the context used by connections."""
        validation = validate_cert_key_pair(candidate, key)
        if not validation.valid:
            raise RuntimeError("obtained certificate and private key do not match")
        payload = candidate.read_bytes()
        cert = x509.load_pem_x509_certificate(payload)
        now = dt.datetime.now(UTC)
        try:
            names = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        if self.domain not in names or not (
            cert.not_valid_before_utc <= now < cert.not_valid_after_utc
        ):
            raise RuntimeError("obtained certificate has invalid hostname or validity")
        if self._renewing and self._active_expiry is not None:
            if cert.not_valid_after_utc <= self._active_expiry:
                raise RuntimeError("renewal did not extend certificate expiry")
        context = self._context_for(candidate, key)
        with self._publication_lock:
            if self._renewal_stop.is_set():
                raise InterruptedError("certificate renewal stopped")
            if candidate != destination:
                _write_atomic(destination, payload, 0o644)
            self.cert_file, self.key_file = str(destination), str(key)
            self.ssl_context = context
            self._active_expiry = cert.not_valid_after_utc
            self._active_fingerprint = certificate_schedule(payload)[0]

    def _retain_valid_cache(self) -> bool:
        if not self.domain:
            return False
        root = Path.home() / ".xferry" / "acme" / "live" / self.domain
        cert, key = root / "fullchain.pem", root / "privkey.pem"
        try:
            if not validate_cert_key_pair(cert, key).valid:
                return False
            if certificate_schedule(cert.read_bytes())[2] <= dt.datetime.now(UTC):
                return False
            self._context_for(cert, key)
        except (OSError, ValueError, ssl.SSLError):
            return False
        self.cert_file, self.key_file = str(cert), str(key)
        self._used_letsencrypt = True
        return True

    @staticmethod
    def _cached_certificate_due(cert: Path) -> bool:
        try:
            fingerprint, _, expiry = certificate_schedule(cert.read_bytes())
            state = load_schedule(cert.with_name("renewal.json"), fingerprint)
            now = dt.datetime.now(UTC)
            if expiry <= now:
                return True
            if TLSManager._timestamp(state.get("next_attempt")) > now.timestamp():
                return False
            due = TLSManager._timestamp(state.get("due"))
            if due:
                return now.timestamp() >= min(due, expiry.timestamp())
        except (OSError, ValueError, TypeError):
            pass
        return check_cert_needs_renewal(cert)

    def start_renewal(self) -> None:
        """Start one ACME worker after a successful listener startup."""
        if not self._used_letsencrypt or self._renewal_thread is not None:
            return
        self._renewal_thread = threading.Thread(
            target=self._renewal_loop, name="xferry-tls-renewal", daemon=True
        )
        self._renewal_thread.start()

    def _renewal_loop(self) -> None:
        while not self._renewal_stop.is_set():
            try:
                self.renew_if_due()
            except InterruptedError:
                return
            except Exception as exc:
                self._record_renewal_failure(exc)
                logger.warning("TLS renewal failed; retaining active context and retrying later")
            self._renewal_stop.wait(60)

    def renew_if_due(self, now: dt.datetime | None = None) -> bool:
        """Refresh ARI and renew if due. Kept separate for deterministic tests."""
        if not self.cert_file or not self.key_file or self._renewal_stop.is_set():
            return False
        now = now or dt.datetime.now(UTC)
        cert_path = Path(self.cert_file)
        current_payload = cert_path.read_bytes()
        fingerprint, fallback, expiry = certificate_schedule(current_payload)
        if self._active_fingerprint is not None and fingerprint != self._active_fingerprint:
            # Another runtime sharing the cache may have already renewed it.
            # Adopt it before consulting its fresh schedule or retry backoff.
            self._publish_certificate(cert_path, Path(self.key_file), cert_path)
            self._clear_issuance_retry(cert_path)
        if self._issuance_deferred(now):
            return False
        state = load_schedule(cert_path.with_name("renewal.json"), fingerprint)
        if self._timestamp(state.get("next_attempt")) > now.timestamp():
            return False
        if self._timestamp(state.get("ari_check")) <= now.timestamp():
            try:
                scheduled, next_check = self._renewal_info(cert_path.read_bytes())
                if scheduled is not None:
                    previous_due = self._timestamp(state.get("due"))
                    state["due"] = (
                        min(previous_due, scheduled.timestamp())
                        if previous_due
                        else (scheduled.timestamp())
                    )
                state["ari_check"] = min(
                    next_check.timestamp(), (now + dt.timedelta(hours=6)).timestamp()
                )
            except Exception:
                state["ari_check"] = (now + dt.timedelta(hours=6)).timestamp()
            state["fingerprint"] = fingerprint
            self._save_schedule(state)
        due = min(self._timestamp(state.get("due")) or fallback.timestamp(), expiry.timestamp())
        if now.timestamp() < due:
            return False
        if not validate_private_key_file(self.key_file).valid:
            raise RuntimeError("cached private key is unavailable; renewal did not replace it")
        self._renewing = True
        try:
            obtain_letsencrypt_cert(
                domain=self.domain or "",
                email=self.email,
                config_dir=Path.home() / ".xferry" / "acme",
                server_url=self._acme_directory_url(),
                http_address=self.acme_http_address,
                http_port=self.acme_http_port,
                user_agent="xferry/acme",
                network_timeout=5,
                challenge_timeout=5,
                order_timeout=90,
                stop_event=self._renewal_stop,
                publish_certificate=self._publish_certificate,
                expected_certificate=current_payload,
            )
        finally:
            self._renewing = False
        self._clear_issuance_retry(Path(self.cert_file))
        logger.info("TLS certificate renewed; new connections use the new certificate")
        return True

    def _renewal_info(self, payload: bytes) -> tuple[dt.datetime | None, dt.datetime]:
        root = Path.home() / ".xferry" / "acme"
        client = _acme_client_for_key(
            _load_private_key(_account_key_path(root, self._acme_directory_url())),
            directory_url=self._acme_directory_url(),
            user_agent="xferry/acme",
            timeout=5,
        )
        scheduled, next_check = client.renewal_time(payload)
        return (
            None if scheduled is None else scheduled.astimezone(UTC),
            next_check.astimezone(UTC),
        )

    def _save_schedule(self, state: dict[str, object]) -> None:
        if self.cert_file:
            _write_atomic(
                Path(self.cert_file).with_name("renewal.json"),
                json.dumps(state, sort_keys=True).encode("utf-8"),
                0o600,
            )

    @staticmethod
    def _timestamp(value: object) -> float:
        try:
            parsed = float(str(value))
            return parsed if math.isfinite(parsed) and parsed > 0 else 0.0
        except (ValueError, TypeError):
            return 0.0

    def _issuance_retry_path(self) -> Path | None:
        if self.cert_file:
            return Path(self.cert_file).with_name("issuance-retry.json")
        if self.domain:
            return Path.home() / ".xferry" / "acme" / "live" / self.domain / "issuance-retry.json"
        return None

    def _issuance_retry_scope(self) -> str:
        return hashlib.sha256(f"{self._acme_directory_url()}\0{self.domain}".encode()).hexdigest()

    def _issuance_deferred(self, now: dt.datetime | None = None) -> bool:
        path = self._issuance_retry_path()
        state = load_schedule(path, self._issuance_retry_scope()) if path is not None else {}
        deadline = max(self._retry_not_before, self._timestamp(state.get("next_attempt")))
        return deadline > (now or dt.datetime.now(UTC)).timestamp()

    def _clear_issuance_retry(self, cert: Path) -> None:
        self._retry_not_before = 0.0
        self._retry_failures = 0
        try:
            cert.with_name("issuance-retry.json").unlink(missing_ok=True)
        except OSError:
            logger.warning("Could not remove completed TLS issuance retry schedule")

    @staticmethod
    def _retry_after_deadline(error: BaseException | None, now: float) -> float:
        """Read Retry-After without persisting response bodies or exception text."""
        pending: list[object] = [error]
        seen: set[int] = set()
        deadline = 0.0

        def parse(value: object) -> float:
            if isinstance(value, dt.datetime):
                return value.astimezone(UTC).timestamp()
            seconds = TLSManager._timestamp(value)
            if seconds:
                return now + seconds
            if isinstance(value, str):
                try:
                    return parsedate_to_datetime(value).astimezone(UTC).timestamp()
                except (ValueError, TypeError, OverflowError):
                    pass
            return 0.0

        while pending and len(seen) < 32:
            item = pending.pop()
            if item is None or id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, BaseException):
                deadline = max(deadline, parse(getattr(item, "retry_after", None)))
                pending.extend((item.__cause__, item.__context__, getattr(item, "response", None)))
                pending.extend(item.args)
            elif isinstance(item, tuple | list):
                pending.extend(item)
            else:
                headers = getattr(item, "headers", None)
                if headers is not None:
                    deadline = max(deadline, parse(headers.get("Retry-After")))
        return deadline

    def _record_renewal_failure(self, error: BaseException | None = None) -> None:
        path = self._issuance_retry_path()
        if path is None:
            return
        now = dt.datetime.now(UTC).timestamp()
        scope = self._issuance_retry_scope()
        retry = load_schedule(path, scope)
        failures = min(
            7, max(self._retry_failures, int(self._timestamp(retry.get("failures")))) + 1
        )
        self._retry_failures = failures
        self._retry_not_before = max(
            now + min(3600, 60 * 2 ** (failures - 1)),
            self._retry_after_deadline(error, now),
        )
        retry.update(fingerprint=scope, failures=failures, next_attempt=self._retry_not_before)
        try:
            _write_atomic(path, json.dumps(retry, sort_keys=True).encode("utf-8"), 0o600)
        except OSError:
            logger.warning("Could not persist TLS issuance retry schedule")
        if not self.cert_file:
            return
        try:
            fingerprint, _, _ = certificate_schedule(Path(self.cert_file).read_bytes())
            state = load_schedule(Path(self.cert_file).with_name("renewal.json"), fingerprint)
            state.update(
                fingerprint=fingerprint,
                failures=failures,
                next_attempt=self._retry_not_before,
            )
            self._save_schedule(state)
        except (OSError, ValueError, TypeError):
            logger.warning("Could not persist TLS renewal retry schedule")

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
        self.stop_renewal()
        thread = self._renewal_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=20)
        for path in self.temp_cert_files:
            try:
                Path(path).unlink()
            except OSError:
                pass
        self.temp_cert_files.clear()

    def stop_renewal(self) -> None:
        """Cancel renewal before listener workers start draining."""
        with self._publication_lock:
            self._renewal_stop.set()
