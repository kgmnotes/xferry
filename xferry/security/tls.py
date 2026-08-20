"""
TLS certificate helpers.

Self-signed certificates are generated in-process with ``cryptography``.
Let's Encrypt certificates are obtained through Certbot's official ``acme``
Python library rather than by shelling out to a certbot executable.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

if TYPE_CHECKING:
    from acme import client, messages, standalone

LE_PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_ACME_HTTP_ADDRESS = ""
DEFAULT_ACME_HTTP_PORT = 80
DEFAULT_RENEWAL_DAYS = 30
DEFAULT_PUBLIC_IP_URL = "https://api.ipify.org"

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")
_WILDCARD_BIND_HOST = "0.0.0.0"  # nosec B104


@dataclass(frozen=True)
class CertKeyPairValidation:
    """Sanitized validation result for a certificate/private-key cache pair."""

    valid: bool
    reason: str = ""
    recoverable_by_renewal: bool = False


def _default_temp_path(prefix: str) -> Path:
    fd, path = tempfile.mkstemp(suffix=".pem", prefix=prefix)
    os.close(fd)
    return Path(path)


def _private_key_pem(key: RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_atomic(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(mode)
        tmp_path.replace(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _load_private_key(path: Path) -> RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, RSAPrivateKey):
        raise RuntimeError(f"private key is not RSA: {path}")
    return key


def _load_or_create_rsa_key(path: Path, key_size: int = 2048) -> RSAPrivateKey:
    if path.exists():
        return _load_private_key(path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    _write_atomic(path, _private_key_pem(key), 0o600)
    return key


def normalize_domain(domain: str) -> str:
    """Return a lowercase ASCII hostname safe for certificates and HTTP."""
    if domain.startswith("*."):
        raise ValueError("wildcard certificates require DNS-01 and are not supported")
    try:
        normalized = domain.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as err:
        raise ValueError(f"invalid domain name: {domain!r}") from err

    if not normalized or len(normalized) > 253 or not _DOMAIN_RE.fullmatch(normalized):
        raise ValueError(f"invalid domain name: {domain!r}")

    labels = normalized.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"invalid domain label in {domain!r}")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"invalid domain label in {domain!r}")
    return normalized


def _directory_slug(directory_url: str) -> str:
    return hashlib.sha256(directory_url.encode("utf-8")).hexdigest()[:16]


def _account_key_path(config_dir: Path, directory_url: str) -> Path:
    return config_dir / "accounts" / f"{_directory_slug(directory_url)}.pem"


def _certificate_paths(config_dir: Path, domain: str) -> tuple[Path, Path]:
    live_dir = config_dir / "live" / domain
    return live_dir / "fullchain.pem", live_dir / "privkey.pem"


def _acme_client_for_key(
    account_key: RSAPrivateKey,
    *,
    directory_url: str,
    user_agent: str,
    timeout: int,
) -> client.ClientV2:
    from acme import client
    from josepy.jwk import JWKRSA

    jwk = JWKRSA(key=account_key)
    net = client.ClientNetwork(jwk, user_agent=user_agent, timeout=timeout)
    directory = client.ClientV2.get_directory(directory_url, net)
    return client.ClientV2(directory, net=net)


def _make_csr_pem(domain_key_pem: bytes, domains: list[str]) -> bytes:
    """Build a PEM CSR without importing ACME helper modules."""
    key = serialization.load_pem_private_key(domain_key_pem, password=None)
    if not isinstance(key, RSAPrivateKey):
        raise RuntimeError("domain private key is not RSA")

    primary_domain = domains[0]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, primary_domain)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _ensure_account(
    acme_client: client.ClientV2,
    *,
    email: str | None,
) -> messages.RegistrationResource:
    from acme import errors, messages

    registration = messages.NewRegistration.from_data(
        email=email,
        terms_of_service_agreed=True,
    )
    try:
        return acme_client.new_account(registration)
    except errors.ConflictError as err:
        existing = messages.RegistrationResource(
            uri=err.location,
            body=messages.Registration.from_data(email=email),
        )
        return acme_client.query_registration(existing)


def _http01_challenges(
    acme_client: client.ClientV2,
    order: messages.OrderResource,
) -> tuple[set[standalone.HTTP01RequestHandler.HTTP01Resource], list[tuple[Any, Any]]]:
    from acme import challenges, standalone

    resources: set[standalone.HTTP01RequestHandler.HTTP01Resource] = set()
    answers: list[tuple[Any, Any]] = []

    for authz in order.authorizations:
        for challenge_body in authz.body.challenges:
            if isinstance(challenge_body.chall, challenges.HTTP01):
                response, validation = challenge_body.response_and_validation(acme_client.net.key)
                resources.add(
                    standalone.HTTP01RequestHandler.HTTP01Resource(
                        chall=challenge_body.chall,
                        response=response,
                        validation=validation,
                    )
                )
                answers.append((challenge_body, response))
                break
        else:
            raise RuntimeError("ACME server did not offer an HTTP-01 challenge")

    return resources, answers


@contextmanager
def _challenge_server(
    resources: set[standalone.HTTP01RequestHandler.HTTP01Resource],
    *,
    address: str,
    port: int,
    timeout: int,
) -> Iterator[standalone.HTTP01DualNetworkedServers]:
    from acme import standalone

    servers = standalone.HTTP01DualNetworkedServers((address, port), resources, timeout=timeout)
    servers.serve_forever()
    try:
        yield servers
    finally:
        servers.shutdown_and_server_close()


def generate_self_signed_cert(
    cert_path: str | Path | None = None,
    key_path: str | Path | None = None,
    days: int = 365,
    common_name: str = "localhost",
    organization: str = "xferry",
    key_size: int = 2048,
) -> tuple[Path, Path]:
    """
    Generate a self-signed server certificate.

    Returns:
        Tuple (certificate path, key path).
    """
    cert_output = Path(cert_path) if cert_path is not None else _default_temp_path("cert_")
    key_output = Path(key_path) if key_path is not None else _default_temp_path("key_")
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ]
    )

    san_names: list[x509.GeneralName] = [x509.DNSName("localhost")]
    try:
        san_names.append(x509.IPAddress(ipaddress.ip_address(common_name)))
    except ValueError:
        san_names.append(x509.DNSName(common_name))
    san_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    _write_atomic(cert_output, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _write_atomic(key_output, _private_key_pem(key), 0o600)
    return cert_output, key_output


def generate_cert_in_memory() -> tuple[str, str]:
    """
    Generate a certificate using temporary files.

    Returns:
        Tuple (certificate path, key path).
    """
    cert_path, key_path = generate_self_signed_cert()
    return str(cert_path), str(key_path)


def check_openssl_available() -> bool:
    """Check whether an external openssl executable is available."""
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_certbot_available() -> bool:
    """Check whether an external certbot executable is available."""
    try:
        result = subprocess.run(
            ["certbot", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_cert_needs_renewal(cert_path: str | Path, days: int = DEFAULT_RENEWAL_DAYS) -> bool:
    """
    Check if a certificate is missing, invalid, or expires within *days* days.
    """
    cert_path = Path(cert_path)
    if not cert_path.exists():
        return True

    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError):
        return True

    expires_at = _certificate_datetime_utc(cert, "not_valid_after")
    renewal_cutoff = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)
    return expires_at <= renewal_cutoff


def _certificate_datetime_utc(certificate: x509.Certificate, field_name: str) -> dt.datetime:
    """Return certificate validity datetimes as timezone-aware UTC."""
    preferred_name = f"{field_name}_utc"
    if hasattr(certificate, preferred_name):
        value = cast(dt.datetime, getattr(certificate, preferred_name))
    else:
        value = cast(dt.datetime, getattr(certificate, field_name))
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _public_key_der(public_key: Any) -> bytes:
    return cast(
        bytes,
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _load_private_key_for_validation(
    key_path: Path,
) -> tuple[Any, CertKeyPairValidation | None]:
    if not key_path.exists():
        return None, CertKeyPairValidation(
            valid=False,
            reason=f"private key file is missing: {key_path}",
            recoverable_by_renewal=True,
        )

    try:
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except OSError:
        return None, CertKeyPairValidation(
            valid=False,
            reason=f"private key file could not be read: {key_path}",
        )
    except (TypeError, ValueError, UnsupportedAlgorithm):
        return None, CertKeyPairValidation(
            valid=False,
            reason=f"private key file is not a valid unencrypted PEM private key: {key_path}",
        )

    return private_key, None


def validate_private_key_file(key_path: str | Path) -> CertKeyPairValidation:
    """
    Validate that a private-key file can be used before ACME attempts to reuse it.
    """
    _private_key, validation = _load_private_key_for_validation(Path(key_path))
    if validation is not None:
        return validation
    return CertKeyPairValidation(valid=True)


def validate_cert_key_pair(
    cert_path: str | Path,
    key_path: str | Path,
) -> CertKeyPairValidation:
    """
    Validate that a PEM certificate and private key are present, parse, and match.

    The returned reason is safe for logs and user-facing errors: it names the
    broken cache state but never includes PEM contents or raw parser exceptions.
    """
    cert_path = Path(cert_path)
    key_path = Path(key_path)

    if not cert_path.exists():
        return CertKeyPairValidation(
            valid=False,
            reason=f"certificate file is missing: {cert_path}",
            recoverable_by_renewal=True,
        )
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except OSError:
        return CertKeyPairValidation(
            valid=False,
            reason=f"certificate file could not be read: {cert_path}",
        )
    except ValueError:
        cert = None

    private_key, key_validation = _load_private_key_for_validation(key_path)
    if key_validation is not None:
        return key_validation

    if cert is None:
        return CertKeyPairValidation(
            valid=False,
            reason=f"certificate file is not a valid PEM X.509 certificate: {cert_path}",
            recoverable_by_renewal=True,
        )

    try:
        cert_public_key = _public_key_der(cert.public_key())
        private_public_key = _public_key_der(private_key.public_key())
    except (TypeError, ValueError, UnsupportedAlgorithm):
        return CertKeyPairValidation(
            valid=False,
            reason=(
                "certificate or private key type is unsupported for TLS pair validation: "
                f"{cert_path} / {key_path}"
            ),
        )

    if cert_public_key != private_public_key:
        return CertKeyPairValidation(
            valid=False,
            reason=f"certificate and private key do not match: {cert_path} / {key_path}",
            recoverable_by_renewal=True,
        )

    return CertKeyPairValidation(valid=True)


def obtain_letsencrypt_cert(
    domain: str,
    email: str | None = None,
    config_dir: str | Path | None = None,
    *,
    server_url: str = LE_PRODUCTION_DIRECTORY,
    http_address: str = DEFAULT_ACME_HTTP_ADDRESS,
    http_port: int = DEFAULT_ACME_HTTP_PORT,
    user_agent: str = "xferry/acme",
    network_timeout: int = 45,
    challenge_timeout: int = 30,
    order_timeout: int = 90,
) -> tuple[Path, Path]:
    """
    Obtain a Let's Encrypt certificate through the ACME HTTP-01 flow.

    Returns:
        Tuple (path to fullchain.pem, path to privkey.pem).
    """
    domain = normalize_domain(domain)
    if config_dir is None:
        config_dir = Path.home() / ".xferry" / "acme"
    config_root = Path(config_dir)

    cert_path, key_path = _certificate_paths(config_root, domain)
    account_key = _load_or_create_rsa_key(_account_key_path(config_root, server_url))
    domain_key = _load_or_create_rsa_key(key_path)
    domain_key_pem = _private_key_pem(domain_key)

    acme_client = _acme_client_for_key(
        account_key,
        directory_url=server_url,
        user_agent=user_agent,
        timeout=network_timeout,
    )
    _ensure_account(acme_client, email=email)

    csr_pem = _make_csr_pem(domain_key_pem, [domain])
    order = acme_client.new_order(csr_pem)
    resources, answers = _http01_challenges(acme_client, order)

    deadline = dt.datetime.now() + dt.timedelta(seconds=order_timeout)
    try:
        with _challenge_server(
            resources,
            address=http_address,
            port=http_port,
            timeout=challenge_timeout,
        ):
            for challenge_body, response in answers:
                acme_client.answer_challenge(challenge_body, response)
            finalized_order = acme_client.poll_and_finalize(order, deadline=deadline)
    except OSError as err:
        bind_host = http_address or _WILDCARD_BIND_HOST
        raise RuntimeError(
            f"could not bind ACME HTTP-01 challenge server on {bind_host}:{http_port}: {err}"
        ) from err

    fullchain_pem = finalized_order.fullchain_pem
    if not fullchain_pem:
        raise RuntimeError("ACME order finalized without a certificate chain")

    _write_atomic(cert_path, fullchain_pem.encode("utf-8"), 0o644)
    _write_atomic(key_path, domain_key_pem, 0o600)
    return cert_path, key_path


def get_cert_info(cert_path: str | Path) -> dict[str, str]:
    """
    Get certificate information from a PEM file.
    """
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    except Exception as err:
        return {"error": str(err)}

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "notBefore": _certificate_datetime_utc(cert, "not_valid_before").isoformat(),
        "notAfter": _certificate_datetime_utc(cert, "not_valid_after").isoformat(),
        "serialNumber": str(cert.serial_number),
    }


def resolve_public_ipv4(
    *,
    url: str = DEFAULT_PUBLIC_IP_URL,
    timeout: float = 3.0,
) -> str:
    """Resolve the caller's public IPv4 address through a small HTTPS lookup."""
    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError(f"public IPv4 lookup URL must be https: {url!r}")
    request = urllib.request.Request(url, headers={"User-Agent": "xferry/public-ip"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            body = response.read(128).decode("ascii").strip()
    except (OSError, urllib.error.URLError) as err:
        raise RuntimeError(f"could not resolve public IPv4 address via {url}: {err}") from err

    return validate_public_ipv4(body)


def validate_public_ipv4(value: str) -> str:
    """Return normalized public IPv4 or raise ValueError."""
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as err:
        raise ValueError(f"invalid IPv4 address: {value!r}") from err
    if not ip.is_global:
        raise ValueError(f"IPv4 address is not globally routable: {value}")
    return str(ip)


def sslip_domain_for_ip(ip: str) -> str:
    """Build a dash-form sslip.io hostname for a public IPv4 address."""
    normalized = validate_public_ipv4(ip)
    return f"{normalized.replace('.', '-')}.sslip.io"
