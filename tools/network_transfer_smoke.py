#!/usr/bin/env python3
"""Measure real, authenticated TLS EUF transfers in isolated Linux processes.

This exercises the HTTP protocol, not browser memory or browser recovery stores.
All files and credentials are synthetic and live in a private temporary folder.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import math
import os
import platform
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography import __version__ as crypto_version  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from xferry.config import __version__  # noqa: E402
from xferry.encrypted_transfer import (  # noqa: E402
    EUF_CHUNK_SIZE,
    EncryptedFileMetadata,
    EncryptedTransferManifest,
    b64url_encode,
    compute_resume_mac,
    decrypt_chunk,
    derive_keys,
    encrypt_chunk,
    encrypt_metadata,
)

MIB = 1024 * 1024
SCHEMA_VERSION = 1
SERVER_RSS_LIMIT = 512 * MIB
SERVER_SETTINGS = {"workers": 10, "body_memory_budget_bytes": 128 * MIB}
MAX_ATTEMPTS = 6
REQUEST_TIMEOUT = 30
MAX_RESPONSE_BYTES = EUF_CHUNK_SIZE + 64 * 1024
SCRIPT = Path(__file__).resolve()


@dataclass(frozen=True)
class Workload:
    """One fresh-process measurement; fault cases are not timing baselines."""

    name: str
    sizes: tuple[int, ...]
    recovery: bool = False


def workloads(profile: str) -> tuple[Workload, ...]:
    small = Workload("boundary-2", (16 * MIB, 16 * MIB + 1))
    recovery = Workload("lost-ack-and-restart", (16 * MIB + 1,), recovery=True)
    if profile == "quick":
        return small, recovery
    if profile == "weekly":
        return (
            *(Workload(f"256mib-{count}", (256 * MIB,) * count) for count in (1, 2, 4)),
            Workload("2gib-1", (2048 * MIB,)),
            recovery,
        )
    raise ValueError("unknown workload profile")


def process_memory(pid: int) -> tuple[int, int]:
    """Read actual current RSS and process high-water RSS on the Linux test host."""
    fields: dict[str, int] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith(("VmRSS:", "VmHWM:")):
            name, value, _unit = line.split()
            fields[name.rstrip(":")] = int(value) * 1024
    if not {"VmRSS", "VmHWM"}.issubset(fields):
        raise RuntimeError("Linux process memory counters are unavailable")
    return fields["VmRSS"], fields["VmHWM"]


def latency_summary(samples: list[float]) -> dict[str, int | float | None]:
    """Report nearest-rank percentiles, withholding sparse p95/p99 estimates."""
    ordered = sorted(samples)

    def percentile(fraction: float, minimum: int) -> float | None:
        if len(ordered) < minimum:
            return None
        return round(ordered[max(0, math.ceil(len(ordered) * fraction) - 1)], 3)

    return {
        "count": len(ordered),
        "p50_ms": percentile(0.50, 1),
        "p95_ms": percentile(0.95, 20),
        "p99_ms": percentile(0.99, 100),
    }


def retry_delay(value: str | None, attempt: int) -> float:
    """Honor bounded Retry-After; fail rather than silently shorten a long wait."""
    delay = min(0.25 * (2**attempt), 5.0)
    if value:
        try:
            parsed = float(value)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(value).timestamp() - time.time()
            except (ValueError, TypeError, OverflowError):
                parsed = delay
        if not math.isfinite(parsed):
            raise RuntimeError("invalid Retry-After")
        delay = max(delay, parsed)
    if delay > REQUEST_TIMEOUT:
        raise RuntimeError("Retry-After exceeds the smoke retry budget")
    return max(0.0, delay)


class Measurements:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.latencies: dict[str, list[float]] = {"upload": [], "download": []}
        self.throttles: dict[str, int] = {"429": 0, "503": 0}
        self.network_retries = 0

    def attempt(self, direction: str | None, elapsed: float, status: int) -> None:
        with self._lock:
            if direction:
                self.latencies[direction].append(elapsed * 1000)
            if str(status) in self.throttles:
                self.throttles[str(status)] += 1

    def network_retry(self) -> None:
        with self._lock:
            self.network_retries += 1

    def report(self) -> dict[str, Any]:
        return {
            "chunk_attempt_latency": {
                key: latency_summary(values) for key, values in self.latencies.items()
            },
            "throttle_responses": dict(self.throttles),
            "network_retries": self.network_retries,
        }


class Client:
    def __init__(
        self,
        port: int,
        root: Path,
        measurements: Measurements,
        *,
        timeout: float = REQUEST_TIMEOUT,
        attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self.port = port
        self.timeout = timeout
        self.attempts = attempts
        self.context = ssl.create_default_context(cafile=str(root / "ca.pem"))
        self.context.verify_flags |= ssl.VERIFY_X509_STRICT
        credential = (root / "auth").read_text(encoding="utf-8").strip()
        self.authorization = "Basic " + base64.b64encode(credential.encode()).decode("ascii")
        self.measurements = measurements

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        expected: tuple[int, ...] = (200,),
        direction: str | None = None,
        authenticated: bool = True,
    ) -> tuple[int, bytes]:
        request_headers = {
            "Connection": "close",
            "Content-Length": str(len(body)),
            **(headers or {}),
        }
        if authenticated:
            request_headers["Authorization"] = self.authorization
        for attempt in range(self.attempts):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", self.port, context=self.context, timeout=self.timeout
            )
            started = time.perf_counter()
            delay = 0.0
            try:
                connection.request(method, path, body=body, headers=request_headers)
                response = connection.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise RuntimeError("smoke response exceeded its bounded chunk buffer")
                status = response.status
                self.measurements.attempt(direction, time.perf_counter() - started, status)
                if status in expected:
                    return status, payload
                if status not in (429, 503):
                    raise RuntimeError(f"{method} smoke request returned HTTP {status}")
                delay = retry_delay(response.getheader("Retry-After"), attempt)
            except ssl.SSLCertVerificationError:
                raise
            except (OSError, http.client.HTTPException):
                self.measurements.network_retry()
                delay = retry_delay(None, attempt)
            finally:
                connection.close()
            if attempt + 1 < self.attempts:
                time.sleep(delay)
        raise RuntimeError(f"{method} smoke request exhausted bounded retries")

    def json(
        self, method: str, path: str, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        _status, raw = self.request(
            method,
            path,
            body=json.dumps(payload).encode() if payload is not None else b"",
            headers={"Content-Type": "application/json"} if payload is not None else {},
            **kwargs,
        )
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise RuntimeError("expected an object response")
        return result


def make_credentials(root: Path) -> None:
    """Generate private test-only TLS and Basic Auth fixtures outside public files."""
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "XFerry smoke CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    fixtures = {
        "ca.pem": ca.public_bytes(serialization.Encoding.PEM),
        "cert.pem": certificate.public_bytes(serialization.Encoding.PEM),
        "key.pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "auth": f"smoke:{secrets.token_urlsafe(24)}\n".encode(),
    }
    for name, content in fixtures.items():
        target = root / name
        target.write_bytes(content)
        target.chmod(0o600)


def serve(root: Path, port: int) -> None:
    from xferry import XFerryServer
    from xferry.server_config import (
        AuthConfig,
        LoggingConfig,
        ServerConfig,
        ServerLimits,
        TLSConfig,
    )

    server = XFerryServer(
        ServerConfig(
            host="127.0.0.1",
            port=port,
            root_dir=root / "state",
            files_dir=root / "files",
            encrypted_uploads=True,
            auth=AuthConfig(auth_file=root / "auth"),
            tls=TLSConfig(cert_file=root / "cert.pem", key_file=root / "key.pem"),
            limits=ServerLimits(
                max_workers=SERVER_SETTINGS["workers"],
                body_memory_budget=SERVER_SETTINGS["body_memory_budget_bytes"],
                upload_storage_limit=8 * 1024 * MIB,
                upload_file_limit=32,
            ),
            logging=LoggingConfig(quiet=True),
        )
    )
    signal.signal(signal.SIGTERM, lambda *_args: server.stop())
    signal.signal(signal.SIGINT, lambda *_args: server.stop())
    server.start()


class ServerProcess:
    def __init__(self, root: Path) -> None:
        self.root = root
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.process: subprocess.Popen[bytes] | None = None
        self.baseline = 0
        self.peak = 0
        self.segments: list[dict[str, int]] = []
        self.log = (root / "server.log").open("ab")

    def start(self) -> None:
        self.process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--serve", str(self.root), "--port", str(self.port)],
            stdout=self.log,
            stderr=self.log,
        )
        probe = Client(self.port, self.root, Measurements(), timeout=0.5, attempts=1)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("isolated server exited before readiness")
            try:
                # Readiness retries here stay short; the transfer client has a separate budget.
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    pass
            except OSError:
                time.sleep(0.05)
                continue
            try:
                if probe.json("PING", "/").get("health") == "ready":
                    probe.request("GET", "/", authenticated=False, expected=(401,))
                    self.baseline, self.peak = process_memory(self.process.pid)
                    return
            except ssl.SSLCertVerificationError:
                raise
            except (OSError, http.client.HTTPException, RuntimeError):
                pass
            time.sleep(0.05)
        raise RuntimeError("isolated server readiness timed out")

    def sample(self) -> None:
        if self.process is not None:
            _current, high = process_memory(self.process.pid)
            self.peak = max(self.peak, high)

    def stop(self) -> None:
        if self.process is None:
            return
        process, self.process = self.process, None
        try:
            if process.poll() is None:
                try:
                    _current, high = process_memory(process.pid)
                    self.peak = max(self.peak, high)
                except OSError:
                    # A failed sample must never bypass child teardown.
                    pass
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired as exc:
                    process.kill()
                    process.wait(timeout=5)
                    raise RuntimeError("isolated server failed graceful shutdown") from exc
            if process.returncode != 0:
                raise RuntimeError(f"isolated server exited with {process.returncode}")
        finally:
            self.segments.append(
                {
                    "baseline_rss_bytes": self.baseline,
                    "peak_rss_bytes": self.peak,
                    "peak_rss_delta_bytes": max(0, self.peak - self.baseline),
                }
            )

    def close(self) -> None:
        try:
            self.stop()
        finally:
            self.log.close()


@dataclass(frozen=True)
class Transfer:
    manifest: EncryptedTransferManifest
    content_key: bytes
    resume_key: bytes
    seed: int


def new_transfer(size: int, seed: int) -> Transfer:
    file_id = secrets.token_hex(16)
    salt = secrets.token_bytes(16)
    key, resume_key = derive_keys("synthetic network smoke", salt=salt, file_id=file_id)
    provisional = EncryptedTransferManifest(
        file_id=file_id,
        plaintext_size=size,
        chunk_size=EUF_CHUNK_SIZE,
        chunk_count=(size + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE,
        salt=salt,
        nonce_prefix=secrets.token_bytes(8),
        encrypted_metadata=b"\0" * 16,
    )
    metadata = encrypt_metadata(
        EncryptedFileMetadata(
            name="network-smoke.bin", content_type="application/octet-stream", last_modified_ms=0
        ),
        key=key,
        manifest=provisional,
    )
    return Transfer(replace(provisional, encrypted_metadata=metadata), key, resume_key, seed)


def plaintext_chunk(transfer: Transfer, index: int) -> bytes:
    manifest = transfer.manifest
    length = min(manifest.chunk_size, manifest.plaintext_size - index * manifest.chunk_size)
    return bytes([(index + transfer.seed) % 251]) * length


def create_transfer(client: Client, transfer: Transfer) -> None:
    manifest = transfer.manifest
    payload = {
        "version": manifest.version,
        "plaintext_size": manifest.plaintext_size,
        "chunk_size": manifest.chunk_size,
        "chunk_count": manifest.chunk_count,
        "salt": b64url_encode(manifest.salt),
        "nonce_prefix": b64url_encode(manifest.nonce_prefix),
        "encrypted_metadata": b64url_encode(manifest.encrypted_metadata),
    }
    client.json(
        "PUT",
        f"/_xferry/encrypted-uploads/{manifest.file_id}",
        payload,
        expected=(200, 201),
    )


def upload_chunk(client: Client, transfer: Transfer, index: int) -> dict[str, Any]:
    plaintext = plaintext_chunk(transfer, index)
    ciphertext = encrypt_chunk(
        plaintext, key=transfer.content_key, manifest=transfer.manifest, index=index
    )
    mac = compute_resume_mac(
        plaintext, key=transfer.resume_key, manifest=transfer.manifest, index=index
    )
    _status, payload = client.request(
        "PUT",
        f"/_xferry/encrypted-uploads/{transfer.manifest.file_id}/chunks/{index}",
        body=ciphertext,
        headers={
            "Content-Type": "application/octet-stream",
            "X-XFerry-Chunk-MAC": b64url_encode(mac),
        },
        expected=(200, 201),
        direction="upload",
    )
    result = json.loads(payload)["encrypted_chunk"]
    if result["resume_mac"] != b64url_encode(mac):
        raise RuntimeError("server returned an inconsistent resume MAC")
    return result


def roundtrip(client: Client, transfer: Transfer, *, first_chunk: int = 0) -> dict[str, Any]:
    manifest = transfer.manifest
    started = time.perf_counter()
    # Only two chunks are materialized at once; executor.map's eagerly queued work is indices.
    with ThreadPoolExecutor(max_workers=2) as pool:
        for _result in pool.map(
            lambda index: upload_chunk(client, transfer, index),
            range(first_chunk, manifest.chunk_count),
        ):
            pass
    client.json("POST", f"/_xferry/encrypted-uploads/{manifest.file_id}/complete")
    upload_seconds = time.perf_counter() - started
    source_hash = hashlib.sha256()
    result_hash = hashlib.sha256()
    downloaded = 0
    started = time.perf_counter()
    for index in range(manifest.chunk_count):
        _status, ciphertext = client.request(
            "GET",
            f"/_xferry/encrypted-files/{manifest.file_id}/chunks/{index}",
            direction="download",
        )
        plaintext = decrypt_chunk(
            ciphertext, key=transfer.content_key, manifest=manifest, index=index
        )
        if plaintext is None:
            raise RuntimeError("downloaded chunk failed client authentication")
        source_hash.update(plaintext_chunk(transfer, index))
        result_hash.update(plaintext)
        downloaded += len(plaintext)
        del plaintext, ciphertext
    download_seconds = time.perf_counter() - started
    if downloaded != manifest.plaintext_size or source_hash.digest() != result_hash.digest():
        raise RuntimeError("network transfer checksum or byte count mismatch")
    return {
        "plaintext_bytes": manifest.plaintext_size,
        "roundtrip_bytes": downloaded,
        "source_sha256": source_hash.hexdigest(),
        "roundtrip_sha256": result_hash.hexdigest(),
        "upload_seconds": round(upload_seconds, 6),
        "download_seconds": round(download_seconds, 6),
    }


def run_case(workload: Workload, root: Path) -> dict[str, Any]:
    if shutil.disk_usage(root).free < sum(workload.sizes) + 256 * MIB:
        raise RuntimeError("insufficient temporary disk capacity for this workload")
    make_credentials(root)
    transfers = [new_transfer(size, index) for index, size in enumerate(workload.sizes)]
    metrics = Measurements()
    server = ServerProcess(root)
    results: list[dict[str, Any]] = []
    recovered = False
    try:
        server.start()
        client = Client(server.port, root, metrics)
        for transfer in transfers:
            create_transfer(client, transfer)
        client_baseline, _peak = process_memory(os.getpid())
        started = time.perf_counter()
        if workload.recovery:
            transfer = transfers[0]
            # Deliberately discard a genuine successful acknowledgement, not a claimed TCP fault.
            upload_chunk(client, transfer, 0)
            duplicate = upload_chunk(client, transfer, 0)
            if duplicate["stored"] is not False:
                raise RuntimeError("lost-ack retry was not idempotent")
            server.stop()
            server.start()
            client = Client(server.port, root, metrics)
            partial = client.json("GET", f"/_xferry/encrypted-uploads/{transfer.manifest.file_id}")[
                "encrypted_upload"
            ]
            expected_mac = b64url_encode(
                compute_resume_mac(
                    plaintext_chunk(transfer, 0),
                    key=transfer.resume_key,
                    manifest=transfer.manifest,
                    index=0,
                )
            )
            chunks = partial["received_chunks"]
            if (
                partial["status"] != "partial"
                or len(chunks) != 1
                or chunks[0]["index"] != 0
                or chunks[0]["resume_mac"] != expected_mac
            ):
                raise RuntimeError("restart lost acknowledged chunk or resume MAC")
            results.append(roundtrip(client, transfer, first_chunk=1))
            recovered = True
        else:
            with ThreadPoolExecutor(max_workers=len(transfers)) as pool:
                results.extend(pool.map(lambda item: roundtrip(client, item), transfers))
        elapsed = time.perf_counter() - started
        server.sample()
        _current, client_peak = process_memory(os.getpid())
        server.stop()
    finally:
        server.close()
    delta = max(item["peak_rss_delta_bytes"] for item in server.segments)
    if delta > SERVER_RSS_LIMIT:
        raise RuntimeError(f"server RSS delta {delta} exceeds {SERVER_RSS_LIMIT}")
    return {
        "name": workload.name,
        "sizes_bytes": list(workload.sizes),
        "concurrency": len(transfers),
        "chunks_in_flight_per_file": 2,
        "timing_eligible": not workload.recovery,
        "elapsed_seconds": round(elapsed, 6),
        "roundtrip_mib_per_second": round(2 * sum(workload.sizes) / MIB / elapsed, 6),
        "files": results,
        "server_memory": server.segments,
        "server_rss_limit_bytes": SERVER_RSS_LIMIT,
        "client_peak_rss_bytes": client_peak,
        "client_peak_rss_delta_bytes": max(0, client_peak - client_baseline),
        "lost_ack_simulation_and_restart_verified": recovered,
        **metrics.report(),
    }


def environment_identity() -> dict[str, Any]:
    cpu_model = "unknown"
    for line in Path("/proc/cpuinfo").read_text(encoding="ascii").splitlines():
        if line.startswith("model name"):
            cpu_model = line.partition(":")[2].strip()
            break
    return {
        "system": platform.system(),
        "architecture": platform.machine(),
        "os_release": platform.freedesktop_os_release().get("PRETTY_NAME", "unknown"),
        "runner_class": os.environ.get("RUNNER_ENVIRONMENT", "local"),
        "runner_image": os.environ.get("ImageOS", "local"),
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "cryptography": crypto_version,
        "openssl": ssl.OPENSSL_VERSION,
    }


def run_profile(profile: str) -> dict[str, Any]:
    results = []
    for workload in workloads(profile):
        with tempfile.TemporaryDirectory(prefix="xferry-network-smoke-") as temporary:
            root = Path(temporary)
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--case",
                    workload.name,
                    "--profile",
                    profile,
                    "--case-root",
                    str(root),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=1800)
            finally:
                # Also clean descendants if a failed client exited before closing its server.
                terminate_case(process)
            if process.returncode:
                # Child errors deliberately do not include request headers, keys or fixture data.
                raise RuntimeError(stderr.strip()[-2000:] or "network case failed")
            results.append(json.loads(stdout))
    return {
        "schema_version": SCHEMA_VERSION,
        "xferry_version": __version__,
        "profile": profile,
        "environment": environment_identity(),
        "server_settings": SERVER_SETTINGS,
        "source_sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "cases": results,
    }


def terminate_case(process: subprocess.Popen[str]) -> None:
    """Own the case process group, including its server, through failure or cancellation."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("quick", "weekly"), default="quick")
    parser.add_argument("--json", action="store_true", help="Print the measurement receipt.")
    parser.add_argument("--output", type=Path, help="Save a measurement receipt.")
    parser.add_argument("--allow-large", action="store_true", help="Allow the 2 GiB profile.")
    parser.add_argument("--serve", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--case", help=argparse.SUPPRESS)
    parser.add_argument("--case-root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("network resource smoke requires Linux /proc memory counters")
    if args.profile == "weekly" and not (args.allow_large or args.case):
        parser.error("weekly profile writes 2 GiB and requires --allow-large")

    def interrupted(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt("network smoke interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.serve:
            if not args.port:
                parser.error("--serve requires --port")
            serve(args.serve, args.port)
            return 0
        if args.case:
            selected = next(item for item in workloads(args.profile) if item.name == args.case)
            if args.case_root is None:
                parser.error("--case requires --case-root")
            result = run_case(selected, args.case_root)
            print(json.dumps(result, sort_keys=True))
            return 0
        result = run_profile(args.profile)
        output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
        if args.json or not args.output:
            print(output, end="")
        return 0
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"Network smoke failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
