#!/usr/bin/env python3
"""Round-trip a large EUF v1 file while recording process peak memory."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xferry import XFerryServer  # noqa: E402
from xferry.encrypted_transfer import (  # noqa: E402
    EUF_CHUNK_SIZE,
    EncryptedFileMetadata,
    EncryptedTransferManifest,
    b64url_encode,
    compute_resume_mac,
    derive_keys,
    encrypt_chunk,
    encrypt_metadata,
)
from xferry.http import HTTPRequest, HTTPResponse  # noqa: E402
from xferry.server_config import LoggingConfig, ServerConfig, ServerLimits  # noqa: E402

MIB = 1024 * 1024
MAX_SIZE_MIB = 2048
FILE_ID = "00112233445566778899aabbccddeeff"
PASSWORD = "resource smoke password"


def _peak_rss_bytes() -> int:
    """Return the best available process high-water RSS in bytes."""
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii")
    except OSError:
        status = ""
    for line in status.splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) * 1024

    usage = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return usage if sys.platform == "darwin" else usage * 1024


def _request(
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> HTTPRequest:
    lines = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1:8080"]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    raw = "\r\n".join(lines).encode("ascii") + b"\r\n\r\n" + body
    request = HTTPRequest(raw)
    request.attach_direct_peer(("127.0.0.1", 43210))
    return request


def _json_request(method: str, path: str, payload: dict[str, object]) -> HTTPRequest:
    return _request(
        method,
        path,
        body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _require_status(response: HTTPResponse, expected: int, operation: str) -> None:
    if response.status_code == expected:
        return
    body = response.body.decode("utf-8", errors="replace") if response.body else ""
    raise RuntimeError(f"{operation} returned HTTP {response.status_code}: {body[:1000]}")


def _plaintext_chunk(index: int, length: int) -> bytes:
    return bytes([index % 251]) * length


def _build_manifest(size_bytes: int, content_key: bytes) -> EncryptedTransferManifest:
    chunk_count = (size_bytes + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE
    placeholder = EncryptedTransferManifest(
        file_id=FILE_ID,
        plaintext_size=size_bytes,
        chunk_size=EUF_CHUNK_SIZE,
        chunk_count=chunk_count,
        salt=bytes(range(16)),
        nonce_prefix=bytes(range(8)),
        encrypted_metadata=b"\0" * 16,
    )
    encrypted_metadata = encrypt_metadata(
        EncryptedFileMetadata(
            name="resource-smoke.bin",
            content_type="application/octet-stream",
            last_modified_ms=0,
        ),
        key=content_key,
        manifest=placeholder,
    )
    return EncryptedTransferManifest(
        file_id=placeholder.file_id,
        plaintext_size=placeholder.plaintext_size,
        chunk_size=placeholder.chunk_size,
        chunk_count=placeholder.chunk_count,
        salt=placeholder.salt,
        nonce_prefix=placeholder.nonce_prefix,
        encrypted_metadata=encrypted_metadata,
    )


def run_resource_smoke(size_mib: int, root_dir: Path) -> dict[str, Any]:
    """Upload and decrypt one deterministic large file without whole-file buffers."""
    if not 1 <= size_mib <= MAX_SIZE_MIB:
        raise ValueError(f"size_mib must be between 1 and {MAX_SIZE_MIB}")

    started_at = time.perf_counter()
    baseline_peak_rss = _peak_rss_bytes()
    size_bytes = size_mib * MIB
    content_key, resume_key = derive_keys(
        PASSWORD,
        salt=bytes(range(16)),
        file_id=FILE_ID,
    )
    manifest = _build_manifest(size_bytes, content_key)
    server = XFerryServer(
        ServerConfig(
            host="127.0.0.1",
            port=8080,
            root_dir=root_dir,
            encrypted_uploads=True,
            limits=ServerLimits(encrypted_upload_max_size=size_bytes),
            logging=LoggingConfig(quiet=True),
        )
    )

    create_payload = {
        "version": manifest.version,
        "plaintext_size": manifest.plaintext_size,
        "chunk_size": manifest.chunk_size,
        "chunk_count": manifest.chunk_count,
        "salt": b64url_encode(manifest.salt),
        "nonce_prefix": b64url_encode(manifest.nonce_prefix),
        "encrypted_metadata": b64url_encode(manifest.encrypted_metadata),
    }
    create_response = server._dispatch_handler(
        _json_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{manifest.file_id}",
            create_payload,
        )
    )
    _require_status(create_response, 201, "create")

    source_digest = hashlib.sha256()
    max_plaintext_chunk = 0
    for index in range(manifest.chunk_count):
        offset = index * manifest.chunk_size
        plaintext_length = min(manifest.chunk_size, manifest.plaintext_size - offset)
        plaintext = _plaintext_chunk(index, plaintext_length)
        max_plaintext_chunk = max(max_plaintext_chunk, len(plaintext))
        source_digest.update(plaintext)
        ciphertext = encrypt_chunk(
            plaintext,
            key=content_key,
            manifest=manifest,
            index=index,
        )
        resume_mac = compute_resume_mac(
            plaintext,
            key=resume_key,
            manifest=manifest,
            index=index,
        )
        request = _request(
            "PUT",
            f"/_xferry/encrypted-uploads/{manifest.file_id}/chunks/{index}",
            body=ciphertext,
            headers={
                "Content-Type": "application/octet-stream",
                "X-XFerry-Chunk-MAC": b64url_encode(resume_mac),
            },
        )
        chunk_response = server._dispatch_handler(request)
        _require_status(chunk_response, 201, f"chunk {index}")
        del request, chunk_response, resume_mac, ciphertext, plaintext

    complete_response = server._dispatch_handler(
        _request("POST", f"/_xferry/encrypted-uploads/{manifest.file_id}/complete")
    )
    _require_status(complete_response, 200, "complete")

    decrypt_response = server._dispatch_handler(
        _json_request(
            "POST",
            f"/_xferry/encrypted-files/{manifest.file_id}/decrypt",
            {"content_key": b64url_encode(content_key)},
        )
    )
    _require_status(decrypt_response, 200, "decrypt")
    if decrypt_response.stream_iterator is None:
        raise RuntimeError("decrypt response did not expose a streaming iterator")
    if decrypt_response.headers.get("Content-Length") != str(size_bytes):
        raise RuntimeError("decrypt response content length does not match plaintext")

    roundtrip_digest = hashlib.sha256()
    roundtrip_bytes = 0
    for plaintext in decrypt_response.stream_iterator:
        roundtrip_digest.update(plaintext)
        roundtrip_bytes += len(plaintext)
        del plaintext

    source_sha256 = source_digest.hexdigest()
    roundtrip_sha256 = roundtrip_digest.hexdigest()
    if source_sha256 != roundtrip_sha256 or roundtrip_bytes != size_bytes:
        raise RuntimeError("decrypted stream does not match the deterministic source")

    plaintext_artifact_created = any(
        candidate.exists()
        for candidate in (
            root_dir / "resource-smoke.bin",
            server.upload_dir / "resource-smoke.bin",
        )
    )
    peak_rss = _peak_rss_bytes()
    return {
        "schema_version": 1,
        "plaintext_bytes": size_bytes,
        "ciphertext_bytes": manifest.ciphertext_size,
        "chunk_count": manifest.chunk_count,
        "source_sha256": source_sha256,
        "roundtrip_sha256": roundtrip_sha256,
        "roundtrip_bytes": roundtrip_bytes,
        "max_plaintext_chunk_bytes": max_plaintext_chunk,
        "plaintext_artifact_created": plaintext_artifact_created,
        "baseline_peak_rss_bytes": baseline_peak_rss,
        "peak_rss_bytes": peak_rss,
        "peak_rss_delta_bytes": max(0, peak_rss - baseline_peak_rss),
        "elapsed_seconds": round(time.perf_counter() - started_at, 6),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Round-trip an EUF v1 encrypted file and report peak RSS",
    )
    parser.add_argument("--size-mib", type=int, default=64)
    parser.add_argument(
        "--allow-2gib",
        action="store_true",
        help="acknowledge the disk/time cost when --size-mib=2048",
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON result object")
    args = parser.parse_args(argv)
    if args.size_mib == MAX_SIZE_MIB and not args.allow_2gib:
        parser.error("--size-mib=2048 requires --allow-2gib")

    with tempfile.TemporaryDirectory(prefix="xferry-encrypted-resource-smoke-") as temp_dir:
        result = run_resource_smoke(args.size_mib, Path(temp_dir))

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("Encrypted transfer resource smoke passed")
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
