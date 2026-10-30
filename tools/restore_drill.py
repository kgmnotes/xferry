#!/usr/bin/env python3
"""Exercise a cold restore using only temporary synthetic data and real HTTP."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
from contextlib import redirect_stdout
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xferry import XFerryServer  # noqa: E402
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
from xferry.management.storage_rebind import rebind_storage  # noqa: E402
from xferry.server_config import AuthConfig, LoggingConfig, ServerConfig  # noqa: E402

_CREDENTIAL = "restore-drill:temporary-test-password"


class _Server:
    def __init__(self, base: Path) -> None:
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            self.port = candidate.getsockname()[1]
        self.server = XFerryServer(
            ServerConfig(
                host="127.0.0.1",
                port=self.port,
                root_dir=base / "state",
                files_dir=base / "files",
                encrypted_uploads=True,
                auth=AuthConfig(auth_file=base / "config" / "auth"),
                logging=LoggingConfig(quiet=True),
            )
        )
        self.errors: list[BaseException] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            self.server.start()
        except BaseException as exc:
            self.errors.append(exc)

    def __enter__(self) -> _Server:
        self.thread.start()
        try:
            for _ in range(100):
                if self.errors:
                    raise RuntimeError("Temporary restore server failed to start") from self.errors[
                        0
                    ]
                try:
                    if self.json("PING", "/")["health"] == "ready":
                        return self
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.05)
            raise RuntimeError("Temporary restore server did not become ready")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self.server.stop()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("Restore snapshot refused: server workers have not stopped")
        if self.errors:
            raise RuntimeError("Temporary restore server failed") from self.errors[0]

    def __exit__(self, *_args: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        headers: dict[str, str] | None = None,
        expected: int = 200,
    ) -> bytes:
        request_headers = {
            "Authorization": "Basic " + base64.b64encode(_CREDENTIAL.encode()).decode(),
            "Connection": "close",
            **(headers or {}),
        }
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, path, body, request_headers)
            response = connection.getresponse()
            payload = response.read()
            if response.status != expected:
                raise RuntimeError(
                    f"Restore drill {method} returned HTTP {response.status}; expected {expected}"
                )
            return payload
        finally:
            connection.close()

    def json(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        expected: int = 200,
    ) -> dict[str, Any]:
        raw = self.request(
            method,
            path,
            b"" if payload is None else json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            expected=expected,
        )
        return dict(json.loads(raw))


@dataclass(frozen=True)
class _EncryptedFixture:
    manifest: EncryptedTransferManifest
    content_key: bytes
    chunks: tuple[bytes, ...]
    macs: tuple[bytes, ...]
    plaintext_sha256: str


def _fixture(plaintext: bytes) -> _EncryptedFixture:
    file_id = secrets.token_hex(16)
    salt = secrets.token_bytes(16)
    content_key, resume_key = derive_keys("synthetic restore fixture", salt=salt, file_id=file_id)
    manifest = EncryptedTransferManifest(
        file_id=file_id,
        plaintext_size=len(plaintext),
        chunk_size=EUF_CHUNK_SIZE,
        chunk_count=(len(plaintext) + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE,
        salt=salt,
        nonce_prefix=secrets.token_bytes(8),
        encrypted_metadata=b"\0" * 16,
    )
    metadata = EncryptedFileMetadata("restore-fixture.bin", "application/octet-stream", 0)
    manifest = replace(
        manifest, encrypted_metadata=encrypt_metadata(metadata, key=content_key, manifest=manifest)
    )
    chunks, macs = [], []
    for index in range(manifest.chunk_count):
        block = plaintext[index * EUF_CHUNK_SIZE : (index + 1) * EUF_CHUNK_SIZE]
        chunks.append(encrypt_chunk(block, key=content_key, manifest=manifest, index=index))
        macs.append(compute_resume_mac(block, key=resume_key, manifest=manifest, index=index))
    return _EncryptedFixture(
        manifest, content_key, tuple(chunks), tuple(macs), hashlib.sha256(plaintext).hexdigest()
    )


def _create(live: _Server, fixture: _EncryptedFixture) -> None:
    manifest = fixture.manifest
    live.json(
        "PUT",
        f"/_xferry/encrypted-uploads/{manifest.file_id}",
        {
            "version": manifest.version,
            "plaintext_size": manifest.plaintext_size,
            "chunk_size": manifest.chunk_size,
            "chunk_count": manifest.chunk_count,
            "salt": b64url_encode(manifest.salt),
            "nonce_prefix": b64url_encode(manifest.nonce_prefix),
            "encrypted_metadata": b64url_encode(manifest.encrypted_metadata),
        },
        expected=201,
    )


def _chunk(
    live: _Server, fixture: _EncryptedFixture, index: int, *, expected: int = 201
) -> dict[str, Any]:
    raw = live.request(
        "PUT",
        f"/_xferry/encrypted-uploads/{fixture.manifest.file_id}/chunks/{index}",
        fixture.chunks[index],
        headers={
            "Content-Type": "application/octet-stream",
            "X-XFerry-Chunk-MAC": b64url_encode(fixture.macs[index]),
        },
        expected=expected,
    )
    return dict(json.loads(raw))


def _complete(live: _Server, fixture: _EncryptedFixture) -> None:
    live.json("POST", f"/_xferry/encrypted-uploads/{fixture.manifest.file_id}/complete")


def _verify_encrypted(live: _Server, fixture: _EncryptedFixture) -> None:
    digest = hashlib.sha256()
    for index in range(fixture.manifest.chunk_count):
        ciphertext = live.request(
            "GET", f"/_xferry/encrypted-files/{fixture.manifest.file_id}/chunks/{index}"
        )
        digest.update(
            decrypt_chunk(
                ciphertext, key=fixture.content_key, manifest=fixture.manifest, index=index
            )
        )
    if digest.hexdigest() != fixture.plaintext_sha256:
        raise RuntimeError("Restored encrypted bytes did not match the original plaintext")


def _inventory(base: Path) -> dict[str, str]:
    return {
        str(path.relative_to(base)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in base.rglob("*")
        if path.is_file()
    }


def run_restore_drill() -> dict[str, object]:
    """Create, back up, restore and discard synthetic data; accept no target path."""
    with tempfile.TemporaryDirectory(prefix="xferry-restore-drill-") as temporary:
        root = Path(temporary)
        source, backup, restored = (root / name for name in ("source", "backup", "restored"))
        (source / "config").mkdir(parents=True, mode=0o700)
        (source / "state").mkdir(mode=0o700)
        (source / "state" / ".xferry").mkdir(mode=0o700)
        (source / "files").mkdir(mode=0o700)
        auth = source / "config" / "auth"
        auth.write_text(_CREDENTIAL + "\n")
        auth.chmod(0o600)
        version_file = source / "xferry-version.txt"
        version_file.write_text(f"xferry {__version__}\n")
        version_file.chmod(0o600)
        ordinary = b"ordinary synthetic restore data\n"
        note_plaintext = b"synthetic note, key retained only by the test client"
        note_key, note_nonce = secrets.token_bytes(32), secrets.token_bytes(12)
        note_blob = note_nonce + AESGCM(note_key).encrypt(note_nonce, note_plaintext, None)
        complete = _fixture(b"completed synthetic encrypted file")
        partial = _fixture(b"p" * EUF_CHUNK_SIZE + b"short final chunk")
        with _Server(source) as live:
            live.request("PUT", "/uploads/ordinary.txt", ordinary, expected=201)
            note = live.json(
                "NOTE",
                "/notes?action=save",
                {
                    "title": "Restore drill",
                    "data": base64.b64encode(note_blob).decode(),
                },
                expected=201,
            )
            note_id = note["note"]["id"]
            for fixture in (complete, partial):
                _create(live, fixture)
                _chunk(live, fixture, 0)
            _complete(live, complete)
        # The context manager has joined the server thread and all workers.
        shutil.copytree(source, backup)
        before_backup = _inventory(backup)
        shutil.copytree(backup, restored)
        version = restored / "xferry-version.txt"
        validation = rebind_storage(restored / "state", restored / "files", version)
        if validation["status"] != "rebind_required":
            raise RuntimeError("Restore drill did not exercise a changed storage identity")
        applied = rebind_storage(restored / "state", restored / "files", version, apply=True)
        if applied["status"] != "applied":
            raise RuntimeError("Restore drill did not apply the explicit binding change")
        with _Server(restored) as live:
            if live.request("GET", "/uploads/ordinary.txt") != ordinary:
                raise RuntimeError("Ordinary restored file differs")
            saved_note = live.json("NOTE", f"/notes/{note_id}?action=load")
            restored_note_blob = base64.b64decode(saved_note["data"])
            if restored_note_blob != note_blob or saved_note["note"] != note["note"]:
                raise RuntimeError("Restored note ciphertext or metadata differs")
            if (
                AESGCM(note_key).decrypt(restored_note_blob[:12], restored_note_blob[12:], None)
                != note_plaintext
            ):
                raise RuntimeError("Restored note failed client decryption")
            _verify_encrypted(live, complete)
            partial_state = live.json(
                "GET", f"/_xferry/encrypted-uploads/{partial.manifest.file_id}"
            )["encrypted_upload"]
            if partial_state["received_chunks"] != [
                {"index": 0, "resume_mac": b64url_encode(partial.macs[0])}
            ]:
                raise RuntimeError("Restored partial lost its acknowledged chunk or resume MAC")
            duplicate = _chunk(live, partial, 0, expected=200)
            if duplicate["encrypted_chunk"]["stored"] is not False:
                raise RuntimeError(
                    "Restored partial did not accept the identical acknowledged chunk"
                )
            _chunk(live, partial, 1)
            _complete(live, partial)
            _verify_encrypted(live, partial)
            live.request("PUT", "/uploads/after-restore.txt", b"new data", expected=201)
            if live.request("GET", "/uploads/after-restore.txt") != b"new data":
                raise RuntimeError("New upload failed after restore")
            live.request("DELETE", "/uploads/after-restore.txt")
        if _inventory(backup) != before_backup:
            raise RuntimeError("Restore changed the source backup")
        return {
            "schema_version": 1,
            "version": __version__,
            "status": "passed",
            "transport": "authenticated loopback HTTP",
            "ordinary_sha256": hashlib.sha256(ordinary).hexdigest(),
            "completed_sha256": complete.plaintext_sha256,
            "resumed_sha256": partial.plaintext_sha256,
            "note_ciphertext_sha256": hashlib.sha256(note_blob).hexdigest(),
            "verified_records": 3,
            "backup_unchanged": True,
            "new_file_lifecycle": True,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="Print a redacted verification receipt."
    )
    args = parser.parse_args(argv)
    # Runtime lifecycle messages belong to diagnostics, not the JSON receipt.
    with redirect_stdout(sys.stderr):
        result = run_restore_drill()
    print(json.dumps(result, sort_keys=True) if args.json else "Synthetic cold restore passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
