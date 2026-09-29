"""HTTP contract tests for the reserved encrypted-transfer namespace."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import quote

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.encrypted_transfer import (
    EUF_CHUNK_SIZE,
    EncryptedFileMetadata,
    EncryptedTransferManifest,
    b64url_encode,
    encrypt_chunk,
    encrypt_metadata,
)

FILE_ID = "00112233445566778899aabbccddeeff"
SECOND_FILE_ID = "ffeeddccbbaa99887766554433221100"


def _manifest(
    *,
    file_id: str = FILE_ID,
    plaintext_size: int = 5,
    encrypted_metadata: bytes = b"m" * 16,
) -> EncryptedTransferManifest:
    return EncryptedTransferManifest(
        file_id=file_id,
        plaintext_size=plaintext_size,
        chunk_size=EUF_CHUNK_SIZE,
        chunk_count=(plaintext_size + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE,
        salt=bytes(range(16)),
        nonce_prefix=bytes(range(8)),
        encrypted_metadata=encrypted_metadata,
    )


def _manifest_payload(manifest: EncryptedTransferManifest) -> dict[str, object]:
    return {
        "version": manifest.version,
        "plaintext_size": manifest.plaintext_size,
        "chunk_size": manifest.chunk_size,
        "chunk_count": manifest.chunk_count,
        "salt": b64url_encode(manifest.salt),
        "nonce_prefix": b64url_encode(manifest.nonce_prefix),
        "encrypted_metadata": b64url_encode(manifest.encrypted_metadata),
    }


def _json_request(method: str, path: str, payload: object):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return make_request(
        method,
        path,
        headers={"Content-Type": "application/json"},
        body=body,
    )


def _create(server, manifest: EncryptedTransferManifest):
    return server._dispatch_handler(
        _json_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{manifest.file_id}",
            _manifest_payload(manifest),
        )
    )


def _chunk_ciphertext(manifest: EncryptedTransferManifest, fill: bytes = b"c") -> bytes:
    return fill * (manifest.plaintext_size + 16)


def _put_chunk(
    server,
    manifest: EncryptedTransferManifest,
    ciphertext: bytes,
    *,
    resume_mac: bytes = b"r" * 32,
):
    return server._dispatch_handler(
        make_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{manifest.file_id}/chunks/0",
            headers={
                "Content-Type": "application/octet-stream",
                "X-XFerry-Chunk-MAC": b64url_encode(resume_mac),
            },
            body=ciphertext,
        )
    )


def _complete(server, file_id: str = FILE_ID):
    return server._dispatch_handler(
        make_request("POST", f"/_xferry/encrypted-uploads/{file_id}/complete")
    )


def _error(response) -> dict[str, object]:
    return json.loads(response.body)["error"]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/_xferry/encrypted-uploads"),
        ("PUT", f"/_xferry/encrypted-uploads/{FILE_ID}"),
        ("GET", f"/_xferry/encrypted-uploads/{FILE_ID}"),
        ("DELETE", f"/_xferry/encrypted-uploads/{FILE_ID}"),
        ("PUT", f"/_xferry/encrypted-uploads/{FILE_ID}/chunks/0"),
        ("POST", f"/_xferry/encrypted-uploads/{FILE_ID}/complete"),
        ("GET", "/_xferry/encrypted-files"),
        ("GET", f"/_xferry/encrypted-files/{FILE_ID}"),
        ("DELETE", f"/_xferry/encrypted-files/{FILE_ID}"),
        ("GET", f"/_xferry/encrypted-files/{FILE_ID}/data"),
        ("POST", f"/_xferry/encrypted-files/{FILE_ID}/decrypt"),
    ],
)
def test_disabled_reserved_routes_return_the_ordinary_404_envelope(
    tmp_path: Path,
    method: str,
    path: str,
) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True)

    response = server._dispatch_handler(make_request(method, path, body=b"x"))

    assert response.status_code == 404
    assert _error(response)["code"] == "resource_not_found"
    assert server.encrypted_storage is None


def test_create_get_and_list_partial_uploads_have_a_stable_wire_shape(tmp_path: Path) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    manifest = _manifest()

    created = _create(server, manifest)
    repeated = _create(server, manifest)
    item = server._dispatch_handler(make_request("GET", f"/_xferry/encrypted-uploads/{FILE_ID}"))
    listing = server._dispatch_handler(make_request("GET", "/_xferry/encrypted-uploads"))

    assert created.status_code == 201
    assert repeated.status_code == 200
    created_payload = json.loads(created.body)["encrypted_upload"]
    assert created_payload == json.loads(repeated.body)["encrypted_upload"]
    assert created_payload == json.loads(item.body)["encrypted_upload"]
    assert json.loads(listing.body) == {"encrypted_uploads": [created_payload]}
    assert created_payload == {
        "id": FILE_ID,
        "version": 1,
        "plaintext_size": 5,
        "ciphertext_size": 21,
        "chunk_size": EUF_CHUNK_SIZE,
        "chunk_count": 1,
        "salt": b64url_encode(manifest.salt),
        "nonce_prefix": b64url_encode(manifest.nonce_prefix),
        "encrypted_metadata": b64url_encode(manifest.encrypted_metadata),
        "status": "partial",
        "received_chunks": [],
        "created_at": created_payload["created_at"],
        "updated_at": created_payload["updated_at"],
    }
    assert created.headers["Cache-Control"] == "no-store"


def test_create_conflict_and_strict_json_errors_are_stable(tmp_path: Path) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    manifest = _manifest()
    assert _create(server, manifest).status_code == 201

    conflict = _create(server, _manifest(encrypted_metadata=b"x" * 16))
    wrong_type = server._dispatch_handler(
        make_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{SECOND_FILE_ID}",
            headers={"Content-Type": "text/plain"},
            body=b"{}",
        )
    )
    malformed = server._dispatch_handler(
        make_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{SECOND_FILE_ID}",
            headers={"Content-Type": "application/json"},
            body=b"{",
        )
    )
    duplicate = server._dispatch_handler(
        make_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{SECOND_FILE_ID}",
            headers={"Content-Type": "application/json"},
            body=b'{"version":1,"version":1}',
        )
    )
    unknown_payload = _manifest_payload(_manifest(file_id=SECOND_FILE_ID))
    unknown_payload["name"] = "leak.txt"
    unknown = server._dispatch_handler(
        _json_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{SECOND_FILE_ID}",
            unknown_payload,
        )
    )

    assert (conflict.status_code, _error(conflict)["code"]) == (
        409,
        "encrypted_file_conflict",
    )
    assert (wrong_type.status_code, _error(wrong_type)["code"]) == (
        415,
        "unsupported_media_type",
    )
    assert (malformed.status_code, _error(malformed)["code"]) == (400, "malformed_json")
    assert (duplicate.status_code, _error(duplicate)["code"]) == (400, "invalid_field")
    assert _error(duplicate)["field"] == "version"
    assert (unknown.status_code, _error(unknown)["code"]) == (400, "invalid_field")
    assert _error(unknown)["field"] == "name"


def test_chunk_upload_is_idempotent_and_rejects_conflicts_or_bad_headers(
    tmp_path: Path,
) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    manifest = _manifest()
    _create(server, manifest)
    ciphertext = _chunk_ciphertext(manifest)

    created = _put_chunk(server, manifest, ciphertext)
    repeated = _put_chunk(server, manifest, ciphertext)
    conflict = _put_chunk(server, manifest, b"d" * len(ciphertext))
    missing_mac = server._dispatch_handler(
        make_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{FILE_ID}/chunks/0",
            headers={"Content-Type": "application/octet-stream"},
            body=ciphertext,
        )
    )
    bad_type = server._dispatch_handler(
        make_request(
            "PUT",
            f"/_xferry/encrypted-uploads/{FILE_ID}/chunks/0",
            headers={
                "Content-Type": "application/json",
                "X-XFerry-Chunk-MAC": b64url_encode(b"r" * 32),
            },
            body=ciphertext,
        )
    )

    assert created.status_code == 201
    assert json.loads(created.body)["encrypted_chunk"] == {
        "id": FILE_ID,
        "index": 0,
        "stored": True,
        "resume_mac": b64url_encode(b"r" * 32),
    }
    assert repeated.status_code == 200
    assert json.loads(repeated.body)["encrypted_chunk"]["stored"] is False
    assert (conflict.status_code, _error(conflict)["code"]) == (
        409,
        "encrypted_chunk_conflict",
    )
    assert (missing_mac.status_code, _error(missing_mac)["code"]) == (400, "missing_field")
    assert _error(missing_mac)["field"] == "X-XFerry-Chunk-MAC"
    assert (bad_type.status_code, _error(bad_type)["code"]) == (
        415,
        "unsupported_media_type",
    )
    upload_item = server._dispatch_handler(
        make_request("GET", f"/_xferry/encrypted-uploads/{FILE_ID}")
    )
    assert json.loads(upload_item.body)["encrypted_upload"]["received_chunks"] == [
        {
            "index": 0,
            "resume_mac": b64url_encode(b"r" * 32),
        }
    ]


def test_complete_list_download_and_final_delete(tmp_path: Path) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    manifest = _manifest()
    _create(server, manifest)

    incomplete = _complete(server)
    assert (incomplete.status_code, _error(incomplete)["code"]) == (
        409,
        "encrypted_file_incomplete",
    )

    ciphertext = _chunk_ciphertext(manifest)
    _put_chunk(server, manifest, ciphertext)
    completed = _complete(server)
    repeated = _complete(server)
    upload_item = server._dispatch_handler(
        make_request("GET", f"/_xferry/encrypted-uploads/{FILE_ID}")
    )
    file_item = server._dispatch_handler(make_request("GET", f"/_xferry/encrypted-files/{FILE_ID}"))
    listing = server._dispatch_handler(make_request("GET", "/_xferry/encrypted-files"))
    data = server._dispatch_handler(make_request("GET", f"/_xferry/encrypted-files/{FILE_ID}/data"))

    assert completed.status_code == 200
    assert json.loads(completed.body)["encrypted_file"]["completed"] is True
    assert json.loads(repeated.body)["encrypted_file"]["completed"] is False
    assert upload_item.status_code == 404
    file_payload = json.loads(file_item.body)["encrypted_file"]
    assert file_payload["status"] == "complete"
    assert json.loads(listing.body) == {"encrypted_files": [file_payload]}
    assert data.status_code == 200
    assert data.stream_path is not None
    assert data.stream_path.read_bytes() == ciphertext
    assert data.headers["Content-Type"] == "application/octet-stream"
    assert data.headers["Content-Disposition"] == f'attachment; filename="{FILE_ID}.xfr"'

    deleted = server._dispatch_handler(
        make_request("DELETE", f"/_xferry/encrypted-files/{FILE_ID}")
    )
    missing = server._dispatch_handler(make_request("GET", f"/_xferry/encrypted-files/{FILE_ID}"))
    assert deleted.status_code == 200
    assert json.loads(deleted.body) == {"deleted_encrypted_file": {"id": FILE_ID}}
    assert missing.status_code == 404


def test_partial_delete_and_route_method_errors_are_stable(tmp_path: Path) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    _create(server, _manifest())

    wrong_method = server._dispatch_handler(
        make_request("POST", f"/_xferry/encrypted-uploads/{FILE_ID}")
    )
    deleted = server._dispatch_handler(
        make_request("DELETE", f"/_xferry/encrypted-uploads/{FILE_ID}")
    )
    missing = server._dispatch_handler(make_request("GET", f"/_xferry/encrypted-uploads/{FILE_ID}"))
    malformed_path = server._dispatch_handler(
        make_request("GET", "/_xferry/encrypted-files/not-an-id")
    )

    assert wrong_method.status_code == 405
    assert _error(wrong_method)["code"] == "method_not_allowed"
    assert wrong_method.headers["Allow"] == "GET, PUT, DELETE"
    assert json.loads(deleted.body) == {"deleted_encrypted_upload": {"id": FILE_ID}}
    assert missing.status_code == 404
    assert malformed_path.status_code == 404


def _prepare_encrypted_file(server) -> tuple[EncryptedTransferManifest, bytes, bytes, bytes]:
    content_key = b"k" * 32
    placeholder = _manifest(plaintext_size=20)
    metadata = EncryptedFileMetadata(
        name="Отчёт final.txt",
        content_type="text/plain",
        last_modified_ms=1_720_000_000_123,
    )
    encrypted_metadata = encrypt_metadata(metadata, key=content_key, manifest=placeholder)
    manifest = _manifest(plaintext_size=20, encrypted_metadata=encrypted_metadata)
    plaintext = b"0123456789abcdefghij"
    ciphertext = encrypt_chunk(plaintext, key=content_key, manifest=manifest, index=0)
    assert _create(server, manifest).status_code == 201
    assert _put_chunk(server, manifest, ciphertext).status_code == 201
    assert _complete(server).status_code == 200
    return manifest, content_key, plaintext, ciphertext


def test_loopback_server_decrypt_validates_metadata_then_streams_plaintext(
    tmp_path: Path,
) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    _manifest_value, content_key, plaintext, _ciphertext = _prepare_encrypted_file(server)
    request = _json_request(
        "POST",
        f"/_xferry/encrypted-files/{FILE_ID}/decrypt",
        {"content_key": b64url_encode(content_key)},
    )
    request.attach_direct_peer(("127.0.0.1", 43210))

    response = server._dispatch_handler(request)

    assert response.status_code == 200
    assert response.stream_iterator is not None
    assert b"".join(response.stream_iterator) == plaintext
    assert response.headers["Content-Length"] == str(len(plaintext))
    assert response.headers["Content-Type"] == "text/plain"
    encoded_name = quote("Отчёт final.txt", safe="")
    assert response.headers["Content-Disposition"] == (
        f"attachment; filename*=UTF-8''{encoded_name}"
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert not (server.root_dir / "Отчёт final.txt").exists()


def test_server_decrypt_rejects_wrong_key_remote_http_and_key_schema(
    tmp_path: Path,
) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    _manifest_value, content_key, _plaintext, _ciphertext = _prepare_encrypted_file(server)

    wrong_key_text = b64url_encode(b"z" * 32)
    wrong_key = _json_request(
        "POST",
        f"/_xferry/encrypted-files/{FILE_ID}/decrypt",
        {"content_key": wrong_key_text},
    )
    wrong_key.attach_direct_peer(("127.0.0.1", 43210))
    wrong_response = server._dispatch_handler(wrong_key)

    remote = _json_request(
        "POST",
        f"/_xferry/encrypted-files/{FILE_ID}/decrypt",
        {"content_key": b64url_encode(content_key)},
    )
    remote.attach_direct_peer(("198.51.100.20", 43210))
    remote_response = server._dispatch_handler(remote)

    extra = _json_request(
        "POST",
        f"/_xferry/encrypted-files/{FILE_ID}/decrypt",
        {"content_key": b64url_encode(content_key), "password": "must-not-be-sent"},
    )
    extra.attach_direct_peer(("127.0.0.1", 43210))
    extra_response = server._dispatch_handler(extra)

    assert (wrong_response.status_code, _error(wrong_response)["code"]) == (
        422,
        "decryption_failed",
    )
    assert wrong_key_text not in wrong_response.body.decode("utf-8")
    assert (remote_response.status_code, _error(remote_response)["code"]) == (
        403,
        "server_decryption_forbidden",
    )
    assert (extra_response.status_code, _error(extra_response)["code"]) == (
        400,
        "invalid_field",
    )
    assert _error(extra_response)["field"] == "password"


class _PipelineSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeout = None

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout) -> None:
        self.timeout = timeout


def _raw_request(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1:8080"]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(lines).encode("ascii") + b"\r\n\r\n" + body


def test_reserved_api_uses_normal_basic_auth(tmp_path: Path) -> None:
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        auth="admin:secret123",
    )
    missing_socket = _PipelineSocket()
    valid_socket = _PipelineSocket()

    server._process_request(
        _raw_request("GET", "/_xferry/encrypted-files"),
        missing_socket,
        ("127.0.0.1", 43210),
        1,
    )
    credentials = base64.b64encode(b"admin:secret123").decode("ascii")
    server._process_request(
        _raw_request(
            "GET",
            "/_xferry/encrypted-files",
            headers={"Authorization": f"Basic {credentials}"},
        ),
        valid_socket,
        ("127.0.0.1", 43210),
        1,
    )

    assert missing_socket.sent[0].startswith(b"HTTP/1.1 401")
    assert b"WWW-Authenticate: Basic" in missing_socket.sent[0]
    assert valid_socket.sent[0].startswith(b"HTTP/1.1 200")


def test_reserved_api_rejects_cross_origin_even_when_general_cors_allows_it(
    tmp_path: Path,
) -> None:
    server = make_server(
        root_dir=str(tmp_path),
        quiet=True,
        encrypted_uploads=True,
        cors_origin="https://app.example",
    )
    cross_site = _PipelineSocket()
    same_site = _PipelineSocket()

    server._process_request(
        _raw_request(
            "GET",
            "/_xferry/encrypted-files",
            headers={
                "Origin": "https://app.example",
                "Sec-Fetch-Site": "cross-site",
            },
        ),
        cross_site,
        ("127.0.0.1", 43210),
        1,
    )
    server._process_request(
        _raw_request(
            "GET",
            "/_xferry/encrypted-files",
            headers={
                "Origin": "http://127.0.0.1:8080",
                "Sec-Fetch-Site": "same-origin",
            },
        ),
        same_site,
        ("127.0.0.1", 43210),
        1,
    )

    assert cross_site.sent[0].startswith(b"HTTP/1.1 403")
    assert json.loads(cross_site.sent[0].split(b"\r\n\r\n", 1)[1])["error"]["code"] == (
        "forbidden_origin"
    )
    assert same_site.sent[0].startswith(b"HTTP/1.1 200")


class _HeaderOnlySocket:
    def __init__(self, header: bytes) -> None:
        self.header = header
        self.calls = 0
        self.timeout = None

    def recv(self, _size: int) -> bytes:
        self.calls += 1
        if self.calls == 1:
            return self.header
        return b""

    def settimeout(self, timeout) -> None:
        self.timeout = timeout


def test_chunk_route_rejects_oversize_content_length_before_body_allocation(
    tmp_path: Path,
) -> None:
    server = make_server(root_dir=str(tmp_path), quiet=True, encrypted_uploads=True)
    declared = EUF_CHUNK_SIZE + 16 + 1
    header = (
        f"PUT /_xferry/encrypted-uploads/{FILE_ID}/chunks/0 HTTP/1.1\r\n"
        "Host: 127.0.0.1:8080\r\n"
        f"Content-Length: {declared}\r\n\r\n"
    ).encode("ascii")
    sock = _HeaderOnlySocket(header)

    received = server._receive_request_result(sock)

    assert received.data == b""
    assert received.rejection_reason == "body_too_large"
    assert sock.calls == 1
    assert server._body_memory_budget.snapshot()["current_bytes"] == 0
