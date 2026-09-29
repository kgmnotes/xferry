"""Reserved HTTP API for resumable EUF v1 encrypted files."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from typing import Any, BinaryIO
from urllib.parse import quote, unquote, urlsplit

from ..encrypted_storage import (
    EncryptedStorageConflict,
    EncryptedStorageIncomplete,
    EncryptedStorageNotFound,
    EncryptedStorageService,
    EncryptedStoredFile,
)
from ..encrypted_transfer import (
    EUF_CHUNK_SIZE,
    EUF_GCM_TAG_SIZE,
    EUF_MAX_FILE_SIZE,
    EUF_MAX_METADATA_SIZE,
    EUF_VERSION,
    EncryptedTransferManifest,
    EncryptedTransferValidationError,
    b64url_decode,
    b64url_encode,
    decrypt_chunk,
    decrypt_metadata,
)
from ..http import HTTPRequest, HTTPResponse, error_response, json_response
from ..storage import UploadStorageQuotaExceeded
from .base import BaseHandler

ENCRYPTED_UPLOADS_PATH = "/_xferry/encrypted-uploads"
ENCRYPTED_FILES_PATH = "/_xferry/encrypted-files"
ENCRYPTED_CREATE_BODY_LIMIT = 16 * 1024
ENCRYPTED_DECRYPT_BODY_LIMIT = 512
ENCRYPTED_CHUNK_BODY_LIMIT = EUF_CHUNK_SIZE + EUF_GCM_TAG_SIZE

_FILE_ID_PATTERN = r"[0-9a-f]{32}"
_UPLOAD_ITEM_RE = re.compile(rf"^{ENCRYPTED_UPLOADS_PATH}/({_FILE_ID_PATTERN})$")
_UPLOAD_CHUNK_RE = re.compile(
    rf"^{ENCRYPTED_UPLOADS_PATH}/({_FILE_ID_PATTERN})/chunks/(0|[1-9][0-9]*)$"
)
_UPLOAD_COMPLETE_RE = re.compile(rf"^{ENCRYPTED_UPLOADS_PATH}/({_FILE_ID_PATTERN})/complete$")
_FILE_ITEM_RE = re.compile(rf"^{ENCRYPTED_FILES_PATH}/({_FILE_ID_PATTERN})$")
_FILE_DATA_RE = re.compile(rf"^{ENCRYPTED_FILES_PATH}/({_FILE_ID_PATTERN})/data$")
_FILE_DECRYPT_RE = re.compile(rf"^{ENCRYPTED_FILES_PATH}/({_FILE_ID_PATTERN})/decrypt$")
_CREATE_FIELDS = (
    "version",
    "plaintext_size",
    "chunk_size",
    "chunk_count",
    "salt",
    "nonce_prefix",
    "encrypted_metadata",
)


class _DuplicateJSONMember(ValueError):
    """Signal one duplicate JSON object member without retaining its value."""

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def _reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field, value in pairs:
        if field in result:
            raise _DuplicateJSONMember(field)
        result[field] = value
    return result


def _reject_non_finite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _is_reserved_path(path: str) -> bool:
    return path.startswith("/_xferry/encrypted-")


def is_encrypted_transfer_target(request: HTTPRequest) -> bool:
    """Return whether a decoded request path belongs to the reserved namespace."""
    return _is_reserved_path(request.path)


def encrypted_request_body_limit(headers_part: str) -> int | None:
    """Return the pre-allocation body cap for one reserved request line."""
    request_line = headers_part.split("\r\n", 1)[0]
    parts = request_line.split(" ")
    if len(parts) != 3:
        return None
    method, raw_target, _version = parts
    parsed = urlsplit(raw_target)
    decoded_path = unquote(parsed.path)
    if not _is_reserved_path(decoded_path):
        return None

    canonical_target = raw_target == parsed.path and parsed.path == decoded_path
    if not canonical_target:
        return 0
    if method == "PUT" and _UPLOAD_CHUNK_RE.fullmatch(parsed.path):
        return ENCRYPTED_CHUNK_BODY_LIMIT
    if method == "PUT" and _UPLOAD_ITEM_RE.fullmatch(parsed.path):
        return ENCRYPTED_CREATE_BODY_LIMIT
    if method == "POST" and _FILE_DECRYPT_RE.fullmatch(parsed.path):
        return ENCRYPTED_DECRYPT_BODY_LIMIT
    return 0


class EncryptedFileHandlersMixin(BaseHandler):
    """Handlers for the opt-in ``/_xferry/encrypted-*`` namespace."""

    def _is_encrypted_transfer_route(self, request: HTTPRequest) -> bool:
        return is_encrypted_transfer_target(request)

    def handle_encrypted_transfer(self, request: HTTPRequest) -> HTTPResponse:
        """Dispatch one canonical encrypted-transfer route."""
        storage = self._get_handler_context().encrypted_storage
        if storage is None:
            return self._not_found(request.path)

        if request.raw_target != request.raw_path or request.raw_path != request.path:
            return self._encrypted_not_found()
        path = request.raw_path

        if path == ENCRYPTED_UPLOADS_PATH:
            if request.method != "GET":
                return self._encrypted_method_not_allowed(request.method, ("GET",))
            if request.body:
                return self._encrypted_invalid_field("body")
            return self._list_encrypted_uploads(storage)

        if match := _UPLOAD_CHUNK_RE.fullmatch(path):
            if request.method != "PUT":
                return self._encrypted_method_not_allowed(request.method, ("PUT",))
            return self._put_encrypted_chunk(
                storage,
                request,
                match.group(1),
                int(match.group(2)),
            )

        if match := _UPLOAD_COMPLETE_RE.fullmatch(path):
            if request.method != "POST":
                return self._encrypted_method_not_allowed(request.method, ("POST",))
            if request.body:
                return self._encrypted_invalid_field("body")
            return self._complete_encrypted_upload(storage, match.group(1))

        if match := _UPLOAD_ITEM_RE.fullmatch(path):
            return self._handle_encrypted_upload_item(
                storage,
                request,
                match.group(1),
            )

        if path == ENCRYPTED_FILES_PATH:
            if request.method != "GET":
                return self._encrypted_method_not_allowed(request.method, ("GET",))
            if request.body:
                return self._encrypted_invalid_field("body")
            return self._list_encrypted_files(storage)

        if match := _FILE_DATA_RE.fullmatch(path):
            if request.method != "GET":
                return self._encrypted_method_not_allowed(request.method, ("GET",))
            if request.body:
                return self._encrypted_invalid_field("body")
            return self._download_encrypted_file(storage, match.group(1))

        if match := _FILE_DECRYPT_RE.fullmatch(path):
            if request.method != "POST":
                return self._encrypted_method_not_allowed(request.method, ("POST",))
            return self._decrypt_encrypted_file(storage, request, match.group(1))

        if match := _FILE_ITEM_RE.fullmatch(path):
            return self._handle_encrypted_file_item(storage, request, match.group(1))

        return self._encrypted_not_found()

    def _handle_encrypted_upload_item(
        self,
        storage: EncryptedStorageService,
        request: HTTPRequest,
        file_id: str,
    ) -> HTTPResponse:
        if request.method == "PUT":
            return self._create_encrypted_upload(storage, request, file_id)
        if request.method == "GET":
            if request.body:
                return self._encrypted_invalid_field("body")
            record = storage.get(file_id)
            if record is None or record.status != "partial":
                return self._encrypted_not_found()
            return json_response(
                {"encrypted_upload": self._encrypted_record_payload(record)},
                no_store=True,
            )
        if request.method == "DELETE":
            if request.body:
                return self._encrypted_invalid_field("body")
            record = storage.get(file_id)
            if record is None or record.status != "partial":
                return self._encrypted_not_found()
            storage.delete(file_id)
            return json_response(
                {"deleted_encrypted_upload": {"id": file_id}},
                no_store=True,
            )
        return self._encrypted_method_not_allowed(
            request.method,
            ("GET", "PUT", "DELETE"),
        )

    def _handle_encrypted_file_item(
        self,
        storage: EncryptedStorageService,
        request: HTTPRequest,
        file_id: str,
    ) -> HTTPResponse:
        if request.method not in {"GET", "DELETE"}:
            return self._encrypted_method_not_allowed(request.method, ("GET", "DELETE"))
        if request.body:
            return self._encrypted_invalid_field("body")
        record = storage.get(file_id)
        if record is None or record.status != "complete":
            return self._encrypted_not_found()
        if request.method == "GET":
            return json_response(
                {"encrypted_file": self._encrypted_record_payload(record)},
                no_store=True,
            )
        storage.delete(file_id)
        return json_response(
            {"deleted_encrypted_file": {"id": file_id}},
            no_store=True,
        )

    def _create_encrypted_upload(
        self,
        storage: EncryptedStorageService,
        request: HTTPRequest,
        file_id: str,
    ) -> HTTPResponse:
        payload, payload_error = self._load_encrypted_json(
            request,
            expected_fields=_CREATE_FIELDS,
            max_bytes=ENCRYPTED_CREATE_BODY_LIMIT,
        )
        if payload_error is not None:
            return payload_error
        assert payload is not None

        manifest, manifest_error = self._manifest_from_payload(storage, file_id, payload)
        if manifest_error is not None:
            return manifest_error
        assert manifest is not None
        try:
            result = storage.create(manifest)
        except EncryptedStorageConflict:
            return self._encrypted_error(
                409,
                "encrypted_file_conflict",
                "Encrypted file conflicts with persisted state",
                field="id",
            )
        except UploadStorageQuotaExceeded as exc:
            return self._encrypted_error(
                exc.status_code,
                "storage_quota_exceeded",
                "Upload storage quota exceeded",
                field="plaintext_size",
                details={"scope": "uploads"},
            )
        except EncryptedTransferValidationError:
            return self._encrypted_invalid_field("plaintext_size")
        return json_response(
            {"encrypted_upload": self._encrypted_record_payload(result.file)},
            status=201 if result.created else 200,
            no_store=True,
        )

    def _put_encrypted_chunk(
        self,
        storage: EncryptedStorageService,
        request: HTTPRequest,
        file_id: str,
        index: int,
    ) -> HTTPResponse:
        media_error = self._require_content_type(request, "application/octet-stream")
        if media_error is not None:
            return media_error
        if len(request.body) > ENCRYPTED_CHUNK_BODY_LIMIT:
            return self._encrypted_error(
                413,
                "payload_too_large",
                "Encrypted chunk is too large",
                field="body",
            )

        mac_values = request.get_header_values("X-XFerry-Chunk-MAC")
        if not mac_values:
            return self._encrypted_error(
                400,
                "missing_field",
                "Missing required field",
                field="X-XFerry-Chunk-MAC",
            )
        if len(mac_values) != 1:
            return self._encrypted_invalid_field("X-XFerry-Chunk-MAC")
        try:
            resume_mac = b64url_decode(mac_values[0], field="X-XFerry-Chunk-MAC")
        except EncryptedTransferValidationError:
            return self._encrypted_invalid_field("X-XFerry-Chunk-MAC")
        if len(resume_mac) != 32:
            return self._encrypted_invalid_field("X-XFerry-Chunk-MAC")

        try:
            result = storage.write_chunk(file_id, index, request.body, resume_mac)
        except EncryptedStorageNotFound:
            return self._encrypted_not_found()
        except EncryptedStorageConflict:
            return self._encrypted_error(
                409,
                "encrypted_chunk_conflict",
                "Encrypted chunk conflicts with persisted data",
                field="body",
            )
        except EncryptedTransferValidationError:
            return self._encrypted_invalid_field("body")
        return json_response(
            {
                "encrypted_chunk": {
                    "id": file_id,
                    "index": index,
                    "stored": result.stored,
                    "resume_mac": b64url_encode(resume_mac),
                }
            },
            status=201 if result.stored else 200,
            no_store=True,
        )

    def _complete_encrypted_upload(
        self,
        storage: EncryptedStorageService,
        file_id: str,
    ) -> HTTPResponse:
        try:
            result = storage.complete(file_id)
        except EncryptedStorageNotFound:
            return self._encrypted_not_found()
        except EncryptedStorageIncomplete:
            return self._encrypted_error(
                409,
                "encrypted_file_incomplete",
                "Encrypted file is missing chunks",
                field="id",
            )
        payload = self._encrypted_record_payload(result.file)
        payload["completed"] = result.completed
        return json_response({"encrypted_file": payload}, no_store=True)

    def _list_encrypted_uploads(self, storage: EncryptedStorageService) -> HTTPResponse:
        return json_response(
            {
                "encrypted_uploads": [
                    self._encrypted_record_payload(record)
                    for record in storage.list_files(status="partial")
                ]
            },
            no_store=True,
        )

    def _list_encrypted_files(self, storage: EncryptedStorageService) -> HTTPResponse:
        return json_response(
            {
                "encrypted_files": [
                    self._encrypted_record_payload(record)
                    for record in storage.list_files(status="complete")
                ]
            },
            no_store=True,
        )

    def _download_encrypted_file(
        self,
        storage: EncryptedStorageService,
        file_id: str,
    ) -> HTTPResponse:
        record = storage.get(file_id)
        if record is None or record.status != "complete":
            return self._encrypted_not_found()
        response = HTTPResponse(200)
        try:
            response.set_file(
                storage.data_dir / f"{file_id}.xfr",
                "application/octet-stream",
            )
        except OSError:
            return self._encrypted_not_found()
        response.set_header("Content-Disposition", f'attachment; filename="{file_id}.xfr"')
        response.set_header("Cache-Control", "no-store")
        return response

    def _decrypt_encrypted_file(
        self,
        storage: EncryptedStorageService,
        request: HTTPRequest,
        file_id: str,
    ) -> HTTPResponse:
        if not self._server_decryption_allowed(request):
            return self._encrypted_error(
                403,
                "server_decryption_forbidden",
                "Server-side decryption requires TLS or a direct loopback peer",
            )

        payload, payload_error = self._load_encrypted_json(
            request,
            expected_fields=("content_key",),
            max_bytes=ENCRYPTED_DECRYPT_BODY_LIMIT,
        )
        if payload_error is not None:
            return payload_error
        assert payload is not None
        content_key_value = payload["content_key"]
        if not isinstance(content_key_value, str):
            return self._encrypted_invalid_field("content_key")
        try:
            content_key = b64url_decode(content_key_value, field="content_key")
        except EncryptedTransferValidationError:
            return self._encrypted_invalid_field("content_key")
        if len(content_key) != 32:
            return self._encrypted_invalid_field("content_key")

        record = storage.get(file_id)
        if record is None or record.status != "complete":
            return self._encrypted_not_found()
        metadata = decrypt_metadata(key=content_key, manifest=record.manifest)
        if metadata is None:
            return self._encrypted_decryption_failed()
        try:
            encoded_name = quote(metadata.name, safe="", encoding="utf-8", errors="strict")
        except UnicodeError:
            return self._encrypted_decryption_failed()

        ciphertext_stream = self._open_complete_ciphertext(storage, record)
        if ciphertext_stream is None:
            return self._encrypted_not_found()
        chunks = self._iter_decrypted_chunks(ciphertext_stream, record, content_key)
        response = HTTPResponse(200)
        response.set_iterator(
            chunks,
            metadata.content_type or "application/octet-stream",
            content_length=record.manifest.plaintext_size,
            stream_cleanup=ciphertext_stream.close,
        )
        response.set_header(
            "Content-Disposition",
            f"attachment; filename*=UTF-8''{encoded_name}",
        )
        response.set_header("Cache-Control", "no-store")
        return response

    @staticmethod
    def _open_complete_ciphertext(
        storage: EncryptedStorageService,
        record: EncryptedStoredFile,
    ) -> BinaryIO | None:
        path = storage.data_dir / f"{record.file_id}.xfr"
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return None
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size != record.manifest.ciphertext_size
            ):
                os.close(descriptor)
                return None
            return os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _iter_decrypted_chunks(
        stream: BinaryIO,
        record: EncryptedStoredFile,
        content_key: bytes,
    ) -> Iterator[bytes]:
        manifest = record.manifest
        try:
            for index in range(manifest.chunk_count):
                plaintext_length = min(
                    manifest.chunk_size,
                    manifest.plaintext_size - index * manifest.chunk_size,
                )
                ciphertext_length = plaintext_length + EUF_GCM_TAG_SIZE
                ciphertext = stream.read(ciphertext_length)
                if len(ciphertext) != ciphertext_length:
                    raise OSError("encrypted data is truncated")
                plaintext = decrypt_chunk(
                    ciphertext,
                    key=content_key,
                    manifest=manifest,
                    index=index,
                )
                if plaintext is None:
                    raise ValueError("encrypted chunk authentication failed")
                yield plaintext
            if stream.read(1):
                raise OSError("encrypted data has trailing bytes")
        finally:
            stream.close()

    def _manifest_from_payload(
        self,
        storage: EncryptedStorageService,
        file_id: str,
        payload: dict[str, object],
    ) -> tuple[EncryptedTransferManifest | None, HTTPResponse | None]:
        version = payload["version"]
        if isinstance(version, bool) or not isinstance(version, int) or version != EUF_VERSION:
            return None, self._encrypted_invalid_field("version")
        plaintext_size = payload["plaintext_size"]
        if (
            isinstance(plaintext_size, bool)
            or not isinstance(plaintext_size, int)
            or not 0 <= plaintext_size <= min(EUF_MAX_FILE_SIZE, storage.max_plaintext_size)
        ):
            return None, self._encrypted_invalid_field("plaintext_size")
        chunk_size = payload["chunk_size"]
        if (
            isinstance(chunk_size, bool)
            or not isinstance(chunk_size, int)
            or chunk_size != EUF_CHUNK_SIZE
        ):
            return None, self._encrypted_invalid_field("chunk_size")
        chunk_count = payload["chunk_count"]
        expected_chunk_count = (plaintext_size + EUF_CHUNK_SIZE - 1) // EUF_CHUNK_SIZE
        if (
            isinstance(chunk_count, bool)
            or not isinstance(chunk_count, int)
            or chunk_count != expected_chunk_count
        ):
            return None, self._encrypted_invalid_field("chunk_count")

        decoded_fields: dict[str, bytes] = {}
        for field in ("salt", "nonce_prefix", "encrypted_metadata"):
            encoded_value = payload[field]
            if not isinstance(encoded_value, str):
                return None, self._encrypted_invalid_field(field)
            try:
                decoded_fields[field] = b64url_decode(encoded_value, field=field)
            except EncryptedTransferValidationError:
                return None, self._encrypted_invalid_field(field)
        if len(decoded_fields["salt"]) != 16:
            return None, self._encrypted_invalid_field("salt")
        if len(decoded_fields["nonce_prefix"]) != 8:
            return None, self._encrypted_invalid_field("nonce_prefix")
        encrypted_metadata_length = len(decoded_fields["encrypted_metadata"])
        if (
            not EUF_GCM_TAG_SIZE
            <= encrypted_metadata_length
            <= (EUF_MAX_METADATA_SIZE + EUF_GCM_TAG_SIZE)
        ):
            return None, self._encrypted_invalid_field("encrypted_metadata")

        return (
            EncryptedTransferManifest(
                file_id=file_id,
                version=version,
                plaintext_size=plaintext_size,
                chunk_size=chunk_size,
                chunk_count=chunk_count,
                salt=decoded_fields["salt"],
                nonce_prefix=decoded_fields["nonce_prefix"],
                encrypted_metadata=decoded_fields["encrypted_metadata"],
            ),
            None,
        )

    def _load_encrypted_json(
        self,
        request: HTTPRequest,
        *,
        expected_fields: tuple[str, ...],
        max_bytes: int,
    ) -> tuple[dict[str, object] | None, HTTPResponse | None]:
        media_error = self._require_content_type(request, "application/json")
        if media_error is not None:
            return None, media_error
        if len(request.body) > max_bytes:
            return None, self._encrypted_error(
                413,
                "payload_too_large",
                "JSON body is too large",
                field="body",
            )
        try:
            decoded = json.loads(
                request.body.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_json_members,
                parse_constant=_reject_non_finite_json,
            )
        except _DuplicateJSONMember as exc:
            return None, self._encrypted_invalid_field(exc.field)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return None, self._encrypted_error(
                400,
                "malformed_json",
                "Malformed JSON body",
                field="body",
            )
        if not isinstance(decoded, dict):
            return None, self._encrypted_invalid_field("body")
        payload = decoded
        expected = set(expected_fields)
        for field in payload:
            if not isinstance(field, str) or field not in expected:
                return None, self._encrypted_invalid_field(str(field))
        for field in expected_fields:
            if field not in payload:
                return None, self._encrypted_error(
                    400,
                    "missing_field",
                    "Missing required field",
                    field=field,
                )
        return payload, None

    def _require_content_type(
        self,
        request: HTTPRequest,
        expected: str,
    ) -> HTTPResponse | None:
        values = request.get_header_values("Content-Type")
        if len(values) > 1:
            return self._encrypted_invalid_field("Content-Type")
        if not values or values[0] != expected:
            return self._encrypted_error(
                415,
                "unsupported_media_type",
                "Unsupported media type",
                field="Content-Type",
                details={"supported": [expected]},
            )
        return None

    @staticmethod
    def _encrypted_record_payload(record: EncryptedStoredFile) -> dict[str, object]:
        manifest = record.manifest
        return {
            "id": record.file_id,
            "version": manifest.version,
            "plaintext_size": manifest.plaintext_size,
            "ciphertext_size": manifest.ciphertext_size,
            "chunk_size": manifest.chunk_size,
            "chunk_count": manifest.chunk_count,
            "salt": b64url_encode(manifest.salt),
            "nonce_prefix": b64url_encode(manifest.nonce_prefix),
            "encrypted_metadata": b64url_encode(manifest.encrypted_metadata),
            "status": record.status,
            "received_chunks": [
                {
                    "index": chunk.index,
                    "resume_mac": b64url_encode(chunk.resume_mac),
                }
                for chunk in record.received_chunks
            ],
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

    def _server_decryption_allowed(self, request: HTTPRequest) -> bool:
        if bool(getattr(self, "tls_enabled", False)):
            return True
        peer = request.security_context.direct_peer
        if peer is None:
            return False
        try:
            return ipaddress.ip_address(peer[0]).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _encrypted_error(
        status: int,
        code: str,
        message: str,
        *,
        field: str | None = None,
        details: Mapping[str, object] | None = None,
    ) -> HTTPResponse:
        return error_response(
            status,
            code,
            message,
            field=field,
            details=details,
            no_store=True,
        )

    def _encrypted_not_found(self) -> HTTPResponse:
        return self._encrypted_error(
            404,
            "resource_not_found",
            "Encrypted resource not found",
            field="id",
        )

    def _encrypted_invalid_field(self, field: str) -> HTTPResponse:
        return self._encrypted_error(
            400,
            "invalid_field",
            "Invalid field",
            field=field,
        )

    def _encrypted_decryption_failed(self) -> HTTPResponse:
        return self._encrypted_error(
            422,
            "decryption_failed",
            "Encrypted metadata authentication failed",
        )

    def _encrypted_method_not_allowed(
        self,
        method: str,
        allowed: tuple[str, ...],
    ) -> HTTPResponse:
        response = self._encrypted_error(
            405,
            "method_not_allowed",
            "Method not allowed",
            details={"method": method, "allowed_methods": list(allowed)},
        )
        response.set_header("Allow", ", ".join(allowed))
        return response


__all__ = [
    "ENCRYPTED_CHUNK_BODY_LIMIT",
    "ENCRYPTED_CREATE_BODY_LIMIT",
    "ENCRYPTED_DECRYPT_BODY_LIMIT",
    "EncryptedFileHandlersMixin",
    "encrypted_request_body_limit",
    "is_encrypted_transfer_target",
]
