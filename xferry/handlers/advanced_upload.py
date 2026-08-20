"""Advanced file upload handler."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Literal

from ..http import HTTPRequest, HTTPResponse, error_response, json_response
from ..security.crypto import decrypt, verify_hmac, xor_decrypt
from ..storage import UploadStorageQuotaExceeded
from .advanced_payload import (
    ADVANCED_UPLOAD_DECODED_SIZE_LIMIT,
    ADVANCED_UPLOAD_HEADER_DATA_LIMIT,
    ADVANCED_UPLOAD_URL_DATA_LIMIT,
    AdvancedPayloadDecodedTooLarge,
    AdvancedPayloadError,
    CanonicalAdvancedPayload,
    decode_advanced_payload_data,
    parse_advanced_payload,
)
from .base import BaseHandler
from .upload_diagnostics import UploadDiagnostics, add_upload_diagnostics

logger = logging.getLogger("xferry")


def _non_negative_int(value: object, default: int) -> int:
    """Coerce configurable limits while keeping invalid values fail-safe."""
    if isinstance(value, int):
        coerced = value
    elif isinstance(value, str):
        try:
            coerced = int(value)
        except ValueError:
            return default
    else:
        return default
    return coerced if coerced >= 0 else default


class AdvancedUploadHandlersMixin(BaseHandler):
    """Mixin with canonical Advanced upload handling."""

    def _advanced_upload_decoded_size_limit(self) -> int:
        configured_limit = _non_negative_int(
            getattr(
                self,
                "advanced_upload_decoded_size_limit",
                ADVANCED_UPLOAD_DECODED_SIZE_LIMIT,
            ),
            ADVANCED_UPLOAD_DECODED_SIZE_LIMIT,
        )
        upload_limit = _non_negative_int(
            getattr(self, "max_upload_size", configured_limit),
            configured_limit,
        )
        return min(configured_limit, upload_limit)

    def _advanced_upload_encoded_size_limit(self, carrier: str) -> int:
        if carrier in {"headers", "cookies"}:
            return _non_negative_int(
                getattr(
                    self,
                    "advanced_upload_header_data_limit",
                    ADVANCED_UPLOAD_HEADER_DATA_LIMIT,
                ),
                ADVANCED_UPLOAD_HEADER_DATA_LIMIT,
            )
        if carrier in {"query", "path"}:
            return _non_negative_int(
                getattr(
                    self,
                    "advanced_upload_url_data_limit",
                    ADVANCED_UPLOAD_URL_DATA_LIMIT,
                ),
                ADVANCED_UPLOAD_URL_DATA_LIMIT,
            )
        return self._advanced_upload_decoded_size_limit()

    def _record_advanced_decode_rejection(self, reason: str | None) -> None:
        """Record one bounded advanced decode rejection when metrics are available."""
        if reason is None:
            return
        metrics = self._get_metrics_collector()
        if metrics is not None:
            metrics.record_advanced_decode_rejection(reason)

    def _advanced_error_response(self, error: AdvancedPayloadError) -> HTTPResponse:
        self._record_advanced_decode_rejection(error.metric_reason)
        return error_response(
            error.status,
            error.code,
            error.message,
            field=error.field,
            details=error.details,
        )

    def _advanced_payload_too_large_response(
        self,
        limit: int,
        *,
        scope: Literal["decoded", "final"],
    ) -> HTTPResponse:
        self._record_advanced_decode_rejection("decoded_too_large")
        return error_response(
            413,
            "payload_too_large",
            "Advanced upload payload is too large",
            field="data",
            details={"scope": "decoded" if scope == "final" else scope, "limit_bytes": limit},
        )

    @staticmethod
    def _safe_advanced_filename(payload: CanonicalAdvancedPayload, data: bytes) -> tuple[str, str]:
        filename_source = payload.filename_source
        filename = payload.name
        if not filename:
            filename = f"{hashlib.sha256(data).hexdigest()[:12]}.bin"
            filename_source = "generated"
        safe_filename = "".join(char for char in filename if char.isalnum() or char in "._-")
        if not safe_filename:
            safe_filename = f"upload_{secrets.token_hex(6)}"
            filename_source = "generated"
        return safe_filename, filename_source

    def _decrypt_advanced_payload(
        self,
        payload: CanonicalAdvancedPayload,
        decoded_data: bytes,
        decoded_limit: int,
    ) -> tuple[bytes | None, HTTPResponse | None]:
        if payload.hmac is not None:
            assert payload.key is not None
            if not verify_hmac(decoded_data, payload.key, payload.hmac):
                self._record_advanced_decode_rejection("hmac_mismatch")
                return None, error_response(
                    400,
                    "hmac_mismatch",
                    "Advanced upload integrity check failed",
                    field="hmac",
                )

        if payload.encryption == "none":
            return decoded_data, None

        assert payload.key is not None
        decrypted: bytes | None
        if payload.encryption == "xor":
            decrypted = xor_decrypt(decoded_data, payload.key)
        else:
            decrypted = decrypt(decoded_data, payload.key)
        if decrypted is None:
            self._record_advanced_decode_rejection("decrypt_failed")
            return None, error_response(
                400,
                "decrypt_failed",
                "Advanced upload decryption failed",
                field="encryption",
            )
        if not decrypted:
            return None, error_response(
                400,
                "empty_payload",
                "Advanced upload payload is empty",
                field="data",
                details={"upload_kind": "advanced"},
            )
        if len(decrypted) > decoded_limit:
            return None, self._advanced_payload_too_large_response(decoded_limit, scope="final")
        return decrypted, None

    def handle_advanced_upload(self, request: HTTPRequest) -> HTTPResponse:
        """Handle one authorized Advanced upload request."""
        dispatch = request.advanced_session_dispatch
        decoder = dispatch.session.decoder if dispatch is not None else "auto"
        diagnostic: dict[str, str | int | bool | None] = {
            "profile": "unknown",
            "carrier": "unknown",
            "filename_source": "unknown",
            "normalized_filename": None,
            "collision_renamed": None,
            "payload_size": None,
            "file_content_type": None,
            "sha256": None,
        }

        def finish(response: HTTPResponse) -> HTTPResponse:
            return add_upload_diagnostics(
                response,
                UploadDiagnostics(
                    dispatch="advanced",
                    profile=str(diagnostic["profile"]),
                    carrier=str(diagnostic["carrier"]),
                    filename_source=str(diagnostic["filename_source"]),
                    normalized_filename=(
                        diagnostic["normalized_filename"]
                        if isinstance(diagnostic["normalized_filename"], str)
                        else None
                    ),
                    collision_renamed=(
                        diagnostic["collision_renamed"]
                        if isinstance(diagnostic["collision_renamed"], bool)
                        else None
                    ),
                    request_body_size=len(request.body),
                    payload_size=(
                        diagnostic["payload_size"]
                        if isinstance(diagnostic["payload_size"], int)
                        else None
                    ),
                    file_content_type=(
                        diagnostic["file_content_type"]
                        if isinstance(diagnostic["file_content_type"], str)
                        else None
                    ),
                    sha256=(
                        diagnostic["sha256"] if isinstance(diagnostic["sha256"], str) else None
                    ),
                ),
                dispatch,
            )

        try:
            payload = parse_advanced_payload(
                request,
                decoder=decoder,
                header_data_limit=self._advanced_upload_encoded_size_limit("headers"),
                url_data_limit=self._advanced_upload_encoded_size_limit("query"),
            )
        except AdvancedPayloadError as error:
            return finish(self._advanced_error_response(error))

        diagnostic["profile"] = payload.body_profile
        diagnostic["carrier"] = payload.carrier
        diagnostic["filename_source"] = payload.filename_source
        diagnostic["file_content_type"] = payload.content_type

        decoded_limit = self._advanced_upload_decoded_size_limit()
        try:
            decoded_data = decode_advanced_payload_data(payload, decoded_limit=decoded_limit)
        except AdvancedPayloadDecodedTooLarge:
            return finish(self._advanced_payload_too_large_response(decoded_limit, scope="decoded"))
        except AdvancedPayloadError as error:
            return finish(self._advanced_error_response(error))

        file_data, crypto_error = self._decrypt_advanced_payload(
            payload,
            decoded_data,
            decoded_limit,
        )
        if crypto_error is not None:
            return finish(crypto_error)
        assert file_data is not None

        safe_filename, filename_source = self._safe_advanced_filename(payload, file_data)
        diagnostic["filename_source"] = filename_source
        diagnostic["normalized_filename"] = safe_filename

        try:
            requested_safe_filename = safe_filename
            file_path = self._get_upload_storage().publish_bytes(
                self.upload_dir / safe_filename,
                file_data,
            )
            safe_filename = file_path.name
            diagnostic["normalized_filename"] = safe_filename
            diagnostic["collision_renamed"] = safe_filename != requested_safe_filename
            diagnostic["payload_size"] = len(file_data)
            diagnostic["sha256"] = hashlib.sha256(file_data).hexdigest()

            response = json_response(
                {
                    "file": {
                        "name": safe_filename,
                        "path": f"/uploads/{safe_filename}",
                        "size_bytes": len(file_data),
                        "size_human": self.format_size(len(file_data)),
                        "content_type": diagnostic["file_content_type"],
                        "uploaded_at": datetime.now(timezone.utc).isoformat(),
                        "sha256": diagnostic["sha256"],
                    },
                    "upload": {
                        "kind": "advanced",
                        "profile": diagnostic["profile"],
                        "carrier": payload.carrier,
                        "filename_source": diagnostic["filename_source"],
                        "normalized_name": safe_filename,
                        "collision_renamed": diagnostic["collision_renamed"],
                        "request_body_size": len(request.body),
                        "payload_size": len(file_data),
                        "encoding": payload.encoding or "raw",
                        "encryption": payload.encryption,
                        "method_override": payload.method_override,
                    },
                },
                status=201,
            )
            touch_dispatch = getattr(self, "_touch_advanced_session_dispatch", None)
            if callable(touch_dispatch):
                touch_dispatch(request)
            return finish(response)

        except UploadStorageQuotaExceeded as quota_error:
            logger.warning("Advanced upload rejected by storage policy")
            return finish(
                error_response(
                    quota_error.status_code,
                    "storage_quota_exceeded",
                    "Upload storage quota exceeded",
                    field="file",
                    details={"scope": "uploads"},
                )
            )
        except Exception:
            logger.error("Advanced upload write failed")
            return finish(
                error_response(
                    500,
                    "internal_error",
                    "Advanced upload failed",
                    field="file",
                )
            )
