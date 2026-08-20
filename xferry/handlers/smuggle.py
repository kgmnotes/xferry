"""HTTP SMUGGLE coordinator.

Request policy, rendering, and temporary-file lifecycle live in the xferry
smuggle package. This mixin only performs source admission, delegates to those
components, and serializes the canonical HTTP response.
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from ..http import HTTPRequest, HTTPResponse, json_response
from ..smuggle.policy import (
    DEFAULT_SMUGGLE_POLICY,
    DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS,
    DEFAULT_SMUGGLE_TEMP_MAX_BYTES,
    DEFAULT_SMUGGLE_TEMP_MAX_FILES,
    SMUGGLE_ERROR_PATH_DETAIL_MAX_CHARS,
    SMUGGLE_OUTPUT_CONTENT_TYPES,
    SMUGGLE_SCHEMA_VERSION,
    SMUGGLE_SOURCE_SIZE_LIMIT,
    SmugglePolicy,
    SmuggleRequestError,
    SmuggleTempArtifact,
    SmuggleTempPolicy,
    SmuggleTempQuotaExceeded,
    SmuggleTempUsage,
    build_smuggle_capabilities,
)
from ..smuggle.renderer import render_artifact
from ..smuggle.request import parse_smuggle_request
from ..smuggle.store import SmuggleArtifactStore
from ..utils.captcha import generate_password_captcha
from .base import BaseHandler

logger = logging.getLogger("xferry")

_PASSWORD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_PASSWORD_LENGTH = 7


class SmuggleHandlersMixin(BaseHandler):
    """Coordinate canonical SMUGGLE requests and artifact generation."""

    smuggle_source_size_limit = SMUGGLE_SOURCE_SIZE_LIMIT
    smuggle_temp_policy: SmuggleTempPolicy

    def get_smuggle_capabilities(self) -> dict[str, object]:
        """Return the policy snapshot exposed through PING."""
        return build_smuggle_capabilities(
            source_size_limit=self._smuggle_source_size_limit(),
            temp_policy=self._smuggle_temp_policy(),
        )

    def handle_smuggle(self, request: HTTPRequest) -> HTTPResponse:
        """Generate a bounded, one-shot SMUGGLE artifact for an upload."""
        try:
            parsed = parse_smuggle_request(
                request,
                policy=SmugglePolicy(
                    source_max_bytes=self._smuggle_source_size_limit(),
                    temp_policy=self._smuggle_temp_policy(),
                ),
            )
        except SmuggleRequestError as exc:
            return self._smuggle_bad_request_response(exc)

        if self._is_hidden_file(request.path):
            return self._smuggle_not_found_response(request.path)

        file_path = self._get_file_path(request.path, for_sandbox=True)
        if file_path is None or not file_path.exists() or file_path.is_dir():
            return self._smuggle_not_found_response(request.path)

        source_size_limit = self._smuggle_source_size_limit()
        try:
            source_size = file_path.stat().st_size
        except OSError:
            return self._smuggle_not_found_response(request.path)
        if source_size > source_size_limit:
            return self._smuggle_too_large_response(source_size, source_size_limit)

        # Read one byte beyond the stat cap to close the file-growth race.
        try:
            with file_path.open("rb") as source:
                file_data = source.read(source_size_limit + 1)
        except OSError:
            return self._smuggle_not_found_response(request.path)
        if len(file_data) > source_size_limit:
            return self._smuggle_too_large_response(len(file_data), source_size_limit)

        password: str | None = None
        password_captcha: str | None = None
        if parsed.encryption != "none":
            password = self._new_smuggle_password()
            password_captcha = generate_password_captcha(password)

        logger.debug(
            "SMUGGLE %s mode=%s encryption=%s",
            file_path.name,
            parsed.mode,
            parsed.encryption,
        )
        try:
            artifact = render_artifact(
                file_data,
                file_path.name,
                parsed.builder,
                password=password,
                password_captcha=password_captcha,
            )
        except (ValueError, TypeError) as exc:
            logger.info("Rejected SMUGGLE render configuration: %s", type(exc).__name__)
            return self._smuggle_bad_request_response(
                SmuggleRequestError(
                    "Invalid SMUGGLE configuration",
                    code="invalid_smuggle_configuration",
                    field="mode",
                )
            )

        try:
            temp_path = self._write_smuggle_temp_artifact(
                artifact.content,
                artifact.extension,
            )
        except SmuggleTempQuotaExceeded as exc:
            logger.warning("SMUGGLE temp artifact rejected by storage policy: %s", exc)
            return self._smuggle_json_error_response(
                507,
                str(exc),
                code="smuggle_temp_quota_exceeded",
                field="smuggle_temp",
                details={"scope": "smuggle_temp", "resource": "artifact"},
            )
        except OSError:
            logger.error("SMUGGLE temp artifact write failed")
            return self._error_response(
                500,
                "Failed to create SMUGGLE artifact",
                code="internal_error",
            )

        try:
            artifact_stat = temp_path.stat()
        except OSError:
            return self._error_response(
                500,
                "Failed to create SMUGGLE artifact",
                code="internal_error",
            )
        max_age = self._smuggle_temp_policy().max_age_seconds
        expires_at = None
        if max_age is not None and math.isfinite(max_age):
            expires_at = datetime.fromtimestamp(
                artifact_stat.st_mtime + max_age,
                tz=timezone.utc,
            ).isoformat()

        builder_payload: dict[str, object] = {
            "schema_version": SMUGGLE_SCHEMA_VERSION,
            "mode": artifact.effective_mode,
            "preset": artifact.effective_preset,
            "locale": artifact.locale,
            "encryption": artifact.encryption,
            "payload_encoding": artifact.payload_encoding,
            "output_format": artifact.output_format,
            "trigger_method": artifact.trigger_method,
            "trigger_event": artifact.trigger_event,
            "trigger_event_custom": artifact.trigger_event_custom,
            "download_variant": artifact.download_variant,
            "page_template": artifact.page_template,
            "notice_shown": artifact.notice_shown,
            "null_byte": artifact.null_byte,
        }
        if artifact.password is not None:
            builder_payload["password"] = artifact.password

        return json_response(
            {
                "artifact": {
                    "url": f"/uploads/{temp_path.name}",
                    "name": temp_path.name,
                    "size_bytes": artifact_stat.st_size,
                    "content_type": SMUGGLE_OUTPUT_CONTENT_TYPES[artifact.output_format],
                    "one_shot": True,
                    "expires_at": expires_at,
                },
                "source": {
                    "name": file_path.name,
                    "path": f"/uploads/{file_path.name}",
                    "size_bytes": len(file_data),
                },
                "download": {
                    "name": artifact.download_name,
                    "name_applied": artifact.download_name_applied,
                    "mime_type": artifact.mime_type,
                },
                "builder": builder_payload,
            }
        )

    @staticmethod
    def _new_smuggle_password() -> str:
        return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(_PASSWORD_LENGTH))

    def _smuggle_source_size_limit(self) -> int:
        configured_limit = int(
            getattr(self, "smuggle_source_size_limit", SMUGGLE_SOURCE_SIZE_LIMIT)
        )
        upload_limit = int(getattr(self, "max_upload_size", configured_limit))
        return min(configured_limit, upload_limit)

    def _smuggle_temp_policy(self) -> SmuggleTempPolicy:
        policy = getattr(self, "smuggle_temp_policy", None)
        if isinstance(policy, SmuggleTempPolicy):
            return policy
        return DEFAULT_SMUGGLE_POLICY.temp_policy

    def _smuggle_store(self) -> SmuggleArtifactStore:
        context = self._get_handler_context()
        return SmuggleArtifactStore(
            context.upload_dir,
            self._smuggle_temp_policy(),
            coordinator=context.smuggle_temp,
            metrics=context.metrics,
            clock=time.time,
        )

    # These methods remain a narrow facade for server lifecycle and test hosts;
    # all filesystem and quota logic is delegated to store.py.
    def _write_smuggle_temp_artifact(self, artifact_bytes: bytes, extension: str) -> Path:
        return self._smuggle_store().write(artifact_bytes, extension)

    def cleanup_smuggle_temp_artifacts(self, *, remove_all: bool = False) -> int:
        return self._smuggle_store().cleanup(remove_all=remove_all)

    def get_smuggle_temp_usage(self) -> SmuggleTempUsage:
        return self._smuggle_store().usage()

    def _smuggle_json_error_response(
        self,
        status: int,
        error: str,
        *,
        code: str,
        field: str | None = None,
        details: dict[str, object] | None = None,
    ) -> HTTPResponse:
        return self._error_response(
            status,
            error,
            code=code,
            field=field,
            details=details,
        )

    def _smuggle_bad_request_response(self, error: SmuggleRequestError) -> HTTPResponse:
        return self._smuggle_json_error_response(
            400,
            str(error),
            code=error.code,
            field=error.field,
        )

    def _smuggle_not_found_response(self, path: str) -> HTTPResponse:
        return self._smuggle_json_error_response(
            404,
            "File not found",
            code="smuggle_source_not_found",
            field="path",
            details={
                "scope": "uploads",
                "resource": "upload",
                "path": self._smuggle_public_source_path(path),
            },
        )

    @staticmethod
    def _smuggle_public_source_path(path: str) -> str:
        clean_path = path.split("?", 1)[0].rstrip("/")
        basename = Path(clean_path).name
        public_path = f"/uploads/{basename}" if basename else "/uploads"
        return public_path[:SMUGGLE_ERROR_PATH_DETAIL_MAX_CHARS]

    def _smuggle_too_large_response(
        self,
        source_size: int,
        source_size_limit: int,
    ) -> HTTPResponse:
        return self._smuggle_json_error_response(
            413,
            f"SMUGGLE source too large. Max size: {self.format_size(source_size_limit)}",
            code="smuggle_source_too_large",
            field="source",
            details={
                "scope": "uploads",
                "resource": "upload",
                "actual_bytes": source_size,
                "limit_bytes": source_size_limit,
            },
        )


__all__ = [
    "SMUGGLE_SOURCE_SIZE_LIMIT",
    "DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS",
    "DEFAULT_SMUGGLE_TEMP_MAX_BYTES",
    "DEFAULT_SMUGGLE_TEMP_MAX_FILES",
    "SmuggleHandlersMixin",
    "SmuggleTempArtifact",
    "SmuggleTempPolicy",
    "SmuggleTempQuotaExceeded",
    "SmuggleTempUsage",
    "build_smuggle_capabilities",
]
