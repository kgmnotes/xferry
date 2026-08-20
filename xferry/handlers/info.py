"""
Info method handlers: INFO, PING.
"""

import json
import logging
import mimetypes
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import HIDDEN_FILES, __version__
from ..features import registry_methods, ui_method_groups
from ..file_inspection import inspect_file
from ..http import HTTPRequest, HTTPResponse, json_response
from .base import BaseHandler

logger = logging.getLogger("xferry")

INFO_ERROR_PATH_DETAIL_MAX_CHARS = 1024
INFO_QUERY_ALLOWED_FIELDS = frozenset({"offset", "limit", "inspect"})
INFO_QUERY_ALLOWED_DETAILS = {"allowed": sorted(INFO_QUERY_ALLOWED_FIELDS)}
INFO_QUERY_ASCII_INTEGER_RE = re.compile(r"^[0-9]+$")
INFO_QUERY_MAX_INTEGER_DIGITS = 4
INFO_QUERY_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class InfoHandlersMixin(BaseHandler):
    """Mixin with info method handlers."""

    def handle_info(self, request: HTTPRequest) -> HTTPResponse:
        """Implement the custom INFO file and directory metadata method."""
        offset, limit, inspect_requested, query_error = self._parse_info_query(request)
        if query_error is not None:
            return query_error

        clean_path = self._info_clean_upload_path(request.path)

        if self._is_hidden_file(request.path):
            return self._info_not_found(clean_path)

        # For INFO, don't substitute / with index.html
        file_path = self._resolve_safe_path(clean_path, self.upload_dir)

        if file_path is None:
            return self._invalid_info_path(request.path)

        is_dir = file_path.is_dir() if file_path.exists() else False
        logger.debug(f"INFO {request.path} -> {'directory' if is_dir else 'file'}")

        if not file_path.exists():
            return self._info_not_found(clean_path)

        response_payload: dict[str, Any] = {
            "entry": self._build_info_entry(file_path, inspect_requested),
        }

        if file_path.is_dir():
            scan_started = time.perf_counter()
            all_items = [
                f
                for f in sorted(file_path.iterdir())
                if not f.name.startswith(".") and f.name not in HIDDEN_FILES and not f.is_symlink()
            ]
            metrics = self._get_metrics_collector()
            if metrics is not None:
                metrics.record_scan_observation(
                    "info",
                    (time.perf_counter() - scan_started) * 1000,
                    items=len(all_items),
                )

            contents = all_items[offset : offset + limit]
            response_payload["page"] = {
                "offset": offset,
                "limit": limit,
                "total_items": len(all_items),
                "returned_items": len(contents),
            }
            response_payload["contents"] = [
                self._build_info_contents_item(item, inspect_requested) for item in contents
            ]

        return json_response(response_payload)

    def _parse_info_query(
        self,
        request: HTTPRequest,
    ) -> tuple[int, int, bool, HTTPResponse | None]:
        """Strictly parse INFO query parameters without using lossy shared params."""
        offset = 0
        limit = 100
        inspect_requested = False
        seen_fields: set[str] = set()

        if not request.query_string:
            return offset, limit, inspect_requested, None

        for token in request.query_string.split("&"):
            if not token:
                return offset, limit, inspect_requested, self._invalid_info_query_field("query")
            raw_key, separator, raw_value = token.partition("=")
            if not raw_key or not raw_key.isascii() or INFO_QUERY_KEY_RE.fullmatch(raw_key) is None:
                return offset, limit, inspect_requested, self._invalid_info_query_field("query")
            key = raw_key
            field = key
            if key not in INFO_QUERY_ALLOWED_FIELDS:
                return offset, limit, inspect_requested, self._invalid_info_query_field(field)
            if key in seen_fields:
                return offset, limit, inspect_requested, self._invalid_info_query_field(key)
            seen_fields.add(key)
            if not separator or raw_value == "":
                return offset, limit, inspect_requested, self._invalid_info_query_field(key)
            if not raw_value.isascii():
                return offset, limit, inspect_requested, self._invalid_info_query_field(key)
            value = raw_value

            if key == "offset":
                if (
                    len(value) > INFO_QUERY_MAX_INTEGER_DIGITS
                    or INFO_QUERY_ASCII_INTEGER_RE.fullmatch(value) is None
                ):
                    return offset, limit, inspect_requested, self._invalid_info_query_field(key)
                offset = int(value)
            elif key == "limit":
                if (
                    len(value) > INFO_QUERY_MAX_INTEGER_DIGITS
                    or INFO_QUERY_ASCII_INTEGER_RE.fullmatch(value) is None
                ):
                    return offset, limit, inspect_requested, self._invalid_info_query_field(key)
                limit = int(value)
                if limit < 1 or limit > 1000:
                    return offset, limit, inspect_requested, self._invalid_info_query_field(key)
            elif value == "true":
                inspect_requested = True
            elif value == "false":
                inspect_requested = False
            else:
                return offset, limit, inspect_requested, self._invalid_info_query_field(key)

        return offset, limit, inspect_requested, None

    def _invalid_info_query_field(self, field: str) -> HTTPResponse:
        """Return canonical invalid_field for malformed INFO query fields."""
        return self._error_response(
            400,
            "Invalid INFO query field",
            code="invalid_field",
            field=field,
            details=INFO_QUERY_ALLOWED_DETAILS,
        )

    @staticmethod
    def _info_clean_upload_path(path: str) -> str:
        """Return the uploads-relative path represented by an INFO URL path."""
        clean_path = path.lstrip("/")
        if clean_path.startswith("uploads/"):
            return clean_path[8:]
        if clean_path == "uploads":
            return ""
        return clean_path

    def _info_public_path(self, file_path: Path) -> str:
        """Return the canonical public uploads path for an existing INFO target."""
        try:
            relative_path = file_path.resolve().relative_to(self.upload_dir.resolve())
        except (OSError, RuntimeError, ValueError):
            return "/uploads"
        if not relative_path.parts:
            return "/uploads"
        return f"/uploads/{relative_path.as_posix()}"

    @staticmethod
    def _info_public_missing_path(clean_path: str) -> str:
        """Return a canonical bounded uploads path for a missing INFO target."""
        if not clean_path:
            return "/uploads"
        return f"/uploads/{clean_path}"[:INFO_ERROR_PATH_DETAIL_MAX_CHARS]

    @staticmethod
    def _bounded_info_request_path(path: str) -> str:
        """Bound raw request-path details in INFO error envelopes."""
        return path[:INFO_ERROR_PATH_DETAIL_MAX_CHARS]

    def _invalid_info_path(self, path: str) -> HTTPResponse:
        """Return canonical invalid_path for malformed or escaping INFO paths."""
        return self._error_response(
            400,
            "Invalid upload path",
            code="invalid_path",
            field="path",
            details={"scope": "uploads", "path": self._bounded_info_request_path(path)},
        )

    def _info_not_found(self, clean_path: str) -> HTTPResponse:
        """Return canonical resource_not_found for absent or hidden INFO targets."""
        return self._error_response(
            404,
            "Upload resource not found",
            code="resource_not_found",
            field="path",
            details={
                "scope": "uploads",
                "resource": "upload",
                "path": self._info_public_missing_path(clean_path),
            },
        )

    def _build_info_entry(self, file_path: Path, inspect_requested: bool) -> dict[str, Any]:
        """Build the canonical INFO entry object."""
        stat = file_path.stat()
        content_type, _ = mimetypes.guess_type(str(file_path))
        inspection = (
            inspect_file(file_path).as_dict() if inspect_requested and file_path.is_file() else None
        )
        return {
            "exists": True,
            "path": self._info_public_path(file_path),
            "name": file_path.name,
            "kind": "directory" if file_path.is_dir() else "file",
            "size_bytes": stat.st_size,
            "size_human": self.format_size(stat.st_size),
            "content_type": content_type or "unknown",
            "created_at": datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "extension": file_path.suffix,
            "access_scope": "uploads",
            "inspection": inspection,
        }

    @staticmethod
    def _build_info_contents_item(file_path: Path, inspect_requested: bool) -> dict[str, Any]:
        """Build one canonical directory contents item."""
        inspection = (
            inspect_file(file_path).as_dict() if inspect_requested and file_path.is_file() else None
        )
        return {
            "name": file_path.name,
            "kind": "directory" if file_path.is_dir() else "file",
            "inspection": inspection,
        }

    def handle_ping(self, request: HTTPRequest) -> HTTPResponse:
        """Implement the custom PING server health check."""
        logger.debug("PING")
        response = HTTPResponse(200)
        plugin_methods = getattr(self, "plugin_methods", {})
        registered_core_methods = tuple(
            method
            for method in registry_methods()
            if method in self.method_handlers and method not in plugin_methods
        )

        ping_info: dict[str, Any] = {
            "health": "ready",
            "server": f"XFerry/{__version__}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "supported_methods": list(registered_core_methods),
            "method_groups": {
                group: list(methods)
                for group, methods in ui_method_groups(registered_core_methods).items()
            },
            "plugin_methods": list(plugin_methods.keys()),
            "access_scope": "uploads",
        }
        get_smuggle_capabilities = getattr(self, "get_smuggle_capabilities", None)
        if callable(get_smuggle_capabilities) and "SMUGGLE" not in plugin_methods:
            ping_info["smuggle_capabilities"] = get_smuggle_capabilities()
        get_metrics = getattr(self, "get_metrics", None)
        if callable(get_metrics):
            ping_info["metrics"] = get_metrics()

        response.set_body(json.dumps(ping_info, indent=2), "application/json")
        return response
