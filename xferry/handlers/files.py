"""
File operation handlers: GET, HEAD, POST, PUT, PATCH, DELETE, FETCH, NONE.
"""

import errno
import hashlib
import json
import logging
import mimetypes
import re
import shutil
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote

from ..config import HIDDEN_FILES
from ..http import HTTPRequest, HTTPResponse, error_response, json_response, sanitize_filename
from ..http.cors import resolve_preflight_allow_headers, resolve_preflight_allow_methods
from ..http.multipart import MultipartError, parse_single_file_multipart
from ..smuggle.policy import SMUGGLE_OUTPUT_CONTENT_TYPES
from ..storage import UploadStorageQuotaExceeded
from .base import BaseHandler, get_package_resource
from .upload_diagnostics import UploadDiagnostics, add_upload_diagnostics

logger = logging.getLogger("xferry")

HTML_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    # The current UI still renders upload/download progress with inline style
    # attributes. Keep this explicit until those widgets are moved to CSS classes.
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)

SMUGGLE_ARTIFACT_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'unsafe-inline' data:; "
    "img-src data:; "
    "connect-src blob:; "
    "base-uri 'none'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)

STATIC_APP_ASSET_RE = re.compile(
    r'(?P<prefix>\b(?:src|href|data-theme-dark|data-theme-light)=["\'])'
    r'(?P<url>/static/[^"\']+)(?P<suffix>["\'])'
)
DELETE_ERROR_PATH_DETAIL_MAX_CHARS = 1024
FETCH_ERROR_PATH_DETAIL_MAX_CHARS = 1024
CLEAR_QUERY_ALLOWED_VALUES = ("true", "false")
DELETE_QUERY_ALLOWED_FIELDS = frozenset({"clear"})


class FileHandlersMixin(BaseHandler):
    """Mixin with file operation handlers."""

    @staticmethod
    def _compute_etag(file_path: Path) -> str:
        """Compute a stat-based ETag for a file (no full read needed)."""
        st = file_path.stat()
        return f'"{st.st_size:x}-{st.st_mtime_ns:x}"'

    def _resolve_get_path(self, request: HTTPRequest) -> Path | None:
        """Resolve the filesystem path for a GET request.

        File content is limited to uploads/. The bundled web app and static
        assets stay readable so the browser UI can load.
        """
        url_path = request.path.lstrip("/")

        if self._is_hidden_file(request.path):
            return None

        if url_path in ("", "index.html"):
            file_path = get_package_resource("index.html")
        elif url_path.startswith("static/"):
            file_path = get_package_resource(url_path)
        else:
            file_path = self._get_file_path(request.path, for_sandbox=True)

        if file_path is None or not file_path.exists():
            return None

        # Directory → index.html fallback
        if file_path.is_dir():
            index_path = file_path / "index.html"
            return index_path if index_path.exists() else None

        return file_path

    def _build_ui_asset_version(self, asset_url: str) -> str | None:
        """Return a stable cache-busting token for a bundled static asset URL."""
        asset_path = asset_url.split("?", 1)[0].split("#", 1)[0].lstrip("/")
        file_path = get_package_resource(asset_path)
        if file_path is None or not file_path.exists():
            return None

        st = file_path.stat()
        return f"{st.st_mtime_ns:x}-{st.st_size:x}"

    def _version_ui_asset_url(self, asset_url: str) -> str:
        """Append or replace the version token for a bundled static asset URL."""
        base_url, fragment_sep, fragment = asset_url.partition("#")
        asset_path, query_sep, query = base_url.partition("?")
        query_parts = [part for part in query.split("&") if part and not part.startswith("v=")]
        version = self._build_ui_asset_version(asset_path)
        if version is None:
            return asset_url

        query_parts.append(f"v={version}")
        versioned_url = asset_path
        if query_parts:
            versioned_url = f"{versioned_url}?{'&'.join(query_parts)}"
        if fragment_sep:
            versioned_url = f"{versioned_url}#{fragment}"
        return versioned_url

    def _render_app_shell(self, file_path: Path) -> str:
        """Render the bundled UI shell with versioned local static asset URLs."""
        source = file_path.read_text(encoding="utf-8")
        return STATIC_APP_ASSET_RE.sub(
            lambda match: (
                f"{match.group('prefix')}"
                f"{self._version_ui_asset_url(match.group('url'))}"
                f"{match.group('suffix')}"
            ),
            source,
        )

    def _cache_control_header(
        self,
        url_path: str,
        request: HTTPRequest,
        *,
        is_user_upload: bool,
    ) -> str:
        """Return the appropriate Cache-Control policy for the response."""
        if is_user_upload or url_path.startswith("uploads/") or url_path == "uploads":
            return "no-cache"
        if url_path.startswith("static/") and request.query_params.get("v"):
            return "public, max-age=31536000, immutable"
        return "public, max-age=0, must-revalidate"

    def _serve_app_shell(self, file_path: Path) -> HTTPResponse:
        """Serve the bundled SPA shell with aggressive cache-busting."""
        response = HTTPResponse(200)
        response.set_body(self._render_app_shell(file_path), "text/html; charset=utf-8")
        response.set_header("Cache-Control", "no-store")
        response.set_header("Pragma", "no-cache")
        response.set_header("Content-Security-Policy", HTML_CONTENT_SECURITY_POLICY)
        return response

    def _serve_file(self, file_path: Path, request: HTTPRequest) -> HTTPResponse:
        """Build a 200 response for *file_path* with ETag, cache, and CSP headers."""
        url_path = request.path.lstrip("/")

        # ETag / conditional request support
        etag = self._compute_etag(file_path)
        st = file_path.stat()
        last_modified = formatdate(st.st_mtime, usegmt=True)
        is_user_upload = self._is_upload_descendant(file_path)
        file_path_str = str(file_path)
        smuggle_coordinator = self._get_handler_context().smuggle_temp
        is_smuggle = smuggle_coordinator.contains(file_path_str)
        if is_smuggle:
            claim = getattr(smuggle_coordinator, "_claim", None)
            if callable(claim) and not claim(file_path_str):
                return self._not_found(request.path)
        is_app_shell = url_path in ("", "index.html") and not is_user_upload and not is_smuggle
        if is_app_shell:
            return self._serve_app_shell(file_path)

        cache_control = self._cache_control_header(
            url_path,
            request,
            is_user_upload=is_user_upload,
        )

        if_none_match = request.headers.get("if-none-match", "")
        if if_none_match and if_none_match == etag:
            response = HTTPResponse(304)
            response.set_header("ETag", etag)
            response.set_header("Last-Modified", last_modified)
            response.set_header("Cache-Control", cache_control)
            if is_smuggle:
                response.stream_cleanup = self._cleanup_smuggle_stream(file_path, file_path_str)
            return response

        response = HTTPResponse(200)
        content_type, _ = mimetypes.guess_type(str(file_path))
        content_type = content_type or "application/octet-stream"
        if is_smuggle:
            content_type = self._smuggle_artifact_content_type(file_path, content_type)

        # Cache headers
        response.set_header("ETag", etag)
        response.set_header("Last-Modified", last_modified)
        response.set_header("Cache-Control", cache_control)

        # Smuggle files use a cleanup callback so they can stream and still be one-shot.
        force_download = (
            is_user_upload and not is_smuggle and self._should_force_download(content_type)
        )
        content_type = self._safe_upload_content_type(content_type, force_download)
        if is_smuggle:
            response.set_file(
                file_path,
                content_type,
                stream_cleanup=self._cleanup_smuggle_stream(file_path, file_path_str),
            )
        else:
            response.set_file(file_path, content_type)

        if force_download:
            safe_download_name = file_path.name.replace('"', "")
            response.set_header(
                "Content-Disposition",
                f'attachment; filename="{safe_download_name}"',
            )

        # CSP header for executable browser documents.
        if is_smuggle:
            response.set_header("Content-Security-Policy", SMUGGLE_ARTIFACT_CONTENT_SECURITY_POLICY)
        elif content_type.startswith("text/html"):
            response.set_header("Content-Security-Policy", HTML_CONTENT_SECURITY_POLICY)

        return response

    def _cleanup_smuggle_stream(self, file_path: Path, file_path_str: str) -> Callable[[], None]:
        """Return a cleanup callback for a streamed temporary SMUGGLE file."""

        def cleanup() -> None:
            try:
                file_path.unlink()
                logger.debug(f"Smuggle file cleaned up: {file_path.name}")
            except OSError:
                pass
            coordinator = self._get_handler_context().smuggle_temp
            release = getattr(coordinator, "_release", None)
            if callable(release):
                release(file_path_str)
            else:
                coordinator.discard(file_path_str)

        return cleanup

    def _is_upload_descendant(self, file_path: Path) -> bool:
        """Return True when *file_path* resolves under the user upload directory."""
        try:
            file_path.resolve().relative_to(self.upload_dir.resolve())
        except ValueError:
            return False
        return True

    @staticmethod
    def _should_force_download(content_type: str) -> bool:
        """Return True for browser-executable uploaded content."""
        return content_type.startswith("text/html") or content_type == "image/svg+xml"

    @staticmethod
    def _safe_download_filename(filename: str) -> str:
        """Normalize an uploaded filename before placing it in response headers."""
        normalized_path = str(filename).replace("\\", "/")
        safe_name = re.sub(r'[\x00-\x1f\x7f"]+', "-", Path(normalized_path).name).strip(" .-")
        return safe_name or "download"

    @classmethod
    def _build_download_content_disposition(cls, filename: str) -> str:
        """Build an injection-safe attachment disposition with RFC 5987 UTF-8 support."""
        safe_name = cls._safe_download_filename(filename)
        suffix = Path(safe_name).suffix
        safe_suffix = suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,32}", suffix) else ""
        ascii_stem = "".join(char for char in Path(safe_name).stem if char.isascii())
        ascii_stem = re.sub(r"[^A-Za-z0-9_-]+", "-", ascii_stem).strip("._-")
        if not re.search(r"[A-Za-z]", ascii_stem):
            ascii_stem = "download"
        ascii_fallback = f"{ascii_stem}{safe_suffix}"
        encoded_filename = quote(safe_name, safe="")
        return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded_filename}"

    @staticmethod
    def _smuggle_artifact_content_type(file_path: Path, fallback: str) -> str:
        """Return browser-runnable content types for generated SMUGGLE artifacts."""
        output_format = file_path.suffix.lower().lstrip(".")
        return SMUGGLE_OUTPUT_CONTENT_TYPES.get(output_format, fallback)

    def _safe_upload_content_type(
        self,
        content_type: str,
        force_download: bool,
    ) -> str:
        """Prevent ordinary user uploads from executing as same-origin HTML/SVG."""
        if force_download:
            return "application/octet-stream"
        return content_type

    def handle_get(self, request: HTTPRequest) -> HTTPResponse:
        """Handle GET request and return file contents."""
        logger.debug(f"GET {request.path}")

        if request.path == "/metrics":
            return json_response({"metrics": self.get_metrics()}, no_store=True)

        file_path = self._resolve_get_path(request)
        if file_path is None:
            return self._not_found(request.path)

        return self._serve_file(file_path, request)

    def handle_head(self, request: HTTPRequest) -> HTTPResponse:
        """Handle HEAD request like GET but with an empty body."""
        response = self.handle_get(request)
        response.body = b""
        response.stream_path = None
        return response

    def handle_delete(self, request: HTTPRequest) -> HTTPResponse:
        """Handle DELETE request by deleting a file from uploads/."""
        clear_value, query_error = self._parse_delete_clear_query(request)
        if query_error is not None:
            return query_error

        if self._is_hidden_file(request.path):
            return self._not_found(request.path)

        try:
            file_path = self._get_file_path(request.path, for_sandbox=True)
        except (OSError, RuntimeError, ValueError):
            return self._invalid_delete_path(request.path)

        if file_path is None:
            return self._invalid_delete_path(request.path)

        if not file_path.exists():
            return self._not_found(request.path)

        if self._is_upload_root(file_path) and clear_value == "true":
            return self._clear_uploads_directory()

        # Reject directories
        if file_path.is_dir():
            return self._invalid_directory_delete(request.path)

        # Defense in depth: verify path is inside upload_dir
        try:
            file_path.resolve().relative_to(self.upload_dir.resolve())
        except (OSError, RuntimeError, ValueError):
            return self._error_response(
                403,
                "Forbidden upload path",
                code="forbidden",
                field="path",
                details={"path": self._bounded_delete_path_detail(request.path)},
            )

        try:
            deleted_name = file_path.name
            file_path.unlink()
            logger.debug(f"DELETE {deleted_name}")
            return json_response(
                {
                    "deleted_file": {
                        "name": deleted_name,
                        "path": self._upload_response_path(file_path),
                    }
                }
            )
        except OSError:
            return self._error_response(
                500,
                "Failed to delete upload",
                code="internal_error",
                field="path",
                details={"path": self._bounded_delete_path_detail(request.path)},
            )

    def _parse_delete_clear_query(
        self,
        request: HTTPRequest,
    ) -> tuple[str | None, HTTPResponse | None]:
        """Strictly parse DELETE query parameters without using lossy shared params."""
        clear_value: str | None = None
        seen_fields: set[str] = set()

        if request.query_string and "" in request.query_string.split("&"):
            return None, self._invalid_delete_query_field("query")

        for key, value in parse_qsl(request.query_string, keep_blank_values=True):
            field = key or "query"
            if key not in DELETE_QUERY_ALLOWED_FIELDS:
                return None, self._invalid_delete_query_field(field)
            if key in seen_fields:
                return None, self._invalid_delete_clear_value()
            seen_fields.add(key)
            if value not in CLEAR_QUERY_ALLOWED_VALUES:
                return None, self._invalid_delete_clear_value()
            clear_value = value

        return clear_value, None

    def _invalid_delete_query_field(self, field: str) -> HTTPResponse:
        """Return canonical invalid_field for DELETE query keys outside this slice."""
        return self._error_response(
            400,
            "Invalid DELETE query field",
            code="invalid_field",
            field=field,
            details={"allowed": sorted(DELETE_QUERY_ALLOWED_FIELDS)},
        )

    def _invalid_delete_clear_value(self) -> HTTPResponse:
        """Return canonical invalid_field for malformed or duplicate clear values."""
        return self._error_response(
            400,
            "Invalid clear value",
            code="invalid_field",
            field="clear",
            details={"allowed": list(CLEAR_QUERY_ALLOWED_VALUES)},
        )

    def _invalid_directory_delete(self, path: str) -> HTTPResponse:
        """Reject directory DELETE unless the upload root is being cleared."""
        return self._error_response(
            400,
            "Directory delete requires clear=true on /uploads",
            code="invalid_field",
            field="path",
            details={"path": self._bounded_delete_path_detail(path)},
        )

    def _invalid_delete_path(self, path: str) -> HTTPResponse:
        """Return canonical invalid_path for malformed or escaping DELETE paths."""
        return self._error_response(
            400,
            "Invalid upload path",
            code="invalid_path",
            field="path",
            details={"path": self._bounded_delete_path_detail(path)},
        )

    @staticmethod
    def _bounded_delete_path_detail(path: str) -> str:
        """Bound path details in DELETE error envelopes."""
        return path[:DELETE_ERROR_PATH_DETAIL_MAX_CHARS]

    def _is_upload_root(self, file_path: Path) -> bool:
        """Return True when *file_path* resolves to the upload directory itself."""
        try:
            return file_path.resolve() == self.upload_dir.resolve()
        except (OSError, RuntimeError):
            return False

    def _upload_response_path(self, file_path: Path) -> str:
        """Return the canonical public uploads path for a resolved upload file."""
        try:
            relative_path = file_path.resolve().relative_to(self.upload_dir.resolve())
        except (OSError, RuntimeError, ValueError):
            return "/uploads"
        if not relative_path.parts:
            return "/uploads"
        return f"/uploads/{relative_path.as_posix()}"

    @staticmethod
    def _clear_failure_reason(exc: OSError) -> str:
        """Map filesystem failures to a bounded low-cardinality reason."""
        if isinstance(exc, PermissionError) or exc.errno in {errno.EACCES, errno.EPERM}:
            return "permission_denied"
        if isinstance(exc, FileNotFoundError) or exc.errno == errno.ENOENT:
            return "not_found"
        if isinstance(exc, BlockingIOError) or exc.errno in {errno.EBUSY, errno.ETXTBSY}:
            return "busy"
        return "io_error"

    def _clear_uploads_directory(self) -> HTTPResponse:
        """Delete user-visible contents from uploads/, preserving hidden service files."""
        deleted_files = 0
        deleted_dirs = 0
        preserved: list[str] = []
        failures: list[dict[str, str]] = []

        for entry in sorted(self.upload_dir.iterdir(), key=lambda path: path.name):
            if entry.name.startswith(".") or entry.name in HIDDEN_FILES:
                preserved.append(entry.name)
                continue

            try:
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry)
                    deleted_dirs += 1
                else:
                    entry.unlink()
                    deleted_files += 1
            except OSError as exc:
                failures.append(
                    {
                        "name": entry.name,
                        "reason": self._clear_failure_reason(exc),
                    }
                )

        if failures:
            return self._error_response(
                500,
                "Failed to clear uploads",
                code="clear_failed",
                field="path",
                details={
                    "path": "/uploads",
                    "deleted_files": deleted_files,
                    "deleted_dirs": deleted_dirs,
                    "preserved": preserved,
                    "failures": failures,
                },
            )

        logger.debug(
            "Cleared uploads/: %s files, %s directories, %s preserved",
            deleted_files,
            deleted_dirs,
            len(preserved),
        )
        return json_response(
            {
                "cleared_uploads": {
                    "path": "/uploads",
                    "deleted_files": deleted_files,
                    "deleted_dirs": deleted_dirs,
                    "preserved": preserved,
                }
            }
        )

    def handle_post(self, request: HTTPRequest) -> HTTPResponse:
        """Handle POST request by delegating to handle_none (file upload).

        POST, PUT, PATCH, and NONE all use the same file upload logic.
        This allows standard HTTP clients to upload without custom methods.
        """
        return self._handle_basic_upload(request)

    def handle_patch(self, request: HTTPRequest) -> HTTPResponse:
        """Handle PATCH request by delegating to handle_none (file upload)."""
        return self._handle_basic_upload(request)

    def handle_options(self, request: HTTPRequest) -> HTTPResponse:
        """Handle OPTIONS request for CORS preflight."""
        response = HTTPResponse(204)
        if not getattr(self, "cors_origin", None):
            return response

        requested_method = request.headers.get("access-control-request-method", "")
        logger.debug(f"OPTIONS preflight: {requested_method}")
        response.set_header(
            "Access-Control-Allow-Methods",
            resolve_preflight_allow_methods(
                requested_method,
                read_only=getattr(self, "cors_origins", ()) == ("*",),
            ),
        )

        requested_headers = request.headers.get("access-control-request-headers", "")
        allowed_headers = resolve_preflight_allow_headers(
            requested_headers,
            allow_advanced=getattr(self, "cors_origins", ()) != ("*",),
        )
        if allowed_headers:
            response.set_header("Access-Control-Allow-Headers", allowed_headers)

        return response

    def handle_fetch(self, request: HTTPRequest) -> HTTPResponse:
        """Implement the custom FETCH file-download method."""
        if self._is_hidden_file(request.path):
            return self._fetch_not_found(request.path)

        file_path = self._get_file_path(request.path, for_sandbox=True)

        if file_path is None:
            return self._invalid_fetch_path(request.path)

        if not file_path.exists() or file_path.is_dir():
            return self._fetch_not_found(request.path)

        response = HTTPResponse(200)

        content_type, _ = mimetypes.guess_type(str(file_path))
        content_type = content_type or "application/octet-stream"

        stat = file_path.stat()
        logger.debug(f"FETCH {file_path.name} ({stat.st_size} bytes)")

        # Stream file directly from disk
        response.set_file(file_path, content_type)
        response.set_header(
            "Content-Disposition",
            self._build_download_content_disposition(file_path.name),
        )

        return response

    def _invalid_fetch_path(self, path: str) -> HTTPResponse:
        """Return canonical invalid_path for malformed or escaping FETCH paths."""
        return self._error_response(
            400,
            "Invalid upload path",
            code="invalid_path",
            field="path",
            details={"scope": "uploads", "path": self._bounded_fetch_path_detail(path)},
        )

    def _fetch_not_found(self, path: str) -> HTTPResponse:
        """Return canonical resource_not_found for absent, hidden, or non-file FETCH targets."""
        return self._error_response(
            404,
            "Upload resource not found",
            code="resource_not_found",
            field="path",
            details={
                "scope": "uploads",
                "resource": "upload",
                "path": self._fetch_public_path_detail(path),
            },
        )

    @staticmethod
    def _bounded_fetch_path_detail(path: str) -> str:
        """Bound raw request-path details in FETCH error envelopes."""
        return path[:FETCH_ERROR_PATH_DETAIL_MAX_CHARS]

    @staticmethod
    def _fetch_public_path_detail(path: str) -> str:
        """Return a bounded canonical uploads path for FETCH resource errors."""
        clean_path = path.lstrip("/")
        if clean_path.startswith("uploads/") or clean_path == "uploads":
            public_path = path
        elif clean_path:
            public_path = f"/uploads/{clean_path}"
        else:
            public_path = "/uploads"
        return public_path[:FETCH_ERROR_PATH_DETAIL_MAX_CHARS]

    def handle_none(self, request: HTTPRequest) -> HTTPResponse:
        """Implement the custom NONE file-upload method."""
        return self._handle_basic_upload(request)

    def _handle_basic_upload(
        self,
        request: HTTPRequest,
    ) -> HTTPResponse:
        """Store one Basic raw or multipart upload."""
        request_body_size = len(request.body)
        is_multipart = (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            == "multipart/form-data"
        )
        header_filename = request.headers.get("x-file-name", "")
        profile = "multipart" if is_multipart else ("raw_header" if header_filename else "raw_url")
        carrier = "multipart" if is_multipart else "body"
        url_filename = self._basic_url_filename(request.path, multipart=is_multipart)
        filename_source = "generated"
        filename: str | None = None
        payload = request.body
        file_content_type = request.headers.get(
            "content-type",
            "application/octet-stream",
        )

        if header_filename:
            filename = unquote(header_filename)
            filename_source = "header"

        if is_multipart:
            try:
                part = parse_single_file_multipart(request.content_type, request.body)
            except MultipartError as exc:
                response = error_response(
                    400,
                    "invalid_field",
                    str(exc),
                    field="file",
                )
                return add_upload_diagnostics(
                    response,
                    UploadDiagnostics(
                        dispatch="basic",
                        profile=profile,
                        carrier=carrier,
                        filename_source=filename_source,
                        normalized_filename=None,
                        collision_renamed=None,
                        request_body_size=request_body_size,
                        payload_size=None,
                        file_content_type=None,
                        sha256=None,
                    ),
                    None,
                )
            payload = part.payload
            file_content_type = part.content_type
            if filename is None and part.filename:
                filename = part.filename
                filename_source = "part"
            if filename is None and url_filename is not None:
                filename = url_filename
                filename_source = "url"
        elif filename is None and url_filename is not None:
            filename = url_filename
            filename_source = "url"

        if filename is None:
            filename = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        safe_filename = sanitize_filename(filename)

        if not payload:
            response = error_response(
                400,
                "empty_payload",
                "Upload payload is empty",
                field="file",
                details={"upload_kind": "basic"},
            )
            return add_upload_diagnostics(
                response,
                UploadDiagnostics(
                    dispatch="basic",
                    profile=profile,
                    carrier=carrier,
                    filename_source=filename_source,
                    normalized_filename=safe_filename,
                    collision_renamed=None,
                    request_body_size=request_body_size,
                    payload_size=None,
                    file_content_type=file_content_type,
                    sha256=None,
                ),
                None,
            )

        try:
            file_path = self._get_upload_storage().publish_bytes(
                self.upload_dir / safe_filename,
                payload,
            )
            requested_safe_filename = safe_filename
            safe_filename = file_path.name

            logger.debug(f"Upload: {safe_filename} ({len(payload)} bytes)")
            response = HTTPResponse(201)
            sha256 = hashlib.sha256(payload).hexdigest()

            result = {
                "file": {
                    "name": safe_filename,
                    "path": f"/uploads/{safe_filename}",
                    "size_bytes": len(payload),
                    "size_human": self.format_size(len(payload)),
                    "content_type": file_content_type,
                    "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    "sha256": sha256,
                },
                "upload": {
                    "kind": "basic",
                    "profile": profile,
                    "carrier": carrier,
                    "filename_source": filename_source,
                    "normalized_name": safe_filename,
                    "collision_renamed": safe_filename != requested_safe_filename,
                    "request_body_size": request_body_size,
                    "payload_size": len(payload),
                },
            }

            response.set_body(json.dumps(result, indent=2, ensure_ascii=False), "application/json")
            return add_upload_diagnostics(
                response,
                UploadDiagnostics(
                    dispatch="basic",
                    profile=profile,
                    carrier=carrier,
                    filename_source=filename_source,
                    normalized_filename=safe_filename,
                    collision_renamed=safe_filename != requested_safe_filename,
                    request_body_size=request_body_size,
                    payload_size=len(payload),
                    file_content_type=file_content_type,
                    sha256=sha256,
                ),
                None,
            )

        except UploadStorageQuotaExceeded as e:
            logger.warning("Basic upload rejected by storage policy")
            response = error_response(
                e.status_code,
                "storage_quota_exceeded",
                "Upload storage quota exceeded",
                field="file",
                details={"scope": "uploads"},
            )
            return add_upload_diagnostics(
                response,
                UploadDiagnostics(
                    dispatch="basic",
                    profile=profile,
                    carrier=carrier,
                    filename_source=filename_source,
                    normalized_filename=safe_filename,
                    collision_renamed=None,
                    request_body_size=request_body_size,
                    payload_size=None,
                    file_content_type=file_content_type,
                    sha256=None,
                ),
                None,
            )

        except Exception:
            logger.error("Basic upload write failed")
            response = error_response(
                500,
                "internal_error",
                "Upload failed",
                field="file",
            )
            return add_upload_diagnostics(
                response,
                UploadDiagnostics(
                    dispatch="basic",
                    profile=profile,
                    carrier=carrier,
                    filename_source=filename_source,
                    normalized_filename=safe_filename,
                    collision_renamed=None,
                    request_body_size=request_body_size,
                    payload_size=None,
                    file_content_type=file_content_type,
                    sha256=None,
                ),
                None,
            )

    @staticmethod
    def _basic_url_filename(path: str, *, multipart: bool) -> str | None:
        """Resolve a URL filename, treating multipart `/uploads` as a collection."""
        normalized = path.rstrip("/") or "/"
        if multipart and normalized == "/uploads":
            return None
        path_name = path.strip("/")
        return Path(path_name).name if path_name else None
