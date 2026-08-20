"""
Base class for HTTP method handlers.
"""

import importlib.resources
import json
import logging
import threading
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, cast
from urllib.parse import unquote

from ..config import HIDDEN_FILES
from ..http import HTTPResponse, error_response, format_file_size
from ..http.utils import resolve_descendant_path
from ..metrics import MetricsCollector
from ..storage import UploadStorageService
from .context import HandlerRuntimeContext, SmuggleTempCoordinator

if TYPE_CHECKING:
    from ..security.keys import ECDHKeyManager
    from .registry import HandlerRegistry

logger = logging.getLogger("xferry")
_ERROR_PATH_DETAIL_MAX_CHARS = 1024


def _safe_package_resource_parts(resource_path: str) -> tuple[str, ...] | None:
    """Return safe package resource path parts, or None when traversal is attempted."""
    decoded_path = unquote(resource_path)
    if (
        not decoded_path
        or "\\" in decoded_path
        or PurePosixPath(decoded_path).is_absolute()
        or PureWindowsPath(decoded_path).is_absolute()
    ):
        return None

    parts = tuple(decoded_path.split("/"))
    if any(
        part in {"", ".", ".."} or PureWindowsPath(part).drive or PureWindowsPath(part).root
        for part in parts
    ):
        return None

    return parts


def _contained_resource_path(path: Path, resource_root: Path) -> Path | None:
    """Resolve *path* only when it remains below *resource_root*."""
    try:
        resolved_path = path.resolve()
        resolved_path.relative_to(resource_root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved_path


def get_package_resource(resource_path: str) -> Path | None:
    """
    Get the path to a package resource.

    Works both in installed-package and dev mode.

    Args:
        resource_path: Path to the resource (e.g. "index.html" or "static/crypto-js.min.js").

    Returns:
        Path to the resource, or None if not found.
    """
    safe_parts = _safe_package_resource_parts(resource_path)
    if safe_parts is None:
        logger.warning("Unsafe package resource path blocked: %s", resource_path)
        return None

    # Try to find in package (installed mode)
    try:
        # Python 3.9+
        files = importlib.resources.files("xferry.data")
        resource_ref = files.joinpath(*safe_parts)

        # Filesystem-backed packages can be contained directly. For
        # importer-backed resources, as_file() may create temporary paths that
        # expire before the response streams, so do not return those here.
        if isinstance(files, Path) and isinstance(resource_ref, Path):
            contained_path = _contained_resource_path(resource_ref, files)
            if contained_path is not None and contained_path.exists():
                return contained_path
    except (
        TypeError,
        FileNotFoundError,
        ModuleNotFoundError,
        AttributeError,
        OSError,
        ValueError,
    ):
        pass

    # Fallback: look relative to xferry/data (dev mode)
    dev_root = Path(__file__).parent.parent / "data"
    dev_path = _contained_resource_path(dev_root.joinpath(*safe_parts), dev_root)
    if dev_path is not None and dev_path.exists():
        return dev_path

    return None


class BaseHandler:
    """Base class with shared logic for handlers."""

    # Attributes set from the server
    root_dir: Path
    upload_dir: Path
    notes_dir: Path
    upload_storage: UploadStorageService
    method_handlers: "HandlerRegistry"
    handler_context: HandlerRuntimeContext
    _temp_smuggle_files: set[str]
    _smuggle_lock: "threading.Lock"
    _ecdh_manager: "ECDHKeyManager | None"
    _metrics: MetricsCollector

    @staticmethod
    def format_size(size: int) -> str:
        """Format file size to human-readable string."""
        return format_file_size(size)

    def _get_upload_storage(self) -> UploadStorageService:
        """Return the shared upload storage service, creating a default for tests."""
        context = getattr(self, "handler_context", None)
        if isinstance(context, HandlerRuntimeContext):
            return context.upload_storage

        storage = getattr(self, "upload_storage", None)
        if isinstance(storage, UploadStorageService):
            return storage

        storage = UploadStorageService(
            self.upload_dir,
            metrics=self._get_metrics_collector(),
        )
        self.upload_storage = storage
        return storage

    def _get_metrics_collector(self) -> MetricsCollector | None:
        """Return the shared collector when this handler host provides one."""
        context = getattr(self, "handler_context", None)
        if isinstance(context, HandlerRuntimeContext):
            return context.metrics

        metrics = getattr(self, "_metrics", None)
        return metrics if isinstance(metrics, MetricsCollector) else None

    def _get_handler_context(self) -> HandlerRuntimeContext:
        """Return the narrow built-in handler context, creating a test fallback."""
        context = getattr(self, "handler_context", None)
        if isinstance(context, HandlerRuntimeContext):
            return context

        registered_paths = getattr(self, "_temp_smuggle_files", None)
        if not isinstance(registered_paths, set):
            registered_paths = set()
            self._temp_smuggle_files = registered_paths

        coordination_lock = getattr(self, "_smuggle_lock", None)
        if coordination_lock is None:
            coordination_lock = threading.Lock()
            self._smuggle_lock = coordination_lock

        context = HandlerRuntimeContext(
            upload_dir=self.upload_dir,
            upload_storage=self._get_upload_storage(),
            metrics=self._get_metrics_collector(),
            smuggle_temp=SmuggleTempCoordinator(
                lock=coordination_lock,
                paths=registered_paths,
            ),
        )
        self.handler_context = context
        return context

    def _get_file_path(self, url_path: str, for_sandbox: bool = False) -> Path | None:
        """
        Convert URL path to filesystem path.

        Args:
            url_path: URL request path
            for_sandbox: If True, restrict access to uploads dir
        """
        if url_path == "/":
            url_path = "/index.html"

        # Strip leading slash and normalize path
        clean_path = url_path.lstrip("/")

        if for_sandbox:
            # Strip uploads/ prefix if present
            if clean_path.startswith("uploads/"):
                clean_path = clean_path[8:]  # len("uploads/") = 8
            elif clean_path == "uploads":
                clean_path = ""
            file_path = resolve_descendant_path(clean_path, self.upload_dir)
            if file_path is None:
                logger.warning(f"Path traversal blocked: {url_path}")
                return None
        else:
            file_path = resolve_descendant_path(clean_path, self.root_dir)
            if file_path is None:
                logger.warning(f"Path traversal blocked: {url_path}")
                return None

            # If file not found in root_dir, try package resources
            # (for index.html and static/)
            if not file_path.exists():
                if clean_path == "index.html" or clean_path.startswith("static/"):
                    package_path = get_package_resource(clean_path)
                    if package_path:
                        return package_path

        return file_path

    def _resolve_safe_path(
        self,
        clean_path: str,
        base_dir: Path,
    ) -> Path | None:
        """
        Resolve a clean (no leading slash) path against base_dir.

        Returns resolved Path if it's inside base_dir, or None on traversal
        or symlink access.
        """
        file_path = resolve_descendant_path(
            clean_path,
            base_dir,
            block_symlinks=True,
        )
        if file_path is None:
            raw_path = base_dir / clean_path if clean_path else base_dir
            if clean_path and raw_path.is_symlink():
                logger.warning("Symlink access blocked: %s", clean_path)
            else:
                logger.warning("Path traversal blocked: %s", clean_path)
            return None

        return file_path

    # Provided by the server
    get_metrics: "Callable[[], dict[str, object]]"

    def _is_hidden_file(self, path: str) -> bool:
        """Return True when any URL path segment is hidden or service-owned."""
        normalized = path.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part]
        return any(
            (part not in {".", ".."} and part.startswith(".")) or part in HIDDEN_FILES
            for part in parts
        )

    def _error_response(
        self,
        status: int,
        message: str,
        *,
        code: str | None = None,
        field: str | None = None,
        details: Mapping[str, object] | None = None,
    ) -> HTTPResponse:
        """Build a canonical JSON error response for handler failures."""
        return error_response(
            status,
            code if code is not None else "http_error",
            message,
            field=field,
            details=details,
        )

    def _not_found(self, path: str) -> HTTPResponse:
        """404 response."""
        return self._error_response(
            404,
            f"File not found: {path}",
            code="resource_not_found",
            field="path",
            details={"path": path[:_ERROR_PATH_DETAIL_MAX_CHARS]},
        )

    def _method_not_allowed(self, method: str) -> HTTPResponse:
        """405 response for unsupported method."""
        allowed_methods = list(self.method_handlers.keys())
        allowed = ", ".join(allowed_methods)
        response = self._error_response(
            405,
            f"Method '{method}' not allowed. Allowed: {allowed}",
            code="method_not_allowed",
            details={"method": method, "allowed_methods": allowed_methods},
        )
        response.set_header("Allow", allowed)
        return response

    def _bad_request(self, message: str) -> HTTPResponse:
        """400 response."""
        return self._error_response(400, message, code="bad_request")

    def _internal_error(self, message: str) -> HTTPResponse:
        """500 response."""
        return self._error_response(500, message, code="internal_error")

    @staticmethod
    def _coerce_json_object(value: object) -> dict[str, object] | None:
        """Return *value* as a JSON object mapping, else ``None``."""
        if not isinstance(value, dict):
            return None
        if not all(isinstance(key, str) for key in value):
            return None
        return cast(dict[str, object], value)

    def _load_json_object(
        self,
        body: bytes,
    ) -> tuple[dict[str, object] | None, HTTPResponse | None]:
        """Decode *body* as UTF-8 JSON and require an object at the top level."""
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, self._bad_request("Invalid JSON body")

        payload_obj = self._coerce_json_object(payload)
        if payload_obj is None:
            return None, self._bad_request("Expected JSON object")

        return payload_obj, None
