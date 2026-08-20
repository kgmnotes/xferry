"""
HTTP utilities.
"""

import secrets
from datetime import datetime
from pathlib import Path

from ..storage import UploadStorageService


def parse_query_string(path: str) -> tuple[str, dict[str, str]]:
    """
    Parse query string from URL path.

    Args:
        path: URL path with possible query string

    Returns:
        Tuple of (clean path, params dict)
    """
    if "?" not in path:
        return path, {}

    clean_path, query = path.split("?", 1)
    params: dict[str, str] = {}

    for param in query.split("&"):
        if "=" in param:
            key, value = param.split("=", 1)
            params[key] = value
        else:
            params[param] = ""

    return clean_path, params


def sanitize_filename(filename: str, allow_cyrillic: bool = True) -> str:
    """
    Sanitize filename by removing unsafe characters.

    Args:
        filename: Original filename
        allow_cyrillic: Allow Cyrillic characters

    Returns:
        Safe filename
    """
    safe_chars = "._- "

    def is_safe_char(c: str) -> bool:
        if c.isalnum():
            return True
        if c in safe_chars:
            return True
        # Cyrillic (U+0400 - U+04FF)
        if allow_cyrillic and "\u0400" <= c <= "\u04ff":
            return True
        return False

    safe_filename = "".join(c for c in filename if is_safe_char(c))

    # Collapse consecutive dots (protection against ".." in paths)
    while ".." in safe_filename:
        safe_filename = safe_filename.replace("..", ".")

    safe_filename = safe_filename.strip()

    if not safe_filename:
        safe_filename = f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    return safe_filename


def format_file_size(size: int) -> str:
    """
    Format file size to human-readable string.

    Args:
        size: Size in bytes

    Returns:
        Formatted string (e.g. "1.5 MB")
    """
    fsize = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if fsize < 1024:
            return f"{fsize:.1f} {unit}"
        fsize /= 1024
    return f"{fsize:.1f} TB"


def resolve_descendant_path(
    clean_path: str,
    base_dir: Path,
    *,
    block_symlinks: bool = False,
) -> Path | None:
    """
    Resolve *clean_path* under *base_dir* and reject traversal escapes.

    Args:
        clean_path: Relative path without a leading slash
        base_dir: Directory the resolved path must remain under
        block_symlinks: Reject when the direct target path is a symlink

    Returns:
        Resolved descendant path, or None when blocked
    """
    resolved_base = base_dir.resolve()

    if clean_path:
        raw_path = base_dir / clean_path
        file_path = raw_path.resolve()
    else:
        raw_path = base_dir
        file_path = resolved_base

    try:
        file_path.relative_to(resolved_base)
    except ValueError:
        return None

    if block_symlinks and clean_path and raw_path.is_symlink():
        return None

    return file_path


def get_safe_path(url_path: str, base_dir: Path, sandbox_dir: Path | None = None) -> Path | None:
    """
    Safely convert URL path to filesystem path.

    Args:
        url_path: URL request path
        base_dir: Base directory
        sandbox_dir: Sandbox directory (if None, base_dir is used)

    Returns:
        File path or None if path is invalid (path traversal)
    """
    # Strip leading slash and normalize path
    clean_path = url_path.lstrip("/")

    if sandbox_dir:
        # In sandbox mode, restrict to sandbox_dir
        if clean_path.startswith("uploads/"):
            clean_path = clean_path[8:]  # len("uploads/") = 8
        return resolve_descendant_path(clean_path, sandbox_dir)

    return resolve_descendant_path(clean_path, base_dir)


def _filename_with_unique_suffix(file_path: Path) -> Path:
    """Return *file_path* with a random suffix inserted before the extension."""
    unique_suffix = secrets.token_hex(4)
    name_parts = file_path.name.rsplit(".", 1)

    if len(name_parts) == 2:
        new_name = f"{name_parts[0]}_{unique_suffix}.{name_parts[1]}"
    else:
        new_name = f"{file_path.name}_{unique_suffix}"

    return file_path.parent / new_name


def make_unique_filename(file_path: Path) -> Path:
    """
    Generate unique filename if file already exists.

    Args:
        file_path: Original file path

    Returns:
        Path with unique name
    """
    if not file_path.exists():
        return file_path

    return _filename_with_unique_suffix(file_path)


def write_unique_file_exclusive(
    file_path: Path,
    data: bytes,
    *,
    max_attempts: int = 64,
) -> Path:
    """Write *data* to a unique destination with atomic no-clobber publish.

    The first attempt uses *file_path*. Collisions retry with random suffixes.
    Data is written to a same-directory hidden temp file, then published with a
    hard link so concurrent writers cannot observe a partial final file or
    overwrite each other.
    """
    return UploadStorageService(file_path.parent).publish_bytes(
        file_path,
        data,
        max_attempts=max_attempts,
    )
