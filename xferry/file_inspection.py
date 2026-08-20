"""Bounded, local content inspection for additive INFO metadata."""

from __future__ import annotations

import io
import mimetypes
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

HEAD_READ_LIMIT = 65_536
_TAIL_READ_LIMIT = 65_557
_MIN_BINARY_SAMPLE = 256

MimeSource = Literal["signature", "text", "extension", "unknown"]
ContentState = Literal["recognized", "opaque", "unknown"]
Warning = Literal["possible_encrypted_or_packed", "extension_mismatch"] | None

_ZIP_EXTENSIONS = frozenset(
    {
        ".zip",
        ".docx",
        ".xlsx",
        ".pptx",
        ".odt",
        ".ods",
        ".odp",
        ".jar",
        ".apk",
    }
)


@dataclass(frozen=True)
class FileInspection:
    """A serializable, deterministic assessment of one local file."""

    mime_type: str
    mime_source: MimeSource
    content_state: ContentState
    warning: Warning
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """Return the stable wire-format object used by INFO."""
        return {
            "mime_type": self.mime_type,
            "mime_source": self.mime_source,
            "content_state": self.content_state,
            "warning": self.warning,
            "reasons": list(self.reasons),
        }


class _BoundedZipReader(io.BufferedIOBase):
    """Expose real file offsets while bounding every ZIP probe read."""

    def __init__(self, file_handle: io.BufferedReader) -> None:
        self._file_handle = file_handle

    def read(self, size: int | None = -1) -> bytes:
        bounded_size = (
            min(size, _TAIL_READ_LIMIT) if size is not None and size >= 0 else _TAIL_READ_LIMIT
        )
        return self._file_handle.read(bounded_size)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._file_handle.seek(offset, whence)

    def tell(self) -> int:
        return self._file_handle.tell()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True


def inspect_file(path: Path) -> FileInspection:
    """Inspect a regular, non-symlink file using bounded head/tail samples."""
    try:
        path_status = path.lstat()
        if not stat.S_ISREG(path_status.st_mode):
            return _unknown(path.name, "unavailable")

        open_flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        file_descriptor = os.open(path, open_flags)
        with os.fdopen(file_descriptor, "rb") as file_handle:
            try:
                opened_status = os.fstat(file_handle.fileno())
                current_path_status = path.lstat()
            except OSError:
                return _unknown(path.name, "unavailable")
            if (
                not stat.S_ISREG(opened_status.st_mode)
                or not stat.S_ISREG(current_path_status.st_mode)
                or not _same_file_identity(path_status, opened_status)
                or not _same_file_identity(path_status, current_path_status)
            ):
                return _unknown(path.name, "unavailable")

            head = file_handle.read(HEAD_READ_LIMIT)
            zip_confirmed = False
            if _needs_zip_confirmation(path, head):
                file_handle.seek(0)
                zip_confirmed = zipfile.is_zipfile(_BoundedZipReader(file_handle))
    except (OSError, ValueError):
        return _unknown(path.name, "unavailable")

    return _classify(path.name, head, zip_confirmed)


def _classify(filename: str, head: bytes, zip_confirmed: bool) -> FileInspection:
    encrypted_suffix = Path(filename).suffix.lower() in {".enc", ".xor"}
    signature_mime = _signature_mime(head)
    zip_mime = _zip_mime(filename, head, zip_confirmed)
    mime_type = zip_mime or signature_mime
    mime_source: MimeSource = "signature" if mime_type else "unknown"
    content_state: ContentState = "recognized" if mime_type else "unknown"
    base_reason: str | None = None

    if mime_type is None and _is_text(head):
        mime_type = "text/plain"
        mime_source = "text"
        content_state = "recognized"
    elif mime_type is None and len(head) >= _MIN_BINARY_SAMPLE:
        extension_mime = _extension_mime(filename)
        if extension_mime is not None:
            mime_type = extension_mime
            mime_source = "extension"
        else:
            mime_type = "application/octet-stream"
        content_state = "opaque"
        base_reason = "unrecognized_binary"
    elif mime_type is None:
        mime_type = "application/octet-stream"
        content_state = "unknown"
        base_reason = "insufficient_data"

    extension_mime = _extension_mime(filename)
    zip_family_match = (
        mime_type == "application/zip" and Path(filename).suffix.lower() in _ZIP_EXTENSIONS
    )
    mismatch = (
        mime_source == "signature"
        and extension_mime is not None
        and extension_mime != "application/octet-stream"
        and not zip_family_match
        and not _mime_types_match(mime_type, extension_mime)
    )
    reasons: list[str] = []
    if encrypted_suffix:
        reasons.append("encrypted_suffix")
    if mismatch:
        reasons.append("extension_mismatch")
    if base_reason is not None:
        reasons.append(base_reason)

    warning: Warning = None
    if encrypted_suffix:
        warning = "possible_encrypted_or_packed"
    elif mismatch:
        warning = "extension_mismatch"

    return FileInspection(mime_type, mime_source, content_state, warning, tuple(reasons))


def _unknown(filename: str, reason: str) -> FileInspection:
    encrypted_suffix = Path(filename).suffix.lower() in {".enc", ".xor"}
    reasons = ("encrypted_suffix", reason) if encrypted_suffix else (reason,)
    warning: Warning = "possible_encrypted_or_packed" if encrypted_suffix else None
    return FileInspection("application/octet-stream", "unknown", "unknown", warning, reasons)


def _needs_zip_confirmation(path: Path, head: bytes) -> bool:
    if path.suffix.lower() in _ZIP_EXTENSIONS or head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return True
    return head.startswith(b"MZ") or (len(head) >= _MIN_BINARY_SAMPLE and not _is_text(head))


def _zip_mime(filename: str, head: bytes, zip_confirmed: bool) -> str | None:
    if not _needs_zip_confirmation(Path(filename), head) or not zip_confirmed:
        return None
    return "application/zip"


def _same_file_identity(before_open: os.stat_result, opened: os.stat_result) -> bool:
    """Ensure the descriptor still refers to the file validated before opening."""
    return (before_open.st_dev, before_open.st_ino) == (opened.st_dev, opened.st_ino)


def _signature_mime(head: bytes) -> str | None:
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"BM"):
        return "image/bmp"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    if head.startswith(b"\x00\x00\x01\x00"):
        return "image/x-icon"
    if head.startswith(b"\x1f\x8b\x08"):
        return "application/gzip"
    if head.startswith(b"BZh"):
        return "application/x-bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "application/x-xz"
    if head.startswith(b"7z\xbc\xaf'\x1c"):
        return "application/x-7z-compressed"
    if head.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "application/vnd.rar"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "application/x-tar"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage"
    if _is_pe(head):
        return "application/vnd.microsoft.portable-executable"
    if head.startswith(b"\x7fELF"):
        return "application/x-elf"
    if head.startswith(
        (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
    ) or _is_mach_fat(head):
        return "application/x-mach-binary"
    if head.startswith(b"\x00asm\x01\x00\x00\x00"):
        return "application/wasm"
    if head.startswith(b"SQLite format 3\x00"):
        return "application/vnd.sqlite3"
    if len(head) >= 12 and head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "audio/wav"
    if len(head) >= 12 and head.startswith(b"RIFF") and head[8:12] == b"AVI ":
        return "video/x-msvideo"
    if head.startswith(b"fLaC"):
        return "audio/flac"
    if head.startswith(b"OggS"):
        return "application/ogg"
    if head.startswith(b"ID3") or head.startswith((b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        return "audio/mpeg"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand == b"qt  ":
            return "video/quicktime"
        if brand in {
            b"3g2a",
            b"3gp4",
            b"3gp5",
            b"M4V ",
            b"MSNV",
            b"avc1",
            b"dash",
            b"iso2",
            b"iso3",
            b"iso4",
            b"iso5",
            b"iso6",
            b"isom",
            b"mp41",
            b"mp42",
        }:
            return "video/mp4"
    if head.startswith(b"\x1aE\xdf\xa3"):
        doc_type = _ebml_doc_type(head[:128])
        if doc_type == b"webm":
            return "video/webm"
        if doc_type == b"matroska":
            return "video/x-matroska"
    if len(head) >= 32774 and head[32769:32774] == b"CD001":
        return "application/x-iso9660-image"
    if len(head) >= 132 and head[128:132] == b"DICM":
        return "application/dicom"
    return None


def _is_pe(head: bytes) -> bool:
    if len(head) < 64 or not head.startswith(b"MZ"):
        return False
    pe_offset = int.from_bytes(head[60:64], "little")
    return pe_offset >= 64 and head[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def _is_mach_fat(head: bytes) -> bool:
    byte_order: Literal["big", "little"] = (
        "big" if head.startswith(b"\xca\xfe\xba\xbe") else "little"
    )
    if byte_order == "little" and not head.startswith(b"\xbe\xba\xfe\xca"):
        return False
    if len(head) < 8:
        return False

    architecture_count = int.from_bytes(head[4:8], byte_order)
    architecture_table_end = 8 + architecture_count * 20
    if not 1 <= architecture_count <= 64 or len(head) < architecture_table_end:
        return False

    known_cpu_types = {
        1,
        6,
        7,
        8,
        10,
        11,
        12,
        14,
        15,
        18,
        0x01000007,
        0x0100000C,
        0x0200000C,
    }
    for index in range(architecture_count):
        offset = 8 + index * 20
        cpu_type = int.from_bytes(head[offset : offset + 4], byte_order)
        slice_offset = int.from_bytes(head[offset + 8 : offset + 12], byte_order)
        slice_size = int.from_bytes(head[offset + 12 : offset + 16], byte_order)
        alignment = int.from_bytes(head[offset + 16 : offset + 20], byte_order)
        if (
            cpu_type not in known_cpu_types
            or slice_offset < architecture_table_end
            or slice_size == 0
            or alignment > 63
        ):
            return False
    return True


def _ebml_doc_type(head: bytes) -> bytes | None:
    element_offset = head.find(b"\x42\x82")
    if element_offset < 0 or element_offset + 3 > len(head):
        return None

    size_offset = element_offset + 2
    first_size_byte = head[size_offset]
    width = 1
    marker = 0x80
    while width <= 8 and not first_size_byte & marker:
        width += 1
        marker >>= 1
    if width > 8 or size_offset + width > len(head):
        return None

    size = first_size_byte & (marker - 1)
    for value in head[size_offset + 1 : size_offset + width]:
        size = (size << 8) | value
    value_offset = size_offset + width
    if size > 32 or value_offset + size > len(head):
        return None
    return head[value_offset : value_offset + size]


def _is_text(head: bytes) -> bool:
    if len(head) < 16:
        return False
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            head.decode("utf-16")
        except UnicodeDecodeError:
            return False
        return True
    try:
        decoded = head.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    if "\x00" in decoded:
        return False
    printable = sum(character.isprintable() or character.isspace() for character in decoded)
    return bool(decoded) and printable / len(decoded) >= 0.85


def _extension_mime(filename: str) -> str | None:
    extension_mime, _encoding = mimetypes.guess_type(filename, strict=False)
    return extension_mime


def _mime_types_match(left: str, right: str) -> bool:
    aliases = {
        frozenset({"application/zip", "application/x-zip-compressed"}),
        frozenset({"image/x-icon", "image/vnd.microsoft.icon"}),
    }
    return left == right or frozenset({left, right}) in aliases
