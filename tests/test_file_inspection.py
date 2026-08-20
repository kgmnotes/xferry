"""Behavioral tests for bounded local file inspection."""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest

from xferry.file_inspection import HEAD_READ_LIMIT, inspect_file


@pytest.mark.parametrize(
    ("filename", "content", "mime_type"),
    [
        ("report.bin", b"%PDF-1.7\n", "application/pdf"),
        ("image.bin", b"\x89PNG\r\n\x1a\n", "image/png"),
        ("archive.bin", b"\x1f\x8b\x08\x00", "application/gzip"),
        ("program.bin", b"\x7fELF\x02\x01\x01\x00", "application/x-elf"),
        ("database.bin", b"SQLite format 3\x00", "application/vnd.sqlite3"),
        ("movie.bin", b"\x00\x00\x00\x18ftypisom", "video/mp4"),
        ("dicom.bin", b"\x00" * 128 + b"DICM", "application/dicom"),
    ],
)
def test_inspect_file_recognizes_common_signatures(
    temp_dir: Path,
    filename: str,
    content: bytes,
    mime_type: str,
) -> None:
    path = temp_dir / filename
    path.write_bytes(content)

    result = inspect_file(path)

    assert result.mime_type == mime_type
    assert result.mime_source == "signature"
    assert result.content_state == "recognized"
    assert result.warning is None
    assert result.reasons == ()


@pytest.mark.parametrize(
    ("case", "content", "mime_type"),
    [
        ("pdf", b"%PDF-1.7\n", "application/pdf"),
        ("png", b"\x89PNG\r\n\x1a\n", "image/png"),
        ("jpeg", b"\xff\xd8\xff\xe0", "image/jpeg"),
        ("gif87a", b"GIF87a", "image/gif"),
        ("gif89a", b"GIF89a", "image/gif"),
        ("webp", b"RIFF\x04\x00\x00\x00WEBP", "image/webp"),
        ("bmp", b"BM\x00\x00", "image/bmp"),
        ("tiff-little-endian", b"II*\x00", "image/tiff"),
        ("tiff-big-endian", b"MM\x00*", "image/tiff"),
        ("ico", b"\x00\x00\x01\x00", "image/x-icon"),
        ("zip", b"PK\x05\x06" + b"\x00" * 18, "application/zip"),
        ("gzip", b"\x1f\x8b\x08\x00", "application/gzip"),
        ("bzip2", b"BZh9", "application/x-bzip2"),
        ("xz", b"\xfd7zXZ\x00", "application/x-xz"),
        ("7z", b"7z\xbc\xaf'\x1c", "application/x-7z-compressed"),
        ("rar4", b"Rar!\x1a\x07\x00", "application/vnd.rar"),
        ("rar5", b"Rar!\x1a\x07\x01\x00", "application/vnd.rar"),
        ("tar", b"\x00" * 257 + b"ustar", "application/x-tar"),
        ("ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
        (
            "pe",
            b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00",
            "application/vnd.microsoft.portable-executable",
        ),
        ("elf", b"\x7fELF\x02\x01\x01\x00", "application/x-elf"),
        ("mach-o-32-big", b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
        ("mach-o-64-big", b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
        ("mach-o-32-little", b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
        ("mach-o-64-little", b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
        (
            "mach-o-fat",
            b"\xca\xfe\xba\xbe"
            b"\x00\x00\x00\x01"
            b"\x01\x00\x00\x07"
            b"\x00\x00\x00\x03"
            b"\x00\x00\x00\x1c"
            b"\x00\x00\x00\x04"
            b"\x00\x00\x00\x02"
            b"DATA",
            "application/x-mach-binary",
        ),
        (
            "mach-o-fat-little-endian",
            b"\xbe\xba\xfe\xca"
            b"\x01\x00\x00\x00"
            b"\x07\x00\x00\x01"
            b"\x03\x00\x00\x00"
            b"\x1c\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"DATA",
            "application/x-mach-binary",
        ),
        ("wasm", b"\x00asm\x01\x00\x00\x00", "application/wasm"),
        ("sqlite", b"SQLite format 3\x00", "application/vnd.sqlite3"),
        ("wav", b"RIFF\x04\x00\x00\x00WAVE", "audio/wav"),
        ("avi", b"RIFF\x04\x00\x00\x00AVI ", "video/x-msvideo"),
        ("flac", b"fLaC", "audio/flac"),
        ("ogg", b"OggS", "application/ogg"),
        ("mp3-id3", b"ID3\x04\x00", "audio/mpeg"),
        ("mp3-frame", b"\xff\xfb\x90\x64", "audio/mpeg"),
        ("mp4", b"\x00\x00\x00\x18ftypisom", "video/mp4"),
        ("mov", b"\x00\x00\x00\x14ftypqt  ", "video/quicktime"),
        ("webm", b"\x1aE\xdf\xa3\x42\x82\x84webm", "video/webm"),
        ("mkv", b"\x1aE\xdf\xa3\x42\x82\x88matroska", "video/x-matroska"),
        (
            "iso9660",
            b"\x00" * 32_769 + b"CD001",
            "application/x-iso9660-image",
        ),
        ("dicom", b"\x00" * 128 + b"DICM", "application/dicom"),
    ],
)
def test_inspect_file_protects_every_advertised_signature_family(
    temp_dir: Path,
    case: str,
    content: bytes,
    mime_type: str,
) -> None:
    """Catches dropped variants or offsets in the advertised signature contract."""
    path = temp_dir / f"{case}.bin"
    path.write_bytes(content)

    result = inspect_file(path)

    assert result.mime_type == mime_type
    assert result.mime_source == "signature"
    assert result.content_state == "recognized"
    assert result.warning is None
    assert result.reasons == ()


@pytest.mark.parametrize(
    ("case", "content"),
    [
        ("invalid-zip-prefix", b"PK\x03\x04" + b"\x00" * 252),
        ("invalid-pe-prefix", b"MZ" + b"\x00" * 254),
        ("java-class", b"\xca\xfe\xba\xbe\x00\x00\x00=\x00\x01" + b"\x00" * 246),
        ("generic-riff", b"RIFF\xf8\x00\x00\x00NOPE" + b"\x00" * 244),
        ("generic-ebml", b"\x1aE\xdf\xa3\x42\x86\x81\x01" + b"\x00" * 248),
        ("generic-ftyp", b"\x00\x00\x00\x18ftypzzzz" + b"\x00" * 244),
        ("avif", b"\x00\x00\x00\x18ftypavif" + b"\x00" * 244),
        ("heic", b"\x00\x00\x00\x18ftypheic" + b"\x00" * 244),
        ("invalid-wasm-version", b"\x00asm\x02\x00\x00\x00" + b"\x00" * 248),
    ],
)
def test_inspect_file_does_not_overclaim_ambiguous_prefixes(
    temp_dir: Path,
    case: str,
    content: bytes,
) -> None:
    """Catches ambiguous magic prefixes being promoted to a recognized format."""
    path = temp_dir / f"{case}.bin"
    path.write_bytes(content)

    result = inspect_file(path)

    assert result.mime_type == "application/octet-stream"
    assert result.mime_source != "signature"
    assert result.content_state == "opaque"
    assert result.warning is None
    assert result.reasons == ("unrecognized_binary",)


def test_inspect_file_reports_a_zip_container_without_inferring_an_office_subtype(
    temp_dir: Path,
) -> None:
    path = temp_dir / "document.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("word/document.xml", "<document />")

    result = inspect_file(path)

    assert result.mime_type == "application/zip"
    assert result.mime_source == "signature"
    assert result.content_state == "recognized"


@pytest.mark.parametrize(
    "extension",
    [".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk"],
)
def test_inspect_file_accepts_confirmed_outer_zip_for_every_zip_family_extension(
    temp_dir: Path,
    extension: str,
) -> None:
    """Catches valid ZIP-family names being reported as extension mismatches."""
    path = temp_dir / f"archive{extension}"
    path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)

    result = inspect_file(path)

    assert result.mime_type == "application/zip"
    assert result.mime_source == "signature"
    assert result.content_state == "recognized"
    assert result.warning is None
    assert result.reasons == ()


def test_inspect_file_confirms_zip_with_the_maximum_legal_comment(temp_dir: Path) -> None:
    """Catches a bounded tail that omits EOCD when a ZIP comment is 65,535 bytes."""
    path = temp_dir / "maximum-comment.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("payload.bin", b"x" * HEAD_READ_LIMIT)
        archive.comment = b"c" * 65_535

    result = inspect_file(path)

    assert result.mime_type == "application/zip"
    assert result.mime_source == "signature"
    assert result.content_state == "recognized"
    assert result.warning is None
    assert result.reasons == ()


def test_inspect_file_recognizes_utf8_and_bom_marked_utf16_text(temp_dir: Path) -> None:
    utf8_path = temp_dir / "message.dat"
    utf8_path.write_bytes(("hello, мир\n" * 40).encode("utf-8"))
    utf16_path = temp_dir / "message-utf16.dat"
    utf16_path.write_text("hello" * 80, encoding="utf-16")

    utf8_result = inspect_file(utf8_path)
    utf16_result = inspect_file(utf16_path)

    assert (utf8_result.mime_type, utf8_result.mime_source, utf8_result.content_state) == (
        "text/plain",
        "text",
        "recognized",
    )
    assert (utf16_result.mime_type, utf16_result.mime_source, utf16_result.content_state) == (
        "text/plain",
        "text",
        "recognized",
    )


@pytest.mark.parametrize(
    ("case", "content"),
    [
        ("utf8", b"hello, \xd0\xbc\xd0\xb8\xd1\x80\n" * 20),
        ("utf16-little-endian", b"\xff\xfe" + b"h\x00e\x00l\x00l\x00o\x00\n\x00" * 20),
        ("utf16-big-endian", b"\xfe\xff" + b"\x00h\x00e\x00l\x00l\x00o\x00\n" * 20),
    ],
)
def test_inspect_file_protects_literal_text_encoding_variants(
    temp_dir: Path,
    case: str,
    content: bytes,
) -> None:
    """Catches removal of contracted UTF-8 or BOM-marked UTF-16 recognition."""
    path = temp_dir / f"{case}.dat"
    path.write_bytes(content)

    result = inspect_file(path)

    assert result.mime_type == "text/plain"
    assert result.mime_source == "text"
    assert result.content_state == "recognized"
    assert result.warning is None
    assert result.reasons == ()


def test_inspect_file_does_not_treat_generic_text_as_a_json_extension_mismatch(
    temp_dir: Path,
) -> None:
    path = temp_dir / "metadata.json"
    path.write_text('{"name": "xferry"}\n', encoding="utf-8")

    result = inspect_file(path)

    assert result.mime_type == "text/plain"
    assert result.mime_source == "text"
    assert result.warning is None
    assert result.reasons == ()


def test_inspect_file_uses_extension_only_as_fallback_and_flags_a_mismatch(temp_dir: Path) -> None:
    fallback = temp_dir / "payload.unknownsuffix"
    fallback.write_bytes(b"\x00\xff" * 128)
    declared = temp_dir / "declared.pdf"
    declared.write_bytes(b"\x00\xff" * 128)
    mismatch = temp_dir / "misleading.png"
    mismatch.write_bytes(b"%PDF-1.7\n")

    fallback_result = inspect_file(fallback)
    declared_result = inspect_file(declared)
    mismatch_result = inspect_file(mismatch)

    assert fallback_result.mime_type == "application/octet-stream"
    assert fallback_result.mime_source == "unknown"
    assert fallback_result.content_state == "opaque"
    assert fallback_result.reasons == ("unrecognized_binary",)
    assert declared_result.mime_type == "application/pdf"
    assert declared_result.mime_source == "extension"
    assert declared_result.content_state == "opaque"
    assert mismatch_result.warning == "extension_mismatch"
    assert mismatch_result.reasons == ("extension_mismatch",)


def test_inspect_file_treats_short_and_unavailable_content_as_unknown(temp_dir: Path) -> None:
    short_path = temp_dir / "short.bin"
    short_path.write_bytes(b"\x01\x02")

    short_result = inspect_file(short_path)
    unavailable_result = inspect_file(temp_dir / "missing.bin")

    assert short_result.content_state == "unknown"
    assert short_result.reasons == ("insufficient_data",)
    assert unavailable_result.content_state == "unknown"
    assert unavailable_result.reasons == ("unavailable",)


def test_inspect_file_rejects_symlinks_and_non_regular_entries(temp_dir: Path) -> None:
    target = temp_dir / "target.bin"
    target.write_bytes(b"x" * 256)
    link = temp_dir / "link.bin"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")

    symlink_result = inspect_file(link)
    directory_result = inspect_file(temp_dir)

    assert symlink_result.content_state == "unknown"
    assert symlink_result.reasons == ("unavailable",)
    assert directory_result.content_state == "unknown"
    assert directory_result.reasons == ("unavailable",)


def test_inspect_file_rejects_a_file_replaced_by_a_symlink_before_opening(
    temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = temp_dir / "candidate.bin"
    candidate.write_bytes(b"\x00\xff" * 128)
    target = temp_dir / "target.pdf"
    target.write_bytes(b"%PDF-1.7\n")
    original_lstat = Path.lstat

    def replace_with_symlink_after_check(self: Path) -> object:
        path_status = original_lstat(self)
        if self == candidate:
            candidate.unlink()
            candidate.symlink_to(target)
        return path_status

    monkeypatch.setattr(Path, "lstat", replace_with_symlink_after_check)

    result = inspect_file(candidate)

    assert result.mime_type == "application/octet-stream"
    assert result.content_state == "unknown"
    assert result.reasons == ("unavailable",)


@pytest.mark.skipif(
    not hasattr(os, "O_NONBLOCK") or not hasattr(os, "mkfifo"),
    reason="non-blocking FIFO opens are unavailable on this platform",
)
def test_inspect_file_rejects_a_file_replaced_by_a_fifo_without_blocking(
    temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches the lstat/open race reopening a FIFO with a blocking descriptor."""
    candidate = temp_dir / "candidate.bin"
    candidate.write_bytes(b"\x00\xff" * 128)
    original_open = os.open

    def replace_with_fifo_before_open(path: os.PathLike[str] | str, flags: int) -> int:
        candidate.unlink()
        os.mkfifo(candidate)
        assert flags & os.O_NONBLOCK
        return original_open(path, flags)

    monkeypatch.setattr(os, "open", replace_with_fifo_before_open)

    result = inspect_file(candidate)

    assert result.mime_type == "application/octet-stream"
    assert result.content_state == "unknown"
    assert result.reasons == ("unavailable",)


def test_inspect_file_uses_only_the_bounded_head_and_zip_tail_limits(
    temp_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = temp_dir / "large.bin"
    path.write_bytes(b"\x00\xff" * ((HEAD_READ_LIMIT // 2) + 1))
    original_fdopen = os.fdopen
    read_sizes: list[int] = []

    class CappedReader(io.BufferedReader):
        def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            if size < 0 or size > 65_557:
                raise AssertionError("inspection attempted an unbounded read")
            return super().read(size)

    def capped_fdopen(file_descriptor: int, *args: object, **kwargs: object) -> CappedReader:
        return CappedReader(original_fdopen(file_descriptor, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", capped_fdopen)

    result = inspect_file(path)

    assert read_sizes[0] == 65_536
    assert len(read_sizes) >= 2
    assert all(0 <= size <= 65_557 for size in read_sizes)
    assert result.content_state == "opaque"
    assert result.reasons == ("unrecognized_binary",)


def test_inspect_file_marks_encrypted_suffix_as_a_heuristic_not_a_confirmed_xor(
    temp_dir: Path,
) -> None:
    path = temp_dir / "ciphertext.xor"
    path.write_bytes(b"\x00\xff" * 128)

    result = inspect_file(path)

    assert result.warning == "possible_encrypted_or_packed"
    assert result.reasons == ("encrypted_suffix", "unrecognized_binary")
    assert "xor" not in result.mime_type
