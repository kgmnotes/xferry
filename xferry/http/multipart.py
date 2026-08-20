"""Strict, byte-preserving multipart/form-data parsing for uploads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.headerregistry import BaseHeader
from email.message import Message
from email.parser import BytesHeaderParser
from email.policy import default as email_policy

_BOUNDARY_RE = re.compile(r"^[0-9A-Za-z'()+_,./:=?\- ]{1,70}$")


class MultipartError(ValueError):
    """Raised when a multipart upload is malformed or ambiguous."""


@dataclass(frozen=True)
class MultipartFile:
    """One top-level multipart file part."""

    field_name: str
    filename: str
    content_type: str
    payload: bytes


@dataclass(frozen=True)
class MultipartPart:
    """One strict top-level multipart/form-data part."""

    field_name: str
    filename: str | None
    content_type: str
    payload: bytes


def validate_multipart_part_headers(part: Message) -> None:
    """Validate singleton MIME headers before interpreting a multipart part."""
    content_dispositions = part.get_all("Content-Disposition", [])
    if len(content_dispositions) != 1:
        if content_dispositions:
            raise MultipartError("Duplicate multipart Content-Disposition")
        raise MultipartError("Multipart part is missing Content-Disposition")

    content_types = part.get_all("Content-Type", [])
    if len(content_types) > 1:
        raise MultipartError("Duplicate multipart Content-Type")

    transfer_encodings = part.get_all("Content-Transfer-Encoding", [])
    if len(transfer_encodings) > 1:
        raise MultipartError("Duplicate multipart Content-Transfer-Encoding")
    if transfer_encodings and transfer_encodings[0].strip().lower() not in {
        "binary",
        "8bit",
    }:
        raise MultipartError("Unsupported Content-Transfer-Encoding")


def _content_type_message(content_type: str) -> Message:
    message = Message(policy=email_policy)
    try:
        content_type.encode("latin-1")
        message["Content-Type"] = content_type
    except (UnicodeEncodeError, ValueError) as exc:
        raise MultipartError("Invalid multipart Content-Type") from exc
    header = message["Content-Type"]
    if (
        not isinstance(header, BaseHeader)
        or header.defects
        or message.get_content_type().lower() != "multipart/form-data"
    ):
        raise MultipartError("Invalid multipart Content-Type")
    return message


def _next_delimiter(body: bytes, delimiter: bytes, start: int) -> int:
    marker = b"\r\n" + delimiter
    candidate = body.find(marker, start)
    while candidate >= 0:
        suffix = body[candidate + len(marker) : candidate + len(marker) + 2]
        if suffix in {b"\r\n", b"--"}:
            return candidate
        candidate = body.find(marker, candidate + len(marker))
    return -1


def _parse_part(part_blob: bytes) -> MultipartPart:
    if b"\r\n\r\n" not in part_blob:
        raise MultipartError("Malformed multipart part")
    raw_headers, payload = part_blob.split(b"\r\n\r\n", 1)
    header_lines = raw_headers.split(b"\r\n")
    if not header_lines or any(
        not line
        or line[:1] in {b" ", b"\t"}
        or b":" not in line
        or not line.split(b":", 1)[0].strip()
        for line in header_lines
    ):
        raise MultipartError("Malformed multipart headers")

    try:
        part = BytesHeaderParser(policy=email_policy).parsebytes(raw_headers + b"\r\n\r\n")
    except ValueError as exc:
        raise MultipartError("Malformed multipart headers") from exc
    if part.defects:
        raise MultipartError("Malformed multipart headers")

    validate_multipart_part_headers(part)

    if part.get_content_type().lower().startswith("multipart/"):
        raise MultipartError("Nested multipart parts are not supported")

    if part.get_content_disposition() != "form-data":
        raise MultipartError("Invalid multipart Content-Disposition")
    field_name = part.get_param("name", header="content-disposition")
    if not isinstance(field_name, str) or not field_name:
        raise MultipartError("Multipart part is missing a field name")

    filename = part.get_param("filename", header="content-disposition")
    if filename is not None and not isinstance(filename, str):
        raise MultipartError("Invalid multipart filename")

    content_type = part.get("Content-Type")
    file_content_type = (
        part.get_content_type().lower() if content_type else "application/octet-stream"
    )
    return MultipartPart(
        field_name=field_name,
        filename=filename,
        content_type=file_content_type,
        payload=payload,
    )


def parse_multipart_form_data(content_type: str, body: bytes) -> tuple[MultipartPart, ...]:
    """Return all top-level parts in a strict multipart/form-data body."""
    message = _content_type_message(content_type)
    boundary = message.get_boundary()
    if not boundary:
        raise MultipartError("Multipart boundary is required")
    if not _BOUNDARY_RE.fullmatch(boundary) or boundary.endswith(" "):
        raise MultipartError("Invalid multipart boundary")
    try:
        delimiter = b"--" + boundary.encode("ascii")
    except UnicodeEncodeError as exc:
        raise MultipartError("Invalid multipart boundary") from exc

    if not body.startswith(delimiter):
        raise MultipartError("Malformed multipart body")

    parts: list[MultipartPart] = []
    position = len(delimiter)
    while True:
        suffix = body[position : position + 2]
        if suffix == b"--":
            trailer = body[position + 2 :]
            if trailer not in {b"", b"\r\n"}:
                raise MultipartError("Malformed multipart closing boundary")
            break
        if suffix != b"\r\n":
            raise MultipartError("Malformed multipart boundary")

        part_start = position + 2
        part_end = _next_delimiter(body, delimiter, part_start)
        if part_end < 0:
            raise MultipartError("Multipart closing boundary is required")
        parts.append(_parse_part(body[part_start:part_end]))
        position = part_end + 2 + len(delimiter)

    return tuple(parts)


def parse_single_file_multipart(content_type: str, body: bytes) -> MultipartFile:
    """Return the only top-level file part in a strict multipart body."""
    files = [
        part for part in parse_multipart_form_data(content_type, body) if part.filename is not None
    ]
    if len(files) != 1:
        raise MultipartError("Exactly one file part is required")
    if not files[0].payload:
        raise MultipartError("Multipart file payload is empty")
    assert files[0].filename is not None
    return MultipartFile(
        field_name=files[0].field_name,
        filename=files[0].filename,
        content_type=files[0].content_type,
        payload=files[0].payload,
    )
