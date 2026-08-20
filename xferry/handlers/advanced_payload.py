"""Canonical Advanced upload payload carriers and bounded decoding."""

from __future__ import annotations

import base64
import binascii
import json
import re
import zlib
from dataclasses import dataclass
from typing import Literal
from xml.etree import ElementTree

from defusedxml import ElementTree as DefusedElementTree  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from ..http import HTTPRequest
from ..http.multipart import MultipartError, parse_multipart_form_data

AdvancedCarrier = Literal["body", "headers", "query", "cookies", "path"]
AdvancedBodyProfile = Literal[
    "json",
    "form",
    "xml",
    "multipart-encoded",
    "multipart-binary",
    "text",
    "raw",
    "header",
    "query",
    "cookies",
    "path",
]
AdvancedEncoding = Literal[
    "raw",
    "base64",
    "base64url",
    "hex",
    "percent",
    "gzip-base64",
    "gzip-base64url",
]
AdvancedEncryption = Literal["none", "xor", "aes"]
FilenameSource = Literal["body", "part", "header", "query", "cookie", "path", "generated"]

ADVANCED_UPLOAD_DECODED_SIZE_LIMIT = 16 * 1024 * 1024
ADVANCED_UPLOAD_HEADER_DATA_LIMIT = 64 * 1024
ADVANCED_UPLOAD_URL_DATA_LIMIT = 16 * 1024
_GZIP_DECOMPRESS_CHUNK_SIZE = 64 * 1024
_GZIP_WBITS = zlib.MAX_WBITS | 16

_SUPPORTED_MEDIA = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/*+xml",
    "text/plain",
    "application/octet-stream",
]
_ENCODINGS = {
    "raw",
    "base64",
    "base64url",
    "hex",
    "percent",
    "gzip-base64",
    "gzip-base64url",
}
_ENCRYPTIONS = {"none", "xor", "aes"}
_FIELD_NAMES = {
    "data",
    "encryption",
    "key",
    "key_is_base64",
    "name",
    "hmac",
    "encoding",
    "method_override",
}
_TEXT_BOOL_FIELDS = {"key_is_base64"}
_HEADER_FIELDS = {
    "x-xferry-data": "data",
    "x-xferry-encryption": "encryption",
    "x-xferry-key": "key",
    "x-xferry-key-is-base64": "key_is_base64",
    "x-xferry-name": "name",
    "x-xferry-hmac": "hmac",
    "x-xferry-encoding": "encoding",
    "x-xferry-method-override": "method_override",
}
_HEADER_METADATA = set(_HEADER_FIELDS) - {"x-xferry-data"}
_HEADER_CHUNK_RE = re.compile(r"^x-xferry-data-([0-9]+)$")
_QUERY_CHUNK_RE = re.compile(r"^data_([0-9]+)$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_LOWER_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_ASCII_RE = re.compile(r"^[\x21-\x7e]+$")
_PERCENT_TRIPLET_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_LEGACY_DATA_FIELD_RE = re.compile(r"^(?:d[-_]?[0-9]+|data-?[0-9]+)$")
_LEGACY_HEADER_DATA_CHUNK_RE = re.compile(r"^x-d-[0-9]+$")

# Rejection-only literals for removed Advanced compatibility spellings.
# These entries are never accepted as aliases; they exist only to provide
# canonical invalid_field responses and to make the clean break statically
# auditable without string concatenation or compatibility lookup tables.
_LEGACY_ADVANCED_REJECTION_ONLY_FIELDS = {
    "headers": (
        ("X-D", "X-D"),
        ("X-D-0", "X-D-0"),
        ("X-E", "X-E"),
        ("X-K", "X-K"),
        ("X-Kb64", "X-Kb64"),
        ("X-N", "X-N"),
        ("X-H", "X-H"),
        ("X-Encoding", "X-Encoding"),
        ("X-HTTP-Method-Override", "X-HTTP-Method-Override"),
        ("X-Payload-In-Path", "X-Payload-In-Path"),
    ),
    "fields": (
        ("d", "data"),
        ("d0", "data"),
        ("d-0", "data"),
        ("d_0", "data"),
        ("data0", "data"),
        ("data-0", "data"),
        ("e", "encryption"),
        ("k", "key"),
        ("kb64", "key_is_base64"),
        ("n", "name"),
        ("h", "hmac"),
        ("enc", "encoding"),
        ("_method", "method_override"),
        ("path_payload", "path_payload"),
        ("path_filename", "path_filename"),
    ),
    "cookies": (
        ("xf_d", "xf_d"),
        ("xf_data", "xf_data"),
        ("xf_e", "xf_e"),
        ("xf_k", "xf_k"),
        ("xf_kb64", "xf_kb64"),
        ("xf_n", "xf_n"),
        ("xf_name", "xf_name"),
        ("xf_h", "xf_h"),
        ("xf_hmac", "xf_hmac"),
        ("xf_encoding", "xf_encoding"),
        ("xf_enc", "xf_enc"),
        ("xf_method", "xf_method"),
    ),
}
_HEADER_LEGACY_REJECTIONS = {
    name.lower(): field for name, field in _LEGACY_ADVANCED_REJECTION_ONLY_FIELDS["headers"]
}
_FIELD_LEGACY_REJECTIONS = dict(_LEGACY_ADVANCED_REJECTION_ONLY_FIELDS["fields"])
_COOKIE_LEGACY_REJECTIONS = dict(_LEGACY_ADVANCED_REJECTION_ONLY_FIELDS["cookies"])


@dataclass(frozen=True, slots=True)
class CanonicalAdvancedPayload:
    """Closed Advanced upload payload model after carrier grammar validation."""

    carrier: AdvancedCarrier
    body_profile: AdvancedBodyProfile
    encoded_data: str | None
    raw_data: bytes | None
    encryption: AdvancedEncryption
    key: str | None
    key_is_base64: bool
    name: str | None
    hmac: str | None
    encoding: AdvancedEncoding | None
    method_override: str | None
    content_type: str
    filename_source: FilenameSource


@dataclass(frozen=True, slots=True)
class FieldOccurrence:
    """One occurrence-preserved canonical field."""

    name: str
    value: object
    wire_order: int
    display_name: str


class AdvancedPayloadError(Exception):
    """Safe canonical Advanced upload failure."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        field: str | None = None,
        details: dict[str, object] | None = None,
        metric_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.field = field
        self.details = details or {}
        self.metric_reason = metric_reason


class AdvancedPayloadDecodedTooLarge(Exception):
    """Raised when decoded data exceeds its configured cap."""


class _DuplicateJSONMember(ValueError):
    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def _error(
    status: int,
    code: str,
    message: str,
    *,
    field: str | None = None,
    details: dict[str, object] | None = None,
    metric_reason: str | None = None,
) -> AdvancedPayloadError:
    return AdvancedPayloadError(
        status,
        code,
        message,
        field=field,
        details=details,
        metric_reason=metric_reason,
    )


def _invalid_field(field: str | None) -> AdvancedPayloadError:
    return _error(400, "invalid_field", "Advanced upload field is invalid", field=field)


def _missing_field(field: str) -> AdvancedPayloadError:
    message = (
        "Advanced upload payload is required"
        if field == "data"
        else "Advanced upload field is required"
    )
    return _error(400, "missing_field", message, field=field)


def _unsupported_media() -> AdvancedPayloadError:
    return _error(
        415,
        "unsupported_media_type",
        "Unsupported advanced upload media type",
        field="Content-Type",
        details={"supported": list(_SUPPORTED_MEDIA)},
    )


def _payload_too_large(limit: int, *, scope: str) -> AdvancedPayloadError:
    return _error(
        413,
        "payload_too_large",
        "Advanced upload payload is too large",
        field="data",
        details={"scope": scope, "limit_bytes": limit},
        metric_reason=f"{scope}_too_large",
    )


def _content_type_base(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def _content_type_params(value: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for item in value.split(";")[1:]:
        if "=" not in item:
            raise _unsupported_media()
        key, raw_value = item.split("=", 1)
        key = key.strip().lower()
        raw_value = raw_value.strip()
        if not key or not raw_value:
            raise _unsupported_media()
        if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] == '"':
            raw_value = raw_value[1:-1]
        params[key] = raw_value
    return params


def _is_xml_media(base: str) -> bool:
    return base in {"application/xml", "text/xml", "application/soap+xml"} or base.endswith("+xml")


def _strict_percent_decode_bytes(raw: str, *, plus_to_space: bool) -> bytes:
    output = bytearray()
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "%":
            if index + 2 >= len(raw) or not re.fullmatch(
                r"[0-9A-Fa-f]{2}",
                raw[index + 1 : index + 3],
            ):
                raise _invalid_field("data")
            output.append(int(raw[index + 1 : index + 3], 16))
            index += 3
            continue
        if char == "+" and plus_to_space:
            output.append(0x20)
        else:
            output.extend(char.encode("utf-8"))
        index += 1
    return bytes(output)


def _strict_percent_decode_text(raw: str, *, plus_to_space: bool) -> str:
    try:
        return _strict_percent_decode_bytes(raw, plus_to_space=plus_to_space).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _invalid_field("data") from exc


def _parse_query_pairs(raw_query: str) -> list[tuple[str, str]]:
    if not raw_query:
        return []
    pairs: list[tuple[str, str]] = []
    for raw_part in raw_query.split("&"):
        raw_key, separator, raw_value = raw_part.partition("=")
        if not separator:
            raw_value = ""
        key = _strict_percent_decode_text(raw_key, plus_to_space=True)
        value = _strict_percent_decode_text(raw_value, plus_to_space=True)
        pairs.append((key, value))
    return pairs


def _header_value_after_separator(raw_value: str, *, field: str) -> str:
    if raw_value.startswith("\t"):
        raise _invalid_field(field)
    if raw_value.startswith(" "):
        raw_value = raw_value[1:]
    return raw_value


def _canonical_advanced_header_value(
    *,
    display_name: str,
    raw_value: str,
    normalized_value: str,
) -> str:
    value = _header_value_after_separator(raw_value, field=display_name)
    if value != normalized_value or value != value.strip(" \t"):
        raise _invalid_field(display_name)
    return value


def _cookie_pairs(request: HTTPRequest) -> list[tuple[str, str]]:
    values = request.get_raw_header_values("cookie") or request.get_header_values("cookie")
    pairs: list[tuple[str, str]] = []
    for header in values:
        header_value = _header_value_after_separator(header, field="Cookie")
        for item in header_value.split(";"):
            if "=" not in item:
                continue
            raw_key, raw_value = item.split("=", 1)
            key = raw_key.strip()
            try:
                value = _strict_percent_decode_text(raw_value, plus_to_space=False)
            except AdvancedPayloadError as exc:
                raise _invalid_field(key or "cookie") from exc
            if key.startswith(("xferry_", "xf_")) and value != value.strip(" \t"):
                raise _invalid_field(key)
            pairs.append((key, value))
    return pairs


def _legacy_header_field(name: str) -> str | None:
    lower = name.lower()
    if _LEGACY_HEADER_DATA_CHUNK_RE.fullmatch(lower):
        return name
    return _HEADER_LEGACY_REJECTIONS.get(lower)


def _legacy_field_rejection(name: str) -> str | None:
    mapped = _FIELD_LEGACY_REJECTIONS.get(name)
    if mapped is not None:
        return mapped
    if _LEGACY_DATA_FIELD_RE.fullmatch(name):
        return "data"
    return None


def _json_field_for_invalid(name: str) -> str:
    mapped = _legacy_field_rejection(name)
    return mapped or name


def _header_scan(request: HTTPRequest) -> tuple[list[FieldOccurrence], bool, bool]:
    occurrences: list[FieldOccurrence] = []
    has_payload = False
    has_metadata = False
    raw_index_by_name: dict[str, int] = {}
    for wire_order, (original_name, value) in enumerate(request.header_occurrences):
        lower = original_name.lower()
        raw_values = request.get_raw_header_values(original_name)
        raw_index = raw_index_by_name.get(lower, 0)
        raw_index_by_name[lower] = raw_index + 1
        raw_value = raw_values[raw_index] if raw_index < len(raw_values) else value
        if "\r\n" in raw_value:
            raise _invalid_field(original_name)
        legacy_field = _legacy_header_field(original_name)
        if legacy_field is not None:
            raise _invalid_field(legacy_field)
        field_name = _HEADER_FIELDS.get(lower)
        chunk_match = _HEADER_CHUNK_RE.fullmatch(lower)
        if field_name is None and chunk_match is None:
            if lower in {"x-xferry-advanced-session", "x-xferry-no-gzip"}:
                continue
            if lower.startswith("x-xferry-"):
                raise _invalid_field(original_name)
            continue
        value = _canonical_advanced_header_value(
            display_name=original_name,
            raw_value=raw_value,
            normalized_value=value,
        )
        if "," in value:
            raise _invalid_field(original_name)
        if chunk_match is not None:
            field_name = f"data_{chunk_match.group(1)}"
            has_payload = True
        elif field_name == "data":
            has_payload = True
        else:
            assert field_name is not None
            has_metadata = True
        occurrences.append(
            FieldOccurrence(
                name=field_name,
                value=value,
                wire_order=wire_order,
                display_name=original_name,
            )
        )
    return occurrences, has_payload, has_metadata


def _query_scan(request: HTTPRequest) -> tuple[list[FieldOccurrence], bool, bool]:
    occurrences: list[FieldOccurrence] = []
    has_payload = False
    has_metadata = False
    for wire_order, (key, value) in enumerate(_parse_query_pairs(request.query_string)):
        legacy = _legacy_field_rejection(key)
        if legacy is not None:
            raise _invalid_field(legacy)
        chunk_match = _QUERY_CHUNK_RE.fullmatch(key)
        if key == "data" or chunk_match is not None:
            has_payload = True
            name = key
        elif key in _FIELD_NAMES - {"data"}:
            has_metadata = True
            name = key
        else:
            name = key
        occurrences.append(
            FieldOccurrence(name=name, value=value, wire_order=wire_order, display_name=key)
        )
    return occurrences, has_payload, has_metadata


def _cookie_scan(request: HTTPRequest) -> tuple[list[FieldOccurrence], bool, bool]:
    cookie_map = {
        "xferry_data": "data",
        "xferry_encryption": "encryption",
        "xferry_key": "key",
        "xferry_key_is_base64": "key_is_base64",
        "xferry_name": "name",
        "xferry_hmac": "hmac",
        "xferry_encoding": "encoding",
        "xferry_method_override": "method_override",
    }
    occurrences: list[FieldOccurrence] = []
    has_payload = False
    has_metadata = False
    for wire_order, (key, value) in enumerate(_cookie_pairs(request)):
        legacy = _COOKIE_LEGACY_REJECTIONS.get(key)
        if legacy is not None or key.startswith("xf_"):
            raise _invalid_field(legacy or key)
        if key.startswith("xferry_") and key not in cookie_map:
            raise _invalid_field(key)
        field_name = cookie_map.get(key)
        if field_name is None:
            continue
        if field_name == "data":
            has_payload = True
        else:
            has_metadata = True
        occurrences.append(
            FieldOccurrence(
                name=field_name,
                value=value,
                wire_order=wire_order,
                display_name=key,
            )
        )
    return occurrences, has_payload, has_metadata


def _payload_path_prefix(request: HTTPRequest) -> str | None:
    dispatch = request.advanced_session_dispatch
    if dispatch is None:
        return None
    prefix = dispatch.session.prefix
    return "/_payload" if prefix == "/" else prefix.rstrip("/") + "/_payload"


def _is_path_candidate(request: HTTPRequest) -> bool:
    payload_prefix = _payload_path_prefix(request)
    if payload_prefix is None:
        return False
    return request.raw_path == payload_prefix or request.raw_path.startswith(payload_prefix + "/")


def _body_profile(request: HTTPRequest, decoder: str) -> tuple[AdvancedBodyProfile, str]:
    if "content-type" not in request.header_values:
        raise _unsupported_media()
    values = request.get_header_values("content-type")
    if len(values) != 1:
        raise _unsupported_media()
    declared = values[0]
    base = _content_type_base(declared)
    params = _content_type_params(declared)
    if base == "text/plain":
        charset = params.get("charset", "utf-8")
        if charset.lower() != "utf-8":
            raise _unsupported_media()
    if decoder == "auto":
        if base == "application/json":
            return "json", base
        if base == "application/x-www-form-urlencoded":
            return "form", base
        if base == "multipart/form-data":
            return "multipart-encoded", base
        if _is_xml_media(base):
            return "xml", base
        if base == "text/plain":
            return "text", base
        if base == "application/octet-stream":
            return "raw", base
        raise _unsupported_media()
    expected = {
        "json": "application/json",
        "form": "application/x-www-form-urlencoded",
        "multipart": "multipart/form-data",
        "text": "text/plain",
        "raw": "application/octet-stream",
    }
    if decoder == "xml":
        if not _is_xml_media(base):
            raise _unsupported_media()
        return "xml", base
    expected_base = expected.get(decoder)
    if expected_base is None or base != expected_base:
        raise _unsupported_media()
    if decoder == "multipart":
        return "multipart-encoded", base
    return decoder, base  # type: ignore[return-value]


def _json_pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONMember(_json_field_for_invalid(key))
        result[key] = value
    return result


def _parse_json_body(request: HTTPRequest, content_type: str) -> CanonicalAdvancedPayload:
    try:
        parsed = json.loads(request.body.decode("utf-8"), object_pairs_hook=_json_pairs_hook)
    except _DuplicateJSONMember as exc:
        raise _invalid_field(exc.field) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error(400, "malformed_json", "Malformed JSON body", field=None) from exc
    if not isinstance(parsed, dict):
        raise _error(
            400,
            "invalid_json_type",
            "Advanced JSON body must be an object",
            field=None,
            details={"expected": "object"},
        )
    occurrences = [
        FieldOccurrence(
            name=key if key in _FIELD_NAMES or _QUERY_CHUNK_RE.fullmatch(key) else key,
            value=value,
            wire_order=index,
            display_name=key,
        )
        for index, (key, value) in enumerate(parsed.items())
    ]
    return _build_payload(
        "body",
        "json",
        occurrences,
        content_type="application/octet-stream",
        filename_source="body",
        allow_chunks=True,
        json_types=True,
    )


def _parse_form_body(request: HTTPRequest, content_type: str) -> CanonicalAdvancedPayload:
    try:
        raw = request.body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _invalid_field("data") from exc
    occurrences = [
        FieldOccurrence(name=key, value=value, wire_order=index, display_name=key)
        for index, (key, value) in enumerate(_parse_form_pairs(raw))
    ]
    return _build_payload(
        "body",
        "form",
        occurrences,
        content_type="application/octet-stream",
        filename_source="body",
        allow_chunks=True,
    )


def _parse_form_pairs(raw: str) -> list[tuple[str, str]]:
    if not raw:
        return []
    pairs: list[tuple[str, str]] = []
    for raw_part in raw.split("&"):
        raw_key, separator, raw_value = raw_part.partition("=")
        if not separator:
            raw_value = ""
        key = _strict_percent_decode_text(raw_key, plus_to_space=True)
        value = _strict_percent_decode_text(raw_value, plus_to_space=True)
        pairs.append((key, value))
    return pairs


class _ClosedXMLTreeBuilder(ElementTree.TreeBuilder):
    """Track noncanonical XML constructs even when they occur before the root."""

    def __init__(self) -> None:
        super().__init__(insert_comments=True, insert_pis=True)
        self.has_noncanonical_construct = False

    def comment(self, text: str | None) -> ElementTree.Element:
        self.has_noncanonical_construct = True
        return super().comment(text)

    def pi(self, target: str, text: str | None = None) -> ElementTree.Element:
        self.has_noncanonical_construct = True
        return super().pi(target, text)


def _parse_xml_body(request: HTTPRequest, content_type: str) -> CanonicalAdvancedPayload:
    try:
        tree_builder = _ClosedXMLTreeBuilder()
        parser = DefusedElementTree.XMLParser(
            target=tree_builder,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
        parser.feed(request.body)
        root = parser.close()
    except (DefusedXmlException, ElementTree.ParseError) as exc:
        raise _invalid_field("data") from exc
    if tree_builder.has_noncanonical_construct:
        raise _invalid_field("data")
    if not isinstance(root.tag, str) or root.tag != "upload" or root.attrib:
        raise _invalid_field("data")
    if root.text:
        raise _invalid_field("data")
    occurrences: list[FieldOccurrence] = []
    seen_children = 0
    for child in list(root):
        seen_children += 1
        if not isinstance(child.tag, str):
            raise _invalid_field("data")
        if child.tag not in _FIELD_NAMES or child.tag == "data" and False:
            raise _invalid_field(_json_field_for_invalid(str(child.tag)))
        if child.tag.startswith("data_"):
            raise _invalid_field("data")
        if child.attrib or list(child) or child.tail:
            raise _invalid_field(str(child.tag))
        occurrences.append(
            FieldOccurrence(
                name=str(child.tag),
                value=child.text or "",
                wire_order=seen_children - 1,
                display_name=str(child.tag),
            )
        )
    return _build_payload(
        "body",
        "xml",
        occurrences,
        content_type="application/octet-stream",
        filename_source="body",
        allow_chunks=False,
    )


def _parse_multipart_body(request: HTTPRequest) -> CanonicalAdvancedPayload:
    try:
        parts = parse_multipart_form_data(
            request.get_header_values("content-type")[0],
            request.body,
        )
    except MultipartError as exc:
        raise _invalid_field("file") from exc

    occurrences: list[FieldOccurrence] = []
    file_parts = [part for part in parts if part.filename is not None]
    scalar_parts = [part for part in parts if part.filename is None]
    for index, part in enumerate(scalar_parts):
        try:
            value = part.payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _invalid_field(part.field_name) from exc
        occurrences.append(
            FieldOccurrence(
                name=part.field_name,
                value=value,
                wire_order=index,
                display_name=part.field_name,
            )
        )
    has_encoded = any(
        occurrence.name == "data" or _QUERY_CHUNK_RE.fullmatch(occurrence.name)
        for occurrence in occurrences
    )
    if len(file_parts) > 1:
        raise _invalid_field("file")
    if file_parts and has_encoded:
        raise _invalid_field("data")
    if file_parts:
        part = file_parts[0]
        if part.field_name != "file" or not part.filename:
            raise _invalid_field("file")
        if not part.payload:
            raise _error(
                400,
                "empty_payload",
                "Advanced upload payload is empty",
                field="file",
                details={"upload_kind": "advanced"},
            )
        return _build_payload(
            "body",
            "multipart-binary",
            occurrences,
            raw_data=part.payload,
            content_type=part.content_type,
            filename_source="part",
            allow_chunks=False,
            part_filename=part.filename,
        )
    return _build_payload(
        "body",
        "multipart-encoded",
        occurrences,
        content_type="application/octet-stream",
        filename_source="body",
        allow_chunks=True,
    )


def _parse_text_body(request: HTTPRequest, content_type: str) -> CanonicalAdvancedPayload:
    try:
        request.body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _invalid_field("data") from exc
    header_occurrences, _has_payload, _has_metadata = _header_scan(request)
    metadata = [
        occ for occ in header_occurrences if occ.name != "data" and not occ.name.startswith("data_")
    ]
    return _build_payload(
        "body",
        "text",
        metadata,
        raw_data=request.body,
        content_type=content_type,
        filename_source="header",
        allow_chunks=False,
    )


def _parse_raw_body(request: HTTPRequest, content_type: str) -> CanonicalAdvancedPayload:
    header_occurrences, _has_payload, _has_metadata = _header_scan(request)
    metadata = [
        occ for occ in header_occurrences if occ.name != "data" and not occ.name.startswith("data_")
    ]
    return _build_payload(
        "body",
        "raw",
        metadata,
        raw_data=request.body,
        content_type=content_type,
        filename_source="header",
        allow_chunks=False,
    )


def _field_as_string(occurrence: FieldOccurrence, *, json_types: bool) -> str:
    if not isinstance(occurrence.value, str):
        raise _invalid_field(occurrence.name)
    return occurrence.value


def _field_as_bool(occurrence: FieldOccurrence, *, json_types: bool) -> bool:
    if json_types:
        if not isinstance(occurrence.value, bool):
            raise _invalid_field(occurrence.name)
        return occurrence.value
    if occurrence.value == "true":
        return True
    if occurrence.value == "false":
        return False
    raise _invalid_field(occurrence.name)


def _validate_chunk_name(name: str) -> int | None:
    match = _QUERY_CHUNK_RE.fullmatch(name)
    if match is None:
        return None
    digits = match.group(1)
    if (len(digits) > 1 and digits.startswith("0")) or int(digits) > 255:
        raise _invalid_field("data")
    return int(digits)


def _build_payload(
    carrier: AdvancedCarrier,
    profile: AdvancedBodyProfile,
    occurrences: list[FieldOccurrence],
    *,
    content_type: str,
    filename_source: FilenameSource,
    allow_chunks: bool,
    json_types: bool = False,
    raw_data: bytes | None = None,
    part_filename: str | None = None,
    encoded_override: str | None = None,
    encoding_override: AdvancedEncoding | None = None,
    name_override: str | None = None,
) -> CanonicalAdvancedPayload:
    values: dict[str, FieldOccurrence] = {}
    chunks: list[tuple[int, FieldOccurrence]] = []
    for occurrence in occurrences:
        if occurrence.name not in _FIELD_NAMES:
            chunk_index = _validate_chunk_name(occurrence.name)
            if chunk_index is None:
                raise _invalid_field(_json_field_for_invalid(occurrence.display_name))
            if not allow_chunks:
                raise _invalid_field("data")
            chunks.append((chunk_index, occurrence))
            continue
        if occurrence.name == "data":
            if "data" in values:
                raise _invalid_field("data")
            values["data"] = occurrence
            continue
        if occurrence.name in values:
            raise _invalid_field(occurrence.name)
        values[occurrence.name] = occurrence

    if "data" in values and chunks:
        raise _invalid_field("data")
    if chunks:
        chunks.sort(key=lambda item: item[1].wire_order)
        expected = 0
        seen: set[int] = set()
        for index, occurrence in chunks:
            if index in seen or index != expected:
                raise _invalid_field("data")
            seen.add(index)
            _field_as_string(occurrence, json_types=json_types)
            expected += 1

    encoded_data: str | None = encoded_override
    if encoded_data is None and "data" in values:
        encoded_data = _field_as_string(values["data"], json_types=json_types)
    elif encoded_data is None and chunks:
        encoded_data = "".join(
            _field_as_string(occurrence, json_types=json_types) for _index, occurrence in chunks
        )

    if raw_data is None and encoded_data is None:
        raise _missing_field("data")
    if raw_data is not None and encoded_data is not None:
        raise _invalid_field("data")
    if encoded_data is not None and encoded_data == "":
        raise _invalid_field("data")
    if raw_data is not None and not raw_data:
        raise _error(
            400,
            "empty_payload",
            "Advanced upload payload is empty",
            field="file" if profile == "multipart-binary" else "data",
            details={"upload_kind": "advanced"},
        )

    encoding: AdvancedEncoding | None = encoding_override
    if raw_data is not None:
        if "encoding" in values:
            raise _invalid_field("encoding")
    else:
        if encoding is None:
            if "encoding" not in values:
                raise _missing_field("encoding")
            encoding_text = _field_as_string(values["encoding"], json_types=json_types)
            if encoding_text not in _ENCODINGS:
                raise _invalid_field("encoding")
            encoding = encoding_text  # type: ignore[assignment]

    encryption_occurrence = values.get("encryption")
    if encryption_occurrence is None:
        raise _missing_field("encryption")
    encryption_text = _field_as_string(encryption_occurrence, json_types=json_types)
    if encryption_text not in _ENCRYPTIONS:
        raise _invalid_field("encryption")
    encryption: AdvancedEncryption = encryption_text  # type: ignore[assignment]

    key = None
    if "key" in values:
        key = _field_as_string(values["key"], json_types=json_types)
        if not key:
            raise _invalid_field("key")
    key_is_base64 = False
    if "key_is_base64" in values:
        key_is_base64 = _field_as_bool(values["key_is_base64"], json_types=json_types)
        if key is None:
            raise _invalid_field("key_is_base64")
    if key is not None and key_is_base64:
        try:
            decoded_key = base64.b64decode(key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _invalid_field("key") from exc
        if not decoded_key or base64.b64encode(decoded_key).decode("ascii") != key:
            raise _invalid_field("key")
        try:
            key = decoded_key.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _invalid_field("key") from exc
        if not key:
            raise _invalid_field("key")

    hmac_value = None
    if "hmac" in values:
        hmac_value = _field_as_string(values["hmac"], json_types=json_types)
        if _LOWER_HEX_64_RE.fullmatch(hmac_value) is None:
            raise _invalid_field("hmac")

    if encryption == "none":
        if key is not None:
            raise _invalid_field("key")
        if key_is_base64:
            raise _invalid_field("key_is_base64")
        if hmac_value is not None:
            raise _invalid_field("hmac")
    elif key is None:
        raise _missing_field("key")

    method_override = None
    if "method_override" in values:
        method_override = _field_as_string(values["method_override"], json_types=json_types)
        if (
            not method_override
            or len(method_override) > 64
            or _ASCII_RE.fullmatch(method_override) is None
        ):
            raise _invalid_field("method_override")

    name = name_override
    if part_filename is not None:
        if not part_filename:
            raise _invalid_field("name")
        name = part_filename
        if "name" in values:
            scalar_name = _field_as_string(values["name"], json_types=json_types)
            if scalar_name != part_filename:
                raise _invalid_field("name")
    elif "name" in values:
        name = _field_as_string(values["name"], json_types=json_types)
    if name is not None:
        if not name or len(name.encode("utf-8")) > 255:
            raise _invalid_field("name")
    elif filename_source != "generated":
        filename_source = "generated"

    return CanonicalAdvancedPayload(
        carrier=carrier,
        body_profile=profile,
        encoded_data=encoded_data,
        raw_data=raw_data,
        encryption=encryption,
        key=key,
        key_is_base64=key_is_base64,
        name=name,
        hmac=hmac_value,
        encoding=encoding,
        method_override=method_override,
        content_type=content_type,
        filename_source=filename_source,
    )


def _encoded_limit_for_carrier(
    carrier: AdvancedCarrier,
    *,
    header_data_limit: int,
    url_data_limit: int,
) -> int | None:
    if carrier in {"headers", "cookies"}:
        return header_data_limit
    if carrier in {"query", "path"}:
        return url_data_limit
    return None


def _check_encoded_limit(
    payload: CanonicalAdvancedPayload,
    *,
    header_data_limit: int,
    url_data_limit: int,
) -> None:
    if payload.encoded_data is None:
        return
    limit = _encoded_limit_for_carrier(
        payload.carrier,
        header_data_limit=header_data_limit,
        url_data_limit=url_data_limit,
    )
    if limit is not None and len(payload.encoded_data.encode("utf-8")) > limit:
        raise _payload_too_large(limit, scope="encoded")


def parse_advanced_payload(
    request: HTTPRequest,
    *,
    decoder: str,
    header_data_limit: int,
    url_data_limit: int,
) -> CanonicalAdvancedPayload:
    """Select and parse exactly one canonical Advanced payload carrier."""
    header_occurrences, header_payload, header_metadata = _header_scan(request)
    query_occurrences, query_payload, query_metadata = _query_scan(request)
    cookie_occurrences, cookie_payload, cookie_metadata = _cookie_scan(request)
    body_payload = bool(request.body)
    path_candidate = _is_path_candidate(request)

    present = []
    if body_payload:
        present.append("body")
    if header_payload:
        present.append("headers")
    if query_payload:
        present.append("query")
    if cookie_payload:
        present.append("cookies")
    if path_candidate:
        present.append("path")
    if not present:
        raise _missing_field("data")
    if len(present) > 1:
        raise _error(
            400,
            "ambiguous_payload",
            "Advanced upload payload carrier is ambiguous",
            field="data",
            details={"carriers": sorted(present)},
        )

    selected = present[0]
    if selected not in {"query", "path"} and query_metadata:
        raise _invalid_field("query")
    if selected not in {"cookies"} and cookie_metadata:
        raise _invalid_field("cookie")
    if selected not in {"headers", "body"} and header_metadata:
        raise _invalid_field("headers")

    if selected == "headers":
        payload = _build_payload(
            "headers",
            "header",
            header_occurrences,
            content_type="application/octet-stream",
            filename_source="header",
            allow_chunks=True,
        )
    elif selected == "query":
        payload = _build_payload(
            "query",
            "query",
            query_occurrences,
            content_type="application/octet-stream",
            filename_source="query",
            allow_chunks=True,
        )
    elif selected == "cookies":
        payload = _build_payload(
            "cookies",
            "cookies",
            cookie_occurrences,
            content_type="application/octet-stream",
            filename_source="cookie",
            allow_chunks=False,
        )
    elif selected == "path":
        payload = _parse_reserved_path_carrier(request, query_occurrences)
    else:
        profile, content_type = _body_profile(request, decoder)
        if profile in {"raw", "text"}:
            if query_metadata or cookie_metadata:
                raise _invalid_field("query" if query_metadata else "cookie")
            payload = (
                _parse_raw_body(request, content_type)
                if profile == "raw"
                else _parse_text_body(request, content_type)
            )
        else:
            if header_metadata:
                first = next(
                    occurrence.display_name
                    for occurrence in header_occurrences
                    if occurrence.name != "data" and not occurrence.name.startswith("data_")
                )
                raise _invalid_field(first)
            if profile == "json":
                payload = _parse_json_body(request, content_type)
            elif profile == "form":
                payload = _parse_form_body(request, content_type)
            elif profile == "xml":
                payload = _parse_xml_body(request, content_type)
            else:
                payload = _parse_multipart_body(request)

    _check_encoded_limit(
        payload,
        header_data_limit=header_data_limit,
        url_data_limit=url_data_limit,
    )
    return payload


def _parse_reserved_path_carrier(
    request: HTTPRequest,
    query_occurrences: list[FieldOccurrence],
) -> CanonicalAdvancedPayload:
    payload_prefix = _payload_path_prefix(request)
    if payload_prefix is None:
        raise _missing_field("data")
    suffix = request.raw_path[len(payload_prefix) :]
    parts = suffix.split("/")
    if len(parts) != 3 or parts[0] != "":
        raise _invalid_field("data")
    raw_name, encoded_data = parts[1], parts[2]
    if not raw_name or not encoded_data:
        raise _invalid_field("data")
    name = _strict_percent_decode_text(raw_name, plus_to_space=False)
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in name)
        or _PERCENT_TRIPLET_RE.search(name)
    ):
        raise _invalid_field("name")
    if _BASE64URL_RE.fullmatch(encoded_data) is None:
        raise _invalid_field("data")
    forbidden = {"data", "name", "encoding"}
    metadata: list[FieldOccurrence] = []
    for occurrence in query_occurrences:
        if occurrence.name in forbidden or _QUERY_CHUNK_RE.fullmatch(occurrence.name):
            raise _invalid_field(occurrence.name)
        if occurrence.name not in _FIELD_NAMES - forbidden:
            raise _invalid_field(occurrence.display_name)
        metadata.append(occurrence)
    return _build_payload(
        "path",
        "path",
        metadata,
        content_type="application/octet-stream",
        filename_source="path",
        allow_chunks=False,
        encoded_override=encoded_data,
        encoding_override="base64url",
        name_override=name,
    )


def _strict_base64(data: str) -> bytes:
    try:
        decoded = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _error(
            400,
            "invalid_encoding",
            "Advanced upload data encoding is invalid",
            field="data",
            metric_reason="invalid_encoding",
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != data:
        raise _error(
            400,
            "invalid_encoding",
            "Advanced upload data encoding is invalid",
            field="data",
            metric_reason="invalid_encoding",
        )
    return decoded


def _strict_base64url(data: str) -> bytes:
    if "=" in data or _BASE64URL_RE.fullmatch(data) is None:
        raise _error(
            400,
            "invalid_encoding",
            "Advanced upload data encoding is invalid",
            field="data",
            metric_reason="invalid_encoding",
        )
    padded = data + ("=" * ((4 - len(data) % 4) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise _error(
            400,
            "invalid_encoding",
            "Advanced upload data encoding is invalid",
            field="data",
            metric_reason="invalid_encoding",
        ) from exc
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != data:
        raise _error(
            400,
            "invalid_encoding",
            "Advanced upload data encoding is invalid",
            field="data",
            metric_reason="invalid_encoding",
        )
    return decoded


def _bounded_gzip_decompress(compressed: bytes, decoded_limit: int) -> bytes:
    if not compressed:
        raise ValueError("Empty gzip stream")
    pending = compressed
    output = bytearray()
    while pending:
        decompressor = zlib.decompressobj(_GZIP_WBITS)
        while pending:
            chunk = pending[:_GZIP_DECOMPRESS_CHUNK_SIZE]
            pending = pending[_GZIP_DECOMPRESS_CHUNK_SIZE:]
            while chunk:
                remaining = decoded_limit - len(output)
                try:
                    decoded = decompressor.decompress(chunk, remaining + 1)
                except zlib.error as exc:
                    raise ValueError("Invalid gzip stream") from exc
                if len(decoded) > remaining:
                    raise AdvancedPayloadDecodedTooLarge
                output.extend(decoded)
                if decompressor.eof:
                    pending = decompressor.unused_data + pending
                    break
                chunk = decompressor.unconsumed_tail
            if decompressor.eof:
                break
        if not decompressor.eof:
            raise ValueError("Invalid gzip stream")
    return bytes(output)


def decode_advanced_payload_data(
    payload: CanonicalAdvancedPayload,
    *,
    decoded_limit: int,
) -> bytes:
    """Decode the payload bytes under the final decoded cap."""
    if payload.raw_data is not None:
        data = payload.raw_data
    else:
        assert payload.encoded_data is not None
        assert payload.encoding is not None
        try:
            if payload.encoding == "raw":
                data = payload.encoded_data.encode("utf-8")
            elif payload.encoding == "base64":
                data = _strict_base64(payload.encoded_data)
            elif payload.encoding == "base64url":
                data = _strict_base64url(payload.encoded_data)
            elif payload.encoding == "hex":
                data = bytes.fromhex(payload.encoded_data)
            elif payload.encoding == "percent":
                data = _strict_percent_decode_bytes(payload.encoded_data, plus_to_space=False)
            elif payload.encoding == "gzip-base64":
                data = _bounded_gzip_decompress(_strict_base64(payload.encoded_data), decoded_limit)
            else:
                data = _bounded_gzip_decompress(
                    _strict_base64url(payload.encoded_data),
                    decoded_limit,
                )
        except AdvancedPayloadDecodedTooLarge:
            raise
        except (ValueError, AdvancedPayloadError) as exc:
            if isinstance(exc, AdvancedPayloadError):
                raise
            raise _error(
                400,
                "invalid_encoding",
                "Advanced upload data encoding is invalid",
                field="data",
                metric_reason="invalid_encoding",
            ) from exc

    if not data:
        raise _error(
            400,
            "empty_payload",
            "Advanced upload payload is empty",
            field="file" if payload.body_profile == "multipart-binary" else "data",
            details={"upload_kind": "advanced"},
        )
    if len(data) > decoded_limit:
        raise AdvancedPayloadDecodedTooLarge
    return data
