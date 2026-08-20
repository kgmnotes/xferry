"""Strict parser for the canonical SMUGGLE query contract."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any

from .policy import (
    DEFAULT_SMUGGLE_BUILDER,
    DEFAULT_SMUGGLE_POLICY,
    SMUGGLE_BUILDER_MAX_CTA_LABEL,
    SMUGGLE_BUILDER_MAX_DELAY_MS,
    SMUGGLE_BUILDER_MAX_DOWNLOAD_NAME,
    SMUGGLE_BUILDER_MAX_MESSAGE,
    SMUGGLE_BUILDER_MAX_TITLE,
    SMUGGLE_CONSTRUCTOR_MODE,
    SMUGGLE_CONSTRUCTOR_ONLY_FIELDS,
    SMUGGLE_DEFAULT_MODE,
    SMUGGLE_DOWNLOAD_VARIANTS,
    SMUGGLE_ENCRYPTIONS,
    SMUGGLE_MODES,
    SMUGGLE_OUTPUT_FORMATS,
    SMUGGLE_PAGE_TEMPLATES,
    SMUGGLE_PAYLOAD_ENCODINGS,
    SMUGGLE_PRESETS,
    SMUGGLE_SIMPLE_ONLY_FIELDS,
    SafeSmuggleBuilderConfig,
    SmugglePolicy,
    SmuggleRequestError,
    normalize_enum,
    normalize_extension,
    normalize_locale,
    normalize_mime_type,
    normalize_optional_text,
    normalize_trigger,
    parse_bool,
)

_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
# mode and encryption are the only algorithm/mode selectors. Aliases from the
# previous builder are intentionally absent.
SMUGGLE_QUERY_FIELDS = frozenset(field.name for field in fields(SafeSmuggleBuilderConfig))


@dataclass(frozen=True, slots=True)
class SmuggleRequest:
    """Validated SMUGGLE request values passed to the coordinator."""

    builder: SafeSmuggleBuilderConfig

    @property
    def mode(self) -> str:
        return self.builder.mode

    @property
    def encryption(self) -> str:
        return self.builder.encryption


def parse_smuggle_request(
    request_or_query: Any,
    *,
    policy: SmugglePolicy = DEFAULT_SMUGGLE_POLICY,
) -> SmuggleRequest:
    """Parse an HTTPRequest or mapping using exact canonical tokens.

    Constructor-only options require an explicit mode=constructor. No aliases,
    case folding, boolean words, or duplicate query parameters are accepted.
    """
    values, occurrences = _query_values(request_or_query)
    _reject_duplicates(occurrences)
    unknown = sorted(set(values) - SMUGGLE_QUERY_FIELDS)
    if unknown:
        field = unknown[0]
        raise SmuggleRequestError(
            f"Unknown SMUGGLE parameter: {field}",
            code="unknown_smuggle_parameter",
            field=field,
        )

    explicit_mode = "mode" in values
    constructor_present = bool(SMUGGLE_CONSTRUCTOR_ONLY_FIELDS & values.keys())
    if explicit_mode:
        mode = normalize_enum(values["mode"], SMUGGLE_MODES, "mode")
    else:
        if constructor_present:
            raise SmuggleRequestError(
                "SMUGGLE constructor options require explicit mode=constructor",
                code="invalid_smuggle_configuration",
                field="mode",
            )
        mode = DEFAULT_SMUGGLE_BUILDER.mode
    if mode == SMUGGLE_DEFAULT_MODE and constructor_present:
        field = sorted(SMUGGLE_CONSTRUCTOR_ONLY_FIELDS & values.keys())[0]
        raise SmuggleRequestError(
            "SMUGGLE constructor options require mode=constructor",
            code="invalid_smuggle_configuration",
            field=field,
        )
    if mode == SMUGGLE_CONSTRUCTOR_MODE:
        simple_present = SMUGGLE_SIMPLE_ONLY_FIELDS & values.keys()
        if simple_present:
            field = sorted(simple_present)[0]
            raise SmuggleRequestError(
                "SMUGGLE simple options require mode=simple",
                code="invalid_smuggle_configuration",
                field=field,
            )

    # Accessing the policy here makes malformed custom policy objects fail at
    # the request boundary rather than in a renderer.
    if int(policy.source_max_bytes) < 0:
        raise SmuggleRequestError(
            "Invalid SMUGGLE source policy",
            code="invalid_smuggle_policy",
            field="source_max_bytes",
        )

    encryption = normalize_enum(
        values.get("encryption"),
        SMUGGLE_ENCRYPTIONS,
        "encryption",
    )
    locale = normalize_locale(values.get("locale"))
    preset = normalize_enum(values.get("preset"), SMUGGLE_PRESETS, "preset")

    download_ext: str | None = None
    if "download_ext" in values:
        download_ext = normalize_extension(values["download_ext"])

    payload_encoding = normalize_enum(
        values.get("payload_encoding"),
        SMUGGLE_PAYLOAD_ENCODINGS,
        "payload_encoding",
    )
    trigger_method, trigger_event, _trigger_custom = normalize_trigger(
        values.get("trigger_method"),
        values.get("trigger_event"),
    )
    output_format = normalize_enum(
        values.get("output_format"),
        SMUGGLE_OUTPUT_FORMATS,
        "output_format",
    )
    download_variant = normalize_enum(
        values.get("download_variant"),
        SMUGGLE_DOWNLOAD_VARIANTS,
        "download_variant",
    )
    page_template = normalize_enum(
        values.get("page_template"),
        SMUGGLE_PAGE_TEMPLATES,
        "page_template",
    )
    delay_ms = _parse_delay(values.get("delay_ms"))
    show_notice = parse_bool(
        values.get("show_notice"),
        field="show_notice",
        default=DEFAULT_SMUGGLE_BUILDER.show_notice,
    )
    null_byte = parse_bool(
        values.get("null_byte"),
        field="null_byte",
        default=DEFAULT_SMUGGLE_BUILDER.null_byte,
    )
    mime_type = _parse_mime(values.get("mime_type"))

    builder = SafeSmuggleBuilderConfig(
        mode=mode,
        preset=preset,
        locale=locale,
        encryption=encryption,
        download_name=normalize_optional_text(
            values.get("download_name"),
            field="download_name",
            limit=SMUGGLE_BUILDER_MAX_DOWNLOAD_NAME,
        ),
        download_ext=download_ext,
        title=normalize_optional_text(
            values.get("title"),
            field="title",
            limit=SMUGGLE_BUILDER_MAX_TITLE,
        ),
        message=normalize_optional_text(
            values.get("message"),
            field="message",
            limit=SMUGGLE_BUILDER_MAX_MESSAGE,
        ),
        cta_label=normalize_optional_text(
            values.get("cta_label"),
            field="cta_label",
            limit=SMUGGLE_BUILDER_MAX_CTA_LABEL,
        ),
        delay_ms=delay_ms,
        show_notice=show_notice,
        payload_encoding=payload_encoding,
        trigger_method=trigger_method,
        trigger_event=trigger_event,
        output_format=output_format,
        download_variant=download_variant,
        page_template=page_template,
        mime_type=mime_type,
        null_byte=null_byte,
    )
    return SmuggleRequest(builder=builder)


def parse_smuggle_query(
    query: Mapping[str, str],
    *,
    policy: SmugglePolicy = DEFAULT_SMUGGLE_POLICY,
) -> SmuggleRequest:
    """Mapping-oriented alias useful for curl/client contract tests."""
    return parse_smuggle_request(query, policy=policy)


def _query_values(value: Any) -> tuple[dict[str, str], tuple[tuple[str, str], ...]]:
    if hasattr(value, "query_params"):
        values = value.query_params
        occurrences = getattr(value, "query_occurrences", ())
    else:
        values = value
        occurrences = ()
    if not isinstance(values, Mapping):
        raise SmuggleRequestError(
            "Invalid SMUGGLE query",
            code="invalid_smuggle_query",
            field=None,
        )
    normalized: dict[str, str] = {}
    for key, raw in values.items():
        if not isinstance(key, str) or not isinstance(raw, str):
            raise SmuggleRequestError(
                "Invalid SMUGGLE query",
                code="invalid_smuggle_query",
                field=key if isinstance(key, str) else None,
            )
        normalized[key] = raw
    normalized_occurrences: tuple[tuple[str, str], ...] = tuple(
        (key, raw) for key, raw in occurrences if isinstance(key, str)
    )
    # HTTPRequest.query_params intentionally omits blank values (parse_qs
    # default). Reintroduce an explicitly supplied blank so strict field
    # grammars can reject it instead of treating it as an omitted default.
    for key, raw in normalized_occurrences:
        normalized.setdefault(key, raw)
    return normalized, normalized_occurrences


def _reject_duplicates(occurrences: tuple[tuple[str, str], ...]) -> None:
    seen: set[str] = set()
    for key, _value in occurrences:
        if key in seen:
            raise SmuggleRequestError(
                f"Duplicate SMUGGLE parameter: {key}",
                code="duplicate_smuggle_parameter",
                field=key,
            )
        seen.add(key)


def _parse_delay(value: str | None) -> int:
    if value is None:
        return DEFAULT_SMUGGLE_BUILDER.delay_ms
    if _DECIMAL_RE.fullmatch(value) is None:
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder delay",
            code="invalid_smuggle_delay",
            field="delay_ms",
        )
    delay = int(value)
    if delay > SMUGGLE_BUILDER_MAX_DELAY_MS:
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder delay",
            code="invalid_smuggle_delay",
            field="delay_ms",
        )
    return delay


def _parse_mime(value: str | None) -> str:
    return normalize_mime_type(value)


__all__ = [
    "SMUGGLE_CONSTRUCTOR_ONLY_FIELDS",
    "SMUGGLE_QUERY_FIELDS",
    "SMUGGLE_SIMPLE_ONLY_FIELDS",
    "SmuggleRequest",
    "parse_smuggle_query",
    "parse_smuggle_request",
]
