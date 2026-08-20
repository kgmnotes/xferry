"""Single source of truth for the canonical SMUGGLE vocabulary and limits.

This module contains no request handling or HTML generation.  Keeping the
policy data here means PING, the HTTP parser, renderers, and future clients
all consume the same closed sets instead of maintaining parallel aliases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SMUGGLE_SCHEMA_VERSION = 1
SMUGGLE_SOURCE_SIZE_LIMIT = 10 * 1024 * 1024
DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS = 3600
DEFAULT_SMUGGLE_TEMP_MAX_FILES = 32
DEFAULT_SMUGGLE_TEMP_MAX_BYTES = 128 * 1024 * 1024

SMUGGLE_BUILDER_MAX_DOWNLOAD_NAME = 120
SMUGGLE_BUILDER_MAX_TITLE = 120
SMUGGLE_BUILDER_MAX_MESSAGE = 280
SMUGGLE_BUILDER_MAX_CTA_LABEL = 80
SMUGGLE_BUILDER_MAX_DELAY_MS = 10_000
SMUGGLE_BUILDER_MAX_DOWNLOAD_EXT = 32
SMUGGLE_BUILDER_MAX_TRIGGER_EVENT = 64
SMUGGLE_BUILDER_MAX_MIME_TYPE = 120
SMUGGLE_ERROR_PATH_DETAIL_MAX_CHARS = 1024
SMUGGLE_TEMP_TOKEN_LENGTH = 16

SMUGGLE_ENCRYPTIONS: tuple[str, ...] = ("none", "xor", "aes")
SMUGGLE_MODES: tuple[str, ...] = ("simple", "constructor")
SMUGGLE_DEFAULT_MODE = SMUGGLE_MODES[0]
SMUGGLE_CONSTRUCTOR_MODE = SMUGGLE_MODES[1]
SMUGGLE_DEFAULT_ENCRYPTION = SMUGGLE_ENCRYPTIONS[0]
SMUGGLE_DEFAULT_LOCALE = "ru"
SMUGGLE_LOCALES: tuple[str, ...] = ("ru", "en")

# These are suggestions for the extracted filename, not a content validator.
SMUGGLE_EXTENSIONS: tuple[str, ...] = (
    "txt",
    "bin",
    "dat",
    "pdf",
    "zip",
    "7z",
    "rar",
    "tar",
    "gz",
    "tar.gz",
    "csv",
    "json",
    "xml",
    "html",
    "htm",
    "js",
    "css",
    "svg",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "mp3",
    "mp4",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "exe",
    "dll",
    "scr",
    "msi",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "sh",
    "py",
    "jar",
    "apk",
    "wasm",
)
SMUGGLE_PRESETS: tuple[str, ...] = ("direct", "card_manual", "card_auto")
SMUGGLE_DEFAULT_PRESET = SMUGGLE_PRESETS[0]
SMUGGLE_PAYLOAD_ENCODINGS: tuple[str, ...] = (
    "base64",
    "base64url",
    "base32",
    "percent",
    "reverse",
    "xor",
    "hex",
    "split",
    "attrs",
    "charcode",
)
SMUGGLE_DEFAULT_PAYLOAD_ENCODING = SMUGGLE_PAYLOAD_ENCODINGS[0]
SMUGGLE_OUTPUT_FORMATS: tuple[str, ...] = (
    "html",
    "htm",
    "shtml",
    "shtm",
    "xhtml",
    "xht",
    "xhtm",
    "xml",
    "svg",
)
SMUGGLE_DEFAULT_OUTPUT_FORMAT = SMUGGLE_OUTPUT_FORMATS[0]
SMUGGLE_PAGE_TEMPLATES: tuple[str, ...] = (
    "default",
    "minimal",
    "corporate",
    "drive",
    "npf-zip-archive-help",
)
SMUGGLE_DEFAULT_PAGE_TEMPLATE = SMUGGLE_PAGE_TEMPLATES[0]
SMUGGLE_DOWNLOAD_VARIANTS: tuple[str, ...] = (
    "blob-anchor",
    "data-uri",
    "iframe-blob",
    "filereader",
    "fetch-blob",
    "window-open",
    "loc-assign",
    "form-post",
    "timeout-blob",
    "promise-blob",
    "raf-blob",
    "microtask-blob",
    "observer-blob",
    "response-blob",
    "readable-stream",
    "message-channel-blob",
    "idle-callback-blob",
)
SMUGGLE_DEFAULT_DOWNLOAD_VARIANT = SMUGGLE_DOWNLOAD_VARIANTS[0]
SMUGGLE_TRIGGER_EVENTS: dict[str, tuple[str, ...]] = {
    "svg": ("onload",),
    "body": ("onload", "onpageshow"),
    "img": ("onerror", "onload"),
    "audio": ("onerror", "onloadstart"),
    "video": ("onerror", "onloadstart"),
    "source": ("onerror",),
    "input": ("onfocus", "oninput", "onchange", "onkeydown"),
    "select": ("onfocus", "onchange"),
    "button": ("onfocus", "onclick", "onpointerdown", "onkeydown"),
    "textarea": ("onfocus", "oninput", "onchange", "onkeydown"),
    "details": ("ontoggle", "onclick"),
    "iframe": ("srcdoc", "onload"),
    "animate": ("onbegin", "onend", "onrepeat"),
    "animmotion": ("onbegin", "onend", "onrepeat"),
    "set": ("onbegin", "onend"),
    "cssanim": ("onanimationstart", "onanimationend", "onanimationiteration"),
    "csstransition": ("ontransitionrun", "ontransitionstart", "ontransitionend"),
    "link": ("onerror", "onload"),
    "script": ("onerror",),
    "form": ("onsubmit",),
    "custom": ("onfocus",),
    "focusin": ("onfocusin",),
    "contentvis": ("oncontentvisibilityautostatechange",),
}
SMUGGLE_TRIGGER_METHODS: tuple[str, ...] = tuple(SMUGGLE_TRIGGER_EVENTS)
SMUGGLE_CUSTOM_TRIGGER_METHODS: tuple[str, ...] = tuple(SMUGGLE_TRIGGER_METHODS)
SMUGGLE_DEFAULT_TRIGGER_METHOD = SMUGGLE_TRIGGER_METHODS[0]
SMUGGLE_DEFAULT_TRIGGER_EVENT = SMUGGLE_TRIGGER_EVENTS[SMUGGLE_DEFAULT_TRIGGER_METHOD][0]

# Mode applicability is part of the public policy. Constructor options must be
# selected explicitly, while these simple-card controls are rejected in
# constructor mode because that renderer does not consume them.
SMUGGLE_CONSTRUCTOR_ONLY_FIELDS = frozenset(
    {
        "payload_encoding",
        "trigger_method",
        "trigger_event",
        "output_format",
        "download_variant",
        "page_template",
        "mime_type",
        "null_byte",
    }
)
SMUGGLE_SIMPLE_ONLY_FIELDS = frozenset({"preset", "cta_label", "delay_ms"})

SMUGGLE_MIME_PRESETS: tuple[str, ...] = (
    "application/octet-stream",
    "text/plain",
    "text/html",
    "text/css",
    "text/csv",
    "text/javascript",
    "application/json",
    "application/xml",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/vnd.rar",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    "audio/mpeg",
    "video/mp4",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/wasm",
    "application/vnd.microsoft.portable-executable",
    "application/x-msi",
    "text/x-python",
    "application/x-powershell",
    "application/x-sh",
)
SMUGGLE_MIME_BY_EXTENSION: dict[str, str] = {
    "bin": "application/octet-stream",
    "dat": "application/octet-stream",
    "txt": "text/plain",
    "log": "text/plain",
    "md": "text/plain",
    "csv": "text/csv",
    "html": "text/html",
    "htm": "text/html",
    "css": "text/css",
    "js": "text/javascript",
    "mjs": "text/javascript",
    "json": "application/json",
    "xml": "application/xml",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "gz": "application/gzip",
    "tgz": "application/gzip",
    "tar.gz": "application/gzip",
    "tar": "application/x-tar",
    "7z": "application/x-7z-compressed",
    "rar": "application/vnd.rar",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "svg": "image/svg+xml",
    "mp3": "audio/mpeg",
    "mp4": "video/mp4",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "jar": "application/java-archive",
    "apk": "application/vnd.android.package-archive",
    "wasm": "application/wasm",
    "exe": "application/vnd.microsoft.portable-executable",
    "dll": "application/vnd.microsoft.portable-executable",
    "scr": "application/vnd.microsoft.portable-executable",
    "msi": "application/x-msi",
    "py": "text/x-python",
    "pyw": "text/x-python",
    "ps1": "application/x-powershell",
    "psm1": "application/x-powershell",
    "psd1": "application/x-powershell",
    "sh": "application/x-sh",
    "bash": "application/x-sh",
    "zsh": "application/x-sh",
}
SMUGGLE_OUTPUT_CONTENT_TYPES: dict[str, str] = {
    "html": "text/html; charset=utf-8",
    "htm": "text/html; charset=utf-8",
    "shtml": "text/html; charset=utf-8",
    "shtm": "text/html; charset=utf-8",
    "xhtml": "application/xhtml+xml; charset=utf-8",
    "xht": "application/xhtml+xml; charset=utf-8",
    "xhtm": "application/xhtml+xml; charset=utf-8",
    "xml": "application/xml; charset=utf-8",
    "svg": "image/svg+xml; charset=utf-8",
}
SMUGGLE_TEMP_EXTENSIONS = frozenset(f".{value}" for value in SMUGGLE_OUTPUT_FORMATS)

_EXTENSION_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_+\-]*(?:\.[A-Za-z0-9][A-Za-z0-9_+\-]*)*\Z",
    flags=re.ASCII,
)
_EVENT_RE = re.compile(r"on[a-z][a-z0-9_\-]*\Z", flags=re.ASCII)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class SmuggleTempPolicy:
    """Bounded retention policy for generated one-shot artifacts."""

    max_age_seconds: float | None = DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS
    max_file_count: int | None = DEFAULT_SMUGGLE_TEMP_MAX_FILES
    max_total_bytes: int | None = DEFAULT_SMUGGLE_TEMP_MAX_BYTES

    def __post_init__(self) -> None:
        if self.max_age_seconds is not None and self.max_age_seconds < 0:
            raise ValueError("smuggle_temp_max_age must be at least 0")
        if self.max_file_count is not None and self.max_file_count < 0:
            raise ValueError("smuggle_temp_file_limit must be at least 0")
        if self.max_total_bytes is not None and self.max_total_bytes < 0:
            raise ValueError("smuggle_temp_storage_limit must be at least 0")


@dataclass(frozen=True, slots=True)
class SmuggleTempArtifact:
    path: Path
    size: int
    mtime: float


@dataclass(frozen=True, slots=True)
class SmuggleTempUsage:
    total_bytes: int
    file_count: int


class SmuggleTempQuotaExceeded(Exception):
    """Raised when an artifact cannot fit the configured retention policy."""


class SmuggleRequestError(ValueError):
    """Stable client-facing SMUGGLE validation error."""

    def __init__(self, message: str, *, code: str, field: str | None = None):
        super().__init__(message)
        self.code = code
        self.field = field


@dataclass(frozen=True, slots=True)
class SafeSmuggleBuilderConfig:
    """Validated canonical builder settings.

    ``mode`` is explicit.  A constructor is never inferred from another
    option, and all tokens are already validated by :mod:`request`.
    """

    mode: str = SMUGGLE_DEFAULT_MODE
    preset: str = SMUGGLE_DEFAULT_PRESET
    locale: str = SMUGGLE_DEFAULT_LOCALE
    encryption: str = SMUGGLE_DEFAULT_ENCRYPTION
    download_name: str | None = None
    download_ext: str | None = None
    title: str | None = None
    message: str | None = None
    cta_label: str | None = None
    delay_ms: int = 0
    show_notice: bool = True
    payload_encoding: str = SMUGGLE_DEFAULT_PAYLOAD_ENCODING
    trigger_method: str = SMUGGLE_DEFAULT_TRIGGER_METHOD
    trigger_event: str = SMUGGLE_DEFAULT_TRIGGER_EVENT
    output_format: str = SMUGGLE_DEFAULT_OUTPUT_FORMAT
    download_variant: str = SMUGGLE_DEFAULT_DOWNLOAD_VARIANT
    page_template: str = SMUGGLE_DEFAULT_PAGE_TEMPLATE
    mime_type: str = "application/octet-stream"
    null_byte: bool = False

    def __post_init__(self) -> None:
        validate_builder_config(self)


@dataclass(frozen=True, slots=True)
class SmugglePolicy:
    """Effective policy snapshot used by all SMUGGLE components."""

    source_max_bytes: int = SMUGGLE_SOURCE_SIZE_LIMIT
    temp_policy: SmuggleTempPolicy = SmuggleTempPolicy()

    def __post_init__(self) -> None:
        if self.source_max_bytes < 0:
            raise ValueError("SMUGGLE source limit must be non-negative")

    def capabilities(self) -> dict[str, object]:
        return build_smuggle_capabilities(
            source_size_limit=self.source_max_bytes,
            temp_policy=self.temp_policy,
        )


DEFAULT_SMUGGLE_POLICY = SmugglePolicy()


def normalize_extension(value: str | None) -> str:
    """Normalize a safe suffix; reject path/control/ambiguous syntax."""
    raw = "" if value is None else value
    if raw.startswith("."):
        raw = raw[1:]
    if (
        not raw
        or len(raw) > SMUGGLE_BUILDER_MAX_DOWNLOAD_EXT
        or _EXTENSION_RE.fullmatch(raw) is None
    ):
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder extension",
            code="invalid_smuggle_extension",
            field="download_ext",
        )
    return raw.lower()


def resolve_download_filename(
    source_filename: str,
    download_name: str | None,
    download_ext: str | None,
) -> str:
    """Resolve the safe download-facing name from canonical builder values."""
    name_parts = source_filename.rsplit(".", 1)
    source_stem = name_parts[0] if len(name_parts) == 2 and name_parts[0] else source_filename
    source_ext = name_parts[1] if len(name_parts) == 2 else ""

    stem = _normalize_download_stem((download_name or source_stem).strip())
    requested_ext = normalize_extension(download_ext) if download_ext is not None else None
    if requested_ext is not None:
        extension = requested_ext
    else:
        try:
            extension = normalize_extension(source_ext) if source_ext else "bin"
        except SmuggleRequestError:
            extension = "bin"
    return f"{stem}.{extension}" if extension else stem


def _normalize_download_stem(stem: str) -> str:
    normalized_chars: list[str] = []
    for char in stem:
        if char.isalnum() or char in {"-", "_", " "}:
            normalized_chars.append(char)
        else:
            normalized_chars.append("-")
    normalized = "-".join("".join(normalized_chars).split())
    while "--" in normalized:
        normalized = normalized.replace("--", "-")
    return normalized.strip("._- ") or "download"


def normalize_locale(value: str | None) -> str:
    raw = SMUGGLE_DEFAULT_LOCALE if value is None else value
    if raw not in SMUGGLE_LOCALES:
        raise SmuggleRequestError(
            "Invalid SMUGGLE locale", code="invalid_smuggle_locale", field="locale"
        )
    return raw


def normalize_enum(value: str | None, allowed: tuple[str, ...], field: str) -> str:
    """Accept only an exact canonical lowercase token from *allowed*."""
    raw = allowed[0] if value is None else value
    if raw not in allowed:
        raise SmuggleRequestError(
            f"Invalid SMUGGLE {'' if field in {'mode', 'encryption'} else 'builder '}{field}",
            code=f"invalid_smuggle_{field}",
            field=field,
        )
    return raw


def parse_bool(value: str | None, *, field: str, default: bool) -> bool:
    """Parse the only public boolean grammar: exact ``0`` or ``1``."""
    if value is None:
        return default
    if value == "1":
        return True
    if value == "0":
        return False
    raise SmuggleRequestError(
        f"Invalid SMUGGLE builder {field}",
        code=f"invalid_smuggle_{field}",
        field=field,
    )


def normalize_trigger(method: str | None, event: str | None) -> tuple[str, str, bool]:
    method_value = normalize_enum(method, SMUGGLE_TRIGGER_METHODS, "trigger_method")
    events = SMUGGLE_TRIGGER_EVENTS[method_value]
    if event is None:
        return method_value, events[0], False
    if event in events:
        return method_value, event, False
    if method_value not in SMUGGLE_CUSTOM_TRIGGER_METHODS or not _EVENT_RE.fullmatch(event):
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder trigger event",
            code="invalid_smuggle_trigger_event",
            field="trigger_event",
        )
    if len(event) > SMUGGLE_BUILDER_MAX_TRIGGER_EVENT:
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder trigger event",
            code="invalid_smuggle_trigger_event",
            field="trigger_event",
        )
    return method_value, event, True


def normalize_optional_text(
    value: str | None,
    *,
    field: str,
    limit: int,
) -> str | None:
    """Validate and trim an optional human-facing builder string."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise SmuggleRequestError(
            f"Invalid SMUGGLE builder {field}",
            code=f"invalid_smuggle_{field}",
            field=field,
        )
    too_long = len(value) > limit
    invalid_control = _CONTROL_RE.search(value) is not None
    if too_long or invalid_control:
        raise SmuggleRequestError(
            f"SMUGGLE builder {field} is too long"
            if too_long
            else f"Invalid SMUGGLE builder {field}",
            code="smuggle_field_too_long" if too_long else f"invalid_smuggle_{field}",
            field=field,
        )
    normalized = value.strip()
    return normalized or None


def normalize_mime_type(value: str | None) -> str:
    """Validate a literal MIME value without case folding or aliases."""
    if value is None:
        return "application/octet-stream"
    if not isinstance(value, str):
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder MIME type",
            code="invalid_smuggle_mime_type",
            field="mime_type",
        )
    too_long = len(value) > SMUGGLE_BUILDER_MAX_MIME_TYPE
    invalid = not value or _CONTROL_RE.search(value) is not None
    if too_long or invalid:
        raise SmuggleRequestError(
            "SMUGGLE builder MIME type is too long"
            if too_long
            else "Invalid SMUGGLE builder MIME type",
            code="smuggle_field_too_long" if too_long else "invalid_smuggle_mime_type",
            field="mime_type",
        )
    return value


def validate_builder_config(builder: SafeSmuggleBuilderConfig) -> None:
    """Validate direct builder construction against the canonical policy.

    HTTP parsing is not the only public seam: callers may construct a builder
    and call :func:`xferry.smuggle.render_artifact` directly. Keeping the
    invariant on the frozen value object prevents that path from bypassing the
    exact-token and size rules enforced for HTTP requests.
    """
    normalize_enum(builder.mode, SMUGGLE_MODES, "mode")
    normalize_enum(builder.preset, SMUGGLE_PRESETS, "preset")
    normalize_locale(builder.locale)
    normalize_enum(builder.encryption, SMUGGLE_ENCRYPTIONS, "encryption")
    normalize_enum(
        builder.payload_encoding,
        SMUGGLE_PAYLOAD_ENCODINGS,
        "payload_encoding",
    )
    trigger_method, trigger_event, _custom = normalize_trigger(
        builder.trigger_method,
        builder.trigger_event,
    )
    if trigger_method != builder.trigger_method or trigger_event != builder.trigger_event:
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder trigger event",
            code="invalid_smuggle_trigger_event",
            field="trigger_event",
        )
    normalize_enum(builder.output_format, SMUGGLE_OUTPUT_FORMATS, "output_format")
    normalize_enum(
        builder.download_variant,
        SMUGGLE_DOWNLOAD_VARIANTS,
        "download_variant",
    )
    normalize_enum(builder.page_template, SMUGGLE_PAGE_TEMPLATES, "page_template")

    if builder.download_ext is not None:
        normalized_extension = normalize_extension(builder.download_ext)
        object.__setattr__(builder, "download_ext", normalized_extension)
    for field, limit in (
        ("download_name", SMUGGLE_BUILDER_MAX_DOWNLOAD_NAME),
        ("title", SMUGGLE_BUILDER_MAX_TITLE),
        ("message", SMUGGLE_BUILDER_MAX_MESSAGE),
        ("cta_label", SMUGGLE_BUILDER_MAX_CTA_LABEL),
    ):
        normalized_text = normalize_optional_text(
            getattr(builder, field),
            field=field,
            limit=limit,
        )
        object.__setattr__(builder, field, normalized_text)
    object.__setattr__(builder, "mime_type", normalize_mime_type(builder.mime_type))

    if (
        type(builder.delay_ms) is not int
        or not 0 <= builder.delay_ms <= SMUGGLE_BUILDER_MAX_DELAY_MS
    ):
        raise SmuggleRequestError(
            "Invalid SMUGGLE builder delay",
            code="invalid_smuggle_delay",
            field="delay_ms",
        )
    for field in ("show_notice", "null_byte"):
        if type(getattr(builder, field)) is not bool:
            raise SmuggleRequestError(
                f"Invalid SMUGGLE builder {field}",
                code=f"invalid_smuggle_{field}",
                field=field,
            )

    if builder.mode == SMUGGLE_DEFAULT_MODE:
        constructor_defaults = SafeSmuggleBuilderConfig.__dataclass_fields__
        for field in SMUGGLE_CONSTRUCTOR_ONLY_FIELDS:
            if getattr(builder, field) != constructor_defaults[field].default:
                raise SmuggleRequestError(
                    "SMUGGLE constructor options require mode=constructor",
                    code="invalid_smuggle_configuration",
                    field=field,
                )
    else:
        simple_defaults = SafeSmuggleBuilderConfig.__dataclass_fields__
        for field in SMUGGLE_SIMPLE_ONLY_FIELDS:
            if getattr(builder, field) != simple_defaults[field].default:
                raise SmuggleRequestError(
                    "SMUGGLE simple options require mode=simple",
                    code="invalid_smuggle_configuration",
                    field=field,
                )


DEFAULT_SMUGGLE_BUILDER = SafeSmuggleBuilderConfig()


def build_smuggle_capabilities(
    *,
    source_size_limit: int = SMUGGLE_SOURCE_SIZE_LIMIT,
    temp_policy: SmuggleTempPolicy | None = None,
) -> dict[str, object]:
    """Build the mandatory, JSON-safe capability contract."""
    policy = temp_policy if temp_policy is not None else SmuggleTempPolicy()
    defaults = DEFAULT_SMUGGLE_BUILDER
    return {
        "schema_version": SMUGGLE_SCHEMA_VERSION,
        "source_max_bytes": int(source_size_limit),
        "field_limits": {
            "download_name": SMUGGLE_BUILDER_MAX_DOWNLOAD_NAME,
            "download_ext": SMUGGLE_BUILDER_MAX_DOWNLOAD_EXT,
            "title": SMUGGLE_BUILDER_MAX_TITLE,
            "message": SMUGGLE_BUILDER_MAX_MESSAGE,
            "cta_label": SMUGGLE_BUILDER_MAX_CTA_LABEL,
            "delay_ms": SMUGGLE_BUILDER_MAX_DELAY_MS,
            "mime_type": SMUGGLE_BUILDER_MAX_MIME_TYPE,
            "trigger_event": SMUGGLE_BUILDER_MAX_TRIGGER_EVENT,
        },
        "defaults": {
            "mode": defaults.mode,
            "preset": defaults.preset,
            "locale": defaults.locale,
            "encryption": defaults.encryption,
            "payload_encoding": defaults.payload_encoding,
            "trigger_method": defaults.trigger_method,
            "trigger_event": defaults.trigger_event,
            "output_format": defaults.output_format,
            "download_variant": defaults.download_variant,
            "page_template": defaults.page_template,
            "mime_type": defaults.mime_type,
            "delay_ms": defaults.delay_ms,
            "show_notice": defaults.show_notice,
            "null_byte": defaults.null_byte,
        },
        "mode_fields": {
            "simple_only": sorted(SMUGGLE_SIMPLE_ONLY_FIELDS),
            "constructor_only": sorted(SMUGGLE_CONSTRUCTOR_ONLY_FIELDS),
        },
        "extensions": list(SMUGGLE_EXTENSIONS),
        "mime_presets": list(SMUGGLE_MIME_PRESETS),
        "mime_by_extension": dict(SMUGGLE_MIME_BY_EXTENSION),
        "presets": list(SMUGGLE_PRESETS),
        "locales": list(SMUGGLE_LOCALES),
        "encryption_modes": list(SMUGGLE_ENCRYPTIONS),
        "modes": list(SMUGGLE_MODES),
        "payload_encodings": list(SMUGGLE_PAYLOAD_ENCODINGS),
        "output_formats": list(SMUGGLE_OUTPUT_FORMATS),
        "page_templates": list(SMUGGLE_PAGE_TEMPLATES),
        "download_variants": list(SMUGGLE_DOWNLOAD_VARIANTS),
        "trigger_events": {
            method: list(events) for method, events in SMUGGLE_TRIGGER_EVENTS.items()
        },
        "custom_trigger_methods": list(SMUGGLE_CUSTOM_TRIGGER_METHODS),
        "temp_policy": {
            "max_age_seconds": policy.max_age_seconds,
            "max_file_count": policy.max_file_count,
            "max_total_bytes": policy.max_total_bytes,
        },
        "caps": {
            "one_shot": True,
            "constructor": True,
            "xor_obfuscation": True,
            "aes_gcm": True,
            "source_cap_enforced": True,
            "custom_extension": True,
            "custom_mime_type": True,
            "custom_trigger_event": True,
            "searchable_options": True,
        },
    }


__all__ = [
    "DEFAULT_SMUGGLE_POLICY",
    "DEFAULT_SMUGGLE_BUILDER",
    "DEFAULT_SMUGGLE_TEMP_MAX_AGE_SECONDS",
    "DEFAULT_SMUGGLE_TEMP_MAX_BYTES",
    "DEFAULT_SMUGGLE_TEMP_MAX_FILES",
    "SMUGGLE_BUILDER_MAX_CTA_LABEL",
    "SMUGGLE_BUILDER_MAX_DELAY_MS",
    "SMUGGLE_BUILDER_MAX_DOWNLOAD_EXT",
    "SMUGGLE_BUILDER_MAX_DOWNLOAD_NAME",
    "SMUGGLE_BUILDER_MAX_MESSAGE",
    "SMUGGLE_BUILDER_MAX_MIME_TYPE",
    "SMUGGLE_BUILDER_MAX_TITLE",
    "SMUGGLE_BUILDER_MAX_TRIGGER_EVENT",
    "SMUGGLE_CUSTOM_TRIGGER_METHODS",
    "SMUGGLE_DEFAULT_LOCALE",
    "SMUGGLE_DOWNLOAD_VARIANTS",
    "SMUGGLE_ENCRYPTIONS",
    "SMUGGLE_ERROR_PATH_DETAIL_MAX_CHARS",
    "SMUGGLE_EXTENSIONS",
    "SMUGGLE_LOCALES",
    "SMUGGLE_MIME_BY_EXTENSION",
    "SMUGGLE_MIME_PRESETS",
    "SMUGGLE_MODES",
    "SMUGGLE_OUTPUT_CONTENT_TYPES",
    "SMUGGLE_OUTPUT_FORMATS",
    "SMUGGLE_PAGE_TEMPLATES",
    "SMUGGLE_PAYLOAD_ENCODINGS",
    "SMUGGLE_PRESETS",
    "SMUGGLE_SCHEMA_VERSION",
    "SMUGGLE_SOURCE_SIZE_LIMIT",
    "SMUGGLE_TEMP_EXTENSIONS",
    "SMUGGLE_TEMP_TOKEN_LENGTH",
    "SMUGGLE_TRIGGER_EVENTS",
    "SMUGGLE_TRIGGER_METHODS",
    "SafeSmuggleBuilderConfig",
    "SmugglePolicy",
    "SmuggleRequestError",
    "SmuggleTempArtifact",
    "SmuggleTempPolicy",
    "SmuggleTempQuotaExceeded",
    "SmuggleTempUsage",
    "build_smuggle_capabilities",
    "normalize_enum",
    "normalize_extension",
    "normalize_locale",
    "normalize_trigger",
    "parse_bool",
    "resolve_download_filename",
    "validate_builder_config",
]
