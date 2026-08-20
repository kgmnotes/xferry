"""Canonical renderer coverage for the decomposed SMUGGLE backend."""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from html import unescape

import pytest

from xferry.security.crypto import aes_decrypt, xor_decrypt
from xferry.smuggle import SafeSmuggleBuilderConfig, render_artifact
from xferry.smuggle.policy import (
    SMUGGLE_CUSTOM_TRIGGER_METHODS,
    SMUGGLE_DOWNLOAD_VARIANTS,
    SMUGGLE_ENCRYPTIONS,
    SMUGGLE_OUTPUT_FORMATS,
    SMUGGLE_PAGE_TEMPLATES,
    SMUGGLE_PAYLOAD_ENCODINGS,
    SMUGGLE_TRIGGER_EVENTS,
    normalize_extension,
    resolve_download_filename,
)


def _artifact_text(content: bytes) -> str:
    payload = content[1:] if content.startswith(b"\x00") else content
    return payload.decode("utf-8")


def _protected_wire(content: bytes, mode: str) -> bytes:
    text = _artifact_text(content)
    if mode == "simple":
        match = re.search(r'var payload="([A-Za-z0-9+/=]+)"', text)
    else:
        match = re.search(r"atob\('([A-Za-z0-9+/=]+)'\)", unescape(text))
    assert match is not None
    return base64.b64decode(match.group(1), validate=True)


@pytest.mark.parametrize("payload_encoding", SMUGGLE_PAYLOAD_ENCODINGS)
def test_constructor_payload_encoding_matrix(payload_encoding: str) -> None:
    artifact = render_artifact(
        b"matrix payload",
        "source.bin",
        SafeSmuggleBuilderConfig(
            mode="constructor",
            download_name="Matrix",
            download_ext="txt",
            payload_encoding=payload_encoding,
        ),
    )

    javascript_text = unescape(_artifact_text(artifact.content))
    markers = {
        "base64": "atob('bWF0cml4IHBheWxvYWQ=')",
        "base64url": ".replace(/-/g,'+').replace(/_/g,'/')",
        "base32": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "percent": "s.match(/%[0-9A-F]{2}/g)",
        "reverse": "reverse().join(''))",
        "xor": "^k;",
        "hex": "var h='6d6174726978207061796c6f6164'",
        "split": "var p=['bWF0cml4IHBheWxvYWQ=']",
        "attrs": 'id="p"',
        "charcode": "new Uint8Array([109,97,116,114,105,120,32,112,97,121,108,111,97,100])",
    }

    assert artifact.payload_encoding == payload_encoding
    assert artifact.download_name == "Matrix.txt"
    assert markers[payload_encoding] in javascript_text


@pytest.mark.parametrize("output_format", SMUGGLE_OUTPUT_FORMATS)
def test_constructor_output_format_matrix(output_format: str) -> None:
    artifact = render_artifact(
        b"matrix payload",
        "source.bin",
        SafeSmuggleBuilderConfig(
            mode="constructor",
            output_format=output_format,
        ),
    )

    text = _artifact_text(artifact.content)
    assert artifact.extension == f".{output_format}"
    assert artifact.output_format == output_format
    if output_format == "svg":
        assert text.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        assert "<foreignObject" in text
        assert ET.fromstring(artifact.content) is not None
    elif output_format in {"xhtml", "xht", "xhtm", "xml"}:
        assert text.startswith('<?xml version="1.0" encoding="UTF-8"?>')
        assert 'xmlns="http://www.w3.org/1999/xhtml"' in text
        assert ET.fromstring(artifact.content) is not None
    else:
        assert text.startswith("<!DOCTYPE html>")


@pytest.mark.parametrize("download_variant", SMUGGLE_DOWNLOAD_VARIANTS)
def test_constructor_download_variant_matrix(download_variant: str) -> None:
    artifact = render_artifact(
        b"matrix payload",
        "source.bin",
        SafeSmuggleBuilderConfig(
            mode="constructor",
            download_name="Matrix",
            download_ext="txt",
            download_variant=download_variant,
            mime_type="application/pdf",
        ),
    )

    javascript_text = unescape(_artifact_text(artifact.content))
    markers = {
        "blob-anchor": "createObjectURL(new Blob([a]",
        "data-uri": "l.href='data:'+mt+';base64,'",
        "iframe-blob": "contentWindow.document",
        "filereader": "new FileReader()",
        "fetch-blob": "fetch(u).then",
        "window-open": "window.open",
        "loc-assign": "window.location.assign",
        "form-post": "new MouseEvent",
        "timeout-blob": "setTimeout(function()",
        "promise-blob": "Promise.resolve",
        "raf-blob": "requestAnimationFrame",
        "microtask-blob": "queueMicrotask",
        "observer-blob": "new MutationObserver",
        "response-blob": "new Response(a,{headers:{'Content-Type':mt}}).blob()",
        "readable-stream": "new ReadableStream",
        "message-channel-blob": "new MessageChannel",
        "idle-callback-blob": "requestIdleCallback",
    }

    assert artifact.download_variant == download_variant
    assert artifact.download_name_applied is (download_variant != "loc-assign")
    assert markers[download_variant] in javascript_text


@pytest.mark.parametrize(
    ("trigger_method", "trigger_event"),
    [(method, event) for method, events in SMUGGLE_TRIGGER_EVENTS.items() for event in events],
)
def test_constructor_builtin_trigger_matrix(
    trigger_method: str,
    trigger_event: str,
) -> None:
    artifact = render_artifact(
        b"matrix payload",
        "source.bin",
        SafeSmuggleBuilderConfig(
            mode="constructor",
            trigger_method=trigger_method,
            trigger_event=trigger_event,
        ),
    )

    text = _artifact_text(artifact.content)
    assert artifact.trigger_method == trigger_method
    assert artifact.trigger_event == trigger_event
    assert artifact.trigger_event_custom is False
    assert trigger_event in text


@pytest.mark.parametrize("trigger_method", SMUGGLE_CUSTOM_TRIGGER_METHODS)
def test_constructor_custom_trigger_matrix(trigger_method: str) -> None:
    artifact = render_artifact(
        b"custom trigger payload",
        "source.bin",
        SafeSmuggleBuilderConfig(
            mode="constructor",
            trigger_method=trigger_method,
            trigger_event="onxferry-ready",
        ),
    )

    text = _artifact_text(artifact.content)
    assert artifact.trigger_event == "onxferry-ready"
    assert artifact.trigger_event_custom is True
    assert 'addEventListener("xferry-ready"' in text


@pytest.mark.parametrize("page_template", SMUGGLE_PAGE_TEMPLATES)
def test_constructor_page_template_matrix(page_template: str) -> None:
    artifact = render_artifact(
        b"template payload",
        "source.bin",
        SafeSmuggleBuilderConfig(
            mode="constructor",
            page_template=page_template,
            title="Controlled title",
            message="Controlled message",
        ),
    )

    text = _artifact_text(artifact.content)
    assert artifact.page_template == page_template
    assert "Controlled title" in text
    assert "Controlled message" in text


@pytest.mark.parametrize("mode", ["simple", "constructor"])
@pytest.mark.parametrize("encryption", SMUGGLE_ENCRYPTIONS)
def test_renderer_supports_none_xor_and_aes(mode: str, encryption: str) -> None:
    source = b"canonical encryption matrix"
    password = None if encryption == "none" else "correct horse battery staple"
    artifact = render_artifact(
        source,
        "source.bin",
        SafeSmuggleBuilderConfig(mode=mode, encryption=encryption),
        password=password,
    )

    wire = _protected_wire(artifact.content, mode)
    if encryption == "none":
        assert wire == source
        assert artifact.password is None
    elif encryption == "xor":
        assert xor_decrypt(wire, password or "") == source
        assert artifact.password == password
    else:
        assert aes_decrypt(wire, password or "") == source
        assert artifact.password == password
    assert artifact.encryption == encryption
    assert artifact.encrypted is (encryption != "none")
    assert artifact.effective_mode == mode


def test_simple_presets_have_distinct_start_behavior() -> None:
    direct = render_artifact(
        b"payload",
        "source.bin",
        SafeSmuggleBuilderConfig(mode="simple", preset="direct"),
    )
    manual = render_artifact(
        b"payload",
        "source.bin",
        SafeSmuggleBuilderConfig(mode="simple", preset="card_manual"),
    )
    automatic = render_artifact(
        b"payload",
        "source.bin",
        SafeSmuggleBuilderConfig(mode="simple", preset="card_auto", delay_ms=1200),
    )

    direct_text = _artifact_text(direct.content)
    manual_text = _artifact_text(manual.content)
    automatic_text = _artifact_text(automatic.content)
    assert "setTimeout(startDownload,500)" in direct_text
    assert "&&false)setTimeout(startDownload,0)" in manual_text
    assert 'id="downloadBtn"' in manual_text
    assert 'id="smuggleCountdown"' in automatic_text
    assert "setTimeout(startDownload,1200)" in automatic_text


def test_constructor_custom_mime_is_preserved_and_script_safe() -> None:
    mime_type = "Application/X-XFerry; charset=\"UTF-8\"; note='A<&>Ω\\tail'"
    artifact = render_artifact(
        b"payload",
        "source.bin",
        SafeSmuggleBuilderConfig(
            mode="constructor",
            download_name="Custom MIME",
            download_ext="acme+pkg",
            mime_type=mime_type,
        ),
    )

    javascript_text = unescape(_artifact_text(artifact.content))
    escaped_text = javascript_text.lower()
    assert artifact.mime_type == mime_type
    assert artifact.download_name == "Custom-MIME.acme+pkg"
    assert mime_type not in javascript_text
    for marker in ("\\u0022", "\\u0027", "\\u003c", "\\u003e", "\\u0026", "\\u03a9"):
        assert marker.lower() in escaped_text


@pytest.mark.parametrize(
    ("raw_extension", "normalized"),
    [
        ("exe", "exe"),
        (".DOCX", "docx"),
        ("7z", "7z"),
        ("tar.gz", "tar.gz"),
        ("Acme+Package", "acme+package"),
    ],
)
def test_extension_normalization_accepts_safe_values(
    raw_extension: str,
    normalized: str,
) -> None:
    assert normalize_extension(raw_extension) == normalized


@pytest.mark.parametrize(
    "raw_extension",
    ["../exe", "tar..gz", "bad/ext", r"bad\ext", "bad ext", "-leading", "x" * 33],
)
def test_extension_normalization_rejects_unsafe_values(raw_extension: str) -> None:
    with pytest.raises(ValueError, match="Invalid SMUGGLE builder extension"):
        normalize_extension(raw_extension)


def test_download_filename_uses_canonical_stem_and_extension() -> None:
    assert (
        resolve_download_filename(
            source_filename="report.bin",
            download_name="../Quarterly\nReport ",
            download_ext=".DOCX",
        )
        == "Quarterly-Report.docx"
    )
