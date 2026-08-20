"""Tests for static UI asset packaging checks."""

import json
import re
import subprocess
from pathlib import Path

from tools.check_static_ui_assets import collect_index_static_assets
from xferry.smuggle.policy import build_smuggle_capabilities

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "xferry" / "data" / "static" / "ui"


def test_browser_xor_and_node_crypto_match_fixed_interoperability_vectors() -> None:
    """Run the canonical browser XOR helper beside independent Node AES/HMAC."""
    script = r"""
const fs = require('node:fs');
const crypto = require('node:crypto');

function extractFunction(source, syncMarker, asyncMarker, nextMarker) {
    const marker = source.includes(asyncMarker) ? asyncMarker : syncMarker;
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${syncMarker}`);
    return eval(`(${source.slice(start, end).trim()})`);
}

(async () => {
    globalThis.crypto = crypto.webcrypto;
    const compiler = fs.readFileSync(process.argv[1], 'utf8');
    const files = fs.readFileSync(process.argv[2], 'utf8');
    const xorEncrypt = extractFunction(
        compiler,
        'function xorEncrypt(bytes, password, cryptoApi)',
        'async function xorEncrypt(bytes, password, cryptoApi)',
        'async function aesEncrypt'
    );
    const xorDecryptBytes = extractFunction(
        files,
        'function xorDecryptBytes(data, password)',
        'async function xorDecryptBytes(data, password)',
        'function getXorDecryptResponseHeader'
    );
    const password = 'correct horse battery staple';
    const plaintext = Buffer.from('58466572727920332064657465726d696e697374696320e29c93', 'hex');
    const xorExpected = Buffer.from('9cfdae6dccb0bd569f3dbd28e9c4438bb5ff4c7b8865d461453c', 'hex');
    const wire = Buffer.from(
        'AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhtUVBi3YoaIROve/LypgRmTf1HpkO8E9klfo+b3D3vjGxz/C3mk/XjkTEI=',
        'base64'
    );
    const key = crypto.pbkdf2Sync(password, wire.subarray(1, 17), 600000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, wire.subarray(17, 29));
    decipher.setAuthTag(wire.subarray(wire.length - 16));
    const aesPlaintext = Buffer.concat([
        decipher.update(wire.subarray(29, wire.length - 16)),
        decipher.final(),
    ]);
    const xorCiphertext = Buffer.from(await Promise.resolve(
        xorEncrypt(plaintext, password, crypto.webcrypto)
    ));
    const xorPlaintext = Buffer.from(await Promise.resolve(xorDecryptBytes(xorExpected, password)));
    const hmac = crypto
        .createHmac('sha256', Buffer.from(password, 'utf8'))
        .update(wire)
        .digest('hex');
    process.stdout.write(JSON.stringify({
        aesPlaintext: aesPlaintext.toString('hex'),
        xorCiphertext: xorCiphertext.toString('hex'),
        xorPlaintext: xorPlaintext.toString('hex'),
        hmac,
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""

    completed = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(UI_ROOT / "advanced-compiler.js"),
            str(UI_ROOT / "files.js"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "aesPlaintext": "58466572727920332064657465726d696e697374696320e29c93",
        "xorCiphertext": "9cfdae6dccb0bd569f3dbd28e9c4438bb5ff4c7b8865d461453c",
        "xorPlaintext": "58466572727920332064657465726d696e697374696320e29c93",
        "hmac": "22fcd72c80c002a91d7eea3f7ea4e5b9cd031feb90674e6ce2f30251f599b0cc",
    }


def extract_locale_values(core_js: str, locale: str) -> str:
    block = extract_locale_block(core_js, locale)
    return "\n".join(re.findall(r': "((?:[^"\\]|\\.)*)"', block))


def extract_locale_block(core_js: str, locale: str) -> str:
    if locale == "ru":
        return core_js.split("ru: {", 1)[1].split("\n    },\n    en: {", 1)[0]
    if locale == "en":
        return core_js.split("en: {", 1)[1].split("\n    }\n};", 1)[0]
    raise ValueError(f"Unsupported locale: {locale}")


def extract_locale_keys(core_js: str, locale: str) -> set[str]:
    block = extract_locale_block(core_js, locale)
    return set(re.findall(r"^\s*([A-Za-z][A-Za-z0-9_]*):", block, flags=re.MULTILINE))


def test_advanced_method_override_copy_uses_canonical_field_name_in_both_locales() -> None:
    """Catches the rejected legacy `_method` spelling returning to live UI copy."""
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")
    values = {
        locale: re.findall(
            r'^\s*opsecMethodOverrideForm:\s*"([^"]*)"',
            extract_locale_block(core_js, locale),
            flags=re.MULTILINE,
        )
        for locale in ("ru", "en")
    }

    assert values == {
        "ru": ["Поле method_override"],
        "en": ["method_override field"],
    }


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def extract_top_tab_buttons(html: str) -> list[tuple[str, str, str]]:
    tablist = html.split('<div class="tabs mode-tabs"', 1)[1].split(
        '<div class="workspace-stage">',
        1,
    )[0]
    return re.findall(
        r'<button\b[^>]*\bid="(tab-[^"]+)"[^>]*\bdata-i18n="([^"]+)"[^>]*>([^<]+)</button>',
        tablist,
    )


def extract_workspace_panel(html: str, panel_id: str) -> str:
    panel_marker = f'<section id="{panel_id}"'
    panel_start = html.index(panel_marker)
    next_panel = re.search(r'\n\s{20}<section id="[^"]+-tab"', html[panel_start + 1 :])
    if next_panel is None:
        return html[panel_start:]
    return html[panel_start : panel_start + 1 + next_panel.start()]


def test_static_ui_uses_larger_readable_base_scale() -> None:
    tokens_css = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "tokens.css").read_text(
        encoding="utf-8"
    )
    base_css = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "base.css").read_text(
        encoding="utf-8"
    )
    css_bundle = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (REPO_ROOT / "xferry" / "data" / "static" / "ui").glob("*.css")
    )

    assert "--app-font-size: 18px;" in tokens_css
    assert "--content-width: 1440px;" in tokens_css
    assert "font-size: var(--app-font-size);" in base_css
    assert "zoom:" not in css_bundle


def test_collect_index_static_assets_tracks_styles_scripts_icons_and_images() -> None:
    html = """
    <link rel="stylesheet" href="/static/ui/tokens.css">
    <link rel="icon" href="/static/ui/xferry-mark.svg"
          data-theme-dark="/static/ui/xferry-mark.svg"
          data-theme-light="/static/ui/xferry-mark-light.svg">
    <script src="/static/ui/core.js"></script>
    <img src="/static/ui/example-illustration.png" alt="">
    <img src="https://example.test/remote.png" alt="">
    """

    assert collect_index_static_assets(html) == [
        "static/ui/tokens.css",
        "static/ui/xferry-mark.svg",
        "static/ui/xferry-mark-light.svg",
        "static/ui/core.js",
        "static/ui/example-illustration.png",
    ]


def test_secure_web_gateway_positioning_covers_the_full_toolkit() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    docs_index = (REPO_ROOT / "docs" / "index.md").read_text(encoding="utf-8")

    assert "веб-шлюзов безопасности (SWG)" in html
    assert "SWG" in core_js
    assert "testing Secure Web Gateways" in readme
    assert "Secure Web Gateway" in normalize_ws(docs_index)
    assert "custom HTTP methods" in readme
    assert "transport experiments" in normalize_ws(docs_index)

    assert "DLP path testing" not in html
    assert "DLP path testing" not in core_js
    assert "HTTP-паром для DLP-проверок" not in html
    assert "HTTP-паром для DLP-проверок" not in core_js


def test_russian_locale_uses_russian_swg_tool_copy() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    ru_values = extract_locale_values(core_js, "ru")

    tagline = "Инструмент для тестирования SWG"
    assert tagline in html
    assert f'brandTagline: "{tagline}"' in core_js
    assert "HTTP-инструмент для Secure Web Gateway проверок" not in html
    assert "HTTP-инструмент для Secure Web Gateway проверок" not in core_js

    assert extract_top_tab_buttons(html) == [
        ("tab-upload", "tabUpload", "Отправить"),
        ("tab-files", "tabFiles", "Файлы"),
        ("tab-request", "tabRequests", "Запросы"),
        ("tab-opsec", "tabOpsec", "Расширенные"),
        ("tab-notepad", "tabNotepad", "Блокнот"),
    ]
    assert 'tabUpload: "Отправить"' in core_js
    assert 'tabFiles: "Файлы"' in core_js
    assert 'tabRequests: "Запросы"' in core_js
    assert 'tabOpsec: "Расширенные"' in core_js
    assert 'tabNotepad: "Блокнот"' in core_js

    for expected in (
        'requestPreviewModeRaw: "Исходный HTTP"',
        'requestPreviewCheckMatch: "Совпадает"',
        'requestPreviewCheckMismatch: "Не совпадает"',
        'uploadRawHttpRequestTitle: "Исходный HTTP-запрос"',
        'uploadRawHttpResponseTitle: "Исходный HTTP-ответ"',
        'opsecRawHttpRequestTitle: "Исходный HTTP-запрос"',
        'opsecRawHttpResponseTitle: "Исходный HTTP-ответ"',
        'opsecBodyFormatRaw: "Сырые байты"',
        'opsecBodyFormatText: "Текст"',
        'opsecBodyFormatForm: "Форма"',
        'opsecEncodingRaw: "Без кодирования"',
        'opsecMetadataBody: "Тело"',
        'opsecMetadataHeaders: "Заголовки"',
        'opsecMetadataQuery: "Параметры URL"',
        'opsecMetadataPath: "Путь URL"',
        'opsecMethodOverrideLabel: "Переопределение метода"',
        'opsecMethodOverrideHeader: "Заголовок"',
        'opsecMethodOverrideQuery: "Параметр URL"',
        'opsecMethodOverrideForm: "Поле method_override"',
    ):
        assert expected in core_js

    for stale_phrase in (
        "Upload (regular)",
        "Upload (advanced)",
        "Raw HTTP",
        "RAW HTTP Request",
        "RAW HTTP Response",
        "RAW-запрос",
        "RAW-ответ",
        "Raw binary",
        "browser-managed",
        "Cookie header",
        "Multipart boundary",
        "byte-exact",
        "frontend JS",
        "upload handler",
        "constructor renderer",
        "Null byte",
        "Payload лежит",
        "payload",
        "Body",
        "Headers",
        "Query",
        "Path",
        "_method field",
    ):
        assert stale_phrase not in ru_values


def test_header_brand_uses_compact_copy_and_theme_aware_ferry_marks() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    header = html.split('<header class="topbar">', 1)[1].split("</header>", 1)[0]
    static_assets = collect_index_static_assets(html)
    dark_mark = UI_ROOT / "xferry-mark.svg"
    light_mark = UI_ROOT / "xferry-mark-light.svg"

    assert 'brandTagline: "Инструмент для тестирования SWG"' in core_js
    assert 'brandTagline: "SWG testing tool"' in core_js
    assert header.count("<img ") == 1
    assert 'id="brandMark"' in header
    assert 'data-theme-dark="/static/ui/xferry-mark.svg"' in header
    assert 'data-theme-light="/static/ui/xferry-mark-light.svg"' in header
    assert 'id="appFavicon"' in html
    assert 'data-theme-dark="/static/ui/xferry-mark.svg"' in html
    assert 'data-theme-light="/static/ui/xferry-mark-light.svg"' in html
    assert "xferry-mascot" not in header
    assert "static/ui/xferry-mascot.png" not in static_assets
    assert "static/ui/xferry-mark.svg" in static_assets
    assert "static/ui/xferry-mark-light.svg" in static_assets

    for mark_path, background, ferry in (
        (dark_mark, "#1a1d20", "#2eb8ff"),
        (light_mark, "#f1eeee", "#064f91"),
    ):
        mark_svg = mark_path.read_text(encoding="utf-8")
        assert "Material Design Icons" in mark_svg
        assert "Apache-2.0" in mark_svg
        assert background in mark_svg
        assert ferry in mark_svg
        assert 'd="M6 6h12v3.96L12 8L6 9.96' in mark_svg

    assert "syncThemeAssets();" in core_js


def test_primary_navigation_uses_manual_tool_actions() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )

    expected_ru_labels = {
        "tabUpload": "Отправить",
        "tabFiles": "Файлы",
        "tabRequests": "Запросы",
        "tabOpsec": "Расширенные",
        "tabNotepad": "Блокнот",
    }
    expected_en_labels = {
        "tabUpload": "Send",
        "tabFiles": "Files",
        "tabRequests": "Requests",
        "tabOpsec": "Advanced",
        "tabNotepad": "Notepad",
    }
    for key, label in expected_ru_labels.items():
        assert f'{key}: "{label}"' in core_js
    for key, label in expected_en_labels.items():
        assert f'{key}: "{label}"' in core_js

    assert extract_top_tab_buttons(html) == [
        ("tab-upload", "tabUpload", "Отправить"),
        ("tab-files", "tabFiles", "Файлы"),
        ("tab-request", "tabRequests", "Запросы"),
        ("tab-opsec", "tabOpsec", "Расширенные"),
        ("tab-notepad", "tabNotepad", "Блокнот"),
    ]
    assert 'tabUpload: "Upload (regular)"' not in core_js
    assert 'tabOpsec: "Upload (advanced)"' not in core_js
    assert 'tabFiles: "Download"' not in core_js


def test_advanced_upload_constructor_is_profile_first() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    opsec_js = (UI_ROOT / "opsec.js").read_text(encoding="utf-8")

    assert 'class="opsec-flow-grid"' in html
    for step in ("endpoint", "profile", "file"):
        assert f'data-opsec-flow-step="{step}"' in html

    assert 'id="opsecSettingsDetails"' in html
    assert 'data-testid="opsec-advanced-options"' in html
    assert 'data-testid="opsec-outcome-summary"' in html
    for element_id in (
        "opsecConstructorMode",
        "opsecProfileSelect",
        "opsecCarrierSelect",
        "opsecMethodOverrideSelect",
        "opsecBodyFormatSelect",
        "opsecEncodingSelect",
        "opsecMimeInput",
        "opsecPartMimeInput",
        "opsecEncryptionSelect",
        "opsecEncryptionPanel",
        "opsecPassword",
        "opsecKeyBase64",
        "opsecFilenamePrimarySelect",
        "opsecFilenameCopies",
        "opsecNormalizationList",
        "opsecValidationError",
        "opsecSizeWarning",
    ):
        assert html.count(f'id="{element_id}"') == 1

    for profile_id in (
        "body-json",
        "body-raw",
        "body-text",
        "body-form",
        "body-xml",
        "multipart-binary",
        "multipart-encoded",
        "headers",
        "query",
        "cookies",
        "path",
    ):
        assert f'<option value="{profile_id}"' in html
    assert '<option value="managed"' in html
    assert '<option value="experimental"' in html
    assert '<option value="body-json" selected' in html
    assert '<option value="base64" selected' in html
    assert '<option value="hidden" selected' in html

    assert "function readAdvancedRequestState()" in opsec_js
    assert "function normalizeAdvancedRequestState(raw, sessionSnapshot)" in opsec_js
    assert "async function compileAdvancedRequest(normalized, file, sessionSnapshot)" in opsec_js
    assert "preview: null" in opsec_js
    assert "fingerprint" in opsec_js
    assert "cookieEffects" in opsec_js
    assert "opsecTransportAutoSwitch" not in opsec_js

    for key in (
        "opsecConstructorModeLabel",
        "opsecConstructorModeManaged",
        "opsecConstructorModeExperimental",
        "opsecProfileLabel",
        "opsecProfileBodyJson",
        "opsecProfileMultipartBinary",
        "opsecProfileMultipartEncoded",
        "opsecNormalizationTitle",
        "opsecValidationTitle",
        "opsecSizeWarningTitle",
        "opsecMimeDecoderMismatch",
    ):
        assert f"{key}:" in core_js


def test_regular_upload_exposes_profile_summary_compare_without_advanced_coupling() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    upload_tab = html.split('<section id="upload-tab"', 1)[1].split('<section id="opsec-tab"', 1)[0]

    assert 'id="uploadProfileGroup"' in upload_tab
    assert re.findall(
        r'class="[^"]*upload-profile-btn[^"]*"\s+data-upload-profile="([^"]+)"',
        upload_tab,
    ) == ["multipart", "raw-url", "raw-header"]
    assert 'data-upload-profile="multipart" role="radio" aria-checked="true"' in upload_tab
    assert 'id="uploadRequestSummary"' in upload_tab
    for field in ("request-line", "body-kind", "mime", "filename-source"):
        assert f'data-upload-summary="{field}"' in upload_tab
    assert 'id="uploadCompareBtn"' in upload_tab
    assert 'id="uploadCompareResults"' in upload_tab
    assert 'id="basicAdvancedRoutingWarning"' not in upload_tab
    assert 'id="basicAdvancedRoutingDisableBtn"' not in upload_tab
    assert 'id="uploadHelpDetails"' not in upload_tab
    assert 'class="upload-flow-strip"' not in upload_tab

    locale_keys = {
        "uploadProfileLabel",
        "uploadProfileMultipart",
        "uploadProfileRawUrl",
        "uploadProfileRawHeader",
        "uploadRequestSummaryTitle",
        "uploadSummaryRequestLine",
        "uploadSummaryBodyKind",
        "uploadSummaryMime",
        "uploadSummaryFilenameSource",
        "uploadCompareBtn",
        "uploadCompareConfirmTitle",
        "uploadCompareConfirmBody",
        "uploadCompareConfirmAction",
        "uploadRoutingConflict",
        "uploadVerdictDelivered",
        "uploadVerdictMetadataChanged",
        "uploadVerdictContentChanged",
        "uploadVerdictRejected",
        "uploadVerdictNotConfirmed",
        "uploadVerdictNotRun",
    }
    assert extract_locale_keys(core_js, "ru") >= locale_keys
    assert extract_locale_keys(core_js, "en") >= locale_keys

    forbidden_visible_experimental_phrases = (
        "experimental-сценари",
        "experimental-провер",
        "experimental-проф",
        "Experimental only",
        "experimental-only",
        "experimental verification",
        "experimental profile",
    )
    for phrase in forbidden_visible_experimental_phrases:
        assert phrase not in upload_tab
        assert phrase not in core_js


def test_upload_composer_exposes_one_visible_method_group_before_file_controls() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    upload_tab = html.split('<section id="upload-tab"', 1)[1].split('<section id="opsec-tab"', 1)[0]
    assert upload_tab.count('class="upload-method-section"') == 1
    assert upload_tab.count('class="upload-method-group"') == 1
    assert upload_tab.count('role="radiogroup"') == 2
    assert re.findall(
        r'class="[^"]*upload-method-btn[^"]*"\s+data-upload-method="([A-Z]+)"',
        upload_tab,
    ) == ["POST", "NONE", "PUT", "PATCH"]

    for element_id in (
        "dropZone",
        "fileInput",
        "fileList",
        "uploadBtn",
        "uploadCompareBtn",
        "uploadSelectionState",
        "uploadRequestSummary",
    ):
        assert upload_tab.count(f'id="{element_id}"') == 1

    source_order = (
        'class="upload-method-section"',
        'id="uploadProfileGroup"',
        'id="dropZone"',
        'id="fileList"',
        'id="uploadRequestSummary"',
        'class="upload-primary-action"',
        'id="uploadCompareResults"',
        'data-testid="upload-result"',
        'data-tool-trace-scope="upload"',
    )
    positions = [upload_tab.index(marker) for marker in source_order]
    assert positions == sorted(positions)
    assert upload_tab.index('role="radiogroup"') < upload_tab.index('id="dropZone"')
    assert upload_tab.index('id="uploadSelectionState"') > upload_tab.index(
        'class="upload-primary-action"'
    )


def test_upload_exchange_logs_have_download_controls() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    inspector_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "inspector.js").read_text(
        encoding="utf-8"
    )

    for area_id in (
        "uploadRequestArea",
        "uploadResponseArea",
        "opsecRequestArea",
        "opsecResponseArea",
    ):
        assert f'data-exchange-download-area="{area_id}"' in html

    assert 'downloadRawRequestBtn: "Скачать запрос"' in core_js
    assert 'downloadRawResponseBtn: "Скачать ответ"' in core_js
    assert 'downloadRawRequestBtn: "Download request"' in core_js
    assert 'downloadRawResponseBtn: "Download response"' in core_js
    assert 'exchangeLogDownloaded: "HTTP-лог сохранён"' in core_js
    assert 'exchangeLogDownloaded: "HTTP log saved"' in core_js
    assert 'exchangeLogSensitiveHint: "Лог может содержать данные, ключи или cookie."' in core_js
    assert 'exchangeLogSensitiveHint: "The log may contain payloads, keys, or cookies."' in core_js

    assert "function downloadExchangeAreaRaw" in inspector_js
    assert "data-exchange-download-area" in inspector_js
    assert "buildExchangeDownloadFilename" in inspector_js


def test_regular_upload_trace_is_raw_http_first() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    inspector_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "inspector.js").read_text(
        encoding="utf-8"
    )
    upload_tab = html.split('<section id="upload-tab"', 1)[1].split('<section id="opsec-tab"', 1)[0]

    assert 'data-i18n="uploadRawHttpRequestTitle">Исходный HTTP-запрос</h3>' in upload_tab
    assert 'data-i18n="uploadRawHttpResponseTitle">Исходный HTTP-ответ</h3>' in upload_tab
    assert (
        'id="uploadRequestArea" data-exchange-pane="request" data-exchange-view="raw"' in upload_tab
    )
    assert (
        'id="uploadResponseArea" data-testid="upload-response-area" '
        'data-exchange-pane="response" data-exchange-view="raw"' in upload_tab
    )
    assert 'uploadRawHttpRequestTitle: "Исходный HTTP-запрос"' in core_js
    assert 'uploadRawHttpResponseTitle: "Исходный HTTP-ответ"' in core_js
    assert "const forceRawView" in inspector_js


def test_advanced_upload_trace_is_raw_http_first() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    opsec_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "opsec.js").read_text(
        encoding="utf-8"
    )
    opsec_tab = html.split('<section id="opsec-tab"', 1)[1].split('<section id="files-tab"', 1)[0]

    assert 'data-i18n="opsecRawHttpRequestTitle">Исходный HTTP-запрос</h3>' in opsec_tab
    assert 'data-i18n="opsecRawHttpResponseTitle">Исходный HTTP-ответ</h3>' in opsec_tab
    assert (
        'id="opsecRequestArea" data-exchange-pane="request" data-exchange-view="raw"' in opsec_tab
    )
    assert (
        'id="opsecResponseArea" data-testid="opsec-response-area" '
        'data-exchange-pane="response" data-exchange-view="raw"' in opsec_tab
    )
    assert 'opsecRawHttpRequestTitle: "Исходный HTTP-запрос"' in core_js
    assert 'opsecRawHttpResponseTitle: "Исходный HTTP-ответ"' in core_js
    assert "emptyText: t('exchangeResponseEmpty')" in opsec_js


def test_advanced_upload_ready_summary_stays_compact() -> None:
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    opsec_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "opsec.js").read_text(
        encoding="utf-8"
    )

    preview_function = opsec_js.split("async function rebuildAdvancedPreview(", 1)[1].split(
        "async function refreshOpsecRequestPreview",
        1,
    )[0]

    assert 'opsecPreviewReady: "Запрос готов к отправке"' in core_js
    assert 'opsecPreviewReady: "Request ready to send"' in core_js
    assert "summaryText: t('opsecPreviewReady')" in preview_function
    assert "...plan.requestExchange" in preview_function
    assert "opsecState.preview = {" in preview_function
    assert "plan," in preview_function


def test_raw_http_panes_constrain_long_unbroken_payload_lines() -> None:
    components_css = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "components.css").read_text(
        encoding="utf-8"
    )
    features_css = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "features.css").read_text(
        encoding="utf-8"
    )

    def block_for(css: str, selector: str) -> str:
        return css.split(f"\n{selector} {{", 1)[1].split("\n}", 1)[0]

    response_area_block = block_for(components_css, ".response-area")

    assert "min-width: 0;" in response_area_block
    assert "max-width: 100%;" in response_area_block
    assert "overflow-wrap: anywhere;" in response_area_block

    for selector in (
        ".exchange-inspector--tool",
        ".exchange-inspector__scroll",
        ".exchange-inspector__grid",
        ".exchange-pane",
        ".exchange-pane__body",
        ".tool-result",
        ".tool-result__header",
        ".tool-result__body",
        ".tool-result__meta",
        ".tool-stack",
        ".tool-card--workflow",
        ".tool-trace",
    ):
        block = block_for(features_css, selector)
        assert "min-width: 0;" in block
        assert "max-width: 100%;" in block

    for selector in (
        ".tool-result",
        ".tool-stack",
        ".tool-card--workflow",
        ".tool-trace",
    ):
        block = block_for(features_css, selector)
        assert "grid-template-columns: minmax(0, 1fr);" in block

    tool_result_body_block = block_for(features_css, ".tool-result__body")
    assert "overflow-wrap: anywhere;" in tool_result_body_block


def test_upload_request_previews_are_built_before_send() -> None:
    upload_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "upload.js").read_text(
        encoding="utf-8"
    )
    opsec_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "opsec.js").read_text(
        encoding="utf-8"
    )

    assert "function refreshUploadRequestPreview" in upload_js
    assert "function compileBasicUploadRequest(state, file, bodyBytes = null)" in upload_js
    assert "function buildUploadExchangeLog(entries, side = 'request', options = {})" in upload_js
    assert "message.rawText || buildExchangeRawMessage(message, side)" in upload_js
    assert "requestExportLog" in upload_js
    assert "refreshUploadRequestPreview();" in upload_js
    assert "'compile-request': compileBasicUploadRequest" in upload_js

    assert "const opsecState = {" in opsec_js
    assert "previewSequence: 0," in opsec_js
    assert "preview: null," in opsec_js
    assert "function readAdvancedRequestState()" in opsec_js
    assert "function normalizeAdvancedRequestState(raw, sessionSnapshot)" in opsec_js
    assert "async function compileAdvancedRequest(normalized, file, sessionSnapshot)" in opsec_js
    assert "async function refreshOpsecRequestPreview" in opsec_js
    assert "await compileAdvancedRequest(" in opsec_js


def test_advanced_upload_reuses_preview_or_consumes_changed_click() -> None:
    opsec_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "opsec.js").read_text(
        encoding="utf-8"
    )

    upload_body = opsec_js.split("async function opsecUpload()", 1)[1]

    assert "const preview = opsecState.preview;" in upload_body
    assert "preview.fingerprint !== fingerprint" in upload_body
    assert "await rebuildAdvancedPreview({ sessionSnapshot: freshSessionSnapshot });" in upload_body
    assert "const plan = preview.plan;" in upload_body
    assert "compileAdvancedRequest(" not in upload_body


def test_navigation_tabs_use_stage005_order_labels_and_default_active_send() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )

    top_tabs = extract_top_tab_buttons(html)
    assert top_tabs == [
        ("tab-upload", "tabUpload", "Отправить"),
        ("tab-files", "tabFiles", "Файлы"),
        ("tab-request", "tabRequests", "Запросы"),
        ("tab-opsec", "tabOpsec", "Расширенные"),
        ("tab-notepad", "tabNotepad", "Блокнот"),
    ]

    assert 'id="tab-upload" data-tool-entry="upload" data-tab-target="upload"' in html
    assert 'class="tab active" role="tab" aria-selected="true"' in html
    assert 'aria-controls="upload-tab" tabindex="0" id="tab-upload"' in html
    assert '<input type="file" id="fileInput" multiple tabindex="-1">' in html
    assert '<input type="file" id="opsecFileInput" tabindex="-1">' in html
    assert (
        '<section id="upload-tab"' in html
        and "hidden>"
        not in html.split(
            '<section id="upload-tab"',
            1,
        )[1].split(">", 1)[0]
    )

    for expected in (
        'tabUpload: "Отправить"',
        'tabFiles: "Файлы"',
        'tabRequests: "Запросы"',
        'tabOpsec: "Расширенные"',
        'tabNotepad: "Блокнот"',
        'tabUpload: "Send"',
        'tabFiles: "Files"',
        'tabRequests: "Requests"',
        'tabOpsec: "Advanced"',
        'tabNotepad: "Notepad"',
    ):
        assert expected in core_js

    assert "Upload (regular)" not in html
    assert "Upload (advanced)" not in html
    assert "Upload (regular)" not in core_js
    assert "Upload (advanced)" not in core_js
    assert "getFirstAvailableToolTabName() || 'upload'" in core_js


def test_request_panel_preview_defaults_to_summary_with_raw_storage_override() -> None:
    requests_js = (UI_ROOT / "requests.js").read_text(encoding="utf-8")

    assert "const requestPreviewModeStorageKey = 'requestPreviewMode';" in requests_js
    assert "const requestPreviewModes = new Set(['summary', 'raw']);" in requests_js
    assert "const requestState = {" in requests_js
    assert "previewMode: 'summary'," in requests_js
    assert "localStorage.getItem(requestPreviewModeStorageKey)" in requests_js
    assert "requestPreviewModes.has(storedRequestPreviewMode)" in requests_js
    assert "requestState.previewMode = storedRequestPreviewMode;" in requests_js
    assert (
        "localStorage.setItem(requestPreviewModeStorageKey, requestState.previewMode);"
        in requests_js
    )


def test_static_ui_uses_one_explicit_namespace_and_stable_load_order() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    bootstrap_js = (UI_ROOT / "bootstrap.js").read_text(encoding="utf-8")

    body_scripts = re.findall(
        r'<script src="(/static/ui/[^"]+\.js)"></script>',
        html,
    )
    assert body_scripts == [
        "/static/ui/theme.js",
        "/static/ui/bootstrap.js",
        "/static/ui/core.js",
        "/static/ui/dialogs.js",
        "/static/ui/inspector.js",
        "/static/ui/http-errors.js",
        "/static/ui/advanced-routing.js",
        "/static/ui/advanced-compiler.js",
        "/static/ui/upload.js",
        "/static/ui/requests.js",
        "/static/ui/smuggle.js",
        "/static/ui/files.js",
        "/static/ui/opsec.js",
        "/static/ui/notepad.js",
        "/static/ui/app.js",
    ]
    assert 'type="module"' not in html
    assert "Object.defineProperty(global, 'XferryApp'" in bootstrap_js
    assert "writable: false" in bootstrap_js
    assert "function unexpectedGlobals(allowedNames = [])" in bootstrap_js
    assert "const services = new Map();" in bootstrap_js
    assert "const workflows = new Map();" in bootstrap_js
    assert "Unknown application event" in bootstrap_js
    assert "Unknown DOM contract" in bootstrap_js

    expected_initializers = {
        "core.js": "initializeCore",
        "dialogs.js": "initializeDialogs",
        "inspector.js": "initializeInspector",
        "http-errors.js": "initializeHttpErrors",
        "upload.js": "initializeUpload",
        "requests.js": "initializeRequests",
        "smuggle.js": "initializeSmuggle",
        "files.js": "initializeFiles",
        "opsec.js": "initializeAdvancedUpload",
        "notepad.js": "initializeNotepad",
        "app.js": "initializeApplication",
    }
    for filename, initializer in expected_initializers.items():
        source = (UI_ROOT / filename).read_text(encoding="utf-8")
        assert source.startswith(f"(function {initializer}(app) {{")
        assert source.rstrip().endswith("})(window.XferryApp);")


def test_workflow_state_events_and_user_lists_are_explicit_and_safe() -> None:
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")
    upload_js = (UI_ROOT / "upload.js").read_text(encoding="utf-8")
    requests_js = (UI_ROOT / "requests.js").read_text(encoding="utf-8")
    smuggle_js = (UI_ROOT / "smuggle.js").read_text(encoding="utf-8")
    files_js = (UI_ROOT / "files.js").read_text(encoding="utf-8")
    opsec_js = (UI_ROOT / "opsec.js").read_text(encoding="utf-8")
    notepad_js = (UI_ROOT / "notepad.js").read_text(encoding="utf-8")

    assert "app.emit(app.events.LOCALE_CHANGED" in core_js
    assert "app.emit(app.events.SERVER_METHODS_CHANGED" in core_js
    assert "app.emit(app.events.WORKSPACE_CHANGED" in core_js
    for source, workflow in (
        (upload_js, "upload"),
        (requests_js, "requests"),
        (smuggle_js, "smuggle"),
        (files_js, "files"),
        (opsec_js, "advanced"),
        (notepad_js, "notepad"),
    ):
        assert f"app.registerWorkflow('{workflow}'" in source
        assert "getState: () => ({" in source

    for forbidden_global in (
        "let filesToUpload",
        "let uploadMethod",
        "let requestPreviewMode",
        "let notepadIsDirty",
        "let notepadSessionId",
    ):
        assert forbidden_global not in "\n".join(
            [core_js, upload_js, requests_js, files_js, opsec_js, notepad_js]
        )

    assert "const generation = ++filesState.browseGeneration;" in files_js
    assert "generation !== filesState.browseGeneration" in files_js
    assert "fileList.replaceChildren(fragment);" in upload_js
    assert "serverFilesEl.replaceChildren(fragment);" in files_js
    assert "notepadNoteListEl.replaceChildren(fragment);" in notepad_js
    assert "fileList.innerHTML" not in upload_js
    assert "serverFiles.innerHTML" not in files_js
    assert "listEl.innerHTML" not in notepad_js
    assert all(
        "window.__xferry" not in path.read_text(encoding="utf-8") for path in UI_ROOT.glob("*.js")
    )


def test_notepad_clients_use_exact_canonical_http_and_websocket_contract() -> None:
    """Keep every bundled NOTE client on the clean-break 3.0 wire contract."""
    notepad_js = (UI_ROOT / "notepad.js").read_text(encoding="utf-8")
    session_http = notepad_js.split("async function notepadInitSession()", 1)[1].split(
        "async function notepadEncrypt", 1
    )[0]
    save_http = notepad_js.split("async function notepadSaveSnapshotViaHttp", 1)[1].split(
        "async function notepadRunSave", 1
    )[0]
    list_http = notepad_js.split("async function notepadRefreshList", 1)[1].split(
        "function notepadRenderList", 1
    )[0]
    load_http = notepad_js.split("async function notepadLoadNoteViaHttp", 1)[1].split(
        "async function notepadApplyLoadResult", 1
    )[0]
    load_handler = notepad_js.split("async function notepadHandleHttpLoadResult", 1)[1].split(
        "async function notepadHandleWsLoadResult", 1
    )[0]
    load_flow = notepad_js.split("async function notepadLoadNote", 1)[1].split(
        "async function notepadLoadNoteViaHttp", 1
    )[0]
    delete_http = notepad_js.split("async function notepadDeleteNoteViaHttp", 1)[1].split(
        "async function notepadDeleteNote", 1
    )[0]
    delete_flow = notepad_js.split("async function notepadDeleteNote", 1)[1].split(
        "function notepadResetEditorAfterDelete", 1
    )[0]
    selected_delete_http = notepad_js.split("async function notepadDeleteSelectedOneViaHttp", 1)[
        1
    ].split("function notepadDeleteSelectedOneViaWs", 1)[0]
    selected_delete_flow = notepad_js.split("async function notepadDeleteSelectedNotes", 1)[
        1
    ].split("function notepadCompleteClear", 1)[0]
    clear_http = notepad_js.split("async function notepadClearNotesViaHttp", 1)[1].split(
        "async function notepadClearNotes", 1
    )[0]
    clear_flow = notepad_js.split("async function notepadClearNotes", 1)[1].split(
        "app.on(app.events.LOCALE_CHANGED", 1
    )[0]
    clear_adapter = notepad_js.split("function notepadApplyClearResult", 1)[1].split(
        "async function notepadClearNotes", 1
    )[0]
    websocket = notepad_js.split("function notepadHandleWsMessage", 1)[1].split(
        "// ── CRUD operations", 1
    )[0]
    websocket_save = notepad_js.split("async function notepadRunSave", 1)[1].split(
        "async function notepadRefreshList", 1
    )[0]
    error_mapper = notepad_js.split("function notepadErrorMessageFromResponse", 1)[1].split(
        "function notepadTryParseJson", 1
    )[0]
    pending_save_lookup = notepad_js.split("function notepadGetPendingWsSaveEntry", 1)[1].split(
        "function notepadCompletePendingWsSave", 1
    )[0]

    for expected in (
        "keyData.key.available",
        "keyData.key.public_key",
        "exchangeData.session.id",
        "exchangeData.server_public_key",
    ):
        assert expected in session_http
    for legacy in (
        "keyData.hasEcdh",
        "keyData.publicKey",
        "exchangeData.sessionId",
        "exchangeData.serverPublicKey",
    ):
        assert legacy not in session_http

    assert "JSON.stringify({ client_public_key: clientPubB64 })" in session_http
    assert "const path = '/notes?action=save';" in save_http
    assert "payload.create_if_missing = true" in save_http
    assert "payload.session_id = snapshot.session_id" in save_http
    assert "result.note" in save_http
    assert "result.success" not in save_http
    assert "'/notes?action=list'" in list_http
    assert "result.notes" in list_http
    assert "'?action=load'" in load_http
    assert "notepadRegisterWsOperation('load', { id }," in load_flow
    assert "loadRequestId" in load_flow
    assert "notepadHandleHttpLoadResult(result" in load_http
    assert "result.note" in load_handler
    assert "'?action=delete'" in delete_http
    assert "notepadRegisterWsOperation('delete', { id }," in delete_flow
    assert "result.deleted_note" in delete_http
    assert "'?action=delete'" in selected_delete_http
    assert "notepadDeleteSelectedOneViaWs" in selected_delete_flow
    assert "result.deleted_note" in selected_delete_http
    assert "'/notes?action=clear'" in clear_http
    assert "notepadRegisterWsOperation('clear', {}," in clear_flow
    assert "notepadApplyClearResult(result" in clear_http
    assert "result.success" not in "\n".join(
        (
            save_http,
            list_http,
            load_http,
            delete_http,
            selected_delete_http,
            clear_http,
            clear_adapter,
        )
    )

    for canonical_ws_read in (
        "msg.action === 'save'",
        "msg.request_id",
        "msg.result.note",
        "msg.action === 'load'",
        "notepadHandleWsOperationSuccess(operationEntry, msg.result)",
        "msg.action === 'list'",
        "msg.result.notes",
        "msg.action === 'delete'",
        "msg.action === 'clear'",
        "msg.error.message",
    ):
        assert canonical_ws_read in websocket

    for canonical_ws_write in (
        "action: 'save'",
        "request_id: requestId",
        "input: {",
        "create_if_missing: preparedSnapshot.create_if_missing",
        "session_id: preparedSnapshot.session_id",
    ):
        assert canonical_ws_write in websocket_save

    for canonical_ws_operation in (
        "pendingWsOperations: new Map()",
        "function notepadRegisterWsOperation(action, input, options = {})",
        "function notepadGetWsOperation(requestId)",
        "notepadFallbackPendingWsOperations();",
        "notepadHandleWsOperationSuccess(operationEntry, msg.result)",
        "notepadHandleWsOperationError(operationEntry",
        "fallback: () => notepadLoadNoteViaHttp(id, loadRequestId)",
        "fallback: () => notepadDeleteNoteViaHttp(id, noteTitle)",
        "fallback: () => notepadClearNotesViaHttp()",
        "forceHttp: true",
    ):
        assert canonical_ws_operation in notepad_js

    for removed_wire_token in (
        "clientPublicKey",
        "sessionId",
        "createIfMissing",
        "noteId",
        "opId",
        "X-Session-Id",
        "type: 'save'",
        "msg.type",
        "msg.success",
        "msg.opId",
        "msg.message",
        "msg.notes",
        "message.id",
        "message.title",
        "message.data",
    ):
        assert removed_wire_token not in notepad_js
    assert "result.error.message" in error_mapper
    assert "responseText" not in error_mapper
    assert "bodyText" not in error_mapper
    assert "for (" not in pending_save_lookup


def test_notepad_example_and_public_docs_publish_only_the_3_0_contract() -> None:
    """The runnable example and canonical API page migrate with the browser client."""
    example = (REPO_ROOT / "examples" / "notepad_client.py").read_text(encoding="utf-8")
    api = (REPO_ROOT / "API.md").read_text(encoding="utf-8")
    note_docs = api.split("## NOTE", 1)[1].split("## OPTIONS", 1)[0]

    for expected in (
        're.compile(r"^[0-9a-f]{32}$")',
        'payload={"client_public_key": _b64(client_pub_raw)}',
        'body["create_if_missing"] = True',
        'body["session_id"] = session_id',
        '"/notes?action=save"',
        'f"/notes/{note_id}?action=load"',
        'saved.get("note")',
        'loaded.get("note")',
    ):
        assert expected in example

    for removed in (
        "clientPublicKey",
        "sessionId",
        "createIfMissing",
        "X-Session-Id",
        '"/notes"',
        'f"/notes/{note_id}"',
    ):
        assert removed not in example

    for expected in (
        "NOTE /notes?action=list",
        "NOTE /notes?action=save",
        "NOTE /notes?action=clear",
        "?action=load",
        "?action=delete",
        '"client_public_key"',
        '"create_if_missing"',
        '"session_id"',
        '"action": "save"',
        '"request_id": "client-123"',
        '"input": {',
        '"result": {',
        '"error": {',
        "[A-Za-z0-9._:-]{1,128}",
        "1002",
        "1003",
        "1009",
        "1011",
        "Only exact `GET /notes/ws` may upgrade",
        "There is no compatibility parser",
    ):
        assert expected in note_docs


def test_files_compact_explorer_exposes_accessible_navigation_and_resilient_list_states() -> None:
    """Protect the Files workflow from regressing to an unstructured action list."""
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")
    files_js = (UI_ROOT / "files.js").read_text(encoding="utf-8")
    features_css = (UI_ROOT / "features.css").read_text(encoding="utf-8")
    files_tab = extract_workspace_panel(html, "files-tab")

    for element_id in (
        "browseRootBtn",
        "browseUpBtn",
        "browsePathInput",
        "browseBtn",
        "browseRefreshBtn",
        "filesSearchInput",
        "filesSearchClearBtn",
        "filesGlobalActions",
        "filesFilterStatus",
        "filesSelectionBar",
        "clearSelectedUploadsBtn",
        "deleteSelectedUploadsBtn",
        "filesListHeader",
        "filesSelectVisibleCheckbox",
        "filesSortNameBtn",
        "filesHttpErrorHost",
        "serverFiles",
    ):
        assert files_tab.count(f'id="{element_id}"') == 1

    assert 'class="file-browser__path-scope" aria-hidden="true">uploads/</span>' in files_tab
    assert 'id="serverFiles" data-testid="server-files" role="list" aria-busy="false"' in files_tab
    assert 'id="filesSelectionBar" class="file-browser__selection" hidden' in files_tab
    assert 'id="filesFilterStatus" class="file-browser__filter-status" role="status"' in files_tab
    assert 'id="filesListHeader" hidden' in files_tab
    assert 'role="table"' not in files_tab
    assert 'role="grid"' not in files_tab
    assert 'role="row"' not in files_tab
    assert 'id="filesDangerZone"' not in files_tab
    global_actions = files_tab.split('id="filesGlobalActions"', 1)[1].split("</details>", 1)[0]
    assert 'data-disclosure-marker="none"' in global_actions
    assert 'id="clearUploadsBtn"' in global_actions
    assert files_tab.index('id="filesHttpErrorHost"') < files_tab.index('id="serverFiles"')
    source_order = (
        'id="filesSearchInput"',
        'id="filesGlobalActions"',
        'id="filesFilterStatus"',
        'id="filesSelectionBar"',
        'id="filesListHeader"',
        'id="serverFiles"',
    )
    positions = [files_tab.index(marker) for marker in source_order]
    assert positions == sorted(positions)

    for locale_key in (
        "filesSearchLabel",
        "filesSearchPlaceholder",
        "filesSearchClear",
        "filesSearchNoMatches",
        "filesFilterSummary",
        "filesFilterSummaryPaged",
        "filesListActions",
        "filesCleanupHint",
        "filesColumnName",
        "filesColumnActions",
        "filesSelectVisible",
        "filesDeselectVisible",
        "filesSortAscending",
        "filesSortDescending",
        "filesSortedAscending",
        "filesSortedDescending",
        "filesSelectionClearedBySearch",
        "filesSelectionCount",
        "clearSelectionBtn",
        "filesBrowseLoading",
        "filesBrowseEmpty",
        "filesBrowseInitialError",
        "filesBrowseVisibleCount",
        "filesMoreActions",
        "deleteFileAction",
    ):
        assert locale_key in extract_locale_keys(core_js, "ru")
        assert locale_key in extract_locale_keys(core_js, "en")

    expected_overflow_copy = {
        "ru": {
            "filesSearchLabel": "Поиск по именам файлов и папок",
            "filesSearchClear": "Очистить поиск",
            "filesListActions": "Действия со списком",
            "filesCleanupHint": (
                "Удаляет всё содержимое uploads/. Служебные скрытые файлы будут сохранены."
            ),
            "filesMoreActions": "Дополнительные действия",
            "filesColumnName": "Имя",
            "filesColumnActions": "Действия",
            "filesSelectVisible": "Выбрать показанные файлы",
            "xorDecryptButtonLabel": "Скачать с XOR-расшифровкой",
            "smuggleButtonLabel": "HTML Smuggling",
            "deleteFileAction": "Удалить файл",
        },
        "en": {
            "filesSearchLabel": "Search file and folder names",
            "filesSearchClear": "Clear search",
            "filesListActions": "List actions",
            "filesCleanupHint": (
                "Deletes all contents of uploads/. Hidden service files are preserved."
            ),
            "filesMoreActions": "More actions",
            "filesColumnName": "Name",
            "filesColumnActions": "Actions",
            "filesSelectVisible": "Select shown files",
            "xorDecryptButtonLabel": "Download with XOR decryption",
            "smuggleButtonLabel": "HTML smuggling",
            "deleteFileAction": "Delete file",
        },
    }
    for locale, labels in expected_overflow_copy.items():
        locale_block = extract_locale_block(core_js, locale)
        for key, label in labels.items():
            assert f'{key}: "{label}"' in locale_block

    assert "filesDangerZone" not in files_js
    assert ".file-browser__danger-zone" not in features_css

    assert "function sortServerFileItems(items)" in files_js
    assert "filesState.sortDirection" in files_js
    assert "leftName.localeCompare(" in files_js
    assert "getFilesLocale()," in files_js
    assert "leftIsDirectory ? -1 : 1" in files_js
    for snippet in (
        "document.getElementById('filesSearchInput')",
        "document.getElementById('filesSearchClearBtn')",
        "document.getElementById('filesFilterStatus')",
        "document.getElementById('filesListHeader')",
        "document.getElementById('filesSelectVisibleCheckbox')",
        "document.getElementById('filesSortNameBtn')",
        "filesSearchInput.addEventListener('input'",
        "filesSearchClearBtn.addEventListener('click'",
        "filesSelectVisibleCheckbox.addEventListener('change'",
        "filesSortNameBtn.addEventListener('click'",
        "filesSelectVisibleCheckbox.indeterminate",
        "filesSelectVisibleCheckbox.disabled",
        "filesState.selectedPaths.clear();",
    ):
        assert snippet in files_js
    assert "role', 'listitem'" in files_js
    assert "input.name = 'file-selection';" in files_js
    assert "const generation = ++filesState.infoGeneration;" in files_js
    assert "generation !== filesState.infoGeneration" in files_js
    browse_directory_source = files_js.split("async function browseDirectory(options = {}) {", 1)[
        1
    ].split("function encodeFileRequestPath", 1)[0]
    assert "filesState.infoGeneration += 1;" in browse_directory_source
    assert "lastSuccessfulItems: []," in files_js
    assert "renderServerFiles(filesState.lastSuccessfulItems" in files_js
    assert "document.addEventListener('keydown', closeFileActionDisclosuresOnEscape);" in files_js
    assert (
        "document.addEventListener('click', closeFileActionDisclosuresOnOutsideClick);" in files_js
    )
    assert "preserveActionSummary: true" in files_js
    assert ".file-browser__list-toolbar" in features_css
    assert ".file-browser__search" in features_css
    assert ".file-browser__global-actions" in features_css
    assert ".file-browser__filter-status" in features_css
    assert ".file-browser__list-header" in features_css
    assert ".file-browser__sort" in features_css
    assert ".file-row__more > summary" in features_css
    assert "min-width: 44px;" in features_css
    assert "overflow-wrap: anywhere;" in features_css
    assert ".file-row__menu-item" in features_css
    assert ".file-row__menu-separator" in features_css
    assert "grid-template-columns: minmax(0, 1fr);" in features_css
    assert "width: 280px;" in features_css


def test_files_bulk_delete_success_uses_non_modal_toast_and_empty_tool_result() -> None:
    """Protect bulk-delete success feedback without regressing persistent action summaries."""
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")
    files_js = (UI_ROOT / "files.js").read_text(encoding="utf-8")
    features_css = (UI_ROOT / "features.css").read_text(encoding="utf-8")
    files_tab = extract_workspace_panel(html, "files-tab")

    assert files_tab.count('id="filesToastRegion"') == 1
    assert files_tab.count('id="filesToastLive"') == 1
    assert '<div class="file-toast-region" id="filesToastRegion">' in files_tab
    assert (
        '<div class="sr-only" id="filesToastLive" role="status" '
        'aria-live="polite" aria-atomic="true"></div>'
    ) in files_tab
    assert files_tab.index('id="serverFiles"') < files_tab.index('id="filesToastRegion"')

    expected_copy = {
        "ru": {
            "deleteSelectedFilesSuccess": "Выбранные файлы удалены",
            "deleteSelectedFilesRefreshError": (
                "Файлы удалены ({0}), но список не удалось обновить"
            ),
            "filesToastDismiss": "Закрыть уведомление",
        },
        "en": {
            "deleteSelectedFilesSuccess": "Selected files deleted",
            "deleteSelectedFilesRefreshError": (
                "Files deleted ({0}), but the list could not be refreshed"
            ),
            "filesToastDismiss": "Dismiss notification",
        },
    }
    for locale, labels in expected_copy.items():
        locale_block = extract_locale_block(core_js, locale)
        for key, label in labels.items():
            assert f'{key}: "{label}"' in locale_block

    toast_helpers = files_js.split("function clearFilesToastTimer()", 1)[1].split(
        "refreshFilesMethodAvailability();",
        1,
    )[0]
    for snippet in (
        "const filesToastRegionEl = document.getElementById('filesToastRegion');",
        "function getFilesDeletedToastMessage()",
        "function syncFilesToastCopy()",
        "function dismissFilesToast({ restoreFocus = false } = {})",
        "function scheduleFilesToastDismiss(toast, delay = 5000)",
        "function showFilesDeletedToast(deletedCount)",
        "toast.dataset.filesToast = '';",
        "message.dataset.filesToastMessage = '';",
        "closeButton.dataset.filesToastDismiss = '';",
        "closeButton.addEventListener('click', () => dismissFilesToast({ restoreFocus: true }))",
        "announceLiveRegion('filesToastLive', getFilesDeletedToastMessage());",
        "toast.addEventListener('focusin', clearFilesToastTimer);",
        "event.stopPropagation();",
        "dismissFilesToast({ restoreFocus: true });",
    ):
        assert snippet in files_js
    assert "filesToastDeletedCount || 0" in toast_helpers
    assert "if (restoreFocus && toastHadFocus)" in toast_helpers
    assert "focusFilesBrowserAnchor();" in toast_helpers
    assert "toast.focus(" not in toast_helpers
    assert "closeButton.focus(" not in toast_helpers

    bulk_delete = files_js.split("async function deleteSelectedUploadFiles", 1)[1].split(
        "// ===== DELETE file =====",
        1,
    )[0]
    success_path = bulk_delete.split(
        "    } else {\n        resetFilesActionSummary();",
        1,
    )[1]
    assert (
        "const refreshed = await browseDirectory({ suppressLiveAnnouncements: true });"
        in success_path
    )
    assert "if (refreshed) {\n            showFilesDeletedToast(deleted.length);" in success_path
    assert "deleteSelectedFilesRefreshError" in success_path
    assert "phase: 'complete'" not in success_path
    assert bulk_delete.index("resetFilesActionSummary();") < bulk_delete.index(
        "showFilesDeletedToast(deleted.length);"
    )
    assert "setExchangeInspector('files', { phase: 'empty' });" in files_js

    browse_directory = files_js.split("async function browseDirectory(options = {}) {", 1)[1].split(
        "function encodeFileRequestPath", 1
    )[0]
    assert "options.suppressLiveAnnouncements === true" in browse_directory
    assert "suppressLiveAnnouncements ? 'off' : 'polite'" in browse_directory
    assert "if (!suppressLiveAnnouncements)" in browse_directory
    assert "filesBrowseStatusEl.setAttribute('aria-live', 'polite');" in browse_directory

    region_block = features_css.split("\n.file-toast-region {", 1)[1].split("\n}", 1)[0]
    toast_block = features_css.split("\n.file-toast {", 1)[1].split("\n}", 1)[0]
    dismiss_block = features_css.split("\n.file-toast__dismiss {", 1)[1].split("\n}", 1)[0]
    for declaration in (
        "position: fixed;",
        "right: max(var(--space-4), env(safe-area-inset-right));",
        "bottom: max(var(--space-4), env(safe-area-inset-bottom));",
        "width: min(360px, calc(100vw - var(--space-6)));",
        "pointer-events: none;",
    ):
        assert declaration in region_block
    assert "pointer-events: auto;" in toast_block
    assert "min-height: 60px;" in toast_block
    for declaration in ("width: 44px;", "min-width: 44px;", "min-height: 44px;"):
        assert declaration in dismiss_block
    assert ".file-toast__dismiss:focus-visible" in features_css
    assert "@media (prefers-reduced-motion: no-preference)" in features_css


def test_files_inspection_ui_uses_one_opt_in_info_contract_and_safe_fallback() -> None:
    """Catches Files INFO calls that omit inspection or per-row inspection requests."""
    files_js = (UI_ROOT / "files.js").read_text(encoding="utf-8")

    assert "function createInspectionInfoUrl(path)" in files_js
    inspection_url = files_js.split("function createInspectionInfoUrl(path)", 1)[1].split(
        "function createFileActionButton", 1
    )[0]
    browse_directory = files_js.split("async function browseDirectory(options = {}) {", 1)[1].split(
        "function encodeFileRequestPath", 1
    )[0]
    file_info = files_js.split("async function showInlineFileDetails(path) {", 1)[1].split(
        "function getFileNameFromPath", 1
    )[0]
    rendered_file_info = files_js.split("function createFileInfo(", 1)[1].split(
        "function createFileSelectControl", 1
    )[0]
    rendered_file_row = files_js.split("function createServerFileRow", 1)[1].split(
        "function getFilesLocale", 1
    )[0]

    assert "searchParams.set('inspect', 'true');" in inspection_url
    assert "createInspectionInfoUrl(path)" in browse_directory
    assert "createInspectionInfoUrl(requestPath)" in file_info
    assert "createInspectionInfoUrl(itemPath)" not in files_js
    assert "const inspection = getFileInspection(item);" in files_js
    assert "if (!inspection ||" in files_js
    assert "textContent =" in rendered_file_info
    assert "textContent =" in rendered_file_row
    assert "innerHTML" not in rendered_file_info
    assert "innerHTML" not in rendered_file_row


def test_files_inspection_ui_localizes_mime_warnings_xor_hints_and_metadata() -> None:
    """Catches missing or misleading inspection state in Files list and details dialog."""
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")
    files_js = (UI_ROOT / "files.js").read_text(encoding="utf-8")
    features_css = (UI_ROOT / "features.css").read_text(encoding="utf-8")

    expected_copy = {
        "ru": {
            "filesInspectionMimeLine": "MIME: {0} · {1}",
            "filesInspectionSourceSignature": "по сигнатуре",
            "filesInspectionSourceText": "по тексту",
            "filesInspectionSourceExtension": "по расширению",
            "filesInspectionSourceUnknown": "источник не определён",
            "filesInspectionWarningPossibleEncryptedOrPacked": "Возможно зашифрован или упакован",
            "filesInspectionWarningExtensionMismatch": "Расширение не совпадает с содержимым",
            "filesXorHintOpaque": "Формат не распознан: пробуйте, только если использовался XOR.",
            "filesXorHintNeutral": "Только для файлов, зашифрованных XOR.",
            "fileInfoMimeSource": "Источник MIME",
            "fileInfoAssessment": "Оценка содержимого",
        },
        "en": {
            "filesInspectionMimeLine": "MIME: {0} · {1}",
            "filesInspectionSourceSignature": "signature",
            "filesInspectionSourceText": "text",
            "filesInspectionSourceExtension": "extension",
            "filesInspectionSourceUnknown": "unknown source",
            "filesInspectionWarningPossibleEncryptedOrPacked": "Possibly encrypted or packed",
            "filesInspectionWarningExtensionMismatch": "Extension does not match content",
            "filesXorHintOpaque": "Format not recognized; try only if XOR was used",
            "filesXorHintNeutral": "Only for files encrypted with XOR.",
            "fileInfoMimeSource": "MIME source",
            "fileInfoAssessment": "Content assessment",
        },
    }
    for locale, labels in expected_copy.items():
        locale_block = extract_locale_block(core_js, locale)
        for key, label in labels.items():
            assert f'{key}: "{label}"' in locale_block

    for state_key in (
        "filesInspectionStateRecognized",
        "filesInspectionStateOpaque",
        "filesInspectionStateUnknown",
    ):
        assert state_key in extract_locale_keys(core_js, "ru")
        assert state_key in extract_locale_keys(core_js, "en")

    for selector in (
        ".file-inspection__mime",
        ".file-inspection__warning",
        ".file-row__xor-hint",
        ".file-row__action-xor--caution",
    ):
        assert selector in features_css

    assert "function getInspectionWarningLabel(inspection)" in files_js
    assert "possible_encrypted_or_packed" in files_js
    assert "extension_mismatch" in files_js
    assert "filesInspectionStateRecognized" in files_js
    assert "filesInspectionStateOpaque" in files_js
    assert "filesInspectionStateUnknown" in files_js
    assert "aria-describedby" in files_js
    assert "fileInfoMimeSource" in files_js
    assert "fileInfoAssessment" in files_js
    assert "not encrypted" not in files_js.lower()


def test_download_tab_does_not_expose_raw_http_logs() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")

    files_tab = extract_workspace_panel(html, "files-tab")

    assert 'data-tool-trace-scope="files"' not in files_tab
    assert 'data-exchange-scope="files"' not in files_tab
    assert 'id="filesRequestArea"' not in files_tab
    assert 'id="filesResponseArea"' not in files_tab
    assert "data-exchange-copy-area" not in files_tab
    assert "data-exchange-download-area" not in files_tab


def test_static_ui_version_matches_package_version() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")

    assert 'id="appVersion" data-app-version="0.1.0">v0.1.0</p>' in html
    assert "function updateVisibleAppVersionFromPing" in core_js
    assert "match(/^XFerry\\/" in core_js


def test_all_static_t_calls_have_russian_and_english_translations() -> None:
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")
    ru_keys = extract_locale_keys(core_js, "ru")
    en_keys = extract_locale_keys(core_js, "en")
    used_keys: set[str] = set()

    for js_path in UI_ROOT.glob("*.js"):
        js_source = js_path.read_text(encoding="utf-8")
        used_keys.update(re.findall(r"\bt\(\s*['\"]([A-Za-z][A-Za-z0-9_]*)['\"]\s*\)", js_source))

    assert used_keys - ru_keys == set()
    assert used_keys - en_keys == set()
    assert ru_keys == en_keys


def test_smuggle_http_consumers_use_only_canonical_wire_contract() -> None:
    """Catch either bundled consumer reading or synthesizing the removed flat aliases."""
    smuggle_js = (UI_ROOT / "smuggle.js").read_text(encoding="utf-8")
    requests_js = (UI_ROOT / "requests.js").read_text(encoding="utf-8")

    result_adapter = smuggle_js.split("function getSmuggleResultModel", 1)[1].split(
        "function buildSmuggleSuccessMarkup", 1
    )[0]
    assert set(re.findall(r"\bresult\.([A-Za-z_][A-Za-z0-9_]*)", result_adapter)) == {
        "artifact",
        "source",
        "download",
        "builder",
    }
    for canonical_read in (
        "artifact.url",
        "artifact.name",
        "source.name",
        "download.name",
        "download.name_applied",
        "download.mime_type",
        "builder.mode",
        "builder.preset",
        "builder.encryption",
        "builder.payload_encoding",
        "builder.trigger_event_custom",
        "builder.password",
    ):
        assert canonical_read in result_adapter
    for legacy_read in (
        "result.url",
        "result.file",
        "result.downloadName",
        "result.encrypted",
        "result.password",
        "result.effectiveMode",
        "result.outputFormat",
    ):
        assert legacy_read not in result_adapter

    smuggle_error_adapter = smuggle_js.split("function resolveSmuggleErrorMessage", 1)[1].split(
        "function getSmuggleResultModel", 1
    )[0]
    assert "payload?.error" in smuggle_error_adapter
    for canonical_error_read in (
        "errorPayload?.code",
        "errorPayload?.message",
        "errorPayload?.field",
        "errorPayload?.details",
    ):
        assert canonical_error_read in smuggle_error_adapter
    for legacy_error_read in (
        "payload?.code",
        "payload?.message",
        "payload?.field",
    ):
        assert legacy_error_read not in smuggle_error_adapter

    smuggle_execute = smuggle_js.split("async function executeSmuggle", 1)[1].split(
        "app.on(app.events.SERVER_METHODS_CHANGED", 1
    )[0]
    requests_execute = requests_js.split("async function executeRequestPanelSmuggle", 1)[1].split(
        "async function launchRequestPanelSmuggleBuilder", 1
    )[0]
    for consumer in (smuggle_execute, requests_execute):
        assert "result.builderState =" not in consumer
        assert "result.downloadName =" not in consumer
        assert "result.downloadName" not in consumer
        assert "result.file" not in consumer

    shared_error_summary = requests_js.split("function summarizeErrorBody", 1)[1].split(
        "function buildScenarioError", 1
    )[0]
    assert "parsed.error.message" in shared_error_summary
    assert "parsed.error.code" in shared_error_summary
    assert "parsed.error.field" in shared_error_summary
    assert "parsed.error.details" in shared_error_summary
    assert "typeof parsed.error === 'string'" not in shared_error_summary


def test_smuggle_capabilities_are_strictly_validated_and_fail_closed_in_node() -> None:
    """A malformed or unavailable PING contract must never open the builder."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

(async () => {
    const source = fs.readFileSync(process.argv[1], 'utf8');
    const validCapabilities = JSON.parse(process.argv[2]);
    const workflows = new Map();
    const listeners = new Map();
    const notices = [];
    let coreState = {
        serverDiscoveryStatus: 'ready',
        smuggleCapabilities: validCapabilities,
    };

    const core = {
        t: key => key,
        escapeHtml: value => String(value),
        formatSize: value => `${value} B`,
        serverUrl: '',
        announceLiveRegion: () => {},
        focusElementWithoutScroll: () => {},
        getState: () => coreState,
        isServerMethodSupported: () => true,
        isServerMethodInGroup: () => true,
        formatActionErrorMessage: (_prefix, error) => error.message,
        writeTextToClipboard: async () => {},
    };
    const app = {
        events: {
            SERVER_METHODS_CHANGED: 'server.methods.changed',
            LOCALE_CHANGED: 'locale.changed',
        },
        service(name) {
            if (name === 'core') return core;
            if (name === 'dialogs') {
                return {
                    open: () => { throw new Error('builder dialog must stay closed'); },
                    notice: async options => { notices.push(options); },
                };
            }
            if (name === 'inspector') {
                return { createTextBody: value => value, setInspector: () => {} };
            }
            if (name === 'http') {
                return { request: () => { throw new Error('HTTP must not run'); } };
            }
            throw new Error(`Unexpected service: ${name}`);
        },
        registerWorkflow(name, definition) { workflows.set(name, definition); },
        on(eventName, listener) {
            const eventListeners = listeners.get(eventName) || [];
            eventListeners.push(listener);
            listeners.set(eventName, eventListeners);
        },
        invoke(name, command, ...args) {
            return workflows.get(name).commands[command](...args);
        },
        getState(name) { return workflows.get(name).getState(); },
    };
    globalThis.window = {
        XferryApp: app,
        location: { href: 'http://127.0.0.1:8000/' },
    };
    globalThis.document = {
        getElementById: () => null,
        createElement: () => ({ textContent: '', innerHTML: '' }),
    };
    vm.runInThisContext(source, { filename: process.argv[1] });

    function refresh(status, capabilities) {
        coreState = {
            serverDiscoveryStatus: status,
            smuggleCapabilities: capabilities,
        };
        for (const listener of listeners.get(app.events.SERVER_METHODS_CHANGED) || []) {
            listener({});
        }
        return app.getState('smuggle');
    }

    const invalidCases = [];
    function captureInvalid(label, mutate) {
        const candidate = structuredClone(validCapabilities);
        mutate(candidate);
        const state = refresh('ready', candidate);
        invalidCases.push({
            label,
            enabled: state.enabled,
            status: state.status,
            reason: state.reason,
        });
    }

    captureInvalid('unsupported schema', value => { value.schema_version = 2; });
    captureInvalid('missing defaults', value => { delete value.defaults; });
    captureInvalid('default outside vocabulary', value => { value.defaults.mode = 'unknown'; });
    captureInvalid('coerced field limit', value => { value.field_limits.title = '120'; });
    captureInvalid('trigger mismatch', value => { value.defaults.trigger_event = 'onunknown'; });
    captureInvalid('malformed cap', value => { value.caps.aes_gcm = 'true'; });
    captureInvalid('partial vocabulary', value => { value.encryption_modes = []; });
    captureInvalid('schema-v1 missing fixed mode', value => { value.modes = ['simple']; });
    captureInvalid('schema-v1 extra fixed mode', value => { value.modes.push('legacy'); });
    captureInvalid('schema-v1 reordered fixed modes', value => { value.modes.reverse(); });
    captureInvalid(
        'schema-v1 duplicated fixed mode', value => { value.modes = ['simple', 'simple']; }
    );
    captureInvalid(
        'schema-v1 reordered encryption modes', value => { value.encryption_modes.reverse(); }
    );
    captureInvalid('schema-v1 duplicated encryption mode', value => {
        value.encryption_modes = ['none', 'xor', 'xor'];
    });
    captureInvalid('schema-v1 swapped payload encoding default', value => {
        value.defaults.payload_encoding = 'hex';
    });
    captureInvalid(
        'schema-v1 missing simple field', value => { value.mode_fields.simple_only.pop(); }
    );
    captureInvalid(
        'schema-v1 extra simple field', value => { value.mode_fields.simple_only.push('legacy'); }
    );
    captureInvalid(
        'schema-v1 reordered simple fields', value => { value.mode_fields.simple_only.reverse(); }
    );
    captureInvalid('schema-v1 duplicated simple field', value => {
        value.mode_fields.simple_only[1] = value.mode_fields.simple_only[0];
    });
    captureInvalid(
        'schema-v1 empty constructor fields', value => { value.mode_fields.constructor_only = []; }
    );
    captureInvalid('schema-v1 extra constructor field', value => {
        value.mode_fields.constructor_only.push('legacy');
    });
    captureInvalid('schema-v1 reordered constructor fields', value => {
        value.mode_fields.constructor_only.reverse();
    });
    captureInvalid('schema-v1 duplicated constructor field', value => {
        value.mode_fields.constructor_only[1] = value.mode_fields.constructor_only[0];
    });
    captureInvalid('schema-v1 overlapping mode fields', value => {
        value.mode_fields.constructor_only[0] = value.mode_fields.simple_only[0];
    });
    captureInvalid('schema-v1 swapped mode fields', value => {
        const simpleOnly = value.mode_fields.simple_only;
        value.mode_fields.simple_only = value.mode_fields.constructor_only;
        value.mode_fields.constructor_only = simpleOnly;
    });

    for (const key of [
        'schema_version', 'source_max_bytes', 'field_limits', 'defaults', 'mode_fields',
        'extensions', 'mime_presets', 'mime_by_extension', 'presets', 'locales',
        'encryption_modes', 'modes', 'payload_encodings', 'output_formats',
        'page_templates', 'download_variants', 'trigger_events',
        'custom_trigger_methods', 'temp_policy', 'caps',
    ]) {
        captureInvalid(`missing root ${key}`, value => { delete value[key]; });
    }
    for (const key of [
        'download_name', 'download_ext', 'title', 'message', 'cta_label',
        'delay_ms', 'mime_type', 'trigger_event',
    ]) {
        captureInvalid(`missing field limit ${key}`, value => { delete value.field_limits[key]; });
    }
    for (const key of [
        'mode', 'preset', 'locale', 'encryption', 'payload_encoding',
        'trigger_method', 'trigger_event', 'output_format', 'download_variant',
        'page_template', 'mime_type', 'delay_ms', 'show_notice', 'null_byte',
    ]) {
        captureInvalid(`missing default ${key}`, value => { delete value.defaults[key]; });
    }
    for (const key of ['simple_only', 'constructor_only']) {
        captureInvalid(`missing mode field ${key}`, value => { delete value.mode_fields[key]; });
    }
    for (const key of ['max_age_seconds', 'max_file_count', 'max_total_bytes']) {
        captureInvalid(`missing temp policy ${key}`, value => { delete value.temp_policy[key]; });
    }
    for (const key of [
        'one_shot', 'constructor', 'xor_obfuscation', 'aes_gcm',
        'source_cap_enforced', 'custom_extension', 'custom_mime_type',
        'custom_trigger_event', 'searchable_options',
    ]) {
        captureInvalid(`missing cap ${key}`, value => { delete value.caps[key]; });
    }

    const zeroSourceCap = structuredClone(validCapabilities);
    zeroSourceCap.source_max_bytes = 0;
    const zeroState = refresh('ready', zeroSourceCap);
    const missingState = refresh('ready', null);
    const arrayState = refresh('ready', []);
    const pendingState = refresh('pending', null);
    const unavailableState = refresh('unavailable', null);
    await app.invoke('smuggle', 'show-dialog', '/uploads/source.bin');

    process.stdout.write(JSON.stringify({
        valid: refresh('ready', validCapabilities),
        invalidCases,
        zeroState,
        missingState,
        arrayState,
        pendingState,
        unavailableState,
        notices,
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""
    completed = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(UI_ROOT / "smuggle.js"),
            json.dumps(build_smuggle_capabilities()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["valid"]["enabled"] is True
    assert observed["valid"]["status"] == "valid"
    assert observed["valid"]["reason"] == ""
    assert all(case["enabled"] is False for case in observed["invalidCases"])
    assert all(case["status"] == "invalid" for case in observed["invalidCases"])
    assert all(case["reason"] for case in observed["invalidCases"])
    assert observed["zeroState"]["enabled"] is True
    assert observed["missingState"]["status"] == "invalid"
    assert observed["arrayState"]["status"] == "invalid"
    assert observed["pendingState"]["status"] == "pending"
    assert observed["unavailableState"]["status"] == "unavailable"
    assert observed["notices"]
    assert observed["notices"][-1]["message"]


def test_invalid_ping_smuggle_capabilities_cannot_launch_or_create_request_demo_in_node() -> None:
    """Catches semantically invalid PING data reaching Requests before any upload mutation."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

(async () => {
    const smuggleSource = fs.readFileSync(process.argv[1], 'utf8');
    const requestsSource = fs.readFileSync(process.argv[2], 'utf8');
    const invalidCapabilities = JSON.parse(process.argv[3]);
    const listeners = new Map();
    const workflows = new Map();
    const events = { demoCalls: 0, dialogCalls: 0, uploadMutations: 0 };
    const coreState = {
        serverDiscoveryStatus: 'ready',
        smuggleCapabilities: invalidCapabilities,
    };
    const core = {
        t: key => key,
        escapeHtml: value => String(value),
        formatSize: value => `${value} B`,
        serverUrl: '',
        announceLiveRegion: () => {},
        focusElementWithoutScroll: () => {},
        getState: () => coreState,
        isServerMethodSupported: () => true,
        isServerMethodInGroup: () => true,
        formatActionErrorMessage: (_prefix, error) => error.message,
        writeTextToClipboard: async () => {},
    };
    const app = {
        events: {
            SERVER_METHODS_CHANGED: 'server.methods.changed',
            LOCALE_CHANGED: 'locale.changed',
        },
        service(name) {
            if (name === 'core') return core;
            if (name === 'dialogs') {
                return { open: () => { events.dialogCalls += 1; }, notice: async () => {} };
            }
            if (name === 'inspector') {
                return { createTextBody: value => value, setInspector: () => {} };
            }
            if (name === 'http') {
                return { request: () => { throw new Error('HTTP must not run'); } };
            }
            throw new Error(`Unexpected service: ${name}`);
        },
        registerWorkflow(name, definition) { workflows.set(name, definition); },
        on(eventName, listener) {
            const registered = listeners.get(eventName) || [];
            registered.push(listener);
            listeners.set(eventName, registered);
        },
        invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
        getState(name) { return workflows.get(name).getState(); },
    };
    globalThis.window = { XferryApp: app, location: { href: 'http://127.0.0.1:8000/' } };
    globalThis.document = {
        getElementById: () => null,
        createElement: () => ({ textContent: '', innerHTML: '' }),
    };
    vm.runInThisContext(smuggleSource, { filename: process.argv[1] });
    const pingState = app.getState('smuggle');

    globalThis.app = app;
    globalThis.responseAreaEl = {};
    globalThis.pathInputEl = { value: '/not-an-upload' };
    globalThis.requestState = { preview: { marker: 'before' } };
    globalThis.t = key => key;
    globalThis.resolveStableRequestTriggerElement = value => value;
    globalThis.isServerMethodSupported = () => true;
    globalThis.normalizeRequestPath = (value, fallback) => String(value || fallback);
    globalThis.cloneRequestPreviewState = value => structuredClone(value);
    globalThis.setRequestButtonsBusy = () => {};
    globalThis.setResponseAreaState = () => {};
    globalThis.renderRequestProgress = () => {};
    globalThis.setRequestPreviewPreparing = () => {};
    globalThis.resolveRequestPanelSmuggleSourcePath = async () => {
        events.demoCalls += 1;
        events.uploadMutations += 1;
        return '/uploads/demo-smuggle.txt';
    };
    globalThis.createRequestPanelDemoFile = async () => {
        events.demoCalls += 1;
        events.uploadMutations += 1;
        return '/uploads/demo-smuggle.txt';
    };
    globalThis.setRequestPathValue = () => {};
    globalThis.createRequestPreviewModel = () => ({});
    globalThis.setRequestPreviewModel = () => {};
    globalThis.setRequestPreviewResult = () => {};
    globalThis.renderRequestPreview = () => {};
    globalThis.renderRequestError = () => {};
    globalThis.announceLiveRegion = () => {};
    globalThis.showSmuggleDialog = () => { events.dialogCalls += 1; };
    globalThis.executeRequestPanelSmuggle = async () => null;

    const start = requestsSource.indexOf('async function launchRequestPanelSmuggleBuilder');
    const end = requestsSource.indexOf('async function sendRequest', start);
    if (start < 0 || end < 0) throw new Error('Could not extract Requests SMUGGLE paths');
    (0, eval)(requestsSource.slice(start, end));

    await launchRequestPanelSmuggleBuilder({ id: 'request-smuggle' });
    let scenarioError = null;
    try {
        await buildRequestScenario('SMUGGLE', '/ignored-smuggle');
    } catch (error) {
        scenarioError = error.message;
    }

    process.stdout.write(JSON.stringify({ pingState, scenarioError, ...events }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""
    invalid_capabilities = build_smuggle_capabilities()
    invalid_capabilities["mode_fields"]["constructor_only"] = []
    completed = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(UI_ROOT / "smuggle.js"),
            str(UI_ROOT / "requests.js"),
            json.dumps(invalid_capabilities),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["pingState"]["enabled"] is False
    assert observed["pingState"]["status"] == "invalid"
    assert observed["dialogCalls"] == 0
    assert observed["demoCalls"] == 0
    assert observed["uploadMutations"] == 0
    assert observed["scenarioError"]


def test_request_panel_smuggle_fails_closed_before_demo_upload_in_node() -> None:
    """Invalid SMUGGLE capabilities must not mutate uploads before reporting the reason."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

(async () => {
    const source = fs.readFileSync(process.argv[1], 'utf8');
    const events = {
        demoCalls: 0,
        dialogCalls: 0,
        previewErrors: [],
        renderedErrors: [],
        phases: [],
        announcements: [],
    };
    globalThis.app = {
        getState: name => name === 'smuggle'
            ? { enabled: false, status: 'invalid', reason: 'Capability contract invalid' }
            : {},
    };
    globalThis.responseAreaEl = {};
    globalThis.pathInputEl = { value: '/not-an-upload' };
    globalThis.requestState = { preview: { marker: 'before' } };
    globalThis.resolveStableRequestTriggerElement = value => value;
    globalThis.isServerMethodSupported = () => true;
    globalThis.normalizeRequestPath = (value, fallback) => String(value || fallback);
    globalThis.cloneRequestPreviewState = value => structuredClone(value);
    globalThis.setRequestButtonsBusy = () => {};
    globalThis.setResponseAreaState = (...args) => { events.phases.push(args); };
    globalThis.renderRequestProgress = () => {};
    globalThis.setRequestPreviewPreparing = () => {};
    globalThis.resolveRequestPanelSmuggleSourcePath = async () => {
        events.demoCalls += 1;
        return '/uploads/demo-smuggle.txt';
    };
    globalThis.setRequestPathValue = () => {};
    globalThis.createRequestPreviewModel = () => ({});
    globalThis.setRequestPreviewModel = () => {};
    globalThis.setRequestPreviewResult = value => { events.previewErrors.push(value.message); };
    globalThis.renderRequestPreview = () => {};
    globalThis.renderRequestError = (_method, _path, error) => {
        events.renderedErrors.push(error.message);
    };
    globalThis.announceLiveRegion = (_id, message) => { events.announcements.push(message); };
    globalThis.showSmuggleDialog = () => { events.dialogCalls += 1; };
    globalThis.executeRequestPanelSmuggle = async () => null;
    globalThis.t = key => key;

    globalThis.isRequestPanelSmuggleStateReady = extractFunction(
        source,
        'function isRequestPanelSmuggleStateReady',
        'async function sendRequest'
    );

    const launch = extractFunction(
        source,
        'async function launchRequestPanelSmuggleBuilder',
        'async function buildRequestScenario'
    );
    await launch({ id: 'request-smuggle' });
    process.stdout.write(JSON.stringify(events));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "requests.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["demoCalls"] == 0
    assert observed["dialogCalls"] == 0
    assert observed["previewErrors"] == ["Capability contract invalid"]
    assert observed["renderedErrors"] == ["Capability contract invalid"]
    assert observed["phases"][-1] == ["SMUGGLE", "/not-an-upload", "error"]
    assert observed["announcements"][-1].endswith("Capability contract invalid")


def test_request_panel_smuggle_gate_requires_enabled_valid_object_capabilities_in_node() -> None:
    """Catches either Requests SMUGGLE path accepting a partial workflow state."""
    script = r"""
const fs = require('node:fs');

(async () => {
    const source = fs.readFileSync(process.argv[1], 'utf8');
    const events = [];
    let smuggleState = null;
    globalThis.app = { getState: name => name === 'smuggle' ? smuggleState : {} };
    globalThis.responseAreaEl = {};
    globalThis.pathInputEl = { value: '/not-an-upload' };
    globalThis.requestState = { preview: { marker: 'before' } };
    globalThis.t = key => key;
    globalThis.resolveStableRequestTriggerElement = value => value;
    globalThis.isServerMethodSupported = () => true;
    globalThis.normalizeRequestPath = (value, fallback) => String(value || fallback);
    globalThis.cloneRequestPreviewState = value => structuredClone(value);
    globalThis.setRequestButtonsBusy = () => {};
    globalThis.setResponseAreaState = () => {};
    globalThis.renderRequestProgress = () => {};
    globalThis.setRequestPreviewPreparing = () => {};
    globalThis.resolveRequestPanelSmuggleSourcePath = async () => {
        events.push('launch-demo');
        return '/uploads/demo-smuggle.txt';
    };
    globalThis.createRequestPanelDemoFile = async () => {
        events.push('scenario-demo');
        return '/uploads/demo-smuggle.txt';
    };
    globalThis.setRequestPathValue = () => {};
    globalThis.createRequestPreviewModel = () => ({});
    globalThis.setRequestPreviewModel = () => {};
    globalThis.setRequestPreviewResult = () => {};
    globalThis.renderRequestPreview = () => {};
    globalThis.renderRequestError = () => {};
    globalThis.announceLiveRegion = () => {};
    globalThis.showSmuggleDialog = () => { events.push('dialog'); };
    globalThis.executeRequestPanelSmuggle = async () => null;

    const start = source.indexOf('async function launchRequestPanelSmuggleBuilder');
    const end = source.indexOf('async function sendRequest', start);
    if (start < 0 || end < 0) throw new Error('Could not extract Requests SMUGGLE paths');
    (0, eval)(source.slice(start, end));

    async function tryScenario(state) {
        smuggleState = state;
        const before = events.length;
        await launchRequestPanelSmuggleBuilder({ id: 'request-smuggle' });
        let scenarioError = null;
        try {
            await buildRequestScenario('SMUGGLE', '/ignored-smuggle');
        } catch (error) {
            scenarioError = error.message;
        }
        return { activity: events.slice(before), scenarioError };
    }

    const invalidStatus = await tryScenario({
        enabled: true, status: 'invalid', capabilities: {}, reason: 'invalid capabilities',
    });
    const arrayCapabilities = await tryScenario({
        enabled: true, status: 'valid', capabilities: [], reason: 'array capabilities',
    });
    const missingCapabilities = await tryScenario({
        enabled: true, status: 'valid', capabilities: null, reason: 'missing capabilities',
    });
    const valid = await tryScenario({
        enabled: true, status: 'valid', capabilities: {}, reason: '',
    });

    process.stdout.write(JSON.stringify({
        invalidStatus, arrayCapabilities, missingCapabilities, valid,
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "requests.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    for key in ("invalidStatus", "arrayCapabilities", "missingCapabilities"):
        assert observed[key]["activity"] == []
        assert observed[key]["scenarioError"]
    assert observed["valid"]["activity"] == ["launch-demo", "dialog", "scenario-demo"]
    assert observed["valid"]["scenarioError"] is None


def test_request_panel_smuggle_scenario_preflight_blocks_demo_upload_in_node() -> None:
    """The direct Requests scenario must share the builder capability gate."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

(async () => {
    const source = fs.readFileSync(process.argv[1], 'utf8');
    const events = {
        demoCalls: [],
    };
    let smuggleState = {
        enabled: false,
        status: 'invalid',
        reason: 'Capability contract invalid',
    };
    globalThis.app = {
        getState: name => name === 'smuggle' ? smuggleState : {},
    };
    globalThis.t = key => key;
    globalThis.normalizeRequestPath = (value, fallback) => String(value || fallback);
    globalThis.createRequestPanelDemoFile = async (slug, label) => {
        events.demoCalls.push({ slug, label });
        return `/uploads/${slug}-demo.txt`;
    };

    const buildRequestScenario = extractFunction(
        source,
        'async function buildRequestScenario',
        'function isRequestPanelSmuggleStateReady'
    );
    globalThis.isRequestPanelSmuggleStateReady = extractFunction(
        source,
        'function isRequestPanelSmuggleStateReady',
        'async function sendRequest'
    );
    async function messageOf(fn) {
        try {
            await fn();
            return null;
        } catch (error) {
            return error.message;
        }
    }

    const invalidMessage = await messageOf(() => (
        buildRequestScenario('SMUGGLE', '/ignored-smuggle')
    ));
    const invalidDemoCalls = events.demoCalls.slice();

    smuggleState = {
        enabled: true,
        status: 'valid',
        reason: '',
        capabilities: {},
    };
    const validScenario = await buildRequestScenario('SMUGGLE', '/ignored-smuggle');

    process.stdout.write(JSON.stringify({
        invalidMessage,
        invalidDemoCalls,
        validScenario,
        demoCalls: events.demoCalls,
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "requests.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["invalidMessage"] == "Capability contract invalid"
    assert observed["invalidDemoCalls"] == []
    assert observed["validScenario"] == {
        "path": "/uploads/smuggle-demo.txt",
        "pathInputBeforeRequest": "/uploads/smuggle-demo.txt",
        "pathInputAfterSuccess": "/uploads/smuggle-demo.txt",
    }
    assert observed["demoCalls"] == [{"slug": "smuggle", "label": "SMUGGLE"}]


def test_smuggle_dialog_terminal_and_field_errors_are_accessible_in_node() -> None:
    """Pending/invalid phases keep focus in-dialog and bind server errors to fields."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

(() => {
    const source = fs.readFileSync(process.argv[1], 'utf8');
    const makeElement = (id, disabled = false) => ({
        id,
        disabled,
        hidden: false,
        textContent: '',
        attributes: {},
        setAttribute(name, value) { this.attributes[name] = String(value); },
        getAttribute(name) { return this.attributes[name] ?? null; },
        removeAttribute(name) { delete this.attributes[name]; },
        toggleAttribute(name, force) {
            if (force) this.attributes[name] = '';
            else delete this.attributes[name];
        },
    });
    const dialog = makeElement('dialog');
    dialog.setAttribute('aria-busy', 'false');
    const status = makeElement('smuggleInlineStatus');
    const submit = makeElement('smuggleSubmitBtn');
    const cancel = makeElement('smuggleCancelBtn');
    const close = makeElement('smuggleCloseBtn');
    const downloadName = makeElement('smuggleDownloadName');
    const editingPanel = makeElement('editingPanel');
    const successPanel = makeElement('successPanel');
    const editingActions = makeElement('editingActions');
    const successActions = makeElement('successActions');
    let encryptionError = '';
    const modal = {
        isConnected: true,
        dataset: { smugglePhase: 'editing' },
        __smuggleRequestSeq: 4,
        __smuggleComboboxes: new Map([
            ['smuggleEncryption', { setError: message => { encryptionError = message; } }],
        ]),
        querySelector(selector) {
            return ({
                '.smuggle-dialog': dialog,
                '#smuggleInlineStatus': status,
                '#smuggleSubmitBtn': submit,
                '#smuggleDownloadName': downloadName,
                '[data-smuggle-panel="editing"]': editingPanel,
                '[data-smuggle-panel="success"]': successPanel,
                '[data-smuggle-actions="editing"]': editingActions,
                '[data-smuggle-actions="success"]': successActions,
                '[data-dialog-action="close"]': close,
            })[selector] || null;
        },
        querySelectorAll(selector) {
            if (selector === '[data-smuggle-edit-control]') return [downloadName];
            if (selector === '[data-smuggle-edit-control], #smuggleSubmitBtn') {
                return [downloadName, submit];
            }
            if (selector === '[data-dialog-action="cancel"], [data-dialog-action="close"]') {
                return [cancel, close];
            }
            return [];
        },
    };
    let focused = '';
    globalThis.t = key => key;
    globalThis.smuggleText = key => key;
    globalThis.focusElementWithoutScroll = element => { focused = element?.id || ''; };
    globalThis.setSmuggleInlineStatus = (target, message, tone) => {
        const node = target.querySelector('#smuggleInlineStatus');
        node.textContent = message;
        node.hidden = !message;
        node.tone = tone;
    };
    globalThis.activeSmuggleModals = new Set([modal]);

    const setPhase = extractFunction(
        source,
        'function setSmuggleModalPhase',
        'function resetSmuggleEditingPhase'
    );
    const invalidate = extractFunction(
        source,
        'function invalidateOpenSmuggleDialogs',
        'function refreshSmuggleState'
    );
    const setFieldError = extractFunction(
        source,
        'function setSmuggleFieldError',
        'function normalizeSmuggleStem'
    );

    setPhase(modal, 'submitting');
    const pendingFocus = focused;
    invalidate('Capability contract changed');
    setFieldError(modal, 'encryption', 'Invalid encryption');
    setFieldError(modal, 'download_name', 'Invalid download name');

    process.stdout.write(JSON.stringify({
        pendingFocus,
        invalidFocus: focused,
        phase: modal.dataset.smugglePhase,
        requestSeq: modal.__smuggleRequestSeq,
        ariaBusy: dialog.getAttribute('aria-busy'),
        disabled: {
            downloadName: downloadName.disabled,
            submit: submit.disabled,
            cancel: cancel.disabled,
            close: close.disabled,
        },
        status: { text: status.textContent, tone: status.tone, hidden: status.hidden },
        encryptionError,
        downloadNameError: {
            invalid: downloadName.getAttribute('aria-invalid'),
            errorMessage: downloadName.getAttribute('aria-errormessage'),
        },
    }));
})();
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "smuggle.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["pendingFocus"] == "smuggleInlineStatus"
    assert observed["invalidFocus"] == "smuggleCloseBtn"
    assert observed["phase"] == "invalid"
    assert observed["requestSeq"] == 5
    assert observed["ariaBusy"] == "false"
    assert observed["disabled"] == {
        "downloadName": True,
        "submit": True,
        "cancel": False,
        "close": False,
    }
    assert observed["status"] == {
        "text": "Capability contract changed",
        "tone": "error",
        "hidden": False,
    }
    assert observed["encryptionError"] == "Invalid encryption"
    assert observed["downloadNameError"] == {
        "invalid": "true",
        "errorMessage": "smuggleInlineStatus",
    }


def test_smuggle_workflow_builds_canonical_mode_encryption_matrix_and_accepts_aes() -> None:
    """Every advertised mode supports none, XOR, and canonical AES-GCM artifacts."""
    capabilities = build_smuggle_capabilities()
    capabilities["extensions"] = ["bin"]
    capabilities["mime_presets"] = ["application/octet-stream"]
    capabilities["mime_by_extension"] = {"bin": "application/octet-stream"}
    capabilities["presets"] = ["card_auto"]
    capabilities["locales"] = ["en"]
    capabilities["payload_encodings"] = ["base64"]
    capabilities["output_formats"] = ["html"]
    capabilities["page_templates"] = ["minimal"]
    capabilities["download_variants"] = ["data-uri"]
    capabilities["trigger_events"] = {"button": ["onclick"]}
    capabilities["custom_trigger_methods"] = ["button"]
    capabilities["defaults"].update(
        {
            "preset": "card_auto",
            "locale": "en",
            "payload_encoding": "base64",
            "trigger_method": "button",
            "trigger_event": "onclick",
            "output_format": "html",
            "download_variant": "data-uri",
            "page_template": "minimal",
            "mime_type": "application/octet-stream",
        }
    )
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

(() => {
    const source = fs.readFileSync(process.argv[1], 'utf8');
    const capabilities = JSON.parse(process.argv[2]);
    const workflows = new Map();
    const app = {
        events: {
            SERVER_METHODS_CHANGED: 'server.methods.changed',
            LOCALE_CHANGED: 'locale.changed',
        },
        service(name) {
            if (name === 'core') return {
                t: key => key,
                escapeHtml: value => String(value),
                formatSize: value => `${value} B`,
                serverUrl: '',
                announceLiveRegion: () => {},
                focusElementWithoutScroll: () => {},
                getState: () => ({
                    serverDiscoveryStatus: 'ready',
                    smuggleCapabilities: capabilities,
                }),
                isServerMethodSupported: () => true,
                isServerMethodInGroup: () => true,
                formatActionErrorMessage: (_prefix, error) => error.message,
                writeTextToClipboard: async () => {},
            };
            if (name === 'dialogs') return { open: () => {}, notice: async () => {} };
            if (name === 'inspector') return {
                createTextBody: value => value,
                setInspector: () => {},
            };
            if (name === 'http') return { request: async () => { throw new Error('unused'); } };
            throw new Error(`Unexpected service: ${name}`);
        },
        registerWorkflow(name, definition) { workflows.set(name, definition); },
        on: () => {},
        invoke(name, command, ...args) { return workflows.get(name).commands[command](...args); },
        getState(name) { return workflows.get(name).getState(); },
    };
    globalThis.window = {
        XferryApp: app,
        location: { href: 'http://127.0.0.1:8000/' },
    };
    globalThis.document = {
        getElementById: () => null,
        createElement: () => ({ textContent: '', innerHTML: '' }),
    };
    vm.runInThisContext(source, { filename: process.argv[1] });

    const matrix = [];
    for (const mode of ['simple', 'constructor']) {
        for (const encryption of ['none', 'xor', 'aes']) {
            const path = app.invoke('smuggle', 'build-request-path', '/uploads/source.bin', {
                mode,
                encryption,
                payloadEncoding: 'base64',
            });
            const url = new URL(path, 'http://127.0.0.1:8000/');
            matrix.push({
                mode,
                encryption,
                observedMode: url.searchParams.get('mode'),
                observedEncryption: url.searchParams.get('encryption'),
                payloadEncoding: url.searchParams.get('payload_encoding'),
                legacyEncrypt: url.searchParams.has('encrypt'),
                legacyConstructor: url.searchParams.has('use_constructor'),
                hasB64: Array.from(url.searchParams.values()).includes('b64'),
            });
        }
    }

    function canonicalResult(encryption, password = undefined) {
        const builder = {
            schema_version: 1,
            mode: 'constructor',
            preset: capabilities.defaults.preset,
            locale: capabilities.defaults.locale,
            encryption,
            payload_encoding: 'base64',
            output_format: capabilities.defaults.output_format,
            trigger_method: capabilities.defaults.trigger_method,
            trigger_event: capabilities.defaults.trigger_event,
            trigger_event_custom: false,
            download_variant: capabilities.defaults.download_variant,
            page_template: capabilities.defaults.page_template,
            notice_shown: false,
            null_byte: false,
        };
        if (password !== undefined) builder.password = password;
        return {
            artifact: {
                url: '/uploads/smuggle_0123abcd4567ef89.html',
                name: 'smuggle_0123abcd4567ef89.html',
                size_bytes: 8192,
                content_type: 'text/html; charset=utf-8',
                one_shot: true,
                expires_at: null,
            },
            source: { name: 'source.bin', path: '/uploads/source.bin', size_bytes: 7 },
            download: {
                name: 'source.bin',
                name_applied: true,
                mime_type: 'application/octet-stream',
            },
            builder,
        };
    }

    const results = {
        none: app.invoke('smuggle', 'adapt-result', canonicalResult('none')).ok,
        xor: app.invoke('smuggle', 'adapt-result', canonicalResult('xor', 'AAAAAAA')).ok,
        aes: app.invoke('smuggle', 'adapt-result', canonicalResult('aes', 'AAAAAAA')).ok,
        aesWithoutPassword: app.invoke('smuggle', 'adapt-result', canonicalResult('aes')).ok,
        noneWithPassword: app.invoke(
            'smuggle', 'adapt-result', canonicalResult('none', 'AAAAAAA')
        ).ok,
    };
    const state = app.getState('smuggle');
    let rejectedUnadvertisedPayload = false;
    try {
        app.invoke('smuggle', 'build-request-path', '/uploads/source.bin', {
            mode: 'constructor',
            encryption: 'none',
            payloadEncoding: 'b64',
        });
    } catch (_error) {
        rejectedUnadvertisedPayload = true;
    }
    process.stdout.write(JSON.stringify({
        matrix,
        results,
        advertised: {
            extensions: state.capabilities.extensions,
            presets: state.capabilities.presets,
            payloadEncodings: state.capabilities.payload_encodings,
            pageTemplates: state.capabilities.page_templates,
            triggerEvents: state.capabilities.trigger_events,
        },
        rejectedUnadvertisedPayload,
    }));
})();
"""
    completed = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(UI_ROOT / "smuggle.js"),
            json.dumps(capabilities),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["matrix"] == [
        {
            "mode": mode,
            "encryption": encryption,
            "observedMode": mode,
            "observedEncryption": encryption,
            "payloadEncoding": "base64" if mode == "constructor" else None,
            "legacyEncrypt": False,
            "legacyConstructor": False,
            "hasB64": False,
        }
        for mode in ("simple", "constructor")
        for encryption in ("none", "xor", "aes")
    ]
    assert observed["results"] == {
        "none": True,
        "xor": True,
        "aes": True,
        "aesWithoutPassword": False,
        "noneWithPassword": False,
    }
    assert observed["advertised"] == {
        "extensions": ["bin"],
        "presets": ["card_auto"],
        "payloadEncodings": ["base64"],
        "pageTemplates": ["minimal"],
        "triggerEvents": {"button": ["onclick"]},
    }
    assert observed["rejectedUnadvertisedPayload"] is True


def test_smuggle_ui_has_a_dedicated_asset_and_workflow_owner() -> None:
    """Files and Requests may launch SMUGGLE but must not own its builder policy."""
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    files_js = (UI_ROOT / "files.js").read_text(encoding="utf-8")
    requests_js = (UI_ROOT / "requests.js").read_text(encoding="utf-8")
    smuggle_js = (UI_ROOT / "smuggle.js").read_text(encoding="utf-8")

    assert '<script src="/static/ui/smuggle.js"></script>' in html
    assert html.index("/static/ui/requests.js") < html.index("/static/ui/smuggle.js")
    assert html.index("/static/ui/smuggle.js") < html.index("/static/ui/files.js")
    assert "app.registerWorkflow('smuggle'" in smuggle_js
    assert "app.invoke('smuggle', 'show-dialog'" in files_js
    assert "app.invoke('smuggle', 'build-request-path'" in requests_js
    assert "app.invoke('smuggle', 'adapt-result'" in requests_js
    assert "app.invoke('smuggle', 'show-dialog'" in requests_js
    for forbidden in (
        "SAFE_SMUGGLE_",
        "SMUGGLE_DEFAULT_SOURCE_MAX_BYTES",
        "SMUGGLE_DEFAULT_FIELD_LIMITS",
        "function buildSmuggleRequestPath",
        "function getSmuggleResultModel",
        "function showSmuggleDialog",
        "async function executeSmuggle",
    ):
        assert forbidden not in files_js
    for removed_token in (
        "params.set('encrypt'",
        "use_constructor",
        "'b64'",
        '"b64"',
        "npf-rar-archive-help",
        "pageshowWarning",
        "constructorXorWarning",
        "getSafeSmuggleOption",
        "smuggleText('legacy')",
        "mode === 'standard'",
        'id="smuggleEncrypt"',
        "smuggleEncryptRow",
        "defaults.encrypt ?",
    ):
        assert removed_token not in smuggle_js


def test_smuggle_malformed_success_is_bounded_in_both_consumers() -> None:
    """Run both real success consumers against invalid canonical responses."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

(async () => {
    const smuggleSource = fs.readFileSync(process.argv[1], 'utf8');
    const requestsSource = fs.readFileSync(process.argv[2], 'utf8');
    const capabilities = JSON.parse(process.argv[3]);
    let responseBody = JSON.stringify({ artifact: null });

    function canonicalResult(encryption, password = undefined) {
        const builder = {
            schema_version: 1,
            mode: 'simple',
            preset: 'direct',
            locale: 'en',
            encryption,
            payload_encoding: capabilities.defaults.payload_encoding,
            output_format: 'html',
            trigger_method: capabilities.defaults.trigger_method,
            trigger_event: capabilities.defaults.trigger_event,
            trigger_event_custom: false,
            download_variant: capabilities.defaults.download_variant,
            page_template: capabilities.defaults.page_template,
            notice_shown: false,
            null_byte: false,
        };
        if (password !== undefined) {
            builder.password = password;
        }
        return {
            artifact: {
                url: '/uploads/smuggle_0123abcd4567ef89.html',
                name: 'smuggle_0123abcd4567ef89.html',
                size_bytes: 8192,
                content_type: 'text/html; charset=utf-8',
                one_shot: true,
                expires_at: null,
            },
            source: {
                name: 'source.txt',
                path: '/uploads/source.txt',
                size_bytes: 7,
            },
            download: {
                name: 'source.txt',
                name_applied: true,
                mime_type: 'text/plain',
            },
            builder,
        };
    }

    globalThis.window = { location: { href: 'http://127.0.0.1:8000/' } };
    globalThis.SERVER_URL = 'http://127.0.0.1:8000';
    globalThis.t = key => ({
        error: 'Error',
        smuggleGenerated: 'HTML generated',
        statusPending: 'Pending',
    })[key] || key;
    globalThis.smuggleText = key => ({
        errorNetwork: 'Network error:',
        retryAfterEdit: 'Review the settings and try again.',
    })[key] || key;
    globalThis.createExchangeTextBody = text => ({ text });
    globalThis.buildSmuggleRequestPath = () => '/uploads/source.txt';
    globalThis.parseSmuggleJson = text => {
        try {
            const parsed = JSON.parse(text);
            return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
        } catch (_error) {
            return null;
        }
    };
    globalThis.requireValidSmuggleCapabilities = () => capabilities;
    globalThis.isNonemptyString = value => typeof value === 'string' && value.length > 0;

    globalThis.getSmuggleResultModel = extractFunction(
        smuggleSource,
        'function getSmuggleResultModel',
        'function buildSmuggleSuccessMarkup'
    );
    globalThis.buildSmuggleResponseSummary = extractFunction(
        smuggleSource,
        'function buildSmuggleResponseSummary',
        'function setSmuggleResultStatus'
    );
    const executeSmuggle = extractFunction(
        smuggleSource,
        'async function executeSmuggle',
        'app.on(app.events.SERVER_METHODS_CHANGED'
    );
    const executeRequestPanelSmuggle = extractFunction(
        requestsSource,
        'async function executeRequestPanelSmuggle',
        'async function launchRequestPanelSmuggleBuilder'
    );

    const filesEvents = {
        inspectors: [],
        inline: [],
        successCalls: 0,
        announcements: [],
    };
    globalThis.sendCustomRequest = async () => ({
        status: 200,
        statusText: 'OK',
        headers: {},
        text: async () => responseBody,
    });
    globalThis.setExchangeInspector = (_scope, state) => filesEvents.inspectors.push(state);
    globalThis.announceLiveRegion = (_id, message) => filesEvents.announcements.push(message);
    globalThis.renderSmuggleSuccess = () => { filesEvents.successCalls += 1; };
    globalThis.showSmuggleResultDialog = () => { filesEvents.successCalls += 1; };
    globalThis.resetSmuggleEditingPhase = () => {};
    globalThis.setSmuggleInlineStatus = (_modal, message, tone) => {
        filesEvents.inline.push({ message, tone });
    };
    globalThis.setSmuggleFieldError = () => {};
    globalThis.focusSmuggleRetryTarget = () => {};
    globalThis.focusElementWithoutScroll = () => {};
    globalThis.resolveSmuggleErrorMessage = () => { throw new Error('non-200 path must not run'); };

    const filesResult = await executeSmuggle(
        '/uploads/source.txt',
        {},
        null,
        { modal: { isConnected: true, __smuggleRequestSeq: 1 }, requestSeq: 1 }
    );

    const requestEvents = {
        invocations: [],
        errors: [],
        phases: [],
        successCalls: 0,
        announcements: [],
    };
    globalThis.app = {
        invoke(scope, command, ...args) {
            requestEvents.invocations.push([scope, command]);
            if (scope === 'smuggle' && command === 'adapt-result') {
                return globalThis.getSmuggleResultModel(...args);
            }
            if (scope === 'smuggle' && command === 'build-response-summary') {
                return globalThis.buildSmuggleResponseSummary(...args);
            }
            throw new Error(`Unexpected workflow invocation: ${scope}/${command}`);
        },
    };
    globalThis.adaptSmuggleResult = requestsSource.includes('function adaptSmuggleResult')
        ? extractFunction(
            requestsSource,
            'function adaptSmuggleResult',
            'function buildSmuggleResponseSummary'
        )
        : (...args) => globalThis.getSmuggleResultModel(...args);
    globalThis.setRequestPreviewModel = () => {};
    globalThis.createRequestPreviewModel = () => ({});
    globalThis.setResponseAreaState = (_method, _path, phase) => requestEvents.phases.push(phase);
    globalThis.renderRequestProgress = () => {};
    globalThis.setRequestPreviewResult = () => {};
    globalThis.renderRequestSuccess = () => { requestEvents.successCalls += 1; };
    globalThis.renderRequestError = (_method, _path, error) => requestEvents.errors.push({
        message: error.message,
        code: error.code || null,
    });
    globalThis.announceLiveRegion = (_id, message) => requestEvents.announcements.push(message);
    globalThis.buildScenarioError = () => { throw new Error('non-200 path must not run'); };

    let requestResult = null;
    let requestThrown = null;
    try {
        requestResult = await executeRequestPanelSmuggle('/uploads/source.txt', {});
    } catch (error) {
        requestThrown = { message: error.message, code: error.code || null };
    }

    const nullRoot = {
        files: {
            result: filesResult,
            inline: [...filesEvents.inline],
            lastInspector: filesEvents.inspectors.at(-1),
            successCalls: filesEvents.successCalls,
        },
        requests: {
            result: requestResult,
            thrown: requestThrown,
            errors: [...requestEvents.errors],
            phases: [...requestEvents.phases],
            successCalls: requestEvents.successCalls,
            invocations: [...requestEvents.invocations],
        },
    };

    responseBody = JSON.stringify(canonicalResult('aes'));
    filesEvents.inspectors.length = 0;
    filesEvents.inline.length = 0;
    filesEvents.successCalls = 0;
    filesEvents.announcements.length = 0;
    const aesMissingPasswordFilesResult = await executeSmuggle(
        '/uploads/source.txt',
        {},
        null,
        { modal: { isConnected: true, __smuggleRequestSeq: 1 }, requestSeq: 1 }
    );

    requestEvents.invocations.length = 0;
    requestEvents.errors.length = 0;
    requestEvents.phases.length = 0;
    requestEvents.successCalls = 0;
    requestEvents.announcements.length = 0;
    let aesMissingPasswordRequestResult = null;
    let aesMissingPasswordRequestThrown = null;
    try {
        aesMissingPasswordRequestResult = await executeRequestPanelSmuggle(
            '/uploads/source.txt', {}
        );
    } catch (error) {
        aesMissingPasswordRequestThrown = { message: error.message, code: error.code || null };
    }

    const passwordSemantics = {
        noneWithoutPassword: globalThis.getSmuggleResultModel(canonicalResult('none')).ok,
        noneWithPassword: globalThis.getSmuggleResultModel(canonicalResult('none', 'AAAAAAA')).ok,
        xorWithPassword: globalThis.getSmuggleResultModel(canonicalResult('xor', 'AAAAAAA')).ok,
        xorWithoutPassword: globalThis.getSmuggleResultModel(canonicalResult('xor')).ok,
        xorWithEmptyPassword: globalThis.getSmuggleResultModel(canonicalResult('xor', '')).ok,
        aesWithPassword: globalThis.getSmuggleResultModel(canonicalResult('aes', 'AAAAAAA')).ok,
        aesWithoutPassword: globalThis.getSmuggleResultModel(canonicalResult('aes')).ok,
        aesWithEmptyPassword: globalThis.getSmuggleResultModel(canonicalResult('aes', '')).ok,
    };

    process.stdout.write(JSON.stringify({
        nullRoot,
        aesMissingPassword: {
            files: {
                result: aesMissingPasswordFilesResult,
                inline: filesEvents.inline,
                lastInspector: filesEvents.inspectors.at(-1),
                successCalls: filesEvents.successCalls,
            },
            requests: {
                result: aesMissingPasswordRequestResult,
                thrown: aesMissingPasswordRequestThrown,
                errors: requestEvents.errors,
                phases: requestEvents.phases,
                successCalls: requestEvents.successCalls,
                invocations: requestEvents.invocations,
            },
        },
        passwordSemantics,
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""

    completed = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(UI_ROOT / "smuggle.js"),
            str(UI_ROOT / "requests.js"),
            json.dumps(build_smuggle_capabilities()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    null_root = observed["nullRoot"]
    assert null_root["files"]["result"] is None
    assert null_root["files"]["successCalls"] == 0
    assert null_root["files"]["inline"] == [
        {
            "message": "Invalid SMUGGLE response (invalid_smuggle_response)",
            "tone": "error",
        }
    ]
    assert null_root["files"]["lastInspector"]["phase"] == "error"
    assert (
        null_root["files"]["lastInspector"]["response"]["summaryText"]
        == "Invalid SMUGGLE response (invalid_smuggle_response)"
    )
    assert "Network error" not in null_root["files"]["lastInspector"]["response"]["summaryText"]

    assert null_root["requests"]["result"] is None
    assert null_root["requests"]["thrown"] is None
    assert null_root["requests"]["successCalls"] == 0
    assert null_root["requests"]["errors"] == [
        {
            "message": "Invalid SMUGGLE response (invalid_smuggle_response)",
            "code": "invalid_smuggle_response",
        }
    ]
    assert null_root["requests"]["phases"][-1] == "error"
    assert null_root["requests"]["invocations"] == [["smuggle", "adapt-result"]]

    aes_missing_password = observed["aesMissingPassword"]
    assert aes_missing_password["files"]["result"] is None
    assert aes_missing_password["files"]["successCalls"] == 0
    assert aes_missing_password["files"]["inline"] == null_root["files"]["inline"]
    assert aes_missing_password["files"]["lastInspector"]["phase"] == "error"
    assert aes_missing_password["requests"]["result"] is None
    assert aes_missing_password["requests"]["thrown"] is None
    assert aes_missing_password["requests"]["successCalls"] == 0
    assert aes_missing_password["requests"]["errors"] == null_root["requests"]["errors"]
    assert aes_missing_password["requests"]["phases"][-1] == "error"
    assert aes_missing_password["requests"]["invocations"] == [["smuggle", "adapt-result"]]
    assert observed["passwordSemantics"] == {
        "noneWithoutPassword": True,
        "noneWithPassword": False,
        "xorWithPassword": True,
        "xorWithoutPassword": False,
        "xorWithEmptyPassword": False,
        "aesWithPassword": True,
        "aesWithoutPassword": False,
        "aesWithEmptyPassword": False,
    }


def test_smuggling_ui_uses_one_stateful_accessible_builder() -> None:
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    files_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "smuggle.js").read_text(
        encoding="utf-8"
    )
    dialogs_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "dialogs.js").read_text(
        encoding="utf-8"
    )
    components_css = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "components.css").read_text(
        encoding="utf-8"
    )

    assert 'methodSmuggle: "HTML smuggling"' in core_js
    assert 'smuggleTitle: "HTML smuggling"' in core_js
    assert 'smuggleButtonLabel: "HTML Smuggling"' in core_js
    assert 'smuggleButtonLabel: "HTML smuggling"' in core_js
    assert 'smuggleGenerated: "HTML сгенерирован"' in core_js
    assert 'smuggleGenerated: "HTML generated"' in core_js
    assert 'smuggleReady: "Выберите действие."' in core_js
    assert 'smuggleReady: "Choose an action."' in core_js
    assert 'smuggleCopyUrl: "Копировать одноразовый URL"' in core_js
    assert 'smuggleCopyUrl: "Copy one-shot URL"' in core_js
    assert 'smuggleEncrypted: "XOR-обфускация"' in core_js
    assert 'smuggleEncrypted: "XOR obfuscation"' in core_js

    for stale_phrase in (
        'smuggleTitle: "HTML-артефакт"',
        'smuggleTitle: "HTML artifact"',
        'smuggleButtonLabel: "Артефакт"',
        'smuggleButtonLabel: "Artifact"',
        'smuggleButtonLabel: "SMUGGLING"',
        "Artifact URL",
    ):
        assert stale_phrase not in core_js

    for control_id in (
        "smuggleConstructorEnabled",
        "smuggleEncryption",
        "smugglePayloadEncoding",
        "smuggleTriggerMethod",
        "smuggleTriggerEvent",
        "smuggleOutputFormat",
        "smuggleDownloadVariant",
        "smugglePageTemplate",
        "smuggleMimeType",
        "smuggleNullByte",
    ):
        assert control_id in files_js

    assert 'id="smugglePageSettings"' in files_js
    assert 'id="smuggleAdvancedSettings"' in files_js
    assert 'id="smuggleTechnicalDetails"' not in files_js
    assert 'id="smuggleResultDetails"' in files_js
    assert 'data-smuggle-mode-panel="simple"' in files_js
    assert 'data-smuggle-mode-panel="constructor"' in files_js
    assert 'data-smuggle-mode-panel="${mode}"' in files_js

    def css_block(selector: str, source: str = components_css) -> str:
        match = re.search(rf"{re.escape(selector)}\s*\{{(?P<body>[^}}]+)\}}", source)
        assert match is not None, f"missing CSS block for {selector}"
        return match.group("body")

    dialog_css = css_block(".smuggle-dialog")
    assert "width: min(720px, calc(100vw - var(--space-8)));" in dialog_css
    assert "grid-template-rows: auto minmax(0, 1fr) auto;" in dialog_css
    assert "overflow: hidden;" in dialog_css

    body_css = css_block(".smuggle-dialog__body")
    assert "overflow-y: auto;" in body_css

    footer_css = css_block(".smuggle-dialog__footer")
    assert "position: sticky;" in footer_css
    assert "bottom: 0;" in footer_css
    assert ".smuggle-dialog__layout" in components_css
    assert ".smuggle-dialog__details" in components_css
    assert ".smuggle-dialog__details-content" in components_css
    assert ".smuggle-dialog__advanced-block" in components_css
    assert ".smuggle-dialog__subgroup" in components_css
    assert ".smuggle-dialog__info" in components_css
    mobile_css = components_css.rsplit("@media (max-width: 640px)", 1)[1]
    assert "flex-direction: column;" in css_block(".smuggle-dialog__actions", mobile_css)
    for constructor_group in ("payload", "trigger", "output"):
        assert f'data-smuggle-constructor-group="{constructor_group}"' in files_js
    assert 'smuggleBuilderConstructorGroupPayload: "Данные"' in core_js
    assert 'smuggleBuilderConstructorGroupPayload: "Payload"' in core_js
    assert 'smuggleBuilderConstructorGroupTrigger: "Запуск"' in core_js
    assert 'smuggleBuilderConstructorGroupTrigger: "Trigger"' in core_js
    assert 'smuggleBuilderConstructorGroupOutput: "Вывод"' in core_js
    assert 'smuggleBuilderConstructorGroupOutput: "Output"' in core_js
    assert 'class="smuggle-dialog__field-label"' in files_js
    assert 'data-smuggle-description-for="smugglePayloadEncoding"' in files_js
    for described_control in (
        "smugglePayloadEncoding",
        "smuggleTriggerMethod",
        "smuggleTriggerEvent",
        "smuggleOutputFormat",
        "smuggleDownloadVariant",
        "smugglePageTemplate",
        "smuggleMimeType",
    ):
        assert f"labelledBy: '{described_control}Label'" in files_js
        assert f"describedBy: '{described_control}Description'" in files_js
    assert 'role="img" aria-label="${esc(t(\'smuggleBuilder' not in files_js

    assert "buildSmuggleComboboxMarkup('smuggleEncryption'" in files_js
    assert 'id="smuggleEncrypt"' not in files_js
    assert '<input type="checkbox" id="smuggleConstructorEnabled"' in files_js
    assert "updateSmuggleDescription(modal, 'smuggleEncryption'" in files_js

    for capability_read in (
        "getSmuggleCapabilities().payload_encodings",
        "getSmuggleCapabilities().output_formats",
        "getSmuggleCapabilities().page_templates",
        "getSmuggleCapabilities().download_variants",
        "getSmuggleCapabilities().trigger_events",
        "getSmuggleCapabilities().mime_presets",
    ):
        assert capability_read in files_js

    assert '<select id="smuggle' not in files_js
    assert 'role="combobox" aria-autocomplete="list" aria-expanded="false"' in files_js
    assert 'aria-controls="${esc(id)}Listbox"' in files_js
    assert "input.removeAttribute('aria-activedescendant')" in files_js
    assert 'role="listbox"' in files_js
    assert 'role="option"' in files_js
    assert "event.key === 'ArrowDown' || event.key === 'ArrowUp'" in files_js
    for keyboard_key in ("Enter", "Escape", "Tab"):
        assert f"event.key === '{keyboard_key}'" in files_js
    assert ".slice(0, 8)" not in files_js
    assert "getSmuggleComboboxOptionScore" in files_js
    assert "option.label;" in files_js
    assert "description.textContent = option.description;" in files_js
    assert "validateSmuggleComboboxes(activeModal, { focusFirst: true })" in files_js
    assert "setSmuggleFieldError(activeModal, errorPayload?.field" in files_js
    assert "custom_extension" in files_js
    assert "custom_mime_type" in files_js
    assert "custom_trigger_event" in files_js
    assert "custom_trigger_methods" in files_js
    assert "mime_presets" in files_js
    assert "mime_by_extension" in files_js
    assert ".smuggle-combobox__listbox" in components_css
    assert ".smuggle-combobox__option" in components_css
    assert 'input[role="combobox"][aria-invalid="true"]' in components_css

    for state_contract in (
        'data-smuggle-panel="editing"',
        'data-smuggle-panel="success"',
        'data-smuggle-actions="editing"',
        'data-smuggle-actions="success"',
        'aria-busy="false"',
        "phase === 'submitting'",
        "renderSmuggleSuccess(activeModal",
        "downloadNameApplied",
        "locAssignFilenameWarning",
        "activeModal.__smuggleRequestSeq",
        "activeModal.isConnected",
        "focusSmuggleRetryTarget",
        "hydrateSmuggleSourceInfo(filePath, modal)",
        "encodeSmuggleSourcePath(filePath)",
        'data-dialog-action="edit-settings"',
        'data-dialog-action="copy-password"',
    ):
        assert state_contract in files_js

    assert "dialogId: 'smuggleResultModal'" not in files_js
    assert 'id="smuggleDialogBody" tabindex="-1"' in files_js
    assert (
        "canDismiss: activeModal => activeModal.dataset.smugglePhase !== 'submitting'" in files_js
    )
    assert "dialogBody.scrollTop = 0;" in files_js
    assert ".smuggle-modal-overlay" in components_css
    assert "element.setAttribute('inert', '');" in dialogs_js
    assert "document.body.style.overflow = 'hidden';" in dialogs_js
    assert "smuggle_capabilities" in core_js
    assert "smuggleCapabilities: serverSmuggleCapabilities" in core_js

    advanced_index = files_js.index('id="smuggleAdvancedSettings"')
    constructor_index = files_js.index('id="smuggleConstructorEnabled"', advanced_index)
    footer_index = files_js.index('class="modal-actions smuggle-dialog__footer"', constructor_index)
    assert advanced_index < constructor_index < footer_index

    for removed_simple_screen_contract in (
        "pipelineTitle",
        "pipelineBody",
        "appearanceTitle",
        "appearanceHint",
        "buildSmugglePreviewMarkup",
        'id="smugglePreview"',
        "smuggle-dialog__preview-column",
        "smuggleModeSimple",
        "smuggleModeConstructor",
    ):
        assert removed_simple_screen_contract not in files_js


def test_files_browser_exposes_client_side_xor_decrypt_download() -> None:
    """Catches XOR decrypt selecting a removed response filename mirror."""
    core_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "core.js").read_text(
        encoding="utf-8"
    )
    files_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "files.js").read_text(
        encoding="utf-8"
    )

    assert 'data-file-action="decrypt-xor"' in files_js
    assert "function showXorDecryptDialog" in files_js
    assert "async function xorDecryptBytes" in files_js
    assert "function getXorDecryptResponseHeader" in files_js
    assert "async function fetchFileBlobForXorDecrypt" in files_js
    assert "xhr.responseType = 'arraybuffer';" in files_js
    assert "async function decryptXorFileFromBrowser" in files_js
    assert "new TextEncoder().encode(password)" in files_js
    assert "downloadBlobFile(" in files_js
    assert "Content-Disposition" in files_js
    assert "X-File-Name" not in files_js
    assert 'id="xorDecryptPassword"' in files_js
    assert 'id="xorDecryptOutputName"' in files_js

    assert 'xorDecryptButtonLabel: "Скачать с XOR-расшифровкой"' in core_js
    assert 'xorDecryptButtonLabel: "Download with XOR decryption"' in core_js
    assert 'xorDecryptTitle: "XOR расшифровка"' in core_js
    assert 'xorDecryptTitle: "XOR decrypt"' in core_js
    assert 'xorDecryptPasswordPlaceholder: "Ключ XOR"' in core_js
    assert 'xorDecryptPasswordPlaceholder: "XOR key"' in core_js
    assert 'xorDecryptPasswordRequired: "Введите ключ XOR"' in core_js
    assert 'xorDecryptPasswordRequired: "Enter an XOR key"' in core_js
    assert 'xorDecryptSaved: "Расшифрованный файл сохранён"' in core_js
    assert 'xorDecryptSaved: "Decrypted file saved"' in core_js
    assert 'xorDecryptWarning: "XOR не проверяет правильность ключа.' in core_js
    assert 'xorDecryptWarning: "XOR cannot verify whether the key is correct.' in core_js


def test_request_downloads_use_content_disposition_or_request_url_not_response_mirrors() -> None:
    """Catches FETCH downloads or Basic demos reading removed result-header aliases."""
    requests_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "requests.js").read_text(
        encoding="utf-8"
    )
    resolver = requests_js.split("function resolveDownloadFilename", 1)[1].split(
        "function encodeDownloadPath", 1
    )[0]

    assert "Content-Disposition" in resolver
    assert "getSafeRequestFilename(path)" in resolver
    assert "X-File-Name" not in resolver
    assert "function getCanonicalUploadPath(text)" in requests_js
    assert "parseJsonSafe(text)?.file?.path" in requests_js
    assert "Invalid upload response" in requests_js
    assert "x-file-path" not in requests_js


def test_request_panel_upload_rejects_malformed_canonical_success_in_node() -> None:
    """Catches Basic demo consumers substituting a predicted path for malformed 201 JSON."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

(async () => {
    const source = fs.readFileSync(process.argv[1], 'utf8');
    globalThis.buildDemoFilename = slug => `${slug}.txt`;
    globalThis.buildDemoUploadPath = filename => `/uploads/${filename}`;
    globalThis.buildDemoUploadBody = () => 'demo';
    globalThis.deleteUploadIfPresent = async () => {};
    globalThis.parseJsonSafe = text => {
        try { return JSON.parse(text); } catch (_error) { return null; }
    };
    globalThis.sendCustomRequest = async () => ({
        ok: true,
        text: async () => '{"file":{}}',
    });
    globalThis.SERVER_URL = 'http://127.0.0.1:8000';
    globalThis.getCanonicalUploadPath = extractFunction(
        source,
        'function getCanonicalUploadPath',
        'async function requestPanelUploadExists'
    );

    const createRequestPanelDemoFile = extractFunction(
        source,
        'async function createRequestPanelDemoFile',
        'function isRequestPanelSmuggleUploadPath'
    );
    const buildRequestScenario = extractFunction(
        source,
        'async function buildRequestScenario',
        'function isRequestPanelSmuggleStateReady'
    );
    async function messageOf(callback) {
        try {
            await callback();
            return null;
        } catch (error) {
            return error.message;
        }
    }

    const scenario = await buildRequestScenario('POST', '');
    process.stdout.write(JSON.stringify({
        create: await messageOf(() => createRequestPanelDemoFile('fetch', 'FETCH')),
        compiled: await messageOf(() => scenario.pathInputAfterSuccess('{"file":{}}')),
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""

    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "requests.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "create": "Invalid upload response",
        "compiled": "Invalid upload response",
    }


def test_basic_upload_comparison_accepts_only_complete_canonical_payload_in_node() -> None:
    """Execute the real comparison consumer against a server-shaped STAGE-006 response."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

const source = fs.readFileSync(process.argv[1], 'utf8');
globalThis.hasCompleteBasicUpload = extractFunction(
    source,
    'function hasCompleteBasicUpload',
    'function getCompareVerdict'
);
globalThis.getCompareVerdict = extractFunction(
    source,
    'function getCompareVerdict',
    'function getCompareVerdictLabel'
);

const hash = 'a'.repeat(64);
const payload = {
    file: {
        name: 'compare.txt',
        path: '/uploads/final-compare.txt',
        size_bytes: 3,
        size_human: '3.0 B',
        content_type: 'text/plain',
        uploaded_at: '2026-08-14T00:00:00+00:00',
        sha256: hash,
    },
    upload: {
        kind: 'basic',
        profile: 'multipart',
        carrier: 'multipart',
        filename_source: 'part',
        normalized_name: 'compare.txt',
        collision_renamed: true,
        request_body_size: 3,
        payload_size: 3,
    },
};
const verdict = globalThis.getCompareVerdict(
    { profile: 'multipart', filenameSource: 'part', mime: 'text/plain' },
    { name: 'compare.txt', size: 3 },
    hash,
    { ok: true },
    payload,
    null,
);
process.stdout.write(JSON.stringify({ verdict }));
"""

    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "upload.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"verdict": "delivered"}


def test_stage006_consumer_validators_reject_incomplete_or_wrong_kind_2xx_in_node() -> None:
    """Execute real consumer validators against malformed canonical-looking 2xx bodies."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

const upload = fs.readFileSync(process.argv[1], 'utf8');
const opsec = fs.readFileSync(process.argv[2], 'utf8');
const files = fs.readFileSync(process.argv[3], 'utf8');
const session = fs.readFileSync(process.argv[4], 'utf8');
const basic = extractFunction(
  upload, 'function hasCompleteBasicUpload', 'function getCompareVerdict'
);
const advanced = extractFunction(
  opsec, 'function getCanonicalAdvancedUpload', 'async function sendAdvancedUploadPlan'
);
const info = extractFunction(
  files, 'function getCanonicalInfoPayload', 'function getCanonicalClearedUploads'
);
const cleared = extractFunction(
  files, 'function getCanonicalClearedUploads', 'function getCanonicalDeletedFile'
);
const deleted = extractFunction(
  files, 'function getCanonicalDeletedFile', 'function downloadFile'
);
const sessionError = extractFunction(
  session, 'function responseErrorMessage', 'function sanitizeError'
);

const baseFile = {
  name: 'final.txt', path: '/uploads/final.txt', size_bytes: 1, size_human: '1 B',
  content_type: 'text/plain', uploaded_at: '2026-08-14T00:00:00+00:00', sha256: 'a'.repeat(64),
};
const baseUpload = {
  kind: 'basic', profile: 'multipart', carrier: 'multipart', filename_source: 'part',
  normalized_name: 'final.txt', collision_renamed: false, request_body_size: 1, payload_size: 1,
};
process.stdout.write(JSON.stringify({
  basicWrongKind: basic({
    file: baseFile, upload: { ...baseUpload, kind: 'advanced' },
  }),
  advancedWrongKind: advanced({
    file: baseFile, upload: { ...baseUpload, kind: 'basic' },
  }) !== null,
  advancedEmptyName: advanced({
    file: { ...baseFile, name: '' }, upload: { ...baseUpload, kind: 'advanced' },
  }) !== null,
  infoEmptyPath: info({ entry: { kind: 'file', path: '' } }) !== null,
  infoFileMissingName: info({
    entry: { kind: 'file', path: '/uploads/final.txt', size_bytes: 1,
      created_at: '2026-08-14T00:00:00+00:00', modified_at: '2026-08-14T00:00:00+00:00' },
  }) !== null,
  infoFileMissingSize: info({
    entry: { kind: 'file', path: '/uploads/final.txt', name: 'final.txt',
      created_at: '2026-08-14T00:00:00+00:00', modified_at: '2026-08-14T00:00:00+00:00' },
  }) !== null,
  infoFileMissingCreated: info({
    entry: { kind: 'file', path: '/uploads/final.txt', name: 'final.txt', size_bytes: 1,
      modified_at: '2026-08-14T00:00:00+00:00' },
  }) !== null,
  infoFileMissingModified: info({
    entry: { kind: 'file', path: '/uploads/final.txt', name: 'final.txt', size_bytes: 1,
      created_at: '2026-08-14T00:00:00+00:00' },
  }) !== null,
  canonicalFileInfo: info({
    entry: { kind: 'file', path: '/uploads/final.txt', name: 'final.txt', size_bytes: 1,
      created_at: '2026-08-14T00:00:00+00:00', modified_at: '2026-08-14T00:00:00+00:00' },
  }) !== null,
  infoDirectoryMissingPage: info({ entry: { kind: 'directory', path: '/uploads' } }) !== null,
  infoDirectoryMalformedItem: info({
    entry: { kind: 'directory', path: '/uploads' }, page: { total_items: 1 },
    contents: [{ name: '', kind: 'file' }],
  }) !== null,
  clearMissingCounts: cleared({ cleared_uploads: {} }) !== null,
  deleteMissingFields: deleted({ deleted_file: {} }) !== null,
  canonicalClear: cleared({
    cleared_uploads: { path: '/uploads', deleted_files: 2, deleted_dirs: 1 },
  })?.deleted_files,
  canonicalDelete: deleted({
    deleted_file: { name: 'final.txt', path: '/uploads/final.txt' },
  })?.path,
  nestedSessionError: sessionError(
    { status: 403, statusText: 'Forbidden' }, { error: { message: 'blocked' } }
  ),
}));
"""

    completed = subprocess.run(
        [
            "node",
            "-e",
            script,
            str(UI_ROOT / "upload.js"),
            str(UI_ROOT / "opsec.js"),
            str(UI_ROOT / "files.js"),
            str(UI_ROOT / "advanced-routing.js"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "basicWrongKind": False,
        "advancedWrongKind": False,
        "advancedEmptyName": False,
        "infoEmptyPath": False,
        "infoFileMissingName": False,
        "infoFileMissingSize": False,
        "infoFileMissingCreated": False,
        "infoFileMissingModified": False,
        "canonicalFileInfo": True,
        "infoDirectoryMissingPage": False,
        "infoDirectoryMalformedItem": False,
        "clearMissingCounts": False,
        "deleteMissingFields": False,
        "canonicalClear": 2,
        "canonicalDelete": "/uploads/final.txt",
        "nestedSessionError": "403: blocked",
    }


def test_inline_file_details_reject_directory_shaped_info_2xx_in_node() -> None:
    """Exercise the real details consumer against a valid-but-wrong INFO envelope."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

const files = fs.readFileSync(process.argv[1], 'utf8');
globalThis.getCanonicalErrorMessage = extractFunction(
    files, 'function getCanonicalErrorMessage', 'function getCanonicalResponseErrorMessage'
);
globalThis.getCanonicalResponseErrorMessage = extractFunction(
    files, 'function getCanonicalResponseErrorMessage', 'function getCanonicalInfoPayload'
);
globalThis.getCanonicalInfoPayload = extractFunction(
    files, 'function getCanonicalInfoPayload', 'function getCanonicalClearedUploads'
);
globalThis.isFileBrowseSupported = () => true;
globalThis.syncInlineFileDetailsDom = () => {};
globalThis.announceLiveRegion = () => {};
globalThis.t = (key) => key;
globalThis.createInspectionInfoUrl = (path) => path;
globalThis.filesState = {
    listActionsDisabled: false,
    expandedFilePath: '/uploads/detail.txt',
    infoGeneration: 0,
    fileInfoPhase: 'idle',
    fileInfoError: '',
    fileInfoCache: new Map(),
};
globalThis.sendCustomRequest = async () => new Response(JSON.stringify({
    entry: { kind: 'directory', path: '/uploads/detail.txt' },
    page: { total_items: 0 },
    contents: [],
}), { status: 200, headers: { 'content-type': 'application/json' } });

const showInlineFileDetails = extractFunction(
    files, 'async function showInlineFileDetails(path)', 'function getFileNameFromPath'
);

(async () => {
    const accepted = await showInlineFileDetails('/uploads/detail.txt');
    process.stdout.write(JSON.stringify({
        accepted,
        phase: globalThis.filesState.fileInfoPhase,
        cached: globalThis.filesState.fileInfoCache.has('/uploads/detail.txt'),
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""

    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "files.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "accepted": False,
        "phase": "error",
        "cached": False,
    }


def test_smuggle_info_hydration_caches_the_canonical_flat_file_entry_in_node() -> None:
    """Catches hydrateSmuggleSourceInfo caching the outer canonical INFO envelope."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

const smuggle = fs.readFileSync(process.argv[1], 'utf8');
globalThis.getCanonicalInfoPayload = extractFunction(
    smuggle, 'function getCanonicalInfoPayload', 'function getFileInspection'
);
globalThis.parseSmuggleJson = extractFunction(
    smuggle, 'function parseSmuggleJson', 'function resolveSmuggleErrorMessage'
);
globalThis.smuggleSourceInfoCache = new Map();
globalThis.createSmuggleInfoUrl = (path) => path;
globalThis.sendCustomRequest = async () => new Response(JSON.stringify({
    entry: {
        kind: 'file',
        name: 'canonical-smuggle-source.txt',
        path: '/uploads/canonical-smuggle-source.txt',
        size_bytes: 73,
        created_at: '2026-08-14T12:00:00+00:00',
        modified_at: '2026-08-14T12:05:00+00:00',
    },
}), { status: 200, headers: { 'content-type': 'application/json' } });
const modal = {
    isConnected: true,
    __smuggleSourceInfoSeq: 0,
    __smuggleComboboxes: new Map(),
    querySelector: () => null,
};
const hydrateSmuggleSourceInfo = extractFunction(
    smuggle,
    'async function hydrateSmuggleSourceInfo(filePath, modal)',
    'function setSmuggleInlineStatus'
);

(async () => {
    await hydrateSmuggleSourceInfo('/uploads/canonical-smuggle-source.txt', modal);
    const cached = globalThis.smuggleSourceInfoCache.get('/uploads/canonical-smuggle-source.txt');
    process.stdout.write(JSON.stringify({
        name: cached?.name,
        path: cached?.path,
        sizeBytes: cached?.size_bytes,
        createdAt: cached?.created_at,
        modifiedAt: cached?.modified_at,
        cachedEnvelope: Object.hasOwn(cached || {}, 'entry'),
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""

    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "smuggle.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "name": "canonical-smuggle-source.txt",
        "path": "/uploads/canonical-smuggle-source.txt",
        "sizeBytes": 73,
        "createdAt": "2026-08-14T12:00:00+00:00",
        "modifiedAt": "2026-08-14T12:05:00+00:00",
        "cachedEnvelope": False,
    }


def test_smuggle_info_hydration_rejects_nonfile_or_nonok_canonical_info_in_node() -> None:
    """Catches dropping either response.ok or file-kind guard in the real hydrator."""
    script = r"""
const fs = require('node:fs');

function extractFunction(source, marker, nextMarker) {
    const start = source.indexOf(marker);
    const end = source.indexOf(nextMarker, start);
    if (start < 0 || end < 0) throw new Error(`Could not extract ${marker}`);
    return (0, eval)(`(${source.slice(start, end).trim()})`);
}

const smuggle = fs.readFileSync(process.argv[1], 'utf8');
globalThis.getCanonicalInfoPayload = extractFunction(
    smuggle, 'function getCanonicalInfoPayload', 'function getFileInspection'
);
globalThis.parseSmuggleJson = extractFunction(
    smuggle, 'function parseSmuggleJson', 'function resolveSmuggleErrorMessage'
);
globalThis.smuggleSourceInfoCache = new Map();
globalThis.createSmuggleInfoUrl = (path) => path;
const scenarios = new Map([
    ['/uploads/canonical-directory', {
        status: 200,
        payload: {
            entry: { kind: 'directory', path: '/uploads/canonical-directory' },
            page: { total_items: 0 },
            contents: [],
        },
    }],
    ['/uploads/server-error-file.txt', {
        status: 500,
        payload: {
            entry: {
                kind: 'file',
                name: 'server-error-file.txt',
                path: '/uploads/server-error-file.txt',
                size_bytes: 73,
                created_at: '2026-08-14T12:00:00+00:00',
                modified_at: '2026-08-14T12:05:00+00:00',
            },
        },
    }],
]);
globalThis.sendCustomRequest = async (_method, path) => {
    const scenario = scenarios.get(path);
    if (!scenario) throw new Error(`Unexpected INFO path: ${path}`);
    return new Response(JSON.stringify(scenario.payload), {
        status: scenario.status,
        headers: { 'content-type': 'application/json' },
    });
};
const modal = {
    isConnected: true,
    __smuggleSourceInfoSeq: 0,
    __smuggleComboboxes: new Map(),
    querySelector: () => null,
};
const hydrateSmuggleSourceInfo = extractFunction(
    smuggle,
    'async function hydrateSmuggleSourceInfo(filePath, modal)',
    'function setSmuggleInlineStatus'
);

(async () => {
    for (const path of scenarios.keys()) {
        await hydrateSmuggleSourceInfo(path, modal);
    }
    process.stdout.write(JSON.stringify({
        directoryCached: globalThis.smuggleSourceInfoCache.has('/uploads/canonical-directory'),
        serverErrorCached: globalThis.smuggleSourceInfoCache.has(
            '/uploads/server-error-file.txt'
        ),
    }));
})().catch(error => {
    process.stderr.write(String(error.stack || error));
    process.exitCode = 1;
});
"""

    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "smuggle.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "directoryCached": False,
        "serverErrorCached": False,
    }


def test_files_xor_decrypt_fetch_uses_the_conditional_no_gzip_header_helper() -> None:
    """Catches XOR decrypt FETCH forcing no-gzip while the response option is off."""
    files_js = (REPO_ROOT / "xferry" / "data" / "static" / "ui" / "files.js").read_text(
        encoding="utf-8"
    )
    decrypt_fetch = files_js.split("async function fetchFileBlobForXorDecrypt(path)", 1)[1].split(
        "async function decryptXorFileFromBrowser",
        1,
    )[0]

    assert "withNoGzipHeader: withUiNoGzipHeader" in files_js
    assert "Object.entries(withUiNoGzipHeader({}))" in decrypt_fetch
    assert "getNoGzipHeaderPair" not in files_js
    assert "xhr.setRequestHeader(uiNoGzipHeader, uiNoGzipHeaderValue)" not in decrypt_fetch


def test_header_controls_expose_state_and_invalid_locale_falls_back() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")

    assert 'id="langRu"' in html and 'aria-pressed="true">RU</button>' in html
    assert 'id="langEn"' in html and 'aria-pressed="false">EN</button>' in html
    assert 'id="themeBtn"' in html and 'aria-pressed="false">🌙</button>' in html

    for key in (
        "langRussianSelectedLabel",
        "langRussianSelectLabel",
        "langEnglishSelectedLabel",
        "langEnglishSelectLabel",
        "themeDarkCurrentLabel",
        "themeLightCurrentLabel",
    ):
        assert extract_locale_keys(core_js, "ru") >= {key}
        assert extract_locale_keys(core_js, "en") >= {key}

    assert "const supportedLangs = new Set(['ru', 'en']);" in core_js
    assert "function normalizeLang(lang)" in core_js
    assert "let currentLang = normalizeLang(storedLang);" in core_js
    assert "translations[currentLang] || translations.ru" in core_js
    assert "button.setAttribute('aria-pressed', String(selected));" in core_js
    assert "btn.setAttribute('aria-pressed', String(isLight));" in core_js


def test_advanced_password_error_is_bound_to_the_invalid_field() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    opsec_js = (UI_ROOT / "opsec.js").read_text(encoding="utf-8")

    assert 'id="opsecEncryptionHelp"' in html
    assert (
        'id="opsecPassword" data-i18n-placeholder="opsecPasswordPlaceholder" '
        'placeholder="Ключ шифрования" aria-describedby="opsecEncryptionHelp opsecPasswordError" '
        'aria-invalid="false"'
    ) in html
    assert (
        'class="field-error" id="opsecPasswordError" data-i18n="opsecPasswordRequired" hidden'
    ) in html
    assert "function showOpsecPasswordError()" in opsec_js
    assert "function clearOpsecPasswordError()" in opsec_js
    assert "opsecPasswordInput.setAttribute('aria-invalid', 'true');" in opsec_js
    assert "focusElementWithoutScroll(opsecPasswordInput);" in opsec_js
    assert "opsecPasswordInput?.addEventListener('input', () => {" in opsec_js
    assert "clearOpsecPasswordError();" in opsec_js


def test_disclosures_use_accessibility_silent_text_markers_and_reduced_motion() -> None:
    features_css = (UI_ROOT / "features.css").read_text(encoding="utf-8")

    assert "▸" not in features_css
    assert "▾" not in features_css
    assert features_css.count('content: "[+]" / "";') >= 6
    assert features_css.count('content: "[-]" / "";') >= 6
    for selector in (
        ".request-batch-summary__history summary",
        ".notepad-loss-details__summary",
    ):
        assert f"{selector}::-webkit-details-marker" in features_css
    assert "@media (prefers-reduced-motion: reduce)" in features_css
    assert "animation: none !important;" in features_css
    assert "transition: none !important;" in features_css
    assert "scroll-behavior: auto !important;" in features_css


def test_shared_visual_system_tokens_and_document_theme_are_exact() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    tokens_css = (UI_ROOT / "tokens.css").read_text(encoding="utf-8")

    dark_tokens = tokens_css.split(":root {", 1)[1].split("\n}", 1)[0]
    light_tokens = tokens_css.split('[data-theme="light"] {', 1)[1].split("\n}", 1)[0]
    for declaration in (
        "--bg-canvas: #111315;",
        "--bg-muted: #1a1d20;",
        "--bg-elevated: #25292d;",
        "--bg-strong: #111315;",
        "--border-subtle: rgba(253, 252, 252, 0.12);",
        "--text-primary: #fdfcfc;",
    ):
        assert declaration in dark_tokens
    for declaration in (
        "--bg-canvas: #fdfcfc;",
        "--bg-muted: #f8f7f7;",
        "--bg-elevated: #f1eeee;",
        "--bg-strong: #fdfcfc;",
        "--border-subtle: rgba(32, 29, 29, 0.12);",
        "--text-primary: #201d1d;",
    ):
        assert declaration in light_tokens
    assert (
        '--font-ui: "JetBrains Mono", "IBM Plex Mono", ui-monospace, '
        '"SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace;'
    ) in dark_tokens
    assert "--font-mono: var(--font-ui);" in dark_tokens
    assert "--radius-sm: 4px;" in dark_tokens
    assert "--radius-md: 0px;" in dark_tokens
    assert "--radius-lg: 0px;" in dark_tokens
    assert '<meta name="theme-color" content="#111315">' in html


def test_light_theme_uses_high_contrast_accent_tokens() -> None:
    tokens_css = (UI_ROOT / "tokens.css").read_text(encoding="utf-8")
    components_css = (UI_ROOT / "components.css").read_text(encoding="utf-8")

    light_tokens = tokens_css.split('[data-theme="light"] {', 1)[1].split("\n}", 1)[0]
    for declaration in (
        "--accent-primary: #05603a;",
        "--accent-secondary: #064f91;",
        "--accent-tertiary: #78350f;",
        "--accent-danger: #991b1b;",
        "--accent-opsec: #581c87;",
        "--accent-note: #14532d;",
        "--accent-orange: #9a3412;",
    ):
        assert declaration in light_tokens
    assert "#f97316" not in components_css
    assert "var(--accent-orange)" in components_css


def test_notepad_warns_about_every_unrecoverable_loss_trigger_before_save() -> None:
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")

    assert 'id="notepadEphemeralWarning"' in html
    assert 'id="notepadLossDetails"' in html
    assert 'data-testid="notepad-loss-details"' in html
    assert 'id="notepadLossDetailsBody"' in html
    assert 'data-i18n="notepadLossDetailsSummary"' in html
    assert 'data-i18n="notepadLossDetailsBody"' in html
    assert 'aria-describedby="notepadTitleMetadataHint notepadEphemeralWarning"' in html
    assert 'aria-describedby="notepadEphemeralWarning"' in html

    for expected in (
        "перезагрузки страницы",
        "перезапуска браузера или сервера",
        "TTL сессии",
        "LRU-вытеснения",
        "Ключ восстановления не хранится",
        "page reload",
        "browser or server restart",
        "session TTL expiry",
        "LRU eviction",
        "No recovery key is stored",
    ):
        assert expected in core_js

    assert "Сессии не сохраняются при перезагрузке сервера" not in core_js
    assert "Sessions are lost on server restart" not in core_js


def test_advanced_session_controls_compiler_and_basic_coexistence_are_packaged() -> None:
    """Catches reintroduction of global routing or Basic upload coupling."""
    html = (REPO_ROOT / "xferry" / "data" / "index.html").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")
    session_js = (UI_ROOT / "advanced-routing.js").read_text(encoding="utf-8")
    compiler_js = (UI_ROOT / "advanced-compiler.js").read_text(encoding="utf-8")
    upload_js = (UI_ROOT / "upload.js").read_text(encoding="utf-8")
    opsec_js = (UI_ROOT / "opsec.js").read_text(encoding="utf-8")

    for element_id in (
        "advancedSessionPanel",
        "advancedSessionPrefixInput",
        "advancedSessionDecoderSelect",
        "advancedSessionDiagnosticHeaders",
        "advancedSessionCreateBtn",
        "advancedSessionRevokeBtn",
        "advancedSessionExpiresOutput",
        "advancedSessionStatus",
    ):
        assert html.count(f'id="{element_id}"') == 1

    upload_tab = extract_workspace_panel(html, "upload-tab")
    opsec_tab = extract_workspace_panel(html, "opsec-tab")
    assert 'id="advancedSessionPanel"' in opsec_tab
    assert 'id="advancedSessionStatus" role="status" aria-live="polite"' in opsec_tab
    assert 'id="responseOptions"' in upload_tab
    assert 'id="responseNoGzip"' in upload_tab
    assert "advancedSession" not in upload_tab
    assert "AdvancedRouting" not in upload_tab

    session_script = '<script src="/static/ui/advanced-routing.js"></script>'
    compiler_script = '<script src="/static/ui/advanced-compiler.js"></script>'
    opsec_script = '<script src="/static/ui/opsec.js"></script>'
    assert html.index(session_script) < html.index(opsec_script)
    assert html.index(compiler_script) < html.index(opsec_script)

    assert "app.registerService('advanced-session'" in session_js
    assert "app.registerService('advanced-compiler'" in compiler_js
    assert "/_xferry/advanced-sessions" in session_js
    assert "/_xferry/advanced-sessions/current" in session_js

    for method_name in (
        "create",
        "current",
        "revoke",
        "ensureActive",
        "getSnapshot",
        "subscribe",
        "attachSessionHeader",
    ):
        assert re.search(rf"\b{re.escape(method_name)}\s*[,}}]", session_js)

    for forbidden_sink in (
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "location.hash",
        "location.search",
        "console.log",
        "console.error",
    ):
        assert forbidden_sink not in session_js

    combined = "\n".join((html, core_js, session_js, compiler_js, upload_js, opsec_js))
    for removed in (
        "GLOBAL SERVER STATE",
        "/_xferry/advanced-routing",
        "Global routing is disabled",
        "global route revision",
        "basicAdvancedRoutingWarning",
    ):
        assert removed not in combined

    for required_copy in (
        "Advanced session inactive",
        "Create session",
        "Revoke session",
        "Session active for this browser tab",
        "Advanced requests include a session header at send time",
        "Session token is never shown or saved",
    ):
        assert required_copy in combined

    assert "service('advanced-session')" not in upload_js
    assert "service('advanced-session')" in opsec_js
    assert "service('advanced-compiler')" in opsec_js
    assert "attachSessionHeader" in opsec_js
    assert 'id="opsecEncryptionSelect"' in opsec_tab
    for mode in ("none", "xor", "aes"):
        assert f'<option value="{mode}"' in opsec_tab


def test_advanced_session_service_keeps_token_closure_local_and_clears_on_revoke_failure() -> None:
    """Exercise the real bundled service with a secret-bearing control response."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(process.argv[1], 'utf8');
const token = 'A'.repeat(43);
const elements = new Map();
for (const id of [
  'advancedSessionPanel', 'advancedSessionPrefixInput', 'advancedSessionDecoderSelect',
  'advancedSessionDiagnosticHeaders', 'advancedSessionCreateBtn', 'advancedSessionRevokeBtn',
  'advancedSessionStatus', 'advancedSessionExpiresOutput',
]) {
  elements.set(id, {
    id, value: id.endsWith('PrefixInput') ? '/advanced' : 'auto', checked: true,
    disabled: false, hidden: false, textContent: '', dataset: {},
    addEventListener() {}, setAttribute() {}, removeAttribute() {},
  });
}
const requests = [];
const snapshots = [];
let service;
const app = {
  events: { WORKSPACE_CHANGED: 'workspace.changed', LOCALE_CHANGED: 'locale.changed' },
  service(name) {
    if (name === 'core') return { t: key => key, serverUrl: '' };
    if (name === 'dialogs') return { async confirm() { return true; } };
    if (name !== 'http') throw new Error(`unexpected service ${name}`);
    return {
      async request(method, url, body, headers, progress, options) {
        requests.push({ method, url, body, headers: { ...(headers || {}) }, progress, options });
        if (method === 'POST') {
          return {
            ok: true, status: 201, statusText: 'Created',
            async text() { return JSON.stringify({ advanced_session: {
              token, prefix: '/advanced', decoder: 'auto', diagnostic_headers: true,
              created_at: '2026-08-14T00:00:00Z', expires_at: '2099-08-14T01:00:00Z',
              idle_timeout_seconds: 900,
            }}); },
          };
        }
        if (method === 'GET') {
          return {
            ok: true, status: 200, statusText: 'OK',
            async text() { return JSON.stringify({ advanced_session: {
              prefix: '/advanced', decoder: 'auto', diagnostic_headers: true,
              created_at: '2026-08-14T00:00:00Z', expires_at: '2099-08-14T01:00:00Z',
              idle_timeout_seconds: 900,
            }}); },
          };
        }
        throw new Error('revoke transport failed');
      },
    };
  },
  registerService(name, api) {
    if (name === 'advanced-session') service = api;
  },
  on() { return () => {}; },
};
const storage = () => ({ values: new Map(), setItem(k, v) { this.values.set(k, v); } });
const context = vm.createContext({
  window: { XferryApp: app, addEventListener() {} },
  document: { getElementById: id => elements.get(id) || null },
  location: { href: 'https://xferry.test/#opsec' },
  URL, Headers, TextDecoder, Object, Set, Array, JSON, Error, TypeError, Promise,
  Date, setTimeout, clearTimeout,
  localStorage: storage(), sessionStorage: storage(), console: { error() {}, log() {} },
});
vm.runInContext(source, context);

(async () => {
  if (!service) {
    process.stdout.write(JSON.stringify({ serviceRegistered: false }));
    return;
  }
  service.subscribe(snapshot => snapshots.push(JSON.parse(JSON.stringify(snapshot))));
  const created = await service.create();
  const attached = service.attachSessionHeader({ method: 'POST', headers: { Existing: 'yes' } });
  await service.current();
  const beforeRevoke = service.getSnapshot();
  const revoked = await service.revoke();
  const afterRevoke = service.getSnapshot();
  const rendered = Array.from(elements.values()).map(node =>
    `${node.textContent}|${JSON.stringify(node.dataset)}`
  ).join('\n');
  process.stdout.write(JSON.stringify({
    created, beforeRevoke, revoked, afterRevoke, attached,
    requests, snapshots, rendered,
    local: Array.from(context.localStorage.values.entries()),
    session: Array.from(context.sessionStorage.values.entries()),
    location: context.location.href,
  }));
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "advanced-routing.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result.get("serviceRegistered", True) is True
    secret = "A" * 43
    assert result["created"]["active"] is True
    assert result["beforeRevoke"]["active"] is True
    assert result["revoked"] is False
    assert result["afterRevoke"]["active"] is False
    assert result["attached"]["headers"] == {
        "Existing": "yes",
        "X-XFerry-Advanced-Session": secret,
    }
    assert result["requests"][-1]["method"] == "DELETE"
    assert result["requests"][-1]["headers"] == {
        "X-XFerry-Advanced-Session": secret,
    }
    non_transient = json.dumps(
        {
            "created": result["created"],
            "before": result["beforeRevoke"],
            "after": result["afterRevoke"],
            "snapshots": result["snapshots"],
            "rendered": result["rendered"],
            "local": result["local"],
            "session": result["session"],
            "location": result["location"],
        }
    )
    assert secret not in non_transient


def _run_advanced_session_lifecycle_probe() -> dict[str, object]:
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const tokens = Object.fromEntries(
  ['A', 'B', 'C', 'D', 'E'].map(letter => [letter, letter.repeat(43)]),
);
const elements = new Map();
for (const id of [
  'advancedSessionPanel', 'advancedSessionPrefixInput', 'advancedSessionDecoderSelect',
  'advancedSessionDiagnosticHeaders', 'advancedSessionCreateBtn',
  'advancedSessionRevokeBtn', 'advancedSessionStatus', 'advancedSessionExpiresOutput',
]) {
  elements.set(id, {
    id, value: id.endsWith('PrefixInput') ? '/advanced' : 'auto', checked: true,
    disabled: false, textContent: '', dataset: {},
    addEventListener() {}, setAttribute() {}, removeAttribute() {},
  });
}
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const response = (status, payload) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: status === 201 ? 'Created' : 'OK',
  async text() { return JSON.stringify(payload); },
});
const sessionPayload = (token, expiresAt) => ({ advanced_session: {
  token,
  prefix: '/advanced',
  decoder: 'auto',
  diagnostic_headers: false,
  created_at: '2026-08-14T00:00:00.000Z',
  expires_at: expiresAt,
  idle_timeout_seconds: 900,
}});
const metadataPayload = expiresAt => ({ advanced_session: {
  prefix: '/advanced',
  decoder: 'auto',
  diagnostic_headers: false,
  created_at: '2026-08-14T00:00:00.000Z',
  expires_at: expiresAt,
  idle_timeout_seconds: 900,
}});
const requests = [];
const pendingPosts = [];
const pendingGets = [];
const appHandlers = new Map();
const windowHandlers = new Map();
let now = Date.parse('2026-08-14T00:00:00.000Z');
let nextTimerId = 1;
const timers = new Map();
const fakeSetTimeout = (callback, delay) => {
  const id = nextTimerId++;
  timers.set(id, { callback, due: now + Math.max(0, Number(delay) || 0) });
  return id;
};
const fakeClearTimeout = id => timers.delete(id);
const advance = milliseconds => {
  now += milliseconds;
  while (true) {
    const due = Array.from(timers.entries())
      .filter(([, timer]) => timer.due <= now)
      .sort((left, right) => left[1].due - right[1].due)[0];
    if (!due) break;
    timers.delete(due[0]);
    due[1].callback();
  }
};
class FakeDate extends Date {
  static now() { return now; }
}
let service;
const app = {
  events: { WORKSPACE_CHANGED: 'workspace.changed', LOCALE_CHANGED: 'locale.changed' },
  service(name) {
    if (name === 'core') return { t: key => key, serverUrl: '' };
    if (name !== 'http') throw new Error(`unexpected service ${name}`);
    return {
      request(method, url, body, headers, progress, options) {
        requests.push({ method, headers: { ...(headers || {}) }, options });
        if (method === 'POST') {
          const pending = deferred();
          pendingPosts.push(pending);
          return pending.promise;
        }
        if (method === 'GET') {
          const pending = deferred();
          pendingGets.push(pending);
          return pending.promise;
        }
        return Promise.resolve(response(200, { revoked: true }));
      },
    };
  },
  registerService(name, api) { if (name === 'advanced-session') service = api; },
  on(name, handler) { appHandlers.set(name, handler); return () => {}; },
};
const context = vm.createContext({
  window: {
    XferryApp: app,
    addEventListener(name, handler) { windowHandlers.set(name, handler); },
  },
  document: { getElementById: id => elements.get(id) || null },
  location: { href: 'https://xferry.test/#opsec' },
  URL, Headers, TextDecoder, Object, Set, Array, JSON, Error, TypeError, Promise,
  Date: FakeDate, setTimeout: fakeSetTimeout, clearTimeout: fakeClearTimeout,
});
vm.runInContext(source, context);
const tick = () => Promise.resolve();

(async () => {
  const farFuture = '2026-08-14T02:00:00.000Z';

  const leavingCreate = service.create();
  appHandlers.get('workspace.changed')({ workspace: 'upload' });
  pendingPosts[0].resolve(response(201, sessionPayload(tokens.A, farFuture)));
  await leavingCreate;
  const afterLeave = service.getSnapshot();

  const reentryPostIndex = pendingPosts.length;
  appHandlers.get('workspace.changed')({ workspace: 'opsec' });
  const reentryCreate = service.create();
  if (pendingPosts[reentryPostIndex]) {
    pendingPosts[reentryPostIndex].resolve(response(201, sessionPayload(tokens.B, farFuture)));
  }
  await reentryCreate;
  const afterReentry = service.getSnapshot();
  await service.revoke();

  const pagehidePostIndex = pendingPosts.length;
  const pagehideCreate = service.create();
  windowHandlers.get('pagehide')();
  pendingPosts[pagehidePostIndex].resolve(response(201, sessionPayload(tokens.C, farFuture)));
  await pagehideCreate;
  const afterPagehide = service.getSnapshot();
  await service.revoke();

  const currentRacePostIndex = pendingPosts.length;
  const currentRaceCreate = service.create();
  pendingPosts[currentRacePostIndex].resolve(
    response(201, sessionPayload(tokens.D, farFuture)),
  );
  await currentRaceCreate;
  const checking = service.current();
  await tick();
  const revoking = service.revoke();
  pendingGets[0].resolve(response(200, metadataPayload(farFuture)));
  await Promise.all([checking, revoking]);
  const afterCurrentRevokeRace = service.getSnapshot();

  const expiringPostIndex = pendingPosts.length;
  const expiringCreate = service.create();
  const expiresAt = new Date(now + 1000).toISOString();
  pendingPosts[expiringPostIndex].resolve(response(201, sessionPayload(tokens.E, expiresAt)));
  await expiringCreate;
  const beforeExpiry = service.getSnapshot();
  advance(1001);
  await tick();
  const afterExpiry = service.getSnapshot();
  let attachAfterExpiry = 'attached';
  try {
    service.attachSessionHeader({ headers: {} });
  } catch (_error) {
    attachAfterExpiry = 'rejected';
  }
  await service.revoke();

  const failedPostIndex = pendingPosts.length;
  const failedCreate = service.create();
  pendingPosts[failedPostIndex].reject(new Error('create transport failed'));
  await failedCreate;
  const afterFailedCreate = service.getSnapshot();

  process.stdout.write(JSON.stringify({
    tokens, requests, afterLeave, afterReentry, afterPagehide,
    afterCurrentRevokeRace, beforeExpiry, afterExpiry, attachAfterExpiry,
    afterFailedCreate, timersRemaining: timers.size,
  }));
})().catch(error => { process.stderr.write(String(error.stack || error)); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "advanced-routing.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_advanced_session_invalidates_late_create_and_current_results() -> None:
    """Catches late control responses restoring authority after leave or revoke."""
    result = _run_advanced_session_lifecycle_probe()
    tokens = result["tokens"]

    assert result["afterLeave"]["active"] is False
    assert result["afterPagehide"]["active"] is False
    assert result["afterCurrentRevokeRace"] == {
        "active": False,
        "phase": "inactive",
        "error": "",
        "prefix": None,
        "decoder": None,
        "diagnostic_headers": False,
        "created_at": None,
        "expires_at": None,
        "idle_timeout_seconds": None,
    }
    assert result["afterReentry"]["active"] is True
    delete_tokens = [
        request["headers"].get("X-XFerry-Advanced-Session")
        for request in result["requests"]
        if request["method"] == "DELETE"
    ]
    assert tokens["A"] in delete_tokens
    assert tokens["B"] in delete_tokens
    assert tokens["C"] in delete_tokens
    assert tokens["D"] in delete_tokens


def test_advanced_session_expires_locally_and_failed_create_stays_inactive() -> None:
    """Catches treating expires_at as display-only session metadata."""
    result = _run_advanced_session_lifecycle_probe()

    assert result["beforeExpiry"]["active"] is True
    assert result["afterExpiry"]["active"] is False
    assert result["afterExpiry"]["phase"] == "inactive"
    assert result["attachAfterExpiry"] == "rejected"
    assert result["afterFailedCreate"]["active"] is False
    assert result["afterFailedCreate"]["phase"] == "inactive"
    assert "create transport failed" in result["afterFailedCreate"]["error"]
    assert result["timersRemaining"] == 0


def test_advanced_compiler_emits_canonical_carriers_and_server_compatible_crypto() -> None:
    """Run every compiler carrier plus independent Node XOR/AES verification."""
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const nodeCrypto = require('node:crypto');
const source = fs.readFileSync(process.argv[1], 'utf8');
let compiler;
const app = { registerService(name, api) {
  if (name !== 'advanced-compiler') throw new Error(`wrong service ${name}`);
  compiler = api;
}};
const context = vm.createContext({
  window: { XferryApp: app }, crypto: nodeCrypto.webcrypto,
  TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, URL, URLSearchParams,
  Headers, FormData, Blob, btoa, atob, Object, Set, JSON, Error, TypeError,
});
vm.runInContext(source, context);
const bytes = new TextEncoder().encode('canonical payload');
const common = {
  method: 'POST', prefix: '/advanced', encoding: 'base64', encryption: 'none',
  name: 'hello world.txt', mime: 'application/json', partMime: 'application/octet-stream',
};
const simplify = plan => ({
  path: plan.requestPath,
  headers: plan.requestHeaders,
  body: typeof plan.requestBody === 'string' ? plan.requestBody : null,
  cookies: plan.cookieEffects,
});
(async () => {
  const json = await compiler.compile(
    { ...common, carrier: 'body', bodyFormat: 'json' }, bytes,
  );
  const form = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'form',
    mime: 'application/x-www-form-urlencoded',
  }, bytes);
  const xml = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'xml', mime: 'application/xml',
  }, bytes);
  const multipartEncoded = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'multipart-encoded',
    mime: 'multipart/form-data',
  }, bytes);
  const multipartBinary = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'multipart-binary',
    mime: 'multipart/form-data',
  }, bytes);
  const raw = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'raw', mime: 'application/octet-stream',
  }, bytes);
  const text = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'text', mime: 'text/plain; charset=utf-8',
  }, bytes);
  const headers = await compiler.compile({
    ...common, carrier: 'headers', bodyFormat: 'json', chunkSize: 4,
  }, bytes);
  const query = await compiler.compile(
    { ...common, carrier: 'query', bodyFormat: 'json' }, bytes,
  );
  const cookies = await compiler.compile(
    { ...common, carrier: 'cookies', bodyFormat: 'json' }, bytes,
  );
  const path = await compiler.compile(
    { ...common, carrier: 'path', bodyFormat: 'json' }, bytes,
  );
  const xor = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'json', encryption: 'xor', key: 'xor-key',
  }, bytes);
  const aes = await compiler.compile({
    ...common, carrier: 'body', bodyFormat: 'json', encryption: 'aes', key: 'aes-key',
  }, bytes);

  const multipartEncodedEntries = Array.from(
    multipartEncoded.requestBody.entries(),
  ).map(([k, v]) => [k, String(v)]);
  const multipartBinaryEntries = Array.from(
    multipartBinary.requestBody.entries(),
  ).map(([k, v]) => [
    k, v instanceof Blob ? { size: v.size, type: v.type } : String(v),
  ]);
  const xorPayload = Buffer.from(
    JSON.parse(xor.requestBody).data.replace(/-/g, '+').replace(/_/g, '/'), 'base64',
  );
  const digest = nodeCrypto.createHash('sha256').update('xor-key', 'utf8').digest();
  const xorExpected = Buffer.from(
    bytes.map((value, index) => value ^ digest[index % digest.length]),
  );
  const aesWire = Buffer.from(
    JSON.parse(aes.requestBody).data.replace(/-/g, '+').replace(/_/g, '/'), 'base64',
  );
  const aesKey = nodeCrypto.pbkdf2Sync('aes-key', aesWire.subarray(1, 17), 600000, 32, 'sha256');
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', aesKey, aesWire.subarray(17, 29));
  decipher.setAuthTag(aesWire.subarray(aesWire.length - 16));
  const aesPlain = Buffer.concat([decipher.update(aesWire.subarray(29, -16)), decipher.final()]);
  process.stdout.write(JSON.stringify({
    json: simplify(json), form: simplify(form), xml: simplify(xml), raw: simplify(raw),
    text: simplify(text), headers: simplify(headers), query: simplify(query),
    cookies: simplify(cookies), path: simplify(path),
    multipartEncodedEntries, multipartBinaryEntries,
    xorMatches: xorPayload.equals(xorExpected), aesVersion: aesWire[0],
    aesSalt: aesWire.subarray(1, 17).length, aesNonce: aesWire.subarray(17, 29).length,
    aesPlain: aesPlain.toString('utf8'),
  }));
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "advanced-compiler.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert json.loads(result["json"]["body"])["encryption"] == "none"
    assert "key" not in json.loads(result["json"]["body"])
    assert "hmac" not in json.loads(result["json"]["body"])
    assert "encryption=none" in result["form"]["body"]
    assert "<upload>" in result["xml"]["body"]
    assert "<encryption>none</encryption>" in result["xml"]["body"]
    assert result["raw"]["headers"]["X-XFerry-Encryption"] == "none"
    assert result["text"]["headers"]["X-XFerry-Encryption"] == "none"
    assert "X-XFerry-Data-0" in result["headers"]["headers"]
    assert "X-XFerry-Data" not in result["headers"]["headers"]
    assert "encryption=none" in result["query"]["path"]
    assert {
        "action": "set",
        "name": "xferry_encryption",
        "value": "none",
    } in result["cookies"]["cookies"]
    assert result["path"]["path"].startswith("/advanced/_payload/hello%20world.txt/")
    assert result["path"]["path"].endswith("?encryption=none")
    assert ["encryption", "none"] in result["multipartEncodedEntries"]
    assert ["encryption", "none"] in result["multipartBinaryEntries"]
    assert result["xorMatches"] is True
    assert result["aesVersion"] == 1
    assert result["aesSalt"] == 16
    assert result["aesNonce"] == 12
    assert result["aesPlain"] == "canonical payload"


def test_advanced_compiler_aes_fails_closed_without_webcrypto() -> None:
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
let compiler;
const context = vm.createContext({
  window: { XferryApp: { registerService(name, api) {
    if (name === 'advanced-compiler') compiler = api;
  }}},
  TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, URL, URLSearchParams,
  Headers, FormData, Blob, btoa, Object, Set, JSON, Error, TypeError,
});
vm.runInContext(source, context);
(async () => {
  try {
    await compiler.compile({
      method: 'POST', prefix: '/advanced', carrier: 'body', bodyFormat: 'json',
      encoding: 'base64', encryption: 'aes', key: 'required-key', name: 'a.bin',
      mime: 'application/json', partMime: 'application/octet-stream',
    }, new TextEncoder().encode('payload'));
    process.stdout.write(JSON.stringify({ sent: true }));
  } catch (error) {
    process.stdout.write(JSON.stringify({ sent: false, message: String(error.message || error) }));
  }
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
"""
    completed = subprocess.run(
        ["node", "-e", script, str(UI_ROOT / "advanced-compiler.js")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "sent": False,
        "message": "WebCrypto AES-GCM is unavailable",
    }


def test_files_inline_details_contract_replaces_metadata_dialog() -> None:
    files_js = (UI_ROOT / "files.js").read_text(encoding="utf-8")
    features_css = (UI_ROOT / "features.css").read_text(encoding="utf-8")
    core_js = (UI_ROOT / "core.js").read_text(encoding="utf-8")

    assert "expandedFilePath:" in files_js
    assert "fileInfoCache: new Map()" in files_js
    assert "file-row__details-trigger" in files_js
    assert "file-row__details-panel" in files_js
    assert "retry.dataset.fileDetailsRetry = '';" in files_js
    assert "async function getFileInfo(" not in files_js
    assert "'info'," not in files_js
    assert 'data-file-action="info"' not in files_js

    for required in (
        "aria-expanded",
        "aria-controls",
        "aria-busy",
        "filesState.infoGeneration",
        "showInlineFileDetails",
        "renderInlineFileDetailsPanel",
        "focusElementWithoutScroll",
    ):
        assert required in files_js

    inline_details_region = files_js.split("function showInlineFileDetails", 1)[1].split(
        "function getFileNameFromPath",
        1,
    )[0]
    assert "setExchangeInspector" not in inline_details_region
    assert "filesHttpErrorHost" not in inline_details_region
    assert "showNoticeDialog" not in inline_details_region
    assert "showConfirmDialog" not in inline_details_region

    for locale_key in (
        "fileDetailsExpand",
        "fileDetailsCollapse",
        "fileDetailsLoading",
        "fileDetailsRetry",
        "fileDetailsTitle",
    ):
        assert extract_locale_keys(core_js, "ru") >= {locale_key}
        assert extract_locale_keys(core_js, "en") >= {locale_key}

    for selector in (
        ".file-row__details-trigger",
        ".file-row__details-panel",
        ".file-row__details-grid",
        ".file-row__details-field",
    ):
        assert selector in features_css

    trigger_block = features_css.split("\n.file-row__details-trigger {", 1)[1].split("\n}", 1)[0]
    panel_block = features_css.split("\n.file-row__details-panel {", 1)[1].split("\n}", 1)[0]
    assert "min-height: 44px;" in trigger_block
    assert "overflow-wrap: anywhere;" in trigger_block
    assert "flex: 1 0 100%;" in panel_block
    assert "overflow-wrap: anywhere;" in panel_block
