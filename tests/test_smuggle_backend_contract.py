"""Backend contract tests for SMUGGLE generation responses."""

import json
from datetime import datetime, timezone
from html import unescape
from urllib.parse import quote

import pytest

from tests.conftest import make_request
from tests.server_factory import make_server
from xferry.handlers.smuggle import SmuggleTempPolicy, build_smuggle_capabilities


def _server(temp_dir):
    (temp_dir / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    return make_server(root_dir=str(temp_dir), quiet=True)


def test_smuggle_capabilities_shape_is_ping_ready() -> None:
    capabilities = build_smuggle_capabilities(
        source_size_limit=123,
        temp_policy=SmuggleTempPolicy(
            max_age_seconds=10,
            max_file_count=2,
            max_total_bytes=456,
        ),
    )

    assert capabilities["source_max_bytes"] == 123
    assert capabilities["schema_version"] == 1
    assert capabilities["modes"] == ["simple", "constructor"]
    assert capabilities["encryption_modes"] == ["none", "xor", "aes"]
    assert capabilities["field_limits"]["download_name"] == 120
    assert capabilities["field_limits"]["download_ext"] == 32
    assert capabilities["field_limits"]["trigger_event"] == 64
    assert capabilities["field_limits"]["mime_type"] == 120
    assert capabilities["defaults"]["preset"] == "direct"
    assert {"exe", "docx", "7z", "tar.gz"} <= set(capabilities["extensions"])
    assert "application/x-7z-compressed" in capabilities["mime_presets"]
    assert capabilities["mime_by_extension"]["tar.gz"] == "application/gzip"
    assert (
        capabilities["mime_by_extension"]["docx"]
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert "card_auto" in capabilities["presets"]
    assert "xor" in capabilities["payload_encodings"]
    assert "base64url" in capabilities["payload_encodings"]
    assert "base32" in capabilities["payload_encodings"]
    assert "percent" in capabilities["payload_encodings"]
    assert "svg" in capabilities["output_formats"]
    assert "minimal" in capabilities["page_templates"]
    assert "npf-zip-archive-help" in capabilities["page_templates"]
    assert "npf-rar-archive-help" not in capabilities["page_templates"]
    assert "timeout-blob" in capabilities["download_variants"]
    assert "response-blob" in capabilities["download_variants"]
    assert "readable-stream" in capabilities["download_variants"]
    assert "message-channel-blob" in capabilities["download_variants"]
    assert "idle-callback-blob" in capabilities["download_variants"]
    assert capabilities["trigger_events"]["body"] == ["onload", "onpageshow"]
    assert "pageshow" not in capabilities["trigger_events"]
    assert "button" in capabilities["custom_trigger_methods"]
    assert "pageshow" not in capabilities["custom_trigger_methods"]
    assert capabilities["caps"]["custom_extension"] is True
    assert capabilities["caps"]["custom_mime_type"] is True
    assert capabilities["caps"]["custom_trigger_event"] is True
    assert capabilities["caps"]["searchable_options"] is True
    assert capabilities["temp_policy"] == {
        "max_age_seconds": 10,
        "max_file_count": 2,
        "max_total_bytes": 456,
    }


def test_smuggle_success_reports_canonical_effective_simple_settings(
    temp_dir,
    monkeypatch,
) -> None:
    server = _server(temp_dir)
    server.smuggle_temp_policy = SmuggleTempPolicy(max_age_seconds=None)
    monkeypatch.setattr(
        "xferry.handlers.smuggle.secrets.token_hex", lambda _size: "0123abcd4567ef89"
    )
    source = server.upload_dir / "Report #1?.bin"
    source.write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            "/uploads/Report%20%231%3F.bin?download_name=Quarterly%20Report"
            "&download_ext=pdf&preset=card_manual&locale=ru&show_notice=0",
        )
    )

    assert response.status_code == 200
    body = json.loads(response.body)
    assert set(body) == {"artifact", "source", "download", "builder"}
    assert body["source"] == {
        "name": "Report #1?.bin",
        "path": "/uploads/Report #1?.bin",
        "size_bytes": 7,
    }
    assert body["download"] == {
        "name": "Quarterly-Report.pdf",
        "name_applied": True,
        "mime_type": "application/octet-stream",
    }
    assert body["builder"] == {
        "schema_version": 1,
        "mode": "simple",
        "preset": "card_manual",
        "locale": "ru",
        "encryption": "none",
        "payload_encoding": "base64",
        "output_format": "html",
        "trigger_method": "svg",
        "trigger_event": "onload",
        "trigger_event_custom": False,
        "download_variant": "blob-anchor",
        "page_template": "default",
        "notice_shown": False,
        "null_byte": False,
    }
    artifact_path = server.upload_dir / body["artifact"]["name"]
    assert body["artifact"] == {
        "url": "/uploads/smuggle_0123abcd4567ef89.html",
        "name": "smuggle_0123abcd4567ef89.html",
        "size_bytes": artifact_path.stat().st_size,
        "content_type": "text/html; charset=utf-8",
        "one_shot": True,
        "expires_at": None,
    }
    assert "X-Smuggle-URL" not in response.headers

    html = artifact_path.read_text(encoding="utf-8")
    assert "Quarterly-Report.pdf" in html
    assert "Internal controlled test page." not in html


def test_smuggle_finite_temp_age_reports_stored_artifact_expiry(temp_dir) -> None:
    server = _server(temp_dir)
    server.smuggle_temp_policy = SmuggleTempPolicy(max_age_seconds=90)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    response = server.handle_smuggle(make_request("SMUGGLE", "/uploads/small.txt"))

    assert response.status_code == 200
    body = json.loads(response.body)
    artifact_path = server.upload_dir / body["artifact"]["name"]
    expected_expiry = datetime.fromtimestamp(
        artifact_path.stat().st_mtime + 90,
        tz=timezone.utc,
    )
    expires_at = datetime.fromisoformat(body["artifact"]["expires_at"])
    assert expires_at == expected_expiry
    assert expires_at.utcoffset() == timezone.utc.utcoffset(expires_at)


def test_smuggle_xor_password_is_only_exposed_under_builder(temp_dir, monkeypatch) -> None:
    server = _server(temp_dir)
    monkeypatch.setattr("xferry.handlers.smuggle.secrets.choice", lambda _alphabet: "A")
    (server.upload_dir / "secret.txt").write_bytes(b"payload")

    response = server.handle_smuggle(make_request("SMUGGLE", "/uploads/secret.txt?encryption=xor"))

    assert response.status_code == 200
    body = json.loads(response.body)
    assert set(body) == {"artifact", "source", "download", "builder"}
    assert body["builder"]["encryption"] == "xor"
    assert body["builder"]["password"] == "AAAAAAA"
    assert "password" not in {key for key in body if key != "builder"}
    assert "encrypted" not in body


def test_smuggle_simple_locale_ru_localizes_safe_builder_copy(temp_dir) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            "/uploads/small.txt?preset=card_manual&locale=ru&show_notice=1",
        )
    )

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["builder"]["locale"] == "ru"
    assert body["builder"]["mode"] == "simple"

    html = (server.upload_dir / body["artifact"]["name"]).read_text(encoding="utf-8")
    assert '<html lang="ru">' in html
    assert "Тестовый артефакт готов" in html
    assert "Внутренняя контролируемая тестовая страница." in html
    assert "Имя файла:" in html
    assert "Internal controlled test page." not in html
    assert "Download name:" not in html


def test_smuggle_constructor_applies_copy_notice_and_canonical_trigger(temp_dir) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "source.bin").write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            "/uploads/source.bin?mode=constructor&page_template=npf-zip-archive-help"
            "&title=Archive%20Instructions&message=Use%20the%20downloaded%20archive."
            "&download_name=Archive%20Instructions&download_ext=zip"
            "&trigger_method=body&trigger_event=onpageshow&locale=en&show_notice=1"
            "&download_variant=loc-assign&mime_type=application%2Fpdf",
        )
    )

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["builder"]["mode"] == "constructor"
    assert body["builder"]["preset"] == "direct"
    assert body["builder"]["page_template"] == "npf-zip-archive-help"
    assert body["builder"]["trigger_method"] == "body"
    assert body["builder"]["trigger_event"] == "onpageshow"
    assert body["builder"]["notice_shown"] is True
    assert body["builder"]["locale"] == "en"
    assert body["download"]["mime_type"] == "application/pdf"
    assert body["download"]["name_applied"] is False

    html = (server.upload_dir / body["artifact"]["name"]).read_text(encoding="utf-8")
    javascript_text = unescape(html)
    assert '<html lang="en">' in html
    assert "Archive Instructions" in html
    assert "Use the downloaded archive." in html
    assert "Internal controlled test artifact." in html
    assert "Check that the ZIP archive downloaded as" in html
    assert "Open the downloads folder and extract the archive." in html
    assert "RAR" not in html
    assert "Откройте папку загрузок" not in html
    assert "Распакуйте архив" not in html
    assert "window.location.assign('data:'+mt+';base64,'" in javascript_text
    assert "l.download=" not in javascript_text


@pytest.mark.parametrize(
    ("query_extension", "expected_extension"),
    [
        ("exe", "exe"),
        ("%2EDOCX", "docx"),
        ("7z", "7z"),
        ("tar.gz", "tar.gz"),
        ("acme%2Bpkg", "acme+pkg"),
    ],
)
def test_smuggle_accepts_safe_suggested_and_custom_extensions(
    temp_dir,
    query_extension: str,
    expected_extension: str,
) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            "/uploads/small.txt?download_name=Artifact"
            f"&download_ext={query_extension}&preset=card_manual",
        )
    )

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["download"]["name"] == f"Artifact.{expected_extension}"


@pytest.mark.parametrize(
    "query_extension",
    [
        "..%2Fexe",
        "tar..gz",
        "bad%2Fext",
        "bad%5Cext",
        "bad%20ext",
        "-leading",
        "tar.-gz",
        "x" * 33,
    ],
)
def test_smuggle_bad_extension_error_has_stable_code_and_field(
    temp_dir,
    query_extension: str,
) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            f"/uploads/small.txt?download_ext={query_extension}&preset=card_manual",
        )
    )

    assert response.status_code == 400
    body = json.loads(response.body)
    assert body == {
        "error": {
            "code": "invalid_smuggle_extension",
            "message": "Invalid SMUGGLE builder extension",
            "field": "download_ext",
            "details": {},
        }
    }


def test_smuggle_preserves_custom_mime_type_with_special_characters(temp_dir) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "small.txt").write_bytes(b"payload")
    mime_type = "Application/X-XFerry; charset=\"UTF-8\"; note='A<&>\u03a9\\tail'"

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            "/uploads/small.txt?mode=constructor&page_template=minimal"
            f"&mime_type={quote(mime_type, safe='')}",
        )
    )

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["builder"]["mode"] == "constructor"
    assert body["download"]["mime_type"] == mime_type

    html = (server.upload_dir / body["artifact"]["name"]).read_text(encoding="utf-8")
    javascript_text = unescape(html)
    assert mime_type not in javascript_text
    assert "\\u0022" in javascript_text.lower()
    assert "\\u0027" in javascript_text.lower()
    assert "\\u003c" in javascript_text.lower()
    assert "\\u003e" in javascript_text.lower()
    assert "\\u0026" in javascript_text.lower()
    assert "\\u03a9" in javascript_text.lower()


def test_smuggle_custom_trigger_event_reports_effective_listener(temp_dir) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            "/uploads/small.txt?mode=constructor&trigger_method=button&trigger_event=onauxclick",
        )
    )

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["builder"]["trigger_method"] == "button"
    assert body["builder"]["trigger_event"] == "onauxclick"
    assert body["builder"]["trigger_event_custom"] is True

    html = (server.upload_dir / body["artifact"]["name"]).read_text(encoding="utf-8")
    assert 'addEventListener("auxclick"' in html
    assert "dispatchEvent" not in html


def test_smuggle_rejects_removed_use_constructor_parameter(
    temp_dir,
) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    response = server.handle_smuggle(
        make_request(
            "SMUGGLE",
            "/uploads/small.txt?use_constructor=0",
        )
    )

    assert response.status_code == 400
    body = json.loads(response.body)
    assert body == {
        "error": {
            "code": "unknown_smuggle_parameter",
            "message": "Unknown SMUGGLE parameter: use_constructor",
            "field": "use_constructor",
            "details": {},
        }
    }


def test_smuggle_not_found_and_too_large_errors_have_stable_codes(temp_dir) -> None:
    server = _server(temp_dir)

    missing = server.handle_smuggle(make_request("SMUGGLE", "/uploads/missing.bin"))
    missing_body = json.loads(missing.body)
    assert missing.status_code == 404
    assert missing_body == {
        "error": {
            "code": "smuggle_source_not_found",
            "message": "File not found",
            "field": "path",
            "details": {
                "scope": "uploads",
                "resource": "upload",
                "path": "/uploads/missing.bin",
            },
        }
    }

    server.smuggle_source_size_limit = 4
    (server.upload_dir / "large.bin").write_bytes(b"12345")
    too_large = server.handle_smuggle(make_request("SMUGGLE", "/uploads/large.bin"))
    too_large_body = json.loads(too_large.body)
    assert too_large.status_code == 413
    assert too_large_body == {
        "error": {
            "code": "smuggle_source_too_large",
            "message": "SMUGGLE source too large. Max size: 4.0 B",
            "field": "source",
            "details": {
                "scope": "uploads",
                "resource": "upload",
                "actual_bytes": 5,
                "limit_bytes": 4,
            },
        }
    }


def test_smuggle_quota_failure_has_stable_code_and_leaves_no_artifact(temp_dir) -> None:
    server = _server(temp_dir)
    server.smuggle_temp_policy = SmuggleTempPolicy(max_total_bytes=1)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    response = server.handle_smuggle(make_request("SMUGGLE", "/uploads/small.txt"))

    assert response.status_code == 507
    body = json.loads(response.body)
    assert set(body) == {"error"}
    assert body["error"]["code"] == "smuggle_temp_quota_exceeded"
    assert body["error"]["field"] == "smuggle_temp"
    assert "SMUGGLE temp storage quota exceeded" in body["error"]["message"]
    assert isinstance(body["error"]["details"], dict)
    assert "X-Smuggle-URL" not in response.headers
    assert server.handler_context.smuggle_temp.snapshot() == frozenset()
    assert list(server.upload_dir.glob("smuggle_*.html")) == []


def test_smuggle_unexpected_artifact_write_failure_is_bounded_internal_error(
    temp_dir,
    monkeypatch,
) -> None:
    server = _server(temp_dir)
    (server.upload_dir / "small.txt").write_bytes(b"payload")

    def fail_write(_content: bytes, _extension: str):
        raise OSError("secret operating-system path")

    monkeypatch.setattr(server, "_write_smuggle_temp_artifact", fail_write)

    response = server.handle_smuggle(make_request("SMUGGLE", "/uploads/small.txt"))

    assert response.status_code == 500
    assert json.loads(response.body) == {
        "error": {
            "code": "internal_error",
            "message": "Failed to create SMUGGLE artifact",
            "field": None,
            "details": {},
        }
    }
    assert b"secret operating-system path" not in response.body
