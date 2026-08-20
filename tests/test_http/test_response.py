"""Tests for HTTP response building."""

import json
from pathlib import Path
from types import MappingProxyType

import pytest

import xferry.http as http
import xferry.http.response as response_module
from xferry.http.response import HTTPResponse


class TestJSONAndErrorResponseFactories:
    """Contract tests for canonical JSON and error responses."""

    def test_error_response_emits_canonical_envelope_with_empty_details(self):
        response = response_module.error_response(
            404,
            "resource_not_found",
            "File not found",
        )

        assert response.status_code == 404
        assert response.headers["Content-Type"] == "application/json"
        assert json.loads(response.body) == {
            "error": {
                "code": "resource_not_found",
                "message": "File not found",
                "field": None,
                "details": {},
            }
        }

    def test_error_response_copies_explicit_field_and_details(self):
        source = {"path": "/uploads/missing.txt", "resource": "upload"}
        response = http.error_response(
            404,
            "resource_not_found",
            "Upload not found",
            field="path",
            details=MappingProxyType(source),
        )

        source["path"] = "/uploads/replaced.txt"

        assert json.loads(response.body) == {
            "error": {
                "code": "resource_not_found",
                "message": "Upload not found",
                "field": "path",
                "details": {
                    "path": "/uploads/missing.txt",
                    "resource": "upload",
                },
            }
        }

    def test_json_response_can_mark_payload_as_no_store(self):
        response = http.json_response({"health": "ready"}, status=202, no_store=True)

        assert response.status_code == 202
        assert response.headers["Content-Type"] == "application/json"
        assert response.headers["Cache-Control"] == "no-store"
        assert json.loads(response.body) == {"health": "ready"}

    def test_error_response_can_mark_canonical_errors_as_no_store(self):
        """Catches control-plane errors losing the shared no-store rendering seam."""
        response = http.error_response(
            403,
            "forbidden_origin",
            "Forbidden origin",
            field="Origin",
            no_store=True,
        )

        assert response.status_code == 403
        assert response.headers["Content-Type"] == "application/json"
        assert response.headers["Cache-Control"] == "no-store"
        assert json.loads(response.body) == {
            "error": {
                "code": "forbidden_origin",
                "message": "Forbidden origin",
                "field": "Origin",
                "details": {},
            }
        }

    @pytest.mark.parametrize(
        ("code", "expected_exception"),
        [
            ("", ValueError),
            ("Bad_Request", ValueError),
            ("bad-request", ValueError),
            ("bad__request", ValueError),
            (7, TypeError),
        ],
    )
    def test_error_response_rejects_invalid_codes(self, code, expected_exception):
        with pytest.raises(expected_exception):
            response_module.error_response(400, code, "Bad request")

    @pytest.mark.parametrize(
        ("message", "expected_exception"),
        [("", ValueError), (None, TypeError), (7, TypeError)],
    )
    def test_error_response_rejects_invalid_messages(self, message, expected_exception):
        with pytest.raises(expected_exception):
            response_module.error_response(400, "bad_request", message)

    def test_error_response_rejects_non_string_field(self):
        with pytest.raises(TypeError):
            response_module.error_response(400, "bad_request", "Bad request", field=7)

    def test_error_response_rejects_non_mapping_details(self):
        with pytest.raises(TypeError):
            response_module.error_response(400, "bad_request", "Bad request", details=[])


class TestHTTPResponse:
    """Tests for HTTPResponse class."""

    def test_default_status_code(self):
        """Test default status code is 200."""
        response = HTTPResponse()
        assert response.status_code == 200

    def test_custom_status_code(self):
        """Test setting custom status code."""
        response = HTTPResponse(404)
        assert response.status_code == 404

    def test_set_header(self):
        """Test setting headers."""
        response = HTTPResponse()
        response.set_header("X-Custom", "value")

        assert response.headers["X-Custom"] == "value"

    def test_set_body_string(self):
        """Test setting body as string."""
        response = HTTPResponse()
        response.set_body("Hello, World!", "text/plain")

        assert response.body == b"Hello, World!"
        assert response.headers["Content-Type"] == "text/plain"
        assert response.headers["Content-Length"] == "13"

    def test_set_body_bytes(self):
        """Test setting body as bytes."""
        response = HTTPResponse()
        response.set_body(b"\x00\x01\x02", "application/octet-stream")

        assert response.body == b"\x00\x01\x02"
        assert response.headers["Content-Length"] == "3"

    def test_build_response(self):
        """Test building complete HTTP response."""
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build()

        assert built.startswith(b"HTTP/1.1 200 OK\r\n")
        assert b"Content-Type: text/plain\r\n" in built
        assert b"Content-Length: 2\r\n" in built
        assert built.endswith(b"\r\n\r\nOK")

    def test_build_sets_server_header(self):
        """Test building response sets the server header."""
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build()

        assert b"Server: XFerry/0.1.0\r\n" in built

    def test_build_sets_nosniff_header(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build()

        assert b"X-Content-Type-Options: nosniff\r\n" in built

    def test_cors_headers_disabled_by_default(self):
        """CORS should be opt-in."""
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build()

        assert b"Access-Control-Allow-Origin:" not in built

    def test_cors_headers_when_enabled(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(cors_origin="https://app.example")

        assert b"Access-Control-Allow-Origin: https://app.example\r\n" in built
        assert b"Vary: Origin\r\n" in built

    def test_cors_multi_origin_config_is_not_emitted_as_single_header(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(cors_origin="https://app.example, https://admin.example")

        assert b"Access-Control-Allow-Origin:" not in built

    def test_cors_headers_expose_actual_custom_response_headers(self):
        """Catches CORS re-exposing result mirrors after canonical JSON migration."""
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(cors_origin="https://app.example")

        expose_header = next(
            line
            for line in built.split(b"\r\n")
            if line.startswith(b"Access-Control-Expose-Headers:")
        )
        exposed = {
            header.strip() for header in expose_header.split(b":", maxsplit=1)[1].split(b",")
        }
        assert {b"Content-Disposition", b"ETag", b"X-Request-Id"} <= exposed
        assert (
            not {
                b"X-Upload-Status",
                b"X-Fetch-Status",
                b"X-File-Name",
                b"X-File-Size",
                b"X-File-Path",
                b"X-File-Modified",
                b"X-Ping-Response",
                b"X-Smuggle-URL",
            }
            & exposed
        )

    def test_cors_headers_allow_implemented_request_headers(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(cors_origin="https://app.example")

        allow_header = next(
            line
            for line in built.split(b"\r\n")
            if line.startswith(b"Access-Control-Allow-Headers:")
        )
        assert b"Authorization" in allow_header
        assert b"If-None-Match" in allow_header
        assert b"X-Request-Id" in allow_header
        assert b"X-XFerry-No-Gzip" in allow_header
        assert b"X-Exphttp-No-Gzip" in allow_header
        assert b"X-Session-Id" not in allow_header

    def test_exact_origin_cors_advertises_canonical_advanced_headers(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(cors_origin="https://app.example")

        allow_header = next(
            line
            for line in built.split(b"\r\n")
            if line.startswith(b"Access-Control-Allow-Headers:")
        )
        assert b"X-XFerry-Advanced-Session" in allow_header
        assert b"X-XFerry-Data-255" in allow_header
        assert b"X-XFerry-Method-Override" in allow_header
        for legacy in (
            b"X-D",
            b"X-E",
            b"X-K",
            b"X-Kb64",
            b"X-N",
            b"X-H",
            b"X-Encoding",
            b"X-HTTP-Method-Override",
            b"X-Payload-In-Path",
        ):
            assert legacy not in allow_header.split(b":", maxsplit=1)[1].split(b", ")

    def test_wildcard_cors_never_advertises_advanced_headers(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(cors_origin="*")

        allow_header = next(
            line
            for line in built.split(b"\r\n")
            if line.startswith(b"Access-Control-Allow-Headers:")
        )
        assert b"Authorization" in allow_header
        assert b"Content-Type" in allow_header
        assert b"X-XFerry-Advanced-Session" not in allow_header
        assert b"X-XFerry-Data" not in allow_header
        assert b"X-XFerry-Encryption" not in allow_header

    def test_cors_headers_include_smuggle_method(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(cors_origin="https://app.example")

        methods_header = next(
            line
            for line in built.split(b"\r\n")
            if line.startswith(b"Access-Control-Allow-Methods:")
        )
        assert b"SMUGGLE" in methods_header

    def test_cors_vary_origin_appends_existing_vary(self):
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        response.set_header("Vary", "Accept-Encoding")
        built = response.build(cors_origin="https://app.example")

        assert b"Vary: Accept-Encoding, Origin\r\n" in built

    def test_set_file_streaming(self, tmp_path: Path):
        """Test set_file sets stream_path and correct headers."""
        f = tmp_path / "data.bin"
        f.write_bytes(b"A" * 256)
        response = HTTPResponse(200)
        response.set_file(f, "application/octet-stream")

        assert response.stream_path == f
        assert response.body == b""  # body stays empty
        assert response.headers["Content-Length"] == "256"
        assert response.headers["Content-Type"] == "application/octet-stream"

    def test_build_headers_only(self):
        """Test build_headers returns header bytes without body."""
        response = HTTPResponse(200)
        response.set_body("hello", "text/plain")
        headers = response.build_headers()

        assert headers.startswith(b"HTTP/1.1 200 OK\r\n")
        assert headers.endswith(b"\r\n")
        assert b"hello" not in headers  # body excluded

    def test_connection_close_by_default(self):
        """Test that Connection: close is set by default."""
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build()
        assert b"Connection: close\r\n" in built

    def test_keep_alive_headers(self):
        """Test keep-alive Connection and Keep-Alive headers."""
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(keep_alive=True, keep_alive_timeout=10, keep_alive_max=50)
        assert b"Connection: keep-alive\r\n" in built
        assert b"Keep-Alive: timeout=10, max=50\r\n" in built

    def test_keep_alive_false_no_keepalive_header(self):
        """Test that Keep-Alive header is absent when keep_alive=False."""
        response = HTTPResponse(200)
        response.set_body("OK", "text/plain")
        built = response.build(keep_alive=False)
        assert b"Connection: close\r\n" in built
        assert b"Keep-Alive:" not in built

    def test_repr(self):
        """Test string representation."""
        response = HTTPResponse(404)
        assert "404" in repr(response)
