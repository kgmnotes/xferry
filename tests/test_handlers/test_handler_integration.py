"""Integration tests for handler mixins (B27).

Tests use a concrete handler class that composes all mixins,
exercising handlers in-process without network I/O.
"""

import base64
import errno
import gzip
import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, quote_from_bytes, urlencode

import pytest

from tests.conftest import make_request
from xferry.advanced_sessions import (
    AdvancedSession,
    AdvancedSessionDispatch,
    AdvancedSessionPrincipal,
)
from xferry.handlers import HandlerMixin
from xferry.http import HTTPRequest
from xferry.security.crypto import aes_encrypt, compute_hmac, xor_bytes, xor_encrypt


def _parse_csp(header: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for directive in header.split(";"):
        tokens = directive.strip().split()
        if tokens:
            directives[tokens[0]] = tokens[1:]
    return directives


def _json_transport(value):
    """Return the value after JSON response serialization."""
    return json.loads(json.dumps(value))


class StubServer(HandlerMixin):
    """Minimal concrete class combining all handler mixins for testing."""

    def __init__(self, root_dir: Path, upload_dir: Path, **kwargs):
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.cors_origin = kwargs.get("cors_origin")
        self.sandbox_mode = kwargs.get("sandbox", False)
        self.opsec_mode = kwargs.get("opsec", False)
        self.method_handlers = self.build_method_handlers()
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()
        self._ecdh_manager = None

    def get_metrics(self):
        return {
            "uptime_seconds": 42.0,
            "requests": {
                "total": 10,
                "client_errors": 0,
                "server_errors": 1,
                "status_counts": {200: 9, 500: 1},
                "latency_ms": {
                    "count": 10,
                    "total": 125.0,
                    "avg": 12.5,
                    "max": 50.0,
                },
            },
            "connections": {"active": 1, "accepted": 3, "closed": 2},
            "request_admission": {"active": 1, "accepted": 3, "rejected": 1},
            "receive": {
                "bytes": 900,
                "rejections": 1,
                "rejection_reasons": {"header_too_large": 1},
            },
            "response": {
                "bytes": 5000,
                "stream_aborts": 0,
                "stream_abort_reasons": {},
            },
            "timeouts": {"websocket_incomplete_frame": 1},
            "websocket": {
                "active": 0,
                "rejected_admissions": 1,
                "closed": 2,
                "protocol_errors": 0,
                "message_too_big": 0,
                "incomplete_frame_timeouts": 1,
                "idle_pings": 4,
                "errors": 0,
            },
            "worker": {
                "exceptions": 1,
                "exception_sources": {"handle_client": 1},
                "last_exception_type": "RuntimeError",
            },
            "storage": {
                "usage": {
                    "notes": {"bytes": 0, "items": 0},
                    "smuggle_temp": {"bytes": 0, "items": 0},
                    "uploads": {"bytes": 0, "items": 0},
                },
                "quota_denials": {},
                "scans": {},
            },
            "advanced_upload": {"decode_rejections": {}},
        }


@pytest.fixture
def server(temp_dir, upload_dir):
    # Create a minimal index.html so GET / works
    (temp_dir / "index.html").write_text("<html>hello</html>")
    return StubServer(temp_dir, upload_dir)


@pytest.fixture
def sandbox_server(temp_dir, upload_dir):
    (temp_dir / "index.html").write_text("<html>hello</html>")
    return StubServer(temp_dir, upload_dir, sandbox=True)


# ── GET tests ──────────────────────────────────────────────────────


class TestHandleGet:
    def test_get_index(self, server):
        req = make_request("GET", "/")
        resp = server.handle_get(req)
        assert resp.status_code == 200
        # The bundled web UI is served outside uploads so the browser can load.
        content = resp.body or (resp.stream_path.read_bytes() if resp.stream_path else b"")
        assert b"xferry" in content

    def test_get_index_disables_shell_caching_and_versions_local_assets(self, server):
        req = make_request("GET", "/")
        resp = server.handle_get(req)

        assert resp.status_code == 200
        assert resp.stream_path is None
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.headers["Pragma"] == "no-cache"
        assert b"/static/ui/core.js?v=" in resp.body
        assert b"/static/ui/features.css?v=" in resp.body
        assert b"/static/crypto-js.min.js?v=" in resp.body
        assert b'data-theme-dark="/static/ui/xferry-mark.svg?v=' in resp.body
        assert b'data-theme-light="/static/ui/xferry-mark-light.svg?v=' in resp.body

    def test_get_existing_file(self, server, upload_dir):
        (upload_dir / "readme.txt").write_text("content here")
        req = make_request("GET", "/readme.txt")
        resp = server.handle_get(req)
        assert resp.status_code == 200
        # Non-HTML files are streamed
        assert resp.stream_path is not None
        assert resp.stream_path.read_bytes() == b"content here"

    def test_get_missing_file(self, server):
        req = make_request("GET", "/no_such_file.xyz")
        resp = server.handle_get(req)
        assert resp.status_code == 404

    def test_get_hidden_file(self, server, temp_dir):
        (temp_dir / ".env").write_text("SECRET=x")
        req = make_request("GET", "/.env")
        resp = server.handle_get(req)
        assert resp.status_code == 404

    def test_get_hidden_upload_file(self, server, upload_dir):
        (upload_dir / ".secret").write_text("SECRET=x")
        req = make_request("GET", "/uploads/.secret")
        resp = server.handle_get(req)
        assert resp.status_code == 404

    def test_get_uploaded_html_forces_download(self, server, upload_dir):
        (upload_dir / "evil.html").write_text("<script>alert(1)</script>")
        req = make_request("GET", "/uploads/evil.html")
        resp = server.handle_get(req)

        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/octet-stream"
        assert resp.headers["Content-Disposition"] == 'attachment; filename="evil.html"'
        assert "Content-Security-Policy" not in resp.headers

    def test_get_smuggle_shtm_uses_browser_runnable_type_and_artifact_csp(
        self,
        server,
        upload_dir,
    ):
        artifact = upload_dir / "smuggle_0123456789abcdef.shtm"
        artifact.write_text("<!DOCTYPE html><script>window.ok=true</script>", encoding="utf-8")
        server._temp_smuggle_files.add(str(artifact))

        req = make_request("GET", f"/uploads/{artifact.name}")
        resp = server.handle_get(req)

        assert resp.status_code == 200
        assert resp.stream_path == artifact
        assert resp.headers["Content-Type"] == "text/html; charset=utf-8"
        directives = _parse_csp(resp.headers["Content-Security-Policy"])
        assert directives["default-src"] == ["'none'"]
        assert directives["script-src"] == ["'self'", "'unsafe-inline'"]
        assert directives["style-src"] == ["'unsafe-inline'", "data:"]
        assert directives["connect-src"] == ["blob:"]
        assert directives["base-uri"] == ["'none'"]

    def test_get_index_csp_blocks_inline_script_and_documents_style_allowance(self, server):
        req = make_request("GET", "/")
        resp = server.handle_get(req)

        csp = resp.headers["Content-Security-Policy"]
        directives = _parse_csp(csp)

        assert directives["default-src"] == ["'self'"]
        assert directives["script-src"] == ["'self'"]
        assert directives["style-src"] == ["'self'", "'unsafe-inline'"]
        assert directives["img-src"] == ["'self'", "data:"]
        assert directives["connect-src"] == ["'self'", "ws:", "wss:"]
        assert directives["base-uri"] == ["'self'"]
        assert directives["object-src"] == ["'none'"]
        assert directives["frame-ancestors"] == ["'none'"]
        assert directives["form-action"] == ["'self'"]
        assert "'unsafe-inline'" not in directives["script-src"]

    def test_get_static_ui_script_does_not_emit_html_csp(self, server):
        req = make_request("GET", "/static/ui/app.js")
        resp = server.handle_get(req)

        assert resp.status_code == 200
        assert resp.stream_path is not None
        assert "Content-Security-Policy" not in resp.headers

    def test_get_upload_in_sandbox(self, sandbox_server, upload_dir):
        (upload_dir / "data.bin").write_bytes(b"\xde\xad")
        req = make_request("GET", "/uploads/data.bin")
        resp = sandbox_server.handle_get(req)
        assert resp.status_code == 200
        assert resp.stream_path is not None
        assert resp.stream_path.read_bytes() == b"\xde\xad"

    def test_get_directory_serves_index(self, server, upload_dir):
        sub = upload_dir / "sub"
        sub.mkdir()
        (sub / "index.html").write_text("<p>sub</p>")
        req = make_request("GET", "/sub")
        resp = server.handle_get(req)
        assert resp.status_code == 200


# ── NONE (upload) tests ────────────────────────────────────────────


class TestHandleNone:
    def test_upload_file(self, server, upload_dir):
        body = b"file content 123"
        req = make_request(
            "NONE",
            "/",
            headers={"X-File-Name": "test.txt"},
            body=body,
        )
        resp = server.handle_none(req)
        assert resp.status_code == 201
        data = json.loads(resp.body)
        assert set(data) == {"file", "upload"}
        assert data["file"]["size_bytes"] == len(body)
        assert data["upload"]["kind"] == "basic"
        # File should exist on disk
        uploaded = upload_dir / data["file"]["name"]
        assert uploaded.exists()
        assert uploaded.read_bytes() == body

    def test_upload_empty_body(self, server):
        req = make_request("NONE", "/", headers={"X-File-Name": "empty.txt"})
        resp = server.handle_none(req)
        assert resp.status_code == 400

    def test_upload_generates_safe_filename(self, server, upload_dir):
        req = make_request(
            "NONE",
            "/",
            headers={"X-File-Name": "../../evil.sh"},
            body=b"pwned",
        )
        resp = server.handle_none(req)
        assert resp.status_code == 201
        data = json.loads(resp.body)
        # Filename should be sanitized, with no path separators.
        assert "/" not in data["file"]["name"]
        assert ".." not in data["file"]["name"]

    def test_upload_unique_name_on_collision(self, server, upload_dir):
        (upload_dir / "dup.txt").write_text("old")
        req = make_request(
            "NONE",
            "/",
            headers={"X-File-Name": "dup.txt"},
            body=b"new",
        )
        resp = server.handle_none(req)
        assert resp.status_code == 201
        data = json.loads(resp.body)
        assert data["file"]["name"] != "dup.txt"  # should get a unique suffix
        assert data["upload"]["collision_renamed"] is True


# ── POST tests (delegates to NONE) ────────────────────────────────


class TestHandlePost:
    def test_post_uploads_like_none(self, server, upload_dir):
        req = make_request(
            "POST",
            "/",
            headers={"X-File-Name": "post_file.bin"},
            body=b"post data",
        )
        resp = server.handle_post(req)
        assert resp.status_code == 201


# ── FETCH tests ────────────────────────────────────────────────────


class TestHandleFetch:
    def test_fetch_existing_file_streams_without_legacy_mirror_headers(self, server, upload_dir):
        (upload_dir / "dl.zip").write_bytes(b"PK\x03\x04")
        req = make_request("FETCH", "/uploads/dl.zip")
        resp = server.handle_fetch(req)
        assert resp.status_code == 200
        assert resp.stream_path is not None
        assert b"PK" in resp.stream_path.read_bytes()
        assert resp.headers["Content-Disposition"] == (
            "attachment; filename=\"dl.zip\"; filename*=UTF-8''dl.zip"
        )
        assert "X-Fetch-Status" not in resp.headers
        assert "X-File-Name" not in resp.headers
        assert "X-File-Size" not in resp.headers
        assert "X-File-Modified" not in resp.headers

    def test_fetch_uses_rfc5987_filename_for_non_ascii_upload(self, server, upload_dir):
        filename = "кириллица #1.bin"
        (upload_dir / filename).write_bytes(b"payload")

        resp = server.handle_fetch(make_request("FETCH", f"/uploads/{quote(filename)}"))

        assert resp.headers["Content-Disposition"] == (
            'attachment; filename="download.bin"; '
            "filename*=UTF-8''%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0%20%231.bin"
        )

    def test_fetch_content_disposition_rejects_header_injection_characters(self, server):
        disposition = server._build_download_content_disposition('report"\r\nX-Injected: yes.bin')
        header_filename = server._safe_download_filename('folder\\report"\r\nX-Injected: yes.bin')

        assert "\r" not in disposition
        assert "\n" not in disposition
        assert '"X-Injected' not in disposition
        assert "\\" not in header_filename
        assert '"' not in header_filename
        assert "\r" not in header_filename
        assert "\n" not in header_filename
        assert disposition.startswith('attachment; filename="report-X-Injected-yes.bin"; ')

    def test_fetch_cors_exposes_content_disposition(self, server, upload_dir):
        (upload_dir / "dl.bin").write_bytes(b"payload")
        resp = server.handle_fetch(make_request("FETCH", "/uploads/dl.bin"))

        header_lines = (
            resp.build(cors_origin="https://browser.example").decode("utf-8").split("\r\n")
        )
        expose_header = next(
            line
            for line in header_lines
            if line.lower().startswith("access-control-expose-headers:")
        )

        assert "Content-Disposition" in expose_header

    def test_fetch_missing_file(self, server):
        req = make_request("FETCH", "/uploads/ghost.txt")
        resp = server.handle_fetch(req)

        assert resp.status_code == 404
        assert resp.headers["Content-Type"] == "application/json"
        assert "X-Fetch-Status" not in resp.headers
        assert json.loads(resp.body) == {
            "error": {
                "code": "resource_not_found",
                "message": "Upload resource not found",
                "field": "path",
                "details": {
                    "scope": "uploads",
                    "resource": "upload",
                    "path": "/uploads/ghost.txt",
                },
            }
        }

    @pytest.mark.parametrize("target", ["/uploads/folder", "/uploads/.secret"])
    def test_fetch_non_file_resources_return_canonical_not_found(self, server, upload_dir, target):
        (upload_dir / "folder").mkdir()
        (upload_dir / ".secret").write_text("SECRET=x")

        resp = server.handle_fetch(make_request("FETCH", target))

        assert resp.status_code == 404
        data = json.loads(resp.body)
        assert data["error"]["code"] == "resource_not_found"
        assert data["error"]["field"] == "path"
        assert data["error"]["details"]["scope"] == "uploads"
        assert data["error"]["details"]["resource"] == "upload"
        assert data["error"]["details"]["path"] == target
        assert "Cannot fetch" not in resp.body.decode("utf-8")
        assert "X-Fetch-Status" not in resp.headers

    def test_fetch_traversal_returns_canonical_invalid_path(self, server):
        resp = server.handle_fetch(make_request("FETCH", "/../../etc/passwd"))

        assert resp.status_code == 400
        assert json.loads(resp.body) == {
            "error": {
                "code": "invalid_path",
                "message": "Invalid upload path",
                "field": "path",
                "details": {"scope": "uploads", "path": "/../../etc/passwd"},
            }
        }


# ── INFO tests ─────────────────────────────────────────────────────


class TestHandleInfo:
    def test_info_file_returns_exact_entry_contract_with_default_null_inspection(
        self,
        server,
        upload_dir,
    ):
        (upload_dir / "info_target.txt").write_text("data")
        req = make_request("INFO", "/info_target.txt")
        resp = server.handle_info(req)

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert set(data) == {"entry"}
        entry = data["entry"]
        assert set(entry) == {
            "exists",
            "path",
            "name",
            "kind",
            "size_bytes",
            "size_human",
            "content_type",
            "created_at",
            "modified_at",
            "extension",
            "access_scope",
            "inspection",
        }
        assert entry["exists"] is True
        assert entry["path"] == "/uploads/info_target.txt"
        assert entry["name"] == "info_target.txt"
        assert entry["kind"] == "file"
        assert entry["size_bytes"] == 4
        assert entry["size_human"] == "4.0 B"
        assert entry["content_type"] == "text/plain"
        assert datetime.fromisoformat(entry["created_at"]).tzinfo is not None
        assert datetime.fromisoformat(entry["modified_at"]).tzinfo is not None
        assert entry["extension"] == ".txt"
        assert entry["access_scope"] == "uploads"
        assert entry["inspection"] is None

    def test_info_inspection_is_opt_in_for_an_individual_file(self, server, upload_dir):
        (upload_dir / "report.pdf").write_bytes(b"%PDF-1.7\n")

        default = json.loads(server.handle_info(make_request("INFO", "/report.pdf")).body)
        inspected = json.loads(
            server.handle_info(make_request("INFO", "/report.pdf?inspect=true")).body
        )

        assert default["entry"]["inspection"] is None
        assert inspected["entry"]["inspection"] == {
            "mime_type": "application/pdf",
            "mime_source": "signature",
            "content_state": "recognized",
            "warning": None,
            "reasons": [],
        }

    def test_info_inspect_false_keeps_null_inspection_without_inspector_calls(
        self,
        server,
        upload_dir,
        monkeypatch,
    ):
        (upload_dir / "default.txt").write_text("default payload", encoding="utf-8")
        inspector_calls = 0

        def unexpected_inspection(_path):
            nonlocal inspector_calls
            inspector_calls += 1
            pytest.fail("inspect=false INFO must not invoke content inspection")

        monkeypatch.setattr("xferry.handlers.info.inspect_file", unexpected_inspection)

        response = server.handle_info(make_request("INFO", "/default.txt?inspect=false"))
        data = json.loads(response.body)

        assert response.status_code == 200
        assert data["entry"]["inspection"] is None
        assert inspector_calls == 0

    def test_info_inspects_only_files_in_the_paginated_directory_slice(self, server, upload_dir):
        directory = upload_dir / "paged-inspection"
        directory.mkdir()
        (directory / "00-folder").mkdir()
        (directory / "01-report.pdf").write_bytes(b"%PDF-1.7\n")
        (directory / "02-later.bin").write_bytes(b"x" * 256)

        response = server.handle_info(
            make_request("INFO", "/paged-inspection?offset=0&limit=2&inspect=true")
        )
        data = json.loads(response.body)

        assert [item["name"] for item in data["contents"]] == ["00-folder", "01-report.pdf"]
        assert data["contents"][0] == {
            "name": "00-folder",
            "kind": "directory",
            "inspection": None,
        }
        assert data["contents"][1]["inspection"]["mime_type"] == "application/pdf"
        assert data["entry"]["inspection"] is None

    def test_info_missing_file(self, server):
        req = make_request("INFO", "/nonexistent")
        resp = server.handle_info(req)

        assert resp.status_code == 404
        assert json.loads(resp.body) == {
            "error": {
                "code": "resource_not_found",
                "message": "Upload resource not found",
                "field": "path",
                "details": {
                    "scope": "uploads",
                    "resource": "upload",
                    "path": "/uploads/nonexistent",
                },
            }
        }

    def test_info_directory_listing_returns_entry_page_and_exact_content_items(
        self,
        server,
        upload_dir,
    ):
        sub = upload_dir / "mydir"
        sub.mkdir()
        (sub / "a.txt").write_text("a")
        (sub / "b.txt").write_text("b")
        req = make_request("INFO", "/mydir")
        resp = server.handle_info(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert set(data) == {"entry", "page", "contents"}
        assert data["entry"]["path"] == "/uploads/mydir"
        assert data["entry"]["kind"] == "directory"
        assert data["entry"]["inspection"] is None
        assert data["page"] == {
            "offset": 0,
            "limit": 100,
            "total_items": 2,
            "returned_items": 2,
        }
        assert data["contents"] == [
            {"name": "a.txt", "kind": "file", "inspection": None},
            {"name": "b.txt", "kind": "file", "inspection": None},
        ]

    def test_info_directory_listing_hides_hidden_and_service_owned_entries(
        self,
        server,
        upload_dir,
    ):
        (upload_dir / ".secret").write_text("secret")
        (upload_dir / "__pycache__").mkdir()
        (upload_dir / "visible.txt").write_text("visible")

        req = make_request("INFO", "/uploads")
        resp = server.handle_info(req)

        assert resp.status_code == 200
        data = json.loads(resp.body)
        names = [c["name"] for c in data["contents"]]
        assert names == ["visible.txt"]
        assert data["contents"][0] == {
            "name": "visible.txt",
            "kind": "file",
            "inspection": None,
        }

    def test_info_sandbox_restricts_to_uploads(self, sandbox_server, upload_dir):
        (upload_dir / "s.txt").write_text("sandbox")
        req = make_request("INFO", "/uploads/s.txt")
        resp = sandbox_server.handle_info(req)
        assert resp.status_code == 200

    def test_info_hidden_file_returns_404(self, server, temp_dir):
        (temp_dir / ".env").write_text("SECRET=x")
        req = make_request("INFO", "/.env")
        resp = server.handle_info(req)
        assert resp.status_code == 404
        assert json.loads(resp.body)["error"]["code"] == "resource_not_found"

    def test_info_traversal_blocked(self, server):
        req = make_request("INFO", "/../../etc/passwd")
        resp = server.handle_info(req)
        assert resp.status_code == 400
        assert json.loads(resp.body) == {
            "error": {
                "code": "invalid_path",
                "message": "Invalid upload path",
                "field": "path",
                "details": {"scope": "uploads", "path": "/../../etc/passwd"},
            }
        }

    def test_info_directory_pagination(self, server, upload_dir):
        sub = upload_dir / "pagedir"
        sub.mkdir()
        for i in range(5):
            (sub / f"file{i}.txt").write_text(str(i))
        req = make_request("INFO", "/pagedir?offset=2&limit=2")
        resp = server.handle_info(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["page"] == {
            "offset": 2,
            "limit": 2,
            "total_items": 5,
            "returned_items": 2,
        }
        assert len(data["contents"]) == 2
        assert data["contents"] == [
            {"name": "file2.txt", "kind": "file", "inspection": None},
            {"name": "file3.txt", "kind": "file", "inspection": None},
        ]

    @pytest.mark.parametrize(
        ("target", "field"),
        [
            ("/uploads?inspect=tr%75e", "inspect"),
            ("/uploads?inspect=%74rue", "inspect"),
            ("/uploads?inspect=true%", "inspect"),
            ("/uploads?inspect=%", "inspect"),
            ("/uploads?offset=%EF%BC%91", "offset"),
            ("/uploads?offset=1%30", "offset"),
            ("/uploads?limit=%EF%BC%91", "limit"),
            ("/uploads?limit=1%", "limit"),
            ("/uploads?%69nspect=false", "query"),
            ("/uploads?%6fffset=0", "query"),
            ("/uploads?offset%=0", "query"),
        ],
    )
    def test_info_rejects_encoded_or_malformed_control_query_tokens(
        self,
        server,
        upload_dir,
        monkeypatch,
        target,
        field,
    ):
        (upload_dir / "keep.txt").write_text("keep")

        def unexpected_inspection(_path):
            pytest.fail("invalid INFO query must reject before inspection")

        monkeypatch.setattr("xferry.handlers.info.inspect_file", unexpected_inspection)

        resp = server.handle_info(make_request("INFO", target))

        assert resp.status_code == 400
        data = json.loads(resp.body)
        assert data["error"]["code"] == "invalid_field"
        assert data["error"]["field"] == field
        assert data["error"]["details"]["allowed"] == ["inspect", "limit", "offset"]

    @pytest.mark.parametrize("field", ["offset", "limit"])
    def test_info_rejects_overlong_ascii_digit_query_values_canonically(
        self,
        server,
        upload_dir,
        field,
    ):
        (upload_dir / "keep.txt").write_text("keep")
        overlong_digits = "1" * 5000

        resp = server.handle_info(make_request("INFO", f"/uploads?{field}={overlong_digits}"))

        assert resp.status_code == 400
        assert json.loads(resp.body) == {
            "error": {
                "code": "invalid_field",
                "message": "Invalid INFO query field",
                "field": field,
                "details": {"allowed": ["inspect", "limit", "offset"]},
            }
        }

    @pytest.mark.parametrize(
        ("target", "field"),
        [
            ("/uploads?offset=-1", "offset"),
            ("/uploads?offset=", "offset"),
            ("/uploads?offset=abc", "offset"),
            ("/uploads?limit=0", "limit"),
            ("/uploads?limit=1001", "limit"),
            ("/uploads?limit=", "limit"),
            ("/uploads?inspect=1", "inspect"),
            ("/uploads?inspect=", "inspect"),
            ("/uploads?inspect=True", "inspect"),
            ("/uploads?unknown=1", "unknown"),
            ("/uploads?offset=0&offset=1", "offset"),
            ("/uploads?limit=1&limit=2", "limit"),
            ("/uploads?inspect=true&inspect=false", "inspect"),
            ("/uploads?limit=1&", "query"),
            ("/uploads?&limit=1", "query"),
            ("/uploads?&&limit=1", "query"),
        ],
    )
    def test_info_rejects_closed_query_object_ambiguity(self, server, upload_dir, target, field):
        (upload_dir / "keep.txt").write_text("keep")

        resp = server.handle_info(make_request("INFO", target))

        assert resp.status_code == 400
        data = json.loads(resp.body)
        assert data["error"]["code"] == "invalid_field"
        assert data["error"]["field"] == field
        assert data["error"]["details"]["allowed"] == ["inspect", "limit", "offset"]

    def test_info_directory_listing_excludes_symlink_children_without_inspecting_them(
        self,
        server,
        upload_dir,
        monkeypatch,
    ):
        target = upload_dir / "real.txt"
        target.write_text("real", encoding="utf-8")
        symlink = upload_dir / "linked.txt"
        try:
            symlink.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable in this environment: {exc}")
        inspector_calls: list[str] = []

        class FakeInspection:
            def as_dict(self):
                return {
                    "mime_type": "text/plain",
                    "mime_source": "text",
                    "content_state": "recognized",
                    "warning": None,
                    "reasons": [],
                }

        def recording_inspection(path):
            inspector_calls.append(path.name)
            if path == symlink:
                pytest.fail("directory INFO must not inspect symlink children")
            return FakeInspection()

        monkeypatch.setattr("xferry.handlers.info.inspect_file", recording_inspection)

        direct = server.handle_info(make_request("INFO", "/uploads/linked.txt?inspect=true"))
        listed = server.handle_info(make_request("INFO", "/uploads"))
        inspected = server.handle_info(make_request("INFO", "/uploads?inspect=true"))

        assert direct.status_code == 400
        assert json.loads(direct.body)["error"]["code"] == "invalid_path"
        assert listed.status_code == 200
        listed_body = json.loads(listed.body)
        assert listed_body["contents"] == [{"name": "real.txt", "kind": "file", "inspection": None}]
        assert listed_body["page"] == {
            "offset": 0,
            "limit": 100,
            "total_items": 1,
            "returned_items": 1,
        }
        assert inspected.status_code == 200
        inspected_body = json.loads(inspected.body)
        assert [item["name"] for item in inspected_body["contents"]] == ["real.txt"]
        assert inspected_body["contents"][0]["inspection"]["mime_type"] == "text/plain"
        assert inspector_calls == ["real.txt"]


class TestHiddenUploadPolicy:
    @pytest.mark.parametrize(
        ("method", "handler_name"),
        [
            ("GET", "handle_get"),
            ("INFO", "handle_info"),
            ("FETCH", "handle_fetch"),
            ("SMUGGLE", "handle_smuggle"),
            ("DELETE", "handle_delete"),
        ],
    )
    def test_hidden_upload_file_is_not_exposed_by_file_methods(
        self,
        server,
        upload_dir,
        method,
        handler_name,
    ):
        hidden = upload_dir / ".secret"
        hidden.write_text("SECRET=x")

        req = make_request(method, "/uploads/.secret")
        resp = getattr(server, handler_name)(req)

        assert resp.status_code == 404
        assert hidden.exists()
        assert server._temp_smuggle_files == set()
        assert list(upload_dir.glob("smuggle_*.html")) == []

    @pytest.mark.parametrize(
        ("method", "handler_name"),
        [
            ("GET", "handle_get"),
            ("INFO", "handle_info"),
            ("FETCH", "handle_fetch"),
            ("SMUGGLE", "handle_smuggle"),
            ("DELETE", "handle_delete"),
        ],
    )
    def test_visible_upload_file_methods_still_work(
        self,
        server,
        upload_dir,
        method,
        handler_name,
    ):
        visible = upload_dir / "visible.txt"
        visible.write_text("visible")

        req = make_request(method, "/uploads/visible.txt")
        resp = getattr(server, handler_name)(req)

        assert resp.status_code == 200
        if method == "DELETE":
            assert not visible.exists()
        else:
            assert visible.exists()


# ── PING tests ─────────────────────────────────────────────────────


class TestHandlePing:
    def test_ping_returns_ready_health_without_legacy_header(self, server):
        """Catches PING regressing to `status:pong` or X-Ping-Response."""
        req = make_request("PING", "/")
        resp = server.handle_ping(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["health"] == "ready"
        assert "status" not in data
        assert "X-Ping-Response" not in resp.headers
        assert data["server"] == "XFerry/0.1.0"
        assert "version" not in data
        assert "timestamp" in data
        assert data["metrics"] == _json_transport(server.get_metrics())
        capabilities = data["smuggle_capabilities"]
        assert capabilities["source_max_bytes"] == server.smuggle_source_size_limit
        assert capabilities["defaults"]["preset"] == "direct"
        assert {"exe", "docx", "7z", "tar.gz"} <= set(capabilities["extensions"])
        assert capabilities["caps"]["custom_extension"] is True
        assert capabilities["caps"]["custom_mime_type"] is True
        assert capabilities["caps"]["custom_trigger_event"] is True
        assert capabilities["trigger_events"]["body"] == ["onload", "onpageshow"]

    def test_ping_reports_uploads_only_scope_without_capability_map(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir)
        req = make_request("PING", "/")
        resp = srv.handle_ping(req)
        data = json.loads(resp.body)
        assert data["access_scope"] == "uploads"
        assert "advanced_upload" not in data
        assert "profile" not in data
        assert "capabilities" not in data


# ── OPTIONS tests ──────────────────────────────────────────────────


class TestHandleOptions:
    def test_options_returns_204(self, server):
        req = make_request(
            "OPTIONS",
            "/",
            headers={"Access-Control-Request-Method": "FETCH"},
        )
        resp = server.handle_options(req)
        assert resp.status_code == 204
        assert "Access-Control-Allow-Methods" not in resp.headers

    def test_options_with_explicit_cors_origin_includes_custom_methods(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, cors_origin="https://app.example")
        req = make_request(
            "OPTIONS",
            "/",
            headers={"Access-Control-Request-Method": "POST"},
        )
        resp = srv.handle_options(req)
        assert resp.status_code == 204
        allowed = resp.headers.get("Access-Control-Allow-Methods", "")
        assert "FETCH" in allowed

    def test_options_with_explicit_cors_origin_sets_allow_methods(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, cors_origin="https://app.example")
        req = make_request(
            "OPTIONS",
            "/",
            headers={"Access-Control-Request-Method": "NOTE"},
        )
        resp = srv.handle_options(req)
        assert resp.status_code == 204
        allowed = resp.headers.get("Access-Control-Allow-Methods", "")
        assert "NOTE" in allowed


# ── OPSEC upload tests ─────────────────────────────────────────────


def _bind_advanced_session_dispatch(
    request: HTTPRequest,
    *,
    prefix: str = "/advanced",
    decoder: str = "auto",
    diagnostic_headers: bool = False,
) -> HTTPRequest:
    """Bind the landed 7D request-local Advanced dispatch for direct handler tests."""
    now = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
    request.advanced_session_dispatch = AdvancedSessionDispatch(
        session=AdvancedSession(
            prefix=prefix,
            decoder=decoder,
            diagnostic_headers=diagnostic_headers,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_activity_at=now,
        ),
        principal=AdvancedSessionPrincipal("no_auth", None),
        direct_peer=None,
    )
    request.advanced_session_admission_prepared = True
    return request


def _advanced_request(
    *,
    method: str = "POST",
    path: str = "/advanced",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    prefix: str = "/advanced",
    decoder: str = "auto",
) -> HTTPRequest:
    return _bind_advanced_session_dispatch(
        make_request(method, path, headers=headers, body=body),
        prefix=prefix,
        decoder=decoder,
    )


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _encoded_payload(payload: bytes, encoding: str) -> str:
    if encoding == "raw":
        return payload.decode("utf-8")
    if encoding == "base64":
        return _b64(payload)
    if encoding == "base64url":
        return _b64url(payload)
    if encoding == "hex":
        return payload.hex()
    if encoding == "percent":
        return quote_from_bytes(payload, safe="")
    if encoding == "gzip-base64":
        return _b64(gzip.compress(payload))
    if encoding == "gzip-base64url":
        return _b64url(gzip.compress(payload))
    raise AssertionError(f"unsupported test encoding {encoding!r}")


def _canonical_json_payload(
    payload: bytes,
    *,
    name: str = "advanced.bin",
    encoding: str = "base64",
    encryption: str = "none",
    key: str | None = None,
    key_is_base64: bool | None = None,
    hmac_value: str | None = None,
    method_override: str | None = None,
) -> bytes:
    fields: dict[str, object] = {
        "data": _encoded_payload(payload, encoding),
        "encoding": encoding,
        "encryption": encryption,
        "name": name,
    }
    if key is not None:
        fields["key"] = key
    if key_is_base64 is not None:
        fields["key_is_base64"] = key_is_base64
    if hmac_value is not None:
        fields["hmac"] = hmac_value
    if method_override is not None:
        fields["method_override"] = method_override
    return json.dumps(fields, separators=(",", ":")).encode("utf-8")


def _canonical_xml_payload(
    payload: bytes,
    *,
    name: str = "advanced.xml.bin",
    encoding: str = "base64",
    encryption: str = "none",
    key: str | None = None,
    key_is_base64: str | None = None,
    hmac_value: str | None = None,
) -> bytes:
    fields = [
        f"<data>{_encoded_payload(payload, encoding)}</data>",
        f"<encoding>{encoding}</encoding>",
        f"<encryption>{encryption}</encryption>",
        f"<name>{name}</name>",
    ]
    if key is not None:
        fields.append(f"<key>{key}</key>")
    if key_is_base64 is not None:
        fields.append(f"<key_is_base64>{key_is_base64}</key_is_base64>")
    if hmac_value is not None:
        fields.append(f"<hmac>{hmac_value}</hmac>")
    return ("<upload>" + "".join(fields) + "</upload>").encode("utf-8")


def _canonical_form_payload(
    payload: bytes,
    *,
    name: str = "advanced-form.bin",
    encoding: str = "base64",
    encryption: str = "none",
    key: str | None = None,
    key_is_base64: str | None = None,
    hmac_value: str | None = None,
    method_override: str | None = None,
) -> bytes:
    fields: dict[str, str] = {
        "data": _encoded_payload(payload, encoding),
        "encoding": encoding,
        "encryption": encryption,
        "name": name,
    }
    if key is not None:
        fields["key"] = key
    if key_is_base64 is not None:
        fields["key_is_base64"] = key_is_base64
    if hmac_value is not None:
        fields["hmac"] = hmac_value
    if method_override is not None:
        fields["method_override"] = method_override
    return urlencode(fields).encode("utf-8")


def _canonical_headers(
    payload: bytes | str,
    *,
    name: str | None = "advanced-header.bin",
    encoding: str = "base64",
    encryption: str = "none",
    key: str | None = None,
    key_is_base64: str | None = None,
    hmac_value: str | None = None,
    method_override: str | None = None,
    chunks: bool = False,
) -> dict[str, str]:
    encoded = payload if isinstance(payload, str) else _encoded_payload(payload, encoding)
    headers = {
        "X-XFerry-Encoding": encoding,
        "X-XFerry-Encryption": encryption,
    }
    if chunks:
        split_at = max(1, len(encoded) // 2)
        headers["X-XFerry-Data-0"] = encoded[:split_at]
        headers["X-XFerry-Data-1"] = encoded[split_at:]
    else:
        headers["X-XFerry-Data"] = encoded
    if name is not None:
        headers["X-XFerry-Name"] = name
    if key is not None:
        headers["X-XFerry-Key"] = key
    if key_is_base64 is not None:
        headers["X-XFerry-Key-Is-Base64"] = key_is_base64
    if hmac_value is not None:
        headers["X-XFerry-HMAC"] = hmac_value
    if method_override is not None:
        headers["X-XFerry-Method-Override"] = method_override
    return headers


def _canonical_query(
    payload: bytes,
    *,
    name: str = "advanced-query.bin",
    encoding: str = "base64",
    encryption: str = "none",
    key: str | None = None,
    key_is_base64: str | None = None,
    hmac_value: str | None = None,
) -> str:
    fields = {
        "data": _encoded_payload(payload, encoding),
        "encoding": encoding,
        "encryption": encryption,
        "name": name,
    }
    if key is not None:
        fields["key"] = key
    if key_is_base64 is not None:
        fields["key_is_base64"] = key_is_base64
    if hmac_value is not None:
        fields["hmac"] = hmac_value
    return "/advanced?" + urlencode(fields)


def _canonical_cookie_header(
    payload: bytes,
    *,
    name: str = "advanced-cookie.bin",
    encoding: str = "base64",
    encryption: str = "none",
    key: str | None = None,
    key_is_base64: str | None = None,
    hmac_value: str | None = None,
) -> dict[str, str]:
    pairs = {
        "xferry_data": _encoded_payload(payload, encoding),
        "xferry_encoding": encoding,
        "xferry_encryption": encryption,
        "xferry_name": name,
    }
    if key is not None:
        pairs["xferry_key"] = key
    if key_is_base64 is not None:
        pairs["xferry_key_is_base64"] = key_is_base64
    if hmac_value is not None:
        pairs["xferry_hmac"] = hmac_value
    return {"Cookie": "; ".join(f"{key}={quote(value, safe='')}" for key, value in pairs.items())}


def _canonical_path(
    payload: bytes,
    *,
    name: str = "advanced-path.bin",
    encryption: str = "none",
    key: str | None = None,
    hmac_value: str | None = None,
) -> str:
    fields = {"encryption": encryption}
    if key is not None:
        fields["key"] = key
    if hmac_value is not None:
        fields["hmac"] = hmac_value
    return f"/advanced/_payload/{quote(name, safe='')}/{_b64url(payload)}?{urlencode(fields)}"


def _multipart_body(
    payload: bytes,
    *,
    filename: str = "part.bin",
    encoded: bool = False,
) -> tuple[str, bytes]:
    boundary = "xferry-handler-boundary"
    if encoded:
        parts = [
            b'Content-Disposition: form-data; name="data"\r\n\r\n' + _b64(payload).encode(),
            b'Content-Disposition: form-data; name="encoding"\r\n\r\nbase64',
            b'Content-Disposition: form-data; name="encryption"\r\n\r\nnone',
            f'Content-Disposition: form-data; name="name"\r\n\r\n{filename}'.encode(),
        ]
    else:
        parts = [
            (
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + payload,
            b'Content-Disposition: form-data; name="encryption"\r\n\r\nnone',
        ]
    body = b"".join(b"--" + boundary.encode() + b"\r\n" + part + b"\r\n" for part in parts)
    body += b"--" + boundary.encode() + b"--\r\n"
    return f"multipart/form-data; boundary={boundary}", body


def _assert_advanced_success(
    response,
    upload_dir: Path,
    *,
    name: str,
    payload: bytes,
    profile: str,
    carrier: str,
    filename_source: str,
    request_body_size: int,
    encoding: str,
    encryption: str = "none",
    method_override: str | None = None,
    content_type: str = "application/octet-stream",
) -> dict[str, object]:
    body = json.loads(response.body)
    assert response.status_code == 201
    assert set(body) == {"file", "upload"}
    file_body = body["file"]
    assert isinstance(file_body, dict)
    uploaded_at = file_body.get("uploaded_at")
    assert isinstance(uploaded_at, str)
    assert uploaded_at.endswith("+00:00")
    assert datetime.fromisoformat(uploaded_at).tzinfo is not None
    sha256 = file_body.get("sha256")
    assert isinstance(sha256, str)
    assert len(sha256) == 64
    assert all(char in "0123456789abcdef" for char in sha256)
    assert file_body == {
        "name": name,
        "path": f"/uploads/{name}",
        "size_bytes": len(payload),
        "size_human": f"{float(len(payload)):.1f} B",
        "content_type": content_type,
        "uploaded_at": uploaded_at,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert body["upload"] == {
        "kind": "advanced",
        "profile": profile,
        "carrier": carrier,
        "filename_source": filename_source,
        "normalized_name": name,
        "collision_renamed": False,
        "request_body_size": request_body_size,
        "payload_size": len(payload),
        "encoding": encoding,
        "encryption": encryption,
        "method_override": method_override,
    }
    assert (upload_dir / name).read_bytes() == payload
    return body


def _assert_advanced_error(
    response,
    *,
    status: int,
    code: str,
    field: str | None,
) -> dict[str, object]:
    body = json.loads(response.body)
    assert response.status_code == status
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert body["error"]["field"] == field
    return body


def _forbid_advanced_touch(srv: StubServer, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_touch(_request: HTTPRequest) -> None:
        pytest.fail("Advanced rejection must not touch session idle activity")

    monkeypatch.setattr(srv, "_touch_advanced_session_dispatch", fail_touch)


class TestHandleOpsecUpload:
    def test_malformed_request_cannot_use_advanced_upload_fallback(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir)
        payload = _b64(b"blocked malformed upload")
        req = HTTPRequest(
            (
                "XUPLOAD\r\n"
                f"X-XFerry-Data: {payload}\r\n"
                "X-XFerry-Encoding: base64\r\n"
                "X-XFerry-Encryption: none\r\n"
                "X-XFerry-Name: malformed.txt\r\n\r\n"
            ).encode("ascii")
        )

        resp = srv._dispatch_handler(req)

        assert resp.status_code == 400
        assert not (upload_dir / "malformed.txt").exists()
        assert list(upload_dir.iterdir()) == []

    def test_invalid_request_target_cannot_use_advanced_upload_fallback(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir)
        payload = _b64(b"blocked target upload")
        req = HTTPRequest(
            (
                "XUPLOAD /\t HTTP/1.1\r\n"
                f"X-XFerry-Data: {payload}\r\n"
                "X-XFerry-Encoding: base64\r\n"
                "X-XFerry-Encryption: none\r\n"
                "X-XFerry-Name: target.txt\r\n\r\n"
            ).encode("ascii")
        )

        resp = srv._dispatch_handler(req)

        assert resp.status_code == 400
        assert not (upload_dir / "target.txt").exists()
        assert list(upload_dir.iterdir()) == []

    def test_valid_unknown_method_without_session_returns_405(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir)
        req = make_request(
            "XUPLOAD",
            "/advanced",
            headers=_canonical_headers(b"valid fallback upload", name="fallback.txt"),
        )

        resp = srv._dispatch_handler(req)

        assert resp.status_code == 405
        assert not (upload_dir / "fallback.txt").exists()

    def test_opsec_json_upload(self, temp_dir, upload_dir, monkeypatch):
        """Catches direct handler tests that omit the 7D dispatch or JSON media type."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        touches: list[AdvancedSessionDispatch | None] = []
        monkeypatch.setattr(
            srv,
            "_touch_advanced_session_dispatch",
            lambda request: touches.append(request.advanced_session_dispatch),
        )
        payload = _canonical_json_payload(b"secret data", name="secret.bin")
        req = _advanced_request(headers={"Content-Type": "application/json"}, body=payload)

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="secret.bin",
            payload=b"secret data",
            profile="json",
            carrier="body",
            filename_source="body",
            request_body_size=len(req.body),
            encoding="base64",
        )
        assert touches == [req.advanced_session_dispatch]

    def test_opsec_empty_body_returns_400(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request()

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="missing_field", field="data")

    def test_opsec_json_array_returns_400_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(headers={"Content-Type": "application/json"}, body=b"[]")

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="invalid_json_type", field=None)
        assert list(upload_dir.iterdir()) == []

    def test_opsec_json_object_missing_data_returns_400_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        payload = json.dumps(
            {"encoding": "base64", "encryption": "none", "name": "missing.bin"}
        ).encode()
        req = _advanced_request(headers={"Content-Type": "application/json"}, body=payload)

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="missing_field", field="data")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_invalid_base64_returns_400_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(headers=_canonical_headers("not!!!base64", name=None))

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="invalid_encoding", field="data")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_invalid_url_base64_returns_400_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            path="/advanced?data=not!!!base64&encoding=base64url&encryption=none"
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="invalid_encoding", field="data")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_invalid_key_is_base64_returns_400_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            headers={
                **_canonical_headers(
                    b"ciphertext",
                    encryption="xor",
                    key="%%%invalid%%%",
                    key_is_base64="true",
                )
            },
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize("chunks", [False, True], ids=["direct", "chunks"])
    def test_opsec_header_payload_limit_returns_413_without_writing(
        self, temp_dir, upload_dir, chunks
    ):
        """Catches canonical header chunks bypassing the encoded 64 KiB-style cap."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"header over limit"
        b64 = _b64(raw)
        srv.advanced_upload_header_data_limit = len(b64) - 1

        resp = srv.handle_advanced_upload(
            _advanced_request(headers=_canonical_headers(b64, name=None, chunks=chunks))
        )

        body = _assert_advanced_error(resp, status=413, code="payload_too_large", field="data")
        assert body["error"]["details"]["scope"] == "encoded"
        assert list(upload_dir.iterdir()) == []

    def test_opsec_url_payload_limit_returns_413_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"url over limit"
        b64 = _b64url(raw)
        srv.advanced_upload_url_data_limit = len(b64) - 1

        resp = srv.handle_advanced_upload(
            _advanced_request(
                path=(f"/advanced?data={quote(b64, safe='')}&encoding=base64url&encryption=none")
            )
        )

        body = _assert_advanced_error(resp, status=413, code="payload_too_large", field="data")
        assert body["error"]["details"]["scope"] == "encoded"
        assert list(upload_dir.iterdir()) == []

    def test_opsec_decoded_payload_limit_returns_413_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"12345"
        srv.advanced_upload_decoded_size_limit = len(raw) - 1
        payload = _canonical_json_payload(raw, name="too-big.bin")

        resp = srv.handle_advanced_upload(
            _advanced_request(headers={"Content-Type": "application/json"}, body=payload)
        )

        body = _assert_advanced_error(resp, status=413, code="payload_too_large", field="data")
        assert body["error"]["details"]["scope"] == "decoded"
        assert list(upload_dir.iterdir()) == []

    def test_opsec_gzip_expansion_limit_returns_413_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        decoded_limit = 64
        srv.advanced_upload_decoded_size_limit = decoded_limit
        raw = b"A" * 10_000
        payload = _canonical_json_payload(raw, name="gzip-bomb.txt", encoding="gzip-base64")

        resp = srv.handle_advanced_upload(
            _advanced_request(headers={"Content-Type": "application/json"}, body=payload)
        )

        _assert_advanced_error(resp, status=413, code="payload_too_large", field="data")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_gzip_base64_at_decoded_limit_still_uploads(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        decoded_limit = 64
        raw = b"B" * decoded_limit
        srv.advanced_upload_decoded_size_limit = decoded_limit
        payload = _canonical_json_payload(raw, name="gzip-limit.txt", encoding="gzip-base64")

        resp = srv.handle_advanced_upload(
            _advanced_request(headers={"Content-Type": "application/json"}, body=payload)
        )

        _assert_advanced_success(
            resp,
            upload_dir,
            name="gzip-limit.txt",
            payload=raw,
            profile="json",
            carrier="body",
            filename_source="body",
            request_body_size=len(payload),
            encoding="gzip-base64",
        )

    def test_opsec_invalid_gzip_returns_400_without_writing(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        payload = json.dumps(
            {
                "data": _b64(b"not a gzip stream"),
                "name": "bad-gzip.txt",
                "encoding": "gzip-base64",
                "encryption": "none",
            }
        ).encode()

        resp = srv.handle_advanced_upload(
            _advanced_request(headers={"Content-Type": "application/json"}, body=payload)
        )

        _assert_advanced_error(resp, status=400, code="invalid_encoding", field="data")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_gzip_trailing_junk_returns_400_without_writing(self, temp_dir, upload_dir):
        """Catches gzip decoders accepting trailing junk after a valid member."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        payload = json.dumps(
            {
                "data": _b64(gzip.compress(b"valid member") + b"junk"),
                "encoding": "gzip-base64",
                "encryption": "none",
                "name": "trailing-junk.bin",
            }
        ).encode()

        resp = srv.handle_advanced_upload(
            _advanced_request(headers={"Content-Type": "application/json"}, body=payload)
        )

        _assert_advanced_error(resp, status=400, code="invalid_encoding", field="data")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_json_payload_at_explicit_limits_still_uploads(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"fits body cap"
        srv.advanced_upload_decoded_size_limit = len(raw)
        payload = _canonical_json_payload(raw, name="fits-body.bin")

        resp = srv.handle_advanced_upload(
            _advanced_request(headers={"Content-Type": "application/json"}, body=payload)
        )

        _assert_advanced_success(
            resp,
            upload_dir,
            name="fits-body.bin",
            payload=raw,
            profile="json",
            carrier="body",
            filename_source="body",
            request_body_size=len(payload),
            encoding="base64",
        )

    def test_opsec_payload_at_explicit_limits_still_uploads(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"fits explicit caps"
        b64 = _b64(raw)
        srv.advanced_upload_decoded_size_limit = len(raw)
        srv.advanced_upload_header_data_limit = len(b64)

        resp = srv.handle_advanced_upload(
            _advanced_request(headers=_canonical_headers(b64, name="fits.bin"))
        )

        _assert_advanced_success(
            resp,
            upload_dir,
            name="fits.bin",
            payload=raw,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
        )

    @pytest.mark.parametrize("chunks", [False, True], ids=["direct", "chunks"])
    def test_opsec_headers_transport(self, temp_dir, upload_dir, chunks):
        """Catches canonical header direct/chunk data using legacy names or dict order."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"headers transport data"
        req = _advanced_request(
            headers=_canonical_headers(raw_data, name="headers.bin", chunks=chunks)
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="headers.bin",
            payload=raw_data,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
        )

    def test_opsec_url_transport(self, temp_dir, upload_dir):
        """Catches query payloads relying on legacy `d` or default base64url."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"url transport data"
        req = _advanced_request(
            path=_canonical_query(raw_data, name="query.bin", encoding="base64url")
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="query.bin",
            payload=raw_data,
            profile="query",
            carrier="query",
            filename_source="query",
            request_body_size=0,
            encoding="base64url",
        )

    def test_opsec_form_urlencoded_transport(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"form-urlencoded transport data"
        req = _advanced_request(
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=_canonical_form_payload(raw_data, name="form.txt"),
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="form.txt",
            payload=raw_data,
            profile="form",
            carrier="body",
            filename_source="body",
            request_body_size=len(req.body),
            encoding="base64",
        )

    def test_opsec_form_split_fields_transport(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"split field transport data"
        b64 = _b64(raw_data)
        body = (
            f"data_0={quote(b64[:8], safe='')}&data_1={quote(b64[8:], safe='')}"
            "&encoding=base64&encryption=none&name=split.txt"
        ).encode()

        req = _advanced_request(
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="split.txt",
            payload=raw_data,
            profile="form",
            carrier="body",
            filename_source="body",
            request_body_size=len(req.body),
            encoding="base64",
        )

    def test_opsec_multipart_file_part_transport_uses_content_disposition_filename(
        self,
        temp_dir,
        upload_dir,
    ):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"multipart file part data"
        content_type, body = _multipart_body(raw_data, filename="part.bin")

        req = _advanced_request(
            headers={"Content-Type": content_type},
            body=body,
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="part.bin",
            payload=raw_data,
            profile="multipart-binary",
            carrier="body",
            filename_source="part",
            request_body_size=len(req.body),
            encoding="raw",
        )

    def test_opsec_xml_transport(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"xml transport data"
        req = _advanced_request(
            headers={"Content-Type": "application/xml"},
            body=_canonical_xml_payload(raw_data, name="xml.bin"),
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="xml.bin",
            payload=raw_data,
            profile="xml",
            carrier="body",
            filename_source="body",
            request_body_size=len(req.body),
            encoding="base64",
        )

    def test_opsec_text_plain_raw_body_transport(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"text/plain raw body data"

        req = _advanced_request(
            headers={
                "Content-Type": "text/plain",
                "X-XFerry-Encryption": "none",
                "X-XFerry-Name": "plain.txt",
            },
            body=raw_data,
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="plain.txt",
            payload=raw_data,
            profile="text",
            carrier="body",
            filename_source="header",
            request_body_size=len(req.body),
            encoding="raw",
            content_type="text/plain",
        )

    def test_opsec_cookie_transport(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"cookie transport data"
        req = _advanced_request(
            headers=_canonical_cookie_header(
                raw_data,
                name="cookie.txt",
                encoding="base64url",
            )
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="cookie.txt",
            payload=raw_data,
            profile="cookies",
            carrier="cookies",
            filename_source="cookie",
            request_body_size=0,
            encoding="base64url",
        )

    def test_opsec_path_segment_transport_uses_reserved_payload_namespace(
        self, temp_dir, upload_dir
    ):
        """Catches reintroducing path markers or decoded-path filename extraction."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"path segment transport data"
        payload = _b64url(raw_data)

        unmarked_resp = srv.handle_advanced_upload(_advanced_request(path=f"/advanced/x/{payload}"))
        assert unmarked_resp.status_code == 400

        req = _advanced_request(path=_canonical_path(raw_data, name="path.txt"))
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="path.txt",
            payload=raw_data,
            profile="path",
            carrier="path",
            filename_source="path",
            request_body_size=0,
            encoding="base64url",
        )

    def test_opsec_hex_encoding(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"hex encoded transport data"

        req = _advanced_request(
            headers=_canonical_headers(raw_data, name="hex.bin", encoding="hex")
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="hex.bin",
            payload=raw_data,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="hex",
        )

    def test_opsec_percent_encoding(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"percent payload /&?"

        req = _advanced_request(
            path=_canonical_query(raw_data, name="percent.txt", encoding="percent")
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="percent.txt",
            payload=raw_data,
            profile="query",
            carrier="query",
            filename_source="query",
            request_body_size=0,
            encoding="percent",
        )

    def test_opsec_gzip_base64_encoding(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"gzip base64 encoded transport data"

        req = _advanced_request(
            headers={"Content-Type": "application/json"},
            body=_canonical_json_payload(raw_data, name="gzip.txt", encoding="gzip-base64"),
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="gzip.txt",
            payload=raw_data,
            profile="json",
            carrier="body",
            filename_source="body",
            request_body_size=len(req.body),
            encoding="gzip-base64",
        )

    def test_opsec_raw_body_xor_decrypts_base64_key(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"raw body xor with base64 key"
        key = "A"
        encrypted = xor_bytes(original, key)
        req = _advanced_request(
            headers={
                "Content-Type": "application/octet-stream",
                "X-XFerry-Encryption": "xor",
                "X-XFerry-Key": _b64(key.encode()),
                "X-XFerry-Key-Is-Base64": "true",
                "X-XFerry-Name": "raw-key-base64.bin",
            },
            body=encrypted,
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="raw-key-base64.bin",
            payload=original,
            profile="raw",
            carrier="body",
            filename_source="header",
            request_body_size=len(req.body),
            encoding="raw",
            encryption="xor",
        )

    @pytest.mark.parametrize(
        ("path", "headers", "field"),
        [
            (
                _canonical_query(b"query payload with forbidden header metadata", name="query.bin"),
                {"X-XFerry-Name": "forbidden-header.txt"},
                "headers",
            ),
            (
                "/advanced?name=forbidden-query.txt",
                _canonical_headers(b"header payload with forbidden query metadata"),
                "query",
            ),
        ],
    )
    def test_opsec_metadata_overlay_inputs_reject_instead_of_precedence_success(
        self, temp_dir, upload_dir, path, headers, field
    ):
        """Catches cross-carrier metadata overlay being restored."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(path=path, headers=headers)

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="invalid_field", field=field)
        assert list(upload_dir.iterdir()) == []

    def test_opsec_path_gzip_base64url_encoding(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"json gzip-base64url payload " * 4
        req = _advanced_request(
            headers={"Content-Type": "application/json"},
            body=_canonical_json_payload(
                raw_data,
                name="gzip-url.txt",
                encoding="gzip-base64url",
            ),
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="gzip-url.txt",
            payload=raw_data,
            profile="json",
            carrier="body",
            filename_source="body",
            request_body_size=len(req.body),
            encoding="gzip-base64url",
        )

    def test_opsec_method_override_form_field_does_not_replace_carrier(
        self,
        temp_dir,
        upload_dir,
    ):
        """Catches method_override regaining routing authority."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"method override form data"
        req = _advanced_request(
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=_canonical_form_payload(
                raw_data,
                name="override.txt",
                method_override="PUT",
            ),
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="override.txt",
            payload=raw_data,
            profile="form",
            carrier="body",
            filename_source="body",
            request_body_size=len(req.body),
            encoding="base64",
            method_override="PUT",
        )

    def test_opsec_headers_xor_decrypt(self, temp_dir, upload_dir):
        """XOR success exposes only canonical plaintext metadata and diagnostics."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"secret plaintext"
        key = "mykey"
        encrypted = xor_bytes(original, key)
        req = _advanced_request(
            headers=_canonical_headers(
                encrypted,
                name="xor.bin",
                encryption="xor",
                key=key,
            )
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="xor.bin",
            payload=original,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
            encryption="xor",
        )
        rendered = resp.body.decode("utf-8")
        assert key not in rendered
        assert _b64(encrypted) not in rendered

    def test_opsec_url_xor_decrypt(self, temp_dir, upload_dir):
        """Canonical query XOR must decrypt and publish, not pass via alias rejection."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"url secret"
        key = "urlkey"
        encrypted = xor_bytes(original, key)
        req = _advanced_request(
            path=_canonical_query(
                encrypted,
                name="query-xor.bin",
                encoding="base64url",
                encryption="xor",
                key=key,
            )
        )
        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="query-xor.bin",
            payload=original,
            profile="query",
            carrier="query",
            filename_source="query",
            request_body_size=0,
            encoding="base64url",
            encryption="xor",
        )

    def test_opsec_headers_hmac_valid(self, temp_dir, upload_dir):
        """Catches HMAC being verified over plaintext instead of decoded ciphertext."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw_data = b"hmac data"
        key = "hmackey"
        encrypted = xor_encrypt(raw_data, key)
        hmac_val = compute_hmac(encrypted, key)
        req = _advanced_request(
            headers=_canonical_headers(
                encrypted,
                name="hmac.bin",
                encryption="xor",
                key=key,
                hmac_value=hmac_val,
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="hmac.bin",
            payload=raw_data,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
            encryption="xor",
        )

    def test_opsec_headers_hmac_invalid(self, temp_dir, upload_dir, monkeypatch):
        """Wrong lowercase 64-hex HMAC reaches hmac_mismatch and never touches."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        _forbid_advanced_touch(srv, monkeypatch)
        raw_data = b"hmac data"
        req = _advanced_request(
            headers=_canonical_headers(
                raw_data,
                encryption="xor",
                key="somekey",
                hmac_value="0" * 64,
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="hmac_mismatch", field="hmac")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_body_and_header_payloads_are_ambiguous_before_parse(
        self, temp_dir, upload_dir, monkeypatch
    ):
        """Catches fallback/precedence letting malformed body fall through to headers."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        _forbid_advanced_touch(srv, monkeypatch)
        req = _advanced_request(
            headers={
                "Content-Type": "application/json",
                **_canonical_headers(b"header must not win", name="fallback.bin"),
            },
            body=b"{",
        )

        resp = srv.handle_advanced_upload(req)

        body = _assert_advanced_error(resp, status=400, code="ambiguous_payload", field="data")
        assert body["error"]["details"]["carriers"] == ["body", "headers"]
        assert list(upload_dir.iterdir()) == []

    def test_opsec_headers_and_query_payloads_are_ambiguous(self, temp_dir, upload_dir):
        """Catches headers-over-query precedence being restored."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            path=_canonical_query(b"query"),
            headers=_canonical_headers(b"header"),
        )

        resp = srv.handle_advanced_upload(req)

        body = _assert_advanced_error(resp, status=400, code="ambiguous_payload", field="data")
        assert body["error"]["details"]["carriers"] == ["headers", "query"]
        assert list(upload_dir.iterdir()) == []

    def test_opsec_empty_all_returns_400(self, temp_dir, upload_dir):
        """No body and no canonical data carrier remains a closed missing-field error."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request()

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="missing_field", field="data")

    @pytest.mark.parametrize(
        ("advanced_req", "name", "payload", "profile", "carrier", "filename_source", "encoding"),
        [
            (
                _advanced_request(
                    headers={"Content-Type": "application/json"},
                    body=_canonical_json_payload(b"transport body", name="body.bin"),
                ),
                "body.bin",
                b"transport body",
                "json",
                "body",
                "body",
                "base64",
            ),
            (
                _advanced_request(
                    headers=_canonical_headers(b"transport header", name="header.bin")
                ),
                "header.bin",
                b"transport header",
                "header",
                "headers",
                "header",
                "base64",
            ),
            (
                _advanced_request(path=_canonical_query(b"transport query", name="query.bin")),
                "query.bin",
                b"transport query",
                "query",
                "query",
                "query",
                "base64",
            ),
        ],
    )
    def test_opsec_transport_in_response(
        self,
        temp_dir,
        upload_dir,
        advanced_req,
        name,
        payload,
        profile,
        carrier,
        filename_source,
        encoding,
    ):
        """Catches response carrier/profile drift across canonical carriers."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(advanced_req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name=name,
            payload=payload,
            profile=profile,
            carrier=carrier,
            filename_source=filename_source,
            request_body_size=len(advanced_req.body) if carrier == "body" else 0,
            encoding=encoding,
        )

    def test_opsec_query_base64url_public_behavior_replaces_private_decode_helper(
        self, temp_dir, upload_dir
    ):
        """Catches removing URL-safe base64 support without testing a private helper."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = bytes(range(1, 128))

        resp = srv.handle_advanced_upload(
            _advanced_request(path=_canonical_query(raw, name="urlsafe.bin", encoding="base64url"))
        )

        _assert_advanced_success(
            resp,
            upload_dir,
            name="urlsafe.bin",
            payload=raw,
            profile="query",
            carrier="query",
            filename_source="query",
            request_body_size=0,
            encoding="base64url",
        )

    def test_opsec_headers_with_filename(self, temp_dir, upload_dir):
        """Canonical X-XFerry-Name controls the final safe filename."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"named file"
        req = _advanced_request(headers=_canonical_headers(raw, name="custom_name.txt"))

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="custom_name.txt",
            payload=raw,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
        )

    def test_opsec_key_is_base64_header(self, temp_dir, upload_dir):
        """Canonical X-XFerry-Key-Is-Base64 only accepts exact string true/false."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"key-is-base64 test"
        key = "mypassword"
        encrypted = xor_bytes(original, key)
        req = _advanced_request(
            headers=_canonical_headers(
                encrypted,
                name="key-base64.bin",
                encryption="xor",
                key=_b64(key.encode()),
                key_is_base64="true",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="key-base64.bin",
            payload=original,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
            encryption="xor",
        )

    def test_opsec_chunked_headers(self, temp_dir, upload_dir):
        """X-XFerry-Data-N chunks reassemble in exact canonical wire order."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"chunked header data that spans multiple headers"
        req = _advanced_request(headers=_canonical_headers(raw, name="chunked.bin", chunks=True))

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="chunked.bin",
            payload=raw,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
        )

    def test_opsec_chunked_single_chunk(self, temp_dir, upload_dir):
        """A single canonical chunk is accepted without direct Data fallback."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        raw = b"single chunk"
        b64 = _b64(raw)
        req = _advanced_request(
            headers={
                "X-XFerry-Data-0": b64,
                "X-XFerry-Encoding": "base64",
                "X-XFerry-Encryption": "none",
                "X-XFerry-Name": "single-chunk.bin",
            }
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="single-chunk.bin",
            payload=raw,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
        )

    @pytest.mark.parametrize(
        "advanced_req",
        [
            _advanced_request(headers={"X-D": _b64(b"legacy header")}),
            _advanced_request(path=f"/advanced?d={quote(_b64(b'legacy query'), safe='')}"),
            _advanced_request(headers={"Cookie": f"xf_d={quote(_b64(b'legacy cookie'), safe='')}"}),
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=f"<upload><d>{_b64(b'legacy xml')}</d></upload>".encode(),
            ),
            _advanced_request(
                path=(
                    f"/advanced/_payload/path.txt/{_b64url(b'legacy path marker')}"
                    "?path_payload=1&encryption=none"
                )
            ),
        ],
        ids=["header-alias", "query-alias", "cookie-alias", "xml-old-name", "path-marker"],
    )
    def test_opsec_legacy_carrier_spellings_are_rejected_without_writing(
        self, temp_dir, upload_dir, advanced_req
    ):
        """Explicit rejection-only coverage for removed 7E compatibility aliases."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(advanced_req)

        assert resp.status_code == 400
        assert json.loads(resp.body)["error"]["code"] in {"invalid_field", "missing_field"}
        assert list(upload_dir.iterdir()) == []


# ── Auth rate limiter tests ────────────────────────────────────────


class TestAuthRateLimiter:
    def test_not_blocked_initially(self):
        from xferry.security.auth import AuthRateLimiter

        rl = AuthRateLimiter(max_attempts=3, cooldown=10.0)
        assert rl.is_blocked("1.2.3.4") is False

    def test_blocked_after_max_failures(self):
        from xferry.security.auth import AuthRateLimiter

        rl = AuthRateLimiter(max_attempts=3, cooldown=10.0)
        for _ in range(3):
            rl.record_failure("1.2.3.4")
        assert rl.is_blocked("1.2.3.4") is True

    def test_reset_unblocks(self):
        from xferry.security.auth import AuthRateLimiter

        rl = AuthRateLimiter(max_attempts=2, cooldown=10.0)
        rl.record_failure("1.2.3.4")
        rl.record_failure("1.2.3.4")
        assert rl.is_blocked("1.2.3.4") is True
        rl.reset("1.2.3.4")
        assert rl.is_blocked("1.2.3.4") is False

    def test_different_ips_independent(self):
        from xferry.security.auth import AuthRateLimiter

        rl = AuthRateLimiter(max_attempts=2, cooldown=10.0)
        rl.record_failure("1.1.1.1")
        rl.record_failure("1.1.1.1")
        assert rl.is_blocked("1.1.1.1") is True
        assert rl.is_blocked("2.2.2.2") is False


# ── HEAD tests ────────────────────────────────────────────────────


class TestHandleHead:
    def test_head_200(self, server):
        req = make_request("HEAD", "/")
        resp = server.handle_head(req)
        assert resp.status_code == 200
        assert resp.body == b""
        assert resp.stream_path is None

    def test_head_empty_body(self, server, upload_dir):
        (upload_dir / "data.txt").write_text("some data")
        req = make_request("HEAD", "/data.txt")
        resp = server.handle_head(req)
        assert resp.status_code == 200
        assert resp.body == b""
        assert resp.stream_path is None

    def test_head_content_length_matches_get(self, server, upload_dir):
        content = "hello world content"
        (upload_dir / "match.txt").write_text(content)
        get_req = make_request("GET", "/match.txt")
        get_resp = server.handle_get(get_req)
        head_req = make_request("HEAD", "/match.txt")
        head_resp = server.handle_head(head_req)
        assert head_resp.headers.get("Content-Length") == get_resp.headers.get("Content-Length")

    def test_head_404_for_missing(self, server):
        req = make_request("HEAD", "/nonexistent.xyz")
        resp = server.handle_head(req)
        assert resp.status_code == 404


# ── DELETE tests ──────────────────────────────────────────────────


class TestHandleDelete:
    def test_delete_existing_file_returns_canonical_deleted_file(self, server, upload_dir):
        (upload_dir / "hello.txt").write_text("bye")
        req = make_request("DELETE", "/uploads/hello.txt")
        resp = server.handle_delete(req)

        assert resp.status_code == 200
        assert json.loads(resp.body) == {
            "deleted_file": {"name": "hello.txt", "path": "/uploads/hello.txt"}
        }
        assert not (upload_dir / "hello.txt").exists()

    def test_delete_missing_file(self, server):
        req = make_request("DELETE", "/uploads/ghost.txt")
        resp = server.handle_delete(req)

        assert resp.status_code == 404
        assert json.loads(resp.body) == {
            "error": {
                "code": "resource_not_found",
                "message": "File not found: /uploads/ghost.txt",
                "field": "path",
                "details": {"path": "/uploads/ghost.txt"},
            }
        }

    def test_delete_outside_uploads(self, server, temp_dir):
        (temp_dir / "root_file.txt").write_text("root")
        req = make_request("DELETE", "/root_file.txt")
        resp = server.handle_delete(req)
        # sandbox restriction: file resolves inside upload_dir or 404
        assert resp.status_code == 404
        assert json.loads(resp.body)["error"]["code"] == "resource_not_found"

    def test_delete_directory_rejected(self, server, upload_dir):
        sub = upload_dir / "subdir"
        sub.mkdir()
        req = make_request("DELETE", "/uploads/subdir")
        resp = server.handle_delete(req)

        assert resp.status_code == 400
        assert json.loads(resp.body) == {
            "error": {
                "code": "invalid_field",
                "message": "Directory delete requires clear=true on /uploads",
                "field": "path",
                "details": {"path": "/uploads/subdir"},
            }
        }

    def test_delete_uploads_root_requires_clear_flag(self, server, upload_dir):
        (upload_dir / "keep.txt").write_text("keep")
        req = make_request("DELETE", "/uploads")
        resp = server.handle_delete(req)

        assert resp.status_code == 400
        assert json.loads(resp.body) == {
            "error": {
                "code": "invalid_field",
                "message": "Directory delete requires clear=true on /uploads",
                "field": "path",
                "details": {"path": "/uploads"},
            }
        }
        assert (upload_dir / "keep.txt").exists()

    def test_delete_uploads_clear_true_returns_canonical_summary(self, server, upload_dir):
        (upload_dir / ".gitkeep").write_text("")
        (upload_dir / "a.txt").write_text("data")
        (upload_dir / "b.txt").write_text("data")
        (upload_dir / "c.txt").write_text("data")
        subdir = upload_dir / "nested"
        subdir.mkdir()
        (subdir / "child.txt").write_text("child")

        req = make_request("DELETE", "/uploads?clear=true")
        resp = server.handle_delete(req)

        assert resp.status_code == 200
        assert json.loads(resp.body) == {
            "cleared_uploads": {
                "path": "/uploads",
                "deleted_files": 3,
                "deleted_dirs": 1,
                "preserved": [".gitkeep"],
            }
        }
        assert (upload_dir / ".gitkeep").exists()
        assert not (upload_dir / "a.txt").exists()
        assert not (upload_dir / "b.txt").exists()
        assert not (upload_dir / "c.txt").exists()
        assert not subdir.exists()

    @pytest.mark.parametrize(
        ("target", "field"),
        [
            ("/uploads?clear=1", "clear"),
            ("/uploads?clear=yes", "clear"),
            ("/uploads?clear=", "clear"),
            ("/uploads?clear", "clear"),
            ("/uploads?clear=true&mode=force", "mode"),
            ("/uploads?clear=true&clear=true", "clear"),
            ("/uploads?clear=true&", "query"),
            ("/uploads?&clear=true", "query"),
            ("/uploads?&&clear=true", "query"),
        ],
    )
    def test_delete_uploads_clear_query_is_strict_and_preserves_contents(
        self,
        server,
        upload_dir,
        target,
        field,
    ):
        (upload_dir / "keep.txt").write_text("keep")

        resp = server.handle_delete(make_request("DELETE", target))

        assert resp.status_code == 400
        data = json.loads(resp.body)
        assert data["error"]["code"] == "invalid_field"
        assert data["error"]["field"] == field
        if field == "clear":
            assert data["error"]["details"] == {"allowed": ["true", "false"]}
        assert (upload_dir / "keep.txt").read_text() == "keep"

    def test_delete_uploads_clear_false_is_directory_delete_not_clear(self, server, upload_dir):
        (upload_dir / "keep.txt").write_text("keep")

        resp = server.handle_delete(make_request("DELETE", "/uploads?clear=false"))

        assert resp.status_code == 400
        assert json.loads(resp.body) == {
            "error": {
                "code": "invalid_field",
                "message": "Directory delete requires clear=true on /uploads",
                "field": "path",
                "details": {"path": "/uploads"},
            }
        }
        assert (upload_dir / "keep.txt").read_text() == "keep"

    def test_delete_uploads_partial_clear_failure_uses_bounded_reason(
        self,
        server,
        upload_dir,
        monkeypatch,
    ):
        (upload_dir / ".gitkeep").write_text("")
        blocked = upload_dir / "blocked"
        blocked.mkdir()
        (blocked / "child.txt").write_text("child")
        (upload_dir / "remove.txt").write_text("remove")

        def fail_blocked_rmtree(path):
            if path == blocked:
                raise PermissionError(errno.EACCES, "raw /secret/path should not leak")
            raise AssertionError(f"unexpected rmtree target: {path}")

        monkeypatch.setattr("xferry.handlers.files.shutil.rmtree", fail_blocked_rmtree)

        resp = server.handle_delete(make_request("DELETE", "/uploads?clear=true"))

        assert resp.status_code == 500
        assert json.loads(resp.body) == {
            "error": {
                "code": "clear_failed",
                "message": "Failed to clear uploads",
                "field": "path",
                "details": {
                    "path": "/uploads",
                    "deleted_files": 1,
                    "deleted_dirs": 0,
                    "preserved": [".gitkeep"],
                    "failures": [{"name": "blocked", "reason": "permission_denied"}],
                },
            }
        }
        body = resp.body.decode("utf-8")
        assert "raw /secret/path" not in body
        assert str(blocked) not in body
        assert (upload_dir / ".gitkeep").exists()
        assert blocked.exists()
        assert not (upload_dir / "remove.txt").exists()

    def test_delete_unexpected_failure_redacts_os_exception(self, server, upload_dir, monkeypatch):
        target = upload_dir / "boom.txt"
        target.write_text("boom")
        original_unlink = Path.unlink

        def fail_target_unlink(path, *args, **kwargs):
            if path == target:
                raise OSError("raw /secret/path should not leak")
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_target_unlink)

        resp = server.handle_delete(make_request("DELETE", "/uploads/boom.txt"))

        assert resp.status_code == 500
        assert json.loads(resp.body) == {
            "error": {
                "code": "internal_error",
                "message": "Failed to delete upload",
                "field": "path",
                "details": {"path": "/uploads/boom.txt"},
            }
        }
        body = resp.body.decode("utf-8")
        assert "raw /secret/path" not in body
        assert str(target) not in body
        assert target.exists()

    def test_delete_path_traversal_blocked(self, server):
        req = make_request("DELETE", "/uploads/../../etc/passwd")
        resp = server.handle_delete(req)

        assert resp.status_code == 400
        assert json.loads(resp.body) == {
            "error": {
                "code": "invalid_path",
                "message": "Invalid upload path",
                "field": "path",
                "details": {"path": "/uploads/../../etc/passwd"},
            }
        }


# ── Cache headers tests ──────────────────────────────────────────


class TestCacheHeaders:
    def test_get_returns_etag_and_last_modified(self, server, upload_dir):
        (upload_dir / "cached.txt").write_text("cache me")
        req = make_request("GET", "/cached.txt")
        resp = server.handle_get(req)
        assert resp.status_code == 200
        assert "ETag" in resp.headers
        assert "Last-Modified" in resp.headers
        assert "Cache-Control" in resp.headers

    def test_conditional_304_with_if_none_match(self, server, upload_dir):
        (upload_dir / "etag_test.txt").write_text("etag content")
        # First request to get ETag
        req1 = make_request("GET", "/etag_test.txt")
        resp1 = server.handle_get(req1)
        etag = resp1.headers["ETag"]
        # Second request with If-None-Match
        req2 = make_request("GET", "/etag_test.txt", headers={"If-None-Match": etag})
        resp2 = server.handle_get(req2)
        assert resp2.status_code == 304
        assert resp2.body == b""

    def test_head_has_cache_headers(self, server, upload_dir):
        (upload_dir / "head_cache.txt").write_text("head cache")
        req = make_request("HEAD", "/head_cache.txt")
        resp = server.handle_head(req)
        assert resp.status_code == 200
        assert "ETag" in resp.headers
        assert "Last-Modified" in resp.headers

    def test_versioned_static_assets_use_immutable_cache(self, server):
        req = make_request("GET", "/static/ui/app.js?v=test-build")
        resp = server.handle_get(req)

        assert resp.status_code == 200
        assert resp.stream_path is not None
        assert resp.headers["Cache-Control"] == "public, max-age=31536000, immutable"


# ── Metrics tests ─────────────────────────────────────────────────


class TestMetrics:
    def test_get_metrics_returns_canonical_envelope_with_no_store(self, server):
        """Catches /metrics exposing the raw legacy snapshot or cacheable response."""
        req = make_request("GET", "/metrics")
        resp = server.handle_get(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data == {"metrics": _json_transport(server.get_metrics())}
        assert resp.headers["Cache-Control"] == "no-store"
        assert "total_requests" not in data["metrics"]
        assert "bytes_sent" not in data["metrics"]
        assert "request_latency_ms" not in data["metrics"]

    def test_metrics_available(self, temp_dir, upload_dir):
        srv = StubServer(temp_dir, upload_dir)
        req = make_request("GET", "/metrics")
        resp = srv.handle_get(req)
        assert resp.status_code == 200


# ── OPSEC AES decryption path tests ──────────────────────────────


class TestOpsecAESDecryption:
    """Test OPSEC upload with AES-256-GCM encrypted payload."""

    def test_opsec_headers_aes_decrypt(self, temp_dir, upload_dir):
        """AES success exposes only canonical plaintext metadata and diagnostics."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"aes encrypted secret"
        key = "strongpassword"
        encrypted = aes_encrypt(original, key)
        req = _advanced_request(
            headers=_canonical_headers(
                encrypted,
                name="aes-header.bin",
                encryption="aes",
                key=key,
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="aes-header.bin",
            payload=original,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
            encryption="aes",
        )
        rendered = resp.body.decode("utf-8")
        assert key not in rendered
        assert _b64(encrypted) not in rendered

    def test_opsec_url_aes_decrypt(self, temp_dir, upload_dir):
        """Canonical query AES must decrypt and publish, not pass via alias rejection."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"url aes secret"
        key = "urlkey"
        encrypted = aes_encrypt(original, key)
        req = _advanced_request(
            path=_canonical_query(
                encrypted,
                name="aes-query.bin",
                encoding="base64url",
                encryption="aes",
                key=key,
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="aes-query.bin",
            payload=original,
            profile="query",
            carrier="query",
            filename_source="query",
            request_body_size=0,
            encoding="base64url",
            encryption="aes",
        )

    def test_opsec_aes_wrong_key_returns_400_without_writing(self, temp_dir, upload_dir):
        """AES with wrong key fails closed without writing ciphertext."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"aes wrong key test"
        encrypted = aes_encrypt(original, "correct_key")
        req = _advanced_request(
            headers=_canonical_headers(
                encrypted,
                name="wrong-key.bin",
                encryption="aes",
                key="wrong_key",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="decrypt_failed", field="encryption")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_aes_tampered_headers_return_400_without_writing(self, temp_dir, upload_dir):
        """Tampered AES-GCM header payload fails closed without writing ciphertext."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        encrypted = bytearray(aes_encrypt(b"tamper me", "correct_key"))
        encrypted[-1] ^= 0x01
        req = _advanced_request(
            headers=_canonical_headers(
                bytes(encrypted),
                name="tampered-header.bin",
                encryption="aes",
                key="correct_key",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="decrypt_failed", field="encryption")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_aes_tampered_url_returns_400_without_writing(self, temp_dir, upload_dir):
        """Tampered AES-GCM URL payload fails closed without writing ciphertext."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        encrypted = bytearray(aes_encrypt(b"url tamper me", "correct_key"))
        encrypted[-1] ^= 0x01
        req = _advanced_request(
            path=_canonical_query(
                bytes(encrypted),
                name="tampered-query.bin",
                encoding="base64url",
                encryption="aes",
                key="correct_key",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="decrypt_failed", field="encryption")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_aes_with_hmac(self, temp_dir, upload_dir):
        """AES + HMAC verifies decoded ciphertext before decrypting."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        original = b"aes hmac verified"
        key = "hmacaeskey"
        encrypted = aes_encrypt(original, key)
        hmac_val = compute_hmac(encrypted, key)
        req = _advanced_request(
            headers=_canonical_headers(
                encrypted,
                name="aes-hmac.bin",
                encryption="aes",
                key=key,
                hmac_value=hmac_val,
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="aes-hmac.bin",
            payload=original,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
            encryption="aes",
        )

    @pytest.mark.parametrize("mode", ["auto", "rot13", "AES-GCM", "AES", "XOR"])
    def test_opsec_rejects_unsupported_encryption_modes_without_writing(
        self,
        temp_dir,
        upload_dir,
        mode,
    ):
        """Only exact public ``none``, ``xor``, and ``aes`` tokens are accepted."""
        wire = b"unsupported mode wire"
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            headers=_canonical_headers(
                wire,
                name="unsupported-mode.bin",
                encryption=mode,
                key="correct horse battery staple",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="invalid_field", field="encryption")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_rejects_encryption_without_a_key(self, temp_dir, upload_dir):
        """Encryption metadata cannot be silently ignored and stored as ciphertext."""
        ciphertext = bytes.fromhex("9cfdae6dccb0bd569f3dbd28e9c4438bb5ff4c7b8865d461453c")
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            headers=_canonical_headers(
                ciphertext,
                name="missing-key.bin",
                encryption="xor",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="missing_field", field="key")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_rejects_hmac_without_a_key(self, temp_dir, upload_dir):
        """An HMAC without its key cannot be ignored as if the payload were plaintext."""
        wire = b"hmac without key wire"
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            headers=_canonical_headers(
                wire,
                name="hmac-without-key.bin",
                encryption="xor",
                hmac_value="2" * 64,
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="missing_field", field="key")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize(
        "crypto_metadata",
        [
            {"encryption": 1},
            {"key": []},
            {"hmac": {}},
            {"key": ""},
            {"hmac": ""},
            {"key_is_base64": "true"},
        ],
    )
    def test_opsec_rejects_malformed_json_crypto_metadata_without_writing(
        self,
        temp_dir,
        upload_dir,
        crypto_metadata,
    ):
        """Present but unusable crypto metadata never degrades to plaintext."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        fields = {
            "data": _b64(b"must not be stored"),
            "encoding": "base64",
            "encryption": "none",
            **crypto_metadata,
        }
        req = _advanced_request(
            headers={"Content-Type": "application/json"},
            body=json.dumps(fields).encode(),
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(
            resp, status=400, code="invalid_field", field=next(iter(crypto_metadata))
        )
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize(
        ("key_is_base64_value", "key_is_base64"),
        [
            (True, True),
            (False, False),
        ],
    )
    def test_opsec_accepts_exact_json_key_is_base64_booleans(
        self,
        temp_dir,
        upload_dir,
        key_is_base64_value,
        key_is_base64,
    ):
        """JSON key_is_base64 accepts booleans only, not truthy/falsy strings."""
        original = b"approved key-is-base64 representation"
        key = "strict-key-base64-key"
        encrypted = xor_encrypt(original, key)
        key_field = _b64(key.encode()) if key_is_base64 else key
        body = _canonical_json_payload(
            encrypted,
            name="json-key-base64.bin",
            encryption="xor",
            key=key_field,
            key_is_base64=key_is_base64_value,
        )
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/json"},
                body=body,
            )
        )

        _assert_advanced_success(
            resp,
            upload_dir,
            name="json-key-base64.bin",
            payload=original,
            profile="json",
            carrier="body",
            filename_source="body",
            request_body_size=len(body),
            encoding="base64",
            encryption="xor",
        )

    @pytest.mark.parametrize(
        "key_is_base64_value", ["1", "true", "yes", "on", "0", "false", "no", "off"]
    )
    def test_opsec_rejects_json_string_key_is_base64_without_writing(
        self, temp_dir, upload_dir, key_is_base64_value
    ):
        """Catches JSON accepting string key_is_base64 values."""
        key = "strict-key-base64-key"
        body = json.dumps(
            {
                "data": _b64(xor_encrypt(b"json string key-is-base64", key)),
                "encoding": "base64",
                "encryption": "xor",
                "key": _b64(key.encode()),
                "key_is_base64": key_is_base64_value,
            }
        ).encode()
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(headers={"Content-Type": "application/json"}, body=body)
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key_is_base64")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize(
        ("key_is_base64_value", "key_is_base64"),
        [
            ("true", True),
            ("false", False),
        ],
    )
    def test_opsec_xml_accepts_exact_key_is_base64_string_tokens(
        self,
        temp_dir,
        upload_dir,
        key_is_base64_value,
        key_is_base64,
    ):
        """XML accepts only exact string true/false for key_is_base64."""
        original = b"exact XML key-is-base64 token"
        key = "strict-xml-key-base64-key"
        encrypted = xor_encrypt(original, key)
        key_field = _b64(key.encode()) if key_is_base64 else key
        body = _canonical_xml_payload(
            encrypted,
            name="xml-key-base64.bin",
            encryption="xor",
            key=key_field,
            key_is_base64=key_is_base64_value,
        )
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=body,
            )
        )

        _assert_advanced_success(
            resp,
            upload_dir,
            name="xml-key-base64.bin",
            payload=original,
            profile="xml",
            carrier="body",
            filename_source="body",
            request_body_size=len(body),
            encoding="base64",
            encryption="xor",
        )

    def test_opsec_rejects_whitespace_padded_xml_key_is_base64_without_writing(
        self,
        temp_dir,
        upload_dir,
    ):
        """XML must not trim malformed present key_is_base64 into an approved token."""
        key = "strict-xml-key-base64-key"
        encrypted = xor_encrypt(b"padded XML key-is-base64 must not be stored", key)
        body = _canonical_xml_payload(
            encrypted,
            encryption="xor",
            key=_b64(key.encode()),
            key_is_base64=" true ",
        )
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=body,
            )
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key_is_base64")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_rejects_unknown_xml_key_is_base64_without_writing(
        self,
        temp_dir,
        upload_dir,
    ):
        """An exact unknown XML key_is_base64 token remains a negative control."""
        key = "strict-xml-key-base64-key"
        encrypted = xor_encrypt(b"unknown XML key-is-base64 must not be stored", key)
        body = _canonical_xml_payload(
            encrypted,
            encryption="xor",
            key=_b64(key.encode()),
            key_is_base64="maybe",
        )
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=body,
            )
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key_is_base64")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_rejects_whitespace_padded_xml_encryption_mode_without_writing(
        self,
        temp_dir,
        upload_dir,
    ):
        """XML must not turn a padded encryption mode into the exact ``xor`` token."""
        key = "strict-xml-key"
        encrypted = xor_encrypt(b"padded XML mode must not be stored", key)
        body = _canonical_xml_payload(encrypted, encryption=" xor ", key=key)
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=body,
            )
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="encryption")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_rejects_whitespace_padded_xml_aes_key_without_writing(
        self,
        temp_dir,
        upload_dir,
    ):
        """XML key text is a secret value and must not be silently trimmed."""
        key = "strict-xml-key"
        encrypted = aes_encrypt(b"padded XML AES key must not be stored", key)
        body = _canonical_xml_payload(encrypted, encryption="aes", key=f" {key} ")
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=body,
            )
        )

        _assert_advanced_error(resp, status=400, code="decrypt_failed", field="encryption")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize("field_name", ["hmac"])
    def test_opsec_rejects_whitespace_padded_xml_hmac_without_writing(
        self,
        temp_dir,
        upload_dir,
        field_name,
    ):
        """XML must not trim an HMAC value before constant-time verification."""
        key = "strict-xml-key"
        encrypted = xor_encrypt(b"padded XML HMAC must not be stored", key)
        hmac_value = compute_hmac(encrypted, key)
        body = (
            "<upload>"
            f"<data>{_b64(encrypted)}</data>"
            "<encoding>base64</encoding>"
            "<encryption>xor</encryption>"
            f"<key>{key}</key>"
            f"<{field_name}> {hmac_value} </{field_name}>"
            "</upload>"
        ).encode()
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=body,
            )
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="hmac")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize("field_name", ["encryption", "key", "hmac", "key_is_base64"])
    def test_opsec_rejects_empty_present_xml_crypto_metadata_without_writing(
        self,
        temp_dir,
        upload_dir,
        field_name,
    ):
        """A self-closing XML crypto element is present metadata, not omission."""
        body = (
            "<upload>"
            f"<data>{_b64(b'empty XML crypto metadata')}</data>"
            "<encoding>base64</encoding>"
            f"<{field_name}/>"
            "</upload>"
        ).encode()
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/xml"},
                body=body,
            )
        )

        assert resp.status_code == 400
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize("carrier", ["headers", "chunked-headers"])
    @pytest.mark.parametrize("key_is_base64_value", ["true"])
    def test_opsec_header_transport_uses_shared_key_is_base64_true_vocabulary(
        self,
        temp_dir,
        upload_dir,
        carrier,
        key_is_base64_value,
    ):
        """Header direct/chunk carriers accept exact string true for key_is_base64."""
        original = b"shared header key-is-base64 vocabulary"
        key = "strict-key-base64-key"
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            headers=_canonical_headers(
                xor_encrypt(original, key),
                name=f"{carrier}-key-base64.bin",
                encryption="xor",
                key=_b64(key.encode()),
                key_is_base64=key_is_base64_value,
                chunks=carrier == "chunked-headers",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name=f"{carrier}-key-base64.bin",
            payload=original,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
            encryption="xor",
        )

    @pytest.mark.parametrize("carrier", ["form", "query", "cookies"])
    @pytest.mark.parametrize(
        ("key_is_base64_value", "key_is_base64"),
        [
            ("true", True),
            ("false", False),
        ],
    )
    def test_opsec_string_carriers_accept_exact_key_is_base64_vocabulary(
        self,
        temp_dir,
        upload_dir,
        carrier,
        key_is_base64_value,
        key_is_base64,
    ):
        """Form, query, and cookie carriers accept only exact true/false strings."""
        original = b"shared string carrier key-is-base64 vocabulary"
        key = "strict-key-base64-key"
        encrypted = xor_encrypt(original, key)
        key_field = _b64(key.encode()) if key_is_base64 else key
        if carrier == "form":
            req = _advanced_request(
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=_canonical_form_payload(
                    encrypted,
                    name="form-key-base64.bin",
                    encryption="xor",
                    key=key_field,
                    key_is_base64=key_is_base64_value,
                ),
            )
            name = "form-key-base64.bin"
        elif carrier == "query":
            req = _advanced_request(
                path=_canonical_query(
                    encrypted,
                    name="query-key-base64.bin",
                    encryption="xor",
                    key=key_field,
                    key_is_base64=key_is_base64_value,
                )
            )
            name = "query-key-base64.bin"
        else:
            req = _advanced_request(
                headers=_canonical_cookie_header(
                    encrypted,
                    name="cookie-key-base64.bin",
                    encryption="xor",
                    key=key_field,
                    key_is_base64=key_is_base64_value,
                )
            )
            name = "cookie-key-base64.bin"
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name=name,
            payload=original,
            profile="form" if carrier == "form" else carrier,
            carrier="body" if carrier == "form" else carrier,
            filename_source="body"
            if carrier == "form"
            else "query"
            if carrier == "query"
            else "cookie",
            request_body_size=len(req.body) if carrier == "form" else 0,
            encoding="base64",
            encryption="xor",
        )

    @pytest.mark.parametrize(
        "key_is_base64_value",
        [
            "maybe",
            "1",
            "0",
            "yes",
            "no",
            "on",
            "off",
            "TRUE",
            "FALSE",
            " true",
            "false ",
        ],
        ids=[
            "unknown-string",
            "one",
            "zero",
            "yes",
            "no",
            "on",
            "off",
            "uppercase-true",
            "uppercase-false",
            "leading-whitespace",
            "trailing-whitespace",
        ],
    )
    def test_opsec_rejects_invalid_json_key_is_base64_without_writing(
        self,
        temp_dir,
        upload_dir,
        key_is_base64_value,
    ):
        """Malformed string key_is_base64 metadata never reaches the publish boundary."""
        original = b"invalid JSON key-is-base64 must not be stored"
        key = "strict-key-base64-key"
        encrypted = xor_encrypt(original, key)
        body = json.dumps(
            {
                "data": _b64(encrypted),
                "encoding": "base64",
                "encryption": "xor",
                "key": _b64(key.encode()),
                "key_is_base64": key_is_base64_value,
            }
        ).encode()
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers={"Content-Type": "application/json"},
                body=body,
            )
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key_is_base64")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize(
        "carrier",
        ["form", "query", "cookies", "headers", "chunked-headers"],
    )
    def test_opsec_rejects_invalid_key_is_base64_from_shared_string_field_paths(
        self,
        temp_dir,
        upload_dir,
        carrier,
    ):
        """String carriers share the same fail-closed key_is_base64 field parser."""
        key = "strict-key-base64-key"
        encrypted = xor_encrypt(b"invalid carrier key-is-base64", key)
        if carrier == "form":
            req = _advanced_request(
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=_canonical_form_payload(
                    encrypted,
                    encryption="xor",
                    key=_b64(key.encode()),
                    key_is_base64="maybe",
                ),
            )
        elif carrier == "query":
            req = _advanced_request(
                path=_canonical_query(
                    encrypted,
                    encryption="xor",
                    key=_b64(key.encode()),
                    key_is_base64="maybe",
                )
            )
        elif carrier == "cookies":
            req = _advanced_request(
                headers=_canonical_cookie_header(
                    encrypted,
                    encryption="xor",
                    key=_b64(key.encode()),
                    key_is_base64="maybe",
                )
            )
        elif carrier == "headers":
            req = _advanced_request(
                headers=_canonical_headers(
                    encrypted,
                    encryption="xor",
                    key=_b64(key.encode()),
                    key_is_base64="maybe",
                )
            )
        else:
            req = _advanced_request(
                headers=_canonical_headers(
                    encrypted,
                    encryption="xor",
                    key=_b64(key.encode()),
                    key_is_base64="maybe",
                    chunks=True,
                )
            )
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key_is_base64")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize("carrier", ["headers", "chunked-headers"])
    @pytest.mark.parametrize("key_is_base64_value", ["false"])
    def test_opsec_header_false_key_is_base64_without_key_rejects(
        self,
        temp_dir,
        upload_dir,
        carrier,
        key_is_base64_value,
    ):
        """Even exact false key_is_base64 is invalid when no key is present."""
        original = b"false key-is-base64 without a key"
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers=_canonical_headers(
                    original,
                    key_is_base64=key_is_base64_value,
                    chunks=carrier == "chunked-headers",
                )
            )
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key_is_base64")
        assert list(upload_dir.iterdir()) == []

    @pytest.mark.parametrize("carrier", ["headers", "chunked-headers"])
    @pytest.mark.parametrize("key_is_base64_value", ["true"])
    def test_opsec_header_true_key_is_base64_requires_a_key_without_writing(
        self,
        temp_dir,
        upload_dir,
        carrier,
        key_is_base64_value,
    ):
        """Exact true without key metadata fails closed for every header shape."""
        srv = StubServer(temp_dir, upload_dir, opsec=True)

        resp = srv.handle_advanced_upload(
            _advanced_request(
                headers=_canonical_headers(
                    b"true key-is-base64 without a key",
                    key_is_base64=key_is_base64_value,
                    chunks=carrier == "chunked-headers",
                )
            )
        )

        _assert_advanced_error(resp, status=400, code="invalid_field", field="key_is_base64")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_verifies_hmac_over_ciphertext_before_aes_decrypt(
        self,
        temp_dir,
        upload_dir,
        monkeypatch,
    ):
        """A bad ciphertext HMAC wins over AES decrypt and prevents all writes."""
        from xferry.handlers import advanced_upload as advanced_upload_module

        def fail_decrypt(_data: bytes, _key: str) -> bytes | None:
            pytest.fail("AES decrypt must not run after HMAC mismatch")

        monkeypatch.setattr(advanced_upload_module, "decrypt", fail_decrypt)
        wire = aes_encrypt(b"hmac order", "correct horse battery staple")
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            headers=_canonical_headers(
                wire,
                name="hmac-order.bin",
                encryption="aes",
                key="correct horse battery staple",
                hmac_value="0" * 64,
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_error(resp, status=400, code="hmac_mismatch", field="hmac")
        assert list(upload_dir.iterdir()) == []

    def test_opsec_fixed_xor_vector_decrypts_with_sha256_derived_key(
        self,
        temp_dir,
        upload_dir,
    ):
        """The handler consumes the same literal SHA-derived XOR wire as browsers."""
        ciphertext = bytes.fromhex("9cfdae6dccb0bd569f3dbd28e9c4438bb5ff4c7b8865d461453c")
        plaintext = bytes.fromhex("58466572727920332064657465726d696e697374696320e29c93")
        srv = StubServer(temp_dir, upload_dir, opsec=True)
        req = _advanced_request(
            headers=_canonical_headers(
                ciphertext,
                name="fixed-xor.bin",
                encryption="xor",
                key="correct horse battery staple",
            )
        )

        resp = srv.handle_advanced_upload(req)

        _assert_advanced_success(
            resp,
            upload_dir,
            name="fixed-xor.bin",
            payload=plaintext,
            profile="header",
            carrier="headers",
            filename_source="header",
            request_body_size=0,
            encoding="base64",
            encryption="xor",
        )
