"""Tests for server method routing and advanced upload routing (B44)."""

import fnmatch
import json
import subprocess
import threading
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

import pytest

from xferry.features import registry_methods
from xferry.handlers import HandlerMixin
from xferry.handlers.base import get_package_resource
from xferry.http import HTTPRequest, HTTPResponse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


class LocalStaticAssetParser(HTMLParser):
    """Collect local static script and stylesheet references from bundled HTML."""

    def __init__(self):
        super().__init__()
        self.asset_paths: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        url: str | None = None
        if tag == "script":
            url = attr_map.get("src")
        elif tag == "link":
            rel_tokens = set((attr_map.get("rel") or "").lower().split())
            if "stylesheet" in rel_tokens:
                url = attr_map.get("href")

        if url and url.startswith("/") and not url.startswith("//"):
            self.asset_paths.append(url.lstrip("/"))


class StubServer(HandlerMixin):
    """Minimal server stub for routing tests."""

    def __init__(self, root_dir: Path, upload_dir: Path):
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self.cors_origin = None
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()
        self._notes_lock = threading.Lock()
        self._ecdh_manager = None
        self.method_handlers = self.build_method_handlers()

    def get_metrics(self):
        return {
            "uptime_seconds": 0,
            "total_requests": 0,
            "total_errors": 0,
            "client_errors": 0,
            "server_errors": 0,
            "bytes_sent": 0,
            "status_counts": {},
        }


def _make_request(
    method: str, path: str = "/", body: bytes = b"", headers: dict[str, str] | None = None
) -> HTTPRequest:
    lines = [f"{method} {path} HTTP/1.1"]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    raw = "\r\n".join(lines).encode() + b"\r\n\r\n" + body
    return HTTPRequest(raw)


def _index_local_static_resource_paths() -> list[str]:
    index_path = get_package_resource("index.html")
    assert index_path is not None

    parser = LocalStaticAssetParser()
    parser.feed(index_path.read_text(encoding="utf-8"))
    return list(dict.fromkeys(parser.asset_paths))


def _xferry_package_data_patterns() -> list[str]:
    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject_path.open("rb") as pyproject_file:
        pyproject = tomllib.load(pyproject_file)

    patterns = pyproject["tool"]["setuptools"]["package-data"]["xferry"]
    assert isinstance(patterns, list)
    return [str(pattern) for pattern in patterns]


def _resource_is_tracked_or_pending_rename(repo_root: Path, source_path: Path) -> bool:
    """Accept tracked assets or byte-identical unstaged moves from ``src/data``."""
    source_file = repo_root / source_path
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", str(source_path)],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if tracked.returncode == 0:
        return True

    legacy_path = Path("src") / source_path.relative_to("xferry")
    legacy_blob = subprocess.run(
        ["git", "show", f":{legacy_path}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    return (
        legacy_blob.returncode == 0
        and not (repo_root / legacy_path).exists()
        and source_file.read_bytes() == legacy_blob.stdout
    )


def test_pending_rename_tracking_fallback_requires_exact_deleted_legacy_asset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only an exact, deleted legacy asset may stand in for Git tracking."""
    monkeypatch.delenv("GIT_INDEX_FILE", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)

    legacy = repo / "src/data/static/ui/app.js"
    legacy.parent.mkdir(parents=True)
    legacy.write_bytes(b"canonical")
    subprocess.run(["git", "add", str(legacy.relative_to(repo))], cwd=repo, check=True)

    legacy.unlink()
    moved_path = Path("xferry/data/static/ui/app.js")
    moved = repo / moved_path
    moved.parent.mkdir(parents=True)
    moved.write_bytes(b"canonical")

    assert _resource_is_tracked_or_pending_rename(repo, moved_path)

    moved.write_bytes(b"changed")
    assert not _resource_is_tracked_or_pending_rename(repo, moved_path)

    rogue_path = Path("xferry/data/static/ui/rogue.js")
    rogue = repo / rogue_path
    rogue.write_bytes(b"rogue")
    assert not _resource_is_tracked_or_pending_rename(repo, rogue_path)


@pytest.fixture
def temp_dir():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "index.html").write_text("<html>test</html>")
        yield p


@pytest.fixture
def upload_dir(temp_dir):
    u = temp_dir / "uploads"
    u.mkdir()
    return u


@pytest.fixture
def server(temp_dir, upload_dir):
    return StubServer(temp_dir, upload_dir)


class TestMethodRouting:
    """Test that standard method_handlers dispatch is correct."""

    def test_all_standard_methods_registered(self, server):
        expected = set(registry_methods())
        assert set(server.method_handlers.keys()) == expected

    def test_get_handler_callable(self, server):
        handler = server.method_handlers["GET"]
        req = _make_request("GET", "/")
        resp = handler(req)
        assert isinstance(resp, HTTPResponse)
        assert resp.status_code == 200

    def test_info_handler_for_root(self, server, temp_dir):
        handler = server.method_handlers["INFO"]
        req = _make_request("INFO", "/")
        resp = handler(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert set(data) == {"entry", "page", "contents"}
        assert data["entry"]["kind"] == "directory"

    def test_unknown_method_not_in_handlers(self, server):
        assert server.method_handlers.get("CONNECT") is None

    def test_post_delegates_to_none(self, server):
        """POST should delegate to handle_none (upload)."""
        assert server.method_handlers["POST"] == server.handle_post
        req = _make_request("POST", "/", body=b"data", headers={"X-File-Name": "test.bin"})
        resp = server.handle_post(req)
        assert resp.status_code == 201

    def test_put_is_none(self, server):
        """PUT should be handle_none."""
        assert server.method_handlers["PUT"] == server.handle_none


class TestStaticResourceRouting:
    """Test bundled static asset routing."""

    def test_valid_static_asset_serves(self, server):
        req = _make_request("GET", "/static/ui/app.js")
        resp = server.handle_get(req)

        assert resp.status_code == 200
        assert resp.stream_path is not None
        assert resp.stream_path.name == "app.js"

    def test_inspector_static_asset_serves(self, server):
        req = _make_request("GET", "/static/ui/inspector.js")
        resp = server.handle_get(req)

        assert resp.status_code == 200
        assert resp.stream_path is not None
        assert resp.stream_path.name == "inspector.js"

    def test_index_local_script_references_resolve(self):
        missing = [
            resource_path
            for resource_path in _index_local_static_resource_paths()
            if get_package_resource(resource_path) is None
        ]

        assert missing == []

    def test_index_local_script_references_match_package_data(self):
        patterns = _xferry_package_data_patterns()
        missing = [
            f"data/{resource_path}"
            for resource_path in _index_local_static_resource_paths()
            if not any(
                fnmatch.fnmatchcase(f"data/{resource_path}", pattern) for pattern in patterns
            )
        ]

        assert missing == []

    def test_index_local_script_references_are_tracked(self):
        repo_root = Path(__file__).resolve().parents[1]
        if not (repo_root / ".git").exists():
            pytest.skip("Git tracking check requires a repository checkout")

        missing = []
        for resource_path in _index_local_static_resource_paths():
            source_path = Path("xferry/data") / resource_path
            if not (repo_root / source_path).is_file():
                missing.append(str(source_path))
                continue
            if not _resource_is_tracked_or_pending_rename(repo_root, source_path):
                missing.append(str(source_path))

        assert missing == []

    def test_static_raw_traversal_returns_not_found(self, server):
        req = _make_request("GET", "/static/../../server.py")
        resp = server.handle_get(req)

        assert resp.status_code == 404
        assert resp.stream_path is None

    def test_static_encoded_traversal_returns_not_found(self, server):
        req = _make_request("GET", "/static/%2e%2e/%2e%2e/server.py")
        resp = server.handle_get(req)

        assert resp.status_code == 404
        assert resp.stream_path is None


class TestAdvancedUploadRouting:
    """Test headerless requests do not select Advanced by payload sniffing."""

    def test_standard_get_still_works(self, server):
        req = _make_request("GET", "/")
        resp = server.handle_get(req)
        assert resp.status_code == 200

    @pytest.mark.parametrize(
        ("path", "headers", "body"),
        [
            ("/?d=dGVzdA", {}, b""),
            ("/", {"X-D": "dGVzdA=="}, b""),
            ("/", {"Cookie": "xf_d=dGVzdA==; xf_encoding=base64url"}, b""),
            ("/x/dGVzdA?path_payload=1&encoding=base64url", {}, b""),
            ("/", {}, b'{"d":"dGVzdA==","n":"sniffed.txt"}'),
        ],
    )
    def test_unknown_method_with_legacy_payload_markers_is_method_not_allowed(
        self,
        server,
        path,
        headers,
        body,
    ):
        req = _make_request("RANDOMMETHOD", path, headers=headers, body=body)
        resp = server._dispatch_handler(req)

        assert resp.status_code == 405


class TestSmuggleHandler:
    """Test SMUGGLE handler (creates temp HTML files)."""

    def test_smuggle_missing_file(self, server):
        req = _make_request("SMUGGLE", "/uploads/nonexistent.bin")
        resp = server.handle_smuggle(req)
        assert resp.status_code == 404

    def test_smuggle_creates_temp_html(self, server, upload_dir):
        (upload_dir / "secret.txt").write_bytes(b"secret data")
        req = _make_request("SMUGGLE", "/uploads/secret.txt")
        resp = server.handle_smuggle(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["artifact"]["url"].startswith("/uploads/smuggle_")
        assert data["source"]["name"] == "secret.txt"
        # Temp file should be registered
        assert len(server._temp_smuggle_files) == 1

    def test_smuggle_constructor_query_creates_requested_artifact_format(self, server, upload_dir):
        (upload_dir / "secret.txt").write_bytes(b"secret data")
        req = _make_request(
            "SMUGGLE",
            "/uploads/secret.txt?"
            "mode=constructor&download_name=Quarterly%20Report&download_ext=pdf&"
            "payload_encoding=hex&trigger_method=img&trigger_event=onerror&"
            "output_format=svg&download_variant=data-uri&page_template=corporate&"
            "mime_type=application/pdf&null_byte=1",
        )

        resp = server.handle_smuggle(req)

        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["artifact"]["url"].startswith("/uploads/smuggle_")
        assert data["artifact"]["url"].endswith(".svg")
        assert data["artifact"]["content_type"] == "image/svg+xml; charset=utf-8"
        assert data["download"]["name"] == "Quarterly-Report.pdf"
        assert data["builder"]["output_format"] == "svg"
        assert data["builder"]["payload_encoding"] == "hex"
        assert data["builder"]["trigger_method"] == "img"
        assert data["builder"]["trigger_event"] == "onerror"
        assert data["builder"]["download_variant"] == "data-uri"
        assert data["builder"]["page_template"] == "corporate"
        artifact_path = upload_dir / data["artifact"]["name"]
        content = artifact_path.read_bytes()
        assert content.startswith(b"\x00<?xml")
        javascript_text = unescape(content.decode("utf-8"))
        assert "var mt='application/pdf'" in javascript_text
        assert "l.href='data:'+mt+';base64,'" in javascript_text

    def test_smuggle_rejects_removed_encrypt_parameter(self, server, upload_dir):
        (upload_dir / "secret.txt").write_bytes(b"secret data")
        req = _make_request(
            "SMUGGLE",
            "/uploads/secret.txt?encrypt=1&mode=constructor&payload_encoding=hex",
        )

        resp = server.handle_smuggle(req)

        assert resp.status_code == 400
        data = json.loads(resp.body)
        assert data["error"]["code"] == "unknown_smuggle_parameter"
        assert data["error"]["field"] == "encrypt"
        assert server._temp_smuggle_files == set()

    def test_smuggle_with_encryption(self, server, upload_dir):
        (upload_dir / "enc.bin").write_bytes(b"\x01\x02\x03")
        req = _make_request("SMUGGLE", "/uploads/enc.bin?encryption=xor")
        resp = server.handle_smuggle(req)
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["builder"]["encryption"] == "xor"


class TestResponseHeaders:
    """Test response header correctness."""

    def test_cors_headers_disabled_by_default(self, server):
        req = _make_request("GET", "/")
        resp = server.handle_get(req)
        built = resp.build()
        assert b"Access-Control-Allow-Origin" not in built

    def test_cors_headers_when_enabled(self, server):
        req = _make_request("GET", "/")
        resp = server.handle_get(req)
        built = resp.build(cors_origin="https://app.example")
        assert b"Access-Control-Allow-Origin: https://app.example" in built

    def test_cors_exposes_file_headers(self, server):
        req = _make_request("GET", "/")
        resp = server.handle_get(req)
        built = resp.build(cors_origin="https://app.example")
        assert b"Server: XFerry/" in built
        assert b"Access-Control-Expose-Headers" in built

    def test_csp_on_html(self, server):
        req = _make_request("GET", "/")
        resp = server.handle_get(req)
        csp = resp.headers["Content-Security-Policy"]

        assert "script-src 'self'" in csp
        assert "style-src 'self' 'unsafe-inline'" in csp
        assert "connect-src 'self' ws: wss:" in csp
        assert "base-uri 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "script-src 'self' 'unsafe-inline'" not in csp
