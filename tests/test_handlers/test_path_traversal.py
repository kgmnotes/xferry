"""Tests for path traversal protection (B26)."""

import threading
from pathlib import Path

import pytest

from xferry.handlers.base import BaseHandler, get_package_resource


class ConcreteHandler(BaseHandler):
    """Concrete handler for testing BaseHandler methods."""

    def __init__(self, root_dir: Path, upload_dir: Path, sandbox: bool = False):
        self.root_dir = root_dir
        self.upload_dir = upload_dir
        self.notes_dir = root_dir / "notes"
        self.method_handlers = {}
        self.sandbox_mode = sandbox
        self.opsec_mode = False
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()


@pytest.fixture
def handler(temp_dir, upload_dir):
    """Non-sandbox handler."""
    return ConcreteHandler(temp_dir, upload_dir, sandbox=False)


@pytest.fixture
def sandbox_handler(temp_dir, upload_dir):
    """Sandbox handler."""
    return ConcreteHandler(temp_dir, upload_dir, sandbox=True)


class TestPathTraversalBlocking:
    """Verify _get_file_path blocks directory traversal attempts."""

    def test_dot_dot_slash(self, handler):
        result = handler._get_file_path("/../../../etc/passwd")
        assert result is None

    def test_dot_dot_encoded(self, handler):
        # URL decoding happens in HTTPRequest, so test with decoded path
        result = handler._get_file_path("/../etc/passwd")
        assert result is None

    def test_dot_dot_double(self, handler):
        result = handler._get_file_path("/../../etc/shadow")
        assert result is None

    def test_deep_traversal(self, handler):
        result = handler._get_file_path("/a/b/c/../../../../etc/hosts")
        assert result is None

    def test_valid_path_resolves(self, handler, temp_dir):
        (temp_dir / "hello.txt").write_text("hi")
        result = handler._get_file_path("/hello.txt")
        assert result is not None
        assert result.name == "hello.txt"

    def test_root_redirects_to_index(self, handler):
        result = handler._get_file_path("/")
        assert result is not None
        assert result.name == "index.html"


class TestPackageStaticResourceTraversal:
    """Verify bundled static resource lookup blocks traversal."""

    def test_static_resource_blocks_raw_traversal(self):
        result = get_package_resource("static/../../server.py")
        assert result is None

    def test_static_resource_blocks_url_encoded_traversal(self):
        result = get_package_resource("static/%2e%2e/%2e%2e/server.py")
        assert result is None

    def test_static_resource_blocks_encoded_separator_traversal(self):
        result = get_package_resource("static%2f..%2f..%2fserver.py")
        assert result is None

    def test_static_resource_blocks_platform_separator_traversal(self):
        result = get_package_resource("static%5c..%5c..%5cserver.py")
        assert result is None

    def test_static_resource_blocks_windows_drive_segment(self):
        result = get_package_resource("static/C:/server.py")
        assert result is None

    def test_valid_static_resource_resolves(self):
        result = get_package_resource("static/ui/app.js")
        assert result is not None
        assert result.name == "app.js"


class TestSandboxPathTraversal:
    """Verify sandbox mode restricts to upload_dir."""

    def test_sandbox_blocks_traversal_out_of_uploads(self, sandbox_handler):
        result = sandbox_handler._get_file_path("/../secret.txt", for_sandbox=True)
        assert result is None

    def test_sandbox_allows_uploads_file(self, sandbox_handler, upload_dir):
        (upload_dir / "test.txt").write_text("data")
        result = sandbox_handler._get_file_path("/uploads/test.txt", for_sandbox=True)
        assert result is not None
        assert result.name == "test.txt"

    def test_sandbox_strips_uploads_prefix(self, sandbox_handler, upload_dir):
        (upload_dir / "file.bin").write_bytes(b"\x00")
        result = sandbox_handler._get_file_path("/uploads/file.bin", for_sandbox=True)
        assert result is not None
        assert result.parent == upload_dir

    def test_sandbox_blocks_dot_dot_in_uploads(self, sandbox_handler):
        result = sandbox_handler._get_file_path(
            "/uploads/../../../etc/passwd",
            for_sandbox=True,
        )
        assert result is None


class TestResolveSafePath:
    """Test the centralized _resolve_safe_path method."""

    def test_valid_path(self, handler, temp_dir):
        (temp_dir / "ok.txt").write_text("ok")
        result = handler._resolve_safe_path("ok.txt", temp_dir)
        assert result is not None
        assert result == (temp_dir / "ok.txt").resolve()

    def test_empty_path_returns_base(self, handler, temp_dir):
        result = handler._resolve_safe_path("", temp_dir)
        assert result == temp_dir.resolve()

    def test_traversal_returns_none(self, handler, temp_dir):
        result = handler._resolve_safe_path("../../../etc/passwd", temp_dir)
        assert result is None

    def test_symlink_outside_blocked(self, handler, temp_dir):
        """Symlink pointing outside base_dir should be blocked."""
        target = Path("/tmp/outside_target")
        link = temp_dir / "evil_link"
        try:
            link.symlink_to(target)
            result = handler._resolve_safe_path("evil_link", temp_dir)
            assert result is None
        except OSError:
            pytest.skip("Cannot create symlink")

    def test_symlink_inside_blocked(self, handler, temp_dir):
        """Even internal symlinks are blocked (defense-in-depth)."""
        target = temp_dir / "real_file.txt"
        target.write_text("data")
        link = temp_dir / "link_to_real"
        try:
            link.symlink_to(target)
            result = handler._resolve_safe_path("link_to_real", temp_dir)
            assert result is None  # all symlinks blocked
        except OSError:
            pytest.skip("Cannot create symlink")


class TestHiddenFiles:
    """Test hidden file protection."""

    def test_hidden_env_file(self, handler):
        assert handler._is_hidden_file("/.env") is True

    def test_hidden_opsec_config(self, handler):
        assert handler._is_hidden_file("/.opsec_config.json") is True

    def test_hidden_upload_segment(self, handler):
        assert handler._is_hidden_file("/uploads/.secret") is True

    def test_normal_file_not_hidden(self, handler):
        assert handler._is_hidden_file("/readme.txt") is False
