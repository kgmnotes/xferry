"""Tests for path traversal prefix attack prevention.

Verifies that get_safe_path() correctly blocks paths like
'/uploads_evil/foo' that could bypass a naive str.startswith()
check but are caught by Path.relative_to().
"""

from pathlib import Path

import pytest

from xferry.http.utils import get_safe_path, resolve_descendant_path


class TestPathTraversalPrefixAttack:
    """Verify that directory-name prefix attacks are blocked."""

    def test_uploads_evil_blocked(self, tmp_path: Path):
        """'uploads_evil' should not be treated as inside 'uploads'."""
        base = tmp_path / "root"
        base.mkdir()
        sandbox = base / "uploads"
        sandbox.mkdir()

        # Create an evil sibling directory
        evil = base / "uploads_evil"
        evil.mkdir()
        (evil / "secret.txt").write_text("stolen")

        # Attempt to access uploads_evil/secret.txt via sandbox
        result = get_safe_path(
            "/uploads/../../uploads_evil/secret.txt",
            base,
            sandbox_dir=sandbox,
        )
        assert result is None

    def test_base_dir_prefix_attack(self, tmp_path: Path):
        """Base dir prefix attack: '/srv/data_evil' vs '/srv/data'."""
        base = tmp_path / "data"
        base.mkdir()
        evil = tmp_path / "data_evil"
        evil.mkdir()
        (evil / "secret.txt").write_text("stolen")

        result = get_safe_path("/../data_evil/secret.txt", base)
        assert result is None

    def test_valid_path_inside_sandbox(self, tmp_path: Path):
        """Normal file inside sandbox should resolve correctly."""
        base = tmp_path / "root"
        base.mkdir()
        sandbox = base / "uploads"
        sandbox.mkdir()
        (sandbox / "legit.txt").write_text("ok")

        result = get_safe_path("/uploads/legit.txt", base, sandbox_dir=sandbox)
        assert result is not None
        assert result.name == "legit.txt"

    def test_valid_path_inside_base(self, tmp_path: Path):
        """Normal file inside base dir should resolve correctly."""
        base = tmp_path / "root"
        base.mkdir()
        (base / "index.html").write_text("ok")

        result = get_safe_path("/index.html", base)
        assert result is not None
        assert result.name == "index.html"

    def test_dot_dot_escape_from_sandbox(self, tmp_path: Path):
        """../../../etc/passwd from sandbox should be blocked."""
        base = tmp_path / "root"
        base.mkdir()
        sandbox = base / "uploads"
        sandbox.mkdir()

        result = get_safe_path(
            "/uploads/../../../etc/passwd",
            base,
            sandbox_dir=sandbox,
        )
        assert result is None

    def test_relative_to_catches_prefix_mismatch(self, tmp_path: Path):
        """Verify that relative_to() handles the prefix-match edge case.

        With str.startswith(), '/srv/uploads' is a prefix of
        '/srv/uploads_evil'. Path.relative_to() correctly raises
        ValueError because 'uploads_evil' is not under 'uploads'.
        """
        uploads = tmp_path / "uploads"
        uploads.mkdir()
        evil = tmp_path / "uploads_evil"
        evil.mkdir()

        # Direct Path.relative_to check (the mechanism get_safe_path uses)
        evil_file = evil / "foo.txt"
        with pytest.raises(ValueError):
            evil_file.relative_to(uploads)


class TestResolveDescendantPath:
    """Verify the shared descendant resolver keeps handler policy intact."""

    def test_blocks_traversal(self, tmp_path: Path):
        base = tmp_path / "root"
        base.mkdir()

        result = resolve_descendant_path("../etc/passwd", base)
        assert result is None

    def test_optionally_blocks_symlink_targets(self, tmp_path: Path):
        base = tmp_path / "root"
        base.mkdir()
        target = base / "real.txt"
        target.write_text("ok")
        link = base / "alias.txt"

        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlink")

        assert resolve_descendant_path("alias.txt", base) == target.resolve()
        assert resolve_descendant_path("alias.txt", base, block_symlinks=True) is None
