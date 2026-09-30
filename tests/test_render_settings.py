"""Mutation and idempotence tests for generated settings samples."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import render_settings
from xferry.settings import load_settings_text

EXPECTED_PROFILE_VALUES = {
    "docker": {
        "port": 8443,
        "root_dir": "/data",
        "auth_file": "/run/secrets/xferry_auth",
        "acme_http_port": 8080,
    },
    "systemd": {
        "port": 443,
        "root_dir": "/var/lib/xferry",
        "auth_file": "/etc/xferry/auth",
        "acme_http_port": 80,
    },
}


def _marked(profile: str, body: bytes = b"stale = true\n") -> bytes:
    return (
        b"human preamble\n"
        + render_settings.start_marker(profile)
        + b"\n"
        + body
        + render_settings.end_marker(profile)
        + b"\nhuman suffix\n"
    )


def _seed_targets(root: Path, body: bytes = b"stale = true\n") -> None:
    for target in render_settings.TARGETS:
        path = root / target.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_marked(target.profile, body))


def _generated_body(document: bytes, profile: str) -> bytes:
    start = document.index(render_settings.start_marker(profile))
    start = document.index(b"\n", start) + 1
    end = document.index(render_settings.end_marker(profile))
    return document[start:end]


@pytest.mark.parametrize("argv", ([], ["--check", "--write"]))
def test_cli_requires_exactly_one_explicit_mode(argv: list[str]) -> None:
    with pytest.raises(SystemExit, match="2"):
        render_settings.parse_args(argv)


def test_repository_settings_regions_are_current_and_parseable() -> None:
    assert render_settings.render_all(check=True) == 0

    for target in render_settings.TARGETS:
        document = (render_settings.REPO_ROOT / target.path).read_bytes()
        settings = load_settings_text(_generated_body(document, target.profile).decode("utf-8"))
        expected = EXPECTED_PROFILE_VALUES[target.profile]
        assert settings.public_direct is True
        assert settings.port == expected["port"]
        assert settings.root_dir == expected["root_dir"]
        assert settings.auth_file == expected["auth_file"]
        assert settings.acme_http_port == expected["acme_http_port"]
        assert settings.plugin_allowlist == ()
        assert settings.allowed_hosts == ()
        assert "remote_update" not in document.decode("utf-8").casefold()


def test_replace_generated_region_preserves_every_outside_byte() -> None:
    start = render_settings.start_marker("test")
    end = render_settings.end_marker("test")
    document = b"\xef\xbb\xbfoutside\r\n" + start + b"\r\nold\r\n" + end + b"\r\ntrailer\x00"

    rendered = render_settings.replace_generated_region(
        document,
        b"new = true\n",
        profile="test",
    )

    assert rendered.startswith(b"\xef\xbb\xbfoutside\r\n" + start + b"\r\n")
    assert rendered.endswith(end + b"\r\ntrailer\x00")
    assert b"new = true\n" in rendered


@pytest.mark.parametrize(
    "document",
    (
        b"no markers\n",
        render_settings.start_marker("test") + b"\nbody\n",
        render_settings.end_marker("test") + b"\nbody\n",
        (
            render_settings.start_marker("test")
            + b"\n"
            + render_settings.start_marker("test")
            + b"\n"
            + render_settings.end_marker("test")
            + b"\n"
        ),
        (
            render_settings.end_marker("test")
            + b"\nbody\n"
            + render_settings.start_marker("test")
            + b"\n"
        ),
        (
            render_settings.start_marker("test")
            + b" extra\nbody\n"
            + render_settings.end_marker("test")
            + b"\n"
        ),
        _marked("foreign"),
        (
            render_settings.start_marker("test")
            + b"\n"
            + _marked("nested")
            + render_settings.end_marker("test")
            + b"\n"
        ),
    ),
)
def test_replace_generated_region_fails_closed_for_malformed_markers(
    document: bytes,
) -> None:
    with pytest.raises(render_settings.MarkerError):
        render_settings.replace_generated_region(document, b"generated\n", profile="test")


def test_render_all_detects_drift_writes_and_is_idempotent(tmp_path: Path) -> None:
    _seed_targets(tmp_path)

    assert render_settings.render_all(check=True, repo_root=tmp_path) == 1
    assert render_settings.render_all(check=False, repo_root=tmp_path) == 0
    first = {
        target.path: (tmp_path / target.path).read_bytes() for target in render_settings.TARGETS
    }
    assert render_settings.render_all(check=True, repo_root=tmp_path) == 0
    assert render_settings.render_all(check=False, repo_root=tmp_path) == 0
    second = {
        target.path: (tmp_path / target.path).read_bytes() for target in render_settings.TARGETS
    }

    assert first == second
    assert all(document.startswith(b"human preamble\n") for document in second.values())
    assert all(document.endswith(b"human suffix\n") for document in second.values())


def test_render_all_refuses_to_write_any_malformed_target(tmp_path: Path) -> None:
    _seed_targets(tmp_path)
    first = tmp_path / render_settings.TARGETS[0].path
    first_original = first.read_bytes()
    malformed = tmp_path / render_settings.TARGETS[-1].path
    original = b"human document without markers\n"
    malformed.write_bytes(original)

    assert render_settings.render_all(check=False, repo_root=tmp_path) == 2
    assert first.read_bytes() == first_original
    assert malformed.read_bytes() == original
