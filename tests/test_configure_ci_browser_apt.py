"""Runner mirror configuration uses fake apt roots without invoking apt."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.configure_ci_browser_apt import configure, main

AZURE = b"http://azure.archive.ubuntu.com/ubuntu"
ARCHIVE = b"https://archive.ubuntu.com/ubuntu"


@pytest.mark.parametrize("scheme", [b"http", b"https"])
@pytest.mark.parametrize("relative", ["apt-mirrors.txt", "apt-mirrors-security.txt"])
def test_runner_mirror_lists_are_rewritten_without_changing_other_entries(
    tmp_path: Path, scheme: bytes, relative: str
) -> None:
    mirror = scheme + b"://azure.archive.ubuntu.com/ubuntu"
    source = tmp_path / relative
    source.write_bytes(mirror + b"/\tpriority:1\r\nhttps://security.ubuntu.com/ubuntu\n")
    source.chmod(0o640)

    assert configure(tmp_path) == (source,)

    assert source.read_bytes() == ARCHIVE + b"/\tpriority:1\r\nhttps://security.ubuntu.com/ubuntu\n"
    assert source.stat().st_mode & 0o777 == 0o640
    assert configure(tmp_path) == ()


def test_direct_deb822_source_preserves_signing_suites_and_components(tmp_path: Path) -> None:
    source = tmp_path / "sources.list.d/ubuntu.sources"
    source.parent.mkdir()
    original = (
        b"Types: deb\n"
        b"URIs: " + AZURE + b" https://security.ubuntu.com/ubuntu\n"
        b"Suites: noble noble-updates noble-backports\n"
        b"Components: main restricted universe multiverse\n"
        b"Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
    )
    source.write_bytes(original)

    assert configure(tmp_path) == (source,)

    assert source.read_bytes() == original.replace(AZURE, ARCHIVE)


def test_mirror_file_deb822_source_stays_intact_while_actual_mirror_is_updated(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sources.list.d/ubuntu.sources"
    source.parent.mkdir()
    original = (
        b"Types: deb\n"
        b"URIs: mirror+file:/etc/apt/apt-mirrors.txt\n"
        b"Suites: noble noble-updates\n"
        b"Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
        b"\nTypes: deb\n"
        b"URIs: mirror+file:/etc/apt/apt-mirrors-security.txt\n"
        b"Suites: noble-security\n"
        b"Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
    )
    source.write_bytes(original)
    archive_list = tmp_path / "apt-mirrors.txt"
    security_list = tmp_path / "apt-mirrors-security.txt"
    archive_list.write_bytes(AZURE + b"\n")
    security_list.write_bytes(AZURE + b"/\n")

    assert configure(tmp_path) == (archive_list, security_list)

    assert source.read_bytes() == original
    assert archive_list.read_bytes() == ARCHIVE + b"\n"
    assert security_list.read_bytes() == ARCHIVE + b"/\n"


def test_legacy_sources_list_preserves_comments_options_and_private_repositories(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sources.list"
    original = (
        b"# Previous mirror: " + AZURE + b"\n"
        b"deb [signed-by=/keyring.gpg arch=amd64] " + AZURE + b" noble main\n"
        b"deb-src https://azure.archive.ubuntu.com/ubuntu/ noble universe # source packages\n"
        b"deb https://private.example.test/ubuntu noble private # " + AZURE + b"\n"
    )
    source.write_bytes(original)
    private = tmp_path / "sources.list.d/private.sources"
    private.parent.mkdir()
    private.write_bytes(b"URIs: " + AZURE + b"\nSuites: custom\n")

    assert configure(tmp_path) == (source,)

    assert source.read_bytes() == (
        b"# Previous mirror: " + AZURE + b"\n"
        b"deb [signed-by=/keyring.gpg arch=amd64] " + ARCHIVE + b" noble main\n"
        b"deb-src " + ARCHIVE + b"/ noble universe # source packages\n"
        b"deb https://private.example.test/ubuntu noble private # " + AZURE + b"\n"
    )
    assert private.read_bytes() == b"URIs: " + AZURE + b"\nSuites: custom\n"


@pytest.mark.parametrize(
    "url",
    [
        b"https://azure.archive.ubuntu.com/ubuntu-private",
        b"https://azure.archive.ubuntu.com/ubuntu/packages",
        b"https://azure.archive.ubuntu.com/ubuntu?token=private",
        b"https://azure.archive.ubuntu.com/ubuntu#private",
        b"https://azure.archive.ubuntu.com.example.test/ubuntu",
        b"https://user@azure.archive.ubuntu.com/ubuntu",
    ],
)
def test_only_the_exact_public_azure_ubuntu_url_is_rewritten(tmp_path: Path, url: bytes) -> None:
    source = tmp_path / "apt-mirrors.txt"
    source.write_bytes(url + b"\n")

    assert configure(tmp_path) == ()
    assert source.read_bytes() == url + b"\n"


def test_absent_sources_are_allowed_without_creating_any_files(tmp_path: Path) -> None:
    assert configure(tmp_path) == ()
    assert list(tmp_path.iterdir()) == []


def test_cli_accepts_a_fake_apt_root_and_reports_the_changed_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "apt-mirrors.txt"
    source.write_bytes(AZURE)

    assert main(["--apt-root", str(tmp_path)]) == 0

    assert source.read_bytes() == ARCHIVE
    assert str(source) in capsys.readouterr().out
