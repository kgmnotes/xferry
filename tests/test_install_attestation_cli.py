"""The attestation verifier toolchain is immutable, isolated, and bounded."""

from __future__ import annotations

import gzip
import hashlib
import io
import stat
import subprocess
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from tools import install_attestation_cli as cli


def _tar(members: list[tuple[str, bytes, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, body, kind in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(body) if kind == tarfile.REGTYPE else 0
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = "outside"
            archive.addfile(member, io.BytesIO(body) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


def _payload(architecture: str = "amd64") -> bytes:
    root = f"gh_{cli.VERSION}_linux_{architecture}"
    return gzip.compress(
        _tar(
            [
                (root, b"", tarfile.DIRTYPE),
                (f"{root}/LICENSE", b"license", tarfile.REGTYPE),
                (f"{root}/bin/gh", b"verified cli bytes", tarfile.REGTYPE),
                (f"{root}/share/man/man1/gh.1", b"manual", tarfile.REGTYPE),
            ]
        ),
        mtime=0,
    )


class FakeResponse(io.BytesIO):
    status = 200

    def geturl(self) -> str:
        return "https://release-assets.githubusercontent.com/github-production-release-asset/gh"


class FakeOpener:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, *, timeout: int) -> FakeResponse:
        assert timeout == 30
        self.requests.append(request)
        return FakeResponse(self.payload)


def _fake_host(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    *,
    machine: str = "x86_64",
    size: int | None = None,
    digest: str | None = None,
) -> tuple[FakeOpener, list[dict[str, Any]]]:
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[machine]
    spec = cli.ArchiveSpec(
        architecture,
        len(payload) if size is None else size,
        hashlib.sha256(payload).hexdigest() if digest is None else digest,
    )
    monkeypatch.setattr(cli, "ARCHIVES", {machine: spec})
    monkeypatch.setattr(cli.platform, "system", lambda: "Linux")
    monkeypatch.setattr(cli.platform, "machine", lambda: machine)
    opener = FakeOpener(payload)
    monkeypatch.setattr(cli.urllib.request, "build_opener", lambda *_args: opener)
    commands: list[dict[str, Any]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        commands.append({"argv": argv, **kwargs})
        if argv[1:] == ["--version"]:
            output = f"gh version {cli.VERSION} (2026-10-23)\n".encode()
        else:
            assert argv[1:] == ["attestation", "verify", "--help"]
            output = "\n".join(f"      {flag} value" for flag in cli.REQUIRED_FLAGS).encode()
        return subprocess.CompletedProcess(argv, 0, output)

    monkeypatch.setattr(cli.subprocess, "run", run)
    return opener, commands


@pytest.mark.parametrize("machine,architecture", [("x86_64", "amd64"), ("aarch64", "arm64")])
def test_install_extracts_only_pinned_binary_without_inheriting_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, machine: str, architecture: str
) -> None:
    opener, commands = _fake_host(monkeypatch, _payload(architecture), machine=machine)
    monkeypatch.setenv("GH_TOKEN", "fake-test-token")
    output = tmp_path / "isolated-bin"
    executable = cli.install(output)

    assert executable == output / "gh"
    assert executable.read_bytes() == b"verified cli bytes"
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(executable.stat().st_mode) == 0o700
    assert {path.name for path in output.iterdir()} == {"gh"}
    assert {path.name for path in tmp_path.iterdir()} == {"isolated-bin"}
    assert len(opener.requests) == 1
    request = opener.requests[0]
    assert request.full_url.endswith(f"gh_{cli.VERSION}_linux_{architecture}.tar.gz")
    assert not request.has_header("Authorization")
    assert not request.has_header("Cookie")
    assert len(commands) == 2
    for command in commands:
        assert "GH_TOKEN" not in command["env"]
        assert command["env"]["GH_PROMPT_DISABLED"] == "1"
        assert command["env"]["GH_NO_UPDATE_NOTIFIER"] == "1"
        assert command["env"]["GH_CONFIG_DIR"] != str(Path.home() / ".config/gh")
        assert command["timeout"] == 15


@pytest.mark.parametrize(
    "size_change,digest",
    [(1, None), (-1, None), (0, "0" * 64)],
)
def test_archive_identity_must_match_before_decompression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size_change: int,
    digest: str | None,
) -> None:
    payload = _payload()
    _fake_host(monkeypatch, payload, size=len(payload) + size_change, digest=digest)

    def unexpected_expand(*_args: Any) -> None:
        pytest.fail("unverified archive reached decompression")

    monkeypatch.setattr(cli, "_expand_archive", unexpected_expand)
    with pytest.raises(ValueError, match="pinned size|SHA256"):
        cli.install(tmp_path / "bin")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../outside", tarfile.REGTYPE),
        ("/outside", tarfile.REGTYPE),
        ("wrong-root/bin/gh", tarfile.REGTYPE),
        (f"gh_{cli.VERSION}_linux_amd64/../outside", tarfile.REGTYPE),
        (f"gh_{cli.VERSION}_linux_amd64/bin/gh", tarfile.SYMTYPE),
        (f"gh_{cli.VERSION}_linux_amd64/bin/gh", tarfile.LNKTYPE),
        (f"gh_{cli.VERSION}_linux_amd64/socket", tarfile.FIFOTYPE),
    ],
)
def test_unsafe_archive_members_are_rejected_before_binary_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, kind: bytes
) -> None:
    normal = f"gh_{cli.VERSION}_linux_amd64/bin/gh"
    members = [(name, b"bad", kind)]
    if name != normal:
        members.append((normal, b"binary", tarfile.REGTYPE))
    payload = gzip.compress(_tar(members), mtime=0)
    _opener, commands = _fake_host(monkeypatch, payload)
    with pytest.raises(ValueError, match="unsafe|unsupported"):
        cli.install(tmp_path / "bin")
    assert commands == []
    assert list(tmp_path.iterdir()) == []


def test_duplicate_binary_member_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = f"gh_{cli.VERSION}_linux_amd64/bin/gh"
    payload = gzip.compress(
        _tar([(name, b"one", tarfile.REGTYPE), (name, b"two", tarfile.REGTYPE)]), mtime=0
    )
    _opener, commands = _fake_host(monkeypatch, payload)
    with pytest.raises(ValueError, match="duplicate"):
        cli.install(tmp_path / "bin")
    assert commands == []
    assert list(tmp_path.iterdir()) == []


def test_bounded_expansion_precedes_tar_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_host(monkeypatch, gzip.compress(b"\0" * 1025, mtime=0))
    monkeypatch.setattr(cli, "MAX_UNPACKED_BYTES", 1024)

    def unexpected_tar(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("oversized expansion reached the tar parser")

    monkeypatch.setattr(cli.tarfile, "open", unexpected_tar)
    with pytest.raises(ValueError, match="expansion bound"):
        cli.install(tmp_path / "bin")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("limit_name", ["MAX_MEMBERS", "MAX_BINARY_BYTES"])
def test_member_and_executable_bounds_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit_name: str
) -> None:
    _fake_host(monkeypatch, _payload())
    monkeypatch.setattr(cli, limit_name, 1)
    with pytest.raises(ValueError, match="too many|bounded regular"):
        cli.install(tmp_path / "bin")
    assert list(tmp_path.iterdir()) == []


def test_missing_executable_cannot_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = f"gh_{cli.VERSION}_linux_amd64"
    _fake_host(monkeypatch, gzip.compress(_tar([(root, b"", tarfile.DIRTYPE)]), mtime=0))
    with pytest.raises(ValueError, match="missing its expected executable"):
        cli.install(tmp_path / "bin")


@pytest.mark.parametrize("system,machine", [("Darwin", "arm64"), ("Linux", "ppc64le")])
def test_unsupported_host_fails_before_any_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, system: str, machine: str
) -> None:
    monkeypatch.setattr(cli.platform, "system", lambda: system)
    monkeypatch.setattr(cli.platform, "machine", lambda: machine)
    with pytest.raises(ValueError, match="requires"):
        cli.install(tmp_path / "bin")
    assert list(tmp_path.iterdir()) == []


def test_existing_output_and_symlink_parent_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opener, _commands = _fake_host(monkeypatch, _payload())
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "owner-data"
    marker.write_bytes(b"keep")
    alias = tmp_path / "alias"
    alias.symlink_to(existing, target_is_directory=True)
    for path in (existing, alias / "bin"):
        with pytest.raises(ValueError, match="fresh"):
            cli.install(path)
    assert marker.read_bytes() == b"keep"
    assert opener.requests == []


@pytest.mark.parametrize("version", ["2.103.20", "2.103.1", "2.103.2-malicious"])
def test_version_check_requires_exact_pinned_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    monkeypatch.setattr(cli, "_command", lambda *_args: f"gh version {version}\n".encode())
    with pytest.raises(ValueError, match="pinned version"):
        cli._check_cli(tmp_path / "gh", tmp_path / "config")


def test_missing_source_policy_flags_cannot_be_silently_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def command(_executable: Path, arguments: tuple[str, ...], _config: Path) -> bytes:
        if arguments == ("--version",):
            return f"gh version {cli.VERSION}\n".encode()
        return b"--repo --bundle --signer-workflow\n"

    monkeypatch.setattr(cli, "_command", command)
    with pytest.raises(ValueError, match="required attestation policy flags"):
        cli._check_cli(tmp_path / "gh", tmp_path / "config")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/cli/cli",
        "https://github.com.attacker.example/file",
        "https://github.com@attacker.example/file",
        "https://user:password@github.com/file",
        "https://github.com:444/file",
        "https://github.com/file#fragment",
        "https://github.com/\\attacker",
    ],
)
def test_redirect_cannot_downgrade_or_leave_public_hosts(url: str) -> None:
    request = urllib.request.Request("https://github.com/cli/cli/releases/download/v1/gh.tar.gz")
    with pytest.raises(ValueError, match="allowed public HTTPS"):
        cli._PublicRedirect().redirect_request(request, None, 302, "Found", {}, url)


def test_redirect_remains_anonymous_and_accepts_the_release_cdn() -> None:
    request = urllib.request.Request("https://github.com/cli/cli/releases/download/v1/gh.tar.gz")
    target = "https://release-assets.githubusercontent.com/release/file?signature=public-test"
    redirected = cli._PublicRedirect().redirect_request(request, None, 302, "Found", {}, target)
    assert redirected is not None and redirected.full_url == target
    request.add_header("Authorization", "fake-test-value")
    with pytest.raises(ValueError, match="anonymous"):
        cli._PublicRedirect().redirect_request(request, None, 302, "Found", {}, target)


def test_cli_failure_does_not_print_raw_transport_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(_output_bin: Path) -> Path:
        raise RuntimeError("private transport details")

    monkeypatch.setattr(cli, "install", fail)
    assert cli.main(["--output-bin", str(tmp_path / "bin")]) == 1
    output = capsys.readouterr()
    assert "attestation_cli_install_failed" in output.out
    assert "private transport details" not in output.out + output.err
