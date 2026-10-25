"""Install an isolated, digest-pinned GitHub CLI for attestation verification.

The runner's bundled ``gh`` may be too old for source/ref policies. This helper
downloads one public HTTPS archive, verifies its complete identity, and copies
only its regular ``bin/gh`` member into a fresh private directory. It neither
uses GitHub credentials nor changes a user's PATH or CLI configuration.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

VERSION = "2.103.2"
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_COMMAND_BYTES = 128 * 1024
REQUIRED_FLAGS = (
    "--repo",
    "--bundle",
    "--signer-workflow",
    "--signer-digest",
    "--source-digest",
    "--source-ref",
    "--deny-self-hosted-runners",
    "--cert-oidc-issuer",
    "--format",
)
_PUBLIC_HOSTS = frozenset(
    {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
)


@dataclass(frozen=True)
class ArchiveSpec:
    architecture: str
    size: int
    sha256: str

    @property
    def root(self) -> str:
        return f"gh_{VERSION}_linux_{self.architecture}"

    @property
    def url(self) -> str:
        return f"https://github.com/cli/cli/releases/download/v{VERSION}/{self.root}.tar.gz"


ARCHIVES = {
    "x86_64": ArchiveSpec(
        "amd64",
        15031001,
        "62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8",
    ),
    "aarch64": ArchiveSpec(
        "arm64",
        13660128,
        "4c3e99a50bd8b181a3fe9d69b25dd978bac768148d88f01507c6b4d1ef61a443",
    ),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _public_url(url: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname in _PUBLIC_HOSTS
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and not any(
                ord(character) <= 32 or ord(character) == 127 or character == "\\"
                for character in url
            )
        )
    except ValueError:
        valid = False
    _require(valid, "CLI download must use an allowed public HTTPS endpoint")


class _PublicRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        _public_url(newurl)
        _require(
            not req.has_header("Authorization") and not req.has_header("Cookie"),
            "CLI downloads must remain anonymous",
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download_archive(spec: ArchiveSpec, destination: Path) -> None:
    _public_url(spec.url)
    opener = urllib.request.build_opener(_PublicRedirect())
    request = urllib.request.Request(
        spec.url,
        headers={
            "User-Agent": "xferry-attestation-toolchain",
            "Accept": "application/octet-stream",
        },
    )
    digest = hashlib.sha256()
    count = 0
    deadline = time.monotonic() + 180
    try:
        with opener.open(request, timeout=30) as response, destination.open("xb") as output:
            _public_url(response.geturl())
            _require(response.status == 200, "CLI download did not return HTTP 200")
            while chunk := response.read(min(1024 * 1024, spec.size - count + 1)):
                count += len(chunk)
                _require(count <= spec.size, "CLI archive exceeds its pinned size")
                _require(time.monotonic() <= deadline, "CLI download exceeded its time bound")
                digest.update(chunk)
                output.write(chunk)
    except (urllib.error.URLError, OSError):
        raise ValueError("CLI download failed") from None
    _require(
        count == spec.size and digest.hexdigest() == spec.sha256,
        "CLI archive differs from its pinned size or SHA256",
    )


def _expand_archive(archive: Path, destination: Path) -> None:
    count = 0
    with gzip.open(archive, "rb") as source, destination.open("xb") as output:
        while chunk := source.read(min(1024 * 1024, MAX_UNPACKED_BYTES - count + 1)):
            count += len(chunk)
            _require(count <= MAX_UNPACKED_BYTES, "CLI archive exceeds its expansion bound")
            output.write(chunk)


def _extract_binary(archive: Path, spec: ArchiveSpec, destination: Path) -> None:
    """Inspect every member, copying only the one bounded regular executable."""
    expected = f"{spec.root}/bin/gh"
    seen: set[str] = set()
    executable: tarfile.TarInfo | None = None
    total_size = 0
    with tarfile.open(archive, mode="r:") as source:
        for member in source:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            _require(
                bool(parts)
                and not name.startswith("/")
                and parts[0] == spec.root
                and all(part not in {".", ".."} for part in parts)
                and str(PurePosixPath(name)) == name
                and not any(character in name for character in "\\\x00\r\n")
                and name not in seen,
                "CLI archive has a duplicate or unsafe member path",
            )
            seen.add(name)
            _require(len(seen) <= MAX_MEMBERS, "CLI archive has too many members")
            _require(
                (member.isfile() or member.isdir()) and not member.issparse(),
                "CLI archive contains a link or unsupported member",
            )
            _require(member.size >= 0, "CLI archive has an invalid member size")
            total_size += member.size
            _require(total_size <= MAX_UNPACKED_BYTES, "CLI members exceed their size bound")
            if name == expected:
                _require(
                    member.isfile() and 0 < member.size <= MAX_BINARY_BYTES,
                    "CLI executable is not a bounded regular member",
                )
                executable = member
        _require(executable is not None, "CLI archive is missing its expected executable")
        assert executable is not None
        stream = source.extractfile(executable)
        _require(stream is not None, "CLI executable could not be read")
        assert stream is not None
        count = 0
        with stream, destination.open("xb") as output:
            while chunk := stream.read(min(1024 * 1024, executable.size - count + 1)):
                count += len(chunk)
                _require(count <= executable.size, "CLI executable exceeds its declared size")
                output.write(chunk)
        _require(count == executable.size, "CLI executable is truncated")
    destination.chmod(0o700)


def _command(executable: Path, arguments: tuple[str, ...], config_dir: Path) -> bytes:
    """Version/help checks have isolated configuration and no inherited tokens."""
    result = subprocess.run(
        [str(executable), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        env={
            "PATH": os.defpath,
            "LANG": "C",
            "LC_ALL": "C",
            "GH_CONFIG_DIR": str(config_dir),
            "GH_PROMPT_DISABLED": "1",
            "GH_NO_UPDATE_NOTIFIER": "1",
        },
    )
    _require(
        result.returncode == 0 and len(result.stdout) <= MAX_COMMAND_BYTES,
        "Pinned CLI capability check failed",
    )
    return result.stdout


def _check_cli(executable: Path, config_dir: Path) -> None:
    version = _command(executable, ("--version",), config_dir)
    _require(
        re.match(rb"^gh version " + re.escape(VERSION.encode()) + rb"(?:[ (]|\r?\n|$)", version)
        is not None,
        "Installed CLI does not match its pinned version",
    )
    help_output = _command(executable, ("attestation", "verify", "--help"), config_dir)
    _require(
        all(
            re.search(rb"(?<![-\w])" + re.escape(flag.encode()) + rb"(?:[ =,\n]|$)", help_output)
            is not None
            for flag in REQUIRED_FLAGS
        ),
        "Pinned CLI lacks required attestation policy flags",
    )


def install(output_bin: Path) -> Path:
    _require(platform.system() == "Linux", "Attestation CLI requires Linux")
    spec = ARCHIVES.get(platform.machine())
    _require(spec is not None, "Attestation CLI requires native x86_64 or aarch64")
    assert spec is not None
    output_bin = Path(output_bin)
    _require(
        output_bin.is_absolute()
        and output_bin.parent.is_dir()
        and output_bin.parent.resolve() == output_bin.parent
        and not os.path.lexists(output_bin),
        "CLI output directory must be fresh under an existing non-symlink parent",
    )
    with tempfile.TemporaryDirectory(
        prefix=".xferry-attestation-cli-", dir=output_bin.parent
    ) as work:
        staging = Path(work)
        archive = staging / "gh.tar.gz"
        _download_archive(spec, archive)
        unpacked = staging / "gh.tar"
        _expand_archive(archive, unpacked)
        executable = staging / "gh"
        _extract_binary(unpacked, spec, executable)
        config_dir = staging / "config"
        config_dir.mkdir(mode=0o700)
        _check_cli(executable, config_dir)
        output_bin.mkdir(mode=0o700)
        try:
            installed = output_bin / "gh"
            executable.replace(installed)
        except BaseException:
            output_bin.rmdir()
            raise
    return installed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-bin", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        executable = install(arguments.output_bin)
    except Exception:
        print(json.dumps({"status": "failed", "code": "attestation_cli_install_failed"}))
        return 1
    print(json.dumps({"status": "installed", "version": VERSION, "executable": str(executable)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
