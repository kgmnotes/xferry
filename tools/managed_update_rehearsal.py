"""Build and exercise a non-publishing native managed-update rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import tarfile
from collections.abc import Mapping, Sequence
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.sign_release_metadata import sign_installer, sign_manifest  # noqa: E402
from xferry.management.release_contract import (  # noqa: E402
    SUPPORTED_PLATFORM_IDS,
    PlatformId,
    release_manifest_asset_name,
)

REHEARSAL_KEY_ID = "xferry-rehearsal-2026-10"
SOURCE_VERSION = "0.1.1"
TARGET_VERSION = "0.1.2"
REHEARSAL_VERSIONS = (SOURCE_VERSION, TARGET_VERSION)
_PRODUCTION_RELEASE_URL = "https://github.com/kgmnotes/xferry/releases"
_TRUST_START = "EMBEDDED_RELEASE_KEYS: tuple[TrustedReleaseKey, ...] = ("
_TRUST_END = "\nDEFAULT_RELEASE_KEY_RING = ReleaseKeyRing(EMBEDDED_RELEASE_KEYS)"
_STATE_PATHS: Mapping[str, Path] = {
    "config": Path("/etc/xferry/xferry.ini"),
    "auth": Path("/etc/xferry/auth"),
    "data": Path("/var/lib/xferry/rehearsal-sentinel"),
}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, document: Mapping[str, Any], *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(mode)


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    capture_output: bool = False,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        check=True,
        capture_output=capture_output,
        text=True,
        env=None if environment is None else dict(environment),
    )


def _replace_once(path: Path, before: str, after: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(before) != 1:
        raise ValueError(f"expected exactly one rehearsal patch marker in {path}")
    path.write_text(text.replace(before, after, 1), encoding="utf-8")


def patch_fixture_source(
    source: Path,
    *,
    version: str,
    public_key_hex: str,
    release_base_url: str,
) -> None:
    """Patch only an ephemeral source copy with its rehearsal identity and trust."""
    if version not in REHEARSAL_VERSIONS:
        raise ValueError("rehearsal version is not fixed to the approved pair")
    if len(public_key_hex) != 64 or any(
        character not in "0123456789abcdef" for character in public_key_hex
    ):
        raise ValueError("rehearsal public key must be 32 lowercase hexadecimal bytes")
    _require_loopback_https(release_base_url)

    config = source / "xferry/config.py"
    config_text = config.read_text(encoding="utf-8")
    version_lines = [line for line in config_text.splitlines() if line.startswith("__version__ = ")]
    if len(version_lines) != 1:
        raise ValueError("fixture source must contain exactly one package version")
    _replace_once(config, version_lines[0], f'__version__ = "{version}"')

    releases = source / "xferry/management/releases.py"
    _replace_once(
        releases,
        f'release_base_url: str = "{_PRODUCTION_RELEASE_URL}"',
        f'release_base_url: str = "{release_base_url.rstrip("/")}"',
    )

    trust = source / "xferry/management/release_trust.py"
    trust_text = trust.read_text(encoding="utf-8")
    start = trust_text.find(_TRUST_START)
    end = trust_text.find(_TRUST_END, start + len(_TRUST_START))
    if start < 0 or end < 0 or trust_text.find(_TRUST_START, start + 1) >= 0:
        raise ValueError("fixture source must contain exactly one embedded trust ring")
    replacement = (
        "EMBEDDED_RELEASE_KEYS: tuple[TrustedReleaseKey, ...] = (\n"
        "    TrustedReleaseKey(\n"
        f'        key_id="{REHEARSAL_KEY_ID}",\n'
        f'        public_key=bytes.fromhex("{public_key_hex}"),\n'
        "    ),\n"
        ")"
    )
    trust.write_text(trust_text[:start] + replacement + trust_text[end:], encoding="utf-8")


def public_key_evidence(public_key: bytes) -> dict[str, str]:
    """Return the only release-key evidence permitted outside the signer process."""
    if len(public_key) != 32:
        raise ValueError("rehearsal Ed25519 public key must contain 32 bytes")
    return {
        "key_id": REHEARSAL_KEY_ID,
        "public_key_sha256": _sha256_bytes(public_key),
    }


def _require_loopback_https(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("rehearsal release URL must be loopback HTTPS without userinfo")


def _git_output(source: Path, *arguments: str) -> str:
    return _run(("git", *arguments), cwd=source, capture_output=True).stdout.strip()


def _commit(source: Path, message: str) -> str:
    _run(("git", "add", "--all"), cwd=source)
    environment = os.environ | {
        "GIT_AUTHOR_DATE": "2026-10-01T00:00:00+03:00",
        "GIT_COMMITTER_DATE": "2026-10-01T00:00:00+03:00",
    }
    _run(
        ("git", "commit", "--quiet", "--no-gpg-sign", "-m", message),
        cwd=source,
        environment=environment,
    )
    return _git_output(source, "rev-parse", "HEAD")


def _git_archive(repo_root: Path, destination: Path) -> None:
    """Extract exactly the committed tree without copying checkout metadata or caches."""
    if destination.exists():
        raise ValueError(f"rehearsal source destination already exists: {destination}")
    payload = subprocess.run(
        ("git", "archive", "--format=tar", "HEAD"),
        cwd=repo_root,
        check=True,
        capture_output=True,
    ).stdout
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        archive.extractall(destination, filter="data")


def _initialize_fixture_repository(source: Path, base_commit: str) -> str:
    _run(("git", "init", "--quiet", "--initial-branch=rehearsal"), cwd=source)
    _run(("git", "config", "user.name", "XFerry Rehearsal"), cwd=source)
    _run(("git", "config", "user.email", "rehearsal@invalid.example"), cwd=source)
    return _commit(source, f"Import XFerry source {base_commit}")


def _build_fixture(
    *,
    repo_root: Path,
    work_root: Path,
    serve_root: Path,
    platform: PlatformId,
    version: str,
    public_key_hex: str,
    private_key: Ed25519PrivateKey,
    release_base_url: str,
    workflow_run: str,
    base_commit: str,
) -> dict[str, Any]:
    source = work_root / "sources" / version
    _git_archive(repo_root, source)
    local_base = _initialize_fixture_repository(source, base_commit)
    patch_fixture_source(
        source,
        version=version,
        public_key_hex=public_key_hex,
        release_base_url=release_base_url,
    )
    fixture_commit = _commit(source, f"Prepare managed update rehearsal {version}")
    fixture_tree = _git_output(source, "rev-parse", "HEAD^{tree}")
    patch = subprocess.run(
        ("git", "diff", "--binary", "HEAD^", "HEAD"),
        cwd=source,
        check=True,
        capture_output=True,
    ).stdout

    wheel_dir = work_root / "wheels" / version
    wheel_dir.mkdir(parents=True)
    _run((sys.executable, "-m", "build", "--wheel", "--outdir", str(wheel_dir)), cwd=source)
    wheels = sorted(wheel_dir.glob(f"xferry-{version}-py3-none-any.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one rehearsal wheel for {version}, found {len(wheels)}")
    wheel = wheels[0]
    wheel_sha256 = _sha256_file(wheel)

    bundle = work_root / "bundles" / version
    _run(
        (
            sys.executable,
            "tools/build_scie_release.py",
            "--platform",
            platform,
            "--output-dir",
            str(bundle),
            "--version",
            version,
            "--source-commit",
            fixture_commit,
            "--workflow-run",
            workflow_run,
            "--signing-key-id",
            REHEARSAL_KEY_ID,
            "--require-hosted-signature",
            "--wheel",
            str(wheel),
            "--wheel-sha256",
            wheel_sha256,
        ),
        cwd=source,
    )

    hosted = serve_root / "releases" / "download" / f"v{version}"
    hosted.mkdir(parents=True)
    manifest_name = release_manifest_asset_name(platform)
    installer_name = f"install-{platform}.sh"
    executable = next(bundle.glob(f"xferry-{version}-{platform}"))
    manifest_payload = bundle.joinpath("xferry-release.json").read_bytes()
    installer_payload = bundle.joinpath("install.sh").read_bytes()
    assets: dict[str, bytes | Path] = {
        executable.name: executable,
        manifest_name: manifest_payload,
        f"{manifest_name}.sig": sign_manifest(
            manifest_payload,
            key_id=REHEARSAL_KEY_ID,
            private_key=private_key,
        ),
        installer_name: installer_payload,
        f"{installer_name}.sig": sign_installer(
            installer_payload,
            key_id=REHEARSAL_KEY_ID,
            private_key=private_key,
        ),
    }
    inventory: dict[str, dict[str, int | str]] = {}
    for name, value in assets.items():
        destination = hosted / name
        if isinstance(value, Path):
            shutil.copyfile(value, destination)
        else:
            destination.write_bytes(value)
        destination.chmod(0o755 if name == executable.name or name == installer_name else 0o644)
        inventory[name] = {
            "sha256": _sha256_file(destination),
            "size": destination.stat().st_size,
        }

    return {
        "base_commit": base_commit,
        "fixture_base_commit": local_base,
        "fixture_commit": fixture_commit,
        "fixture_tree": fixture_tree,
        "patch_sha256": _sha256_bytes(patch),
        "version": version,
        "wheel_sha256": wheel_sha256,
        "assets": inventory,
    }


def prepare_rehearsal(
    *,
    repo_root: Path,
    work_root: Path,
    serve_root: Path,
    evidence: Path,
    platform: PlatformId,
    release_base_url: str,
    workflow_run: str,
    base_commit: str,
) -> None:
    """Build both signed versions while keeping the ephemeral private key in memory."""
    _require_loopback_https(release_base_url)
    actual_commit = _git_output(repo_root, "rev-parse", "HEAD")
    if actual_commit != base_commit:
        raise ValueError("rehearsal base commit does not match the checked-out revision")
    if work_root.exists() or serve_root.exists():
        raise ValueError("rehearsal output roots must not already exist")
    work_root.mkdir(parents=True)
    serve_root.mkdir(parents=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    public_key_hex = public_key.hex()
    versions = {
        version: _build_fixture(
            repo_root=repo_root,
            work_root=work_root,
            serve_root=serve_root,
            platform=platform,
            version=version,
            public_key_hex=public_key_hex,
            private_key=private_key,
            release_base_url=release_base_url,
            workflow_run=workflow_run,
            base_commit=base_commit,
        )
        for version in REHEARSAL_VERSIONS
    }
    _write_json(
        evidence,
        {
            "base_commit": base_commit,
            "platform": platform,
            "release_base_url": release_base_url,
            "release_key": public_key_evidence(public_key),
            "versions": versions,
            "workflow_run": workflow_run,
        },
    )


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_arguments: object) -> None:
        return


def serve_fixture(
    *,
    root: Path,
    certificate: Path,
    private_key: Path,
    host: str,
    port: int,
    ready_file: Path,
) -> None:
    """Serve immutable rehearsal assets over loopback TLS without request logging."""
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("rehearsal server must bind only to loopback")
    handler = partial(_QuietHandler, directory=str(root))
    server = ThreadingHTTPServer((host, port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    ready_file.parent.mkdir(parents=True, exist_ok=True)
    ready_file.write_text(f"https://{host}:{port}\n", encoding="utf-8")
    try:
        server.serve_forever()
    finally:
        server.server_close()


def verify_health(expected_version: str, evidence: Path) -> None:
    """Perform an authenticated local PING and emit no credential material."""
    from xferry.management.health import HealthEndpoint, authenticated_ping
    from xferry.settings import load_settings_file

    settings = load_settings_file("/etc/xferry/xferry.ini")
    raw_auth = Path("/etc/xferry/auth").read_text(encoding="utf-8").strip()
    username, separator, password = raw_auth.partition(":")
    if not separator or not username or not password:
        raise RuntimeError("managed authentication file is invalid")
    endpoint = HealthEndpoint("127.0.0.1", settings.port, "127.0.0.1", tls=False)
    result = authenticated_ping(endpoint, username, password, 5.0)
    if not result.ok or result.version != expected_version:
        raise RuntimeError("managed service did not report the exact expected version")
    _write_json(
        evidence,
        {
            "detail": "authenticated exact-version health passed",
            "status": "ok",
            "version": result.version,
        },
    )


def capture_state(output: Path) -> None:
    """Capture root-only hashes used solely for later equality checks."""
    snapshot: dict[str, str] = {}
    for name, path in _STATE_PATHS.items():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"managed rehearsal state is missing: {name}")
        snapshot[name] = _sha256_file(path)
    _write_json(output, snapshot, mode=0o600)


def verify_state(baseline: Path, evidence: Path) -> None:
    """Assert preserved configuration/auth/data without emitting their hashes or contents."""
    expected = json.loads(baseline.read_text(encoding="utf-8"))
    if not isinstance(expected, dict) or set(expected) != set(_STATE_PATHS):
        raise RuntimeError("managed rehearsal baseline is invalid")
    unchanged: dict[str, bool] = {}
    for name, path in _STATE_PATHS.items():
        unchanged[name] = (
            path.is_file() and not path.is_symlink() and _sha256_file(path) == expected[name]
        )
    if not all(unchanged.values()):
        raise RuntimeError("managed state changed during release lifecycle")
    _write_json(evidence, {"status": "ok", "unchanged": unchanged})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--repo-root", type=Path, required=True)
    prepare.add_argument("--work-root", type=Path, required=True)
    prepare.add_argument("--serve-root", type=Path, required=True)
    prepare.add_argument("--evidence", type=Path, required=True)
    prepare.add_argument("--platform", choices=SUPPORTED_PLATFORM_IDS, required=True)
    prepare.add_argument("--release-base-url", required=True)
    prepare.add_argument("--workflow-run", required=True)
    prepare.add_argument("--base-commit", required=True)

    serve = commands.add_parser("serve")
    serve.add_argument("--fixture-root", type=Path, required=True)
    serve.add_argument("--certificate", type=Path, required=True)
    serve.add_argument("--private-key", type=Path, required=True)
    serve.add_argument("--host", choices=("127.0.0.1", "::1"), default="127.0.0.1")
    serve.add_argument("--port", type=int, required=True)
    serve.add_argument("--ready-file", type=Path, required=True)

    health = commands.add_parser("verify-health")
    health.add_argument("--expected-version", choices=REHEARSAL_VERSIONS, required=True)
    health.add_argument("--evidence", type=Path, required=True)

    capture = commands.add_parser("capture-state")
    capture.add_argument("--output", type=Path, required=True)

    state = commands.add_parser("verify-state")
    state.add_argument("--baseline", type=Path, required=True)
    state.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "prepare":
        prepare_rehearsal(
            repo_root=arguments.repo_root.resolve(),
            work_root=arguments.work_root.resolve(),
            serve_root=arguments.serve_root.resolve(),
            evidence=arguments.evidence.resolve(),
            platform=arguments.platform,
            release_base_url=arguments.release_base_url,
            workflow_run=arguments.workflow_run,
            base_commit=arguments.base_commit,
        )
    elif arguments.command == "serve":
        serve_fixture(
            root=arguments.fixture_root.resolve(),
            certificate=arguments.certificate.resolve(),
            private_key=arguments.private_key.resolve(),
            host=arguments.host,
            port=arguments.port,
            ready_file=arguments.ready_file.resolve(),
        )
    elif arguments.command == "verify-health":
        verify_health(arguments.expected_version, arguments.evidence.resolve())
    elif arguments.command == "capture-state":
        capture_state(arguments.output.resolve())
    else:
        verify_state(arguments.baseline.resolve(), arguments.evidence.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
