"""Build and verify immutable packages for the opt-in testing channel."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    from setuptools._vendor import tomli as tomllib  # type: ignore[no-redef]

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from xferry.management.channels import (  # noqa: E402
    TESTING_IMAGE,
    TESTING_IMAGES_NAME,
    parse_testing_images,
    release_tag,
)
from xferry.management.release_contract import (  # noqa: E402
    SUPPORTED_PLATFORM_IDS,
    ReleaseManifest,
    release_manifest_asset_name,
    require_source_commit,
)
from xferry.management.release_trust import (  # noqa: E402
    INSTALLER_SIGNATURE_TYPE,
    TESTING_MANIFEST_SIGNATURE_TYPE,
    TESTING_SIGNING_KEY_ID,
    create_detached_signature,
    verify_signed_manifest,
)

REPOSITORY = "kgmnotes/xferry"
WORKFLOW = ".github/workflows/testpypi.yml"
READY_NAME = "testing-ready.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FINAL = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class TestingIdentity:
    version: str
    target_version: str
    source_commit: str
    workflow_run: str
    run_attempt: int
    build_id: str
    tag: str
    channel: str = "testing"

    @classmethod
    def create(
        cls, target_version: str, source_commit: str, run: str, attempt: int
    ) -> TestingIdentity:
        if not isinstance(target_version, str) or not _FINAL.fullmatch(target_version):
            raise ValueError("testing target must be an exact final X.Y.Z version")
        require_source_commit(source_commit)
        if (
            not isinstance(run, str)
            or not re.fullmatch(r"[1-9][0-9]*", run)
            or type(attempt) is not int
            or not 1 <= attempt < 1000
        ):
            raise ValueError(
                "testing build requires a positive workflow run and attempt below 1000"
            )
        version = f"{target_version}.dev{int(run) * 1000 + attempt}"
        return cls(
            version,
            target_version,
            source_commit,
            run,
            attempt,
            f"{run}.{attempt}",
            release_tag(version, "testing"),
        )

    @classmethod
    def read(cls, path: Path) -> TestingIdentity:
        document = json.loads(path.read_bytes())
        if not isinstance(document, dict):
            raise ValueError("testing identity must be an object")
        expected = cls.create(
            document.get("target_version", ""),
            document.get("source_commit", ""),
            document.get("workflow_run", ""),
            document.get("run_attempt", 0),
        )
        if document != asdict(expected):
            raise ValueError("testing identity fields are inconsistent")
        return expected

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_canonical(asdict(self)))


def target_version(workspace: Path, source_commit: str | None = None) -> str:
    if source_commit is None:
        with (workspace / "packaging/channels.toml").open("rb") as source:
            document = tomllib.load(source)
    else:
        require_source_commit(source_commit)
        payload = subprocess.check_output(
            ["git", "show", f"{source_commit}:packaging/channels.toml"], cwd=workspace
        )
        document = tomllib.loads(payload.decode())
    value = document["testing"]["target_version"]
    if not isinstance(value, str) or not _FINAL.fullmatch(value):
        raise ValueError("testing target must be an exact final X.Y.Z version")
    return value


def _new_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"testing output must not already exist: {path}")
    path.mkdir(parents=True)


def prepare_source(workspace: Path, output: Path, identity: TestingIdentity) -> Path:
    """Export the exact committed source and overlay build metadata outside the checkout."""
    workspace = workspace.resolve()
    output = output.resolve()
    if output == workspace or output.is_relative_to(workspace):
        raise ValueError("testing source overlay must be outside the source checkout")
    _new_directory(output)
    archive = subprocess.check_output(
        ["git", "archive", "--format=tar", identity.source_commit], cwd=workspace
    )
    source_root = output / "source"
    source_root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("testing source archive contains an unsafe path")
            destination = source_root.joinpath(*path.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("testing source archive member is missing")
            destination.write_bytes(stream.read())
            destination.chmod(0o755 if member.mode & 0o111 else 0o644)
    config = source_root / "xferry/config.py"
    content, count = re.subn(
        r'(?m)^__version__\s*=\s*"[^"]+"', f'__version__ = "{identity.version}"', config.read_text()
    )
    if count != 1:
        raise ValueError("testing source must have one literal package version")
    config.write_text(content)
    build = source_root / "xferry/build_info.py"
    build.write_text(
        '"""Immutable identity of this testing distribution."""\n\n'
        'BUILD_CHANNEL = "testing"\n'
        f'SOURCE_COMMIT = "{identity.source_commit}"\n'
        f'BUILD_ID = "{identity.build_id}"\n'
    )
    html = source_root / "xferry/data/index.html"
    if html.exists():
        content, count = re.subn(
            r'id="appVersion"\s+data-app-version="[^"]+">v[^<]+</p>',
            f'id="appVersion" data-app-version="{identity.version}">v{identity.version}</p>',
            html.read_text(),
        )
        if count != 1:
            raise ValueError("testing source must have one UI version marker")
        html.write_text(content)
    readme = source_root / "README.md"
    if readme.exists():
        readme.write_text(
            re.sub(
                r"version-[^-\s/]+-orange\.svg",
                f"version-{identity.version}-orange.svg",
                readme.read_text(),
            )
        )
    identity.write(output / "identity.json")
    return source_root


def classify_changes(paths: Sequence[str]) -> bool:
    """Only prose/configured documentation assets may take the documentation lane."""

    def documentation(path: str) -> bool:
        item = PurePosixPath(path)
        if item.is_absolute() or ".." in item.parts:
            return False
        if path in {
            "README.md",
            "API.md",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
            "LICENSE",
            "mkdocs.yml",
        }:
            return True
        return path.startswith("docs/") and item.suffix in {
            ".md",
            ".png",
            ".jpg",
            ".jpeg",
            ".svg",
            ".webp",
        }

    return bool(paths) and all(documentation(path) for path in paths)


def changed_files(workspace: Path, before: str, after: str) -> list[str]:
    if not before or set(before) == {"0"}:
        return []
    require_source_commit(before)
    require_source_commit(after)
    output = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", before, after], cwd=workspace
    )
    return [item.decode() for item in output.split(b"\0") if item]


def eligible_ci_run(document: Mapping[str, Any], source_commit: str) -> bool:
    return (
        document.get("head_sha") == source_commit
        and document.get("head_branch") == "testing"
        and document.get("event") == "push"
        and document.get("path") == ".github/workflows/ci.yml"
        and document.get("status") == "completed"
        and document.get("conclusion") == "success"
        and document.get("repository", {}).get("full_name") == REPOSITORY
    )


def wait_for_ci(source_commit: str, *, timeout: float = 2400, interval: float = 20) -> int:
    require_source_commit(source_commit)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = subprocess.check_output(
            [
                "gh",
                "api",
                f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs?branch=testing&event=push&head_sha={source_commit}&per_page=20",
            ],
            text=True,
        )
        runs = json.loads(payload)["workflow_runs"]
        for item in runs:
            if eligible_ci_run(item, source_commit):
                return int(item["id"])
        completed = [item for item in runs if item.get("status") == "completed"]
        if completed and len(completed) == len(runs):
            raise ValueError("the exact testing source did not pass CI")
        time.sleep(interval)
    raise ValueError("timed out waiting for exact-source testing CI")


def _asset(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("testing assets must be regular files")
    return {"size": path.stat().st_size, "sha256": sha256(path)}


def sign_assets(
    candidate: Path,
    output: Path,
    identity: TestingIdentity,
    image_digest: str,
    private_key: bytes,
    key_id: str = TESTING_SIGNING_KEY_ID,
) -> dict[str, Any]:
    """Sign the exact native payloads and bind the multiarch image and Python bytes."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise ValueError("testing image must have an exact OCI digest")
    if key_id != TESTING_SIGNING_KEY_ID:
        raise ValueError("testing signing identity is not trusted")
    signer = serialization.load_pem_private_key(private_key, password=None)
    if not isinstance(signer, Ed25519PrivateKey):
        raise ValueError("testing signing key must be Ed25519")
    _new_directory(output)
    names = [f"xferry-{identity.version}-py3-none-any.whl", f"xferry-{identity.version}.tar.gz"]
    records: dict[str, dict[str, object]] = {}
    for name in names:
        path = candidate / "python" / name
        records[name] = _asset(path)
        shutil.copyfile(path, output / name)
    common = {name: str(record["sha256"]) for name, record in records.items()}
    catalog = {
        "schema": 1,
        "channel": "testing",
        "version": identity.version,
        "source_commit": identity.source_commit,
        "build_id": identity.build_id,
        "image": f"{TESTING_IMAGE}@{image_digest}",
    }
    catalog_payload = (json.dumps(catalog, indent=2) + "\n").encode()
    (output / TESTING_IMAGES_NAME).write_bytes(catalog_payload)
    common[TESTING_IMAGES_NAME] = hashlib.sha256(catalog_payload).hexdigest()
    for platform in SUPPORTED_PLATFORM_IDS:
        bundle = candidate / f"scie-{platform}"
        original = ReleaseManifest.parse_new((bundle / "xferry-release.json").read_bytes())
        if (
            original.channel,
            original.version,
            original.source_commit,
            original.build_id,
            original.platform,
        ) != ("testing", identity.version, identity.source_commit, identity.build_id, platform):
            raise ValueError("native testing manifest does not match the exact build")
        executable = bundle / original.executable_name
        executable_record = _asset(executable)
        if (executable_record["sha256"], executable_record["size"]) != (
            original.executable_sha256,
            original.executable_size,
        ):
            raise ValueError("native executable differs from its manifest")
        installer_name = f"install-{platform}.sh"
        installer = bundle / "install.sh"
        digests = {
            **common,
            original.executable_name: original.executable_sha256,
            installer_name: sha256(installer),
        }
        manifest = ReleaseManifest.create_v3(
            version=identity.version,
            platform=platform,
            executable_size=original.executable_size,
            executable_sha256=original.executable_sha256,
            source_commit=identity.source_commit,
            workflow_run=identity.workflow_run,
            build_id=identity.build_id,
            artifact_digests=digests,
            signing_key_ids=[key_id],
        )
        manifest_name = release_manifest_asset_name(platform)
        payload = manifest.to_bytes()
        signature = create_detached_signature(
            payload, signer=signer, key_id=key_id, payload_type=TESTING_MANIFEST_SIGNATURE_TYPE
        )
        verify_signed_manifest(payload, signature, channel="testing")
        (output / manifest_name).write_bytes(payload)
        (output / f"{manifest_name}.sig").write_bytes(signature)
        shutil.copyfile(executable, output / executable.name)
        (output / executable.name).chmod(0o755)
        shutil.copyfile(installer, output / installer_name)
        (output / installer_name).chmod(0o755)
        (output / f"{installer_name}.sig").write_bytes(
            create_detached_signature(
                installer.read_bytes(),
                signer=signer,
                key_id=key_id,
                payload_type=INSTALLER_SIGNATURE_TYPE,
            )
        )
    for path in output.iterdir():
        records[path.name] = _asset(path)
    handoff = {**asdict(identity), "image_digest": image_digest, "assets": records}
    (output / "testing-build.json").write_bytes(_canonical(handoff))
    return handoff


def verify_testpypi(identity: TestingIdentity, assets: Path, document: Mapping[str, Any]) -> str:
    info = document.get("info", {})
    if info.get("name") != "xferry" or info.get("version") != identity.version:
        raise ValueError("TestPyPI returned another testing version")
    expected = {f"xferry-{identity.version}-py3-none-any.whl", f"xferry-{identity.version}.tar.gz"}
    urls = document.get("urls", [])
    by_name = {item["filename"]: item for item in urls}
    if len(by_name) != len(urls) or set(by_name) != expected:
        raise ValueError("TestPyPI distribution set differs from the testing build")
    for name, item in by_name.items():
        url = urllib.parse.urlsplit(item["url"])
        if (
            url.scheme != "https"
            or url.netloc != "test-files.pythonhosted.org"
            or not url.path.startswith("/packages/")
            or url.query
            or url.fragment
        ):
            raise ValueError("TestPyPI distribution has an unexpected origin")
        local = _asset(assets / name)
        if (
            item.get("size") != local["size"]
            or item.get("digests", {}).get("sha256") != local["sha256"]
            or item.get("yanked") is not False
        ):
            raise ValueError("TestPyPI bytes differ from the testing build")
    wheel = by_name[f"xferry-{identity.version}-py3-none-any.whl"]
    return f"{wheel['url']}#sha256={wheel['digests']['sha256']}"


def fetch_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = response.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ValueError("registry metadata exceeds its size limit")
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise ValueError("registry metadata must be an object")
    return document


def verify_signed_assets(assets: Path, identity: TestingIdentity, image_digest: str) -> None:
    for platform in SUPPORTED_PLATFORM_IDS:
        name = release_manifest_asset_name(platform)
        manifest = verify_signed_manifest(
            (assets / name).read_bytes(), (assets / f"{name}.sig").read_bytes(), channel="testing"
        )
        if (
            manifest.version,
            manifest.source_commit,
            manifest.build_id,
            manifest.platform,
            manifest.workflow_run,
        ) != (
            identity.version,
            identity.source_commit,
            identity.build_id,
            platform,
            identity.workflow_run,
        ):
            raise ValueError("signed assets belong to another testing build")
        digests = dict(manifest.artifact_digests)
        if (
            parse_testing_images((assets / TESTING_IMAGES_NAME).read_bytes(), manifest)
            != f"{TESTING_IMAGE}@{image_digest}"
        ):
            raise ValueError("testing image does not match the signed manifest")
        for asset_name in (
            f"xferry-{identity.version}-py3-none-any.whl",
            f"xferry-{identity.version}.tar.gz",
            manifest.executable_name,
            f"install-{platform}.sh",
        ):
            if digests.get(asset_name) != sha256(assets / asset_name):
                raise ValueError("testing asset differs from its signed manifest")


def ready_report(
    identity: TestingIdentity, assets: Path, image_digest: str, index_document: Mapping[str, Any]
) -> dict[str, Any]:
    verify_signed_assets(assets, identity, image_digest)
    wheel_url = verify_testpypi(identity, assets, index_document)
    image = f"{TESTING_IMAGE}@{image_digest}"
    quoted = shlex.quote(wheel_url)
    return {
        "schema": 1,
        **asdict(identity),
        "image": image,
        "wheel_url": wheel_url,
        "assets": {path.name: _asset(path) for path in sorted(assets.iterdir()) if path.is_file()},
        "commands": {
            "pip": f"python -m pip install --upgrade {quoted}",
            "pipx": f"pipx install --force --suffix=-preview {quoted}",
            "native": (
                f"xferry-preview setup --channel testing --to {identity.version} "
                "--backend native --access public --files-dir /srv/share"
            ),
            "docker": (
                f"xferry-preview setup --channel testing --to {identity.version} "
                "--backend docker --access public --files-dir /srv/share"
            ),
            "update": f"xferry-preview update --channel testing --to {identity.version}",
            "rollback": "xferry-preview rollback --channel stable",
        },
        "manual_acceptance": "pending",
    }


def verify_published_assets(identity: TestingIdentity, assets: Path) -> None:
    """Read public release bytes back and compare every signed handoff asset."""
    metadata = json.loads(
        subprocess.check_output(
            ["gh", "api", f"repos/{REPOSITORY}/releases/tags/{identity.tag}"], text=True
        )
    )
    if (
        metadata.get("tag_name") != identity.tag
        or metadata.get("prerelease") is not True
        or metadata.get("draft") is not False
    ):
        raise ValueError("testing release must be a public prerelease")
    reference = json.loads(
        subprocess.check_output(
            ["gh", "api", f"repos/{REPOSITORY}/git/ref/tags/{identity.tag}"], text=True
        )
    )
    if (
        reference.get("object", {}).get("type") != "commit"
        or reference.get("object", {}).get("sha") != identity.source_commit
    ):
        raise ValueError("testing release tag points to another source commit")
    remote = {item["name"]: item for item in metadata.get("assets", [])}
    for path in assets.iterdir():
        if not path.is_file():
            continue
        record = _asset(path)
        if remote.get(path.name, {}).get("size") != record["size"]:
            raise ValueError("published testing release asset is missing or differs")
        url = f"https://github.com/{REPOSITORY}/releases/download/{identity.tag}/{path.name}"
        with urllib.request.urlopen(url, timeout=60) as response:
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                size += len(chunk)
                if size > int(str(record["size"])):
                    raise ValueError("published testing asset exceeds expected size")
                digest.update(chunk)
        if size != record["size"] or digest.hexdigest() != record["sha256"]:
            raise ValueError("published testing bytes differ from signed handoff")


def _anonymous_image_index(image_digest: str) -> bytes:
    token_document = fetch_json(
        "https://ghcr.io/token?service=ghcr.io&scope=repository:kgmnotes/xferry-testing:pull"
    )
    token = token_document.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("testing image does not allow anonymous access")
    request = urllib.request.Request(
        f"https://ghcr.io/v2/kgmnotes/xferry-testing/manifests/{image_digest}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": (
                "application/vnd.oci.image.index.v1+json, "
                "application/vnd.docker.distribution.manifest.list.v2+json"
            ),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = bytes(response.read(1024 * 1024 + 1))
    if len(payload) > 1024 * 1024:
        raise ValueError("testing OCI index exceeds its size limit")
    return payload


def verify_public_image(identity: TestingIdentity, image_digest: str) -> None:
    """Prove an anonymous VPS can pull both architectures and inspect image identity."""
    image = f"{TESTING_IMAGE}@{image_digest}"
    with TemporaryDirectory(prefix="xferry-anonymous-docker-") as directory:
        command = ["docker", "--config", directory]
        payload = _anonymous_image_index(image_digest)
        if hashlib.sha256(payload).hexdigest() != image_digest.removeprefix("sha256:"):
            raise ValueError("published image index differs from the signed digest")
        manifests = json.loads(payload).get("manifests", [])
        platforms = {
            item.get("platform", {}).get("architecture")
            for item in manifests
            if item.get("platform", {}).get("os") == "linux"
        }
        if platforms != {"amd64", "arm64"}:
            raise ValueError("testing image does not contain both supported Linux architectures")
        for architecture in ("arm64", "amd64"):
            subprocess.run(
                [*command, "pull", "--platform", f"linux/{architecture}", image], check=True
            )
            document = json.loads(
                subprocess.check_output(
                    [*command, "image", "inspect", "--platform", f"linux/{architecture}", image],
                    text=True,
                )
            )[0]
            labels = document.get("Config", {}).get("Labels", {})
            expected = {
                "org.opencontainers.image.version": identity.version,
                "org.opencontainers.image.revision": identity.source_commit,
                "io.xferry.build-id": identity.build_id,
                "io.xferry.channel": "testing",
            }
            if document.get("Architecture") != architecture or any(
                labels.get(key) != value for key, value in expected.items()
            ):
                raise ValueError("published image identity labels differ from testing build")


def _identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--identity", type=Path, required=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    classify = commands.add_parser("classify")
    classify.add_argument("--workspace", type=Path, default=REPO_ROOT)
    classify.add_argument("--before", required=True)
    classify.add_argument("--after", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--workspace", type=Path, default=REPO_ROOT)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--source-commit", required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--run-attempt", type=int, required=True)
    wait = commands.add_parser("wait-ci")
    wait.add_argument("--source-commit", required=True)
    sign = commands.add_parser("sign")
    _identity_arguments(sign)
    sign.add_argument("--candidate", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    sign.add_argument("--image-digest", required=True)
    sign.add_argument("--private-key-env", default="XFERRY_TESTING_SIGNING_KEY_PEM")
    sign.add_argument("--key-id", default=TESTING_SIGNING_KEY_ID)
    ready = commands.add_parser("ready")
    _identity_arguments(ready)
    ready.add_argument("--assets", type=Path, required=True)
    ready.add_argument("--image-digest", required=True)
    ready.add_argument("--output", type=Path, required=True)
    ready.add_argument("--verify-published", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "classify":
            only_docs = classify_changes(changed_files(args.workspace, args.before, args.after))
            print(f"code={'false' if only_docs else 'true'}")
        elif args.action == "prepare":
            identity = TestingIdentity.create(
                target_version(args.workspace, args.source_commit),
                args.source_commit,
                args.run_id,
                args.run_attempt,
            )
            prepare_source(args.workspace, args.output, identity)
            print(json.dumps(asdict(identity), sort_keys=True))
        elif args.action == "wait-ci":
            print(wait_for_ci(args.source_commit))
        elif args.action == "sign":
            key = os.environ.get(args.private_key_env)
            if key is None:
                raise ValueError("testing signing key is not configured")
            sign_assets(
                args.candidate,
                args.output,
                TestingIdentity.read(args.identity),
                args.image_digest,
                key.encode(),
                args.key_id,
            )
        elif args.action == "ready":
            identity = TestingIdentity.read(args.identity)
            deadline = time.monotonic() + 300
            while True:
                try:
                    document = fetch_json(
                        f"https://test.pypi.org/pypi/xferry/{identity.version}/json"
                    )
                    report = ready_report(identity, args.assets, args.image_digest, document)
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(10)
            if args.verify_published:
                verify_published_assets(identity, args.assets)
                verify_public_image(identity, args.image_digest)
            args.output.write_bytes(_canonical(report))
            print(json.dumps(report["commands"], indent=2))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"testing build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
