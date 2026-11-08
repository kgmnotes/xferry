"""Immutable preview source, publishing, readiness and manual promotion boundaries."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools import testing_build as builds
from tools import testing_release as promotion
from tools.testing_build import TestingIdentity as PreviewIdentity
from xferry.management.channels import TESTING_IMAGES_NAME, parse_testing_images
from xferry.management.release_contract import (
    SUPPORTED_PLATFORM_IDS,
    ReleaseManifest,
    release_manifest_asset_name,
)
from xferry.management.release_trust import (
    TESTING_SIGNING_KEY_ID,
    ReleaseKeyRing,
    TrustedReleaseKey,
    verify_signed_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def _commit(root: Path) -> str:
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Preview Test",
        "-c",
        "user.email=preview@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    return _git(root, "rev-parse", "HEAD")


def _repository(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    (path / "xferry/data").mkdir(parents=True)
    (path / "packaging").mkdir()
    (path / "xferry/config.py").write_text('__version__ = "0.5.0"\nSETTING = True\n')
    (path / "xferry/data/index.html").write_text(
        '<p id="appVersion" data-app-version="0.5.0">v0.5.0</p>\n'
    )
    (path / "packaging/channels.toml").write_text('[testing]\ntarget_version = "0.5.1"\n')
    (path / "README.md").write_text("Release version-0.5.0-orange.svg\n")
    _commit(path)
    return path


def _api_fixture(name: str) -> str:
    """Keep promotion fixtures version-changing after the real project advances."""
    text, count = re.subn(
        r'(?m)^  "server": "XFerry/[0-9]+\.[0-9]+\.[0-9]+",$',
        '  "server": "XFerry/0.5.0",',
        (ROOT / name).read_text(),
        count=1,
    )
    assert count == 1
    return text


def _cli_fixture() -> str:
    """Exercise generated CLI version changes even after the real version advances."""
    version = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    text, default_count = re.subn(
        r"(?m)^(  --to VERSION          Signed release version to install \(default: )"
        + version
        + r"(\)\.)$",
        r"\g<1>0.5.0\g<2>",
        (ROOT / "docs/cli-reference.md").read_text(),
        count=1,
    )
    text, example_count = re.subn(
        r"(?m)^(Example: xferry update --to )" + version + r"$",
        r"\g<1>0.5.0",
        text,
        count=1,
    )
    assert default_count == example_count == 1
    return text


@pytest.fixture
def identity() -> PreviewIdentity:
    return PreviewIdentity.create("0.5.1", SOURCE, "12345", 2)


@pytest.fixture
def signed(
    tmp_path: Path, identity: PreviewIdentity, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, Any]]:
    signer = Ed25519PrivateKey.generate()
    key = signer.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    ring = ReleaseKeyRing(
        (
            TrustedReleaseKey(
                TESTING_SIGNING_KEY_ID,
                signer.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
            ),
        )
    )

    def verify(payload: bytes, signature: bytes, **kwargs: Any) -> ReleaseManifest:
        return verify_signed_manifest(payload, signature, key_ring=ring, **kwargs)

    monkeypatch.setattr(builds, "verify_signed_manifest", verify)
    monkeypatch.setattr(promotion, "verify_signed_manifest", verify)
    candidate = tmp_path / "candidate"
    (candidate / "python").mkdir(parents=True)
    for name in (
        f"xferry-{identity.version}-py3-none-any.whl",
        f"xferry-{identity.version}.tar.gz",
    ):
        (candidate / "python" / name).write_bytes(name.encode())
    for platform in SUPPORTED_PLATFORM_IDS:
        bundle = candidate / f"scie-{platform}"
        bundle.mkdir()
        native = f"native for {platform}".encode()
        manifest = ReleaseManifest.create_v3(
            version=identity.version,
            platform=platform,
            source_commit=identity.source_commit,
            workflow_run=identity.workflow_run,
            build_id=identity.build_id,
            executable_size=len(native),
            executable_sha256=hashlib.sha256(native).hexdigest(),
            signing_key_ids=[TESTING_SIGNING_KEY_ID],
        )
        (bundle / manifest.executable_name).write_bytes(native)
        (bundle / "xferry-release.json").write_bytes(manifest.to_bytes())
        (bundle / "install.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    assets = tmp_path / "signed"
    builds.sign_assets(candidate, assets, identity, IMAGE_DIGEST, key)
    registry: dict[str, Any] = {"info": {"name": "xferry", "version": identity.version}, "urls": []}
    for path in sorted((candidate / "python").iterdir()):
        registry["urls"].append(
            {
                "filename": path.name,
                "size": path.stat().st_size,
                "digests": {"sha256": builds.sha256(path)},
                "yanked": False,
                "url": f"https://test-files.pythonhosted.org/packages/ab/{path.name}",
            }
        )
    return assets, registry


def test_preview_identity_is_unique_for_runs_and_attempts(identity: PreviewIdentity) -> None:
    assert identity.version == "0.5.1.dev12345002"
    assert identity.build_id == "12345.2"
    assert identity.tag == "testing-v0.5.1.dev12345002"
    versions = {
        PreviewIdentity.create("0.5.1", SOURCE, run, attempt).version
        for run in ("12345", "12346")
        for attempt in (1, 2)
    }
    assert len(versions) == 4


@pytest.mark.parametrize(
    "target,source,run,attempt",
    [
        ("0.5.1rc1", SOURCE, "12345", 1),
        ("0.5.1.dev1", SOURCE, "12345", 1),
        ("0.5.1", "bad", "12345", 1),
        ("0.5.1", SOURCE, "0", 1),
        ("0.5.1", SOURCE, "12345", True),
        ("0.5.1", SOURCE, "12345", 1000),
    ],
)
def test_preview_identity_rejects_ambiguous_fields(
    target: str, source: str, run: str, attempt: int
) -> None:
    with pytest.raises(ValueError):
        PreviewIdentity.create(target, source, run, attempt)


def test_identity_json_cannot_relabel_a_build(tmp_path: Path, identity: PreviewIdentity) -> None:
    path = tmp_path / "identity.json"
    identity.write(path)
    assert PreviewIdentity.read(path) == identity
    document = json.loads(path.read_bytes())
    document["source_commit"] = "c" * 40
    path.write_text(json.dumps(document))
    assert PreviewIdentity.read(path).source_commit == "c" * 40
    document["build_id"] = "12345.3"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        PreviewIdentity.read(path)


def test_prepare_exports_only_exact_commit_and_leaves_checkout_dirty(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    sha = _git(repository, "rev-parse", "HEAD")
    identity = PreviewIdentity.create("0.5.1", sha, "12345", 1)
    original = (repository / "xferry/config.py").read_bytes()
    (repository / "packaging/channels.toml").write_text('[testing]\ntarget_version = "0.9.9"\n')
    assert builds.target_version(repository, sha) == "0.5.1"
    (repository / "README.md").write_text("local unfinished prose\n")
    before = _git(repository, "status", "--porcelain")
    source = builds.prepare_source(repository, tmp_path / "overlay", identity)
    assert (repository / "xferry/config.py").read_bytes() == original
    assert _git(repository, "status", "--porcelain") == before
    assert "local unfinished prose" not in (source / "README.md").read_text()
    assert identity.version in (source / "xferry/config.py").read_text()
    assert identity.source_commit in (source / "xferry/build_info.py").read_text()
    assert identity.build_id in (source / "xferry/build_info.py").read_text()
    assert identity.version in (source / "xferry/data/index.html").read_text()
    assert not (source / ".git").exists()
    assert PreviewIdentity.read(source.parent / "identity.json") == identity
    with pytest.raises(ValueError, match="outside"):
        builds.prepare_source(repository, repository / "generated", identity)


@pytest.mark.parametrize(
    "paths,only_docs",
    [
        (["README.md", "docs/installation.md", "docs/logo.svg"], True),
        (["CHANGELOG.md", "mkdocs.yml"], True),
        ([], False),
        (["docs/hook.py"], False),
        (["README.md", "xferry/config.py"], False),
        ([".github/workflows/ci.yml"], False),
        (["constraints/ci.txt"], False),
        (["docs/../xferry/code.md"], False),
        (["pyproject.toml"], False),
    ],
)
def test_docs_lane_is_conservative(paths: list[str], only_docs: bool) -> None:
    assert builds.classify_changes(paths) is only_docs


def test_ci_producer_requires_exact_trusted_workflow_success() -> None:
    run = {
        "head_sha": SOURCE,
        "head_branch": "testing",
        "event": "push",
        "path": ".github/workflows/ci.yml",
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": builds.REPOSITORY},
    }
    assert builds.eligible_ci_run(run, SOURCE)
    for field, value in (
        ("head_sha", "c" * 40),
        ("head_branch", "main"),
        ("event", "pull_request"),
        ("path", ".github/workflows/other.yml"),
        ("status", "queued"),
        ("conclusion", "failure"),
        ("repository", {"full_name": "untrusted/fork"}),
    ):
        assert not builds.eligible_ci_run({**run, field: value}, SOURCE)


def test_signing_binds_both_native_platforms_and_image_catalog(
    signed: tuple[Path, dict[str, Any]], identity: PreviewIdentity
) -> None:
    assets, _ = signed
    builds.verify_signed_assets(assets, identity, IMAGE_DIGEST)
    for platform in SUPPORTED_PLATFORM_IDS:
        manifest = builds.verify_signed_manifest(
            (assets / release_manifest_asset_name(platform)).read_bytes(),
            (assets / f"{release_manifest_asset_name(platform)}.sig").read_bytes(),
            channel="testing",
        )
        assert manifest.schema_version == 3
        assert manifest.channel == "testing"
        assert manifest.build_id == identity.build_id
        assert (
            parse_testing_images((assets / TESTING_IMAGES_NAME).read_bytes(), manifest)
            == f"ghcr.io/kgmnotes/xferry-testing@{IMAGE_DIGEST}"
        )
    with pytest.raises(ValueError):
        builds.verify_signed_assets(assets, identity, "sha256:" + "c" * 64)
    wheel = assets / f"xferry-{identity.version}-py3-none-any.whl"
    wheel.write_bytes(b"substitution")
    with pytest.raises(ValueError):
        builds.verify_signed_assets(assets, identity, IMAGE_DIGEST)


@pytest.mark.parametrize(
    "tamper", ["digest", "origin", "missing", "duplicate", "yanked", "version"]
)
def test_testpypi_metadata_cannot_substitute_packages(
    signed: tuple[Path, dict[str, Any]], identity: PreviewIdentity, tamper: str
) -> None:
    assets, registry = signed
    assert "#sha256=" in builds.verify_testpypi(identity, assets, registry)
    if tamper == "digest":
        registry["urls"][0]["digests"]["sha256"] = "c" * 64
    elif tamper == "origin":
        registry["urls"][0]["url"] = "https://files.pythonhosted.org/packages/wrong.whl"
    elif tamper == "missing":
        registry["urls"].pop()
    elif tamper == "duplicate":
        registry["urls"].append(registry["urls"][0])
    elif tamper == "yanked":
        registry["urls"][0]["yanked"] = True
    else:
        registry["info"]["version"] = "0.5.1"
    with pytest.raises(ValueError):
        builds.verify_testpypi(identity, assets, registry)


def _ready(
    signed: tuple[Path, dict[str, Any]], identity: PreviewIdentity
) -> tuple[dict[str, Any], dict[str, tuple[bytes, bytes]], bytes]:
    assets, registry = signed
    ready = builds.ready_report(identity, assets, IMAGE_DIGEST, registry)
    manifests = {
        platform: (
            (assets / release_manifest_asset_name(platform)).read_bytes(),
            (assets / f"{release_manifest_asset_name(platform)}.sig").read_bytes(),
        )
        for platform in SUPPORTED_PLATFORM_IDS
    }
    return ready, manifests, (assets / TESTING_IMAGES_NAME).read_bytes()


def test_ready_commands_pin_testing_and_keep_pypi_dependencies(
    signed: tuple[Path, dict[str, Any]], identity: PreviewIdentity
) -> None:
    ready, manifests, catalog = _ready(signed, identity)
    assert promotion.verify_ready(ready, manifests, catalog) == identity
    assert ready["manual_acceptance"] == "pending"
    assert "--extra-index-url" not in str(ready)
    assert "--index-url" not in ready["commands"]["pip"]
    assert "#sha256=" in ready["commands"]["pipx"]
    assert "--suffix=-preview" in ready["commands"]["pipx"]
    for key in ("native", "docker", "update"):
        assert "--channel testing" in ready["commands"][key]
        assert identity.version in ready["commands"][key]
    assert "--channel stable" in ready["commands"]["rollback"]


@pytest.mark.parametrize("field", ["image", "build_id", "source_commit", "version", "assets"])
def test_acceptance_authenticates_ready_identity(
    signed: tuple[Path, dict[str, Any]], identity: PreviewIdentity, field: str
) -> None:
    ready, manifests, catalog = _ready(signed, identity)
    ready[field] = {} if field == "assets" else "forged"
    with pytest.raises(ValueError):
        promotion.verify_ready(ready, manifests, catalog)


def test_acceptance_receipt_is_bound_to_build_and_actor(
    signed: tuple[Path, dict[str, Any]], identity: PreviewIdentity
) -> None:
    ready, _, _ = _ready(signed, identity)
    record = promotion.acceptance_record(identity, ready, "maintainer", "67890")
    promotion.verify_acceptance(record, identity, ready)
    assert record["source_commit"] == SOURCE
    assert record["build_id"] == identity.build_id
    assert set(record["checks"]) == {"clean-vps", "upgrade", "health", "persistence", "rollback"}
    with pytest.raises(ValueError):
        promotion.verify_acceptance({**record, "version": "0.5.1.dev1"}, identity, ready)


def test_final_rebuild_allows_version_changelog_metadata_only(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    preview = _git(repository, "rev-parse", "HEAD")
    config = repository / "xferry/config.py"
    config.write_text(config.read_text().replace("0.5.0", "0.5.1"))
    (repository / "CHANGELOG.md").write_text("Release 0.5.1\n")
    channels = repository / "packaging/channels.toml"
    channels.write_text(
        channels.read_text()
        + f'\n[promotion]\nversion="0.5.1.dev1"\nsource_commit="{preview}"\nbuild_id="1.1"\n'
    )
    final = _commit(repository)
    promotion.validate_final_diff(repository, preview, final)
    config.write_text(config.read_text().replace("SETTING = True", "SETTING = False"))
    changed = _commit(repository)
    with pytest.raises(ValueError, match="behavior"):
        promotion.validate_final_diff(repository, preview, changed)


def test_final_rebuild_allows_synchronized_changelog_and_cli_version_metadata(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repo")
    docs = repository / "docs"
    docs.mkdir()
    cli = docs / "cli-reference.md"
    cli.write_text(_cli_fixture())
    changelog = repository / "CHANGELOG.md"
    changelog.write_bytes((ROOT / "CHANGELOG.md").read_bytes())
    generated_changelog = docs / "changelog.md"
    generated_changelog.write_bytes((ROOT / "docs/changelog.md").read_bytes())
    for name in ("API.md", "docs/api.md"):
        (repository / name).write_text(_api_fixture(name))
    preview = _commit(repository)

    for name in ("xferry/config.py", "xferry/data/index.html", "README.md"):
        path = repository / name
        path.write_text(path.read_text().replace("0.5.0", "0.5.1"))
    changelog.write_text(
        changelog.read_text().replace("## [Unreleased]", "## [0.5.1] - 2026-11-06")
    )
    header = generated_changelog.read_text().split("\n\n", 1)[0]
    generated_changelog.write_text(header + "\n\n" + changelog.read_text())
    cli_before = cli.read_text()
    cli_after = cli_before.replace(
        "Signed release version to install (default: 0.5.0).",
        "Signed release version to install (default: 0.5.1).",
    ).replace("Example: xferry update --to 0.5.0", "Example: xferry update --to 0.5.1")
    assert cli_after != cli_before
    assert "Signed release version to install (default: 0.5.1)." in cli_after
    assert "Example: xferry update --to 0.5.1" in cli_after
    cli.write_text(cli_after)
    for name in ("API.md", "docs/api.md"):
        path = repository / name
        before = path.read_text()
        after = before.replace('"server": "XFerry/0.5.0"', '"server": "XFerry/0.5.1"', 1)
        assert after != before
        path.write_text(after)
    final = _commit(repository)
    promotion.validate_final_diff(repository, preview, final)


@pytest.mark.parametrize("name", ("API.md", "docs/api.md"))
@pytest.mark.parametrize(
    "before,after",
    [
        ("Health check endpoint.", "Unauthenticated health check endpoint."),
        ('"health": "ready"', '"health": "unavailable"'),
        ("PING / HTTP/1.1", "INFO / HTTP/1.1"),
        (
            '"supported_methods": ["GET", "HEAD",',
            '"supported_methods": ["GET", "HEAD", "INJECTED",',
        ),
    ],
)
def test_final_rebuild_rejects_api_contract_changes_beside_ping_version(
    tmp_path: Path, name: str, before: str, after: str
) -> None:
    repository = _repository(tmp_path / "repo")
    path = repository / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(_api_fixture(name))
    preview = _commit(repository)
    text = path.read_text()
    assert before in text
    path.write_text(
        text.replace('"server": "XFerry/0.5.0"', '"server": "XFerry/0.5.1"').replace(before, after)
    )
    final = _commit(repository)
    with pytest.raises(ValueError, match="changes behavior"):
        promotion.validate_final_diff(repository, preview, final)


@pytest.mark.parametrize("name", ("API.md", "docs/api.md"))
def test_final_rebuild_rejects_same_server_marker_outside_ping(tmp_path: Path, name: str) -> None:
    repository = _repository(tmp_path / "repo")
    path = repository / name
    path.parent.mkdir(exist_ok=True)
    text = _api_fixture(name)
    extra = '\n## Other response\n\n```json\n{\n  "server": "XFerry/0.5.0",\n}\n```\n'
    path.write_text(text + extra)
    preview = _commit(repository)
    path.write_text(text + extra.replace("XFerry/0.5.0", "XFerry/0.5.1"))
    final = _commit(repository)
    with pytest.raises(ValueError, match="changes behavior"):
        promotion.validate_final_diff(repository, preview, final)


@pytest.mark.parametrize(
    "before,after",
    [
        ("Signed release version to install", "Unsigned release version to install"),
        ("Exact release version.", "Newest release version."),
        (
            "Example: xferry update --to 0.5.0",
            "Example: xferry update --to 0.5.1 --channel testing",
        ),
        ("Protocol example: 0.5.0", "Protocol example: 0.5.1"),
    ],
)
def test_final_rebuild_rejects_cli_reference_changes_outside_exact_version_markers(
    tmp_path: Path,
    before: str,
    after: str,
) -> None:
    repository = _repository(tmp_path / "repo")
    docs = repository / "docs"
    docs.mkdir()
    cli = docs / "cli-reference.md"
    cli.write_text(_cli_fixture() + "\nProtocol example: 0.5.0\n")
    preview = _commit(repository)
    assert before in cli.read_text()
    cli.write_text(cli.read_text().replace(before, after))
    final = _commit(repository)
    with pytest.raises(ValueError, match="changes behavior"):
        promotion.validate_final_diff(repository, preview, final)


def test_final_rebuild_rejects_dependency_changes(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repo")
    preview = _git(repository, "rev-parse", "HEAD")
    (repository / "pyproject.toml").write_text("[project]\ndependencies=[]\n")
    final = _commit(repository)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        promotion.validate_final_diff(repository, preview, final)


@pytest.mark.parametrize("code,candidate", [(False, False), (True, False), (True, True)])
def test_ci_gate_requires_every_applicable_job(code: bool, candidate: bool) -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    gate = workflow.split("  gate:\n", 1)[1]
    script = textwrap.dedent(
        gate.split("          python - <<'PY'\n", 1)[1].split("          PY", 1)[0]
    )
    names = [
        "changes",
        "test",
        "network-smoke",
        "python314-readiness",
        "docs",
        "risk-lanes",
        "cross-platform",
        "smoke",
        "browser-matrix",
        "scie-verify",
        "security",
    ]
    optional = {"python314-readiness", "cross-platform", "scie-verify", "security"}
    jobs = {
        name: {
            "result": "skipped"
            if name not in {"changes", "docs"} and (not code or candidate and name in optional)
            else "success"
        }
        for name in names
    }
    jobs["changes"]["outputs"] = {"code": str(code).lower()}
    environment = {
        **os.environ,
        "RESULTS": json.dumps(jobs),
        "CANDIDATE_GATES": str(candidate).lower(),
    }
    result = subprocess.run([os.sys.executable, "-c", script], env=environment, capture_output=True)
    assert result.returncode == 0, result.stderr
    jobs["docs"]["result"] = "skipped"
    environment["RESULTS"] = json.dumps(jobs)
    assert (
        subprocess.run(
            [os.sys.executable, "-c", script], env=environment, capture_output=True
        ).returncode
        != 0
    )


def test_testing_workflow_keeps_publishers_and_refs_separate() -> None:
    workflow = (ROOT / ".github/workflows/testpypi.yml").read_text()
    assert "branches: [testing]" in workflow
    assert "github.ref == 'refs/heads/testing'" in workflow
    assert "wait-ci --source-commit" in workflow
    assert "environment: testpypi" in workflow
    assert "environment: testing-signing" in workflow
    assert "XFERRY_TESTING_SIGNING_KEY_PEM" in workflow
    assert "ghcr.io/kgmnotes/xferry-testing:v$VERSION" in workflow
    assert "--prerelease --latest=false" in workflow
    assert "skip-existing: false" in workflow
    assert "--verify-published" in workflow
    ready_step = workflow.split(
        "      - name: Verify public GitHub bytes, TestPyPI hashes and anonymous GHCR access\n", 1
    )[1].split("      - name: Publish verified ready report", 1)[0]
    for variable, directory in (
        ("PIPX_HOME", "home"),
        ("PIPX_BIN_DIR", "bin"),
        ("PIPX_MAN_DIR", "man"),
    ):
        assert f"{variable}: ${{{{ runner.temp }}}}/xferry-ready-pipx/{directory}" in ready_step
    assert "PIP_CONFIG_FILE: /dev/null" in ready_step
    assert 'PYTHONNOUSERSITE: "1"' in ready_step
    assert "PIP_INDEX_URL: https://pypi.org/simple/" in ready_step
    assert 'PIP_EXTRA_INDEX_URL: ""' in ready_step
    assert 'python -I -m pipx install --suffix=-preview "$wheel_url"' in ready_step
    assert '"$PIPX_BIN_DIR/xferry-preview" run --version' in ready_step
    assert "$HOME/.local/bin" not in ready_step
    assert "retention-days: 90" in workflow
    assert "name: testing-source-${{ github.run_id }}.${{ github.run_attempt }}" in workflow
    assert "name: testing-signed-${{ needs.identity.outputs.build-id }}" in workflow
    assert "pattern: testing-*-${{ needs.identity.outputs.build-id }}" in workflow
    assert "$GITHUB_WORKSPACE/dist/xferry-*.whl" not in workflow
    assert "--clobber" not in workflow
    assert "https://upload.pypi.org/legacy/" not in workflow
    assert not re.search(r"\bssh\b|\bscp\b", workflow)
    acceptance = (ROOT / ".github/workflows/testing-acceptance.yml").read_text()
    assert "confirm_vps_checks" in acceptance
    assert "github.ref == 'refs/heads/main'" in acceptance
    production = (ROOT / ".github/workflows/release-production.yml").read_text()
    assert "testing_release.py preflight" in production
    assert "environment: production" in production


def _registry_fixture(
    identity: PreviewIdentity, tamper: str | None = None
) -> tuple[str, dict[str, bytes]]:
    payloads: dict[str, bytes] = {}
    descriptors = []

    def encoded(document: object) -> bytes:
        return json.dumps(document, sort_keys=True).encode()

    def descriptor(payload: bytes) -> dict[str, Any]:
        return {"digest": "sha256:" + hashlib.sha256(payload).hexdigest(), "size": len(payload)}

    for architecture in ("arm64", "amd64"):
        labels = {
            "org.opencontainers.image.version": identity.version,
            "org.opencontainers.image.revision": SOURCE,
            "io.xferry.build-id": identity.build_id,
            "io.xferry.channel": "testing",
        }
        if architecture == "arm64" and tamper in labels:
            labels[tamper] = "wrong-build"
        config = {"architecture": architecture, "os": "linux", "config": {"Labels": labels}}
        if architecture == "arm64" and tamper in {"architecture", "os"}:
            config[tamper] = "unsupported"
        config_payload = encoded(config)
        config_descriptor = descriptor(config_payload)
        payloads[f"blobs/{config_descriptor['digest']}"] = (
            config_payload.replace(b'"linux"', b'"linuX"')
            if architecture == "arm64" and tamper == "config-hash"
            else config_payload
        )
        if architecture == "arm64" and tamper == "config-size":
            config_descriptor["size"] += 1
        if architecture == "arm64" and tamper == "config-digest-format":
            config_descriptor["digest"] = "sha256:invalid"
        manifest = {"schemaVersion": 2, "config": config_descriptor, "layers": []}
        manifest_payload = encoded(manifest)
        manifest_descriptor = descriptor(manifest_payload)
        payloads[f"manifests/{manifest_descriptor['digest']}"] = (
            manifest_payload.replace(b'"schemaVersion": 2', b'"schemaVersion": 3')
            if architecture == "arm64" and tamper == "manifest-hash"
            else manifest_payload
        )
        if architecture == "arm64" and tamper == "manifest-size":
            manifest_descriptor["size"] += 1
        if architecture == "arm64" and tamper == "descriptor-size-boolean":
            manifest_descriptor["size"] = True
        if architecture == "arm64" and tamper == "manifest-digest-format":
            manifest_descriptor["digest"] = "sha256:invalid"
        manifest_descriptor["platform"] = {"os": "linux", "architecture": architecture}
        descriptors.append(manifest_descriptor)
    if tamper == "duplicate-architecture":
        descriptors.append(descriptors[0])
    index = encoded({"schemaVersion": 2, "manifests": descriptors})
    digest = "sha256:" + hashlib.sha256(index).hexdigest()
    payloads[f"manifests/{digest}"] = index
    return digest, payloads


def _mock_registry(
    monkeypatch: pytest.MonkeyPatch, payloads: dict[str, bytes]
) -> tuple[list[list[str]], list[str]]:
    commands: list[list[str]] = []
    requests: list[str] = []
    stored_images: dict[str, str] = {}
    monkeypatch.setattr(builds, "_anonymous_registry_token", lambda: "public-fixture-token")

    def read(path: str, *, accept: str, token: str | None = None) -> bytes:
        assert token == "public-fixture-token"
        assert accept
        requests.append(path)
        return payloads[path]

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        assert command[:2] == ["docker", "--config"]
        assert command[3] == "pull"
        assert kwargs["check"] is True
        architecture = (
            command[command.index("--platform") + 1].split("/")[1]
            if "--platform" in command
            else "amd64"
        )
        reference = command[-1]
        if reference in stored_images and stored_images[reference] != architecture:
            raise subprocess.CalledProcessError(1, command, stderr="cannot overwrite digest")
        stored_images[reference] = architecture
        return subprocess.CompletedProcess(command, 0)

    def unsupported_inspect(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("older Docker clients must not need image inspect --platform")

    monkeypatch.setattr(builds, "_anonymous_registry_payload", read)
    monkeypatch.setattr(builds.subprocess, "run", run)
    monkeypatch.setattr(builds.subprocess, "check_output", unsupported_inspect)
    return commands, requests


def test_anonymous_image_readback_checks_both_architectures_without_new_docker_flags(
    identity: PreviewIdentity, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest, payloads = _registry_fixture(identity)
    commands, requests = _mock_registry(monkeypatch, payloads)
    builds.verify_public_image(identity, digest)
    assert [command[5] for command in commands[:2]] == ["linux/arm64", "linux/amd64"]
    index = json.loads(payloads[f"manifests/{digest}"])
    descriptors = {item["platform"]["architecture"]: item["digest"] for item in index["manifests"]}
    expected = [descriptors["arm64"], descriptors["amd64"], digest]
    assert [command[-1] for command in commands] == [
        f"ghcr.io/kgmnotes/xferry-testing@{item}" for item in expected
    ]
    assert "--platform" not in commands[-1]
    assert len({command[-1] for command in commands}) == 3
    assert len(requests) == 5
    assert sum(path.startswith("blobs/") for path in requests) == 2


def test_classic_store_regression_rejects_reusing_one_index_for_two_platforms(
    identity: PreviewIdentity,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest, payloads = _registry_fixture(identity)
    _mock_registry(monkeypatch, payloads)
    image = f"ghcr.io/kgmnotes/xferry-testing@{digest}"
    command = ["docker", "--config", "/temporary-anonymous-client", "pull", "--platform"]
    builds.subprocess.run([*command, "linux/arm64", image], check=True)
    with pytest.raises(subprocess.CalledProcessError, match="non-zero exit status 1"):
        builds.subprocess.run([*command, "linux/amd64", image], check=True)


@pytest.mark.parametrize(
    "tamper",
    [
        "manifest-hash",
        "manifest-size",
        "config-hash",
        "config-size",
        "manifest-digest-format",
        "config-digest-format",
        "descriptor-size-boolean",
        "architecture",
        "os",
        "duplicate-architecture",
        "org.opencontainers.image.version",
        "org.opencontainers.image.revision",
        "io.xferry.build-id",
        "io.xferry.channel",
    ],
)
def test_anonymous_image_readback_rejects_tampered_descriptors_and_identity(
    identity: PreviewIdentity,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    digest, payloads = _registry_fixture(identity, tamper)
    commands, _ = _mock_registry(monkeypatch, payloads)
    with pytest.raises(ValueError):
        builds.verify_public_image(identity, digest)
    assert not commands


@pytest.mark.parametrize(
    "path",
    [
        "https://untrusted.example/manifest",
        "../manifest",
        "blobs/sha256:invalid",
        "manifests/sha256:" + "a" * 64 + "/extra",
    ],
)
def test_anonymous_registry_metadata_rejects_other_paths(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    def forbid(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("invalid registry paths must not make network requests")

    monkeypatch.setattr(builds.urllib.request, "urlopen", forbid)
    with pytest.raises(ValueError, match="exact digest"):
        builds._anonymous_registry_payload(path, accept="application/json", token="public-token")


def test_anonymous_registry_metadata_uses_fixed_https_origin_and_bounded_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "blobs/sha256:" + "a" * 64

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            assert size == builds._REGISTRY_METADATA_LIMIT + 1
            return b"x" * size

    def open_request(request: Any, *, timeout: int) -> Response:
        assert request.full_url == f"https://ghcr.io/v2/kgmnotes/xferry-testing/{path}"
        assert request.get_header("Authorization") == "Bearer public-token"
        assert timeout == 30
        return Response()

    monkeypatch.setattr(builds.urllib.request, "urlopen", open_request)
    with pytest.raises(ValueError, match="size limit"):
        builds._anonymous_registry_payload(
            path, accept="application/octet-stream", token="public-token"
        )


def test_manual_acceptance_cannot_reuse_another_dispatch_or_skipped_job(
    identity: PreviewIdentity,
) -> None:
    record = {"actor": "maintainer"}
    run = {
        "path": ".github/workflows/testing-acceptance.yml",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "display_title": f"Accept {identity.version} ({identity.build_id}) from {SOURCE}",
        "repository": {"full_name": builds.REPOSITORY},
        "actor": {"login": "maintainer"},
    }
    jobs = {
        "jobs": [
            {
                "name": "accept",
                "conclusion": "success",
                "steps": [
                    {
                        "name": "Record explicit acceptance of the authenticated preview",
                        "conclusion": "success",
                    }
                ],
            }
        ]
    }
    promotion.verify_acceptance_run(run, jobs, identity, record)
    for field, value in (
        ("display_title", "Accept another preview"),
        ("head_branch", "testing"),
        ("actor", {"login": "someone-else"}),
    ):
        with pytest.raises(ValueError):
            promotion.verify_acceptance_run({**run, field: value}, jobs, identity, record)
    with pytest.raises(ValueError):
        promotion.verify_acceptance_run(
            run, {"jobs": [{"name": "accept", "conclusion": "skipped"}]}, identity, record
        )
    with pytest.raises(ValueError):
        promotion.verify_acceptance_run(
            run,
            {"jobs": [{"name": "accept", "conclusion": "success", "steps": []}]},
            identity,
            record,
        )


@pytest.mark.parametrize(
    "event,ref,base,code,candidate,expected",
    [
        ("push", "refs/heads/main", "", True, False, True),
        ("pull_request", "refs/pull/1/merge", "main", True, False, True),
        ("push", "refs/heads/testing", "", True, False, False),
        ("pull_request", "refs/pull/1/merge", "testing", True, False, False),
        ("workflow_dispatch", "refs/heads/main", "", True, False, False),
        ("push", "refs/tags/v0.5.1", "", True, False, False),
        ("push", "refs/heads/main", "", False, False, False),
        ("pull_request", "refs/pull/1/merge", "main", False, False, False),
        ("push", "refs/heads/main", "", True, True, False),
    ],
)
def test_main_security_compatibility_contexts_have_narrow_rollout_guard(
    event: str,
    ref: str,
    base: str,
    code: bool,
    candidate: bool,
    expected: bool,
) -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    job = workflow.split("  security-compatibility:\n", 1)[1].split("  gate:\n", 1)[0]
    assert "name: ${{ matrix.context }}" in job
    assert "needs: [changes, security]" in job
    for context in ("bandit", "pip-audit (Python 3.12)", "pip-audit (Python 3.14)"):
        assert f"          - {context}\n" in job
    expression = job.split("    if: ${{ ", 1)[1].split(" }}", 1)[0]
    assert "always()" in expression
    expression = expression.replace("!inputs.candidate-gates", str(not candidate))
    values = {
        "needs.changes.outputs.code": str(code).lower(),
        "github.event_name": event,
        "github.ref": ref,
        "github.base_ref": base,
    }
    for name, value in values.items():
        expression = expression.replace(name, repr(value))
    expression = expression.replace("always()", "True").replace("&&", "and").replace("||", "or")
    parsed = ast.parse(expression, mode="eval")
    assert eval(compile(parsed, "compatibility guard", "eval"), {"__builtins__": {}}) is expected
    assert "python -m pip" not in job
    assert "pip_audit" not in job
    assert "bandit -r" not in job


@pytest.mark.parametrize("security_result", ["success", "failure", "cancelled", "skipped"])
def test_main_security_compatibility_fails_when_actual_audits_do_not_pass(
    security_result: str,
) -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    job = workflow.split("  security-compatibility:\n", 1)[1].split("  gate:\n", 1)[0]
    assert "SECURITY_RESULT: ${{ needs.security.result }}" in job
    command = job.split("        run: ", 1)[1].splitlines()[0]
    result = subprocess.run(
        ["bash", "-c", command],
        env={**os.environ, "SECURITY_RESULT": security_result},
        capture_output=True,
    )
    assert (result.returncode == 0) is (security_result == "success")


def test_every_ci_browser_dependency_install_configures_complete_apt_sources_first() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text().split("jobs:\n", 1)[1]
    jobs = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):\n", workflow))
    configured = set()
    for index, match in enumerate(jobs):
        end = jobs[index + 1].start() if index + 1 < len(jobs) else len(workflow)
        job = workflow[match.end() : end]
        lines = job.splitlines()
        for line_number, line in enumerate(lines):
            if "install-browser" not in line or "--with-deps" not in line:
                continue
            before_install = "\n".join(lines[:line_number])
            assert "run: sudo python3 tools/configure_ci_browser_apt.py" in before_install, match[1]
            assert "sudo sed -i" not in before_install
            configured.add(match[1])
    assert configured == {"smoke", "browser-matrix"}
