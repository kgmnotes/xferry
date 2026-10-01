"""Draft GitHub Release rehearsal rejects candidate and workflow substitution."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.candidate_inventory import create_inventory, pack_candidate
from xferry.management.release_contract import (
    SUPPORTED_PLATFORM_IDS,
    ReleaseManifest,
    artifact_name,
)
from xferry.management.release_trust import ReleaseKeyRing, TrustedReleaseKey

REPO_ROOT = Path(__file__).resolve().parents[1]
TAG = "v0.1.0"
VERSION = "0.1.0"
COMMIT = "40ac9bc031aa28b9adc2765857a8926f522e4005"
RUN = "36712344792"
REHEARSAL_TAG = "xferry-stage-012-rehearsal-v0.1.0-36712344792-v2"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _blob(root: Path, payload: bytes, media_type: str) -> dict[str, object]:
    digest = _sha(payload)
    path = root / "oci/blobs/sha256" / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {"mediaType": media_type, "digest": f"sha256:{digest}", "size": len(payload)}


def _image(root: Path, arch: str) -> dict[str, object]:
    config = _blob(
        root,
        _json(
            {
                "architecture": arch,
                "os": "linux",
                "config": {
                    "Labels": {
                        "org.opencontainers.image.version": VERSION,
                        "org.opencontainers.image.revision": COMMIT,
                    }
                },
            }
        ),
        OCI_CONFIG,
    )
    layer = _blob(root, f"layer-{arch}".encode(), "application/vnd.oci.image.layer.v1.tar")
    manifest = _blob(
        root,
        _json({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": config, "layers": [layer]}),
        OCI_MANIFEST,
    )
    manifest["platform"] = {"os": "linux", "architecture": arch}
    return manifest


def _candidate(root: Path) -> Path:
    for directory in ("python", "oci/blobs/sha256", *(f"scie-{p}" for p in SUPPORTED_PLATFORM_IDS)):
        (root / directory).mkdir(parents=True)
    metadata = f"Metadata-Version: 2.4\nName: xferry\nVersion: {VERSION}\n\n".encode()
    with zipfile.ZipFile(root / f"python/xferry-{VERSION}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"xferry-{VERSION}.dist-info/METADATA", metadata)
        wheel.writestr("xferry/config.py", f'__version__ = "{VERSION}"\n')
    with tarfile.open(root / f"python/xferry-{VERSION}.tar.gz", "w:gz") as sdist:
        member = tarfile.TarInfo(f"xferry-{VERSION}/PKG-INFO")
        member.size = len(metadata)
        sdist.addfile(member, io.BytesIO(metadata))
    (root / "python/xferry-dependency-sbom.cdx.json").write_bytes(
        _json({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1})
    )
    for platform in SUPPORTED_PLATFORM_IDS:
        directory = root / f"scie-{platform}"
        executable = directory / artifact_name(VERSION, platform)
        executable.write_bytes(f"scie-{platform}".encode())
        executable.chmod(0o755)
        manifest = ReleaseManifest.create_v2(
            version=VERSION,
            platform=platform,
            executable_size=executable.stat().st_size,
            executable_sha256=_sha(executable.read_bytes()),
            source_commit=COMMIT,
            workflow_run=RUN,
        )
        (directory / "xferry-release.json").write_bytes(manifest.to_bytes())
        installer = directory / "install.sh"
        installer.write_text(
            "#!/bin/sh\n"
            f"version='{VERSION}'\nplatform_id='{platform}'\n"
            f"artifact_name='{executable.name}'\nartifact_size='{executable.stat().st_size}'\n"
            f"artifact_sha256='{manifest.executable_sha256}'\nmanifest_signature_required='false'\n"
            "hosted_signature_required='true'\n"
            f"hosted_manifest_name='xferry-release-{platform}.json'\n"
            "supported_release_major='0'\n"
            "cat > \"$candidate_release/xferry-release.json\" <<'XFERRY_CANDIDATE_MANIFEST'\n"
            + manifest.to_bytes().decode()
            + "XFERRY_CANDIDATE_MANIFEST\n",
            encoding="utf-8",
        )
        installer.chmod(0o755)
        (directory / "SHA256SUMS").write_text(
            f"{manifest.executable_sha256}  {executable.name}\n", encoding="utf-8"
        )
    manifests = [_image(root, arch) for arch in ("amd64", "arm64")]
    config = _blob(root, _json({"architecture": "unknown", "os": "unknown"}), OCI_CONFIG)
    for image in list(manifests):
        layers = [
            _blob(
                root,
                _json(
                    {
                        "_type": "https://in-toto.io/Statement/v0.1",
                        "predicateType": predicate,
                        "subject": [
                            {"name": "xferry", "digest": {"sha256": str(image["digest"])[7:]}}
                        ],
                        "predicate": (
                            {
                                "spdxVersion": "SPDX-2.3",
                                "packages": [{"name": "xferry", "versionInfo": VERSION}],
                            }
                            if predicate == "https://spdx.dev/Document"
                            else {"buildType": "xferry/test", "builder": {"id": "offline"}}
                        ),
                    }
                ),
                "application/vnd.in-toto+json",
            )
            for predicate in ("https://spdx.dev/Document", "https://slsa.dev/provenance/v0.2")
        ]
        attestation = _blob(
            root,
            _json({"schemaVersion": 2, "config": config, "layers": layers}),
            OCI_MANIFEST,
        )
        attestation["platform"] = {"os": "unknown", "architecture": "unknown"}
        attestation["annotations"] = {
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": image["digest"],
        }
        manifests.append(attestation)
    index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests}
    (root / "oci/index.json").write_bytes(_json(index))
    (root / "oci/oci-layout").write_bytes(_json({"imageLayoutVersion": "1.0.0"}))
    return root


def _identity(tmp_path: Path) -> tuple[dict, Path, Path]:
    root = _candidate(tmp_path / "candidate")
    inventory_sha = create_inventory(root, TAG, COMMIT, RUN)
    archive = tmp_path / "release-candidate.tar"
    archive_sha = pack_candidate(root, archive)
    identity = {
        "repository": "kgmnotes/xferry",
        "repository_id": 1341230685,
        "version": VERSION,
        "tag": TAG,
        "release_tag": REHEARSAL_TAG,
        "source_commit": COMMIT,
        "workflow_run": int(RUN),
        "artifact_id": 11095067140,
        "artifact_name": "release-candidate-36712344792-1",
        "artifact_sha256": "a" * 64,
        "artifact_size": 123,
        "archive_sha256": archive_sha,
        "inventory_sha256": inventory_sha,
    }
    return identity, root, archive


def _metadata(identity: dict) -> tuple[dict, dict]:
    artifact = {
        "id": identity["artifact_id"],
        "name": identity["artifact_name"],
        "digest": "sha256:" + identity["artifact_sha256"],
        "expired": False,
        "size_in_bytes": identity["artifact_size"],
        "workflow_run": {
            "id": identity["workflow_run"],
            "head_sha": identity["source_commit"],
            "repository_id": identity["repository_id"],
        },
    }
    run = {
        "id": identity["workflow_run"],
        "run_attempt": 1,
        "head_sha": identity["source_commit"],
        "event": "workflow_dispatch",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": identity["repository_id"], "full_name": identity["repository"]},
    }
    return artifact, run


def _private_key(path: Path) -> tuple[str, ReleaseKeyRing]:
    key_id = "test-release-2026"
    private_key = Ed25519PrivateKey.generate()
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key_id, ReleaseKeyRing(
        (TrustedReleaseKey(key_id, private_key.public_key().public_bytes_raw()),)
    )


def _rewrite_release_asset_record(directory: Path, name: str) -> None:
    inventory_path = directory / "github-release-assets.json"
    inventory = json.loads(inventory_path.read_bytes())
    payload = (directory / name).read_bytes()
    inventory["assets"][name]["size"] = len(payload)
    inventory["assets"][name]["sha256"] = hashlib.sha256(payload).hexdigest()
    inventory_path.write_bytes((json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode())


def _remove_release_asset_record(directory: Path, name: str) -> None:
    inventory_path = directory / "github-release-assets.json"
    inventory = json.loads(inventory_path.read_bytes())
    inventory["assets"].pop(name)
    inventory_path.write_bytes((json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode())


def test_api_identity_substitution_is_rejected(tmp_path: Path) -> None:
    from tools import github_release_assets as assets

    identity, _candidate_root, _archive = _identity(tmp_path)
    artifact, run = _metadata(identity)
    assets.verify_api_identity(identity, artifact, run)
    artifact["workflow_run"]["head_sha"] = "b" * 40

    with pytest.raises(ValueError, match="STAGE-009"):
        assets.verify_api_identity(identity, artifact, run)


def test_release_asset_assembly_signs_manifests_and_preserves_candidate_bytes(
    tmp_path: Path,
) -> None:
    from tools import github_release_assets as assets

    identity, candidate, archive = _identity(tmp_path)
    artifact, run = _metadata(identity)
    key_id, key_ring = _private_key(tmp_path / "key.pem")
    unsigned = tmp_path / "unsigned-assets"
    signed = tmp_path / "signed-assets"

    assets.prepare_unsigned_assets(
        identity, artifact, run, archive, tmp_path / "promoted", unsigned
    )
    assets.sign_prepared_assets(
        unsigned,
        signed,
        key_id=key_id,
        private_key=tmp_path / "key.pem",
        identity=identity,
    )

    expected = {
        "SHA256SUMS-linux-aarch64",
        "SHA256SUMS-linux-x86_64",
        "candidate-inventory.json",
        "github-release-assets.json",
        "install-linux-aarch64.sh",
        "install-linux-aarch64.sh.sig",
        "install-linux-x86_64.sh",
        "install-linux-x86_64.sh.sig",
        "release-candidate.tar",
        "xferry-0.1.0-linux-aarch64",
        "xferry-0.1.0-linux-x86_64",
        "xferry-0.1.0-py3-none-any.whl",
        "xferry-0.1.0.tar.gz",
        "xferry-dependency-sbom.cdx.json",
        "xferry-release-linux-aarch64.json",
        "xferry-release-linux-aarch64.json.sig",
        "xferry-release-linux-x86_64.json",
        "xferry-release-linux-x86_64.json.sig",
    }
    assert {path.name for path in signed.iterdir()} == expected
    assert (
        signed.joinpath("xferry-0.1.0-linux-x86_64").read_bytes()
        == candidate.joinpath("scie-linux-x86_64/xferry-0.1.0-linux-x86_64").read_bytes()
    )
    assert (
        signed.joinpath("install-linux-aarch64.sh").read_bytes()
        == candidate.joinpath("scie-linux-aarch64/install.sh").read_bytes()
    )
    assert stat.S_IMODE(signed.joinpath("xferry-0.1.0-linux-x86_64").stat().st_mode) == 0o755
    assert stat.S_IMODE(signed.joinpath("install-linux-x86_64.sh").stat().st_mode) == 0o755

    inventory = json.loads(signed.joinpath("github-release-assets.json").read_bytes())
    assert inventory["release_tag"] == REHEARSAL_TAG
    assert inventory["signing_key_id"] == key_id
    assert inventory["assets"]["xferry-release-linux-x86_64.json"]["generated"] is True
    manifest = ReleaseManifest.parse_new(
        signed.joinpath("xferry-release-linux-x86_64.json").read_bytes()
    )
    assert manifest.signing_scheme == "ed25519"
    assert manifest.signing_key_ids == (key_id,)
    assert manifest.source_commit == COMMIT
    assert (
        dict(manifest.artifact_digests)["install-linux-x86_64.sh"]
        == hashlib.sha256(signed.joinpath("install-linux-x86_64.sh").read_bytes()).hexdigest()
    )

    assets.verify_downloaded_assets(identity, signed, key_ring=key_ring)
    assets.verify_tamper_is_rejected(signed, identity=identity, key_ring=key_ring)


def test_signing_rejects_prepared_asset_substitution_before_key_load(tmp_path: Path) -> None:
    from tools import github_release_assets as assets

    identity, _candidate, archive = _identity(tmp_path)
    artifact, run = _metadata(identity)
    unsigned = tmp_path / "unsigned"
    signed = tmp_path / "signed"
    assets.prepare_unsigned_assets(
        identity, artifact, run, archive, tmp_path / "promoted", unsigned
    )
    unsigned.joinpath("xferry-0.1.0-linux-x86_64").write_bytes(b"substituted-scie")

    with pytest.raises(ValueError, match="candidate|prepared"):
        assets.sign_prepared_assets(
            unsigned,
            signed,
            key_id="test-release-2026",
            private_key=tmp_path / "missing-key.pem",
            identity=identity,
        )

    assert not signed.exists() or not any(signed.iterdir())


def test_release_asset_verification_rejects_tampered_download(tmp_path: Path) -> None:
    from tools import github_release_assets as assets

    identity, _candidate, archive = _identity(tmp_path)
    artifact, run = _metadata(identity)
    key_id, key_ring = _private_key(tmp_path / "key.pem")
    assets.prepare_unsigned_assets(
        identity,
        artifact,
        run,
        archive,
        tmp_path / "promoted",
        tmp_path / "unsigned",
    )
    assets.sign_prepared_assets(
        tmp_path / "unsigned",
        tmp_path / "signed",
        key_id=key_id,
        private_key=tmp_path / "key.pem",
        identity=identity,
    )

    tampered = tmp_path / "signed" / "install-linux-x86_64.sh"
    tampered.write_bytes(tampered.read_bytes() + b"# tamper\n")

    with pytest.raises(ValueError, match="asset digest"):
        assets.verify_downloaded_assets(identity, tmp_path / "signed", key_ring=key_ring)


def test_release_asset_verification_rejects_missing_candidate_asset_even_with_coherent_receipt(
    tmp_path: Path,
) -> None:
    from tools import github_release_assets as assets

    identity, _candidate, archive = _identity(tmp_path)
    artifact, run = _metadata(identity)
    key_id, key_ring = _private_key(tmp_path / "key.pem")
    assets.prepare_unsigned_assets(
        identity,
        artifact,
        run,
        archive,
        tmp_path / "promoted",
        tmp_path / "unsigned",
    )
    assets.sign_prepared_assets(
        tmp_path / "unsigned",
        tmp_path / "signed",
        key_id=key_id,
        private_key=tmp_path / "key.pem",
        identity=identity,
    )
    missing = tmp_path / "signed" / "xferry-0.1.0-py3-none-any.whl"
    missing.unlink()
    _remove_release_asset_record(tmp_path / "signed", missing.name)

    with pytest.raises(ValueError, match="asset set|candidate"):
        assets.verify_downloaded_assets(identity, tmp_path / "signed", key_ring=key_ring)


def test_release_asset_verification_rejects_coherent_receipt_payload_substitution(
    tmp_path: Path,
) -> None:
    from tools import github_release_assets as assets

    identity, _candidate, archive = _identity(tmp_path)
    artifact, run = _metadata(identity)
    key_id, key_ring = _private_key(tmp_path / "key.pem")
    assets.prepare_unsigned_assets(
        identity,
        artifact,
        run,
        archive,
        tmp_path / "promoted",
        tmp_path / "unsigned",
    )
    assets.sign_prepared_assets(
        tmp_path / "unsigned",
        tmp_path / "signed",
        key_id=key_id,
        private_key=tmp_path / "key.pem",
        identity=identity,
    )
    substituted = tmp_path / "signed" / "xferry-0.1.0-py3-none-any.whl"
    substituted.write_bytes(b"coherent but foreign wheel")
    _rewrite_release_asset_record(tmp_path / "signed", substituted.name)

    with pytest.raises(ValueError, match="candidate"):
        assets.verify_downloaded_assets(identity, tmp_path / "signed", key_ring=key_ring)


def test_tamper_probe_uses_fixed_identity_not_mutable_release_inventory(
    tmp_path: Path,
) -> None:
    from tools import github_release_assets as assets

    identity, _candidate, archive = _identity(tmp_path)
    artifact, run = _metadata(identity)
    key_id, key_ring = _private_key(tmp_path / "key.pem")
    assets.prepare_unsigned_assets(
        identity,
        artifact,
        run,
        archive,
        tmp_path / "promoted",
        tmp_path / "unsigned",
    )
    assets.sign_prepared_assets(
        tmp_path / "unsigned",
        tmp_path / "signed",
        key_id=key_id,
        private_key=tmp_path / "key.pem",
        identity=identity,
    )
    inventory_path = tmp_path / "signed" / "github-release-assets.json"
    inventory = json.loads(inventory_path.read_bytes())
    inventory["source_commit"] = "b" * 40
    inventory_path.write_bytes((json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode())

    with pytest.raises(ValueError, match="identity"):
        assets.verify_tamper_is_rejected(tmp_path / "signed", identity=identity, key_ring=key_ring)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("workflow_dispatch:", "push:"),
        ("environment: production-release", "environment: testpypi"),
        ("environment: github-release-staging", "environment: production-release"),
        ("contents: write", "contents: read"),
        ("contents: read\n  actions: read", "contents: write\n  actions: read"),
        ("xferry-stage-012-rehearsal-v0.1.0-36712344792-v2", "v0.1.0"),
        ("--draft --prerelease --latest=false", "--prerelease"),
        ("gh release create", "gh release upload"),
        ("gh release create", "gh release edit"),
        ("printf '%s' \"${XFERRY_RELEASE_PRIVATE_KEY_PEM}\"", "true"),
        ("trap cleanup EXIT", "# trap cleanup EXIT"),
        ("shred -u", "rm -f"),
        (
            "python tools/github_release_assets.py verify --assets-dir signed-assets",
            "python tools/github_release_assets.py sign --unsigned-dir unsigned-assets",
        ),
        (
            (
                'gh release view "${RELEASE_TAG}" --repo kgmnotes/xferry '
                "--json tagName,isDraft,isPrerelease"
            ),
            "true",
        ),
        ('gh release download "${RELEASE_TAG}"', "true"),
        (
            "artifact-id: ${{ steps.downloaded-assets.outputs.artifact-id }}",
            "artifact-id: missing",
        ),
        (
            "artifact-ids: ${{ needs.publish-draft.outputs.artifact-id }}",
            "artifact-ids: ${{ needs.sign-assets.outputs.artifact-id }}",
        ),
        (
            "python tools/github_release_assets.py verify-tamper",
            "python tools/github_release_assets.py verify",
        ),
        ("refs/heads/codex/stage-012-draft-release-rehearsal-v2", "refs/heads/main"),
        ("run-id: 36712344792", "run-id: 1"),
        ("artifact-ids: 11095067140", "artifact-ids: 1"),
        ("persist-credentials: false", "persist-credentials: true"),
    ],
)
def test_github_release_rehearsal_policy_rejects_boundary_regressions(
    before: str,
    after: str,
) -> None:
    from tools.check_stale_docs import github_release_rehearsal_policy_findings

    workflow = (REPO_ROOT / ".github/workflows/github-release-rehearsal.yml").read_text()
    assert github_release_rehearsal_policy_findings(workflow) == []
    assert before in workflow
    assert github_release_rehearsal_policy_findings(workflow.replace(before, after, 1))


def test_github_release_rehearsal_policy_is_included_in_repository_guard() -> None:
    from tools.check_stale_docs import find_release_policy_issues

    assert find_release_policy_issues(REPO_ROOT) == []


def test_github_release_draft_postcondition_uses_draft_aware_lookup() -> None:
    """A created draft must not be queried through the published-release tag endpoint."""
    workflow = (REPO_ROOT / ".github/workflows/github-release-rehearsal.yml").read_text()
    publish = workflow.split("\n  publish-draft:", 1)[1].split("\n  download-verify:", 1)[0]

    assert (
        'gh release view "${RELEASE_TAG}" --repo kgmnotes/xferry '
        "--json tagName,isDraft,isPrerelease"
    ) in publish
    assert "releases/tags/" not in publish
    assert "jq -r '.tagName'" in publish
    assert "jq -r '.isDraft'" in publish
    assert "jq -r '.isPrerelease'" in publish


def test_draft_assets_cross_the_write_boundary_only_as_an_actions_artifact() -> None:
    """The read-only verifier must not need push access to discover a draft Release."""
    workflow = (REPO_ROOT / ".github/workflows/github-release-rehearsal.yml").read_text()
    publish = workflow.split("\n  publish-draft:", 1)[1].split("\n  download-verify:", 1)[0]
    verify = workflow.split("\n  download-verify:", 1)[1]

    assert 'gh release download "${RELEASE_TAG}"' in publish
    assert "id: downloaded-assets" in publish
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in publish
    assert "artifact-id: ${{ steps.downloaded-assets.outputs.artifact-id }}" in publish
    assert "gh release download" not in verify
    assert "artifact-ids: ${{ needs.publish-draft.outputs.artifact-id }}" in verify
    assert "path: downloaded" in verify


def test_github_release_rehearsal_policy_rejects_secret_in_publisher_job() -> None:
    from tools.check_stale_docs import github_release_rehearsal_policy_findings

    workflow = (REPO_ROOT / ".github/workflows/github-release-rehearsal.yml").read_text()
    publish = "\n  publish-draft:"
    injection = '          echo "${{ secrets.XFERRY_RELEASE_ED25519_PRIVATE_KEY_PEM }}"\n'

    findings = github_release_rehearsal_policy_findings(
        workflow.replace(publish, injection + publish, 1)
    )

    assert any("signing secret" in finding.message.lower() for finding in findings)


def test_github_release_rehearsal_policy_rejects_publish_shell_tag_override() -> None:
    from tools.check_stale_docs import github_release_rehearsal_policy_findings

    workflow = (REPO_ROOT / ".github/workflows/github-release-rehearsal.yml").read_text()
    findings = github_release_rehearsal_policy_findings(
        workflow.replace(
            "          gh release create",
            "          RELEASE_TAG=v0.1.0\n          gh release create",
            1,
        )
    )

    assert any("release tag" in finding.message.lower() for finding in findings)
